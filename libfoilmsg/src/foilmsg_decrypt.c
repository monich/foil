/*
 * Copyright (C) 2016-2019 by Slava Monich
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1.Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   2.Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer
 *     in the documentation and/or other materials provided with the
 *     distribution.
 *  3. Neither the names of the copyright holders nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) ARISING
 * IN ANY WAY OUT OF THE USE OR INABILITY TO USE THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation
 * are those of the authors and should not be interpreted as representing
 * any official policies, either expressed or implied.
 */

#include "foilmsg_p.h"

#include <foil_input.h>
#include <foil_output.h>
#include <foil_util.h>

#include <gutil_macros.h>
#include <gutil_strv.h>
#include <gutil_log.h>

#include <ctype.h>

typedef struct foilmsg_priv {
    FoilMsg msg;
    GBytes* sig;
    GBytes* sig_digest;
    GType sig_cipher_type;
    char* content_type;
    FoilMsgHeader* headers;
    char** header_strings;
} FoilMsgPriv;

typedef struct foilmsg_decrypt_context {
    FoilCipher* cipher;
    GType sig_digest_type;
    GType sig_cipher_type;
    FoilBytes fingerprint_data;
    FoilBytes sig_data;
    FoilBytes enc_data;
} FoilMsgDecrypt;

#define foilmsg_priv_cast(x) G_CAST(x,FoilMsgPriv,msg)

#define MAX_LEN (65536)

enum foilmsg_block {
    FOILMSG_BLOCK_FINGERPRINT,
    FOILMSG_BLOCK_ENCRYPT_KEY,
    FOILMSG_BLOCK_ENCRYPT_DATA,
    FOILMSG_BLOCK_SIGNATURE,
    FOILMSG_BLOCK_COUNT
};

/* Takes ownership of content_type and headers */
static
FoilMsg*
foilmsg_alloc(
    char* content_type,
    char** headers,
    FoilOutput* out,
    FoilDigest* digest,
    GType sig_cipher_type,
    const FoilBytes* fingerprint,
    const FoilBytes* signature)
{
    FoilMsgPriv* priv = g_slice_new0(FoilMsgPriv);
    FoilMsg* msg = &priv->msg;
    msg->content_type = priv->content_type = content_type;
    msg->data = foil_output_free_to_bytes(foil_output_ref(out));
    msg->fingerprint = g_bytes_new(fingerprint->val, fingerprint->len);
    msg->headers.count = gutil_strv_length(headers)/2;
    if (msg->headers.count > 0) {
        guint i;
        msg->headers.header =
        priv->headers = g_new(FoilMsgHeader, msg->headers.count);
        for (i=0; i<msg->headers.count; i++) {
            priv->headers[i].name = headers[2*i];
            priv->headers[i].value = headers[2*i+1];
        }
    }
    priv->header_strings = headers;
    priv->sig_cipher_type = sig_cipher_type;
    priv->sig_digest = g_bytes_ref(foil_digest_finish(digest));
    priv->sig = g_bytes_new(signature->val, signature->len);
    return msg;
}

void
foilmsg_free(
    FoilMsg* msg)
{
    if (G_LIKELY(msg)) {
        FoilMsgPriv* priv = foilmsg_priv_cast(msg);
        g_strfreev(priv->header_strings);
        g_free(priv->content_type);
        g_free(priv->headers);
        g_bytes_unref(msg->data);
        g_bytes_unref(msg->fingerprint);
        g_bytes_unref(priv->sig);
        g_bytes_unref(priv->sig_digest);
        g_slice_free(FoilMsgPriv, priv);
    }
}

const char*
foilmsg_get_value(
    const FoilMsg* msg,
    const char* name)
{
    if (G_LIKELY(msg) && G_LIKELY(name)) {
        guint i;
        for (i=0; i<msg->headers.count; i++) {
            if (!strcmp(msg->headers.header[i].name, name)) {
                return msg->headers.header[i].value;
            }
        }
    }
    return NULL;
}

/* SEQUENCE { tag INTEGER data OCTET STRING } */
static
gboolean
foilmsg_decode_tagged_data(
    FoilParsePos* pos,
    FoilMsgTaggedData* block)
{
    guint32 len;
    if (foil_asn1_parse_start_sequence(pos, &len)) {
        FoilParsePos seq;
        seq.ptr = pos->ptr;
        seq.end = pos->ptr + len;
        if (foil_asn1_parse_int32(&seq, &block->tag) &&
            foil_asn1_parse_octet_string(&seq, &block->data) &&
            seq.ptr == seq.end) {
            pos->ptr = seq.ptr;
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * EncryptedKey ::= SEQUENCE {
 *     fingerprint     TaggedData,
 *     encryptedKey    OCTET STRING
 * }
 *
 * EncryptedKeys ::= SEQUENCE {
 *     keyFormat       INTEGER
 *     keys            SEQUENCE OF EncryptedKey,
 * }
 */

static
void
foilmsg_free_encrypt_key(
    gpointer ptr)
{
    FoilMsgEncryptKey* key = ptr;
    g_slice_free1(sizeof(*key), key);
}

static
FoilMsgInfo*
foilmsg_parse_encrypted_keys(
    FoilParsePos* pos)
{
    FoilMsgInfo* msg = NULL;
    guint32 len;
    if (foil_asn1_parse_start_sequence(pos, &len)) {
        gint32 key_format;
        FoilParsePos seq;
        seq.ptr = pos->ptr;
        seq.end = pos->ptr + len;
        if (foil_asn1_parse_int32(&seq, &key_format)) {
            FoilMsgEncryptKey* key;
            GSList* keys = NULL;
            guint i, nkeys = 0;
            while (foil_asn1_parse_start_sequence(&seq, &len)) {
                FoilParsePos seq2;
                seq2.ptr = seq.ptr;
                seq2.end = seq.ptr + len;
                key = g_slice_new(FoilMsgEncryptKey);
                keys = g_slist_append(keys, key);
                if (foilmsg_decode_tagged_data(&seq2, &key->fingerprint) &&
                    foil_asn1_parse_octet_string(&seq2, &key->data)) {
                    seq.ptr = seq2.ptr;
                    nkeys++;
                    continue;
                }
                /* Broken data stream */
                g_slist_free_full(keys, foilmsg_free_encrypt_key);
                return NULL;
            }

            /* Must reach the end of the sequence */
            if (seq.ptr == seq.end) {
                pos->ptr = seq.ptr;
                msg = g_malloc0(sizeof(*msg) + nkeys*sizeof(*key));
                key = (FoilMsgEncryptKey*)(msg+1);
                msg->encrypt_keys = key;
                msg->encrypt_key_format = key_format;
                msg->num_encrypt_keys = nkeys;
                for (i=0; i<nkeys; i++) {
                    memcpy(key, keys->data, sizeof(*key));
                    foilmsg_free_encrypt_key(keys->data);
                    keys = g_slist_delete_link(keys, keys);
                    key++;
                }
            }

            g_slist_free_full(keys, foilmsg_free_encrypt_key);
        }
    }
    return msg;
}

void
foilmsg_info_free(
    FoilMsgInfo* info)
{
    /* The whole thing is allocated as a single memory block */
    g_free(info);
}

static
gboolean
foilmsg_decrypt_find_key(
    const FoilMsgInfo* msg,
    GBytes* fingerprint,
    FoilMsgTaggedData* key_block)
{
    int i;
    FoilBytes fp_bytes;
    foil_bytes_from_data(&fp_bytes, fingerprint);
    for (i=0; i<msg->num_encrypt_keys; i++) {
        const FoilMsgEncryptKey* key = msg->encrypt_keys + i;
        if (key->fingerprint.tag == FOILMSG_FINGERPRINT_FORMAT &&
            foil_bytes_equal(&key->fingerprint.data, &fp_bytes)) {
            key_block->tag = msg->encrypt_key_format;
            key_block->data = key->data;
            return TRUE;
        }
    }
    return FALSE;
}

static
gboolean
foilmsg_decrypt_init_signature(
    FoilMsgDecrypt* dec,
    FoilMsgTaggedData* sig)
{
    switch (sig->tag) {
    case FOILMSG_SIGNATURE_FORMAT_MD5_RSA:
        dec->sig_digest_type = FOIL_DIGEST_MD5;
        dec->sig_cipher_type = FOIL_CIPHER_RSA_DECRYPT;
        break;
    default:
        return FALSE;
    }
    dec->sig_data = sig->data;
    return TRUE;
}

static
gboolean
foilmsg_decrypt_init_cipher(
    FoilMsgDecrypt* dec,
    FoilPrivateKey* recipient,
    const FoilMsgTaggedData* enc_key,
    gint32 enc_data_tag)
{
    GType block_key_type = 0;
    GType block_cipher_type = 0;
    GType block_key_decrypt_type = FOIL_CIPHER_RSA_DECRYPT;

    /* Make sure that key and cipher types match each other */
    switch (enc_key->tag) {
    case FOILMSG_ENCRYPT_KEY_FORMAT_AES128:
        block_key_type = FOIL_KEY_AES128;
        break;
    case FOILMSG_ENCRYPT_KEY_FORMAT_AES192:
        block_key_type = FOIL_KEY_AES192;
        break;
    case FOILMSG_ENCRYPT_KEY_FORMAT_AES256:
        block_key_type = FOIL_KEY_AES256;
        break;
    default:
        GDEBUG("Unsupported key tag %d", enc_key->tag);
        break;
    }

    switch (enc_data_tag) {
    case FOILMSG_ENCRYPT_FORMAT_AES_CBC:
        block_cipher_type = FOIL_CIPHER_AES_CBC_DECRYPT;
        break;
    case FOILMSG_ENCRYPT_FORMAT_AES_CFB:
        block_cipher_type = FOIL_CIPHER_AES_CFB_DECRYPT;
        break;
    default:
        GDEBUG("Unsupported cipher tag %d", enc_data_tag);
        break;
    }

    /* Decrypt the key and initialize the cipher */
    if (block_key_type && block_cipher_type) {
        GBytes* key_data = foil_cipher_data(block_key_decrypt_type,
            FOIL_KEY(recipient), enc_key->data.val, enc_key->data.len);
        if (key_data) {
            FoilKey* key = foil_key_new_from_bytes(block_key_type, key_data);
            dec->cipher = foil_cipher_new(block_cipher_type, key);
            foil_key_unref(key);
            g_bytes_unref(key_data);
            if (dec->cipher) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

FoilMsgInfo*
foilmsg_parse(
    const FoilBytes* bytes)
{
    guint32 len;
    FoilParsePos pos;
    pos.ptr = bytes->val;
    pos.end = pos.ptr + bytes->len;
    if (foil_asn1_parse_start_sequence(&pos, &len)) {
        gint32 format;
        FoilMsgTaggedData fingerprint;
        pos.end = pos.ptr + len;

        /* formatVersion */
        if (!foil_asn1_parse_int32(&pos, &format)) {
            GDEBUG("Error parsing format version");
        } else if (format != FOILMSG_FORMAT_VERSION) {
            GDEBUG("Unsuported format %d", format);

        /* senderKey */
        } else if (!foilmsg_decode_tagged_data(&pos, &fingerprint)) {
            GDEBUG("Error parsing figerprint block");

        /* encryptedKey */
        } else {
            FoilMsgInfo* msg = foilmsg_parse_encrypted_keys(&pos);
            if (!msg) {
                GDEBUG("Error parsing encryption key");
                /* encryptedData */
            } else {
                if (!foilmsg_decode_tagged_data(&pos, &msg->encrypted)) {
                    GDEBUG("Error parsing encryption data block");
                    /* signature */
                } else if (!foilmsg_decode_tagged_data(&pos, &msg->signature)) {
                    GDEBUG("Error parsing signature block");
                } else {
                    msg->format = format;
                    msg->sender_fingerprint = fingerprint;
                    return msg;
                }
                foilmsg_info_free(msg);
            }
        }
    } else {
        GDEBUG("Garbage, sir!");
    }
    return NULL;
}

static
gboolean
foilmsg_decrypt_init(
    FoilMsgDecrypt* dec,
    FoilPrivateKey* recipient,
    const FoilBytes* bytes)
{
    FoilMsgInfo* msg = foilmsg_parse(bytes);
    gboolean ok = FALSE;
    memset(dec, 0, sizeof(*dec));
    if (msg) {
        const FoilMsgTaggedData* fp = &msg->sender_fingerprint;
        FoilMsgTaggedData enc_key;
        if (fp->tag != FOILMSG_FINGERPRINT_FORMAT) {
            GDEBUG("Unsuported fingerprint format %d", fp->tag);
        } else if (!foilmsg_decrypt_find_key(msg,
            foil_private_key_fingerprint(recipient), &enc_key)) {
            GDEBUG("Recipient's fingerprint is missing");
        } else if (!foilmsg_decrypt_init_signature(dec, &msg->signature)) {
            GDEBUG("Unsupported signature type %d", msg->signature.tag);
        } else if (!foilmsg_decrypt_init_cipher(dec, recipient, &enc_key,
            msg->encrypted.tag)) {
            GDEBUG("Error initializing decryption cipher");
        } else {
            dec->fingerprint_data = fp->data;
            dec->enc_data = msg->encrypted.data;
            ok = TRUE;
        }
        foilmsg_info_free(msg);
    }
    return ok;
}

static
void
foilmsg_decrypt_deinit(
    FoilMsgDecrypt* dec)
{
    foil_cipher_unref(dec->cipher);
}

/*
 * Header ::= SEQUENCE {
 *     name     IA5String
 *     value    IA5String
 * }
 */

static
char**
foilmsg_decrypt_read_headers(
    FoilInput* in,
    guint32 len)
{
    FoilInput* headers_in = foil_input_range_new(in, 0, len);
    GPtrArray* strings = g_ptr_array_new();
    guint32 header_len;
    while (foil_asn1_read_sequence_header(headers_in, &header_len) &&
           foil_input_has_available(headers_in, header_len)) {
        FoilInput* hdr_in = foil_input_range_new(headers_in, 0, header_len);
        char* name = foil_asn1_read_ia5_string(hdr_in, MAX_LEN, NULL);
        char* value = foil_asn1_read_ia5_string(hdr_in, MAX_LEN, NULL);
        if (name && value) {
            g_ptr_array_add(strings, name);
            g_ptr_array_add(strings, value);
        } else {
            g_free(name);
            g_free(value);
        }
        foil_input_skip(hdr_in, header_len - foil_input_bytes_read(hdr_in));
        foil_input_unref(hdr_in);
    }
    foil_input_skip(headers_in, len - foil_input_bytes_read(headers_in));
    foil_input_unref(headers_in);
    g_ptr_array_add(strings, NULL);
    return (char**)g_ptr_array_free(strings, FALSE);
}

/*
 * PlainData ::= SEQUENCE {
 *     format INTEGER
 *     contentType IA5String OPTIONAL,
 *     headers SEQUENCE OF Header OPTIONAL,
 *     data OCTET STRING
 * }
 */

static
FoilMsg*
foilmsg_decrypt_run(
    FoilMsgDecrypt* dec,
    FoilOutput* out)
{
    FoilMsg* msg = NULL;
    FoilDigest* digest = foil_digest_new(dec->sig_digest_type);
    FoilInput* enc_in = foil_input_mem_new_bytes(&dec->enc_data);
    FoilInput* dec_in = foil_input_cipher_new(dec->cipher, enc_in);
    FoilInput* digest_in = foil_input_digest_new(dec_in, digest);
    guint32 plain_data_len;
    if (foil_asn1_read_sequence_header(digest_in, &plain_data_len)) {
        FoilInput* range = foil_input_range_new(dec_in, 0, plain_data_len);
        FoilInput* in = foil_input_digest_new(range, digest);
        gint32 format;
        if (!foil_asn1_read_int32(in, &format)) {
            GDEBUG("Failed to read plain data format");
        } else if (format != FOILMSG_FORMAT_VERSION) {
            GDEBUG("Unexpected plain data format %u", format);
        } else {
            guint32 headers_len, data_len;
            char* content_type = foil_asn1_read_ia5_string(in, MAX_LEN, NULL);
            char** headers = NULL;
            if (foil_asn1_read_sequence_header(in, &headers_len)) {
                headers = foilmsg_decrypt_read_headers(in, headers_len);
            }
            if (foil_asn1_read_octet_string_header(in, &data_len)) {
                gssize copied = foil_input_copy(in, out, data_len);
                if (copied >= 0 && copied == (gssize)data_len) {
                    msg = foilmsg_alloc(content_type, headers, out, digest,
                        dec->sig_cipher_type, &dec->fingerprint_data,
                        &dec->sig_data);
                    /* foilmsg_alloc takes ownership of these */
                    content_type = NULL;
                    headers = NULL;
                }
            }
            g_free(content_type);
            g_strfreev(headers);
        }
        foil_input_unref(range);
        foil_input_unref(in);
    }
    foil_digest_unref(digest);
    foil_input_unref(digest_in);
    foil_input_unref(dec_in);
    foil_input_unref(enc_in);
    return msg;
}

FoilMsg*
foilmsg_decrypt(
    FoilPrivateKey* recipient,
    const FoilBytes* bytes,
    FoilOutput* out)
{
    FoilMsg* msg = NULL;
    if (G_LIKELY(recipient) && G_LIKELY(bytes)) {
        FoilMsgDecrypt dec;
        /* Writing to memory by default */
        out = out ? foil_output_ref(out) : foil_output_mem_new(NULL);
        if (foilmsg_decrypt_init(&dec, recipient, bytes)) {
            msg = foilmsg_decrypt_run(&dec, out);
            foilmsg_decrypt_deinit(&dec);
        }
        foil_output_unref(out);
    }
    return msg;
}

FoilMsg*
foilmsg_decrypt_file(
    FoilPrivateKey* recipient,
    const char* path,
    FoilOutput* out)
{
    FoilMsg* msg = NULL;
    if (G_LIKELY(recipient) && G_LIKELY(path)) {
        GError* error = NULL;
        GMappedFile* map = g_mapped_file_new(path, FALSE, &error);
        if (map) {
            FoilBytes bytes;
            bytes.val = (void*)g_mapped_file_get_contents(map);
            bytes.len = g_mapped_file_get_length(map);
            msg = foilmsg_decrypt(recipient, &bytes, out);
            g_mapped_file_unref(map);
        } else {
            GDEBUG("Failed to read %s: %s", path, GERRMSG(error));
            g_error_free(error);
        }
    }
    return msg;
}

FoilMsg*
foilmsg_decrypt_text(
    FoilPrivateKey* recipient,
    const char* message)
{
    if (G_LIKELY(recipient) && G_LIKELY(message)) {
        return foilmsg_decrypt_text_len(recipient, message, strlen(message));
    } else {
        return NULL;
    }
}

FoilMsg*
foilmsg_decrypt_text_len(
    FoilPrivateKey* recipient,
    const char* message,
    gsize length)
{
    if (G_LIKELY(recipient) && G_LIKELY(message)) {
        FoilBytes bytes;
        bytes.val = (const void*)message;
        bytes.len = length;
        return foilmsg_decrypt_text_bytes(recipient, &bytes, NULL);
    } else {
        return NULL;
    }
}

GBytes*
foilmsg_to_binary(
    const FoilBytes* data)
{
    GBytes* bytes = NULL;
    if (G_LIKELY(data)) {
        FoilParsePos pos;
        pos.ptr = data->val;
        pos.end = pos.ptr + data->len;
        foil_parse_skip_spaces(&pos);
        if (foil_parse_skip_bytes(&pos, &foilmsg_prefix)) {
            FoilInput* mem;
            FoilInput* base64;
            /* TODO: use temporary file for large amounts of input data */
            FoilOutput* out = foil_output_mem_new(NULL);
            mem = foil_input_mem_new_static(pos.ptr, pos.end - pos.ptr);
            base64 = foil_input_base64_new_full(mem,
                FOIL_INPUT_BASE64_IGNORE_SPACES |
                FOIL_INPUT_BASE64_VALIDATE);
            foil_input_unref(mem);
            if (foil_input_copy_all(base64, out, NULL)) {
                bytes = foil_output_free_to_bytes(out);
            } else {
                foil_output_unref(out);
            }
            foil_input_unref(base64);
        }
        if (!bytes) {
            bytes = g_bytes_new_static(data->val, data->len);
        }
    }
    return bytes;
}

FoilMsg*
foilmsg_decrypt_text_bytes(
    FoilPrivateKey* recipient,
    const FoilBytes* text,
    FoilOutput* out)
{
    FoilMsg* ret = NULL;
    if (G_LIKELY(recipient) && G_LIKELY(text)) {
        FoilParsePos pos;
        pos.ptr = text->val;
        pos.end = pos.ptr + text->len;
        foil_parse_skip_spaces(&pos);
        if (foil_parse_skip_bytes(&pos, &foilmsg_prefix)) {
            GBytes* decoded;
            decoded = foil_parse_base64(&pos, FOIL_INPUT_BASE64_IGNORE_SPACES);
            if (decoded) {
                FoilBytes bytes;
                foil_bytes_from_data(&bytes, decoded);
                ret = foilmsg_decrypt(recipient, &bytes, out);
                g_bytes_unref(decoded);
            }
        }
    }
    return ret;
}

gboolean
foilmsg_verify(
    const FoilMsg* msg,
    FoilKey* sender)
{
    if (G_LIKELY(msg) && G_LIKELY(sender)) {
        GBytes* fp = foil_key_fingerprint(sender);
        if (G_LIKELY(fp) && g_bytes_equal(fp, msg->fingerprint)) {
            FoilMsgPriv* priv = foilmsg_priv_cast(msg);
            gsize digest_size = g_bytes_get_size(priv->sig_digest);
            const void* digest_bytes = g_bytes_get_data(priv->sig_digest,
                &digest_size);
            GBytes* digest2 = foil_cipher_bytes(priv->sig_cipher_type,
                sender, priv->sig);
            if (digest2 && g_bytes_get_size(digest2) >= digest_size) {
                const void* digest2_bytes = g_bytes_get_data(digest2, NULL);
                gboolean ok = !memcmp(digest2_bytes, digest_bytes, digest_size);
                if (!ok) {
                    GDEBUG("Signature verification failed");
                }
                g_bytes_unref(digest2);
                return ok;
            } else {
                GDEBUG("Failed to decipher the signature");
            }
        } else {
            GDEBUG("Fingerprint check failed");
        }
    }
    return FALSE;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
