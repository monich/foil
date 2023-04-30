/*
 * Copyright (C) 2016-2023 Slava Monich <slava@monich.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
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
#include <foil_output.h>
#include <foil_random.h>
#include <foil_util.h>
#include <gutil_log.h>

/* Text prefix for BASE64 encoded foilmsg blob */
const FoilBytes foilmsg_prefix = {
    (const void*)FOILMSG_PREFIX,
    FOILMSG_PREFIX_LENGTH
};

/* SEQUENCE { tag INTEGER data OCTET STRING } */
static
gboolean
foilmsg_encode_tagged_bytes(
    FoilOutput* out,
    int tag,
    const FoilBytes* bytes)
{
    gsize tag_len;
    GBytes* tag_bytes = foil_asn1_encode_integer_value(tag);
    const void* tag_data = g_bytes_get_data(tag_bytes, &tag_len);
    gsize data_size = foil_asn1_block_length(bytes->len);
    gboolean ok = foil_asn1_encode_sequence_header(out, tag_len + data_size) &&
        foil_output_write_all(out, tag_data, tag_len) &&
        foil_asn1_encode_octet_string(out, bytes);
    g_bytes_unref(tag_bytes);
    return ok;
}

static
gboolean
foilmsg_encode_tagged_data(
    FoilOutput* out,
    int tag,
    GBytes* data)
{
    FoilBytes bytes;
    bytes.val = g_bytes_get_data(data, &bytes.len);
    return foilmsg_encode_tagged_bytes(out, tag, &bytes);
}

static
gboolean
foilmsg_encode_unref_tagged_data(
    FoilOutput* out,
    int tag,
    GBytes* data)
{
    gboolean ok;
    FoilBytes bytes;
    bytes.val = g_bytes_get_data(data, &bytes.len);
    ok = foilmsg_encode_tagged_bytes(out, tag, &bytes);
    g_bytes_unref(data);
    return ok;
}

/* Part 1 - format version */
static
void
foilmsg_encode_part1(
    FoilOutput* out)
{
    foil_asn1_encode_integer(out, FOILMSG_FORMAT_VERSION);
}

/* Part 2 - fingerprint  */
static
void
foilmsg_encode_part2(
    FoilOutput* out,
    FoilPrivateKey* sender)
{
    foilmsg_encode_tagged_data(out, FOILMSG_FINGERPRINT_FORMAT,
        foil_private_key_fingerprint(sender));
}

/* Part 3 - encrypted keys  */

/*
 * EncryptedKey ::= SEQUENCE {
 *     fingerprint     TaggedData,
 *     encryptedKey    OCTET STRING
 * }
 */
static
gsize
foilmsg_encode_encrypt_key(
    FoilOutput* out,
    FoilKey* pubkey,
    GBytes* key)
{
    gsize res = 0;
    /* encryptedKey */
    GBytes* enc = foil_cipher_bytes(FOIL_CIPHER_RSA_ENCRYPT, pubkey, key);
    if (enc) {
        GBytes* tmp_bytes;
        FoilBytes part[2];
        const FoilBytes* bytes[G_N_ELEMENTS(part)];
        FoilOutput* tmp = foil_output_mem_new(NULL);

        /* fingerprint  */
        foilmsg_encode_tagged_data(tmp, FOILMSG_FINGERPRINT_FORMAT,
            foil_key_fingerprint(pubkey));

        /* Pack fingerprint and encryptedKey into a SEQUENCE */
        foil_asn1_encode_octet_string_header(tmp, g_bytes_get_size(enc));
        tmp_bytes = foil_output_free_to_bytes(tmp);
        bytes[0] = foil_bytes_from_data(part + 0, tmp_bytes);
        bytes[1] = foil_bytes_from_data(part + 1, enc);
        res = foil_asn1_encode_sequence(out, bytes, G_N_ELEMENTS(bytes));

        g_bytes_unref(tmp_bytes);
        g_bytes_unref(enc);
    }
    return res;
}

/*
 * EncryptedKeys ::= SEQUENCE {
 *     keyFormat       INTEGER
 *     keys            SEQUENCE OF EncryptedKey,
 * }
 */
static
void
foilmsg_encode_part3(
    FoilOutput* out,
    GPtrArray* pubkeys,
    GBytes* key,
    int key_tag)
{
    guint i;
    FoilBytes part[2];
    const FoilBytes* bytes[G_N_ELEMENTS(part)];
    FoilOutput* keys_out = foil_output_mem_new(NULL);
    GBytes* keys;
    /* keyFormat */
    GBytes* key_format = foil_asn1_encode_integer_value(key_tag);
    /* keys */
    for (i=0; i<pubkeys->len; i++) {
        GVERIFY(foilmsg_encode_encrypt_key(keys_out, pubkeys->pdata[i], key));
    }
    keys = foil_output_free_to_bytes(keys_out);

    /* Pack keyFormat and keys into a SEQUENCE */
    bytes[0] = foil_bytes_from_data(part + 0, key_format);
    bytes[1] = foil_bytes_from_data(part + 1, keys);
    foil_asn1_encode_sequence(out, bytes, G_N_ELEMENTS(bytes));

    g_bytes_unref(key_format);
    g_bytes_unref(keys);
}

/* Part 4 - AES encrypted data */

/*
 * Header ::= SEQUENCE {
 *     name IA5String
 *     value IA5String
 * }
 * Headers ::= SEQUENCE OF Header
 */
static
void
foilmsg_encode_headers(
    FoilOutput* out,
    const FoilMsgHeaders* headers)
{
    if (headers) {
        gsize* size = g_new(gsize, headers->count);
        gsize total = 0;
        guint i;

        for (i=0; i<headers->count; i++) {
            total += foil_asn1_block_length(size[i] =
                foil_asn1_block_length(strlen(headers->header[i].name)) +
                foil_asn1_block_length(strlen(headers->header[i].value)));
        }

        foil_asn1_encode_sequence_header(out, total);
        for (i=0; i<headers->count; i++) {
            foil_asn1_encode_sequence_header(out, size[i]);
            foil_asn1_encode_ia5_string(out, headers->header[i].name);
            foil_asn1_encode_ia5_string(out, headers->header[i].value);
        }

        g_free(size);
    }
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
gboolean
foilmsg_encode_part4(
    FoilOutput* out,
    FoilCipher* cipher,
    int tag,
    const FoilBytes* data,
    const char* content_type,
    const FoilMsgHeaders* headers,
    FoilDigest* digest)
{
    gboolean ok;
    const int block_size = foil_cipher_output_block_size(cipher);
    FoilOutput* prefix_out = foil_output_mem_new(NULL);
    FoilOutput* out0 = foil_output_mem_new(NULL);
    FoilOutput* out1 = foil_output_mem_new(NULL);
    GBytes* prefix_bytes;
    GBytes* bytes0;
    GBytes* bytes1;
    FoilBytes prefix_data;
    FoilBytes blocks[3];
    gsize total_len = 0;

    /* First elements of plain text sequence (except the actual data) */
    foil_asn1_encode_integer(out1, FOILMSG_PLAIN_DATA_FORMAT);
    foil_asn1_encode_ia5_string(out1, content_type);
    foilmsg_encode_headers(out1, headers);
    foil_asn1_encode_octet_string_header(out1, data->len);

    /* No we can calculate the length of the whole plain data sequence */
    bytes1 = foil_output_free_to_bytes(out1);
    blocks[1].val = g_bytes_get_data(bytes1, &blocks[1].len);
    total_len += blocks[1].len;

    /* Encode the sequence header */
    foil_asn1_encode_sequence_header(out0, blocks[1].len + data->len);
    bytes0 = foil_output_free_to_bytes(out0);
    blocks[0].val = g_bytes_get_data(bytes0, &blocks[0].len);
    total_len += blocks[0].len;

    /*
     * We assume that the data size is preserved, just rounded up to
     * the nearest block boundary.
     */
    blocks[2] = *data;
    total_len += blocks[2].len;
    total_len = (total_len + block_size - 1) / block_size * block_size;
    GASSERT(block_size == foil_cipher_input_block_size(cipher));

    /* Add the cipher tag + octet string header */
    foil_asn1_encode_integer(prefix_out, tag);
    foil_asn1_encode_octet_string_header(prefix_out, total_len);
    prefix_bytes = foil_output_free_to_bytes(prefix_out);
    prefix_data.val = g_bytes_get_data(prefix_bytes, &prefix_data.len);
    total_len += prefix_data.len;

    /* Put the whole thing together and encrypt it. */
    ok = foil_asn1_encode_sequence_header(out, total_len) &&
        foil_output_write_all(out, prefix_data.val, prefix_data.len) &&
        foil_cipher_write_data_blocks(cipher, blocks, G_N_ELEMENTS(blocks),
            out, digest);

    g_bytes_unref(bytes0);
    g_bytes_unref(bytes1);
    g_bytes_unref(prefix_bytes);
    return ok;
}

/* Part 5 - Signature of part 4 */
static
void
foilmsg_encode_part5(
    FoilOutput* out,
    FoilPrivateKey* sender,
    GBytes* digest,
    int tag)
{
    gsize len;
    const void* data = g_bytes_get_data(digest, &len);
    GByteArray* buf = g_byte_array_sized_new(2*len);
    g_byte_array_set_size(buf, 2*len);
    memcpy(buf->data, data, len);
    foil_random(buf->data + len, len);
    foilmsg_encode_unref_tagged_data(out, tag, foil_cipher_data
        (FOIL_CIPHER_RSA_ENCRYPT, FOIL_KEY(sender), buf->data, buf->len));
    g_byte_array_free(buf, TRUE);
}

static
FoilKey*
foilmsg_encrypt_generate_key(
    const FoilMsgEncryptOptions* opt,
    int* tag)
{
    GType type = 0; /* Will remain zero if we miss all the cases */
    switch (opt ? opt->key_type : FOILMSG_KEY_TYPE_DEFAULT) {
    case FOILMSG_KEY_AES_128:
        type = FOIL_KEY_AES128;
        *tag = FOILMSG_ENCRYPT_KEY_FORMAT_AES128;
        break;
    case FOILMSG_KEY_AES_192:
        type = FOIL_KEY_AES192;
        *tag = FOILMSG_ENCRYPT_KEY_FORMAT_AES192;
        break;
    case FOILMSG_KEY_AES_256:
        type = FOIL_KEY_AES256;
        *tag = FOILMSG_ENCRYPT_KEY_FORMAT_AES256;
        break;
    }
    return foil_key_generate_new(type, FOIL_KEY_BITS_DEFAULT);
}

static
FoilCipher*
foilmsg_encrypt_cipher(
    const FoilMsgEncryptOptions* opt,
    FoilKey* key,
    int* tag)
{
    GType type = 0; /* Will remain zero if we miss all the cases */
    switch (opt ? opt->cipher : FOILMSG_CIPHER_DEFAULT) {
    case FOILMSG_CIPHER_AES_CBC:
        type = FOIL_CIPHER_AES_CBC_ENCRYPT;
        *tag = FOILMSG_ENCRYPT_FORMAT_AES_CBC;
        break;
    case FOILMSG_CIPHER_AES_CFB:
        type = FOIL_CIPHER_AES_CFB_ENCRYPT;
        *tag = FOILMSG_ENCRYPT_FORMAT_AES_CFB;
        break;
    case FOILMSG_CIPHER_AES_CTR:
        type = FOIL_CIPHER_AES_CTR_ENCRYPT;
        *tag = FOILMSG_ENCRYPT_FORMAT_AES_CTR;
        break;
    }
    return foil_cipher_new(type, key);
}

static
FoilDigest*
foilmsg_encrypt_signature_digest(
    const FoilMsgEncryptOptions* opt,
    int* tag)
{
    GType type = 0; /* Will remain zero if we miss all the cases */
    switch (opt ? opt->signature : FOILMSG_SIGNATURE_DEFAULT) {
    case FOILMSG_SIGNATURE_MD5_RSA:
        type = FOIL_DIGEST_MD5;
        *tag = FOILMSG_SIGNATURE_FORMAT_MD5_RSA;
        break;
    case FOILMSG_SIGNATURE_SHA1_RSA:
        type = FOIL_DIGEST_SHA1;
        *tag = FOILMSG_SIGNATURE_FORMAT_SHA1_RSA;
        break;
    case FOILMSG_SIGNATURE_SHA256_RSA:
        type = FOIL_DIGEST_SHA256;
        *tag = FOILMSG_SIGNATURE_FORMAT_SHA256_RSA;
        break;
    case FOILMSG_SIGNATURE_SHA512_RSA:
        type = FOIL_DIGEST_SHA512;
        *tag = FOILMSG_SIGNATURE_FORMAT_SHA512_RSA;
        break;
    }
    return foil_digest_new(type);
}

/* Initialize default options */
FoilMsgEncryptOptions*
foilmsg_encrypt_defaults(
    FoilMsgEncryptOptions* opt)
{
    if (opt) {
        opt->key_type = FOILMSG_KEY_TYPE_DEFAULT;
        opt->flags = 0;
        opt->cipher = FOILMSG_CIPHER_DEFAULT;
        opt->signature = FOILMSG_SIGNATURE_DEFAULT;
    }
    return opt;
}

/* Encrypt to the binary format */
gsize
foilmsg_encrypt(
    FoilOutput* out,
    const FoilBytes* data,
    const char* ctype,
    const FoilMsgHeaders* hdrs,
    FoilPrivateKey* sender,
    FoilKey* recipient,
    const FoilMsgEncryptOptions* opt,
    FoilOutput* part4)
{
    gboolean ok = FALSE;
    gsize prev_written = foil_output_bytes_written(out);
    gboolean for_self = opt && (opt->flags & FOILMSG_FLAG_ENCRYPT_FOR_SELF);
    int ktag = 0, ctag = 0, stag = 0;
    FoilKey* key = foilmsg_encrypt_generate_key(opt, &ktag);
    FoilCipher* cipher = foilmsg_encrypt_cipher(opt, key, &ctag);
    FoilDigest* md = foilmsg_encrypt_signature_digest(opt, &stag);
    if (G_LIKELY(cipher) && G_LIKELY(out) && G_LIKELY(data) && G_LIKELY(md) &&
        G_LIKELY(sender) && G_LIKELY(recipient || for_self)) {
        GBytes* key_bytes = foil_key_to_bytes(key);

        /* part4 could be large and may point to a temporary file */
        if (part4) {
            foil_output_ref(part4);
            foil_output_reset(part4);
        } else {
            part4 = foil_output_mem_new(NULL);
        }

        /* Part 4 - AES encrypted text */
        if (foilmsg_encode_part4(part4, cipher, ctag, data, ctype, hdrs, md)) {
            GBytes* bytes4 = foil_output_free_to_bytes(part4);
            if (bytes4) {
                gsize total = 0;
                GBytes* digest_bytes = foil_digest_finish(md);
                FoilOutput* part1 = foil_output_mem_new(NULL);
                FoilOutput* part2 = foil_output_mem_new(NULL);
                FoilOutput* part3 = foil_output_mem_new(NULL);
                FoilOutput* part5 = foil_output_mem_new(NULL);
                GPtrArray* pubkeys = g_ptr_array_new_full(2, g_object_unref);
                GBytes* bytes1;
                GBytes* bytes2;
                GBytes* bytes3;
                GBytes* bytes5;
                const void* data[5];
                gsize len[5];

                /* Collect public keys */
                if (recipient) {
                    g_ptr_array_add(pubkeys, foil_key_ref(recipient));
                }
                if (for_self) {
                    FoilKey* pub = foil_public_key_new_from_private(sender);
                    if (foil_key_equal(pub, recipient)) {
                        GDEBUG("Not adding duplicate sender's public key");
                        foil_key_unref(pub);
                    } else {
                        g_ptr_array_add(pubkeys, pub);
                    }
                }

                /* Part 1 - format version */
                foilmsg_encode_part1(part1);
                /* Part 2 - fingerprint */
                foilmsg_encode_part2(part2, sender);
                /* Part 3 - encrypted keys */
                foilmsg_encode_part3(part3, pubkeys, key_bytes, ktag);
                /* Part 5 - Signature of part 4 */
                foilmsg_encode_part5(part5, sender, digest_bytes, stag);

                bytes1 = foil_output_free_to_bytes(part1);
                bytes2 = foil_output_free_to_bytes(part2);
                bytes3 = foil_output_free_to_bytes(part3);
                bytes5 = foil_output_free_to_bytes(part5);

                data[0] = g_bytes_get_data(bytes1, len);
                data[1] = g_bytes_get_data(bytes2, len + 1);
                data[2] = g_bytes_get_data(bytes3, len + 2);
                data[3] = g_bytes_get_data(bytes4, len + 3);
                data[4] = g_bytes_get_data(bytes5, len + 4);

                /* Combine the whole thing into an ASN.1 sequence */
                total = len[0] + len[1] + len[2] + len[3] + len[4];
                ok = foil_asn1_encode_sequence_header(out, total) &&
                    foil_output_write_all(out, data[0], len[0]) &&
                    foil_output_write_all(out, data[1], len[1]) &&
                    foil_output_write_all(out, data[2], len[2]) &&
                    foil_output_write_all(out, data[3], len[3]) &&
                    foil_output_write_all(out, data[4], len[4]);

                g_bytes_unref(bytes1);
                g_bytes_unref(bytes2);
                g_bytes_unref(bytes3);
                g_bytes_unref(bytes4);
                g_bytes_unref(bytes5);
                g_ptr_array_free(pubkeys, TRUE);
            }
        }

        g_bytes_unref(key_bytes);
    }
    foil_cipher_unref(cipher);
    foil_digest_unref(md);
    foil_key_unref(key);
    return ok ? (foil_output_bytes_written(out) - prev_written) : 0;
}

GString*
foilmsg_encrypt_text(
    const char* text,
    FoilPrivateKey* from,
    FoilKey* to,
    int linebreaks,
    const FoilMsgEncryptOptions* opt)
{
    GString* result = NULL;
    GBytes* bytes = foilmsg_encrypt_text_to_bytes(text, from, to, opt);
    if (bytes) {
        FoilOutput* out64 = foil_output_base64_new_full(NULL, 0, linebreaks);
        if (foil_output_write_bytes_all(out64, bytes)) {
            GBytes* bytes64 = foil_output_free_to_bytes(out64);
            if (bytes64) {
                gsize len64;
                const char* base64 = g_bytes_get_data(bytes64, &len64);
                result = g_string_sized_new(foilmsg_prefix.len + 1 + len64);
                g_string_append_len(result, (const char*)foilmsg_prefix.val,
                    foilmsg_prefix.len);
                g_string_append_c(result, '\n');
                g_string_append_len(result, base64, len64);
                g_bytes_unref(bytes64);
            }
        } else {
            foil_output_unref(out64);
        }
        g_bytes_unref(bytes);
    }
    return result;
}

GBytes*
foilmsg_encrypt_text_to_bytes(
    const char* text,
    FoilPrivateKey* sender,
    FoilKey* recipient,
    const FoilMsgEncryptOptions* opt)
{
    FoilBytes bytes;
    return foilmsg_encrypt_to_bytes(foil_bytes_from_string(&bytes, text),
        NULL, NULL, sender, recipient, opt);
}

GBytes*
foilmsg_encrypt_to_bytes(
    const FoilBytes* data,
    const char* type,
    const FoilMsgHeaders* headers,
    FoilPrivateKey* from,
    FoilKey* to,
    const FoilMsgEncryptOptions* opt)
{
    FoilOutput* out = foil_output_mem_new(NULL);
    if (foilmsg_encrypt(out, data, type, headers, from, to, opt, NULL)) {
        return foil_output_free_to_bytes(out);
    } else {
        foil_output_unref(out);
        return NULL;
    }
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
