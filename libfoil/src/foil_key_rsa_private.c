/*
 * Copyright (C) 2016-2017 by Slava Monich
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

#include "foil_key_rsa_private.h"
#include "foil_key_rsa_public.h"
#include "foil_key_aes.h"
#include "foil_random.h"
#include "foil_cipher.h"
#include "foil_digest.h"
#include "foil_input.h"
#include "foil_output.h"
#include "foil_util_p.h"
#include "foil_asn1.h"

#include <gutil_strv.h>
#include <gutil_misc.h>

#include <ctype.h>

/* Logging */
#define GLOG_MODULE_NAME foil_log_key
#include "foil_log_p.h"

G_DEFINE_ABSTRACT_TYPE(FoilKeyRsaPrivate, foil_key_rsa_private,
        FOIL_TYPE_PRIVATE_KEY);
#define FOIL_KEY_RSA_PRIVATE_CAST_TO_KEY(obj) &((obj)->super.super)

#define FOIL_KEY_RSA_PRIVATE_CLEAR_BYTES(bytes) \
    memset((void*)((bytes)->val), 0, (bytes)->len);
#define FOIL_KEY_RSA_PRIVATE_HAS_PREFIX(data,len,prefix) (\
    (guint)(len) >= G_N_ELEMENTS(prefix) && \
    memcmp(data, prefix, G_N_ELEMENTS(prefix)) == 0)
#define FOIL_KEY_RSA_PRIVATE_HAS_TEXT_PREFIX(data,len,prefix) (\
    (guint)(len) >= G_N_ELEMENTS(prefix) && \
    memcmp(data, prefix, G_N_ELEMENTS(prefix)) == 0 &&  \
    isspace((data)[G_N_ELEMENTS(prefix)]))

#define FOIL_RSA_VERSION (0)
#define FOIL_PKCS5_SALT_LEN (8)
G_STATIC_ASSERT(FOIL_AES_BLOCK_SIZE >= FOIL_PKCS5_SALT_LEN);

static const guint8 rsa_private_key_prefix[] = {
    '-','-','-','-','-','B','E','G','I','N',' ','R','S','A',' ','P',
    'R','I','V','A','T','E',' ','K','E','Y','-','-','-','-','-'
};
static const guint8 rsa_private_key_suffix[] = {
    '-','-','-','-','-','E','N','D',' ','R','S','A',' ','P','R','I',
    'V','A','T','E',' ','K','E','Y','-','-','-','-','-'
};

static
inline
void
foil_key_rsa_private_get_public_data(
    FoilKeyRsaPrivate* self,
    FoilKeyRsaPublicData* pub_data)
{
    pub_data->e = self->data->e;
    pub_data->n = self->data->n;
}

static
FoilKeyRsaPrivateData*
foil_key_rsa_private_data_copy(
    const FoilKeyRsaPrivateData* data)
{
    const gsize total = FOIL_ALIGN(sizeof(*data)) +
            FOIL_ALIGN(data->n.len) + FOIL_ALIGN(data->e.len) +
            FOIL_ALIGN(data->d.len) + FOIL_ALIGN(data->p.len) +
            FOIL_ALIGN(data->q.len) + FOIL_ALIGN(data->dmp1.len) +
            FOIL_ALIGN(data->dmq1.len) + FOIL_ALIGN(data->iqmp.len);
    FoilKeyRsaPrivateData* copy = g_malloc(total);
    guint8* ptr = ((guint8*)copy) + FOIL_ALIGN(sizeof(*copy));
    ptr = foil_bytes_copy(&copy->n, &data->n, ptr);
    ptr = foil_bytes_copy(&copy->e, &data->e, ptr);
    ptr = foil_bytes_copy(&copy->d, &data->d, ptr);
    ptr = foil_bytes_copy(&copy->p, &data->p, ptr);
    ptr = foil_bytes_copy(&copy->q, &data->q, ptr);
    ptr = foil_bytes_copy(&copy->dmp1, &data->dmp1, ptr);
    ptr = foil_bytes_copy(&copy->dmq1, &data->dmq1, ptr);
    ptr = foil_bytes_copy(&copy->iqmp, &data->iqmp, ptr);
    GASSERT((gsize)(ptr - ((guint8*)copy)) == total);
    return copy;
}

static
gboolean
foil_key_rsa_private_data_equal(
    const FoilKeyRsaPrivateData* data1,
    const FoilKeyRsaPrivateData* data2)
{
    if (data1 == data2) {
        return TRUE;
    } else if (!data1 || !data2) {
        return FALSE;
    } else {
        return foil_bytes_equal(&data1->n, &data2->n) &&
            foil_bytes_equal(&data1->e, &data2->e) &&
            foil_bytes_equal(&data1->d, &data2->d) &&
            foil_bytes_equal(&data1->p, &data2->p) &&
            foil_bytes_equal(&data1->q, &data2->q) &&
            foil_bytes_equal(&data1->dmp1, &data2->dmp1) &&
            foil_bytes_equal(&data1->dmq1, &data2->dmq1) &&
            foil_bytes_equal(&data1->iqmp, &data2->iqmp);
    }
}

static
GBytes*
foil_key_rsa_private_data_to_bytes(
    const FoilKeyRsaPrivateData* key_data)
{
    GBytes* bytes = NULL;
    if (key_data) {
        GByteArray* seq;
        GByteArray* buf = g_byte_array_sized_new(19 +
            key_data->n.len + key_data->e.len + key_data->d.len +
            key_data->p.len + key_data->q.len + key_data->dmp1.len +
            key_data->dmq1.len + key_data->iqmp.len);
        FoilOutput* seq_out;
        FoilOutput* data_out = foil_output_mem_new(buf);
        foil_asn1_encode_integer(data_out, FOIL_RSA_VERSION);
        foil_asn1_encode_integer_bytes(data_out, &key_data->n);
        foil_asn1_encode_integer_bytes(data_out, &key_data->e);
        foil_asn1_encode_integer_bytes(data_out, &key_data->d);
        foil_asn1_encode_integer_bytes(data_out, &key_data->p);
        foil_asn1_encode_integer_bytes(data_out, &key_data->q);
        foil_asn1_encode_integer_bytes(data_out, &key_data->dmp1);
        foil_asn1_encode_integer_bytes(data_out, &key_data->dmq1);
        foil_asn1_encode_integer_bytes(data_out, &key_data->iqmp);
        seq = g_byte_array_sized_new(foil_asn1_block_length(buf->len));
        seq_out = foil_output_mem_new(seq);
        foil_asn1_encode_sequence_data(seq_out, buf->data, buf->len);
        bytes = foil_output_free_to_bytes(seq_out);
        foil_output_unref(data_out);
        g_byte_array_unref(seq);
        g_byte_array_unref(buf);
    }
    return bytes;
}

static
GBytes*
foil_key_rsa_private_to_bytes(
    FoilKey* key)
{
    FoilKeyRsaPrivate* self = FOIL_KEY_RSA_PRIVATE_(key);
    return foil_key_rsa_private_data_to_bytes(self->data);
}

/**
 * https://www.ietf.org/rfc/rfc3447.txt (Appendix A)
 *
 * RSAPrivateKey ::= SEQUENCE {
 *     version           Version,
 *     modulus           INTEGER,  -- n
 *     publicExponent    INTEGER,  -- e
 *     privateExponent   INTEGER,  -- d
 *     prime1            INTEGER,  -- p
 *     prime2            INTEGER,  -- q
 *     exponent1         INTEGER,  -- d mod (p-1)
 *     exponent2         INTEGER,  -- d mod (q-1)
 *     coefficient       INTEGER,  -- (inverse of q) mod p
 *     otherPrimeInfos   OtherPrimeInfos OPTIONAL
 * }
 */
static
gboolean
foil_key_rsa_private_parse_asn1(
    FoilKeyRsaPrivate* self,
    const guint8* data,
    gsize size)
{
    guint32 len;
    FoilParsePos pos;
    pos.ptr = data;
    pos.end = data + size;
    if (foil_asn1_parse_start_sequence(&pos, &len)) {
        gint32 version;
        FoilKeyRsaPrivateData key_data;
        pos.end = pos.ptr + len;
        if (foil_asn1_parse_int32(&pos, &version) &&
            version == FOIL_RSA_VERSION &&
            foil_asn1_parse_integer_bytes(&pos, &key_data.n) &&
            foil_asn1_parse_integer_bytes(&pos, &key_data.e) &&
            foil_asn1_parse_integer_bytes(&pos, &key_data.d) &&
            foil_asn1_parse_integer_bytes(&pos, &key_data.p) &&
            foil_asn1_parse_integer_bytes(&pos, &key_data.q) &&
            foil_asn1_parse_integer_bytes(&pos, &key_data.dmp1) &&
            foil_asn1_parse_integer_bytes(&pos, &key_data.dmq1) &&
            foil_asn1_parse_integer_bytes(&pos, &key_data.iqmp) &&
            pos.ptr == pos.end) {
            g_free(self->data);
            self->data = foil_key_rsa_private_data_copy(&key_data);
            FOIL_KEY_RSA_PRIVATE_GET_CLASS(self)->fn_apply(self);
            return TRUE;
        }
    }
    return FALSE;
}

/* This does kind of like what EVP_BytesToKey does with count=1 */
static
GBytes*
foil_key_rsa_private_pass_key(
     const char* pass,
     const void* iv,
     guint bits)
{
    const guint key_size = bits/8;
    const guint total = key_size + FOIL_AES_BLOCK_SIZE;
    gsize pass_len = pass ? strlen(pass) : 0;
    guint8* data = g_malloc(total);
    GBytes* last_md = NULL;
    guint remain = key_size;
    guint8* ptr = data;

    do {
        gsize md_size, n;
        const void* md_bytes;
        FoilDigest* md = foil_digest_new_md5();
        if (last_md) {
            foil_digest_update_bytes(md, last_md);
            g_bytes_unref(last_md);
        }
        foil_digest_update(md, pass, pass_len);
        foil_digest_update(md, iv, FOIL_PKCS5_SALT_LEN);
        last_md = foil_digest_free_to_bytes(md);
        md_bytes = g_bytes_get_data(last_md, &md_size);
        n = MIN(remain, md_size);
        memcpy(ptr, md_bytes, n);
        ptr += n;
        remain -= n;
    } while (remain > 0);

    g_bytes_unref(last_md);
    memcpy(ptr, iv, FOIL_AES_BLOCK_SIZE);
    return g_bytes_new_take(data, total);
}

static
GBytes*
foil_key_rsa_private_decrypt(
    GHashTable* headers,
    const guint8* data,
    gsize size,
    const char* pass,
    gboolean* was_decrypted,
    GError** error)
{
    /*
     * Proc-Type and DEK-Info header tags are described in RFC 1421:
     *
     * https://www.ietf.org/rfc/rfc1421.txt
     */
    GBytes* decrypted = NULL;
    const char* proc_type = g_hash_table_lookup(headers, "Proc-Type");
    const char* dek_info = g_hash_table_lookup(headers, "DEK-Info");
    *was_decrypted = FALSE;
    if (proc_type && dek_info) {

        /* Proc-Type: 4,ENCRYPTED */
        GStrV* proc = gutil_strv_strip(g_strsplit(proc_type, ",", 0));
        if (gutil_strv_length(proc) >= 2 && !strcmp(proc[0], "4") &&
            gutil_strv_contains(proc, "ENCRYPTED")) {

            /* DEK-Info: alg,params... */
            GStrV* dek = gutil_strv_strip(g_strsplit(dek_info, ",", 0));
            if (gutil_strv_length(dek) >= 2) {
                const char* alg = dek[0];
                GType cipher = (GType)0;
                FoilKey* key = NULL;

                /* Choose algorithm and parse the get the key */
                if (g_str_has_prefix(alg, "AES-")) {
                    /* Check the IV size */
                    const char* hiv = dek[1];
                    const gsize hiv_len = strlen(hiv);
                    if (hiv_len == FOIL_AES_BLOCK_SIZE*2) {
                        guint bits = 0;
                        GType key_type = (GType)0;
                        guint8 iv[FOIL_AES_BLOCK_SIZE];
                        /* Figure out key size */
                        if (!strcmp(alg, "AES-256-CBC")) {
                            bits = 256;
                            key_type = FOIL_KEY_AES256;
                            cipher = FOIL_CIPHER_AES_CBC_DECRYPT;
                        } else if (!strcmp(alg, "AES-192-CBC")) {
                            bits = 192;
                            key_type = FOIL_KEY_AES192;
                            cipher = FOIL_CIPHER_AES_CBC_DECRYPT;
                        } else if (!strcmp(alg, "AES-128-CBC")) {
                            bits = 128;
                            key_type = FOIL_KEY_AES128;
                            cipher = FOIL_CIPHER_AES_CBC_DECRYPT;
                        }

                        /* Decode IV (16 bytes) */
                        if (bits && gutil_hex2bin(hiv, hiv_len, iv)) {
                            GBytes* b;
                            b = foil_key_rsa_private_pass_key(pass, iv, bits);
                            key = foil_key_new_from_bytes_full(key_type, b,
                                NULL, error);
                            g_bytes_unref(b);
                        }
                    }
                }

                if (key) {
                    decrypted = foil_cipher_data(cipher, key, data, size);
                    *was_decrypted = (decrypted != NULL);
                    foil_key_unref(key);
                } else if (error && !*error) {
                    if (cipher) {
                        *error = g_error_new(FOIL_ERROR,
                             FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT,
                             "RSA private key decryption %s failed", alg);
                    } else {
                        *error = g_error_new(FOIL_ERROR,
                             FOIL_ERROR_KEY_UNKNOWN_ENCRYPTION,
                             "Unsupported RSA private key encryption %s", alg);
                    }
                }
            } else if (error) {
                *error = g_error_new_literal(FOIL_ERROR,
                    FOIL_ERROR_KEY_UNKNOWN_ENCRYPTION,
                    "Unrecognized RSA private key encryption format");
            }
            g_strfreev(dek);
        }
        g_strfreev(proc);
    }
    return decrypted;
}

static
gboolean
foil_key_rsa_private_parse_text(
    FoilKeyRsaPrivate* self,
    const guint8* data,
    gsize size,
    const char* pass,
    GError** error)
{
    gboolean ok = FALSE;
    const gsize min_size = G_N_ELEMENTS(rsa_private_key_prefix) +
        G_N_ELEMENTS(rsa_private_key_suffix);
    if (size > min_size && FOIL_KEY_RSA_PRIVATE_HAS_TEXT_PREFIX(data, size,
        rsa_private_key_prefix)) {
        GBytes* decoded;
        FoilParsePos pos;
        GHashTable* headers;

        /* Parse the header tags */
        pos.ptr = data + G_N_ELEMENTS(rsa_private_key_prefix) + 1;
        pos.end = data + size;
        headers = foil_parse_headers(&pos, NULL);

        /* Collect BASE64 encoded data */
        decoded = foil_parse_base64(&pos, FOIL_INPUT_BASE64_IGNORE_SPACES);
        if (decoded) {
            if (FOIL_KEY_RSA_PRIVATE_HAS_PREFIX(pos.ptr,pos.end - pos.ptr,
                rsa_private_key_suffix)) {
                pos.ptr += G_N_ELEMENTS(rsa_private_key_suffix);
                foil_parse_skip_spaces(&pos);
                if (pos.ptr == pos.end) {
                    gsize len;
                    const void* bin = g_bytes_get_data(decoded, &len);
                    GBytes* decrypt = NULL;
                    gboolean was_decrypted = FALSE;
                    if (headers) {
                        /* The key may be encrypted */
                        decrypt = foil_key_rsa_private_decrypt(headers,
                            bin, len, pass, &was_decrypted, error);
                    }
                    if (decrypt) {
                        gsize len1;
                        const void* asn1 = g_bytes_get_data(decrypt, &len1);
                        ok = foil_key_rsa_private_parse_asn1(self, asn1, len1);
                        g_bytes_unref(decrypt);
                        if (was_decrypted) {
                            g_propagate_error(error, g_error_new_literal(
                                FOIL_ERROR, (pass && pass[0]) ?
                                FOIL_ERROR_KEY_DECRYPTION_FAILED :
                                FOIL_ERROR_KEY_ENCRYPTED,
                               "Failed to decrypt RSA private key"));
                        }
                    } else if (!error || !*error) {
                        ok = foil_key_rsa_private_parse_asn1(self, bin, len);
                    }
                }
            }
            g_bytes_unref(decoded);
        }

        if (headers) {
            g_hash_table_unref(headers);
        }
    }
    return ok;
}

static
gboolean
foil_key_rsa_private_parse_bytes(
    FoilKey* key,
    const void* data,
    gsize len,
    GHashTable* param,
    GError** error)
{
    FoilKeyRsaPrivate* self = FOIL_KEY_RSA_PRIVATE_(key);
    const char* pass = NULL;
    if (param) {
        /* Extract the passphrase */
        GVariant* var = g_hash_table_lookup(param, FOIL_KEY_PARAM_PASSPHRASE);
        if (g_variant_is_of_type(var, G_VARIANT_TYPE_STRING)) {
            pass = g_variant_get_string(var, NULL);
        }
    }
    if (foil_key_rsa_private_parse_text(self, data, len, pass, error) ||
        foil_key_rsa_private_parse_asn1(self, data, len)) {
        g_clear_error(error);
        return TRUE;
    } else {
        if (error && !*error) {
            *error = g_error_new_literal(FOIL_ERROR,
                FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT,
                "Unrecognized RSA private key format");
        }
        return FALSE;
    }
}

static
gboolean
foil_key_rsa_private_export_default(
    FoilKeyRsaPrivate* self,
    FoilOutput* out,
    const char* comment,
    const char* pass,
    GError** error)
{
    const char eol = '\n';
    gboolean ok = foil_output_write_all(out, rsa_private_key_prefix,
        sizeof(rsa_private_key_prefix)) && foil_output_write_all(out, &eol, 1);
    if (ok && comment) {
        char* header = foil_format_header("Comment", comment);
        if (header) {
            ok = foil_output_write_all(out, header, strlen(header)) &&
                foil_output_write_all(out, &eol, 1);
            g_free(header);
        }
    }
    if (ok) {
        GBytes* bytes = NULL;
        if (pass && pass[0]) {
            /* Encrypt the key */
            static const char tags[] = "Proc-Type: 4,ENCRYPTED\n"
               "DEK-Info: AES-256-CBC,";
            const guint bits = 256;
            GType key_type = FOIL_KEY_AES256;
            GType cipher = FOIL_CIPHER_AES_CBC_ENCRYPT;
            guint8 iv[FOIL_AES_BLOCK_SIZE];
            if (foil_random_generate(FOIL_RANDOM_DEFAULT, iv, sizeof(iv))) {
                char hiv[2*sizeof(iv)];
                guint i;
                for (i=0; i<sizeof(iv); i++) {
                    static const char x[] = "0123456789ABCDEF";
                    hiv[2*i] = x[iv[i] >> 4];
                    hiv[2*i+1] = x[iv[i] & 0xf];
                }
                ok = foil_output_write_all(out, tags, sizeof(tags) - 1) &&
                    foil_output_write_all(out, hiv, sizeof(hiv)) &&
                    foil_output_write_all(out, &eol, 1) &&
                    foil_output_write_all(out, &eol, 1);
                if (ok) {
                    GBytes* b = foil_key_rsa_private_pass_key(pass, iv, bits);
                    FoilKey* key = foil_key_new_from_bytes(key_type, b);
                    g_bytes_unref(b);
                    if (key) {
                        b = foil_key_rsa_private_data_to_bytes(self->data);
                        bytes = foil_cipher_bytes(cipher, key, b);
                        g_bytes_unref(b);
                        foil_key_unref(key);
                    }
                }
            } else if (error) {
                g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
                    FOIL_ERROR_UNSPECIFIED, "Key encryption error"));
            }
        } else {
            /* No encryption */
            bytes = foil_key_rsa_private_data_to_bytes(self->data);
        }
        if (bytes) {
            FoilOutput* base64 = foil_output_base64_new_full(out, 0, 64);
            ok = foil_output_write_bytes_all(base64, bytes) &&
                foil_output_flush(base64) &&
                foil_output_write_all(out, rsa_private_key_suffix,
                sizeof(rsa_private_key_suffix)) &&
                foil_output_write_all(out, &eol, 1);
            foil_output_unref(base64);
            g_bytes_unref(bytes);
        }
    }
    if (!ok && error && !*error) {
        g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_KEY_WRITE, "Output error"));
    }
    return ok;
}

static
gboolean
foil_key_rsa_private_export(
    FoilKey* key,
    FoilOutput* out,
    FoilKeyExportFormat format,
    GHashTable* param,
    GError** error)
{
    FoilKeyRsaPrivate* self = FOIL_KEY_RSA_PRIVATE_(key);
    gboolean ok = FALSE;
    if (self->data) {
        const char* comment = NULL;
        const char* passphrase = NULL;
        if (param) {
            GVariant* var = g_hash_table_lookup(param, FOIL_KEY_PARAM_COMMENT);
            if (var && g_variant_is_of_type(var, G_VARIANT_TYPE_STRING)) {
                comment = g_variant_get_string(var, NULL);
            }
            var = g_hash_table_lookup(param, FOIL_KEY_PARAM_PASSPHRASE);
            if (var && g_variant_is_of_type(var, G_VARIANT_TYPE_STRING)) {
                passphrase = g_variant_get_string(var, NULL);
            }
        }
        switch (format) {
        case FOIL_KEY_EXPORT_FORMAT_DEFAULT:
            ok = foil_key_rsa_private_export_default(self, out, comment,
                passphrase, error);
            break;
        default:
            if (error) {
                g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
                    FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT,
                    "Unsupported export format"));
            }
            break;
        }
    } else if (error) {
        g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_UNSPECIFIED, "Uninitialized private key"));
    }
    return ok;
}

static
gboolean
foil_key_rsa_private_equal(
    FoilKey* key1,
    FoilKey* key2)
{
    GASSERT(FOIL_IS_KEY_RSA_PRIVATE(key1));
    if (FOIL_IS_KEY_RSA_PRIVATE(key2)) {
        FoilKeyRsaPrivate* rsa1 = FOIL_KEY_RSA_PRIVATE_(key1);
        FoilKeyRsaPrivate* rsa2 = FOIL_KEY_RSA_PRIVATE_(key2);
        return foil_key_rsa_private_data_equal(rsa1->data, rsa2->data);
    }
    return FALSE;
}

int
foil_key_rsa_private_num_bits(
    FoilKeyRsaPrivate* self)
{
    if (G_LIKELY(self)) {
        return FOIL_KEY_RSA_PRIVATE_GET_CLASS(self)->fn_num_bits(self);
    }
    return 0;
}

static
FoilKey*
foil_key_rsa_private_create_public_key(
    FoilPrivateKey* key)
{
    FoilKey* public_key = NULL;
    FoilKeyRsaPrivate* self = FOIL_KEY_RSA_PRIVATE_(key);
    FoilPrivateKeyClass* private_class = FOIL_PRIVATE_KEY_GET_CLASS(self);
    if (private_class->fn_get_public_type && self->data) {
        GType public_type = private_class->fn_get_public_type();
        FoilKeyRsaPublic* rsa_public = g_object_new(public_type, NULL);
        GASSERT(FOIL_IS_RSA_PUBLIC_KEY(rsa_public));
        if (rsa_public) {
            FoilKeyRsaPublicData pub_data;
            foil_key_rsa_private_get_public_data(self, &pub_data);
            foil_key_rsa_public_set_data(rsa_public, &pub_data);
            public_key = FOIL_KEY(rsa_public);
        }
    }
    return public_key;
}

static
void
foil_key_rsa_private_apply(
    FoilKeyRsaPrivate* self)
{
}

static
GBytes*
foil_key_rsa_private_fingerprint(
    FoilKey* key)
{
    FoilKeyRsaPrivate* self = FOIL_KEY_RSA_PRIVATE_(key);
    FoilKeyRsaPublicData pub_data;
    foil_key_rsa_private_get_public_data(self, &pub_data);
    return foil_key_rsa_public_data_fingerprint(&pub_data);
}

static
void
foil_key_rsa_private_finalize(
    GObject* object)
{
    FoilKeyRsaPrivate* self = FOIL_KEY_RSA_PRIVATE_(object);
    FoilKeyRsaPrivateData* data = self->data;
    if (data) {
        FOIL_KEY_RSA_PRIVATE_CLEAR_BYTES(&data->d);
        FOIL_KEY_RSA_PRIVATE_CLEAR_BYTES(&data->p);
        FOIL_KEY_RSA_PRIVATE_CLEAR_BYTES(&data->q);
        FOIL_KEY_RSA_PRIVATE_CLEAR_BYTES(&data->dmp1);
        FOIL_KEY_RSA_PRIVATE_CLEAR_BYTES(&data->dmq1);
        FOIL_KEY_RSA_PRIVATE_CLEAR_BYTES(&data->iqmp);
        g_free(self->data);
    }
    G_OBJECT_CLASS(foil_key_rsa_private_parent_class)->finalize(object);
}

static
void
foil_key_rsa_private_init(
    FoilKeyRsaPrivate* key)
{
}

static
void
foil_key_rsa_private_class_init(
    FoilKeyRsaPrivateClass* klass)
{
    FoilKeyClass* key_class = FOIL_KEY_CLASS(klass);
    FoilPrivateKeyClass* private_key_class = FOIL_PRIVATE_KEY_CLASS(klass);
    key_class->fn_equal = foil_key_rsa_private_equal;
    key_class->fn_parse_bytes = foil_key_rsa_private_parse_bytes;
    key_class->fn_to_bytes = foil_key_rsa_private_to_bytes;
    key_class->fn_export = foil_key_rsa_private_export;
    key_class->fn_fingerprint = foil_key_rsa_private_fingerprint;
    private_key_class->create_public = foil_key_rsa_private_create_public_key;
    klass->fn_apply = foil_key_rsa_private_apply;
    G_OBJECT_CLASS(klass)->finalize = foil_key_rsa_private_finalize;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
