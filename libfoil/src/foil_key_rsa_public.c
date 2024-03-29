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

#include "foil_key_rsa_public.h"
#include "foil_digest.h"
#include "foil_output.h"
#include "foil_input.h"
#include "foil_asn1_p.h"
#include "foil_pool.h"
#include "foil_util_p.h"
#include "foil_oid.h"

#include <ctype.h>

/* Logging */
#define GLOG_MODULE_NAME foil_log_key
#include "foil_log_p.h"

G_DEFINE_TYPE(FoilKeyRsaPublic, foil_key_rsa_public, FOIL_TYPE_KEY);

static const guint8 RSA_PUBLIC_KEY_AID[] = {
    ASN1_CLASS_STRUCTURED | ASN1_TAG_SEQUENCE,
    ASN1_OID_RSA_LENGTH + 4,
    ASN1_TAG_OBJECT_ID,
    ASN1_OID_RSA_LENGTH,
    ASN1_OID_RSA_BYTES,
    ASN1_TAG_NULL, 0x00
};

#define FOIL_KEY_RSA_PUBLIC_HAS_PREFIX(data,len,prefix) ( \
    (guint)(len) >= G_N_ELEMENTS(prefix) && \
    memcmp(data, prefix, G_N_ELEMENTS(prefix)) == 0)
#define foil_key_rsa_public_write_all(out, data) \
    foil_output_write_all(out, (data)->val, (data)->len)

/* First 84 bits of binary ssh-rsa prefix, BASE-64 encoded */
static const guint8 rsa_public_base64_prefix[] = {
    'A','A','A','A','B','3','N','z','a','C','1','y','c','2'
};
/* Text formats */
static const guint8 ssh_rsa_text_prefix_data[] = {
    's','s','h','-','r','s','a'
};
static const guint8 rsa_public_rfc4716_prefix_data[] = {
    '-','-','-','-',' ','B','E','G','I','N',' ','S','S','H','2',' ',
    'P','U','B','L','I','C',' ','K','E','Y',' ','-','-','-','-'
};
static const guint8 rsa_public_rfc4716_suffix_data[] = {
    '-','-','-','-',' ','E','N','D',' ','S','S','H','2',' ','P','U',
    'B','L','I','C',' ','K','E','Y',' ','-','-','-','-'
};
static const guint8 rsa_public_pkcs8_prefix_data[] = {
    '-','-','-','-','-','B','E','G','I','N',' ','P','U','B','L','I',
    'C',' ','K','E','Y','-','-','-','-','-'
};
static const guint8 rsa_public_pkcs8_suffix_data[] = {
    '-','-','-','-','-','E','N','D',' ','P','U','B','L','I','C',' ',
    'K','E','Y','-','-','-','-','-'
};
static const FoilBytes ssh_rsa_text_prefix = {
    FOIL_ARRAY_AND_SIZE(ssh_rsa_text_prefix_data)
};
static const FoilBytes rsa_public_rfc4716_prefix = {
    FOIL_ARRAY_AND_SIZE(rsa_public_rfc4716_prefix_data)
};
static const FoilBytes rsa_public_rfc4716_suffix = {
    FOIL_ARRAY_AND_SIZE(rsa_public_rfc4716_suffix_data)
};
static const FoilBytes rsa_public_pkcs8_prefix = {
    FOIL_ARRAY_AND_SIZE(rsa_public_pkcs8_prefix_data)
};
static const FoilBytes rsa_public_pkcs8_suffix = {
    FOIL_ARRAY_AND_SIZE(rsa_public_pkcs8_suffix_data)
};

static
FoilKeyRsaPublicData*
foil_key_rsa_public_data_copy(
    const FoilKeyRsaPublicData* data)
{
    /* Argument is never NULL */
    const gsize total = FOIL_ALIGN(sizeof(*data)) +
        FOIL_ALIGN(data->n.len) + FOIL_ALIGN(data->e.len);
    FoilKeyRsaPublicData* copy = g_malloc(total);
    guint8* ptr = ((guint8*)copy) + FOIL_ALIGN(sizeof(*copy));
    ptr = foil_bytes_copy(&copy->n, &data->n, ptr);
    ptr = foil_bytes_copy(&copy->e, &data->e, ptr);
    GASSERT((ptr - ((guint8*)copy)) + total);
    return copy;
}

static
gboolean
foil_key_rsa_public_data_equal(
    const FoilKeyRsaPublicData* data1,
    const FoilKeyRsaPublicData* data2)
{
    if (data1 == data2) {
        return TRUE;
    } else if (!data1 || !data2) {
        return FALSE;
    } else {
        return foil_bytes_equal(&data1->n, &data2->n) &&
            foil_bytes_equal(&data1->e, &data2->e);
    }
}

void
foil_key_rsa_public_set_data(
    FoilKeyRsaPublic* self,
    const FoilKeyRsaPublicData* key_data)
{
    GASSERT(!self->data);
    self->data = foil_key_rsa_public_data_copy(key_data);
}

gboolean
foil_key_rsa_public_data_write_ssh_rsa(
    FoilOutput* out,
    const FoilKeyRsaPublicData* data)
{
    /*
     * string    "ssh-rsa"
     * mpint     e
     * mpint     n
     */
    return foil_key_rsa_write_n_bytes(out, &foil_ssh_rsa_mark) &&
        foil_key_rsa_write_n_bytes(out, &data->e) &&
        foil_key_rsa_write_n_bytes(out, &data->n);
}

GBytes*
foil_key_rsa_public_data_ssh_rsa_bytes(
    const FoilKeyRsaPublicData* data)
{
    GBytes* bytes = NULL;
    if (data) {
        GByteArray* buf = g_byte_array_sized_new(12 + foil_ssh_rsa_mark.len +
            data->e.len + data->n.len);
        FoilOutput* out = foil_output_mem_new(buf);
        foil_key_rsa_public_data_write_ssh_rsa(out, data);
        bytes = foil_output_free_to_bytes(out);
        g_byte_array_unref(buf);
    }
    return bytes;
}

gboolean
foil_key_rsa_public_parse_ssh_rsa_binary(
    FoilKeyRsaPublicData* key,
    const FoilBytes* data)
{
    /*
     * string    "ssh-rsa"
     * mpint     e
     * mpint     n
     */
    GUtilRange pos;
    FoilBytes mark;
    foil_parse_init_data(&pos, data);
    return foil_key_rsa_parse_n_bytes(&pos, &mark) &&
        foil_bytes_equal(&mark, &foil_ssh_rsa_mark) &&
        foil_key_rsa_parse_n_bytes(&pos, &key->e) &&
        foil_key_rsa_parse_n_bytes(&pos, &key->n) &&
        pos.ptr == pos.end;
}

static
gboolean
foil_key_rsa_public_parse_ssh_rsa_text(
    FoilKeyRsaPublicData* key,
    const FoilBytes* data,
    FoilPool* pool)
{
    GUtilRange pos;
    gboolean ok = FALSE;
    foil_parse_init_data(&pos, data);
    if (foil_parse_skip_bytes(&pos, &foil_ssh_rsa_mark) &&
        pos.ptr < pos.end && isspace(*pos.ptr)) {
        GBytes* decoded;
        foil_parse_skip_spaces(&pos);
        decoded = foil_parse_base64(&pos, 0);
        if (decoded) {
            if (pos.ptr == pos.end || isspace(*pos.ptr)) {
                FoilBytes b;
                ok = foil_key_rsa_public_parse_ssh_rsa_binary(key,
                    foil_bytes_from_data(&b, decoded));
                foil_pool_add_bytes(pool, decoded);
            } else {
                g_bytes_unref(decoded);
            }
        }
    }
    return ok;
}

/*
 * PKCS #1
 *
 * https://www.ietf.org/rfc/rfc3447 (Appendix A)
 *
 * RSAPublicKey ::= SEQUENCE {
 *   modulus INTEGER, -- n
 *   publicExponent INTEGER -- e }
 */
static
gboolean
foil_key_rsa_public_parse_pkcs1(
    FoilKeyRsaPublicData* key,
    const FoilBytes* bytes)
{
    guint32 len;
    GUtilRange pos;
    foil_parse_init_data(&pos, bytes);
    if (foil_asn1_parse_start_sequence(&pos, &len)) {
        pos.end = pos.ptr + len;
        if (foil_asn1_parse_integer_bytes(&pos, &key->n) &&
            foil_asn1_parse_integer_bytes(&pos, &key->e) &&
            pos.ptr == pos.end) {
            return TRUE;
        }
    }
    return FALSE;
}

/* OpenSSH private key file contains unencrypted public key */

static
gboolean
foil_key_rsa_public_parse_openssh_text(
    FoilKeyRsaPublicData* key,
    const FoilBytes* bytes,
    FoilPool* pool)
{
    FoilKeyRsaOpensshPrivData priv;
    return foil_key_rsa_parse_openssh_text(bytes, key, &priv, pool);
}

static
gboolean
foil_key_rsa_public_parse_openssh_binary(
    FoilKeyRsaPublicData* key,
    const FoilBytes* bytes)
{
    FoilKeyRsaOpensshPrivData priv;
    return foil_key_rsa_parse_openssh_binary(bytes, key, &priv);
}

static
GBytes*
foil_key_rsa_public_data_to_asn1(
    const FoilKeyRsaPublicData* data)
{
    if (data) {
        gsize seq_len = foil_asn1_block_length(data->n.len) +
            foil_asn1_block_length(data->e.len);
        GByteArray* buf = g_byte_array_sized_new(4 + seq_len);
        FoilOutput* out = foil_output_mem_new(buf);
        foil_asn1_encode_sequence_header(out, seq_len);
        foil_asn1_encode_integer_bytes(out, &data->n);
        foil_asn1_encode_integer_bytes(out, &data->e);
        foil_output_unref(out);
        return g_byte_array_free_to_bytes(buf);
    }
    return NULL;
}

static
GBytes*
foil_key_rsa_public_to_bytes(
    FoilKey* key,
    FoilKeyBinaryFormat format)
{
    FoilKeyRsaPublic* self = FOIL_KEY_RSA_PUBLIC_(key);
    switch (format) {
    case FOIL_KEY_BINARY_FORMAT_DEFAULT: /* fallthrough */
    case FOIL_KEY_BINARY_FORMAT_OPENSSH:
    case FOIL_KEY_BINARY_FORMAT_RSA_SSH:
        return foil_key_rsa_public_data_ssh_rsa_bytes(self->data);
    case FOIL_KEY_BINARY_FORMAT_RSA_PKCS1:
        return foil_key_rsa_public_data_to_asn1(self->data);
    }
    /* Invalid/unsupported format */
    return NULL;
}

/*
 * Format defined in RFC 5208:
 *
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm           AlgorithmIdentifier,
 *      subjectPublicKey    BIT STRING }
 *
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *      algorithm           OBJECT IDENTIFIER,
 *      parameters          ANY DEFINED BY algorithm OPTIONAL }
 *
 * For an RSA public key, the OID is 1.2.840.113549.1.1.1
 * In binary form it's [06 09 2a 86 48 86 f7 0d 01 01 01]
 * Algorithm parameters are ignored.
 */
static
gboolean
foil_key_rsa_public_parse_rfc5208(
    FoilKeyRsaPublicData* key,
    const FoilBytes* data)
{
    static const guint8 oid_rsa_bytes[] = { ASN1_OID_RSA_BYTES };
    static const FoilBytes oid_rsa = { oid_rsa_bytes, sizeof(oid_rsa_bytes) };
    gboolean ok = FALSE;
    guint32 len;
    GUtilRange pos;
    foil_parse_init_data(&pos, data);
    if (foil_asn1_parse_start_sequence(&pos, &len)) {
        GUtilRange aid;
        pos.end = pos.ptr + len;
        aid = pos;
        /* Check AlgorithmIdentifier */
        if (foil_asn1_parse_start_sequence(&aid, &len)) {
            guint8 unused;
            FoilBytes oid, bits;
            pos.ptr = aid.ptr + len;
            if (foil_asn1_parse_object_id(&aid, &oid) &&
                foil_bytes_equal(&oid, &oid_rsa) &&
                foil_asn1_parse_bit_string(&pos, &bits, &unused) && !unused) {
                return foil_key_rsa_public_parse_pkcs1(key, &bits);
            }
        }
    }
    return ok;
}

static
gboolean
foil_key_rsa_public_parse_pkcs8(
    FoilKeyRsaPublicData* key,
    const FoilBytes* data,
    FoilPool* pool)
{
    gboolean ok = FALSE;
    GUtilRange pos;
    foil_parse_init_data(&pos, data);
    foil_parse_skip_spaces(&pos);
    if (foil_parse_skip_bytes(&pos, &rsa_public_pkcs8_prefix) &&
        foil_parse_skip_to_next_line(&pos, TRUE) &&
        (pos.end - pos.ptr) > (gssize) rsa_public_pkcs8_prefix.len) {
        GBytes* decoded = foil_parse_base64(&pos,
            FOIL_INPUT_BASE64_IGNORE_SPACES |
            FOIL_INPUT_BASE64_STANDARD);
        if (decoded) {
            if (foil_parse_skip_bytes(&pos, &rsa_public_pkcs8_suffix)) {
                foil_parse_skip_spaces(&pos);
                if (pos.ptr == pos.end) {
                    FoilBytes b;
                    ok = foil_key_rsa_public_parse_rfc5208(key,
                        foil_bytes_from_data(&b, decoded));
                    /* Save GBytes in the pool to keep pointers valid */
                    foil_pool_add_bytes_ref(pool, decoded);
                }
            }
            g_bytes_unref(decoded);
        }
    }
    return ok;
}

static
gboolean
foil_key_rsa_public_parse_rfc4716(
    FoilKeyRsaPublicData* key,
    const FoilBytes* data,
    FoilPool* pool)
{
    gboolean ok = FALSE;
    GUtilRange pos;
    foil_parse_init_data(&pos, data);
    foil_parse_skip_spaces(&pos);
    if (foil_parse_skip_bytes(&pos, &rsa_public_rfc4716_prefix) &&
        foil_parse_skip_to_next_line(&pos, TRUE)) {
        /* Skip headers until we find expected BASE64 signature */
        while (pos.ptr < pos.end && !FOIL_KEY_RSA_PUBLIC_HAS_PREFIX(
            pos.ptr, pos.end - pos.ptr, rsa_public_base64_prefix)) {
            foil_parse_skip_to_next_line(&pos, TRUE);
        }
        if ((pos.end - pos.ptr) > (gssize) rsa_public_rfc4716_suffix.len) {
            GBytes* decoded = foil_parse_base64(&pos,
                FOIL_INPUT_BASE64_IGNORE_SPACES |
                FOIL_INPUT_BASE64_STANDARD);
            if (decoded) {
                if (foil_parse_skip_bytes(&pos, &rsa_public_rfc4716_suffix)) {
                    foil_parse_skip_spaces(&pos);
                    if (pos.ptr == pos.end) {
                        FoilBytes b;
                        ok = foil_key_rsa_public_parse_ssh_rsa_binary(key,
                            foil_bytes_from_data(&b, decoded));
                        /* Save GBytes in the pool to keep pointers valid */
                        foil_pool_add_bytes_ref(pool, decoded);
                    }
                }
                g_bytes_unref(decoded);
            }
        }
    }
    return ok;
}

static
FoilKey*
foil_key_rsa_public_from_data(
    FoilKeyClass* klass,
    const void* bytes,
    gsize size,
    GHashTable* param,
    GError** error)
{
    FoilKey* result = NULL;
    FoilKeyRsaPublicData key;
    FoilBytes data;
    FoilPool pool;
    foil_pool_init(&pool);
    memset(&key, 0, sizeof(key));
    data.val = bytes;
    data.len = size;
    if (foil_key_rsa_public_parse_ssh_rsa_text(&key, &data, &pool) ||
        foil_key_rsa_public_parse_pkcs8(&key, &data, &pool) ||
        foil_key_rsa_public_parse_rfc4716(&key, &data, &pool) ||
        foil_key_rsa_public_parse_ssh_rsa_binary(&key, &data) ||
        foil_key_rsa_public_parse_pkcs1(&key, &data) ||
        foil_key_rsa_public_parse_openssh_text(&key, &data, &pool) ||
        foil_key_rsa_public_parse_openssh_binary(&key, &data)) {
        FoilKeyRsaPublic* pub = g_object_new(G_TYPE_FROM_CLASS(klass), NULL);
        foil_key_rsa_public_set_data(pub, &key);
        g_clear_error(error);
        result = FOIL_KEY(pub);
    } else {
        if (error) {
            g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
                FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT,
                "Unrecognized RSA public key format"));
        }
        GDEBUG("Unsupported RSA public key format");
    }
    foil_pool_drain(&pool);
    return result;
}

static
gboolean
foil_key_rsa_public_export_ssh_rsa(
    FoilKeyRsaPublic* self,
    FoilOutput* out,
    const char* comment,
    GError** error)
{
    const char space = ' ';
    gboolean ok = foil_key_rsa_public_write_all(out, &ssh_rsa_text_prefix) &&
        foil_output_write_all(out, &space, 1);
    if (ok) {
        GBytes* bytes = foil_key_rsa_public_data_ssh_rsa_bytes(self->data);
        FoilOutput* base64 = foil_output_base64_new(out);
        ok = foil_output_write_bytes_all(base64, bytes) &&
            foil_output_flush(base64);
        foil_output_unref(base64);
        g_bytes_unref(bytes);
        if (ok && comment) {
            ok = foil_output_write_all(out, &space, 1) &&
                foil_output_write_all(out, comment, strlen(comment)) &&
                foil_output_write_eol(out);
        }
    }
    if (!ok && error) {
        g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_KEY_WRITE, "Output error"));
    }
    return ok;
}

static
gboolean
foil_key_rsa_public_export_rfc4716(
    FoilKeyRsaPublic* self,
    FoilOutput* out,
    const char* comment,
    GError** error)
{
    gboolean ok = foil_key_rsa_public_write_all(out,
        &rsa_public_rfc4716_prefix) &&
        foil_output_write_eol(out);
    if (ok) {
        if (comment) {
            char* header = foil_format_header("Comment", comment);
            if (header) {
                ok = foil_output_write_all(out, header, strlen(header)) &&
                    foil_output_write_eol(out);
                g_free(header);
            }
        }
        if (ok) {
            GBytes* bytes = foil_key_rsa_public_data_ssh_rsa_bytes(self->data);
            FoilOutput* base64 = foil_output_base64_new_full(out, 0, 70);
            ok = foil_output_write_bytes_all(base64, bytes) &&
                foil_output_flush(base64);
            foil_output_unref(base64);
            g_bytes_unref(bytes);
            if (ok) {
                ok = foil_key_rsa_public_write_all(out,
                    &rsa_public_rfc4716_suffix) &&
                    foil_output_write_eol(out);
            }
        }
    }
    if (!ok && error) {
        g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_KEY_WRITE, "Output error"));
    }
    return ok;
}

static
gboolean
foil_key_rsa_public_export_pkcs8(
    FoilKeyRsaPublic* self,
    FoilOutput* out,
    const char* comment,
    GError** error)
{
    gboolean ok = FALSE;
    GBytes* bitstring = foil_key_rsa_public_data_to_asn1(self->data);
    if (bitstring) {
        ok = foil_key_rsa_public_write_all(out, &rsa_public_pkcs8_prefix) &&
            foil_output_write_eol(out);
        if (ok) {
            const guint8* aid = RSA_PUBLIC_KEY_AID;
            const guint aid_size = sizeof(RSA_PUBLIC_KEY_AID);
            FoilOutput* base64 = foil_output_base64_new_full(out, 0, 64);
            FoilBytes bytes;
            foil_bytes_from_data(&bytes, bitstring);
            ok = foil_asn1_encode_sequence_header(base64, aid_size +
                foil_asn1_bit_string_block_length(bytes.len * 8)) &&
                foil_output_write_all(base64, aid, aid_size) &&
                foil_asn1_encode_bit_string_header(base64, bytes.len * 8) &&
                foil_key_rsa_public_write_all(base64, &bytes) &&
                foil_output_flush(base64);
            foil_output_unref(base64);
            if (ok) {
                ok = foil_key_rsa_public_write_all(out,
                    &rsa_public_pkcs8_suffix) &&
                    foil_output_write_eol(out);
            }
        }
        g_bytes_unref(bitstring);
    }
    if (!ok && error) {
        g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_KEY_WRITE, "Output error"));
    }
    return ok;
}

static
gboolean
foil_key_rsa_public_export(
    FoilKey* key,
    FoilOutput* out,
    FoilKeyExportFormat format,
    GHashTable* param,
    GError** error)
{
    FoilKeyRsaPublic* self = FOIL_KEY_RSA_PUBLIC_(key);
    if (self->data) {
        const char* comment = NULL;
        if (param) {
            GVariant* var = g_hash_table_lookup(param, FOIL_KEY_PARAM_COMMENT);
            if (var && g_variant_is_of_type(var, G_VARIANT_TYPE_STRING)) {
                comment = g_variant_get_string(var, NULL);
            }
        }
        switch (format) {
        case FOIL_KEY_EXPORT_FORMAT_DEFAULT:
        case FOIL_KEY_EXPORT_FORMAT_OPENSSH:
            return foil_key_rsa_public_export_ssh_rsa(self, out, comment,
                error);
        case FOIL_KEY_EXPORT_FORMAT_RFC4716:
            return foil_key_rsa_public_export_rfc4716(self, out, comment,
                error);
        case FOIL_KEY_EXPORT_FORMAT_PKCS8:
            return foil_key_rsa_public_export_pkcs8(self, out, comment,
                error);
        }
        if (error) {
            g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
                FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT,
                "Unsupported export format"));
        }
    } else if (error) {
        g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_UNSPECIFIED, "Uninitialized public key"));
    }
    return FALSE;
}

static
gboolean
foil_key_rsa_public_equal(
    FoilKey* key1,
    FoilKey* key2)
{
    GASSERT(FOIL_IS_KEY_RSA_PUBLIC(key1));
    if (FOIL_IS_KEY_RSA_PUBLIC(key2)) {
        FoilKeyRsaPublic* rsa1 = FOIL_KEY_RSA_PUBLIC_(key1);
        FoilKeyRsaPublic* rsa2 = FOIL_KEY_RSA_PUBLIC_(key2);
        return foil_key_rsa_public_data_equal(rsa1->data, rsa2->data);
    }
    return FALSE;
}

GBytes*
foil_key_rsa_public_data_fingerprint(
    const FoilKeyRsaPublicData* data)
{
    GBytes* bytes = foil_key_rsa_public_data_ssh_rsa_bytes(data);
    GBytes* fingerprint = foil_digest_bytes(FOIL_DIGEST_MD5, bytes);
    g_bytes_unref(bytes);
    return fingerprint;
}

static
GBytes*
foil_key_rsa_public_fingerprint(
    FoilKey* key)
{
    FoilKeyRsaPublic* self = FOIL_KEY_RSA_PUBLIC_(key);
    return foil_key_rsa_public_data_fingerprint(self->data);
}

static
void
foil_key_rsa_public_finalize(
    GObject* object)
{
    FoilKeyRsaPublic* self = FOIL_KEY_RSA_PUBLIC_(object);
    g_free(self->data);
    G_OBJECT_CLASS(foil_key_rsa_public_parent_class)->finalize(object);
}

static
void
foil_key_rsa_public_init(
    FoilKeyRsaPublic* key)
{
}

static
void
foil_key_rsa_public_class_init(
    FoilKeyRsaPublicClass* klass)
{
    FoilKeyClass* key_class = FOIL_KEY_CLASS(klass);
    key_class->fn_equal = foil_key_rsa_public_equal;
    key_class->fn_from_data = foil_key_rsa_public_from_data;
    key_class->fn_to_bytes = foil_key_rsa_public_to_bytes;
    key_class->fn_export = foil_key_rsa_public_export;
    key_class->fn_fingerprint = foil_key_rsa_public_fingerprint;
    G_OBJECT_CLASS(klass)->finalize = foil_key_rsa_public_finalize;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
