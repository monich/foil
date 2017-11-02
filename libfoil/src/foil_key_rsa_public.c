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

#include "foil_key_rsa_public.h"
#include "foil_digest.h"
#include "foil_output.h"
#include "foil_input.h"
#include "foil_util_p.h"

#include <ctype.h>

/* Logging */
#define GLOG_MODULE_NAME foil_log_key
#include "foil_log_p.h"

G_DEFINE_ABSTRACT_TYPE(FoilKeyRsaPublic, foil_key_rsa_public, FOIL_TYPE_KEY);

#define FOIL_KEY_RSA_PUBLIC_HAS_PREFIX(data,len,prefix) ( \
    (guint)(len) >= G_N_ELEMENTS(prefix) && \
    memcmp(data, prefix, G_N_ELEMENTS(prefix)) == 0)
#define FOIL_KEY_RSA_PUBLIC_HAS_TEXT_PREFIX(data,len,prefix) ( \
    FOIL_KEY_RSA_PUBLIC_HAS_PREFIX(data,len,prefix) && \
    ((guint)(len) == G_N_ELEMENTS(prefix) || \
    isspace((data)[G_N_ELEMENTS(prefix)])))

/*
 * string    "ssh-rsa"
 * mpint     e
 * mpint     n
 */
static const guint8 rsa_public_binary_prefix[] = {
    0x00,0x00,0x00,0x07,'s','s','h','-','r','s','a'
};
/* First 84 bits of the above, BASE-64 encoded */
static const guint8 rsa_public_base64_prefix[] = {
    'A','A','A','A','B','3','N','z','a','C','1','y','c','2'
};
/* Text formats */
static const guint8 ssh_rsa_text_prefix[] = {
    's','s','h','-','r','s','a'
};
static const guint8 rsa_public_rfc4716_prefix[] = {
    '-','-','-','-',' ','B','E','G','I','N',' ','S','S','H','2',' ',
    'P','U','B','L','I','C',' ','K','E','Y',' ','-','-','-','-'
};
static const guint8 rsa_public_rfc4716_suffix[] = {
    '-','-','-','-',' ','E','N','D',' ','S','S','H','2',' ','P','U',
    'B','L','I','C',' ','K','E','Y',' ','-','-','-','-'
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

static
gboolean
foil_key_rsa_public_parse_len(
    FoilParsePos* pos,
    guint32* len)
{
    if ((pos->ptr + 4) <= pos->end) {
        *len = ((((((pos->ptr[0]) << 8) +
                     pos->ptr[1]) << 8) +
                     pos->ptr[2]) << 8) +
                     pos->ptr[3];
        pos->ptr += 4;
        return TRUE;
    }
    return FALSE;
}

void
foil_key_rsa_public_set_data(
    FoilKeyRsaPublic* self,
    const FoilKeyRsaPublicData* key_data)
{
    GASSERT(!self->data);
    self->data = foil_key_rsa_public_data_copy(key_data);
    FOIL_KEY_RSA_PUBLIC_GET_CLASS(self)->fn_apply(self);
}

static
void
foil_key_rsa_public_append_bytes(
    GByteArray* buf,
    const FoilBytes* bytes)
{
    guint8 len[4];
    len[0] = (guint8)(bytes->len >> 24);
    len[1] = (guint8)(bytes->len >> 16);
    len[2] = (guint8)(bytes->len >> 8);
    len[3] = (guint8)(bytes->len);
    g_byte_array_append(buf, len, sizeof(len));
    g_byte_array_append(buf, bytes->val, bytes->len);
}

static
GBytes*
foil_key_rsa_public_data_to_bytes(
    const FoilKeyRsaPublicData* data)
{
    GBytes* bytes = NULL;
    if (data) {
        GByteArray* buf = g_byte_array_sized_new(
            G_N_ELEMENTS(rsa_public_binary_prefix) + 8 +
            data->e.len + data->n.len);
        g_byte_array_append(buf, rsa_public_binary_prefix,
            G_N_ELEMENTS(rsa_public_binary_prefix));
        foil_key_rsa_public_append_bytes(buf, &data->e);
        foil_key_rsa_public_append_bytes(buf, &data->n);
        bytes = g_byte_array_free_to_bytes(buf);
    }
    return bytes;
}

static
GBytes*
foil_key_rsa_public_to_bytes(
    FoilKey* key)
{
    FoilKeyRsaPublic* self = FOIL_KEY_RSA_PUBLIC_(key);
    return foil_key_rsa_public_data_to_bytes(self->data);
}

static
gboolean
foil_key_rsa_public_parse_ssh_rsa_binary(
    FoilKeyRsaPublic* self,
    const guint8* data,
    gsize size)
{
    gboolean ok = FALSE;
    if (FOIL_KEY_RSA_PUBLIC_HAS_PREFIX(data, size, rsa_public_binary_prefix)) {
        guint32 len;
        FoilParsePos pos;
        pos.ptr = data + G_N_ELEMENTS(rsa_public_binary_prefix);
        pos.end = data + size;
        if (foil_key_rsa_public_parse_len(&pos, &len) &&
           (pos.ptr + len) < pos.end) {
            FoilKeyRsaPublicData key_data;
            key_data.e.val = pos.ptr;
            key_data.e.len = len;
            pos.ptr += len;
            if (foil_key_rsa_public_parse_len(&pos, &len) &&
               (pos.ptr + len) == pos.end) {
                key_data.n.val = pos.ptr;
                key_data.n.len = len;
                foil_key_rsa_public_set_data(self, &key_data);
                ok = TRUE;
            }
        }
    }
    return ok;
}

static
gboolean
foil_key_rsa_public_parse_rfc4716(
    FoilKeyRsaPublic* self,
    const guint8* data,
    gsize len)
{
    gboolean ok = FALSE;
    if (FOIL_KEY_RSA_PUBLIC_HAS_TEXT_PREFIX(data, len,
        rsa_public_rfc4716_prefix)) {
        FoilParsePos pos;
        pos.ptr = data + G_N_ELEMENTS(rsa_public_rfc4716_prefix);
        pos.end = data + len;
        if (foil_parse_skip_to_next_line(&pos, TRUE)) {
            /* Skip headers until we find expected BASE64 signature */
            while (pos.ptr < pos.end && !FOIL_KEY_RSA_PUBLIC_HAS_PREFIX(
                   pos.ptr, pos.end - pos.ptr, rsa_public_base64_prefix)) {
                foil_parse_skip_to_next_line(&pos, TRUE);
            }
            if ((pos.ptr < pos.end) &&
                (pos.ptr + G_N_ELEMENTS(rsa_public_rfc4716_suffix)) < pos.end) {
                GBytes* decoded = foil_parse_base64(&pos,
                    FOIL_INPUT_BASE64_IGNORE_SPACES);
                if (decoded) {
                    if (FOIL_KEY_RSA_PUBLIC_HAS_PREFIX(pos.ptr,
                        pos.end - pos.ptr, rsa_public_rfc4716_suffix)) {
                        pos.ptr += G_N_ELEMENTS(rsa_public_rfc4716_suffix);
                        foil_parse_skip_spaces(&pos);
                        if (pos.ptr == pos.end) {
                            gsize n;
                            const void* bin = g_bytes_get_data(decoded, &n);
                            ok = foil_key_rsa_public_parse_ssh_rsa_binary(self,
                                bin, n);
                        }
                    }
                    g_bytes_unref(decoded);
                }
            }
        }
    }
    return ok;
}

static
gboolean
foil_key_rsa_public_parse_ssh_rsa_text(
    FoilKeyRsaPublic* self,
    const guint8* data,
    gsize len)
{
    gboolean ok = FALSE;
    if (FOIL_KEY_RSA_PUBLIC_HAS_TEXT_PREFIX(data, len, ssh_rsa_text_prefix)) {
        FoilParsePos pos;
        pos.ptr = data + G_N_ELEMENTS(ssh_rsa_text_prefix);
        pos.end = data + len;
        if (pos.ptr < pos.end && isspace(*pos.ptr)) {
            GBytes* decoded;
            foil_parse_skip_spaces(&pos);
            decoded = foil_parse_base64(&pos, 0);
            if (decoded) {
                if (pos.ptr == pos.end || isspace(*pos.ptr)) {
                    gsize size;
                    const void* bin = g_bytes_get_data(decoded, &size);
                    ok = foil_key_rsa_public_parse_ssh_rsa_binary(self,
                        bin, size);
                }
                g_bytes_unref(decoded);
            }
        }
    }
    return ok;
}

static
gboolean
foil_key_rsa_public_parse_bytes(
    FoilKey* key,
    const void* data,
    gsize len,
    GHashTable* param,
    GError** error)
{
    FoilKeyRsaPublic* self = FOIL_KEY_RSA_PUBLIC_(key);
    if (foil_key_rsa_public_parse_ssh_rsa_text(self, data, len) ||
        foil_key_rsa_public_parse_rfc4716(self, data, len) ||
        foil_key_rsa_public_parse_ssh_rsa_binary(self, data, len)) {
        g_clear_error(error);
        return TRUE;
    } else {
        if (error) {
            g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
                FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT,
                "Unrecognized RSA public key format"));
        }
        GWARN("Unsupported RSA public key format");
        return FALSE;
    }
}

static
gboolean
foil_key_rsa_public_export_rfc4716(
    FoilKeyRsaPublic* self,
    FoilOutput* out,
    const char* comment,
    GError** error)
{
    const char eol = '\n';
    gboolean ok = foil_output_write_all(out, rsa_public_rfc4716_prefix,
        sizeof(rsa_public_rfc4716_prefix)) &&
        foil_output_write_all(out, &eol, 1);
    if (ok) {
        if (comment) {
            char* header = foil_format_header("Comment", comment);
            if (header) {
                ok = foil_output_write_all(out, header, strlen(header)) &&
                    foil_output_write_all(out, &eol, 1);
                g_free(header);
            }
        }
        if (ok) {
            GBytes* bytes = foil_key_rsa_public_data_to_bytes(self->data);
            FoilOutput* base64 = foil_output_base64_new_full(out, 0, 70);
            ok = foil_output_write_bytes_all(base64, bytes) &&
                foil_output_flush(base64);
            foil_output_unref(base64);
            g_bytes_unref(bytes);
            if (ok) {
                ok = foil_output_write_all(out, rsa_public_rfc4716_suffix,
                    sizeof(rsa_public_rfc4716_suffix)) &&
                    foil_output_write_all(out, &eol, 1);
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
foil_key_rsa_public_export_ssh_rsa(
    FoilKeyRsaPublic* self,
    FoilOutput* out,
    const char* comment,
    GError** error)
{
    const char space = ' ';
    gboolean ok = foil_output_write_all(out, ssh_rsa_text_prefix,
        sizeof(ssh_rsa_text_prefix)) && foil_output_write_all(out, &space, 1);
    if (ok) {
        GBytes* bytes = foil_key_rsa_public_data_to_bytes(self->data);
        FoilOutput* base64 = foil_output_base64_new(out);
        ok = foil_output_write_bytes_all(base64, bytes) &&
            foil_output_flush(base64);
        foil_output_unref(base64);
        g_bytes_unref(bytes);
        if (ok && comment) {
            const char eol = '\n';
            ok = foil_output_write_all(out, &space, 1) &&
                foil_output_write_all(out, comment, strlen(comment)) &&
                foil_output_write_all(out, &eol, 1);
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
foil_key_rsa_public_export(
    FoilKey* key,
    FoilOutput* out,
    FoilKeyExportFormat format,
    GHashTable* param,
    GError** error)
{
    FoilKeyRsaPublic* self = FOIL_KEY_RSA_PUBLIC_(key);
    gboolean ok = FALSE;
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
            ok = foil_key_rsa_public_export_ssh_rsa(self, out, comment, error);
            break;
        case FOIL_KEY_EXPORT_FORMAT_RFC4716:
            ok = foil_key_rsa_public_export_rfc4716(self, out, comment, error);
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
            FOIL_ERROR_UNSPECIFIED, "Uninitialized public key"));
    }
    return ok;
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

int
foil_key_rsa_public_num_bits(
    FoilKeyRsaPublic* self)
{
    if (G_LIKELY(self)) {
        return FOIL_KEY_RSA_PUBLIC_GET_CLASS(self)->fn_num_bits(self);
    }
    return 0;
}

static
void
foil_key_rsa_public_apply(
    FoilKeyRsaPublic* self)
{
}

GBytes*
foil_key_rsa_public_data_fingerprint(
    const FoilKeyRsaPublicData* data)
{
    GBytes* bytes = foil_key_rsa_public_data_to_bytes(data);
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
    key_class->fn_parse_bytes = foil_key_rsa_public_parse_bytes;
    key_class->fn_to_bytes = foil_key_rsa_public_to_bytes;
    key_class->fn_export = foil_key_rsa_public_export;
    key_class->fn_fingerprint = foil_key_rsa_public_fingerprint;
    klass->fn_apply = foil_key_rsa_public_apply;
    G_OBJECT_CLASS(klass)->finalize = foil_key_rsa_public_finalize;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
