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

#include "foil_key_p.h"
#include "foil_digest.h"
#include "foil_output.h"
#include "foil_input.h"
#include "foil_util_p.h"

#include <gutil_misc.h>

#include <ctype.h>

/* Logging */
#define GLOG_MODULE_NAME foil_log_key
#include "foil_log_p.h"
GLOG_MODULE_DEFINE2("foil-key", FOIL_LOG_MODULE);

G_DEFINE_ABSTRACT_TYPE(FoilKey, foil_key, G_TYPE_OBJECT);
#define foil_abstract_key_class_ref(type) ((FoilKeyClass*) \
        foil_abstract_class_ref(type, FOIL_TYPE_KEY))
#define foil_key_class_ref(type) ((FoilKeyClass*) \
        foil_class_ref(type, FOIL_TYPE_KEY))

FoilKey*
foil_key_ref(
     FoilKey* self)
{
    if (G_LIKELY(self)) {
        GASSERT(FOIL_IS_KEY(self));
        g_object_ref(self);
    }
    return self;
}

void
foil_key_unref(
     FoilKey* self)
{
    if (G_LIKELY(self)) {
        GASSERT(FOIL_IS_KEY(self));
        g_object_unref(self);
    }
}

gboolean
foil_key_equal(
    FoilKey* key,
    FoilKey* key2)
{
    if (G_UNLIKELY(key == key2)) {
        return TRUE;
    } else if (G_LIKELY(key) && G_LIKELY(key2)) {
        FoilKeyClass* klass = FOIL_KEY_GET_CLASS(key);
        return klass->fn_equal(key, key2);
    } else {
        return FALSE;
    }
}

GBytes*
foil_key_fingerprint(
    FoilKey* self)
{
    if (G_LIKELY(self)) {
        if (!self->fingerprint) {
            FoilKeyClass* klass = FOIL_KEY_GET_CLASS(self);
            GBytes* fingerprint = klass->fn_fingerprint(self);
            GASSERT(fingerprint);
            /* FoilKey is an immutable object and should be safe
             * to use in multi-threaded environment. Make sure that
             * foil_key_fingerprint() being invoked simultaneously
             * by multiple threads don't leak fingerprint bytes. */
            if (fingerprint && !g_atomic_pointer_compare_and_exchange
               (&self->fingerprint, NULL, fingerprint)) {
                g_bytes_unref(fingerprint);
            }
        }
        return self->fingerprint;
    }
    return NULL;
}

GBytes*
foil_key_to_bytes(
    FoilKey* self)
{
    GBytes* bytes = NULL;
    if (G_LIKELY(self)) {
        FoilKeyClass* klass = FOIL_KEY_GET_CLASS(self);
        bytes = klass->fn_to_bytes(self);
    }
    return bytes;
}

gboolean
foil_key_export(
    FoilKey* self,
    FoilOutput* out)
{
    return foil_key_export_format(self, out,
        FOIL_KEY_EXPORT_FORMAT_DEFAULT, NULL);
}

gboolean
foil_key_export_format(
    FoilKey* self,
    FoilOutput* out,
    FoilKeyExportFormat format,
    const char* comment)
{
    gboolean ok = FALSE;
    if (G_LIKELY(self) && G_LIKELY(out)) {
        FoilKeyClass* klass = FOIL_KEY_GET_CLASS(self);
        if (klass->fn_export) {
            GHashTable* params =
                foil_param_add(NULL, FOIL_KEY_PARAM_COMMENT, comment);
            ok = klass->fn_export(self, out, format, params, NULL);
            if (params) {
                g_hash_table_destroy(params);
            }
        }
    }
    return ok;
}

char*
foil_key_to_string(
    FoilKey* self,
    FoilKeyExportFormat format,
    const char* comment)
{
    char* str = NULL;
    if (G_LIKELY(self)) {
        FoilKeyClass* klass = FOIL_KEY_GET_CLASS(self);
        if (klass->fn_export) {
            GByteArray* buf = g_byte_array_new();
            FoilOutput* mem = foil_output_mem_new(buf);
            gboolean ok = foil_key_export_format(self, mem, format, comment);
            foil_output_unref(mem);
            if (ok && g_utf8_validate((char*)buf->data, buf->len, NULL)) {
                const guint8 null = 0;
                g_byte_array_append(buf, &null, 1);
                str = (char*)g_byte_array_free(buf, FALSE);
            } else {
                g_byte_array_free(buf, TRUE);
            }
        }
    }
    return str;
}

gboolean
foil_key_export_full(
    FoilKey* self,
    FoilOutput* out,
    FoilKeyExportFormat format,
    GHashTable* params,
    GError** error)
{
    gboolean ok = FALSE;
    if (G_LIKELY(self) && G_LIKELY(out)) {
        FoilKeyClass* klass = FOIL_KEY_GET_CLASS(self);
        if (klass->fn_export) {
            ok = klass->fn_export(self, out, format, params, error);
        } else if (error) {
            g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
                FOIL_ERROR_KEY_UNSUPPORTED, "Export not supported"));
        }
    } else if (error) {
        g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_INVALID_ARG, "Missing key or destination"));
    }
    return ok;
}

FoilKey*
foil_key_new_from_data(
    GType type,
    const void* data,
    unsigned int len)
{
    return foil_key_new_from_data_full(type, data, len, NULL, NULL);
}

FoilKey*
foil_key_new_from_string(
    GType type,
    const char* str)
{
    return foil_key_new_from_string_full(type, str, NULL, NULL);
}

FoilKey*
foil_key_new_from_bytes(
    GType type,
    GBytes* bytes)
{
    return foil_key_new_from_bytes_full(type, bytes, NULL, NULL);
}

FoilKey*
foil_key_new_from_file(
    GType type,
    const char* file)
{
    return foil_key_new_from_file_full(type, file, NULL, NULL);
}

FoilKey*
foil_key_decrypt_from_data(
    GType type,
    const void* data,
    guint len,
    const char* pass,
    GError** error)
{
    GHashTable* param = foil_param_add(NULL, FOIL_KEY_PARAM_PASSPHRASE, pass);
    FoilKey* key = foil_key_new_from_data_full(type, data, len, param, error);
    if (param) {
        g_hash_table_destroy(param);
    }
    return key;
}

FoilKey*
foil_key_decrypt_from_string(
    GType type,
    const char* str,
    const char* pass,
    GError** error)
{
    GHashTable* param = foil_param_add(NULL, FOIL_KEY_PARAM_PASSPHRASE, pass);
    FoilKey* key = foil_key_new_from_string_full(type, str, param, error);
    if (param) {
        g_hash_table_destroy(param);
    }
    return key;
}

FoilKey*
foil_key_decrypt_from_bytes(
    GType type,
    GBytes* bytes,
    const char* pass,
    GError** error)
{
    GHashTable* param = foil_param_add(NULL, FOIL_KEY_PARAM_PASSPHRASE, pass);
    FoilKey* key = foil_key_new_from_bytes_full(type, bytes, param, error);
    if (param) {
        g_hash_table_destroy(param);
    }
    return key;
}

FoilKey*
foil_key_decrypt_from_file(
    GType type,
    const char* file,
    const char* pass,
    GError** error)
{
    GHashTable* param = foil_param_add(NULL, FOIL_KEY_PARAM_PASSPHRASE, pass);
    FoilKey* key = foil_key_new_from_file_full(type, file, param, error);
    if (param) {
        g_hash_table_destroy(param);
    }
    return key;
}

static
FoilKey*
foil_key_from_bytes(
    FoilKeyClass* klass,
    const void* data,
    guint len,
    GHashTable* params,
    GError** error)
{
    GBytes* bytes;
    FoilParsePos pos;
    GString* buf = NULL;
    FoilKey* key = NULL;

    /* Try BASE64 first */
    pos.ptr = data;
    pos.end = pos.ptr + len;
    bytes = foil_parse_base64(&pos, FOIL_INPUT_BASE64_IGNORE_SPACES);
    if (bytes) {
        if (pos.ptr == pos.end) {
            gsize size;
            const guint8* bin = g_bytes_get_data(bytes, &size);
            key = klass->fn_from_data(klass, bin, size, params, error);
        }
        g_bytes_unref(bytes);
        if (key) {
            return key;
        }
    }

    /* Then try to decode the data as hex */
    for (pos.ptr = data; pos.ptr < pos.end && pos.ptr[0]; pos.ptr++) {
        const int c = pos.ptr[0];
        if (isxdigit(c)) {
            if (!buf) {
                buf = g_string_new(NULL);
            }
            g_string_append_c(buf, c);
        } else if (!isspace(c)) {
            /* We are only expecting spaces and gex characters */
            break;
        }
    }

    if (pos.ptr == pos.end && buf && !(buf->len & 1)) {
        const gsize size = buf->len/2;
        void* bin = g_malloc(size);
        /* hex2bin must succeed since we have validated the input */
        gutil_hex2bin(buf->str, buf->len, bin);
        key = klass->fn_from_data(klass, bin, size, params, error);
        g_free(bin);
    }

    if (buf) {
        g_string_free(buf, TRUE);
    }

    if (!key) {
        /* Otherwise let the class to decide how to interpret that */
        g_clear_error(error);
        key = klass->fn_from_data(klass, data, len, params, error);
    }

    return key;
}

FoilKey*
foil_key_new_from_data_full(
    GType type,
    const void* data,
    guint len,
    GHashTable* param,
    GError** error)
{
    if (G_LIKELY(type) && G_LIKELY(data) && G_LIKELY(len)) {
        FoilKeyClass* klass = foil_key_class_ref(type);
        if (G_LIKELY(klass)) {
            FoilKey* key = foil_key_from_bytes(klass, data, len, param, error);
            g_type_class_unref(klass);
            return key;
        } else if (error) {
            g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
                FOIL_ERROR_INVALID_ARG, "Invalid key type"));
        }
    } else if (error) {
        g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_INVALID_ARG, "Missing key type or data"));
    }
    return NULL;
}

FoilKey*
foil_key_new_from_string_full(
    GType type,
    const char* str,
    GHashTable* params,
    GError** error)
{
    FoilKey* key = NULL;
    if (G_LIKELY(type) && G_LIKELY(str) && G_LIKELY(str[0])) {
        const gsize len = strlen(str);
        return foil_key_new_from_data_full(type, str, len, params, error);
    } else if (error) {
        g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_INVALID_ARG, "Missing key type or data"));
    }
    return key;
}

FoilKey*
foil_key_new_from_bytes_full(
    GType type,
    GBytes* bytes,
    GHashTable* param,
    GError** error)
{
    FoilKey* key = NULL;
    if (G_LIKELY(type) && G_LIKELY(bytes)) {
        gsize size = 0;
        const void* data = g_bytes_get_data(bytes, &size);
        key = foil_key_new_from_data_full(type, data, size, param, error);
    } else if (error) {
        g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_INVALID_ARG, "Missing key type or data"));
    }
    return key;
}

FoilKey*
foil_key_new_from_file_full(
    GType type,
    const char* file,
    GHashTable* param,
    GError** error)
{
    FoilKey* key = NULL;
    if (G_LIKELY(type) && G_LIKELY(file)) {
        GError* ioerror = NULL;
        GMappedFile* map = g_mapped_file_new(file, FALSE, &ioerror);
        if (map) {
            const void* data = g_mapped_file_get_contents(map);
            const gsize size = g_mapped_file_get_length(map);
            key = foil_key_new_from_data_full(type, data, size, param, error);
            g_mapped_file_unref(map);
        } else {
            GERR("%s", GERRMSG(ioerror));
            g_propagate_error(error, ioerror);
        }
    } else if (error) {
        g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_INVALID_ARG, "Missing key type or data"));
    }
    return key;
}

FoilKey*
foil_key_generate_new(
    GType type,
    guint bits)
{
    FoilKey* key = NULL;
    FoilKeyClass* klass = foil_abstract_key_class_ref(type);
    if (G_LIKELY(klass)) {
        if (G_LIKELY(klass->fn_generate)) {
            key = klass->fn_generate(klass, bits);
        }
        g_type_class_unref(klass);
    }
    return key;
}

static
GBytes*
foil_key_default_fingerprint(
    FoilKey* self)
{
    FoilKeyClass* klass = FOIL_KEY_GET_CLASS(self);
    GBytes* bytes = klass->fn_to_bytes(self);
    GBytes* fingerprint = foil_digest_bytes(FOIL_DIGEST_MD5, bytes);
    GASSERT(!self->fingerprint);
    g_bytes_unref(bytes);
    return fingerprint;
}

static
void
foil_key_finalize(
    GObject* object)
{
    FoilKey* self = FOIL_KEY(object);
    if (self->fingerprint) {
        g_bytes_unref(self->fingerprint);
    }
    G_OBJECT_CLASS(foil_key_parent_class)->finalize(object);
}

static
void
foil_key_init(
    FoilKey* self)
{
}

static
void
foil_key_class_init(
    FoilKeyClass* klass)
{
    G_OBJECT_CLASS(klass)->finalize = foil_key_finalize;
    klass->fn_fingerprint = foil_key_default_fingerprint;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
