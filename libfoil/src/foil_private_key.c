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

#include "foil_private_key_p.h"
#include "foil_output.h"
#include "foil_util_p.h"

#include <gutil_misc.h>

/* Logging */
#define GLOG_MODULE_NAME foil_log_key
#include "foil_log_p.h"

G_DEFINE_ABSTRACT_TYPE(FoilPrivateKey, foil_private_key, FOIL_TYPE_KEY);
#define foil_private_key_class_ref(type) ((FoilPrivateKeyClass*) \
        foil_class_ref(type, FOIL_TYPE_PRIVATE_KEY))

FoilPrivateKey*
foil_private_key_new_from_data(
    GType type,
    const void* data,
    guint len)
{
    return foil_private_key_new_from_data_full(type, data, len, NULL, NULL);
}

FoilPrivateKey*
foil_private_key_new_from_bytes(
    GType type,
    GBytes* bytes)
{
    return foil_private_key_new_from_bytes_full(type, bytes, NULL, NULL);
}

FoilPrivateKey*
foil_private_key_new_from_file(
    GType type,
    const char* file)
{
    return foil_private_key_new_from_file_full(type, file, NULL, NULL);
}

FoilPrivateKey*
foil_private_key_decrypt_from_string(
    GType type,
    const char* str,
    const char* pass,
    GError** error)
{
    if (str && str[0]) {
        return foil_private_key_decrypt_from_data(type, str, strlen(str),
            pass, error);
    } else {
        if (error) {
            g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
                FOIL_ERROR_INVALID_ARG, "Missing key data"));
        }
        return NULL;
    }
}

FoilPrivateKey*
foil_private_key_decrypt_from_data(
    GType type,
    const void* data,
    guint len,
    const char* pass,
    GError** error)
{
    GHashTable* param = foil_param_add(NULL, FOIL_KEY_PARAM_PASSPHRASE, pass);
    FoilPrivateKey* key = foil_private_key_new_from_data_full(type, data, len,
        param, error);
    if (param) {
        g_hash_table_destroy(param);
    }
    return key;
}

FoilPrivateKey*
foil_private_key_decrypt_from_bytes(
    GType type,
    GBytes* bytes,
    const char* pass,
    GError** error)
{
    GHashTable* param = foil_param_add(NULL, FOIL_KEY_PARAM_PASSPHRASE, pass);
    FoilPrivateKey* key = foil_private_key_new_from_bytes_full(type, bytes,
        param, error);
    if (param) {
        g_hash_table_destroy(param);
    }
    return key;
}

FoilPrivateKey*
foil_private_key_decrypt_from_file(
    GType type,
    const char* file,
    const char* pass,
    GError** error)
{
    GHashTable* param = foil_param_add(NULL, FOIL_KEY_PARAM_PASSPHRASE, pass);
    FoilPrivateKey* key = foil_private_key_new_from_file_full(type, file,
        param, error);
    if (param) {
        g_hash_table_destroy(param);
    }
    return key;
}

FoilPrivateKey*
foil_private_key_new_from_data_full(
    GType type,
    const void* data,
    guint len,
    GHashTable* param,
    GError** error)
{
    FoilPrivateKey* priv_key = NULL;
    FoilPrivateKeyClass* klass = foil_private_key_class_ref(type);
    if (G_LIKELY(klass)) {
        FoilKey* key = foil_key_new_from_data_full(type, data, len,
            param, error);
        if (key) {
            priv_key = FOIL_PRIVATE_KEY(key);
        }
        g_type_class_unref(klass);
    } else if (error) {
        g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_INVALID_ARG, "Missing or invalid key type"));
    }
    return priv_key;
}

FoilPrivateKey*
foil_private_key_new_from_string(
    GType type,
    const char* str)
{
    return foil_private_key_new_from_string_full(type, str, NULL, NULL);
}

FoilPrivateKey*
foil_private_key_new_from_string_full(
    GType type,
    const char* str,
    GHashTable* params,
    GError** error)
{
    FoilPrivateKey* key = NULL;
    if (G_LIKELY(type) && G_LIKELY(str)) {
        const gsize len = strlen(str);
        if (len & 1) {
            key = foil_private_key_new_from_data_full(type, str, len,
                params, error);
        } else if (len > 0) {
            const gsize size = len/2;
            void* data = g_malloc(size);
            if (gutil_hex2bin(str, len, data)) {
                key = foil_private_key_new_from_data_full(type, data,
                    size, params, error);
            }
            g_free(data);
            if (!key) {
                g_clear_error(error);
                key = foil_private_key_new_from_data_full(type, str, len,
                    params, error);
            }
        }
    } else if (error) {
        g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_INVALID_ARG, "Missing key type or data"));
    }
    return key;
}

FoilPrivateKey*
foil_private_key_new_from_bytes_full(
    GType type,
    GBytes* bytes,
    GHashTable* param,
    GError** error)
{
    FoilPrivateKey* priv_key = NULL;
    FoilPrivateKeyClass* klass = foil_private_key_class_ref(type);
    if (G_LIKELY(klass)) {
        FoilKey* key = foil_key_new_from_bytes_full(type, bytes, param, error);
        if (key) {
            priv_key = FOIL_PRIVATE_KEY(key);
        }
        g_type_class_unref(klass);
    } else if (error) {
        g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_INVALID_ARG, "Missing or invalid key type"));
    }
    return priv_key;
}

FoilPrivateKey*
foil_private_key_new_from_file_full(
    GType type,
    const char* file,
    GHashTable* param,
    GError** error)
{
    FoilPrivateKey* priv_key = NULL;
    FoilPrivateKeyClass* klass = foil_private_key_class_ref(type);
    if (G_LIKELY(klass)) {
        FoilKey* key = foil_key_new_from_file_full(type, file, param, error);
        if (key) {
            priv_key = FOIL_PRIVATE_KEY(key);
        }
        g_type_class_unref(klass);
    } else if (error) {
        g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_INVALID_ARG, "Missing or invalid key type"));
    }
    return priv_key;
}

gboolean
foil_private_key_export(
    FoilPrivateKey* self,
    FoilOutput* out)
{
    if (G_LIKELY(self)) {
        return foil_key_export(FOIL_KEY(self), out);
    }
    return FALSE;
}

gboolean
foil_private_key_encrypt(
    FoilPrivateKey* self,
    FoilOutput* out,
    FoilKeyExportFormat format,
    const char* passphrase,
    const char* comment,
    GError** error)
{
    gboolean ok = FALSE;
    if (G_UNLIKELY(!self)) {
        if (error) {
            g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
                FOIL_ERROR_INVALID_ARG, "Missing key"));
        }
    } else if (G_UNLIKELY(!out)) {
        if (error) {
            g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
                FOIL_ERROR_INVALID_ARG, "Missing destination"));
        }
    } else {
        GHashTable* params = foil_param_add(foil_param_add(NULL,
            FOIL_KEY_PARAM_PASSPHRASE, passphrase),
            FOIL_KEY_PARAM_COMMENT, comment);
        ok = foil_private_key_export_full(self, out, format, params, error);
        if (params) {
            g_hash_table_destroy(params);
        }
    }
    return ok;
}

char*
foil_private_key_encrypt_to_string(
    FoilPrivateKey* self,
    FoilKeyExportFormat format,
    const char* pass,
    const char* comment)
{
    char* result = NULL;
    if (G_LIKELY(self)) {
        GByteArray* buf = g_byte_array_new();
        FoilOutput* out = foil_output_mem_new(buf);
        if (foil_private_key_encrypt(self, out, format, pass, comment, NULL)) {
            guint8 zero = 0;
            g_byte_array_append(buf, &zero, 1);
            result = (char*)g_byte_array_free(buf, FALSE);
        } else {
            g_byte_array_free(buf, TRUE);
        }
        foil_output_unref(out);
    }
    return result;
}

gboolean
foil_private_key_export_full(
    FoilPrivateKey* self,
    FoilOutput* out,
    FoilKeyExportFormat format,
    GHashTable* params,
    GError** error)
{
    if (G_LIKELY(self)) {
        FoilKey* key = FOIL_KEY(self);
        return foil_key_export_full(key, out, format, params, error);
    } else if (error) {
        g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_INVALID_ARG, "Missing key"));
    }
    return FALSE;
}

char*
foil_private_key_to_string(
    FoilPrivateKey* self,
    FoilKeyExportFormat format,
    const char* comment)
{
    if (G_LIKELY(self)) {
        return foil_key_to_string(FOIL_KEY(self), format, comment);
    }
    return FALSE;
}

FoilPrivateKey*
foil_private_key_ref(
    FoilPrivateKey* self)
{
    if (G_LIKELY(self)) {
        GASSERT(FOIL_IS_PRIVATE_KEY(self));
        g_object_ref(self);
    }
    return self;
}

void
foil_private_key_unref(
    FoilPrivateKey* self)
{
    if (G_LIKELY(self)) {
        GASSERT(FOIL_IS_PRIVATE_KEY(self));
        g_object_unref(self);
    }
}

gboolean
foil_private_key_equal(
    FoilPrivateKey* key,
    FoilPrivateKey* key2)
{
    if (G_UNLIKELY(key == key2)) {
        return TRUE;
    } else if (G_LIKELY(key) && G_LIKELY(key2)) {
        FoilKeyClass* klass = FOIL_KEY_GET_CLASS(key);
        return klass->fn_equal(FOIL_KEY(key), FOIL_KEY(key2));
    } else {
        return FALSE;
    }
}

GBytes*
foil_private_key_fingerprint(
    FoilPrivateKey* self)
{
    return G_LIKELY(self) ? foil_key_fingerprint(&self->super) : NULL;
}

FoilKey*
foil_public_key_new_from_private(
    FoilPrivateKey* self)
{
    FoilKey* pub = NULL;
    if (G_LIKELY(self)) {
        FoilPrivateKeyClass* klass = FOIL_PRIVATE_KEY_GET_CLASS(self);
        pub = klass->create_public(self);
    }
    return pub;
}

static
void
foil_private_key_init(
    FoilPrivateKey* self)
{
}

static
void
foil_private_key_class_init(
    FoilPrivateKeyClass* klass)
{
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
