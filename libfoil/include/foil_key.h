/*
 * Copyright (C) 2016-2022 by Slava Monich <slava@monich.com>
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

#ifndef FOIL_KEY_H
#define FOIL_KEY_H

#include "foil_types.h"

#include <glib-object.h>

G_BEGIN_DECLS

/*
 * Optional GHashTable passed in as a parameter may contain
 * references (normal, not floating) to GVariant's providing
 * format specific parameters necessary for loading the key
 * from the data.
 */

/*
 * "Passphrase" is necessary for decrypting and encrypting RSA private keys.
 */
#define FOIL_KEY_PARAM_PASSPHRASE "Passphrase"  /* G_VARIANT_TYPE_STRING */

/*
 * "Comment" is used for exporting RSA keys to text format. Ignored
 * when the key is being loaded from text or binary data.
 */
#define FOIL_KEY_PARAM_COMMENT "Comment"        /* G_VARIANT_TYPE_STRING */

/* Key export format (for exporting to text) */
typedef enum foil_key_export_format {
    FOIL_KEY_EXPORT_FORMAT_DEFAULT,
    FOIL_KEY_EXPORT_FORMAT_RFC4716,
    FOIL_KEY_EXPORT_FORMAT_PKCS8    /* Since 1.0.7 */
} FoilKeyExportFormat;

/* Format of binary key data */
typedef enum foil_key_binary_format { /* Since 1.0.26 */
    FOIL_KEY_BINARY_FORMAT_DEFAULT,   /* Valid for all key formats */
    FOIL_KEY_EXPORT_FORMAT_RSA_PKCS1, /* RFC 3447 (Appendix A) */
    FOIL_KEY_BINARY_FORMAT_RSA_SSH    /* RFC 4253 (ssh-rsa format) */
} FoilKeyBinaryFormat;

FoilKey*
foil_key_new_from_data(
    GType type,
    const void* data,
    guint len);

FoilKey*
foil_key_new_from_string(
    GType type,
    const char* str);

FoilKey*
foil_key_new_from_bytes(
    GType type,
    GBytes* bytes);

FoilKey*
foil_key_new_from_file(
    GType type,
    const char* file);

FoilKey*
foil_key_decrypt_from_data(
    GType type,
    const void* data,
    guint len,
    const char* passphrase,
    GError** error);

FoilKey*
foil_key_decrypt_from_string(
    GType type,
    const char* str,
    const char* passphrase,
    GError** error);

FoilKey*
foil_key_decrypt_from_bytes(
    GType type,
    GBytes* bytes,
    const char* passphrase,
    GError** error);

FoilKey*
foil_key_decrypt_from_file(
    GType type,
    const char* file,
    const char* passphrase,
    GError** error);

FoilKey*
foil_key_new_from_data_full(
    GType type,
    const void* data,
    guint len,
    GHashTable* param,
    GError** error);

FoilKey*
foil_key_new_from_string_full(
    GType type,
    const char* str,
    GHashTable* param,
    GError** error);

FoilKey*
foil_key_new_from_bytes_full(
    GType type,
    GBytes* bytes,
    GHashTable* param,
    GError** error);

FoilKey*
foil_key_new_from_file_full(
    GType type,
    const char* file,
    GHashTable* param,
    GError** error);

FoilKey*
foil_key_generate_new(
    GType type,
    guint bits);

#define FOIL_KEY_BITS_DEFAULT (0)

FoilKey*
foil_key_ref(
    FoilKey* key);

void
foil_key_unref(
    FoilKey* key);

gboolean
foil_key_equal(
    FoilKey* key,
    FoilKey* key2);

GBytes*
foil_key_fingerprint(
    FoilKey* key);

GBytes*
foil_key_to_bytes(
    FoilKey* key);

GBytes*
foil_key_to_binary_format(
    FoilKey* key,
    FoilKeyBinaryFormat format); /* Since 1.0.26 */

gboolean
foil_key_export(
    FoilKey* key,
    FoilOutput* out);

gboolean
foil_key_export_format(
    FoilKey* key,
    FoilOutput* out,
    FoilKeyExportFormat format,
    const char* comment);

gboolean
foil_key_export_full(
    FoilKey* key,
    FoilOutput* out,
    FoilKeyExportFormat format,
    GHashTable* param,
    GError** error);

char*
foil_key_to_string(
    FoilKey* key,
    FoilKeyExportFormat format,
    const char* comment);

#define FOIL_KEY(obj) (G_TYPE_CHECK_INSTANCE_CAST(obj, \
        FOIL_TYPE_KEY, FoilKey))

/* Abstract types */
GType foil_key_get_type(void);
GType foil_key_des_get_type(void); /* Since 1.0.16 */
GType foil_key_aes_get_type(void);
GType foil_key_rsa_public_get_type(void);
GType foil_key_rsa_private_get_type(void);

#define FOIL_TYPE_KEY (foil_key_get_type())
#define FOIL_TYPE_KEY_DES (foil_key_des_get_type()) /* Since 1.0.16 */
#define FOIL_TYPE_KEY_AES (foil_key_aes_get_type())
#define FOIL_TYPE_KEY_RSA_PUBLIC (foil_key_rsa_public_get_type())
#define FOIL_TYPE_KEY_RSA_PRIVATE (foil_key_rsa_private_get_type())

#define FOIL_IS_KEY_DES(obj) \
    G_TYPE_CHECK_INSTANCE_TYPE(obj, FOIL_TYPE_KEY_DES)
#define FOIL_IS_KEY_AES(obj) \
    G_TYPE_CHECK_INSTANCE_TYPE(obj, FOIL_TYPE_KEY_AES)
#define FOIL_IS_KEY_RSA_PUBLIC(obj) \
    G_TYPE_CHECK_INSTANCE_TYPE(obj, FOIL_TYPE_KEY_RSA_PUBLIC)
#define FOIL_IS_KEY_RSA_PRIVATE(obj) \
    G_TYPE_CHECK_INSTANCE_TYPE(obj, FOIL_TYPE_KEY_RSA_PRIVATE)

/* Implementation types */
GType foil_key_aes128_get_type(void);
GType foil_key_aes192_get_type(void);
GType foil_key_aes256_get_type(void);
GType foil_impl_key_des_get_type(void); /* Since 1.0.16 */
GType foil_impl_key_rsa_public_get_type(void);
GType foil_impl_key_rsa_private_get_type(void);

#define FOIL_KEY_DES (foil_impl_key_des_get_type()) /* Since 1.0.16 */
#define FOIL_KEY_AES128 (foil_key_aes128_get_type())
#define FOIL_KEY_AES192 (foil_key_aes192_get_type())
#define FOIL_KEY_AES256 (foil_key_aes256_get_type())
#define FOIL_KEY_RSA_PUBLIC (foil_impl_key_rsa_public_get_type())
#define FOIL_KEY_RSA_PRIVATE (foil_impl_key_rsa_private_get_type())

G_END_DECLS

#endif /* FOIL_KEY_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
