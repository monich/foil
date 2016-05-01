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

#ifndef FOIL_PRIVATE_KEY_H
#define FOIL_PRIVATE_KEY_H

#include "foil_key.h"

G_BEGIN_DECLS

FoilPrivateKey*
foil_private_key_new_from_data(
    GType type,
    const void* data,
    guint len);

FoilPrivateKey*
foil_private_key_new_from_bytes(
    GType type,
    GBytes* bytes);

FoilPrivateKey*
foil_private_key_new_from_file(
    GType type,
    const char* file);

FoilPrivateKey*
foil_private_key_decrypt_from_string(
    GType type,
    const char* str,
    const char* pass,
    GError** error);

FoilPrivateKey*
foil_private_key_decrypt_from_data(
    GType type,
    const void* data,
    guint len,
    const char* passphrase,
    GError** error);

FoilPrivateKey*
foil_private_key_decrypt_from_bytes(
    GType type,
    GBytes* bytes,
    const char* passphrase,
    GError** error);

FoilPrivateKey*
foil_private_key_decrypt_from_file(
    GType type,
    const char* file,
    const char* passphrase,
    GError** error);

FoilPrivateKey*
foil_private_key_new_from_data_full(
    GType type,
    const void* data,
    guint len,
    GHashTable* param,
    GError** error);

FoilPrivateKey*
foil_private_key_new_from_bytes_full(
    GType type,
    GBytes* bytes,
    GHashTable* param,
    GError** error);

FoilPrivateKey*
foil_private_key_new_from_file_full(
    GType type,
    const char* file,
    GHashTable* param,
    GError** error);

FoilPrivateKey*
foil_private_key_new_from_string(
    GType type,
    const char* str);

FoilPrivateKey*
foil_private_key_new_from_string_full(
    GType type,
    const char* str,
    GHashTable* params,
    GError** error);

gboolean
foil_private_key_export(
    FoilPrivateKey* key,
    FoilOutput* out);

gboolean
foil_private_key_encrypt(
    FoilPrivateKey* key,
    FoilOutput* out,
    FoilKeyExportFormat format,
    const char* passphrase,
    const char* comment,
    GError** error);

char*
foil_private_key_encrypt_to_string(
    FoilPrivateKey* key,
    FoilKeyExportFormat format,
    const char* passphrase,
    const char* comment);

gboolean
foil_private_key_export_full(
    FoilPrivateKey* key,
    FoilOutput* out,
    FoilKeyExportFormat format,
    GHashTable* params,
    GError** error);

char*
foil_private_key_to_string(
    FoilPrivateKey* key,
    FoilKeyExportFormat format,
    const char* comment);

FoilPrivateKey*
foil_private_key_ref(
    FoilPrivateKey* key);

void
foil_private_key_unref(
    FoilPrivateKey* key);

gboolean
foil_private_key_equal(
    FoilPrivateKey* key,
    FoilPrivateKey* key2);

GBytes*
foil_private_key_fingerprint(
    FoilPrivateKey* key);

FoilKey*
foil_public_key_new_from_private(
    FoilPrivateKey* key);

GType foil_private_key_get_type(void);
#define FOIL_TYPE_PRIVATE_KEY (foil_private_key_get_type())
#define FOIL_IS_PRIVATE_KEY(obj) G_TYPE_CHECK_INSTANCE_TYPE(obj, \
        FOIL_TYPE_PRIVATE_KEY)
#define FOIL_PRIVATE_KEY(obj) (G_TYPE_CHECK_INSTANCE_CAST(obj, \
        FOIL_TYPE_PRIVATE_KEY, FoilPrivateKey))

G_END_DECLS

#endif /* FOIL_KEY_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
