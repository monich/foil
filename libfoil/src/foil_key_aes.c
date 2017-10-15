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

#include "foil_key_aes.h"
#include "foil_random.h"
#include "foil_input.h"
#include "foil_util.h"

#include <ctype.h>

/* Logging */
#define GLOG_MODULE_NAME foil_log_key
#include "foil_log_p.h"

typedef FoilKeyAes FoilKeyAes128;
typedef FoilKeyAes FoilKeyAes192;
typedef FoilKeyAes FoilKeyAes256;
typedef FoilKeyAesClass FoilKeyAes128Class;
typedef FoilKeyAesClass FoilKeyAes192Class;
typedef FoilKeyAesClass FoilKeyAes256Class;

G_DEFINE_ABSTRACT_TYPE(FoilKeyAes, foil_key_aes, FOIL_TYPE_KEY);
G_DEFINE_TYPE(FoilKeyAes128, foil_key_aes128, FOIL_TYPE_KEY_AES);
G_DEFINE_TYPE(FoilKeyAes192, foil_key_aes192, FOIL_TYPE_KEY_AES);
G_DEFINE_TYPE(FoilKeyAes256, foil_key_aes256, FOIL_TYPE_KEY_AES);

static
FoilKey*
foil_key_aes_generate(
    GType type,
    guint bits)
{
    FoilKey* key = NULL;
    const guint key_size = (bits/8);
    const guint size = key_size + FOIL_AES_BLOCK_SIZE; /* Key + IV */
    guint8 data[FOIL_AES_MAX_KEY_SIZE + FOIL_AES_BLOCK_SIZE];
    /* The caller guarantees that the number of bits is sane */
    GASSERT(bits && !(bits % 8) && bits <= FOIL_AES_MAX_KEY_SIZE*8);
    if (foil_random_generate(FOIL_RANDOM_DEFAULT, data, size)) {
        key = foil_key_new_from_data(type, data, size);
    }
    return key;
}

static
FoilKey*
foil_key_aes_generate_any(
    guint bits)
{
    switch (bits) {
    case FOIL_KEY_BITS_DEFAULT: bits = 128; /* no break */
    case 128: return foil_key_aes_generate(FOIL_KEY_AES128, bits);
    case 192: return foil_key_aes_generate(FOIL_KEY_AES192, bits);
    case 256: return foil_key_aes_generate(FOIL_KEY_AES256, bits);
    default:
        GERR("Unsupported number of bits for AES (%u)", bits);
        return NULL;
    }
}

static
gboolean
foil_key_aes_parse_binary(
    FoilKeyAes* self,
    FoilKeyAesClass* klass,
    const guint8* data,
    gsize size)
{
    if (size == klass->size + FOIL_AES_BLOCK_SIZE) {
        memcpy(self->key, data, klass->size);
        memcpy(self->iv, data + klass->size, FOIL_AES_BLOCK_SIZE);
        return TRUE;
    }
    return FALSE;
}

static
gboolean
foil_key_aes_parse_bytes(
    FoilKey* key,
    const void* data,
    gsize len,
    GHashTable* param,
    GError** error)
{
    FoilKeyAes* self = FOIL_KEY_AES_(key);
    FoilKeyAesClass* klass = FOIL_KEY_AES_GET_CLASS(self);
    if (foil_key_aes_parse_binary(self, klass, data, len)) {
        g_clear_error(error);
        return TRUE;
    } else {
        if (error) {
            g_propagate_error(error, g_error_new(FOIL_ERROR,
                FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT,
                "Unsupported AES%d key format", klass->size*8));
        }
        GWARN("Unsupported AES%d key format", klass->size*8);
        return FALSE;
    }
}

static
gboolean
foil_key_aes_equal(
    FoilKey* key1,
    FoilKey* key2)
{
    GASSERT(FOIL_IS_KEY_AES(key1));
    if (FOIL_IS_KEY_AES(key2)) {
        FoilKeyAes* aes1 = FOIL_KEY_AES_(key1);
        FoilKeyAes* aes2 = FOIL_KEY_AES_(key2);
        FoilKeyAesClass* klass1 = FOIL_KEY_AES_GET_CLASS(aes1);
        FoilKeyAesClass* klass2 = FOIL_KEY_AES_GET_CLASS(aes2);
        return klass1->size == klass2->size &&
           !memcmp(aes1->key, aes2->key, klass1->size) &&
           !memcmp(aes1->iv, aes2->iv, FOIL_AES_BLOCK_SIZE);
    }
    return FALSE;
}

static
GBytes*
foil_key_aes_to_bytes(
    FoilKey* key)
{
    FoilKeyAes* self = FOIL_KEY_AES_(key);
    FoilKeyAesClass* klass = FOIL_KEY_AES_GET_CLASS(self);
    guint8* bytes = g_malloc(klass->size + FOIL_AES_BLOCK_SIZE);
    memcpy(bytes, self->key, klass->size);
    memcpy(bytes + klass->size, self->iv, FOIL_AES_BLOCK_SIZE);
    return g_bytes_new_take(bytes, klass->size + FOIL_AES_BLOCK_SIZE);
}

static
void
foil_key_aes_init(
    FoilKeyAes* key)
{
}

static
void
foil_key_aes_class_init(
    FoilKeyAesClass* klass)
{
    FoilKeyClass* key_class = FOIL_KEY_CLASS(klass);
    key_class->fn_generate = foil_key_aes_generate_any;
    key_class->fn_equal = foil_key_aes_equal;
    key_class->fn_parse_bytes = foil_key_aes_parse_bytes;
    key_class->fn_to_bytes = foil_key_aes_to_bytes;
}

/* AES128 */

static
FoilKey*
foil_key_aes128_generate(
    guint bits)
{
    return (bits == FOIL_KEY_BITS_DEFAULT || bits == 128) ?
        foil_key_aes_generate(FOIL_KEY_AES128, 128) : NULL;
}

static
void
foil_key_aes128_init(
    FoilKeyAes* self)
{
    self->key = g_type_instance_get_private((void*)self, FOIL_KEY_AES128);
}

static
void
foil_key_aes128_class_init(
    FoilKeyAesClass* klass)
{
    FoilKeyClass* key_class = FOIL_KEY_CLASS(klass);
    key_class->fn_generate = foil_key_aes128_generate;
    klass->size = 16;
    g_type_class_add_private(klass, klass->size);
}

/* AES192 */

static
FoilKey*
foil_key_aes192_generate(
    guint bits)
{
    return (bits == FOIL_KEY_BITS_DEFAULT || bits == 192) ?
        foil_key_aes_generate(FOIL_KEY_AES192, 192) : NULL;
}

static
void
foil_key_aes192_init(
    FoilKeyAes* self)
{
    self->key = g_type_instance_get_private((void*)self, FOIL_KEY_AES192);
}

static
void
foil_key_aes192_class_init(
    FoilKeyAesClass* klass)
{
    FoilKeyClass* key_class = FOIL_KEY_CLASS(klass);
    key_class->fn_generate = foil_key_aes192_generate;
    klass->size = 24;
    g_type_class_add_private(klass, klass->size);
}

/* AES256 */

static
FoilKey*
foil_key_aes256_generate(
    guint bits)
{
    return (bits == FOIL_KEY_BITS_DEFAULT || bits == 256) ?
        foil_key_aes_generate(FOIL_KEY_AES256, 256) : NULL;
}

static
void
foil_key_aes256_init(
    FoilKeyAes* self)
{
    self->key = g_type_instance_get_private((void*)self, FOIL_KEY_AES256);
}

static
void
foil_key_aes256_class_init(
    FoilKeyAesClass* klass)
{
    FoilKeyClass* key_class = FOIL_KEY_CLASS(klass);
    key_class->fn_generate = foil_key_aes256_generate;
    klass->size = 32;
    g_type_class_add_private(klass, klass->size);
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */