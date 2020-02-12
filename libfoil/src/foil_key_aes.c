/*
 * Copyright (C) 2016-2020 by Slava Monich
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

#define GLIB_DISABLE_DEPRECATION_WARNINGS

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
    if (foil_random(data, size)) {
        key = foil_key_new_from_data(type, data, size);
    }
    return key;
}

static
FoilKey*
foil_key_aes_generate_any(
    FoilKeyClass* klass,
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
FoilKey*
foil_key_aes_generate_specific(
    FoilKeyClass* klass,
    guint bits)
{
    FoilKeyAesClass* aes = FOIL_KEY_AES_CLASS(klass);
    const guint klass_bits = aes->size * 8;
    if (bits == FOIL_KEY_BITS_DEFAULT || bits == klass_bits) {
        return foil_key_aes_generate(G_TYPE_FROM_CLASS(aes), klass_bits);
    } else {
        GERR("Invalid number of bits for AES%u (%u)", klass_bits, bits);
        return NULL;
    }
}

static
FoilKey*
foil_key_aes_new(
    FoilKeyAesClass* klass,
    const void* iv,
    const void* key)
{
    FoilKeyAes* aes = g_object_new(G_TYPE_FROM_CLASS(klass), NULL);
    memcpy(aes->key, key, klass->size);
    if (iv) {
        memcpy(aes->iv, iv, FOIL_AES_BLOCK_SIZE);
    }
    return FOIL_KEY(aes);
}

static
FoilKey*
foil_key_aes_from_data(
    GType type,
    const guint8* data,
    gsize len)
{
    /* Caller has checked that size matches the type */
    FoilKeyAes* aes = g_object_new(type, NULL);
    const gsize key_size = len - FOIL_AES_BLOCK_SIZE;
    memcpy(aes->key, data, key_size);
    memcpy(aes->iv, data + key_size, FOIL_AES_BLOCK_SIZE);
    return FOIL_KEY(aes);
}

static
FoilKey*
foil_key_aes_from_data_any(
    FoilKeyClass* key_class,
    const void* data,
    gsize len,
    GHashTable* param,
    GError** error)
{
    switch (len) {
    case FOIL_AES_BLOCK_SIZE + 128/8:
        g_clear_error(error);
        return foil_key_aes_from_data(FOIL_KEY_AES128, data, len);
    case FOIL_AES_BLOCK_SIZE + 192/8:
        g_clear_error(error);
        return foil_key_aes_from_data(FOIL_KEY_AES192, data, len);
    case FOIL_AES_BLOCK_SIZE + 256/8:
        g_clear_error(error);
        return foil_key_aes_from_data(FOIL_KEY_AES256, data, len);
    default:
        if (error) {
            g_propagate_error(error, g_error_new(FOIL_ERROR,
                FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT,
                "Unsupported AES key size"));
        }
        GERR("Unsupported AES key size (%u)", (guint)len);
        return NULL;
    }
}

static
FoilKey*
foil_key_aes_from_data_specific(
    FoilKeyClass* key_class,
    const void* data,
    gsize len,
    GHashTable* param,
    GError** error)
{
    FoilKeyAesClass* klass = FOIL_KEY_AES_CLASS(key_class);
    if (len == klass->size + FOIL_AES_BLOCK_SIZE) {
        g_clear_error(error);
        return foil_key_aes_from_data(G_TYPE_FROM_CLASS(klass), data, len);
    } else {
        if (error) {
            g_propagate_error(error, g_error_new(FOIL_ERROR,
                FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT,
                "Unsupported AES%d key format", klass->size*8));
        }
        GWARN("Unsupported AES%d key format", klass->size*8);
        return NULL;
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
FoilKey*
foil_key_aes_set_iv(
    FoilKey* key,
    const void* iv,
    gsize len)
{
    if (len == FOIL_AES_BLOCK_SIZE) {
        FoilKeyAes* self = FOIL_KEY_AES_(key);
        if (iv) {
            return foil_key_aes_new(FOIL_KEY_AES_GET_CLASS(self),
                iv, self->key);
        } else {
            /* Zero the IV */
            guint i;
            for (i = 0; i < FOIL_AES_BLOCK_SIZE; i++) {
                if (self->iv[i]) {
                    return foil_key_aes_new(FOIL_KEY_AES_GET_CLASS(self),
                        NULL, self->key);
                }
            }
            /* IV is already zero, there's nothing to do */
            return foil_key_ref(key);
        }
    }
    return NULL;
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
    key_class->fn_from_data = foil_key_aes_from_data_any;
    key_class->fn_to_bytes = foil_key_aes_to_bytes;
    key_class->fn_set_iv = foil_key_aes_set_iv;
}

/* AES128 */

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
    key_class->fn_generate = foil_key_aes_generate_specific;
    key_class->fn_from_data = foil_key_aes_from_data_specific;
    klass->size = 16;
    g_type_class_add_private(klass, klass->size);
}

/* AES192 */

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
    key_class->fn_generate = foil_key_aes_generate_specific;
    key_class->fn_from_data = foil_key_aes_from_data_specific;
    klass->size = 24;
    g_type_class_add_private(klass, klass->size);
}

/* AES256 */

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
    key_class->fn_generate = foil_key_aes_generate_specific;
    key_class->fn_from_data = foil_key_aes_from_data_specific;
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
