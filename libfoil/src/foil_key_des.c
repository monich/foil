/*
 * Copyright (C) 2019 by Slava Monich
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

#include "foil_key_des_p.h"
#include "foil_random.h"
#include "foil_util_p.h"

/* Logging */
#define GLOG_MODULE_NAME foil_log_key
#include "foil_log_p.h"

G_DEFINE_ABSTRACT_TYPE(FoilKeyDes, foil_key_des, FOIL_TYPE_KEY);

static const guint8 foil_key_des_parity[256] = {
    0x01, 0x01, 0x02, 0x02, 0x04, 0x04, 0x07, 0x07,
    0x08, 0x08, 0x0B, 0x0B, 0x0D, 0x0D, 0x0E, 0x0E,
    0x10, 0x10, 0x13, 0x13, 0x15, 0x15, 0x16, 0x16,
    0x19, 0x19, 0x1A, 0x1A, 0x1C, 0x1C, 0x1F, 0x1F,
    0x20, 0x20, 0x23, 0x23, 0x25, 0x25, 0x26, 0x26,
    0x29, 0x29, 0x2A, 0x2A, 0x2C, 0x2C, 0x2F, 0x2F,
    0x31, 0x31, 0x32, 0x32, 0x34, 0x34, 0x37, 0x37,
    0x38, 0x38, 0x3B, 0x3B, 0x3D, 0x3D, 0x3E, 0x3E,
    0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46,
    0x49, 0x49, 0x4A, 0x4A, 0x4C, 0x4C, 0x4F, 0x4F,
    0x51, 0x51, 0x52, 0x52, 0x54, 0x54, 0x57, 0x57,
    0x58, 0x58, 0x5B, 0x5B, 0x5D, 0x5D, 0x5E, 0x5E,
    0x61, 0x61, 0x62, 0x62, 0x64, 0x64, 0x67, 0x67,
    0x68, 0x68, 0x6B, 0x6B, 0x6D, 0x6D, 0x6E, 0x6E,
    0x70, 0x70, 0x73, 0x73, 0x75, 0x75, 0x76, 0x76,
    0x79, 0x79, 0x7A, 0x7A, 0x7C, 0x7C, 0x7F, 0x7F,
    0x80, 0x80, 0x83, 0x83, 0x85, 0x85, 0x86, 0x86,
    0x89, 0x89, 0x8A, 0x8A, 0x8C, 0x8C, 0x8F, 0x8F,
    0x91, 0x91, 0x92, 0x92, 0x94, 0x94, 0x97, 0x97,
    0x98, 0x98, 0x9B, 0x9B, 0x9D, 0x9D, 0x9E, 0x9E,
    0xA1, 0xA1, 0xA2, 0xA2, 0xA4, 0xA4, 0xA7, 0xA7,
    0xA8, 0xA8, 0xAB, 0xAB, 0xAD, 0xAD, 0xAE, 0xAE,
    0xB0, 0xB0, 0xB3, 0xB3, 0xB5, 0xB5, 0xB6, 0xB6,
    0xB9, 0xB9, 0xBA, 0xBA, 0xBC, 0xBC, 0xBF, 0xBF,
    0xC1, 0xC1, 0xC2, 0xC2, 0xC4, 0xC4, 0xC7, 0xC7,
    0xC8, 0xC8, 0xCB, 0xCB, 0xCD, 0xCD, 0xCE, 0xCE,
    0xD0, 0xD0, 0xD3, 0xD3, 0xD5, 0xD5, 0xD6, 0xD6,
    0xD9, 0xD9, 0xDA, 0xDA, 0xDC, 0xDC, 0xDF, 0xDF,
    0xE0, 0xE0, 0xE3, 0xE3, 0xE5, 0xE5, 0xE6, 0xE6,
    0xE9, 0xE9, 0xEA, 0xEA, 0xEC, 0xEC, 0xEF, 0xEF,
    0xF1, 0xF1, 0xF2, 0xF2, 0xF4, 0xF4, 0xF7, 0xF7,
    0xF8, 0xF8, 0xFB, 0xFB, 0xFD, 0xFD, 0xFE, 0xFE
};

void
foil_key_des_adjust_parity(
    void* key)
{
    if (G_LIKELY(key)) {
        guint8* ptr = key;
        guint8* end = ptr + FOIL_DES_KEY_SIZE;
        while (ptr < end) {
            *ptr = foil_key_des_parity[*ptr];
            ptr++;
        }
    }
}

FoilKey*
foil_key_des_new(
    const guint8* iv /* Optional */,
    const guint8* key1,
    const guint8* key2,
    const guint8* key3 /* Optional */) /* Since 1.0.16 */
{
    FoilKey* key = NULL;
    if (G_LIKELY(key1)) {
        FoilKeyDesClass* cls = foil_class_ref(FOIL_KEY_DES, FOIL_TYPE_KEY_DES);
        if (cls) {
            if (cls->fn_valid(cls, key1) &&
                (!key2 || cls->fn_valid(cls, key2)) &&
                (!key3 || cls->fn_valid(cls, key3))) {
                FoilKeyDes* des = cls->fn_create(cls, iv, key1, key2, key3);
                if (des) {
                    key = FOIL_KEY(des);
                }
            }
            g_type_class_unref(cls);
        }
    }
    return key;
}

FoilKey*
foil_key_des_new_from_bytes(
    GBytes* iv /* Optional */,
    GBytes* key1,
    GBytes* key2,
    GBytes* key3 /* Optional */) /* Since 1.0.16 */
{
    if (G_LIKELY(key1)) {
        gsize iv_size = 0, size1, size2 = 0, size3 = 0;
        const guint8* iv_ptr = iv ? g_bytes_get_data(iv, &iv_size) : NULL;
        const guint8* key1_ptr = g_bytes_get_data(key1, &size1);
        const guint8* key2_ptr = key2 ? g_bytes_get_data(key2, &size2) : NULL;
        const guint8* key3_ptr = key3 ? g_bytes_get_data(key3, &size3) : NULL;
        if (G_LIKELY(size1 == FOIL_DES_KEY_SIZE) &&
            G_LIKELY(!key2 || size2 == FOIL_DES_IV_SIZE) &&
            G_LIKELY(!key3 || size3 == FOIL_DES_IV_SIZE) &&
            G_LIKELY(!iv || iv_size == FOIL_DES_IV_SIZE)) {
            return foil_key_des_new(iv_ptr, key1_ptr, key2_ptr, key3_ptr);
        }
    }
    return NULL;
}

static
gboolean
foil_key_des_generate_key(
    FoilKeyDesClass* klass,
    guint8* key)
{
    do {
        if (!foil_random(key, FOIL_DES_KEY_SIZE)) {
            return FALSE;
        }
        foil_key_des_adjust_parity(key);
    } while (!klass->fn_valid(klass, key));
    return TRUE;
}

static
FoilKey*
foil_key_des_generate(
    FoilKeyClass* key_klass,
    guint bits)
{
    FoilKeyDesClass* klass = FOIL_KEY_DES_CLASS(key_klass);
    FoilKeyDes* key = NULL;
    guint8 iv[FOIL_DES_IV_SIZE];
    if (foil_random(iv, sizeof(iv))) {
        guint8 key1[FOIL_DES_KEY_SIZE];
        guint8 key2[FOIL_DES_KEY_SIZE];
        guint8 key3[FOIL_DES_KEY_SIZE];
        switch (bits) {
        case FOIL_KEY_BITS_DEFAULT: bits = FOIL_DES_KEY_BITS*3; /* no break */
        case FOIL_DES_KEY_BITS*3:
            /* Keying option 1 */
            if (foil_key_des_generate_key(klass, key1) &&
                foil_key_des_generate_key(klass, key2) &&
                foil_key_des_generate_key(klass, key3)) {
                key = klass->fn_create(klass, iv, key1, key2, key3);
            }
            break;
        case FOIL_DES_KEY_BITS*2:
            /* Keying option 2 */
            if (foil_key_des_generate_key(klass, key1) &&
                foil_key_des_generate_key(klass, key2)) {
                key = klass->fn_create(klass, iv, key1, key2, NULL);
            }
            break;
        case FOIL_DES_KEY_BITS:
            /* Keying option 3 (deprecated) */
            if (foil_key_des_generate_key(klass, key1)) {
                key = klass->fn_create(klass, iv, key1, NULL, NULL);
            }
            break;
        default:
            GERR("Invalid number of bits for Triple DES (%u)", bits);
            break;
        }
    }
    return key ? &key->super : NULL;
}

static
FoilKey*
foil_key_des_from_data(
    FoilKeyClass* key_class,
    const void* data,
    gsize len,
    GHashTable* param,
    GError** error)
{
    FoilKeyDesClass* klass = FOIL_KEY_DES_CLASS(key_class);
    const guint8* iv = data;
    const guint8* key1 = iv + FOIL_DES_IV_SIZE;
    const guint8* key2;
    const guint8* key3;
    FoilKeyDes* key = NULL;

    switch (len) {
    case FOIL_DES_IV_SIZE + FOIL_DES_KEY_SIZE*3:
        /* Keying option 1 */
        key2 = key1 + FOIL_DES_KEY_SIZE;
        key3 = key2 + FOIL_DES_KEY_SIZE;
        key = klass->fn_create(klass, iv, key1, key2, key3);
        break;
    case FOIL_DES_IV_SIZE + FOIL_DES_KEY_SIZE*2:
        /* Keying option 2 */
        key2 = key1 + FOIL_DES_KEY_SIZE;
        key = klass->fn_create(klass, iv, key1, key2, NULL);
        break;
    case FOIL_DES_IV_SIZE + FOIL_DES_KEY_SIZE:
        /* Keying option 3 (deprecated) */
        key = klass->fn_create(klass, iv, key1, NULL, NULL);
        break;
    default:
        GERR("Invalid key size for DES (%u bytes)", (guint)len);
        key = NULL;
        break;
    }

    /* Creation function validates the keys and may fail */
    if (key) {
        return FOIL_KEY(key);
    } else {
        if (error) {
            g_propagate_error(error, g_error_new(FOIL_ERROR,
                FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT,
                "Invalid DES key"));
        }
        return NULL;
    }
}

static
gboolean
foil_key_des_equal(
    FoilKey* key1,
    FoilKey* key2)
{
    GASSERT(FOIL_IS_KEY_DES(key1));
    if (FOIL_IS_KEY_DES(key2)) {
        const FoilKeyDes* des1 = FOIL_KEY_DES_(key1);
        const FoilKeyDes* des2 = FOIL_KEY_DES_(key2);
        return !memcmp(des1->iv, des2->iv, FOIL_DES_IV_SIZE) &&
            !memcmp(des1->key1, des2->key1, FOIL_DES_KEY_SIZE) &&
            ((!des1->key2 && !des2->key2) || (des1->key2 && des2->key2 &&
            !memcmp(des1->key2, des2->key2, FOIL_DES_KEY_SIZE))) &&
            ((!des1->key3 && !des2->key3) || (des1->key3 && des2->key3 &&
            !memcmp(des1->key3, des2->key3, FOIL_DES_KEY_SIZE)));
    }
    return FALSE;
}

static
GBytes*
foil_key_des_to_bytes(
    FoilKey* key)
{
    FoilKeyDes* self = FOIL_KEY_DES_(key);
    guint8* bytes;
    gsize size = FOIL_DES_IV_SIZE + FOIL_DES_KEY_SIZE;
    if (self->key2) {
        size += FOIL_DES_KEY_SIZE;
        if (self->key3) {
            size += FOIL_DES_KEY_SIZE;
        }
    }
    bytes = g_malloc(size);
    memcpy(bytes, self->iv, FOIL_DES_IV_SIZE);
    memcpy(bytes + FOIL_DES_IV_SIZE, self->key1, FOIL_DES_KEY_SIZE);
    if (self->key2) {
        memcpy(bytes + FOIL_DES_IV_SIZE + FOIL_DES_KEY_SIZE,
            self->key2, FOIL_DES_KEY_SIZE);
        if (self->key3) {
            memcpy(bytes + FOIL_DES_IV_SIZE + FOIL_DES_KEY_SIZE * 2,
                self->key3, FOIL_DES_KEY_SIZE);
        }
    }
    return g_bytes_new_take(bytes, size);
}

static
FoilKey*
foil_key_des_set_iv(
    FoilKey* key,
    const void* iv,
    gsize len)
{
    if (len == FOIL_DES_IV_SIZE) {
        FoilKeyDes* self = FOIL_KEY_DES_(key);
        if (iv) {
            FoilKeyDesClass* klass = FOIL_KEY_DES_GET_CLASS(self);
            FoilKeyDes* out = klass->fn_create(klass, iv,
               self->key1, self->key2, self->key3);
            return FOIL_KEY(out);
        } else {
            /* Zero the IV */
            guint i;
            for (i = 0; i < FOIL_DES_IV_SIZE; i++) {
                if (self->iv[i]) {
                    FoilKeyDesClass* klass = FOIL_KEY_DES_GET_CLASS(self);
                    FoilKeyDes* out = klass->fn_create(klass, NULL,
                        self->key1, self->key2, self->key3);
                    return FOIL_KEY(out);
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
foil_key_des_init(
    FoilKeyDes* key)
{
}

static
void
foil_key_des_class_init(
    FoilKeyDesClass* klass)
{
    FoilKeyClass* key_class = FOIL_KEY_CLASS(klass);
    key_class->fn_generate = foil_key_des_generate;
    key_class->fn_equal = foil_key_des_equal;
    key_class->fn_from_data = foil_key_des_from_data;
    key_class->fn_to_bytes = foil_key_des_to_bytes;
    key_class->fn_set_iv = foil_key_des_set_iv;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
