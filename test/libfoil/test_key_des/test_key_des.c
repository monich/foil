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

#include "test_common.h"

#include "foil_key_des_p.h"

static
void
test_null(
    void)
{
    static guint8 data[FOIL_DES_BLOCK_SIZE];
    GBytes* bytes = g_bytes_new_static(data, sizeof(data));

    foil_key_des_adjust_parity(NULL);
    g_assert(!foil_key_des_new(NULL, NULL, NULL, NULL));
    g_assert(!foil_key_des_new(data, NULL, NULL, NULL));
    g_assert(!foil_key_des_new(data, data, NULL, NULL));
    g_assert(!foil_key_des_new_from_bytes(NULL, NULL, NULL, NULL));
    g_assert(!foil_key_des_new_from_bytes(bytes, NULL, NULL, NULL));
    g_assert(!foil_key_des_new_from_bytes(bytes, bytes, NULL, NULL));
    g_bytes_unref(bytes);
}

static
void
test_parity(
    void)
{
    static const guint8 in[FOIL_DES_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    static const guint8 out[FOIL_DES_KEY_SIZE] = {
        0x01, 0x01, 0x02, 0x02, 0x04, 0x04, 0x07, 0x07
    };
    guint8 key[FOIL_DES_KEY_SIZE];
    memcpy(key, in, FOIL_DES_KEY_SIZE);
    foil_key_des_adjust_parity(key);
    g_assert(!memcmp(key, out, FOIL_DES_KEY_SIZE));
}

static
void
test_invalid(
    void)
{
    static const guint8 good[] = { 0x76,0x64,0x52,0x49,0x5b,0xbf,0x79,0x7c };
    static const guint8 bad[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07 };
    static const guint8 too_short[] = { 0x76,0x64,0x52,0x49,0x5b,0xbf,0x79 };
    static const guint8 too_long[] =
        { 0x76,0x64,0x52,0x49,0x5b,0xbf,0x79,0x7c, 0x7c };
    GBytes* good_bytes = g_bytes_new_static(good, sizeof(good));
    GBytes* bad_bytes = g_bytes_new_static(bad, sizeof(bad));
    GBytes* short_bytes = g_bytes_new_static(too_short, sizeof(too_short));
    GBytes* long_bytes = g_bytes_new_static(too_long, sizeof(too_long));

    /* Length check */
    g_assert(!foil_key_des_new_from_bytes(short_bytes,
        good_bytes, good_bytes, good_bytes));
    g_assert(!foil_key_des_new_from_bytes(good_bytes,
        short_bytes, good_bytes, good_bytes));
    g_assert(!foil_key_des_new_from_bytes(good_bytes,
        good_bytes, short_bytes, good_bytes));
    g_assert(!foil_key_des_new_from_bytes(good_bytes,
        good_bytes, good_bytes, short_bytes));

    /* Parity check */
    g_assert(!foil_key_des_new_from_bytes(good_bytes,
        bad_bytes, good_bytes, good_bytes));
    g_assert(!foil_key_des_new_from_bytes(good_bytes,
        good_bytes, bad_bytes, good_bytes));
    g_assert(!foil_key_des_new_from_bytes(good_bytes,
        good_bytes, good_bytes, bad_bytes));

    g_bytes_unref(good_bytes);
    g_bytes_unref(bad_bytes);
    g_bytes_unref(short_bytes);
    g_bytes_unref(long_bytes);
}

static
void
test_basic(
    void)
{
    static const guint8 iv[] = {0x20,0x0e,0x89,0xb4,0x09,0x7e,0xf9,0x67};
    static const guint8 k1[] = {0x8a,0x4c,0x10,0x10,0xdf,0xfe,0x2f,0x52};
    static const guint8 k2[] = {0xdf,0x1c,0xc2,0xe9,0xa1,0xab,0xe5,0x5d};
    static const guint8 k3[] = {0xce,0x86,0xe0,0x7c,0x1c,0x8a,0x4a,0x13};
    GBytes* b0 = g_bytes_new_static(iv, sizeof(iv));
    GBytes* b1 = g_bytes_new_static(k1, sizeof(k1));
    GBytes* b2 = g_bytes_new_static(k2, sizeof(k2));
    GBytes* b3 = g_bytes_new_static(k3, sizeof(k3));
    FoilKey* key = foil_key_des_new_from_bytes(b0, b1, b2, b3);
    FoilKey* key2 = foil_key_des_new_from_bytes(b0, b1, b2, NULL);
    FoilKey* key3 = foil_key_set_iv(key2, NULL, FOIL_DES_IV_SIZE);
    FoilKeyDes* des = FOIL_KEY_DES_(key);
    FoilKeyDes* des2 = FOIL_KEY_DES_(key2);
    GBytes* serialized = foil_key_to_bytes(key);
    FoilKey* deserialized = foil_key_new_from_bytes(FOIL_KEY_DES, serialized);
    GError* error = NULL;

    /* If IV is already zero, foil_key_set_iv works like foil_key_ref */
    g_assert(foil_key_set_iv(key3, NULL, FOIL_DES_IV_SIZE) == key3);
    foil_key_unref(key3);

    /* Wrong IV size */
    g_assert(!foil_key_set_iv(key3, NULL, FOIL_DES_IV_SIZE - 1));

    /* Make sure everything is copied correctly */
    g_assert(des);
    g_assert(!memcmp(des->iv, iv, FOIL_DES_IV_SIZE));
    g_assert(!memcmp(des->key1, k1, FOIL_DES_KEY_SIZE));
    g_assert(!memcmp(des->key2, k2, FOIL_DES_KEY_SIZE));
    g_assert(!memcmp(des->key3, k3, FOIL_DES_KEY_SIZE));

    g_assert(des2);
    g_assert(!memcmp(des2->iv, iv, FOIL_DES_IV_SIZE));
    g_assert(!memcmp(des2->key1, k1, FOIL_DES_KEY_SIZE));
    g_assert(!memcmp(des2->key2, k2, FOIL_DES_KEY_SIZE));
    g_assert(!des2->key3);

   /* Deserialized key must match the original */
    g_assert(serialized);
    g_assert(deserialized);
    g_assert(foil_key_equal(key, deserialized));

    /* b0 doesn't contain enough data */
    g_assert(!foil_key_new_from_bytes(FOIL_KEY_DES, b0));
    g_assert(!foil_key_new_from_bytes_full(FOIL_KEY_DES, b0, NULL, &error));
    g_assert(error);
    g_assert(error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT);
    g_error_free(error);

    foil_key_unref(key);
    foil_key_unref(key2);
    foil_key_unref(key3);
    foil_key_unref(deserialized);
    g_bytes_unref(serialized);
    g_bytes_unref(b0);
    g_bytes_unref(b1);
    g_bytes_unref(b2);
    g_bytes_unref(b3);
}

static
void
test_generate(
    void)
{
    FoilKey* key1 = foil_key_generate_new(FOIL_KEY_DES, FOIL_DES_KEY_BITS);
    FoilKey* key2 = foil_key_generate_new(FOIL_KEY_DES, FOIL_DES_KEY_BITS*2);
    FoilKey* key3 = foil_key_generate_new(FOIL_KEY_DES, FOIL_DES_KEY_BITS*3);
    FoilKey* key4 = foil_key_generate_new(FOIL_KEY_DES, FOIL_KEY_BITS_DEFAULT);
    FoilKeyDes* des1 = FOIL_KEY_DES_(key1);
    FoilKeyDes* des2 = FOIL_KEY_DES_(key2);
    FoilKeyDes* des3 = FOIL_KEY_DES_(key3);
    FoilKeyDes* des4 = FOIL_KEY_DES_(key4);
    GBytes* serialized1 = foil_key_to_bytes(key1);
    GBytes* serialized2 = foil_key_to_bytes(key2);
    GBytes* serialized3 = foil_key_to_bytes(key3);
    FoilKey* deserialized1 = foil_key_new_from_bytes(FOIL_KEY_DES, serialized1);
    FoilKey* deserialized2 = foil_key_new_from_bytes(FOIL_KEY_DES, serialized2);
    FoilKey* deserialized3 = foil_key_new_from_bytes(FOIL_KEY_DES, serialized3);

    /* Invalid number of bits */
    g_assert(!foil_key_generate_new(FOIL_KEY_DES, 2));

    g_assert(key1);
    g_assert(des1->key1);
    g_assert(!des1->key2);
    g_assert(!des1->key3);

    g_assert(key2);
    g_assert(des2->key1);
    g_assert(des2->key2);
    g_assert(!des2->key3);

    g_assert(key3);
    g_assert(des3->key1);
    g_assert(des3->key2);
    g_assert(des3->key3);

    g_assert(key4);
    g_assert(des4->key1);
    g_assert(des4->key2);
    g_assert(des4->key3); /* Default is Triple-DES */

    g_assert(!foil_key_equal(key1, key2));
    g_assert(!foil_key_equal(key2, key1));
    g_assert(!foil_key_equal(key2, key3));
    g_assert(!foil_key_equal(key3, key2));
    foil_key_equal(key1, deserialized1);
    foil_key_equal(key2, deserialized2);
    foil_key_equal(key3, deserialized3);

    g_bytes_unref(serialized1);
    g_bytes_unref(serialized2);
    g_bytes_unref(serialized3);
    foil_key_unref(key1);
    foil_key_unref(key2);
    foil_key_unref(key3);
    foil_key_unref(key4);
    foil_key_unref(deserialized1);
    foil_key_unref(deserialized2);
    foil_key_unref(deserialized3);
}

static
void
test_compare(
    void)
{
    static const guint8 iv[] = {0x20,0x0e,0x89,0xb4,0x09,0x7e,0xf9,0x67};
    static const guint8 k1[] = {0x8a,0x4c,0x10,0x10,0xdf,0xfe,0x2f,0x52};
    static const guint8 k2[] = {0xdf,0x1c,0xc2,0xe9,0xa1,0xab,0xe5,0x5d};
    static const guint8 k3[] = {0xce,0x86,0xe0,0x7c,0x1c,0x8a,0x4a,0x13};

    FoilKey* key1 = foil_key_des_new(iv, k1, k2, k3);
    FoilKey* key2 = foil_key_des_new(iv, k1, k2, k3);
    FoilKey* key3 = foil_key_des_new(iv, k2, k1, k3);
    FoilKey* key4 = foil_key_des_new(iv, k1, k3, k2);
    FoilKey* key5 = foil_key_des_new(iv, k1, k3, k3);
    FoilKey* key6 = foil_key_des_new(k1, k1, k3, k3);
    FoilKey* key7 = foil_key_des_new(iv, k1, k3, NULL);
    FoilKey* key8 = foil_key_des_new(iv, k1, k3, NULL);
    FoilKey* key9 = foil_key_des_new(iv, k1, NULL, NULL);
    FoilKey* key10 = foil_key_des_new(iv, k2, NULL, NULL);
    FoilKey* aes = foil_key_generate_new(FOIL_KEY_AES128,
        FOIL_KEY_BITS_DEFAULT);

    g_assert(foil_key_equal(key1, key2));
    g_assert(foil_key_equal(key7, key8));
    g_assert(!foil_key_equal(key1, aes));
    g_assert(!foil_key_equal(key1, key3));
    g_assert(!foil_key_equal(key1, key4));
    g_assert(!foil_key_equal(key4, key5));
    g_assert(!foil_key_equal(key1, key5));
    g_assert(!foil_key_equal(key1, key6));
    g_assert(!foil_key_equal(key1, key7));
    g_assert(!foil_key_equal(key5, key7));
    g_assert(!foil_key_equal(key6, key7));
    g_assert(!foil_key_equal(key7, key5));
    g_assert(!foil_key_equal(key7, key6));
    g_assert(!foil_key_equal(key9, key8));
    g_assert(!foil_key_equal(key8, key9));
    g_assert(!foil_key_equal(key9, key10));

    foil_key_unref(aes);
    foil_key_unref(key1);
    foil_key_unref(key2);
    foil_key_unref(key3);
    foil_key_unref(key4);
    foil_key_unref(key5);
    foil_key_unref(key6);
    foil_key_unref(key7);
    foil_key_unref(key8);
    foil_key_unref(key9);
    foil_key_unref(key10);
}

#define TEST_(name) "/key_des/" name

int main(int argc, char* argv[])
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func(TEST_("null"), test_null);
    g_test_add_func(TEST_("parity"), test_parity);
    g_test_add_func(TEST_("invalid"), test_invalid);
    g_test_add_func(TEST_("basic"), test_basic);
    g_test_add_func(TEST_("generate"), test_generate);
    g_test_add_func(TEST_("compare"), test_compare);
    return test_run();
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
