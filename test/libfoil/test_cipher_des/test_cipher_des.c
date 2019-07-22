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

#include "foil_key_des.h"
#include "foil_cipher.h"

#define DATA_DIR "data/"

static
void
test_padding(
    guint8* block,
    gsize data_size,
    gsize block_size)
{
    memset(block + data_size, 0xaa, block_size - data_size);
}

static
void
test_basic(
    void)
{
    FoilKey* key = foil_key_generate_new(FOIL_KEY_DES, FOIL_KEY_BITS_DEFAULT);
    FoilCipher* enc = foil_cipher_new(FOIL_CIPHER_DES_CBC_ENCRYPT, key);
    FoilCipher* dec = foil_cipher_new(FOIL_CIPHER_DES_CBC_DECRYPT, key);

    g_assert(!foil_cipher_type_supports_key(FOIL_CIPHER_DES_CBC_ENCRYPT,0));
    g_assert(!foil_cipher_type_supports_key(FOIL_CIPHER_DES_CBC_DECRYPT,0));
    g_assert(!foil_cipher_type_supports_key(FOIL_KEY_DES, 0));
    g_assert(foil_cipher_symmetric(enc));
    g_assert(foil_cipher_symmetric(dec));
    g_assert(foil_cipher_set_padding_func(enc, test_padding));

    foil_key_unref(key);
    foil_cipher_unref(enc);
    foil_cipher_unref(dec);
}

static
void
test_sample(
    void)
{
    /*
     * NIST Special Publication 800-17
     * Appendix A. Sample Round Outputs for the DES
     */
    static const guint8 key[] = {0x10,0x31,0x6E,0x02,0x8C,0x8F,0x3B,0x4A};
    static const guint8 in[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    static const guint8 answer[] = {0x82,0xDC,0xBA,0xFB,0xDE,0xAB,0x66,0x02};

    FoilKey* k = foil_key_des_new(NULL, key, NULL, NULL);
    GBytes* enc_bytes = foil_cipher_data(FOIL_CIPHER_DES_CBC_ENCRYPT,
        k, in, sizeof(in));
    GBytes* dec_bytes = foil_cipher_bytes(FOIL_CIPHER_DES_CBC_DECRYPT,
        k, enc_bytes);
    gsize enc_size, dec_size;
    const guint8* enc_data = g_bytes_get_data(enc_bytes, &enc_size);
    const guint8* dec_data = g_bytes_get_data(dec_bytes, &dec_size);

    g_assert(enc_size == FOIL_DES_BLOCK_SIZE);
    g_assert(dec_size == FOIL_DES_BLOCK_SIZE);
    g_assert(!memcmp(enc_data, answer, enc_size));
    g_assert(!memcmp(dec_data, in, dec_size));
    g_bytes_unref(enc_bytes);
    g_bytes_unref(dec_bytes);
    foil_key_unref(k);
}

static
void
test_clone(
    const guint8* iv,
    const guint8* k1,
    const guint8* k2,
    const guint8* k3)
{
    static const guint8 in[] = {
        'T', 'h', 'i', 's', ' ', 'i', 's', ' ',
        'a', ' ', 't', 'e', 's', 't'
    };
    guint8 out1[2 * FOIL_DES_BLOCK_SIZE];
    guint8 out2[sizeof(out1)];
    FoilKey* key = foil_key_des_new(iv, k1, k2, k3);
    FoilCipher* enc1 = foil_cipher_new(FOIL_CIPHER_DES_CBC_ENCRYPT, key);
    FoilCipher* enc2;

    g_assert(foil_cipher_set_padding_func(enc1, test_padding));

    /* Make one step */
    memset(out1, 0, sizeof(out1));
    memset(out2, 0, sizeof(out2));
    g_assert(foil_cipher_step(enc1, in, out1) == FOIL_DES_BLOCK_SIZE);
    memcpy(out2, out1, FOIL_DES_BLOCK_SIZE);

    /* Clone the current state */
    enc2 = foil_cipher_clone(enc1);

    /* Finish the encryption process independently */
    g_assert(foil_cipher_finish(enc1, in + FOIL_DES_BLOCK_SIZE,
        sizeof(in) - FOIL_DES_BLOCK_SIZE, out1 + FOIL_DES_BLOCK_SIZE) ==
        FOIL_DES_BLOCK_SIZE);
    g_assert(foil_cipher_finish(enc2, in + FOIL_DES_BLOCK_SIZE,
        sizeof(in) - FOIL_DES_BLOCK_SIZE, out2 + FOIL_DES_BLOCK_SIZE) ==
        FOIL_DES_BLOCK_SIZE);

    /* The result must be the same */
    g_assert(!memcmp(out1, out2, sizeof(out1)));

    foil_key_unref(key);
    foil_cipher_unref(enc1);
    foil_cipher_unref(enc2);
}

static
void
test_clone1(
    void)
{
    static const guint8 iv[] = {0x03,0x49,0x76,0x24,0xec,0xcc,0x76,0xc7};
    static const guint8 k1[] = {0x76,0x64,0x52,0x49,0x5b,0xbf,0x79,0x7c};

    test_clone(iv, k1, NULL, NULL);
}

static
void
test_clone2(
    void)
{
    static const guint8 iv[] = {0x20,0x0e,0x89,0xb4,0x09,0x7e,0xf9,0x67};
    static const guint8 k1[] = {0x16,0x0b,0x70,0xad,0x26,0xe6,0x0e,0x8a};
    static const guint8 k2[] = {0x1a,0xda,0xdc,0xc2,0x40,0x61,0x9e,0xc2};

    test_clone(iv, k1, k2, NULL);
}

static
void
test_clone3(
    void)
{
    static const guint8 iv[] = {0x96,0x56,0x7f,0xf6,0x2c,0x6b,0xfa,0x95};
    static const guint8 k1[] = {0x49,0x8a,0xdf,0x3b,0x0e,0x0e,0x0d,0xce};
    static const guint8 k2[] = {0x8c,0x91,0x7c,0xfd,0x19,0xa8,0x38,0x02};
    static const guint8 k3[] = {0x49,0x8a,0xdf,0x3b,0x0e,0x0e,0x0d,0xce};

    test_clone(iv, k1, k2, k3);
}

#define TEST_(name) "/cipher_des/" name

int main(int argc, char* argv[])
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func(TEST_("basic"), test_basic);
    g_test_add_func(TEST_("sample"), test_sample);
    g_test_add_func(TEST_("clone1"), test_clone1);
    g_test_add_func(TEST_("clone2"), test_clone2);
    g_test_add_func(TEST_("clone3"), test_clone3);
    return test_run();
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
