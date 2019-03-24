/*
 * Copyright (C) 2019 by Slava Monich
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

#include "test_common.h"

#include "foil_key.h"
#include "foil_cipher.h"

static
void
test_cipher_null(
    void)
{
    FoilKey* key = foil_key_generate_new(FOIL_TYPE_KEY_AES, 128);
    FoilCipher* enc = foil_cipher_new(FOIL_CIPHER_AES_CBC_ENCRYPT, key);
    FoilCipher* dec = foil_cipher_new(FOIL_CIPHER_AES_CBC_DECRYPT, key);

    /* Test resistance to NULL and all kinds of invalid parameters */
    foil_cipher_unref(NULL);
    foil_cipher_cancel_all(NULL);
    g_assert(!foil_cipher_type_name(0));
    g_assert(!foil_cipher_type_supports_key(0, 0));
    g_assert(!foil_cipher_set_padding_func(NULL, NULL));
    g_assert(!foil_cipher_set_padding_func(dec, NULL));
    g_assert(foil_cipher_set_padding_func(enc, NULL));
    g_assert(!foil_cipher_new(0, NULL));
    g_assert(!foil_cipher_new(0, key));
    g_assert(!foil_cipher_ref(NULL));
    g_assert(!foil_cipher_key(NULL));
    g_assert(!foil_cipher_name(NULL));
    g_assert(!foil_cipher_input_block_size(NULL));
    g_assert(!foil_cipher_output_block_size(NULL));
    g_assert(!foil_cipher_symmetric(NULL));
    g_assert(foil_cipher_step(NULL, NULL, NULL) < 0);
    g_assert(foil_cipher_step(dec, NULL, NULL) < 0);
    g_assert(!foil_cipher_step_async(NULL, NULL, NULL, NULL, NULL));
    g_assert(!foil_cipher_step_async(dec, NULL, NULL, NULL, NULL));
    g_assert(foil_cipher_finish(NULL, NULL, 0, NULL) < 0);
    g_assert(foil_cipher_finish(dec, NULL, -1, NULL) < 0);
    g_assert(foil_cipher_finish(dec, NULL, 0, NULL) == 0);
    g_assert(!foil_cipher_finish_async(NULL, NULL, 0, NULL, NULL, NULL));
    g_assert(!foil_cipher_finish_async(dec, NULL, -1, NULL, NULL, NULL));
    g_assert(!foil_cipher_data(0, NULL, NULL, 0));
    g_assert(!foil_cipher_data(0, NULL, NULL, 1));
    g_assert(!foil_cipher_bytes(0, NULL, NULL));

    foil_key_unref(key);
    foil_cipher_unref(enc);
    foil_cipher_unref(dec);
}

#define TEST_(name) "/cipher/" name

int main(int argc, char* argv[])
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func(TEST_("null"), test_cipher_null);
    return test_run();
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
