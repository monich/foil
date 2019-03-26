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

#include "foil_cipher.h"
#include "foil_cmac.h"
#include "foil_key.h"

static
void
test_null(
    void)
{
    g_assert(!foil_cmac_new(NULL));
    g_assert(!foil_cmac_ref(NULL));
    g_assert(!foil_cmac_finish(NULL));
    g_assert(!foil_cmac_free_to_bytes(NULL));
    foil_cmac_update(NULL, NULL, 0);
    foil_cmac_unref(NULL);
}

static
void
test_basic(
    void)
{
    FoilKey* rsa_key = foil_key_generate_new(FOIL_KEY_RSA_PRIVATE, 0);
    FoilKey* aes_key = foil_key_generate_new(FOIL_KEY_AES128, 0);
    FoilCipher* rsa = foil_cipher_new(FOIL_CIPHER_RSA_ENCRYPT, rsa_key);
    FoilCipher* aes = foil_cipher_new(FOIL_CIPHER_AES_CBC_ENCRYPT, aes_key);
    FoilCmac* cmac;
    GBytes* mac;

    /* Symmetric cipher is required */
    g_assert(!foil_cmac_new(rsa));
    cmac = foil_cmac_new(aes);
    foil_cmac_unref(foil_cmac_ref(cmac));
    mac = foil_cmac_finish(cmac);
    g_assert(foil_cmac_free_to_bytes(cmac) == mac);
    g_assert(g_bytes_get_size(mac)==(gsize)foil_cipher_input_block_size(aes));
    g_bytes_unref(mac);
    foil_key_unref(rsa_key);
    foil_key_unref(aes_key);
    foil_cipher_unref(aes);
    foil_cipher_unref(rsa);
}

#define TEST_(name) "/cmac/" name

int main(int argc, char* argv[])
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func(TEST_("null"), test_null);
    g_test_add_func(TEST_("basic"), test_basic);
    return test_run();
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
