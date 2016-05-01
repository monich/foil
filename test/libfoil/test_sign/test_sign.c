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

#include "test_common.h"

#include "foil_sign.h"
#include "foil_cipher.h"
#include "foil_digest.h"
#include "foil_private_key.h"
#include "foil_util.h"

#define DATA_DIR "data/"

typedef struct test_sign {
    const char* name;
    GTestDataFunc fn;
    const char* priv;
    const char* pub;
    int damage;
} TestSign;

#define BYTES_SET(b,d) ((b).val = (d), (b).len = sizeof(d))

static
void
test_sign_invalid(
    void)
{
    static const guint8 data[] = { '1', '2', '3' };
    char* priv_path = g_strconcat(DATA_DIR, "rsa-768", NULL);
    char* pub_path = g_strconcat(DATA_DIR, "rsa-768.pub", NULL);
    FoilPrivateKey* priv = foil_private_key_new_from_file(FOIL_KEY_RSA_PRIVATE,
        priv_path);
    FoilKey* pub = foil_key_new_from_file(FOIL_KEY_RSA_PUBLIC, pub_path);
    FoilBytes bytes, sign_bytes;
    GBytes* sign;

    g_assert(priv);
    g_assert(pub);
    BYTES_SET(bytes, data);

    /* Test NULL resistance */
    g_assert(!foil_rsa_sign(NULL, FOIL_DIGEST_MD5, NULL));
    g_assert(!foil_rsa_sign(&bytes, FOIL_DIGEST_MD5, NULL));
    g_assert(!foil_rsa_sign(NULL, FOIL_DIGEST_MD5, priv));
    g_assert(!foil_rsa_verify(NULL, NULL, FOIL_DIGEST_MD5, NULL));
    g_assert(!foil_rsa_verify(&bytes, NULL, FOIL_DIGEST_MD5, NULL));
    g_assert(!foil_rsa_verify(&bytes, &bytes, FOIL_DIGEST_MD5, NULL));

    /* Test resistance to invalid arguments (invalid digest type) */
    g_assert(!foil_rsa_sign(&bytes, 0, priv));

    sign = foil_rsa_sign(&bytes, FOIL_DIGEST_SHA1, priv);
    g_assert(sign);
    foil_bytes_from_data(&sign_bytes, sign);
    g_assert(!foil_rsa_verify(&bytes, &sign_bytes, 0, pub));

    foil_private_key_unref(priv);
    foil_key_unref(pub);
    g_bytes_unref(sign);
    g_free(priv_path);
    g_free(pub_path);
}

static
void
test_sign(
    gconstpointer param)
{
    const TestSign* test = param;
    static const guint8 input[] = { '1', '2', '3' };
    GType digest_type = FOIL_DIGEST_MD5;
    char* priv_path = g_strconcat(DATA_DIR, test->priv, NULL);
    char* pub_path = g_strconcat(DATA_DIR, test->pub, NULL);
    FoilPrivateKey* priv = foil_private_key_new_from_file(FOIL_KEY_RSA_PRIVATE,
        priv_path);
    FoilKey* pub = foil_key_new_from_file(FOIL_KEY_RSA_PUBLIC, pub_path);
    GBytes* sign;
    FoilBytes in_bytes;
    FoilBytes sign_bytes;
    
    BYTES_SET(in_bytes, input);
    sign = foil_rsa_sign(&in_bytes, digest_type, priv);
    g_assert(sign);
    TEST_DEBUG_HEXDUMP_BYTES(sign);
    foil_bytes_from_data(&sign_bytes, sign);
    if (test->damage >= 0) {
        guint8* ptr = (void*)sign_bytes.val;
        ptr[test->damage] ^= ptr[test->damage];
        /* Verification of a damaged signature must fail */
        g_assert(!foil_rsa_verify(&in_bytes, &sign_bytes, digest_type, pub));
    } else {
        g_assert(foil_rsa_verify(&in_bytes, &sign_bytes, digest_type, pub));
    }

    g_bytes_unref(sign);
    foil_private_key_unref(priv);
    foil_key_unref(pub);
    g_free(priv_path);
    g_free(pub_path);
}

/* Test descriptors */

#define TEST_(name) "/sign/" name
#define TEST_SIGN_OK(name) \
    { TEST_("sign-ok-" name), test_sign, name, name ".pub", -1 }
#define TEST_VERIFY_FAIL(name,damage) \
    { TEST_("verify-err-" name), test_sign, name, name ".pub", damage }

static const TestSign tests[] = {
    TEST_SIGN_OK("rsa-768"),
    TEST_SIGN_OK("rsa-1024"),
    TEST_SIGN_OK("rsa-1500"),
    TEST_SIGN_OK("rsa-2048"),
    TEST_VERIFY_FAIL("rsa-768", 0),
    TEST_VERIFY_FAIL("rsa-1024", 1),
    TEST_VERIFY_FAIL("rsa-1500", 2),
    TEST_VERIFY_FAIL("rsa-2048", 3),
};

int main(int argc, char* argv[])
{
    guint i;
    g_test_init(&argc, &argv, NULL);
    g_test_add_func(TEST_("invalid"), test_sign_invalid);
    for (i = 0; i < G_N_ELEMENTS(tests); i++) {
        g_test_add_data_func(tests[i].name, tests + i, tests[i].fn);
    }
    return test_run();
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
