/*
 * Copyright (C) 2016-2019 by Slava Monich
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
#include "foil_digest.h"
#include "foil_output.h"
#include "foil_private_key.h"

#include "foil_key_rsa_private.h"
#include "foil_key_rsa_public.h"

#define DATA_DIR "data/"

typedef struct test_key_rsa {
    const char* name;
    GTestDataFunc fn;
    const char* file1;
    const char* file2;
    const char* data;
    int param;
} TestKeyRsa;

typedef struct test_key_rsa_keys {
    char* path1;
    char* path2;
    FoilPrivateKey* priv;
    FoilKey* pub;
} TestKeyRsaKeys;

static
void
test_key_rsa_keys_deinit(
    TestKeyRsaKeys* keys)
{
    /* Additional ref/unref to improve code coverage */
    foil_private_key_ref(keys->priv);
    foil_private_key_unref(keys->priv);
    foil_private_key_unref(keys->priv);
    foil_key_ref(keys->pub);
    foil_key_unref(keys->pub);
    foil_key_unref(keys->pub);
    g_free(keys->path1);
    g_free(keys->path2);
}

static
void
test_key_rsa_keys_init(
    TestKeyRsaKeys* keys,
    const TestKeyRsa* test)
{
    keys->path1 = g_strconcat(DATA_DIR, test->file1, NULL);
    keys->path2 = g_strconcat(DATA_DIR, test->file2, NULL);
    keys->priv = foil_private_key_new_from_file(FOIL_KEY_RSA_PRIVATE,
        keys->path1);
    keys->pub = foil_key_new_from_file(FOIL_KEY_RSA_PUBLIC, keys->path2);
    g_assert(!foil_key_equal(keys->pub, NULL));
    g_assert(!foil_key_equal(NULL, keys->pub));
    g_assert(!foil_private_key_equal(keys->priv, NULL));
    g_assert(!foil_private_key_equal(NULL, keys->priv));
}

static
FoilKey*
test_public_key()
{
    return foil_key_new_from_string(FOIL_KEY_RSA_PUBLIC,
        "000000077373682d727361000000030100010000006100c3e8b4fdda80200a52"
        "6f0cba34467f592c17f9766ae303de883b45de47d5fdd0dffbb0cadbc3cc1f93"
        "6efedb59e1c5c05a78679f8605c55fe6cc08a73e0f29543ee6954443e117a86e"
        "3e7faab313cf17a4508c2f75ff112ce9c5e5f10f32019d");
}

static
FoilPrivateKey*
test_private_key()
{
    return foil_private_key_new_from_string(FOIL_KEY_RSA_PRIVATE,
        "308201cc020100026100c3e8b4fdda80200a526f0cba34467f592c17f9766ae3"
        "03de883b45de47d5fdd0dffbb0cadbc3cc1f936efedb59e1c5c05a78679f8605"
        "c55fe6cc08a73e0f29543ee6954443e117a86e3e7faab313cf17a4508c2f75ff"
        "112ce9c5e5f10f32019d02030100010261008f50c26ede94525c1ab7e060ab73"
        "532021d09c0f13dc64ed3b4dd92be5f356cda1bd5734df9619d293a16451852c"
        "53e3bedf5acca17a882dd3dbda82672fca71dfe2f620411598c64560aab2415a"
        "c6b7bc5b225e92b6d3016ef9c1876f245d85023100e1e7417330e817830b5151"
        "840fe593f15463391184e1916ee30d7c86468961b54f5af7731625e5b83cef42"
        "5a2f4a31fb023100de027412e1d22143082460501d8483cb406458e5ac0f2208"
        "26a2921b6d26379c610b2e735a9a467505b75f5e60965f47023036f0ea6f1c8e"
        "e5e0fe28a9dda78c1b5e0f3b0e8f1f35490ca1f60eba0d7fae1ecd8cff2fa34c"
        "564167b87cf7b816a06f023100855efdf255fd51841e8113e72d446d948e137a"
        "a047543402a78b24b11b4a494045c05ce069bea2b32c82f3e513ab6283023100"
        "8f83f9afc3e37e2f6c5f0e35ba4254737602b2d3785f3dc24682e08bee026dbd"
        "e9c896a7c284149dea1c92a6e4a29d3b");
}

static
void
test_key_rsa_null(
    void)
{
    int dummy;
    GError* error = NULL;

    /* Test NULL resistance */
    foil_key_unref(NULL);
    foil_private_key_unref(NULL);
    g_assert(foil_key_equal(NULL, NULL));
    g_assert(foil_private_key_equal(NULL, NULL));
    g_assert(!foil_key_ref(NULL));
    g_assert(!foil_key_fingerprint(NULL));
    g_assert(!foil_key_to_bytes(NULL));
    g_assert(!foil_key_new_from_data(FOIL_KEY_RSA_PRIVATE, NULL, 0));
    g_assert(!foil_key_new_from_data(0, NULL, 0));
    g_assert(!foil_key_new_from_data(0, NULL, 1));
    g_assert(!foil_key_new_from_data(0, &dummy, 0));
    g_assert(!foil_key_new_from_bytes(0, NULL));
    g_assert(!foil_key_new_from_bytes(FOIL_KEY_RSA_PRIVATE, NULL));
    g_assert(!foil_key_new_from_file(0, NULL));
    g_assert(!foil_key_new_from_file(FOIL_KEY_RSA_PRIVATE, NULL));
    g_assert(!foil_key_decrypt_from_data(0, NULL, 0, NULL, NULL));
    g_assert(!foil_key_decrypt_from_data(0, NULL, 0, "pass", NULL));
    g_assert(!foil_key_decrypt_from_string(0, NULL, NULL, NULL));
    g_assert(!foil_key_decrypt_from_string(0, NULL, "pass", NULL));
    g_assert(!foil_key_decrypt_from_bytes(0, NULL, NULL, NULL));
    g_assert(!foil_key_decrypt_from_bytes(0, NULL, "pass", NULL));
    g_assert(!foil_key_decrypt_from_file(0, NULL, NULL, NULL));
    g_assert(!foil_key_decrypt_from_file(0, NULL, "pass", NULL));
    g_assert(!foil_private_key_ref(NULL));
    g_assert(!foil_private_key_new_from_data(FOIL_KEY_RSA_PRIVATE, NULL, 0));
    g_assert(!foil_private_key_new_from_data(0, NULL, 0));
    g_assert(!foil_private_key_new_from_data(0, NULL, 1));
    g_assert(!foil_private_key_new_from_data(0, &dummy, 0));
    g_assert(!foil_private_key_new_from_data(FOIL_KEY_RSA_PRIVATE, &dummy, 0));
    g_assert(!foil_private_key_new_from_bytes(0, NULL));
    g_assert(!foil_private_key_new_from_bytes(FOIL_KEY_RSA_PRIVATE, NULL));
    g_assert(!foil_private_key_new_from_file(0, NULL));
    g_assert(!foil_private_key_new_from_file(FOIL_KEY_RSA_PRIVATE, NULL));
    g_assert(!foil_private_key_decrypt_from_data(0, NULL, 0, NULL, NULL));
    g_assert(!foil_private_key_decrypt_from_data(0, NULL, 0, "pass", NULL));
    g_assert(!foil_private_key_decrypt_from_bytes(0, NULL, NULL, NULL));
    g_assert(!foil_private_key_decrypt_from_bytes(0, NULL, "pass", NULL));
    g_assert(!foil_private_key_decrypt_from_file(0, NULL, NULL, NULL));
    g_assert(!foil_private_key_decrypt_from_file(0, NULL, "pass", NULL));
    g_assert(!foil_private_key_encrypt_to_string(NULL, 0, NULL, NULL));
    g_assert(!foil_private_key_fingerprint(NULL));
    g_assert(!foil_public_key_new_from_private(NULL));

    g_assert(!foil_private_key_encrypt(NULL, NULL, 0, NULL, NULL, NULL));
    g_assert(!foil_private_key_encrypt(NULL, NULL, 0, NULL, NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_INVALID_ARG);
    g_clear_error(&error);

    g_assert(!foil_private_key_new_from_string_full(0, NULL, NULL, NULL));
    g_assert(!foil_private_key_new_from_string_full(0, NULL, NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_INVALID_ARG);
    g_clear_error(&error);

    g_assert(!foil_private_key_decrypt_from_string(0, "", NULL, NULL));
    g_assert(!foil_private_key_decrypt_from_string(0, NULL, NULL, NULL));
    g_assert(!foil_private_key_decrypt_from_string(0, NULL, NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_INVALID_ARG);
    g_clear_error(&error);

    /* Non-key type */
    g_assert(!foil_key_new_from_data(FOIL_DIGEST_MD5, &dummy, sizeof(dummy)));

    g_assert(!foil_private_key_new_from_data_full(FOIL_DIGEST_MD5, &dummy,
        sizeof(dummy), NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_INVALID_ARG);
    g_clear_error(&error);

    g_assert(!foil_private_key_new_from_bytes_full(FOIL_DIGEST_MD5, NULL,
        NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_INVALID_ARG);
    g_clear_error(&error);

    g_assert(!foil_private_key_new_from_file_full(FOIL_DIGEST_MD5, NULL,
        NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_INVALID_ARG);
    g_clear_error(&error);

    g_assert(!foil_private_key_new_from_string_full(FOIL_DIGEST_MD5, NULL,
        NULL, NULL));
    g_assert(!foil_private_key_new_from_string_full(FOIL_DIGEST_MD5, "",
        NULL, NULL));
    g_assert(!foil_private_key_new_from_string_full(FOIL_DIGEST_MD5, NULL,
        NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_INVALID_ARG);
    g_clear_error(&error);

    g_assert(!foil_private_key_new_from_string_full(FOIL_DIGEST_MD5, "AA",
        NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_INVALID_ARG);
    g_clear_error(&error);
}

static
void
test_key_rsa_uninitialized_type(
    GType type)
{
    GError* error = NULL;
    FoilOutput* mem = foil_output_mem_new(NULL);
    FoilKey* key = g_object_new(type, NULL);
    FoilKey* key2 = g_object_new(type, NULL);
    g_assert(foil_key_equal(key, key2));
    g_assert(!foil_key_equal(key, NULL));
    g_assert(!foil_key_to_bytes(key));
    g_assert(!foil_key_export_full(key, mem, FOIL_KEY_EXPORT_FORMAT_DEFAULT,
        NULL, NULL));
    g_assert(!foil_key_export_full(key, mem, FOIL_KEY_EXPORT_FORMAT_DEFAULT,
        NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_UNSPECIFIED);
    g_clear_error(&error);
    foil_key_unref(key);
    foil_key_unref(key2);
    foil_output_unref(mem);
}

static
void
test_key_rsa_uninitialized(
    void)
{
    test_key_rsa_uninitialized_type(FOIL_KEY_RSA_PUBLIC);
    test_key_rsa_uninitialized_type(FOIL_KEY_RSA_PRIVATE);
}

static
void
test_key_rsa_invalid_params(
    void)
{
    GError* error = NULL;
    FoilOutput* mem = foil_output_mem_new(NULL);
    GHashTable* params = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
        (GDestroyNotify)g_variant_unref);
    FoilKey* pub = test_public_key();
    FoilKey* bad_pub = g_object_new(FOIL_KEY_RSA_PUBLIC, NULL);
    FoilPrivateKey* priv = test_private_key();
    FoilPrivateKey* bad_priv = g_object_new(FOIL_KEY_RSA_PRIVATE, NULL);

    g_assert(pub);
    g_assert(priv);
    g_assert(!foil_key_equal(pub, bad_pub));
    g_assert(!foil_private_key_equal(priv, bad_priv));

    /* Missing destination */
    g_assert(!foil_private_key_encrypt(priv, NULL, 0, NULL, NULL, NULL));
    g_assert(!foil_private_key_encrypt(priv, NULL, 0, NULL, NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_INVALID_ARG);
    g_clear_error(&error);

    /* Empty hash table */
    g_assert(foil_key_export_full(pub, mem,
        FOIL_KEY_EXPORT_FORMAT_DEFAULT, params, &error));
    g_assert(!error);

    g_assert(foil_private_key_export_full(priv, mem,
        FOIL_KEY_EXPORT_FORMAT_DEFAULT, params, &error));
    g_assert(!error);

    /* Invalid import/export parameters */
    g_hash_table_insert(params, (gpointer)FOIL_KEY_PARAM_COMMENT,
        g_variant_ref_sink(g_variant_new_boolean(FALSE)));
    g_hash_table_insert(params, (gpointer)FOIL_KEY_PARAM_PASSPHRASE,
        g_variant_ref_sink(g_variant_new_boolean(FALSE)));

    g_assert(foil_key_export_full(pub, mem,
        FOIL_KEY_EXPORT_FORMAT_DEFAULT, params, &error));
    g_assert(!error);

    g_assert(foil_private_key_export_full(priv, mem,
        FOIL_KEY_EXPORT_FORMAT_DEFAULT, params, &error));
    g_assert(!error);

    foil_key_unref(pub);
    foil_key_unref(bad_pub);
    foil_private_key_unref(priv);
    foil_private_key_unref(bad_priv);
    g_hash_table_destroy(params);
    foil_output_unref(mem);
}

static
void
test_key_rsa_generate(
    void)
{
    FoilKey* key1;
    FoilKey* key2;
    FoilKey* pub1;
    FoilKey* pub2;
    GBytes* bytes;

    /* It doesn't make sense to generate public keys */
    g_assert(!foil_key_generate_new(FOIL_KEY_RSA_PUBLIC, 0));

    /* Try invalid bit count */
    g_assert(!foil_key_generate_new(FOIL_KEY_RSA_PRIVATE, 0));
    g_assert(!foil_key_generate_new(FOIL_KEY_RSA_PRIVATE, 4));

    key1 = foil_key_generate_new(FOIL_KEY_RSA_PRIVATE, 1024);
    key2 = foil_key_generate_new(FOIL_KEY_RSA_PRIVATE, 1024);
    g_assert(FOIL_IS_KEY_RSA_PRIVATE(key1));
    g_assert(FOIL_IS_KEY_RSA_PRIVATE(key2));
    g_assert(!foil_key_equal(key1, key2));

    pub1 = foil_public_key_new_from_private(FOIL_PRIVATE_KEY(key1));
    pub2 = foil_public_key_new_from_private(FOIL_PRIVATE_KEY(key2));
    g_assert(!foil_key_equal(pub1, pub2));

    foil_key_unref(pub1);
    foil_key_unref(pub2);
    foil_key_unref(key2);

    /* Make sure it can be converted to bytes and back */
    bytes = foil_key_to_bytes(key1);
    key2 = foil_key_new_from_bytes(FOIL_KEY_RSA_PRIVATE, bytes);
    g_bytes_unref(bytes);
    g_assert(FOIL_IS_KEY_RSA_PRIVATE(key2));
    g_assert(foil_key_equal(key1, key2));

    foil_key_unref(key1);
    foil_key_unref(key2);
}

static
void
test_key_rsa_fingerprint(
    gconstpointer param)
{
    const TestKeyRsa* test = param;
    TestKeyRsaKeys keys;
    GBytes* fingerprint1;
    GBytes* fingerprint2;
    gchar* data = NULL;
    gsize len;
    GBytes* bytes;
    FoilPrivateKey* priv1;
    FoilPrivateKey* priv2;

    test_key_rsa_keys_init(&keys, test);
    fingerprint1 = foil_private_key_fingerprint(keys.priv);
    fingerprint2 = foil_key_fingerprint(keys.pub);
    /* Second time returns the same pointer: */
    g_assert(foil_key_fingerprint(keys.pub) == fingerprint2);
    /* Keys are not equal but fingerprints are */
    g_assert(!foil_key_equal(FOIL_KEY(keys.priv), keys.pub));
    g_assert(!foil_key_equal(keys.pub, FOIL_KEY(keys.priv)));
    g_assert(g_bytes_equal(fingerprint1, fingerprint2));

    g_assert(g_file_get_contents(keys.path1, &data, &len, NULL));
    bytes = g_bytes_new_take(data, len);
    priv1 = foil_private_key_new_from_data(FOIL_KEY_RSA_PRIVATE, data, len);
    priv2 = foil_private_key_new_from_bytes(FOIL_KEY_RSA_PRIVATE, bytes);
    g_assert(foil_private_key_equal(keys.priv, priv1));
    g_assert(foil_private_key_equal(keys.priv, priv2));
    g_assert(foil_private_key_equal(priv1, priv2));
    foil_private_key_unref(priv1);
    foil_private_key_unref(priv2);
    g_bytes_unref(bytes);

    test_key_rsa_keys_deinit(&keys);
}

static
void
test_key_rsa_bytes(
    gconstpointer param)
{
    const TestKeyRsa* test = param;
    TestKeyRsaKeys keys;
    GBytes* pub_data;
    GBytes* priv_data;
    FoilKey* pub2;
    FoilPrivateKey* priv2;

    test_key_rsa_keys_init(&keys, test);
    pub_data = foil_key_to_bytes(keys.pub);
    priv_data = foil_key_to_bytes(FOIL_KEY(keys.priv));
    pub2 = foil_key_new_from_bytes(FOIL_KEY_RSA_PUBLIC, pub_data);
    priv2 = foil_private_key_new_from_bytes(FOIL_KEY_RSA_PRIVATE, priv_data);
    g_assert(pub2);
    g_assert(foil_key_equal(pub2, keys.pub));
    g_assert(priv2);
    g_assert(foil_private_key_equal(priv2, keys.priv));

    foil_key_unref(pub2);
    foil_private_key_unref(priv2);
    g_bytes_unref(pub_data);
    g_bytes_unref(priv_data);
    test_key_rsa_keys_deinit(&keys);
}

static
void
test_key_rsa_public_hex(
    gconstpointer param)
{
    const TestKeyRsa* test = param;
    FoilKey* pub2;
    TestKeyRsaKeys keys;
    test_key_rsa_keys_init(&keys, test);

    pub2 = foil_key_new_from_string_full(FOIL_KEY_RSA_PUBLIC, test->data,
        NULL, NULL);
    g_assert(pub2);
    g_assert(foil_key_equal(pub2, keys.pub));

    foil_key_unref(pub2);
    test_key_rsa_keys_deinit(&keys);
}

static
void
test_key_rsa_private_hex(
    gconstpointer param)
{
    const TestKeyRsa* test = param;
    FoilPrivateKey* priv2;
    TestKeyRsaKeys keys;
    test_key_rsa_keys_init(&keys, test);

    priv2 = foil_private_key_new_from_string_full(FOIL_KEY_RSA_PRIVATE,
        test->data, NULL, NULL);
    g_assert(priv2);
    g_assert(foil_private_key_equal(priv2, keys.priv));

    foil_private_key_unref(priv2);
    test_key_rsa_keys_deinit(&keys);
}

static
void
test_key_rsa_string(
    gconstpointer param)
{
    const TestKeyRsa* test = param;
    TestKeyRsaKeys keys;
    char* str;
    FoilKey* pub2;
    GError* error = NULL;
    FoilOutput* mem = foil_output_mem_new(NULL);

    test_key_rsa_keys_init(&keys, test);

    /* Try invalid parameters */
    g_assert(!foil_key_export(NULL, NULL));
    g_assert(!foil_key_export(keys.pub, NULL));
    g_assert(!foil_key_to_string(NULL, FOIL_KEY_EXPORT_FORMAT_DEFAULT, NULL));
    g_assert(!foil_key_export_full(NULL, NULL, FOIL_KEY_EXPORT_FORMAT_DEFAULT,
        NULL, NULL));

    g_assert(!foil_key_export_full(NULL, NULL, FOIL_KEY_EXPORT_FORMAT_DEFAULT,
        NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_INVALID_ARG);
    g_clear_error(&error);

    g_assert(!foil_key_export_full(keys.pub, NULL,
        FOIL_KEY_EXPORT_FORMAT_DEFAULT, NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_INVALID_ARG);
    g_clear_error(&error);

    g_assert(!foil_key_export_full(keys.pub, mem,
        (FoilKeyExportFormat)UINT_MAX, NULL, NULL));
    g_assert(!foil_key_export_full(keys.pub, mem,
        (FoilKeyExportFormat)UINT_MAX, NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT);
    g_clear_error(&error);

    /* Simulate I/O error */
    foil_output_close(mem);
    g_assert(!foil_key_export_full(keys.pub, mem, test->param, NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_KEY_WRITE);
    g_clear_error(&error);

    /* Private keys */
    g_assert(!foil_private_key_export(NULL, NULL));
    g_assert(!foil_private_key_export(keys.priv, NULL));
    g_assert(!foil_private_key_to_string(NULL,
        FOIL_KEY_EXPORT_FORMAT_DEFAULT, NULL));

    g_assert(!foil_private_key_export_full(NULL, mem, test->param, NULL,
        NULL));
    g_assert(!foil_private_key_export_full(NULL, mem, test->param, NULL,
        &error));
    g_assert(error && error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_INVALID_ARG);
    g_clear_error(&error);

    /* Convert to text and back */
    str = foil_key_to_string(keys.pub, test->param, test->data);
    GVERBOSE("%s", str);
    pub2 = foil_key_new_from_string(FOIL_KEY_RSA_PUBLIC, str);
    g_assert(pub2);
    g_assert(foil_key_equal(pub2, keys.pub));
    g_free(str);

    /* And private keys too */
    if (test->param == FOIL_KEY_EXPORT_FORMAT_DEFAULT) {
        FoilPrivateKey* priv2;
        str = foil_private_key_to_string(keys.priv, test->param, test->data);
        GVERBOSE("%s", str);
        priv2 = foil_private_key_new_from_string(FOIL_KEY_RSA_PRIVATE, str);
        g_assert(priv2);
        g_assert(foil_private_key_equal(priv2, keys.priv));
        g_free(str);
        foil_private_key_unref(priv2);

        /* I/O error (closed stream) */
        g_assert(!foil_private_key_export_full(keys.priv, mem, test->param,
            NULL, &error));
        g_assert(error && error->domain == FOIL_ERROR);
        g_assert(error->code == FOIL_ERROR_KEY_WRITE);
        g_clear_error(&error);
    } else {
        g_assert(!foil_private_key_to_string(keys.priv, test->param,
            test->data));
        g_assert(!foil_private_key_export_full(keys.priv, mem, test->param,
            NULL, &error));
        g_assert(error && error->domain == FOIL_ERROR);
        g_assert(error->code == FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT);
        g_clear_error(&error);
    }

    foil_key_unref(pub2);
    foil_output_unref(mem);
    test_key_rsa_keys_deinit(&keys);
}

static
void
test_key_rsa_convert(
    gconstpointer param)
{
    const TestKeyRsa* test = param;
    TestKeyRsaKeys keys;
    FoilKey* pub2;

    test_key_rsa_keys_init(&keys, test);
    pub2 = foil_public_key_new_from_private(keys.priv);
    g_assert(foil_key_equal(keys.pub, pub2));
    g_assert(foil_key_equal(pub2, keys.pub));

    foil_key_unref(pub2);
    test_key_rsa_keys_deinit(&keys);
}


static
void
test_key_rsa_read_ok(
    const TestKeyRsa* test,
    GType type)
{
    char* path1 = g_strconcat(DATA_DIR, test->file1, NULL);
    gchar* contents = NULL;
    gsize length = 0;
    GBytes* bytes;
    FoilKey* key1;
    FoilKey* key2;

    g_assert(g_file_get_contents(path1, &contents, &length, NULL));
    bytes = g_bytes_new_take(contents, length);
    key1 = foil_key_new_from_bytes(type, bytes);
    if (test->file2) {
        char* path2 = g_strconcat(DATA_DIR, test->file2, NULL);
        key2 = foil_key_new_from_file(type, path2);
        g_free(path2);
    } else {
        key2 = foil_key_new_from_file(type, path1);
    }
    g_assert(key1);
    g_assert(key2);
    g_assert(foil_key_equal(key1, key2));
    g_assert(foil_key_equal(key2, key1));
    g_assert(!foil_key_equal(NULL, key2));
    g_assert(!foil_key_equal(key1, NULL));

    foil_key_unref(foil_key_ref(key1));
    foil_key_unref(key1);
    foil_key_unref(key2);
    g_bytes_unref(bytes);
    g_free(path1);
}

static
void
test_key_rsa_public_read_ok(
    gconstpointer param)
{
    test_key_rsa_read_ok(param, FOIL_KEY_RSA_PUBLIC);
}

static
void
test_key_rsa_private_read_ok(
    gconstpointer param)
{
    test_key_rsa_read_ok(param, FOIL_KEY_RSA_PRIVATE);
}

static
void
test_key_rsa_read_err(
    const TestKeyRsa* test,
    GType type)
{
    GError* error = NULL;
    char* path = g_strconcat(DATA_DIR, test->file1, NULL);
    g_assert(!foil_key_new_from_file(type, path));
    g_assert(!foil_key_new_from_file_full(type, path, NULL, &error));
    g_assert(error);
    if (error->domain == FOIL_ERROR) {
        g_assert(error->code == FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT);
    } else {
        g_assert(error->domain == G_FILE_ERROR);
        g_assert(error->code == G_FILE_ERROR_NOENT);
    }
    g_error_free(error);
    g_free(path);
}

static
void
test_key_rsa_public_read_err(
    gconstpointer param)
{
    test_key_rsa_read_err(param, FOIL_KEY_RSA_PUBLIC);
}

static
void
test_key_rsa_private_read_err(
    gconstpointer param)
{
    test_key_rsa_read_err(param, FOIL_KEY_RSA_PRIVATE);
}

static
void
test_key_rsa_encrypt(
    gconstpointer param)
{
    const TestKeyRsa* test = param;
    const char* pwd = test->data;
    const char* comment = test->file2;
    FoilKeyExportFormat format = test->param;
    GType type = FOIL_KEY_RSA_PRIVATE;
    char* path = g_strconcat(DATA_DIR, test->file1, NULL);
    FoilPrivateKey* priv2;
    FoilPrivateKey* priv = foil_private_key_new_from_file(type, path);
    char* str = foil_private_key_encrypt_to_string(priv, format, pwd, comment);
    g_assert(priv);
    GDEBUG("%s", str);
    g_assert(str);

    /* Try invalid password first */
    if (pwd && pwd[0]) {
        GError* error = NULL;
        g_assert(!foil_private_key_decrypt_from_string(type, str,
            "wrong password", &error));
        g_assert(error);
        g_assert(error->domain == FOIL_ERROR);
        g_assert(error->code == FOIL_ERROR_KEY_DECRYPTION_FAILED);
        g_clear_error(&error);
    }

    /* Now with te right password it must succeed */
    priv2 = foil_private_key_decrypt_from_string(type, str, pwd, NULL);
    g_assert(priv2);
    g_assert(foil_private_key_equal(priv, priv2));
    g_free(str);
    g_free(path);
    foil_private_key_unref(priv);
    foil_private_key_unref(priv2);
}

static
void
test_key_rsa_passphrase_read_ok(
    gconstpointer param)
{
    const TestKeyRsa* test = param;
    const char* passphrase = test->data;
    GType priv = FOIL_KEY_RSA_PRIVATE;
    char* path1 = g_strconcat(DATA_DIR, test->file1, NULL);
    char* path2 = g_strconcat(DATA_DIR, test->file2, NULL);
    GError* error = NULL;
    FoilPrivateKey* key1;
    FoilKey* key2;
    FoilKey* pub1;

    g_assert(!foil_private_key_decrypt_from_file(priv, path1, NULL, NULL));
    g_assert(!foil_private_key_decrypt_from_file(priv, path1, NULL, &error));
    g_assert(error);
    g_assert(error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_KEY_ENCRYPTED);
    g_clear_error(&error);

    g_assert(!foil_private_key_decrypt_from_file(priv, path1, NULL, NULL));
    g_assert(!foil_private_key_decrypt_from_file(priv, path1, NULL, &error));
    g_assert(error);
    g_assert(error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_KEY_ENCRYPTED);
    g_clear_error(&error);

    /* Invalid UTF8 is treated as if there was no password at all */
    g_assert(!foil_private_key_decrypt_from_file(priv, path1, "\x82", &error));
    g_assert(error);
    g_assert(error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_KEY_ENCRYPTED);
    g_clear_error(&error);

    g_assert(!foil_private_key_decrypt_from_file(priv, path1, "wrong", NULL));
    g_assert(!foil_private_key_decrypt_from_file(priv, path1, "wrong", &error));
    g_assert(error);
    g_assert(error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_KEY_DECRYPTION_FAILED);
    g_clear_error(&error);

    key1 = foil_private_key_decrypt_from_file(priv, path1, passphrase, &error);
    g_assert(key1);
    g_assert(!error);

    pub1 = foil_public_key_new_from_private(key1);
    key2 = foil_key_new_from_file(FOIL_KEY_RSA_PUBLIC, path2);
    g_assert(foil_key_equal(key2, pub1));
    g_assert(pub1);
    g_assert(key2);

    foil_private_key_unref(key1);
    foil_key_unref(pub1);
    foil_key_unref(key2);
    g_free(path1);
    g_free(path2);
}

static
void
test_key_rsa_passphrase_read_err(
    gconstpointer param)
{
    const TestKeyRsa* t = param;
    GType type = FOIL_KEY_RSA_PRIVATE;
    char* path = g_strconcat(DATA_DIR, t->file1, NULL);
    GError* e = NULL;

    g_assert(!foil_private_key_decrypt_from_file(type, path, t->data, NULL));
    g_assert(!foil_private_key_decrypt_from_file(type, path, t->data, &e));
    g_assert(e->domain == FOIL_ERROR);
    g_assert(e->code == t->param);

    g_error_free(e);
    g_free(path);
}

static
void
test_key_rsa_fingerprint_value(
    gconstpointer param)
{
    const TestKeyRsa* test = param;
    TestKeyRsaKeys keys;
    GBytes* expect;
    GBytes* fp1;
    GBytes* fp2;
    char* s1;
    char* s2;

    test_key_rsa_keys_init(&keys, test);
    fp1 = foil_private_key_fingerprint(keys.priv);
    fp2 = foil_key_fingerprint(keys.pub);

    g_assert(fp1);
    g_assert(fp2);

    s1 = test_hex_bytes(fp1, ":");
    s2 = test_hex_bytes(fp2, ":");
    GDEBUG("%s", s1);
    GDEBUG("%s", s2);
    g_free(s1);
    g_free(s2);

    g_assert(g_bytes_equal(fp1, fp2));

    expect = test_hex_to_bytes(test->data);
    g_assert(g_bytes_equal(fp1, expect));
    g_bytes_unref(expect);

    test_key_rsa_keys_deinit(&keys);
}

#define TEST_(name) "/key_rsa/" name
#define TEST_READ_OK(type,name) TEST_READ_OK2(type,name,"")
#define TEST_READ_OK1(type,name) \
    { TEST_("read-" name), test_key_rsa_##type##_read_ok, \
      name }
#define TEST_READ_OK2(type,name,suffix) \
    { TEST_("read-" name suffix), test_key_rsa_##type##_read_ok, \
      name suffix, name ".bin" }
#define TEST_ENCRYPT(name, password, comment) \
    { TEST_("encrypt-" name), test_key_rsa_encrypt, \
      name, comment, password, FOIL_KEY_EXPORT_FORMAT_DEFAULT }
#define TEST_READ_PASSPHRASE_OK(name,enc,passphrase) \
    { TEST_("read-" name "-" enc), test_key_rsa_passphrase_read_ok, \
      name "." enc, name ".pub", passphrase }
#define TEST_READ_PASSPHRASE_ERR(name,enc,passphrase,err) \
    { TEST_("read-" name "-" enc), test_key_rsa_passphrase_read_err, \
      name "." enc, NULL, passphrase, FOIL_ERROR_##err }
#define TEST_READ_RFC4716_OK(type,name) \
    { TEST_("read-" name ".RFC4716"), test_key_rsa_##type##_read_ok,  \
      name ".RFC4716", name ".bin" }
#define TEST_READ_PKCS8_OK(type,name) \
    { TEST_("read-" name ".PKCS8"), test_key_rsa_##type##_read_ok,  \
      name ".PKCS8", name ".bin" }
#define TEST_READ_ERR(type,name) \
    { TEST_("read-" name), test_key_rsa_##type##_read_err, \
      name }
#define TEST_FINGERPRINT(name) \
    { TEST_("fingerprint-" name), test_key_rsa_fingerprint, \
      name, name ".pub" }
#define TEST_FPVAL(name,value) \
    { TEST_("fingerprint-value-" name), test_key_rsa_fingerprint_value, \
      name, name ".pub" , value }
#define TEST_CONVERT(name) \
    { TEST_("convert-" name), test_key_rsa_convert, \
      name, name ".pub" }
#define TEST_BYTES(name) \
    { TEST_("bytes-" name), test_key_rsa_bytes, \
      name, name ".pub" }
#define TEST_PUBLIC_HEX(name,hex) \
    { TEST_("public-hex-" name), test_key_rsa_public_hex, \
      name, name ".pub", hex}
#define TEST_PRIVATE_HEX(name,hex) \
    { TEST_("private-hex-" name), test_key_rsa_private_hex, \
      name, name ".pub", hex}
#define TEST_STRING(name) \
    { TEST_("string-" name), test_key_rsa_string, \
      name, name ".pub", NULL, FOIL_KEY_EXPORT_FORMAT_DEFAULT }
#define TEST_STRING_COMMENT(name) \
    { TEST_("string-comment-" name), test_key_rsa_string, \
      name, name ".pub", name, FOIL_KEY_EXPORT_FORMAT_DEFAULT }
#define TEST_STRING_RFC4716(name) \
    { TEST_("string-rfc4716-" name), test_key_rsa_string, \
      name, name ".pub", NULL, FOIL_KEY_EXPORT_FORMAT_RFC4716 }
#define TEST_STRING_RFC4716_COMMENT(name,comment) \
    { TEST_("string-rfc4716-comment-" name), test_key_rsa_string, \
      name, name ".pub", comment, FOIL_KEY_EXPORT_FORMAT_RFC4716 }
#define TEST_STRING_PKCS8(name) \
    { TEST_("string-pkcs8-" name), test_key_rsa_string, \
      name, name ".pub", NULL, FOIL_KEY_EXPORT_FORMAT_PKCS8 }

static const TestKeyRsa tests[] = {
    TEST_READ_OK(private,  "rsa-768"  ),
    TEST_READ_OK(private,  "rsa-1024" ),
    TEST_READ_OK(private,  "rsa-1500" ),
    TEST_READ_OK(private,  "rsa-2048" ),
    TEST_READ_OK(public,   "rsa-768.pub"  ),
    TEST_READ_OK(public,   "rsa-1024.pub" ),
    TEST_READ_OK(public,   "rsa-1500.pub" ),
    TEST_READ_OK(public,   "rsa-2048.pub" ),
    TEST_READ_OK2(private, "rsa-768", ".1" ),
    TEST_ENCRYPT("rsa-768", NULL, NULL),
    TEST_ENCRYPT("rsa-1024", "passphrase1", "Encrypted key"),
    TEST_ENCRYPT("rsa-1500", "passphrase2", ""),
    TEST_ENCRYPT("rsa-2048", "", "TooLongLongLongLongLongLongLongLong"
        "LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"
        "LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"
        "LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"
        "LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"
        "LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"
        "LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"
        "LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"
        "LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"
        "LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"
        "LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"
        "LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"
        "LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"
        "LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"
        "LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"
        "LongLongLongLongLongLongLongLongLongComment"),
    TEST_READ_PASSPHRASE_OK("rsa-768-passphrase", "aes128", "passphrase"),
    TEST_READ_PASSPHRASE_OK("rsa-768-passphrase", "pkcs8.aes128", "passwd"),
    TEST_READ_PASSPHRASE_OK("rsa-768-passphrase", "pkcs8.aes192", "passwd"),
    TEST_READ_PASSPHRASE_OK("rsa-768-passphrase", "pkcs8.aes256", "passwd"),
    TEST_READ_PASSPHRASE_OK("rsa-1024-passphrase", "aes192", "passphrase"),
    TEST_READ_PASSPHRASE_OK("rsa-1500-passphrase", "aes256", "passphrase"),
    TEST_READ_PASSPHRASE_ERR("rsa-2048-passphrase", "camellia256", NULL,
        KEY_UNKNOWN_ENCRYPTION),  /* Unknown algorithm */
    TEST_READ_PASSPHRASE_ERR("rsa-2048-passphrase", "des3", "passphrase",
        KEY_UNKNOWN_ENCRYPTION),  /* Unknown algorithm */
    TEST_READ_PASSPHRASE_ERR("rsa-2048-passphrase", "seed", "passphrase",
        KEY_UNKNOWN_ENCRYPTION),  /* Unknown algorithm */
    TEST_READ_PASSPHRASE_ERR("rsa-2048-passphrase", "err1", NULL,
        KEY_UNKNOWN_ENCRYPTION),  /* Missing IV */
    TEST_READ_PASSPHRASE_ERR("rsa-2048-passphrase", "err2", NULL,
        KEY_UNKNOWN_ENCRYPTION),  /* Short IV */
    TEST_READ_PASSPHRASE_ERR("rsa-2048-passphrase", "err3", NULL,
        KEY_ENCRYPTED),           /* Broken IV => decryption fails (no pass) */
    TEST_READ_PASSPHRASE_ERR("rsa-2048-passphrase", "err4", "passphrase",
        KEY_DECRYPTION_FAILED),   /* Broken IV => decryption fails */
    TEST_READ_PASSPHRASE_ERR("rsa-2048-passphrase", "err5", NULL,
        KEY_UNKNOWN_ENCRYPTION),  /* Invalid algorithm */
    TEST_READ_RFC4716_OK(public, "rsa-768.pub" ),
    TEST_READ_PKCS8_OK(public, "rsa-768.pub" ),
    TEST_FINGERPRINT("rsa-768"  ),
    TEST_FINGERPRINT("rsa-1024" ),
    TEST_FINGERPRINT("rsa-1500" ),
    TEST_FINGERPRINT("rsa-2048" ),
    /* Fingerprint values are produced by e.g. ssh-key -lf data/rsa-768 */
    TEST_FPVAL("rsa-768", "9a:76:f1:62:d8:7c:81:2d:03:f6:f0:6b:9a:1f:d1:69"),
    TEST_FPVAL("rsa-1024", "9b:f5:c4:eb:c2:f0:a0:2b:de:f6:37:63:f6:0c:30:2c"),
    TEST_FPVAL("rsa-1500", "a7:fc:53:56:e3:d2:7e:f1:02:14:5c:69:ad:aa:6b:43"),
    TEST_FPVAL("rsa-2048", "93:2f:fe:5d:87:0e:d6:fd:1f:aa:f9:41:af:e0:26:3f"),
    TEST_CONVERT("rsa-768"  ),
    TEST_CONVERT("rsa-1024" ),
    TEST_CONVERT("rsa-1500" ),
    TEST_CONVERT("rsa-2048" ),
    TEST_BYTES("rsa-768"  ),
    TEST_BYTES("rsa-1024" ),
    TEST_BYTES("rsa-1500" ),
    TEST_BYTES("rsa-2048" ),
    TEST_PUBLIC_HEX("rsa-768", "000000077373682d7273610000000301"
"00010000006100c3e8b4fdda80200a526f0cba34467f592c17f9766ae303de88"
"3b45de47d5fdd0dffbb0cadbc3cc1f936efedb59e1c5c05a78679f8605c55fe6"
"cc08a73e0f29543ee6954443e117a86e3e7faab313cf17a4508c2f75ff112ce9"
"c5e5f10f32019d"),
    TEST_PUBLIC_HEX("rsa-1024", "000000077373682d7273610000000301"
"00010000008100b7ad1b70c257af64a196a87169d5ae5a2df19833ebcc83ef63"
"b2c4decc929203fcba78b962a3106d2dfca3bb1cab7e9f091d54d180a8362993"
"32a32fb50665025e7a145e4063f2dfa532285ce482e22774e9cb5bf29249b0c9"
"201cb9f1d3da40d0b2f3c073104d6cbdd829e62292d9e997a648eee190c2dfab"
"fdae5c245c948f"),
    TEST_PUBLIC_HEX("rsa-1500", "000000077373682d7273610000000301"
"0001000000bc0e0bfdc1dc721e4b1272ef4289ad58a3b44b3ba06c33614f3209"
"8c51e872ffa1b004945218d23917a82deaaa19b7c0f965fe91ee303e53d23352"
"ff420753317516f4ddb3130e809937a775969d4cb3ace4257edf5dabcfbb6ab3"
"0e1be53e584cab24f50f20d19162260c17be66c30177ac8b6d0c198a3274e2ac"
"44ea6ad58057cda8b1f6e11fa31b88fe68fbb298a8545648d025d71a4fa0f940"
"41c0e99e3da5cb58b59855f8ceaa1d5320401c34941adb98f8107b75b4f9e4cb"
"34a3"),
    TEST_PUBLIC_HEX("rsa-2048", "000000077373682d7273610000000301"
"00010000010100bfc39178fec871bc7aa43a898672d67619e69e6d330600c501"
"14c5ec9bf707ef3a159d992b1ebe01639dbc89bdfadddf42a2b4f84c8927401f"
"b93ee527f6f4aa8610f1087b6eeaa99611401b384fc57a5699a98d6644212efb"
"e42a78a7eef81927aff7ca9340e897b84348181812ef651001f7092539295929"
"a3b2560e0d959db180f05f40e9ac57ed8e038c7499b49dc09efb9f388692f135"
"7718c7596207bd74ba3a17c65fecc86970df1077c2201c099a280ba1e438b3de"
"a1d9d74143c648b89a8e985ca43c54875e0cdd5399f0f85a4b2e56fcf8c9f0ec"
"eff5d7030a2fd6a188f27a5a8b484f455081935f64e145c045e7275b83078443"
"462ebd4566748b"),
    TEST_PRIVATE_HEX("rsa-768", "308201cc020100026100c3e8b4fdda80"
"200a526f0cba34467f592c17f9766ae303de883b45de47d5fdd0dffbb0cadbc3"
"cc1f936efedb59e1c5c05a78679f8605c55fe6cc08a73e0f29543ee6954443e1"
"17a86e3e7faab313cf17a4508c2f75ff112ce9c5e5f10f32019d020301000102"
"61008f50c26ede94525c1ab7e060ab73532021d09c0f13dc64ed3b4dd92be5f3"
"56cda1bd5734df9619d293a16451852c53e3bedf5acca17a882dd3dbda82672f"
"ca71dfe2f620411598c64560aab2415ac6b7bc5b225e92b6d3016ef9c1876f24"
"5d85023100e1e7417330e817830b5151840fe593f15463391184e1916ee30d7c"
"86468961b54f5af7731625e5b83cef425a2f4a31fb023100de027412e1d22143"
"082460501d8483cb406458e5ac0f220826a2921b6d26379c610b2e735a9a4675"
"05b75f5e60965f47023036f0ea6f1c8ee5e0fe28a9dda78c1b5e0f3b0e8f1f35"
"490ca1f60eba0d7fae1ecd8cff2fa34c564167b87cf7b816a06f023100855efd"
"f255fd51841e8113e72d446d948e137aa047543402a78b24b11b4a494045c05c"
"e069bea2b32c82f3e513ab62830231008f83f9afc3e37e2f6c5f0e35ba425473"
"7602b2d3785f3dc24682e08bee026dbde9c896a7c284149dea1c92a6e4a29d3b"),
    TEST_PRIVATE_HEX("rsa-1024", "3082025e02010002818100b7ad1b70c2"
"57af64a196a87169d5ae5a2df19833ebcc83ef63b2c4decc929203fcba78b962"
"a3106d2dfca3bb1cab7e9f091d54d180a836299332a32fb50665025e7a145e40"
"63f2dfa532285ce482e22774e9cb5bf29249b0c9201cb9f1d3da40d0b2f3c073"
"104d6cbdd829e62292d9e997a648eee190c2dfabfdae5c245c948f0203010001"
"02818049f3464305dbebdfe6371426656804c4860ee92aae5b2f1b68d686f0f5"
"08660578f152bdc0faca184b15968e3522cede14fb5c34e549d454b4d10466a6"
"c9a64cb8c0fe4a72a0c91e141ad89f14aaff1487ae90894bd31701e959511d83"
"0164007af95e566c33ec98497845608480da4b99cd3f220881e2bb994424de60"
"f090b1024100ea2576af86ccd49829ff0a420c2f32122414967c221368853ce9"
"edd547740225c6627d14654e88950ed7121bb358a7745da62d95e034559fa044"
"839e4cd2babb024100c8d1be62525414421d236e932d73d7d3e58e3e3f745260"
"aa63c2e5ecdf51dd042242b66fb882c171d97e7e874c08bf5406657727f47540"
"8c3f07d494eb97e23d024100e35e6dda14f4629d406ac0f35211a275ab43b2bd"
"e7f920ce0150c7fb0bdfc3161b87181eee214cd03210f72c9f03bfd867f82edc"
"1353beb1bb57ccd7b3920e71024100a6ab2d4f7cf4bb3b83e37c4a3a5702b1a2"
"bbc37df694c815a266875d689b10cbf58358d6b0541528e051d3c186a15be9e8"
"c51d77d3b3dcb689397e7d7a6abc21024100a5efdecc573a9194e6e516d6f625"
"af7d4335da074ea55b509623cbee167adbb8a0c91718858f2df39b6f392c1503"
"097abf759b89406daf4010bd433577f907fa"),
    TEST_PRIVATE_HEX("rsa-1500", "308203660201000281bc0e0bfdc1dc72"
"1e4b1272ef4289ad58a3b44b3ba06c33614f32098c51e872ffa1b004945218d2"
"3917a82deaaa19b7c0f965fe91ee303e53d23352ff420753317516f4ddb3130e"
"809937a775969d4cb3ace4257edf5dabcfbb6ab30e1be53e584cab24f50f20d1"
"9162260c17be66c30177ac8b6d0c198a3274e2ac44ea6ad58057cda8b1f6e11f"
"a31b88fe68fbb298a8545648d025d71a4fa0f94041c0e99e3da5cb58b59855f8"
"ceaa1d5320401c34941adb98f8107b75b4f9e4cb34a302030100010281bc0ae0"
"4e0324e5577f593195003809f87008d197c18705e17aa88bac125fa16b3d8e44"
"7d7373b4927036d016bace5ef1142a5d0a311b39a73d42702924bef7337c2de2"
"3b26c4c29de004aface489b73207d43f14156f39f106747f5f9549d2b727f3b3"
"5d05db00dbe44326d02f6103f978e5db92e4ecb9f15891bbe825413f8f7d525a"
"2438fa622d98418285870a207df8800e7596aed4e645e1e06a03e93f938906fa"
"87c3a8c21e641473b5090542d0b6377b79a63d33fbc9fc9e6081025e3ea8e13b"
"433c49f1a8a693c1af20749806284260eee55b025b189b4171fad9a588b61d8f"
"afa383a8a98746d56eb3bf7dd0dbfc9e1c4ae40ff0968c8dfd180d24a41e9603"
"ac48b1095fa73cd16fa06f3131b8fd54ca79a2f55461e0aa3499025e3963a4a4"
"f575badf25d9f789794112a3ed28ea48e130e05b894ae8abcb0f52afc82f4271"
"9af308bbfd5c53232bb6a847e1e0bad137a4af18f4a3a0d970063238a3217310"
"6e805b020b2bc980b6bc0975164cadb492cd5635bf688d25bc9b025e0fde899c"
"8ebcb82582071e28d187b0bfc7df6e604a60c019eaa462bdc2763ba516e8b8b7"
"e94dca4c6f1319b7786001c185a2116aa1d3bdcae3addd4f20a874bbb0ed2625"
"2bff050750b87448beb2ad3692573da1b9ddf08d9d9f645cf711025e1fe05ae9"
"4d75f1305563f67ca39f236d6e2395ce99567ea81960445077dfb0fbf66359b2"
"a4706ddf8d6124c49a5940ab7ca948db40def66b142777068f94c17c780ff24b"
"a4352357c540b3120d6df08adab208a20e1083dc22cf3de74215025e1b41b270"
"deb177b6cd0d073028d14ff6c60e3caa83bf73e1d9c66677e11dfd5f2df583f8"
"78b87578c100ee3c41bec3d550346f2c9833cce84f230f5ef5a8e226985dcfbe"
"814640329b50f1669f1bb6a482e1fe4e248aca20b6490d9954a1"),
    TEST_STRING("rsa-768" ),
    TEST_STRING("rsa-1024"),
    TEST_STRING("rsa-1500"),
    TEST_STRING("rsa-2048"),
    TEST_STRING_PKCS8("rsa-768" ),
    TEST_STRING_COMMENT("rsa-768" ),
    TEST_STRING_COMMENT("rsa-1024"),
    TEST_STRING_COMMENT("rsa-1500"),
    TEST_STRING_COMMENT("rsa-2048"),
    TEST_STRING_RFC4716("rsa-768" ),
    TEST_STRING_RFC4716("rsa-1024"),
    TEST_STRING_RFC4716("rsa-1500"),
    TEST_STRING_RFC4716("rsa-2048"),
    TEST_STRING_RFC4716_COMMENT("rsa-768", "Short comment"),
    TEST_STRING_RFC4716_COMMENT("rsa-1024", "This is a long multiline comment"
" which fits into 1024-byte limit imposed by RFC 4716"),
    TEST_STRING_RFC4716_COMMENT("rsa-1500", "Invalid UTF8: \x82\xD0"),
    TEST_STRING_RFC4716_COMMENT("rsa-2048", "This is a really long UTF8 "
"comment which doesn't fit into 1024-byte limit and will be ignored "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "
"\xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 "),
    TEST_READ_ERR(public,  "bad.pub.001"),
    TEST_READ_ERR(public,  "bad.pub.002"),
    TEST_READ_ERR(public,  "bad.pub.003"),
    TEST_READ_ERR(public,  "bad.pub.004"),
    TEST_READ_ERR(public,  "bad.pub.005"),
    TEST_READ_ERR(public,  "bad.pub.006"),
    TEST_READ_ERR(public,  "bad.pub.007"),
    TEST_READ_ERR(public,  "bad.pub.008"),
    TEST_READ_OK1(private, "zero_e" ),
    TEST_READ_ERR(private, "bad.001"),
    TEST_READ_ERR(private, "bad.002"),
    TEST_READ_ERR(private, "bad.003"),
    TEST_READ_ERR(private, "bad.004"),
    TEST_READ_ERR(private, "bad.005"),
    TEST_READ_ERR(private, "bad.006"),
    TEST_READ_ERR(private, "bad.007"),
    TEST_READ_ERR(private, "bad.008"),
    TEST_READ_ERR(private, "bad.009"),
    TEST_READ_ERR(private, "bad.010"),
    TEST_READ_ERR(private, "bad.011"),
    TEST_READ_ERR(private, "bad.012"),
    TEST_READ_ERR(private, "bad.013"),
    TEST_READ_ERR(private, "bad.014"),
    TEST_READ_ERR(private, "bad.015"),
    TEST_READ_ERR(private, "bad.016"),
    TEST_READ_ERR(private, "bad.017"),
    TEST_READ_ERR(private, "bad.018"),
    TEST_READ_ERR(private, "bad.019"),
    TEST_READ_ERR(private, "missing")
};

int main(int argc, char* argv[])
{
    guint i;
    g_test_init(&argc, &argv, NULL);
    g_test_add_func(TEST_("null"), test_key_rsa_null);
    g_test_add_func(TEST_("uninitialized"), test_key_rsa_uninitialized);
    g_test_add_func(TEST_("invalid_params"), test_key_rsa_invalid_params);
    g_test_add_func(TEST_("generate"), test_key_rsa_generate);
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
