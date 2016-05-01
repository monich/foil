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

#include "foil_key.h"
#include "foil_digest.h"
#include "foil_private_key.h"
#include "foil_key_aes.h"

#define DATA_DIR "data/"

typedef struct test_key_aes {
    const char* name;
    GTestDataFunc fn;
    GType (*fn_type)(void);
    const char* file1;
    const char* file2;
} TestKeyAes;

static
void
test_key_aes_basic(
    gconstpointer param)
{
    const TestKeyAes* test = param;
    char* rsa_path = g_strconcat(DATA_DIR, test->file1, NULL);
    FoilKey* rsa = foil_key_new_from_file(test->fn_type(), rsa_path);
    FoilKey* aes1 = foil_key_generate_new(FOIL_KEY_AES128,
        FOIL_KEY_BITS_DEFAULT);
    FoilKey* aes2 = foil_key_generate_new(FOIL_KEY_AES128,
        FOIL_KEY_BITS_DEFAULT);
    FoilKey* aes3 = foil_key_generate_new(FOIL_KEY_AES192,
        FOIL_KEY_BITS_DEFAULT);
    GError* error = NULL;
    int dummy;

    g_assert(foil_key_equal(aes1, aes1));
    g_assert(!foil_key_equal(aes1, aes2)); /* Different contents */
    g_assert(!foil_key_equal(aes1, aes3)); /* Different key sizes */
    g_assert(!foil_key_equal(aes1, rsa));  /* Different ky types */

    /* Test resistance to NULL and all kinds of invalid parameters */
    foil_key_unref(NULL);
    foil_private_key_unref(NULL);
    g_assert(foil_key_equal(NULL, NULL));
    g_assert(!foil_key_ref(NULL));
    g_assert(!foil_key_fingerprint(NULL));
    g_assert(!foil_key_generate_new(FOIL_KEY_AES128, 127));
    g_assert(!foil_key_generate_new(FOIL_KEY_AES192, 191));
    g_assert(!foil_key_generate_new(FOIL_KEY_AES256, 255));
    g_assert(!foil_key_generate_new(0, FOIL_KEY_BITS_DEFAULT));
    g_assert(!foil_key_generate_new(FOIL_TYPE_KEY, 7));
    g_assert(!foil_key_generate_new(FOIL_TYPE_KEY_AES, 666));
    g_assert(!foil_key_new_from_data(FOIL_KEY_AES128, NULL, 0));
    g_assert(!foil_key_new_from_data(0, NULL, 0));
    g_assert(!foil_key_new_from_data(0, NULL, 1));
    g_assert(!foil_key_new_from_data(0, &dummy, 0));
    g_assert(!foil_key_new_from_string(0, NULL));
    g_assert(!foil_key_new_from_string(0, ""));
    g_assert(!foil_key_new_from_string(FOIL_KEY_AES128, NULL));
    g_assert(!foil_key_new_from_string(FOIL_KEY_AES128, ""));
    g_assert(!foil_key_new_from_string(FOIL_KEY_AES128, "x"));
    g_assert(!foil_key_new_from_string(FOIL_KEY_AES128, "xx"));
    g_assert(!foil_key_new_from_bytes(0, NULL));
    g_assert(!foil_key_new_from_bytes(FOIL_KEY_AES128, NULL));
    g_assert(!foil_key_new_from_file(0, NULL));
    g_assert(!foil_key_new_from_file(FOIL_KEY_AES128, NULL));
    g_assert(!foil_private_key_ref(NULL));
    g_assert(!foil_private_key_new_from_data(FOIL_KEY_AES128, NULL, 0));
    g_assert(!foil_private_key_new_from_data(0, NULL, 0));
    g_assert(!foil_private_key_new_from_data(0, NULL, 1));
    g_assert(!foil_private_key_new_from_data(0, &dummy, 0));
    g_assert(!foil_private_key_new_from_bytes(0, NULL));
    g_assert(!foil_private_key_new_from_bytes(FOIL_KEY_AES128, NULL));
    g_assert(!foil_private_key_new_from_file(0, NULL));
    g_assert(!foil_private_key_new_from_file(FOIL_KEY_AES128, NULL));

    g_assert(!foil_key_new_from_string_full(FOIL_KEY_AES128, "xx",
        NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR);
    g_assert(error->code == FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT);
    g_clear_error(&error);

    /* Non-key type */
    g_assert(!foil_key_new_from_data(FOIL_DIGEST_MD5, &dummy, sizeof(dummy)));
    g_assert(!foil_key_generate_new(FOIL_DIGEST_MD5, FOIL_KEY_BITS_DEFAULT));

    g_assert(!foil_key_new_from_data_full(0, NULL, 0, NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR &&
        error->code == FOIL_ERROR_INVALID_ARG);
    g_clear_error(&error);

    g_assert(!foil_key_new_from_data_full(FOIL_TYPE_KEY, &dummy,
        sizeof(dummy), NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR &&
        error->code == FOIL_ERROR_INVALID_ARG);
    g_clear_error(&error);

    g_assert(!foil_key_new_from_string_full(0, NULL, NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR &&
        error->code == FOIL_ERROR_INVALID_ARG);
    g_clear_error(&error);

    g_assert(!foil_key_new_from_bytes_full(0, NULL, NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR &&
        error->code == FOIL_ERROR_INVALID_ARG);
    g_clear_error(&error);

    g_assert(!foil_key_new_from_file_full(0, NULL, NULL, &error));
    g_assert(error && error->domain == FOIL_ERROR &&
        error->code == FOIL_ERROR_INVALID_ARG);
    g_clear_error(&error);

    foil_key_unref(aes1);
    foil_key_unref(aes2);
    foil_key_unref(aes3);
    foil_key_unref(rsa);
    g_free(rsa_path);
}

static
void
test_key_aes_generate2(
    GType type,
    guint bits)
{
    FoilKey* key1 = foil_key_generate_new(type, bits);
    FoilKey* key2 = foil_key_generate_new(type, FOIL_KEY_BITS_DEFAULT);
    GBytes* bytes = foil_key_to_bytes(key2);
    FoilKey* key3;
    g_assert(key1 && key2);
    key3 = foil_key_new_from_bytes(G_TYPE_FROM_INSTANCE(key2), bytes);
    g_assert(key3);
    g_assert(!foil_key_equal(key1, key2));
    g_assert(foil_key_equal(key2, key3));
    g_bytes_unref(bytes);
    foil_key_unref(key1);
    foil_key_unref(key2);
    foil_key_unref(key3);
}

static
void
test_key_aes_generate(
    gconstpointer param)
{
    /* FOIL_TYPE_KEY_AES picks the right type based on the number of bits */
    FoilKey* key = foil_key_generate_new(FOIL_TYPE_KEY_AES, 128);
    g_assert(G_TYPE_FROM_INSTANCE(key) == FOIL_KEY_AES128);
    foil_key_unref(key);

    key = foil_key_generate_new(FOIL_TYPE_KEY_AES, 192);
    g_assert(G_TYPE_FROM_INSTANCE(key) == FOIL_KEY_AES192);
    foil_key_unref(key);

    key = foil_key_generate_new(FOIL_TYPE_KEY_AES, 256);
    g_assert(G_TYPE_FROM_INSTANCE(key) == FOIL_KEY_AES256);
    foil_key_unref(key);

    test_key_aes_generate2(FOIL_TYPE_KEY_AES, 128);
    test_key_aes_generate2(FOIL_KEY_AES128, 128);
    test_key_aes_generate2(FOIL_KEY_AES192, 192);
    test_key_aes_generate2(FOIL_KEY_AES256, 256);
}

static
void
test_key_aes_from_string2(
    GType wrong_type,
    guint bits)
{
    FoilKey* key2;
    FoilKey* key1 = foil_key_generate_new(FOIL_TYPE_KEY_AES, bits);
    GType type = G_TYPE_FROM_INSTANCE(key1);
    GBytes* bytes = foil_key_to_bytes(key1);
    gsize i, n;
    const guint8* data = g_bytes_get_data(bytes, &n);
    GString* buf = g_string_new(NULL);

    for (i=0; i<n; i++) {
        g_string_append_printf(buf, "%02X", data[i]);
    }

    key2 = foil_key_new_from_string(type, buf->str);
    g_assert(!foil_key_new_from_string(wrong_type, buf->str));
    g_assert(key2);
    g_assert(foil_key_equal(key1, key2));

    foil_key_unref(key1);
    foil_key_unref(key2);
    g_bytes_unref(bytes);
    g_string_free(buf, TRUE);
}

static
void
test_key_aes_from_string(
    gconstpointer param)
{
    test_key_aes_from_string2(FOIL_KEY_AES192, 128);
    test_key_aes_from_string2(FOIL_KEY_AES256, 192);
    test_key_aes_from_string2(FOIL_KEY_AES128, 256);
}

static
void
test_key_aes_fingerprint(
    gconstpointer param)
{
    const TestKeyAes* test = param;
    GType type = test->fn_type();
    char* path1 = g_strconcat(DATA_DIR, test->file1, NULL);
    char* path2 = g_strconcat(DATA_DIR, test->file2, NULL);
    FoilKey* key1 = foil_key_new_from_file(type, path1);
    FoilKey* key2 = foil_key_new_from_file(type, path2);
    GBytes* fingerprint1 = foil_key_fingerprint(key1);
    GBytes* fingerprint2 = foil_key_fingerprint(key2);
    g_assert(key1 && key2);
    g_assert(foil_key_equal(key1, key2));
    g_assert(foil_key_equal(key2, key1));
    g_assert(g_bytes_equal(fingerprint1, fingerprint2));
    foil_key_unref(key1);
    foil_key_unref(key2);
    g_free(path1);
    g_free(path2);
}

static
void
test_key_aes_read_ok(
    gconstpointer param)
{
    const TestKeyAes* test = param;
    GType type = test->fn_type();
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
    g_assert(key1 && key2);
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
test_key_aes_read_err(
    gconstpointer param)
{
    const TestKeyAes* test = param;
    GType type = test->fn_type();
    char* path = g_strconcat(DATA_DIR, test->file1, NULL);
    g_assert(!foil_key_new_from_file(type, path));
    g_free(path);

    path = g_strconcat(DATA_DIR, test->file2, NULL);
    g_assert(!foil_key_new_from_file(type, path));
    g_free(path);
}

#define TEST_(name) "/key_aes/" name
#define TEST_READ_OK(bits,name) \
    { TEST_(#bits "-read-" name), test_key_aes_read_ok, \
      foil_key_aes##bits##_get_type, name, name ".txt" }
#define TEST_READ_ERR_(bits,name,name2) \
    { TEST_(#bits "-read-" name), test_key_aes_read_err, \
      foil_key_aes##bits##_get_type, name, name2 }
#define TEST_READ_ERR(bits,name) \
    TEST_READ_ERR_(bits, name, name ".txt")
#define TEST_FINGERPRINT(bits,name) \
    { TEST_(#bits "-fingerprint-" name), test_key_aes_fingerprint, \
      foil_key_aes##bits##_get_type, name, name ".txt" }

static const TestKeyAes tests[] = {
    { TEST_("basic"), test_key_aes_basic,
      foil_impl_key_rsa_private_get_type, "rsa-768" },
    { TEST_("generate"), test_key_aes_generate },
    { TEST_("from_string"), test_key_aes_from_string },
    TEST_READ_OK(128,"128-1"),
    TEST_READ_OK(128,"128-2"),
    TEST_READ_OK(128,"128-3"),
    TEST_READ_OK(256,"256-1"),
    TEST_FINGERPRINT(128,"128-1"),
    TEST_FINGERPRINT(128,"128-2"),
    TEST_READ_ERR(128,"128-short"),
    TEST_READ_ERR(128,"128-long"),
    TEST_READ_ERR(128,"non-existent"),
    TEST_READ_ERR(192,"non-existent"),
    TEST_READ_ERR(256,"non-existent"),
    TEST_READ_ERR(128,"too-big"),
    TEST_READ_ERR_(128,"too-small","blank.txt"),
    TEST_READ_ERR(192,"too-small"),
    TEST_READ_ERR(256,"too-small")
};

int main(int argc, char* argv[])
{
    guint i;
    g_test_init(&argc, &argv, NULL);
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
