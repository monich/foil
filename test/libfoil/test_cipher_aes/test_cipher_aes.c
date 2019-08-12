/*
 * Copyright (C) 2016-2019 by Slava Monich
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

#include "foil_key.h"
#include "foil_cipher.h"
#include "foil_output.h"

#define DATA_DIR "data/"
#define TEST_TIMEOUT (10) /* seconds */

typedef struct test_cipher_aes {
    const char* name;
    GTestDataFunc fn;
    const char* key_file;
    GType (*key_type)(void);
    GType (*enc_type)(void);
    GType (*dec_type)(void);
    const void* input;
    gsize input_size;
} TestCipherAes;

static
void
test_padding(
    guint8* block,
    gsize data_size,
    gsize block_size)
{
    memset(block + data_size, 0, block_size - data_size);
}

static
void
test_cipher_aes_basic(
    gconstpointer param)
{
    const TestCipherAes* test = param;
    char* key_path = g_strconcat(DATA_DIR, test->key_file, NULL);
    FoilKey* key = foil_key_new_from_file(FOIL_KEY_AES128, key_path);
    FoilCipher* enc = foil_cipher_new(test->enc_type(), key);
    FoilCipher* dec = foil_cipher_new(test->dec_type(), key);

    g_assert(!foil_cipher_type_supports_key(test->enc_type(), 0));
    g_assert(!foil_cipher_type_supports_key(test->dec_type(), 0));
    g_assert(!foil_cipher_type_supports_key(FOIL_KEY_AES128, 0));
    g_assert(foil_cipher_symmetric(enc));
    g_assert(foil_cipher_symmetric(dec));
    g_assert(foil_cipher_set_padding_func(enc, test_padding));
    g_assert(foil_cipher_step(dec, key_path, NULL) < 0);

    foil_key_unref(key);
    foil_cipher_unref(enc);
    foil_cipher_unref(dec);
    g_free(key_path);
}

static
gboolean
test_timeout(
    gpointer param)
{
    GERR("TIMEOUT");
    g_assert(FALSE);
    g_main_loop_quit(param);
    return G_SOURCE_CONTINUE;
}

static
void
test_cipher_aes_async_done(
    FoilCipher* cipher,
    int result,
    void* arg)
{
    g_assert(result == 16);
    g_main_loop_quit(arg);
}

static
void
test_cipher_aes_cancel(
    gconstpointer param)
{
    GMainLoop* loop;
    guint timeout_id;
    const TestCipherAes* test = param;
    char* key_path = g_strconcat(DATA_DIR, test->key_file, NULL);
    FoilKey* key = foil_key_new_from_file(FOIL_KEY_AES128, key_path);
    GType type = FOIL_CIPHER_AES_CBC_ENCRYPT;
    FoilCipher* enc = foil_cipher_new(type, key);
    FoilOutput* memout;
    guint id;
    static const guint8 in[16] = {0};
    static const guint8 expected1[] = {
        0x07, 0xfe, 0xef, 0x74, 0xe1, 0xd5, 0x03, 0x6e,
        0x90, 0x0e, 0xee, 0x11, 0x8e, 0x94, 0x92, 0x93
    };
    static const guint8 expected2[] = {
        0x89, 0xcf, 0x84, 0x08, 0x25, 0x0b, 0xf8, 0xc4,
        0xac, 0x9a, 0x44, 0x86, 0x53, 0x64, 0xb8, 0x37
    };
    guint8 out[16];
    guint8 original[sizeof(out)];

    g_assert(foil_cipher_input_block_size(enc) == sizeof(in));
    g_assert(foil_cipher_output_block_size(enc) == sizeof(out));
    memset(out, 0, sizeof(out));
    memcpy(original, out, sizeof(out));
    g_assert(!foil_cipher_step_async(enc, in, NULL /* error */, NULL, NULL));
    id = foil_cipher_step_async(enc, in, out, NULL, NULL);
    g_assert(id);
    g_source_remove(id);
    foil_cipher_cancel_all(enc);
    g_assert(!memcmp(out, original, sizeof(out)));
    foil_cipher_unref(enc);

    enc = foil_cipher_new(type, key);
    g_assert(foil_cipher_finish_async(enc, in, 0, NULL, NULL, NULL));
    g_assert(foil_cipher_finish_async(enc, in, 0, NULL, NULL, NULL));
    foil_cipher_cancel_all(enc);
    foil_cipher_unref(enc);

    enc = foil_cipher_new(type, key);
    g_assert(foil_cipher_step_async(enc, in, out, NULL, NULL));
    id = foil_cipher_step_async(enc, in, out, NULL, NULL);
    g_assert(foil_cipher_step_async(enc, in, out, NULL, NULL));
    g_source_remove(id);
    foil_cipher_unref(enc);

    enc = foil_cipher_new(type, key);
    id = foil_cipher_step_async(enc, in, out, NULL, NULL);
    g_assert(foil_cipher_step_async(enc, in, out, NULL, NULL));
    g_source_remove(id);
    foil_cipher_unref(enc);

    /* Even if we don't cancel the requests, they get cancelled
     * automatically when the cipher gets destroyed */
    enc = foil_cipher_new(type, key);
    g_assert(foil_cipher_step_async(enc, in, out, NULL, NULL));
    g_assert(foil_cipher_finish_async(enc, in, 0, NULL, NULL, NULL));
    g_assert(!memcmp(out, original, sizeof(out)));
    foil_cipher_unref(enc);

    /* Actually encrypt something */
    enc = foil_cipher_new(type, key);
    loop = g_main_loop_new(NULL, TRUE);
    g_assert(foil_cipher_finish_async(enc, in, sizeof(in), out,
        test_cipher_aes_async_done, loop));
    timeout_id = g_timeout_add_seconds(TEST_TIMEOUT, test_timeout, loop);
    g_main_loop_run(loop);
    g_source_remove(timeout_id);
    g_main_loop_unref(loop);
    foil_cipher_unref(enc);
    GDEBUG("Result:");
    TEST_DEBUG_HEXDUMP(out, sizeof(out));
    g_assert(!memcmp(out, expected1, sizeof(out)));

    /* The same but with the additional foil_cipher_step_async */
    enc = foil_cipher_new(type, key);
    loop = g_main_loop_new(NULL, TRUE);
    g_assert(foil_cipher_step_async(enc, in, out, NULL, NULL));
    g_assert(foil_cipher_finish_async(enc, in, sizeof(in), out,
        test_cipher_aes_async_done, loop));
    timeout_id = g_timeout_add_seconds(TEST_TIMEOUT, test_timeout, loop);
    g_main_loop_run(loop);
    g_source_remove(timeout_id);
    g_main_loop_unref(loop);
    foil_cipher_unref(enc);
    GDEBUG("Result:");
    TEST_DEBUG_HEXDUMP(out, sizeof(out));
    g_assert(!memcmp(out, expected2, sizeof(out)));

    enc = foil_cipher_new(type, key);
    memout = foil_output_file_new_tmp();
    g_assert(foil_cipher_write_data_async(enc, in, sizeof(in), memout,
        NULL, NULL, NULL));
    g_assert(id);
    foil_cipher_cancel_all(enc);
    foil_cipher_unref(enc);
    foil_output_unref(memout);

    foil_key_unref(key);
    g_free(key_path);
}

static
GBytes*
test_cipher_bytes(
    FoilCipher* cipher,
    GBytes* bytes)
{
    gsize size = 0;
    const void* data = g_bytes_get_data(bytes, &size);
    const gsize in_size = foil_cipher_input_block_size(cipher);
    const gsize out_size = foil_cipher_output_block_size(cipher);
    const guint8* ptr = data;
    const gsize tail = size % in_size;
    const guint n = size / in_size;
    void* out_block = g_malloc(out_size);
    GByteArray* out = g_byte_array_new();
    int nout = 0;
    guint i;

    /* Full input blocks */
    for (i = 0; i < n; i++) {
        nout = foil_cipher_step(cipher, ptr, out_block);
        g_assert(nout >= 0);
        g_byte_array_append(out, out_block, nout);
        ptr += in_size;
    }

    /* Finish the process */
    nout = foil_cipher_finish(cipher, ptr, tail, out_block);
    g_assert(nout >= 0);
    g_byte_array_append(out, out_block, nout);
    g_free(out_block);
    return g_byte_array_free_to_bytes(out);
}

static
void
test_cipher_aes_clone(
    gconstpointer param)
{
    const TestCipherAes* test = param;
    char* key_path = g_strconcat(DATA_DIR, test->key_file, NULL);
    GBytes* in = g_bytes_new_static(test->input, test->input_size);
    FoilKey* key = foil_key_new_from_file(test->key_type(), key_path);
    FoilCipher* enc1 = foil_cipher_new(test->enc_type(), key);
    FoilCipher* enc2 = foil_cipher_clone(enc1);
    GBytes* out1 = test_cipher_bytes(enc1, in);
    GBytes* out2 = test_cipher_bytes(enc2, in);
    FoilCipher* dec1 = foil_cipher_new(test->dec_type(), key);
    FoilCipher* dec2 = foil_cipher_clone(dec1);
    GBytes* res1 = test_cipher_bytes(dec1, in);
    GBytes* res2 = test_cipher_bytes(dec2, in);
    GDEBUG("Plain text:");
    TEST_DEBUG_HEXDUMP_BYTES(in);
    GDEBUG("Encrypted (%u bytes):", (guint)g_bytes_get_size(out1));
    TEST_DEBUG_HEXDUMP_BYTES(out1);
    g_assert(g_bytes_equal(out1, out2));
    GDEBUG("Decrypted:");
    TEST_DEBUG_HEXDUMP_BYTES(res1);
    g_assert(g_bytes_equal(res1, res2));
    g_bytes_unref(in);
    g_bytes_unref(out1);
    g_bytes_unref(out2);
    g_bytes_unref(res1);
    g_bytes_unref(res2);
    foil_cipher_unref(enc1);
    foil_cipher_unref(enc2);
    foil_cipher_unref(dec1);
    foil_cipher_unref(dec2);
    foil_key_unref(key);
    g_free(key_path);
}

static
void
test_cipher_aes_sync(
    gconstpointer param)
{
    const TestCipherAes* test = param;
    char* key_path = g_strconcat(DATA_DIR, test->key_file, NULL);
    FoilKey* key = foil_key_new_from_file(test->key_type(), key_path);
    GBytes* in = g_bytes_new_static(test->input, test->input_size);
    GBytes* out = foil_cipher_bytes(test->enc_type(), key, in);
    GBytes* dec = foil_cipher_bytes(test->dec_type(), key, out);
    GBytes* dec2;
    g_assert(dec);
    dec2 = g_bytes_new_from_bytes(dec, 0, test->input_size);
    GDEBUG("Plain text:");
    TEST_DEBUG_HEXDUMP_BYTES(in);
    GDEBUG("Encrypted (%u bytes):", (guint)g_bytes_get_size(out));
    TEST_DEBUG_HEXDUMP_BYTES(out);
    GDEBUG("Decrypted:");
    TEST_DEBUG_HEXDUMP_BYTES(dec);
    g_assert(g_bytes_equal(in, dec2));
    g_bytes_unref(in);
    g_bytes_unref(out);
    g_bytes_unref(dec);
    g_bytes_unref(dec2);
    foil_key_unref(key);
    g_free(key_path);
}

static
void
test_cipher_aes_async_proc(
    FoilCipher* cipher,
    gboolean ok,
    void* arg)
{
    g_assert(ok);
    g_main_loop_quit(arg);
}

static
void
test_cipher_aes_async(
    gconstpointer param)
{
    const TestCipherAes* test = param;
    GMainLoop* loop = g_main_loop_new(NULL, TRUE);
    char* key_path = g_strconcat(DATA_DIR, test->key_file, NULL);
    FoilKey* key = foil_key_new_from_file(test->key_type(), key_path);
    FoilCipher* cipher = foil_cipher_new(test->enc_type(), key);
    FoilOutput* out = foil_output_mem_new(NULL);
    GBytes* enc;
    GBytes* dec;
    GBytes* dec2;
    guint timeout_id, id;

    /* This one must fail (no output) */
    g_assert(!foil_cipher_write_data_async(cipher, test->input,
        test->input_size, NULL, NULL, test_cipher_aes_async_proc, loop));

    /* Encrypt asynchronously (the second attempt must fail) */
    id = foil_cipher_write_data_async(cipher, test->input,
        test->input_size, out, NULL, test_cipher_aes_async_proc, loop);
    g_assert(id);
    g_assert(!foil_cipher_write_data_async(cipher, test->input,
        test->input_size, out, NULL, test_cipher_aes_async_proc, loop));
    timeout_id = g_timeout_add_seconds(TEST_TIMEOUT, test_timeout, loop);
    g_main_loop_run(loop);
    g_source_remove(timeout_id);
    foil_cipher_unref(cipher);
    enc = foil_output_free_to_bytes(out);
    g_assert(enc);

    /* Decrypt asynchronously */
    cipher = foil_cipher_new(test->dec_type(), key);
    out = foil_output_mem_new(NULL);
    id = foil_cipher_write_data_async(cipher, g_bytes_get_data(enc, NULL),
        g_bytes_get_size(enc), out, NULL, test_cipher_aes_async_proc, loop);
    timeout_id = g_timeout_add_seconds(TEST_TIMEOUT, test_timeout, loop);
    g_main_loop_run(loop);
    g_source_remove(timeout_id);
    foil_cipher_unref(cipher);
    dec = foil_output_free_to_bytes(out);
    g_assert(dec);
    dec2 = g_bytes_new_from_bytes(dec, 0, test->input_size);

    GDEBUG("Plain text:");
    TEST_DEBUG_HEXDUMP(test->input, test->input_size);
    GDEBUG("Encrypted (%u bytes):", (guint)g_bytes_get_size(enc));
    TEST_DEBUG_HEXDUMP_BYTES(enc);
    GDEBUG("Decrypted:");
    TEST_DEBUG_HEXDUMP_BYTES(dec);
    g_assert(test_bytes_equal(dec2, test->input, test->input_size));
    g_bytes_unref(enc);
    g_bytes_unref(dec);
    g_bytes_unref(dec2);
    foil_key_unref(key);
    g_main_loop_unref(loop);
    g_free(key_path);
}

static const char input_short[] = "This is a secret.This is a secr";
static const char input_long[] =
    "When in the Course of human events, it becomes necessary for one "
    "people to dissolve the political bands which have connected them "
    "with another, and to assume among the powers of the earth, the "
    "separate and equal station to which the Laws of Nature and of "
    "Nature's God entitle them, a decent respect to the opinions of "
    "mankind requires that they should declare the causes which impel "
    "them to the separation.\n\n"
    "We hold these truths to be self-evident, that all men are created "
    "equal, that they are endowed by their Creator with certain "
    "unalienable Rights, that among these are Life, Liberty and the "
    "pursuit of Happiness.--That to secure these rights, Governments "
    "are instituted among Men, deriving their just powers from the "
    "consent of the governed, --That whenever any Form of Government "
    "becomes destructive of these ends, it is the Right of the People "
    "to alter or to abolish it, and to institute new Government, laying "
    "its foundation on such principles and organizing its powers in such "
    "form, as to them shall seem most likely to effect their Safety and "
    "Happiness. Prudence, indeed, will dictate that Governments long "
    "established should not be changed for light and transient causes; "
    "and accordingly all experience hath shewn, that mankind are more "
    "disposed to suffer, while evils are sufferable, than to right "
    "themselves by abolishing the forms to which they are accustomed. "
    "But when a long train of abuses and usurpations, pursuing "
    "invariably the same Object evinces a design to reduce them under "
    "absolute Despotism, it is their right, it is their duty, to throw "
    "off such Government, and to provide new Guards for their future "
    "security.--Such has been the patient sufferance of these Colonies; "
    "and such is now the necessity which constrains them to alter their "
    "former Systems of Government. The history of the present King of "
    "Great Britain is a history of repeated injuries and usurpations, "
    "all having in direct object the establishment of an absolute "
    "Tyranny over these States. To prove this, let Facts be submitted "
    "to a candid world.\n";

#define TEST_(name) "/cipher_aes/" name
#define TEST_CLONE_(bits,mode,name) \
    { TEST_("clone" #bits "-" #mode "-" #name), \
      test_cipher_aes_clone, "aes" #bits, foil_key_aes##bits##_get_type, \
      foil_impl_cipher_aes_##mode##_encrypt_get_type, \
      foil_impl_cipher_aes_##mode##_decrypt_get_type, \
      input_##name, sizeof(input_##name) }
#define TEST_CLONE(bits,name) \
    TEST_CLONE_(bits,cbc,name), \
    TEST_CLONE_(bits,ecb,name)
#define TEST_SYNC_(bits,mode,name) \
    { TEST_("sync" #bits "-" #mode "-" #name), \
      test_cipher_aes_sync, "aes" #bits, foil_key_aes##bits##_get_type, \
      foil_impl_cipher_aes_##mode##_encrypt_get_type, \
      foil_impl_cipher_aes_##mode##_decrypt_get_type, \
      input_##name, sizeof(input_##name) }
#define TEST_SYNC(bits,name) \
    TEST_SYNC_(bits,cbc,name), \
    TEST_SYNC_(bits,ecb,name)
#define TEST_ASYNC_(bits,mode,name) \
    { TEST_("async" #bits "-" #mode "-" #name), \
      test_cipher_aes_async, "aes" #bits, foil_key_aes##bits##_get_type, \
      foil_impl_cipher_aes_##mode##_encrypt_get_type, \
      foil_impl_cipher_aes_##mode##_decrypt_get_type, \
      input_##name, sizeof(input_##name) }
#define TEST_ASYNC(bits,name) \
    TEST_ASYNC_(bits,cbc,name), \
    TEST_ASYNC_(bits,ecb,name)

static const TestCipherAes tests[] = {
    { TEST_("basic-cbc"), test_cipher_aes_basic, "aes128", NULL,
      foil_impl_cipher_aes_cbc_encrypt_get_type,
      foil_impl_cipher_aes_cbc_decrypt_get_type},
    { TEST_("basic-ecb"), test_cipher_aes_basic, "aes128", NULL,
      foil_impl_cipher_aes_cbc_encrypt_get_type,
      foil_impl_cipher_aes_cbc_decrypt_get_type},
    { TEST_("cancel"), test_cipher_aes_cancel, "aes128" },
    TEST_CLONE(128,short),
    TEST_CLONE(192,short),
    TEST_CLONE(256,short),
    TEST_CLONE(128,long),
    TEST_CLONE(192,long),
    TEST_CLONE(256,long),
    TEST_SYNC(128,short),
    TEST_SYNC(192,short),
    TEST_SYNC(256,short),
    TEST_SYNC(128,long),
    TEST_SYNC(192,long),
    TEST_SYNC(256,long),
    TEST_ASYNC(128,short),
    TEST_ASYNC(192,short),
    TEST_ASYNC(256,short),
    TEST_ASYNC(128,long),
    TEST_ASYNC(192,long),
    TEST_ASYNC(256,long),
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
