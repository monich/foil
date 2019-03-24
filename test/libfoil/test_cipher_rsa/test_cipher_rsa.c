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
#include "foil_cipher.h"
#include "foil_input.h"
#include "foil_output.h"

#define DATA_DIR "data/"

typedef struct test_cipher_rsa {
    const char* name;
    GTestDataFunc fn;
    const char* priv;
    const char* pub;
} TestCipherRsa;

static
void
test_cipher_rsa_basic(
    gconstpointer param)
{
    const TestCipherRsa* test = param;
    char* priv_path = g_strconcat(DATA_DIR, test->priv, NULL);
    FoilKey* priv = foil_key_new_from_file(FOIL_KEY_RSA_PRIVATE, priv_path);
    FoilCipher* rsa = foil_cipher_new(FOIL_CIPHER_RSA_DECRYPT, priv);
    FoilKey* aes_key = foil_key_generate_new(FOIL_KEY_AES128,
        FOIL_KEY_BITS_DEFAULT);

    g_assert(!foil_cipher_type_supports_key(FOIL_CIPHER_RSA_ENCRYPT, 0));
    g_assert(!foil_cipher_type_supports_key(FOIL_KEY_RSA_PRIVATE, 0));
    g_assert(!foil_cipher_new(FOIL_CIPHER_RSA_ENCRYPT, aes_key));
    g_assert(!foil_cipher_new(FOIL_CIPHER_RSA_DECRYPT, aes_key));
    g_assert(!foil_cipher_symmetric(rsa));
    g_assert(!foil_cipher_new(0, priv));
    g_assert(foil_cipher_step(rsa, priv_path, NULL) < 0);

    foil_key_unref(priv);
    foil_key_unref(aes_key);
    foil_cipher_unref(rsa);
    g_free(priv_path);
}

static
void
test_cipher_rsa_decode_failure(
    gconstpointer param)
{
    const TestCipherRsa* test = param;
    char* key_path = g_strconcat(DATA_DIR, test->priv, NULL);
    FoilKey* key = foil_key_new_from_file(FOIL_KEY_RSA_PRIVATE, key_path);
    const static guint8 garbage_bytes[] = {0x01, 0x02, 0x03, 0x04, 0x04, 0x06};
    GBytes* garbage = g_bytes_new_static(garbage_bytes, sizeof(garbage_bytes));
    g_assert(!foil_cipher_bytes(FOIL_CIPHER_RSA_DECRYPT, key, garbage));
    g_bytes_unref(garbage);
    foil_key_unref(key);
    g_free(key_path);
}

static
void
test_cipher_rsa_key_check(
    gconstpointer param)
{
    const TestCipherRsa* test = param;
    char* priv_path = g_strconcat(DATA_DIR, test->priv, NULL);
    char* pub_path = g_strconcat(DATA_DIR, test->pub, NULL);
    FoilKey* priv = foil_key_new_from_file(FOIL_KEY_RSA_PRIVATE, priv_path);
    FoilKey* pub = foil_key_new_from_file(FOIL_KEY_RSA_PUBLIC, pub_path);
    FoilCipher* enc = foil_cipher_new(FOIL_CIPHER_RSA_ENCRYPT, pub);
    FoilCipher* dec = foil_cipher_new(FOIL_CIPHER_RSA_DECRYPT, priv);

    g_assert(!foil_cipher_type_supports_key(FOIL_CIPHER_RSA_ENCRYPT,
                                            FOIL_KEY_AES128));
    g_assert(!foil_cipher_type_supports_key(FOIL_CIPHER_RSA_DECRYPT,
                                            FOIL_KEY_AES128));
    g_assert(foil_cipher_type_supports_key(FOIL_CIPHER_RSA_ENCRYPT,
                                           FOIL_KEY_RSA_PRIVATE));
    g_assert(foil_cipher_type_supports_key(FOIL_CIPHER_RSA_ENCRYPT,
                                           FOIL_KEY_RSA_PUBLIC));
    g_assert(foil_cipher_type_supports_key(FOIL_CIPHER_RSA_DECRYPT,
                                           FOIL_KEY_RSA_PRIVATE));
    g_assert(foil_cipher_type_supports_key(FOIL_CIPHER_RSA_DECRYPT,
                                           FOIL_KEY_RSA_PUBLIC));

    g_assert(foil_cipher_key(enc) == pub);
    g_assert(foil_cipher_key(dec) == priv);

    g_assert(!g_strcmp0(foil_cipher_type_name(FOIL_CIPHER_RSA_ENCRYPT),
                        foil_cipher_name(enc)));
    g_assert(!g_strcmp0(foil_cipher_type_name(FOIL_CIPHER_RSA_DECRYPT),
                        foil_cipher_name(dec)));

    /* Different ciphers should name different names */
    g_assert(g_strcmp0(foil_cipher_name(enc), foil_cipher_name(dec)));

    foil_cipher_unref(foil_cipher_ref(enc));
    foil_cipher_unref(enc);
    foil_cipher_unref(foil_cipher_ref(dec));
    foil_cipher_unref(dec);
    foil_key_unref(priv);
    foil_key_unref(pub);
    g_free(priv_path);
    g_free(pub_path);
}

static
GBytes*
test_cipher_rsa_decrypt(
    FoilKey* key,
    GBytes* bytes)
{
    gsize size = 0;
    const void* data = g_bytes_get_data(bytes, &size);
    FoilCipher* cipher = foil_cipher_new(FOIL_CIPHER_RSA_DECRYPT, key);
    const gsize in_size = foil_cipher_input_block_size(cipher);
    const gsize out_size = foil_cipher_output_block_size(cipher);
    const guint8* ptr = data;
    const gsize tail = size % in_size;
    const guint n = size / in_size;
    void* out_block = g_malloc(out_size);
    GByteArray* out = g_byte_array_new();
    guint i, nout;

    /* Full input blocks */
    for (i=0; i<n; i++) {
        nout = foil_cipher_step(cipher, ptr, out_block);
        g_byte_array_append(out, out_block, nout);
        ptr += in_size;
    }

    /* Finish the process */
    nout = foil_cipher_finish(cipher, ptr, tail, out_block);
    foil_cipher_unref(cipher);
    g_byte_array_append(out, out_block, nout);
    g_free(out_block);
    return g_byte_array_free_to_bytes(out);
}

static
void
test_cipher_rsa(
    const TestCipherRsa* test,
    const void* input,
    gssize input_size)
{
    char* priv_path = g_strconcat(DATA_DIR, test->priv, NULL);
    char* pub_path = g_strconcat(DATA_DIR, test->pub, NULL);
    FoilKey* priv = foil_key_new_from_file(FOIL_KEY_RSA_PRIVATE, priv_path);
    FoilKey* pub = foil_key_new_from_file(FOIL_KEY_RSA_PUBLIC, pub_path);
    GBytes* in = g_bytes_new_static(input, input_size);
    GBytes* out = foil_cipher_bytes(FOIL_CIPHER_RSA_ENCRYPT, pub, in);
    GBytes* decrypted = test_cipher_rsa_decrypt(priv, out);
    GBytes* decrypted2;

    FoilCipher* decrypt = foil_cipher_new(FOIL_CIPHER_RSA_DECRYPT, priv);
    FoilInput* mem_in = foil_input_mem_new(out);
    FoilInput* cipher_in = foil_input_cipher_new(decrypt, mem_in);

    /* Test has_available functionality */
    g_assert(foil_input_has_available(cipher_in, 1));
    g_assert(!foil_input_has_available(cipher_in, input_size*10));

    foil_cipher_unref(decrypt);
    foil_input_unref(mem_in);
    foil_input_unref(cipher_in);

    /* Test reading into a NULL buffer */
    decrypt = foil_cipher_new(FOIL_CIPHER_RSA_DECRYPT, priv);
    mem_in = foil_input_mem_new(out);
    cipher_in = foil_input_cipher_new(decrypt, mem_in);
    g_assert(foil_input_has_available(cipher_in, 1));
    g_assert(!foil_input_read(cipher_in, NULL, input_size+1) != input_size);

    foil_cipher_unref(decrypt);
    foil_input_unref(mem_in);
    foil_input_unref(cipher_in);

    /* Decrypt the data using cipher FoilInput wrapper */
    decrypt = foil_cipher_new(FOIL_CIPHER_RSA_DECRYPT, priv);
    mem_in = foil_input_mem_new(out);
    cipher_in = foil_input_cipher_new(decrypt, mem_in);
    decrypted2 = foil_input_read_all(cipher_in);

    g_assert(!foil_input_read(cipher_in, NULL, 0));
    g_assert(!foil_input_has_available(cipher_in, 1));

    foil_cipher_unref(decrypt);
    foil_input_unref(mem_in);
    foil_input_unref(cipher_in);

    GDEBUG("Plain text:");
    TEST_DEBUG_HEXDUMP_BYTES(in);
    GDEBUG("Encrypted (%u bytes):", (guint)g_bytes_get_size(out));
    TEST_DEBUG_HEXDUMP_BYTES(out);

    GDEBUG("Decrypted:");
    TEST_DEBUG_HEXDUMP_BYTES(decrypted);
    g_assert(g_bytes_equal(in, decrypted));

    GERR("Decrypted (again):");
    TEST_DEBUG_HEXDUMP_BYTES(decrypted2);
    g_assert(g_bytes_equal(in, decrypted2));

    g_bytes_unref(in);
    g_bytes_unref(out);
    g_bytes_unref(decrypted);
    g_bytes_unref(decrypted2);
    foil_key_unref(priv);
    foil_key_unref(pub);
    g_free(priv_path);
    g_free(pub_path);
}

static
void
test_cipher_rsa_short(
    gconstpointer param)
{
    /* Exactly one block for 768-bit key (54 bytes)*/
    static const char clear_text[] =
        "This is a secret.This is a secret.This is a secret.Th";
    test_cipher_rsa(param, clear_text, sizeof(clear_text)-1);
}

static
void
test_cipher_rsa_long(
    gconstpointer param)
{
    static const char clear_text[] =
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
    test_cipher_rsa(param, clear_text, sizeof(clear_text)-1);
}

static
void
test_cipher_rsa_blocks(
    gconstpointer param)
{
    static const char clear_text[] =
        "Nor have We been wanting in attentions to our British brethren. "
        "We have warned them from time to time of attempts by their "
        "legislature to extend an unwarrantable jurisdiction over us. "
        "We have reminded them of the circumstances of our emigration and "
        "settlement here. We have appealed to their native justice and "
        "magnanimity, and we have conjured them by the ties of our common "
        "kindred to disavow these usurpations, which, would inevitably "
        "interrupt our connections and correspondence. They too have been "
        "deaf to the voice of justice and of consanguinity. We must, "
        "therefore, acquiesce in the necessity, which denounces our "
        "Separation, and hold them, as we hold the rest of mankind, "
        "Enemies in War, in Peace Friends.\n               ";
    const gsize clear_text_len = sizeof(clear_text)-1;

    const TestCipherRsa* test = param;
    char* priv_path = g_strconcat(DATA_DIR, test->priv, NULL);
    char* pub_path = g_strconcat(DATA_DIR, test->pub, NULL);
    FoilKey* priv = foil_key_new_from_file(FOIL_KEY_RSA_PRIVATE, priv_path);
    FoilKey* pub = foil_key_new_from_file(FOIL_KEY_RSA_PUBLIC, pub_path);
    GBytes* in = g_bytes_new_static(clear_text, clear_text_len);
    FoilCipher* rsa_encrypt = foil_cipher_new(FOIL_CIPHER_RSA_ENCRYPT, pub);
    FoilOutput* out = foil_output_mem_new(NULL);
    GBytes* enc;
    GBytes* dec;

    FoilBytes data[5];
    gsize count;
    data[0].val = (void*)clear_text;
    count = data[0].len = 40;
    data[1].val = (void*)(clear_text + count);
    count += (data[1].len = 12);
    data[2].val = (void*)(clear_text + count);
    count += (data[2].len = 53);
    data[3].val = (void*)(clear_text + count);
    count += (data[3].len = 3);
    data[4].val = (void*)(clear_text + count);
    data[4].len = clear_text_len - count;

    foil_cipher_write_data_blocks(rsa_encrypt, data, G_N_ELEMENTS(data),
        out, NULL);
    enc = foil_output_free_to_bytes(out);
    dec = test_cipher_rsa_decrypt(priv, enc);
    GDEBUG("Plain text:");
    TEST_DEBUG_HEXDUMP_BYTES(in);
    GDEBUG("Encrypted (%u bytes):", (guint)g_bytes_get_size(enc));
    TEST_DEBUG_HEXDUMP_BYTES(enc);
    GDEBUG("Decrypted:");
    TEST_DEBUG_HEXDUMP_BYTES(dec);
    g_assert(g_bytes_equal(in, dec));

    g_bytes_unref(in);
    g_bytes_unref(enc);
    g_bytes_unref(dec);
    foil_cipher_unref(rsa_encrypt);
    foil_key_unref(priv);
    foil_key_unref(pub);
    g_free(priv_path);
    g_free(pub_path);
}

#define TEST_(name) "/cipher_rsa/" name
#define TEST_CIPHER_SHORT(name) \
    { TEST_("short-" name), test_cipher_rsa_short, name, name ".pub" }
#define TEST_CIPHER_LONG(name) \
    { TEST_("long-" name), test_cipher_rsa_long, name, name ".pub" }
#define TEST_CIPHER_BLOCKS(name) \
    { TEST_("blocks-" name), test_cipher_rsa_blocks, name, name ".pub" }
#define TEST_CIPHER_KEY_CHECK(name) \
    { TEST_("key-check-" name), test_cipher_rsa_key_check, name, name ".pub" }

static const TestCipherRsa tests[] = {
    { TEST_("basic"), test_cipher_rsa_basic, "rsa-768" },
    { TEST_("decode_failure"), test_cipher_rsa_decode_failure, "rsa-768" },
    TEST_CIPHER_KEY_CHECK("rsa-768"  ),
    TEST_CIPHER_KEY_CHECK("rsa-1024" ),
    TEST_CIPHER_KEY_CHECK("rsa-1500" ),
    TEST_CIPHER_KEY_CHECK("rsa-2048" ),
    TEST_CIPHER_SHORT("rsa-768"  ),
    TEST_CIPHER_SHORT("rsa-1024" ),
    TEST_CIPHER_SHORT("rsa-1500" ),
    TEST_CIPHER_SHORT("rsa-2048" ),
    TEST_CIPHER_LONG("rsa-768"  ),
    TEST_CIPHER_LONG("rsa-1024" ),
    TEST_CIPHER_LONG("rsa-1500" ),
    TEST_CIPHER_LONG("rsa-2048" ),
    TEST_CIPHER_BLOCKS("rsa-768"  ),
    TEST_CIPHER_BLOCKS("rsa-1024" ),
    TEST_CIPHER_BLOCKS("rsa-1500" ),
    TEST_CIPHER_BLOCKS("rsa-2048" )
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
