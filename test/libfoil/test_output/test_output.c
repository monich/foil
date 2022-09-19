/*
 * Copyright (C) 2016-2022 by Slava Monich <slava@monich.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *   3. Neither the names of the copyright holders nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation
 * are those of the authors and should not be interpreted as representing
 * any official policies, either expressed or implied.
 */

#include "test_common.h"

#include "foil_output.h"
#include "foil_cipher.h"
#include "foil_digest.h"
#include "foil_key.h"
#include "foil_private_key.h"

#include <glib/gstdio.h>

#define TEST_(name) "/output/" name

typedef struct test_output_cipher_data {
    const char* name;
    GUtilData key;
    GType (*key_type)(void);
    FoilKey* (*dec_key)(FoilKey*);
    GType (*enc_type)(void);
    GType (*dec_type)(void);
    const void* input;
    gsize input_size;
} TestOutputCipher;

static
void
test_output_null(
    void)
{
    guint8 buf[1];
    FoilKey* key = foil_key_generate_new(FOIL_TYPE_KEY_AES, 128);
    FoilCipher* cipher = foil_cipher_new(FOIL_CIPHER_AES_CBC_ENCRYPT, key);
    FoilOutput* out = foil_output_mem_new(NULL);
    GBytes* empty = g_bytes_new_static(buf, 0);

    /* Test resistance to NULL and all kinds of invalid output */
    foil_output_unref(foil_output_mem_new(NULL));
    foil_output_close(NULL);
    foil_output_unref(NULL);
    g_assert(!foil_output_ref(NULL));
    g_assert(!foil_output_cipher_mem_new(NULL, NULL, NULL));
    g_assert(!foil_output_cipher_new(NULL, cipher, NULL));
    g_assert(!foil_output_cipher_new(NULL, NULL, NULL));
    g_assert(!foil_output_digest_new(NULL, NULL));
    g_assert(!foil_output_file_new_open(NULL));
    g_assert(!foil_output_free_to_bytes(NULL));
    g_assert(!foil_output_flush(NULL));
    g_assert(!foil_output_reset(NULL));
    g_assert(!foil_output_bytes_written(NULL));
    g_assert(foil_output_write(NULL, NULL, 0) < 0);
    g_assert(!foil_output_write(out, NULL, 0));
    g_assert(!foil_output_write(out, buf, 0));
    g_assert(!foil_output_write(out, NULL, 1));
    g_assert(foil_output_write_bytes(NULL, NULL) < 0);
    g_assert(!foil_output_write_bytes(out, NULL));
    g_assert(foil_output_write_bytes(out, empty) == 0);
    g_assert(!foil_output_write_bytes_all(NULL, NULL));
    g_assert(foil_output_write_bytes_all(out, NULL));
    g_assert(foil_output_write_bytes_all(out, empty));
    foil_output_unref(out);
    foil_cipher_unref(cipher);
    foil_key_unref(key);
    g_bytes_unref(empty);
}

static
void
test_output_basic(
    void)
{
    static const guint8 test123[] = { '1', '2', '3' };
    GByteArray* buf = g_byte_array_new();
    FoilOutput* out = foil_output_mem_new(buf);

    /* free_to_bytes after close returns NULL */
    foil_output_close(out);
    g_assert(!foil_output_free_to_bytes(out));

    out = foil_output_mem_new(buf);
    g_assert(foil_output_write_all(out, test123, sizeof(test123)));
    g_assert(buf->len == sizeof(test123));
    g_assert(foil_output_bytes_written(out) == sizeof(test123));
    g_assert(!memcmp(buf->data, test123, sizeof(test123)));

    /* Reset sets number of bytes to zero.*/
    g_assert(foil_output_reset(out));
    g_assert(!foil_output_bytes_written(out));

    /* Write and reset after free has to fail */
    foil_output_ref(out);
    foil_output_ref(out);
    g_bytes_unref(foil_output_free_to_bytes(out));
    foil_output_close(out);
    g_assert(!foil_output_free_to_bytes(out));
    g_assert(foil_output_write(out, test123, sizeof(test123)) < 0);
    g_assert(!foil_output_reset(out));
    foil_output_unref(out);

    /* Modifying the buffer in parallel with FoilOutputMem - this is not
     * a correct behaviour, if foil_output_mem_to_bytes detects that, it
     * should fail */
    out = foil_output_mem_new(buf);
    g_assert(foil_output_write_all(out, test123, sizeof(test123)));
    g_byte_array_append(buf, test123, sizeof(test123));
    g_assert(!foil_output_free_to_bytes(out));

    g_byte_array_unref(buf);
}

static
void
test_output_cipher_basic(
    void)
{
    static const char prefix[] = "This is a prefix";
    static const char test_data[] = "This is a secret";
    GByteArray* buf1 = g_byte_array_new();
    GByteArray* buf2 = g_byte_array_new();
    FoilKey* key = foil_key_generate_new(FOIL_TYPE_KEY_AES, 128);
    FoilCipher* cipher1 = foil_cipher_new(FOIL_CIPHER_AES_CBC_ENCRYPT, key);
    FoilCipher* cipher2 = foil_cipher_new(FOIL_CIPHER_AES_CBC_ENCRYPT, key);
    FoilOutput* buf = foil_output_mem_new(buf1);
    FoilOutput* out = foil_output_cipher_new(buf, cipher1, NULL);
    FoilOutput* out_mem;

    /* Add some data in front of the ciphered data */
    g_byte_array_append(buf2, (const void*)prefix, sizeof(prefix));
    out_mem = foil_output_cipher_mem_new(buf2, cipher2, NULL);

    foil_cipher_unref(cipher1);
    foil_cipher_unref(cipher2);
    g_assert(!foil_output_reset(out));
    g_assert(!foil_output_reset(out_mem));
    g_assert(foil_output_flush(out));
    g_assert(foil_output_write_all(out, test_data, sizeof(test_data)));
    g_assert(foil_output_write_all(out_mem, test_data, sizeof(test_data)));
    TEST_DEBUG_HEXDUMP(buf1->data, buf1->len);
    g_assert_cmpuint(buf1->len, > ,0);
    g_assert_cmpuint(buf1->len, == ,buf2->len - sizeof(prefix));
    g_assert(!memcmp(buf1->data, buf2->data + sizeof(prefix), buf1->len));
    foil_output_unref(out_mem);

    /* Fail to write to a closed stream */
    foil_output_close(buf);
    foil_output_unref(buf);
    g_assert(!foil_output_write_all(out, test_data, sizeof(test_data)));
    foil_output_unref(out);

    /* Another kind of failure due to a closed underlying stream */
    cipher1 = foil_cipher_new(FOIL_CIPHER_AES_CBC_ENCRYPT, key);
    buf = foil_output_mem_new(NULL);
    out = foil_output_cipher_new(buf, cipher1, NULL);
    foil_cipher_unref(cipher1);

    g_assert(foil_output_write_all(out, test_data, sizeof(test_data)));
    foil_output_close(buf);
    foil_output_unref(buf);
    g_assert(!foil_output_free_to_bytes(out));

    g_byte_array_unref(buf1);
    g_byte_array_unref(buf2);
    foil_key_unref(key);
}

static
void
test_output_cipher(
    gconstpointer param)
{
    static const char prefix[] = "This is a prefix";
    const TestOutputCipher* test = param;
    const guint8* in = test->input;
    GType digest_type = FOIL_DIGEST_SHA1;
    GByteArray* mem2 = g_byte_array_new_take(g_memdup(prefix, sizeof(prefix)),
        sizeof(prefix)); /* Byte array with a prefix */
    GBytes* in_bytes = g_bytes_new_static(in, test->input_size);
    FoilKey* enc_key = foil_key_new_from_data(test->key_type(),
        test->key.bytes, test->key.size);
    FoilKey* dec_key = test->dec_key(enc_key);
    FoilDigest* digest = foil_digest_new(digest_type);
    FoilDigest* digest2 = foil_digest_new(digest_type);
    FoilCipher* enc = foil_cipher_new(test->enc_type(), enc_key);
    FoilCipher* enc2 = foil_cipher_new(test->enc_type(), enc_key);
    FoilCipher* enc3 = foil_cipher_new(test->enc_type(), enc_key);
    FoilCipher* dec = foil_cipher_new(test->dec_type(), dec_key);
    FoilOutput* buf = foil_output_mem_new(NULL);
    FoilOutput* out = foil_output_cipher_new(buf, enc, digest);
    FoilOutput* out2 = foil_output_cipher_mem_new(mem2, enc2, digest2);
    FoilOutput* out3 = foil_output_cipher_mem_new(NULL, enc3, NULL);
    GByteArray* dec_bytes = g_byte_array_new();
    GBytes* d;
    GBytes* d1;
    GBytes* d2;
    GBytes* enc_bytes;
    GBytes* enc_bytes2;
    GBytes* enc_bytes3;
    gsize i;

    foil_key_unref(enc_key);
    foil_key_unref(dec_key);
    foil_output_unref(buf);
    foil_cipher_unref(enc);
    foil_cipher_unref(enc2);
    foil_cipher_unref(enc3);
    g_byte_array_unref(mem2);

    /* Cipher input byte by byte */
    for (i = 0; i < test->input_size; i++) {
        g_assert(foil_output_write_all(out, in + i, 1));
        g_assert(foil_output_write_all(out2, in + i, 1));
        g_assert(foil_output_write_all(out3, in + i, 1));
    }
    enc_bytes = foil_output_free_to_bytes(out);
    enc_bytes2 = foil_output_free_to_bytes(out2);
    enc_bytes3 = foil_output_free_to_bytes(out3);
    g_assert(g_bytes_equal(enc_bytes, enc_bytes2));
    g_assert(g_bytes_equal(enc_bytes, enc_bytes3));
    g_bytes_unref(enc_bytes2);
    g_bytes_unref(enc_bytes3);

    d = foil_digest_bytes(digest_type, in_bytes);
    d1 = foil_digest_free_to_bytes(digest);
    d2 = foil_digest_free_to_bytes(digest2);
    g_assert(g_bytes_equal(d, d1));
    g_assert(g_bytes_equal(d, d2));
    g_bytes_unref(d);
    g_bytes_unref(d1);
    g_bytes_unref(d2);

    /* And decipher it in one shot */
    buf = foil_output_mem_new(dec_bytes);
    out = foil_output_cipher_new(buf, dec, NULL);
    foil_output_unref(buf);
    foil_cipher_unref(dec);
    g_assert(foil_output_write_bytes_all(out, enc_bytes));
    foil_output_close(out);
    foil_output_unref(out);

    GDEBUG("Plain text:");
    TEST_DEBUG_HEXDUMP_BYTES(in_bytes);
    GDEBUG("Encrypted (%u bytes):", (guint)g_bytes_get_size(enc_bytes));
    TEST_DEBUG_HEXDUMP_BYTES(enc_bytes);
    GDEBUG("Decrypted:");
    TEST_DEBUG_HEXDUMP(dec_bytes->data, dec_bytes->len);

    /* Encryption and/or decryption may add some padding */
    g_assert_cmpuint(dec_bytes->len, >= ,test->input_size);
    g_assert(!memcmp(dec_bytes->data, test->input, test->input_size));

    g_bytes_unref(in_bytes);
    g_bytes_unref(enc_bytes);
    g_byte_array_unref(dec_bytes);
}

static
void
test_output_digest1(
    void)
{
    static const guint8 test1234[] = { '1', '2', '3', '4' };
    GType digest_type = FOIL_DIGEST_MD5;
    GByteArray* buf = g_byte_array_new();
    FoilDigest* digest = foil_digest_new(digest_type);
    FoilOutput* out = foil_output_mem_new(buf);
    FoilOutput* out_digest = foil_output_digest_new(out, digest);
    GBytes* d1 = foil_digest_data(digest_type, test1234, sizeof(test1234));
    GBytes* d2;

    g_assert(foil_output_write_all(out_digest, test1234, sizeof(test1234)));
    g_assert_cmpuint(buf->len, == ,sizeof(test1234));
    g_assert_cmpint(foil_output_bytes_written(out), == ,sizeof(test1234));
    g_assert_cmpint(foil_output_bytes_written(out_digest),==,sizeof(test1234));
    g_assert(!memcmp(buf->data, test1234, sizeof(test1234)));

    /* Write has to fail if we close the underlying output stream */
    foil_output_close(out);
    g_assert_cmpint(foil_output_write(out_digest, test1234, 1), < ,0);
    g_assert_cmpint(foil_output_write_bytes(out_digest, d1), < ,0);
    g_assert(!foil_output_write_bytes_all(out_digest, d1));

    /* Reset always fails for the digest output */
    g_assert(!foil_output_reset(out_digest));
    d2 = foil_digest_finish(digest);
    g_assert(g_bytes_equal(d1, d2));

    foil_output_unref(out);
    foil_output_unref(out_digest);
    foil_digest_unref(digest);
    g_byte_array_unref(buf);
    g_bytes_unref(d1);
}

static
void
test_output_digest2(
    void)
{
    static const guint8 test123[] = { '1', '2', '3' };
    GType digest_type = FOIL_DIGEST_MD5;
    GByteArray* buf = g_byte_array_new();
    FoilDigest* digest = foil_digest_new(digest_type);
    FoilOutput* out = foil_output_mem_new(buf);
    FoilOutput* out_digest = foil_output_digest_new(out, digest);
    GBytes* d1 = foil_digest_data(digest_type, test123, sizeof(test123));
    GBytes* d2;
    GBytes* b;

    g_assert(foil_output_write_all(out_digest, test123, sizeof(test123)));
    g_assert(buf->len == sizeof(test123));
    g_assert(foil_output_bytes_written(out) == sizeof(test123));
    g_assert(foil_output_bytes_written(out_digest) == sizeof(test123));
    g_assert(!memcmp(buf->data, test123, sizeof(test123)));

    /* Reset always fails for the digest output */
    g_assert(!foil_output_reset(out_digest));

    /* Write has to fail if we close the underlying output stream */
    b = foil_output_free_to_bytes(foil_output_ref(out_digest));
    g_assert(b);
    g_assert(foil_output_write(out_digest, test123, 1) < 0);
    g_assert(test_bytes_equal(b, test123, sizeof(test123)));

    d2 = foil_digest_finish(digest);
    g_assert(g_bytes_equal(d1, d2));

    foil_output_unref(out);
    foil_output_unref(out_digest);
    foil_digest_unref(digest);
    g_byte_array_unref(buf);
    g_bytes_unref(d1);
    g_bytes_unref(b);
}

static
void
test_output_path(
    void)
{
    const char data[] = "This is a file output test\n";
    const gssize datalen = sizeof(data)-1;
    char* tmpdir = g_dir_make_tmp("test_output_XXXXXX", NULL);
    char* fname = g_build_filename(tmpdir, "test", NULL);
    char* contents = NULL;
    gsize length = 0;
    FoilOutput* out = foil_output_file_new_open(fname);
    GBytes* bytes_written;
    GBytes* bytes_expected = g_bytes_new_static(data, datalen);

    g_assert(foil_output_write_all(out, data, datalen));
    g_assert(foil_output_reset(out));
    g_assert(foil_output_write_all(out, data, datalen));
    foil_output_unref(out);

    g_assert(g_file_get_contents(fname, &contents, &length, NULL));
    g_assert(length == (gsize)datalen);
    g_assert(!memcmp(data, contents, length));

    out = foil_output_file_new_open(fname);
    g_assert(foil_output_write_bytes_all(out, bytes_expected));
    bytes_written = foil_output_free_to_bytes(out);
    g_assert(g_bytes_equal(bytes_written, bytes_expected));

    out = foil_output_file_new_tmp();
    g_assert(foil_output_write_bytes(out, bytes_expected) == datalen);
    foil_output_unref(out);

    out = foil_output_file_new_tmp();
    g_assert(foil_output_write_all(out, data, datalen));

    foil_output_ref(out); /* So that to_bytes doesn't deallocate it */
    g_bytes_unref(bytes_written);
    bytes_written = foil_output_free_to_bytes(out);
    g_assert(g_bytes_equal(bytes_written, bytes_expected));

    /* These fail because the stream is already closed */
    g_assert(foil_output_write_bytes(out, bytes_expected) < 0);
    g_assert(!foil_output_write_bytes_all(out, bytes_expected));
    foil_output_unref(out);

#ifdef _WIN32
    /* We can't remove open file on Windows */
    g_unlink(fname);
    g_rmdir(tmpdir);
#else
    /* Simulate to_bytes failure (requires Linux). First write the file ... */
    out = foil_output_file_new_open(fname);
    g_assert(foil_output_write_all(out, data, datalen));

    /* but on Linux we can remove it and to_bytes will fail */
    g_unlink(fname);
    g_assert(!foil_output_free_to_bytes(out));

    /* Simulate reopen failure (requires Linux). First write the file ... */
    out = foil_output_file_new_open(fname);
    g_assert(foil_output_write_all(out, data, datalen));

    /* then remove it together with the directory */
    g_unlink(fname);
    g_rmdir(tmpdir);

    /* ... and now reset and everythine after that should file */
    g_assert(!foil_output_reset(out));
    g_assert(!foil_output_reset(out));
    g_assert(!foil_output_write_all(out, data, datalen));
    g_assert(!foil_output_flush(out));
    g_assert(!foil_output_free_to_bytes(out));
#endif

    /* Since we have removed the directory we shouldn't be able to open
     * the file anymore */
    g_assert(!foil_output_file_new_open(fname));

    g_free(tmpdir);
    g_free(fname);
    g_free(contents);
    g_bytes_unref(bytes_written);
    g_bytes_unref(bytes_expected);
}

static
void
test_output_file(
    void)
{
    const char data[] = "This is a file output test";
    const gssize datalen = sizeof(data)-1;
    char* tmpdir = g_dir_make_tmp("test_output_XXXXXX", NULL);
    char* fname = g_build_filename(tmpdir, "test", NULL);
    FILE* f = fopen(fname, "wb");
    char* contents = NULL;
    gsize length = 0;
    FoilOutput* out = foil_output_file_new(f, 0);
    GBytes* bytes_expected = g_bytes_new_static(data, datalen);

    g_assert(foil_output_write_all(out, data, datalen));
    g_assert(!foil_output_reset(out));
    g_assert(!foil_output_free_to_bytes(out));
    fclose(f);

    g_assert(g_file_get_contents(fname, &contents, &length, NULL));
    g_assert(length == (gsize)datalen);
    g_assert(!memcmp(data, contents, length));

    /* Same thing but let foil_output_stream to close the file */
    f = fopen(fname, "wb");
    out = foil_output_file_new(f, FOIL_OUTPUT_FILE_CLOSE);
    g_assert(foil_output_write_all(out, data, datalen));
    foil_output_close(out);
    foil_output_unref(out);

    g_free(contents);
    g_assert(g_file_get_contents(fname, &contents, &length, NULL));
    g_assert(length == (gsize)datalen);
    g_assert(!memcmp(data, contents, length));

    /* NULL file is handled gracefully */
    g_assert(!foil_output_file_new(NULL, 0));

    g_unlink(fname);
    g_rmdir(tmpdir);
    g_free(tmpdir);
    g_free(fname);
    g_free(contents);
    g_bytes_unref(bytes_expected);
}

static
void
test_output_assert_equal(
    GByteArray* buf,
    const char* str)
{
    const gsize len = strlen(str);
    g_assert(buf->len == len);
    g_assert(!memcmp(buf->data, str, len));
}

static
void
test_output_base64(
    void)
{
    GBytes* bytes;
    GByteArray* buf = g_byte_array_new();
    FoilOutput* mem = foil_output_mem_new(buf);
    FoilOutput* base64 = foil_output_base64_new(mem);

    g_assert(foil_output_write_all(base64, "\x01", 1));
    foil_output_close(base64);
    test_output_assert_equal(buf, "AQ==");
    foil_output_unref(base64);

    base64 = foil_output_base64_new(mem);
    g_assert(foil_output_reset(base64));
    g_assert(!buf->len);
    g_assert(foil_output_write_all(base64, "\x01\x02", 2));
    g_assert(foil_output_flush(base64));
    g_assert(foil_output_flush(base64));
    test_output_assert_equal(buf, "AQI=");
    foil_output_close(base64);
    g_assert(!foil_output_flush(base64));
    foil_output_unref(base64);

    base64 = foil_output_base64_new(mem);
    g_assert(foil_output_reset(base64));
    g_assert(!buf->len);
    g_assert(foil_output_write_all(base64, "\x01\x02\x03", 3));
    foil_output_close(base64);
    test_output_assert_equal(buf, "AQID");
    foil_output_unref(base64);

    base64 = foil_output_base64_new(NULL);
    g_assert(foil_output_write_all(base64, "\x01\x02\x03\x04", 4));
    bytes = foil_output_free_to_bytes(base64);
    g_assert(bytes);
    g_assert(test_bytes_equal_str(bytes, "AQIDBA=="));
    g_bytes_unref(bytes);

    base64 = foil_output_base64_new_full(NULL, 0, 3);
    g_assert(foil_output_write_all(base64, "\x01\x02\x03\x04", 4));
    bytes = foil_output_free_to_bytes(base64);
    g_assert(bytes);
    g_assert(test_bytes_equal_str(bytes, "AQI\nDBA\n==\n"));
    g_bytes_unref(bytes);

    base64 = foil_output_base64_new_full(mem, 0, 8);
    g_assert(foil_output_reset(base64));
    g_assert(!buf->len);
    g_assert(foil_output_write_all(base64, "\x01\x02\x03", 3));
    foil_output_close(base64);
    test_output_assert_equal(buf, "AQID\n");
    foil_output_unref(base64);

    base64 = foil_output_base64_new_full(mem, 0, 4);
    g_assert(foil_output_reset(base64));
    g_assert(!buf->len);
    g_assert(foil_output_write_all(base64, "\xfb\xfc\xfd", 3));
    foil_output_close(base64);
    test_output_assert_equal(buf, "+/z9\n");
    foil_output_unref(base64);

    /* Test FOIL_OUTPUT_BASE64_FILESAFE flag */
    base64 = foil_output_base64_new_full(mem, FOIL_OUTPUT_BASE64_FILESAFE, 0);
    g_assert(foil_output_reset(base64));
    g_assert(!buf->len);
    g_assert(foil_output_write_all(base64, "\xfb\xfc\xfd", 3));
    foil_output_close(base64);
    test_output_assert_equal(buf, "-_z9");
    foil_output_unref(base64);

    /* Make sure FOIL_OUTPUT_BASE64_CLOSE flag works */
    base64 = foil_output_base64_new_full(mem, FOIL_OUTPUT_BASE64_CLOSE, 0);
    g_assert(foil_output_reset(base64));
    g_assert(foil_output_write_all(base64, "\x01\x02", 2));
    g_assert(buf->len == 0);
    g_assert(foil_output_write_all(base64, "\x03\x04\x05\x06", 4));
    g_assert(buf->len == 8);
    foil_output_flush(base64);
    test_output_assert_equal(buf, "AQIDBAUG");
    foil_output_unref(base64);
    g_assert(!foil_output_flush(mem)); /* Already closed by base64 */
    foil_output_unref(mem);

    /* Make sure to_bytes cuts off the prefix */
    mem = foil_output_mem_new(buf);
    g_assert(foil_output_write_all(mem, "====", 4));
    base64 = foil_output_base64_new_full(mem, FOIL_OUTPUT_BASE64_CLOSE, 0);
    g_assert(foil_output_write_all(base64, "\xf1\xf2\xf3\xf4\xf5\xf6", 6));
    bytes = foil_output_free_to_bytes(base64);
    g_assert(bytes);
    g_assert(test_bytes_equal_str(bytes, "8fLz9PX2"));
    g_bytes_unref(bytes);
    foil_output_unref(mem);

    /* Let's see how it reacts to resetting the underlying stream */
    mem = foil_output_mem_new(buf);
    g_assert(foil_output_write_all(mem, "====", 4));
    base64 = foil_output_base64_new(mem);
    g_assert(foil_output_write_all(base64, "\x01", 1));
    g_assert(foil_output_reset(mem)); /* This is a wrong thing to do */
    g_assert(!foil_output_free_to_bytes(base64));
    foil_output_unref(mem);

    mem = foil_output_mem_new(buf);
    base64 = foil_output_base64_new_full(mem, 0, 1);
    g_assert(foil_output_write_all(base64, "\x01", 1));
    foil_output_close(mem);
    g_assert(!foil_output_flush(base64));
    g_assert(!foil_output_free_to_bytes(base64));
    foil_output_unref(mem);

    g_byte_array_unref(buf);
}

static
FoilKey*
test_key_public_from_private(
    FoilKey* key)
{
    return foil_public_key_new_from_private(FOIL_PRIVATE_KEY(key));
}

static const guint8 test_key_rsa[] = {
    0x30, 0x82, 0x02, 0x58, 0x02, 0x01, 0x00, 0x02,
    0x81, 0x80, 0xc6, 0x0c, 0x2d, 0x39, 0x1b, 0x2b,
    0x35, 0x69, 0x06, 0x6e, 0x30, 0x33, 0xee, 0xe7,
    0xcf, 0x7c, 0x4a, 0xc8, 0x8c, 0x49, 0x7c, 0x8f,
    0x38, 0xff, 0xd7, 0x40, 0xb1, 0x8c, 0x79, 0x46,
    0x7f, 0x54, 0x4e, 0xc4, 0x19, 0x7b, 0x1b, 0xc2,
    0x1c, 0xb6, 0x83, 0x39, 0xc2, 0x9f, 0x2c, 0x7b,
    0xca, 0xde, 0x95, 0xd6, 0x0f, 0xcd, 0x87, 0x31,
    0xfc, 0x2c, 0x43, 0x84, 0x6f, 0x80, 0x8c, 0x69,
    0xca, 0xe6, 0xd3, 0x4a, 0xc6, 0x6e, 0x0a, 0x0e,
    0x1c, 0x5b, 0x4d, 0x33, 0x26, 0x11, 0xba, 0x26,
    0x15, 0xbd, 0x25, 0xa2, 0x3b, 0x8b, 0xa5, 0x1f,
    0x8f, 0x75, 0x63, 0xb7, 0x7f, 0xf5, 0x00, 0xc9,
    0x59, 0x94, 0x92, 0xbf, 0x2e, 0x13, 0x34, 0x92,
    0x4f, 0xa6, 0x21, 0x81, 0x5d, 0xce, 0xe1, 0xcf,
    0x5e, 0xd4, 0x6a, 0x6d, 0xe1, 0x60, 0xd5, 0x13,
    0x21, 0x63, 0x09, 0x3c, 0x8c, 0x49, 0x30, 0xd9,
    0xa9, 0x6b, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02,
    0x81, 0x80, 0x24, 0x6a, 0xca, 0xca, 0x0c, 0x6f,
    0xe6, 0x93, 0x58, 0x66, 0x5c, 0xa0, 0xc0, 0x16,
    0x8a, 0x35, 0xad, 0xbe, 0xb0, 0xe5, 0x36, 0x6d,
    0x53, 0xaa, 0xdf, 0xd6, 0xfa, 0x8e, 0xfd, 0x21,
    0xf4, 0x79, 0xf9, 0x3d, 0xdf, 0xfd, 0x9e, 0x3e,
    0x14, 0x6f, 0x8f, 0x33, 0xc8, 0xd0, 0xe2, 0x2a,
    0x25, 0x44, 0xc6, 0xc2, 0xa5, 0x07, 0x43, 0x0b,
    0xf2, 0xf5, 0xe4, 0xb8, 0x6e, 0x94, 0x71, 0xbd,
    0x66, 0x5c, 0xb6, 0xa8, 0x6f, 0x4a, 0xb9, 0x65,
    0xb4, 0xb0, 0xc6, 0xe2, 0x41, 0x9b, 0x5f, 0x5d,
    0xf2, 0x0c, 0x3c, 0xb9, 0x9f, 0xf2, 0xdf, 0x3c,
    0x35, 0x60, 0xc1, 0x3a, 0x17, 0x7c, 0x41, 0xc2,
    0x99, 0x2c, 0xb5, 0xdb, 0xeb, 0x4c, 0x0e, 0x72,
    0xd0, 0xc7, 0xfa, 0x7f, 0xfa, 0x87, 0xa5, 0x83,
    0x31, 0x90, 0x7e, 0xc3, 0xb3, 0xdf, 0xba, 0xb8,
    0xfe, 0x2e, 0xbf, 0xdc, 0x34, 0xf5, 0xa4, 0x75,
    0x38, 0x19, 0x02, 0x40, 0xec, 0x2c, 0x17, 0x64,
    0x72, 0x61, 0x39, 0x17, 0xaf, 0xd2, 0x8a, 0x96,
    0x38, 0x96, 0x09, 0xe1, 0x68, 0xf2, 0x71, 0x3e,
    0xfa, 0xdc, 0x7f, 0x0c, 0xd7, 0xc5, 0x4e, 0x3f,
    0x30, 0x82, 0x45, 0x59, 0x1a, 0x86, 0xb0, 0xab,
    0xda, 0xb9, 0x7d, 0xb7, 0xab, 0x17, 0xb7, 0x8f,
    0x92, 0xf9, 0x64, 0xd6, 0x01, 0xf9, 0xe2, 0xf9,
    0x78, 0x8e, 0x61, 0xa7, 0x68, 0x18, 0x51, 0x26,
    0x5d, 0x71, 0x63, 0x97, 0x02, 0x40, 0xd6, 0xac,
    0xb1, 0xd1, 0x22, 0x93, 0x13, 0x59, 0x1f, 0x2b,
    0xf4, 0xe6, 0xff, 0x1a, 0x33, 0xca, 0x99, 0x47,
    0x06, 0xc4, 0x94, 0x04, 0xcf, 0x16, 0x37, 0x8c,
    0xfa, 0x26, 0xf8, 0x58, 0x59, 0xdc, 0x47, 0x5e,
    0x98, 0xb9, 0x09, 0x30, 0x97, 0x69, 0x48, 0xad,
    0x64, 0x92, 0x5e, 0x0c, 0x9c, 0xad, 0xfe, 0xff,
    0x96, 0xeb, 0x70, 0x21, 0xbc, 0xb3, 0x5d, 0x70,
    0xdb, 0xc7, 0x78, 0xc9, 0x93, 0x4d, 0x02, 0x40,
    0xdf, 0x3c, 0x32, 0x04, 0x4d, 0x25, 0x5e, 0xec,
    0xe7, 0xd1, 0xb0, 0x13, 0x9c, 0x7b, 0x1d, 0xed,
    0xc5, 0xe0, 0x5c, 0x70, 0xf6, 0x78, 0x93, 0x53,
    0x15, 0x65, 0x37, 0xb7, 0xfc, 0xe7, 0x36, 0x1b,
    0xaa, 0x3a, 0x24, 0x26, 0xdd, 0x41, 0x35, 0xf6,
    0xf5, 0x2f, 0x1e, 0xe0, 0x04, 0x41, 0xde, 0x31,
    0x77, 0x7e, 0xb7, 0x2f, 0xad, 0xe7, 0x8f, 0xa0,
    0xc8, 0x81, 0x2b, 0xbb, 0x82, 0xd9, 0xda, 0x13,
    0x02, 0x40, 0x46, 0x64, 0xa6, 0x82, 0x3f, 0x66,
    0x1e, 0xe8, 0x10, 0x72, 0xa7, 0x81, 0xbf, 0x90,
    0xe5, 0xfe, 0xbf, 0x38, 0x2d, 0x1d, 0xf4, 0xb3,
    0x86, 0xfc, 0x70, 0x06, 0xc8, 0x58, 0x53, 0x03,
    0x15, 0xa4, 0x47, 0xba, 0xdb, 0x35, 0x81, 0xaf,
    0xef, 0x56, 0x54, 0xc0, 0x96, 0xc3, 0xf0, 0x17,
    0x0e, 0xa1, 0x77, 0x86, 0x74, 0x04, 0x8b, 0xe6,
    0x64, 0x2c, 0x24, 0xad, 0xc7, 0x43, 0xa7, 0x75,
    0xe1, 0xd9, 0x02, 0x40, 0x85, 0x6e, 0xc5, 0x4d,
    0x91, 0xb4, 0x1d, 0x31, 0xbc, 0x02, 0x83, 0x1b,
    0xda, 0x9e, 0xe4, 0x43, 0xe8, 0xbc, 0xb4, 0x3a,
    0x13, 0x89, 0x6a, 0x58, 0x74, 0xa4, 0x4e, 0x8e,
    0xd7, 0xc7, 0xae, 0x16, 0x40, 0x35, 0xe5, 0xce,
    0xd2, 0x22, 0x32, 0xef, 0xdf, 0x58, 0x13, 0x35,
    0x70, 0xc6, 0x15, 0x99, 0xd9, 0xc0, 0xe2, 0xf5,
    0xca, 0xfb, 0xfa, 0x9c, 0xbd, 0x51, 0x81, 0x9c,
    0x7d, 0x60, 0xbb, 0xe0
};

static const char test_input_short[] = "This is a secret.This is a secr";
static const char test_input_long[] =
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
static const guint8 test_key_aes128[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const guint8 test_key_aes192[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const guint8 test_key_aes256[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const TestOutputCipher test_cipher[] = {
#define TEST_AES_(bits,name) \
    { TEST_("/cipher/aes" #bits "/" #name), \
      { TEST_ARRAY_AND_SIZE(test_key_aes##bits) }, \
      foil_key_aes##bits##_get_type, foil_key_ref, \
      foil_impl_cipher_aes_cbc_encrypt_get_type, \
      foil_impl_cipher_aes_cbc_decrypt_get_type, \
      test_input_##name, sizeof(test_input_##name) }
    TEST_AES_(128,short),
    TEST_AES_(128,long),
    TEST_AES_(192,short),
    TEST_AES_(192,long),
    TEST_AES_(256,short),
    TEST_AES_(256,long),
#define TEST_RSA_(name) \
    { TEST_("/cipher/rsa/" #name), \
      { TEST_ARRAY_AND_SIZE(test_key_rsa) }, \
      foil_impl_key_rsa_private_get_type, test_key_public_from_private, \
      foil_impl_cipher_rsa_encrypt_get_type, \
      foil_impl_cipher_rsa_decrypt_get_type, \
      test_input_##name, sizeof(test_input_##name) }
    TEST_RSA_(short),
    TEST_RSA_(long)
};

int main(int argc, char* argv[])
{
    guint i;
    g_test_init(&argc, &argv, NULL);
    g_test_add_func(TEST_("null"), test_output_null);
    g_test_add_func(TEST_("basic"), test_output_basic);
    g_test_add_func(TEST_("digest1"), test_output_digest1);
    g_test_add_func(TEST_("digest2"), test_output_digest2);
    g_test_add_func(TEST_("path"), test_output_path);
    g_test_add_func(TEST_("file"), test_output_file);
    g_test_add_func(TEST_("base64"), test_output_base64);
    g_test_add_func(TEST_("cipher/basic"), test_output_cipher_basic);
    for (i = 0; i < G_N_ELEMENTS(test_cipher); i++) {
        g_test_add_data_func(test_cipher[i].name, test_cipher + i,
            test_output_cipher);
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
