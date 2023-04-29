/*
 * Copyright (C) 2016-2023 Slava Monich <slava@monich.com>
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

#include "foil_input_p.h"
#include "foil_output.h"
#include "foil_digest.h"

#ifdef _WIN32
#  include <io.h>
#  include <direct.h>
#else
#  include <unistd.h>
#endif

#define GBYTES_STATIC(data) g_bytes_new_static(data, sizeof(data))
#define READ_CHUNK (0x1000)

static
void
test_input_null(
    void)
{
    guint8 buf[1];
    gsize copied = (gsize)-1;
    FoilInput* in = foil_input_mem_new(NULL);
    FoilInput* in2 = foil_input_mem_new_bytes(NULL);

    /* Test resistance to NULL and all kinds of invalid input */
    foil_input_unref(NULL);
    foil_input_close(NULL);
    foil_input_push_back(NULL, NULL, 0);
    foil_input_push_back(in, NULL, 0);

    g_assert(!foil_input_ref(NULL));
    g_assert(!foil_input_range_new(NULL, 0, 0));
    g_assert(!foil_input_base64_new(NULL));
    g_assert(!foil_input_digest_new(NULL, NULL));
    g_assert(!foil_input_cipher_new(NULL, NULL));
    g_assert(!foil_input_cipher_new(NULL, in));
    g_assert(!foil_input_cipher_new((FoilCipher*)in, NULL));
    g_assert(!foil_input_file_new(NULL, TRUE));
    g_assert(!foil_input_file_new_open(NULL));
    g_assert(!foil_input_has_available(NULL, 1));
    g_assert(!foil_input_has_available(in, 1));
    g_assert(!foil_input_has_available(in2, 1));
    g_assert(!foil_input_bytes_read(NULL));
    g_assert(!foil_input_bytes_read(in));
    g_assert(!foil_input_peek(NULL, 0, NULL));
    g_assert(!foil_input_peek(in, 1, NULL));
    g_assert(!foil_input_read_all(NULL));
    g_assert(foil_input_read(NULL, NULL, 0) < 0);
    g_assert(foil_input_read(in, NULL, 0) == 0);
    g_assert(foil_input_read(in, buf, 0) == 0);
    g_assert(foil_input_read(in, NULL, 1) == 0);
    g_assert(foil_input_copy(NULL, NULL, 0) < 0);
    g_assert(foil_input_copy(in, NULL, 1) == 0);
    g_assert(!foil_input_copy_all(NULL, NULL, NULL));
    g_assert(!foil_input_copy_all(in, NULL, NULL));
    g_assert(!foil_input_copy_all(in, NULL, &copied));
    g_assert(!copied);

    /* Zero bytes is always available */
    g_assert(foil_input_has_available(in, 0));
    g_assert(foil_input_has_available(in2, 0));

    foil_input_unref(foil_input_ref(in));

    /* Nothing can be read after close */
    foil_input_close(in);
    g_assert(!foil_input_read_all(in));
    g_assert(!foil_input_peek(in, 1, NULL));
    g_assert(foil_input_read(in, NULL, 1) < 0);
    g_assert(foil_input_copy(in, NULL, 1) < 0);
    foil_input_push_back(in, NULL, 0);

    foil_input_unref(in);
    foil_input_unref(in2);
}

static
void
test_input_basic(
    void)
{
    static const guint8 test12345[] = { '1', '2', '3', '4', '5' };
    GBytes* bytes12345 = GBYTES_STATIC(test12345);
    guint8 buf[5];
    gsize nbytes;
    const void* peek;
    FoilInput* in = foil_input_mem_new(bytes12345);

    /* Peek first 3 bytes */
    peek = foil_input_peek(in, 3, &nbytes);
    g_assert(peek);
    g_assert(nbytes == 3);
    g_assert(!memcmp(peek, test12345, nbytes));

    /* Read 2 bytes */
    g_assert(foil_input_read(in, buf, 2) == 2);
    g_assert(!memcmp(buf, test12345, 2));

    /* Peek 1 byte (should still be in the peek buffer) */
    peek = foil_input_peek(in, 1, &nbytes);
    g_assert(peek);
    g_assert(nbytes == 1);
    g_assert(!memcmp(peek, test12345 + 2, nbytes));

    /* Peek 2 more bytes */
    peek = foil_input_peek(in, 2, &nbytes);
    g_assert(peek);
    g_assert(nbytes == 2);
    g_assert(!memcmp(peek, test12345 + 2, nbytes));

    /* Ask for 4 more bytes (should get 3) */
    g_assert(foil_input_read(in, buf, 4) == 3);
    g_assert(!memcmp(buf, test12345 + 2, 3));

    /* And there should be no more data left */
    g_assert(!foil_input_peek(in, 1, &nbytes));
    g_assert(!nbytes);
    g_assert(foil_input_read(in, buf, 1) == 0);
    foil_input_unref(in);

    /* And again, this time without peeking */
    in = foil_input_mem_new(bytes12345);
    g_assert(foil_input_read(in, buf, 2) == 2);
    g_assert(!memcmp(buf, test12345, 2));
    g_assert(foil_input_read(in, buf, 4) == 3);
    g_assert(!memcmp(buf, test12345 + 2, 3));
    foil_input_unref(in);

    /* Buffer pointer is optional */
    in = foil_input_mem_new(bytes12345);
    peek = foil_input_peek(in, 2, &nbytes);
    g_assert(peek);
    g_assert(nbytes == 2);
    g_assert(!memcmp(peek, test12345, nbytes));
    g_assert(foil_input_has_available(in, 2));
    g_assert(foil_input_has_available(in, 5));
    g_assert(!foil_input_has_available(in, 6));
    g_assert(foil_input_skip(in, 2) == 2);
    g_assert(foil_input_skip(in, 1) == 1);
    g_assert(foil_input_read(in, buf, 4) == 2);
    g_assert(!memcmp(buf, test12345 + 3, 2));
    foil_input_close(in);
    foil_input_unref(in);

    g_bytes_unref(bytes12345);
}

static
void
test_input_range(
    void)
{
    guint8 buf[5];
    static const guint8 test12345[] = { '1', '2', '3', '4', '5' };
    GBytes* bytes12345 = GBYTES_STATIC(test12345);
    FoilInput* in1 = foil_input_mem_new(bytes12345);
    FoilInput* in2 = foil_input_mem_new(bytes12345);
    FoilInput* in3 = foil_input_mem_new(bytes12345);
    FoilInput* range1234 = foil_input_range_new(in1, 0, 4);
    FoilInput* range234 = foil_input_range_new(in2, 1, 3);
    FoilInput* range345 = foil_input_range_new(in3, 2, 4);
    GBytes* bytes1234;
    GBytes* bytes234 = foil_input_read_all(range234);
    GBytes* bytes345 = foil_input_read_all(range345);
    GType digest_type = FOIL_DIGEST_MD5;
    FoilDigest* digest1234 = foil_digest_new(digest_type);
    FoilInput* digest_range1234 = foil_input_digest_new(range1234, digest1234);
    FoilOutput* out1234 = foil_output_mem_new(NULL);
    GBytes* digest_bytes1234 = foil_digest_data(digest_type, test12345, 4);
    GBytes* digest_bytes1234copy;
    FoilBytes in_bytes;

    g_assert(foil_input_copy(digest_range1234, out1234, 2) == 2);
    g_assert(foil_input_copy(digest_range1234, out1234, 3) == 2);
    g_assert(foil_input_copy(digest_range1234, out1234, 1) == 0);
    g_assert(foil_input_copy(digest_range1234, out1234, 0) == 0);
    g_assert(!foil_input_has_available(digest_range1234, 1));

    digest_bytes1234copy = foil_digest_free_to_bytes(digest1234);
    g_assert(g_bytes_equal(digest_bytes1234copy, digest_bytes1234));

    bytes1234 = foil_output_free_to_bytes(out1234);
    g_assert(test_bytes_equal(bytes1234, test12345, 4));
    g_assert(test_bytes_equal(bytes234, test12345 + 1, 3));
    g_assert(test_bytes_equal(bytes345, test12345 + 2, 3));

    foil_input_unref(in3);
    foil_input_unref(range345);

    in3 = foil_input_mem_new(bytes12345);
    range345 = foil_input_range_new(in3, 2, 4);
    g_assert(!foil_input_has_available(range345, 4));
    g_assert(foil_input_has_available(range345, 2));
    foil_input_close(in3);
    foil_input_unref(range345);

    /* Range of a closed input */
    range345 = foil_input_range_new(in3, 2, 4);
    g_assert(!foil_input_has_available(range345, 1));

    foil_input_unref(in3);
    foil_input_unref(range345);
    in_bytes.val = test12345;
    in_bytes.len = sizeof(test12345);
    in3 = foil_input_mem_new_bytes(&in_bytes);
    range345 = foil_input_range_new(in3, 2, 4);
    g_assert(foil_input_read(range345, buf, 3) == 3);
    g_assert(!memcmp(buf, test12345 + 2, 3));
    g_assert(!foil_input_has_available(range345, 1));

    foil_input_unref(in1);
    foil_input_unref(in2);
    foil_input_unref(in3);
    foil_input_unref(digest_range1234);
    foil_input_unref(range1234);
    foil_input_unref(range234);
    foil_input_unref(range345);
    g_bytes_unref(digest_bytes1234copy);
    g_bytes_unref(digest_bytes1234);
    g_bytes_unref(bytes12345);
    g_bytes_unref(bytes1234);
    g_bytes_unref(bytes234);
    g_bytes_unref(bytes345);
}

static
void
test_input_copy(
    void)
{
    gsize len = READ_CHUNK + 16;
    gsize partial = len - 8;
    void* data = g_malloc(len);
    GBytes* in_bytes = g_bytes_new_take(data, len);
    FoilInput* in = foil_input_mem_new(in_bytes);
    FoilOutput* out = foil_output_mem_new(NULL);
    GBytes* out_bytes;
    gsize size, copied = 0;
    gconstpointer out_data;

    /* Successfully copy len bytes */
    memset(data, 0xAA, len);
    g_assert(foil_input_copy_all(in, out, &copied));
    g_assert(copied == len);
    foil_input_close(in);

    /* Can't copy to the closed stream */
    g_assert(!foil_input_copy_all(in, out, &copied));
    g_assert(!copied);
    foil_input_unref(in);

    /* Verify the data */
    out_bytes = foil_output_free_to_bytes(out);
    g_assert(g_bytes_equal(in_bytes, out_bytes));
    g_bytes_unref(out_bytes);

    /* Test flush failure */
    copied = 0;
    in = foil_input_mem_new(in_bytes);
    out = test_output_mem_new(-1, TEST_OUTPUT_FLUSH_FAILS_ONCE);
    g_assert(!foil_input_copy_all(in, out, &copied));
    g_assert(copied == len);
    out_bytes = foil_output_free_to_bytes(out);
    g_assert(g_bytes_equal(in_bytes, out_bytes));
    foil_input_unref(in);
    g_bytes_unref(out_bytes);

    /* Test partial copy */
    in = foil_input_mem_new(in_bytes);
    out = test_output_mem_new(partial, 0);
    g_assert(!foil_input_copy_all(in, out, &copied));
    g_assert(copied == partial);
    out_bytes = foil_output_free_to_bytes(out);
    out_data = g_bytes_get_data(out_bytes, &size);
    g_assert(size == copied);
    g_assert(!memcmp(data, out_data, size));
    foil_input_unref(in);
    g_bytes_unref(out_bytes);

    /* (Almost) the same as above but hits a different condition */
    in = foil_input_mem_new(in_bytes);
    out = test_output_mem_new(READ_CHUNK, 0);
    g_assert(!foil_input_copy_all(in, out, &copied));
    g_assert(copied == READ_CHUNK);
    out_bytes = foil_output_free_to_bytes(out);
    out_data = g_bytes_get_data(out_bytes, &size);
    g_assert(size == copied);
    g_assert(!memcmp(data, out_data, size));
    foil_input_unref(in);
    g_bytes_unref(out_bytes);

    /* Test write failure */
    out = test_output_mem_new(0, TEST_OUTPUT_WRITE_FAILS);
    in = foil_input_mem_new(in_bytes);
    g_assert(!foil_input_copy(in, out, len));
    foil_input_unref(in);
    foil_output_unref(out);

    g_bytes_unref(in_bytes);
}

static
void
test_input_push(
    void)
{
    static const guint8 test12345[] = { '1', '2', '3', '4', '5' };
    static const guint8 test123456[] = { '1', '2', '3', '4', '5', '6' };
    FoilInput* in = foil_input_mem_new_static(TEST_ARRAY_AND_SIZE(test123456));
    GBytes* bytes;

    foil_input_skip(in, sizeof(test12345));
    /* Second push won't work */
    foil_input_push_back(in, TEST_ARRAY_AND_SIZE(test12345));
    foil_input_push_back(in, TEST_ARRAY_AND_SIZE(test12345));
    bytes = foil_input_read_all(in);
    foil_input_unref(in);

    g_assert(test_bytes_equal(bytes, TEST_ARRAY_AND_SIZE(test123456)));
    g_bytes_unref(bytes);
}

static
void
test_input_digest(
    void)
{
    static const guint8 md5_hash[] = {
        0x57,0xed,0xf4,0xa2,0x2b,0xe3,0xc9,0x55,
        0xac,0x49,0xda,0x2e,0x21,0x07,0xb6,0x7a
    };
    const char* data =
        "12345678901234567890123456789012"
        "34567890123456789012345678901234"
        "5678901234567890";
    GBytes* bytes = g_bytes_new_static(data, strlen(data));
    GBytes* digest = GBYTES_STATIC(md5_hash);
    FoilInput* in1 = foil_input_mem_new(bytes);
    FoilInput* in2 = foil_input_mem_new(bytes);
    FoilDigest* d1 = foil_digest_new_md5();
    FoilDigest* d2 = foil_digest_new_md5();
    FoilInput* di1 = foil_input_digest_new(in1, d1);
    FoilInput* di2 = foil_input_digest_new(in2, d2);
    GBytes* md1;
    GBytes* md2;
    const gssize bytes_expected = g_bytes_get_size(bytes);
    const gssize buflen = bytes_expected + 1;
    void* buf = g_malloc(buflen);
    gssize n1, n2;

    foil_input_unref(in1);
    foil_input_unref(in2);

    /*
     * Both reads should consume the same amount of data and produce
     * the same digest
     */
    n1 = foil_input_read(di1, buf, buflen);
    n2 = foil_input_skip(di2, 16) + foil_input_skip(di2, buflen - 16);
    foil_input_unref(di1);
    foil_input_unref(di2);
    md1 = foil_digest_finish(d1);
    md2 = foil_digest_finish(d2);

    g_assert(n1 == bytes_expected);
    g_assert(n2 == bytes_expected);
    g_assert(g_bytes_equal(md1, digest));
    g_assert(g_bytes_equal(md2, digest));

    foil_digest_unref(d1);
    foil_digest_unref(d2);
    g_bytes_unref(bytes);
    g_bytes_unref(digest);
    g_free(buf);
}

static
void
test_input_file(
    void)
{
    const char data[] = "This is a file input test";
    const gssize datalen = sizeof(data)-1;
    char* tmpdir = g_dir_make_tmp("test_input_XXXXXX", NULL);
    char* fname = g_build_filename(tmpdir, "test", NULL);
    FILE* f;
    FoilInput* in;
    GBytes* bytes_read;
    GBytes* bytes_expected = g_bytes_new_static(data, datalen);

    g_file_set_contents(fname, data, datalen, NULL);
    in = foil_input_file_new_open(fname);
    bytes_read = foil_input_read_all(in);
    foil_input_unref(in);

    g_assert(g_bytes_equal(bytes_read, bytes_expected));

    /* Make sure we are not closing the file if we are not asked to do so */
    f = fopen(fname, "rb");
    in = foil_input_file_new(f, FALSE);
    foil_input_unref(in);
    g_assert(!fclose(f));

    /* We should fail to open non-existent file */
    remove(fname);
    in = foil_input_file_new_open(fname);
    g_assert(!in);

    rmdir(tmpdir);
    g_free(tmpdir);
    g_free(fname);
    g_bytes_unref(bytes_read);
    g_bytes_unref(bytes_expected);
}

/* base64 test */

typedef struct test_input_base64_data {
    const char* in;
    const guint8* out;
    gsize outbytes;
    gsize remaining;
    guint flags;
} TestInputBase64;

static
void
test_input_base64(
    gconstpointer param)
{
    const TestInputBase64* t = param;
    gsize inputlen = strlen(t->in);
    FoilInput* mem = foil_input_mem_new_static(t->in, inputlen);
    FoilInput* base64 = foil_input_base64_new_full(mem, t->flags);
    GBytes* decoded = foil_input_read_all(base64);
    guint8 buf[6];
    const gsize bufsize = MIN(t->outbytes, sizeof(buf));
    gsize i;

    GDEBUG("%s", t->in);
    g_assert(decoded);
    if (t->out) {
        g_assert(test_bytes_equal(decoded, t->out, t->outbytes));
        g_assert(inputlen - foil_input_bytes_read(mem) == t->remaining);
    } else {
        g_assert(!g_bytes_get_size(decoded));
    }
    g_bytes_unref(decoded);
    foil_input_unref(base64);
    foil_input_unref(mem);

    /* Same but without output buffer */
    mem = foil_input_mem_new_static(t->in, inputlen);
    base64 = foil_input_base64_new_full(mem, t->flags);
    g_assert((gsize)foil_input_skip(base64, t->outbytes) == t->outbytes);
    g_assert(inputlen - foil_input_bytes_read(mem) == t->remaining);
    foil_input_unref(base64);
    foil_input_unref(mem);

    /* Split reads */
    for (i = 1; i + 1 < bufsize; i++) {
        const gsize part2 = bufsize - i;
        mem = foil_input_mem_new_static(t->in, inputlen);
        base64 = foil_input_base64_new_full(mem, t->flags);
        memset(buf, 0xff, bufsize);
        g_assert_cmpint(foil_input_read(base64, buf, i), == ,i);
        g_assert(!memcmp(buf, t->out, i));
        g_assert_cmpint(foil_input_read(base64, buf + i, part2), == ,part2);
        g_assert(!memcmp(buf, t->out, bufsize));
        foil_input_unref(base64);
        foil_input_unref(mem);

        /* Same but without the output buffer */
        mem = foil_input_mem_new_static(t->in, inputlen);
        base64 = foil_input_base64_new_full(mem, t->flags);
        g_assert_cmpint(foil_input_read(base64, NULL, i), == ,i);
        g_assert_cmpint(foil_input_read(base64, NULL, part2), == ,part2);
        foil_input_unref(base64);
        foil_input_unref(mem);
    }

    if (t->remaining) {
        /* Check the validation option */
        FoilOutput* out = foil_output_mem_new(NULL);
        gsize copied = 0;

        /* foil_input_copy_all() fails on invalid input */
        mem = foil_input_mem_new_static(t->in, inputlen);
        base64 = foil_input_base64_new_full(mem, t->flags |
            FOIL_INPUT_BASE64_VALIDATE);
        g_assert(!foil_input_copy_all(base64, out, &copied));
        g_assert(foil_output_bytes_written(out) == t->outbytes);
        g_assert(copied == t->outbytes);
        foil_input_unref(base64);
        foil_input_unref(mem);
        foil_output_unref(out);

        /* foil_input_read_all() fails too. */
        mem = foil_input_mem_new_static(t->in, inputlen);
        base64 = foil_input_base64_new_full(mem, t->flags |
            FOIL_INPUT_BASE64_VALIDATE);
        g_assert(!foil_input_read_all(base64));
        foil_input_unref(base64);
        foil_input_unref(mem);
    }
}

static const guint8 test_input_base64_out1[] = { 0x00 };
static const guint8 test_input_base64_out2[] = { 0x00,0x01 };
static const guint8 test_input_base64_out3[] = { 0x00,0x01,0x02 };
static const guint8 test_input_base64_out5[] = { 0x00,0x01,0x02,0xfb,0xfc};
static const guint8 test_input_base64_out17[] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10};
static const guint8 test_input_base64_out265[] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
    0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
    0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
    0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
    0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
    0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
    0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,
    0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,
    0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,
    0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f,
    0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
    0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
    0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
    0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
    0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,
    0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,
    0xb8,0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf,
    0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,
    0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf,
    0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,
    0xd8,0xd9,0xda,0xdb,0xdc,0xdd,0xde,0xdf,
    0xe0,0xe1,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,
    0xe8,0xe9,0xea,0xeb,0xec,0xed,0xee,0xef,
    0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
    0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
};

static const TestInputBase64 base64_tests[] = {
    { "\x80""AAA", NULL, 0, 4 },
    { "*AAA", NULL, 0, 4 },
    { "A*AA", NULL, 0, 4 },
    { "-AA", NULL, 0, 3, FOIL_INPUT_BASE64_STANDARD },
    { "_AA", NULL, 0, 3, FOIL_INPUT_BASE64_STANDARD },
    { "+AA", NULL, 0, 3, FOIL_INPUT_BASE64_FILESAFE },
    { "/AA", NULL, 0, 3, FOIL_INPUT_BASE64_FILESAFE },
    { "AA", TEST_ARRAY_AND_SIZE(test_input_base64_out1) },
    { "AA==", TEST_ARRAY_AND_SIZE(test_input_base64_out1) },
    { "AA=", TEST_ARRAY_AND_SIZE(test_input_base64_out1), 1 },  /* Short pad */
    { "AA=A", TEST_ARRAY_AND_SIZE(test_input_base64_out1), 2 },
    { "AA===", TEST_ARRAY_AND_SIZE(test_input_base64_out1), 1 },
    { "AAE=", TEST_ARRAY_AND_SIZE(test_input_base64_out2) },
    { "AAE =", TEST_ARRAY_AND_SIZE(test_input_base64_out2), 2}, /* Space */
    { "AAE =", TEST_ARRAY_AND_SIZE(test_input_base64_out2), 0,
      FOIL_INPUT_BASE64_IGNORE_SPACES },
    { "AAE ==", TEST_ARRAY_AND_SIZE(test_input_base64_out2), 1,
      FOIL_INPUT_BASE64_IGNORE_SPACES },
    { "AAEC==", TEST_ARRAY_AND_SIZE(test_input_base64_out3), 2 },
    { "AAEC+/w", TEST_ARRAY_AND_SIZE(test_input_base64_out5) },
    { "AAEC+/w", TEST_ARRAY_AND_SIZE(test_input_base64_out3), 3,
      FOIL_INPUT_BASE64_FILESAFE},
    { "AAEC+/z", TEST_ARRAY_AND_SIZE(test_input_base64_out3), 3 },
    { "AAEC+/w-", TEST_ARRAY_AND_SIZE(test_input_base64_out5), 1 },
    { "AAEC-_w", TEST_ARRAY_AND_SIZE(test_input_base64_out5) },
    { "AAEC-_w", TEST_ARRAY_AND_SIZE(test_input_base64_out3), 3,
      FOIL_INPUT_BASE64_STANDARD},
    { "AAEC-_z", TEST_ARRAY_AND_SIZE(test_input_base64_out3), 3 },
    { "AAEC-_w+", TEST_ARRAY_AND_SIZE(test_input_base64_out5), 1 },
    { "AAECAwQFBgcICQoLDA0ODxA=",
      TEST_ARRAY_AND_SIZE(test_input_base64_out17), 0 },
    { "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGx"
      "wdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4"
      "OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVF"
      "VWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3Bx"
      "cnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY"
      "6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmq"
      "q6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxs"
      "fIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj"
      "5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w",
      TEST_ARRAY_AND_SIZE(test_input_base64_out265), 0}
};

#define TEST_(name) "/input/" name

int main(int argc, char* argv[])
{
    guint i;
    g_test_init(&argc, &argv, NULL);
    g_test_add_func(TEST_("null"), test_input_null);
    g_test_add_func(TEST_("basic"), test_input_basic);
    g_test_add_func(TEST_("range"), test_input_range);
    g_test_add_func(TEST_("copy"), test_input_copy);
    g_test_add_func(TEST_("push"), test_input_push);
    g_test_add_func(TEST_("digest"), test_input_digest);
    g_test_add_func(TEST_("file"), test_input_file);
    for (i = 0; i < G_N_ELEMENTS(base64_tests); i++) {
        char* name = g_strdup_printf(TEST_("base64") "/%d", i + 1);
        g_test_add_data_func(name, base64_tests + i, test_input_base64);
        g_free(name);
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
