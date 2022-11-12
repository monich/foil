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

#include "foil_digest_p.h"

#include <gutil_misc.h>

typedef struct test_digest {
    const char* name;
    GTestDataFunc fn;
    GType (*digest_type)(void);
    const char* input;
    int repeat_count;
    const guint8* output;
    guint output_size;
} TestDigest;

/* Empty digests */
#define empty_md5_data test_md5_data1
static const guint8 empty_sha1_data[] = {
    0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,
    0x32,0x55,0xbf,0xef,0x95,0x60,0x18,0x90,
    0xaf,0xd8,0x07,0x09
};
static const guint8 empty_sha256_data[] = {
    0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
    0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
    0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
    0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
};
static const guint8 empty_sha512_data[] = {
    0xcf,0x83,0xe1,0x35,0x7e,0xef,0xb8,0xbd,
    0xf1,0x54,0x28,0x50,0xd6,0x6d,0x80,0x07,
    0xd6,0x20,0xe4,0x05,0x0b,0x57,0x15,0xdc,
    0x83,0xf4,0xa9,0x21,0xd3,0x6c,0xe9,0xce,
    0x47,0xd0,0xd1,0x3c,0x5d,0x85,0xf2,0xb0,
    0xff,0x83,0x18,0xd2,0x87,0x7e,0xec,0x2f,
    0x63,0xb9,0x31,0xbd,0x47,0x41,0x7a,0x81,
    0xa5,0x38,0x32,0x7a,0xf9,0x27,0xda,0x3e
};

/* MD5 examples from http://www.ietf.org/rfc/rfc1321 */

#define MD5_TEST1 ""
#define MD5_TEST2 "a"
#define MD5_TEST3 "abc"
#define MD5_TEST4 "message digest"
#define MD5_TEST5 "abcdefghijklmnopqrstuvwxyz"
#define MD5_TEST6 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef" \
                  "ghijklmnopqrstuvwxyz0123456789"
#define MD5_TEST7 "12345678901234567890123456789012" \
                  "34567890123456789012345678901234" \
                  "5678901234567890"
static const guint8 test_md5_data1[] = {
    0xd4,0x1d,0x8c,0xd9,0x8f,0x00,0xb2,0x04,
    0xe9,0x80,0x09,0x98,0xec,0xf8,0x42,0x7e
};
static const guint8 test_md5_data2[] = {
    0x0c,0xc1,0x75,0xb9,0xc0,0xf1,0xb6,0xa8,
    0x31,0xc3,0x99,0xe2,0x69,0x77,0x26,0x61
};
static const guint8 test_md5_data3[] = {
    0x90,0x01,0x50,0x98,0x3c,0xd2,0x4f,0xb0,
    0xd6,0x96,0x3f,0x7d,0x28,0xe1,0x7f,0x72
};
static const guint8 test_md5_data4[] = {
    0xf9,0x6b,0x69,0x7d,0x7c,0xb7,0x93,0x8d,
    0x52,0x5a,0x2f,0x31,0xaa,0xf1,0x61,0xd0
};
static const guint8 test_md5_data5[] = {
    0xc3,0xfc,0xd3,0xd7,0x61,0x92,0xe4,0x00,
    0x7d,0xfb,0x49,0x6c,0xca,0x67,0xe1,0x3b
};
static const guint8 test_md5_data6[] = {
    0xd1,0x74,0xab,0x98,0xd2,0x77,0xd9,0xf5,
    0xa5,0x61,0x1c,0x2c,0x9f,0x41,0x9d,0x9f
};
static const guint8 test_md5_data7[] = {
    0x57,0xed,0xf4,0xa2,0x2b,0xe3,0xc9,0x55,
    0xac,0x49,0xda,0x2e,0x21,0x07,0xb6,0x7a
};

/* SHA1 examples from http://www.ietf.org/rfc/rfc3174 */

#define SHA1_TEST1   "abc"
#define SHA1_TEST2a  "abcdbcdecdefdefgefghfghighijhi"
#define SHA1_TEST2b  "jkijkljklmklmnlmnomnopnopq"
#define SHA1_TEST2   SHA1_TEST2a SHA1_TEST2b
#define SHA1_TEST3   "a"
#define SHA1_TEST4a  "01234567012345670123456701234567"
#define SHA1_TEST4b  "01234567012345670123456701234567"
#define SHA1_TEST4   SHA1_TEST4a SHA1_TEST4b

static const guint8 test_sha1_data1[] = {
    0xA9,0x99,0x3E,0x36,0x47,0x06,0x81,0x6A,
    0xBA,0x3E,0x25,0x71,0x78,0x50,0xC2,0x6C,
    0x9C,0xD0,0xD8,0x9D
};
static const guint8 test_sha1_data2[] = {
    0x84,0x98,0x3E,0x44,0x1C,0x3B,0xD2,0x6E,
    0xBA,0xAE,0x4A,0xA1,0xF9,0x51,0x29,0xE5,
    0xE5,0x46,0x70,0xF1
};
static const guint8 test_sha1_data3[] = {
    0x34,0xAA,0x97,0x3C,0xD4,0xC4,0xDA,0xA4,
    0xF6,0x1E,0xEB,0x2B,0xDB,0xAD,0x27,0x31,
    0x65,0x34,0x01,0x6F
};
static const guint8 test_sha1_data4[] = {
    0xDE,0xA3,0x56,0xA2,0xCD,0xDD,0x90,0xC7,
    0xA7,0xEC,0xED,0xC5,0xEB,0xB5,0x63,0x93,
    0x4F,0x46,0x04,0x52
};

/* SHA256 examples from https://www.ietf.org/rfc/rfc4634 */

#define SHA256_TEST1    "abc"
#define SHA256_TEST2a   "abcdbcdecdefdefgefghfghighij"
#define SHA256_TEST2b   "hijkijkljklmklmnlmnomnopnopq"
#define SHA256_TEST2    SHA256_TEST2a SHA256_TEST2b
#define SHA256_TEST3    "a"                         /* times 1000000 */
#define SHA256_TEST4a   "01234567012345670123456701234567"
#define SHA256_TEST4b   "01234567012345670123456701234567"
#define SHA256_TEST4    SHA256_TEST4a SHA256_TEST4b /* times 10 */

static const guint8 test_sha256_data1[] = {
    0xBA,0x78,0x16,0xBF,0x8F,0x01,0xCF,0xEA,
    0x41,0x41,0x40,0xDE,0x5D,0xAE,0x22,0x23,
    0xB0,0x03,0x61,0xA3,0x96,0x17,0x7A,0x9C,
    0xB4,0x10,0xFF,0x61,0xF2,0x00,0x15,0xAD
};
static const guint8 test_sha256_data2[] = {
    0x24,0x8D,0x6A,0x61,0xD2,0x06,0x38,0xB8,
    0xE5,0xC0,0x26,0x93,0x0C,0x3E,0x60,0x39,
    0xA3,0x3C,0xE4,0x59,0x64,0xFF,0x21,0x67,
    0xF6,0xEC,0xED,0xD4,0x19,0xDB,0x06,0xC1
};
static const guint8 test_sha256_data3[] = {
    0xCD,0xC7,0x6E,0x5C,0x99,0x14,0xFB,0x92,
    0x81,0xA1,0xC7,0xE2,0x84,0xD7,0x3E,0x67,
    0xF1,0x80,0x9A,0x48,0xA4,0x97,0x20,0x0E,
    0x04,0x6D,0x39,0xCC,0xC7,0x11,0x2C,0xD0
};
static const guint8 test_sha256_data4[] = {
    0x59,0x48,0x47,0x32,0x84,0x51,0xBD,0xFA,
    0x85,0x05,0x62,0x25,0x46,0x2C,0xC1,0xD8,
    0x67,0xD8,0x77,0xFB,0x38,0x8D,0xF0,0xCE,
    0x35,0xF2,0x5A,0xB5,0x56,0x2B,0xFB,0xB5
};

/* SHA512 examples from https://tools.ietf.org/html/rfc6234 */

#define SHA512_TEST1    "abc"
#define SHA512_TEST2_1  "abcdbcdecdefdefgefghfghighij" \
                        "hijkijkljklmklmnlmnomnopnopq"
#define SHA512_TEST2a   "abcdefghbcdefghicdefghijdefg" \
                        "hijkefghijklfghijklmghijklmn"
#define SHA512_TEST2b   "hijklmnoijklmnopjklmnopqklmn" \
                        "opqrlmnopqrsmnopqrstnopqrstu"
#define SHA512_TEST2    SHA512_TEST2a SHA512_TEST2b
#define SHA512_TEST3    "a"
#define SHA512_TEST4a   "01234567012345670123456701234567"
#define SHA512_TEST4b   "01234567012345670123456701234567"
#define SHA512_TEST4     SHA512_TEST4a SHA512_TEST4b

static const guint8 test_sha512_data1[] = {
    0xDD,0xAF,0x35,0xA1,0x93,0x61,0x7A,0xBA,
    0xCC,0x41,0x73,0x49,0xAE,0x20,0x41,0x31,
    0x12,0xE6,0xFA,0x4E,0x89,0xA9,0x7E,0xA2,
    0x0A,0x9E,0xEE,0xE6,0x4B,0x55,0xD3,0x9A,
    0x21,0x92,0x99,0x2A,0x27,0x4F,0xC1,0xA8,
    0x36,0xBA,0x3C,0x23,0xA3,0xFE,0xEB,0xBD,
    0x45,0x4D,0x44,0x23,0x64,0x3C,0xE8,0x0E,
    0x2A,0x9A,0xC9,0x4F,0xA5,0x4C,0xA4,0x9F
};

static const guint8 test_sha512_data2[] = {
    0x8E,0x95,0x9B,0x75,0xDA,0xE3,0x13,0xDA,
    0x8C,0xF4,0xF7,0x28,0x14,0xFC,0x14,0x3F,
    0x8F,0x77,0x79,0xC6,0xEB,0x9F,0x7F,0xA1,
    0x72,0x99,0xAE,0xAD,0xB6,0x88,0x90,0x18,
    0x50,0x1D,0x28,0x9E,0x49,0x00,0xF7,0xE4,
    0x33,0x1B,0x99,0xDE,0xC4,0xB5,0x43,0x3A,
    0xC7,0xD3,0x29,0xEE,0xB6,0xDD,0x26,0x54,
    0x5E,0x96,0xE5,0x5B,0x87,0x4B,0xE9,0x09
};

static const guint8 test_sha512_data3[] = {
    0xE7,0x18,0x48,0x3D,0x0C,0xE7,0x69,0x64,
    0x4E,0x2E,0x42,0xC7,0xBC,0x15,0xB4,0x63,
    0x8E,0x1F,0x98,0xB1,0x3B,0x20,0x44,0x28,
    0x56,0x32,0xA8,0x03,0xAF,0xA9,0x73,0xEB,
    0xDE,0x0F,0xF2,0x44,0x87,0x7E,0xA6,0x0A,
    0x4C,0xB0,0x43,0x2C,0xE5,0x77,0xC3,0x1B,
    0xEB,0x00,0x9C,0x5C,0x2C,0x49,0xAA,0x2E,
    0x4E,0xAD,0xB2,0x17,0xAD,0x8C,0xC0,0x9B
};

static const guint8 test_sha512_data4[] = {
    0x89,0xD0,0x5B,0xA6,0x32,0xC6,0x99,0xC3,
    0x12,0x31,0xDE,0xD4,0xFF,0xC1,0x27,0xD5,
    0xA8,0x94,0xDA,0xD4,0x12,0xC0,0xE0,0x24,
    0xDB,0x87,0x2D,0x1A,0xBD,0x2B,0xA8,0x14,
    0x1A,0x0F,0x85,0x07,0x2A,0x9B,0xE1,0xE2,
    0xAA,0x04,0xCF,0x33,0xC7,0x65,0xCB,0x51,
    0x08,0x13,0xA3,0x9C,0xD5,0xA8,0x4C,0x4A,
    0xCA,0xA6,0x4D,0x3F,0x3F,0xB7,0xBA,0xE9
};

static
void
test_basic(
    gconstpointer param)
{
    static const guchar data[1] = { 1 };
    GBytes* bytes = g_bytes_new_static(data, sizeof(data));
    FoilDigest* md5 = foil_digest_new_md5();
    int tmp;

    g_assert(!foil_digest_type_size(0));
    g_assert(!foil_digest_type_block_size(0));
    g_assert(!foil_digest_type_name(0));
    g_assert(!foil_digest_new(0));
    g_assert(!foil_digest_clone(NULL));
    g_assert(!foil_digest_reset(NULL));
    g_assert(!foil_digest_ref(NULL));
    g_assert(!foil_digest_size(NULL));
    g_assert(!foil_digest_block_size(NULL));
    g_assert(!foil_digest_name(NULL));
    g_assert(!foil_digest_finish(NULL));
    g_assert(!foil_digest_free_to_bytes(NULL));
    g_assert(!foil_digest_data(G_TYPE_OBJECT, NULL, 0));
    g_assert(!foil_digest_data(0, NULL, 0));
    g_assert(!foil_digest_data(0, NULL, sizeof(data)));
    g_assert(!foil_digest_data(0, data, sizeof(data)));
    g_assert(!foil_digest_data(0, data, 0));
    g_assert(!foil_digest_data_buf(G_TYPE_OBJECT, NULL, 0, NULL));
    g_assert(!foil_digest_data_buf(G_TYPE_OBJECT, NULL, 0, &tmp));
    g_assert(!foil_digest_data_buf(FOIL_DIGEST_MD5, NULL, 0, NULL));
    g_assert(!foil_digest_bytes(0, NULL));
    g_assert(!foil_digest_bytes(0, bytes));
    g_assert(!foil_digest_type_block_size(FOIL_TYPE_DIGEST));
    g_assert_cmpuint(foil_digest_type_block_size(FOIL_DIGEST_MD5), == ,64);
    g_assert_cmpuint(foil_digest_type_block_size(FOIL_DIGEST_SHA1), == ,64);
    g_assert_cmpuint(foil_digest_type_block_size(FOIL_DIGEST_SHA256), == ,64);
    g_assert_cmpuint(foil_digest_type_block_size(FOIL_DIGEST_SHA512), == ,128);
    g_assert_cmpuint(foil_digest_block_size(md5), == ,64);
    foil_digest_update(NULL, NULL, 0);
    foil_digest_update_bytes(NULL, NULL);
    foil_digest_update_bytes(md5, NULL);
    foil_digest_update_bytes(NULL, bytes);
    foil_digest_unref(NULL);
    g_bytes_unref(bytes);
    foil_digest_reset(md5);
    foil_digest_unref(md5);
}

static
void
test_clone(
    gconstpointer param)
{
    FoilDigest* d1 = foil_digest_new_md5();
    FoilDigest* d2;
    GBytes* md5_in = g_bytes_new_static(MD5_TEST2, strlen(MD5_TEST2));
    GBytes* b1;
    GBytes* b2;

    /* Clone unfinished digest */
    g_assert(foil_digest_update_bytes(d1, md5_in));
    d2 = foil_digest_clone(d1);
    b1 = foil_digest_finish(d1);
    b2 = foil_digest_finish(d2);

    /* Finished digest is not updated */
    g_assert(!foil_digest_update_bytes(d1, md5_in));

    g_assert(g_bytes_equal(b1, b2));
    g_assert(g_bytes_get_size(b1) == sizeof(test_md5_data2));
    g_assert(!memcmp(g_bytes_get_data(b1, NULL), test_md5_data2,
        sizeof(test_md5_data2)));

    foil_digest_unref(d1);
    foil_digest_unref(d2);

    /* Clone finished digest */
    d1 = foil_digest_new_sha1();
    g_assert(foil_digest_update(d1, SHA1_TEST1, strlen(SHA1_TEST1)));
    b1 = foil_digest_finish(d1);

    /* Finished digest is not updated */
    g_assert(!foil_digest_update(d1, SHA1_TEST1, strlen(SHA1_TEST1)));

    d2 = foil_digest_clone(d1);
    b2 = foil_digest_finish(d2);

    g_assert(g_bytes_equal(b1, b2));
    g_assert(g_bytes_get_size(b1) == sizeof(test_sha1_data1));
    g_assert(!memcmp(g_bytes_get_data(b1, NULL), test_sha1_data1,
        sizeof(test_sha1_data1)));

    foil_digest_unref(d1);
    foil_digest_unref(d2);
    g_bytes_unref(md5_in);
}

static
void
test_copy(
    gconstpointer param)
{
    FoilDigest* d1 = foil_digest_new_md5();
    FoilDigest* d2 = foil_digest_new_md5();
    GBytes* b1;
    GBytes* b2;

    g_assert(!foil_digest_copy(NULL, NULL));
    g_assert(!foil_digest_copy(d1, NULL));
    g_assert(!foil_digest_copy(NULL, d1));
    g_assert(foil_digest_copy(d1, d1));

    /* MD5 */
    foil_digest_update(d1, MD5_TEST2, strlen(MD5_TEST2));
    g_assert(foil_digest_copy(d2, d1));
    b1 = foil_digest_finish(d1);
    b2 = foil_digest_finish(d2);

    g_assert(g_bytes_equal(b1, b2));
    g_assert(g_bytes_get_size(b1) == sizeof(test_md5_data2));
    g_assert(!memcmp(g_bytes_get_data(b1, NULL), test_md5_data2,
        sizeof(test_md5_data2)));

    /* Mix */
    foil_digest_unref(d1);
    d1 = foil_digest_new_sha1();
    g_assert(!foil_digest_copy(d1, d2));
    g_assert(!foil_digest_copy(d2, d1));
    foil_digest_unref(d2);
    d2 = foil_digest_new_sha1();

    /* SHA1 */
    foil_digest_update(d1, SHA1_TEST1, strlen(SHA1_TEST1));
    foil_digest_update(d2, SHA1_TEST2, strlen(SHA1_TEST2));
    foil_digest_finish(d1);
    b2 = foil_digest_finish(d2);

    g_assert(foil_digest_copy(d1, d2));
    g_assert(foil_digest_finish(d1) == b2);
    g_assert(foil_digest_finish(d2) == b2);

    foil_digest_unref(d1);
    foil_digest_unref(d2);

    /* SHA256 */
    d1 = foil_digest_new_sha256();
    d2 = foil_digest_new_sha256();
    foil_digest_update(d1, SHA256_TEST1, strlen(SHA256_TEST1));
    g_assert(foil_digest_copy(d1, d2));
    foil_digest_update(d1, SHA256_TEST2, strlen(SHA256_TEST2));
    b1 = foil_digest_finish(d1);
    g_assert(g_bytes_get_size(b1) == sizeof(test_sha256_data2));
    g_assert(!memcmp(g_bytes_get_data(b1, NULL), test_sha256_data2,
        sizeof(test_sha256_data2)));

    foil_digest_unref(d1);
    foil_digest_unref(d2);

    /* SHA512 */
    d1 = foil_digest_new_sha512();
    d2 = foil_digest_new_sha512();
    foil_digest_update(d1, SHA512_TEST1, strlen(SHA512_TEST1));
    g_assert(foil_digest_copy(d1, d2));
    foil_digest_update(d1, SHA512_TEST2, strlen(SHA512_TEST2));
    b1 = foil_digest_finish(d1);
    g_assert(g_bytes_get_size(b1) == sizeof(test_sha512_data2));
    g_assert(!memcmp(g_bytes_get_data(b1, NULL), test_sha512_data2,
        sizeof(test_sha512_data2)));

    foil_digest_unref(d1);
    foil_digest_unref(d2);
}

static
void
test_reset(
    gconstpointer param)
{
    const TestDigest* test = param;
    const size_t input_len = strlen(test->input);
    GType type = test->digest_type();
    FoilDigest* digest = foil_digest_new(type);
    GBytes* b1;
    GBytes* b2;
    int i;

    for (i = 0; i < test->repeat_count; i++) {
        foil_digest_update(digest, test->input, input_len);
    }
    b1 = g_bytes_ref(foil_digest_finish(digest));

    g_assert(foil_digest_reset(digest));

    for (i = 0; i < test->repeat_count; i++) {
        foil_digest_update(digest, test->input, input_len);
    }
    b2 = foil_digest_finish(digest);

    /* Results must be different but identical */
    g_assert(b1 != b2);
    g_assert(g_bytes_equal(b1, b2));

    g_bytes_unref(b1);
    foil_digest_unref(digest);
}

static
void
test_digest(
    gconstpointer param)
{
    int i;
    const TestDigest* test = param;
    GType type = test->digest_type();
    FoilDigest* digest = foil_digest_new(type);
    FoilDigest* unfinished = foil_digest_new(type);
    const char* name = foil_digest_type_name(type);
    const size_t input_len = gutil_strlen0(test->input);
    GBytes* result;
    gsize size = 0;
    gconstpointer data;

    for (i=0; i<test->repeat_count; i++) {
        foil_digest_update(digest, test->input, input_len);
        foil_digest_update(unfinished, test->input, input_len);
    }

    result = foil_digest_finish(digest);
    data = g_bytes_get_data(result, &size);

    g_assert(foil_digest_type_size(type) == test->output_size);
    g_assert(size == test->output_size);
    g_assert(size == foil_digest_size(digest));
    g_assert(!memcmp(data, test->output, size));
    g_assert(!g_strcmp0(foil_digest_name(digest), name));
    g_assert(foil_digest_finish(digest) == result);
    g_assert(!foil_digest_data(type, NULL, 1));

    if (test->repeat_count == 1) {
        GBytes* in = g_bytes_new(test->input, input_len);
        GBytes* out = foil_digest_bytes(type, in);
        void* buf = g_malloc0(size);

        g_assert(foil_digest_data_buf(type, test->input, input_len, buf));
        g_assert(!memcmp(buf, test->output, size));
        g_assert(g_bytes_equal(result, out));
        g_bytes_unref(in);
        g_bytes_unref(out);
        g_free(buf);
    }

    foil_digest_unref(foil_digest_ref(digest));
    foil_digest_unref(digest);
    foil_digest_unref(unfinished);
}

/* Test descriptors */

#define TEST_NAME(name) "/digest/" name
#define TEST_DATA(d) d, sizeof(d)

#define TEST_(ALG,alg,i,n) { \
    TEST_NAME(#ALG "_TEST" #i), test_digest, \
    foil_impl_digest_##alg##_get_type, \
    ALG##_TEST##i, n, TEST_DATA(test_##alg##_data##i) }
#define TEST_MD5(i,n) TEST_(MD5,md5,i,n)
#define TEST_SHA1(i,n) TEST_(SHA1,sha1,i,n)
#define TEST_SHA256(i,n) TEST_(SHA256,sha256,i,n)
#define TEST_SHA512(i,n) TEST_(SHA512,sha512,i,n)

#define TEST_EMPTY(ALG,alg) {              \
    TEST_NAME(#ALG "_EMPTY"), test_digest, \
    foil_impl_digest_##alg##_get_type, \
    NULL, 1, TEST_DATA(empty_##alg##_data) }

#define TEST_RESET(ALG,alg,i,n) { \
    TEST_NAME("reset/" #ALG), test_reset, \
    foil_impl_digest_##alg##_get_type, \
    ALG##_TEST##i, n, TEST_DATA(test_##alg##_data##i) }

static const TestDigest tests[] = {
    { TEST_NAME("Basic"), test_basic },
    { TEST_NAME("Clone"), test_clone },
    { TEST_NAME("Copy"), test_copy },
    TEST_EMPTY(MD5,md5),
    TEST_EMPTY(SHA1,sha1),
    TEST_EMPTY(SHA256,sha256),
    TEST_EMPTY(SHA512,sha512),
    TEST_RESET(MD5,md5,2,1),
    TEST_RESET(SHA1,sha1,2,1),
    TEST_RESET(SHA256,sha256,2,1),
    TEST_RESET(SHA512,sha512,2,1),
    /* MD5 */
    TEST_MD5(1,1),
    TEST_MD5(2,1),
    TEST_MD5(3,1),
    TEST_MD5(4,1),
    TEST_MD5(5,1),
    TEST_MD5(6,1),
    TEST_MD5(7,1),
    /* SHA1 */
    TEST_SHA1(1,1),
    TEST_SHA1(2,1),
    TEST_SHA1(3,1000000),
    TEST_SHA1(4,10),
    /* SHA256 */
    TEST_SHA256(1,1),
    TEST_SHA256(2,1),
    TEST_SHA256(3,1000000),
    TEST_SHA256(4,10),
    /* SHA512 */
    TEST_SHA512(1,1),
    TEST_SHA512(2,1),
    TEST_SHA512(3,1000000),
    TEST_SHA512(4,10)
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
