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

#include "foil_util_p.h"
#include "foil_asn1.h"
#include "foil_digest.h"
#include "foil_input.h"
#include "foil_output.h"
#include "foil_random_p.h"

#define BYTES_SET(b,d) ((b).val = (d), (b).len = sizeof(d))
#define BYTES_IN(d) foil_input_mem_new_static(d,sizeof(d))
#define POS_SET(p,d) ((p).ptr = (p).end = (d), (p).end += sizeof(d))
#define GBYTES_STATIC(d) g_bytes_new_static(d, sizeof(d))
#define GBYTES_EQUAL(g,d) test_bytes_equal(g,d,sizeof(d))

static
void
test_bytes(
    void)
{
    static const guint8 val_123[] = { '1', '2', '3' };
    static const guint8 val_1234[] = { '1', '2', '3', '4' };
    static const guint8 val_321[] = { '3', '2', '1' };
    static const guint8 val_123_1234321[] = {
        '1', '2', '3', 0, '1', '2', '3', '4', '3', '2', '1'
    };
    static const guint8 digest_data_empty[] = {
        0xf1, 0xd3, 0xff, 0x84, 0x43, 0x29, 0x77, 0x32,
        0x86, 0x2d, 0xf2, 0x1d, 0xc4, 0xe5, 0x72, 0x62
    };
    static const guint8 digest_data_123[] = {
        0x20, 0xf9, 0x41, 0x72, 0x00, 0x34, 0xf7, 0xfe,
        0x4b, 0x8e, 0x68, 0x49, 0xef, 0x64, 0x62, 0x61
    };
    GBytes* digest_bytes_empty = GBYTES_STATIC(digest_data_empty);
    GBytes* digest_bytes_123 = GBYTES_STATIC(digest_data_123);
    GBytes* data_123 = GBYTES_STATIC(val_123);
    FoilBytes bytes_123, bytes_1234, bytes_321;
    FoilBytes _bytes_123, _bytes_1234, _bytes_321, _null, empty;
    FoilBytes bytes_123a, bytes_123b, bytes_123c;
    FoilDigest* digest;
    guint8* data;
    guint8* ptr;
    gsize size;

    BYTES_SET(bytes_123, val_123);
    BYTES_SET(bytes_123a, val_123);
    BYTES_SET(bytes_1234, val_1234);
    BYTES_SET(bytes_321, val_321);
    g_assert(!foil_bytes_from_string(NULL, NULL));
    g_assert(foil_bytes_from_string(&bytes_123b, NULL) == &bytes_123b);
    g_assert(!bytes_123b.len);
    g_assert(!bytes_123b.val);
    g_assert(foil_bytes_from_string(&bytes_123b, "123") == &bytes_123b);
    g_assert(!foil_bytes_from_data(NULL, NULL));
    g_assert(foil_bytes_from_data(&bytes_123c, NULL) == &bytes_123c);
    g_assert(!bytes_123c.len);
    g_assert(!bytes_123c.val);
    g_assert(foil_bytes_from_data(&bytes_123c, data_123) == &bytes_123c);
    g_assert(foil_bytes_equal(NULL, NULL));
    g_assert(foil_bytes_equal(&bytes_123, &bytes_123));
    g_assert(foil_bytes_equal(&bytes_123, &bytes_123a));
    g_assert(foil_bytes_equal(&bytes_123, &bytes_123b));
    g_assert(foil_bytes_equal(&bytes_123, &bytes_123c));
    g_assert(!foil_bytes_equal(&bytes_123, &bytes_1234));
    g_assert(!foil_bytes_equal(&bytes_123, &bytes_321));
    g_assert(!foil_bytes_equal(&bytes_123, NULL));
    g_assert(!foil_bytes_equal(NULL, &bytes_123));

    g_assert(!foil_bytes_copy(&_null, NULL, NULL));
    g_assert(!foil_bytes_copy(&_null, &_null, NULL));
    g_assert(!_null.len);

    memset(&empty, 0, sizeof(empty));
    empty.val = (void*)&empty;
    g_assert(!foil_bytes_copy(&_null, &empty, NULL));
    g_assert(!_null.len);

    digest = foil_digest_new(FOIL_DIGEST_MD5);
    foil_bytes_digest(NULL, digest);
    g_assert(g_bytes_equal(foil_digest_finish(digest), digest_bytes_empty));
    foil_digest_unref(digest);

    digest = foil_digest_new(FOIL_DIGEST_MD5);
    foil_bytes_digest(&_null, digest);
    g_assert(g_bytes_equal(foil_digest_finish(digest), digest_bytes_empty));
    foil_digest_unref(digest);

    digest = foil_digest_new(FOIL_DIGEST_MD5);
    foil_bytes_digest(&bytes_123, digest);
    g_assert(g_bytes_equal(foil_digest_finish(digest), digest_bytes_123));
    foil_digest_unref(digest);

    size = FOIL_ALIGN(sizeof(val_123)) + FOIL_ALIGN(sizeof(val_1234)) +
        FOIL_ALIGN(sizeof(val_321));
    data = g_malloc(size);
    memset(data, 0, size);
    ptr = foil_bytes_copy(&_bytes_321, &bytes_321,
        foil_bytes_copy(&_bytes_1234, &bytes_1234,
        foil_bytes_copy(&_bytes_123, &bytes_123, data)));
    g_assert(ptr == (data + size));
    g_assert(!memcmp(data, val_123_1234321, sizeof(val_123_1234321)));
    g_assert(foil_bytes_equal(&_bytes_321, &bytes_321));
    g_assert(foil_bytes_equal(&_bytes_1234, &bytes_1234));
    g_assert(foil_bytes_equal(&_bytes_123, &bytes_123));
    g_free(data);

    g_bytes_unref(digest_bytes_empty);
    g_bytes_unref(digest_bytes_123);
    g_bytes_unref(data_123);
}

static
void
test_random(
    void)
{
    const guint len = 256;
    GBytes* bytes1 = foil_random_generate_bytes(FOIL_RANDOM_DEFAULT, len);
    GBytes* bytes2 = foil_random_generate_bytes(FOIL_RANDOM_DEFAULT, len);
    g_assert(!foil_random_generate(FOIL_TYPE_RANDOM, NULL, 0));
    g_assert(!foil_random_generate(0, NULL, 0));
    g_assert(!foil_random_generate_bytes(0, 0));
    g_assert(!foil_random_generate_bytes(FOIL_DIGEST_MD5, 10));
    g_assert(g_bytes_get_size(bytes1) == len);
    g_assert(!g_bytes_equal(bytes1, bytes2));
    g_bytes_unref(bytes1);
    g_bytes_unref(bytes2);
}

static
void
test_skip(
    void)
{
    FoilParsePos pos;
    static const FoilBytes bytes = { (const void*)"xyz", 3 };

    /* Test NULL resistance */
    g_assert(!foil_parse_init_string(NULL, NULL));
    g_assert(!foil_parse_init_string(&pos, NULL));

    g_assert(foil_parse_init_string(&pos, "") == 0);
    g_assert(!foil_parse_skip_to_next_line(&pos, TRUE));
    g_assert(!foil_parse_skip_to_next_line(&pos, FALSE));

    g_assert(foil_parse_init_string(&pos, "      \\\r\nx"));
    g_assert(foil_parse_skip_to_next_line(&pos, FALSE));
    g_assert(!g_strcmp0((char*)pos.ptr, "x"));

    g_assert(foil_parse_init_string(&pos, "      \\\r\nx"));
    g_assert(!foil_parse_skip_to_next_line(&pos, TRUE));
    g_assert(!g_strcmp0((char*)pos.ptr, ""));

    g_assert(foil_parse_init_string(&pos, "xy"));
    g_assert(!foil_parse_skip_bytes(&pos, &bytes));

    g_assert(foil_parse_init_string(&pos, "xxx"));
    g_assert(!foil_parse_skip_bytes(&pos, &bytes));

    g_assert(foil_parse_init_string(&pos, "xyz"));
    g_assert(foil_parse_skip_bytes(&pos, &bytes));
    g_assert(pos.ptr == pos.end);

    g_assert(foil_parse_init_string(&pos, "xyz "));
    g_assert(foil_parse_skip_bytes(&pos, &bytes));
    g_assert(!g_strcmp0((char*)pos.ptr, " "));
}

static
void
test_format_header_1(
    const char* tag,
    const char* value,
    const char* expected)
{
    FoilParsePos pos;
    GHashTable* headers;
    char* header = foil_format_header(tag, value);

    GDEBUG("%s", header);
    g_assert(!g_strcmp0(header, expected));
    foil_parse_init_string(&pos, header);
    headers = foil_parse_headers(&pos, NULL);
    g_assert(headers);
    g_assert(g_hash_table_size(headers) == 1);
    if (!value) value = "";
    g_assert(!g_strcmp0(g_hash_table_lookup(headers, tag), value));
    g_hash_table_destroy(headers);
    g_free(header);
}

static
void
test_format_header(
    void)
{
    g_assert(!foil_format_header(NULL, NULL));
    g_assert(!foil_format_header("", NULL));
    g_assert(!foil_format_header("TooLongLongLongLongLongLongLongLongLongLong"
        "LongLongLongLongLongTag", NULL));
    g_assert(!foil_format_header("Tag", "TooLongLongLongLongLongLongLongLong"
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
        "LongLongLongLongLongLongLongLongLongValue"));

    test_format_header_1("Tag", NULL, "Tag: ");
    test_format_header_1("Tag", "", "Tag: ");
    test_format_header_1("Tag", "Value", "Tag: Value");

    /* One continued line */
    test_format_header_1("Tag", "LongLongLongLongLongLongLongLong"
        "LongLongLongLongLongLongLongLongLongLongValue",
        "Tag: LongLongLongLongLongLongLongLongLong"
        "LongLongLongLongLongLongLongLo\\\n" "ngLongValue");

    /* Two continued lines */
    test_format_header_1("Tag", "LongLongLongLongLongLongLongLongLong"
      "LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"
      "LongLongLongLongLongLongLongLongValue",
      "Tag: LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"
      "Lo\\\n" "ngLongLongLongLongLongLongLongLongLongLongLongLongLongLongLo"
      "ngLongLongV\\\n""alue");

    /* UTF-8 should be split at the character boundary */
    test_format_header_1("Tag", "Long UTF-8 value"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82",
        "Tag: Long UTF-8 value"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\\\n"
        "\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\\\n"
        "\xD0\xB5\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82"
        " \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82");
}

static
void
test_parse_headers(
    void)
{
    GString* buf = g_string_new(NULL);
    FoilParsePos pos;
    GHashTable* headers;

    foil_parse_init_string(&pos, "");
    headers = foil_parse_headers(&pos, buf);
    g_assert(!headers);
    g_assert(!buf->len);

    foil_parse_init_string(&pos, "\r\nFoo:foo\n Bar:   \n"
        "FooBar: foo\\\r\nbar\n\n:");
    headers = foil_parse_headers(&pos, buf);
    g_assert(headers);
    g_assert(g_hash_table_size(headers) == 3);
    g_assert(!g_strcmp0((char*)pos.ptr, ":"));
    g_assert(!g_strcmp0(g_hash_table_lookup(headers, "Foo"), "foo"));
    g_assert(!g_strcmp0(g_hash_table_lookup(headers, "Bar"), ""));
    g_assert(!g_strcmp0(g_hash_table_lookup(headers, "FooBar"), "foobar"));
    g_assert(!buf->len);
    g_hash_table_destroy(headers);

    g_string_free(buf, TRUE);
}

static
void
test_base64(
    void)
{
    static const guint8 a[] = { 0x01 };
    static const guint8 b[] = { 0x01, 0x02 };
    static const guint8 c[] = { 0x01, 0x02, 0x03 };
    FoilParsePos pos;
    GBytes* bytes;

    foil_parse_init_string(&pos, "AQ");
    bytes = foil_parse_base64(&pos, 0);
    GBYTES_EQUAL(bytes, a);
    g_bytes_unref(bytes);

    foil_parse_init_string(&pos, "AQI");
    bytes = foil_parse_base64(&pos, 0);
    GBYTES_EQUAL(bytes, b);
    g_bytes_unref(bytes);

    foil_parse_init_string(&pos, "A Q I D");
    bytes = foil_parse_base64(&pos, FOIL_INPUT_BASE64_IGNORE_SPACES);
    GBYTES_EQUAL(bytes, c);
    g_bytes_unref(bytes);

    foil_parse_init_string(&pos, "A Q I D");
    g_assert(!foil_parse_base64(&pos, FOIL_INPUT_BASE64_VALIDATE));
}

static
void
test_memmem(
    void)
{
    static const guint8 a[] = { 0x01 };
    static const guint8 b[] = { 0x01, 0x02 };
    static const guint8 c[] = { 0x01, 0x02, 0x03 };
    static const guint8 d[] = { 0x02, 0x03 };

    g_assert(!foil_memmem(NULL, 0, NULL, 0));
    g_assert(!foil_memmem(a, sizeof(a), NULL, 0));
    g_assert(!foil_memmem(a, sizeof(a), b, sizeof(b)));
    g_assert(foil_memmem(b, sizeof(b), a, sizeof(a)) == b);
    g_assert(foil_memmem(c, sizeof(c), d, sizeof(d)) == c + 1);
}

static
void
test_asn1_len(
    void)
{
    static const guint8 len_short [] = { 0x1};
    static const guint8 len_indef [] = { 0x80};
    static const guint8 len_long1 [] = { 0x81,0x80};
    static const guint8 len_long2 [] = { 0x82,0x01,0x02 };
    static const guint8 len_too_long [] = { 0x85,0x01,0x02,0x03,0x04,0x05 };
    static const guint8 len_err1 [] = { 0x82,0x01 };
    static const guint8 len_err2 [] = { 0x82 };
    FoilInput* in;
    guint32 len;
    gboolean def;
    FoilParsePos pos;

    pos.ptr = pos.end = len_short;
    in = foil_input_mem_new(NULL);
    g_assert(!foil_asn1_parse_len(&pos, NULL, NULL));
    g_assert(!foil_asn1_read_len(in, NULL, NULL));
    foil_input_unref(in);

    /* Short form */
    POS_SET(pos, len_short);
    in = BYTES_IN(len_short);
    g_assert(foil_asn1_parse_len(&pos, &len, &def));
    g_assert(len == len_short[0]);
    g_assert(def);
    g_assert(pos.ptr == pos.end);
    g_assert(foil_asn1_read_len(in, &len, &def));
    g_assert(len == len_short[0]);
    g_assert(def);
    g_assert(!foil_input_has_available(in, 1));
    foil_input_unref(in);

    POS_SET(pos, len_short);
    in = BYTES_IN(len_short);
    g_assert(foil_asn1_parse_len(&pos, NULL, NULL));
    g_assert(pos.ptr == pos.end);
    g_assert(foil_asn1_read_len(in, NULL, NULL));
    g_assert(!foil_input_has_available(in,1));
    foil_input_unref(in);

    /* Indefinite form */
    POS_SET(pos, len_indef);
    in = BYTES_IN(len_indef);
    g_assert(foil_asn1_parse_len(&pos, &len, &def));
    g_assert(pos.ptr == pos.end);
    g_assert(!len);
    g_assert(!def);
    g_assert(foil_asn1_read_len(in, &len, &def));
    g_assert(!foil_input_has_available(in,1));
    g_assert(!len);
    g_assert(!def);
    foil_input_unref(in);

    POS_SET(pos, len_indef);
    in = BYTES_IN(len_indef);
    g_assert(foil_asn1_parse_len(&pos, NULL, NULL));
    g_assert(pos.ptr == pos.end);
    g_assert(foil_asn1_read_len(in, NULL, NULL));
    g_assert(!foil_input_has_available(in,1));
    foil_input_unref(in);

    /* Long form (1 byte) */
    POS_SET(pos, len_long1);
    in = BYTES_IN(len_long1);
    g_assert(foil_asn1_parse_len(&pos, &len, &def));
    g_assert(pos.ptr == pos.end);
    g_assert(len == 0x80);
    g_assert(def);
    g_assert(foil_asn1_read_len(in, &len, &def));
    g_assert(!foil_input_has_available(in,1));
    g_assert(len == 0x80);
    g_assert(def);
    foil_input_unref(in);

    POS_SET(pos, len_long1);
    in = BYTES_IN(len_long1);
    g_assert(foil_asn1_parse_len(&pos, NULL, NULL));
    g_assert(pos.ptr == pos.end);
    g_assert(foil_asn1_read_len(in, NULL, NULL));
    g_assert(!foil_input_has_available(in,1));
    foil_input_unref(in);

    /* Long form (2 byte) */
    POS_SET(pos, len_long2);
    in = BYTES_IN(len_long2);
    g_assert(foil_asn1_parse_len(&pos, &len, &def));
    g_assert(pos.ptr == pos.end);
    g_assert(len == 0x102);
    g_assert(def);
    g_assert(foil_asn1_read_len(in, &len, &def));
    g_assert(!foil_input_has_available(in,1));
    g_assert(len == 0x102);
    g_assert(def);
    foil_input_unref(in);

    POS_SET(pos, len_long2);
    in = BYTES_IN(len_long2);
    g_assert(foil_asn1_parse_len(&pos, NULL, NULL));
    g_assert(pos.ptr == pos.end);
    g_assert(foil_asn1_read_len(in, NULL, NULL));
    g_assert(!foil_input_has_available(in,1));
    foil_input_unref(in);

    /* Long form (too long) */
    POS_SET(pos, len_too_long);
    in = BYTES_IN(len_too_long);
    g_assert(!foil_asn1_parse_len(&pos, &len, &def));
    g_assert(pos.ptr <= len_too_long);
    g_assert(!foil_asn1_read_len(in, &len, &def));
    g_assert(foil_input_has_available(in,1));
    foil_input_unref(in);

    POS_SET(pos, len_too_long);
    in = BYTES_IN(len_too_long);
    g_assert(!foil_asn1_parse_len(&pos, NULL, NULL));
    g_assert(pos.ptr <= len_too_long);
    g_assert(!foil_asn1_read_len(in, NULL, NULL));
    g_assert(foil_input_has_available(in,1));
    foil_input_unref(in);

    /* Long form (truncated) */
    POS_SET(pos, len_err1);
    in = BYTES_IN(len_err1);
    g_assert(!foil_asn1_parse_len(&pos, &len, &def));
    g_assert(pos.ptr <= len_err1);
    g_assert(!foil_asn1_read_len(in, &len, &def));
    g_assert(foil_input_has_available(in,1));
    foil_input_unref(in);

    POS_SET(pos, len_err1);
    in = BYTES_IN(len_err1);
    g_assert(!foil_asn1_parse_len(&pos, NULL, NULL));
    g_assert(pos.ptr <= len_err1);
    g_assert(!foil_asn1_read_len(in, NULL, NULL));
    g_assert(foil_input_has_available(in,1));
    foil_input_unref(in);

    POS_SET(pos, len_err2);
    in = BYTES_IN(len_err2);
    g_assert(!foil_asn1_parse_len(&pos, &len, &def));
    g_assert(pos.ptr <= len_err2);
    g_assert(!foil_asn1_read_len(in, &len, &def));
    g_assert(foil_input_has_available(in,1));
    foil_input_unref(in);

    POS_SET(pos, len_err2);
    in = BYTES_IN(len_err2);
    g_assert(!foil_asn1_parse_len(&pos, NULL, NULL));
    g_assert(pos.ptr <= len_err2);
    g_assert(!foil_asn1_read_len(in, NULL, NULL));
    g_assert(foil_input_has_available(in,1));
    foil_input_unref(in);
}

static
void
test_asn1_seq(
    void)
{
    static const guint8 seq1 [] = { 0x30, 0x01, 0x02 };
    static const guint8 seq2 [] = {
        0x30, 0x82, 0x01, 0x04,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
        0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x88, 0x88,
        0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
        0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
        0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
        0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xe8,
        0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xd8,
        0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
        0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x88, 0x88,
        0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
        0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
        0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
        0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xe8,
        0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xd8,
        0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
        0xf9, 0xfa, 0xfb, 0xfc
    };
    static const guint8 badseq1 [] = { 0x30 };
    static const guint8 badseq2 [] = { 0x30, 0x80 };
    static const guint8 notseq [] = { 0x04, 0x01, 0x02 };

    const FoilBytes bytes1 = { seq1 + 2, sizeof(seq1) - 2 };
    const FoilBytes bytes2 = { seq2 + 4, sizeof(seq2) - 4 };
    const FoilBytes* data1 = &bytes1;
    FoilParsePos pos;
    guint32 len;
    FoilInput* in0 = foil_input_mem_new(NULL);
    FoilInput* in1 = foil_input_mem_new_static(seq1, sizeof(seq1));
    FoilInput* in2 = foil_input_mem_new_static(seq2, sizeof(seq2));
    FoilInput* in_bad1 = foil_input_mem_new_static(badseq1, sizeof(badseq1));
    FoilInput* in_bad2 = foil_input_mem_new_static(badseq2, sizeof(badseq2));
    FoilInput* in_notseq = foil_input_mem_new_static(notseq, sizeof(notseq));
    GBytes* enc1 = foil_asn1_encode_sequence_bytes(&data1, 1);
    FoilOutput* out2 = foil_output_ref(foil_output_mem_new(NULL));
    FoilOutput* out3 = foil_output_mem_new(NULL);
    gsize n2 = foil_asn1_encode_sequence_data(out2, bytes2.val, bytes2.len);
    GBytes* enc2 = foil_output_free_to_bytes(out2);
    GBytes* enc3;
    foil_output_unref(out2);

    g_assert(foil_asn1_encode_sequence_header(out3, bytes2.len));
    foil_output_write(out3, bytes2.val, bytes2.len);
    enc3 = foil_output_free_to_bytes(out3);
    g_assert(g_bytes_equal(enc2, enc3));
    g_bytes_unref(enc3);

    g_assert(n2);
    g_assert(n2 == foil_asn1_block_length(bytes2.len));
    g_assert(GBYTES_EQUAL(enc1, seq1));
    g_assert(GBYTES_EQUAL(enc2, seq2));

    POS_SET(pos, seq1);
    g_assert(foil_asn1_is_block_header(&pos, NULL));
    g_assert(foil_asn1_is_block_header(&pos, &len));
    g_assert(len == sizeof(seq1));
    g_assert(foil_asn1_parse_skip_sequence_header(&pos, NULL));

    POS_SET(pos, seq2);
    g_assert(foil_asn1_is_block_header(&pos, NULL));
    g_assert(foil_asn1_is_block_header(&pos, &len));
    g_assert(len == sizeof(seq2));
    g_assert(foil_asn1_parse_skip_sequence_header(&pos, NULL));
    g_assert(foil_asn1_read_sequence_header(in1, &len));
    g_assert(len == bytes1.len);
    g_assert(foil_asn1_read_sequence_header(in2, &len));
    g_assert(len == bytes2.len);
    g_assert(!foil_asn1_read_sequence_header(in_bad1, &len));
    g_assert(!foil_asn1_read_sequence_header(in_bad2, &len));
    g_assert(!foil_asn1_read_sequence_header(in0, &len));
    g_assert(!foil_asn1_read_sequence_header(in1, &len));
    g_assert(!foil_asn1_read_sequence_header(in2, &len));

    POS_SET(pos, badseq1);
    g_assert(!foil_asn1_is_block_header(&pos, &len));

    POS_SET(pos, badseq2);
    g_assert(!foil_asn1_is_block_header(&pos, &len));

    POS_SET(pos, notseq);
    g_assert(foil_asn1_is_block_header(&pos, NULL));
    g_assert(!foil_asn1_read_sequence_header(in_notseq, NULL));

    foil_input_unref(in0);
    foil_input_unref(in1);
    foil_input_unref(in2);
    foil_input_unref(in_bad1);
    foil_input_unref(in_bad2);
    foil_input_unref(in_notseq);
    g_bytes_unref(enc1);
    g_bytes_unref(enc2);
}

static
void
test_asn1_bit_string(
    void)
{
    static const guint8 test1 [] = { 0x03, 0x01, 0x00 };
    static const guint8 test2 [] = {
        0x03, 0x82, 0x01, 0x05, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
        0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x88, 0x88,
        0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
        0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
        0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
        0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xe8,
        0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xd8,
        0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
        0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x88, 0x88,
        0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
        0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
        0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
        0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xe8,
        0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xd8,
        0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
        0xf9, 0xfa, 0xfb, 0xfc
    };
    static const struct asn1_bit_strings_test {
        const guint8* enc;
        gsize len;
        guint header;
    } subtest [] = {
        { test1, sizeof(test1),  3 },
        { test2, sizeof(test2),  5 },
    };

    guint i;
    guint32 len;
    FoilParsePos pos;
    static const guint8 not_bit_string[] = { 0x00 };
    static const guint8 broken_bit_string[] = { 0x03, 0x82, 0x01 };
    static const guint8 broken_bit_string2[] = { 0x03, 0x00 };
    static const guint8 broken_bit_string3[] = { 0x03, 0x01, 0x08 };
    static const guint8 broken_bit_string4[] = { 0x03, 0x02, 0x00 };

    POS_SET(pos, not_bit_string);
    g_assert(!foil_asn1_is_bit_string(&pos));
    g_assert(!foil_asn1_parse_bit_string(&pos, NULL, NULL));
    g_assert(!foil_asn1_parse_start_bit_string(&pos, NULL, NULL));
    g_assert(pos.ptr == not_bit_string);

    POS_SET(pos, broken_bit_string);
    g_assert(foil_asn1_is_bit_string(&pos));
    g_assert(!foil_asn1_parse_bit_string(&pos, NULL, NULL));
    g_assert(!foil_asn1_parse_start_bit_string(&pos, NULL, NULL));
    g_assert(pos.ptr == broken_bit_string);

    POS_SET(pos, broken_bit_string2);
    g_assert(foil_asn1_is_bit_string(&pos));
    g_assert(!foil_asn1_parse_bit_string(&pos, NULL, NULL));
    g_assert(!foil_asn1_parse_start_bit_string(&pos, NULL, NULL));
    g_assert(pos.ptr == broken_bit_string2);

    POS_SET(pos, broken_bit_string3);
    g_assert(foil_asn1_is_bit_string(&pos));
    g_assert(!foil_asn1_parse_bit_string(&pos, NULL, NULL));
    g_assert(!foil_asn1_parse_start_bit_string(&pos, NULL, NULL));
    g_assert(pos.ptr == broken_bit_string3);

    POS_SET(pos, broken_bit_string4);
    g_assert(foil_asn1_is_bit_string(&pos));
    g_assert(!foil_asn1_parse_bit_string(&pos, NULL, NULL));
    g_assert(!foil_asn1_parse_start_bit_string(&pos, NULL, NULL));
    g_assert(pos.ptr == broken_bit_string4);

    pos.end = pos.ptr;
    g_assert(!foil_asn1_is_bit_string(&pos));

    for (i=0; i<G_N_ELEMENTS(subtest); i++) {
        const FoilBytes bytes = { subtest[i].enc + subtest[i].header,
            subtest[i].len - subtest[i].header };
        FoilInput* in = foil_input_mem_new_static(subtest[i].enc,
            subtest[i].len);
        GBytes* enc = foil_asn1_encode_bit_string_bytes(&bytes, 0);
        GBytes* enc1;
        FoilOutput* out = foil_output_mem_new(NULL);
        FoilBytes bytes1;
        guint8 unused_bits = 0xff;

        GDEBUG("%u: %u bytes", i, (guint)bytes.len);
        g_assert(foil_asn1_encode_bit_string_header(out, bytes.len*8));
        foil_output_write(out, bytes.val, bytes.len);
        enc1 = foil_output_free_to_bytes(out);
        g_assert(g_bytes_equal(enc, enc1));
        g_bytes_unref(enc1);

        out = foil_output_mem_new(NULL);
        g_assert(foil_asn1_encode_bit_string(out, &bytes, 0));
        enc1 = foil_output_free_to_bytes(out);
        g_assert(g_bytes_equal(enc, enc1));
        g_bytes_unref(enc1);

        g_assert(g_bytes_get_size(enc) ==
            foil_asn1_bit_string_block_length(bytes.len*8));
        g_assert(test_bytes_equal(enc, subtest[i].enc, subtest[i].len));

        /* Parse the header */
        pos.ptr = subtest[i].enc;
        pos.end = pos.ptr + subtest[i].len;
        g_assert(foil_asn1_parse_start_bit_string(&pos, NULL, NULL));

        /* Same thing again, this time checking length and unused bits */
        pos.ptr = subtest[i].enc;
        pos.end = pos.ptr + subtest[i].len;
        g_assert(foil_asn1_parse_start_bit_string(&pos, &len, &unused_bits));
        g_assert(!unused_bits);
        g_assert(len == bytes.len);

        /* Parse the whole thing */
        pos.ptr = subtest[i].enc;
        pos.end = pos.ptr + subtest[i].len;
        g_assert(foil_asn1_parse_bit_string(&pos, NULL, NULL));
        g_assert(pos.end == pos.ptr);

        /* Same thing again, this time checking bytes and unused bits */
        pos.ptr = subtest[i].enc;
        pos.end = pos.ptr + subtest[i].len;
        unused_bits = 0xff;
        g_assert(foil_asn1_parse_bit_string(&pos, &bytes1, &unused_bits));
        g_assert(foil_bytes_equal(&bytes, &bytes1));
        g_assert(!unused_bits);
        g_assert(pos.end == pos.ptr);

        foil_input_unref(in);
        g_bytes_unref(enc);
    }
}

static
void
test_asn1_octet_string(
    void)
{
    static const guint8 test1 [] = { 0x04, 0x01, 0x02 };
    static const guint8 test2 [] = {
        0x04, 0x82, 0x01, 0x04,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
        0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x88, 0x88,
        0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
        0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
        0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
        0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xe8,
        0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xd8,
        0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
        0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x88, 0x88,
        0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
        0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
        0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
        0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xe8,
        0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xd8,
        0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
        0xf9, 0xfa, 0xfb, 0xfc
    };
    static const struct asn1_octet_strings_test {
        const guint8* enc;
        gsize len;
        guint header;
    } subtest [] = {
        { test1, sizeof(test1),  2 },
        { test2, sizeof(test2),  4 },
    };

    guint i;
    for (i=0; i<G_N_ELEMENTS(subtest); i++) {
        const FoilBytes bytes = { subtest[i].enc + subtest[i].header,
            subtest[i].len - subtest[i].header };
        FoilInput* in = foil_input_mem_new_static(subtest[i].enc,
            subtest[i].len);
        GBytes* enc = foil_asn1_encode_octet_string_bytes(&bytes);
        GBytes* enc1;
        FoilOutput* out = foil_output_mem_new(NULL);
        guint32 len;

        g_assert(foil_asn1_encode_octet_string_header(out, bytes.len));
        foil_output_write(out, bytes.val, bytes.len);
        enc1 = foil_output_free_to_bytes(out);
        g_assert(g_bytes_equal(enc, enc1));
        g_bytes_unref(enc1);

        g_assert(g_bytes_get_size(enc) == foil_asn1_block_length(bytes.len));
        g_assert(test_bytes_equal(enc, subtest[i].enc, subtest[i].len));

        g_assert(foil_asn1_read_octet_string_header(in, &len));
        g_assert(len == bytes.len);

        foil_input_unref(in);
        g_bytes_unref(enc);
    }
}

static
void
test_asn1_octet_string2(
    void)
{
    static const guint8 good1 [] = { 0x04, 0x01, 0x01 };
    static const guint8 good2 [] = { 0x44, 0x01, 0x01 };
    static const guint8 good3 [] = { 0x44, 0x00 };
    static const guint8 indef1 [] = { 0x04, 0xff, 0x00, 0x00 };
    static const guint8 short1 [] = { 0x04, 0x83, 0x01, 0x00, 0x00 };
    static const guint8 short2 [] = { 0x04, 0x84, 0xff, 0xff, 0xff, 0xff };
    static const guint8 wrong1 [] = { 0x02, 0x01, 0xff };
    static const guint8 broken1 [] = { 0x03, 0x88, 0x99 };
    static const struct asn1_octet_strings2_test {
        gboolean good_tag;
        gboolean good_header;
        gboolean good;
        const void* data;
        gsize len;
    } subtest [] = {
        { TRUE,  TRUE,  TRUE,  good1,   sizeof(good1) },
        { TRUE,  TRUE,  TRUE,  good2,   sizeof(good2) },
        { TRUE,  TRUE,  TRUE,  good3,   sizeof(good3) },
        { TRUE,  FALSE, FALSE, indef1,  sizeof(indef1) },
        { TRUE,  TRUE,  FALSE, short1,  sizeof(short1) },
        { TRUE,  FALSE, FALSE, short2,  sizeof(short2) },
        { FALSE, TRUE,  FALSE, wrong1,  sizeof(wrong1) },
        { FALSE, FALSE, FALSE, broken1, sizeof(broken1) },
        { FALSE, FALSE, FALSE, broken1, 0 }
    };

    guint i;
    for (i=0; i<G_N_ELEMENTS(subtest); i++) {
        FoilParsePos pos, pos2;
        FoilBytes bytes;
        gboolean expected = subtest[i].good;
        pos.ptr = subtest[i].data;
        pos.end = pos.ptr + subtest[i].len;
        pos2 = pos;

        g_assert(foil_asn1_is_octet_string(&pos) == subtest[i].good_tag);
        g_assert(foil_asn1_parse_octet_string(&pos, &bytes) == expected);
        g_assert(foil_asn1_parse_octet_string(&pos2, NULL) == expected);
        g_assert(!expected || !foil_asn1_is_octet_string(&pos));

        pos.ptr = subtest[i].data;
        pos.end = pos.ptr + subtest[i].len;
        g_assert(foil_asn1_is_block_header(&pos, NULL) ==
            subtest[i].good_header);
    }
}

static
void
test_asn1_ia5_string(
    void)
{
    static const guint8 good1 [] = { 0x16, 0x00 };
    static const guint8 good2 [] = { 0x16, 0x01, 0x31 };
    static const guint8 good3 [] = { 0x16, 0x02, 0x31, 0x32 };
    static const guint8 good4 [] = { 0x56, 0x01, 0x31 };
    static const guint8 good5 [] = { 0x56, 0x00 };
    static const guint8 indef1 [] = { 0x16, 0xff, 0x00, 0x00 };
    static const guint8 short1 [] = { 0x16, 0x83, 0x01, 0x00, 0x00 };
    static const guint8 wrong1 [] = { 0x02, 0x01, 0xff };
    static const guint8 broken1 [] = { 0x03, 0x88, 0x99 };
    static const struct asn1_ia5_strings_test {
        gboolean good_tag;
        gboolean good;
        gboolean convert_back;
        const void* data;
        gsize len;
    } strtest [] = {
        { TRUE, TRUE, TRUE, good1, sizeof(good1) },
        { TRUE, TRUE, TRUE, good2, sizeof(good2) },
        { TRUE, TRUE, TRUE, good3, sizeof(good3) },
        { TRUE, TRUE, FALSE, good4, sizeof(good4) },
        { TRUE, TRUE, FALSE, good5, sizeof(good5) },
        { TRUE, FALSE, FALSE, indef1, sizeof(indef1) },
        { TRUE, FALSE, FALSE, short1, sizeof(short1) },
        { FALSE, FALSE, FALSE, wrong1, sizeof(wrong1) },
        { FALSE, FALSE, FALSE, broken1, sizeof(broken1) },
        { FALSE, FALSE, FALSE, broken1, 0 }
    };

    guint i;

    g_assert(!foil_asn1_encode_ia5_string(NULL, NULL));
    g_assert(!foil_asn1_encode_ia5_string_bytes(NULL));

    for (i=0; i<G_N_ELEMENTS(strtest); i++) {
        const struct asn1_ia5_strings_test* subtest = strtest + i;
        gsize length;
        FoilInput* in = foil_input_mem_new_static(subtest->data, subtest->len);
        char* str = foil_asn1_read_ia5_string(in, -1, &length);
        FoilParsePos pos, pos2;
        FoilBytes bytes;
        gboolean expected = subtest->good;
        pos.ptr = subtest->data;
        pos.end = pos.ptr + subtest->len;
        pos2 = pos;
        g_assert(foil_asn1_is_ia5_string(&pos) == subtest->good_tag);
        g_assert(foil_asn1_parse_ia5_string(&pos, &bytes) == expected);
        g_assert(foil_asn1_parse_ia5_string(&pos2, NULL) == expected);
        g_assert(!expected || !foil_asn1_is_ia5_string(&pos));
        if (subtest->convert_back) {
            GString* s = g_string_new_len((char*)bytes.val, bytes.len);
            GBytes* enc = foil_asn1_encode_ia5_string_bytes(s->str);
            g_assert(test_bytes_equal(enc, subtest->data, subtest->len));
            g_string_free(s, TRUE);
            g_bytes_unref(enc);
        } else {
            g_assert(!expected || length == subtest->len - 2);
        }
        g_assert(expected == (str != NULL));
        if (str) {
            char* str2;
            if (length > 1) {
                foil_input_unref(in);
                in = foil_input_mem_new_static(subtest->data, subtest->len);
                g_assert(!foil_asn1_read_ia5_string(in, length - 1, NULL));
                g_assert(foil_input_has_available(in, subtest->len));
            }
            foil_input_unref(in);
            in = foil_input_mem_new_static(subtest->data, subtest->len);
            str2 = foil_asn1_read_ia5_string(in, length + 1, NULL);
            g_assert(str2);
            g_assert(!strcmp(str, str2));
            g_assert(!foil_input_has_available(in, 1));
            g_free(str2);
        }
        g_free(str);
        foil_input_unref(in);
    }
}

static
void
test_asn1_integer(
    void)
{
    static const guint8 notint [] = { 0x01 };
    static const guint8 indef [] = { 0x02,0x80 };
    static const guint8 truncated [] = { 0x02,0x01 };
    static const guint8 toolong [] = { 0x02,0x05,0x01,0x02,0x03,0x04,0x05 };
    static const guint8 toolong2 [] = {0x02,0x81,0x05,0x01,0x02,0x03,0x04,0x05};
    static const guint8 lentoolong [] = {0x02,0x85,0x01,0x02,0x03,0x04,0x05};
    static const guint8 plus0 [] = { 0x02,0x01,0x00 };
    static const guint8 plus1 [] = { 0x02,0x01,0x01 };
    static const guint8 plus127 [] = { 0x02,0x01,0x7f };
    static const guint8 plus128 [] = { 0x02,0x02,0x00,0x80 };
    static const guint8 plus74565 [] = { 0x02,0x03,0x01,0x23,0x45 };
    static const guint8 plus19088743 [] = { 0x02,0x04, 0x01,0x23,0x45,0x67 };
    static const guint8 minus1 [] = { 0x02,0x01,0xff };
    static const guint8 minus128 [] = { 0x02,0x01,0x80 };
    static const guint8 minus1555 [] = { 0x02,0x02,0xf9,0xed };
    static const guint8 minus32768 [] = { 0x02,0x02,0x80,0x00 };
    static const guint8 minus8388608 [] = { 0x02,0x03,0x80,0x00,0x00 };
    static const guint8 minus134217728 [] = { 0x02,0x04,0xf8,0x00,0x00,0x00 };
    static const struct asn1_int_test {
        gboolean ok;
        gint32 value;
        const guint8* data;
        gsize len;
    } number [] = {
        {FALSE, 0, truncated, 0},
#define ERR(name) {FALSE, 0, name, sizeof(name)}
        ERR(notint),
        ERR(indef),
        ERR(truncated),
        ERR(toolong),
        ERR(toolong2),
        ERR(lentoolong),
#define PLUS(n) {TRUE, n, plus##n, sizeof(plus##n)}
        PLUS(0),
        PLUS(1),
        PLUS(127),
        PLUS(128),
        PLUS(74565),
        PLUS(19088743),
#define MINUS(n) {TRUE, -(n), minus##n, sizeof(minus##n)}
        MINUS(1),
        MINUS(128),
        MINUS(1555),
        MINUS(32768),
        MINUS(8388608),
        MINUS(134217728)
    };

    guint i;
    for (i=0; i<G_N_ELEMENTS(number); i++) {
        const struct asn1_int_test* subtest = number + i;
        FoilInput* in1 = foil_input_mem_new_static(subtest->data, subtest->len);
        FoilInput* in2 = foil_input_mem_new_static(subtest->data, subtest->len);
        FoilParsePos pos, pos1;
        gint32 value;
        if (subtest->ok) {
            GBytes* enc1 = foil_asn1_encode_integer_value(subtest->value);
            /* The same thing but using foil_asn1_encode_integer_bytes */
            GBytes* enc2;
            FoilBytes bytes;
            FoilOutput* out = foil_output_mem_new(NULL);
            bytes.val = subtest->data + 2;
            bytes.len = subtest->len - 2;
            foil_asn1_encode_integer_bytes(out, &bytes);
            enc2 = foil_output_free_to_bytes(out);
            TEST_DEBUG_HEXDUMP_BYTES(enc1);
            g_assert(test_bytes_equal(enc1, subtest->data, subtest->len));
            TEST_DEBUG_HEXDUMP_BYTES(enc2);
            g_assert(test_bytes_equal(enc2, subtest->data, subtest->len));
            g_bytes_unref(enc1);
            g_bytes_unref(enc2);
        }
        pos.ptr = subtest->data;
        pos.end = pos.ptr + subtest->len;
        pos1 = pos;
        TEST_DEBUG_HEXDUMP(subtest->data, subtest->len);
        g_assert(foil_asn1_parse_int32(&pos, &value) == subtest->ok);
        g_assert(foil_asn1_parse_int32(&pos1, NULL) == subtest->ok);
        g_assert(!subtest->ok || value == subtest->value);
        g_assert(foil_asn1_read_int32(in1, &value) == subtest->ok);
        if (subtest->ok) {
            g_assert(value == subtest->value);
            g_assert(!foil_input_has_available(in1, 1));
        }
        g_assert(foil_asn1_read_int32(in2, NULL) == subtest->ok);
        g_assert(!subtest->ok || !foil_input_has_available(in2, 1));
        foil_input_unref(in1);
        foil_input_unref(in2);
    }
}

#define TEST_(name) "/basic/" name

int main(int argc, char* argv[])
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func(TEST_("bytes"), test_bytes);
    g_test_add_func(TEST_("random"), test_random);
    g_test_add_func(TEST_("skip"), test_skip);
    g_test_add_func(TEST_("format_header"), test_format_header);
    g_test_add_func(TEST_("parse_headers"), test_parse_headers);
    g_test_add_func(TEST_("base64"), test_base64);
    g_test_add_func(TEST_("memmem"), test_memmem);
    g_test_add_func(TEST_("asn1/Len"), test_asn1_len);
    g_test_add_func(TEST_("asn1/Seq"), test_asn1_seq);
    g_test_add_func(TEST_("asn1/BitString"), test_asn1_bit_string);
    g_test_add_func(TEST_("asn1/OctetString"), test_asn1_octet_string);
    g_test_add_func(TEST_("asn1/OctetString2"), test_asn1_octet_string2);
    g_test_add_func(TEST_("asn1/IA5String"), test_asn1_ia5_string);
    g_test_add_func(TEST_("asn1/Integer"), test_asn1_integer);
    return test_run();
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
