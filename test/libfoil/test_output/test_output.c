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

#include "foil_output.h"
#include "foil_digest.h"

#include <glib/gstdio.h>

static
void
test_output_null(
    void)
{
    guint8 buf[1];
    FoilOutput* out = foil_output_mem_new(NULL);
    GBytes* empty = g_bytes_new_static(buf, 0);

    /* Test resistance to NULL and all kinds of invalid output */
    foil_output_unref(foil_output_mem_new(NULL));
    foil_output_close(NULL);
    foil_output_unref(NULL);
    g_assert(!foil_output_ref(NULL));
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
    g_assert(buf->len == sizeof(test1234));
    g_assert(foil_output_bytes_written(out) == sizeof(test1234));
    g_assert(foil_output_bytes_written(out_digest) == sizeof(test1234));
    g_assert(!memcmp(buf->data, test1234, sizeof(test1234)));

    /* Write has to fail if we close the underlying output stream */
    foil_output_close(out);
    g_assert(foil_output_write(out_digest, test1234, 1) < 0);

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

#define TEST_(name) "/output/" name

int main(int argc, char* argv[])
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func(TEST_("null"), test_output_null);
    g_test_add_func(TEST_("basic"), test_output_basic);
    g_test_add_func(TEST_("digest1"), test_output_digest1);
    g_test_add_func(TEST_("digest2"), test_output_digest2);
    g_test_add_func(TEST_("path"), test_output_path);
    g_test_add_func(TEST_("file"), test_output_file);
    g_test_add_func(TEST_("base64"), test_output_base64);
    return test_run();
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
