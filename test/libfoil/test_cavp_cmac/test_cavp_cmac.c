/*
 * Copyright (C) 2019 by Slava Monich
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

#include "foil_key_des.h"
#include "foil_cmac.h"
#include "foil_cipher.h"
#include "foil_output.h"

#include <gutil_misc.h>

#include <stdlib.h>
#include <ctype.h>

#define DATA_DIR "data/"

#define FIELD_COUNT     (0x0001)
#define FIELD_KLEN      (0x0002)
#define FIELD_MLEN      (0x0004)
#define FIELD_TLEN      (0x0008)
#define FIELD_KEY       (0x0010)
#define FIELD_KEY1      (0x0020)
#define FIELD_KEY2      (0x0040)
#define FIELD_KEY3      (0x0080)
#define FIELD_MSG       (0x0100)
#define FIELD_MAC       (0x0200)
#define FIELD_RESULT    (0x0400)
#define FIELDS_GEN_AES  (0x031f)
#define FIELDS_GEN_DES  (0x03ef)
#define FIELDS_VER_AES  (FIELDS_GEN_AES | FIELD_RESULT)
#define FIELDS_VER_DES  (FIELDS_GEN_DES | FIELD_RESULT)

typedef struct cmac_test_case {
    int Count;
    int Klen;
    int Mlen;
    int Tlen;
    GBytes* Key;
    GBytes* Key1;
    GBytes* Key2;
    GBytes* Key3;
    GBytes* Msg;
    GBytes* Mac;
    gboolean Result; /* Ignored for Gen tests */
} TestCase;

typedef struct cmac_test Test;
struct cmac_test {
    const char* file;
    int bs;
    int mask;
    FoilKey* (*make_key)(const Test* test, const TestCase* tc);
    GType (*cipher_type)(void);
};

static
void
test_delete(
    gpointer data)
{
    TestCase* test = data;
    if (test->Key) {
        g_bytes_unref(test->Key);
    }
    if (test->Key1) {
        g_bytes_unref(test->Key1);
        g_bytes_unref(test->Key2);
        g_bytes_unref(test->Key3);
    }
    g_bytes_unref(test->Msg);
    g_bytes_unref(test->Mac);
    g_free(test);
}

static
const char*
test_read_line(
    FILE* f,
    GString* str)
{
    int c;

    g_string_truncate(str, 0);
    while ((c = fgetc(f)) != EOF) {
        if (c == '\r' || c == '\n') {
            while ((c = fgetc(f)) != EOF && (c == '\r' || c == '\n'));
            if (c != EOF) ungetc(c, f);
            break;
        }
        if (!isspace(c)) g_string_append_c(str, c);
    }
    return (str->len || c != EOF) ? str->str : NULL;
}

static
GBytes*
test_bytes_truncate(
    GBytes* bytes,
    gsize maxsize)
{
    if (bytes) {
        GBytes* truncated = g_bytes_new_from_bytes(bytes, 0, maxsize);

        g_bytes_unref(bytes);
        return truncated;
    } else {
        return NULL;
    }
}

static
int
test_parse_line(
    const char* line,
    TestCase* test)
{
    /* Spaces are removed by test_read_line() */
    static const char COUNT[] = "Count=";
    static const char KLEN[] = "Klen=";
    static const char MLEN[] = "Mlen=";
    static const char TLEN[] = "Tlen=";
    static const char KEY[] = "Key=";
    static const char KEY1[] = "Key1=";
    static const char KEY2[] = "Key2=";
    static const char KEY3[] = "Key3=";
    static const char MSG[] = "Msg=";
    static const char MAC[] = "Mac=";
    static const char RESULT[] = "Result=";

    if (strstr(line, COUNT) == line) {
        const char* val = line + (G_N_ELEMENTS(COUNT) - 1);

        g_assert(gutil_parse_int(val, 10, &test->Count));
        return FIELD_COUNT;
    } else if (strstr(line, KLEN) == line) {
        const char* val = line + (G_N_ELEMENTS(KLEN) - 1);

        g_assert(gutil_parse_int(val, 10, &test->Klen));
        g_assert(test->Klen > 0);
        return FIELD_KLEN;
    } else if (strstr(line, MLEN) == line) {
        const char* val = line + (G_N_ELEMENTS(MLEN) - 1);

        g_assert(gutil_parse_int(val, 10, &test->Mlen));
        g_assert(test->Mlen >= 0);
        return FIELD_MLEN;
    } else if (strstr(line, TLEN) == line) {
        const char* val = line + (G_N_ELEMENTS(TLEN) - 1);

        g_assert(gutil_parse_int(val, 10, &test->Tlen));
        g_assert(test->Tlen > 0);
        return FIELD_TLEN;
    } else if (strstr(line, KEY) == line) {
        const char* val = line + (G_N_ELEMENTS(KEY) - 1);
        GBytes* bytes = gutil_hex2bytes(val, -1);

        g_assert(bytes);
        g_assert(!test->Key);
        test->Key = bytes;
        return FIELD_KEY;
    } else if (strstr(line, KEY1) == line) {
        const char* val = line + (G_N_ELEMENTS(KEY1) - 1);
        GBytes* bytes = gutil_hex2bytes(val, -1);

        g_assert(bytes);
        g_assert(!test->Key1);
        test->Key1 = bytes;
        return FIELD_KEY1;
    } else if (strstr(line, KEY2) == line) {
        const char* val = line + (G_N_ELEMENTS(KEY2) - 1);
        GBytes* bytes = gutil_hex2bytes(val, -1);

        g_assert(bytes);
        g_assert(!test->Key2);
        test->Key2 = bytes;
        return FIELD_KEY2;
    } else if (strstr(line, KEY3) == line) {
        const char* val = line + (G_N_ELEMENTS(KEY3) - 1);
        GBytes* bytes = gutil_hex2bytes(val, -1);

        g_assert(bytes);
        g_assert(!test->Key3);
        test->Key3 = bytes;
        return FIELD_KEY3;
    } else if (strstr(line, MSG) == line) {
        const char* val = line + (G_N_ELEMENTS(MSG) - 1);
        GBytes* bytes = gutil_hex2bytes(val, -1);

        g_assert(bytes);
        g_assert(!test->Msg);
        test->Msg = bytes;
        return FIELD_MSG;
    } else if (strstr(line, MAC) == line) {
        const char* val = line + (G_N_ELEMENTS(MAC) - 1);
        GBytes* bytes = gutil_hex2bytes(val, -1);

        g_assert(bytes);
        g_assert(!test->Mac);
        test->Mac = bytes;
        return FIELD_MAC;
    } else if (strstr(line, RESULT) == line) {
        const char* val = line + (G_N_ELEMENTS(RESULT) - 1);

        g_assert(val[0] == 'P' || val[0] == 'F');
        test->Result = (val[0] == 'P');
        return FIELD_RESULT;
    } else {
        /* Skip this one */
        return 0;
    }
}

static
GSList*
test_parse_file(
    const char* fname,
    int fields)
{
    FILE* f = fopen(fname, "rt");
    TestCase test;
    int flags = 0;
    const char* line;
    GString* str = g_string_new(NULL);
    GSList* tests = NULL;

    GDEBUG("Reading %s", fname);
    g_assert(f);
    memset(&test, 0, sizeof(test));
    while ((line = test_read_line(f, str)) != NULL) {
        flags |= test_parse_line(line, &test);
        if ((flags & fields) == fields) {
            test.Key = test_bytes_truncate(test.Key, test.Klen);
            test.Key1 = test_bytes_truncate(test.Key1, FOIL_DES_KEY_SIZE);
            test.Key2 = test_bytes_truncate(test.Key2, FOIL_DES_KEY_SIZE);
            test.Key3 = test_bytes_truncate(test.Key3, FOIL_DES_KEY_SIZE);
            test.Msg = test_bytes_truncate(test.Msg, test.Mlen);
            test.Mac = test_bytes_truncate(test.Mac, test.Tlen);
            tests = g_slist_append(tests, g_memdup(&test, sizeof(test)));
            memset(&test, 0, sizeof(test));
            flags = 0;
        }
    }
    g_string_free(str, TRUE);
    fclose(f);
    return tests;
}

static
FoilKey*
test_aes_key(
    const Test* test,
    const TestCase* tc)
{
    gsize key_size;
    const guint8* key_bytes = g_bytes_get_data(tc->Key, &key_size);
    gsize total = test->bs + key_size;
    guint8* full_key = g_malloc0(total);
    FoilKey* key;

    memcpy(full_key, key_bytes, key_size);
    key = foil_key_new_from_data(FOIL_TYPE_KEY_AES, full_key, total);
    g_free(full_key);
    g_assert(key);
    return key;
}

static
FoilKey*
test_des_key(
    const Test* test,
    const TestCase* tc)
{
    return foil_key_des_new_from_bytes(NULL, tc->Key1, tc->Key2, tc->Key3);
}

static
GBytes*
test_cmac(
    const Test* test,
    const TestCase* tc)
{
    FoilKey* key = test->make_key(test, tc);
    FoilCipher* cipher = foil_cipher_new(test->cipher_type(), key);
    FoilCmac* cmac = foil_cmac_new(cipher);
    const guint8* msg = g_bytes_get_data(tc->Msg, NULL);
    GBytes* mac;
    GBytes* mac2;
    int i, n;

    GDEBUG("[%d] Msg:", tc->Count);
    TEST_DEBUG_HEXDUMP_BYTES(tc->Msg);
    foil_cmac_update(cmac, msg, tc->Mlen);
    mac = test_bytes_truncate(foil_cmac_free_to_bytes(cmac), tc->Tlen);
    GDEBUG("[%d] CMAC:", tc->Count);
    TEST_DEBUG_HEXDUMP_BYTES(mac);

    /* Once again in multiple chunks, the result must be the same */
    cmac = foil_cmac_new(cipher);
    for (i = 0, n = 1; i < tc->Mlen; i += n) {
        n += 3;
        if (i + n > tc->Mlen) n = tc->Mlen - i;
        foil_cmac_update(cmac, msg + i, n);
    }
    mac2 = test_bytes_truncate(foil_cmac_free_to_bytes(cmac), tc->Tlen);
    if (mac2) {
        g_assert(g_bytes_equal(mac, mac2));
        g_bytes_unref(mac2);
    } else {
        g_assert(!mac);
    }

    foil_key_unref(key);
    foil_cipher_unref(cipher);
    return mac;
}

static
void
test_cavp_cmac_gen(
    gconstpointer param)
{
    const Test* test = param;
    char* path = g_strconcat(DATA_DIR, test->file, NULL);
    GSList* tests = test_parse_file(path, test->mask);
    GSList* l;

    g_assert(tests);
    for (l = tests; l; l = l->next) {
        const TestCase* tc = l->data;
        GBytes* mac = test_cmac(test, tc);

        g_assert(g_bytes_equal(mac, tc->Mac));
        g_bytes_unref(mac);
    }

    g_slist_free_full(tests, test_delete);
    g_free(path);
}

static
void
test_cavp_cmac_ver(
    gconstpointer param)
{
    const Test* test = param;
    char* path = g_strconcat(DATA_DIR, test->file, NULL);
    GSList* tests = test_parse_file(path, test->mask);
    GSList* l;

    g_assert(tests);
    for (l = tests; l; l = l->next) {
        const TestCase* tc = l->data;
        GBytes* mac = test_cmac(test, tc);

        if (mac) {
            g_assert(g_bytes_equal(mac, tc->Mac) == tc->Result);
            g_bytes_unref(mac);
        } else {
            g_assert(!tc->Result);
        }
    }

    g_slist_free_full(tests, test_delete);
    g_free(path);
}

#define TEST_PREFIX "/cavp_cmac/"

#define TEST_GEN_AES(file) TEST_AES(file, FIELDS_GEN_AES)
#define TEST_VER_AES(file) TEST_AES(file, FIELDS_VER_AES)
#define TEST_AES(file,mask) file, 16, mask, test_aes_key, \
        foil_impl_cipher_aes_cbc_encrypt_get_type

#define TEST_GEN_DES(file) TEST_DES(file, FIELDS_GEN_DES)
#define TEST_VER_DES(file) TEST_DES(file, FIELDS_VER_DES)
#define TEST_DES(file,mask) file, 8, mask, test_des_key, \
        foil_impl_cipher_des_cbc_encrypt_get_type

/* https://csrc.nist.rip/groups/STM/cavp/documents/mac/cmactestvectors.zip */
static Test tests_gen [] = {
    { TEST_GEN_AES("CMACGenAES128.rsp") },
    { TEST_GEN_AES("CMACGenAES192.rsp") },
    { TEST_GEN_AES("CMACGenAES256.rsp") },
    { TEST_GEN_DES("CMACGenTDES2.rsp") },
    { TEST_GEN_DES("CMACGenTDES3.rsp") }
};

static Test tests_ver [] = {
    { TEST_VER_AES("CMACVerAES128.rsp") },
    { TEST_VER_AES("CMACVerAES192.rsp") },
    { TEST_VER_AES("CMACVerAES256.rsp") },
    { TEST_VER_DES("CMACVerTDES2.rsp") },
    { TEST_VER_DES("CMACVerTDES3.rsp") }
};

int main(int argc, char* argv[])
{
    guint i;

    g_test_init(&argc, &argv, NULL);
    for (i = 0; i < G_N_ELEMENTS(tests_gen); i++) {
        const Test* test = tests_gen + i;

        char* name = g_strconcat(TEST_PREFIX, test->file, NULL);
        g_test_add_data_func(name, test, test_cavp_cmac_gen);
        g_free(name);
    }
    for (i = 0; i < G_N_ELEMENTS(tests_ver); i++) {
        const Test* test = tests_ver + i;

        char* name = g_strconcat(TEST_PREFIX, test->file, NULL);
        g_test_add_data_func(name, test, test_cavp_cmac_ver);
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
