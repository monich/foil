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
#include "foil_cipher.h"

#include <stdlib.h>
#include <ctype.h>

#define DATA_DIR "data/"

#define TEST_COUNT      (0x01)
#define TEST_KEY        (0x02)
#define TEST_IV         (0x04)
#define TEST_PLAINTEXT  (0x08)
#define TEST_CIPHERTEXT (0x10)
#define TEST_ALL        (0x1f)

typedef enum aes_test_section {
    TEST_SECTION_NONE = -1,
    TEST_SECTION_ENCRYPT,
    TEST_SECTION_DECRYPT,
    TEST_SECTION_COUNT
} TestSection;

typedef struct aes_test {
    int count;
    GBytes* key;
    GBytes* iv;
    GBytes* plaintext;
    GBytes* ciphertext;
} Test;

typedef struct aes_tests {
    GSList* tests[TEST_SECTION_COUNT];
} Tests;

static
void
test_delete(
    gpointer data)
{
    Test* test = data;
    g_bytes_unref(test->key);
    g_bytes_unref(test->iv);
    g_bytes_unref(test->plaintext);
    g_bytes_unref(test->ciphertext);
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
test_line_to_bytes(
    const char* line)
{
    const int n = strlen(line)/2;
    if (n > 0) {
        int i;
        guint8* data = g_malloc(n);
        char hex[3];
        hex[2] = 0;
        for (i=0; i<n; i++) {
            char* endptr = NULL;
            hex[0] = *line++;
            hex[1] = *line++;
            data[i] = (guint8)strtol(hex, &endptr, 16);
            if (*endptr) {
                g_free(data);
                return NULL;
            }
        }
        return g_bytes_new_take(data, n);
    }
    return NULL;
}

static
int
test_parse_line(
    const char* line,
    Test* test)
{
    static const char COUNT[] = "COUNT=";
    static const char KEY[] = "KEY=";
    static const char IV[] = "IV=";
    static const char PLAINTEXT[] = "PLAINTEXT=";
    static const char CIPHERTEXT[] = "CIPHERTEXT=";
    if (strstr(line, COUNT) == line) {
        test->count = atoi(line + (G_N_ELEMENTS(COUNT)-1));
        return TEST_COUNT;
    } else if (strstr(line, KEY) == line) {
        GBytes* data = test_line_to_bytes(line + (G_N_ELEMENTS(KEY)-1));
        if (data) {
            if (test->key) g_bytes_unref(test->key);
            test->key = data;
            return TEST_KEY;
        }
    } else if (strstr(line, IV) == line) {
        GBytes* data = test_line_to_bytes(line + (G_N_ELEMENTS(IV)-1));
        if (data) {
            if (test->iv) g_bytes_unref(test->iv);
            test->iv = data;
            return TEST_IV;
        }
    } else if (strstr(line, PLAINTEXT) == line) {
        GBytes* data = test_line_to_bytes(line+(G_N_ELEMENTS(PLAINTEXT)-1));
        if (data) {
            if (test->plaintext) g_bytes_unref(test->plaintext);
            test->plaintext = data;
            return TEST_PLAINTEXT;
        }
    } else if (strstr(line, CIPHERTEXT) == line) {
        GBytes* data = test_line_to_bytes(line + (G_N_ELEMENTS(CIPHERTEXT)-1));
        if (data) {
            if (test->ciphertext) g_bytes_unref(test->ciphertext);
            test->ciphertext = data;
            return TEST_CIPHERTEXT;
        }
    }
    return 0;
}

static
gboolean
test_parse_file(
    const char* fname,
    Tests* tests)
{
    FILE* f = fopen(fname, "rt");
    if (f) {
        int flags = 0;
        TestSection section = TEST_SECTION_NONE;
        Test test;
        const char* line;
        GString* str = g_string_new(NULL);
        GDEBUG("Reading %s", fname);
        memset(&test, 0, sizeof(test));
        while ((line = test_read_line(f, str)) != NULL) {
            if (!strcmp(line, "[ENCRYPT]")) {
                section = TEST_SECTION_ENCRYPT;
                flags = 0;
            } else if (!strcmp(line, "[DECRYPT]")) {
                section = TEST_SECTION_DECRYPT;
                flags = 0;
            } else if (section != TEST_SECTION_NONE) {
                flags |= test_parse_line(line, &test);
                if ((flags & TEST_ALL) == TEST_ALL) {
                    Test* t = g_new0(Test, 1);
                    *t = test;
                    tests->tests[section] = g_slist_append(
                        tests->tests[section], t);
                    flags = 0;
                    memset(&test, 0, sizeof(test));
                }
            }
        }
        g_string_free(str, TRUE);
        fclose(f);
        return TRUE;
    } else {
        GERR("Failed to open %s", fname);
        return FALSE;
    }
}

static
void
test_cavp_aes_run(
    GType cipher_type,
    FoilKey* key,
    int count,
    GBytes* in,
    GBytes* expected)
{
    GBytes* out = foil_cipher_bytes(cipher_type, key, in);
    GDEBUG("[%d] Input:", count);
    TEST_DEBUG_HEXDUMP_BYTES(in);
    GDEBUG("[%d] Output:", count);
    TEST_DEBUG_HEXDUMP_BYTES(out);
    g_assert(g_bytes_equal(out, expected));
    g_bytes_unref(out);
}

static
FoilKey*
test_cavp_aes_key(
    const Test* test)
{
    GBytes* key_bytes = test_bytes_concat(test->key, test->iv);
    GType key_type;
    FoilKey* key;
    switch (g_bytes_get_size(test->key)*8) {
    case 128: key_type = FOIL_KEY_AES128; break;
    case 192: key_type = FOIL_KEY_AES192; break;
    case 256: key_type = FOIL_KEY_AES256; break;
    default:  key_type = 0; break;
    }
    key = foil_key_new_from_bytes(key_type, key_bytes);
    g_assert(key);
    g_bytes_unref(key_bytes);
    return key;
}
    
static
void
test_cavp_aes(
    gconstpointer param)
{
    const char* file = param;
    char* path = g_strconcat(DATA_DIR, file, NULL);
    Tests tests;
    GSList* l;
    int i;

    /* Parse the file */
    memset(&tests, 0, sizeof(tests));
    g_assert(test_parse_file(path, &tests));

    /* Run the encryption tests */
    for (l=tests.tests[TEST_SECTION_ENCRYPT]; l; l=l->next) {
        const Test* test = l->data;
        FoilKey* key = test_cavp_aes_key(test);
        test_cavp_aes_run(FOIL_CIPHER_AES_CBC_ENCRYPT, key,
            test->count, test->plaintext, test->ciphertext);
        foil_key_unref(key);
    }

    /* Run the decryption tests */
    for (l=tests.tests[TEST_SECTION_DECRYPT]; l; l=l->next) {
        const Test* test = l->data;
        FoilKey* key = test_cavp_aes_key(test);
        test_cavp_aes_run(FOIL_CIPHER_AES_CBC_DECRYPT, key,
            test->count, test->ciphertext, test->plaintext);
        foil_key_unref(key);
    }

    for (i=0; i<TEST_SECTION_COUNT; i++) {
        g_slist_free_full(tests.tests[i], test_delete);
    }
    g_free(path);
}

#define TEST_PREFIX "/cavp_aes/"

/* http://csrc.nist.gov/groups/STM/cavp/ */
static const char* tests [] = {
    /* http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip */
    "CBCGFSbox128.rsp",
    "CBCGFSbox192.rsp",
    "CBCGFSbox256.rsp",
    "CBCKeySbox128.rsp",
    "CBCKeySbox192.rsp",
    "CBCKeySbox256.rsp",
    "CBCVarKey128.rsp",
    "CBCVarKey192.rsp",
    "CBCVarKey256.rsp",
    "CBCVarTxt128.rsp",
    "CBCVarTxt192.rsp",
    "CBCVarTxt256.rsp",
    /* http://csrc.nist.gov/groups/STM/cavp/documents/aes/aesmmt.zip */
    "CBCMMT128.rsp",
    "CBCMMT192.rsp",
    "CBCMMT256.rsp",
    /* http://tools.ietf.org/rfc/rfc3602.txt */
    "rfc3602.rsp"
};

int main(int argc, char* argv[])
{
    guint i;
    g_test_init(&argc, &argv, NULL);
    for (i = 0; i < G_N_ELEMENTS(tests); i++) {
        char* name = g_strconcat(TEST_PREFIX, tests[i], NULL);
        g_test_add_data_func(name, tests[i], test_cavp_aes);
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
