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
#include "foil_cipher.h"

#include <stdlib.h>
#include <ctype.h>

#define DATA_DIR "data/"

#define TEST_COUNT      (0x01)
#define TEST_KEY        (0x02)
#define TEST_KEY1       (TEST_KEY << 0) /* 0x02 */
#define TEST_KEY2       (TEST_KEY << 1) /* 0x04 */
#define TEST_KEY3       (TEST_KEY << 2) /* 0x08 */
#define TEST_IV         (0x10)
#define TEST_PLAINTEXT  (0x20)
#define TEST_CIPHERTEXT (0x40)
#define TEST_ALL        (0x7f)

#define KEY_COUNT (3)

typedef enum des_test_section {
    TEST_SECTION_NONE = -1,
    TEST_SECTION_ENCRYPT,
    TEST_SECTION_DECRYPT,
    TEST_SECTION_COUNT
} TestSection;

typedef struct des_test {
    int count;
    GBytes* key[KEY_COUNT];
    GBytes* iv;
    GBytes* plaintext;
    GBytes* ciphertext;
} Test;

typedef struct des_tests {
    GSList* tests[TEST_SECTION_COUNT];
} Tests;

static
void
test_delete(
    gpointer data)
{
    Test* test = data;
    int i;
    for (i = 0; i < KEY_COUNT; i++) g_bytes_unref(test->key[i]);
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
    static const char IV[] = "IV=";
    static const char PLAINTEXT[] = "PLAINTEXT=";
    static const char CIPHERTEXT[] = "CIPHERTEXT=";
    static const char* KEY[] =  { "KEY1=", "KEY2=", "KEY3=" };
    if (strstr(line, COUNT) == line) {
        test->count = atoi(line + (G_N_ELEMENTS(COUNT)-1));
        return TEST_COUNT;
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
    } else {
        int i;
        for (i = 0; i < 3; i++) {
            if (strstr(line, KEY[i]) == line) {
                GBytes* data = test_line_to_bytes(line + strlen(KEY[i]));
                if (data) {
                    if (test->key[i]) g_bytes_unref(test->key[i]);
                    test->key[i] = data;
                    return (TEST_KEY << i);
                }
            }
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
test_cavp_des_run(
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
void
test_cavp_des(
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
    for (l = tests.tests[TEST_SECTION_ENCRYPT]; l; l = l->next) {
        const Test* test = l->data;
        FoilKey* key = foil_key_des_new_from_bytes(test->iv, test->key[0],
            test->key[1], test->key[2]);
        test_cavp_des_run(FOIL_CIPHER_DES_CBC_ENCRYPT, key,
            test->count, test->plaintext, test->ciphertext);
        foil_key_unref(key);
    }

    /* Run the decryption tests */
    for (l = tests.tests[TEST_SECTION_DECRYPT]; l; l = l->next) {
        const Test* test = l->data;
        FoilKey* key = foil_key_des_new_from_bytes(test->iv, test->key[0],
            test->key[1], test->key[2]);
        test_cavp_des_run(FOIL_CIPHER_DES_CBC_DECRYPT, key,
            test->count, test->ciphertext, test->plaintext);
        foil_key_unref(key);
    }

    for (i = 0; i < TEST_SECTION_COUNT; i++) {
        g_slist_free_full(tests.tests[i], test_delete);
    }
    g_free(path);
}

#define TEST_PREFIX "/cavp_des/"

/* https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#TDES */
static const char* tests [] = {
    /* https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/des/tdesmmt.zip */
    "TCBCMMT2.rsp",
    "TCBCMMT3.rsp"
};

int main(int argc, char* argv[])
{
    guint i;
    g_test_init(&argc, &argv, NULL);
    for (i = 0; i < G_N_ELEMENTS(tests); i++) {
        char* name = g_strconcat(TEST_PREFIX, tests[i], NULL);
        g_test_add_data_func(name, tests[i], test_cavp_des);
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
