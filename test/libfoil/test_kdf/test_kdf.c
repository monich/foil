/*
 * Copyright (C) 2022 by Slava Monich
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

#include "foil_kdf.h"
#include "foil_digest.h"
#include "foil_random.h"

typedef struct test_kdf {
    const char* name;
    GType (*digest_type)(void);
    const char* pw;
    gssize pwlen;
    FoilBytes salt;
    guint iter;
    guint dlen;
    FoilBytes output;
} TestKdf;

static
void
test_null(
    void)
{
    FoilBytes salt;

    salt.val = (void*)&salt;
    salt.len = sizeof(salt);
    g_assert(!foil_kdf_pbkdf2((GType)0, NULL, 0, NULL, 0, 0));
    /* Not a digest type: */
    g_assert(!foil_kdf_pbkdf2(FOIL_RANDOM_DEFAULT, NULL, 0, &salt, 1, 0));
    /* No iterations */
    g_assert(!foil_kdf_pbkdf2(FOIL_DIGEST_SHA1, NULL, 0, &salt, 0, 0));
    /* NULL password */
    g_assert(!foil_kdf_pbkdf2(FOIL_DIGEST_SHA1, NULL, -1, &salt, 1, 0));
}

static
void
test_kdf(
    gconstpointer param)
{
    const TestKdf* test = param;
    GBytes* result = foil_kdf_pbkdf2(test->digest_type(), test->pw,
        test->pwlen, &test->salt, test->iter, test->dlen);
    gsize size = 0;
    gconstpointer data;

    g_assert(result);
    data = g_bytes_get_data(result, &size);

    g_assert_cmpuint(size, == ,test->output.len);
    g_assert(!memcmp(data, test->output.val, size));
    g_bytes_unref(result);
}

/* Test descriptors */

#define TEST_(name) "/kdf/" name

/*
 * RFC 6070
 * PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2) Test Vectors
 */

static guint8 rfc6070_001_output[] = {
    0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
    0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
    0x2f, 0xe0, 0x37, 0xa6
};

static guint8 rfc6070_002_output[] = {
    0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
    0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
    0xd8, 0xde, 0x89, 0x57
};

static guint8 rfc6070_003_output[] = {
    0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
    0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
    0x65, 0xa4, 0x29, 0xc1
};

#ifdef TEST_16777216
/* This one takes too long to run it on every build (although it succeeds) */
static guint8 rfc6070_004_output[] = {
    0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4,
    0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2, 0x15, 0x8c,
    0x26, 0x34, 0xe9, 0x84
};
#endif

static guint8 rfc6070_005_output[] = {
    0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
    0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
    0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
    0x38
};

static guint8 rfc6070_006_output[] = {
    0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d,
    0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3
};

static guint8 collision_salt[] = {
    0xa0, 0x09, 0xc1, 0xa4, 0x85, 0x91, 0x2c, 0x6a,
    0xe6, 0x30, 0xd3, 0xe7, 0x44, 0x24, 0x0b, 0x04
};

static guint8 collision_output[] = {
    0x17, 0xeb, 0x40, 0x14, 0xc8, 0xc4, 0x61, 0xc3,
    0x00, 0xe9, 0xb6, 0x15, 0x18, 0xb9, 0xa1, 0x8b
};

static const TestKdf tests[] = {
    {
        TEST_("RFC6070/001"),
        foil_impl_digest_sha1_get_type,
        "password", 8,
        { (const guint8*) "salt", 4 },
        1,
        20,
        { TEST_ARRAY_AND_SIZE(rfc6070_001_output) }
    },{
        TEST_("RFC6070/002"),
        foil_impl_digest_sha1_get_type,
        "password", -1, /* Do strlen() on the password */
        { (const guint8*) "salt", 4 },
        2,
        0, /* Use the default (digest size) */
        { TEST_ARRAY_AND_SIZE(rfc6070_002_output) }
    },{
        TEST_("RFC6070/003"),
        foil_impl_digest_sha1_get_type,
        "password", 8,
        { (const guint8*) "salt", 4 },
        4096,
        20,
        { TEST_ARRAY_AND_SIZE(rfc6070_003_output) }
#ifdef TEST_16777216
    },{ /* This one takes too long to run it on every build */
        TEST_("RFC6070/004"),
        foil_impl_digest_sha1_get_type,
        "password", 8,
        { (const guint8*) "salt", 4 },
        16777216,
        20,
        { TEST_ARRAY_AND_SIZE(rfc6070_004_output) }
#endif
    },{
        TEST_("RFC6070/005"),
        foil_impl_digest_sha1_get_type,
        "passwordPASSWORDpassword", 24,
        { (const guint8*) "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36 },
        4096,
        25,
        { TEST_ARRAY_AND_SIZE(rfc6070_005_output) }
    },{
        TEST_("RFC6070/006"),
        foil_impl_digest_sha1_get_type,
        "pass\0word", 9,
        { (const guint8*) "sa\0lt", 5 },
        4096,
        16,
        { TEST_ARRAY_AND_SIZE(rfc6070_006_output) }
    },{ /* Collision example from Wikipedia */
        TEST_("collision/1"),
        foil_impl_digest_sha1_get_type,
        "plnlrtfpijpuhqylxbgqiiyipieyxvfsavzgxbbcfusqkozwpngsyejqlmjsytrmd", -1,
        { TEST_ARRAY_AND_SIZE(collision_salt) },
        1000,
        16,
        { TEST_ARRAY_AND_SIZE(collision_output) }
    },{
        TEST_("collision/2"),
        foil_impl_digest_sha1_get_type,
        "eBkXQTfuBqp'cTcar&g*", -1,
        { TEST_ARRAY_AND_SIZE(collision_salt) },
        1000,
        16,
        { TEST_ARRAY_AND_SIZE(collision_output) }
    }
};

int main(int argc, char* argv[])
{
    guint i;

    g_test_init(&argc, &argv, NULL);
    g_test_add_func(TEST_("null"), test_null);
    for (i = 0; i < G_N_ELEMENTS(tests); i++) {
        g_test_add_data_func(tests[i].name, tests + i, test_kdf);
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
