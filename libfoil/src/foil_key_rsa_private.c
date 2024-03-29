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

#include "foil_key_rsa_private.h"
#include "foil_key_rsa_public.h"
#include "foil_key_aes.h"
#include "foil_kdf.h"
#include "foil_random.h"
#include "foil_cipher.h"
#include "foil_digest.h"
#include "foil_hmac.h"
#include "foil_input.h"
#include "foil_output.h"
#include "foil_pool.h"
#include "foil_util_p.h"
#include "foil_asn1.h"
#include "foil_oid.h"
#include "foil_bcrypt.h"

#include <gutil_strv.h>
#include <gutil_misc.h>

/* Logging */
#define GLOG_MODULE_NAME foil_log_key
#include "foil_log_p.h"

typedef struct foil_key_rsa_openssh_cipher {
    const char* name;
    guint blocklen;
    guint keysize; /* key_len + iv */
    GType (*key)(void);
    GType (*encrypt)(void);
    GType (*decrypt)(void);
} FoilKeyRsaOpensshCipher;

G_DEFINE_ABSTRACT_TYPE(FoilKeyRsaPrivate, foil_key_rsa_private,
        FOIL_TYPE_PRIVATE_KEY);
#define FOIL_KEY_RSA_PRIVATE_CAST_TO_KEY(obj) &((obj)->super.super)

#define FOIL_KEY_RSA_PRIVATE_CLEAR_BYTES(bytes) \
    memset((void*)((bytes)->val), 0, (bytes)->len);

#define foil_key_rsa_private_write_data(out,data) \
    foil_output_write(out, (data)->val, (data)->len)
#define foil_key_rsa_private_write_all(out,data) \
    foil_output_write_all(out, (data)->val, (data)->len)

#define OPENSSH_PLAINTEXT_ALIGN (8)
#define OPENSSH_SALT_LEN (16)
#define	OPENSSH_ROUNDS (8)

#define FOIL_PKCS1_SALT_LEN (8)
G_STATIC_ASSERT(FOIL_AES_BLOCK_SIZE >= FOIL_PKCS1_SALT_LEN);

static const guint8 rsa_private_key_pkcs1_prefix_data[] = {
    '-','-','-','-','-','B','E','G','I','N',' ','R','S','A',' ','P',
    'R','I','V','A','T','E',' ','K','E','Y','-','-','-','-','-'
};
static const guint8 rsa_private_key_pkcs1_suffix_data[] = {
    '-','-','-','-','-','E','N','D',' ','R','S','A',' ','P','R','I',
    'V','A','T','E',' ','K','E','Y','-','-','-','-','-'
};
static const FoilBytes rsa_private_key_pkcs1_prefix = {
    FOIL_ARRAY_AND_SIZE(rsa_private_key_pkcs1_prefix_data)
};
static const FoilBytes rsa_private_key_pkcs1_suffix = {
    FOIL_ARRAY_AND_SIZE(rsa_private_key_pkcs1_suffix_data)
};

static const guint8 rsa_private_key_pkcs8_prefix_data[] = {
    '-','-','-','-','-','B','E','G','I','N',' ','E','N','C','R','Y',
    'P','T','E','D',' ','P','R','I','V','A','T','E',' ','K','E','Y',
    '-','-','-','-','-'
};
static const guint8 rsa_private_key_pkcs8_suffix_data[] = {
    '-','-','-','-','-','E','N','D',' ','E','N','C','R','Y','P','T',
    'E','D',' ','P','R','I','V','A','T','E',' ','K','E','Y','-','-',
    '-','-','-'
};

static const FoilBytes rsa_private_key_pkcs8_prefix = {
    FOIL_ARRAY_AND_SIZE(rsa_private_key_pkcs8_prefix_data)
};
static const FoilBytes rsa_private_key_pkcs8_suffix = {
    FOIL_ARRAY_AND_SIZE(rsa_private_key_pkcs8_suffix_data)
};

static const guint8 openssh_bcrypt_data[] = { 'b','c','r','y','p','t' };
static const FoilBytes openssh_bcrypt = {
    FOIL_ARRAY_AND_SIZE(openssh_bcrypt_data)
};

static const guint8 openssh_none_data[] = {'n','o','n','e' };
static const FoilBytes openssh_none = {
    FOIL_ARRAY_AND_SIZE(openssh_none_data)
};

#define OPENSSH_DEFAULT_CIPHER (openssh_ciphers + 5) /* aes256-ctr */
static const FoilKeyRsaOpensshCipher openssh_ciphers[] = {
    #define OPENSSH_CIPHER_AES(bits,mode) { \
        "aes" #bits "-" #mode, FOIL_AES_BLOCK_SIZE, \
        (bits)/8 + FOIL_AES_BLOCK_SIZE, foil_key_aes##bits##_get_type, \
        foil_impl_cipher_aes_##mode##_encrypt_get_type, \
        foil_impl_cipher_aes_##mode##_decrypt_get_type }
    OPENSSH_CIPHER_AES(128,cbc),
    OPENSSH_CIPHER_AES(192,cbc),
    OPENSSH_CIPHER_AES(256,cbc),
    OPENSSH_CIPHER_AES(128,ctr),
    OPENSSH_CIPHER_AES(192,ctr),
    OPENSSH_CIPHER_AES(256,ctr)
    #undef OPENSSH_CIPHER_AES
};

void
foil_key_rsa_private_get_public_data(
    FoilKeyRsaPrivate* self,
    FoilKeyRsaPublicData* pub_data)
{
    pub_data->e = self->data->e;
    pub_data->n = self->data->n;
}

static
FoilKeyRsaPrivateData*
foil_key_rsa_private_data_copy(
    const FoilKeyRsaPrivateData* data)
{
    const gsize total = FOIL_ALIGN(sizeof(*data)) +
        FOIL_ALIGN(data->n.len) + FOIL_ALIGN(data->e.len) +
        FOIL_ALIGN(data->d.len) + FOIL_ALIGN(data->p.len) +
        FOIL_ALIGN(data->q.len) + FOIL_ALIGN(data->dmp1.len) +
        FOIL_ALIGN(data->dmq1.len) + FOIL_ALIGN(data->iqmp.len);
    FoilKeyRsaPrivateData* copy = g_malloc(total);
    guint8* ptr = ((guint8*)copy) + FOIL_ALIGN(sizeof(*copy));
    ptr = foil_bytes_copy(&copy->n, &data->n, ptr);
    ptr = foil_bytes_copy(&copy->e, &data->e, ptr);
    ptr = foil_bytes_copy(&copy->d, &data->d, ptr);
    ptr = foil_bytes_copy(&copy->p, &data->p, ptr);
    ptr = foil_bytes_copy(&copy->q, &data->q, ptr);
    ptr = foil_bytes_copy(&copy->dmp1, &data->dmp1, ptr);
    ptr = foil_bytes_copy(&copy->dmq1, &data->dmq1, ptr);
    ptr = foil_bytes_copy(&copy->iqmp, &data->iqmp, ptr);
    GASSERT((gsize)(ptr - ((guint8*)copy)) == total);
    return copy;
}

static
gboolean
foil_key_rsa_private_data_equal(
    const FoilKeyRsaPrivateData* data1,
    const FoilKeyRsaPrivateData* data2)
{
    if (data1 == data2) {
        return TRUE;
    } else if (!data1 || !data2) {
        return FALSE;
    } else {
        return foil_bytes_equal(&data1->n, &data2->n) &&
            foil_bytes_equal(&data1->e, &data2->e) &&
            foil_bytes_equal(&data1->d, &data2->d) &&
            foil_bytes_equal(&data1->p, &data2->p) &&
            foil_bytes_equal(&data1->q, &data2->q) &&
            foil_bytes_equal(&data1->dmp1, &data2->dmp1) &&
            foil_bytes_equal(&data1->dmq1, &data2->dmq1) &&
            foil_bytes_equal(&data1->iqmp, &data2->iqmp);
    }
}

static
GBytes*
foil_key_rsa_private_data_to_bytes(
    const FoilKeyRsaPrivateData* key_data)
{
    GBytes* bytes = NULL;
    if (key_data) {
        GByteArray* seq;
        GByteArray* buf = g_byte_array_sized_new(19 +
            key_data->n.len + key_data->e.len + key_data->d.len +
            key_data->p.len + key_data->q.len + key_data->dmp1.len +
            key_data->dmq1.len + key_data->iqmp.len);
        FoilOutput* seq_out;
        FoilOutput* data_out = foil_output_mem_new(buf);
        /* PKCS #1 format https://www.ietf.org/rfc/rfc3447 */
        foil_asn1_encode_integer(data_out, PKCS1_RSA_VERSION);
        foil_asn1_encode_integer_bytes(data_out, &key_data->n);
        foil_asn1_encode_integer_bytes(data_out, &key_data->e);
        foil_asn1_encode_integer_bytes(data_out, &key_data->d);
        foil_asn1_encode_integer_bytes(data_out, &key_data->p);
        foil_asn1_encode_integer_bytes(data_out, &key_data->q);
        foil_asn1_encode_integer_bytes(data_out, &key_data->dmp1);
        foil_asn1_encode_integer_bytes(data_out, &key_data->dmq1);
        foil_asn1_encode_integer_bytes(data_out, &key_data->iqmp);
        seq = g_byte_array_sized_new(foil_asn1_block_length(buf->len));
        seq_out = foil_output_mem_new(seq);
        foil_asn1_encode_sequence_data(seq_out, buf->data, buf->len);
        bytes = foil_output_free_to_bytes(seq_out);
        foil_output_unref(data_out);
        g_byte_array_unref(seq);
        g_byte_array_unref(buf);
    }
    return bytes;
}

static
GBytes*
foil_key_rsa_private_data_to_openssh_private(
    const FoilKeyRsaPrivateData* priv,
    guint align,
    const char* comment)
{
    FoilOutput* out = foil_output_mem_new(NULL);
    FoilBytes c;
    guint32 check;
    guint8 pad;

    c.val = (void*) comment;
    c.len =  comment ? strlen(comment) : 0;
    foil_random(&check, sizeof(check));

    /* Memory-backed I/O never fails in a meaningful way */
    foil_key_rsa_write_n(out, check); /* check1 */
    foil_key_rsa_write_n(out, check); /* check2 */
    foil_key_rsa_write_n_bytes(out, &foil_ssh_rsa_mark); /* keytype */
    foil_key_rsa_write_n_bytes(out, &priv->n);
    foil_key_rsa_write_n_bytes(out, &priv->e);
    foil_key_rsa_write_n_bytes(out, &priv->d);
    foil_key_rsa_write_n_bytes(out, &priv->iqmp);
    foil_key_rsa_write_n_bytes(out, &priv->p);
    foil_key_rsa_write_n_bytes(out, &priv->q);
    foil_key_rsa_write_n_bytes(out, &c);  /* comment */
    for (pad = 1; foil_output_bytes_written(out) % align; pad++) {
        foil_output_write(out, &pad, 1);
    }
    return foil_output_free_to_bytes(out);
}

static
GBytes*
foil_key_rsa_private_data_to_openssh_bytes(
    const FoilKeyRsaPrivateData* priv,
    const char* comment)
{
    FoilOutput* out = foil_output_mem_new(NULL);
    FoilKeyRsaPublicData pub;
    GBytes* data;
    FoilBytes b;

    /* Memory-backed I/O never fails in a meaningful way */
    foil_key_rsa_private_write_data(out, &foil_key_openssh_auth_magic);
    foil_key_rsa_write_n_bytes(out, &openssh_none); /* ciphername */
    foil_key_rsa_write_n_bytes(out, &openssh_none); /* kdfname */
    foil_key_rsa_write_n(out, 0); /* kdf */
    foil_key_rsa_write_n(out, 1); /* nkeys */

    /* pubkey */
    pub.n = priv->n;
    pub.e = priv->e;
    data = foil_key_rsa_public_data_ssh_rsa_bytes(&pub);
    foil_key_rsa_write_n_bytes(out, foil_bytes_from_data(&b, data));
    g_bytes_unref(data);

    /* private part */
    data = foil_key_rsa_private_data_to_openssh_private(priv,
        OPENSSH_PLAINTEXT_ALIGN, comment);
    foil_key_rsa_write_n_bytes(out, foil_bytes_from_data(&b, data));
    g_bytes_unref(data);
    return foil_output_free_to_bytes(out);
}

static
GBytes*
foil_key_rsa_private_data_to_openssh_encrypted_bytes(
    const FoilKeyRsaPrivateData* priv,
    const FoilKeyRsaOpensshCipher* cipher,
    guint rounds,
    const char* pass,
    const char* comment)
{
    FoilOutput* out = foil_output_mem_new(NULL);
    FoilKeyRsaPublicData pub;
    FoilKey* key;
    FoilBytes b;
    guint8 salt[OPENSSH_SALT_LEN];
    GBytes* data;
    GBytes* encrypted;

    /* Generate salted key */
    foil_random(&salt, sizeof(salt));
    b.val = salt;
    b.len = sizeof(salt);
    data = foil_bcrypt_pbkdf(pass, &b, cipher->keysize, rounds);
    key = foil_key_new_from_bytes(cipher->key(), data);
    g_bytes_unref(data);

    /* Memory-backed I/O never fails in a meaningful way */
    foil_key_rsa_private_write_data(out, &foil_key_openssh_auth_magic);
    foil_key_rsa_write_n_bytes(out, foil_bytes_from_string(&b, cipher->name));
    foil_key_rsa_write_n_bytes(out, &openssh_bcrypt); /* kdfname */
    foil_key_rsa_write_n(out, OPENSSH_SALT_LEN + 8); /* kdf block */
    foil_key_rsa_write_n(out, sizeof(salt));
    foil_output_write(out, salt, sizeof(salt));
    foil_key_rsa_write_n(out, rounds);
    foil_key_rsa_write_n(out, 1); /* nkeys */

    /* pubkey */
    pub.n = priv->n;
    pub.e = priv->e;
    data = foil_key_rsa_public_data_ssh_rsa_bytes(&pub);
    foil_key_rsa_write_n_bytes(out, foil_bytes_from_data(&b, data));
    g_bytes_unref(data);

    /* Encrypt private part */
    data = foil_key_rsa_private_data_to_openssh_private(priv,
        cipher->blocklen, comment);
    encrypted = foil_cipher_bytes(cipher->encrypt(), key, data);
    g_bytes_unref(data);
    foil_key_unref(key);
    if (encrypted) {
        foil_key_rsa_write_n_bytes(out, foil_bytes_from_data(&b, encrypted));
        g_bytes_unref(encrypted);
        return foil_output_free_to_bytes(out);
    } else {
        foil_output_unref(out);
        return NULL;
    }
}

static
GBytes*
foil_key_rsa_private_to_bytes(
    FoilKey* key,
    FoilKeyBinaryFormat format)
{
    FoilKeyRsaPrivate* self = FOIL_KEY_RSA_PRIVATE_(key);
    switch (format) {
    case FOIL_KEY_BINARY_FORMAT_DEFAULT:
    case FOIL_KEY_BINARY_FORMAT_RSA_PKCS1:
        return foil_key_rsa_private_data_to_bytes(self->data);
    case FOIL_KEY_BINARY_FORMAT_OPENSSH:
        return foil_key_rsa_private_data_to_openssh_bytes(self->data, NULL);
    case FOIL_KEY_BINARY_FORMAT_RSA_SSH:
        break;
    }
    /* Invalid/unsupported format */
    return NULL;
}

/*
 * AlgorithmIdentifier is defined in RFC 5280 as follows:
 *
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *      algorithm         OBJECT IDENTIFIER,
 *      parameters        ANY DEFINED BY algorithm OPTIONAL }
 */
static
gboolean
foil_key_rsa_private_parse_aid(
    GUtilRange* pos,
    FoilBytes* oid,
    FoilBytes* params)
{
    guint32 len;
    GUtilRange parse = *pos;
    if (foil_asn1_parse_start_sequence(&parse, &len)) {
        parse.end = parse.ptr + len;
        if (foil_asn1_parse_object_id(&parse, oid)) {
            params->val = parse.ptr;
            params->len = parse.end - parse.ptr;
            pos->ptr = parse.end;
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * PKCS #1
 *
 * https://www.ietf.org/rfc/rfc3447 (Appendix A)
 *
 * RSAPrivateKey ::= SEQUENCE {
 *     version           Version,
 *     modulus           INTEGER,  -- n
 *     publicExponent    INTEGER,  -- e
 *     privateExponent   INTEGER,  -- d
 *     prime1            INTEGER,  -- p
 *     prime2            INTEGER,  -- q
 *     exponent1         INTEGER,  -- d mod (p-1)
 *     exponent2         INTEGER,  -- d mod (q-1)
 *     coefficient       INTEGER,  -- (inverse of q) mod p
 *     otherPrimeInfos   OtherPrimeInfos OPTIONAL
 * }
 */
static
gboolean
foil_key_rsa_private_parse_pkcs1(
    FoilKeyRsaPrivateData* key,
    const FoilBytes* data)
{
    guint32 len;
    GUtilRange pos;
    foil_parse_init_data(&pos, data);
    if (foil_asn1_parse_start_sequence(&pos, &len)) {
        gint32 version;
        pos.end = pos.ptr + len;
        if (foil_asn1_parse_int32(&pos, &version) &&
            version == PKCS1_RSA_VERSION &&
            foil_asn1_parse_integer_bytes(&pos, &key->n) &&
            foil_asn1_parse_integer_bytes(&pos, &key->e) &&
            foil_asn1_parse_integer_bytes(&pos, &key->d) &&
            foil_asn1_parse_integer_bytes(&pos, &key->p) &&
            foil_asn1_parse_integer_bytes(&pos, &key->q) &&
            foil_asn1_parse_integer_bytes(&pos, &key->dmp1) &&
            foil_asn1_parse_integer_bytes(&pos, &key->dmq1) &&
            foil_asn1_parse_integer_bytes(&pos, &key->iqmp) &&
            pos.ptr == pos.end) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * PKCS #8
 *
 * https://tools.ietf.org/html/rfc3447
 *
 * PrivateKeyInfo ::= SEQUENCE {
 *     version                   Version,
 *     privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
 *     privateKey                PrivateKey,
 *     attributes           [0]  IMPLICIT Attributes OPTIONAL }
 */
static
gboolean
foil_key_rsa_private_parse_pkcs8(
    FoilKeyRsaPrivateData* key,
    const FoilBytes* data)
{
    static const guint8 oid_rsa_bytes[] = { ASN1_OID_RSA_BYTES };
    static const FoilBytes oid_rsa = { oid_rsa_bytes, sizeof(oid_rsa_bytes) };
    guint32 len;
    GUtilRange pos;
    foil_parse_init_data(&pos, data);
    /* PrivateKeyInfo */
    if (foil_asn1_parse_start_sequence(&pos, &len)) {
        gint32 version;
        FoilBytes oid, params, priv;
        pos.end = pos.ptr + len;
        if (foil_asn1_parse_int32(&pos, &version) &&
            /* version */
            version == PKCS8_RSA_VERSION &&
            /* privateKeyAlgorithm */
            foil_key_rsa_private_parse_aid(&pos, &oid, &params) &&
            foil_bytes_equal(&oid, &oid_rsa) &&
            /* privateKey */
            foil_asn1_parse_octet_string(&pos, &priv)) {
            return foil_key_rsa_private_parse_pkcs1(key, &priv);
        }
    }
    return FALSE;
}

/* This does kind of like what EVP_BytesToKey does with count=1 */
static
GBytes*
foil_key_rsa_private_pass_key(
    const char* pass,
    const void* iv,
    guint bits)
{
    const guint key_size = bits/8;
    const guint total = key_size + FOIL_AES_BLOCK_SIZE;
    gsize pass_len = pass ? strlen(pass) : 0;
    guint8* data = g_malloc(total);
    GBytes* last_md = NULL;
    guint remain = key_size;
    guint8* ptr = data;

    do {
        gsize md_size, n;
        const void* md_bytes;
        FoilDigest* md = foil_digest_new_md5();
        if (last_md) {
            foil_digest_update_bytes(md, last_md);
            g_bytes_unref(last_md);
        }
        foil_digest_update(md, pass, pass_len);
        foil_digest_update(md, iv, FOIL_PKCS1_SALT_LEN);
        last_md = foil_digest_free_to_bytes(md);
        md_bytes = g_bytes_get_data(last_md, &md_size);
        n = MIN(remain, md_size);
        memcpy(ptr, md_bytes, n);
        ptr += n;
        remain -= n;
    } while (remain > 0);

    g_bytes_unref(last_md);
    memcpy(ptr, iv, FOIL_AES_BLOCK_SIZE);
    return g_bytes_new_take(data, total);
}

static
GBytes*
foil_key_rsa_private_decrypt_pkcs1(
    GHashTable* headers,
    GBytes* bytes,
    const char* pass,
    GError** error)
{
    /*
     * Proc-Type and DEK-Info header tags are described in RFC 1421:
     *
     * https://www.ietf.org/rfc/rfc1421
     */
    GBytes* decrypted = NULL;
    const char* proc_type;
    const char* dek_info;
    if (headers &&
        (proc_type = g_hash_table_lookup(headers, "Proc-Type")) != NULL &&
        (dek_info = g_hash_table_lookup(headers, "DEK-Info")) != NULL) {

        /* Proc-Type: 4,ENCRYPTED */
        GStrV* proc = gutil_strv_strip(g_strsplit(proc_type, ",", 0));
        if (gutil_strv_length(proc) >= 2 && !strcmp(proc[0], "4") &&
            gutil_strv_contains(proc, "ENCRYPTED")) {

            /* DEK-Info: alg,params... */
            GStrV* dek = gutil_strv_strip(g_strsplit(dek_info, ",", 0));
            if (gutil_strv_length(dek) >= 2) {
                const char* alg = dek[0];
                GType cipher = (GType)0;
                FoilKey* key = NULL;

                /* Choose algorithm and parse the get the key */
                if (g_str_has_prefix(alg, "AES-")) {
                    /* Check the IV size */
                    const char* hiv = dek[1];
                    const gsize hiv_len = strlen(hiv);
                    if (hiv_len == FOIL_AES_BLOCK_SIZE*2) {
                        guint bits = 0;
                        GType key_type = (GType)0;
                        guint8 iv[FOIL_AES_BLOCK_SIZE];
                        /* Figure out key size */
                        if (!strcmp(alg, "AES-256-CBC")) {
                            bits = 256;
                            key_type = FOIL_KEY_AES256;
                            cipher = FOIL_CIPHER_AES_CBC_DECRYPT;
                        } else if (!strcmp(alg, "AES-192-CBC")) {
                            bits = 192;
                            key_type = FOIL_KEY_AES192;
                            cipher = FOIL_CIPHER_AES_CBC_DECRYPT;
                        } else if (!strcmp(alg, "AES-128-CBC")) {
                            bits = 128;
                            key_type = FOIL_KEY_AES128;
                            cipher = FOIL_CIPHER_AES_CBC_DECRYPT;
                        }

                        /* Decode IV (16 bytes) */
                        if (bits && gutil_hex2bin(hiv, hiv_len, iv)) {
                            GBytes* b;
                            b = foil_key_rsa_private_pass_key(pass, iv, bits);
                            key = foil_key_new_from_bytes_full(key_type, b,
                                NULL, error);
                            g_bytes_unref(b);
                        }
                    }
                }

                if (key) {
                    decrypted = foil_cipher_bytes(cipher, key, bytes);
                    foil_key_unref(key);
                } else if (error && !*error) {
                    if (cipher) {
                        *error = g_error_new(FOIL_ERROR,
                             FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT,
                             "RSA private key decryption %s failed", alg);
                    } else {
                        *error = g_error_new(FOIL_ERROR,
                             FOIL_ERROR_KEY_UNKNOWN_ENCRYPTION,
                             "Unsupported RSA private key encryption %s", alg);
                    }
                }
            } else if (error) {
                *error = g_error_new_literal(FOIL_ERROR,
                    FOIL_ERROR_KEY_UNKNOWN_ENCRYPTION,
                    "Unrecognized RSA private key encryption format");
            }
            g_strfreev(dek);
        }
        g_strfreev(proc);
    }
    return decrypted;
}

static
GBytes*
foil_key_rsa_private_pbkdf2(
    guint bits,
    const char* pass,
    FoilBytes* salt,
    guint count,
    GType digest,
    FoilBytes* iv)
{
    const gsize key_size = bits/8;
    const gsize total = key_size + iv->len;
    guint8* data = g_malloc(total);
    GBytes* key = foil_kdf_pbkdf2(digest, pass, pass ? strlen(pass) : 0,
        salt, count, key_size);

    memcpy(data, g_bytes_get_data(key, NULL), key_size);
    memcpy(data + key_size, iv->val, iv->len);
    g_bytes_unref(key);
    return g_bytes_new_take(data, total);
}

/* PBES2 defined in RFC 2898 */
static
GBytes*
foil_key_rsa_private_decrypt_pbes2(
    const FoilBytes* data,
    const char* pass,
    const FoilBytes* params,
    GError** error)
{
    static const guint8 pbkdf2[] = { ASN1_OID_PBKDF2_BYTES };
    static const guint8 aes128cbc[] = { ASN1_OID_AES128_CBC_BYTES };
    static const guint8 aes192cbc[] = { ASN1_OID_AES192_CBC_BYTES };
    static const guint8 aes256cbc[] = { ASN1_OID_AES256_CBC_BYTES };
    static const FoilBytes oid_pbkdf2 = { pbkdf2, sizeof(pbkdf2) };
    static const FoilBytes oid_aes128_cbc = { aes128cbc, sizeof(aes128cbc) };
    static const FoilBytes oid_aes192_cbc = { aes192cbc, sizeof(aes192cbc) };
    static const FoilBytes oid_aes256_cbc = { aes256cbc, sizeof(aes256cbc) };

    GBytes* decrypted = NULL;
    guint32 len;
    GUtilRange pos;
    foil_parse_init_data(&pos, params);
    if (foil_asn1_parse_start_sequence(&pos, &len)) {
        FoilBytes kdf, kdf_param, alg, alg_param;
        pos.end = pos.ptr + len;
        if (foil_key_rsa_private_parse_aid(&pos, &kdf, &kdf_param) &&
            foil_key_rsa_private_parse_aid(&pos, &alg, &alg_param)) {
            FoilBytes iv;
            GType cipher = (GType)0;
            guint bits = 0, ivsize = 0;
            GType key_type = (GType)0;
            /* Encryption scheme */
            if (foil_bytes_equal(&alg, &oid_aes256_cbc)) {
                /* AES256-CBC */
                bits = 256;
                key_type = FOIL_KEY_AES256;
                ivsize = FOIL_AES_BLOCK_SIZE;
                cipher = FOIL_CIPHER_AES_CBC_DECRYPT;
            } else if (foil_bytes_equal(&alg, &oid_aes192_cbc)) {
                /* AES192-CBC */
                bits = 192;
                key_type = FOIL_KEY_AES192;
                ivsize = FOIL_AES_BLOCK_SIZE;
                cipher = FOIL_CIPHER_AES_CBC_DECRYPT;
            } else if (foil_bytes_equal(&alg, &oid_aes128_cbc)) {
                /* AES128-CBC */
                bits = 128;
                key_type = FOIL_KEY_AES128;
                ivsize = FOIL_AES_BLOCK_SIZE;
                cipher = FOIL_CIPHER_AES_CBC_DECRYPT;
            }
            pos.ptr = alg_param.val;
            pos.end = alg_param.val + alg_param.len;
            if (bits && foil_asn1_parse_octet_string(&pos, &iv) &&
                iv.len == ivsize) {
                FoilKey* key = NULL;
                /* Key derivation function */
                if (foil_bytes_equal(&kdf, &oid_pbkdf2)) {
                    /* PBKDF2 */
                    pos.ptr = kdf_param.val;
                    pos.end = kdf_param.val + alg_param.len;
                    if (foil_asn1_parse_start_sequence(&pos, &len)) {
                        FoilBytes salt;
                        gint32 count;
                        pos.end = pos.ptr + len;
                        if (foil_asn1_parse_octet_string(&pos, &salt) &&
                            foil_asn1_parse_int32(&pos, &count) && count > 0 &&
                            /* keyLength and prf are optional, we assume
                             * the defaults */
                            pos.ptr == pos.end) {
                            /* Default is hmacWithSHA1 */
                            GType hmac_digest = FOIL_DIGEST_SHA1;
                            GBytes* b = foil_key_rsa_private_pbkdf2(bits,
                                pass, &salt, count, hmac_digest, &iv);
                            if (b) {
                                key = foil_key_new_from_bytes_full(key_type,
                                    b, NULL, error);
                                g_bytes_unref(b);
                            }
                        } else if (error && !*error) {
                            *error = g_error_new(FOIL_ERROR,
                                 FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT,
                                 "Usupported PBKDF2 parameters");
                        }
                    }
                } else if (error && !*error) {
                    *error = g_error_new(FOIL_ERROR,
                         FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT,
                         "Usupported PBES2 key derivation function");
                }
                if (key) {
                    decrypted = foil_cipher_data(cipher, key,
                        data->val, data->len);
                    foil_key_unref(key);
                }
            }
        }
    }
    return decrypted;
}

/*
 * Format of encrypted private-key information according to RFC 5208:
 *
 * EncryptedPrivateKeyInfo ::= SEQUENCE {
 *   encryptionAlgorithm  AlgorithmIdentifier,
 *   encryptedData        OCTET STRING }
 */
static
GBytes*
foil_key_rsa_private_decrypt_pkcs8(
    GHashTable* headers,
    GBytes* bytes,
    const char* pass,
    GError** error)
{
    /*
     * RFC 2898:
     *
     * PBES2-params ::= SEQUENCE {
     *     keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
     *     encryptionScheme AlgorithmIdentifier {{PBES2-Encs}} }
     *
     * PBES2-KDFs ALGORITHM-IDENTIFIER ::= {
     *     {PBKDF2-params IDENTIFIED BY id-PBKDF2}, ... }
     *
     * PBES2-Encs ALGORITHM-IDENTIFIER ::= { ... }
     */

    /* ASN.1 encoding of OID 1.2.840.113549.1.5.13 (id-PBES2) */
    static const guint8 OID_PBES2[] = {
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d
    };
    static const FoilBytes oid_pbes2 = { FOIL_ARRAY_AND_SIZE(OID_PBES2) };
    guint32 len;
    GUtilRange pos;
    foil_parse_init_bytes(&pos, bytes);
    if (foil_asn1_parse_start_sequence(&pos, &len)) {
        FoilBytes oid;
        FoilBytes params;
        FoilBytes enc;
        pos.end = pos.ptr + len;
        if (foil_key_rsa_private_parse_aid(&pos, &oid, &params) &&
            foil_asn1_parse_octet_string(&pos, &enc)) {
            if (foil_bytes_equal(&oid, &oid_pbes2)) {
                /* PBES2 */
                return foil_key_rsa_private_decrypt_pbes2(&enc, pass,
                    &params, error);
            }
        }
    }
    return NULL;
}

static
gboolean
foil_key_rsa_private_parse_text(
    FoilKeyRsaPrivateData* key,
    const FoilBytes* data,
    const char* pass,
    FoilPool* pool,
    GError** error,
    const FoilBytes* prefix,
    const FoilBytes* suffix,
    GBytes* (*decrypt)(
        GHashTable* headers,
        GBytes* bytes,
        const char* pass,
        GError** error),
    gboolean (*parse_asn1)(
        FoilKeyRsaPrivateData* key,
        const FoilBytes* data))
{
    gboolean ok = FALSE;
    const guint8* start = foil_memmem(data, prefix);
    if (start && data->len > (prefix->len + suffix->len)) {
        GBytes* decoded;
        GUtilRange pos;
        GHashTable* headers;

        /* Parse the header tags */
        pos.ptr = start + prefix->len;
        pos.end = data->val + data->len;
        foil_parse_skip_spaces(&pos);
        headers = foil_parse_headers(&pos, NULL);

        /* Collect BASE64 encoded data */
        decoded = foil_parse_base64(&pos, FOIL_INPUT_BASE64_IGNORE_SPACES |
            FOIL_INPUT_BASE64_STANDARD);
        if (decoded) {
            const guint bytes_left = pos.end - pos.ptr;
            if (bytes_left >= suffix->len &&
                memcmp(pos.ptr, suffix->val, suffix->len) == 0) {
                /* And ignore the rest */
                GBytes* decrypted = NULL;
                FoilBytes b;
                if (headers || decrypt) {
                    /* The key may be encrypted */
                    decrypted = decrypt(headers, decoded, pass, error);
                }
                if (decrypted) {
                    ok = parse_asn1(key, foil_bytes_from_data(&b, decrypted));
                    /* Preserve GBytes in the pool to keep pointers valid */
                    foil_pool_add_bytes(pool, decrypted);
                    if (!ok && error) {
                        g_propagate_error(error, g_error_new_literal(
                            FOIL_ERROR, (pass && pass[0]) ?
                            FOIL_ERROR_KEY_DECRYPTION_FAILED :
                            FOIL_ERROR_KEY_ENCRYPTED,
                           "Failed to decrypt RSA private key"));
                    }
                } else if (!error || !*error) {
                    ok = parse_asn1(key, foil_bytes_from_data(&b, decoded));
                    /* Preserve GBytes in the pool to keep pointers valid */
                    foil_pool_add_bytes_ref(pool, decoded);
                }
            }
            g_bytes_unref(decoded);
        }
        if (headers) {
            g_hash_table_unref(headers);
        }
    }
    return ok;
}

static
gboolean
foil_key_rsa_private_parse_text_pkcs1(
    FoilKeyRsaPrivateData* key,
    const FoilBytes* data,
    const char* pass,
    FoilPool* pool,
    GError** error)
{
    return foil_key_rsa_private_parse_text(key, data, pass, pool, error,
        &rsa_private_key_pkcs1_prefix, &rsa_private_key_pkcs1_suffix,
        foil_key_rsa_private_decrypt_pkcs1,
        foil_key_rsa_private_parse_pkcs1);
}

static
gboolean
foil_key_rsa_private_parse_text_pkcs8(
    FoilKeyRsaPrivateData* key,
    const FoilBytes* data,
    const char* pass,
    FoilPool* pool,
    GError** error)
{
    return foil_key_rsa_private_parse_text(key, data, pass, pool, error,
        &rsa_private_key_pkcs8_prefix, &rsa_private_key_pkcs8_suffix,
        foil_key_rsa_private_decrypt_pkcs8,
        foil_key_rsa_private_parse_pkcs8);
}

static
gboolean
foil_key_rsa_private_check_openssh_padding(
    GUtilRange* pos)
{
    guint8 counter = 1;
    while (pos->ptr < pos->end) {
        if (*pos->ptr++ != counter++) {
            return FALSE;
        }
    }
    return TRUE;
}

static
const FoilKeyRsaOpensshCipher*
foil_key_rsa_private_openssh_cipher_by_name(
    const FoilBytes* name)
{
    gsize i;
    for (i = 0; i < G_N_ELEMENTS(openssh_ciphers); i++) {
        const FoilKeyRsaOpensshCipher* cipher = openssh_ciphers + i;
        if (!strncmp((char*)name->val, cipher->name, name->len) &&
            !cipher->name[name->len]) {
            return cipher;
        }
    }
    return NULL;
}

static
gboolean
foil_key_rsa_private_decode_openssh_plaintext(
    FoilKeyRsaPrivateData* key,
    const FoilKeyRsaPublicData* pub,
    const FoilBytes* data,
    FoilBytes* comment)
{
    guint32 check1, check2;
    FoilBytes keytype;
    GUtilRange pos;
    foil_parse_init_data(&pos, data);
    if (foil_key_rsa_parse_n(&pos, &check1) &&
        foil_key_rsa_parse_n(&pos, &check2) &&
        check1 == check2 &&
        foil_key_rsa_parse_n_bytes(&pos, &keytype)) {
        if (foil_bytes_equal(&keytype, &foil_ssh_rsa_mark)) {
            if (foil_key_rsa_parse_n_bytes(&pos, &key->n) &&
                foil_key_rsa_parse_n_bytes(&pos, &key->e) &&
                foil_key_rsa_parse_n_bytes(&pos, &key->d) &&
                foil_key_rsa_parse_n_bytes(&pos, &key->iqmp) &&
                foil_key_rsa_parse_n_bytes(&pos, &key->p) &&
                foil_key_rsa_parse_n_bytes(&pos, &key->q) &&
                foil_key_rsa_parse_n_bytes(&pos, comment) &&
                foil_key_rsa_private_check_openssh_padding(&pos) &&
                foil_bytes_equal(&key->n, &pub->n) &&
                foil_bytes_equal(&key->e, &pub->e)) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

static
gboolean
foil_key_rsa_private_decode_openssh_bcrypt(
    FoilKeyRsaPrivateData* priv,
    const FoilKeyRsaPublicData* pub,
    const FoilKeyRsaOpensshCipher* cipher,
    const FoilBytes* kdf,
    const FoilBytes* encrypted,
    const char* pass,
    FoilPool* pool,
    FoilBytes* comment)
{
    GUtilRange pos;
    FoilBytes salt;
    guint32 n;
    foil_parse_init_data(&pos, kdf);
    if (foil_key_rsa_parse_n_bytes(&pos, &salt) &&
        foil_key_rsa_parse_n(&pos, &n) &&
        pos.ptr == pos.end) {
        GBytes* keydata = foil_bcrypt_pbkdf(pass, &salt, cipher->keysize, n);
        if (keydata) {
            FoilKey* key = foil_key_new_from_bytes(cipher->key(), keydata);
            g_bytes_unref(keydata);
            if (key) {
                GBytes* decrypted = foil_cipher_data(cipher->decrypt(), key,
                    encrypted->val, encrypted->len);
                foil_key_unref(key);
                if (decrypted) {
                    FoilBytes data;
                    if (foil_key_rsa_private_decode_openssh_plaintext(priv,
                        pub, foil_bytes_from_data(&data, decrypted), comment)) {
                        /* Preserve GBytes reference in the pool */
                        foil_pool_add_bytes(pool, decrypted);
                        return TRUE;
                    }
                    g_bytes_unref(decrypted);
                }
            }
        }
    }
    return FALSE;
}

static
gboolean
foil_key_rsa_private_decode_openssh(
    FoilKeyRsaPrivateData* key,
    const FoilKeyRsaPublicData* pub,
    const FoilKeyRsaOpensshPrivData* priv,
    const char* pass,
    FoilPool* pool,
    GError** error)
{
    if (foil_bytes_equal(&priv->kdfname, &openssh_none)) {
        /* Private part is not encrypted */
        FoilBytes comment;
        if (foil_bytes_equal(&priv->ciphername, &openssh_none) &&
            foil_key_rsa_private_decode_openssh_plaintext(key, pub,
            &priv->data, &comment)) {
            return TRUE;
        } else if (error && !*error) {
            *error = g_error_new_literal(FOIL_ERROR,
                FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT,
                "Unrecognized OpenSSH key format");
        }
    } else if (!pass || !pass[0]) {
        /* Private part is encrypted but there's no password */
        if (error && !*error) {
            *error = g_error_new_literal(FOIL_ERROR,
                FOIL_ERROR_KEY_ENCRYPTED,
                "Key is encrypted");
        }
    } else {
        const FoilKeyRsaOpensshCipher* cipher =
            foil_key_rsa_private_openssh_cipher_by_name(&priv->ciphername);
        if (cipher && foil_bytes_equal(&priv->kdfname, &openssh_bcrypt)) {
            FoilBytes comment;
            if (foil_key_rsa_private_decode_openssh_bcrypt(key, pub,
                cipher, &priv->kdf, &priv->data, pass, pool, &comment)) {
                return TRUE;
            } else if (error && !*error) {
                *error = g_error_new_literal(FOIL_ERROR,
                    FOIL_ERROR_KEY_DECRYPTION_FAILED,
                    "OpenSSH key decryption failed");
            }
        } else if (error && !*error) {
            *error = g_error_new_literal(FOIL_ERROR,
                FOIL_ERROR_KEY_UNKNOWN_ENCRYPTION,
                "Unknown OpenSSH key cipher");
        }
    }
    return FALSE;
}

static
gboolean
foil_key_rsa_private_parse_openssh(
    FoilKeyRsaPrivateData* key,
    const FoilBytes* data,
    const char* pass,
    FoilPool* pool,
    GError** error)
{
    FoilKeyRsaPublicData pub;
    FoilKeyRsaOpensshPrivData priv;

    return foil_key_rsa_parse_openssh_binary(data, &pub, &priv) &&
        foil_key_rsa_private_decode_openssh(key, &pub, &priv, pass, pool,
        error);
}

static
gboolean
foil_key_rsa_private_parse_text_openssh(
    FoilKeyRsaPrivateData* key,
    const FoilBytes* data,
    const char* pass,
    FoilPool* pool,
    GError** error)
{
    FoilKeyRsaPublicData pub;
    FoilKeyRsaOpensshPrivData priv;

    return foil_key_rsa_parse_openssh_text(data, &pub, &priv, pool) &&
        foil_key_rsa_private_decode_openssh(key, &pub, &priv, pass, pool,
        error);
}

static
FoilKey*
foil_key_rsa_private_from_data(
    FoilKeyClass* klass,
    const void* bytes,
    gsize size,
    GHashTable* param,
    GError** err)
{
    FoilKey* result = NULL;
    FoilKeyRsaPrivateData key;
    FoilBytes data;
    FoilPool pool;
    const char* pw = NULL;
    if (param) {
        /* Extract the passphrase */
        GVariant* var = g_hash_table_lookup(param, FOIL_KEY_PARAM_PASSPHRASE);
        if (g_variant_is_of_type(var, G_VARIANT_TYPE_STRING)) {
            pw = g_variant_get_string(var, NULL);
        }
    }
    foil_pool_init(&pool);
    memset(&key, 0, sizeof(key));
    data.val = bytes;
    data.len = size;
    if (foil_key_rsa_private_parse_text_pkcs8(&key, &data, pw, &pool, err) ||
        foil_key_rsa_private_parse_text_pkcs1(&key, &data, pw, &pool, err) ||
        foil_key_rsa_private_parse_text_openssh(&key, &data, pw, &pool, err) ||
        foil_key_rsa_private_parse_pkcs1(&key, &data) ||
        foil_key_rsa_private_parse_pkcs8(&key, &data) ||
        foil_key_rsa_private_parse_openssh(&key, &data, pw, &pool, err)) {
        FoilKeyRsaPrivate* priv = g_object_new(G_TYPE_FROM_CLASS(klass), NULL);
        priv->data = foil_key_rsa_private_data_copy(&key);
        g_clear_error(err);
        result = FOIL_KEY(priv);
    } else if (err && !*err) {
        *err = g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT,
            "Unrecognized RSA private key format");
    }
    foil_pool_drain(&pool);
    return result;
}

static
void
foil_key_rsa_private_encrypt_pad(
    guint8* block,
    gsize data_size,
    gsize block_size)
{
    /* Padding expected by openssl */
    guint8 n = block_size - data_size;
    memset(block + data_size, n, n);
}

/*
 * Kind of similar to foil_cipher_bytes except that we need to use the
 * specific padding. Otherwise openssl rsa will refuse to decrypt the key.
 */
static
GBytes*
foil_key_rsa_private_encrypt(
    GType type,
    FoilKey* key,
    GBytes* bytes)
{
    GBytes* result = NULL;
    if (G_LIKELY(bytes)) {
        gsize size = 0;
        const void* data = g_bytes_get_data(bytes, &size);
        if (G_LIKELY(data || !size)) {
            FoilCipher* cipher = foil_cipher_new(type, key);
            if (cipher) {
                FoilOutput* out = foil_output_mem_new(NULL);
                foil_cipher_set_padding_func(cipher,
                    foil_key_rsa_private_encrypt_pad);
                if (foil_cipher_write_data(cipher, data, size, out, NULL)) {
                    result = foil_output_free_to_bytes(out);
                } else {
                    foil_output_unref(out);
                }
                foil_cipher_unref(cipher);
            }
        }
    }
    return result;
}

static
gboolean
foil_key_rsa_private_export_pkcs1(
    FoilKeyRsaPrivate* self,
    FoilOutput* out,
    const char* comment,
    const char* pass,
    GError** error)
{
    gboolean ok = foil_key_rsa_private_write_all(out,
        &rsa_private_key_pkcs1_prefix) &&
        foil_output_write_eol(out);
    if (ok && comment) {
        char* header = foil_format_header("Comment", comment);
        if (header) {
            ok = foil_output_write_all(out, header, strlen(header)) &&
                foil_output_write_eol(out);
            g_free(header);
        }
    }
    if (ok) {
        GBytes* bytes = NULL;
        if (pass && pass[0]) {
            /* Encrypt the key */
            static const char tags[] = "Proc-Type: 4,ENCRYPTED\n"
               "DEK-Info: AES-256-CBC,";
            const guint bits = 256;
            GType key_type = FOIL_KEY_AES256;
            GType cipher = FOIL_CIPHER_AES_CBC_ENCRYPT;
            guint8 iv[FOIL_AES_BLOCK_SIZE];
            if (foil_random(iv, sizeof(iv))) {
                char hiv[2*sizeof(iv)];
                guint i;
                for (i=0; i<sizeof(iv); i++) {
                    static const char x[] = "0123456789ABCDEF";
                    hiv[2*i] = x[iv[i] >> 4];
                    hiv[2*i+1] = x[iv[i] & 0xf];
                }
                ok = foil_output_write_all(out, tags, sizeof(tags) - 1) &&
                    foil_output_write_all(out, hiv, sizeof(hiv)) &&
                    foil_output_write_eol(out) && foil_output_write_eol(out);
                if (ok) {
                    GBytes* b = foil_key_rsa_private_pass_key(pass, iv, bits);
                    FoilKey* key = foil_key_new_from_bytes(key_type, b);
                    g_bytes_unref(b);
                    if (key) {
                        b = foil_key_rsa_private_data_to_bytes(self->data);
                        bytes = foil_key_rsa_private_encrypt(cipher, key, b);
                        g_bytes_unref(b);
                        foil_key_unref(key);
                    }
                }
            } else if (error) {
                g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
                    FOIL_ERROR_UNSPECIFIED, "Key encryption error"));
            }
        } else {
            /* No encryption */
            bytes = foil_key_rsa_private_data_to_bytes(self->data);
        }
        if (bytes) {
            FoilOutput* base64 = foil_output_base64_new_full(out, 0, 64);
            ok = foil_output_write_bytes_all(base64, bytes) &&
                foil_output_flush(base64) &&
                foil_key_rsa_private_write_all(out,
                &rsa_private_key_pkcs1_suffix) &&
                foil_output_write_eol(out);
            foil_output_unref(base64);
            g_bytes_unref(bytes);
        }
    }
    if (!ok && error && !*error) {
        *error =  g_error_new_literal(FOIL_ERROR, FOIL_ERROR_KEY_WRITE,
            "Output error");
    }
    return ok;
}

static
gboolean
foil_key_rsa_private_export_openssh(
    FoilKeyRsaPrivate* self,
    FoilOutput* out,
    const char* comment,
    const char* pass,
    GError** error)
{
    GBytes* bytes = (pass && pass[0]) ?
        foil_key_rsa_private_data_to_openssh_encrypted_bytes(self->data,
            OPENSSH_DEFAULT_CIPHER, OPENSSH_ROUNDS, pass, comment) :
        foil_key_rsa_private_data_to_openssh_bytes(self->data, comment);
    if (bytes) {
        gboolean ok = FALSE;
        if (foil_key_rsa_private_write_all(out,
            &foil_key_openssh_text_prefix) &&
            foil_output_write_eol(out)) {
            FoilOutput* base64 = foil_output_base64_new_full(out, 0, 70);

            ok = foil_output_write_bytes_all(base64, bytes) &&
                foil_output_flush(base64) &&
                foil_key_rsa_private_write_all(out,
                &foil_key_openssh_text_suffix) &&
                foil_output_write_eol(out);
            foil_output_unref(base64);
        }
        g_bytes_unref(bytes);
        if (ok) {
            return TRUE;
        } else if (error && !*error) {
            *error =  g_error_new_literal(FOIL_ERROR, FOIL_ERROR_KEY_WRITE,
                "Output error");
        }
    } else if (error && !*error) {
        *error = g_error_new_literal(FOIL_ERROR, FOIL_ERROR_UNSPECIFIED,
            "Key export error");
    }
    return FALSE;
}

static
gboolean
foil_key_rsa_private_export(
    FoilKey* key,
    FoilOutput* out,
    FoilKeyExportFormat format,
    GHashTable* param,
    GError** error)
{
    FoilKeyRsaPrivate* self = FOIL_KEY_RSA_PRIVATE_(key);
    gboolean ok = FALSE;
    if (self->data) {
        const char* comment = NULL;
        const char* passphrase = NULL;
        if (param) {
            GVariant* var = g_hash_table_lookup(param, FOIL_KEY_PARAM_COMMENT);
            if (var && g_variant_is_of_type(var, G_VARIANT_TYPE_STRING)) {
                comment = g_variant_get_string(var, NULL);
            }
            var = g_hash_table_lookup(param, FOIL_KEY_PARAM_PASSPHRASE);
            if (var && g_variant_is_of_type(var, G_VARIANT_TYPE_STRING)) {
                passphrase = g_variant_get_string(var, NULL);
            }
        }
        switch (format) {
        case FOIL_KEY_EXPORT_FORMAT_DEFAULT:
            ok = foil_key_rsa_private_export_pkcs1(self, out, comment,
                passphrase, error);
            break;
        case FOIL_KEY_EXPORT_FORMAT_OPENSSH:
            ok = foil_key_rsa_private_export_openssh(self, out, comment,
                passphrase, error);
            break;
        default:
            if (error) {
                g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
                    FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT,
                    "Unsupported export format"));
            }
            break;
        }
    } else if (error) {
        g_propagate_error(error, g_error_new_literal(FOIL_ERROR,
            FOIL_ERROR_UNSPECIFIED, "Uninitialized private key"));
    }
    return ok;
}

static
gboolean
foil_key_rsa_private_equal(
    FoilKey* key1,
    FoilKey* key2)
{
    GASSERT(FOIL_IS_KEY_RSA_PRIVATE(key1));
    if (FOIL_IS_KEY_RSA_PRIVATE(key2)) {
        FoilKeyRsaPrivate* rsa1 = FOIL_KEY_RSA_PRIVATE_(key1);
        FoilKeyRsaPrivate* rsa2 = FOIL_KEY_RSA_PRIVATE_(key2);
        return foil_key_rsa_private_data_equal(rsa1->data, rsa2->data);
    }
    return FALSE;
}

static
GBytes*
foil_key_rsa_private_fingerprint(
    FoilKey* key)
{
    FoilKeyRsaPrivate* self = FOIL_KEY_RSA_PRIVATE_(key);
    FoilKeyRsaPublicData pub_data;
    foil_key_rsa_private_get_public_data(self, &pub_data);
    return foil_key_rsa_public_data_fingerprint(&pub_data);
}

static
void
foil_key_rsa_private_finalize(
    GObject* object)
{
    FoilKeyRsaPrivate* self = FOIL_KEY_RSA_PRIVATE_(object);
    FoilKeyRsaPrivateData* data = self->data;
    if (data) {
        FOIL_KEY_RSA_PRIVATE_CLEAR_BYTES(&data->d);
        FOIL_KEY_RSA_PRIVATE_CLEAR_BYTES(&data->p);
        FOIL_KEY_RSA_PRIVATE_CLEAR_BYTES(&data->q);
        FOIL_KEY_RSA_PRIVATE_CLEAR_BYTES(&data->dmp1);
        FOIL_KEY_RSA_PRIVATE_CLEAR_BYTES(&data->dmq1);
        FOIL_KEY_RSA_PRIVATE_CLEAR_BYTES(&data->iqmp);
        g_free(self->data);
    }
    G_OBJECT_CLASS(foil_key_rsa_private_parent_class)->finalize(object);
}

static
void
foil_key_rsa_private_init(
    FoilKeyRsaPrivate* key)
{
}

static
void
foil_key_rsa_private_class_init(
    FoilKeyRsaPrivateClass* klass)
{
    FoilKeyClass* key_class = FOIL_KEY_CLASS(klass);
    key_class->fn_equal = foil_key_rsa_private_equal;
    key_class->fn_from_data = foil_key_rsa_private_from_data;
    key_class->fn_to_bytes = foil_key_rsa_private_to_bytes;
    key_class->fn_export = foil_key_rsa_private_export;
    key_class->fn_fingerprint = foil_key_rsa_private_fingerprint;
    G_OBJECT_CLASS(klass)->finalize = foil_key_rsa_private_finalize;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
