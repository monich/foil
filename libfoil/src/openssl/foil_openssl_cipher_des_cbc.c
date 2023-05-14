/*
 * Copyright (C) 2019-2023 Slava Monich <slava@monich.com>
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

#include "foil_cipher_p.h"
#include "foil_util_p.h"

/* Yes we know that this API is deprecated */
#define OPENSSL_SUPPRESS_DEPRECATED

#include "foil_openssl_des.h"

/* Logging */
#define GLOG_MODULE_NAME foil_log_cipher
#include "foil_log_p.h"

typedef struct foil_openssl_cipher_cbc_class {
    FoilCipherClass cipher;
    int op;
} FoilOpensslCipherDesCbcClass;

typedef struct foil_openssl_cipher_cbc {
    FoilCipher cipher;
    FoilOpensslKeyDes* key;
    DES_cblock ivec;
} FoilOpensslCipherDesCbc;

typedef FoilOpensslCipherDesCbc FoilOpensslCipherDesCbcEncrypt;
typedef FoilOpensslCipherDesCbc FoilOpensslCipherDesCbcDecrypt;
typedef FoilOpensslCipherDesCbcClass FoilOpensslCipherDesCbcEncryptClass;
typedef FoilOpensslCipherDesCbcClass FoilOpensslCipherDesCbcDecryptClass;

GType foil_openssl_cipher_des_cbc_get_type() FOIL_INTERNAL;
GType foil_openssl_cipher_des_cbc_encrypt_get_type() FOIL_INTERNAL;
GType foil_openssl_cipher_des_cbc_decrypt_get_type() FOIL_INTERNAL;

G_DEFINE_ABSTRACT_TYPE(FoilOpensslCipherDesCbc,
    foil_openssl_cipher_des_cbc,
    FOIL_TYPE_CIPHER);

#define FOIL_TYPE_OPENSSL_CIPHER_DES_CBC \
    foil_openssl_cipher_des_cbc_get_type()

#define FOIL_OPENSSL_CIPHER_DES_CBC(obj) \
    G_TYPE_CHECK_INSTANCE_CAST(obj, \
    FOIL_TYPE_OPENSSL_CIPHER_DES_CBC, \
    FoilOpensslCipherDesCbc)
#define FOIL_OPENSSL_CIPHER_DES_CBC_GET_CLASS(obj) \
    G_TYPE_INSTANCE_GET_CLASS(obj,\
    FOIL_TYPE_OPENSSL_CIPHER_DES_CBC, \
    FoilOpensslCipherDesCbcClass)

G_DEFINE_TYPE(FoilOpensslCipherDesCbcEncrypt,
    foil_openssl_cipher_des_cbc_encrypt,
    FOIL_TYPE_OPENSSL_CIPHER_DES_CBC)
G_DEFINE_TYPE(FoilOpensslCipherDesCbcDecrypt,
    foil_openssl_cipher_des_cbc_decrypt,
    FOIL_TYPE_OPENSSL_CIPHER_DES_CBC)

GType foil_impl_cipher_des_cbc_encrypt_get_type()
{
    return foil_openssl_cipher_des_cbc_encrypt_get_type();
}

GType foil_impl_cipher_des_cbc_decrypt_get_type()
{
    return foil_openssl_cipher_des_cbc_decrypt_get_type();
}

static
gboolean
foil_openssl_cipher_des_cbc_supports_key(
    FoilCipherClass* klass,
    GType key_type)
{
    FoilKeyClass* key_klass =
        foil_abstract_class_ref(key_type, FOIL_OPENSSL_TYPE_KEY_DES);
    if (key_klass) {
        g_type_class_unref(key_klass);
        return TRUE;
    }
    return FALSE;
}

static
void
foil_openssl_cipher_des_cbc_init_with_key(
    FoilCipher* cipher,
    FoilKey* key)
{
    FoilOpensslCipherDesCbc* self = FOIL_OPENSSL_CIPHER_DES_CBC(cipher);
    FOIL_CIPHER_CLASS(foil_openssl_cipher_des_cbc_parent_class)->
        fn_init_with_key(cipher, key);
    self->key = FOIL_OPENSSL_KEY_DES(key);
    cipher->input_block_size = FOIL_DES_BLOCK_SIZE;
    cipher->output_block_size = FOIL_DES_BLOCK_SIZE;
    memcpy(&self->ivec, self->key->super.iv, FOIL_DES_IV_SIZE);
}

static
void
foil_openssl_cipher_des_cbc_copy(
    FoilCipher* dest,
    FoilCipher* src)
{
    FoilOpensslCipherDesCbc* des_dest = FOIL_OPENSSL_CIPHER_DES_CBC(dest);
    FoilOpensslCipherDesCbc* des_src = FOIL_OPENSSL_CIPHER_DES_CBC(src);
    FOIL_CIPHER_CLASS(foil_openssl_cipher_des_cbc_parent_class)->
        fn_copy(dest, src);
    des_dest->key = FOIL_OPENSSL_KEY_DES(dest->key);
    memcpy(&des_dest->ivec, &des_src->ivec, FOIL_DES_BLOCK_SIZE);
}

static
int
foil_openssl_cipher_des_cbc_step(
    FoilCipher* cipher,
    const void* from,
    void* to)
{
    FoilOpensslCipherDesCbc* self = FOIL_OPENSSL_CIPHER_DES_CBC(cipher);
    FoilOpensslKeyDes* key = self->key;
    DES_key_schedule* ks2 = key->k2 ? &key->k2->ks : &key->k1->ks;
    DES_key_schedule* ks3 = key->k3 ? &key->k3->ks : &key->k1->ks;
    DES_ede3_cbc_encrypt(from, to, FOIL_DES_BLOCK_SIZE, &key->k1->ks, ks2, ks3,
        &self->ivec, FOIL_OPENSSL_CIPHER_DES_CBC_GET_CLASS(self)->op);
    return FOIL_DES_BLOCK_SIZE;
}

static
void
foil_openssl_cipher_des_cbc_init(
    FoilOpensslCipherDesCbc* self)
{
}

static
void
foil_openssl_cipher_des_cbc_class_init(
    FoilOpensslCipherDesCbcClass* klass)
{
    FoilCipherClass* cipher = FOIL_CIPHER_CLASS(klass);
    cipher->flags |= FOIL_CIPHER_SYMMETRIC;
    cipher->fn_supports_key = foil_openssl_cipher_des_cbc_supports_key;
    cipher->fn_init_with_key = foil_openssl_cipher_des_cbc_init_with_key;
    cipher->fn_copy = foil_openssl_cipher_des_cbc_copy;
    cipher->fn_step = foil_openssl_cipher_des_cbc_step;
    cipher->fn_finish = foil_cipher_symmetric_finish;
}

static
void
foil_openssl_cipher_des_cbc_encrypt_init(
    FoilOpensslCipherDesCbcEncrypt* self)
{
}

static
void
foil_openssl_cipher_des_cbc_encrypt_class_init(
    FoilOpensslCipherDesCbcEncryptClass* klass)
{
    FoilCipherClass* cipher = FOIL_CIPHER_CLASS(klass);
    cipher->name = "TDESCBC(Encrypt)";
    cipher->flags |= FOIL_CIPHER_ENCRYPT;
    klass->op = DES_ENCRYPT;
}

static
void
foil_openssl_cipher_des_cbc_decrypt_init(
    FoilOpensslCipherDesCbcDecrypt* self)
{
}

static
void
foil_openssl_cipher_des_cbc_decrypt_class_init(
    FoilOpensslCipherDesCbcDecryptClass* klass)
{
    FoilCipherClass* cipher = FOIL_CIPHER_CLASS(klass);
    cipher->name = "TDESCBC(Decrypt)";
    cipher->flags |= FOIL_CIPHER_DECRYPT;
    klass->op = DES_DECRYPT;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
