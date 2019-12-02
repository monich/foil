/*
 * Copyright (C) 2016-2019 by Slava Monich
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

#include "foil_cipher_aes.h"

#include <openssl/aes.h>

typedef struct foil_openssl_cipher_decrypt_class {
    FoilCipherAesClass aes;
    int (*fn_set_key)(const unsigned char* data, const int bits, AES_KEY *key);
} FoilOpensslCipherAesDecryptClass;

typedef struct foil_openssl_cipher_decrypt {
    FoilCipherAes cipher_aes;
    AES_KEY aes;
} FoilOpensslCipherAesDecrypt;

typedef FoilOpensslCipherAesDecryptClass FoilOpensslCipherAesCbcDecryptClass;
typedef FoilOpensslCipherAesDecryptClass FoilOpensslCipherAesCfbDecryptClass;
typedef FoilOpensslCipherAesDecryptClass FoilOpensslCipherAesEcbDecryptClass;
typedef FoilOpensslCipherAesDecrypt FoilOpensslCipherAesCbcDecrypt;
typedef FoilOpensslCipherAesDecrypt FoilOpensslCipherAesCfbDecrypt;
typedef FoilOpensslCipherAesDecrypt FoilOpensslCipherAesEcbDecrypt;

G_DEFINE_ABSTRACT_TYPE(FoilOpensslCipherAesDecrypt,
    foil_openssl_cipher_aes_decrypt, FOIL_TYPE_CIPHER_AES)

#define FOIL_TYPE_OPENSSL_CIPHER_AES_DECRYPT \
    foil_openssl_cipher_aes_decrypt_get_type()
#define FOIL_OPENSSL_CIPHER_AES_DECRYPT(obj) G_TYPE_CHECK_INSTANCE_CAST(obj, \
    FOIL_TYPE_OPENSSL_CIPHER_AES_DECRYPT, FoilOpensslCipherAesDecrypt)
#define FOIL_OPENSSL_CIPHER_AES_DECRYPT_GET_CLASS(obj) \
    G_TYPE_INSTANCE_GET_CLASS(obj, FOIL_TYPE_OPENSSL_CIPHER_AES_DECRYPT, \
    FoilOpensslCipherAesDecryptClass)

G_DEFINE_TYPE(FoilOpensslCipherAesCbcDecrypt,
    foil_openssl_cipher_aes_cbc_decrypt, FOIL_TYPE_OPENSSL_CIPHER_AES_DECRYPT)
G_DEFINE_TYPE(FoilOpensslCipherAesCfbDecrypt,
    foil_openssl_cipher_aes_cfb_decrypt, FOIL_TYPE_OPENSSL_CIPHER_AES_DECRYPT)
G_DEFINE_TYPE(FoilOpensslCipherAesEcbDecrypt,
    foil_openssl_cipher_aes_ecb_decrypt, FOIL_TYPE_OPENSSL_CIPHER_AES_DECRYPT)

GType foil_impl_cipher_aes_cbc_decrypt_get_type()
{
    return foil_openssl_cipher_aes_cbc_decrypt_get_type();
}

GType foil_impl_cipher_aes_cfb_decrypt_get_type()
{
    return foil_openssl_cipher_aes_cfb_decrypt_get_type();
}

GType foil_impl_cipher_aes_ecb_decrypt_get_type()
{
    return foil_openssl_cipher_aes_ecb_decrypt_get_type();
}

static
int
foil_openssl_cipher_aes_cbc_decrypt_step(
    FoilCipher* cipher,
    const void* from,
    void* to)
{
    FoilOpensslCipherAesDecrypt* self = FOIL_OPENSSL_CIPHER_AES_DECRYPT(cipher);
    AES_cbc_encrypt(from, to, FOIL_AES_BLOCK_SIZE, &self->aes,
        self->cipher_aes.block, AES_DECRYPT);
    return FOIL_AES_BLOCK_SIZE;
}

static
int
foil_openssl_cipher_aes_cfb_decrypt_step(
    FoilCipher* cipher,
    const void* from,
    void* to)
{
    int num = 0;
    FoilOpensslCipherAesDecrypt* self = FOIL_OPENSSL_CIPHER_AES_DECRYPT(cipher);
    AES_cfb128_encrypt(from, to, FOIL_AES_BLOCK_SIZE, &self->aes,
        self->cipher_aes.block, &num, AES_DECRYPT);
    return FOIL_AES_BLOCK_SIZE;
}

static
int
foil_openssl_cipher_aes_ecb_decrypt_step(
    FoilCipher* cipher,
    const void* from,
    void* to)
{
    FoilOpensslCipherAesDecrypt* self = FOIL_OPENSSL_CIPHER_AES_DECRYPT(cipher);
    AES_ecb_encrypt(from, to, &self->aes, AES_DECRYPT);
    return FOIL_AES_BLOCK_SIZE;
}

static
void
foil_openssl_cipher_aes_decrypt_reset(
    FoilOpensslCipherAesDecrypt* self)
{
    FoilKey* key = FOIL_CIPHER(self)->key;
    FoilKeyAes* aes_key = FOIL_KEY_AES_(key);
    FOIL_OPENSSL_CIPHER_AES_DECRYPT_GET_CLASS(self)->fn_set_key(aes_key->key,
        FOIL_KEY_AES_GET_CLASS(key)->size * 8, &self->aes);
}

static
void
foil_openssl_cipher_aes_decrypt_init_with_key(
    FoilCipher* cipher,
    FoilKey* key)
{
    FOIL_CIPHER_CLASS(foil_openssl_cipher_aes_decrypt_parent_class)->
        fn_init_with_key(cipher, key);
    foil_openssl_cipher_aes_decrypt_reset
        (FOIL_OPENSSL_CIPHER_AES_DECRYPT(cipher));
}

static
void
foil_openssl_cipher_aes_decrypt_copy(
    FoilCipher* dest,
    FoilCipher* src)
{
    FOIL_CIPHER_CLASS(foil_openssl_cipher_aes_decrypt_parent_class)->
        fn_copy(dest, src);
    foil_openssl_cipher_aes_decrypt_reset
        (FOIL_OPENSSL_CIPHER_AES_DECRYPT(dest));
}

static
void
foil_openssl_cipher_aes_decrypt_init(
    FoilOpensslCipherAesDecrypt* self)
{
}

static
void
foil_openssl_cipher_aes_decrypt_class_init(
    FoilOpensslCipherAesDecryptClass* klass)
{
    FoilCipherClass* cipher = FOIL_CIPHER_CLASS(klass);
    cipher->name = "AES(Decrypt)";
    cipher->flags |= FOIL_CIPHER_DECRYPT;
    cipher->fn_init_with_key = foil_openssl_cipher_aes_decrypt_init_with_key;
    cipher->fn_copy = foil_openssl_cipher_aes_decrypt_copy;
    klass->fn_set_key = AES_set_decrypt_key;
}

static
void
foil_openssl_cipher_aes_cbc_decrypt_init(
    FoilOpensslCipherAesCbcDecrypt* self)
{
}

static
void
foil_openssl_cipher_aes_cbc_decrypt_class_init(
    FoilOpensslCipherAesCbcDecryptClass* klass)
{
    FoilCipherClass* cipher = FOIL_CIPHER_CLASS(klass);
    cipher->name = "AESCBC(Decrypt)";
    cipher->fn_step = foil_openssl_cipher_aes_cbc_decrypt_step;
}

static
void
foil_openssl_cipher_aes_cfb_decrypt_init(
    FoilOpensslCipherAesCfbDecrypt* self)
{
}

static
void
foil_openssl_cipher_aes_cfb_decrypt_class_init(
    FoilOpensslCipherAesCfbDecryptClass* klass)
{
    FoilCipherClass* cipher = FOIL_CIPHER_CLASS(klass);
    cipher->name = "AESCFB(Decrypt)";
    cipher->fn_step = foil_openssl_cipher_aes_cfb_decrypt_step;
    klass->fn_set_key = AES_set_encrypt_key;
}

static
void
foil_openssl_cipher_aes_ecb_decrypt_init(
    FoilOpensslCipherAesEcbDecrypt* self)
{
}

static
void
foil_openssl_cipher_aes_ecb_decrypt_class_init(
    FoilOpensslCipherAesEcbDecryptClass* klass)
{
    FoilCipherClass* cipher = FOIL_CIPHER_CLASS(klass);
    cipher->name = "AESECB(Decrypt)";
    cipher->fn_step = foil_openssl_cipher_aes_ecb_decrypt_step;
}
/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
