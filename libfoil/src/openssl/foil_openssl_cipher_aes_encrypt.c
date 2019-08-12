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

typedef struct foil_openssl_cipher_encrypt {
    FoilCipherAes cipher_aes;
    AES_KEY aes;
} FoilOpensslCipherAesEncrypt;

typedef FoilCipherAesClass FoilOpensslCipherAesEncryptClass;
typedef FoilOpensslCipherAesEncryptClass FoilOpensslCipherAesCbcEncryptClass;
typedef FoilOpensslCipherAesEncryptClass FoilOpensslCipherAesEcbEncryptClass;
typedef FoilOpensslCipherAesEncrypt FoilOpensslCipherAesCbcEncrypt;
typedef FoilOpensslCipherAesEncrypt FoilOpensslCipherAesEcbEncrypt;

G_DEFINE_ABSTRACT_TYPE(FoilOpensslCipherAesEncrypt,
    foil_openssl_cipher_aes_encrypt, FOIL_TYPE_CIPHER_AES)

#define FOIL_TYPE_OPENSSL_CIPHER_AES_ENCRYPT \
    foil_openssl_cipher_aes_encrypt_get_type()
#define FOIL_OPENSSL_CIPHER_AES_ENCRYPT(obj) G_TYPE_CHECK_INSTANCE_CAST(obj, \
    FOIL_TYPE_OPENSSL_CIPHER_AES_ENCRYPT, FoilOpensslCipherAesEncrypt)

G_DEFINE_TYPE(FoilOpensslCipherAesCbcEncrypt,
    foil_openssl_cipher_aes_cbc_encrypt, FOIL_TYPE_OPENSSL_CIPHER_AES_ENCRYPT)
G_DEFINE_TYPE(FoilOpensslCipherAesEcbEncrypt,
    foil_openssl_cipher_aes_ecb_encrypt, FOIL_TYPE_OPENSSL_CIPHER_AES_ENCRYPT)

GType foil_impl_cipher_aes_cbc_encrypt_get_type()
{
    return foil_openssl_cipher_aes_cbc_encrypt_get_type();
}

GType foil_impl_cipher_aes_ecb_encrypt_get_type()
{
    return foil_openssl_cipher_aes_ecb_encrypt_get_type();
}

static
int
foil_openssl_cipher_aes_cbc_encrypt_step(
    FoilCipher* cipher,
    const void* from,
    void* to)
{
    FoilOpensslCipherAesEncrypt* self = FOIL_OPENSSL_CIPHER_AES_ENCRYPT(cipher);
    AES_cbc_encrypt(from, to, FOIL_AES_BLOCK_SIZE, &self->aes,
        self->cipher_aes.block, AES_ENCRYPT);
    return FOIL_AES_BLOCK_SIZE;
}

static
int
foil_openssl_cipher_aes_ecb_encrypt_step(
    FoilCipher* cipher,
    const void* from,
    void* to)
{
    FoilOpensslCipherAesEncrypt* self = FOIL_OPENSSL_CIPHER_AES_ENCRYPT(cipher);
    AES_ecb_encrypt(from, to, &self->aes, AES_ENCRYPT);
    return FOIL_AES_BLOCK_SIZE;
}

static
void
foil_openssl_cipher_aes_encrypt_reset(
    FoilOpensslCipherAesEncrypt* self)
{
    FoilKey* key = FOIL_CIPHER(self)->key;
    AES_set_encrypt_key(FOIL_KEY_AES_(key)->key,
        FOIL_KEY_AES_GET_CLASS(key)->size * 8, &self->aes);
}

static
void
foil_openssl_cipher_aes_encrypt_init_with_key(
    FoilCipher* cipher,
    FoilKey* key)
{
    FOIL_CIPHER_CLASS(foil_openssl_cipher_aes_encrypt_parent_class)->
        fn_init_with_key(cipher, key);
    foil_openssl_cipher_aes_encrypt_reset
        (FOIL_OPENSSL_CIPHER_AES_ENCRYPT(cipher));
}

static
void
foil_openssl_cipher_aes_encrypt_copy(
    FoilCipher* dest,
    FoilCipher* src)
{
    FOIL_CIPHER_CLASS(foil_openssl_cipher_aes_encrypt_parent_class)->
        fn_copy(dest, src);
    foil_openssl_cipher_aes_encrypt_reset
        (FOIL_OPENSSL_CIPHER_AES_ENCRYPT(dest));
}

static
void
foil_openssl_cipher_aes_encrypt_init(
    FoilOpensslCipherAesCbcEncrypt* self)
{
}

static
void
foil_openssl_cipher_aes_encrypt_class_init(
    FoilOpensslCipherAesEncryptClass* klass)
{
    FoilCipherClass* cipher = FOIL_CIPHER_CLASS(klass);
    cipher->name = "AES(Encrypt)";
    cipher->flags |= FOIL_CIPHER_ENCRYPT;
    cipher->fn_init_with_key = foil_openssl_cipher_aes_encrypt_init_with_key;
    cipher->fn_copy = foil_openssl_cipher_aes_encrypt_copy;
}

static
void
foil_openssl_cipher_aes_cbc_encrypt_init(
    FoilOpensslCipherAesCbcEncrypt* self)
{
}

static
void
foil_openssl_cipher_aes_cbc_encrypt_class_init(
    FoilOpensslCipherAesCbcEncryptClass* klass)
{
    FoilCipherClass* cipher = FOIL_CIPHER_CLASS(klass);
    cipher->name = "AESCBC(Encrypt)";
    cipher->fn_step = foil_openssl_cipher_aes_cbc_encrypt_step;
}

static
void
foil_openssl_cipher_aes_ecb_encrypt_init(
    FoilOpensslCipherAesEcbEncrypt* self)
{
}

static
void
foil_openssl_cipher_aes_ecb_encrypt_class_init(
    FoilOpensslCipherAesEcbEncryptClass* klass)
{
    FoilCipherClass* cipher = FOIL_CIPHER_CLASS(klass);
    cipher->name = "AESECB(Encrypt)";
    cipher->fn_step = foil_openssl_cipher_aes_ecb_encrypt_step;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
