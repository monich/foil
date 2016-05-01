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

#include "foil_cipher_aes.h"

#include <openssl/aes.h>

typedef struct foil_openssl_cipher_aes_cbc_encrypt {
    FoilCipherAes cipher_aes;
    AES_KEY aes;
} FoilOpensslCipherAesCbcEncrypt;

typedef FoilCipherAesClass FoilOpensslCipherAesCbcEncryptClass;
#define PARENT_CLASS foil_openssl_cipher_aes_cbc_encrypt_parent_class
G_DEFINE_TYPE(FoilOpensslCipherAesCbcEncrypt,
    foil_openssl_cipher_aes_cbc_encrypt, FOIL_TYPE_CIPHER_AES)
#define FOIL_OPENSSL_CIPHER_AES_CBC_ENCRYPT(obj) \
    G_TYPE_CHECK_INSTANCE_CAST(obj, \
    foil_openssl_cipher_aes_cbc_encrypt_get_type(), \
    FoilOpensslCipherAesCbcEncrypt)

GType foil_impl_cipher_aes_cbc_encrypt_get_type()
{
    return foil_openssl_cipher_aes_cbc_encrypt_get_type();
}

static
int
foil_openssl_cipher_aes_cbc_encrypt_step(
    FoilCipher* cipher,
    const void* from,
    void* to)
{
    FoilOpensslCipherAesCbcEncrypt* self =
        FOIL_OPENSSL_CIPHER_AES_CBC_ENCRYPT(cipher);
    AES_cbc_encrypt(from, to, FOIL_AES_BLOCK_SIZE, &self->aes,
        self->cipher_aes.block, AES_ENCRYPT);
    return FOIL_AES_BLOCK_SIZE;
}

static
void
foil_openssl_cipher_aes_cbc_encrypt_post_init(
    FoilCipher* cipher)
{
    FoilOpensslCipherAesCbcEncrypt* self =
        FOIL_OPENSSL_CIPHER_AES_CBC_ENCRYPT(cipher);
    FoilKeyAes* aes_key = FOIL_KEY_AES_(cipher->key);
    const int bits = FOIL_KEY_AES_GET_CLASS(cipher->key)->size*8;
    AES_set_encrypt_key(aes_key->key, bits, &self->aes);
    FOIL_CIPHER_CLASS(PARENT_CLASS)->fn_post_init(cipher);
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
    cipher->fn_post_init = foil_openssl_cipher_aes_cbc_encrypt_post_init;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
