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

typedef struct foil_openssl_cipher_aes_cbc_decrypt {
    FoilCipherAes cipher_aes;
    AES_KEY aes;
} FoilOpensslCipherAesCbcDecrypt;

typedef FoilCipherAesClass FoilOpensslCipherAesCbcDecryptClass;
#define PARENT_CLASS foil_openssl_cipher_aes_cbc_decrypt_parent_class
G_DEFINE_TYPE(FoilOpensslCipherAesCbcDecrypt,
    foil_openssl_cipher_aes_cbc_decrypt, FOIL_TYPE_CIPHER_AES)
#define FOIL_OPENSSL_CIPHER_AES_CBC_DECRYPT(obj) \
    G_TYPE_CHECK_INSTANCE_CAST(obj, \
    foil_openssl_cipher_aes_cbc_decrypt_get_type(), \
    FoilOpensslCipherAesCbcDecrypt)

GType foil_impl_cipher_aes_cbc_decrypt_get_type()
{
    return foil_openssl_cipher_aes_cbc_decrypt_get_type();
}

static
int
foil_openssl_cipher_aes_cbc_decrypt_step(
    FoilCipher* cipher,
    const void* from,
    void* to)
{
    FoilOpensslCipherAesCbcDecrypt* self =
        FOIL_OPENSSL_CIPHER_AES_CBC_DECRYPT(cipher);
    AES_cbc_encrypt(from, to, FOIL_AES_BLOCK_SIZE, &self->aes,
        self->cipher_aes.block, AES_DECRYPT);
    return FOIL_AES_BLOCK_SIZE;
}

static
void
foil_openssl_cipher_aes_cbc_decrypt_post_init(
    FoilCipher* cipher)
{
    FoilOpensslCipherAesCbcDecrypt* self =
        FOIL_OPENSSL_CIPHER_AES_CBC_DECRYPT(cipher);
    FoilKeyAes* aes_key = FOIL_KEY_AES_(cipher->key);
    const int bits = FOIL_KEY_AES_GET_CLASS(cipher->key)->size*8;
    AES_set_decrypt_key(aes_key->key, bits, &self->aes);
    FOIL_CIPHER_CLASS(PARENT_CLASS)->fn_post_init(cipher);
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
    /* Padding makes no sense if we are decrypting */
    cipher->fn_set_padding_func = NULL;
    cipher->fn_step = foil_openssl_cipher_aes_cbc_decrypt_step;
    cipher->fn_post_init = foil_openssl_cipher_aes_cbc_decrypt_post_init;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
