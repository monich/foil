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

#include "foil_cipher_aes.h"

/* Yes we know that this API is deprecated */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/aes.h>
#include <openssl/modes.h>

typedef struct foil_openssl_cipher_aes_decrypt {
    FoilCipherAes parent;
    AES_KEY aes;
} FoilOpensslCipherAesDecrypt;

typedef struct foil_openssl_cipher_aes_decrypt_class {
    FoilCipherAesClass parent;
    int (*fn_set_key)(const unsigned char* data, const int bits, AES_KEY *key);
    void (*fn_reset)(FoilOpensslCipherAesDecrypt* self);
} FoilOpensslCipherAesDecryptClass;

typedef struct foil_openssl_cipher_aes_ctr_decrypt {
    FoilOpensslCipherAesDecrypt parent;
    guint8 iv[FOIL_AES_BLOCK_SIZE];
} FoilOpensslCipherAesCtrDecrypt;

typedef FoilOpensslCipherAesDecryptClass FoilOpensslCipherAesCbcDecryptClass;
typedef FoilOpensslCipherAesDecryptClass FoilOpensslCipherAesCfbDecryptClass;
typedef FoilOpensslCipherAesDecryptClass FoilOpensslCipherAesCtrDecryptClass;
typedef FoilOpensslCipherAesDecryptClass FoilOpensslCipherAesEcbDecryptClass;
typedef FoilOpensslCipherAesDecrypt FoilOpensslCipherAesCbcDecrypt;
typedef FoilOpensslCipherAesDecrypt FoilOpensslCipherAesCfbDecrypt;
typedef FoilOpensslCipherAesDecrypt FoilOpensslCipherAesEcbDecrypt;

GType foil_openssl_cipher_aes_decrypt_get_type() FOIL_INTERNAL;
GType foil_openssl_cipher_aes_cbc_decrypt_get_type() FOIL_INTERNAL;
GType foil_openssl_cipher_aes_cfb_decrypt_get_type() FOIL_INTERNAL;
GType foil_openssl_cipher_aes_ctr_decrypt_get_type() FOIL_INTERNAL;
GType foil_openssl_cipher_aes_ecb_decrypt_get_type() FOIL_INTERNAL;

G_DEFINE_ABSTRACT_TYPE(FoilOpensslCipherAesDecrypt,
    foil_openssl_cipher_aes_decrypt, FOIL_TYPE_CIPHER_AES)

#define FOIL_TYPE_OPENSSL_CIPHER_AES_DECRYPT \
    foil_openssl_cipher_aes_decrypt_get_type()
#define FOIL_OPENSSL_CIPHER_AES_DECRYPT(obj) G_TYPE_CHECK_INSTANCE_CAST(obj, \
    FOIL_TYPE_OPENSSL_CIPHER_AES_DECRYPT, FoilOpensslCipherAesDecrypt)
#define FOIL_OPENSSL_CIPHER_AES_DECRYPT_CLASS(klass) \
    G_TYPE_CHECK_CLASS_CAST(klass, FOIL_TYPE_OPENSSL_CIPHER_AES_DECRYPT, \
    FoilOpensslCipherAesDecryptClass)
#define FOIL_OPENSSL_CIPHER_AES_DECRYPT_GET_CLASS(obj) \
    G_TYPE_INSTANCE_GET_CLASS(obj, FOIL_TYPE_OPENSSL_CIPHER_AES_DECRYPT, \
    FoilOpensslCipherAesDecryptClass)

#define FOIL_TYPE_OPENSSL_CIPHER_AES_CTR_DECRYPT \
    foil_openssl_cipher_aes_ctr_decrypt_get_type()
#define FOIL_OPENSSL_CIPHER_AES_CTR_DECRYPT(obj) \
    G_TYPE_CHECK_INSTANCE_CAST(obj, FOIL_TYPE_OPENSSL_CIPHER_AES_CTR_DECRYPT, \
    FoilOpensslCipherAesCtrDecrypt)

#define foil_openssl_cipher_aes_cbc_decrypt_init \
    foil_openssl_cipher_aes_decrypt_init
#define foil_openssl_cipher_aes_cfb_decrypt_init \
    foil_openssl_cipher_aes_decrypt_init
#define foil_openssl_cipher_aes_ecb_decrypt_init \
    foil_openssl_cipher_aes_decrypt_init

G_DEFINE_TYPE(FoilOpensslCipherAesCbcDecrypt,
    foil_openssl_cipher_aes_cbc_decrypt, FOIL_TYPE_OPENSSL_CIPHER_AES_DECRYPT)
G_DEFINE_TYPE(FoilOpensslCipherAesCfbDecrypt,
    foil_openssl_cipher_aes_cfb_decrypt, FOIL_TYPE_OPENSSL_CIPHER_AES_DECRYPT)
G_DEFINE_TYPE(FoilOpensslCipherAesCtrDecrypt,
    foil_openssl_cipher_aes_ctr_decrypt, FOIL_TYPE_OPENSSL_CIPHER_AES_DECRYPT)
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

GType foil_impl_cipher_aes_ctr_decrypt_get_type()
{
    return foil_openssl_cipher_aes_ctr_decrypt_get_type();
}

GType foil_impl_cipher_aes_ecb_decrypt_get_type()
{
    return foil_openssl_cipher_aes_ecb_decrypt_get_type();
}

static
int
foil_openssl_cipher_aes_cbc_decrypt_step(
    FoilCipher* cipher,
    const void* in,
    void* out)
{
    FoilOpensslCipherAesDecrypt* self = FOIL_OPENSSL_CIPHER_AES_DECRYPT(cipher);
    AES_cbc_encrypt(in, out, FOIL_AES_BLOCK_SIZE, &self->aes,
        self->parent.block, AES_DECRYPT);
    return FOIL_AES_BLOCK_SIZE;
}

static
int
foil_openssl_cipher_aes_cfb_decrypt_step(
    FoilCipher* cipher,
    const void* in,
    void* out)
{
    int num = 0;
    FoilOpensslCipherAesDecrypt* self = FOIL_OPENSSL_CIPHER_AES_DECRYPT(cipher);
    AES_cfb128_encrypt(in, out, FOIL_AES_BLOCK_SIZE, &self->aes,
        self->parent.block, &num, AES_DECRYPT);
    return FOIL_AES_BLOCK_SIZE;
}

static
int
foil_openssl_cipher_aes_ctr_decrypt_step(
    FoilCipher* cipher,
    const void* in,
    void* out)
{
    unsigned int num = 0;
    FoilOpensslCipherAesCtrDecrypt* self =
        FOIL_OPENSSL_CIPHER_AES_CTR_DECRYPT(cipher);
    CRYPTO_ctr128_encrypt(in, out, FOIL_AES_BLOCK_SIZE, &self->parent.aes,
        self->iv, self->parent.parent.block, &num, (block128_f) AES_encrypt);
    return FOIL_AES_BLOCK_SIZE;
}

static
int
foil_openssl_cipher_aes_ecb_decrypt_step(
    FoilCipher* cipher,
    const void* in,
    void* out)
{
    FoilOpensslCipherAesDecrypt* self = FOIL_OPENSSL_CIPHER_AES_DECRYPT(cipher);
    AES_ecb_encrypt(in, out, &self->aes, AES_DECRYPT);
    return FOIL_AES_BLOCK_SIZE;
}

static
void
foil_openssl_cipher_aes_decrypt_reset(
    FoilOpensslCipherAesDecrypt* self)
{
    FoilKey* key = FOIL_CIPHER(self)->key;
    FoilKeyAes* aes_key = FOIL_KEY_AES_(key);
    int result = FOIL_OPENSSL_CIPHER_AES_DECRYPT_GET_CLASS(self)->fn_set_key(aes_key->key,
        FOIL_KEY_AES_GET_CLASS(key)->size * 8, &self->aes);
    if (result<0) {
		self->parent.cipher.key = NULL;
		self->parent.cipher.input_block_size = 0;
		self->parent.cipher.output_block_size = 0;
    }
}

static
void
foil_openssl_cipher_aes_ctr_decrypt_reset(
    FoilOpensslCipherAesDecrypt* aes)
{
    FoilKey* key = FOIL_CIPHER(aes)->key;
    FoilOpensslCipherAesCtrDecrypt* self =
        FOIL_OPENSSL_CIPHER_AES_CTR_DECRYPT(aes);
    FOIL_OPENSSL_CIPHER_AES_DECRYPT_CLASS
        (foil_openssl_cipher_aes_ctr_decrypt_parent_class)->
            fn_reset(&self->parent);
    memcpy(self->iv, FOIL_KEY_AES_(key)->iv, FOIL_AES_BLOCK_SIZE);
}

static
void
foil_openssl_cipher_aes_decrypt_init_with_key(
    FoilCipher* cipher,
    FoilKey* key)
{
    FOIL_CIPHER_CLASS(foil_openssl_cipher_aes_decrypt_parent_class)->
        fn_init_with_key(cipher, key);
    FOIL_OPENSSL_CIPHER_AES_DECRYPT_GET_CLASS(cipher)->fn_reset
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
    FOIL_OPENSSL_CIPHER_AES_DECRYPT_GET_CLASS(dest)->fn_reset
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
foil_openssl_cipher_aes_ctr_decrypt_init(
    FoilOpensslCipherAesCtrDecrypt* self)
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
    klass->fn_reset = foil_openssl_cipher_aes_decrypt_reset;
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
foil_openssl_cipher_aes_ctr_decrypt_class_init(
    FoilOpensslCipherAesCfbDecryptClass* klass)
{
    FoilCipherClass* cipher = FOIL_CIPHER_CLASS(klass);
    cipher->name = "AESCTR(Decrypt)";
    cipher->fn_step = foil_openssl_cipher_aes_ctr_decrypt_step;
    klass->fn_set_key = AES_set_encrypt_key;
    klass->fn_reset = foil_openssl_cipher_aes_ctr_decrypt_reset;
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
