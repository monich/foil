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

#include "foil_cipher_sync.h"
#include "foil_openssl_rsa.h"

/* Logging */
#define GLOG_MODULE_NAME foil_log_cipher
#include "foil_log_p.h"

typedef FoilCipherClass FoilOpensslCipherRsaEncryptClass;
typedef struct foil_openssl_cipher_rsa_encrypt {
    FoilCipherSync sync;
    RSA* rsa;
    int rsa_size;
    int padding_size;
    int padding;
    int (*encrypt)(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa, int padding);
} FoilOpensslCipherRsaEncrypt;

G_DEFINE_TYPE(FoilOpensslCipherRsaEncrypt, foil_openssl_cipher_rsa_encrypt,
        FOIL_TYPE_CIPHER_SYNC)
#define FOIL_OPENSSL_TYPE_CIPHER_RSA_ENCRYPT \
        foil_openssl_cipher_rsa_encrypt_get_type()
#define FOIL_OPENSSL_CIPHER_RSA_ENCRYPT(obj) (G_TYPE_CHECK_INSTANCE_CAST(obj, \
        FOIL_OPENSSL_TYPE_CIPHER_RSA_ENCRYPT, FoilOpensslCipherRsaEncrypt))

#define SUPER_CLASS foil_openssl_cipher_rsa_encrypt_parent_class

GType
foil_impl_cipher_rsa_encrypt_get_type()
{
    return foil_openssl_cipher_rsa_encrypt_get_type();
}

static
gboolean
foil_openssl_cipher_rsa_encrypt_supports_key(
    FoilCipherClass* klass,
    GType key_type)
{
    return key_type == FOIL_OPENSSL_TYPE_KEY_RSA_PUBLIC ||
           key_type == FOIL_OPENSSL_TYPE_KEY_RSA_PRIVATE;
}

static
int
foil_openssl_cipher_rsa_encrypt_block(
    FoilCipher* cipher,
    const void* from,
    int flen,
    void* to)
{
    FoilOpensslCipherRsaEncrypt* self = FOIL_OPENSSL_CIPHER_RSA_ENCRYPT(cipher);
    int ret = self->encrypt(flen, from, to, self->rsa, self->padding);
    if (ret < 0) {
        if (GLOG_ENABLED(GLOG_LEVEL_ERR)) {
            ERR_load_crypto_strings();
            GERR("%s", ERR_error_string(ERR_get_error(), NULL));
        }
    }
    return ret;
}

static
int
foil_openssl_cipher_rsa_encrypt_step(
    FoilCipher* cipher,
    const void* from,
    void* to)
{
    return foil_openssl_cipher_rsa_encrypt_block(cipher, from,
        cipher->input_block_size, to);
}

static
void
foil_openssl_cipher_rsa_encrypt_post_init(
    FoilCipher* cipher)
{
    FoilOpensslCipherRsaEncrypt* self = FOIL_OPENSSL_CIPHER_RSA_ENCRYPT(cipher);
    if (FOIL_IS_KEY_RSA_PUBLIC(cipher->key)) {
        self->rsa = FOIL_OPENSSL_KEY_RSA_PUBLIC(cipher->key)->rsa;
        self->padding = RSA_PKCS1_OAEP_PADDING;
        self->padding_size = FOIL_RSA_PKCS1_OAEP_PADDING_SIZE;
        self->encrypt = RSA_public_encrypt;
    } else {
        self->rsa = FOIL_OPENSSL_KEY_RSA_PRIVATE(cipher->key)->rsa;
        self->padding = RSA_PKCS1_PADDING;
        self->padding_size = RSA_PKCS1_PADDING_SIZE + 1;
        self->encrypt = RSA_private_encrypt;
    }
    self->rsa_size = RSA_size(self->rsa);
    cipher->input_block_size = self->rsa_size - self->padding_size;
    cipher->output_block_size = self->rsa_size;
    FOIL_CIPHER_CLASS(SUPER_CLASS)->fn_post_init(cipher);
}

static
void
foil_openssl_cipher_rsa_encrypt_init(
    FoilOpensslCipherRsaEncrypt* self)
{
}

static
void
foil_openssl_cipher_rsa_encrypt_class_init(
    FoilOpensslCipherRsaEncryptClass* klass)
{
    FoilCipherClass* cipher = FOIL_CIPHER_CLASS(klass);
    cipher->name = "RSA(encrypt)";
    cipher->fn_supports_key = foil_openssl_cipher_rsa_encrypt_supports_key;
    cipher->fn_post_init = foil_openssl_cipher_rsa_encrypt_post_init;
    cipher->fn_step = foil_openssl_cipher_rsa_encrypt_step;
    cipher->fn_finish = foil_openssl_cipher_rsa_encrypt_block;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
