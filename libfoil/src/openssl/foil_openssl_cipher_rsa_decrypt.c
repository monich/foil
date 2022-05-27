/*
 * Copyright (C) 2016-2022 by Slava Monich
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

#include "foil_cipher_sync.h"
#include "foil_openssl_rsa.h"

/* Logging */
#define GLOG_MODULE_NAME foil_log_cipher
#include "foil_log_p.h"

typedef FoilOpensslCipherRsaClass FoilOpensslCipherRsaDecryptClass;
typedef FoilOpensslCipherRsa FoilOpensslCipherRsaDecrypt;

GType foil_openssl_cipher_rsa_decrypt_get_type() FOIL_INTERNAL;

G_DEFINE_TYPE(FoilOpensslCipherRsaDecrypt, foil_openssl_cipher_rsa_decrypt,
        FOIL_OPENSSL_TYPE_CIPHER_RSA)
#define FOIL_OPENSSL_TYPE_CIPHER_RSA_DECRYPT \
        foil_openssl_cipher_rsa_decrypt_get_type()
#define FOIL_OPENSSL_CIPHER_RSA_DECRYPT(obj) (G_TYPE_CHECK_INSTANCE_CAST(obj, \
        FOIL_OPENSSL_TYPE_CIPHER_RSA_DECRYPT, FoilOpensslCipherRsaDecrypt))

#define SUPER_CLASS foil_openssl_cipher_rsa_decrypt_parent_class

GType
foil_impl_cipher_rsa_decrypt_get_type()
{
    return foil_openssl_cipher_rsa_decrypt_get_type();
}

static
void
foil_openssl_cipher_rsa_decrypt_init_with_key(
    FoilCipher* cipher,
    FoilKey* key)
{
    FoilOpensslCipherRsaDecrypt* self = FOIL_OPENSSL_CIPHER_RSA_DECRYPT(cipher);
    FOIL_CIPHER_CLASS(SUPER_CLASS)->fn_init_with_key(cipher, key);
    if (FOIL_IS_KEY_RSA_PUBLIC(key)) {
        self->padding = RSA_PKCS1_PADDING;
        self->padding_size = RSA_PKCS1_PADDING_SIZE + 1;
        self->dup = RSAPublicKey_dup;
        self->proc = RSA_public_decrypt;
        foil_openssl_key_rsa_public_apply(FOIL_KEY_RSA_PUBLIC_(key),
            self->rsa);
    } else {
        self->padding = RSA_PKCS1_OAEP_PADDING;
        self->padding_size = FOIL_RSA_PKCS1_OAEP_PADDING_SIZE;
        self->dup = RSAPrivateKey_dup;
        self->proc = RSA_private_decrypt;
        foil_openssl_key_rsa_private_apply(FOIL_KEY_RSA_PRIVATE_(key),
            self->rsa);
    }
    cipher->input_block_size =
    cipher->output_block_size = RSA_size(self->rsa);
}

static
int
foil_openssl_cipher_rsa_decrypt_finish(
    FoilCipher* cipher,
    const void* from,
    int flen,
    void* to)
{
    return (flen > 0) ? FOIL_CIPHER_CLASS(SUPER_CLASS)->
        fn_finish(cipher, from, flen, to) : 0;
}

void
foil_openssl_cipher_rsa_decrypt_init(
    FoilOpensslCipherRsaDecrypt* self)
{
}

static
void
foil_openssl_cipher_rsa_decrypt_class_init(
    FoilOpensslCipherRsaDecryptClass* klass)
{
    FoilCipherClass* cipher = FOIL_CIPHER_CLASS(klass);
    cipher->name = "RSA(decrypt)";
    cipher->flags |= FOIL_CIPHER_DECRYPT;
    cipher->fn_init_with_key = foil_openssl_cipher_rsa_decrypt_init_with_key;
    cipher->fn_finish = foil_openssl_cipher_rsa_decrypt_finish;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
