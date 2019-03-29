/*
 * Copyright (C) 2016-2019 by Slava Monich
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

G_DEFINE_ABSTRACT_TYPE(FoilOpensslCipherRsa, foil_openssl_cipher_rsa,
        FOIL_TYPE_CIPHER_SYNC)
#define FOIL_OPENSSL_CIPHER_RSA(obj) (G_TYPE_CHECK_INSTANCE_CAST(obj, \
        FOIL_OPENSSL_TYPE_CIPHER_RSA, FoilOpensslCipherRsa))

#define SUPER_CLASS foil_openssl_cipher_rsa_parent_class

static
gboolean
foil_openssl_cipher_rsa_supports_key(
    FoilCipherClass* klass,
    GType key_type)
{
    if (key_type) {
        GTypeClass* klass = g_type_class_ref(key_type);
        if (klass) {
            const gboolean is_rsa_key =
                G_TYPE_CHECK_CLASS_TYPE(klass, FOIL_TYPE_KEY_RSA_PUBLIC) ||
                G_TYPE_CHECK_CLASS_TYPE(klass, FOIL_TYPE_KEY_RSA_PRIVATE);
            g_type_class_unref(klass);
            return is_rsa_key;
        }
    }
    return FALSE;
}

static
int
foil_openssl_cipher_rsa_block(
    FoilCipher* cipher,
    const void* from,
    int flen,
    void* to)
{
    FoilOpensslCipherRsa* self = FOIL_OPENSSL_CIPHER_RSA(cipher);
    int ret = self->proc(flen, from, to, self->rsa, self->padding);
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
foil_openssl_cipher_rsa_step(
    FoilCipher* cipher,
    const void* from,
    void* to)
{
    return foil_openssl_cipher_rsa_block(cipher, from,
        cipher->input_block_size, to);
}

static
void
foil_openssl_cipher_rsa_copy(
    FoilCipher* cipher,
    FoilCipher* src)
{
    FoilOpensslCipherRsa* self = FOIL_OPENSSL_CIPHER_RSA(cipher);
    FoilOpensslCipherRsa* that = FOIL_OPENSSL_CIPHER_RSA(src);
    FOIL_CIPHER_CLASS(SUPER_CLASS)->fn_copy(cipher, src);
    RSA_free(self->rsa);
    self->rsa = that->dup(that->rsa);
    self->padding = that->padding;
    self->padding_size = that->padding_size;
    self->proc = that->proc;
    self->dup = that->dup;
}

static
void
foil_openssl_cipher_rsa_finalize(
    GObject* object)
{
    FoilOpensslCipherRsa* self = FOIL_OPENSSL_CIPHER_RSA(object);
    RSA_free(self->rsa);
    G_OBJECT_CLASS(SUPER_CLASS)->finalize(object);
}

static
void
foil_openssl_cipher_rsa_init(
    FoilOpensslCipherRsa* self)
{
    self->rsa = RSA_new();
}

static
void
foil_openssl_cipher_rsa_class_init(
    FoilOpensslCipherRsaClass* klass)
{
    FoilCipherClass* cipher = FOIL_CIPHER_CLASS(klass);
    cipher->name = "RSA";
    cipher->fn_supports_key = foil_openssl_cipher_rsa_supports_key;
    cipher->fn_copy = foil_openssl_cipher_rsa_copy;
    cipher->fn_step = foil_openssl_cipher_rsa_step;
    cipher->fn_finish = foil_openssl_cipher_rsa_block;
    G_OBJECT_CLASS(klass)->finalize = foil_openssl_cipher_rsa_finalize;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
