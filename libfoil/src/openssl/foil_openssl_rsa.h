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

#ifndef FOIL_OPENSSL_RSA_H
#define FOIL_OPENSSL_RSA_H

#include "foil_cipher_sync.h"
#include "foil_key_rsa_public.h"
#include "foil_key_rsa_private.h"

#include <openssl/rsa.h>
#include <openssl/err.h>

typedef FoilCipherClass FoilOpensslCipherRsaClass;
typedef struct foil_openssl_cipher_rsa {
    FoilCipherSync sync;
    int padding_size;
    int padding;
    RSA* rsa;
    RSA* (*dup)(RSA *rsa);
    int (*proc)(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa, int padding);
} FoilOpensslCipherRsa;

GType foil_openssl_cipher_rsa_get_type(void);
#define FOIL_OPENSSL_TYPE_CIPHER_RSA foil_openssl_cipher_rsa_get_type()

typedef FoilKeyRsaPrivate FoilOpensslKeyRsaPrivate;
GType foil_openssl_key_rsa_private_get_type(void);
#define FOIL_OPENSSL_TYPE_KEY_RSA_PRIVATE \
    foil_openssl_key_rsa_private_get_type()

void
foil_openssl_key_rsa_private_apply(
    FoilKeyRsaPrivate* priv,
    RSA* rsa);

void
foil_openssl_key_rsa_public_apply(
    FoilKeyRsaPublic* pub,
    RSA* rsa);

/* Getters for RSA fields */

const BIGNUM*
foil_openssl_rsa_get_n(
    const RSA* rsa);

const BIGNUM*
foil_openssl_rsa_get_e(
    const RSA* rsa);

const BIGNUM*
foil_openssl_rsa_get_d(
    const RSA* rsa);

const BIGNUM*
foil_openssl_rsa_get_p(
    const RSA* rsa);

const BIGNUM*
foil_openssl_rsa_get_q(
    const RSA* rsa);

const BIGNUM*
foil_openssl_rsa_get_dmp1(
    const RSA* rsa);

const BIGNUM*
foil_openssl_rsa_get_dmq1(
    const RSA* rsa);

const BIGNUM*
foil_openssl_rsa_get_iqmp(
    const RSA* rsa);

/* Setters for RSA fields */

const BIGNUM*
foil_openssl_rsa_set_n(
    RSA* rsa,
    const FoilBytes* bytes);

const BIGNUM*
foil_openssl_rsa_set_e(
    RSA* rsa,
    const FoilBytes* bytes);

const BIGNUM*
foil_openssl_rsa_set_d(
    RSA* rsa,
    const FoilBytes* bytes);

const BIGNUM*
foil_openssl_rsa_set_p(
    RSA* rsa,
    const FoilBytes* bytes);

const BIGNUM*
foil_openssl_rsa_set_q(
    RSA* rsa,
    const FoilBytes* bytes);

const BIGNUM*
foil_openssl_rsa_set_dmp1(
    RSA* rsa,
    const FoilBytes* bytes);

const BIGNUM*
foil_openssl_rsa_set_dmq1(
    RSA* rsa,
    const FoilBytes* bytes);

const BIGNUM*
foil_openssl_rsa_set_iqmp(
    RSA* rsa,
    const FoilBytes* bytes);

#define FOIL_RSA_FIELD(rsa,x) foil_openssl_rsa_get_##x(rsa)
#define FOIL_RSA_KEY_SET_BN(rsa,x,data) foil_openssl_rsa_set_##x(rsa, &(data)->x)

#define FOIL_RSA_PKCS1_OAEP_PADDING_SIZE 42

#endif /* FOIL_OPENSSL_RSA_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
