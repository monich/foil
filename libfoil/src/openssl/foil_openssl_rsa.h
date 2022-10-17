/*
 * Copyright (C) 2016-2022 by Slava Monich
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *   3. Neither the names of the copyright holders nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

/*
 * Accessors (if present at all) may have slightly different
 * prototypes, with different const qualifiers.
 */
#define RSA_set0_key RSA_set0_key_
#define RSA_set0_factors RSA_set0_factors_
#define RSA_set0_crt_params RSA_set0_crt_params_
#define RSA_get0_key RSA_get0_key_
#define RSA_get0_factors RSA_get0_factors_
#define RSA_get0_crt_params RSA_get0_crt_params_
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/rsa.h>
#include <openssl/err.h>

#undef RSA_set0_key
#undef RSA_set0_factors
#undef RSA_set0_crt_params
#undef RSA_get0_key
#undef RSA_get0_factors
#undef RSA_get0_crt_params

#if OPENSSL_API_LEVEL >= 30000
#  define RSA_CONST_PTR_3 const RSA*
#else
#  define RSA_CONST_PTR_3 RSA*
#endif

typedef FoilCipherClass FoilOpensslCipherRsaClass;
typedef struct foil_openssl_cipher_rsa {
    FoilCipherSync sync;
    int padding_size;
    int padding;
    RSA* rsa;
    RSA* (*dup)(RSA_CONST_PTR_3 rsa);
    int (*proc)(int flen, const unsigned char* from,
        unsigned char* to, RSA* rsa, int padding);
} FoilOpensslCipherRsa;

GType foil_openssl_cipher_rsa_get_type(void) FOIL_INTERNAL;
#define FOIL_OPENSSL_TYPE_CIPHER_RSA foil_openssl_cipher_rsa_get_type()

typedef FoilKeyRsaPrivate FoilOpensslKeyRsaPrivate;
GType foil_openssl_key_rsa_private_get_type(void) FOIL_INTERNAL;
#define FOIL_OPENSSL_TYPE_KEY_RSA_PRIVATE \
    foil_openssl_key_rsa_private_get_type()

void
foil_openssl_key_rsa_private_apply(
    FoilKeyRsaPrivate* priv,
    RSA* rsa)
    FOIL_INTERNAL;

void
foil_openssl_key_rsa_public_apply(
    FoilKeyRsaPublic* pub,
    RSA* rsa)
    FOIL_INTERNAL;

/* Getters for RSA fields */

const BIGNUM*
foil_openssl_rsa_get_n(
    const RSA* rsa)
    FOIL_INTERNAL;

const BIGNUM*
foil_openssl_rsa_get_e(
    const RSA* rsa)
    FOIL_INTERNAL;

const BIGNUM*
foil_openssl_rsa_get_d(
    const RSA* rsa)
    FOIL_INTERNAL;

const BIGNUM*
foil_openssl_rsa_get_p(
    const RSA* rsa)
    FOIL_INTERNAL;

const BIGNUM*
foil_openssl_rsa_get_q(
    const RSA* rsa)
    FOIL_INTERNAL;

const BIGNUM*
foil_openssl_rsa_get_dmp1(
    const RSA* rsa)
    FOIL_INTERNAL;

const BIGNUM*
foil_openssl_rsa_get_dmq1(
    const RSA* rsa)
    FOIL_INTERNAL;

const BIGNUM*
foil_openssl_rsa_get_iqmp(
    const RSA* rsa)
    FOIL_INTERNAL;

/* Setters for RSA fields */

void
foil_openssl_rsa_set_key(
    RSA* rsa,
    const FoilBytes* n,
    const FoilBytes* e,
    const FoilBytes* d)
    FOIL_INTERNAL;

void
foil_openssl_rsa_set_factors(
    RSA* rsa,
    const FoilBytes* p,
    const FoilBytes* q)
    FOIL_INTERNAL;

void
foil_openssl_rsa_set_params(
    RSA* rsa,
    const FoilBytes* dmp1,
    const FoilBytes* dmq1,
    const FoilBytes* iqmp)
    FOIL_INTERNAL;

#define FOIL_RSA_PKCS1_OAEP_PADDING_SIZE 42

#endif /* FOIL_OPENSSL_RSA_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
