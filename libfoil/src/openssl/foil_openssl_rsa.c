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

#include "foil_openssl_rsa.h"

/*
 * In OpenSSL 1.0 struct rsa_st was public and there were no RSA_get0_xxx
 * and RSA_set0_xxx accessors. We use the accessors when they are* available,
 * and only if they are not there, access the fields directly (which hopefully
 * means that we are linked against OpenSSL 1.0)
 */

typedef struct rsa_st_1_0 {
    int pad;
    long version;
    void* meth;
    void* engine;
    BIGNUM* n;
    BIGNUM* e;
    BIGNUM* d;
    BIGNUM* p;
    BIGNUM* q;
    BIGNUM* dmp1;
    BIGNUM* dmq1;
    BIGNUM* iqmp;
} RSA_1_0;

#define FOIL_WEAK_FN __attribute__((weak))

void
RSA_get0_key(
    const RSA* r,
    const BIGNUM** n,
    const BIGNUM** e,
    const BIGNUM** d)
    FOIL_WEAK_FN;

void
RSA_get0_factors(
    const RSA* r,
    const BIGNUM** p,
    const BIGNUM** q)
    FOIL_WEAK_FN;

void
RSA_get0_crt_params(
    const RSA* r,
    const BIGNUM** dmp1,
    const BIGNUM** dmq1,
    const BIGNUM** iqmp)
    FOIL_WEAK_FN;

int
RSA_set0_key(
    RSA* r,
    BIGNUM* n,
    BIGNUM* e,
    BIGNUM* d)
    FOIL_WEAK_FN;

int
RSA_set0_factors(
    RSA* r,
    BIGNUM* p,
    BIGNUM* q)
    FOIL_WEAK_FN;

int
RSA_set0_crt_params(
    RSA* r,
    BIGNUM* dmp1,
    BIGNUM* dmq1,
    BIGNUM* iqmp)
    FOIL_WEAK_FN;

/* Getters for RSA fields */

const BIGNUM*
foil_openssl_rsa_get_n(
    const RSA* rsa)
{
    if (RSA_get0_key) {
        const BIGNUM* n = NULL;
        RSA_get0_key(rsa, &n, NULL, NULL);
        if (n) return n;
    }
    /* Risky path */
    return ((const RSA_1_0*)rsa)->n;
}

const BIGNUM*
foil_openssl_rsa_get_e(
    const RSA* rsa)
{
    if (RSA_get0_key) {
        const BIGNUM* e = NULL;
        RSA_get0_key(rsa, NULL, &e, NULL);
        if (e) return e;
    }
    /* OpenSSL 1.0 path */
    return ((const RSA_1_0*)rsa)->e;
}

const BIGNUM*
foil_openssl_rsa_get_d(
    const RSA* rsa)
{
    if (RSA_get0_key) {
        const BIGNUM* d = NULL;
        RSA_get0_key(rsa, NULL, NULL, &d);
        if (d) return d;
    }
    /* OpenSSL 1.0 path */
    return ((const RSA_1_0*)rsa)->d;
}

const BIGNUM*
foil_openssl_rsa_get_p(
    const RSA* rsa)
{
    if (RSA_get0_factors) {
        const BIGNUM* p = NULL;
        RSA_get0_factors(rsa, &p, NULL);
        if (p) return p;
    }
    /* OpenSSL 1.0 path */
    return ((const RSA_1_0*)rsa)->p;
}

const BIGNUM*
foil_openssl_rsa_get_q(
    const RSA* rsa)
{
    if (RSA_get0_factors) {
        const BIGNUM* q = NULL;
        RSA_get0_factors(rsa, NULL, &q);
        if (q) return q;
    }
    /* OpenSSL 1.0 path */
    return ((const RSA_1_0*)rsa)->q;
}

const BIGNUM*
foil_openssl_rsa_get_dmp1(
    const RSA* rsa)
{
    if (RSA_get0_crt_params) {
        const BIGNUM* dmp1 = NULL;
        RSA_get0_crt_params(rsa, &dmp1, NULL, NULL);
        if (dmp1) return dmp1;
    }
    /* OpenSSL 1.0 path */
    return ((const RSA_1_0*)rsa)->dmp1;
}

const BIGNUM*
foil_openssl_rsa_get_dmq1(
    const RSA* rsa)
{
    if (RSA_get0_crt_params) {
        const BIGNUM* dmq1 = NULL;
        RSA_get0_crt_params(rsa, NULL, &dmq1, NULL);
        if (dmq1) return dmq1;
    }
    /* OpenSSL 1.0 path */
    return ((const RSA_1_0*)rsa)->dmq1;
}

const BIGNUM*
foil_openssl_rsa_get_iqmp(
    const RSA* rsa)
{
    if (RSA_get0_crt_params) {
        const BIGNUM* iqmp = NULL;
        RSA_get0_crt_params(rsa, NULL, NULL, &iqmp);
        if (iqmp) return iqmp;
    }
    /* OpenSSL 1.0 path */
    return ((const RSA_1_0*)rsa)->iqmp;
}

/* Setters for RSA fields */

void
foil_openssl_rsa_set_key(
    RSA* rsa,
    const FoilBytes* n_bytes,
    const FoilBytes* e_bytes,
    const FoilBytes* d_bytes)
{
    /* d is NULL for the public key */
    BIGNUM* n = BN_bin2bn(n_bytes->val, n_bytes->len, NULL);
    BIGNUM* e = BN_bin2bn(e_bytes->val, e_bytes->len, NULL);
    BIGNUM* d = d_bytes ? BN_bin2bn(d_bytes->val, d_bytes->len, NULL) : NULL;
    if (!RSA_set0_key || !RSA_set0_key(rsa, n, e, d)) {
        /* OpenSSL 1.0 path */
        RSA_1_0* r = (RSA_1_0*)rsa;
        BN_free(r->n);
        BN_free(r->e);
        r->n = n;
        r->e = e;
        if (d) {
            BN_clear_free(r->d);
            r->d = d;
        }
    }
}

void
foil_openssl_rsa_set_factors(
    RSA* rsa,
    const FoilBytes* p_bytes,
    const FoilBytes* q_bytes)
{
    BIGNUM* p = BN_bin2bn(p_bytes->val, p_bytes->len, NULL);
    BIGNUM* q = BN_bin2bn(q_bytes->val, q_bytes->len, NULL);
    if (!RSA_set0_factors || !RSA_set0_factors(rsa, p, q)) {
        /* OpenSSL 1.0 path */
        RSA_1_0* r = (RSA_1_0*)rsa;
        BN_clear_free(r->p);
        BN_clear_free(r->q);
        r->p = p;
        r->q = q;
    }
}

void
foil_openssl_rsa_set_params(
    RSA* rsa,
    const FoilBytes* dmp1_bytes,
    const FoilBytes* dmq1_bytes,
    const FoilBytes* iqmp_bytes)
{
    BIGNUM* dmp1 = BN_bin2bn(dmp1_bytes->val, dmp1_bytes->len, NULL);
    BIGNUM* dmq1 = BN_bin2bn(dmq1_bytes->val, dmq1_bytes->len, NULL);
    BIGNUM* iqmp = BN_bin2bn(iqmp_bytes->val, iqmp_bytes->len, NULL);
    if (!RSA_set0_crt_params || !RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp)) {
        /* OpenSSL 1.0 path */
        RSA_1_0* r = (RSA_1_0*)rsa;
        BN_clear_free(r->dmp1);
        BN_clear_free(r->dmq1);
        BN_clear_free(r->iqmp);
        r->dmp1 = dmp1;
        r->dmq1 = dmq1;
        r->iqmp = iqmp;
    }
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
