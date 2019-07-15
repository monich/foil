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

#include "foil_openssl_rsa.h"

/*
 * Originally, struct rsa_st was public then it was made opaque then it
 * started to mutate. Binary compatibility - what's that? Never heard of it!
 */

#if GLIB_SIZEOF_LONG != 4
typedef struct rsa_st_v1 {
    int pad;
    long version;
    const RSA_METHOD* meth;
    ENGINE* engine;
    BIGNUM* n;
    BIGNUM* e;
    BIGNUM* d;
    BIGNUM* p;
    BIGNUM* q;
    BIGNUM* dmp1;
    BIGNUM* dmq1;
    BIGNUM* iqmp;
} RSA_V1;
#  define CHECK_RSA_V1
#else
#  undef CHECK_RSA_V1
#endif

typedef struct rsa_st_v2 {
    int pad;
    guint32 version;
    const RSA_METHOD* meth;
    ENGINE* engine;
    BIGNUM* n;
    BIGNUM* e;
    BIGNUM* d;
    BIGNUM* p;
    BIGNUM* q;
    BIGNUM* dmp1;
    BIGNUM* dmq1;
    BIGNUM* iqmp;
} RSA_V2;

#ifdef CHECK_RSA_V1
static
RSA_V1*
foil_openssl_rsa_v1(
    const RSA* rsa)
{
    RSA_V1* v1 = (void*)rsa;
    return (!v1->version && v1->meth && !v1->engine) ? v1 : NULL;
}
#endif /* CHECK_RSA_V1 */

static
RSA_V2*
foil_openssl_rsa_v2(
    const RSA* rsa)
{
    RSA_V2* v2 = (void*)rsa;
    return (!v2->version && v2->meth && !v2->engine) ? v2 : NULL;
}

#ifdef CHECK_RSA_V1
#  define FOIL_RSA_GET_FIELD_PTR(rsa,x) \
    RSA_V1* v1 = foil_openssl_rsa_v1(rsa); \
    if (v1) { \
        return &v1->x; \
    } else { \
        RSA_V2* v2 = foil_openssl_rsa_v2(rsa); \
        if (v2) return &v2->x; \
    } \
    return NULL
#else
#  define FOIL_RSA_GET_FIELD_PTR(rsa,x) \
    RSA_V2* v2 = foil_openssl_rsa_v2(rsa); \
    return v2 ? &v2->x : NULL
#endif

static
BIGNUM**
foil_openssl_rsa_get_n_ptr(
    const RSA* rsa)
{
    FOIL_RSA_GET_FIELD_PTR(rsa,n);
}

static
BIGNUM**
foil_openssl_rsa_get_e_ptr(
    const RSA* rsa)
{
    FOIL_RSA_GET_FIELD_PTR(rsa,e);
}

static
BIGNUM**
foil_openssl_rsa_get_d_ptr(
    const RSA* rsa)
{
    FOIL_RSA_GET_FIELD_PTR(rsa,d);
}

static
BIGNUM**
foil_openssl_rsa_get_p_ptr(
    const RSA* rsa)
{
    FOIL_RSA_GET_FIELD_PTR(rsa,p);
}

static
BIGNUM**
foil_openssl_rsa_get_q_ptr(
    const RSA* rsa)
{
    FOIL_RSA_GET_FIELD_PTR(rsa,q);
}

static
BIGNUM**
foil_openssl_rsa_get_dmp1_ptr(
    const RSA* rsa)
{
    FOIL_RSA_GET_FIELD_PTR(rsa,dmp1);
}

static
BIGNUM**
foil_openssl_rsa_get_dmq1_ptr(
    const RSA* rsa)
{
    FOIL_RSA_GET_FIELD_PTR(rsa,dmq1);
}

static
BIGNUM**
foil_openssl_rsa_get_iqmp_ptr(
    const RSA* rsa)
{
    FOIL_RSA_GET_FIELD_PTR(rsa,iqmp);
}

/* Getters for RSA fields */


const BIGNUM*
foil_openssl_rsa_get_n(
    const RSA* rsa)
{
    BIGNUM** bn = foil_openssl_rsa_get_n_ptr(rsa);
    return bn ? *bn : NULL;
}

const BIGNUM*
foil_openssl_rsa_get_e(
    const RSA* rsa)
{
    BIGNUM** bn = foil_openssl_rsa_get_e_ptr(rsa);
    return bn ? *bn : NULL;
}

const BIGNUM*
foil_openssl_rsa_get_d(
    const RSA* rsa)
{
    BIGNUM** bn = foil_openssl_rsa_get_d_ptr(rsa);
    return bn ? *bn : NULL;
}

const BIGNUM*
foil_openssl_rsa_get_p(
    const RSA* rsa)
{
    BIGNUM** bn = foil_openssl_rsa_get_p_ptr(rsa);
    return bn ? *bn : NULL;
}

const BIGNUM*
foil_openssl_rsa_get_q(
    const RSA* rsa)
{
    BIGNUM** bn = foil_openssl_rsa_get_q_ptr(rsa);
    return bn ? *bn : NULL;
}

const BIGNUM*
foil_openssl_rsa_get_dmp1(
    const RSA* rsa)
{
    BIGNUM** bn = foil_openssl_rsa_get_dmp1_ptr(rsa);
    return bn ? *bn : NULL;
}

const BIGNUM*
foil_openssl_rsa_get_dmq1(
    const RSA* rsa)
{
    BIGNUM** bn = foil_openssl_rsa_get_dmq1_ptr(rsa);
    return bn ? *bn : NULL;
}

const BIGNUM*
foil_openssl_rsa_get_iqmp(
    const RSA* rsa)
{
    BIGNUM** bn = foil_openssl_rsa_get_iqmp_ptr(rsa);
    return bn ? *bn : NULL;
}

/* Setters for RSA fields */

const BIGNUM*
foil_openssl_rsa_set_n(
    RSA* rsa,
    const FoilBytes* bytes)
{
    BIGNUM** bn = foil_openssl_rsa_get_n_ptr(rsa);
    return (bn ? (*bn = BN_bin2bn(bytes->val, bytes->len, *bn)) : NULL);
}

const BIGNUM*
foil_openssl_rsa_set_e(
    RSA* rsa,
    const FoilBytes* bytes)
{
    BIGNUM** bn = foil_openssl_rsa_get_e_ptr(rsa);
    return (bn ? (*bn = BN_bin2bn(bytes->val, bytes->len, *bn)) : NULL);
}

const BIGNUM*
foil_openssl_rsa_set_d(
    RSA* rsa,
    const FoilBytes* bytes)
{
    BIGNUM** bn = foil_openssl_rsa_get_d_ptr(rsa);
    return (bn ? (*bn = BN_bin2bn(bytes->val, bytes->len, *bn)) : NULL);
}

const BIGNUM*
foil_openssl_rsa_set_p(
    RSA* rsa,
    const FoilBytes* bytes)
{
    BIGNUM** bn = foil_openssl_rsa_get_p_ptr(rsa);
    return (bn ? (*bn = BN_bin2bn(bytes->val, bytes->len, *bn)) : NULL);
}

const BIGNUM*
foil_openssl_rsa_set_q(
    RSA* rsa,
    const FoilBytes* bytes)
{
    BIGNUM** bn = foil_openssl_rsa_get_q_ptr(rsa);
    return (bn ? (*bn = BN_bin2bn(bytes->val, bytes->len, *bn)) : NULL);
}

const BIGNUM*
foil_openssl_rsa_set_dmp1(
    RSA* rsa,
    const FoilBytes* bytes)
{
    BIGNUM** bn = foil_openssl_rsa_get_dmp1_ptr(rsa);
    return (bn ? (*bn = BN_bin2bn(bytes->val, bytes->len, *bn)) : NULL);
}

const BIGNUM*
foil_openssl_rsa_set_dmq1(
    RSA* rsa,
    const FoilBytes* bytes)
{
    BIGNUM** bn = foil_openssl_rsa_get_dmq1_ptr(rsa);
    return (bn ? (*bn = BN_bin2bn(bytes->val, bytes->len, *bn)) : NULL);
}

const BIGNUM*
foil_openssl_rsa_set_iqmp(
    RSA* rsa,
    const FoilBytes* bytes)
{
    BIGNUM** bn = foil_openssl_rsa_get_iqmp_ptr(rsa);
    return (bn ? (*bn = BN_bin2bn(bytes->val, bytes->len, *bn)) : NULL);
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
