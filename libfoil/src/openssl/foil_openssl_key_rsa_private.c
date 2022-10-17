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
#include "foil_openssl_random.h"

/* Logging */
#define GLOG_MODULE_NAME foil_log_key
#include "foil_log_p.h"

#define FOIL_RSA_FIELD(rsa,x) foil_openssl_rsa_get_##x(rsa)

typedef FoilKeyRsaPrivateClass FoilOpensslKeyRsaPrivateClass;
G_DEFINE_TYPE(FoilOpensslKeyRsaPrivate, foil_openssl_key_rsa_private, \
    FOIL_TYPE_KEY_RSA_PRIVATE);

GType
foil_impl_key_rsa_private_get_type()
{
    return FOIL_OPENSSL_TYPE_KEY_RSA_PRIVATE;
}

void
foil_openssl_key_rsa_private_apply(
    FoilKeyRsaPrivate* key,
    RSA* rsa)
{
    const FoilKeyRsaPrivateData* data = key->data;
    foil_openssl_rsa_set_key(rsa, &data->n, &data->e, &data->d);
    foil_openssl_rsa_set_factors(rsa, &data->p, &data->q);
    foil_openssl_rsa_set_params(rsa, &data->dmp1, &data->dmq1, &data->iqmp);
}

static
FoilKeyRsaPrivateData*
foil_key_rsa_private_data_from_rsa(
    RSA* rsa)
{
    const int nlen = BN_num_bytes(FOIL_RSA_FIELD(rsa,n));
    const int elen = BN_num_bytes(FOIL_RSA_FIELD(rsa,e));
    const int dlen = BN_num_bytes(FOIL_RSA_FIELD(rsa,d));
    const int plen = BN_num_bytes(FOIL_RSA_FIELD(rsa,p));
    const int qlen = BN_num_bytes(FOIL_RSA_FIELD(rsa,q));
    const int dmp1len = BN_num_bytes(FOIL_RSA_FIELD(rsa,dmp1));
    const int dmq1len = BN_num_bytes(FOIL_RSA_FIELD(rsa,dmq1));
    const int iqmplen = BN_num_bytes(FOIL_RSA_FIELD(rsa,iqmp));
    const gsize total = FOIL_ALIGN(sizeof(FoilKeyRsaPrivateData)) +
        FOIL_ALIGN(nlen) + FOIL_ALIGN(elen) + FOIL_ALIGN(dlen) +
        FOIL_ALIGN(plen) + FOIL_ALIGN(qlen) + FOIL_ALIGN(dmp1len) +
        FOIL_ALIGN(dmq1len) + FOIL_ALIGN(iqmplen);
    FoilKeyRsaPrivateData* data = g_malloc(total);
    guint8* ptr = ((guint8*)data) + FOIL_ALIGN(sizeof(*data));
    BN_bn2bin(FOIL_RSA_FIELD(rsa,n), ptr); data->n.val = ptr;
    ptr += FOIL_ALIGN(data->n.len = nlen);
    BN_bn2bin(FOIL_RSA_FIELD(rsa,e), ptr); data->e.val = ptr;
    ptr += FOIL_ALIGN(data->e.len = elen);
    BN_bn2bin(FOIL_RSA_FIELD(rsa,d), ptr); data->d.val = ptr;
    ptr += FOIL_ALIGN(data->d.len = dlen);
    BN_bn2bin(FOIL_RSA_FIELD(rsa,p), ptr); data->p.val = ptr;
    ptr += FOIL_ALIGN(data->p.len = plen);
    BN_bn2bin(FOIL_RSA_FIELD(rsa,q), ptr); data->q.val = ptr;
    ptr += FOIL_ALIGN(data->q.len = qlen);
    BN_bn2bin(FOIL_RSA_FIELD(rsa,dmp1), ptr); data->dmp1.val = ptr;
    ptr += FOIL_ALIGN(data->dmp1.len = dmp1len);
    BN_bn2bin(FOIL_RSA_FIELD(rsa,dmq1), ptr); data->dmq1.val = ptr;
    ptr += FOIL_ALIGN(data->dmq1.len = dmq1len);
    BN_bn2bin(FOIL_RSA_FIELD(rsa,iqmp), ptr); data->iqmp.val = ptr;
    ptr += FOIL_ALIGN(data->iqmp.len = iqmplen);
    GASSERT((gsize)(ptr - ((guint8*)data)) == total);
    return data;
}

static
FoilKey*
foil_openssl_key_rsa_private_generate(
    FoilKeyClass* klass,
    guint bits)
{
    FoilKey* key = NULL;
    BIGNUM* pub_exp = BN_new();
    if (pub_exp) {
        /* Make sure RNG is seeded */
        GTypeClass* rng = g_type_class_ref(foil_openssl_random_get_type());
        if (BN_set_word(pub_exp, RSA_F4)) {
            RSA* rsa = RSA_new();
            if (rsa) {
                if (RSA_generate_key_ex(rsa, bits, pub_exp, NULL)) {
                    FoilKeyRsaPrivate* priv = g_object_new
                        (FOIL_OPENSSL_TYPE_KEY_RSA_PRIVATE, NULL);
                    priv->data = foil_key_rsa_private_data_from_rsa(rsa);
                    key = FOIL_KEY(priv);
                }
                RSA_free(rsa);
            }
        }
        BN_free(pub_exp);
        g_type_class_unref(rng);
    }
    return key;
}

static
FoilKey*
foil_openssl_key_rsa_private_create_public(
    FoilPrivateKey* key)
{
    FoilKeyRsaPrivate* self = FOIL_KEY_RSA_PRIVATE_(key);
    FoilKeyRsaPublic* pub = g_object_new(FOIL_KEY_RSA_PUBLIC, NULL);
    FoilKeyRsaPublicData pub_data;
    foil_key_rsa_private_get_public_data(self, &pub_data);
    foil_key_rsa_public_set_data(pub, &pub_data);
    return FOIL_KEY(pub);
}

static
void
foil_openssl_key_rsa_private_init(
    FoilOpensslKeyRsaPrivate* self)
{
}

static
void
foil_openssl_key_rsa_private_class_init(
    FoilOpensslKeyRsaPrivateClass* klass)
{
    FOIL_KEY_CLASS(klass)->fn_generate = foil_openssl_key_rsa_private_generate;
    FOIL_PRIVATE_KEY_CLASS(klass)->fn_create_public =
        foil_openssl_key_rsa_private_create_public;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
