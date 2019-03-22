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
#include "foil_openssl_random.h"

/* Logging */
#define GLOG_MODULE_NAME foil_log_key
#include "foil_log_p.h"

typedef FoilKeyRsaPrivateClass FoilOpensslKeyRsaPrivateClass;
G_DEFINE_TYPE(FoilOpensslKeyRsaPrivate, foil_openssl_key_rsa_private, \
    FOIL_TYPE_KEY_RSA_PRIVATE);

#define SUPER_CLASS foil_openssl_key_rsa_private_parent_class

#define FOIL_RSA_KEY_SET_BN(rsa,x,data) \
    ((rsa)->x = BN_bin2bn((data)->x.val, (data)->x.len, (rsa)->x))

GType
foil_impl_key_rsa_private_get_type()
{
    return foil_openssl_key_rsa_private_get_type();
}

static
FoilKeyRsaPrivateData*
foil_key_rsa_private_data_from_rsa(
    RSA* rsa)
{
    const int nlen = BN_num_bytes(rsa->n);
    const int elen = BN_num_bytes(rsa->e);
    const int dlen = BN_num_bytes(rsa->d);
    const int plen = BN_num_bytes(rsa->p);
    const int qlen = BN_num_bytes(rsa->q);
    const int dmp1len = BN_num_bytes(rsa->dmp1);
    const int dmq1len = BN_num_bytes(rsa->dmq1);
    const int iqmplen = BN_num_bytes(rsa->iqmp);
    const gsize total = FOIL_ALIGN(sizeof(FoilKeyRsaPrivateData)) +
        FOIL_ALIGN(nlen) + FOIL_ALIGN(elen) + FOIL_ALIGN(dlen) +
        FOIL_ALIGN(plen) + FOIL_ALIGN(qlen) + FOIL_ALIGN(dmp1len) +
        FOIL_ALIGN(dmq1len) + FOIL_ALIGN(iqmplen);
    FoilKeyRsaPrivateData* data = g_malloc(total);
    guint8* ptr = ((guint8*)data) + FOIL_ALIGN(sizeof(*data));
    BN_bn2bin(rsa->n, ptr); data->n.val = ptr;
    ptr += FOIL_ALIGN(data->n.len = nlen);
    BN_bn2bin(rsa->e, ptr); data->e.val = ptr;
    ptr += FOIL_ALIGN(data->e.len = elen);
    BN_bn2bin(rsa->d, ptr); data->d.val = ptr;
    ptr += FOIL_ALIGN(data->d.len = dlen);
    BN_bn2bin(rsa->p, ptr); data->p.val = ptr;
    ptr += FOIL_ALIGN(data->p.len = plen);
    BN_bn2bin(rsa->q, ptr); data->q.val = ptr;
    ptr += FOIL_ALIGN(data->q.len = qlen);
    BN_bn2bin(rsa->dmp1, ptr); data->dmp1.val = ptr;
    ptr += FOIL_ALIGN(data->dmp1.len = dmp1len);
    BN_bn2bin(rsa->dmq1, ptr); data->dmq1.val = ptr;
    ptr += FOIL_ALIGN(data->dmq1.len = dmq1len);
    BN_bn2bin(rsa->iqmp, ptr); data->iqmp.val = ptr;
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
                    RSA* tmp;
                    FoilOpensslKeyRsaPrivate* priv = g_object_new
                        (foil_openssl_key_rsa_private_get_type(), NULL);
                    tmp = priv->rsa;
                    priv->rsa = rsa;
                    priv->super.data = foil_key_rsa_private_data_from_rsa(rsa);
                    rsa = tmp;
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
void
foil_openssl_key_rsa_private_apply(
    FoilKeyRsaPrivate* key)
{
    FoilOpensslKeyRsaPrivate* self = FOIL_OPENSSL_KEY_RSA_PRIVATE(key);
    FOIL_RSA_KEY_SET_BN(self->rsa, n, key->data);
    FOIL_RSA_KEY_SET_BN(self->rsa, e, key->data);
    FOIL_RSA_KEY_SET_BN(self->rsa, d, key->data);
    FOIL_RSA_KEY_SET_BN(self->rsa, p, key->data);
    FOIL_RSA_KEY_SET_BN(self->rsa, q, key->data);
    FOIL_RSA_KEY_SET_BN(self->rsa, dmp1, key->data);
    FOIL_RSA_KEY_SET_BN(self->rsa, dmq1, key->data);
    FOIL_RSA_KEY_SET_BN(self->rsa, iqmp, key->data);
    FOIL_KEY_RSA_PRIVATE_CLASS(SUPER_CLASS)->fn_apply(key);
}

static
int
foil_openssl_key_rsa_private_num_bits(
    FoilKeyRsaPrivate* key)
{
    FoilOpensslKeyRsaPrivate* self = FOIL_OPENSSL_KEY_RSA_PRIVATE(key);
    return self->rsa->n ? BN_num_bits(self->rsa->n) : 0;
}

static
void
foil_openssl_key_rsa_private_finalize(
    GObject* object)
{
    FoilOpensslKeyRsaPrivate* self = FOIL_OPENSSL_KEY_RSA_PRIVATE(object);
    RSA_free(self->rsa);
    G_OBJECT_CLASS(SUPER_CLASS)->finalize(object);
}

static
void
foil_openssl_key_rsa_private_init(
    FoilOpensslKeyRsaPrivate* self)
{
    self->rsa = RSA_new();
}

static
void
foil_openssl_key_rsa_private_class_init(
    FoilOpensslKeyRsaPrivateClass* klass)
{
    FoilKeyClass* key_class = FOIL_KEY_CLASS(klass);
    FoilPrivateKeyClass* privkey_class = FOIL_PRIVATE_KEY_CLASS(klass);
    key_class->fn_generate = foil_openssl_key_rsa_private_generate;
    privkey_class->fn_get_public_type = foil_openssl_key_rsa_public_get_type;
    klass->fn_apply = foil_openssl_key_rsa_private_apply;
    klass->fn_num_bits = foil_openssl_key_rsa_private_num_bits;
    G_OBJECT_CLASS(klass)->finalize = foil_openssl_key_rsa_private_finalize;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
