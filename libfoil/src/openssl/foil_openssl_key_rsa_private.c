/*
 * Copyright (C) 2016 by Slava Monich
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
    FoilPrivateKeyClass* privkey_class = FOIL_PRIVATE_KEY_CLASS(klass);
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
