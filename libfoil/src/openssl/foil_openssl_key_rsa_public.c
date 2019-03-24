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

typedef FoilKeyRsaPublicClass FoilOpensslKeyRsaPublicClass;
G_DEFINE_TYPE(FoilOpensslKeyRsaPublic, foil_openssl_key_rsa_public, \
    FOIL_TYPE_KEY_RSA_PUBLIC);

GType
foil_impl_key_rsa_public_get_type()
{
    return FOIL_OPENSSL_TYPE_KEY_RSA_PUBLIC;
}

void
foil_openssl_key_rsa_public_apply(
    FoilKeyRsaPublic* key,
    RSA* rsa)
{
    FOIL_RSA_KEY_SET_BN(rsa, n, key->data);
    FOIL_RSA_KEY_SET_BN(rsa, e, key->data);
}

static
void
foil_openssl_key_rsa_public_init(
    FoilOpensslKeyRsaPublic* self)
{
}

static
void
foil_openssl_key_rsa_public_class_init(
    FoilOpensslKeyRsaPublicClass* klass)
{
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
