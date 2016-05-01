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

#ifndef FOIL_OPENSSL_RSA_H
#define FOIL_OPENSSL_RSA_H

#include "foil_key_rsa_public.h"
#include "foil_key_rsa_private.h"

#include <openssl/rsa.h>
#include <openssl/err.h>

typedef struct foil_openssl_key_rsa_public {
    FoilKeyRsaPublic super;
    FoilKeyRsaPublicData* data;
    RSA* rsa;
} FoilOpensslKeyRsaPublic;

GType foil_openssl_key_rsa_public_get_type(void);
#define FOIL_OPENSSL_TYPE_KEY_RSA_PUBLIC \
    (foil_openssl_key_rsa_public_get_type())
#define FOIL_OPENSSL_KEY_RSA_PUBLIC(obj) (G_TYPE_CHECK_INSTANCE_CAST(obj, \
    FOIL_OPENSSL_TYPE_KEY_RSA_PUBLIC, FoilOpensslKeyRsaPublic))

typedef struct foil_openssl_key_rsa_private {
    FoilKeyRsaPrivate super;
    RSA* rsa;
} FoilOpensslKeyRsaPrivate;

GType foil_openssl_key_rsa_private_get_type(void);
#define FOIL_OPENSSL_TYPE_KEY_RSA_PRIVATE \
    (foil_openssl_key_rsa_private_get_type())
#define FOIL_OPENSSL_KEY_RSA_PRIVATE(obj) (G_TYPE_CHECK_INSTANCE_CAST(obj, \
    FOIL_OPENSSL_TYPE_KEY_RSA_PRIVATE, FoilOpensslKeyRsaPrivate))

#define FOIL_RSA_BN_NUM_BYTES(x) ((x) ? BN_num_bytes(x) : 0)

#define FOIL_RSA_PKCS1_OAEP_PADDING_SIZE 42

#endif /* FOIL_OPENSSL_RSA_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
