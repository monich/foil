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

#ifndef FOIL_KEY_RSA_PRIVATE_H
#define FOIL_KEY_RSA_PRIVATE_H

#include "foil_private_key_p.h"

/*
 * RSAPrivateKey ::= SEQUENCE {
 *   version           Version,
 *   modulus           INTEGER,  -- n
 *   publicExponent    INTEGER,  -- e
 *   privateExponent   INTEGER,  -- d
 *   prime1            INTEGER,  -- p
 *   prime2            INTEGER,  -- q
 *   exponent1         INTEGER,  -- d mod (p-1)
 *   exponent2         INTEGER,  -- d mod (q-1)
 *   coefficient       INTEGER,  -- (inverse of q) mod p
 *   otherPrimeInfos   OtherPrimeInfos OPTIONAL
 * }
 */

typedef struct foil_key_rsa_private_data {
    FoilBytes n;
    FoilBytes e;
    FoilBytes d;
    FoilBytes p;
    FoilBytes q;
    FoilBytes dmp1;
    FoilBytes dmq1;
    FoilBytes iqmp;
} FoilKeyRsaPrivateData;

typedef struct foil_key_rsa_private {
    FoilPrivateKey super;
    FoilKeyRsaPrivateData* data;
} FoilKeyRsaPrivate;

typedef struct foil_key_rsa_private_class {
    FoilPrivateKeyClass super;
} FoilKeyRsaPrivateClass;

#define FOIL_KEY_RSA_PRIVATE_(obj) (G_TYPE_CHECK_INSTANCE_CAST(obj, \
        FOIL_TYPE_KEY_RSA_PRIVATE, FoilKeyRsaPrivate))
#define FOIL_KEY_RSA_PRIVATE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
        FOIL_TYPE_KEY_RSA_PRIVATE, FoilKeyRsaPrivateClass))
#define FOIL_KEY_RSA_PRIVATE_GET_CLASS(obj) G_TYPE_INSTANCE_GET_CLASS((obj),\
        FOIL_TYPE_KEY_RSA_PRIVATE, FoilKeyRsaPrivateClass)

void
foil_key_rsa_private_get_public_data(
    FoilKeyRsaPrivate* priv,
    FoilKeyRsaPublicData* pub_data)
    FOIL_INTERNAL;

#endif /* FOIL_KEY_PRIVATE_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
