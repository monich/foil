/*
 * Copyright (C) 2019 by Slava Monich
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer
 *     in the documentation and/or other materials provided with the
 *     distribution.
 *  3. Neither the names of the copyright holders nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
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

#ifndef FOIL_OPENSSL_DES_H
#define FOIL_OPENSSL_DES_H

#include "foil_key_des_p.h"

#include <openssl/des.h>

G_STATIC_ASSERT(FOIL_DES_BLOCK_SIZE == sizeof(DES_cblock));
G_STATIC_ASSERT(FOIL_DES_KEY_SIZE == sizeof(DES_cblock));

typedef struct foil_openssl_key_des_data {
    DES_cblock k;
    DES_key_schedule ks;
} FoilOpensslKeyDesData;

typedef struct foil_openssl_key_des {
    FoilKeyDes super;
    FoilOpensslKeyDesData* k1;
    FoilOpensslKeyDesData* k2;
    FoilOpensslKeyDesData* k3;
} FoilOpensslKeyDes;

GType foil_openssl_key_des_get_type(void);
#define FOIL_OPENSSL_TYPE_KEY_DES (foil_openssl_key_des_get_type())
#define FOIL_OPENSSL_KEY_DES(obj) (G_TYPE_CHECK_INSTANCE_CAST(obj, \
    FOIL_OPENSSL_TYPE_KEY_DES, FoilOpensslKeyDes))

#endif /* FOIL_OPENSSL_DES_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
