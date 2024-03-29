/*
 * Copyright (C) 2016-2023 Slava Monich <slava@monich.com>
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

#ifndef FOIL_KEY_RSA_PUBLIC_H
#define FOIL_KEY_RSA_PUBLIC_H

#include "foil_key_p.h"
#include "foil_key_rsa.h"

typedef struct foil_key_rsa_public {
    FoilKey key;
    FoilKeyRsaPublicData* data;
} FoilKeyRsaPublic;

typedef struct foil_key_rsa_public_class {
    FoilKeyClass key;
} FoilKeyRsaPublicClass;

#define FOIL_KEY_RSA_PUBLIC_(obj) (G_TYPE_CHECK_INSTANCE_CAST(obj, \
        FOIL_TYPE_KEY_RSA_PUBLIC, FoilKeyRsaPublic))
#define FOIL_KEY_RSA_PUBLIC_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
        FOIL_TYPE_KEY_RSA_PUBLIC, FoilKeyRsaPublicClass))
#define FOIL_KEY_RSA_PUBLIC_GET_CLASS(obj) G_TYPE_INSTANCE_GET_CLASS(obj,\
        FOIL_TYPE_KEY_RSA_PUBLIC, FoilKeyRsaPublicClass)
#define FOIL_IS_RSA_PUBLIC_KEY(obj) G_TYPE_CHECK_INSTANCE_TYPE(obj, \
        FOIL_TYPE_KEY_RSA_PUBLIC)

extern const FoilBytes foil_rsa_public_binary_prefix FOIL_INTERNAL;

void
foil_key_rsa_public_set_data(
    FoilKeyRsaPublic* pub,
    const FoilKeyRsaPublicData* data)
    FOIL_INTERNAL;

gboolean
foil_key_rsa_public_data_write_ssh_rsa(
    FoilOutput* out,
    const FoilKeyRsaPublicData* data)
    FOIL_INTERNAL;

GBytes*
foil_key_rsa_public_data_ssh_rsa_bytes(
    const FoilKeyRsaPublicData* data)
    FOIL_INTERNAL;

gboolean
foil_key_rsa_public_parse_ssh_rsa_binary(
    FoilKeyRsaPublicData* key,
    const FoilBytes* data)
    FOIL_INTERNAL;

GBytes*
foil_key_rsa_public_data_fingerprint(
    const FoilKeyRsaPublicData* data)
    FOIL_INTERNAL;

#endif /* FOIL_KEY_PUBLIC_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
