/*
 * Copyright (C) 2023 Slava Monich <slava@monich.com>
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

#ifndef FOIL_KEY_RSA_H
#define FOIL_KEY_RSA_H

#include "foil_types_p.h"

typedef struct foil_key_rsa_public_data {
    FoilBytes n;
    FoilBytes e;
} FoilKeyRsaPublicData;

typedef struct foil_key_rsa_openssh_priv_data {
    FoilBytes ciphername;
    FoilBytes kdfname;
    FoilBytes kdf;
    FoilBytes data;
} FoilKeyRsaOpensshPrivData;

extern const FoilBytes foil_key_openssh_text_prefix FOIL_INTERNAL;
extern const FoilBytes foil_key_openssh_text_suffix FOIL_INTERNAL;
extern const FoilBytes foil_key_openssh_auth_magic FOIL_INTERNAL;
extern const FoilBytes foil_ssh_rsa_mark FOIL_INTERNAL;

gboolean
foil_key_rsa_parse_n(
    GUtilRange* pos,
    guint32* n)
    FOIL_INTERNAL;

gboolean
foil_key_rsa_parse_n_bytes(
    GUtilRange* pos,
    FoilBytes* bytes)
    FOIL_INTERNAL;

gboolean
foil_key_rsa_write_n(
    FoilOutput* out,
    guint32 n)
    FOIL_INTERNAL;

gboolean
foil_key_rsa_write_n_bytes(
    FoilOutput* out,
    const FoilBytes* data)
    FOIL_INTERNAL;

gboolean
foil_key_rsa_parse_openssh_text(
    const FoilBytes* data,
    FoilKeyRsaPublicData* pub,
    FoilKeyRsaOpensshPrivData* priv,
    FoilPool* pool)
    FOIL_INTERNAL;

gboolean
foil_key_rsa_parse_openssh_binary(
    const FoilBytes* data,
    FoilKeyRsaPublicData* pub,
    FoilKeyRsaOpensshPrivData* priv)
    FOIL_INTERNAL;

#endif /* FOIL_KEY_RSA_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
