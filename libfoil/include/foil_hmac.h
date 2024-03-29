/*
 * Copyright (C) 2018-2022 by Slava Monich <slava@monich.com>
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

#ifndef FOIL_HMAC_H
#define FOIL_HMAC_H

#include "foil_types.h"

#include <glib-object.h>

G_BEGIN_DECLS

/*
 * HMAC: Keyed-Hashing for Message Authntication (RFC 2104)
 *
 * Since 1.0.8
 */

FoilHmac*
foil_hmac_new(
    GType digest,
    const void* key,
    gsize keylen);

FoilHmac*
foil_hmac_ref(
    FoilHmac* hmac);

void
foil_hmac_unref(
    FoilHmac* hmac);

FoilHmac*
foil_hmac_clone(
    FoilHmac* hmac);

void
foil_hmac_copy(
    FoilHmac* hmac,
    FoilHmac* source);

void
foil_hmac_update(
    FoilHmac* hmac,
    const void* data,
    gsize size);

void
foil_hmac_reset(
    FoilHmac* hmac); /* Since 1.0.27 */

GBytes*
foil_hmac_finish(
    FoilHmac* hmac);

GBytes*
foil_hmac_free_to_bytes(
    FoilHmac* hmac);

G_END_DECLS

#endif /* FOIL_HMAC_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
