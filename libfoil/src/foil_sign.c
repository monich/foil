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

#include "foil_sign.h"
#include "foil_cipher.h"
#include "foil_digest.h"
#include "foil_key.h"
#include "foil_util_p.h"

GBytes*
foil_sign(
    const FoilBytes* bytes,
    GType digest_type,
    GType cipher_type,
    FoilPrivateKey* priv)
{
    GBytes* sign = NULL;
    if (G_LIKELY(bytes) && G_LIKELY(priv)) {
        GBytes* digest = foil_digest_data(digest_type, bytes->val, bytes->len);
        if (digest) {
            sign = foil_cipher_bytes(cipher_type, FOIL_KEY(priv), digest);
            g_bytes_unref(digest);
        }
    }
    return sign;
}

gboolean
foil_verify(
    const FoilBytes* bytes,
    const FoilBytes* sign,
    GType digest_type,
    GType cipher_type,
    FoilKey* pub)
{
    gboolean ok = FALSE;
    if (G_LIKELY(bytes) && G_LIKELY(sign) && G_LIKELY(pub)) {
        GBytes* d1 = foil_cipher_data(cipher_type, pub, sign->val, sign->len);
        if (d1) {
            GBytes* d2 = foil_digest_data(digest_type, bytes->val, bytes->len);
            if (d2) {
                ok = g_bytes_equal(d1, d2);
                g_bytes_unref(d2);
            }
            g_bytes_unref(d1);
        }
    }
    return ok;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
