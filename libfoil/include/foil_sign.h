/*
 * Copyright (C) 2016-2018 by Slava Monich
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

#ifndef FOIL_SIGN_H
#define FOIL_SIGN_H

#include "foil_types.h"

#include <glib-object.h>

G_BEGIN_DECLS

GBytes*
foil_sign(
    const FoilBytes* bytes,
    GType digest_type,
    GType encrypt_type,
    FoilPrivateKey* priv);

gboolean
foil_verify(
    const FoilBytes* bytes,
    const FoilBytes* signature,
    GType digest_type,
    GType cipher_type,
    FoilKey* pub);

#define foil_rsa_sign(bytes,digest_type,priv) \
    foil_sign(bytes,digest_type,FOIL_CIPHER_RSA_ENCRYPT,priv)
#define foil_rsa_verify(bytes,signature,digest_type,pub) \
    foil_verify(bytes,signature,digest_type,FOIL_CIPHER_RSA_DECRYPT,pub)

G_END_DECLS

#endif /* FOIL_SIGN_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
