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

#ifndef FOIL_KEY_DES_H
#define FOIL_KEY_DES_H

#include "foil_key.h"

/* DES specific stuff */

/* Since 1.0.16 */

G_BEGIN_DECLS

#define FOIL_DES_KEY_BITS   (56)
#define FOIL_DES_KEY_SIZE   (8) /* 56 key bits + 8 bits parity bits */
#define FOIL_DES_BLOCK_SIZE (8)
#define FOIL_DES_IV_SIZE    FOIL_DES_BLOCK_SIZE

void
foil_key_des_adjust_parity(
    void* key /* FOIL_DES_KEY_SIZE bytes */);

FoilKey*
foil_key_des_new(
    const guint8* iv /* Optional */,
    const guint8* key1,
    const guint8* key2,
    const guint8* key3 /* Optional */); /* Since 1.0.16 */

FoilKey*
foil_key_des_new_from_bytes(
    GBytes* iv /* Optional */,
    GBytes* key1,
    GBytes* key2,
    GBytes* key3 /* Optional */); /* Since 1.0.16 */

G_END_DECLS

#endif /* FOIL_KEY_DES_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
