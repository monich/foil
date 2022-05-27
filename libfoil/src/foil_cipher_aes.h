/*
 * Copyright (C) 2016-2022 by Slava Monich
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

#ifndef FOIL_CIPHER_AES_H
#define FOIL_CIPHER_AES_H

#include "foil_cipher_sync.h"
#include "foil_key_aes.h"

typedef FoilCipherSyncClass FoilCipherAesClass;
typedef struct foil_cipher_aes {
    FoilCipherSync sync;
    guint8 block[FOIL_AES_BLOCK_SIZE];
} FoilCipherAes;

GType foil_cipher_aes_get_type(void) FOIL_INTERNAL;
#define FOIL_TYPE_CIPHER_AES (foil_cipher_aes_get_type())
#define FOIL_CIPHER_AES(obj) (G_TYPE_CHECK_INSTANCE_CAST(obj, \
        FOIL_TYPE_CIPHER_AES, FoilCipherAes))
#define FOIL_CIPHER_AES_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
        FOIL_TYPE_CIPHER_AES, FoilCipherAesClass))
#define FOIL_CIPHER_AES_GET_CLASS(obj) G_TYPE_INSTANCE_GET_CLASS((obj),\
        FOIL_TYPE_CIPHER_AES, FoilCipherAesClass)

#endif /* FOIL_CIPHER_AES_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
