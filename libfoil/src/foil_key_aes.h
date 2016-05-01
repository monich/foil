/*
 * Copyright (C) 2016-2017 by Slava Monich
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

#ifndef FOIL_KEY_AES_H
#define FOIL_KEY_AES_H

#include "foil_key_p.h"

#define FOIL_AES_MAX_KEY_SIZE (32)
#define FOIL_AES_BLOCK_SIZE   (16)

typedef struct foil_key_aes_class {
    FoilKeyClass key;
    guint size;  /* 16, 24 or 32 (bytes) */
} FoilKeyAesClass;

typedef struct foil_key_aes {
    FoilKey super;
    guint8 iv[FOIL_AES_BLOCK_SIZE];
    guint8* key;  /* klass->size bytes */
} FoilKeyAes;

#define FOIL_KEY_AES_(obj) (G_TYPE_CHECK_INSTANCE_CAST(obj, \
        FOIL_TYPE_KEY_AES, FoilKeyAes))
#define FOIL_KEY_AES_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
        FOIL_TYPE_KEY_AES, FoilKeyAesClass))
#define FOIL_KEY_AES_GET_CLASS(obj) G_TYPE_INSTANCE_GET_CLASS(obj,\
        FOIL_TYPE_KEY_AES, FoilKeyAesClass)
#define FOIL_IS_AES_KEY(obj) G_TYPE_CHECK_INSTANCE_TYPE(obj, \
        FOIL_TYPE_KEY_AES)

#endif /* FOIL_KEY_AES_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
