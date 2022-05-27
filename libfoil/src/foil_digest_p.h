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

#ifndef FOIL_DIGEST_P_H
#define FOIL_DIGEST_P_H

#include "foil_types_p.h"
#include "foil_digest.h"

struct foil_digest {
    GObject object;
    GBytes* result;
};

typedef struct foil_digest_class {
    GObjectClass object;
    const char* name;
    gsize size;
    gsize block_size;
    FoilBytes oid;
    void* (*fn_digest_alloc)(void);
    void (*fn_digest_free)(void* md);
    void (*fn_digest)(const void* in, gsize n, void* md);
    void (*fn_copy)(FoilDigest* digest, FoilDigest* source);
    void (*fn_update)(FoilDigest* digest, const void* data, gsize size);
    void (*fn_finish)(FoilDigest* digest, void* md);
} FoilDigestClass;

typedef FoilDigest FoilDigestMD5;
typedef FoilDigest FoilDigestSHA1;
typedef FoilDigest FoilDigestSHA256;
typedef FoilDigest FoilDigestSHA512;

typedef FoilDigestClass FoilDigestMD5Class;
typedef FoilDigestClass FoilDigestSHA1Class;
typedef FoilDigestClass FoilDigestSHA256Class;
typedef FoilDigestClass FoilDigestSHA512Class;

/* Abstract types */
GType foil_digest_get_type(void) FOIL_INTERNAL;
GType foil_digest_md5_get_type(void) FOIL_INTERNAL;
GType foil_digest_sha1_get_type(void) FOIL_INTERNAL;
GType foil_digest_sha256_get_type(void) FOIL_INTERNAL;
GType foil_digest_sha512_get_type(void) FOIL_INTERNAL;
#define FOIL_TYPE_DIGEST (foil_digest_get_type())
#define FOIL_TYPE_DIGEST_MD5 (foil_digest_md5_get_type())
#define FOIL_TYPE_DIGEST_SHA1 (foil_digest_sha1_get_type())
#define FOIL_TYPE_DIGEST_SHA256 (foil_digest_sha256_get_type())
#define FOIL_TYPE_DIGEST_SHA512 (foil_digest_sha512_get_type())

#define FOIL_DIGEST_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
        FOIL_TYPE_DIGEST, FoilDigestClass))

/* Internal API */

gsize
foil_digest_type_block_size(
    GType type)
    FOIL_INTERNAL;

gsize
foil_digest_block_size(
    FoilDigest* digest)
    FOIL_INTERNAL;

#endif /* FOIL_DIGEST_P_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
