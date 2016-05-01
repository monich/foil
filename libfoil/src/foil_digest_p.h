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
    FoilBytes oid;
    void* (*fn_digest_alloc)(void);
    void (*fn_digest_free)(void* md);
    void (*fn_digest)(const void* in, gsize n, void* md);
    void (*fn_update)(FoilDigest* digest, const void* data, gsize size);
    void (*fn_finish)(FoilDigest* digest, void* md);
} FoilDigestClass;

typedef FoilDigest FoilDigestMD5;
typedef FoilDigest FoilDigestSHA1;
typedef FoilDigest FoilDigestSHA256;

typedef FoilDigestClass FoilDigestMD5Class;
typedef FoilDigestClass FoilDigestSHA1Class;
typedef FoilDigestClass FoilDigestSHA256Class;

/* Abstract types */
GType foil_digest_get_type(void);
GType foil_digest_md5_get_type(void);
GType foil_digest_sha1_get_type(void);
GType foil_digest_sha256_get_type(void);
#define FOIL_TYPE_DIGEST (foil_digest_get_type())
#define FOIL_TYPE_DIGEST_MD5 (foil_digest_md5_get_type())
#define FOIL_TYPE_DIGEST_SHA1 (foil_digest_sha1_get_type())
#define FOIL_TYPE_DIGEST_SHA256 (foil_digest_sha256_get_type())

#define FOIL_DIGEST_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
        FOIL_TYPE_DIGEST, FoilDigestClass))

#endif /* FOIL_DIGEST_P_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
