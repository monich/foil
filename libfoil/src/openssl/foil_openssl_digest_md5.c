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

#include "foil_digest_p.h"

#include <openssl/md5.h>

/* Logging */
#define GLOG_MODULE_NAME foil_log_digest
#include "foil_log_p.h"

typedef FoilDigestMD5Class FoilOpensslDigestMD5Class;
typedef struct foil_openssl_digest_md5 {
    FoilDigestMD5 md5;
    MD5_CTX ctx;
} FoilOpensslDigestMD5;

G_DEFINE_TYPE(FoilOpensslDigestMD5, foil_openssl_digest_md5, \
        FOIL_TYPE_DIGEST_MD5)
#define FOIL_OPENSSL_DIGEST_MD5(obj) (G_TYPE_CHECK_INSTANCE_CAST(obj, \
        FOIL_DIGEST_MD5, FoilOpensslDigestMD5))

GType
foil_impl_digest_md5_get_type()
{
    return foil_openssl_digest_md5_get_type();
}

static
void
foil_openssl_digest_md5_update(
    FoilDigest* digest,
    const void* data,
    size_t size)
{
    FoilOpensslDigestMD5* self = FOIL_OPENSSL_DIGEST_MD5(digest);
    MD5_Update(&self->ctx, data, size);
}

static
void
foil_openssl_digest_md5_finish(
    FoilDigest* digest,
    void* md)
{
    FoilOpensslDigestMD5* self = FOIL_OPENSSL_DIGEST_MD5(digest);
    if (md) {
        MD5_Final(md, &self->ctx);
    } else {
        memset(&self->ctx, 0, sizeof(self->ctx));
    }
}

static
void
foil_openssl_digest_md5_digest(
    const void* data,
    size_t size,
    void* digest)
{
    MD5(data, size, digest);
}

static
void
foil_openssl_digest_md5_init(
    FoilOpensslDigestMD5* self)
{
    MD5_Init(&self->ctx);
}

static
void
foil_openssl_digest_md5_class_init(
    FoilOpensslDigestMD5Class* klass)
{
    GASSERT(klass->size == MD5_DIGEST_LENGTH);
    klass->fn_digest = foil_openssl_digest_md5_digest;
    klass->fn_update = foil_openssl_digest_md5_update;
    klass->fn_finish = foil_openssl_digest_md5_finish;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
