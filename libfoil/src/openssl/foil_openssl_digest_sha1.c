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

#include <openssl/sha.h>

/* Logging */
#define GLOG_MODULE_NAME foil_log_digest
#include "foil_log_p.h"

typedef FoilDigestSHA1Class FoilOpensslDigestSHA1Class;
typedef struct foil_openssl_digest_sha1 {
    FoilDigestSHA1 sha1;
    SHA_CTX ctx;
} FoilOpensslDigestSHA1;

G_DEFINE_TYPE(FoilOpensslDigestSHA1, foil_openssl_digest_sha1, \
        FOIL_TYPE_DIGEST_SHA1)
#define FOIL_OPENSSL_DIGEST_SHA1(obj) (G_TYPE_CHECK_INSTANCE_CAST(obj, \
        FOIL_DIGEST_SHA1, FoilOpensslDigestSHA1))

GType
foil_impl_digest_sha1_get_type()
{
    return foil_openssl_digest_sha1_get_type();
}

static
void
foil_openssl_digest_sha1_update(
    FoilDigest* digest,
    const void* data,
    size_t size)
{
    FoilOpensslDigestSHA1* self = FOIL_OPENSSL_DIGEST_SHA1(digest);
    SHA1_Update(&self->ctx, data, size);
}

static
void
foil_openssl_digest_sha1_finish(
    FoilDigest* digest,
    void* md)
{
    FoilOpensslDigestSHA1* self = FOIL_OPENSSL_DIGEST_SHA1(digest);
    if (G_LIKELY(md)) {
        SHA1_Final(md, &self->ctx);
    } else {
        memset(&self->ctx, 0, sizeof(self->ctx));
    }
}

static
void
foil_openssl_digest_sha1_digest(
    const void* data,
    size_t size,
    void* digest)
{
    SHA1(data, size, digest);
}

static
void
foil_openssl_digest_sha1_init(
    FoilOpensslDigestSHA1* self)
{
    SHA1_Init(&self->ctx);
}

static
void
foil_openssl_digest_sha1_class_init(
    FoilOpensslDigestSHA1Class* klass)
{
    GASSERT(klass->size == SHA_DIGEST_LENGTH);
    klass->fn_digest = foil_openssl_digest_sha1_digest;
    klass->fn_update = foil_openssl_digest_sha1_update;
    klass->fn_finish = foil_openssl_digest_sha1_finish;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
