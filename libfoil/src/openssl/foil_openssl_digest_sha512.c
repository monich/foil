/*
 * Copyright (C) 2021-2023 Slava Monich <slava@monich.com>
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

#include "foil_digest_p.h"

/* Yes we know that this API is deprecated */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/sha.h>

/* Logging */
#define GLOG_MODULE_NAME foil_log_digest
#include "foil_log_p.h"

typedef FoilDigestSHA512Class FoilOpensslDigestSHA512Class;
typedef struct foil_openssl_digest_sha512 {
    FoilDigestSHA512 sha512;
    SHA512_CTX ctx;
} FoilOpensslDigestSHA512;

#define THIS_TYPE foil_openssl_digest_sha512_get_type()
#define THIS(obj) (G_TYPE_CHECK_INSTANCE_CAST(obj, THIS_TYPE, \
    FoilOpensslDigestSHA512))

GType THIS_TYPE FOIL_INTERNAL;
G_DEFINE_TYPE(FoilOpensslDigestSHA512, foil_openssl_digest_sha512, \
    FOIL_TYPE_DIGEST_SHA512)

GType
foil_impl_digest_sha512_get_type()
{
    return THIS_TYPE;
}

static
void
foil_openssl_digest_sha512_copy(
    FoilDigest* digest,
    FoilDigest* source)
{
    THIS(digest)->ctx = THIS(source)->ctx;
}

static
void
foil_openssl_digest_sha512_reset(
    FoilDigest* digest)
{
    SHA512_Init(&(THIS(digest)->ctx));
}

static
void
foil_openssl_digest_sha512_update(
    FoilDigest* digest,
    const void* data,
    size_t size)
{
    SHA512_Update(&(THIS(digest)->ctx), data, size);
}

static
void
foil_openssl_digest_sha512_finish(
    FoilDigest* digest,
    void* md)
{
    FoilOpensslDigestSHA512* self = THIS(digest);

    if (G_LIKELY(md)) {
        SHA512_Final(md, &self->ctx);
    } else {
        memset(&self->ctx, 0, sizeof(self->ctx));
    }
}

static
void
foil_openssl_digest_sha512_digest(
    const void* data,
    size_t size,
    void* digest)
{
    SHA512(data, size, digest);
}

static
void
foil_openssl_digest_sha512_init(
    FoilOpensslDigestSHA512* self)
{
    SHA512_Init(&self->ctx);
}

static
void
foil_openssl_digest_sha512_class_init(
    FoilOpensslDigestSHA512Class* klass)
{
    GASSERT(klass->size == SHA512_DIGEST_LENGTH);
    klass->fn_copy = foil_openssl_digest_sha512_copy;
    klass->fn_reset = foil_openssl_digest_sha512_reset;
    klass->fn_digest = foil_openssl_digest_sha512_digest;
    klass->fn_update = foil_openssl_digest_sha512_update;
    klass->fn_finish = foil_openssl_digest_sha512_finish;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
