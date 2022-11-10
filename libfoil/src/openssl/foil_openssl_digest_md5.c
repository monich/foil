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

#define THIS_TYPE foil_openssl_digest_md5_get_type()
#define THIS(obj) G_TYPE_CHECK_INSTANCE_CAST(obj, THIS_TYPE, \
    FoilOpensslDigestMD5)

GType THIS_TYPE FOIL_INTERNAL;
G_DEFINE_TYPE(FoilOpensslDigestMD5, foil_openssl_digest_md5, \
    FOIL_TYPE_DIGEST_MD5)

GType
foil_impl_digest_md5_get_type()
{
    return THIS_TYPE;
}

static
void
foil_openssl_digest_md5_copy(
    FoilDigest* digest,
    FoilDigest* source)
{
    THIS(digest)->ctx = THIS(source)->ctx;
}

static
void
foil_openssl_digest_md5_reset(
    FoilDigest* digest)
{
    MD5_Init(&(THIS(digest)->ctx));
}

static
void
foil_openssl_digest_md5_update(
    FoilDigest* digest,
    const void* data,
    size_t size)
{
    MD5_Update(&(THIS(digest)->ctx), data, size);
}

static
void
foil_openssl_digest_md5_finish(
    FoilDigest* digest,
    void* md)
{
    FoilOpensslDigestMD5* self = THIS(digest);

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
    klass->fn_copy = foil_openssl_digest_md5_copy;
    klass->fn_reset = foil_openssl_digest_md5_reset;
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
