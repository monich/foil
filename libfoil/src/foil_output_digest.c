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

#include "foil_output_p.h"
#include "foil_digest.h"

#include <gutil_macros.h>

/* Logging */
#define GLOG_MODULE_NAME foil_log_output
#include "foil_log_p.h"

typedef struct foil_output_digest {
    FoilOutput parent;
    FoilOutput* out;
    FoilDigest* digest;
} FoilOutputDigest;

static
gssize
foil_output_digest_write(
    FoilOutput* out,
    const void* buf,
    gsize size)
{
    FoilOutputDigest* self = G_CAST(out, FoilOutputDigest, parent);
    gssize written = foil_output_write(self->out, buf, size);
    if (written > 0) {
        foil_digest_update(self->digest, buf, written);
    }
    return written;
}

static
gboolean
foil_output_digest_flush(
    FoilOutput* out)
{
    return TRUE;
}

static
gboolean
foil_output_digest_reset(
    FoilOutput* out)
{
    return FALSE;
}

static
GBytes*
foil_output_digest_to_bytes(
    FoilOutput* out)
{
    FoilOutputDigest* self = G_CAST(out, FoilOutputDigest, parent);
    GBytes* bytes = foil_output_free_to_bytes(self->out);
    foil_digest_unref(self->digest);
    self->out = NULL;
    self->digest = NULL;
    return bytes;
}

static
void
foil_output_digest_close(
    FoilOutput* out)
{
    FoilOutputDigest* self = G_CAST(out, FoilOutputDigest, parent);
    foil_output_unref(self->out);
    foil_digest_unref(self->digest);
    self->out = NULL;
    self->digest = NULL;
}

static
void
foil_output_digest_free(
    FoilOutput* out)
{
    FoilOutputDigest* self = G_CAST(out, FoilOutputDigest, parent);
    GASSERT(!self->out);
    GASSERT(!self->digest);
    g_slice_free(FoilOutputDigest, self);
}

FoilOutput*
foil_output_digest_new(
    FoilOutput* out,
    FoilDigest* digest)
{
    static const FoilOutputFunc foil_output_digest_fn = {
        foil_output_digest_write,       /* fn_write */
        foil_output_digest_flush,       /* fn_flush */
        foil_output_digest_reset,       /* fn_reset */
        foil_output_digest_to_bytes,    /* fn_to_bytes */
        foil_output_digest_close,       /* fn_close */
        foil_output_digest_free         /* fn_free */
    };
    if (G_LIKELY(out)) {
        FoilOutputDigest* self = g_slice_new0(FoilOutputDigest);
        self->out = foil_output_ref(out);
        self->digest = foil_digest_ref(digest);
        return foil_output_init(&self->parent, &foil_output_digest_fn);
    }
    return NULL;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
