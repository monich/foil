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

#include "foil_input_p.h"
#include "foil_digest.h"
#include "foil_log_p.h"

#include <gutil_macros.h>

typedef struct foil_input_digest {
    FoilInput parent;
    FoilInput* in;
    FoilDigest* digest;
    void* buf;
} FoilInputDigest;

static
gboolean
foil_input_digest_has_available(
    FoilInput* in,
    gsize nbytes)
{
    FoilInputDigest* self = G_CAST(in, FoilInputDigest, parent);
    return foil_input_has_available(self->in, nbytes);
}

static
gssize
foil_input_digest_read(
    FoilInput* in,
    void* buf,
    gsize size)
{
    FoilInputDigest* self = G_CAST(in, FoilInputDigest, parent);
    gssize bytes_read;
    if (buf || !size) {
        bytes_read = foil_input_read(self->in, buf, size);
        if (bytes_read > 0) {
            foil_digest_update(self->digest, buf, bytes_read);
        }
    } else {
        /* Buffer is NULL, digest and drop size bytes from the input */
        const gssize max_chunk = foil_digest_size(self->digest);
        gssize bytes_left = size, nbytes;
        gssize chunk = MIN(max_chunk, bytes_left);
        if (!self->buf) self->buf = g_malloc(max_chunk);
        bytes_read = 0;
        while (chunk > 0 && (nbytes = foil_input_read(self->in, self->buf,
            MIN(max_chunk, bytes_left))) > 0) {
            foil_digest_update(self->digest, self->buf, nbytes);
            bytes_read += nbytes;
            bytes_left -= nbytes;
            chunk = MIN(max_chunk, bytes_left);
        }
    }
    return bytes_read;
}

static
void
foil_input_digest_close(
    FoilInput* in)
{
    FoilInputDigest* self = G_CAST(in, FoilInputDigest, parent);
    foil_input_unref(self->in);
    foil_digest_unref(self->digest);
    self->in = NULL;
    self->digest = NULL;
}

static
void
foil_input_digest_free(
    FoilInput* in)
{
    FoilInputDigest* self = G_CAST(in, FoilInputDigest, parent);
    GASSERT(!self->in);
    GASSERT(!self->digest);
    foil_input_finalize(in);
    g_free(self->buf);
    g_slice_free(FoilInputDigest, self);
}

FoilInput*
foil_input_digest_new(
    FoilInput* in,
    FoilDigest* digest)
{
    static const FoilInputFunc foil_input_digest_fn = {
        foil_input_digest_has_available,  /* fn_has_available */
        foil_input_digest_read,           /* fn_read */
        foil_input_digest_close,          /* fn_close */
        foil_input_digest_free            /* fn_free */
    };
    if (G_LIKELY(in)) {
        FoilInputDigest* self = g_slice_new0(FoilInputDigest);
        self->in = foil_input_ref(in);
        self->digest = foil_digest_ref(digest);
        return foil_input_init(&self->parent, &foil_input_digest_fn);
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
