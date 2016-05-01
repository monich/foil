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

#include "foil_input_p.h"
#include "foil_log_p.h"

#include <gutil_macros.h>

typedef struct foil_input_range {
    FoilInput parent;
    FoilInput* in;
    gsize max_bytes;
} FoilInputRange;

static
gboolean
foil_input_range_has_available(
    FoilInput* in,
    gsize n)
{
    FoilInputRange* self = G_CAST(in, FoilInputRange, parent);
    return n <= self->max_bytes && foil_input_has_available(self->in, n);
}

static
gssize
foil_input_range_read(
    FoilInput* in,
    void* buf,
    gsize size)
{
    FoilInputRange* self = G_CAST(in, FoilInputRange, parent);
    if (self->max_bytes) {
        gssize bytes_read;
        if (size > self->max_bytes) {
            size = self->max_bytes;
        }
        bytes_read = foil_input_read(self->in, buf, size);
        if (bytes_read > 0) {
            self->max_bytes -= bytes_read;
        }
        return bytes_read;
    } else {
        return 0;
    }
}

static
void
foil_input_range_close(
    FoilInput* in)
{
    FoilInputRange* self = G_CAST(in, FoilInputRange, parent);
    foil_input_unref(self->in);
    self->in = NULL;
}

static
void
foil_input_range_free(
    FoilInput* in)
{
    FoilInputRange* self = G_CAST(in, FoilInputRange, parent);
    GASSERT(!self->in);
    foil_input_finalize(in);
    g_slice_free(FoilInputRange, self);
}

FoilInput*
foil_input_range_new(
    FoilInput* in,
    gsize offset,
    gsize max_bytes)
{
    static const FoilInputFunc foil_input_range_fn = {
        foil_input_range_has_available,  /* fn_has_available */
        foil_input_range_read,           /* fn_read */
        foil_input_range_close,          /* fn_close */
        foil_input_range_free            /* fn_free */
    };
    if (G_LIKELY(in)) {
        FoilInputRange* self = g_slice_new0(FoilInputRange);
        self->in = foil_input_ref(in);
        self->max_bytes = max_bytes;
        if (offset) {
            const gssize skipped = foil_input_skip(in, offset);
            if (skipped < 0 || (gsize)skipped != offset) {
                self->max_bytes = 0;
            }
        }
        return foil_input_init(&self->parent, &foil_input_range_fn);
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
