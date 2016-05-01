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

#include <gutil_macros.h>

/* Logging */
#define GLOG_MODULE_NAME foil_log_output
#include "foil_log_p.h"

typedef struct foil_output_mem {
    FoilOutput parent;
    GByteArray* buf;
    gsize offset;
} FoilOutputMem;

static
gssize
foil_output_mem_write(
    FoilOutput* out,
    const void* buf,
    gsize size)
{
    FoilOutputMem* self = G_CAST(out, FoilOutputMem, parent);
    g_byte_array_append(self->buf, buf, size);
    return size;
}

static
gboolean
foil_output_mem_flush(
    FoilOutput* out)
{
    return TRUE;
}

static
gboolean
foil_output_mem_reset(
    FoilOutput* out)
{
    FoilOutputMem* self = G_CAST(out, FoilOutputMem, parent);
    g_byte_array_set_size(self->buf, 0);
    return TRUE;
}

static
GBytes*
foil_output_mem_to_bytes(
    FoilOutput* out)
{
    FoilOutputMem* self = G_CAST(out, FoilOutputMem, parent);
    GBytes* bytes = g_byte_array_free_to_bytes(self->buf);
    const gsize size = g_bytes_get_size(bytes);
    self->buf = NULL;
    GASSERT(size == self->offset + out->bytes_written);
    if (size != self->offset + out->bytes_written) {
        g_bytes_unref(bytes);
        bytes = NULL;
    } else if (self->offset) {
        GBytes* our_bytes = g_bytes_new_from_bytes(bytes,
            self->offset, size - self->offset);
        g_bytes_unref(bytes);
        bytes = our_bytes;
    }
    return bytes;
}

static
void
foil_output_mem_close(
    FoilOutput* out)
{
    FoilOutputMem* self = G_CAST(out, FoilOutputMem, parent);
    g_byte_array_unref(self->buf);
    self->buf = NULL;
}

static
void
foil_output_mem_free(
    FoilOutput* out)
{
    FoilOutputMem* self = G_CAST(out, FoilOutputMem, parent);
    GASSERT(!self->buf);
    g_slice_free(FoilOutputMem, self);
}

FoilOutput*
foil_output_mem_new(
    GByteArray* buf)
{
    static const FoilOutputFunc foil_output_mem_fn = {
        foil_output_mem_write,      /* fn_write */
        foil_output_mem_flush,      /* fn_flush */
        foil_output_mem_reset,      /* fn_reset */
        foil_output_mem_to_bytes,   /* fn_to_bytes */
        foil_output_mem_close,      /* fn_close */
        foil_output_mem_free        /* fn_free */
    };
    FoilOutputMem* mem = g_slice_new0(FoilOutputMem);
    if (buf) {
        mem->buf = g_byte_array_ref(buf);
        mem->offset = buf->len;
    } else {
        mem->buf = g_byte_array_new();
    }
    return foil_output_init(&mem->parent, &foil_output_mem_fn);
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
