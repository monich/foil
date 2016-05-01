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

typedef struct foil_input_mem {
    FoilInput parent;
    GBytes* bytes;
    const guint8* data;
    gsize bytes_available;
} FoilInputMem;

static
gboolean
foil_input_mem_has_available(
    FoilInput* in,
    gsize count)
{
    FoilInputMem* self = G_CAST(in, FoilInputMem, parent);
    return self->bytes_available >= count;
}

static
gssize
foil_input_mem_read(
    FoilInput* in,
    void* buf,
    gsize size)
{
    FoilInputMem* self = G_CAST(in, FoilInputMem, parent);
    if (self->bytes_available) {
        const gssize bytes_copied = MIN(size, self->bytes_available);
        if (buf) {
            memcpy(buf, self->data, bytes_copied);
        }
        self->bytes_available -= bytes_copied;
        self->data += bytes_copied;
        return bytes_copied;
    } else {
        return 0;
    }
}

static
void
foil_input_mem_close(
    FoilInput* in)
{
    FoilInputMem* self = G_CAST(in, FoilInputMem, parent);
    self->data = NULL;
    self->bytes_available = 0;
    if (self->bytes) {
        g_bytes_unref(self->bytes);
        self->bytes = NULL;
    }
}

static
void
foil_input_mem_free(
    FoilInput* in)
{
    FoilInputMem* self = G_CAST(in, FoilInputMem, parent);
    GASSERT(!self->bytes);
    foil_input_finalize(in);
    g_slice_free(FoilInputMem, self);
}

static const FoilInputFunc foil_input_mem_fn = {
    foil_input_mem_has_available,  /* fn_has_available */
    foil_input_mem_read,           /* fn_read */
    foil_input_mem_close,          /* fn_close */
    foil_input_mem_free            /* fn_free */
};

FoilInput*
foil_input_mem_new(
    GBytes* bytes)
{
    FoilInputMem* self = g_slice_new0(FoilInputMem);
    if (bytes) {
        self->bytes = g_bytes_ref(bytes);
        self->data = g_bytes_get_data(bytes, &self->bytes_available);
    }
    return foil_input_init(&self->parent, &foil_input_mem_fn);
}

FoilInput*
foil_input_mem_new_static(
    const void* data,
    gsize size)
{
    FoilInputMem* self = g_slice_new0(FoilInputMem);
    self->data = data;
    self->bytes_available = size;
    return foil_input_init(&self->parent, &foil_input_mem_fn);
}

FoilInput*
foil_input_mem_new_bytes(
    const FoilBytes* bytes)
{
    FoilInputMem* self = g_slice_new0(FoilInputMem);
    if (bytes) {
        self->data = bytes->val;
        self->bytes_available = bytes->len;
    }
    return foil_input_init(&self->parent, &foil_input_mem_fn);
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
