/*
 * Copyright (C) 2017 by Slava Monich
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

#include "test_common.h"
#include "foil_output_p.h"

typedef struct test_output_mem {
    FoilOutput parent;
    GByteArray* buf;
    gssize maxsize;
    guint flags;
    gboolean flush_failed;
} TestOutputMem;

static
gssize
test_output_mem_write(
    FoilOutput* out,
    const void* buf,
    gsize size)
{
    TestOutputMem* self = G_CAST(out, TestOutputMem, parent);
    if (self->flags & TEST_OUTPUT_WRITE_FAILS) {
        return -1;
    } else {
        if (self->maxsize >= 0 &&
            (self->buf->len + size) > (gsize)self->maxsize) {
            size = self->maxsize - self->buf->len;
        }
        g_byte_array_append(self->buf, buf, size);
        return size;
    }
}

static
gboolean
test_output_mem_flush(
    FoilOutput* out)
{
    TestOutputMem* self = G_CAST(out, TestOutputMem, parent);
    if ((self->flags & TEST_OUTPUT_FLUSH_FAILS_ALWAYS) ||
        ((self->flags & TEST_OUTPUT_FLUSH_FAILS_ONCE) &&
         !self->flush_failed)) {
        GDEBUG("Simulating flush failure%s",
            (self->flags & TEST_OUTPUT_FLUSH_FAILS_ONCE) ? " (once)" : "");
        self->flush_failed = TRUE;
        return FALSE;
    } else {
        return TRUE;
    }
}

static
gboolean
test_output_mem_reset(
    FoilOutput* out)
{
    TestOutputMem* self = G_CAST(out, TestOutputMem, parent);
    g_byte_array_set_size(self->buf, 0);
    return TRUE;
}

static
GBytes*
test_output_mem_to_bytes(
    FoilOutput* out)
{
    TestOutputMem* self = G_CAST(out, TestOutputMem, parent);
    return g_byte_array_free_to_bytes(self->buf);
}

static
void
test_output_mem_close(
    FoilOutput* out)
{
    TestOutputMem* self = G_CAST(out, TestOutputMem, parent);
    g_byte_array_unref(self->buf);
}

static
void
test_output_mem_free(
    FoilOutput* out)
{
    TestOutputMem* self = G_CAST(out, TestOutputMem, parent);
    g_slice_free(TestOutputMem, self);
}

FoilOutput*
test_output_mem_new(
    gssize maxsize,
    guint flags)
{
    static const FoilOutputFunc test_output_mem_fn = {
        test_output_mem_write,      /* fn_write */
        test_output_mem_flush,      /* fn_flush */
        test_output_mem_reset,      /* fn_reset */
        test_output_mem_to_bytes,   /* fn_to_bytes */
        test_output_mem_close,      /* fn_close */
        test_output_mem_free        /* fn_free */
    };
    TestOutputMem* mem = g_slice_new0(TestOutputMem);
    mem->buf = g_byte_array_new();
    mem->maxsize = maxsize;
    mem->flags = flags;
    return foil_output_init(&mem->parent, &test_output_mem_fn);
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
