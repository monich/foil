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
#include "foil_output.h"
#include "foil_log_p.h"

#define DEFAULT_READ_CHUNK (0x1000)

FoilInput*
foil_input_init(
    FoilInput* in,
    const FoilInputFunc* fn)
{
    /* Caller is supposed to zero-initialize the whole thing */
    GASSERT(!in->bytes_read);
    GASSERT(!in->peek_offset);
    GASSERT(!in->peek_buf);
    in->ref_count = 1;
    in->fn = fn;
    return in;
}

void
foil_input_finalize(
    FoilInput* in)
{
    GASSERT(!in->peek_buf);
}

FoilInput*
foil_input_ref(
    FoilInput* in)
{
    if (G_LIKELY(in)) {
        GASSERT(in->ref_count > 0);
        g_atomic_int_inc(&in->ref_count);
    }
    return in;
}

void
foil_input_unref(
    FoilInput* in)
{
    if (G_LIKELY(in)) {
        GASSERT(in->ref_count > 0);
        if (g_atomic_int_dec_and_test(&in->ref_count)) {
            foil_input_close(in);
            in->fn->fn_free(in);
        }
    }
}

gssize
foil_input_read(
    FoilInput* in,
    void* buf,
    gsize size)
{
    gssize read = -1;
    if (G_LIKELY(in) && !in->closed) {
        GASSERT(in->ref_count > 0);
        if (G_LIKELY(size)) {
            guint8* ptr = buf;
            if (in->peek_buf && in->peek_buf->len) {
                /* Copy data from the peek buffer */
                const gsize available = in->peek_buf->len - in->peek_offset;
                const gsize copied = MIN(available, size);
                if (ptr) {
                    memcpy(ptr, in->peek_buf->data + in->peek_offset, copied);
                    ptr += copied;
                }
                in->peek_offset += copied;
                in->bytes_read += copied;
                size -= copied;
                if (in->peek_buf->len == in->peek_offset) {
                    /* Reset the buffer */
                    g_byte_array_set_size(in->peek_buf, 0);
                    in->peek_offset = 0;
                }
                read = copied;
            } else {
                read = 0;
            }
            /* Need more bytes? */
            if (size > 0) {
                const gssize more_bytes = in->fn->fn_read(in, ptr, size);
                if (more_bytes > 0) {
                    GASSERT((gsize)more_bytes <= size);
                    in->bytes_read += more_bytes;
                    read += more_bytes;
                } else if (more_bytes < 0 && !read) {
                    read = -1;
                }
            }
        } else {
            read = 0;
        }
    }
    return read;
}

gssize
foil_input_copy(
    FoilInput* in,
    FoilOutput* out,
    gsize size)
{
    if (G_LIKELY(in) && !in->closed) {
        gssize copied = 0;
        if (G_LIKELY(size > 0)) {
            const gsize chunk_size = MIN(size, DEFAULT_READ_CHUNK);
            void* chunk = g_slice_alloc(chunk_size);
            while (size > 0) {
                const gsize count = MIN(size, chunk_size);
                gssize real_count = foil_input_read(in, chunk, count);
                if (real_count > 0) {
                    real_count = foil_output_write(out, chunk, real_count);
                    if (real_count > 0) {
                        copied += real_count;
                        if ((gsize)real_count == count) {
                            size -= count;
                            continue;
                        }
                    }
                }
                /* Couldn't copy the entire chunk */
                break;
            }
            g_slice_free1(chunk_size, chunk);
        }
        return copied;
    }
    return -1;
}

/* Since 1.0.1 */
gboolean
foil_input_copy_all(
    FoilInput* in,
    FoilOutput* out,
    gsize* copied)
{
    gboolean ok = FALSE;
    gsize total = 0;
    if (G_LIKELY(in) && G_LIKELY(out) && !in->closed) {
        const gsize chunk_size = DEFAULT_READ_CHUNK;
        void* chunk = g_slice_alloc(chunk_size);
        gssize bytes_in;
        ok = TRUE;
        while ((bytes_in = foil_input_read(in, chunk, chunk_size)) > 0) {
            const gssize bytes_out = foil_output_write(out, chunk, bytes_in);
            if (bytes_out > 0) {
                total += bytes_out;
                if (bytes_out == bytes_in) {
                    continue;
                }
            }
            ok = FALSE;
            break;
        }
        if (bytes_in < 0 || !foil_output_flush(out)) {
            ok = FALSE;
        }
        g_slice_free1(chunk_size, chunk);
    }
    if (copied) {
        *copied = total;
    }
    return ok;
}

gboolean
foil_input_has_available(
    FoilInput* in,
    gsize count)
{
    if (G_LIKELY(in)) {
        if (count > 0) {
            gsize available;
            if (in->peek_buf) {
                GASSERT(in->peek_buf->len >= in->peek_offset);
                available = in->peek_buf->len - in->peek_offset;
            } else {
                available = 0;
            }
            if (available >= count) {
                return TRUE;
            } else if (in->fn->fn_has_available) {
                return in->fn->fn_has_available(in, count - available);
            } else {
                return foil_input_peek(in, count, &available) &&
                    available >= count;
            }
        } else {
            return TRUE;
        }
    }
    return FALSE;
}

const void*
foil_input_peek(
    FoilInput* in,
    gsize requested,
    gsize* available)
{
    if (G_LIKELY(in) && !in->closed) {
        gsize have_bytes = 0;
        if (in->peek_buf) {
            GASSERT(in->peek_buf->len >= in->peek_offset);
            have_bytes = in->peek_buf->len - in->peek_offset;
        }
        if (requested > have_bytes) {
            /* Need to read more data */
            gssize more_bytes;
            if (in->peek_offset) {
                g_byte_array_remove_range(in->peek_buf, 0, in->peek_offset);
                GASSERT(in->peek_buf->len == have_bytes);
                in->peek_offset = 0;
            }
            if (!in->peek_buf) {
                in->peek_buf = g_byte_array_sized_new(requested);
            }
            g_byte_array_set_size(in->peek_buf, requested);
            more_bytes = in->fn->fn_read(in, in->peek_buf->data + have_bytes,
                requested - have_bytes);
            if (more_bytes > 0) {
                have_bytes += more_bytes;
            }
            g_byte_array_set_size(in->peek_buf, have_bytes);
        }
        if (available) {
            *available = have_bytes;
        }
        if (have_bytes >= requested) {
            return in->peek_buf->data + in->peek_offset;
        }
    }
    return NULL;
}

void
foil_input_push_back(
    FoilInput* in,
    const void* buf,
    gsize size)
{
    if (G_LIKELY(in) && !in->closed) {
        GASSERT(size <= in->bytes_read);
        if (buf && size && size <= in->bytes_read) {
            if (!in->peek_buf) {
                in->peek_buf = g_byte_array_sized_new(size);
            }
            if (in->peek_offset) {
                g_byte_array_remove_range(in->peek_buf, 0, in->peek_offset);
                in->peek_offset = 0;
            }
            g_byte_array_prepend(in->peek_buf, buf, size);
            in->bytes_read -= size;
        }
    }
}

gsize
foil_input_bytes_read(
    FoilInput* in)
{
    return G_LIKELY(in) ? in->bytes_read : 0;
}

GBytes*
foil_input_read_all(
    FoilInput* in)
{
    if (G_LIKELY(in) && !in->closed) {
        const int chunk = 128;
        GByteArray* buf = g_byte_array_sized_new(chunk);
        guint len = 0;
        gssize nbytes;
        g_byte_array_set_size(buf, chunk);
        while ((nbytes = foil_input_read(in, buf->data + len, chunk)) > 0) {
            len += nbytes;
            g_byte_array_set_size(buf, len + chunk);
        }
        g_byte_array_set_size(buf, len);
        return g_byte_array_free_to_bytes(buf);
    }
    return NULL;
}

void
foil_input_close(
    FoilInput* in)
{
    if (G_LIKELY(in) && !in->closed) {
        if (in->peek_buf) {
            g_byte_array_unref(in->peek_buf);
            in->peek_buf = NULL;
            in->peek_offset = 0;
        }
        in->closed = TRUE;
        in->fn->fn_close(in);
    }
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
