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

#include "foil_output_p.h"

/* Logging */
#define GLOG_MODULE_NAME foil_log_output
#include "foil_log_p.h"
GLOG_MODULE_DEFINE2("foil-output", FOIL_LOG_MODULE);

FoilOutput*
foil_output_init(
    FoilOutput* out,
    const FoilOutputFunc* fn)
{
    /* Caller is supposed to zero-initialize the whole thing */
    GASSERT(!out->bytes_written);
    g_atomic_int_set(&out->ref_count, 1);
    out->fn = fn;
    return out;
}

FoilOutput*
foil_output_ref(
    FoilOutput* out)
{
    if (G_LIKELY(out)) {
        GASSERT(out->ref_count > 0);
        g_atomic_int_inc(&out->ref_count);
    }
    return out;
}

void
foil_output_unref(
    FoilOutput* out)
{
    if (G_LIKELY(out)) {
        GASSERT(out->ref_count > 0);
        if (g_atomic_int_dec_and_test(&out->ref_count)) {
            foil_output_close(out);
            out->fn->fn_free(out);
        }
    }
}

gssize
foil_output_write(
    FoilOutput* out,
    const void* buf,
    gsize size)
{
    if (G_LIKELY(out) && !out->closed) {
        GASSERT(out->ref_count > 0);
        if (G_LIKELY(buf) && G_LIKELY(size)) {
            const gssize written = out->fn->fn_write(out, buf, size);
            if (written > 0) {
                GASSERT((gsize)written <= size);
                out->bytes_written += written;
            }
            return written;
        }
        return 0;
    }
    return -1;
}

gssize
foil_output_write_bytes(
    FoilOutput* out,
    GBytes* bytes)
{
    if (G_LIKELY(out) && !out->closed) {
        GASSERT(out->ref_count > 0);
        if (G_LIKELY(bytes)) {
            gsize size;
            const void* data = g_bytes_get_data(bytes, &size);
            if (size > 0) {
                const gssize written = out->fn->fn_write(out, data, size);
                if (written > 0) {
                    GASSERT((gsize)written <= size);
                    out->bytes_written += written;
                }
                return written;
            }
        }
        return 0;
    }
    return -1;
}

gboolean
foil_output_write_bytes_all(
    FoilOutput* out,
    GBytes* bytes)
{
    if (G_LIKELY(out) && !out->closed) {
        GASSERT(out->ref_count > 0);
        if (G_LIKELY(bytes)) {
            gsize size;
            const void* data = g_bytes_get_data(bytes, &size);
            if (size > 0) {
                const gssize written = out->fn->fn_write(out, data, size);
                if (written > 0) {
                    GASSERT((gsize)written <= size);
                    out->bytes_written += written;
                    return ((gsize)written == size);
                }
                return FALSE;
            }
        }
        return TRUE;
    }
    return FALSE;
}

/**
 * foil_output_write_eol() returns number of bytes written (currently, just
 * one but could be more if we decide to support e.g. Windows eol sequence),
 * zero on failure. Meaning that its return value can be safely interpreted
 * as a boolean.
 */
guint
foil_output_write_eol(
    FoilOutput* out) /* Since 1.0.9 */
{
    static const char eol = '\n';
    gssize written = foil_output_write(out, &eol, 1);
    return written > 0 ? 1 : 0;
}

gboolean
foil_output_write_byte(
    FoilOutput* out,
    guint8 byte) /* Since 1.0.27 */
{
    return foil_output_write(out, &byte, 1) == 1;
}

gboolean
foil_output_flush(
    FoilOutput* out)
{
    gboolean ok = FALSE;
    if (G_LIKELY(out) && !out->closed) {
        ok = out->fn->fn_flush(out);
    }
    return ok;
}

gboolean
foil_output_reset(
    FoilOutput* out)
{
    gboolean ok = FALSE;
    if (G_LIKELY(out) && !out->closed) {
        out->bytes_written = 0;
        ok = out->fn->fn_reset && out->fn->fn_reset(out);
    }
    return ok;
}

GBytes*
foil_output_free_to_bytes(
    FoilOutput* out)
{
    if (G_LIKELY(out)) {
        GBytes* bytes = NULL;
        if (!out->closed) {
            out->closed = TRUE;
            if (out->fn->fn_flush(out) && out->fn->fn_to_bytes) {
                bytes = out->fn->fn_to_bytes(out);
            } else {
                out->fn->fn_close(out);
           }
        }
        foil_output_unref(out);
        return bytes;
    }
    return NULL;
}

void
foil_output_close(
    FoilOutput* out)
{
    if (G_LIKELY(out) && !out->closed) {
        out->closed = TRUE;
        out->fn->fn_flush(out);
        out->fn->fn_close(out);
    }
}

gsize
foil_output_bytes_written(
    FoilOutput* out)
{
    return G_LIKELY(out) ? out->bytes_written : 0;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
