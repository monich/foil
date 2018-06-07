/*
 * Copyright (C) 2016-2018 by Slava Monich
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
#include "foil_log_p.h"

#include <gutil_macros.h>

#define BASE64_ENCODE_INPUT_CHUNK  3 /* 3 bytes of binary data */
#define BASE64_ENCODE_OUTPUT_CHUNK 4 /* encoded to 4 printable characters */

typedef enum foil_output_base64_state_flags {
    FOIL_OUTPUT_BASE64_STATE_NONE           = (0x00),
    FOIL_OUTPUT_BASE64_STATE_FINISHED       = (0x01),
    FOIL_OUTPUT_BASE64_STATE_FINISH_FAILED  = (0x02)
} FOIL_OUTPUT_BASE64_STATE_FLAGS;

typedef struct foil_output_base64 {
    FoilOutput parent;
    FoilOutput* out;
    FOIL_OUTPUT_BASE64_STATE_FLAGS state;
    gsize base64_count;
    gsize total_count;
    gsize offset;
    guint flags;
    guint linebreak;
    guint bufsize;
    guint8 buf[BASE64_ENCODE_INPUT_CHUNK];
} FoilOutputBase64;

static
const char*
foil_output_base64_map(
    FoilOutputBase64* self)
{
    static const char foil_output_base64_default_map[64] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',     /* 0-7 */
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',     /* 8-15 */
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',     /* 16-23 */
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',     /* 24-31 */
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',     /* 32-39 */
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',     /* 40-47 */
        'w', 'x', 'y', 'z', '0', '1', '2', '3',     /* 48-55 */
        '4', '5', '6', '7', '8', '9', '+', '/',     /* 56-63 */
    };

    static const char foil_output_base64_filesafe_map[64] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',     /* 0-7 */
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',     /* 8-15 */
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',     /* 16-23 */
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',     /* 24-31 */
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',     /* 32-39 */
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',     /* 40-47 */
        'w', 'x', 'y', 'z', '0', '1', '2', '3',     /* 48-55 */
        '4', '5', '6', '7', '8', '9', '-', '_',     /* 56-63 */
    };
    return (self->flags & FOIL_OUTPUT_BASE64_FILESAFE) ?
        foil_output_base64_filesafe_map : foil_output_base64_default_map;
}

static
void
foil_output_base64_encode_chunk(
    char* out,
    const guint8* in,
    const char* map)
{
    out[0] = map[(in[0] >> 2) & 0x3F];
    out[1] = map[((in[0] << 4) & 0x30) | ((in[1] >> 4) & 0x0F)];
    out[2] = map[((in[1] << 2) & 0x3C) | ((in[2] >> 6) & 0x03)];
    out[3] = map[in[2] & 0x3F];
}

static
void
foil_output_base64_encode_chunk_1(
    char* out,
    const guint8* in,
    const char* map)
{
    out[0] = map[(in[0] >> 2) & 0x3F];
    out[1] = map[(in[0] << 4) & 0x30];
    out[2] = out[3] = '=';
}

static
void
foil_output_base64_encode_chunk_2(
    char* out,
    const guint8* in,
    const char* map)
{
    out[0] = map[(in[0] >> 2) & 0x3F];
    out[1] = map[((in[0] << 4) & 0x30) | ((in[1] >> 4) & 0x0F)];
    out[2] = map[(in[1] << 2) & 0x3C];
    out[3] = '=';
}

static
gboolean
foil_output_base64_linebreak(
    FoilOutputBase64* self)
{
    guint written = foil_output_write_eol(self->out);
    if (written) {
        self->total_count += written;
        return TRUE;
    } else {
        return FALSE;
    }
}

static
gboolean
foil_output_base64_linebreak_check(
    FoilOutputBase64* self)
{
    return !self->base64_count ||
        (self->base64_count % self->linebreak) ||
        foil_output_base64_linebreak(self);
}

static
gboolean
foil_output_base64_write_chunk(
    FoilOutputBase64* self,
    char* chunk)
{
    gsize size = BASE64_ENCODE_OUTPUT_CHUNK;
    if (self->linebreak) {
        if (!foil_output_base64_linebreak_check(self)) {
            return FALSE;
        } else {
            const gsize lines1 = self->base64_count/self->linebreak;
            const gsize lines2 = (self->base64_count + size)/self->linebreak;
            if (lines1 == lines2) {
                if (foil_output_write_all(self->out, chunk, size)) {
                    self->base64_count += size;
                    self->total_count += size;
                    return TRUE;
                } else {
                    return FALSE;
                }
            } else {
                while (size > 0) {
                    gsize lines = self->base64_count/self->linebreak;
                    gsize n = (lines+1) * self->linebreak - self->base64_count;
                    if (!foil_output_base64_linebreak_check(self)) {
                        return FALSE;
                    } else if (n > size) {
                        if (foil_output_write_all(self->out, chunk, size)) {
                            n = size;
                        } else {
                            return FALSE;
                        }
                    } else if (!foil_output_write_all(self->out, chunk, n)) {
                        return FALSE;
                    }
                    self->base64_count += n;
                    self->total_count += n;
                    size -= n;
                    chunk += n;
                }
                return TRUE;
            }
        }
    } else if (foil_output_write_all(self->out, chunk, size)) {
        self->base64_count += size;
        self->total_count += size;
        return TRUE;
    } else {
        return FALSE;
    }
}

static
gssize
foil_output_base64_write(
    FoilOutput* out,
    const void* buf,
    gsize size)
{
    gssize written = 0;
    FoilOutputBase64* self = G_CAST(out, FoilOutputBase64, parent);
    if (self->state & FOIL_OUTPUT_BASE64_STATE_FINISHED) {
        /* Can't write after padding BASE64 stream with = */
        written = -1;
    } else {
        char chunk[BASE64_ENCODE_OUTPUT_CHUNK];
        const guint8* ptr = buf;
        const char* map = foil_output_base64_map(self);
        if (self->bufsize > 0) {
            /* The tail of the previous chunk has been buffered */
            while (self->bufsize < BASE64_ENCODE_INPUT_CHUNK && size) {
                self->buf[self->bufsize++] = *ptr++;
                written++;
                size--;
            }
            if (self->bufsize == BASE64_ENCODE_INPUT_CHUNK) {
                self->bufsize = 0;
                foil_output_base64_encode_chunk(chunk, self->buf, map);
                if (!foil_output_base64_write_chunk(self, chunk)) {
                    return -1;
                }
            }
        }
        /* Write full chunks */
        while (size >= BASE64_ENCODE_INPUT_CHUNK) {
            foil_output_base64_encode_chunk(chunk, ptr, map);
            written += BASE64_ENCODE_INPUT_CHUNK;
            ptr += BASE64_ENCODE_INPUT_CHUNK;
            size -= BASE64_ENCODE_INPUT_CHUNK;
            if (!foil_output_base64_write_chunk(self, chunk)) {
                return -1;
            }
        }
        /* Store the remaining bytes */
        while (size > 0) {
            self->buf[self->bufsize++] = *ptr++;
            written++;
            size--;
        }
    }
    return written;
}

static
gboolean
foil_output_base64_flush(
    FoilOutput* out)
{
    FoilOutputBase64* self = G_CAST(out, FoilOutputBase64, parent);
    if (self->state & FOIL_OUTPUT_BASE64_STATE_FINISHED) {
        return !(self->state & FOIL_OUTPUT_BASE64_STATE_FINISH_FAILED);
    } else {
        const char* map = foil_output_base64_map(self);
        void (*fn)(char* chunk, const guint8* in, const char* map);
        switch (self->bufsize % BASE64_ENCODE_INPUT_CHUNK) {
        case 1:  fn = foil_output_base64_encode_chunk_1; break;
        case 2:  fn = foil_output_base64_encode_chunk_2; break;
        default: fn = NULL; break;
        }
        /* This can only be done once */
        self->state |= FOIL_OUTPUT_BASE64_STATE_FINISHED;
        if (fn) {
            char chunk[BASE64_ENCODE_OUTPUT_CHUNK];
            fn(chunk, self->buf, map);
            if (foil_output_base64_write_chunk(self, chunk)) {
                if (!self->linebreak || foil_output_base64_linebreak(self)) {
                    return TRUE;
                }
            }
            self->state |= FOIL_OUTPUT_BASE64_STATE_FINISH_FAILED;
            return FALSE;
        } else if (!self->linebreak || foil_output_base64_linebreak(self)) {
            return TRUE;
        } else {
            self->state |= FOIL_OUTPUT_BASE64_STATE_FINISH_FAILED;
            return FALSE;
        }
    }
}

static
gboolean
foil_output_base64_reset(
    FoilOutput* out)
{
    FoilOutputBase64* self = G_CAST(out, FoilOutputBase64, parent);
    self->base64_count = 0;
    self->total_count = 0;
    self->bufsize = 0;
    return foil_output_reset(self->out);
}

static
GBytes*
foil_output_base64_to_bytes(
    FoilOutput* out)
{
    FoilOutputBase64* self = G_CAST(out, FoilOutputBase64, parent);
    /* Note that this will close the target regardless of
     * FOIL_OUTPUT_BASE64_CLOSE flag */
    GBytes* bytes = foil_output_free_to_bytes(self->out);
    self->out = NULL;
    if (bytes && self->offset) {
        gsize size = g_bytes_get_size(bytes);
        /* The size shouldn't be smaller than what we have started with */
        GASSERT(size == self->total_count + self->offset);
        if (size == self->total_count + self->offset) {
            GBytes* our_bytes = g_bytes_new_from_bytes(bytes,
                self->offset, size - self->offset);
            g_bytes_unref(bytes);
            bytes = our_bytes;
        } else {
            g_bytes_unref(bytes);
            bytes = NULL;
        }
    }
    return bytes;
}

static
void
foil_output_base64_close(
    FoilOutput* out)
{
    FoilOutputBase64* self = G_CAST(out, FoilOutputBase64, parent);
    if (self->flags & FOIL_OUTPUT_BASE64_CLOSE) {
        foil_output_close(self->out);
    }
    foil_output_unref(self->out);
    self->out = NULL;
}

static
void
foil_output_base64_free(
    FoilOutput* out)
{
    FoilOutputBase64* self = G_CAST(out, FoilOutputBase64, parent);
    GASSERT(!self->out);
    g_slice_free(FoilOutputBase64, self);
}

FoilOutput*
foil_output_base64_new_full(
    FoilOutput* out,
    guint flags,
    guint linebreak)
{
    static const FoilOutputFunc foil_output_base64_fn = {
        foil_output_base64_write,       /* fn_write */
        foil_output_base64_flush,       /* fn_flush */
        foil_output_base64_reset,       /* fn_reset */
        foil_output_base64_to_bytes,    /* fn_to_bytes */
        foil_output_base64_close,       /* fn_close */
        foil_output_base64_free         /* fn_free */
    };

    FoilOutputBase64* self = g_slice_new0(FoilOutputBase64);
    self->out = out ? foil_output_ref(out) : foil_output_mem_new(NULL);
    self->offset = foil_output_bytes_written(out);
    self->flags = flags;
    self->linebreak = linebreak;
    return foil_output_init(&self->parent, &foil_output_base64_fn);
}

FoilOutput*
foil_output_base64_new(
    FoilOutput* out)
{
    return foil_output_base64_new_full(out, 0, 0);
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
