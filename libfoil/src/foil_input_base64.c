/*
 * Copyright (C) 2016-2023 Slava Monich <slava@monich.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer
 *     in the documentation and/or other materials provided with the
 *     distribution.
 *  3. Neither the names of the copyright holders nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
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

#define BASE64_DECODE_INPUT_CHUNK  4 /* 4 printable characters */
#define BASE64_DECODE_OUTPUT_CHUNK 3 /* decoded to 3 bytes of binary data */

typedef struct foil_input_base64 {
    FoilInput parent;
    FoilInput* in;
    guint flags;
    guint8 buf[BASE64_DECODE_OUTPUT_CHUNK];
    guint buffered;
    const guint8* map;
    GByteArray* skip_buf;
} FoilInputBase64;

/*
 * We allow any encoding scheme but not a mix of those. They are referred to
 * by RFC 4648 as "base64" and "base64url", respectively,
 */
#define NONE 0xff
static const guint8 foil_input_base64_table[128] = {
    NONE, NONE, NONE, NONE, NONE, NONE, NONE, NONE,
    NONE, NONE, NONE, NONE, NONE, NONE, NONE, NONE,
    NONE, NONE, NONE, NONE, NONE, NONE, NONE, NONE,
    NONE, NONE, NONE, NONE, NONE, NONE, NONE, NONE,
    NONE, NONE, NONE, NONE, NONE, NONE, NONE, NONE,
    NONE, NONE, NONE, 0x3E, NONE, NONE, NONE, 0x3F,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
    0x3C, 0x3D, NONE, NONE, NONE, 0x00, NONE, NONE,
    NONE, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, NONE, NONE, NONE, NONE, NONE,
    NONE, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, NONE, NONE, NONE, NONE, NONE
};

static const guint8 foil_input_base64url_table[128] = {
    NONE, NONE, NONE, NONE, NONE, NONE, NONE, NONE,
    NONE, NONE, NONE, NONE, NONE, NONE, NONE, NONE,
    NONE, NONE, NONE, NONE, NONE, NONE, NONE, NONE,
    NONE, NONE, NONE, NONE, NONE, NONE, NONE, NONE,
    NONE, NONE, NONE, NONE, NONE, NONE, NONE, NONE,
    NONE, NONE, NONE, NONE, NONE, 0x3E, NONE, NONE,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
    0x3C, 0x3D, NONE, NONE, NONE, 0x00, NONE, NONE,
    NONE, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, NONE, NONE, NONE, NONE, 0x3F,
    NONE, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, NONE, NONE, NONE, NONE, NONE
};

static
const guint8*
foil_input_base64_next(
    FoilInputBase64* self)
{
    if (self->flags & FOIL_INPUT_BASE64_IGNORE_SPACES) {
        const guint8* next;
        while ((next = foil_input_peek(self->in, 1, NULL)) &&
            g_ascii_isspace(*next)) {
            g_byte_array_append(self->skip_buf, next, 1);
            foil_input_skip(self->in, 1);
        }
        return next;
    } else {
        return foil_input_peek(self->in, 1, NULL);
    }
}

static
gboolean
foil_input_base64_map(
    FoilInputBase64* self,
    guint8* ptr)
{
    const guint8 c = *ptr;
    if ((c & 0x7f) == c) {
        guint8 mapped = NONE;
        if (self->map) {
            /* Have already chosen the map */
            mapped = self->map[c];
        } else {
            const guint8* map = foil_input_base64_table;
            if (map[c] == NONE) {
                map = foil_input_base64url_table;
                if (map[c] != NONE) {
                    /* Stick with the filename safe map */
                    mapped = map[c];
                    self->map = map;
                }
            } else {
                if (foil_input_base64url_table[c] == NONE) {
                    /* Stick with the standard map */
                    self->map = map;
                }
                mapped = map[c];
            }
        }
        if (mapped != NONE) {
            *ptr = mapped;
            return TRUE;
        }
    }
    return FALSE;
}

static
int
foil_input_base64_read_chunk(
    FoilInputBase64* self,
    guint8* chunk /* [BASE64_DECODE_INPUT_CHUNK] */)
{
    int i, len, pad;
    const guint8* next;
    guint skip_buf_len[BASE64_DECODE_INPUT_CHUNK];

    /* Skip spaces (if allowed) */
    if (self->flags & FOIL_INPUT_BASE64_IGNORE_SPACES) {
        while ((next = foil_input_peek(self->in, 1, NULL)) &&
            g_ascii_isspace(*next)) {
            foil_input_skip(self->in, 1);
        }
    }

    next = foil_input_peek(self->in, BASE64_DECODE_INPUT_CHUNK, NULL);
    if (next) {
        memcpy(chunk, next, BASE64_DECODE_INPUT_CHUNK);
        if (!memchr(chunk, '=', BASE64_DECODE_INPUT_CHUNK) &&
            foil_input_base64_map(self, chunk + 0) &&
            foil_input_base64_map(self, chunk + 1) &&
            foil_input_base64_map(self, chunk + 2) &&
            foil_input_base64_map(self, chunk + 3)) {
            /* The happy case */
            foil_input_skip(self->in, BASE64_DECODE_INPUT_CHUNK);
            return BASE64_DECODE_INPUT_CHUNK;
        }
    }

    /* The chunk can't start with '=' */
    next = foil_input_peek(self->in, 1, NULL);
    if (!next) {
        return 0;
    } else if ((char)(*next) == '=') {
        return -1;
    }

    /* Sophisticated case. We need to accumulate skipped characters in
     * order to be able to roll everything back if something goes wrong. */
    if (self->skip_buf) {
        g_byte_array_set_size(self->skip_buf, 0);
    } else {
        self->skip_buf = g_byte_array_new();
    }

    pad = 0;
    len = 0;
    for (i=0; i<BASE64_DECODE_INPUT_CHUNK; i++) {
        next = foil_input_base64_next(self);
        skip_buf_len[i] = self->skip_buf->len;
        if (!next) {
            break;
        } else {
            if ((char)(*next) == '=') {
                pad++;
            } else if (!pad) {
                chunk[len] = *next;
                if (!foil_input_base64_map(self, chunk + len)) {
                    break;
                }
                len++;
            }
        }
        g_byte_array_append(self->skip_buf, next, 1);
        foil_input_skip(self->in, 1);
    }

    /* We need at least two valid BASE64 characters in order to parse
     * the first byte. If we have 3 characters, the lower 2 bits of the
     * last one should be zero (otherwise they should have been part of
     * the 3-rd decoded byte for which we would need the 4th character) */
    if (len >= 2 && (len != 3 || !(chunk[2] & 0x03))) {
        if (len < BASE64_DECODE_INPUT_CHUNK) {
            memset(chunk + len, 0, BASE64_DECODE_INPUT_CHUNK - len);
        }
        /* Padding should pad the input to the chunk size.
         * If it's too short, push it back */
        if (pad && (len + pad) != BASE64_DECODE_INPUT_CHUNK) {
            const guint off = skip_buf_len[len];
            foil_input_push_back(self->in, self->skip_buf->data + off,
                self->skip_buf->len - off);
            g_byte_array_set_size(self->skip_buf, off);
            pad = 0;
        }
        return len;
    }

    if ((len + pad) > 0) {
        /* Roll things back */
        foil_input_push_back(self->in, self->skip_buf->data,
            self->skip_buf->len);
        g_byte_array_set_size(self->skip_buf, 0);
    }

    return -1;
}

static
gssize
foil_input_base64_read(
    FoilInput* in,
    void* buf,
    gsize size)
{
    FoilInputBase64* self = G_CAST(in, FoilInputBase64, parent);
    guint8 chunk[BASE64_DECODE_INPUT_CHUNK];
    guint8* ptr = buf;
    gsize remain = size;
    gssize bytes_read = 0;
    int k = 0;

    /* Copy already decoded bytes */
    if (self->buffered) {
        gsize n = MIN(remain, self->buffered);
        if (ptr) {
            gsize off = BASE64_DECODE_OUTPUT_CHUNK - self->buffered;
            memcpy(ptr, self->buf + off, n);
            ptr += n;
        }
        remain -= n;
        self->buffered -= n;
        bytes_read += n;
    }

    /* Pre-read the input */
    foil_input_peek(self->in, remain*4/3, NULL);

    /* Decode more */
    while (remain && (k = foil_input_base64_read_chunk(self, chunk)) > 0) {
        gsize n, off = BASE64_DECODE_OUTPUT_CHUNK;
        self->buffered = 0;
        switch (k) {
        case 4:
            self->buffered++;
            self->buf[--off] = ((chunk[2]<<6)&0xC0) | (chunk[3]&0x3F);
            /* fallthrough */
        case 3:
            self->buffered++;
            self->buf[--off] = ((chunk[1]<<4)&0xF0) | ((chunk[2]>>2)&0x0F);
            /* fallthrough */
        case 2:
            self->buffered++;
            self->buf[--off] = ((chunk[0]<<2)&0xFC) | ((chunk[1]>>4)&0x03);
            break;
        }
        n = MIN(remain, self->buffered);
        remain -= n;
        self->buffered -= n;
        bytes_read += n;
        if (ptr) {
            memcpy(ptr, self->buf + off, n);
            ptr += n;
        }
    }

    if (bytes_read > 0) {
        /* Something has been decoded */
        return bytes_read;
    } else {
        /* FOIL_INPUT_BASE64_VALIDATE means that we fail on invalid input */
        return (self->flags & FOIL_INPUT_BASE64_VALIDATE) ? k : 0;
    }
}

static
void
foil_input_base64_close(
    FoilInput* in)
{
    FoilInputBase64* self = G_CAST(in, FoilInputBase64, parent);
    foil_input_unref(self->in);
    self->in = NULL;
    if (self->skip_buf) {
        g_byte_array_unref(self->skip_buf);
        self->skip_buf = NULL;
    }
}

static
void
foil_input_base64_free(
    FoilInput* in)
{
    FoilInputBase64* self = G_CAST(in, FoilInputBase64, parent);
    GASSERT(!self->in);
    GASSERT(!self->skip_buf);
    foil_input_finalize(in);
    g_slice_free(FoilInputBase64, self);
}

FoilInput*
foil_input_base64_new_full(
    FoilInput* in,
    guint flags)
{
    static const FoilInputFunc foil_input_base64_fn = {
        NULL,                     /* fn_has_available */
        foil_input_base64_read,   /* fn_read */
        foil_input_base64_close,  /* fn_close */
        foil_input_base64_free    /* fn_free */
    };
    if (G_LIKELY(in)) {
        FoilInputBase64* self = g_slice_new0(FoilInputBase64);
        self->in = foil_input_ref(in);
        switch ((self->flags = flags) &
            (FOIL_INPUT_BASE64_STANDARD | FOIL_INPUT_BASE64_FILESAFE)) {
        case FOIL_INPUT_BASE64_STANDARD:
            self->map = foil_input_base64_table;
            break;
        case FOIL_INPUT_BASE64_FILESAFE:
            self->map = foil_input_base64url_table;
            break;
        }
        return foil_input_init(&self->parent, &foil_input_base64_fn);
    }
    return NULL;
}

FoilInput*
foil_input_base64_new(
    FoilInput* in)
{
    return foil_input_base64_new_full(in, 0);
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
