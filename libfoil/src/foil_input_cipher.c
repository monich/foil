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
#include "foil_cipher.h"
#include "foil_log_p.h"

#include <gutil_macros.h>

typedef struct foil_input_cipher {
    FoilInput parent;
    FoilInput* in;
    FoilCipher* cipher;
    guint8* in_block;
    guint8* out_block;
    gsize in_block_size;
    gsize in_len;
    gsize out_len;
    gsize out_offset;
} FoilInputCipher;

static
gssize
foil_input_cipher_read(
    FoilInput* in,
    void* buf,
    gsize size)
{
    FoilInputCipher* self = G_CAST(in, FoilInputCipher, parent);
    guint8* ptr = buf;
    gssize total = 0;

    /* Copy previously buffered data */
    if (self->out_offset < self->out_len) {
        const gsize copied = MIN(self->out_len - self->out_offset, size);
        if (ptr) {
            memcpy(ptr, self->out_block + self->out_offset, copied);
            ptr += copied;
        }
        size -= copied;
        total += copied;
        self->out_offset += copied;
        if (self->out_offset == self->out_len) {
            self->out_offset = self->out_len = 0;
        }
    }

    /* Pull in and cipher more data */
    while (size && self->out_offset == self->out_len) {
        const gssize in_bytes = foil_input_read(self->in, self->in_block,
            self->in_block_size);
        self->out_offset = 0;
        if (in_bytes > 0) {
            int nout;
            if ((in_bytes == (gssize)self->in_block_size) &&
                foil_input_has_available(self->in, 1)) {
                nout = foil_cipher_step(self->cipher, self->in_block,
                    self->out_block);
            } else {
                /* This is the last block */
                nout = foil_cipher_finish(self->cipher, self->in_block,
                    in_bytes, self->out_block);
            }
            if (nout > 0) {
                gsize copied;
                self->out_len = nout;
                copied = MIN(self->out_len - self->out_offset, size);
                if (ptr) {
                    memcpy(ptr, self->out_block + self->out_offset, copied);
                    ptr += copied;
                }
                size -= copied;
                total += copied;
                self->out_offset += copied;
                if (self->out_offset == self->out_len) {
                    self->out_offset = self->out_len = 0;
                }
                continue;
            }
        }
        self->out_len = 0;
        break;
    }

    return total;
}

static
void
foil_input_cipher_close(
    FoilInput* in)
{
    FoilInputCipher* self = G_CAST(in, FoilInputCipher, parent);
    foil_input_unref(self->in);
    foil_cipher_unref(self->cipher);
    g_free(self->in_block);
    g_free(self->out_block);
    self->in = NULL;
    self->cipher = NULL;
    self->in_block = NULL;
    self->out_block = NULL;
}

static
void
foil_input_cipher_free(
    FoilInput* in)
{
    FoilInputCipher* self = G_CAST(in, FoilInputCipher, parent);
    GASSERT(!self->in);
    GASSERT(!self->cipher);
    foil_input_finalize(in);
    g_slice_free(FoilInputCipher, self);
}

FoilInput*
foil_input_cipher_new(
    FoilCipher* cipher,
    FoilInput* in)
{
    static const FoilInputFunc foil_input_cipher_fn = {
        NULL,                       /* fn_has_available */
        foil_input_cipher_read,     /* fn_read */
        foil_input_cipher_close,    /* fn_close */
        foil_input_cipher_free      /* fn_free */
    };
    if (G_LIKELY(cipher) && G_LIKELY(in)) {
        FoilInputCipher* self = g_slice_new0(FoilInputCipher);
        self->in = foil_input_ref(in);
        self->cipher = foil_cipher_ref(cipher);
        self->in_block_size = foil_cipher_input_block_size(cipher);
        self->in_block = g_malloc(self->in_block_size);
        self->out_block = g_malloc(foil_cipher_output_block_size(cipher));
        return foil_input_init(&self->parent, &foil_input_cipher_fn);
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
