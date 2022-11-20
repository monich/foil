/*
 * Copyright (C) 2022 by Slava Monich <slava@monich.com>
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

#include "foil_cipher.h"
#include "foil_digest_p.h"
#include "foil_hmac.h"
#include "foil_output_p.h"

#include <gutil_macros.h>

/* Logging */
#define GLOG_MODULE_NAME foil_log_output
#include "foil_log_p.h"

typedef struct foil_output_cipher_mem {
    FoilOutput parent;
    FoilCipher* cipher;
    GByteArray* buf;
    gsize offset;
    gsize out_block_size;
    gsize in_block_size;
    gsize in_block_used;
    guint8* in_block;
    void* digest;
    FoilDigestGenericUpdateFunc digest_update;
    FoilDigestGenericUnrefFunc digest_unref;
} FoilOutputCipherMem;

static
gssize
foil_output_cipher_mem_write(
    FoilOutput* out,
    const void* data,
    gsize size)
{
    FoilOutputCipherMem* self = G_CAST(out, FoilOutputCipherMem, parent);
    GByteArray* buf = self->buf;
    const guint8* ptr = data;
    gsize left = size;

    while (self->in_block_used + left >= self->in_block_size) {
        const guint prev_len = buf->len;
        const void* in_block;
        int nout;

        if (self->in_block_used) {
            const guint remaining = self->in_block_size - self->in_block_used;

            in_block = self->in_block;
            memcpy(self->in_block + self->in_block_used, ptr, remaining);
            self->in_block_used = 0;
            left -= remaining;
            ptr += remaining;
        } else {
            /* Can write directly into the output buffer */
            in_block = ptr;
            left -= self->in_block_size;
            ptr += self->in_block_size;
        }

        g_byte_array_set_size(buf, prev_len + self->out_block_size);
        nout = foil_cipher_step(self->cipher, in_block, buf->data + prev_len);
        if (nout < 0) {
            g_byte_array_set_size(buf, prev_len);
            return -1;
        } else {
            g_byte_array_set_size(buf, prev_len + nout);
        }
    }

    /* Stash the remaining non-encrypted bytes */
    if (left > 0) {
        if (!self->in_block) {
            self->in_block = g_malloc(self->in_block_size);
        }
        memcpy(self->in_block + self->in_block_used, ptr, left);
        self->in_block_used += left;
    }

    self->digest_update(self->digest, data, size);
    return size;
}

static
gboolean
foil_output_cipher_mem_finish(
    FoilOutputCipherMem* self)
{
    GByteArray* buf = self->buf;
    const guint prev_len = buf->len;
    int nout;

    /* Cipher the remaining data */
    g_byte_array_set_size(buf, prev_len + self->out_block_size);
    nout = foil_cipher_finish(self->cipher, self->in_block,
        self->in_block_used, buf->data + prev_len);
    if (nout < 0) {
        g_byte_array_set_size(buf, prev_len);
    } else {
        g_byte_array_set_size(buf, prev_len + nout);
    }

    /* Leave self->buf to the caller */
    self->digest_unref(self->digest);
    foil_cipher_unref(self->cipher);
    g_free(self->in_block);
    self->in_block_used = 0;
    self->in_block = NULL;
    self->cipher = NULL;
    return (nout >= 0);
}

static
gboolean
foil_output_cipher_mem_flush(
    FoilOutput* out)
{
    return TRUE;
}

static
gboolean
foil_output_cipher_mem_reset(
    FoilOutput* out)
{
    /* There's no generic way to reset the cipher state */
    return FALSE;
}

static
GBytes*
foil_output_cipher_mem_to_bytes(
    FoilOutput* out)
{
    FoilOutputCipherMem* self = G_CAST(out, FoilOutputCipherMem, parent);
    GByteArray* buf = self->buf;

    if (!foil_output_cipher_mem_finish(self)) {
        g_byte_array_unref(buf);
        self->buf = NULL;
        return NULL;
    } else {
        /* Avoid copying the data */
        GBytes* bytes = g_byte_array_free_to_bytes(buf);

        self->buf = NULL;
        if (self->offset) {
            GBytes* our_bytes = g_bytes_new_from_bytes(bytes, self->offset,
                g_bytes_get_size(bytes) - self->offset);

            g_bytes_unref(bytes);
            return our_bytes;
        } else {
            return bytes;
        }
    }
}

static
void
foil_output_cipher_mem_close(
    FoilOutput* out)
{
    FoilOutputCipherMem* self = G_CAST(out, FoilOutputCipherMem, parent);

    foil_output_cipher_mem_finish(self);
    g_byte_array_unref(self->buf);
    self->buf = NULL;
}

static
void
foil_output_cipher_mem_free(
    FoilOutput* out)
{
    g_slice_free(FoilOutputCipherMem,G_CAST(out, FoilOutputCipherMem, parent));
}

static
FoilOutput*
foil_output_cipher_mem_internal_new(
    GByteArray* buf,
    FoilCipher* cipher,
    gsize in_size,
    gsize out_size,
    void* digest_ref,
    FoilDigestGenericUpdateFunc digest_update,
    FoilDigestGenericUnrefFunc digest_unref)
{
    static const FoilOutputFunc foil_output_cipher_fn = {
        foil_output_cipher_mem_write,       /* fn_write */
        foil_output_cipher_mem_flush,       /* fn_flush */
        foil_output_cipher_mem_reset,       /* fn_reset */
        foil_output_cipher_mem_to_bytes,    /* fn_to_bytes */
        foil_output_cipher_mem_close,       /* fn_close */
        foil_output_cipher_mem_free         /* fn_free */
    };

    FoilOutputCipherMem* self = g_slice_new0(FoilOutputCipherMem);

    if (buf) {
        self->buf = g_byte_array_ref(buf);
        self->offset = buf->len;
    } else {
        self->buf = g_byte_array_new();
    }
    self->cipher = foil_cipher_ref(cipher);
    self->in_block_size = in_size;
    self->out_block_size = out_size;
    self->digest = digest_ref;
    self->digest_update = digest_update;
    self->digest_unref = digest_unref;
    return foil_output_init(&self->parent, &foil_output_cipher_fn);
}

FoilOutput*
foil_output_cipher_mem_new(
    GByteArray* buf,
    FoilCipher* cipher,
    FoilDigest* digest) /* Since 1.0.26 */
{
    const int in_size = foil_cipher_input_block_size(cipher);
    const int out_size = foil_cipher_output_block_size(cipher);

    if (G_LIKELY(in_size > 0) && G_LIKELY(out_size > 0)) {
        return foil_output_cipher_mem_internal_new(buf, cipher,
            in_size, out_size, foil_digest_ref(digest),
            foil_digest_update_digest, foil_digest_unref_digest);
    }
    return NULL;
}

FoilOutput*
foil_output_cipher_mem_new2(
    GByteArray* buf,
    FoilCipher* cipher,
    FoilHmac* hmac) /* Since 1.0.27 */
{
    const int in_size = foil_cipher_input_block_size(cipher);
    const int out_size = foil_cipher_output_block_size(cipher);

    if (G_LIKELY(in_size > 0) && G_LIKELY(out_size > 0)) {
        return foil_output_cipher_mem_internal_new(buf, cipher,
            in_size, out_size, foil_hmac_ref(hmac),
            foil_digest_update_hmac, foil_digest_unref_hmac);
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
