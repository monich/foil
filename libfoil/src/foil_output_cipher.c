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

#include "foil_output_p.h"
#include "foil_cipher.h"
#include "foil_digest.h"

#include <gutil_macros.h>

/* Logging */
#define GLOG_MODULE_NAME foil_log_output
#include "foil_log_p.h"

typedef struct foil_output_cipher {
    FoilOutput parent;
    FoilOutput* out;
    FoilCipher* cipher;
    FoilDigest* digest;
    gsize in_block_size;
    gsize in_block_used;
    guint8* in_block;
    guint8* out_block;
} FoilOutputCipher;

static
gssize
foil_output_cipher_write(
    FoilOutput* out,
    const void* data,
    gsize size)
{
    FoilOutputCipher* self = G_CAST(out, FoilOutputCipher, parent);
    const guint8* ptr = data;
    gsize left = size;

    while (self->in_block_used + left >= self->in_block_size) {
        int encrypted;

        if (self->in_block_used) {
            const guint remaining = self->in_block_size - self->in_block_used;

            memcpy(self->in_block + self->in_block_used, ptr, remaining);
            encrypted = foil_cipher_step(self->cipher, self->in_block,
                self->out_block);
            foil_digest_update(self->digest, self->in_block,
                self->in_block_size);
            self->in_block_used = 0;
            left -= remaining;
            ptr += remaining;
        } else {
            encrypted = foil_cipher_step(self->cipher, ptr, self->out_block);
            foil_digest_update(self->digest, ptr, self->in_block_size);
            left -= self->in_block_size;
            ptr += self->in_block_size;
        }

        if (encrypted < 0 || !foil_output_write_all(self->out,
            self->out_block, encrypted)) {
            return -1;
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

    return size;
}

static
gboolean
foil_output_cipher_finish(
    FoilOutputCipher* self)
{
    const int nout = foil_cipher_finish(self->cipher, self->in_block,
        self->in_block_used, self->out_block);
    const gboolean ok = ((nout == 0) || ((nout > 0) &&
        foil_output_write_all(self->out, self->out_block, nout)));

    /* Leave self->out to the caller */
    foil_digest_update(self->digest, self->in_block, self->in_block_used);
    foil_digest_unref(self->digest);
    foil_cipher_unref(self->cipher);
    g_free(self->in_block);
    g_free(self->out_block);
    self->in_block_used = 0;
    self->in_block = NULL;
    self->out_block = NULL;
    self->cipher = NULL;
    return ok;
}

static
gboolean
foil_output_cipher_flush(
    FoilOutput* out)
{
    return TRUE;
}

static
gboolean
foil_output_cipher_reset(
    FoilOutput* out)
{
    return FALSE;
}

static
GBytes*
foil_output_cipher_to_bytes(
    FoilOutput* out)
{
    FoilOutputCipher* self = G_CAST(out, FoilOutputCipher, parent);
    GBytes* bytes;

    if (foil_output_cipher_finish(self)) {
        bytes = foil_output_free_to_bytes(self->out);
    } else {
        foil_output_close(self->out);
        foil_output_unref(self->out);
        bytes = NULL;
    }
    self->out = NULL;
    return bytes;
}

static
void
foil_output_cipher_close(
    FoilOutput* out)
{
    FoilOutputCipher* self = G_CAST(out, FoilOutputCipher, parent);

    foil_output_cipher_finish(self);
    foil_output_close(self->out);
    foil_output_unref(self->out);
    self->out = NULL;
}

static
void
foil_output_cipher_free(
    FoilOutput* out)
{
    g_slice_free(FoilOutputCipher, G_CAST(out, FoilOutputCipher, parent));
}

FoilOutput*
foil_output_cipher_new(
    FoilOutput* out,
    FoilCipher* cipher,
    FoilDigest* digest) /* Since 1.0.26 */
{
    static const FoilOutputFunc foil_output_cipher_fn = {
        foil_output_cipher_write,       /* fn_write */
        foil_output_cipher_flush,       /* fn_flush */
        foil_output_cipher_reset,       /* fn_reset */
        foil_output_cipher_to_bytes,    /* fn_to_bytes */
        foil_output_cipher_close,       /* fn_close */
        foil_output_cipher_free         /* fn_free */
    };

    const int in_size = foil_cipher_input_block_size(cipher);
    const int out_size = foil_cipher_output_block_size(cipher);

    if (G_LIKELY(in_size > 0) && G_LIKELY(out_size > 0) && G_LIKELY(out)) {
        FoilOutputCipher* self = g_slice_new0(FoilOutputCipher);

        self->out = foil_output_ref(out);
        self->cipher = foil_cipher_ref(cipher);
        self->digest = foil_digest_ref(digest);
        self->out_block = g_malloc(out_size);
        self->in_block_size = in_size; /* in_block is allocated on demand */
        return foil_output_init(&self->parent, &foil_output_cipher_fn);
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
