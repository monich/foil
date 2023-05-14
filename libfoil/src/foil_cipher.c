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

#include "foil_cipher_p.h"
#include "foil_util_p.h"
#include "foil_digest.h"
#include "foil_output.h"
#include "foil_key.h"

/* Logging */
#define GLOG_MODULE_NAME foil_log_cipher
#include "foil_log_p.h"
GLOG_MODULE_DEFINE2("foil-cipher", FOIL_LOG_MODULE);

G_DEFINE_ABSTRACT_TYPE(FoilCipher, foil_cipher, G_TYPE_OBJECT);
#define foil_cipher_class_ref(type) ((FoilCipherClass*)foil_class_ref(type, \
        FOIL_TYPE_CIPHER))

/*==========================================================================*
 * Public API
 *==========================================================================*/

const char*
foil_cipher_type_name(
    GType type)
{
    const char* name = NULL;
    FoilCipherClass* klass = foil_cipher_class_ref(type);
    if (G_LIKELY(klass)) {
        name = klass->name;
        g_type_class_unref(klass);
    }
    return name;
}

gboolean
foil_cipher_type_supports_key(
    GType type,
    GType key_type)
{
    gboolean ret = FALSE;
    FoilCipherClass* klass = foil_cipher_class_ref(type);
    if (G_LIKELY(klass)) {
        ret = klass->fn_supports_key(klass, key_type);
        g_type_class_unref(klass);
    }
    return ret;
}

FoilCipher*
foil_cipher_new(
    GType type,
    FoilKey* key)
{
    FoilCipher* cipher = NULL;
    if (G_LIKELY(key)) {
        FoilCipherClass* klass = foil_cipher_class_ref(type);
        if (G_LIKELY(klass)) {
            GType key_type = G_TYPE_FROM_INSTANCE(key);
            if (klass->fn_supports_key(klass, key_type)) {
                cipher = g_object_new(type, NULL);
                klass->fn_init_with_key(cipher, key);
                GASSERT(cipher->key); /* Set by foil_cipher_init_with_key */
                GASSERT(cipher->input_block_size);  /* and these two are set */
                GASSERT(cipher->output_block_size); /* by the implementation */
            }
            g_type_class_unref(klass);
        }
    }
    return cipher;
}

FoilCipher*
foil_cipher_clone(
    FoilCipher* self) /* Since 1.0.14 */
{
    if (G_LIKELY(self)) {
        FoilCipherClass* klass = FOIL_CIPHER_GET_CLASS(self);
        if (klass->fn_copy) {
            FoilCipher* clone = g_object_new(G_TYPE_FROM_INSTANCE(self), NULL);
            klass->fn_init_with_key(clone, self->key);
            klass->fn_copy(clone, self);
            return clone;
        }
    }
    return NULL;
}

FoilCipher*
foil_cipher_ref(
    FoilCipher* self)
{
    if (G_LIKELY(self)) {
        GASSERT(FOIL_IS_CIPHER(self));
        g_object_ref(self);
    }
    return self;
}

void
foil_cipher_unref(
    FoilCipher* self)
{
    if (G_LIKELY(self)) {
        GASSERT(FOIL_IS_CIPHER(self));
        g_object_unref(self);
    }
}

FoilKey*
foil_cipher_key(
    FoilCipher* self)
{
    return G_LIKELY(self) ? self->key : NULL;
}

const char*
foil_cipher_name(
    FoilCipher* self)
{
    return G_LIKELY(self) ? FOIL_CIPHER_GET_CLASS(self)->name : NULL;
}

int
foil_cipher_input_block_size(
    FoilCipher* self)
{
    return G_LIKELY(self) ? self->input_block_size : 0;
}

int
foil_cipher_output_block_size(
    FoilCipher* self)
{
    return G_LIKELY(self) ? self->output_block_size : 0;
}

gboolean
foil_cipher_symmetric(
    FoilCipher* self) /* Since 1.0.14 */
{
    return G_LIKELY(self) &&
        (FOIL_CIPHER_GET_CLASS(self)->flags & FOIL_CIPHER_SYMMETRIC);
}

gboolean
foil_cipher_set_padding_func(
    FoilCipher* self,
    FoilCipherPaddingFunc fn)
{
    if (G_LIKELY(self)) {
        FoilCipherClass* klass = FOIL_CIPHER_GET_CLASS(self);
        /* Padding makes no sense if we can't encrypt */
        if (klass->flags & FOIL_CIPHER_ENCRYPT) {
            self->fn_pad = klass->fn_pad;
            return TRUE;
        }
    }
    return FALSE;
}

int
foil_cipher_step(
    FoilCipher* self,
    const void* in,
    void* out)
{
    if (G_LIKELY(self) && G_LIKELY(in) && G_LIKELY(out)) {
        FoilCipherClass* klass = FOIL_CIPHER_GET_CLASS(self);
        return klass->fn_step(self, in, out);
    }
    return -1;
}

int
foil_cipher_finish(
    FoilCipher* self,
    const void* in,
    int len,
    void* out)
{
    if (G_LIKELY(self) && len >= 0) {
        FoilCipherClass* klass = FOIL_CIPHER_GET_CLASS(self);
        return klass->fn_finish(self, in, len, out);
    }
    return -1;
}

void
foil_cipher_cancel_all(
    FoilCipher* self)
{
    if (G_LIKELY(self)) {
        foil_cipher_priv_cancel_all(self->priv);
    }
}

gboolean
foil_cipher_write_data(
    FoilCipher* self,
    const void* data,
    gsize size,
    FoilOutput* out,
    FoilDigest* digest)
{
    gboolean ok = FALSE;
    const int in_size = foil_cipher_input_block_size(self);
    const int out_size = foil_cipher_output_block_size(self);

    if (G_LIKELY(in_size > 0) && G_LIKELY(out_size > 0)) {
        FoilCipherClass* klass = FOIL_CIPHER_GET_CLASS(self);
        const guint8* ptr = data;
        const guint n = (size + in_size - 1) / in_size;
        void* out_block = g_slice_alloc(out_size);
        guint i;
        int nout = 0;

        /* Full input blocks */
        ok = TRUE;
        for (i=1; i<n && ok; i++) {
            foil_digest_update(digest, ptr, in_size);
            nout = klass->fn_step(self, ptr, out_block);
            if (nout > 0) {
                if (foil_output_write_all(out, out_block, nout)) {
                    ptr += in_size;
                    continue;
                }
                ok = FALSE;
            } else if (nout < 0) {
                ok = FALSE;
            }
            break;
        }

        /* Finish the process */
        if (ok && n > 0) {
            const gsize tail = size - (in_size * (n - 1));
            foil_digest_update(digest, ptr, tail);
            nout = klass->fn_finish(self, ptr, tail, out_block);
            if (nout > 0) {
                if (!foil_output_write_all(out, out_block, nout)) {
                    ok = FALSE;
                }
            } else if (nout < 0) {
                ok = FALSE;
            }
        }

        g_slice_free1(out_size, out_block);
    }
    return ok;
}

GBytes*
foil_cipher_data(
    GType type,
    FoilKey* key,
    const void* data,
    gsize size)
{
    GBytes* result = NULL;
    if (G_LIKELY(data || !size)) {
        FoilCipher* cipher = foil_cipher_new(type, key);
        if (cipher) {
            /*
             * Preallocate some space in the destination buffer.
             * With symmetric ciphers we know exactly how much
             * we need, for all others just take a wild guess.
             */
            GByteArray* buf = g_byte_array_sized_new((FOIL_CIPHER_GET_CLASS
                (cipher)->flags & FOIL_CIPHER_SYMMETRIC) ? size : (size/2));
            FoilOutput* out = foil_output_mem_new(buf);
            g_byte_array_unref(buf); /* FoilOutputMem keeps the reference */
            if (foil_cipher_write_data(cipher, data, size, out, NULL)) {
                result = foil_output_free_to_bytes(out);
            } else {
                foil_output_unref(out);
            }
            foil_cipher_unref(cipher);
        }
    }
    return result;
}

GBytes*
foil_cipher_bytes(
    GType type,
    FoilKey* key,
    GBytes* bytes)
{
    GBytes* result = NULL;
    if (G_LIKELY(bytes)) {
        gsize size = 0;
        const void* data = g_bytes_get_data(bytes, &size);
        result = foil_cipher_data(type, key, data, size);
    }
    return result;
}

/*==========================================================================*
 * Internal API
 *==========================================================================*/

void
foil_cipher_run_init(
    FoilCipher* self,
    FoilCipherRun* run,
    const FoilBytes* blocks,
    guint nblocks)
{
    guint i;
    memset(run, 0, sizeof(*run));
    run->blocks = blocks;
    run->nblocks = nblocks;
    run->in_block_size = self->input_block_size;

    /* Calculate the total size of all data blocks */
    for (i=0; i<nblocks; i++) {
        run->bytes_total += blocks[i].len;
    }
    run->bytes_left = run->bytes_total;
    foil_cipher_run_next(run);
}

void
foil_cipher_run_deinit(
    FoilCipherRun* run)
{
    g_slice_free1(run->in_block_size, run->in_buf);
}

int
foil_cipher_symmetric_finish(
    FoilCipher* self,
    const void* from,
    int flen,
    void* to)
{
    FoilCipherClass* klass = FOIL_CIPHER_GET_CLASS(self);
    const int block_size = self->input_block_size;
    /* These must be the same for symmetric ciphers */
    GASSERT(self->input_block_size == self->output_block_size);
    GASSERT(klass->flags & FOIL_CIPHER_SYMMETRIC);
    if (flen == block_size) {
        return klass->fn_step(self, from, to);
    } else if (flen > 0) {
        GASSERT(flen < block_size);
        if (flen > block_size) {
            return -1;
        } else {
            int ret;
            guint8* last = g_slice_alloc(block_size);
            memcpy(last, from, flen);
            self->fn_pad(last, flen, block_size);
            ret = klass->fn_step(self, last, to);
            g_slice_free1(block_size, last);
            return ret;
        }
    } else {
        return 0;
    }
}

void
foil_cipher_run_next(
    FoilCipherRun* run)
{
    /* Do we have anything left? */
    if (run->bytes_left) {
        const FoilBytes* data = run->blocks + run->current_block;
        const gsize buffer_bytes_left = data->len - run->current_offset;

        /* Does the input block span across the input block boundary? */
        if (buffer_bytes_left < run->in_block_size &&
            run->nblocks > (run->current_block + 1)) {
            gsize to_copy = MIN(run->in_block_size, run->bytes_left);

            /* We need a temporary buffer */
            if (!run->in_buf) {
                run->in_buf = g_slice_alloc(run->in_block_size);
            }
            run->in_ptr = run->in_buf;
            run->in_len = 0;

            /* Copy scattered data into a single buffer */
            while (to_copy) {
                const void* chunk_ptr = data->val + run->current_offset;
                const gsize chunk_size = data->len - run->current_offset;
                const gsize copied = MIN(chunk_size, to_copy);
                memcpy(run->in_buf + run->in_len, chunk_ptr, copied);
                to_copy -= copied;
                run->bytes_left -= copied;
                run->in_len += copied;
                run->current_offset += copied;
                if (run->current_offset == data->len) {
                    /* Switch to the next buffer */
                    data++;
                    run->current_block++;
                    run->current_offset = 0;
                }
            }
            GASSERT(run->in_len <= run->in_block_size);
        } else {
            run->in_ptr = data->val + run->current_offset;
            run->in_len = MIN(run->in_block_size, buffer_bytes_left);
            run->current_offset += run->in_len;
            run->bytes_left -= run->in_len;
        }
    }
}

/*==========================================================================*
 * Implementation
 *==========================================================================*/

static
void
foil_cipher_default_padding_func(
    guint8* block,
    gsize data_size,
    gsize block_size)
{
    if (data_size < block_size) {
        guint8* ptr = block;
        guint8* end = block + block_size;
        GType digest_type = FOIL_DIGEST_MD5;
        GBytes* digest = foil_digest_data(digest_type, block, data_size);
        gsize digest_size, bytes_to_copy;
        const void* digest_data = g_bytes_get_data(digest, &digest_size);

        /* Append the digest */
        ptr += data_size;
        bytes_to_copy = MIN(digest_size, (gsize)(end - ptr));
        memcpy(ptr, digest_data, bytes_to_copy);
        ptr += bytes_to_copy;

        /* If there's more space to fill, start digesting the digest */
        while (ptr < end) {
            GBytes* digest2 = foil_digest_bytes(digest_type, digest);
            g_bytes_unref(digest);
            digest = digest2;
            digest_data = g_bytes_get_data(digest, &digest_size);
            bytes_to_copy = MIN(digest_size, (gsize)(end - ptr));
            memcpy(ptr, digest_data, bytes_to_copy);
            ptr += bytes_to_copy;
        }

        g_bytes_unref(digest);
    }
}

gboolean
foil_cipher_write_data_blocks(
    FoilCipher* self,
    const FoilBytes* blocks,
    guint nblocks,
    FoilOutput* out,
    FoilDigest* digest)
{
    gboolean ok = FALSE;
    const int out_size = foil_cipher_output_block_size(self);

    if (G_LIKELY(out_size > 0)) {
        void* out_block = g_slice_alloc(out_size);
        FoilCipherClass* klass = FOIL_CIPHER_GET_CLASS(self);
        FoilCipherRun run;
        int nout = 0;

        ok = TRUE;
        foil_cipher_run_init(self, &run, blocks, nblocks);

        /* Full input blocks */
        while (run.in_len == run.in_block_size && run.bytes_left) {
            GASSERT(run.in_len == run.in_block_size);
            foil_digest_update(digest, run.in_ptr, run.in_len);
            nout = klass->fn_step(self, run.in_ptr, out_block);
            if (nout > 0) {
                if (foil_output_write_all(out, out_block, nout)) {
                    foil_cipher_run_next(&run);
                    continue;
                }
                ok = FALSE;
            }
            break;
        }

        /* Finish the process */
        if (ok) {
            foil_digest_update(digest, run.in_ptr, run.in_len);
            nout = klass->fn_finish(self, run.in_ptr, run.in_len, out_block);
            if (nout > 0) {
                if (!foil_output_write_all(out, out_block, nout)) {
                    ok = FALSE;
                }
            }
        }

        foil_cipher_run_deinit(&run);
        g_slice_free1(self->output_block_size, out_block);
    }
    return ok;
}

static
void
foil_cipher_init_with_key(
    FoilCipher* self,
    FoilKey* key)
{
    GASSERT(!self->key);
    self->key = foil_key_ref(key);
}

static
void
foil_cipher_default_copy(
    FoilCipher* self,
    FoilCipher* src)
{
    self->input_block_size = src->input_block_size;
    self->output_block_size = src->output_block_size;
    self->fn_pad = src->fn_pad;
    foil_key_ref(src->key);
    foil_key_unref(self->key);
    self->key = src->key;
}

static
void
foil_cipher_finalize(
    GObject* object)
{
    FoilCipher* self = FOIL_CIPHER(object);
    FoilCipherPriv* priv = self->priv;
    foil_cipher_priv_finalize(priv);
    foil_key_unref(self->key);
    G_OBJECT_CLASS(foil_cipher_parent_class)->finalize(object);
}

static
void
foil_cipher_init(
    FoilCipher* self)
{
    self->priv = foil_cipher_priv_get(self);
    self->fn_pad = FOIL_CIPHER_GET_CLASS(self)->fn_pad;
}

static
void
foil_cipher_class_init(
    FoilCipherClass* klass)
{
    klass->fn_pad = foil_cipher_default_padding_func;
    klass->fn_init_with_key = foil_cipher_init_with_key;
    klass->fn_copy = foil_cipher_default_copy;
    G_OBJECT_CLASS(klass)->finalize = foil_cipher_finalize;
    foil_cipher_priv_add(klass);
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
