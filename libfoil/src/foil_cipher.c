/*
 * Copyright (C) 2016-2019 by Slava Monich
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

struct foil_cipher_priv {
    guint async_id;
};

typedef struct foil_cipher_run {
    const FoilBytes* blocks;
    guint nblocks;
    guint current_block;
    guint current_offset;
    gsize bytes_total;
    gsize bytes_left;
    const guint8* in_ptr;
    guint8* in_buf;
    gsize in_len;
    guint in_block_size;
} FoilCipherRun;

typedef struct foil_cipher_async_overlap {
    FoilCipherAsyncFunc fn;
    void* out_block;
    guint id;
} FoilCipherAsyncOverlap;

typedef struct foil_cipher_async_data_source {
    GSource source;
    FoilCipher* cipher;
    FoilOutput* out;
    FoilDigest* digest;
    FoilCipherAsyncBoolFunc fn;
    void* fn_arg;
    FoilBytes block;
    FoilCipherRun run;
    FoilCipherAsyncOverlap* finished;
    FoilCipherAsyncOverlap overlap[2];
} FoilCipherAsyncDataSource;

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
                cipher->key = foil_key_ref(key);
                klass->fn_post_init(cipher);
                GASSERT(cipher->input_block_size);
                GASSERT(cipher->output_block_size);
            }
            g_type_class_unref(klass);
        }
    }
    return cipher;
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
        if (klass->fn_set_padding_func) {
            klass->fn_set_padding_func(self, fn);
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

guint
foil_cipher_step_async(
    FoilCipher* self,
    const void* in,
    void* out,
    FoilCipherAsyncFunc fn,
    void* arg)
{
    if (G_LIKELY(self) && G_LIKELY(in) && G_LIKELY(out)) {
        FoilCipherClass* klass = FOIL_CIPHER_GET_CLASS(self);
        return klass->fn_step_async(self, in, out, fn, arg);
    }
    return 0;
}

guint
foil_cipher_finish_async(
    FoilCipher* self,
    const void* in,
    int len,
    void* out,
    FoilCipherAsyncFunc fn,
    void* arg)
{
    if (G_LIKELY(self) && len >= 0) {
        FoilCipherClass* klass = FOIL_CIPHER_GET_CLASS(self);
        return klass->fn_finish_async(self, in, len, out, fn, arg);
    }
    return 0;
}

void
foil_cipher_cancel_all(
    FoilCipher* self)
{
    if (G_LIKELY(self)) {
        FoilCipherClass* klass = FOIL_CIPHER_GET_CLASS(self);
        klass->fn_cancel_all(self);
    }
}

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

static
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

static
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

static
void
foil_cipher_run_deinit(
    FoilCipherRun* run)
{
    g_slice_free1(run->in_block_size, run->in_buf);
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
        const gsize tail = size - (in_size * (n - 1));
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
        if (ok) {
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
            FoilOutput* out = foil_output_mem_new(NULL);
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

/*
 * Asynchronously run the ciphering sequence. Can be cancelled with
 * either g_source_remove or foil_cipher_cancel_all. Allows 2 overlapping
 * asynchronous operations. If the cipher is actually asynchronous, the
 * next chunk of data will be already delivered by the time the previous
 * chunk has been processed.
 */

static
void
foil_cipher_async_write_complete(
    FoilCipherAsyncDataSource* async,
    gboolean ok)
{
    FoilCipher* cipher = foil_cipher_ref(async->cipher);
    FoilCipherPriv* priv = cipher->priv;
    FoilCipherAsyncBoolFunc fn = async->fn;
    void* fn_arg = async->fn_arg;

    /*
     * Note: this g_source_remove call deallocates FoilCipherAsyncDataSource,
     * don't touch it after that
     */ 

    g_source_remove(priv->async_id);
    GASSERT(!priv->async_id);
    if (fn) {
        fn(cipher, ok, fn_arg);
    }
    foil_cipher_unref(cipher);
}

static
void
foil_cipher_async_write_finished(
    FoilCipher* cipher,
    int nout,
    void* arg)
{
    FoilCipherAsyncDataSource* async = arg;
    FoilCipherAsyncOverlap* finished = async->finished;
    foil_cipher_async_write_complete(async, nout > 0 &&
        foil_output_write_all(async->out, finished->out_block, nout));
}

static
void
foil_cipher_async_write_step_start(
    FoilCipherAsyncDataSource* async,
    FoilCipherAsyncOverlap* overlap)
{
    FoilCipher* cipher = async->cipher;
    FoilCipherClass* klass = FOIL_CIPHER_GET_CLASS(cipher);
    FoilCipherRun* run = &async->run;

    GASSERT(!overlap->id);
    GASSERT(!async->finished);
    foil_digest_update(async->digest, run->in_ptr, run->in_len);
    if (!overlap->out_block) {
        overlap->out_block = g_slice_alloc(cipher->output_block_size);
    }
    if (run->in_len == run->in_block_size && run->bytes_left) {
        /* Next full input block */
        GASSERT(run->in_len == run->in_block_size);
        overlap->id = klass->fn_step_async(cipher, run->in_ptr,
            overlap->out_block, overlap->fn, async);
        foil_cipher_run_next(&async->run);
    } else {
        /* Finish the process */
        async->finished = overlap;
        overlap->id = klass->fn_finish_async(cipher,
            run->in_ptr, run->in_len, overlap->out_block,
            foil_cipher_async_write_finished, async);
    }
}

static
void
foil_cipher_async_write_step_complete(
    FoilCipherAsyncDataSource* async,
    FoilCipherAsyncOverlap* overlap,
    int nout)
{
    overlap->id = 0;
    if (nout > 0 &&
        foil_output_write_all(async->out, overlap->out_block, nout)) {
        if (!async->finished) {
            foil_cipher_async_write_step_start(async, overlap);
        }
    } else {
        foil_cipher_async_write_complete(async, FALSE);
    }
}

static
void
foil_cipher_async_write_step0_complete(
    FoilCipher* cipher,
    int result,
    void* arg)
{
    FoilCipherAsyncDataSource* async = arg;
    foil_cipher_async_write_step_complete(async, async->overlap + 0, result);
}

static
void
foil_cipher_async_write_step1_complete(
    FoilCipher* cipher,
    int result,
    void* arg)
{
    FoilCipherAsyncDataSource* async = arg;
    foil_cipher_async_write_step_complete(async, async->overlap + 1, result);
}

/* glib prior to 2.36 requires prepare and check callback */
static
gboolean
foil_cipher_async_data_source_prepare(
    GSource* source,
    gint* timeout)
{
    return FALSE;
}

static
gboolean
foil_cipher_async_data_source_check(
    GSource* source)
{
    return FALSE;
}

static
void
foil_cipher_async_data_source_finalize(
    GSource* source)
{
    FoilCipherAsyncDataSource* async = (FoilCipherAsyncDataSource*)source;
    FoilCipher* cipher = async->cipher;
    FoilCipherPriv* priv = cipher->priv;
    guint i;
    GASSERT(priv->async_id);
    priv->async_id = 0;
    for (i=0; i<G_N_ELEMENTS(async->overlap); i++) {
        FoilCipherAsyncOverlap* overlap = async->overlap + i;
        if (overlap->id) {
            g_source_remove(overlap->id);
        }
        if (overlap->out_block) {
            g_slice_free1(cipher->output_block_size, overlap->out_block);
        }
    }
    foil_cipher_run_deinit(&async->run);
}

guint
foil_cipher_write_data_async(
    FoilCipher* self,
    const void* data,
    gsize size,
    FoilOutput* out,
    FoilDigest* digest,         /* optional */
    FoilCipherAsyncBoolFunc fn,
    void* arg)
{
    FoilCipherPriv* priv = self->priv;

    /* No more than one sequence at a time */
    if (priv->async_id) {
        GERR("Multiple ciphering sequences not allowed");
        return 0;
    } else if (!out) {
        return 0;
    } else {
        static GSourceFuncs foil_cipher_async_funcs = {
            foil_cipher_async_data_source_prepare,
            foil_cipher_async_data_source_check,
            NULL,
            foil_cipher_async_data_source_finalize,
            NULL,
            NULL
        };
        GSource* source = g_source_new(&foil_cipher_async_funcs,
            sizeof(FoilCipherAsyncDataSource));
        FoilCipherAsyncDataSource* async = (FoilCipherAsyncDataSource*)source;
        guint i;
        async->cipher = self;
        async->fn = fn;
        async->fn_arg = arg;
        async->out = out;
        async->digest = digest;
        async->block.val = data;
        async->block.len = size;
        async->finished = FALSE;
        foil_cipher_run_init(self, &async->run, &async->block, 1);
        priv->async_id = g_source_attach(source, NULL);
        g_source_unref(source);
        async->overlap[0].fn = foil_cipher_async_write_step0_complete;
        async->overlap[1].fn = foil_cipher_async_write_step1_complete;
        for (i=0; i<G_N_ELEMENTS(async->overlap) && !async->finished; i++) {
            foil_cipher_async_write_step_start(async, async->overlap + i);
        }
        return priv->async_id;
    }
}

/*
 * Class callbacks
 */

static
void
foil_cipher_post_init(
    FoilCipher* self)
{
}

static
void
foil_cipher_cancel_all_impl(
    FoilCipher* self)
{
    FoilCipherPriv* priv = self->priv;
    if (priv->async_id) {
        /* Destroy callback clears priv->async_id */
        g_source_remove(priv->async_id);
        GASSERT(!priv->async_id);
    }
}

static
void
foil_cipher_finalize(
    GObject* object)
{
    FoilCipher* self = FOIL_CIPHER(object);
    foil_cipher_cancel_all_impl(self);
    foil_key_unref(self->key);
    G_OBJECT_CLASS(foil_cipher_parent_class)->finalize(object);
}

static
void
foil_cipher_init(
    FoilCipher* self)
{
    self->priv = G_TYPE_INSTANCE_GET_PRIVATE(self, FOIL_TYPE_CIPHER,
        FoilCipherPriv);
}

static
void
foil_cipher_class_init(
    FoilCipherClass* klass)
{
    klass->fn_post_init = foil_cipher_post_init;
    klass->fn_cancel_all = foil_cipher_cancel_all_impl;
    G_OBJECT_CLASS(klass)->finalize = foil_cipher_finalize;
    g_type_class_add_private(klass, sizeof(FoilCipherPriv));
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
