/*
 * Copyright (C) 2023 by Slava Monich <slava@monich.com>
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
#include "foil_digest.h"
#include "foil_output.h"

/* Logging */
#define GLOG_MODULE_NAME foil_log_cipher
#include "foil_log_p.h"

#include <gutil_intarray.h>
#include <gutil_weakref.h>

struct foil_cipher_priv {
    GUtilWeakRef* ref;
    GQueue async_queue;
    GUtilIntArray* ids;
};

typedef struct foil_cipher_async_data {
    GUtilWeakRef* ref;
    FoilCipherAsyncFunc fn;
    void* arg;
    guint id;
} FoilCipherAsyncData;

typedef struct foil_cipher_async_step_data {
    FoilCipherAsyncData common;
    const void* in;
    void* out;
} FoilCipherAsyncStepData;

typedef struct foil_cipher_async_finish_data {
    FoilCipherAsyncData common;
    const void* in;
    int len;
    void* out;
} FoilCipherAsyncFinishData;

typedef struct foil_cipher_async_overlap {
    FoilCipherAsyncFunc fn;
    void* out_block;
    guint id;
} FoilCipherAsyncOverlap;

typedef struct foil_cipher_async_data_source {
    GSource source;
    guint id;
    GUtilWeakRef* ref;
    FoilOutput* out;
    FoilDigest* digest;
    FoilCipherAsyncBoolFunc fn;
    void* fn_arg;
    FoilBytes block;
    FoilCipherRun run;
    FoilCipherAsyncOverlap* finished;
    FoilCipherAsyncOverlap overlap[2];
} FoilCipherAsyncDataSource;

static
guint
foil_cipher_async_queue_and_submit(
    FoilCipherPriv* priv,
    FoilCipherAsyncData* data,
    GSourceFunc run,
    GDestroyNotify destroy)
{
    data->ref = gutil_weakref_ref(priv->ref);
    data->id = g_idle_add_full(G_PRIORITY_DEFAULT_IDLE, run, data, destroy);
    g_queue_push_tail(&priv->async_queue, data);
    return data->id;
}

static
void
foil_cipher_async_data_destroy(
    gpointer user_data)
{
    FoilCipherAsyncData* data = user_data;
    FoilCipher* cipher = gutil_weakref_get(data->ref);

    if (cipher) {
        g_queue_remove(&cipher->priv->async_queue, data);
        foil_cipher_unref(cipher);
    }
    gutil_weakref_unref(data->ref);
    g_free(data);
}

static
gboolean
foil_cipher_async_step_func(
    gpointer user_data)
{
    FoilCipherAsyncStepData* step = user_data;
    FoilCipherAsyncData* data = &step->common;
    FoilCipher* cipher = gutil_weakref_get(data->ref);

    GASSERT(cipher);
    if (cipher) {
        int result;
        FoilCipherPriv* priv = cipher->priv;

        g_queue_remove(&priv->async_queue, data);
        result = foil_cipher_step(cipher, step->in, step->out);
        if (data->fn) {
            data->fn(cipher, result, data->arg);
        }
        foil_cipher_unref(cipher);
    }
    return G_SOURCE_REMOVE;
}

static
gboolean
foil_cipher_async_finish_func(
    gpointer user_data)
{
    FoilCipherAsyncFinishData* finish = user_data;
    FoilCipherAsyncData* data = &finish->common;
    FoilCipher* cipher = gutil_weakref_get(data->ref);

    GASSERT(cipher);
    if (cipher) {
        FoilCipherPriv* priv = cipher->priv;
        int result;

        g_queue_remove(&priv->async_queue, data);
        result = foil_cipher_finish(cipher, finish->in, finish->len,
            finish->out);
        if (data->fn) {
            data->fn(cipher, result, data->arg);
        }
        foil_cipher_unref(cipher);
    }
    return G_SOURCE_REMOVE;
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
    FoilCipher* cipher = gutil_weakref_get(async->ref);

    if (cipher) {
        FoilCipherAsyncBoolFunc fn = async->fn;
        void* fn_arg = async->fn_arg;

        /*
         * Note: this g_source_remove() deallocates FoilCipherAsyncDataSource,
         * not touching it after that
         */
        g_source_remove(async->id);
        if (fn) {
            fn(cipher, ok, fn_arg);
        }
        foil_cipher_unref(cipher);
    }
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
    FoilCipher* cipher = gutil_weakref_get(async->ref);

    GASSERT(cipher);
    if (cipher) {
        FoilCipherRun* run = &async->run;

        GASSERT(!overlap->id);
        GASSERT(!async->finished);
        foil_digest_update(async->digest, run->in_ptr, run->in_len);
        if (!overlap->out_block) {
            overlap->out_block = g_malloc(cipher->output_block_size);
        }
        if (run->in_len == run->in_block_size && run->bytes_left) {
            /* Next full input block */
            GASSERT(run->in_len == run->in_block_size);
            overlap->id = foil_cipher_step_async(cipher,
                run->in_ptr, overlap->out_block, overlap->fn, async);
            foil_cipher_run_next(&async->run);
        } else {
            /* Finish the process */
            async->finished = overlap;
            overlap->id = foil_cipher_finish_async(cipher,
                run->in_ptr, run->in_len, overlap->out_block,
                foil_cipher_async_write_finished, async);
        }
        foil_cipher_unref(cipher);
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
    FoilCipher* cipher = gutil_weakref_get(async->ref);
    guint i;

    if (cipher) {
        FoilCipherPriv* priv = cipher->priv;

        gutil_int_array_remove_fast(priv->ids, async->id);
        foil_cipher_unref(cipher);
    }
    for (i = 0; i < G_N_ELEMENTS(async->overlap); i++) {
        FoilCipherAsyncOverlap* overlap = async->overlap + i;

        if (overlap->id) {
            g_source_remove(overlap->id);
        }
        if (overlap->out_block) {
            g_free(overlap->out_block);
        }
    }
    foil_cipher_run_deinit(&async->run);
    gutil_weakref_unref(async->ref);
}

/*==========================================================================*
 * Public API
 *==========================================================================*/

guint
foil_cipher_write_data_async(
    FoilCipher* self,
    const void* data,
    gsize size,
    FoilOutput* out,
    FoilDigest* digest,
    FoilCipherAsyncBoolFunc fn,
    void* arg)
{
    if (!out) {
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
        FoilCipherPriv* priv = self->priv;
        GUtilIntArray* ids = priv->ids;
        FoilCipherAsyncDataSource* async = (FoilCipherAsyncDataSource*)source;
        guint i;

        async->ref = gutil_weakref_ref(priv->ref);
        async->fn = fn;
        async->fn_arg = arg;
        async->out = out;
        async->digest = digest;
        async->block.val = data;
        async->block.len = size;
        async->finished = FALSE;
        foil_cipher_run_init(self, &async->run, &async->block, 1);
        async->id = g_source_attach(source, NULL);
        g_source_unref(source);
        if (!ids) {
            ids = (priv->ids = gutil_int_array_new());
        }
        if (!gutil_int_array_contains(ids, async->id)) {
            gutil_int_array_append(ids, async->id);
        }
        async->overlap[0].fn = foil_cipher_async_write_step0_complete;
        async->overlap[1].fn = foil_cipher_async_write_step1_complete;
        for (i = 0; i < G_N_ELEMENTS(async->overlap) && !async->finished; i++) {
            foil_cipher_async_write_step_start(async, async->overlap + i);
        }
        return async->id;
    }
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
        FoilCipherAsyncStepData* data = g_new(FoilCipherAsyncStepData, 1);

        data->in = in;
        data->out = out;
        data->common.fn = fn;
        data->common.arg = arg;
        return foil_cipher_async_queue_and_submit(self->priv, &data->common,
            foil_cipher_async_step_func, foil_cipher_async_data_destroy);
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
        FoilCipherAsyncFinishData* data = g_new(FoilCipherAsyncFinishData, 1);

        data->in = in;
        data->len = len;
        data->out = out;
        data->common.fn = fn;
        data->common.arg = arg;
        return foil_cipher_async_queue_and_submit(self->priv, &data->common,
            foil_cipher_async_finish_func, foil_cipher_async_data_destroy);
    }
    return 0;
}

/*==========================================================================*
 * Internal API
 *==========================================================================*/

void
foil_cipher_priv_add(
    FoilCipherClass* klass)
{
    g_type_class_add_private(klass, sizeof(FoilCipherPriv));
}

FoilCipherPriv*
foil_cipher_priv_get(
    FoilCipher* cipher)
{
    FoilCipherPriv* priv = G_TYPE_INSTANCE_GET_PRIVATE(cipher,
        FOIL_TYPE_CIPHER, FoilCipherPriv);

    priv->ref = gutil_weakref_new(cipher);
    g_queue_init(&priv->async_queue);
    return priv;
}

void
foil_cipher_priv_finalize(
    FoilCipherPriv* priv)
{
    foil_cipher_priv_cancel_all(priv);
    g_queue_clear(&priv->async_queue);
    gutil_int_array_free(priv->ids, TRUE);
    gutil_weakref_unref(priv->ref);
}

void
foil_cipher_priv_cancel_all(
    FoilCipherPriv* priv)
{
    GUtilIntArray* ids = priv->ids;

    if (ids && ids->count) {
        guint i;

        priv->ids = NULL;
        for (i = 0; i < ids->count; i++) {
            g_source_remove(ids->data[i]);
        }
        gutil_int_array_free(ids, TRUE);
    }
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
