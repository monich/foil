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

#include "foil_cipher_sync.h"

/* Logging */
#define GLOG_MODULE_NAME foil_log_cipher
#include "foil_log_p.h"

typedef struct foil_cipher_sync_data FoilCipherSyncData;
struct foil_cipher_sync_data {
    FoilCipherSyncData* next;
    FoilCipherSync* cipher;
    FoilCipherAsyncFunc fn;
    void* arg;
    guint id;
};

typedef struct foil_cipher_sync_step_data {
    FoilCipherSyncData common;
    const void* in;
    void* out;
} FoilCipherSyncStepData;

typedef struct foil_cipher_sync_finish_data {
    FoilCipherSyncData common;
    const void* in;
    int len;
    void* out;
} FoilCipherSyncFinishData;

/*
 * Normally the entries are added to the end of the list, and
 * removed from the beginning. There's no need to optimize the
 * removal of an arbitrary entry.
 */
struct foil_cipher_sync_priv {
    FoilCipherSyncData* first;
    FoilCipherSyncData* last;
};

G_DEFINE_ABSTRACT_TYPE(FoilCipherSync, foil_cipher_sync, FOIL_TYPE_CIPHER);
#define PARENT_CLASS foil_cipher_sync_parent_class

static
void
foil_cipher_sync_data_dequeue(
    FoilCipherSyncData* data)
{
    if (data->cipher) {
        FoilCipherSyncPriv* priv = data->cipher->priv;
        data->cipher = NULL;
        if (G_LIKELY(priv->first == data)) {
            /* Most typical case */
            if (!(priv->first = data->next)) {
                priv->last = NULL;
            }
        } else if (data->next || priv->last == data) {
            /* It's not been removed yet */
            FoilCipherSyncData* ptr;
            FoilCipherSyncData* prev = NULL;
            for (ptr = priv->first; ptr; ptr = ptr->next) {
                if (ptr == data) {
                    /* It cannot be the first entry, prev must be non zero */
                    GASSERT(prev);
                    prev->next = data->next;
                    /* Mark it as removed */
                    if (data->next) {
                        data->next = NULL;
                    } else {
                        GASSERT(priv->last == data);
                        priv->last = prev;
                    }
                    break;
                }
                prev = ptr;
            }
            GASSERT(ptr == data);
        }
    }
}

static
void
foil_cipher_sync_data_queue(
    FoilCipherSync* self,
    FoilCipherSyncData* data)
{
    FoilCipherSyncPriv* priv = self->priv;
    data->cipher = self;
    data->next = NULL;
    if (priv->last) {
        priv->last->next = data;
        GASSERT(priv->first);
    } else {
        GASSERT(!priv->first);
        priv->first = data;
    }
    priv->last = data;
}

static
void
foil_cipher_sync_cancel_all_impl(
    FoilCipherSyncPriv* priv)
{
    while (priv->first) {
        FoilCipherSyncData* data = priv->first;
        foil_cipher_sync_data_dequeue(data);
        g_source_remove(data->id);
    }
}

static
void
foil_cipher_sync_step_destroy(
    gpointer arg)
{
    FoilCipherSyncStepData* data = arg;
    foil_cipher_sync_data_dequeue(&data->common);
    g_slice_free(FoilCipherSyncStepData, data);
}

static
void
foil_cipher_sync_finish_destroy(
    gpointer arg)
{
    FoilCipherSyncFinishData* data = arg;
    foil_cipher_sync_data_dequeue(&data->common);
    g_slice_free(FoilCipherSyncFinishData, data);
}

static
FoilCipher*
foil_cipher_sync_start(
    FoilCipherSyncData* data)
{
    FoilCipherSync* self = data->cipher;
    FoilCipher* cipher = foil_cipher_ref(FOIL_CIPHER(self));
    foil_cipher_sync_data_dequeue(data);
    data->id = 0;
    return cipher;
}

static
gboolean
foil_cipher_sync_done(
    FoilCipher* cipher,
    FoilCipherSyncData* data,
    int result)
{
    if (data->fn) {
        data->fn(cipher, result, data->arg);
    }
    foil_cipher_unref(cipher);
    return G_SOURCE_REMOVE;
}

static
gboolean
foil_cipher_sync_step_async_func(
    gpointer user_data)
{
    FoilCipherSyncStepData* data = user_data;
    FoilCipher* cipher = foil_cipher_sync_start(&data->common);
    int result = foil_cipher_step(cipher, data->in, data->out);
    return foil_cipher_sync_done(cipher, &data->common, result);
}

static
gboolean
foil_cipher_sync_finish_async_func(
    gpointer user_data)
{
    FoilCipherSyncFinishData* data = user_data;
    FoilCipher* cipher = foil_cipher_sync_start(&data->common);
    int result = foil_cipher_finish(cipher, data->in, data->len, data->out);
    return foil_cipher_sync_done(cipher, &data->common, result);
}

static
guint
foil_cipher_sync_queue_and_submit(
    FoilCipherSync* self,
    FoilCipherSyncData* data,
    GSourceFunc run,
    GDestroyNotify destroy)
{
    data->id = g_idle_add_full(self->priority, run, data, destroy);
    data->cipher = self;
    foil_cipher_sync_data_queue(self, data);
    return data->id;
}

static
guint
foil_cipher_sync_step_async(
    FoilCipher* cipher,
    const void* in,
    void* out,
    FoilCipherAsyncFunc fn,
    void* arg)
{
    FoilCipherSync* self = FOIL_CIPHER_SYNC(cipher);
    FoilCipherSyncStepData* data = g_slice_new(FoilCipherSyncStepData);
    data->in = in;
    data->out = out;
    data->common.fn = fn;
    data->common.arg = arg;
    return foil_cipher_sync_queue_and_submit(self, &data->common,
        foil_cipher_sync_step_async_func, foil_cipher_sync_step_destroy);
}

static
guint
foil_cipher_sync_finish_async(
    FoilCipher* cipher,
    const void* in,
    int len,
    void* out,
    FoilCipherAsyncFunc fn,
    void* arg)
{
    FoilCipherSync* self = FOIL_CIPHER_SYNC(cipher);
    FoilCipherSyncFinishData* data = g_slice_new(FoilCipherSyncFinishData);
    data->in = in;
    data->len = len;
    data->out = out;
    data->common.fn = fn;
    data->common.arg = arg;
    return foil_cipher_sync_queue_and_submit(self, &data->common,
        foil_cipher_sync_finish_async_func, foil_cipher_sync_finish_destroy);
}

static
void
foil_cipher_sync_cancel_all(
    FoilCipher* cipher)
{
    FoilCipherSync* self = FOIL_CIPHER_SYNC(cipher);

    /*
     * Asynchronous requests could be submitted in two different ways:
     *
     * 1. By foil_cipher_write_data_async and friends
     * 2. Directly by the application code
     *
     * In the former case we have to invoke the superclass implementation
     * first, in the latter one it doesn't matter. This is a bit unusual
     * but it seems to be the easiest way to avoid removing the source
     * twice. Cancelling the asynchronous ciphering sequence (which is
     * what the parent code does) removes the sources associated with
     * the sequence.
     */
    FOIL_CIPHER_CLASS(PARENT_CLASS)->fn_cancel_all(cipher);
    foil_cipher_sync_cancel_all_impl(self->priv);
}

static
void
foil_cipher_sync_finalize(
    GObject* object)
{
    foil_cipher_sync_cancel_all(FOIL_CIPHER(object));
    G_OBJECT_CLASS(PARENT_CLASS)->finalize(object);
}

static
void
foil_cipher_sync_init(
    FoilCipherSync* self)
{
    self->priority = G_PRIORITY_DEFAULT_IDLE;
    self->priv = G_TYPE_INSTANCE_GET_PRIVATE(self, FOIL_TYPE_CIPHER_SYNC,
        FoilCipherSyncPriv);
}

static
void
foil_cipher_sync_class_init(
    FoilCipherSyncClass* klass)
{
    klass->fn_step_async = foil_cipher_sync_step_async;
    klass->fn_finish_async = foil_cipher_sync_finish_async;
    klass->fn_cancel_all = foil_cipher_sync_cancel_all;
    G_OBJECT_CLASS(klass)->finalize = foil_cipher_sync_finalize;
    g_type_class_add_private(klass, sizeof(FoilCipherSyncPriv));
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
