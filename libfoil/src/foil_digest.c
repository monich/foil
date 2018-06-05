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

#include "foil_digest_p.h"
#include "foil_util_p.h"

/* Logging */
#define GLOG_MODULE_NAME foil_log_digest
#include "foil_log_p.h"
GLOG_MODULE_DEFINE2("foil-digest", FOIL_LOG_MODULE);

G_DEFINE_ABSTRACT_TYPE(FoilDigest, foil_digest, G_TYPE_OBJECT);
#define FOIL_DIGEST(obj) (G_TYPE_CHECK_INSTANCE_CAST(obj, \
        FOIL_TYPE_DIGEST, FoilDigest))
#define FOIL_IS_DIGEST(obj) G_TYPE_CHECK_INSTANCE_TYPE(obj, \
        FOIL_TYPE_DIGEST)
#define FOIL_DIGEST_GET_CLASS(obj) G_TYPE_INSTANCE_GET_CLASS((obj),\
        FOIL_TYPE_DIGEST, FoilDigestClass)
#define foil_digest_class_ref(type) ((FoilDigestClass*)foil_class_ref(type, \
        FOIL_TYPE_DIGEST))

gsize
foil_digest_type_size(
    GType type)
{
    gsize size = 0;
    FoilDigestClass* klass = foil_digest_class_ref(type);
    if (G_LIKELY(klass)) {
        size = klass->size;
        g_type_class_unref(klass);
    }
    return size;
}

const char*
foil_digest_type_name(
    GType type)
{
    const char* name = NULL;
    FoilDigestClass* klass = foil_digest_class_ref(type);
    if (G_LIKELY(klass)) {
        name = klass->name;
        g_type_class_unref(klass);
    }
    return name;
}

GBytes*
foil_digest_data(
    GType type,
    const void* data,
    gsize size)
{
    GBytes* result = NULL;
    if (G_LIKELY(data || !size)) {
        FoilDigestClass* klass = foil_digest_class_ref(type);
        if (G_LIKELY(klass)) {
            void* digest = klass->fn_digest_alloc();
            klass->fn_digest(data, size, digest);
            result = g_bytes_new_with_free_func(digest, klass->size,
                klass->fn_digest_free, digest);
            g_type_class_unref(klass);
        }
    }
    return result;
}

GBytes*
foil_digest_bytes(
    GType type,
    GBytes* bytes)
{
    GBytes* result = NULL;
    if (G_LIKELY(bytes)) {
        gsize size = 0;
        const void* data = g_bytes_get_data(bytes, &size);
        result = foil_digest_data(type, data, size);
    }
    return result;
}

gsize
foil_digest_size(
    FoilDigest* self)
{
    return G_LIKELY(self) ? FOIL_DIGEST_GET_CLASS(self)->size : 0;
}

const char*
foil_digest_name(
    FoilDigest* self)
{
    return G_LIKELY(self) ? FOIL_DIGEST_GET_CLASS(self)->name : NULL;
}

FoilDigest*
foil_digest_new(
    GType type)
{
    FoilDigest* digest = NULL;
    FoilDigestClass* klass = foil_digest_class_ref(type);
    if (G_LIKELY(klass)) {
        digest = g_object_new(type, NULL);
        g_type_class_unref(klass);
    }
    return digest;
}

FoilDigest*
foil_digest_ref(
     FoilDigest* self)
{
    if (G_LIKELY(self)) {
        GASSERT(FOIL_IS_DIGEST(self));
        g_object_ref(self);
    }
    return self;
}

void
foil_digest_unref(
     FoilDigest* self)
{
    if (G_LIKELY(self)) {
        GASSERT(FOIL_IS_DIGEST(self));
        g_object_unref(self);
    }
}

gboolean
foil_digest_copy(
    FoilDigest* self,
    FoilDigest* source)
{
    if (G_LIKELY(self) && G_LIKELY(source)) {
        if (self == source) {
            /* Same object, nothing to copy */
            return TRUE;
        } else {
            /* Both must be of the same class */
            FoilDigestClass* klass = FOIL_DIGEST_GET_CLASS(self);
            if (klass == FOIL_DIGEST_GET_CLASS(source) && klass->fn_copy) {
                klass->fn_copy(self, source);
                if (self->result) {
                    g_bytes_unref(self->result);
                    self->result = NULL;
                }
                if (source->result) {
                    self->result = g_bytes_ref(source->result);
                }
                return TRUE;
            }
        }
    }
    return FALSE;
}

void
foil_digest_update(
    FoilDigest* self,
    const void* data,
    gsize size)
{
    if (G_LIKELY(self)) {
        GASSERT(!self->result);
        FOIL_DIGEST_GET_CLASS(self)->fn_update(self, data, size);
    }
}

void
foil_digest_update_bytes(
    FoilDigest* self,
    GBytes* bytes)
{
    if (G_LIKELY(self) && G_LIKELY(bytes)) {
        gsize size = 0;
        const void* data = g_bytes_get_data(bytes, &size);
        foil_digest_update(self, data, size);
    }
}

GBytes*
foil_digest_finish(
    FoilDigest* self)
{
    if (G_LIKELY(self)) {
        if (!self->result) {
            FoilDigestClass* klass = FOIL_DIGEST_GET_CLASS(self);
            void* data = klass->fn_digest_alloc();
            FOIL_DIGEST_GET_CLASS(self)->fn_finish(self, data);
            self->result = g_bytes_new_with_free_func(data, klass->size,
                klass->fn_digest_free, data);
        }
        return self->result;
    }
    return NULL;
}

GBytes*
foil_digest_free_to_bytes(
    FoilDigest* self)
{
    if (G_LIKELY(self)) {
        GBytes* bytes = foil_digest_finish(self);
        g_bytes_ref(bytes);
        foil_digest_unref(self);
        return bytes;
    }
    return NULL;
}

static
void
foil_digest_finalize(
    GObject* object)
{
    FoilDigest* self = FOIL_DIGEST(object);
    if (self->result) {
        g_bytes_unref(self->result);
    } else {
        /* This clears the internal buffers */
        FOIL_DIGEST_GET_CLASS(self)->fn_finish(self, NULL);
    }
    G_OBJECT_CLASS(foil_digest_parent_class)->finalize(object);
}

static
void
foil_digest_init(
    FoilDigest* self)
{
}

static
void
foil_digest_class_init(
    FoilDigestClass* klass)
{
    G_OBJECT_CLASS(klass)->finalize = foil_digest_finalize;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
