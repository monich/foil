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

#include "foil_random_p.h"

/* Logging */
#define GLOG_MODULE_NAME foil_log_random
#include "foil_log_p.h"
GLOG_MODULE_DEFINE2("foil-random", FOIL_LOG_MODULE);

G_DEFINE_ABSTRACT_TYPE(FoilRandom, foil_random, G_TYPE_OBJECT);
#define FOIL_IS_RANDOM_TYPE(klass) G_TYPE_CHECK_CLASS_TYPE(klass, \
        FOIL_TYPE_RANDOM)

static
FoilRandomClass*
foil_random_class_ref(
    GType type)
{
    if (G_LIKELY(type)) {
        GTypeClass* klass = g_type_class_ref(type);
        if (klass) {
            if (FOIL_IS_RANDOM_TYPE(klass)) {
                return FOIL_RANDOM_CLASS(klass);
            }
            g_type_class_unref(klass);
        }
        GERR("Not a random class");
    }
    return NULL;
}

gboolean
foil_random_generate(
    GType type,
    void* data,
    guint len)
{
    gboolean ok = FALSE;
    FoilRandomClass* klass = foil_random_class_ref(type);
    if (G_LIKELY(klass)) {
        ok = klass->fn_generate(data, len);
        g_type_class_unref(klass);
    }
    return ok;
}

GBytes*
foil_random_generate_bytes(
    GType type,
    guint len)
{
    GBytes* result = NULL;
    if (G_LIKELY(len)) {
        FoilRandomClass* klass = foil_random_class_ref(type);
        if (G_LIKELY(klass)) {
            void* data = g_malloc(len);
            if (klass->fn_generate(data, len)) {
                result = g_bytes_new_take(data, len);
            } else {
                g_free(data);
            }
            g_type_class_unref(klass);
        }
    }
    return result;
}

static
void
foil_random_init(
    FoilRandom* random)
{
}

static
void
foil_random_class_init(
    FoilRandomClass* klass)
{
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
