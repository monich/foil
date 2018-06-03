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

#ifndef FOIL_KEY_P_H
#define FOIL_KEY_P_H

#include "foil_types_p.h"
#include "foil_key.h"

struct foil_key {
    GObject super;
    GBytes* fingerprint;
};

typedef struct foil_key_class {
    GObjectClass super;
    FoilKey* (*fn_generate)(guint bits);
    gboolean (*fn_parse_bytes)(FoilKey* key, const void* data, gsize len,
        GHashTable* param, GError** error);
    gboolean (*fn_equal)(FoilKey* key1, FoilKey* key2);
    GBytes* (*fn_to_bytes)(FoilKey* key);
    gboolean (*fn_export)(FoilKey* key, FoilOutput* out,
        FoilKeyExportFormat format, GHashTable* param, GError** error);
    GBytes* (*fn_fingerprint)(FoilKey* key);
} FoilKeyClass;

#define FOIL_IS_KEY(obj) G_TYPE_CHECK_INSTANCE_TYPE(obj, \
        FOIL_TYPE_KEY)
#define FOIL_KEY_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
        FOIL_TYPE_KEY, FoilKeyClass))
#define FOIL_KEY_GET_CLASS(obj) G_TYPE_INSTANCE_GET_CLASS((obj),\
        FOIL_TYPE_KEY, FoilKeyClass)

#define FOIL_RSA_VERSION (0)

#endif /* FOIL_KEY_P_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
