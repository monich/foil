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

#ifndef FOIL_UTIL_P_H
#define FOIL_UTIL_P_H

#include "foil_util.h"
#include "foil_types_p.h"

guint8*
foil_bytes_copy(
    FoilBytes* dest,
    const FoilBytes* src,
    guint8* ptr);

void
foil_bytes_digest(
    FoilBytes* bytes,
    FoilDigest* digest);

void*
foil_class_ref(
    GType type,
    GType base);

void*
foil_abstract_class_ref(
    GType type,
    GType base);

gsize
foil_parse_init_string(
    FoilParsePos* pos,
    const char* str);

gboolean
foil_parse_skip_to_next_line(
    FoilParsePos* pos,
    gboolean continued);

GHashTable*
foil_parse_headers(
    FoilParsePos* pos,
    GString* buf);

char*
foil_format_header(
    const char* tag,
    const char* value);

GHashTable*
foil_param_add(
    GHashTable* params,
    const char* key,
    const char* value);

#endif /* FOIL_UTIL_P_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
