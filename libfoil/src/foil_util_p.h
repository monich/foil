/*
 * Copyright (C) 2016-2021 by Slava Monich <slava@monich.com>
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
foil_parse_init_data(
    GUtilRange* pos,
    const FoilBytes* data);

gsize
foil_parse_init_bytes(
    GUtilRange* pos,
    GBytes* bytes);

gsize
foil_parse_init_string(
    GUtilRange* pos,
    const char* str);

gboolean
foil_parse_skip_to_next_line(
    GUtilRange* pos,
    gboolean continued);

GHashTable*
foil_parse_headers(
    GUtilRange* pos,
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

const void*
foil_memmem(
    const FoilBytes* haystack,
    const FoilBytes* needle);

#endif /* FOIL_UTIL_P_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
