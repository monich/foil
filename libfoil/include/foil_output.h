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

#ifndef FOIL_OUTPUT_H
#define FOIL_OUTPUT_H

#include "foil_types.h"

G_BEGIN_DECLS

FoilOutput*
foil_output_ref(
    FoilOutput* out);

void
foil_output_unref(
    FoilOutput* out);

GBytes*
foil_output_free_to_bytes(
    FoilOutput* out);

gssize
foil_output_write(
    FoilOutput* out,
    const void* buf,
    gsize size);

gssize
foil_output_write_bytes(
    FoilOutput* out,
    GBytes* bytes);

gboolean
foil_output_write_bytes_all(
    FoilOutput* out,
    GBytes* bytes);

/* Since 1.0.9 */
guint
foil_output_write_eol(
    FoilOutput* out);

#define foil_output_write_all(out,buf,size) \
    (foil_output_write(out,buf,size) == (gssize)(size))

gboolean
foil_output_flush(
    FoilOutput* out);

gboolean
foil_output_reset(
    FoilOutput* out);

void
foil_output_close(
    FoilOutput* out);

gsize
foil_output_bytes_written(
    FoilOutput* out);

/* Implementations */

FoilOutput*
foil_output_mem_new(
    GByteArray* buf);

FoilOutput*
foil_output_digest_new(
    FoilOutput* out,
    FoilDigest* digest);

FoilOutput*
foil_output_base64_new(
    FoilOutput* out);

FoilOutput*
foil_output_base64_new_full(
    FoilOutput* out,
    guint flags,
    guint linebreak);

#define FOIL_OUTPUT_BASE64_CLOSE    (0x01)  /* Close the target stream */
#define FOIL_OUTPUT_BASE64_FILESAFE (0x02)  /* Use filename safe enciding */

/* Since 1.0.1 */
FoilOutput*
foil_output_file_new(
    FILE* file,
    guint flags);

#define FOIL_OUTPUT_FILE_CLOSE      (0x01)  /* Close the file when done */

FoilOutput*
foil_output_file_new_open(
    const char* path);

FoilOutput*
foil_output_file_new_tmp(void);

G_END_DECLS

#endif /* FOIL_OUTPUT_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
