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

#ifndef FOIL_INPUT_H
#define FOIL_INPUT_H

#include "foil_types.h"

G_BEGIN_DECLS

FoilInput*
foil_input_ref(
    FoilInput* in);

void
foil_input_unref(
    FoilInput* in);

gssize
foil_input_read(
    FoilInput* in,
    void* buf,          /* optional */
    gsize size);

gssize
foil_input_copy(
    FoilInput* in,
    FoilOutput* out,
    gsize size);

/* Since 1.0.1 */
gboolean
foil_input_copy_all(
    FoilInput* in,
    FoilOutput* out,
    gsize* copied);

gboolean
foil_input_has_available(
    FoilInput* in,
    gsize count);

const void*
foil_input_peek(
    FoilInput* in,
    gsize requested,
    gsize* available);  /* optional */

gsize
foil_input_bytes_read(
    FoilInput* in);

GBytes*
foil_input_read_all(
    FoilInput* in);

void
foil_input_close(
    FoilInput* in);

#define foil_input_skip(in,size) \
  foil_input_read(in,NULL,size)

/* Implementations */

FoilInput*
foil_input_mem_new(
    GBytes* data);

FoilInput*
foil_input_mem_new_static(
    const void* data,
    gsize size);

FoilInput*
foil_input_mem_new_bytes(
    const FoilBytes* bytes);

FoilInput*
foil_input_range_new(
    FoilInput* in,
    gsize offset,
    gsize max_bytes);

FoilInput*
foil_input_digest_new(
    FoilInput* in,
    FoilDigest* digest);

FoilInput*
foil_input_base64_new(
    FoilInput* in);

FoilInput*
foil_input_base64_new_full(
    FoilInput* in,
    guint flags);

#define FOIL_INPUT_BASE64_IGNORE_SPACES (0x01)
#define FOIL_INPUT_BASE64_VALIDATE      (0x02)  /* Since 1.0.1 */

FoilInput*
foil_input_cipher_new(
    FoilCipher* cipher,
    FoilInput* in);

FoilInput*
foil_input_file_new(
    FILE* file,
    guint flags);

#define FOIL_INPUT_FILE_CLOSE           (0x01)  /* Close the file when done */

FoilInput*
foil_input_file_new_open(
    const char* path);

G_END_DECLS

#endif /* FOIL_INPUT_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
