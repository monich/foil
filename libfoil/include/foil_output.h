/*
 * Copyright (C) 2016-2022 by Slava Monich <slava@monich.com>
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

guint
foil_output_write_eol(
    FoilOutput* out); /* Since 1.0.9 */

gboolean
foil_output_write_byte(
    FoilOutput* out,
    guint8 byte); /* Since 1.0.27 */

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
foil_output_cipher_new(
    FoilOutput* out,
    FoilCipher* cipher,
    FoilDigest* digest); /* Since 1.0.26 */

FoilOutput*
foil_output_cipher_new2(
    FoilOutput* out,
    FoilCipher* cipher,
    FoilHmac* hmac); /* Since 1.0.27 */

FoilOutput*
foil_output_cipher_mem_new(
    GByteArray* buf,
    FoilCipher* cipher,
    FoilDigest* digest); /* Since 1.0.26 */

FoilOutput*
foil_output_cipher_mem_new2(
    GByteArray* buf,
    FoilCipher* cipher,
    FoilHmac* hmac); /* Since 1.0.27 */

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

FoilOutput*
foil_output_file_new(
    FILE* file,
    guint flags); /* Since 1.0.1 */

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
