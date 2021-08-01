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

#ifndef FOIL_ASN1_H
#define FOIL_ASN1_H

#include "foil_types.h"

G_BEGIN_DECLS

/*
 * Simple set of ASN.1 encoding/decoding utilities, by no means complete.
 */

gboolean
foil_asn1_is_block_header(
    const GUtilRange* pos,
    guint32* total_len);

gboolean
foil_asn1_is_sequence(
    const GUtilRange* pos);

gboolean
foil_asn1_is_integer(
    const GUtilRange* pos);

/* Since 1.0.7 */
gboolean
foil_asn1_is_bit_string(
    const GUtilRange* pos);

gboolean
foil_asn1_is_octet_string(
    const GUtilRange* pos);

gboolean
foil_asn1_is_ia5_string(
    const GUtilRange* pos);

gboolean
foil_asn1_parse_skip_sequence_header(
    GUtilRange* pos,
    guint32* len);

gboolean
foil_asn1_parse_start_sequence(
    GUtilRange* pos,
    guint32* len);

/* Since 1.0.7 */
gboolean
foil_asn1_parse_start_bit_string(
    GUtilRange* pos,
    guint32* num_bytes,
    guint8* unused_bits);

gboolean
foil_asn1_parse_integer_bytes(
    GUtilRange* pos,
    FoilBytes* bytes);

gboolean
foil_asn1_parse_int32(
    GUtilRange* pos,
    gint32* value);

/* Since 1.0.7 */
gboolean
foil_asn1_parse_bit_string(
    GUtilRange* pos,
    FoilBytes* bytes,
    guint8* unused_bits);

/* Since 1.0.8 */
gboolean
foil_asn1_parse_object_id(
    GUtilRange* pos,
    FoilBytes* oid_bytes);

gboolean
foil_asn1_parse_octet_string(
    GUtilRange* pos,
    FoilBytes* bytes);

gboolean
foil_asn1_parse_ia5_string(
    GUtilRange* pos,
    FoilBytes* bytes);

gsize
foil_asn1_block_length(
    gsize data_length);

/* Since 1.0.7 */
#define foil_asn1_bit_string_block_length(bitcount) \
    foil_asn1_block_length(1 + ((bitcount) + 7)/8)

gboolean
foil_asn1_parse_len(
    GUtilRange* pos,
    guint32* len,
    gboolean* def);

gboolean
foil_asn1_read_len(
    FoilInput* in,
    guint32* len,
    gboolean* def);

gboolean
foil_asn1_read_sequence_header(
    FoilInput* in,
    guint32* len);

gboolean
foil_asn1_read_octet_string_header(
    FoilInput* in,
    guint32* len);

gboolean
foil_asn1_read_int32(
    FoilInput* in,
    gint32* value);

char*
foil_asn1_read_ia5_string(
    FoilInput* in,
    gssize max_len,
    gsize* length);

gsize
foil_asn1_encode_sequence_header(
    FoilOutput* out,
    gsize data_length);

gsize
foil_asn1_encode_sequence(
    FoilOutput* out,
    const FoilBytes* bytes[],
    guint count);

gsize
foil_asn1_encode_sequence_data(
    FoilOutput* out,
    const void* data,
    gsize len);

GBytes*
foil_asn1_encode_sequence_bytes(
    const FoilBytes* bytes[],
    guint count);

gsize
foil_asn1_encode_octet_string_header(
    FoilOutput* out,
    gsize data_length);

/* Since 1.0.7 */
gsize
foil_asn1_encode_bit_string_header(
    FoilOutput* out,
    gsize bitcount);

/* Since 1.0.7 */
gsize
foil_asn1_encode_bit_string(
    FoilOutput* out,
    const FoilBytes* bytes,
    guint unused_bits);

/* Since 1.0.7 */
GBytes*
foil_asn1_encode_bit_string_bytes(
    const FoilBytes* bytes,
    guint unused_bits);

gsize
foil_asn1_encode_octet_string(
    FoilOutput* out,
    const FoilBytes* bytes);

GBytes*
foil_asn1_encode_octet_string_bytes(
    const FoilBytes* bytes);

gsize
foil_asn1_encode_integer(
    FoilOutput* out,
    gint32 value);

gsize
foil_asn1_encode_integer_bytes(
    FoilOutput* out,
    const FoilBytes* bytes);

GBytes*
foil_asn1_encode_integer_value(
    gint32 value);

gsize
foil_asn1_encode_ia5_string(
    FoilOutput* out,
    const char* str);

GBytes*
foil_asn1_encode_ia5_string_bytes(
    const char* str);

/* Since 1.0.23 */
gboolean
foil_asn1_parse_tag(
    GUtilRange* pos,
    guint8* tag_id, /* Full tag or just leading octet for multi-byte tags */
    guint32* tag_num);

G_END_DECLS

#endif /* FOIL_ASN1_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
