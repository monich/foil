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

#include "foil_asn1.h"
#include "foil_input.h"
#include "foil_output.h"
#include "foil_util.h"
#include "foil_log_p.h"

#define ASN1_CLASS_UNIVERSAL            (0x00)
#define ASN1_CLASS_APPLICATION          (0x40)
#define ASN1_CLASS_CONTEXT_SPECIFIC     (0x80)
#define ASN1_CLASS_PRIVATE              (0xC0)
#define ASN1_CLASS_MASK                 (0xC0)
#define ASN1_CLASS_STRUCTURED           (0x20)

#define ASN1_TAG_BOOLEAN                (0x01)
#define ASN1_TAG_INTEGER                (0x02)
#define ASN1_TAG_BIT_STRING             (0x03)
#define ASN1_TAG_OCTET_STRING           (0x04)
#define ASN1_TAG_NULL                   (0x05)
#define ASN1_TAG_OBJECT_ID              (0x06)
#define ASN1_TAG_ENUMERATED             (0x0A)
#define ASN1_TAG_UTF8_STRING            (0x0C)
#define ASN1_TAG_SEQUENCE               (0x10)
#define ASN1_TAG_SET                    (0x11)
#define ASN1_TAG_NUMERIC_STRING         (0x12)
#define ASN1_TAG_PRINTABLE_STRING       (0x13)
#define ASN1_TAG_TELETEX_STRING         (0x14)
#define ASN1_TAG_IA5_STRING             (0x16)
#define ASN1_TAG_UTC_TIME               (0x17)
#define ASN1_TAG_GENERALIZED_TIME       (0x18)
#define ASN1_TAG_VISIBLE_STRING         (0x1A)
#define ASN1_TAG_GENERAL_STRING         (0x1B)
#define ASN1_TAG_UNIVERSAL_STRING       (0x1C)
#define ASN1_TAG_BMP_STRING             (0x1E)

/**
 * Parse length octets. For indefinite form, length set to zero.
 */
gboolean
foil_asn1_parse_len(
    FoilParsePos* pos,
    guint32* len,
    gboolean* def)
{
    if (pos->ptr < pos->end) {
        const guint8 x = pos->ptr[0];
        if (x & 0x80) {
            const unsigned int n = x & 0x7f;
            if (n < 5 && (pos->ptr + (n+1)) <= pos->end) {
                if (!n) {
                    /* Indefinite form */
                    if (def) *def = FALSE;
                    if (len) *len = 0;
                } else {
                    /* Long form */
                    if (def) *def = TRUE;
                    if (len) {
                        unsigned int i, val = 0;
                        for (i=0; i<n; i++) val = (val << 8) + pos->ptr[i+1];
                        *len = val;
                    }
                }
                pos->ptr += (n+1);
                return TRUE;
            }
        } else {
            /* Short form */
            if (def) *def = TRUE;
            if (len) *len = x;
            pos->ptr++;
            return TRUE;
        }
    }
    return FALSE;
}

static
gsize
foil_asn1_peek_len(
    FoilInput* in,
    gsize off,
    guint32* len,
    gboolean* def)
{
    gsize available;
    const guint8* ptr = foil_input_peek(in, off+1, &available);
    if (ptr && available >= off+1) {
        const guint8 x = ptr[off];
        if (x & 0x80) {
            const unsigned int n = x & 0x7f;
            ptr = foil_input_peek(in, off+n+1, &available);
            if (available >= (off+n+1)) {
                FoilParsePos pos;
                pos.ptr = ptr + off;
                pos.end = pos.ptr + available - off;
                if (foil_asn1_parse_len(&pos, len, def)) {
                    return pos.ptr - (ptr + off);
                }
            }
        } else {
            /* Short form */
            if (def) *def = TRUE;
            if (len) *len = x;
            return 1;
        }
    }
    return 0;
}

gboolean
foil_asn1_read_len(
    FoilInput* in,
    guint32* len,
    gboolean* def)
{
    gsize nbytes = foil_asn1_peek_len(in, 0, len, def);
    if (nbytes) {
        foil_input_skip(in, nbytes);
        return TRUE;
    }
    return FALSE;
}

/**
 * Checks if the buffer contains an ASN.1 block header (not necessarily
 * the data). Returns the full length of the block (including the header)
 * so that the caller knows how much data is needed to actually parse the
 * block.
 */
gboolean
foil_asn1_is_block_header(
    const FoilParsePos* pos,
    guint32* total_len)
{
    if (pos->ptr < pos->end) {
        FoilParsePos tmp = *pos;
        guint32 data_len;
        gboolean def;
        tmp.ptr++;
        if (foil_asn1_parse_len(&tmp, &data_len, &def) && def) {
            const guint32 total = data_len + (tmp.ptr - pos->ptr);
            /* Check for overflow */
            if (total > data_len) {
                if (total_len) *total_len = total;
                return TRUE;
            }
        }
    }
    return FALSE;
}

gboolean
foil_asn1_is_sequence(
    const FoilParsePos* pos)
{
    return pos->ptr < pos->end &&
        (pos->ptr[0] & (~ASN1_CLASS_MASK)) ==
        (ASN1_CLASS_STRUCTURED | ASN1_TAG_SEQUENCE);
}

gboolean
foil_asn1_is_integer(
    const FoilParsePos* pos)
{
    return pos->ptr < pos->end &&
        (pos->ptr[0] & (~ASN1_CLASS_MASK)) == ASN1_TAG_INTEGER;
}

gboolean
foil_asn1_is_octet_string(
    const FoilParsePos* pos)
{
    return pos->ptr < pos->end &&
        (pos->ptr[0] & (~ASN1_CLASS_MASK)) == ASN1_TAG_OCTET_STRING;
}

gboolean
foil_asn1_is_ia5_string(
    const FoilParsePos* pos)
{
    return pos->ptr < pos->end &&
        (pos->ptr[0] & (~ASN1_CLASS_MASK)) == ASN1_TAG_IA5_STRING;
}

gboolean
foil_asn1_parse_skip_sequence_header(
    FoilParsePos* pos,
    guint32* len)
{
    if (foil_asn1_is_sequence(pos)) {
        FoilParsePos tmp = *pos;
        guint32 seq_len;
        gboolean def;
        tmp.ptr++;
        if (foil_asn1_parse_len(&tmp, &seq_len, &def) && def) {
            pos->ptr = tmp.ptr;
            if (len) *len = seq_len;
            return TRUE;
        }
    }
    return FALSE;
}

gboolean
foil_asn1_parse_start_sequence(
    FoilParsePos* pos,
    guint32* len)
{
    guint32 seq_len;
    FoilParsePos tmp = *pos;
    if (foil_asn1_parse_skip_sequence_header(&tmp, &seq_len) &&
        /* Overflow can occur on 32-bit systems */
        tmp.ptr + seq_len >= tmp.ptr &&
        tmp.ptr + seq_len <= tmp.end) {
        pos->ptr = tmp.ptr;
        if (len) *len = seq_len;
        return TRUE;
    }
    return FALSE;
}

static
gboolean
foil_asn1_read_block_header(
    FoilInput* in,
    guint tag,
    guint32* len)
{
    const guint8* ptr = foil_input_peek(in, 1, NULL);
    if (ptr && (guint)(ptr[0] & (~ASN1_CLASS_MASK)) == tag) {
        guint32 block_len;
        gboolean def;
        gsize len_bytes = foil_asn1_peek_len(in, 1, &block_len, &def);
        if (len_bytes && def) {
            foil_input_skip(in, len_bytes + 1);
            if (len) *len = block_len;
            return TRUE;
        }
    }
    return FALSE;
}

gboolean
foil_asn1_read_sequence_header(
    FoilInput* in,
    guint32* len)
{
    return foil_asn1_read_block_header(in,
        ASN1_CLASS_STRUCTURED | ASN1_TAG_SEQUENCE, len);
}

gboolean
foil_asn1_read_octet_string_header(
    FoilInput* in,
    guint32* len)
{
    return foil_asn1_read_block_header(in, ASN1_TAG_OCTET_STRING, len);
}

static
gint32
foil_asn1_decode_int32(
    const FoilBytes* bytes)
{
    gint value = 0;
    switch (bytes->len) {
    case 4:
        value = ((((((bytes->val[0]) << 8) +
                      bytes->val[1]) << 8) +
                      bytes->val[2]) << 8) +
                      bytes->val[3];
        break;
    case 3:
        value = ((((bytes->val[0]) << 8) +
                    bytes->val[1]) << 8) +
                    bytes->val[2];
        if (bytes->val[0] & 0x80) {
            value |= 0xff000000;
        }
        break;
    case 2:
        value = ((bytes->val[0]) << 8) + bytes->val[1];
        if (bytes->val[0] & 0x80) {
            value |= 0xffff0000;
        }
        break;
    case 1:
        value = bytes->val[0];
        if (bytes->val[0] & 0x80) {
            value |= 0xffffff00;
        }
        break;
    }
    return value;
}

gboolean
foil_asn1_read_int32(
    FoilInput* in,
    gint32* value)
{
    gsize have_bytes;
    const guint8* ptr = foil_input_peek(in, 1, &have_bytes);
    if (ptr && (ptr[0] & (~ASN1_CLASS_MASK)) == ASN1_TAG_INTEGER) {
        guint32 int_len;
        gsize len_bytes = foil_asn1_peek_len(in, 1, &int_len, NULL);
        if (len_bytes && int_len > 0 && int_len <= 4) {
            const gsize need_bytes = len_bytes + int_len + 1;
            const guint8* ptr = foil_input_peek(in, need_bytes, &have_bytes);
            if (have_bytes == need_bytes) {
                if (value) {
                    FoilBytes bytes;
                    bytes.val = ptr + (len_bytes + 1);
                    bytes.len = int_len;
                    *value = foil_asn1_decode_int32(&bytes);
                }
                foil_input_skip(in, have_bytes);
                return TRUE;
            }
        }
    }
    return FALSE;
}

char*
foil_asn1_read_ia5_string(
    FoilInput* in,
    gssize max_len,
    gsize* length)
{
    gsize have_bytes;
    const guint8* ptr = foil_input_peek(in, 1, &have_bytes);
    if (ptr && (ptr[0] & (~ASN1_CLASS_MASK)) == ASN1_TAG_IA5_STRING) {
        guint32 str_len;
        gsize len_bytes = foil_asn1_peek_len(in, 1, &str_len, NULL);
        if (len_bytes && (max_len < 0 || str_len <= (gsize)max_len)) {
            char* str = g_malloc(str_len + 1);
            foil_input_skip(in, len_bytes + 1);
            if (foil_input_read(in, str, str_len) == (gssize)str_len) {
                str[str_len] = 0;
                GASSERT(strlen(str) == str_len);
                if (length) {
                    *length = str_len;
                }
                return str;
            }
            g_free(str);
        }
    }
    return NULL;
}

gboolean
foil_asn1_parse_integer_bytes(
    FoilParsePos* pos,
    FoilBytes* bytes)
{
    if (foil_asn1_is_integer(pos)) {
        FoilParsePos tmp = *pos;
        guint32 len;
        tmp.ptr++;
        /*
         * If length is in indefinite form, foil_asn1_parse_len will
         * set len to zero, which is invalid for integer, so we don't
         * need to check the form.
         */
        if (foil_asn1_parse_len(&tmp, &len, NULL) && len &&
            tmp.ptr + len <= tmp.end) {
            if (bytes) {
                bytes->val = tmp.ptr;
                bytes->len = len;
            }
            pos->ptr = tmp.ptr + len;
            return TRUE;
        }
    }
    return FALSE;
}

gboolean
foil_asn1_parse_int32(
    FoilParsePos* pos,
    gint32* value)
{
    FoilBytes bytes;
    FoilParsePos tmp = *pos;
    if (foil_asn1_parse_integer_bytes(&tmp, &bytes) && bytes.len <= 4) {
        if (value) {
            *value = foil_asn1_decode_int32(&bytes);
        }
        *pos = tmp;
        return TRUE;
    }
    return FALSE;
}

static
gboolean
foil_asn1_parse_block(
    FoilParsePos* pos,
    guint tag,
    FoilBytes* bytes)
{
    if (pos->ptr < pos->end &&
        (pos->ptr[0] & (guint)(~ASN1_CLASS_MASK)) == tag) {
        FoilParsePos tmp = *pos;
        guint32 len;
        gboolean def;
        tmp.ptr++;
        if (foil_asn1_parse_len(&tmp, &len, &def) && def &&
            /* Overflow can occur on 32-bit systems */
            tmp.ptr + len >= tmp.ptr &&
            tmp.ptr + len <= tmp.end) {
            if (bytes) {
                bytes->val = tmp.ptr;
                bytes->len = len;
            }
            pos->ptr = tmp.ptr + len;
            return TRUE;
        }
    }
    return FALSE;
}

gboolean
foil_asn1_parse_octet_string(
    FoilParsePos* pos,
    FoilBytes* bytes)
{
    return foil_asn1_parse_block(pos, ASN1_TAG_OCTET_STRING, bytes);
}

gboolean
foil_asn1_parse_ia5_string(
    FoilParsePos* pos,
    FoilBytes* bytes)
{
    return foil_asn1_parse_block(pos, ASN1_TAG_IA5_STRING, bytes);
}

gsize
foil_asn1_block_length(
    gsize data_length)
{
    /* Check if we need to use the long form */
    gsize total_length = data_length + 2;
    if (data_length >= 0x7f) {
        gsize len = data_length;
        while (len) {
            len >>= 8;
            total_length++;
        }
    }
    return total_length;
}

static
gsize
foil_asn1_encode_block_header(
    FoilOutput* out,
    guint8 id,
    gsize data_length)
{
    const gsize prev_written = foil_output_bytes_written(out);
    guint i, len_octets = 0;
    guint8 octet;

    /* Check if we need to use the long form */
    if (data_length >= 0x7f) {
        gsize len = data_length;
        while (len) {
            len >>= 8;
            len_octets++;
        }
    }

    /* Identifier octet */
    if (foil_output_write(out, &id, 1) < 1) {
        return 0;
    }

    /* Length octet(s) */
    if (len_octets) {
        /* Long form */
        octet = 0x80 | len_octets;
        if (foil_output_write(out, &octet, 1) < 1) {
            return 0;
        }
        for (i=0; i<len_octets; i++) {
            octet = (guint8)(data_length >> 8*(len_octets - i - 1));
            if (foil_output_write(out, &octet, 1) < 1) {
                return 0;
            }
        }
    } else {
        /* Short form */
        octet = (guint8)data_length;
        if (foil_output_write(out, &octet, 1) < 1) {
            return 0;
        }
    }

    return foil_output_bytes_written(out) - prev_written;
}

gsize
foil_asn1_encode_sequence_header(
    FoilOutput* out,
    gsize data_length)
{
    return foil_asn1_encode_block_header(out, ASN1_CLASS_STRUCTURED |
        ASN1_TAG_SEQUENCE, data_length);
}

gsize
foil_asn1_encode_octet_string_header(
    FoilOutput* out,
    gsize datalen)
{
    return foil_asn1_encode_block_header(out, ASN1_TAG_OCTET_STRING, datalen);
}

static
gsize
foil_asn1_encode_block(
    FoilOutput* out,
    guint8 id,
    const FoilBytes* bytes[],
    guint count)
{
    const gsize prev_written = foil_output_bytes_written(out);
    guint i;
    gsize total = 0;

    /* Sum the lengths */
    for (i=0; i<count; i++) {
        total += bytes[i]->len;
    }

    /* Identifier octet */
    if (!foil_asn1_encode_block_header(out, id, total)) {
        return 0;
    }

    /* Contents octets */
    for (i=0; i<count; i++) {
        const gssize len = bytes[i]->len;
        if (foil_output_write(out, bytes[i]->val, len) < len) {
            return 0;
        }
    }

    return foil_output_bytes_written(out) - prev_written;
}

static
gsize
foil_asn1_encode_block1(
    FoilOutput* out,
    guint8 id,
    const FoilBytes* bytes)
{
    return foil_asn1_encode_block(out, id, &bytes, 1);
}

gsize
foil_asn1_encode_sequence(
    FoilOutput* out,
    const FoilBytes* bytes[],
    guint count)
{
    return foil_asn1_encode_block(out, ASN1_CLASS_STRUCTURED |
        ASN1_TAG_SEQUENCE, bytes, count);
}

gsize
foil_asn1_encode_sequence_data(
    FoilOutput* out,
    const void* data,
    gsize len)
{
    FoilBytes bytes;
    const FoilBytes* bytes_ptr = &bytes;
    bytes.val = data;
    bytes.len = len;
    return foil_asn1_encode_sequence(out, &bytes_ptr, 1);
}

GBytes*
foil_asn1_encode_sequence_bytes(
    const FoilBytes* bytes[],
    guint count)
{
    FoilOutput* out = foil_output_mem_new(NULL);
    GVERIFY(foil_asn1_encode_sequence(out, bytes, count));
    return foil_output_free_to_bytes(out);
}

gsize
foil_asn1_encode_octet_string(
    FoilOutput* out,
    const FoilBytes* bytes)
{
    return foil_asn1_encode_block1(out, ASN1_TAG_OCTET_STRING, bytes);
}

GBytes*
foil_asn1_encode_octet_string_bytes(
    const FoilBytes* bytes)
{
    FoilOutput* out = foil_output_mem_new(NULL);
    GVERIFY(foil_asn1_encode_octet_string(out, bytes));
    return foil_output_free_to_bytes(out);
}

gsize
foil_asn1_encode_integer_bytes(
    FoilOutput* out,
    const FoilBytes* bytes)
{
    return foil_asn1_encode_block1(out, ASN1_TAG_INTEGER, bytes);
}

gsize
foil_asn1_encode_integer(
    FoilOutput* out,
    gint32 value)
{
    FoilBytes bytes;
    guint8 data[4];
    int len = 0;
    if (value < 0) {
        len = ((value & 0xffffff80) == 0xffffff80) ? 1 :
              ((value & 0xffff8000) == 0xffff8000) ? 2 :
              ((value & 0xff800000) == 0xff800000) ? 3 : 4;
    } else {
        len = !(value & 0xffffff80) ? 1 :
              !(value & 0xffff8000) ? 2 :
              !(value & 0xff800000) ? 3 : 4;
    }
    bytes.val = data;
    bytes.len = 0;
    switch (len) {
    case 4: data[bytes.len++] = (guint8)(value >> 24);
    case 3: data[bytes.len++] = (guint8)(value >> 16);
    case 2: data[bytes.len++] = (guint8)(value >> 8);
    case 1: data[bytes.len++] = (guint8)(value);
    }
    return foil_asn1_encode_integer_bytes(out, &bytes);
}

GBytes*
foil_asn1_encode_integer_value(
    gint32 value)
{
    FoilOutput* out = foil_output_mem_new(NULL);
    foil_asn1_encode_integer(out, value);
    return foil_output_free_to_bytes(out);
}

gsize
foil_asn1_encode_ia5_string(
    FoilOutput* out,
    const char* str)
{
    if (G_LIKELY(str)) {
        FoilBytes bytes;
        return foil_asn1_encode_block1(out, ASN1_TAG_IA5_STRING,
            foil_bytes_from_string(&bytes, str));
    }
    return 0;
}

GBytes*
foil_asn1_encode_ia5_string_bytes(
    const char* str)
{
    if (G_LIKELY(str)) {
        FoilOutput* out = foil_output_mem_new(NULL);
        foil_asn1_encode_ia5_string(out, str);
        return foil_output_free_to_bytes(out);
    }
    return NULL;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
