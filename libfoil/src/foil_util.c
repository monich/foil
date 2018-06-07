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

#include "foil_util_p.h"
#include "foil_input.h"
#include "foil_digest.h"
#include "foil_log_p.h"

#include <ctype.h>

/* Default log module */
GLOG_MODULE_DEFINE("foil");

GQuark foil_error_quark()
{
    return g_quark_from_static_string("foil-error-quark");
}

/**
 * N.B. The data length will not include the NULL terminator.
 */
const FoilBytes*
foil_bytes_from_string(
    FoilBytes* bytes,
    const char* str)
{
    if (bytes) {
        if (str) {
            bytes->val = (const void*)str;
            bytes->len = strlen(str);
        } else {
            bytes->val = NULL;
            bytes->len = 0;
        }
    }
    return bytes;
}

const FoilBytes*
foil_bytes_from_data(
    FoilBytes* bytes,
    GBytes* data)
{
    if (bytes) {
        if (data) {
            bytes->val = g_bytes_get_data(data, &bytes->len);
        } else {
            bytes->val = NULL;
            bytes->len = 0;
        }
    }
    return bytes;
}

gboolean
foil_bytes_equal(
    const FoilBytes* bytes1,
    const FoilBytes* bytes2)
{
    if (bytes1 == bytes2) {
        return TRUE;
    } else if (!bytes1 || !bytes2) {
        return FALSE;
    } else if (bytes1->len == bytes2->len) {
        return !memcmp(bytes1->val, bytes2->val, bytes1->len);
    } else {
        return FALSE;
    }
}

guint8*
foil_bytes_copy(
    FoilBytes* dest,
    const FoilBytes* src,
    guint8* ptr)
{
    if (src && src->val && src->len) {
        dest->val = ptr;
        dest->len = src->len;
        memcpy(ptr, src->val, src->len);
        return ptr + FOIL_ALIGN(dest->len);
    } else {
        dest->val = NULL;
        dest->len = 0;
        return ptr;
    }
}

void
foil_bytes_digest(
    FoilBytes* bytes,
    FoilDigest* digest)
{
    if (bytes && bytes->len) {
        guint8 len[4];
        guint32 tmp = bytes->len;
        len[0] = (guint8)(tmp >> 24);
        len[1] = (guint8)(tmp >> 16);
        len[2] = (guint8)(tmp >> 8);
        len[3] = (guint8)(tmp);
        foil_digest_update(digest, len, sizeof(len));
        foil_digest_update(digest, bytes->val, bytes->len);
    } else {
        guint32 zero = 0;
        foil_digest_update(digest, &zero, sizeof(zero));
    }
}

void*
foil_class_ref(
    GType type,
    GType base)
{
    if (G_LIKELY(type) && !G_TYPE_IS_ABSTRACT(type)) {
        GTypeClass* klass = g_type_class_ref(type);
        if (klass) {
            if (G_TYPE_CHECK_CLASS_TYPE(klass, base)) {
                return klass;
            }
            g_type_class_unref(klass);
        }
    }
    return NULL;
}

void*
foil_abstract_class_ref(
    GType type,
    GType base)
{
    if (G_LIKELY(type)) {
        GTypeClass* klass = g_type_class_ref(type);
        if (klass) {
            if (G_TYPE_CHECK_CLASS_TYPE(klass, base)) {
                return klass;
            }
            g_type_class_unref(klass);
        }
    }
    return NULL;
}

gsize
foil_parse_init_string(
    FoilParsePos* pos,
    const char* str)
{
    if (pos) {
        if (str) {
            gsize len = strlen(str);
            pos->ptr = (const guint8*)str;
            pos->end = pos->ptr + len;
            return len;
        } else {
            pos->ptr = pos->end = NULL;
        }
    }
    return 0;
}

void
foil_parse_skip_spaces(
    FoilParsePos* pos)
{
    while (pos->ptr < pos->end && isspace(pos->ptr[0])) {
        pos->ptr++;
    }
}

static
char
foil_parse_skip_to_next_line2(
    FoilParsePos* pos)
{
    char last = 0;
    while (pos->ptr < pos->end && *pos->ptr != '\r' && *pos->ptr != '\n') {
        last = *pos->ptr;
        pos->ptr++;
    }
    while (pos->ptr < pos->end && (*pos->ptr == '\r' || *pos->ptr == '\n')) {
        pos->ptr++;
    }
    return (pos->ptr < pos->end) ? last : 0;
}

gboolean
foil_parse_skip_to_next_line(
    FoilParsePos* pos,
    gboolean continued)
{
    char last = foil_parse_skip_to_next_line2(pos);
    if (continued) {
        while (last == '\\') {
            last = foil_parse_skip_to_next_line2(pos);
        }
    }
    return (pos->ptr < pos->end);
}

gboolean
foil_parse_skip_bytes(
    FoilParsePos* pos,
    const FoilBytes* bytes)
{
    if (pos->end >= pos->ptr + bytes->len &&
        !memcmp(pos->ptr, bytes->val, bytes->len)) {
        pos->ptr += bytes->len;
        return TRUE;
    }
    return FALSE;
}

static
char
foil_parse_read_line2(
    FoilParsePos* pos,
    GString* buf,
    gboolean skip_spaces)
{
    char last = 0;
    while (pos->ptr < pos->end && *pos->ptr != '\r' && *pos->ptr != '\n') {
        last = *pos->ptr;
        if (!skip_spaces) {
            g_string_append_c(buf, last);
        } else if (!isspace(last)) {
            /* Don't skip spaces after the first non-space character */
            g_string_append_c(buf, last);
            skip_spaces = FALSE;
        }
        pos->ptr++;
    }
    while (pos->ptr < pos->end && (*pos->ptr == '\r' || *pos->ptr == '\n')) {
        pos->ptr++;
    }
    return (pos->ptr < pos->end) ? last : 0;
}

static
gsize
foil_parse_read_line(
    FoilParsePos* pos,
    GString* buf)
{
    char last;
    const guint8* prev = pos->ptr;
    g_string_set_size(buf, 0);
    last = foil_parse_read_line2(pos, buf, TRUE);
    while (last == '\\') {
        /* Drop the continuation character and read the next line */
        g_string_set_size(buf, buf->len - 1);
        last = foil_parse_read_line2(pos, buf, FALSE);
    }
    return pos->ptr - prev;
}

static
gsize
foil_parse_read_tag_line(
    FoilParsePos* pos,
    GString* buf)
{
    /* Skip empty lines */
    const guint8* start = pos->ptr;
    const char* delim;
    while (foil_parse_read_line(pos, buf) && !buf->len) {
        start = pos->ptr;
    }
    delim = strchr(buf->str, ':');
    if (delim && delim > buf->str) {
        return delim - buf->str;
    } else {
        /*
         * Zero would also be returned if the line started with : but that
         * would mean that the tag is missing, which in turn means that it's
         * not really a tag line (probably, garbage) so who cares.
         */
        pos->ptr = start;
        return 0;
    }
}

GHashTable*
foil_parse_headers(
    FoilParsePos* pos,
    GString* buf)
{
    GHashTable* headers = NULL;
    GString* tmp = NULL;
    gsize off;
    if (!buf) {
        buf = tmp = g_string_new(NULL);
    }
    while ((off = foil_parse_read_tag_line(pos, buf)) > 0) {
        char* tag = g_strndup(buf->str, off);
        char* value = buf->str + off + 1;
        while (*value && isspace(*value)) value++;
        value = g_strdup(value);
        if (!headers) {
            headers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                g_free);
        }
        g_hash_table_replace(headers, tag, value);
    }
    if (tmp) {
        g_string_free(tmp, TRUE);
    } else {
        g_string_set_size(buf, 0);
    }
    return headers;
}

/*
 * The tag is formatted according to RFC4716:
 *
 * 3.3.  Key File Header
 *
 * The key file header section consists of multiple RFC822-style header
 * fields.  Each field is a line of the following format:
 *
 * Header-tag ':' ' ' Header-value
 *
 * The Header-tag MUST NOT be more than 64 8-bit bytes and is case-
 * insensitive.  The Header-value MUST NOT be more than 1024 8-bit
 * bytes.  Each line in the header MUST NOT be more than 72 8-bit bytes.
 *
 * A line is continued if the last character in the line is a '\'.  If
 * the last character of a line is a '\', then the logical contents of
 * the line are formed by removing the '\' and the line termination
 * characters, and appending the contents of the next line.
 *
 * The Header-tag MUST be encoded in US-ASCII.  The Header-value MUST be
 * encoded in UTF-8 [RFC3629].
 */
char*
foil_format_header(
    const char* tag,
    const char* value)
{
    /*
     * The caller is supposed to make sure that the value is either empty
     * or is a UTF-8 string.
     */
    gsize tlen, vlen = 0;
    if (tag && tag[0] && (tlen = strlen(tag)) <= 64 &&
        (!value || (vlen = strlen(value)) <= 1024)) {
        GString* buf = g_string_new_len(tag, tlen);
        const char* line;
        gsize off;
        g_string_append(buf, ": ");
        if (vlen > 0) {
            g_string_append_len(buf, value, vlen);
        }
        line = buf->str;
        /* The header tag fits into the line length limit, skip it */
        off = tlen + 2;
        /* Split the line if necessary */
        while (off < buf->len) {
            /* This must succeed since UTF-8 was validated by the caller */
            const gchar* next = g_utf8_find_next_char(buf->str + off, NULL);
            if (next - line >= 72) {
                /* g_string_insert may reallocate the buffer */
                const gsize charsize = (next - buf->str) - off;
                const gsize lineoff = off + 2;
                g_string_insert(buf, off, "\\\n");
                line =  buf->str + lineoff;
                off = lineoff + charsize;
            } else {
                off = next - buf->str;
            }
        }
        return g_string_free(buf, FALSE);
    }
    return NULL;
}

GHashTable*
foil_param_add(
    GHashTable* params,
    const char* key,
    const char* value)
{
    if (value && g_utf8_validate(value, -1, NULL)) {
        if (!params) {
            params = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
                (GDestroyNotify)g_variant_unref);
        }
        g_hash_table_insert(params, (gpointer)key,
            g_variant_ref_sink(g_variant_new_string(value)));
    }
    return params;
}

GBytes*
foil_parse_base64(
    FoilParsePos* pos,
    guint flags)
{
    FoilInput* mem = foil_input_mem_new_static(pos->ptr, pos->end - pos->ptr);
    FoilInput* decoder = foil_input_base64_new_full(mem, flags);
    GBytes* decoded = foil_input_read_all(decoder);
    if (decoded) {
        pos->ptr += foil_input_bytes_read(mem);
        GASSERT(pos->ptr <= pos->end);
    }
    foil_input_unref(decoder);
    foil_input_unref(mem);
    return decoded;
}

const void*
foil_memmem(
    const void* haystack,
    gsize haystacklen,
    const void* needle,
    gsize needlelen)
{
    if (needlelen > 0 && haystacklen >= needlelen) {
        const guint8 c = *(guint8*)needle;
        if (needlelen == 1) {
            /* Trivial case */
            return memchr(haystack, c, haystacklen);
        } else {
            const guint8* ptr = haystack;
            const guint8* last = ptr + haystacklen - needlelen;
            for (; ptr <= last; ptr++) {
                if (*ptr == c && memcmp(ptr, needle, needlelen) == 0) {
                    return ptr;
                }
            }
        }
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
