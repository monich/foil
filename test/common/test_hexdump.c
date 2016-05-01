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

#include "test_common.h"

#include <ctype.h>

static
guint
test_hexdump_line(
    char* buf,
    const void* data,
    guint len)
{
    static const char hex[] = "0123456789abcdef";
    const guint bytes_to_print = MIN(len, 16);
    const guchar* bytes = data;
    char* ptr = buf;
    guint i;

    for (i=0; i<16; i++) {
        if (i > 0) {
            *ptr++ = ' ';
            if (i == 8) *ptr++ = ' ';
        }
        if (i < len) {
            const guchar b = bytes[i];
            *ptr++ = hex[(b >> 4) & 0xf];
            *ptr++ = hex[b & 0xf];
        } else {
            *ptr++ = ' ';
            *ptr++ = ' ';
        }
    }

    *ptr++ = ' ';
    *ptr++ = ' ';
    *ptr++ = ' ';
    *ptr++ = ' ';
    for (i=0; i<bytes_to_print; i++) {
        const char c = bytes[i];
        if (i == 8) *ptr++ = ' ';
        *ptr++ = isprint(c) ? c : '.';
    }

    *ptr++ = 0;
    return ptr - buf;
}

void
test_hexdump(
    const GLogModule* module,
    int level,
    const void* data,
    guint size)
{
    char buf[80];
    guint off = 0;
    const char* prefix = " ";
    while (off < size) {
        const guint len = MIN(size - off, 16);
        test_hexdump_line(buf, ((const guchar*)data) + off, len);
        gutil_log(module, level, "%s%04x: %s", prefix, off, buf);
        off += len;
    }
}

void
test_hexdump_bytes(
    const GLogModule* module,
    int level,
    GBytes* bytes)
{
    if (bytes) {
        gsize size = 0;
        const void* data = g_bytes_get_data(bytes, &size);
        test_hexdump(module, level, data, size);
    }
}

GBytes*
test_hex_to_bytes(
    const char* hex)
{
    if (hex) {
        GByteArray* out = g_byte_array_new();
        while (*hex) {
            if (isxdigit(hex[0]) && isxdigit(hex[1])) {
                const char a = *hex++;
                const char b = *hex++;
                guint8 byte;
                if (a >= 'a') {
                    byte = (a - 'a' + 10) << 4;
                } else if (a >= 'A') {
                    byte = (a - 'A' + 10) << 4;
                } else {
                    byte = (a - '0') << 4;
                }
                if (b >= 'a') {
                    byte |= (b - 'a' + 10);
                } else if (b >= 'A') {
                    byte |= (b - 'A' + 10);
                } else {
                    byte |= (b - '0');
                }
                if (*hex == ':') hex++;
                g_byte_array_append(out, &byte, 1);
            } else {
                g_byte_array_unref(out);
                return NULL;
            }
        }
        return g_byte_array_free_to_bytes(out);
    }
    return NULL;
}

char*
test_hex_bytes(
    GBytes* bytes,
    const char* sep)
{
    if (!sep) sep = "";
    if (bytes) {
        gsize i, size;
        const guint8* data = g_bytes_get_data(bytes, &size);
        GString* buf = g_string_sized_new(3*(size + strlen(sep)));
        if (size > 0) {
            g_string_append_printf(buf, "%02x", data[0]);
            for (i=1; i<size; i++) {
                g_string_append_printf(buf, "%s%02x", sep, data[i]);
            }
        }
        return g_string_free(buf, FALSE);
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
