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

#include "test_common.h"

gboolean
test_bytes_equal(
    GBytes* bytes,
    const void* data,
    guint len)
{
    gsize size;
    const void* bytes_data = g_bytes_get_data(bytes, &size);
    return size == len && !memcmp(bytes_data, data, len);
}

gboolean
test_bytes_equal_str(
    GBytes* bytes,
    const char* str)
{
    return test_bytes_equal(bytes, str, strlen(str));
}

GBytes*
test_bytes_concat(
    GBytes* bytes1,
    GBytes* bytes2)
{
    guint8* data;
    guint8* ptr;
    gsize size = 0;
    if (bytes1) {
        size += g_bytes_get_size(bytes1);
    }
    if (bytes2) {
        size += g_bytes_get_size(bytes2);
    }
    ptr = data = g_malloc(size);
    if (bytes1) {
        const gsize nbytes = g_bytes_get_size(bytes1);
        memcpy(ptr, g_bytes_get_data(bytes1, NULL), nbytes);
        ptr += nbytes;
    }
    if (bytes2) {
        const gsize nbytes = g_bytes_get_size(bytes2);
        memcpy(ptr, g_bytes_get_data(bytes2, NULL), nbytes);
        ptr += nbytes;
    }
    return g_bytes_new_take(data, size);
}

int
test_run(
    void)
{
    /* g_type_init has been deprecated since version 2.36
     * the type system is initialised automagically since then */
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
    g_type_init();
    G_GNUC_END_IGNORE_DEPRECATIONS;
    gutil_log_timestamp = FALSE;
    gutil_log_default.level = g_test_verbose() ?
        GLOG_LEVEL_VERBOSE : GLOG_LEVEL_NONE;
    return g_test_run();
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
