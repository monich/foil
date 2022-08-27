/*
 * Copyright (C) 2016-2022 by Slava Monich
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

#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include "foil_types.h"

#include <gutil_log.h>
#include <gutil_macros.h>

#include <glib-object.h>

#define TEST_ARRAY_AND_SIZE(array) array, sizeof(array)
#define TEST_ARRAY_AND_COUNT(array) array, G_N_ELEMENTS(array)

int
test_run(
    void);

gboolean
test_bytes_equal(
    GBytes* bytes,
    const void* data,
    guint len);

gboolean
test_bytes_equal_str(
    GBytes* bytes,
    const char* str);

void
test_hexdump(
    const GLogModule* module,
    int level,
    const void* data,
    guint data_len);

void
test_hexdump_bytes(
    const GLogModule* module,
    int level,
    GBytes* bytes);

#define TEST_DEBUG_HEXDUMP_BYTES(bytes) \
    test_hexdump_bytes(GLOG_MODULE_CURRENT, GLOG_LEVEL_DEBUG, bytes)
#define TEST_DEBUG_HEXDUMP(bytes,len) \
    test_hexdump(GLOG_MODULE_CURRENT, GLOG_LEVEL_DEBUG, bytes, len)

GBytes*
test_hex_to_bytes(
    const char* hex);

char*
test_hex_bytes(
    GBytes* bytes,
    const char* sep);

FoilOutput*
test_output_mem_new(
    gssize maxsize,
    guint flags);

#define TEST_OUTPUT_FLUSH_FAILS_ONCE   (0x01)
#define TEST_OUTPUT_FLUSH_FAILS_ALWAYS (0x02)
#define TEST_OUTPUT_WRITE_FAILS        (0x04)

#endif /* TEST_COMMON_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
