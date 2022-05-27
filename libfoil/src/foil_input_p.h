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

#ifndef FOIL_INPUT_P_H
#define FOIL_INPUT_P_H

#include "foil_types_p.h"
#include "foil_input.h"

typedef struct foil_input_func {
    gboolean (*fn_has_available)(FoilInput* in, gsize count);   /* optional */
    gssize (*fn_read)(FoilInput* in, void* buf, gsize size);
    void (*fn_close)(FoilInput* in);
    void (*fn_free)(FoilInput* in);
} FoilInputFunc;

struct foil_input {
    gint ref_count;
    gboolean closed;
    gsize bytes_read;
    guint peek_offset;
    GByteArray* peek_buf;
    const FoilInputFunc* fn;
};

FoilInput*
foil_input_init(
    FoilInput* in,
    const FoilInputFunc* fn)
    FOIL_INTERNAL;

void
foil_input_finalize(
    FoilInput* in)
    FOIL_INTERNAL;

void
foil_input_push_back(
    FoilInput* in,
    const void* buf,
    gsize size)
    FOIL_INTERNAL;

#endif /* FOIL_INPUT_P_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
