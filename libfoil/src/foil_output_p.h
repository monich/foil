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

#ifndef FOIL_OUTPUT_P_H
#define FOIL_OUTPUT_P_H

#include "foil_output.h"

typedef struct foil_output_func {
    gssize (*fn_write)(FoilOutput* out, const void* buf, gsize size);
    gboolean (*fn_flush)(FoilOutput* out);
    gboolean (*fn_reset)(FoilOutput* out);
    GBytes* (*fn_to_bytes)(FoilOutput* out);
    void (*fn_close)(FoilOutput* out);
    void (*fn_free)(FoilOutput* out);
} FoilOutputFunc;

struct foil_output {
    gint ref_count;
    gboolean closed;
    gsize bytes_written;
    const FoilOutputFunc* fn;
};

FoilOutput*
foil_output_init(
    FoilOutput* out,
    const FoilOutputFunc* fn);

#endif /* FOIL_OUTPUT_P_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
