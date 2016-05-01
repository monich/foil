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

#include "foil_input_p.h"
#include "foil_log_p.h"

#include <gutil_macros.h>

typedef struct foil_input_file {
    FoilInput parent;
    FILE* file;
    guint flags;
} FoilInputFile;

static
gssize
foil_input_file_read(
    FoilInput* in,
    void* buf,
    gsize size)
{
    FoilInputFile* self = G_CAST(in, FoilInputFile, parent);
    return fread(buf, 1, size, self->file);
}

static
void
foil_input_file_close(
    FoilInput* in)
{
    FoilInputFile* self = G_CAST(in, FoilInputFile, parent);
    if (self->flags & FOIL_INPUT_FILE_CLOSE) {
        fclose(self->file);
    }
    self->file = NULL;
}

static
void
foil_input_file_free(
    FoilInput* in)
{
    FoilInputFile* self = G_CAST(in, FoilInputFile, parent);
    GASSERT(!self->file);
    foil_input_finalize(in);
    g_slice_free(FoilInputFile, self);
}

FoilInput*
foil_input_file_new(
    FILE* file,
    guint flags)
{
    static const FoilInputFunc foil_input_file_fn = {
        NULL,                       /* fn_has_available */
        foil_input_file_read,       /* fn_read */
        foil_input_file_close,      /* fn_close */
        foil_input_file_free        /* fn_free */
    };
    if (file) {
        FoilInputFile* self = g_slice_new0(FoilInputFile);
        self->file = file;
        self->flags = flags;
        return foil_input_init(&self->parent, &foil_input_file_fn);
    }
    return NULL;
}

FoilInput*
foil_input_file_new_open(
    const char* path)
{
    if (path) {
        return foil_input_file_new(fopen(path, "rb"), TRUE);
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
