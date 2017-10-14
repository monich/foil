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

#include "foil_output_p.h"

#include <gutil_macros.h>

#ifdef _WIN32
#  include <io.h>
#  include <direct.h>
#else
#  include <unistd.h>
#endif

/* Logging */
#define GLOG_MODULE_NAME foil_log_output
#include "foil_log_p.h"

typedef struct foil_output_file_map {
    GMappedFile* map;
    char* path;
    char* tmpdir;
} FoilOutputFileMap;

typedef struct foil_output_file {
    FoilOutput parent;
    FILE* file;
    guint flags;
} FoilOutputFile;

typedef struct foil_output_path {
    FoilOutputFile parent;
    char* path;
    char* tmpdir;
    gboolean delete_when_closed;
} FoilOutputPath;

static
void
foil_output_file_map_free(
    gpointer data)
{
    FoilOutputFileMap* fm = data;
    g_mapped_file_unref(fm->map);
    remove(fm->path);
    if (fm->tmpdir) {
        rmdir(fm->tmpdir);
    }
    g_free(fm->path);
    g_free(fm->tmpdir);
    g_slice_free(FoilOutputFileMap, fm);
}

static
void
foil_output_file_unref_mapped_file(
    gpointer data)
{
    g_mapped_file_unref(data);
}

static
gssize
foil_output_file_write(
    FoilOutput* out,
    const void* buf,
    gsize size)
{
    FoilOutputFile* self = G_CAST(out, FoilOutputFile, parent);
    /* self->file can be NULL if foil_output_path_reset() fails */
    return self->file ? fwrite(buf, 1, size, self->file) : -1;
}

static
gboolean
foil_output_file_flush(
    FoilOutput* out)
{
    FoilOutputFile* self = G_CAST(out, FoilOutputFile, parent);
    /* self->file can be NULL if foil_output_path_reset() fails */
    return self->file && fflush(self->file) == 0;
}

static
void
foil_output_file_close(
    FoilOutput* out)
{
    FoilOutputFile* self = G_CAST(out, FoilOutputFile, parent);
    /* self->file can be NULL if foil_output_path_reset() fails */
    if (self->file) {
        if (self->flags & FOIL_OUTPUT_FILE_CLOSE) {
            fclose(self->file);
        }
        self->file = NULL;
    }
}

static
void
foil_output_file_free(
    FoilOutput* out)
{
    FoilOutputFile* self = G_CAST(out, FoilOutputFile, parent);
    GASSERT(!self->file);
    g_slice_free(FoilOutputFile, self);
}

static
gboolean
foil_output_path_reset(
    FoilOutput* out)
{
    FoilOutputPath* self = G_CAST(out, FoilOutputPath, parent.parent);
    if (self->parent.file) {
        fclose(self->parent.file);
    }
    self->parent.file = fopen(self->path, "wb");
    return (self->parent.file != NULL);
}

static
GBytes*
foil_output_path_to_bytes(
    FoilOutput* out)
{
    FoilOutputPath* self = G_CAST(out, FoilOutputPath, parent.parent);
    GBytes* bytes = NULL;
    if (self->parent.file) {
        GMappedFile* map;
        GError* error = NULL;
        foil_output_file_close(out);
        map = g_mapped_file_new(self->path, FALSE, &error);
        if (map) {
            if (self->delete_when_closed) {
                /* Need to wait until GBytes are released */
                FoilOutputFileMap* fm = g_slice_new0(FoilOutputFileMap);
                fm->map = map;
                fm->path = self->path;
                fm->tmpdir = self->tmpdir;
                self->path = NULL;
                self->tmpdir = NULL;
                bytes = g_bytes_new_with_free_func(
                    g_mapped_file_get_contents(map),
                    g_mapped_file_get_length(map),
                    foil_output_file_map_free, fm);
            } else {
                bytes = g_bytes_new_with_free_func(
                    g_mapped_file_get_contents(map),
                    g_mapped_file_get_length(map),
                    foil_output_file_unref_mapped_file, map);
            }
        } else {
            GERR("%s", GERRMSG(error));
            g_error_free(error);
        }
    }
    return bytes;
}

static
void
foil_output_path_close(
    FoilOutput* out)
{
    FoilOutputPath* self = G_CAST(out, FoilOutputPath, parent.parent);
    foil_output_file_close(out);
    if (self->delete_when_closed) {
        remove(self->path);
    }
    if (self->tmpdir) {
        rmdir(self->tmpdir);
    }
}

static
void
foil_output_path_free(
    FoilOutput* out)
{
    FoilOutputPath* self = G_CAST(out, FoilOutputPath, parent);
    GASSERT(!self->parent.file);
    g_free(self->path);
    g_free(self->tmpdir);
    g_slice_free(FoilOutputPath, self);
}

/* Since 1.0.1 */
FoilOutput*
foil_output_file_new(
    FILE* file,
    guint flags)
{
    static const FoilOutputFunc foil_output_file_fn = {
        foil_output_file_write, /* fn_write */
        foil_output_file_flush, /* fn_flush */
        NULL,                   /* fn_reset */
        NULL,                   /* fn_to_bytes */
        foil_output_file_close, /* fn_close */
        foil_output_file_free   /* fn_free */
    };

    if (file) {
        FoilOutputFile* self = g_slice_new0(FoilOutputFile);
        self->file = file;
        self->flags = flags;
        return foil_output_init(&self->parent, &foil_output_file_fn);
    }
    return NULL;
}

static const FoilOutputFunc foil_output_path_fn = {
    foil_output_file_write,     /* fn_write */
    foil_output_file_flush,     /* fn_flush */
    foil_output_path_reset,     /* fn_reset */
    foil_output_path_to_bytes,  /* fn_to_bytes */
    foil_output_path_close,     /* fn_close */
    foil_output_path_free       /* fn_free */
};

FoilOutput*
foil_output_file_new_open(
    const char* path)
{
    if (path) {
        FILE* file = fopen(path, "wb");
        if (file) {
            FoilOutputPath* self = g_slice_new0(FoilOutputPath);
            FoilOutputFile* parent = &self->parent;
            self->path = g_strdup(path);
            parent->file = file;
            parent->flags = FOIL_OUTPUT_FILE_CLOSE;
            return foil_output_init(&parent->parent, &foil_output_path_fn);
        }
    }
    return NULL;
}

FoilOutput*
foil_output_file_new_tmp(void)
{
    char* tmpdir = g_dir_make_tmp("foil_XXXXXX", NULL);
    if (tmpdir) {
        char* path = g_build_filename(tmpdir, "tmp", NULL);
        FILE* file = fopen(path, "wb");
        if (file) {
            FoilOutputPath* self = g_slice_new0(FoilOutputPath);
            FoilOutputFile* parent = &self->parent;
            self->path = path;
            self->tmpdir = tmpdir;
            self->delete_when_closed = TRUE;
            parent->file = file;
            parent->flags = FOIL_OUTPUT_FILE_CLOSE;
            return foil_output_init(&parent->parent, &foil_output_path_fn);
        }
        g_free(path);
        g_free(tmpdir);
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
