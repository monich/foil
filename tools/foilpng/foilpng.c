/*
 * Copyright (C) 2017-2022 by Slava Monich
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

#include "foilmsg.h"

#include <foil_key.h>
#include <foil_input.h>
#include <foil_output.h>
#include <foil_random.h>
#include <foil_util.h>
#include <foil_private_key.h>
#include <gutil_log.h>

#ifdef HAVE_MAGIC
#  include <magic.h>
#endif

#include <png.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <setjmp.h>

#define DEFAULT_PRIV_KEY "/.ssh/id_rsa" /* Relative to $HOME */
#define FILENAME_HEADER "Filename"

#define RET_OK 0
#define RET_ERR 1
#define RET_CMDLINE 2

static
guint
foilpng_isqrt(
    guint val)
{
    guint bit = ((guint)1) << (sizeof(guint)*4 - 1);
    guint x = 0;
    do {
        guint x2;
        x ^= bit;
        x2 = x * x;
        if (x2 > val) {
            x ^= bit;
        } else if (x2 == val) {
            break;
        }
    } while (bit >>= 1);
    return x;
}

static
void
foilpng_pick_res(
    gsize len,
    guint* width,
    guint* height)
{
    /* Keep the width aligned at 32, height even and ratio close to 4:3 */
    const guint align = 32;
    const guint rx = 4;
    const guint ry = 3;
    const guint bpp = 3;  /* 3 bytes per pixel */
    guint h, w = foilpng_isqrt(rx*len/ry/bpp);
    w = align*((w+align-1)/align);
    if (!w) w = align;
    h = w/rx*ry;
    while (h > 0 && bpp*w*(h-1) > len) h--;
    while(bpp*w*h < len) h++;
    if (h & 1) h++;
    GDEBUG("Picked %ux%u resolution", (unsigned int)w, (unsigned int)h);
    *width = w;
    *height = h;
}

static
void
foilpng_error(
    png_structp png,
    png_const_charp msg)
{
    jmp_buf* jmp = png_get_error_ptr(png);
    GERR("%s", msg);
    longjmp(*jmp, 1);
}

static
void
foilpng_warning(
    png_structp png,
    png_const_charp msg)
{
    GWARN("%s", msg);
}

static
void
PNGAPI
foilpng_png_read(
    png_structp png,
    png_bytep bytes,
    png_size_t len)
{
    FoilInput* in = png_get_io_ptr(png);
    if (foil_input_read(in, bytes, len) != (gssize)len) {
        png_error(png, "Read error");
    }
}

static
void
PNGAPI
foilpng_png_write(
    png_structp png,
    png_bytep bytes,
    png_size_t len)
{
    FoilOutput* out = png_get_io_ptr(png);
    if (!foil_output_write_all(out, bytes, len)) {
        png_error(png, "Write error");
    }
}

static
void
PNGAPI
foilpng_png_flush(
    png_structp png)
{
    FoilOutput* out = png_get_io_ptr(png);
    if (!foil_output_flush(out)) {
        png_error(png, "Flush error");
    }
}

static
int
foilpng_save(
    const FoilBytes* bytes,
    FoilOutput* out)
{
    guint width, height;
    png_structp png;
    int ret = RET_ERR;
    jmp_buf jmp;
    foilpng_pick_res(bytes->len, &width, &height);
    png = png_create_write_struct(PNG_LIBPNG_VER_STRING, &jmp, foilpng_error,
        foilpng_warning);
    if (png) {
        png_infop info = png_create_info_struct(png);
        if (info) {
            const guint rowsize = width*3;
            guint8* row = g_malloc(rowsize);
            if (!setjmp(jmp)) {
                const guint8* ptr = bytes->val;
                guint y;
                png_set_write_fn(png, out,
                    foilpng_png_write,
                    foilpng_png_flush);
                /* Encrypted data is not getting compressed well, if at all.
                 * It's just a waste of CPU time and in some cases it even
                 * inflates the data. Let's turn it off. */
                png_set_compression_level(png, 0);
                png_set_filter(png, 0, PNG_FILTER_NONE);
                png_set_IHDR(png, info, width, height, 8,
                    PNG_COLOR_TYPE_RGB, PNG_INTERLACE_NONE,
                    PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_BASE);
                png_write_info(png, info);
                for (y=0; y<height; y++) {
                    const gsize written = rowsize * y;
                    if ((written + rowsize) > bytes->len) {
                        gsize copied = 0;
                        if (written < bytes->len) {
                            copied = bytes->len - written;
                            memcpy(row, ptr, copied);
                        }
                        foil_random(row + copied, rowsize - copied);
                        png_write_row(png, row);
                    } else {
                        png_write_row(png, (void*)ptr);
                        ptr += rowsize;
                    }
                }
                png_write_end(png, info);
                ret = RET_OK;
            }
            g_free(row);
        }
        png_destroy_write_struct(&png, &info);
    }
    return ret;
}

static
int
foilpng_encode(
    FoilKey* recipient,
    FoilPrivateKey* sender,
    GBytes* data,
    const char* type,
    const char* filename,
    const FoilMsgEncryptOptions* opts,
    FoilOutput* out)
{
    int ret = RET_ERR;
    FoilOutput* tmp = foil_output_file_new_tmp();
    if (tmp) {
        FoilBytes bytes;
        FoilOutput* tmp2 = foil_output_file_new_tmp();
        const FoilMsgHeaders* encode_headers = NULL;
        FoilMsgHeaders headers;
        FoilMsgHeader filename_header;
        char* tmpfilename = NULL;
        gsize len;

        if (filename) {
            /* Store the file name in the headers */
            GError* error = NULL;
            char* basename = g_path_get_basename(filename);
            tmpfilename = g_filename_to_utf8(basename, -1, NULL, NULL, &error);
            g_free(basename);
            if (tmpfilename) {
                filename_header.name = FILENAME_HEADER;
                filename_header.value = tmpfilename;
                headers.header = &filename_header;
                headers.count = 1;
                encode_headers = &headers;
            } else {
                GERR("Can't convert file name to UTF-8: %s", GERRMSG(error));
                g_error_free(error);
            }
        }

        len = foilmsg_encrypt(tmp, foil_bytes_from_data(&bytes, data),
            type, encode_headers, sender, recipient, opts, tmp2);
        foil_output_unref(tmp2);
        if (len) {
            GBytes* enc = foil_output_free_to_bytes(tmp);
            if (enc) {
                GDEBUG("Encoded %u bytes", (unsigned int)len);
                ret = foilpng_save(foil_bytes_from_data(&bytes, enc), out);
                g_bytes_unref(enc);
            }
        } else {
            foil_output_unref(tmp);
        }
        g_free(tmpfilename);
    }
    return ret;
}

static
GBytes*
foilpng_extract(
    GBytes* data)
{
    jmp_buf jmp;
    GBytes* result = NULL;
    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, &jmp,
        foilpng_error, foilpng_warning);
    if (png) {
        png_infop info = png_create_info_struct(png);
        if (info) {
            FoilInput* in = foil_input_mem_new(data);
            FoilOutput* out = foil_output_file_new_tmp();
            if (!setjmp(jmp)) {
                png_uint_32 width, height;
                int bit_depth, color_type, interlace_type, filter_method;
                png_set_read_fn(png, in, foilpng_png_read);
                png_read_info(png, info);
                png_get_IHDR(png, info, &width, &height, &bit_depth,
                    &color_type, &interlace_type, NULL, &filter_method);
                if (bit_depth == 8 && color_type == PNG_COLOR_TYPE_RGB &&
                    interlace_type == PNG_INTERLACE_NONE &&
                    filter_method == PNG_FILTER_TYPE_BASE) {
                    guint rowsize = png_get_rowbytes(png, info);
                    png_bytep rows[1];
                    png_bytep row = png_malloc(png, rowsize);
                    guint y;
                    rows[0] = row;
                    for (y=0; y<height; y++) {
                        png_read_rows(png, rows, NULL, 1);
                        if (!foil_output_write_all(out, row, rowsize)) {
                            png_error(png, "Write error");
                        }
                    }
                    foil_output_ref(out);
                    result = foil_output_free_to_bytes(out);
                }
                png_read_end(png, info);
            }
            foil_input_unref(in);
            foil_output_unref(out);
        }
        png_destroy_read_struct(&png, &info, NULL);
    }
    return result;
}

static
int
foilpng_decode(
    FoilKey* sender,
    FoilPrivateKey* recipient,
    GBytes* data,
    FoilOutput* out)
{
    int ret = RET_ERR;
    GBytes* enc = foilpng_extract(data);
    if (enc) {
        FoilBytes bytes;
        FoilMsg* msg;
        GDEBUG("Extracted %lu bytes", (gulong)g_bytes_get_size(enc));
        msg = foilmsg_decrypt(recipient, foil_bytes_from_data(&bytes, enc),
            out);
        if (msg) {
            guint i;
            ret = RET_OK;
            /* If FoilOutput is pointing to stdout, msg->data is NULL.
             * FoilOutput however is never NULL, caller checks that. */
            GDEBUG("Decoded %lu bytes", (gulong)foil_output_bytes_written(out));
            GDEBUG("Type: %s", msg->content_type);
            for (i=0; i<msg->headers.count; i++) {
                const FoilMsgHeader* header = msg->headers.header + i;
                GDEBUG("%s: %s", header->name, header->value);
            }
            if (sender) {
                if (foilmsg_verify(msg, sender)) {
                    GDEBUG("Signature verified");
                    ret = RET_OK;
                } else {
                    GERR("Signature verification failed");
                }
            } else {
                GINFO("[UNVERIFIED]");
                ret = RET_OK;
            }
            foilmsg_free(msg);
        }
        g_bytes_unref(enc);
    }
    return ret;
}

static
GString*
foilpng_bytes_to_hex(
    GBytes* bytes)
{
    gsize len = 0;
    const guint8* data = g_bytes_get_data(bytes, &len);
    GString* buf = g_string_sized_new(len ? (len*3 - 1) : 0);
    if (len > 0) {
        guint i;
        g_string_append_printf(buf, "%02x", data[0]);
        for (i=1; i<len; i++) {
            g_string_append_printf(buf, ":%02x", data[i]);
        }
    }
    return buf;
}

int
main(
    int argc,
    char* argv[])
{
    int ret = RET_ERR;
    gboolean ok;
    gboolean verbose = FALSE;
    gboolean decrypt = FALSE;
    gboolean for_self = FALSE;
#ifdef FOIL_VERSION_STRING
    gboolean print_version = FALSE;
#endif
    GError* error = NULL;
    char* type = NULL;
    char* pass = NULL;
    char* priv_key = NULL;
    char* pub_key = NULL;
    char* digest = NULL;
    int key_size = 128;
    GOptionContext* options;
    GOptionGroup* encrypt_group;
    GOptionEntry entries[] = {
        { "decrypt", 'd', 0, G_OPTION_ARG_NONE, &decrypt,
          "Decrypt the data", NULL },
        { "secret", 's', 0, G_OPTION_ARG_FILENAME, &priv_key,
          "Your private key [~" DEFAULT_PRIV_KEY "]", "FILE" },
        { "pass", 'P', 0, G_OPTION_ARG_STRING, &pass,
          "Passphrase to decrypt your private key", "PASS" },
        { "public", 'p', 0, G_OPTION_ARG_FILENAME, &pub_key,
          "Public key of the other party", "FILE" },
        { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose,
          "Enable verbose output", NULL },
#ifdef FOIL_VERSION_STRING
        { "version", 0, 0, G_OPTION_ARG_NONE, &print_version,
          "Print version and exit", NULL },
#endif
        { NULL }
    };
    GOptionEntry encrypt_entries[] = {
        { "type", 't', 0, G_OPTION_ARG_STRING, &type,
          "Content type", "TYPE" },
        { "bits", 'b', 0, G_OPTION_ARG_INT, &key_size,
          "Encryption key size (128, 192 or 256) [128]", "BITS" },
        { "self", 'S', 0, G_OPTION_ARG_NONE, &for_self,
          "Encrypt to self and the recipient", NULL },
        { "digest", 'D', 0, G_OPTION_ARG_STRING, &digest,
          "Signature digest (MD5, SHA1, SHA256 or SHA512) [MD5]", "DIGEST" },
        { NULL }
    };
    const char* summary =
        "This tool uses PNG file as a container for encrypted data.\n"
        "\n"
        "When you encrypt the data (default action), the output is a PNG\n"
        "file. When you decrypt it back with -d, the input is a PNG file\n"
        "produced by this tool and the output is the original file.\n"
        "\n"
        "Recipent's public key is required for encryption. You can decrypt\n"
        "the message without recipent's public key but in this case it's\n"
        "impossible to validate the signature and ensure that the message\n"
        "hasn't been modified in transit";

    /* g_type_init has been deprecated since version 2.36
     * the type system is initialised automagically since then */
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
    g_type_init();
    G_GNUC_END_IGNORE_DEPRECATIONS;

    options = g_option_context_new("IN OUT");
    encrypt_group = g_option_group_new("encrypt", "Encryption Options:",
        "Show encryption options", NULL, NULL);
    g_option_context_add_main_entries(options, entries, NULL);
    g_option_group_add_entries(encrypt_group, encrypt_entries);
    g_option_context_add_group(options, encrypt_group);
    g_option_context_set_summary(options, summary);
    ok = g_option_context_parse(options, &argc, &argv, &error);

    /* Set up logging */
    gutil_log_timestamp = FALSE;
    gutil_log_func = gutil_log_stderr;
    gutil_log_default.name = "foilpng";
    if (verbose) {
        gutil_log_default.level = GLOG_LEVEL_VERBOSE;
    }

    /* Private key is required */
    if (ok && !priv_key) {
        priv_key = g_strconcat(getenv("HOME"), DEFAULT_PRIV_KEY, NULL);
        if (priv_key && !g_file_test(priv_key, G_FILE_TEST_EXISTS)) {
            g_free(priv_key);
            priv_key = NULL;
        }
    }

    if (ok && key_size != 128 && key_size != 192 && key_size != 256) {
        GERR("Invalid key size, should be 128, 192 or 256");
        ok = FALSE;
    }

#ifdef FOIL_VERSION_STRING
    if (ok && print_version) {
        printf("%s %s\n", gutil_log_default.name, FOIL_VERSION_STRING);
        ret = RET_OK;
    } else
#endif
    if (ok && priv_key && argc == 3) {
        FoilKey* pub = NULL;
        FoilPrivateKey* priv;
        const char* pub_pad = "";

        /* Load the keys */
        priv = foil_private_key_decrypt_from_file(FOIL_KEY_RSA_PRIVATE,
            priv_key, pass, &error);
        if (priv) {
            if (GLOG_ENABLED(GLOG_LEVEL_DEBUG)) {
                GBytes* fp = foil_private_key_fingerprint(priv);
                GString* buf = foilpng_bytes_to_hex(fp);
                GDEBUG("Private key fingerprint: %s", buf->str);
                g_string_free(buf, TRUE);
                pub_pad = " "; /* Align output for public and private keys */
            }
        } else {
            if (error->domain == FOIL_ERROR) {
                switch (error->code) {
                case FOIL_ERROR_KEY_ENCRYPTED:
                    GERR("Private key %s is encrypted (use -P option to "
                        "supply the password)", priv_key);
                    break;
                case FOIL_ERROR_KEY_DECRYPTION_FAILED:
                    GERR("Invalid password for %s", priv_key);
                    break;
                default:
                    GERR("Failed to load private key from %s (%s)", priv_key,
                        GERRMSG(error));
                    break;
                }
            } else {
                GERR("Failed to load private key from %s (%s)", priv_key,
                    GERRMSG(error));
            }
            g_error_free(error);
            error = NULL;
        }

        if (pub_key) {
            pub = foil_key_new_from_file(FOIL_KEY_RSA_PUBLIC, pub_key);
            if (pub) {
                if (GLOG_ENABLED(GLOG_LEVEL_DEBUG)) {
                    GBytes* fp = foil_key_fingerprint(pub);
                    GString* buf = foilpng_bytes_to_hex(fp);
                    GDEBUG("Public key fingerprint: %s%s", pub_pad, buf->str);
                    g_string_free(buf, TRUE);
                }
            } else {
                GERR("Failed to load public key from %s", pub_key);
            }
        }

        /* Encrypt or decrypt something */
        if (priv && (pub || !pub_key)) {
            const char* in_file = argv[1];
            const char* out_file = argv[2];
            GBytes* in = NULL;

#ifdef HAVE_MAGIC
            magic_t magic = (magic_t)0;
            if (!decrypt) {
                /* Use magic to determine mime type */
                magic = magic_open(MAGIC_MIME_TYPE);
                if (magic && magic_load(magic, NULL)) {
                    magic_close(magic);
                    magic = (magic_t)0;
                }
            }
#endif /* HAVE_MAGIC */

            /* Open the input data */
            if (!in_file[0]) in_file = "-";
            if (in_file && strcmp(in_file, "-")) {
                GError* error = NULL;
                GMappedFile* map = g_mapped_file_new(in_file, FALSE, &error);
                if (map) {
                    /* g_mapped_file_get_bytes() appeared in glib 2.34 */
                    void* contents = g_mapped_file_get_contents(map);
                    gsize size = g_mapped_file_get_length(map);
                    in = g_bytes_new_with_free_func(contents, size,
                        (GDestroyNotify)g_mapped_file_unref, map);
                    GDEBUG("Reading %s", in_file);
#ifdef HAVE_MAGIC
                    if (magic) {
                        /* Use magic to determine the content type */
                        const char* detected = magic_file(magic, in_file);
                        if (detected) {
                            GDEBUG("Detected %s", detected);
                            type = g_strdup(detected);
                        }
                    }
#endif /* HAVE_MAGIC */
                } else {
                    GERR("Failed to open input file %s: %s", in_file,
                        GERRMSG(error));
                    g_error_free(error);
                    error = NULL;
                }
            } else {
                /* Read the standard input into a temporary file */
                FoilInput* input = foil_input_file_new(stdin, 0);
                FoilOutput* tmp = foil_output_file_new_tmp();
                if (foil_input_copy_all(input, tmp, NULL)) {
                    in = foil_output_free_to_bytes(tmp);
                    /* This tells foilpng_encode that we have no file name */
                    in_file = NULL;
                } else {
                    GERR("Failed to read standard input");
                    foil_output_unref(tmp);
                }
#ifdef HAVE_MAGIC
                if (in && magic) {
                    /* Use magic to determine the content type */
                    gsize size = 0;
                    const void* data = g_bytes_get_data(in, &size);
                    const char* detected = magic_buffer(magic, data, size);
                    if (detected) {
                        GDEBUG("Detected %s", detected);
                        type = g_strdup(detected);
                    }
                }
#endif /* HAVE_MAGIC */
            }
            if (in) {
                FoilOutput* out;
                if (out_file && strcmp(out_file, "-")) {
                    out = foil_output_file_new_open(out_file);
                    if (out) {
                        GDEBUG("Writing %s", out_file);
                    } else {
                        GERR("Failed to open output file %s: %s", out_file,
                            strerror(errno));
                    }
                } else {
                    out = foil_output_file_new(stdout, 0);
                }
                if (out) {
                    if (decrypt) {
                        ret = foilpng_decode(pub, priv, in, out);
                    } else {
                        FoilMsgEncryptOptions opt;

                        /* Without a public key, encrypt to self */
                        foilmsg_encrypt_defaults(&opt);
                        if (for_self || !pub) {
                            opt.flags |= FOILMSG_FLAG_ENCRYPT_FOR_SELF;
                        }
                        switch (key_size) {
                        default:  opt.key_type = FOILMSG_KEY_AES_128; break;
                        case 192: opt.key_type = FOILMSG_KEY_AES_192; break;
                        case 256: opt.key_type = FOILMSG_KEY_AES_256; break;
                        }
                        if (digest) {
                            if (!g_ascii_strcasecmp(digest, "MD5") ||
                                !g_ascii_strcasecmp(digest, "MD-5")) {
                                opt.signature = FOILMSG_SIGNATURE_MD5_RSA;
                            } else if (!g_ascii_strcasecmp(digest, "SHA1") ||
                                !g_ascii_strcasecmp(digest, "SHA-1")) {
                                opt.signature = FOILMSG_SIGNATURE_SHA1_RSA;
                            } else if (!g_ascii_strcasecmp(digest, "SHA256") ||
                                !g_ascii_strcasecmp(digest, "SHA-256")) {
                                opt.signature = FOILMSG_SIGNATURE_SHA256_RSA;
                            } else if (!g_ascii_strcasecmp(digest, "SHA512") ||
                                !g_ascii_strcasecmp(digest, "SHA-512")) {
                                opt.signature = FOILMSG_SIGNATURE_SHA512_RSA;
                            } else {
                                GWARN("Invalid signature digest \"%s\", using "
                                    "the default one (MD5)", digest);
                            }
                        }
                        ret = foilpng_encode(pub, priv, in, type, in_file,
                            &opt, out);
                    }
                    foil_output_close(out);
                    foil_output_unref(out);
                }
                g_bytes_unref(in);
            }
#ifdef HAVE_MAGIC
            if (magic) {
                magic_close(magic);
            }
#endif /* HAVE_MAGIC */
        }

        foil_key_unref(pub);
        foil_private_key_unref(priv);
    } else {
        if (error) {
            fprintf(stderr, "%s\n", GERRMSG(error));
            g_error_free(error);
        } else {
            char* help = g_option_context_get_help(options, TRUE, NULL);
            fprintf(stderr, "%s", help);
            g_free(help);
        }
        ret = RET_CMDLINE;
    }
    g_option_context_free(options);
    g_free(priv_key);
    g_free(pub_key);
    g_free(pass);
    g_free(type);
    g_free(digest);
    return ret;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
