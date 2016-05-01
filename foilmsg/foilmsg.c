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

#include "foilmsg.h"

#include <foil_key.h>
#include <foil_input.h>
#include <foil_util.h>
#include <foil_private_key.h>
#include <gutil_log.h>

#include <stdlib.h>
#include <stdio.h>

#define RET_OK 0
#define RET_ERR 1
#define RET_CMDLINE 2

static
int
foilmsg_encode(
    FoilKey* recipient,
    FoilPrivateKey* sender,
    const char* text,
    int cols,
    const FoilMsgEncryptOptions* opts)
{
    GString* enc = foilmsg_encrypt_text(text, sender, recipient, cols, opts);
    if (enc) {
        printf("%s", enc->str);
        g_string_free(enc, TRUE);
        return RET_OK;
    }
    return RET_ERR;
}

static
int
foilmsg_decode(
    FoilKey* sender,
    FoilPrivateKey* recipient,
    const FoilBytes* bytes)
{
    FoilMsg* msg = foilmsg_decrypt_text_bytes(recipient, bytes);
    if (!msg) {
        msg = foilmsg_decrypt(recipient, bytes, NULL);
    }
    if (msg) {
        gsize len;
        const void* data = g_bytes_get_data(msg->data, &len);
        GString* text = g_string_new_len(data, len);
        if (sender) {
            if (foilmsg_verify(msg, sender)) {
                printf("%s", text->str);
                g_string_free(text, TRUE);
                return RET_OK;
            } else {
                GERR("Signature verification failed");
            }
        } else {
            printf("[UNVERIFIED] %s", text->str);
            g_string_free(text, TRUE);
            return RET_OK;
        }
        g_string_free(text, TRUE);
    }
    return RET_ERR;
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
    GError* error = NULL;
    char* priv_key = NULL;
    char* pub_key = NULL;
    char* enc_file = NULL;
    char* in_file = NULL;
    int key_size = 128;
    int columns = 64;
    GOptionContext* options;
    GOptionEntry entries[] = {
        { "decrypt", 'd', 0, G_OPTION_ARG_NONE, &decrypt,
          "Decrypt the data", NULL },
        { "secret", 's', 0, G_OPTION_ARG_FILENAME, &priv_key,
          "Your private key", "FILE" },
        { "public", 'p', 0, G_OPTION_ARG_FILENAME, &pub_key,
          "Public key of the other party", "FILE" },
        { "bits", 'b', 0, G_OPTION_ARG_INT, &key_size,
          "Encryption key size (128, 192 or 256) [128]", "BITS" },
        { "input", 'i', 0, G_OPTION_ARG_FILENAME, &in_file,
          "Read input from FILE", "FILE" },
        { "columns", 'c', 0, G_OPTION_ARG_INT, &columns,
          "Wrap lines at the specified column [64]", "COLS" },
        { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose,
          "Enable verbose output", NULL },
        { NULL }
    };
    const char* summary =
        "By default, encrypts the data coming from stdin. Use -d option to\n"
        "decrypt the data.\n\n"
        "Recipent's public key is required for encryption. You can decrypt\n"
        "the message without recipent's public key but in this case it's\n"
        "impossible to validate the signature and ensure that the message\n"
        "hasn't been modified in transit";

    /* g_type_init has been deprecated since version 2.36
     * the type system is initialised automagically since then */
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
    g_type_init();
    G_GNUC_END_IGNORE_DEPRECATIONS;

    options = g_option_context_new("- encrypt or decrypt text messages");
    g_option_context_add_main_entries(options, entries, NULL);
    g_option_context_set_summary(options, summary);
    ok = g_option_context_parse(options, &argc, &argv, &error);

    /* Use ~/.ssh/id_rsa as the default private key */
    if (ok && !priv_key) {
        priv_key = g_strconcat(getenv("HOME"), "/.ssh/id_rsa", NULL);
        if (priv_key && !g_file_test(priv_key, G_FILE_TEST_EXISTS)) {
            g_free(priv_key);
            priv_key = NULL;
        }
    }

    if (ok && key_size != 128 && key_size != 192 && key_size != 256) {
        GERR("Invalid key size, should be 128, 192 or 256");
        ok = FALSE;
    }

    if (ok && priv_key) {
        FoilKey* pub = NULL;
        FoilPrivateKey* priv;

        /* Set up logging */
        gutil_log_timestamp = FALSE;
        gutil_log_func = gutil_log_stderr;
        gutil_log_default.name = "foilmsg";
        if (verbose) {
            gutil_log_default.level = GLOG_LEVEL_VERBOSE;
        }

        /* Load the keys */
        if (pub_key) {
            pub = foil_key_new_from_file(FOIL_KEY_RSA_PUBLIC, pub_key);
            if (!pub) {
                GERR("Failed to load public key from %s", pub_key);
            }
        }

        priv = foil_private_key_new_from_file(FOIL_KEY_RSA_PRIVATE, priv_key);
        if (!priv) {
            GERR("Failed to load private key from %s", priv_key);
        }

        /* Encrypt or decrypt something */
        if (priv && (pub || !pub_key)) {

            /* Read the input data */
            GBytes* in = NULL;
            if (in_file) {
                GError* error = NULL;
                GMappedFile* map = g_mapped_file_new(in_file, FALSE, &error);
                if (map) {
                    /* g_mapped_file_get_bytes() appeared in glib 2.34 */
                    void* contents = g_mapped_file_get_contents(map);
                    gsize size = g_mapped_file_get_length(map);
                    in = g_bytes_new_with_free_func(contents, size,
                        (GDestroyNotify)g_mapped_file_unref, map);
                } else {
                    GERR("Failed to read %s: %s", in_file, GERRMSG(error));
                    g_error_free(error);
                }
            } else {
                FoilInput* input = foil_input_file_new(stdin, FALSE);
                in = foil_input_read_all(input);
                foil_input_unref(input);
            }
            if (in) {
                FoilBytes bytes;
                foil_bytes_from_data(&bytes, in);
                if (decrypt) {
                    ret = foilmsg_decode(pub, priv, &bytes);
                } else if (g_utf8_validate((void*)bytes.val, bytes.len, 0)) {
                    /* NULL terminate the text */
                    FoilMsgEncryptOptions opt;
                    char* text = g_malloc(bytes.len + 1);
                    memcpy(text, bytes.val, bytes.len);
                    text[bytes.len] = 0;
                    memset(&opt, 0, sizeof(opt));
                    opt.flags |= FOILMSG_FLAG_ENCRYPT_FOR_SELF;
                    switch (key_size) {
                    default:  opt.key_type = FOILMSG_KEY_AES_128; break;
                    case 192: opt.key_type = FOILMSG_KEY_AES_192; break;
                    case 256: opt.key_type = FOILMSG_KEY_AES_256; break;
                    }
                    ret = foilmsg_encode(pub, priv, text, columns, &opt);
                    g_free(text);
                } else {
                    GERR("The input doesn't seem to be valid UTF-8");
                    ret = RET_ERR;
                }
                g_bytes_unref(in);
            }
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
    g_free(enc_file);
    return ret;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
