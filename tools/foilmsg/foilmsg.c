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
const char*
foilmsg_info_fingerprint_format_name(
    int tag)
{
    switch (tag) {
    case FOILMSG_FINGERPRINT_SSH_RSA:
        return " (rsa-ssh)";
    default:
        return "";
    }
}

static
const char*
foilmsg_info_key_format_name(
    int tag)
{
    switch (tag) {
    case FOILMSG_ENCRYPT_KEY_FORMAT_AES128:
        return " (AES-128)";
    case FOILMSG_ENCRYPT_KEY_FORMAT_AES192:
        return " (AES-192)";
    case FOILMSG_ENCRYPT_KEY_FORMAT_AES256:
        return " (AES-256)";
    default:
        return "";
    }
}

static
const char*
foilmsg_info_signature_format_name(
    int tag)
{
    switch (tag) {
    case FOILMSG_SIGNATURE_FORMAT_MD5_RSA:
        return " (MD5-RSA)";
    default:
        return "";
    }
}

static
const char*
foilmsg_info_cipher_name(
    int tag)
{
    switch (tag) {
    case FOILMSG_ENCRYPT_FORMAT_AES_CBC:
        return " (AES-CBC)";
    default:
        return "";
    }
}

static
void
foilmsg_info_dump_data(
    const char* prefix,
    const char* name,
    const FoilBytes* data)
{
    printf("%s%s: %lu bytes\n", prefix, name, (unsigned long)data->len);
    if (data->len > 0 && GLOG_ENABLED(GLOG_LEVEL_DEBUG)) {
        const char* prefix2 = "  ";
        const gsize prefix_len = strlen(prefix) + strlen(prefix2);
        const gsize line = 16;
        const gsize block = line/2;
        gsize pos;
        GString* buf = g_string_new(NULL);
        g_string_append(buf, prefix);
        g_string_append(buf, prefix2);
        for (pos = 0; pos < data->len; pos++) {
            if (pos > 0 && !(pos % line)) {
                /* Beginning of the line (except for the first one) */
                printf("%s\n", buf->str);
                g_string_set_size(buf,prefix_len );
            }
            if ((pos % line) > 0) {
                g_string_append_c(buf, ' ');
                if (!(pos % block)) {
                    g_string_append_c(buf, ' ');
                }
            }
            g_string_append_printf(buf, "%02x", data->val[pos]);
        }
        if (buf->len > 0) {
            /* Print the remaining part */
            printf("%s\n", buf->str);
        }
        g_string_free(buf, TRUE);
    }
}

static
int
foilmsg_info(
    const FoilBytes* bytes)
{
    int ret;
    GBytes* converted = NULL;
    FoilMsgInfo* msg = foilmsg_parse(bytes);
    if (!msg) {
        GDEBUG("Trying to convert to binary form...");
        converted = foilmsg_to_binary(bytes);
        if (converted) {
            FoilBytes binary;
            msg = foilmsg_parse(foil_bytes_from_data(&binary, converted));
        }
    }
    if (msg) {
        printf("Format: %d\n", msg->format);
        printf("Sender fingerprint:\n");
        printf("  Format: %d%s\n", msg->sender_fingerprint.tag,
            foilmsg_info_fingerprint_format_name(msg->sender_fingerprint.tag));
        foilmsg_info_dump_data("  ", "Data", &msg->sender_fingerprint.data);
        printf("Key format: %d%s\n", msg->encrypt_key_format,
            foilmsg_info_key_format_name(msg->encrypt_key_format));
        if (msg->num_encrypt_keys) {
            int i;
            printf("Keys:\n");
            for (i=0; i<msg->num_encrypt_keys; i++) {
                const FoilMsgEncryptKey* key = msg->encrypt_keys + i;
                const FoilMsgTaggedData* fp = &key->fingerprint;
                const char* fp_prefix = "       ";
                printf("%3d. Fingerprint:\n", i+1);
                printf("%sFormat: %d%s\n", fp_prefix, fp->tag,
                    foilmsg_info_fingerprint_format_name(fp->tag));
                foilmsg_info_dump_data(fp_prefix, "Data", &fp->data);
                foilmsg_info_dump_data("     ", "Encryption key", &key->data);
            }
        } else {
            printf("Keys: (none)\n");
        }
        printf("Encrypted data:\n");
        printf("  Cipher: %d%s\n", msg->encrypted.tag,
            foilmsg_info_cipher_name(msg->encrypted.tag));
        foilmsg_info_dump_data("  ", "Data", &msg->encrypted.data);
        printf("Signature:\n");
        printf("  Format: %d%s\n", msg->signature.tag,
            foilmsg_info_signature_format_name(msg->signature.tag));
        foilmsg_info_dump_data("  ", "Data", &msg->signature.data);
        foilmsg_info_free(msg);
        ret = RET_OK;
    } else {
        GERR("Failed to parse the message");
        ret = RET_ERR;
    }
    if (converted) {
        g_bytes_unref(converted);
    }
    return ret;
}

static
GString*
foilmsg_bytes_to_hex(
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
        /* Make sure that the last line is terminated */
        if (enc->len > 0 && enc->str[enc->len-1] != '\n') {
            g_string_append_c(enc, '\n');
        }
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
    gboolean show_info = FALSE;
    gboolean for_self = FALSE;
    GError* error = NULL;
    char* priv_key = NULL;
    char* pub_key = NULL;
    char* enc_file = NULL;
    char* in_file = NULL;
    int key_size = 128;
    int columns = 64;
    GOptionContext* options;
    GOptionGroup* encrypt_group;
    GOptionGroup* decrypt_group;
    GOptionEntry entries[] = {
        { "decrypt", 'd', 0, G_OPTION_ARG_NONE, &decrypt,
          "Decrypt the data", NULL },
        { "secret", 's', 0, G_OPTION_ARG_FILENAME, &priv_key,
          "Your private key [~/.ssh/id_rsa]", "FILE" },
        { "public", 'p', 0, G_OPTION_ARG_FILENAME, &pub_key,
          "Public key of the other party", "FILE" },
        { "file", 'f', 0, G_OPTION_ARG_FILENAME, &in_file,
          "Read input from FILE", "FILE" },
        { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose,
          "Enable verbose output", NULL },
        { NULL }
    };
    GOptionEntry encrypt_entries[] = {
        { "bits", 'b', 0, G_OPTION_ARG_INT, &key_size,
          "Encryption key size (128, 192 or 256) [128]", "BITS" },
        { "columns", 'c', 0, G_OPTION_ARG_INT, &columns,
          "Wrap lines at the specified column [64]", "COLS" },
        { "self", 'S', 0, G_OPTION_ARG_NONE, &for_self,
          "Encrypt to self and the recipient", NULL },
        { NULL }
    };
    GOptionEntry decrypt_entries[] = {
        { "info", 'i', 0, G_OPTION_ARG_NONE, &show_info,
          "Show information about the encrypted message", NULL },
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
    encrypt_group = g_option_group_new("encrypt", "Encryption Options:",
        "Show encryption options", NULL, NULL);
    decrypt_group = g_option_group_new("decrypt", "Decryption Options:",
        "Show decryption options", NULL, NULL);
    g_option_context_add_main_entries(options, entries, NULL);
    g_option_group_add_entries(encrypt_group, encrypt_entries);
    g_option_group_add_entries(decrypt_group, decrypt_entries);
    g_option_context_add_group(options, encrypt_group);
    g_option_context_add_group(options, decrypt_group);
    g_option_context_set_summary(options, summary);
    ok = g_option_context_parse(options, &argc, &argv, &error);

    /* Set up logging */
    gutil_log_timestamp = FALSE;
    gutil_log_func = gutil_log_stderr;
    gutil_log_default.name = "foilmsg";
    if (verbose) {
        gutil_log_default.level = GLOG_LEVEL_VERBOSE;
    }

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

    if (show_info && !decrypt) {
        GWARN("Ignoring --info option because we are not decrypting");
    }

    if (ok && priv_key && argc == 1) {
        FoilKey* pub = NULL;
        FoilPrivateKey* priv;
        const char* pub_pad = "";

        /* Load the keys */
        priv = foil_private_key_new_from_file(FOIL_KEY_RSA_PRIVATE, priv_key);
        if (priv) {
            if (GLOG_ENABLED(GLOG_LEVEL_DEBUG)) {
                GBytes* fp = foil_private_key_fingerprint(priv);
                GString* buf = foilmsg_bytes_to_hex(fp);
                GDEBUG("Private key fingerprint: %s", buf->str);
                g_string_free(buf, TRUE);
                pub_pad = " "; /* Align output for public and private keys */
            }
        } else {
            GERR("Failed to load private key from %s", priv_key);
        }

        if (pub_key) {
            pub = foil_key_new_from_file(FOIL_KEY_RSA_PUBLIC, pub_key);
            if (pub) {
                if (GLOG_ENABLED(GLOG_LEVEL_DEBUG)) {
                    GBytes* fp = foil_key_fingerprint(pub);
                    GString* buf = foilmsg_bytes_to_hex(fp);
                    GDEBUG("Public key fingerprint: %s%s", pub_pad, buf->str);
                    g_string_free(buf, TRUE);
                }
            } else {
                GERR("Failed to load public key from %s", pub_key);
            }
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
                FoilInput* input = foil_input_file_new(stdin, 0);
                in = foil_input_read_all(input);
                foil_input_unref(input);
            }
            if (in) {
                FoilBytes bytes;
                foil_bytes_from_data(&bytes, in);
                if (decrypt) {
                    if (show_info) {
                        ret = foilmsg_info(&bytes);
                    } else {
                        ret = foilmsg_decode(pub, priv, &bytes);
                    }
                } else if (g_utf8_validate((void*)bytes.val, bytes.len, 0)) {
                    /* NULL terminate the text */
                    FoilMsgEncryptOptions opt;
                    char* text = g_malloc(bytes.len + 1);
                    memcpy(text, bytes.val, bytes.len);
                    text[bytes.len] = 0;
                    memset(&opt, 0, sizeof(opt));
                    /* Without a public key, encrypt to self */
                    if (for_self || !pub) {
                        opt.flags |= FOILMSG_FLAG_ENCRYPT_FOR_SELF;
                    }
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
