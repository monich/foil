/*
 * Copyright (C) 2016-2019 by Slava Monich
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
#include <foil_util.h>
#include <foil_private_key.h>
#include <gutil_log.h>

#include <stdlib.h>
#include <stdio.h>

#define RET_OK 0
#define RET_ERR 1
#define RET_CMDLINE 2

#define DEFAULT_PRIV_KEY "/.ssh/id_rsa" /* Relative to $HOME */
#define FILENAME_HEADER "Filename"

typedef struct header {
    char* name;
    char* value;
} Header;

typedef struct encrypt_opts {
    GSList* headers;
} EncryptOpts;

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
foilmsg_encode_base64(
    FoilKey* to,
    FoilPrivateKey* from,
    const FoilBytes* data,
    const char* type,
    const FoilMsgHeaders* hdrs,
    FoilOutput* out,
    int linebreaks,
    const FoilMsgEncryptOptions* opts)
{
    int ret = RET_ERR;
    if (foil_output_write_all(out, foilmsg_prefix.val, foilmsg_prefix.len) &&
        foil_output_write_eol(out)) {
        FoilOutput* out64 = foil_output_base64_new_full(out, 0, linebreaks);
        if (foilmsg_encrypt(out64, data, type, hdrs, from, to, opts, NULL)) {
            ret = RET_OK;
        }
        foil_output_unref(out64);
    }
    return ret;
}

static
int
foilmsg_decode(
    FoilKey* sender,
    FoilPrivateKey* recipient,
    const FoilBytes* bytes,
    FoilOutput* out)
{
    FoilMsg* msg = foilmsg_decrypt_text_bytes(recipient, bytes, out);
    if (!msg && (!out || foil_output_reset(out))) {
        msg = foilmsg_decrypt(recipient, bytes, out);
    }
    if (msg) {
        guint i;
        gsize len;
        const char* data = g_bytes_get_data(msg->data, &len);

        if (msg->headers.count) {
            GVERBOSE("Found %u header(s)", msg->headers.count);
            for (i = 0; i < msg->headers.count; i++) {
                const FoilMsgHeader* hdr = msg->headers.header + i;
                GVERBOSE("  %s: %s", hdr->name, hdr->value);
            }
        } else {
            GVERBOSE("No headers");
        }

        if (sender) {
            if (foilmsg_verify(msg, sender)) {
                if (!out) {
                    printf("%.*s", (int)len, data);
                }
                return RET_OK;
            } else {
                GERR("Signature verification failed");
            }
        } else {
            /* Try to validate against the private key */
            FoilKey* pub = foil_public_key_new_from_private(recipient);
            if (foilmsg_verify(msg, pub)) {
                if (!out) {
                    printf("%.*s", (int)len, data);
                }
            } else {
                if (out) {
                    printf("[UNVERIFIED] %.*s", (int)len, data);
                } else {
                    printf("[UNVERIFIED]\n");
                }
            }
            foil_key_unref(pub);
            return RET_OK;
        }
    }
    return RET_ERR;
}

static
const Header*
foilmsg_header_find(
    GSList* list,
    const char* name)
{
    GSList* l;

    for (l = list; l; l = l->next) {
        const Header* header = l->data;

        if (!g_strcmp0(header->name, name)) {
            return header;
        }
    }
    return NULL;
}

static
gboolean
foilmsg_header_opt(
    const gchar* name,
    const gchar* value,
    gpointer data,
    GError** error)
{
    EncryptOpts* opts = data;
    Header* header = g_new0(Header, 1);
    const char* sep = strchr(value, ':');

    if (sep) {
        header->name = g_strstrip(g_strndup(value, sep - value));
        header->value = g_strstrip(g_strdup(sep + 1));
    } else {
        header->name = g_strstrip(g_strdup(value));
    }
    opts->headers = g_slist_append(opts->headers, header);
    return TRUE;
}

static
void
foilmsg_header_free(
    gpointer data)
{
    Header* header = data;

    g_free(header->name);
    g_free(header->value);
    g_free(header);
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
    gboolean binary = FALSE;
#ifdef VERSION
    gboolean print_version = FALSE;
#endif
    GError* error = NULL;
    char* priv_key = NULL;
    char* pub_key = NULL;
    char* in_file = NULL;
    char* out_file = NULL;
    char* type = NULL;
    char* pass = NULL;
    int key_size = 128;
    int columns = 64;
    EncryptOpts encrypt_opts;
    GOptionContext* options;
    GOptionGroup* encrypt_group;
    GOptionGroup* decrypt_group;
    GOptionEntry entries[] = {
        { "decrypt", 'd', 0, G_OPTION_ARG_NONE, &decrypt,
          "Decrypt the data", NULL },
        { "secret", 's', 0, G_OPTION_ARG_FILENAME, &priv_key,
          "Your private key [~" DEFAULT_PRIV_KEY "]", "FILE" },
        { "pass", 'P', 0, G_OPTION_ARG_STRING, &pass,
          "Passphrase to decrypt your private key", "PASS" },
        { "public", 'p', 0, G_OPTION_ARG_FILENAME, &pub_key,
          "Public key of the other party", "FILE" },
        { "file", 'f', 0, G_OPTION_ARG_FILENAME, &in_file,
          "Read input from FILE", "FILE" },
        { "output", 'o', 0, G_OPTION_ARG_FILENAME, &out_file,
          "Write output to FILE", "FILE" },
        { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose,
          "Enable verbose output", NULL },
#ifdef VERSION
        { "version", 0, 0, G_OPTION_ARG_NONE, &print_version,
          "Print version and exit", NULL },
#endif
        { NULL }
    };
    GOptionEntry encrypt_entries[] = {
        { "type", 't', 0, G_OPTION_ARG_STRING, &type,
          "Specify content type", "TYPE" },
        { "bits", 'b', 0, G_OPTION_ARG_INT, &key_size,
          "Encryption key size (128, 192 or 256) [128]", "BITS" },
        { "columns", 'c', 0, G_OPTION_ARG_INT, &columns,
          "Wrap lines at the specified column [64]", "COLS" },
        { "header", 'H', 0, G_OPTION_ARG_CALLBACK, foilmsg_header_opt,
          "Add metadata header (repeatable)", "NAME:VALUE"},
        { "binary", 'B', 0, G_OPTION_ARG_NONE, &binary,
          "Output binary data in ASN.1 format", NULL },
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

    memset(&encrypt_opts, 0, sizeof(encrypt_opts));
    options = g_option_context_new("- encrypt or decrypt text messages");
    encrypt_group = g_option_group_new("encrypt", "Encryption Options:",
        "Show encryption options", &encrypt_opts, NULL);
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

    if (show_info) {
        decrypt = TRUE;
    }

#ifdef VERSION
    if (ok && print_version) {
        printf("%s %s\n", gutil_log_default.name, G_STRINGIFY(VERSION));
        ret = RET_OK;
    } else
#endif

    if (ok && priv_key && argc == 1) {
        FoilKey* pub = NULL;
        FoilPrivateKey* priv;
        const char* pub_pad = "";

        /* Load the keys */
        if (pass) {
            priv = foil_private_key_decrypt_from_file(FOIL_KEY_RSA_PRIVATE,
                priv_key, pass, &error);
        } else {
            priv = foil_private_key_new_from_file(FOIL_KEY_RSA_PRIVATE,
                priv_key);
        }

        if (priv) {
            if (GLOG_ENABLED(GLOG_LEVEL_DEBUG)) {
                GBytes* fp = foil_private_key_fingerprint(priv);
                GString* buf = foilmsg_bytes_to_hex(fp);
                GDEBUG("Private key fingerprint: %s", buf->str);
                g_string_free(buf, TRUE);
                pub_pad = " "; /* Align output for public and private keys */
            }
        } else if (error) {
            GERR("Failed to load private key from %s (%s)", priv_key,
                GERRMSG(error));
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
                        FoilOutput* out = NULL;
                        if (out_file) {
                            out = foil_output_file_new_open(out_file);
                            if (!out) {
                                GERR("Failed to open %s", out_file);
                            }
                        }
                        if (!out_file || out) {
                            ret = foilmsg_decode(pub, priv, &bytes, out);
                        }
                        foil_output_unref(out);
                    }
                } else {
                    FoilMsgHeaders headers;
                    FoilMsgHeader filename_header;
                    FoilMsgHeader* alloc_headers = NULL;
                    const FoilMsgHeaders* encode_headers = NULL;
                    FoilOutput* tmp = foil_output_file_new_tmp();
                    FoilOutput* out = NULL;
                    char* tmpfilename = NULL;
                    FoilMsgEncryptOptions opt;

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

                    memset(&filename_header, 0, sizeof(filename_header));
                    if (in_file && !foilmsg_header_find(encrypt_opts.headers,
                        FILENAME_HEADER)) {
                        /* Store the file name in the headers */
                        char* basename = g_path_get_basename(in_file);
                        tmpfilename = g_filename_to_utf8(basename, -1,
                            NULL, NULL, NULL);
                        g_free(basename);
                        if (tmpfilename) {
                            filename_header.name = FILENAME_HEADER;
                            filename_header.value = tmpfilename;
                            headers.header = &filename_header;
                            headers.count = 1;
                            encode_headers = &headers;
                        }
                    }

                    /* Buld the list of headers */
                    if (encrypt_opts.headers) {
                        GSList* l;
                        guint n = g_slist_length(encrypt_opts.headers);

                        if (filename_header.name) n++;

                        alloc_headers = g_new(FoilMsgHeader, n);
                        headers.header = alloc_headers;
                        headers.count = 0;
                        encode_headers = &headers;

                        GVERBOSE("Adding %u header(s)", n);
                        if (filename_header.name) {
                            alloc_headers[headers.count++] = filename_header;
                            GVERBOSE("  %s: %s", filename_header.name,
                                filename_header.value);
                        }
                        for (l = encrypt_opts.headers; l; l = l->next) {
                            const Header* user_header = l->data;
                            FoilMsgHeader* msg_header = alloc_headers +
                                (headers.count++);

                            msg_header->name = user_header->name;
                            msg_header->value = user_header->value ?
                                user_header->value : "";
                            GVERBOSE("  %s: %s", msg_header->name,
                                msg_header->value);
                        }
                    } else if (filename_header.name) {
                        headers.header = &filename_header;
                        headers.count = 1;
                        encode_headers = &headers;
                    }

                    if (out_file) {
                        out = foil_output_file_new_open(out_file);
                        if (!out) {
                            GERR("Failed to open %s", out_file);
                        }
                    } else {
                        out = foil_output_file_new(stdout, 0);
                    }

                    if (out) {
                        if (binary) {
                            if (foilmsg_encrypt(out, &bytes, type,
                                encode_headers, priv, pub, &opt, tmp)) {
                                ret = RET_OK;
                            }
                        } else {
                            ret = foilmsg_encode_base64(pub, priv, &bytes,
                                type, encode_headers, out, columns, &opt);
                        }
                        foil_output_unref(out);
                    }

                    g_free(alloc_headers);
                    g_free(tmpfilename);
                    foil_output_unref(tmp);
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
    g_slist_free_full(encrypt_opts.headers, foilmsg_header_free);
    g_free(priv_key);
    g_free(pub_key);
    g_free(in_file);
    g_free(out_file);
    g_free(pass);
    g_free(type);
    return ret;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
