/*
 * Copyright (C) 2016-2023 Slava Monich <slava@monich.com>
 *
 * You may use this file under the terms of the BSD license as follows:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer
 *     in the documentation and/or other materials provided with the
 *     distribution.
 *  3. Neither the names of the copyright holders nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
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

#ifndef FOILMSG_H
#define FOILMSG_H

#include "foil_types.h"

G_BEGIN_DECLS

typedef struct foilmsg_tagged_data {
    gint32 tag;
    FoilBytes data;
} FoilMsgTaggedData;

typedef struct foilmsg_encrypt_key {
    FoilMsgTaggedData fingerprint;
    FoilBytes data;
} FoilMsgEncryptKey;

/* Valid tags for various blocks */
#define FOILMSG_FINGERPRINT_SSH_RSA       (1)

#define FOILMSG_ENCRYPT_KEY_FORMAT_AES128 (1) /* 16 bytes key + 16 bytes IV */
#define FOILMSG_ENCRYPT_KEY_FORMAT_AES192 (2) /* 24 bytes key + 16 bytes IV */
#define FOILMSG_ENCRYPT_KEY_FORMAT_AES256 (3) /* 32 bytes key + 16 bytes IV */

#define FOILMSG_ENCRYPT_FORMAT_AES_CBC    (1)
#define FOILMSG_ENCRYPT_FORMAT_AES_CFB    (2)
#define FOILMSG_ENCRYPT_FORMAT_AES_CTR    (3) /* Since 1.0.28 */

#define FOILMSG_SIGNATURE_FORMAT_MD5_RSA    (1)
#define FOILMSG_SIGNATURE_FORMAT_SHA1_RSA   (2)
#define FOILMSG_SIGNATURE_FORMAT_SHA256_RSA (3)
#define FOILMSG_SIGNATURE_FORMAT_SHA512_RSA (4)

/* N.B. Must be freed with foilmsg_info_free */
typedef struct foilmsg_info {
    gint32 format;
    FoilMsgTaggedData sender_fingerprint;
    gint32 encrypt_key_format;
    gint32 num_encrypt_keys;
    const FoilMsgEncryptKey* encrypt_keys;
    FoilMsgTaggedData encrypted;
    FoilMsgTaggedData signature;
} FoilMsgInfo;

typedef struct foilmsg_header {
    const char* name;
    const char* value;
} FoilMsgHeader;

typedef struct foilmsg_headers {
    const FoilMsgHeader* header;
    guint count;
} FoilMsgHeaders;

/* N.B. Must be freed with foilmsg_free */
typedef struct foilmsg {
    const char* content_type;
    FoilMsgHeaders headers;
    GBytes* data;
    GBytes* fingerprint;
} FoilMsg;

/*
 * Encrypt the data. This is a simple single-step process.
 */

typedef enum foilmsg_key_type {
    FOILMSG_KEY_AES_128,
    FOILMSG_KEY_AES_192,
    FOILMSG_KEY_AES_256
} FOILMSG_KEY_TYPE;

typedef enum foilmsg_cipher {
    FOILMSG_CIPHER_AES_CBC,
    FOILMSG_CIPHER_AES_CFB,
    FOILMSG_CIPHER_AES_CTR  /* Since 1.0.28 */
} FOILMSG_CIPHER;

typedef enum foilmsg_signature {
    FOILMSG_SIGNATURE_MD5_RSA,
    FOILMSG_SIGNATURE_SHA1_RSA,
    FOILMSG_SIGNATURE_SHA256_RSA,
    FOILMSG_SIGNATURE_SHA512_RSA
} FOILMSG_SIGNATURE;

#define FOILMSG_KEY_TYPE_DEFAULT (FOILMSG_KEY_AES_256)
#define FOILMSG_CIPHER_DEFAULT (FOILMSG_CIPHER_AES_CBC)
#define FOILMSG_SIGNATURE_DEFAULT (FOILMSG_SIGNATURE_SHA1_RSA)

typedef struct foilmsg_encrypt_options {
    FOILMSG_KEY_TYPE key_type;
    guint flags;

/*
 * FOILMSG_FLAG_ENCRYPT_FOR_SELF - encrypt the key with sender's public
 * key (in addition to recipient's public key). If this flag is specified
 * then the recipient's public key may be omitted, i.e. the data will be
 * encrypted only for the sender itself.
 */
#define FOILMSG_FLAG_ENCRYPT_FOR_SELF (0x01)

    FOILMSG_CIPHER cipher;
    FOILMSG_SIGNATURE signature;
} FoilMsgEncryptOptions;

/*
 * Text prefix for BASE64 encoded foilmsg blob. A space (or line break)
 * between the prefix and BASE64 encoded data is encouraged but not really
 * required.
 */
extern const FoilBytes foilmsg_prefix;

FoilMsgEncryptOptions*
foilmsg_encrypt_defaults(
    FoilMsgEncryptOptions* opt);

gsize
foilmsg_encrypt(
    FoilOutput* out,
    const FoilBytes* data,
    const char* content_type,           /* optional */
    const FoilMsgHeaders* headers,      /* optional */
    FoilPrivateKey* sender,
    FoilKey* recipient,
    const FoilMsgEncryptOptions* opt,   /* optional */
    FoilOutput* tmp);                   /* optional */

GString*
foilmsg_encrypt_text(
    const char* plain_text,
    FoilPrivateKey* sender,
    FoilKey* recipient,
    int linebreaks,
    const FoilMsgEncryptOptions* opt);  /* optional */

GBytes*
foilmsg_encrypt_text_to_bytes(
    const char* plain_text,
    FoilPrivateKey* sender,
    FoilKey* recipient,
    const FoilMsgEncryptOptions* opt);  /* optional */

GBytes*
foilmsg_encrypt_to_bytes(
    const FoilBytes* data,
    const char* content_type,           /* optional */
    const FoilMsgHeaders* headers,      /* optional */
    FoilPrivateKey* sender,
    FoilKey* recipient,
    const FoilMsgEncryptOptions* opt);  /* optional */

/*
 * foilmsg_parse checks the structure of the encrypted message.
 * Returns NULL if parsing fails. FoilMsgInfo contains pointers
 * to the bytes provided as input (doesn't copy the data).
 */

FoilMsgInfo*
foilmsg_parse(
    const FoilBytes* bytes);

void
foilmsg_info_free(
    FoilMsgInfo* info);

/*
 * Converts BASE64 encoded text representation into a binary format.
 *
 * Note that if the input is not recognized as a FOILMSG encoded text
 * the returned GBytes points to the data pointed to by FoilBytes, i.e.
 * in the binary data is not being copied. In that case the callers is
 * responsible for releasing the GBytes reference before deallocating
 * the input data.
 */

GBytes*
foilmsg_to_binary(
    const FoilBytes* data);

/*
 * Decryption is a two-step process.
 *
 * First, you need to decrypt the message with foilmsg_decrypt()
 * or foilmsg_decrypt_binary(). That gives you the fingerprint of the
 * sender's public key and the decrypted text. It doesn't guarantee
 * that the message hasn't been modified in transit (block cipher
 * would happily process any garbage).
 *
 * Then you need to lookup the sender's public key using the fingerprint
 * and call foilmsg_verify. If that returns TRUE then the message has
 * been delivered to you intact.
 *
 * If FoilOutput is NULL, the message will be processed in RAM (it's your
 * responsibility then to ensure that there's enough RAM).
 */

FoilMsg*
foilmsg_decrypt(
    FoilPrivateKey* recipient,
    const FoilBytes* bytes,
    FoilOutput* out);   /* optional */

FoilMsg*
foilmsg_decrypt_file(
    FoilPrivateKey* recipient,
    const char* path,
    FoilOutput* out);   /* optional */

FoilMsg*
foilmsg_decrypt_text(
    FoilPrivateKey* recipient,
    const char* message);

FoilMsg*
foilmsg_decrypt_text_len(
    FoilPrivateKey* recipient,
    const char* message,
    gsize length);

FoilMsg*
foilmsg_decrypt_text_bytes(
    FoilPrivateKey* recipient,
    const FoilBytes* bytes,
    FoilOutput* out);   /* optional */

/* Verify the signature */
gboolean
foilmsg_verify(
    const FoilMsg* msg,
    FoilKey* sender);

/* Free the decrypted message */
void
foilmsg_free(
    FoilMsg* msg);

/* Utilities */
const char*
foilmsg_get_value(
    const FoilMsg* msg,
    const char* name);

G_END_DECLS

#endif /* FOILMSG_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
