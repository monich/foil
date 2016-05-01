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

#ifndef FOIL_CIPHER_H
#define FOIL_CIPHER_H

#include "foil_types.h"

G_BEGIN_DECLS

typedef
void
(*FoilCipherAsyncFunc)(
    FoilCipher* cipher,
    int result,
    void* arg);

typedef
void
(*FoilCipherAsyncBoolFunc)(
    FoilCipher* cipher,
    gboolean ok,
    void* arg);

/* Cipher type information */

const char*
foil_cipher_type_name(
    GType type);

gboolean
foil_cipher_type_supports_key(
    GType type,
    GType key_type);

/* Life cycle */

FoilCipher*
foil_cipher_new(
    GType type,
    FoilKey* key);

FoilCipher*
foil_cipher_ref(
    FoilCipher* cipher);

void
foil_cipher_unref(
    FoilCipher* cipher);

/* Cipher information */

const char*
foil_cipher_name(
    FoilCipher* cipher);

FoilKey*
foil_cipher_key(
    FoilCipher* cipher);

int
foil_cipher_input_block_size(
    FoilCipher* cipher);

int
foil_cipher_output_block_size(
    FoilCipher* cipher);

/*
 * Primitive operations, synchronous or asynchronous variants.
 *
 * Individual asynchronous operations can be cancelled with
 * g_source_remove, all operations with foil_cipher_cancel_all
 * That applies to both the primitive operations (step/finish) and
 * complete encryption sequences like foil_cipher_write_data_async.
 * It's an error to cancel the individual operation mode than once
 * or after it's completed. foil_cipher_cancel_all can be called
 * as many times as you wish.
 */

int
foil_cipher_step(
    FoilCipher* cipher,
    const void* in,
    void* out);

guint
foil_cipher_step_async(
    FoilCipher* self,
    const void* in,
    void* out,
    FoilCipherAsyncFunc fn,
    void* arg);

int
foil_cipher_finish(
    FoilCipher* cipher,
    const void* in,
    int len,
    void* out);

guint
foil_cipher_finish_async(
    FoilCipher* self,
    const void* in,
    int len,
    void* out,
    FoilCipherAsyncFunc fn,
    void* arg);

void
foil_cipher_cancel_all(
    FoilCipher* self);

/* Utilities for ciphering data blocks of arbitrary sizes */

gboolean
foil_cipher_write_data(
    FoilCipher* self,
    const void* data,
    gsize size,
    FoilOutput* out,
    FoilDigest* digest);        /* optional */

guint
foil_cipher_write_data_async(
    FoilCipher* self,
    const void* data,
    gsize size,
    FoilOutput* out,
    FoilDigest* digest,         /* optional */
    FoilCipherAsyncBoolFunc fn,
    void* arg);

gboolean
foil_cipher_write_data_blocks(
    FoilCipher* self,
    const FoilBytes* blocks,
    guint nblocks,
    FoilOutput* out,
    FoilDigest* digest);        /* optional */

GBytes*
foil_cipher_data(
    GType type,
    FoilKey* key,
    const void* data,
    gsize size);

GBytes*
foil_cipher_bytes(
    GType type,
    FoilKey* key,
    GBytes* bytes);

/* Implementation types */

GType foil_impl_cipher_rsa_encrypt_get_type(void);
GType foil_impl_cipher_rsa_decrypt_get_type(void);
GType foil_impl_cipher_aes_cbc_encrypt_get_type(void);
GType foil_impl_cipher_aes_cbc_decrypt_get_type(void);

#define FOIL_CIPHER_RSA_ENCRYPT foil_impl_cipher_rsa_encrypt_get_type()
#define FOIL_CIPHER_RSA_DECRYPT foil_impl_cipher_rsa_decrypt_get_type()
#define FOIL_CIPHER_AES_CBC_ENCRYPT foil_impl_cipher_aes_cbc_encrypt_get_type()
#define FOIL_CIPHER_AES_CBC_DECRYPT foil_impl_cipher_aes_cbc_decrypt_get_type()

G_END_DECLS

#endif /* FOIL_CIPHER_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
