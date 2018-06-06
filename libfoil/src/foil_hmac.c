/*
 * Copyright (C) 2018 by Slava Monich
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

#include "foil_hmac.h"
#include "foil_digest_p.h"
#include "foil_log_p.h"

/*
 * https://www.ietf.org/rfc/rfc2104.txt
 *
 * The HMAC transform looks like:
 *
 * H(K XOR opad, H(K XOR ipad, text))
 *
 * where K is an n byte key
 * ipad is the byte 0x36 repeated 64 times
 * opad is the byte 0x5c repeated 64 times
 * and text is the data being protected
 */

struct foil_hmac {
    gint ref_count;
    FoilDigest* digest;
    guint8* k_opad;
    GBytes* result;
};

static
void
foil_hmac_finalize(
    FoilHmac* self)
{
    if (self->result) {
        g_bytes_unref(self->result);
        GASSERT(!self->digest);
        GASSERT(!self->k_opad);
    } else {
        const gsize blocksize = foil_digest_block_size(self->digest);
        memset(self->k_opad, 0, blocksize);
        g_slice_free1(blocksize, self->k_opad);
        foil_digest_unref(self->digest);
    }
}

FoilHmac*
foil_hmac_ref(
    FoilHmac* hmac)
{
    if (G_LIKELY(hmac)) {
        GASSERT(hmac->ref_count > 0);
        g_atomic_int_inc(&hmac->ref_count);
    }
    return hmac;
}

void
foil_hmac_unref(
    FoilHmac* hmac)
{
    if (G_LIKELY(hmac)) {
        GASSERT(hmac->ref_count > 0);
        if (g_atomic_int_dec_and_test(&hmac->ref_count)) {
            foil_hmac_finalize(hmac);
            g_slice_free(FoilHmac, hmac);
        }
    }
}

FoilHmac*
foil_hmac_new(
    GType digest_type,
    const void* key,
    gsize keylen)
{
    FoilDigest* digest = foil_digest_new(digest_type);
    if (digest) {
        FoilHmac* hmac = g_slice_new0(FoilHmac);
        const gsize blocksize = foil_digest_block_size(digest);
        guint8* k_ipad = g_slice_alloc0(blocksize);
        GBytes* tmp_key = NULL;
        gsize i;

        g_atomic_int_set(&hmac->ref_count, 1);
        hmac->digest = digest;
        hmac->k_opad = g_slice_alloc0(blocksize);

        /* If key is longer than digest block size, reset it to H(key) */
        if (keylen > blocksize) {
            tmp_key = foil_digest_data(digest_type, key, keylen);
            key = g_bytes_get_data(tmp_key, &keylen);
        }

        /* XOR key with ipad and opad values */
        memcpy(k_ipad, key, keylen);
        memcpy(hmac->k_opad, key, keylen);
        for (i = 0; i < blocksize; i++) {
            k_ipad[i] ^= 0x36;
            hmac->k_opad[i] ^= 0x5c;
        }

        /* Perform inner digest */
        foil_digest_update(digest, k_ipad, blocksize);
        memset(k_ipad, 0, blocksize);
        g_slice_free1(blocksize, k_ipad);
        if (tmp_key) {
            g_bytes_unref(tmp_key);
        }
        return hmac;
    }
    return NULL;
}

FoilHmac*
foil_hmac_clone(
    FoilHmac* self)
{
    if (G_LIKELY(self)) {
        FoilHmac* hmac = g_slice_new0(FoilHmac);
        g_atomic_int_set(&hmac->ref_count, 1);
        if (self->result) {
            hmac->result = g_bytes_ref(self->result);
            GASSERT(!self->digest);
            GASSERT(!self->k_opad);
        } else {
            const gsize blocksize = foil_digest_block_size(self->digest);
            hmac->digest = foil_digest_clone(self->digest);
            hmac->k_opad = g_slice_alloc0(blocksize);
            memcpy(hmac->k_opad, self->k_opad, blocksize);
        }
        return hmac;
    }
    return NULL;
}

void
foil_hmac_copy(
    FoilHmac* self,
    FoilHmac* source)
{
    if (G_LIKELY(self) && G_LIKELY(source) && self != source) {
        /* Clean up the old state but don't deallocate k_opad just yet */
        FoilDigest* prev_digest = self->digest;
        guint8* prev_k_opad = self->k_opad;
        self->k_opad = NULL;
        self->digest = NULL;
        if (self->result) {
            g_bytes_unref(self->result);
            self->result = NULL;
        }
        if (source->result) {
            self->result = g_bytes_ref(source->result);
        } else {
            const gsize blocksize = foil_digest_block_size(source->digest);
            if (blocksize == foil_digest_block_size(prev_digest)) {
                /* No need to reallocate k_opad */
                self->k_opad = prev_k_opad;
                prev_k_opad = NULL;
            } else {
                self->k_opad = g_slice_alloc0(blocksize);
            }
            memcpy(self->k_opad, source->k_opad, blocksize);
            if (foil_digest_copy(prev_digest, source->digest)) {
                /* No need to reallocate the digest */
                self->digest = foil_digest_ref(prev_digest);
            } else {
                self->digest = foil_digest_clone(source->digest);
            }
        }
        if (prev_k_opad) {
            const gsize blocksize = foil_digest_block_size(prev_digest);
            memset(prev_k_opad, 0, blocksize);
            g_slice_free1(blocksize, prev_k_opad);
        }
        foil_digest_unref(prev_digest);
    }
}

void
foil_hmac_update(
    FoilHmac* self,
    const void* data,
    gsize size)
{
    if (G_LIKELY(self)) {
        foil_digest_update(self->digest, data, size);
    }
}

GBytes*
foil_hmac_finish(
    FoilHmac* self)
{
    if (G_LIKELY(self)) {
        if (!self->result) {
            const gsize blocksize = foil_digest_block_size(self->digest);
            GType type = G_TYPE_FROM_INSTANCE(self->digest);
            FoilDigest* md = foil_digest_new(type);
            GBytes* d = foil_digest_free_to_bytes(self->digest);

            foil_digest_update(md, self->k_opad, blocksize);
            foil_digest_update_bytes(md, d);
            self->result = foil_digest_free_to_bytes(md);

            g_bytes_unref(d);
            memset(self->k_opad, 0, blocksize);
            g_slice_free1(blocksize, self->k_opad);
            self->k_opad = NULL;
            self->digest = NULL;
        }
        return self->result;
    }
    return NULL;
}

GBytes*
foil_hmac_free_to_bytes(
    FoilHmac* self)
{
    if (G_LIKELY(self)) {
        GBytes* bytes = foil_hmac_finish(self);
        g_bytes_ref(bytes);
        foil_hmac_unref(self);
        return bytes;
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
