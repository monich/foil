/*
 * Copyright (C) 2019 by Slava Monich
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

#include "foil_cmac.h"
#include "foil_cipher.h"
#include "foil_key.h"
#include "foil_log_p.h"

/*
 * CMAC Mode for Authentication (NIST SP 800-38B)
 *
 * Since 1.0.14
 */

struct foil_cmac {
    gint ref_count;
    FoilCipher* cipher;
    GBytes* result;
    guint blocksize;
    guint nlb;
    guint8* lb;
    guint8* tmp;
    guint8* k1;
    guint8* k2;
};

/* 6.1 Subkey Generation */
static
void
foil_cmac_subkey(
    guint8* k,
    const guint8* l,
    int b,
    guint8 r)
{
    int i;
    guint8 carry = 0;

    /* Walk from LSB to MSB */
    for (i = b - 1; i >= 0; i--) {
        k[i] = (l[i] << 1) | carry;
        carry = (l[i] & 0x80) ? 1 : 0;
    }

    if (carry) {
        k[b - 1] ^= r;
    }
}

static
void
foil_cmac_finalize(
    FoilCmac* self)
{
    if (self->result) {
        g_bytes_unref(self->result);
    }
    foil_cipher_unref(self->cipher);
    g_slice_free1(self->blocksize, self->lb);
    g_slice_free1(self->blocksize, self->tmp);
    g_slice_free1(self->blocksize, self->k1);
    g_slice_free1(self->blocksize, self->k2);
}

FoilCmac*
foil_cmac_ref(
    FoilCmac* self)
{
    if (G_LIKELY(self)) {
        GASSERT(self->ref_count > 0);
        g_atomic_int_inc(&self->ref_count);
    }
    return self;
}

void
foil_cmac_unref(
    FoilCmac* self)
{
    if (G_LIKELY(self)) {
        GASSERT(self->ref_count > 0);
        if (g_atomic_int_dec_and_test(&self->ref_count)) {
            foil_cmac_finalize(self);
            g_slice_free1(sizeof(*self), self);
        }
    }
}

FoilCmac*
foil_cmac_new(
    FoilCipher* cipher)
{
    FoilCmac* self = NULL;
    const guint bs = foil_cipher_input_block_size(cipher);

    if (foil_cipher_symmetric(cipher) &&
        foil_cipher_output_block_size(cipher) == (int)bs) {
        guint8 r;
        gsize ks;
        FoilKey* key = foil_cipher_key(cipher);
        GBytes* kb = foil_key_to_bytes(key);
        const guint8* kd = g_bytes_get_data(kb, &ks);

        /* Approved block ciphers use 128 and 64 bit keys */
        switch (bs) {
        case 8:
            r = 0x1b;
            break;
        case 16:
            r = 0x87;
            break;
        default:
            GERR("Invalid CMAC block size %u", bs);
            r = 0;
            break;
        }
        if (r && ks > bs) {
            guint8* kdata = g_memdup(kd, ks);
            guint8* iv = kdata + (ks - bs);
            FoilCipher* c;
            FoilKey* k;

            /* Zero the IV part of the key */
            memset(iv, 0, bs);
            k = foil_key_new_from_data(G_TYPE_FROM_INSTANCE(key), kdata, ks);
            c = foil_cipher_new(G_TYPE_FROM_INSTANCE(cipher), k);
            foil_key_unref(k);
            g_free(kdata);

            if (c) {
                self = g_slice_new0(FoilCmac);
                g_atomic_int_set(&self->ref_count, 1);
                self->cipher = foil_cipher_clone(c);
                self->blocksize = bs;
                self->lb = g_slice_alloc0(bs);
                self->tmp = g_slice_alloc0(bs);
                self->k1 = g_slice_alloc0(bs);
                self->k2 = g_slice_alloc0(bs);
                if (foil_cipher_finish(c, self->lb, bs, self->tmp) > 0) {
                    foil_cmac_subkey(self->k1, self->tmp, bs, r);
                    foil_cmac_subkey(self->k2, self->k1, bs, r);
                } else {
                    foil_cmac_unref(self);
                    self = NULL;
                }
            }
            foil_cipher_unref(c);
        }
        g_bytes_unref(kb);
    }
    return self;
}

void
foil_cmac_update(
    FoilCmac* self,
    const void* data,
    gsize size)
{
    if (G_LIKELY(self) && G_LIKELY(size)) {
        const guint8* ptr = data;

        if (self->nlb < self->blocksize) {
            const gsize space_left = self->blocksize - self->nlb;
            const gsize copied = MIN(size, space_left);

            /* Continue filling the partial block */
            memcpy(self->lb + self->nlb, ptr, copied);
            self->nlb += copied;
            ptr += copied;
            size -= copied;
        }

        if (size > 0) {
            /* Last block must be full, otherwise size would be zero */
            foil_cipher_step(self->cipher, self->lb, self->tmp);

            /* Process all full blocks except for the last one */
            while (size > self->blocksize) {
                foil_cipher_step(self->cipher, ptr, self->tmp);
                ptr += self->blocksize;
                size -= self->blocksize;
            }

            /* Store the last one for the finish */
            memcpy(self->lb, ptr, size);
            self->nlb = size;
        }
    }
}

GBytes*
foil_cmac_finish(
    FoilCmac* self)
{
    if (G_LIKELY(self)) {
        if (!self->result) {
            guint8* out = g_malloc(self->blocksize);
            guint i;

            if (self->nlb == self->blocksize) {
                /* Last block is complete */
                for (i = 0; i < self->blocksize; i++) {
                    self->lb[i] ^= self->k1[i];
                }
            } else {
                /* Last block is incomplete */
                self->lb[(self->nlb)++] = 0x80;
                if (self->nlb < self->blocksize) {
                    memset(self->lb + self->nlb, 0,
                        self->blocksize - self->nlb);
                }
                for (i = 0; i < self->blocksize; i++) {
                    self->lb[i] ^= self->k2[i];
                }
            }
            foil_cipher_step(self->cipher, self->lb, out);
            self->result = g_bytes_new_take(out, self->blocksize);
        }
        return self->result;
    }
    return NULL;
}

GBytes*
foil_cmac_free_to_bytes(
    FoilCmac* self)
{
    if (G_LIKELY(self)) {
        GBytes* bytes = foil_cmac_finish(self);
        g_bytes_ref(bytes);
        foil_cmac_unref(self);
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
