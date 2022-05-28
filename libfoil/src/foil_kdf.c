/*
 * Copyright (C) 2022 by Slava Monich <slava@monich.com>
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation
 * are those of the authors and should not be interpreted as representing
 * any official policies, either expressed or implied.
 */

#include "foil_kdf.h"
#include "foil_hmac.h"
#include "foil_digest.h"

/*
 * KDF: Key Derivation Functions (RFC 2898)
 *
 * Since 1.0.25
 */

/*
 * RFC 2898
 *
 * 5.2 PBKDF2
 *
 * ...
 *
 * PBKDF2 (P, S, c, dkLen)
 *
 * Options:        PRF        underlying pseudorandom function (hLen
 *                            denotes the length in octets of the
 *                            pseudorandom function output)
 *
 * Input:          P          password, an octet string
 *                 S          salt, an octet string
 *                 c          iteration count, a positive integer
 *                 dkLen      intended length in octets of the derived
 *                            key, a positive integer, at most
 *                            (2^32 - 1) * hLen
 *
 * Output:         DK         derived key, a dkLen-octet string
 */
GBytes*
foil_kdf_pbkdf2(
    GType digest,   /* HMAC digest algorithm, e.g. FOIL_DIGEST_SHA1 */
    const char* pw, /* UTF-8 encoded password from which to derive the key */
    gssize pwlen,   /* Negative to strlen() the password */
    const FoilBytes* salt,
    guint iter,     /* Number of iterations */
    guint dlen)     /* Derived key length, zero for auto (digest length) */
{
    const gsize hlen = foil_digest_type_size(digest);
    const gsize dklen = dlen ? dlen : hlen;

    /*
     * 1. If dkLen > (2^32 - 1) * hLen, output "derived key too long" and
     *    stop. (we skip that because our dlen won't exceed 0xffffffff)
     */
    if ((pw || !pwlen) && salt && iter && hlen) {
        /*
         * This one must succeed because non-zero hlen guarantees that
         * the digest type is valid.
         */
        FoilHmac* pmac = foil_hmac_new(digest, pw, (pwlen >= 0) ?
            (gsize) pwlen : strlen(pw));

        /*
         * 2. Let l be the number of hLen-octet blocks in the derived key,
         *    rounding up, and let r be the number of octets in the last
         *    block:
         *
         *              l = CEIL (dkLen / hLen) ,
         *              r = dkLen - (l - 1) * hLen .
         *
         *    Here, CEIL (x) is the "ceiling" function, i.e. the smallest
         *    integer greater than, or equal to, x.
         *
         * 3. For each block of the derived key apply the function F defined
         *    below to the password P, the salt S, the iteration count c, and
         *    the block index to compute the block:
         *
         *              T_1 = F (P, S, c, 1) ,
         *              T_2 = F (P, S, c, 2) ,
         *              ...
         *              T_l = F (P, S, c, l) ,
         *
         *    where the function F is defined as the exclusive-or sum of the
         *    first c iterates of the underlying pseudorandom function PRF
         *    applied to the password P and the concatenation of the salt S
         *    and the block index i:
         *
         *             F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
         *
         *    where
         *
         *              U_1 = PRF (P, S || INT (i)) ,
         *              U_2 = PRF (P, U_1) ,
         *              ...
         *              U_c = PRF (P, U_{c-1}) .
         *
         *    Here, INT (i) is a four-octet encoding of the integer i, most
         *    significant octet first.
         */
        guint8* key = g_malloc(dklen);
        gsize offset = 0;
        guint i = 1;

        while (offset < dklen) {
            const gsize remaining = dklen - offset;
            const gsize blocklen = MIN(remaining, hlen);
            const guint32 ibuf = htobe32(i);
            guint8* block = key + offset;
            FoilHmac* prf;
            const guint8* prev;
            GBytes* prev_bytes;
            guint m;

            /* U_1 = PRF (P, S || INT (i)) */
            prf = foil_hmac_clone(pmac);
            foil_hmac_update(prf, salt->val, salt->len);
            foil_hmac_update(prf, &ibuf, sizeof(ibuf));
            prev_bytes = foil_hmac_free_to_bytes(prf);
            prev = g_bytes_get_data(prev_bytes, NULL);
            memcpy(block, prev, blocklen);

            for (m = 1; m < iter; m++) {
                GBytes* next_bytes;
                const guint8* next;
                guint k;

                /* U_m = PRF (P, U_{m-1}) */
                prf = foil_hmac_clone(pmac);
                foil_hmac_update(prf, prev, hlen);
                next_bytes = foil_hmac_free_to_bytes(prf);
                next = g_bytes_get_data(next_bytes, NULL);
                for (k = 0; k < blocklen; k++) {
                    block[k] ^= next[k];
                }

                g_bytes_unref(prev_bytes);
                prev_bytes = next_bytes;
                prev = next;
            }

            g_bytes_unref(prev_bytes);
            offset += blocklen;
            i++;
        }

        foil_hmac_unref(pmac);
        return g_bytes_new_take(key, dklen);
    } else {
        return NULL;
    }
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
