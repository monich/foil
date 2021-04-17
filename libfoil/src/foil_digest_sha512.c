/*
 * Copyright (C) 2021 by Slava Monich
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

#include "foil_digest_p.h"

#define DIGEST_LENGTH (64)
#define DIGEST_BLOCK_SIZE (128)

G_DEFINE_ABSTRACT_TYPE(FoilDigestSHA512, foil_digest_sha512, FOIL_TYPE_DIGEST);

/*
 * http://www.ietf.org/rfc/rfc3447
 *
 * id-sha512  OBJECT IDENTIFIER  ::=  {
 *     joint-iso-itu-t(2) country(16) us(840) organization(1)
 *     gov(101) csor(3) nistalgorithm(4) hashalgs(2) 3
 * }
 * }
 */
static const guint8 foil_digest_sha512_digest_oid [] = {
    0x60,       /* joint-iso-itu-t(2) country(16) */
    0x86, 0x48, /* us(840) */
    0x01,       /* organization(1) */
    0x65,       /* gov(101) */
    0x03,       /* csor(3) */
    0x04,       /* nistalgorithm(4) */
    0x02,       /* hashalgs(2) */
    0x03        /* 3 */
};

static
void*
foil_digest_sha512_digest_alloc(void)
{
    return g_slice_alloc(DIGEST_LENGTH);
}

static
void
foil_digest_sha512_digest_free(
    void* md)
{
    g_slice_free1(DIGEST_LENGTH, md);
}

static
void
foil_digest_sha512_init(
    FoilDigestSHA512* self)
{
}

static
void
foil_digest_sha512_class_init(
    FoilDigestSHA512Class* klass)
{
    klass->name = "SHA512";
    klass->size = DIGEST_LENGTH;
    klass->block_size = DIGEST_BLOCK_SIZE;
    FOIL_BYTES_SET(klass->oid, foil_digest_sha512_digest_oid);
    klass->fn_digest_alloc = foil_digest_sha512_digest_alloc;
    klass->fn_digest_free = foil_digest_sha512_digest_free;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
