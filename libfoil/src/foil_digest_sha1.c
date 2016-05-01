/*
 * Copyright (C) 2016 by Slava Monich
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

#include "foil_digest_p.h"

#define DIGEST_LENGTH (20)

G_DEFINE_ABSTRACT_TYPE(FoilDigestSHA1, foil_digest_sha1, FOIL_TYPE_DIGEST);

/*
 * http://www.ietf.org/rfc/rfc3447
 *
 * id-sha1    OBJECT IDENTIFIER ::= {
 *     iso(1) identified-organization(3) oiw(14) secsig(3)
 *     algorithms(2) 26
 * }
 */
static const guint8 foil_digest_sha1_digest_oid [] = {
    0x2b,   /* iso(1) identified-organization(3) */
    0x0e,   /* oiw(14) */
    0x03,   /* secsig(3) */
    0x02,   /* digestAlgorithm(2) */
    0x1a    /* 26 */
};

static
void*
foil_digest_sha1_digest_alloc(void)
{
    return g_slice_alloc(DIGEST_LENGTH);
}

static
void
foil_digest_sha1_digest_free(
    void* md)
{
    g_slice_free1(DIGEST_LENGTH, md);
}

static
void
foil_digest_sha1_init(
    FoilDigestSHA1* self)
{
}

static
void
foil_digest_sha1_class_init(
    FoilDigestSHA1Class* klass)
{
    klass->name = "SHA1";
    klass->size = DIGEST_LENGTH;
    FOIL_BYTES_SET(klass->oid, foil_digest_sha1_digest_oid);
    klass->fn_digest_alloc = foil_digest_sha1_digest_alloc;
    klass->fn_digest_free = foil_digest_sha1_digest_free;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
