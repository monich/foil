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

#include "foil_random_p.h"

#include <openssl/rand.h>

typedef FoilRandom FoilOpensslRandom;
typedef FoilRandomClass FoilOpensslRandomClass;

/* There's no need to instantiate this class, make it abstract */
G_DEFINE_ABSTRACT_TYPE(FoilOpensslRandom, foil_openssl_random, FOIL_TYPE_RANDOM)

GType
foil_impl_random_get_type()
{
    return foil_openssl_random_get_type();
}

static
gboolean
foil_openssl_random_generate(
    void* data,
    guint size)
{
    return RAND_bytes(data, size) != 0;
}

static
void
foil_openssl_random_init(
    FoilOpensslRandom* self)
{
}

static
void
foil_openssl_random_class_init(
    FoilOpensslRandomClass* klass)
{
    klass->name = "OpenSSL";
    klass->fn_generate = foil_openssl_random_generate;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
