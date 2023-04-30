/*
 * Copyright (C) 2019-2023 Slava Monich <slava@monich.com>
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

#ifndef FOIL_POOL_H
#define FOIL_POOL_H

#include "foil_types_p.h"

typedef struct foil_pool_item FoilPoolItem;

struct foil_pool {
    FoilPoolItem* first;
    FoilPoolItem* last;
};

void
foil_pool_init(
    FoilPool* pool)
    FOIL_INTERNAL;

void
foil_pool_drain(
    FoilPool* pool)
    FOIL_INTERNAL;

void
foil_pool_add(
    FoilPool* pool,
    gpointer pointer,
    GDestroyNotify destroy)
    FOIL_INTERNAL;

void
foil_pool_add_bytes(
    FoilPool* pool,
    GBytes* bytes)
    FOIL_INTERNAL;

void
foil_pool_add_bytes_ref(
    FoilPool* pool,
    GBytes* bytes)
    FOIL_INTERNAL;

#endif /* FOIL_POOL_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
