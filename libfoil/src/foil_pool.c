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

#include "foil_pool.h"
#include "foil_log_p.h"

struct foil_pool_item {
    FoilPoolItem* next;
    gpointer pointer;
    GDestroyNotify destroy;
};

void
foil_pool_init(
    FoilPool* self)
{
    memset(self, 0, sizeof(*self));
}

void
foil_pool_drain(
    FoilPool* self)
{
    FoilPoolItem* items = self->first;
    while (items) {
        FoilPoolItem* item = items;
        self->first = self->last = NULL;
        while (item) {
            item->destroy(item->pointer);
            item = item->next;
        }
        g_slice_free_chain(FoilPoolItem, items, next);
        items = self->first;
    }
}

void
foil_pool_add(
    FoilPool* self,
    gpointer pointer,
    GDestroyNotify destroy)
{
    FoilPoolItem* item = g_slice_new(FoilPoolItem);

    GASSERT(destroy);
    item->next = NULL;
    item->pointer = pointer;
    item->destroy = destroy;

    if (self->last) {
        self->last->next = item;
    } else {
        GASSERT(!self->first);
        self->first = item;
    }
    self->last = item;
}

void
foil_pool_add_bytes(
    FoilPool* self,
    GBytes* bytes)
{
    if (G_LIKELY(bytes)) {
        foil_pool_add(self, bytes, (GDestroyNotify)g_bytes_unref);
    }
}

void
foil_pool_add_bytes_ref(
    FoilPool* self,
    GBytes* bytes)
{
    if (G_LIKELY(bytes)) {
        foil_pool_add_bytes(self, g_bytes_ref(bytes));
    }
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
