/*
 * Copyright (C) 2019 by Slava Monich
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

#include "foil_openssl_des.h"

/* Logging */
#define GLOG_MODULE_NAME foil_log_key
#include "foil_log_p.h"

typedef FoilKeyDesClass FoilOpensslKeyDesClass;
G_DEFINE_TYPE(FoilOpensslKeyDes, foil_openssl_key_des, FOIL_TYPE_KEY_DES);
#define SUPER_CLASS foil_openssl_key_des_parent_class

GType
foil_impl_key_des_get_type(void)
{
    return FOIL_OPENSSL_TYPE_KEY_DES;
}

static
FoilOpensslKeyDesData*
foil_impl_key_des_data_new(
    const guint8* key)
{
    if (key) {
        FoilOpensslKeyDesData* data = g_slice_new0(FoilOpensslKeyDesData);
        memcpy(&data->k, key, FOIL_DES_KEY_SIZE);
        DES_set_key(&data->k, &data->ks);
        return data;
    } else {
        return NULL;
    }
}

static
gboolean
foil_openssl_key_des_valid(
    FoilKeyDesClass* klass,
    const guint8* key)
{
    /*
     * In at least some versions of openssl headers, DES_check_key_parity
     * and DES_is_weak_key take non-const pointers (but don't actually
     * modify the contents). Hence this cast.
     */
    DES_cblock* cblock = (void*)key;
    return DES_check_key_parity(cblock) && !DES_is_weak_key(cblock);
}

static
FoilKeyDes*
foil_openssl_key_des_create(
    FoilKeyDesClass* klass,
    const guint8* iv,
    const guint8* key1,
    const guint8* key2,
    const guint8* key3 /* Optional */)
{
    FoilOpensslKeyDes* self = g_object_new(FOIL_OPENSSL_TYPE_KEY_DES, NULL);
    FoilKeyDes* des = FOIL_KEY_DES_(self);
    des->key1 = (self->k1 = foil_impl_key_des_data_new(key1))->k;
    des->key2 = (self->k2 = foil_impl_key_des_data_new(key2))->k;
    if ((self->k3 = foil_impl_key_des_data_new(key3)) != NULL) {
        des->key3 = self->k3->k;
    }
    if (iv) {
        memcpy(des->iv, iv, FOIL_DES_IV_SIZE);
    }
    return des;
}

static
void
foil_openssl_key_des_finalize(
    GObject* object)
{
    FoilOpensslKeyDes* self = FOIL_OPENSSL_KEY_DES(object);
    g_slice_free(FoilOpensslKeyDesData, self->k1);
    g_slice_free(FoilOpensslKeyDesData, self->k2);
    g_slice_free(FoilOpensslKeyDesData, self->k3);
    G_OBJECT_CLASS(SUPER_CLASS)->finalize(object);
}

static
void
foil_openssl_key_des_init(
    FoilOpensslKeyDes* self)
{
}

static
void
foil_openssl_key_des_class_init(
    FoilOpensslKeyDesClass* klass)
{
    FoilKeyDesClass* des = FOIL_KEY_DES_CLASS(klass);
    des->fn_valid = foil_openssl_key_des_valid;
    des->fn_create = foil_openssl_key_des_create;
    G_OBJECT_CLASS(klass)->finalize = foil_openssl_key_des_finalize;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
