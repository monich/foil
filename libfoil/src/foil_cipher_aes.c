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

#include "foil_cipher_aes.h"
#include "foil_util_p.h"

/* Logging */
#define GLOG_MODULE_NAME foil_log_cipher
#include "foil_log_p.h"

G_DEFINE_ABSTRACT_TYPE(FoilCipherAes, foil_cipher_aes, FOIL_TYPE_CIPHER_SYNC)
#define SUPER_CLASS foil_cipher_aes_parent_class

static
gboolean
foil_cipher_aes_supports_key(
    FoilCipherClass* klass,
    GType key_type)
{
    FoilKeyAesClass* key_klass =
        foil_abstract_class_ref(key_type, FOIL_TYPE_KEY_AES);
    if (key_klass) {
        g_type_class_unref(key_klass);
        return TRUE;
    }
    return FALSE;
}

static
int
foil_cipher_aes_finish(
    FoilCipher* cipher,
    const void* from,
    int flen,
    void* to)
{
    FoilCipherAesClass* klass = FOIL_CIPHER_AES_GET_CLASS(cipher);
    if (flen == FOIL_AES_BLOCK_SIZE) {
        return klass->fn_step(cipher, from, to);
    } else if (flen > 0) {
        GASSERT(flen < FOIL_AES_BLOCK_SIZE);
        if (flen > FOIL_AES_BLOCK_SIZE) {
            return -1;
        } else {
            int ret;
            guint8 tmp[FOIL_AES_BLOCK_SIZE];
            memcpy(tmp, from, flen);
            foil_cipher_pad(tmp, flen, FOIL_AES_BLOCK_SIZE);
            ret = klass->fn_step(cipher, tmp, to);
            return ret;
        }
    } else {
        return 0;
    }
}

static
void
foil_cipher_aes_post_init(
    FoilCipher* cipher)
{
    FoilCipherAes* self = FOIL_CIPHER_AES(cipher);
    FoilKeyAes* key = FOIL_KEY_AES_(cipher->key);
    cipher->input_block_size = FOIL_AES_BLOCK_SIZE;
    cipher->output_block_size = FOIL_AES_BLOCK_SIZE;
    memcpy(self->block, key->iv, FOIL_AES_BLOCK_SIZE);
    FOIL_CIPHER_CLASS(SUPER_CLASS)->fn_post_init(cipher);
}

static
void
foil_cipher_aes_init(
    FoilCipherAes* self)
{
}

static
void
foil_cipher_aes_class_init(
    FoilCipherAesClass* klass)
{
    FoilCipherClass* cipher = FOIL_CIPHER_CLASS(klass);
    cipher->name = "AES";
    cipher->fn_supports_key = foil_cipher_aes_supports_key;
    cipher->fn_post_init = foil_cipher_aes_post_init;
    cipher->fn_finish = foil_cipher_aes_finish;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
