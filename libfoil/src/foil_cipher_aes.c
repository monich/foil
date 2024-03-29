/*
 * Copyright (C) 2016-2023 Slava Monich <slava@monich.com>
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

#include "foil_cipher_aes.h"
#include "foil_util_p.h"

/* Logging */
#define GLOG_MODULE_NAME foil_log_cipher
#include "foil_log_p.h"

G_DEFINE_ABSTRACT_TYPE(FoilCipherAes, foil_cipher_aes, FOIL_TYPE_CIPHER);
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
void
foil_cipher_aes_init_with_key(
    FoilCipher* cipher,
    FoilKey* key)
{
    FoilCipherAes* self = FOIL_CIPHER_AES(cipher);
    FoilKeyAes* aes_key = FOIL_KEY_AES_(key);
    FOIL_CIPHER_CLASS(SUPER_CLASS)->fn_init_with_key(cipher, key);
    cipher->input_block_size = FOIL_AES_BLOCK_SIZE;
    cipher->output_block_size = FOIL_AES_BLOCK_SIZE;
    memcpy(self->block, aes_key->iv, FOIL_AES_BLOCK_SIZE);
}

static
void
foil_cipher_aes_copy(
    FoilCipher* dest,
    FoilCipher* src)
{
    FOIL_CIPHER_CLASS(SUPER_CLASS)->fn_copy(dest, src);
    memcpy(FOIL_CIPHER_AES(dest)->block, FOIL_CIPHER_AES(src)->block,
        FOIL_AES_BLOCK_SIZE);
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
    cipher->flags |= FOIL_CIPHER_SYMMETRIC;
    cipher->fn_supports_key = foil_cipher_aes_supports_key;
    cipher->fn_init_with_key = foil_cipher_aes_init_with_key;
    cipher->fn_copy = foil_cipher_aes_copy;
    cipher->fn_finish = foil_cipher_symmetric_finish;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
