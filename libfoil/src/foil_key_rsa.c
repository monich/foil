/*
 * Copyright (C) 2023 Slava Monich <slava@monich.com>
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

#include "foil_input.h"
#include "foil_key_rsa.h"
#include "foil_key_rsa_public.h"
#include "foil_output.h"
#include "foil_pool.h"
#include "foil_util_p.h"

#include <ctype.h>

static const guint8 openssh_key_prefix_data[] = {
    '-','-','-','-','-','B','E','G','I','N',' ','O','P','E','N','S',
    'S','H',' ','P','R','I','V','A','T','E',' ','K','E','Y','-','-',
    '-','-','-'
};
static const guint8 openssh_key_suffix_data[] = {
    '-','-','-','-','-','E','N','D',' ','O','P','E','N','S','S','H',
    ' ','P','R','I','V','A','T','E',' ','K','E','Y','-','-','-','-',
    '-'
};

static const guint8 openssh_key_auth_magic_data[] = {
    'o','p','e','n','s','s','h','-','k','e','y','-','v','1',0
};

static const guint8 ssh_rsa_mark_data[] = {
    's','s','h','-','r','s','a'
};

const FoilBytes foil_key_openssh_text_prefix = {
    FOIL_ARRAY_AND_SIZE(openssh_key_prefix_data)
};

const FoilBytes foil_key_openssh_text_suffix = {
    FOIL_ARRAY_AND_SIZE(openssh_key_suffix_data)
};

const FoilBytes foil_key_openssh_auth_magic = {
    FOIL_ARRAY_AND_SIZE(openssh_key_auth_magic_data)
};

const FoilBytes foil_ssh_rsa_mark = {
    FOIL_ARRAY_AND_SIZE(ssh_rsa_mark_data)
};

#define FROM_BE32(ptr) \
    ((((((((ptr)[0]) << 8) + \
           (ptr)[1]) << 8) + \
           (ptr)[2]) << 8) + \
           (ptr)[3])

gboolean
foil_key_rsa_parse_n(
    GUtilRange* pos,
    guint32* n)
{
    if ((pos->ptr + 4) <= pos->end) {
        *n = FROM_BE32(pos->ptr);
        pos->ptr += 4;
        return TRUE;
    }
    return FALSE;
}

gboolean
foil_key_rsa_parse_n_bytes(
    GUtilRange* pos,
    FoilBytes* data)
{
    if ((pos->ptr + 4) <= pos->end) {
        const guint32 len = FROM_BE32(pos->ptr);
        if ((pos->ptr + 4 + len) <= pos->end) {
            data->val = pos->ptr + 4;
            data->len = len;
            pos->ptr = data->val + len;
            return TRUE;
        }
    }
    return FALSE;
}

gboolean
foil_key_rsa_write_n(
    FoilOutput* out,
    guint32 n)
{
    guint8 bytes[4];

    bytes[0] = (guint8)(n >> 24);
    bytes[1] = (guint8)(n >> 16);
    bytes[2] = (guint8)(n >> 8);
    bytes[3] = (guint8)n;
    return foil_output_write(out, bytes, sizeof(bytes));
}

gboolean
foil_key_rsa_write_n_bytes(
    FoilOutput* out,
    const FoilBytes* data)
{
    return foil_key_rsa_write_n(out, data->len) &&
        foil_output_write_all(out, data->val, data->len);
}

gboolean
foil_key_rsa_parse_openssh_text(
    const FoilBytes* data,
    FoilKeyRsaPublicData* pub,
    FoilKeyRsaOpensshPrivData* priv,
    FoilPool* pool)
{
    gboolean ok = FALSE;
    GUtilRange pos;
    foil_parse_init_data(&pos, data);
    foil_parse_skip_spaces(&pos);
    if (foil_parse_skip_bytes(&pos, &foil_key_openssh_text_prefix) &&
        pos.ptr < pos.end && isspace(*pos.ptr)) {
        GBytes* decoded = foil_parse_base64(&pos,
            FOIL_INPUT_BASE64_IGNORE_SPACES |
            FOIL_INPUT_BASE64_STANDARD);
        if (decoded) {
            if (foil_parse_skip_bytes(&pos, &foil_key_openssh_text_suffix)) {
                FoilBytes b;
                if (foil_key_rsa_parse_openssh_binary
                    (foil_bytes_from_data(&b, decoded), pub, priv)) {
                    /* Preserve GBytes in the pool to keep pointers valid */
                    foil_pool_add_bytes_ref(pool, decoded);
                    ok = TRUE;
                }
            }
            g_bytes_unref(decoded);
        }
    }
    return ok;
}

gboolean
foil_key_rsa_parse_openssh_binary(
    const FoilBytes* data,
    FoilKeyRsaPublicData* pub,
    FoilKeyRsaOpensshPrivData* priv)
{
    guint32 nkeys;
    GUtilRange pos;
    FoilBytes pubkey;
    foil_parse_init_data(&pos, data);
    return foil_parse_skip_bytes(&pos, &foil_key_openssh_auth_magic) &&
        foil_key_rsa_parse_n_bytes(&pos, &priv->ciphername) &&
        foil_key_rsa_parse_n_bytes(&pos, &priv->kdfname) &&
        foil_key_rsa_parse_n_bytes(&pos, &priv->kdf) &&
        foil_key_rsa_parse_n(&pos, &nkeys) && nkeys == 1 &&
        foil_key_rsa_parse_n_bytes(&pos, &pubkey) &&
        foil_key_rsa_public_parse_ssh_rsa_binary(pub, &pubkey) &&
        foil_key_rsa_parse_n_bytes(&pos, &priv->data) &&
        pos.ptr == pos.end;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
