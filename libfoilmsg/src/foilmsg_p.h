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

#ifndef FOILMSG_P_H
#define FOILMSG_P_H

#include "foilmsg.h"

#include <foil_asn1.h>
#include <foil_digest.h>
#include <foil_cipher.h>
#include <foil_key.h>
#include <foil_private_key.h>
#include <foil_sign.h>

#define FOILMSG_FORMAT_VERSION            (1)
#define FOILMSG_FINGERPRINT_FORMAT        (1)
#define FOILMSG_ENCRYPT_FORMAT            FOILMSG_ENCRYPT_FORMAT_AES_CBC
#define FOILMSG_SIGNATURE_FORMAT          FOILMSG_SIGNATURE_FORMAT_MD5_RSA
#define FOILMSG_PLAIN_DATA_FORMAT         (1)

#define FOILMSG_ENCRYPT_KEY_FORMAT_AES128 (1)
#define FOILMSG_ENCRYPT_KEY_FORMAT_AES192 (2)
#define FOILMSG_ENCRYPT_KEY_FORMAT_AES256 (3)
#define FOILMSG_ENCRYPT_FORMAT_AES_CBC    (1)
#define FOILMSG_SIGNATURE_FORMAT_MD5_RSA  (1)

#define FOILMSG_PREFIX                   "FOILMSG"
#define FOILMSG_PREFIX_LENGTH             (7)

#endif /* FOILMSG_P_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
