/*
 * Copyright (C) 2016-2021 by Slava Monich <slava@monich.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *   3. Neither the names of the copyright holders nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation
 * are those of the authors and should not be interpreted as representing
 * any official policies, either expressed or implied.
 */

#ifndef FOIL_TYPES_H
#define FOIL_TYPES_H

#include <gutil_types.h>

G_BEGIN_DECLS

typedef struct foil_digest FoilDigest;
typedef struct foil_cipher FoilCipher;
typedef struct foil_cmac FoilCmac;
typedef struct foil_hmac FoilHmac;
typedef struct foil_input FoilInput;
typedef struct foil_key FoilKey;
typedef struct foil_output FoilOutput;
typedef struct foil_private_key FoilPrivateKey;
typedef struct foil_random FoilRandom;

typedef struct foil_bytes {
    const guint8* val;
    gsize len;
} FoilBytes;

#define FoilParsePos GUtilRange

#define FOIL_ERROR (foil_error_quark())
GQuark foil_error_quark(void);

typedef enum foil_error {
    FOIL_ERROR_UNSPECIFIED,             /* Unspecified (internal?) error */
    FOIL_ERROR_INVALID_ARG,             /* Invalid argument(s) */
    FOIL_ERROR_KEY_UNSUPPORTED,         /* Unsupported operation */
    FOIL_ERROR_KEY_UNRECOGNIZED_FORMAT, /* Invalid or unsupported format */
    FOIL_ERROR_KEY_ENCRYPTED,           /* Key is encrypted, need passphrase */
    FOIL_ERROR_KEY_UNKNOWN_ENCRYPTION,  /* Unsupported key encryption */
    FOIL_ERROR_KEY_DECRYPTION_FAILED,   /* Probably, invalid passphrase */
    FOIL_ERROR_KEY_READ,                /* I/O error */
    FOIL_ERROR_KEY_WRITE                /* I/O error */
} FoilError;

G_END_DECLS

#endif /* FOIL_TYPES_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
