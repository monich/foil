/*
 * Copyright (C) 2018 by Slava Monich
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

#ifndef FOIL_OID_H
#define FOIL_OID_H

/* ASN.1 encoded OID values */

/* 1.2.840.113549.1.1.1 - RSA */
#define ASN1_OID_RSA_LENGTH (9)
#define ASN1_OID_RSA_BYTES \
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01

/* 1.2.840.113549.1.5.12 - PBKDF2 (Key Derivation Function) */
#define ASN1_OID_PBKDF2_LENGTH (9)
#define ASN1_OID_PBKDF2_BYTES \
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C

/* 2.16.840.1.101.3.4.1.2 (AES128-CBC) */
#define ASN1_OID_AES128_CBC_LENGTH (9)
#define ASN1_OID_AES128_CBC_BYTES \
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02

/* 2.16.840.1.101.3.4.1.22 (AES192-CBC) */
#define ASN1_OID_AES192_CBC_LENGTH (9)
#define ASN1_OID_AES192_CBC_BYTES \
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16

/* 2.16.840.1.101.3.4.1.42 (AES256-CBC) */
#define ASN1_OID_AES256_CBC_LENGTH (9)
#define ASN1_OID_AES256_CBC_BYTES \
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A

#endif /* FOIL_OID_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
