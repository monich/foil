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

#ifndef FOIL_ASN1_P_H
#define FOIL_ASN1_P_H

#include "foil_asn1.h"

#define ASN1_CLASS_UNIVERSAL            (0x00)
#define ASN1_CLASS_APPLICATION          (0x40)
#define ASN1_CLASS_CONTEXT_SPECIFIC     (0x80)
#define ASN1_CLASS_PRIVATE              (0xC0)
#define ASN1_CLASS_MASK                 (0xC0)
#define ASN1_CLASS_STRUCTURED           (0x20)

#define ASN1_TAG_BOOLEAN                (0x01)
#define ASN1_TAG_INTEGER                (0x02)
#define ASN1_TAG_BIT_STRING             (0x03)
#define ASN1_TAG_OCTET_STRING           (0x04)
#define ASN1_TAG_NULL                   (0x05)
#define ASN1_TAG_OBJECT_ID              (0x06)
#define ASN1_TAG_ENUMERATED             (0x0A)
#define ASN1_TAG_UTF8_STRING            (0x0C)
#define ASN1_TAG_SEQUENCE               (0x10)
#define ASN1_TAG_SET                    (0x11)
#define ASN1_TAG_NUMERIC_STRING         (0x12)
#define ASN1_TAG_PRINTABLE_STRING       (0x13)
#define ASN1_TAG_TELETEX_STRING         (0x14)
#define ASN1_TAG_IA5_STRING             (0x16)
#define ASN1_TAG_UTC_TIME               (0x17)
#define ASN1_TAG_GENERALIZED_TIME       (0x18)
#define ASN1_TAG_VISIBLE_STRING         (0x1A)
#define ASN1_TAG_GENERAL_STRING         (0x1B)
#define ASN1_TAG_UNIVERSAL_STRING       (0x1C)
#define ASN1_TAG_BMP_STRING             (0x1E)

#endif /* FOIL_ASN1_P_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
