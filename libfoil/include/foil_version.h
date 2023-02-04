/*
 * Copyright (C) 2022-2023 by Slava Monich <slava@monich.com>
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

#ifndef FOIL_VERSION_H
#define FOIL_VERSION_H

#include <glib.h>

G_BEGIN_DECLS

/*
 * This header first appeared in version 1.0.24 therefore version checks
 * in the code which is supposed to be compilable against earlier versions
 * of libfoil should look like this:
 *
 * #if defined(FOIL_VERSION) && FOIL_VERSION > FOIL_VERSION_WORD(1,0,24)
 * ...
 * #endif
 *
 * of better like this:
 *
 * #ifdef FOIL_VERSION_1_0_24
 * ...
 * #endif
 *
 * FOIL_VERSION_X_Y_Z macros will be added with each release. The fact that
 * such macro is defined means that you're compiling against libfoil version
 * X.Y.Z or greater.
 */

#define FOIL_VERSION_MAJOR   1
#define FOIL_VERSION_MINOR   0
#define FOIL_VERSION_RELEASE 27
#define FOIL_VERSION_STRING  "1.0.27"

/* Version as a single word */
#define FOIL_VERSION_WORD(v1,v2,v3) \
    ((((v1) & 0x7f) << 24) | \
     (((v2) & 0xfff) << 12) | \
      ((v3) & 0xfff))

#define FOIL_VERSION_GET_MAJOR(v)   (((v) >> 24) & 0x7f)
#define FOIL_VERSION_GET_MINOR(v)   (((v) >> 12) & 0xfff)
#define FOIL_VERSION_GET_RELEASE(v)  ((v) & 0xfff)

/*
 * Function for run-time version detection in case if you're linking
 * against the dynamic library.
 */
unsigned int
foil_version(
    void); /* Since 1.0.24 */

/* Current version as a single word */
#define FOIL_VERSION FOIL_VERSION_WORD \
    (FOIL_VERSION_MAJOR, FOIL_VERSION_MINOR, FOIL_VERSION_RELEASE)

/* Specific versions */
#define FOIL_VERSION_1_0_24 FOIL_VERSION_WORD(1,0,24)
#define FOIL_VERSION_1_0_25 FOIL_VERSION_WORD(1,0,25)
#define FOIL_VERSION_1_0_26 FOIL_VERSION_WORD(1,0,26)
#define FOIL_VERSION_1_0_27 FOIL_VERSION_WORD(1,0,27)

G_END_DECLS

#endif /* FOIL_VERSION_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
