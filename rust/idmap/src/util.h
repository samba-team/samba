/*
   Himmelblaud

   ID-mapping library utils

   Copyright (C) David Mulder 2024

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _UTILS_H
#define _UTILS_H

#include <string.h>
#include <stdint.h>

static inline void
safealign_memcpy(void *dest, const void *src, size_t n, size_t *counter)
{
    memcpy(dest, src, n);
    if (counter) {
        *counter += n;
    }
}

#define SAFEALIGN_COPY_UINT32(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(uint32_t), pctr)

#if defined(__GNUC__) && __GNUC__ >= 7
 #define SSS_ATTRIBUTE_FALLTHROUGH __attribute__ ((fallthrough))
#else
 #define SSS_ATTRIBUTE_FALLTHROUGH
#endif

#endif /* _UTILS_H */
