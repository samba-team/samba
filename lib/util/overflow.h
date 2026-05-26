/*
 * Unix SMB/CIFS implementation.
 * Samba utility functions
 *
 * Copyright (C) Gary Lockyer 2026
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LIB_UTIL_OVERFLOW_H__
#define __LIB_UTIL_OVERFLOW_H__

#include <stdint.h>
/**
* Will adding offset to base pointer, result in a pointer that points
* past end, or overflow
*
* @param base   The pointer to the start of the range
* @param end    The pointer to the end of the range
* @param offset The offset being added to base
*
* @return True  resulting pointer is between base and end
*         False resulting pointer is after end
*/
#define offset_outside_range(base, end, offset) \
	(((end) - (base)) < (offset))

/**
* Will adding offset to base pointer, result in overflow.
* Pointer arithmetic overflow is undefined behaviour and some compilers
* (i.e. Clang from version 20) will treat an overflow check like the following:
*    (ptr + offset) < ptr
* as always evaluating to false
*
* @param ptr    The pointer to check
* @param offset The offset being added to ptr
* @param type   Type being pointed to by pointer
*               needed to cast INTPTR_MAX to the correct type
*
* @return True  pointer would over flow
*         False pointer would not overflow
*/
#define ptr_overflow(ptr, offset, type) \
	offset_outside_range((ptr), ((type*)INTPTR_MAX), (offset))

#endif
