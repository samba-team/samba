/*
   Unix SMB/CIFS implementation.

   fixed string functions

   Copyright (C) Igor Vergeichik <iverg@mail.ru> 2001
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Simo Sorce 2001
   Copyright (C) Martin Pool 2003

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

#include "includes.h"

size_t push_ascii_fstring(void *dest, const char *src)
{
	return push_ascii(dest, src, sizeof(fstring), STR_TERMINATE);
}

/********************************************************************
 Push an nstring (a netbios string)
 this function uses convert_string_error() to avoid common debug
 warnings where is unable to convert strings to CH_DOS. The target
 string is truncated at the first character that cannot be converted
 The target is always null terminated.
********************************************************************/

size_t push_ascii_nstring(void *dest, const char *src)
{
	size_t converted_size = 0;
	bool ret = convert_string_error(CH_UNIX, CH_DOS, src, -1, dest, sizeof(nstring), &converted_size);
	if (ret) {
		SCVAL(dest, sizeof(nstring)-1, 0);
	} else {
		SCVAL(dest, 0, 0);
	}
	return ret ? converted_size : (size_t)-1;
}

size_t pull_ascii_fstring(char *dest, const void *src)
{
	return pull_ascii(dest, src, sizeof(fstring), -1, STR_TERMINATE);
}

/* When pulling an nstring it can expand into a larger size (dos cp -> utf8). Cope with this. */

size_t pull_ascii_nstring(char *dest, size_t dest_len, const void *src)
{
	return pull_ascii(dest, src, dest_len, sizeof(nstring), STR_TERMINATE);
}

