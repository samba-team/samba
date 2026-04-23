/*
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Simo Sorce      2001-2002
   Copyright (C) Martin Pool     2003
   Copyright (C) James Peach	 2006
   Copyright (C) Jeremy Allison  1992-2007

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

/**
 Similar to string_sub2, but it will accept only allocated strings
 and may realloc them so pay attention at what you pass on no
 pointers inside strings, no const may be passed
 as string.
**/

char *realloc_string_sub2(char *string,
			const char *pattern,
			const char *insert,
			bool remove_unsafe_characters,
			bool allow_trailing_dollar)
{
	const char *unsafe_characters = NULL;
	char safe_character = '\0';
	bool ok;

	if (!insert || !pattern || !*pattern || !string || !*string)
		return NULL;

	if (remove_unsafe_characters) {
		unsafe_characters = STRING_SUB_UNSAFE_CHARACTERS;
		safe_character = '_';
	}

	ok = realloc_string_sub_raw(&string,
				    pattern,
				    insert,
				    false,  /* replace_once */
				    allow_trailing_dollar,
				    unsafe_characters,
				    safe_character);
	if (!ok) {
		DBG_ERR("out of memory, realloc_string_sub_raw()!\n");
		/*
		 * The calling convention of realloc_string_sub2()
		 * is very strange regarding stale string pointers.
		 *
		 * It is assumed the given string was allocated
		 * on talloc_tos(), so we just don't touch
		 * it at all here...
		 */
		return NULL;
	}

	return string;
}

char *realloc_string_sub(char *string,
			const char *pattern,
			const char *insert)
{
	return realloc_string_sub2(string, pattern, insert, true, false);
}
