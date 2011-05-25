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

/* this is used to prevent lots of mallocs of size 1 */
static const char null_string[] = "";

/**
 Set a string value, allocing the space for the string
**/

static bool string_init(char **dest,const char *src)
{
	size_t l;

	if (!src)
		src = "";

	l = strlen(src);

	if (l == 0) {
		*dest = discard_const_p(char, null_string);
	} else {
		(*dest) = SMB_STRDUP(src);
		if ((*dest) == NULL) {
			DEBUG(0,("Out of memory in string_init\n"));
			return false;
		}
	}
	return(true);
}

/**
 Free a string value.
**/

void string_free(char **s)
{
	if (!s || !(*s))
		return;
	if (*s == null_string)
		*s = NULL;
	SAFE_FREE(*s);
}

/**
 Set a string value, deallocating any existing space, and allocing the space
 for the string
**/

bool string_set(char **dest,const char *src)
{
	string_free(dest);
	return(string_init(dest,src));
}
