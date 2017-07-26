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

void fstring_sub(char *s,const char *pattern,const char *insert)
{
	string_sub(s, pattern, insert, sizeof(fstring));
}

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
	char *p, *in;
	char *s;
	ssize_t ls,lp,li,ld, i;

	if (!insert || !pattern || !*pattern || !string || !*string)
		return NULL;

	s = string;

	in = talloc_strdup(talloc_tos(), insert);
	if (!in) {
		DEBUG(0, ("realloc_string_sub: out of memory!\n"));
		return NULL;
	}
	ls = (ssize_t)strlen(s);
	lp = (ssize_t)strlen(pattern);
	li = (ssize_t)strlen(insert);
	ld = li - lp;
	for (i=0;i<li;i++) {
		switch (in[i]) {
			case '$':
				/* allow a trailing $
				 * (as in machine accounts) */
				if (allow_trailing_dollar && (i == li - 1 )) {
					break;
				}
				FALL_THROUGH;
			case '`':
			case '"':
			case '\'':
			case ';':
			case '%':
			case '\r':
			case '\n':
				if ( remove_unsafe_characters ) {
					in[i] = '_';
					break;
				}
				FALL_THROUGH;
			default:
				/* ok */
				break;
		}
	}

	while ((p = strstr_m(s,pattern))) {
		if (ld > 0) {
			int offset = PTR_DIFF(s,string);
			string = talloc_realloc(NULL, string, char, ls + ld + 1);
			if (!string) {
				DEBUG(0, ("realloc_string_sub: "
					"out of memory!\n"));
				talloc_free(in);
				return NULL;
			}
			p = string + offset + (p - s);
		}
		if (li != lp) {
			memmove(p+li,p+lp,strlen(p+lp)+1);
		}
		memcpy(p, in, li);
		s = p + li;
		ls += ld;
	}
	talloc_free(in);
	return string;
}

char *realloc_string_sub(char *string,
			const char *pattern,
			const char *insert)
{
	return realloc_string_sub2(string, pattern, insert, true, false);
}
