/*
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Simo Sorce      2001-2002
   Copyright (C) Martin Pool     2003
   Copyright (C) James Peach	 2005

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

#ifndef _SAMBA_SUBSTITUTE_H_
#define _SAMBA_SUBSTITUTE_H_

#include <talloc.h>

/**
 Substitute a string for a pattern in another string. Make sure there is
 enough room!

 This routine looks for pattern in s and replaces it with
 insert. It may do multiple replacements.

 Any of " ; ' $ or ` in the insert string are replaced with _
 if len==0 then the string cannot be extended. This is different from the old
 use of len==0 which was for no length checks to be done.
**/
void string_sub(char *s,const char *pattern, const char *insert, size_t len);

void string_sub_once(char *s, const char *pattern,
		     const char *insert, size_t len);

char *string_sub_talloc(TALLOC_CTX *mem_ctx, const char *s,
			const char *pattern, const char *insert);

/**
 Similar to string_sub() but allows for any character to be substituted.
 Use with caution!
 if len==0 then the string cannot be extended. This is different from the old
 use of len==0 which was for no length checks to be done.
**/
void all_string_sub(char *s,const char *pattern,const char *insert, size_t len);

#endif /* _SAMBA_SUBSTITUTE_H_ */
