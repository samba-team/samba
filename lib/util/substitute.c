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

#include "includes.h"

/**
 * @file
 * @brief Substitute utilities.
 **/

/**
 Substitute a string for a pattern in another string. Make sure there is
 enough room!

 This routine looks for pattern in s and replaces it with
 insert. It may do multiple replacements or just one.

 Any of " ; ' $ or ` in the insert string are replaced with _
 if len==0 then the string cannot be extended. This is different from the old
 use of len==0 which was for no length checks to be done.
**/

static void string_sub2(char *s,const char *pattern, const char *insert, size_t len,
			bool remove_unsafe_characters, bool replace_once,
			bool allow_trailing_dollar)
{
	char *p;
	ssize_t ls, lp, li, i;

	if (!insert || !pattern || !*pattern || !s)
		return;

	ls = (ssize_t)strlen(s);
	lp = (ssize_t)strlen(pattern);
	li = (ssize_t)strlen(insert);

	if (len == 0)
		len = ls + 1; /* len is number of *bytes* */

	while (lp <= ls && (p = strstr_m(s,pattern))) {
		if (ls + (li-lp) >= len) {
			DEBUG(0,("ERROR: string overflow by "
				"%d in string_sub(%.50s, %d)\n",
				 (int)(ls + (li-lp) - len),
				 pattern, (int)len));
			break;
		}
		if (li != lp) {
			memmove(p+li,p+lp,strlen(p+lp)+1);
		}
		for (i=0;i<li;i++) {
			switch (insert[i]) {
			case '$':
				/* allow a trailing $
				 * (as in machine accounts) */
				if (allow_trailing_dollar && (i == li - 1 )) {
					p[i] = insert[i];
					break;
				}
			case '`':
			case '"':
			case '\'':
			case ';':
			case '%':
			case '\r':
			case '\n':
				if ( remove_unsafe_characters ) {
					p[i] = '_';
					/* yes this break should be here
					 * since we want to fall throw if
					 * not replacing unsafe chars */
					break;
				}
			default:
				p[i] = insert[i];
			}
		}
		s = p + li;
		ls += (li-lp);

		if (replace_once)
			break;
	}
}

void string_sub_once(char *s, const char *pattern,
		const char *insert, size_t len)
{
	string_sub2( s, pattern, insert, len, true, true, false );
}

void string_sub(char *s,const char *pattern, const char *insert, size_t len)
{
	string_sub2( s, pattern, insert, len, true, false, false );
}

/**
 * Talloc'ed version of string_sub
 */
_PUBLIC_ char *string_sub_talloc(TALLOC_CTX *mem_ctx, const char *s, 
				const char *pattern, const char *insert)
{
	const char *p;
	char *ret;
	size_t len, alloc_len;

	if (insert == NULL || pattern == NULL || !*pattern || s == NULL)
		return NULL;

	/* determine length needed */
	len = strlen(s);
	
	for (p = strstr(s, pattern); p != NULL; 
	     p = strstr(p+strlen(pattern), pattern)) {
		len += strlen(insert) - strlen(pattern);
	}

	alloc_len = MAX(len, strlen(s))+1;
	ret = talloc_array(mem_ctx, char, alloc_len);
	if (ret == NULL)
		return NULL;
	strncpy(ret, s, alloc_len);
	string_sub(ret, pattern, insert, alloc_len);

	ret = talloc_realloc(mem_ctx, ret, char, len+1);
	if (ret == NULL)
		return NULL;

	SMB_ASSERT(ret[len] == '\0');

	talloc_set_name_const(ret, ret);

	return ret;
}

/**
 Similar to string_sub() but allows for any character to be substituted. 
 Use with caution!
 if len==0 then the string cannot be extended. This is different from the old
 use of len==0 which was for no length checks to be done.
**/

_PUBLIC_ void all_string_sub(char *s,const char *pattern,const char *insert, size_t len)
{
	char *p;
	ssize_t ls,lp,li;

	if (!insert || !pattern || !s)
		return;

	ls = (ssize_t)strlen(s);
	lp = (ssize_t)strlen(pattern);
	li = (ssize_t)strlen(insert);

	if (!*pattern)
		return;

	if (len == 0)
		len = ls + 1; /* len is number of *bytes* */

	while (lp <= ls && (p = strstr_m(s,pattern))) {
		if (ls + (li-lp) >= len) {
			DEBUG(0,("ERROR: string overflow by "
				"%d in all_string_sub(%.50s, %d)\n",
				 (int)(ls + (li-lp) - len),
				 pattern, (int)len));
			break;
		}
		if (li != lp) {
			memmove(p+li,p+lp,strlen(p+lp)+1);
		}
		memcpy(p, insert, li);
		s = p + li;
		ls += (li-lp);
	}
}
