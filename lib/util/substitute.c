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

#include "replace.h"
#include "debug.h"
#ifndef SAMBA_UTIL_CORE_ONLY
#include "charset/charset.h"
#else
#include "charset_compat.h"
#endif
#include "substitute.h"

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
	size_t ls, lp, li, i;

	if (!insert || !pattern || !*pattern || !s)
		return;

	ls = strlen(s);
	lp = strlen(pattern);
	li = strlen(insert);

	if (len == 0)
		len = ls + 1; /* len is number of *bytes* */

	while (lp <= ls && (p = strstr_m(s,pattern))) {
		if (ls + li - lp >= len) {
			DBG_ERR("ERROR: string overflow by "
				"%zu in string_sub(%.50s, %zu)\n",
				ls + li - lp + 1 - len,
				pattern,
				len);
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
				FALL_THROUGH;
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
				FALL_THROUGH;
			default:
				p[i] = insert[i];
			}
		}
		s = p + li;
		ls = ls + li - lp;

		if (replace_once)
			break;
	}
}

void string_sub(char *s,const char *pattern, const char *insert, size_t len)
{
	string_sub2( s, pattern, insert, len, true, false, false );
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
	size_t ls,lp,li;

	if (!insert || !pattern || !s)
		return;

	ls = strlen(s);
	lp = strlen(pattern);
	li = strlen(insert);

	if (!*pattern)
		return;

	if (len == 0)
		len = ls + 1; /* len is number of *bytes* */

	while (lp <= ls && (p = strstr_m(s,pattern))) {
		if (ls + li - lp >= len) {
			DBG_ERR("ERROR: string overflow by "
				"%zu in all_string_sub(%.50s, %zu)\n",
				ls + li - lp + 1 - len,
				pattern,
				len);
			break;
		}
		if (li != lp) {
			memmove(p+li,p+lp,strlen(p+lp)+1);
		}
		memcpy(p, insert, li);
		s = p + li;
		ls = ls + li - lp;
	}
}

/*
 * Internal guts of talloc_string_sub and talloc_all_string_sub.
 * talloc version of string_sub2.
 */

char *talloc_string_sub2(TALLOC_CTX *mem_ctx, const char *src,
			const char *pattern,
			const char *insert,
			bool remove_unsafe_characters,
			bool replace_once,
			bool allow_trailing_dollar)
{
	char *p, *in;
	char *s;
	char *string;
	ssize_t ls,lp,li,ld, i;

	if (!insert || !pattern || !*pattern || !src) {
		return NULL;
	}

	string = talloc_strdup(mem_ctx, src);
	if (string == NULL) {
		DEBUG(0, ("talloc_string_sub2: "
			"talloc_strdup failed\n"));
		return NULL;
	}

	s = string;

	in = talloc_strdup(mem_ctx, insert);
	if (!in) {
		DEBUG(0, ("talloc_string_sub2: ENOMEM\n"));
		talloc_free(string);
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
				if (remove_unsafe_characters) {
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
			string = (char *)talloc_realloc_size(mem_ctx, string,
							ls + ld + 1);
			if (!string) {
				DEBUG(0, ("talloc_string_sub: out of "
					  "memory!\n"));
				TALLOC_FREE(in);
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

		if (replace_once) {
			break;
		}
	}
	TALLOC_FREE(in);
	return string;
}

/* Same as string_sub, but returns a talloc'ed string */

char *talloc_string_sub(TALLOC_CTX *mem_ctx,
			const char *src,
			const char *pattern,
			const char *insert)
{
	return talloc_string_sub2(mem_ctx, src, pattern, insert,
			true, false, false);
}

char *talloc_all_string_sub(TALLOC_CTX *ctx,
				const char *src,
				const char *pattern,
				const char *insert)
{
	return talloc_string_sub2(ctx, src, pattern, insert,
			false, false, false);
}
