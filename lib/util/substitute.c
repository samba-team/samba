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
#include "system/locale.h"
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

static inline
char mask_unsafe_character(char in,
			   bool is_last,
			   bool allow_trailing_dollar,
			   const char *unsafe_characters,
			   char safe_out)
{
	const char *unsafe = NULL;

	if (unsafe_characters == NULL) {
		return in;
	}

	/* allow a trailing $ (as in machine accounts) */
	if (allow_trailing_dollar && is_last && in == '$') {
		return in;
	}

	if (iscntrl(in)) {
		return safe_out;
	}

	unsafe = strchr(unsafe_characters, in);
	if (unsafe != NULL) {
		return safe_out;
	}

	/* ok */
	return in;
}

/**
 Substitute a string for a pattern in another string. Make sure there is
 enough room!

 This routine looks for pattern in s and replaces it with
 insert. It may do multiple replacements or just one.

 Any of STRING_SUB_UNSAFE_CHARACTERS and any character
 caught by calling iscntrl() in the insert string are replaced with _

 if len==0 then the string cannot be extended. This is different from the old
 use of len==0 which was for no length checks to be done.
**/

void string_sub(char *s, const char *pattern, const char *insert, size_t len)
{
	const char *unsafe_characters = STRING_SUB_UNSAFE_CHARACTERS;
	char safe_character = '_';
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
			/*
			 * Without allow_trailing_dollar we don't
			 * need to calculate is_last...
			 */
			const bool is_last = false;
			const bool allow_trailing_dollar = false;

			p[i] = mask_unsafe_character(insert[i],
						     is_last,
						     allow_trailing_dollar,
						     unsafe_characters,
						     safe_character);
		}
		s = p + li;
		ls = ls + li - lp;
	}
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

bool realloc_string_sub_raw(char **_string,
			    const char *pattern,
			    const char *insert,
			    bool replace_once,
			    bool allow_trailing_dollar,
			    const char *unsafe_characters,
			    char safe_character)
{
	char *p = NULL;
	char *s = NULL;
	char *string = NULL;
	ssize_t ls,lp,li,ld, i;

	if (!insert || !pattern || !*pattern || !_string|| !*_string) {
		return false;
	}

	s = string = *_string;

	ls = (ssize_t)strlen(s);
	lp = (ssize_t)strlen(pattern);
	li = (ssize_t)strlen(insert);
	ld = li - lp;

	while ((p = strstr_m(s,pattern))) {
		if (ld > 0) {
			ptrdiff_t offset = PTR_DIFF(s,string);
			string = talloc_realloc(NULL, string, char, ls + ld + 1);
			if (!string) {
				DBG_ERR("out of memory(realloc)!\n");
				return false;
			}
			*_string = string;
			p = string + offset + (p - s);
		}
		if (li != lp) {
			memmove(p+li,p+lp,strlen(p+lp)+1);
		}
		for (i=0; i < li; i++) {
			bool is_last = (i == li - 1);

			p[i] = mask_unsafe_character(insert[i],
						     is_last,
						     allow_trailing_dollar,
						     unsafe_characters,
						     safe_character);
		}
		s = p + li;
		ls += ld;

		if (replace_once) {
			break;
		}
	}
	return true;
}

char *talloc_string_sub2(TALLOC_CTX *mem_ctx,
			 const char *src,
			 const char *pattern,
			 const char *insert,
			 bool remove_unsafe_characters,
			 bool replace_once,
			 bool allow_trailing_dollar)
{
	const char *unsafe_characters = NULL;
	char safe_character = '\0';
	char *string = NULL;
	bool ok;

	if (!insert || !pattern || !*pattern || !src) {
		return NULL;
	}

	if (remove_unsafe_characters) {
		unsafe_characters = STRING_SUB_UNSAFE_CHARACTERS;
		safe_character = '_';
	}

	string = talloc_strdup(mem_ctx, src);
	if (string == NULL) {
		DBG_ERR("out of memory, talloc_strdup(src)!\n");
		return NULL;
	}

	ok = realloc_string_sub_raw(&string,
				    pattern,
				    insert,
				    replace_once,
				    allow_trailing_dollar,
				    unsafe_characters,
				    safe_character);
	if (!ok) {
		TALLOC_FREE(string);
		DBG_ERR("out of memory, realloc_string_sub_raw()!\n");
		return NULL;
	}

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
