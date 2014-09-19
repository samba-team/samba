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
#include "system/locale.h"
#undef strncasecmp
#undef strcasemp

/**
 * @file
 * @brief String utilities.
 **/

/**
 * Parse a string containing a boolean value.
 *
 * val will be set to the read value.
 *
 * @retval true if a boolean value was parsed, false otherwise.
 */
_PUBLIC_ bool conv_str_bool(const char * str, bool * val)
{
	char *	end = NULL;
	long	lval;

	if (str == NULL || *str == '\0') {
		return false;
	}

	lval = strtol(str, &end, 10 /* base */);
	if (end == NULL || *end != '\0' || end == str) {
		return set_boolean(str, val);
	}

	*val = (lval) ? true : false;
	return true;
}

/**
 * Convert a size specification like 16K into an integral number of bytes. 
 **/
_PUBLIC_ bool conv_str_size_error(const char * str, uint64_t * val)
{
	char *		    end = NULL;
	unsigned long long  lval;

	if (str == NULL || *str == '\0') {
		return false;
	}

	lval = strtoull(str, &end, 10 /* base */);
	if (end == NULL || end == str) {
		return false;
	}

	if (*end) {
		if (strwicmp(end, "K") == 0) {
			lval *= 1024ULL;
		} else if (strwicmp(end, "M") == 0) {
			lval *= (1024ULL * 1024ULL);
		} else if (strwicmp(end, "G") == 0) {
			lval *= (1024ULL * 1024ULL * 1024ULL);
		} else if (strwicmp(end, "T") == 0) {
			lval *= (1024ULL * 1024ULL * 1024ULL * 1024ULL);
		} else if (strwicmp(end, "P") == 0) {
			lval *= (1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL);
		} else {
			return false;
		}
	}

	*val = (uint64_t)lval;
	return true;
}

/**
 * Parse a uint64_t value from a string
 *
 * val will be set to the value read.
 *
 * @retval true if parsing was successful, false otherwise
 */
_PUBLIC_ bool conv_str_u64(const char * str, uint64_t * val)
{
	char *		    end = NULL;
	unsigned long long  lval;

	if (str == NULL || *str == '\0') {
		return false;
	}

	lval = strtoull(str, &end, 10 /* base */);
	if (end == NULL || *end != '\0' || end == str) {
		return false;
	}

	*val = (uint64_t)lval;
	return true;
}

/**
 * Compare 2 strings.
 *
 * @note The comparison is case-insensitive.
 **/
_PUBLIC_ bool strequal(const char *s1, const char *s2)
{
	if (s1 == s2)
		return true;
	if (!s1 || !s2)
		return false;
  
	return strcasecmp_m(s1,s2) == 0;
}

/**
 * @file
 * @brief String utilities.
 **/

static bool next_token_internal_talloc(TALLOC_CTX *ctx,
				const char **ptr,
                                char **pp_buff,
                                const char *sep,
                                bool ltrim)
{
	const char *s;
	const char *saved_s;
	char *pbuf;
	bool quoted;
	size_t len=1;

	*pp_buff = NULL;
	if (!ptr) {
		return(false);
	}

	s = *ptr;

	/* default to simple separators */
	if (!sep) {
		sep = " \t\n\r";
	}

	/* find the first non sep char, if left-trimming is requested */
	if (ltrim) {
		while (*s && strchr_m(sep,*s)) {
			s++;
		}
	}

	/* nothing left? */
	if (!*s) {
		return false;
	}

	/* When restarting we need to go from here. */
	saved_s = s;

	/* Work out the length needed. */
	for (quoted = false; *s &&
			(quoted || !strchr_m(sep,*s)); s++) {
		if (*s == '\"') {
			quoted = !quoted;
		} else {
			len++;
		}
	}

	/* We started with len = 1 so we have space for the nul. */
	*pp_buff = talloc_array(ctx, char, len);
	if (!*pp_buff) {
		return false;
	}

	/* copy over the token */
	pbuf = *pp_buff;
	s = saved_s;
	for (quoted = false; *s &&
			(quoted || !strchr_m(sep,*s)); s++) {
		if ( *s == '\"' ) {
			quoted = !quoted;
		} else {
			*pbuf++ = *s;
		}
	}

	*ptr = (*s) ? s+1 : s;
	*pbuf = 0;

	return true;
}

bool next_token_talloc(TALLOC_CTX *ctx,
			const char **ptr,
			char **pp_buff,
			const char *sep)
{
	return next_token_internal_talloc(ctx, ptr, pp_buff, sep, true);
}

/*
 * Get the next token from a string, return false if none found.  Handles
 * double-quotes.  This version does not trim leading separator characters
 * before looking for a token.
 */

bool next_token_no_ltrim_talloc(TALLOC_CTX *ctx,
			const char **ptr,
			char **pp_buff,
			const char *sep)
{
	return next_token_internal_talloc(ctx, ptr, pp_buff, sep, false);
}

/**
 * Get the next token from a string, return False if none found.
 * Handles double-quotes.
 *
 * Based on a routine by GJC@VILLAGE.COM.
 * Extensively modified by Andrew.Tridgell@anu.edu.au
 **/
_PUBLIC_ bool next_token(const char **ptr,char *buff, const char *sep, size_t bufsize)
{
	const char *s;
	bool quoted;
	size_t len=1;

	if (!ptr)
		return false;

	s = *ptr;

	/* default to simple separators */
	if (!sep)
		sep = " \t\n\r";

	/* find the first non sep char */
	while (*s && strchr_m(sep,*s))
		s++;

	/* nothing left? */
	if (!*s)
		return false;

	/* copy over the token */
	for (quoted = false; len < bufsize && *s && (quoted || !strchr_m(sep,*s)); s++) {
		if (*s == '\"') {
			quoted = !quoted;
		} else {
			len++;
			*buff++ = *s;
		}
	}

	*ptr = (*s) ? s+1 : s;
	*buff = 0;

	return true;
}

/**
 Set a boolean variable from the text value stored in the passed string.
 Returns true in success, false if the passed string does not correctly
 represent a boolean.
**/

_PUBLIC_ bool set_boolean(const char *boolean_string, bool *boolean)
{
	if (strwicmp(boolean_string, "yes") == 0 ||
	    strwicmp(boolean_string, "true") == 0 ||
	    strwicmp(boolean_string, "on") == 0 ||
	    strwicmp(boolean_string, "1") == 0) {
		*boolean = true;
		return true;
	} else if (strwicmp(boolean_string, "no") == 0 ||
		   strwicmp(boolean_string, "false") == 0 ||
		   strwicmp(boolean_string, "off") == 0 ||
		   strwicmp(boolean_string, "0") == 0) {
		*boolean = false;
		return true;
	}
	return false;
}

/**
return the number of bytes occupied by a buffer in CH_UTF16 format
the result includes the null termination
**/
_PUBLIC_ size_t utf16_len(const void *buf)
{
	size_t len;

	for (len = 0; SVAL(buf,len); len += 2) ;

	return len + 2;
}

/**
return the number of bytes occupied by a buffer in CH_UTF16 format
the result includes the null termination
limited by 'n' bytes
**/
_PUBLIC_ size_t utf16_len_n(const void *src, size_t n)
{
	size_t len;

	for (len = 0; (len+2 < n) && SVAL(src, len); len += 2) ;

	if (len+2 <= n) {
		len += 2;
	}

	return len;
}
