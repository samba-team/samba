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
#include "lib/util/samba_util.h"
#include "system/locale.h"
#include "smb_strtox.h"
#undef strncasecmp
#undef strcasemp

/**
 * @file
 * @brief String utilities.
 **/

/*
 * The number of fractional digits we take into account in
 * conv_str_size_error(). Everything beyond that is truncated, as it
 * cannot influence the resulting byte count anyway. The limit keeps
 * the scale below 10^9, which is what the overflow reasoning in
 * conv_str_size_error() relies on.
 */
#define CONV_STR_SIZE_MAX_SCALE 1000000000ULL

/**
 * Convert a size specification like 16K or 16.5M into a number of bytes.
 * Both integer and fractional values are accepted, with an optional
 * K/M/G/T/P suffix. Fractional parts are truncated towards zero.
 **/
_PUBLIC_ bool conv_str_size_error(const char * str, uint64_t * val)
{
	char *end = NULL;
	unsigned long long lval;
	uint64_t mult = 1;
	uint64_t frac = 0;	/* the fractional digits as an integer */
	uint64_t scale = 1;	/* 10^(number of fractional digits) */
	uint64_t bytes;
	int error = 0;

	if (str == NULL || *str == '\0') {
		return false;
	}

	lval = smb_strtoull(str, &end, 10, &error, SMB_STR_STANDARD);
	if (error != 0) {
		return false;
	}

	/*
	 * Parse the optional fractional part ourselves instead of using
	 * strtod(). strtod() honours LC_NUMERIC, and smbd calls
	 * setlocale(LC_ALL, "") via smb_init_locale(), so "1.5M" would be
	 * rejected and "1,5M" accepted when smbd happens to run in e.g. a
	 * de_DE locale. An smb.conf has to parse identically everywhere.
	 */
	if (*end == '.') {
		end++;
		if (!isdigit((unsigned char)*end)) {
			return false;
		}
		while (isdigit((unsigned char)*end)) {
			if (scale < CONV_STR_SIZE_MAX_SCALE) {
				frac = frac * 10 + (uint64_t)(*end - '0');
				scale *= 10;
			}
			end++;
		}
	}

	if (*end != '\0') {
		if (strwicmp(end, "K") == 0) {
			mult = 1024ULL;
		} else if (strwicmp(end, "M") == 0) {
			mult = 1024ULL * 1024ULL;
		} else if (strwicmp(end, "G") == 0) {
			mult = 1024ULL * 1024ULL * 1024ULL;
		} else if (strwicmp(end, "T") == 0) {
			mult = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
		} else if (strwicmp(end, "P") == 0) {
			mult = 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
		} else {
			return false;
		}
	}

	if (lval > UINT64_MAX / mult) {
		return false;
	}
	bytes = (uint64_t)lval * mult;

	if (frac != 0) {
		/*
		 * Add frac/scale * mult without leaving integer
		 * arithmetic. Both terms are bounded: frac < scale, so
		 * (mult / scale) * frac <= mult, and (mult % scale) and
		 * frac are both below 10^9, so their product fits.
		 */
		uint64_t add = (mult / scale) * frac +
			       ((mult % scale) * frac) / scale;

		if (add > UINT64_MAX - bytes) {
			return false;
		}
		bytes += add;
	}

	*val = bytes;
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

/**
 * Get the next token from a string, return False if none found.
 * Handles double-quotes.
 *
 * Based on a routine by GJC@VILLAGE.COM.
 * Extensively modified by Andrew.Tridgell@anu.edu.au
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
	}
	if (strwicmp(boolean_string, "no") == 0 ||
	    strwicmp(boolean_string, "false") == 0 ||
	    strwicmp(boolean_string, "off") == 0 ||
	    strwicmp(boolean_string, "0") == 0) {
		*boolean = false;
		return true;
	}
	return false;
}

_PUBLIC_ const char *strstr_for_invalid_account_characters(const char *name)
{
	/*
	 * Return a pointer to the first invalid character in the
	 * sAMAccountName, or NULL if the whole name is valid.
	 *
	 * The rules here are based on
	 *
	 * https://social.technet.microsoft.com/wiki/contents/articles/11216.active-directory-requirements-for-creating-objects.aspx
	 */
	size_t i;

	for (i = 0; name[i] != '\0'; i++) {
		uint8_t c = name[i];
		const char *p = NULL;

		if (iscntrl(c)) {
			return &name[i];
		}

		p = strchr("\"[]:;|=+*?<>/\\,", c);
		if (p != NULL) {
			return &name[i];
		}
	}

	if (i == 0) {
		return &name[i];
	}

	if (name[i - 1] == '.') {
		i -= 1;
		return &name[i];
	}

	return NULL;
}
