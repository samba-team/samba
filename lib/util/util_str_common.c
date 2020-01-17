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
Do a case-insensitive, whitespace-ignoring ASCII string compare.
**/
_PUBLIC_ int strwicmp(const char *psz1, const char *psz2)
{
	/* if BOTH strings are NULL, return TRUE, if ONE is NULL return */
	/* appropriate value. */
	if (psz1 == psz2)
		return (0);
	else if (psz1 == NULL)
		return (-1);
	else if (psz2 == NULL)
		return (1);

	/* sync the strings on first non-whitespace */
	while (1) {
		while (isspace((int)*psz1))
			psz1++;
		while (isspace((int)*psz2))
			psz2++;

		/*
		 * This does not do a genuine multi-byte comparison,
		 * instead it just uses the fast-path for ASCII in
		 * these common routines
		 */
		if (toupper_m((unsigned char)*psz1) != toupper_m((unsigned char)*psz2)
		    || *psz1 == '\0'
		    || *psz2 == '\0')
			break;
		psz1++;
		psz2++;
	}
	return (*psz1 - *psz2);
}

_PUBLIC_ size_t ucs2_align(const void *base_ptr, const void *p, int flags)
{
	if (flags & (STR_NOALIGN|STR_ASCII))
		return 0;
	return PTR_DIFF(p, base_ptr) & 1;
}

/**
 String replace.
 NOTE: oldc and newc must be 7 bit characters
**/
void string_replace( char *s, char oldc, char newc )
{
	char *p;

	/* this is quite a common operation, so we want it to be
	   fast. We optimise for the ascii case, knowing that all our
	   supported multi-byte character sets are ascii-compatible
	   (ie. they match for the first 128 chars) */

	for (p = s; *p; p++) {
		if (*p & 0x80) /* mb string - slow path. */
			break;
		if (*p == oldc) {
			*p = newc;
		}
	}

	if (!*p)
		return;

	/* Slow (mb) path. */
#ifdef BROKEN_UNICODE_COMPOSE_CHARACTERS
	/* With compose characters we must restart from the beginning. JRA. */
	p = s;
#endif

	while (*p) {
		size_t c_size;
		next_codepoint(p, &c_size);

		if (c_size == 1) {
			if (*p == oldc) {
				*p = newc;
			}
		}
		p += c_size;
	}
}


/**
 Paranoid strcpy into a buffer of given length (includes terminating
 zero. Strips out all but 'a-Z0-9' and the character in other_safe_chars
 and replaces with '_'. Deliberately does *NOT* check for multibyte
 characters. Treats src as an array of bytes, not as a multibyte
 string. Any byte >0x7f is automatically converted to '_'.
 other_safe_chars must also contain an ascii string (bytes<0x7f).
**/

char *alpha_strcpy(char *dest,
		   const char *src,
		   const char *other_safe_chars,
		   size_t maxlength)
{
	size_t len, i;

	if (!dest) {
		smb_panic("ERROR: NULL dest in alpha_strcpy");
	}

	if (!src) {
		*dest = 0;
		return dest;
	}

	len = strlen(src);
	if (len >= maxlength)
		len = maxlength - 1;

	if (!other_safe_chars)
		other_safe_chars = "";

	for(i = 0; i < len; i++) {
		int val = (src[i] & 0xff);
		if (val > 0x7f) {
			dest[i] = '_';
			continue;
		}
		if (isupper(val) || islower(val) ||
				isdigit(val) || strchr(other_safe_chars, val))
			dest[i] = src[i];
		else
			dest[i] = '_';
	}

	dest[i] = '\0';

	return dest;
}

char *talloc_alpha_strcpy(TALLOC_CTX *mem_ctx,
			  const char *src,
			  const char *other_safe_chars)
{
	char *dest = NULL;
	size_t slen;

	if (src == NULL) {
		return NULL;
	}

	slen = strlen(src);

	dest = talloc_zero_size(mem_ctx, slen + 1);
	if (dest == NULL) {
		return NULL;
	}

	alpha_strcpy(dest, src, other_safe_chars, slen + 1);
	return dest;
}
