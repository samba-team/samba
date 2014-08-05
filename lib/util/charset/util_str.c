/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Simo Sorce 2001
   Copyright (C) Andrew Bartlett 2011
   Copyright (C) Jeremy Allison  1992-2007
   Copyright (C) Martin Pool     2003
   Copyright (C) James Peach	 2006

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

#ifdef strcasecmp
#undef strcasecmp
#endif

/**
 Case insensitive string compararison, handle specified for testing
**/
_PUBLIC_ int strcasecmp_m_handle(struct smb_iconv_handle *iconv_handle,
				 const char *s1, const char *s2)
{
	codepoint_t c1=0, c2=0;
	size_t size1, size2;

	/* handle null ptr comparisons to simplify the use in qsort */
	if (s1 == s2) return 0;
	if (s1 == NULL) return -1;
	if (s2 == NULL) return 1;

	while (*s1 && *s2) {
		c1 = next_codepoint_handle(iconv_handle, s1, &size1);
		c2 = next_codepoint_handle(iconv_handle, s2, &size2);

		if (c1 == INVALID_CODEPOINT ||
		    c2 == INVALID_CODEPOINT) {
			return strcasecmp(s1, s2);
		}

		s1 += size1;
		s2 += size2;

		if (c1 == c2) {
			continue;
		}

		if (toupper_m(c1) != toupper_m(c2)) {
			return c1 - c2;
		}
	}

	return *s1 - *s2;
}

/**
 Case insensitive string compararison
**/
_PUBLIC_ int strcasecmp_m(const char *s1, const char *s2)
{
	struct smb_iconv_handle *iconv_handle = get_iconv_handle();
	return strcasecmp_m_handle(iconv_handle, s1, s2);
}

/**
 Case insensitive string compararison, length limited, handle specified for testing
**/
_PUBLIC_ int strncasecmp_m_handle(struct smb_iconv_handle *iconv_handle,
				  const char *s1, const char *s2, size_t n)
{
	codepoint_t c1=0, c2=0;
	size_t size1, size2;

	/* handle null ptr comparisons to simplify the use in qsort */
	if (s1 == s2) return 0;
	if (s1 == NULL) return -1;
	if (s2 == NULL) return 1;

	while (*s1 && *s2 && n) {
		n--;

		c1 = next_codepoint_handle(iconv_handle, s1, &size1);
		c2 = next_codepoint_handle(iconv_handle, s2, &size2);

		if (c1 == INVALID_CODEPOINT ||
		    c2 == INVALID_CODEPOINT) {
			/*
			 * n was specified in characters,
			 * now we must convert it to bytes.
			 * As bytes are the smallest
			 * character unit, the following
			 * increment and strncasecmp is always
			 * safe.
			 *
			 * The source string was already known
			 * to be n characters long, so we are
			 * guaranteed to be able to look at the
			 * (n remaining + size1) bytes from the
			 * s1 position).
			 */
			n += size1;
			return strncasecmp(s1, s2, n);
		}

		s1 += size1;
		s2 += size2;

		if (c1 == c2) {
			continue;
		}

		if (toupper_m(c1) != toupper_m(c2)) {
			return c1 - c2;
		}
	}

	if (n == 0) {
		return 0;
	}

	return *s1 - *s2;
}

/**
 Case insensitive string compararison, length limited
**/
_PUBLIC_ int strncasecmp_m(const char *s1, const char *s2, size_t n)
{
	struct smb_iconv_handle *iconv_handle = get_iconv_handle();
	return strncasecmp_m_handle(iconv_handle, s1, s2, n);
}

/**
 * Compare 2 strings.
 *
 * @note The comparison is case-insensitive.
 **/
_PUBLIC_ bool strequal_m(const char *s1, const char *s2)
{
	return strcasecmp_m(s1,s2) == 0;
}

/**
 Compare 2 strings (case sensitive).
**/
_PUBLIC_ bool strcsequal(const char *s1,const char *s2)
{
	if (s1 == s2)
		return true;
	if (!s1 || !s2)
		return false;

	return strcmp(s1,s2) == 0;
}

/**
 * Calculate the number of units (8 or 16-bit, depending on the
 * destination charset), that would be needed to convert the input
 * string which is expected to be in in src_charset encoding to the
 * destination charset (which should be a unicode charset).
 */
_PUBLIC_ size_t strlen_m_ext_handle(struct smb_iconv_handle *ic,
				    const char *s, charset_t src_charset, charset_t dst_charset)
{
	size_t count = 0;

#ifdef DEVELOPER
	switch (dst_charset) {
	case CH_DOS:
	case CH_UNIX:
		smb_panic("cannot call strlen_m_ext() with a variable dest charset (must be UTF16* or UTF8)");
	default:
		break;
	}

	switch (src_charset) {
	case CH_UTF16LE:
	case CH_UTF16BE:
		smb_panic("cannot call strlen_m_ext() with a UTF16 src charset (must be DOS, UNIX, DISPLAY or UTF8)");
	default:
		break;
	}
#endif
	if (!s) {
		return 0;
	}

	while (*s && !(((uint8_t)*s) & 0x80)) {
		s++;
		count++;
	}

	if (!*s) {
		return count;
	}

	while (*s) {
		size_t c_size;
		codepoint_t c = next_codepoint_handle_ext(ic, s, src_charset, &c_size);
		s += c_size;

		switch (dst_charset) {
		case CH_UTF16LE:
		case CH_UTF16BE:
		case CH_UTF16MUNGED:
			if (c < 0x10000) {
				/* Unicode char fits into 16 bits. */
				count += 1;
			} else {
				/* Double-width unicode char - 32 bits. */
				count += 2;
			}
			break;
		case CH_UTF8:
			/*
			 * this only checks ranges, and does not
			 * check for invalid codepoints
			 */
			if (c < 0x80) {
				count += 1;
			} else if (c < 0x800) {
				count += 2;
			} else if (c < 0x10000) {
				count += 3;
			} else {
				count += 4;
			}
			break;
		default:
			/*
			 * non-unicode encoding:
			 * assume that each codepoint fits into
			 * one unit in the destination encoding.
			 */
			count += 1;
		}
	}

	return count;
}

/**
 * Calculate the number of units (8 or 16-bit, depending on the
 * destination charset), that would be needed to convert the input
 * string which is expected to be in in src_charset encoding to the
 * destination charset (which should be a unicode charset).
 */
_PUBLIC_ size_t strlen_m_ext(const char *s, charset_t src_charset, charset_t dst_charset)
{
	struct smb_iconv_handle *ic = get_iconv_handle();
	return strlen_m_ext_handle(ic, s, src_charset, dst_charset);
}

_PUBLIC_ size_t strlen_m_ext_term(const char *s, const charset_t src_charset,
				  const charset_t dst_charset)
{
	if (!s) {
		return 0;
	}
	return strlen_m_ext(s, src_charset, dst_charset) + 1;
}

/**
 * Calculate the number of 16-bit units that would be needed to convert
 * the input string which is expected to be in CH_UNIX encoding to UTF16.
 *
 * This will be the same as the number of bytes in a string for single
 * byte strings, but will be different for multibyte.
 */
_PUBLIC_ size_t strlen_m(const char *s)
{
	return strlen_m_ext(s, CH_UNIX, CH_UTF16LE);
}

/**
   Work out the number of multibyte chars in a string, including the NULL
   terminator.
**/
_PUBLIC_ size_t strlen_m_term(const char *s)
{
	if (!s) {
		return 0;
	}

	return strlen_m(s) + 1;
}

/*
 * Weird helper routine for the winreg pipe: If nothing is around, return 0,
 * if a string is there, include the terminator.
 */

_PUBLIC_ size_t strlen_m_term_null(const char *s)
{
	size_t len;
	if (!s) {
		return 0;
	}
	len = strlen_m(s);
	if (len == 0) {
		return 0;
	}

	return len+1;
}

/**
 Strchr and strrchr_m are a bit complex on general multi-byte strings.
**/
_PUBLIC_ char *strchr_m(const char *src, char c)
{
	const char *s;
	struct smb_iconv_handle *ic = get_iconv_handle();
	if (src == NULL) {
		return NULL;
	}
	/* characters below 0x3F are guaranteed to not appear in
	   non-initial position in multi-byte charsets */
	if ((c & 0xC0) == 0) {
		return strchr(src, c);
	}

	/* this is quite a common operation, so we want it to be
	   fast. We optimise for the ascii case, knowing that all our
	   supported multi-byte character sets are ascii-compatible
	   (ie. they match for the first 128 chars) */

	for (s = src; *s && !(((unsigned char)s[0]) & 0x80); s++) {
		if (*s == c)
			return discard_const_p(char, s);
	}

	if (!*s)
		return NULL;

#ifdef BROKEN_UNICODE_COMPOSE_CHARACTERS
	/* With compose characters we must restart from the beginning. JRA. */
	s = src;
#endif

	while (*s) {
		size_t size;
		codepoint_t c2 = next_codepoint_handle(ic, s, &size);
		if (c2 == c) {
			return discard_const_p(char, s);
		}
		s += size;
	}

	return NULL;
}

/**
 * Multibyte-character version of strrchr
 */
_PUBLIC_ char *strrchr_m(const char *s, char c)
{
	struct smb_iconv_handle *ic = get_iconv_handle();
	char *ret = NULL;

	if (s == NULL) {
		return NULL;
	}

	/* characters below 0x3F are guaranteed to not appear in
	   non-initial position in multi-byte charsets */
	if ((c & 0xC0) == 0) {
		return strrchr(s, c);
	}

	/* this is quite a common operation, so we want it to be
	   fast. We optimise for the ascii case, knowing that all our
	   supported multi-byte character sets are ascii-compatible
	   (ie. they match for the first 128 chars). Also, in Samba
	   we only search for ascii characters in 'c' and that
	   in all mb character sets with a compound character
	   containing c, if 'c' is not a match at position
	   p, then p[-1] > 0x7f. JRA. */

	{
		size_t len = strlen(s);
		const char *cp = s;
		bool got_mb = false;

		if (len == 0)
			return NULL;
		cp += (len - 1);
		do {
			if (c == *cp) {
				/* Could be a match. Part of a multibyte ? */
				if ((cp > s) &&
					(((unsigned char)cp[-1]) & 0x80)) {
					/* Yep - go slow :-( */
					got_mb = true;
					break;
				}
				/* No - we have a match ! */
				return discard_const_p(char , cp);
			}
		} while (cp-- != s);
		if (!got_mb)
			return NULL;
	}

	while (*s) {
		size_t size;
		codepoint_t c2 = next_codepoint_handle(ic, s, &size);
		if (c2 == c) {
			ret = discard_const_p(char, s);
		}
		s += size;
	}

	return ret;
}

/**
  return True if any (multi-byte) character is lower case
*/
_PUBLIC_ bool strhaslower_handle(struct smb_iconv_handle *ic,
				 const char *string)
{
	while (*string) {
		size_t c_size;
		codepoint_t s;
		codepoint_t t;

		s = next_codepoint_handle(ic, string, &c_size);
		string += c_size;

		t = toupper_m(s);

		if (s != t) {
			return true; /* that means it has lower case chars */
		}
	}

	return false;
}

_PUBLIC_ bool strhaslower(const char *string)
{
	struct smb_iconv_handle *ic = get_iconv_handle();
	return strhaslower_handle(ic, string);
}

/**
  return True if any (multi-byte) character is upper case
*/
_PUBLIC_ bool strhasupper_handle(struct smb_iconv_handle *ic,
				 const char *string)
{
	while (*string) {
		size_t c_size;
		codepoint_t s;
		codepoint_t t;

		s = next_codepoint_handle(ic, string, &c_size);
		string += c_size;

		t = tolower_m(s);

		if (s != t) {
			return true; /* that means it has upper case chars */
		}
	}

	return false;
}

_PUBLIC_ bool strhasupper(const char *string)
{
	struct smb_iconv_handle *ic = get_iconv_handle();
	return strhasupper_handle(ic, string);
}

/***********************************************************************
 strstr_m - We convert via ucs2 for now.
***********************************************************************/

char *strstr_m(const char *src, const char *findstr)
{
	smb_ucs2_t *p;
	smb_ucs2_t *src_w, *find_w;
	const char *s;
	char *s2;
	char *retp;
	size_t converted_size, findstr_len = 0;

	TALLOC_CTX *frame; /* Only set up in the iconv case */

	/* for correctness */
	if (!findstr[0]) {
		return discard_const_p(char, src);
	}

	/* Samba does single character findstr calls a *lot*. */
	if (findstr[1] == '\0')
		return strchr_m(src, *findstr);

	/* We optimise for the ascii case, knowing that all our
	   supported multi-byte character sets are ascii-compatible
	   (ie. they match for the first 128 chars) */

	for (s = src; *s && !(((unsigned char)s[0]) & 0x80); s++) {
		if (*s == *findstr) {
			if (!findstr_len)
				findstr_len = strlen(findstr);

			if (strncmp(s, findstr, findstr_len) == 0) {
				return discard_const_p(char, s);
			}
		}
	}

	if (!*s)
		return NULL;

#if 1 /* def BROKEN_UNICODE_COMPOSE_CHARACTERS */
	/* 'make check' fails unless we do this */

	/* With compose characters we must restart from the beginning. JRA. */
	s = src;
#endif

	frame = talloc_stackframe();

	if (!push_ucs2_talloc(frame, &src_w, src, &converted_size)) {
		DEBUG(0,("strstr_m: src malloc fail\n"));
		TALLOC_FREE(frame);
		return NULL;
	}

	if (!push_ucs2_talloc(frame, &find_w, findstr, &converted_size)) {
		DEBUG(0,("strstr_m: find malloc fail\n"));
		TALLOC_FREE(frame);
		return NULL;
	}

	p = strstr_w(src_w, find_w);

	if (!p) {
		TALLOC_FREE(frame);
		return NULL;
	}

	*p = 0;
	if (!pull_ucs2_talloc(frame, &s2, src_w, &converted_size)) {
		TALLOC_FREE(frame);
		DEBUG(0,("strstr_m: dest malloc fail\n"));
		return NULL;
	}
	retp = discard_const_p(char, (s+strlen(s2)));
	TALLOC_FREE(frame);
	return retp;
}
