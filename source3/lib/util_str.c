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
#include "lib/param/loadparm.h"
#include "lib/util/smb_strtox.h"

static const char toupper_ascii_fast_table[128] = {
	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
	0x60, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f
};

/**
 * Compare 2 strings up to and including the nth char.
 *
 * @note The comparison is case-insensitive.
 **/
bool strnequal(const char *s1,const char *s2,size_t n)
{
	if (s1 == s2)
		return(true);
	if (!s1 || !s2 || !n)
		return(false);

	return(strncasecmp_m(s1,s2,n)==0);
}

/**
 Skip past a string in a buffer. Buffer may not be
 null terminated. end_ptr points to the first byte after
 then end of the buffer.
**/

char *skip_string(const char *base, size_t len, char *buf)
{
	const char *end_ptr = base + len;

	if (end_ptr < base || !base || !buf || buf >= end_ptr) {
		return NULL;
	}

	/* Skip the string */
	while (*buf) {
		buf++;
		if (buf >= end_ptr) {
			return NULL;
		}
	}
	/* Skip the '\0' */
	buf++;
	return buf;
}

/**
 Count the number of characters in a string. Normally this will
 be the same as the number of bytes in a string for single byte strings,
 but will be different for multibyte.
**/

size_t str_charnum(const char *s)
{
	size_t ret, converted_size;
	smb_ucs2_t *tmpbuf2 = NULL;
	if (!push_ucs2_talloc(talloc_tos(), &tmpbuf2, s, &converted_size)) {
		return 0;
	}
	ret = strlen_w(tmpbuf2);
	TALLOC_FREE(tmpbuf2);
	return ret;
}

bool trim_char(char *s,char cfront,char cback)
{
	bool ret = false;
	char *ep;
	char *fp = s;

	/* Ignore null or empty strings. */
	if (!s || (s[0] == '\0'))
		return false;

	if (cfront) {
		while (*fp && *fp == cfront)
			fp++;
		if (!*fp) {
			/* We ate the string. */
			s[0] = '\0';
			return true;
		}
		if (fp != s)
			ret = true;
	}

	ep = fp + strlen(fp) - 1;
	if (cback) {
		/* Attempt ascii only. Bail for mb strings. */
		while ((ep >= fp) && (*ep == cback)) {
			ret = true;
			if ((ep > fp) && (((unsigned char)ep[-1]) & 0x80)) {
				/* Could be mb... bail back to trim_string. */
				char fs[2], bs[2];
				if (cfront) {
					fs[0] = cfront;
					fs[1] = '\0';
				}
				bs[0] = cback;
				bs[1] = '\0';
				return trim_string(s, cfront ? fs : NULL, bs);
			} else {
				ep--;
			}
		}
		if (ep < fp) {
			/* We ate the string. */
			s[0] = '\0';
			return true;
		}
	}

	ep[1] = '\0';
	memmove(s, fp, ep-fp+2);
	return ret;
}

/**
 Check if a string is part of a list.
**/

bool in_list(const char *s, const char *list, bool casesensitive)
{
	char *tok = NULL;
	bool ret = false;
	TALLOC_CTX *frame;

	if (!list) {
		return false;
	}

	frame = talloc_stackframe();
	while (next_token_talloc(frame, &list, &tok,LIST_SEP)) {
		if (casesensitive) {
			if (strcmp(tok,s) == 0) {
				ret = true;
				break;
			}
		} else {
			if (strcasecmp_m(tok,s) == 0) {
				ret = true;
				break;
			}
		}
	}
	TALLOC_FREE(frame);
	return ret;
}

/**
 Truncate a string at a specified length.
**/

char *string_truncate(char *s, unsigned int length)
{
	if (s && strlen(s) > length)
		s[length] = 0;
	return s;
}

static bool unix_strlower(const char *src, size_t srclen, char *dest, size_t destlen)
{
	size_t size;
	smb_ucs2_t *buffer = NULL;
	bool ret;

	if (!convert_string_talloc(talloc_tos(), CH_UNIX, CH_UTF16LE, src, srclen,
				   (void **)(void *)&buffer, &size))
	{
		return false;
	}
	if (!strlower_w(buffer) && (dest == src)) {
		TALLOC_FREE(buffer);
		return true;
	}
	ret = convert_string(CH_UTF16LE, CH_UNIX, buffer, size, dest, destlen, &size);
	TALLOC_FREE(buffer);
	return ret;
}

#if 0 /* Alternate function that avoid talloc calls for ASCII and non ASCII */

/**
 Convert a string to lower case.
**/
_PUBLIC_ void strlower_m(char *s)
{
	char *d;
	struct smb_iconv_handle *iconv_handle;

	iconv_handle = get_iconv_handle();

	d = s;

	while (*s) {
		size_t c_size, c_size2;
		codepoint_t c = next_codepoint_handle(iconv_handle, s, &c_size);
		c_size2 = push_codepoint_handle(iconv_handle, d, tolower_m(c));
		if (c_size2 > c_size) {
			DEBUG(0,("FATAL: codepoint 0x%x (0x%x) expanded from %d to %d bytes in strlower_m\n",
				 c, tolower_m(c), (int)c_size, (int)c_size2));
			smb_panic("codepoint expansion in strlower_m\n");
		}
		s += c_size;
		d += c_size2;
	}
	*d = 0;
}

#endif

/**
 Convert a string to lower case.
**/

bool strlower_m(char *s)
{
	size_t len;
	int errno_save;
	bool ret = false;

	/* this is quite a common operation, so we want it to be
	   fast. We optimise for the ascii case, knowing that all our
	   supported multi-byte character sets are ascii-compatible
	   (ie. they match for the first 128 chars) */

	while (*s && !(((unsigned char)s[0]) & 0x80)) {
		*s = tolower_m((unsigned char)*s);
		s++;
	}

	if (!*s)
		return true;

	/* I assume that lowercased string takes the same number of bytes
	 * as source string even in UTF-8 encoding. (VIV) */
	len = strlen(s) + 1;
	errno_save = errno;
	errno = 0;
	ret = unix_strlower(s,len,s,len);
	/* Catch mb conversion errors that may not terminate. */
	if (errno) {
		s[len-1] = '\0';
	}
	errno = errno_save;
	return ret;
}

static bool unix_strupper(const char *src, size_t srclen, char *dest, size_t destlen)
{
	size_t size;
	smb_ucs2_t *buffer;
	bool ret;

	if (!push_ucs2_talloc(talloc_tos(), &buffer, src, &size)) {
		return false;
	}

	if (!strupper_w(buffer) && (dest == src)) {
		TALLOC_FREE(buffer);
		return true;
	}

	ret = convert_string(CH_UTF16LE, CH_UNIX, buffer, size, dest, destlen, &size);
	TALLOC_FREE(buffer);
	return ret;
}

#if 0 /* Alternate function that avoid talloc calls for ASCII and non ASCII */

/**
 Convert a string to UPPER case.
**/
_PUBLIC_ void strupper_m(char *s)
{
	char *d;
	struct smb_iconv_handle *iconv_handle;

	iconv_handle = get_iconv_handle();

	d = s;

	while (*s) {
		size_t c_size, c_size2;
		codepoint_t c = next_codepoint_handle(iconv_handle, s, &c_size);
		c_size2 = push_codepoint_handle(iconv_handle, d, toupper_m(c));
		if (c_size2 > c_size) {
			DEBUG(0,("FATAL: codepoint 0x%x (0x%x) expanded from %d to %d bytes in strupper_m\n",
				 c, toupper_m(c), (int)c_size, (int)c_size2));
			smb_panic("codepoint expansion in strupper_m\n");
		}
		s += c_size;
		d += c_size2;
	}
	*d = 0;
}

#endif

/**
 Convert a string to upper case.
**/

bool strupper_m(char *s)
{
	size_t len;
	bool ret = false;

	/* this is quite a common operation, so we want it to be
	   fast. We optimise for the ascii case, knowing that all our
	   supported multi-byte character sets are ascii-compatible
	   (ie. they match for the first 128 chars) */

	while (*s && !(((unsigned char)s[0]) & 0x80)) {
		*s = toupper_ascii_fast_table[(unsigned char)s[0]];
		s++;
	}

	if (!*s)
		return true;

	/* I assume that uppercased string takes the same number of bytes
	 * as source string even in multibyte encoding. (VIV) */
	len = strlen(s) + 1;
	ret = unix_strupper(s,len,s,len);
	/* Catch mb conversion errors that may not terminate. */
	if (!ret) {
		s[len-1] = '\0';
	}
	return ret;
}

/**
 Just a typesafety wrapper for snprintf into a fstring.
**/

int fstr_sprintf(fstring s, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vsnprintf(s, FSTRING_LEN, fmt, ap);
	va_end(ap);
	return ret;
}

/* Convert a size specification to a count of bytes. We accept the following
 * suffixes:
 *	    bytes if there is no suffix
 *	kK  kibibytes
 *	mM  mebibytes
 *	gG  gibibytes
 *	tT  tibibytes
 *	pP  whatever the ISO name for petabytes is
 *
 *  Returns 0 if the string can't be converted.
 */
uint64_t conv_str_size(const char * str)
{
        uint64_t lval;
        char *end;
	int error = 0;

        if (str == NULL || *str == '\0') {
                return 0;
        }

	lval = smb_strtoull(str, &end, 10, &error, SMB_STR_STANDARD);

        if (error != 0) {
                return 0;
        }

	if (*end == '\0') {
		return lval;
	}

	if (strwicmp(end, "K") == 0) {
		lval *= 1024ULL;
	} else if (strwicmp(end, "M") == 0) {
		lval *= (1024ULL * 1024ULL);
	} else if (strwicmp(end, "G") == 0) {
		lval *= (1024ULL * 1024ULL *
			 1024ULL);
	} else if (strwicmp(end, "T") == 0) {
		lval *= (1024ULL * 1024ULL *
			 1024ULL * 1024ULL);
	} else if (strwicmp(end, "P") == 0) {
		lval *= (1024ULL * 1024ULL *
			 1024ULL * 1024ULL *
			 1024ULL);
	} else {
		return 0;
	}

	return lval;
}

char *talloc_asprintf_strupper_m(TALLOC_CTX *t, const char *fmt, ...)
{
	va_list ap;
	char *ret;

	va_start(ap, fmt);
	ret = talloc_vasprintf(t, fmt, ap);
	va_end(ap);

	if (ret == NULL) {
		return NULL;
	}
	if (!strupper_m(ret)) {
		TALLOC_FREE(ret);
		return NULL;
	}
	return ret;
}

char *talloc_asprintf_strlower_m(TALLOC_CTX *t, const char *fmt, ...)
{
	va_list ap;
	char *ret;

	va_start(ap, fmt);
	ret = talloc_vasprintf(t, fmt, ap);
	va_end(ap);

	if (ret == NULL) {
		return NULL;
	}
	if (!strlower_m(ret)) {
		TALLOC_FREE(ret);
		return NULL;
	}
	return ret;
}


/********************************************************************
 Check a string for any occurrences of a specified list of invalid
 characters.
********************************************************************/

bool validate_net_name( const char *name,
		const char *invalid_chars,
		int max_len)
{
	int i;

	if (!name) {
		return false;
	}

	for ( i=0; i<max_len && name[i]; i++ ) {
		/* fail if strchr_m() finds one of the invalid characters */
		if ( name[i] && strchr_m( invalid_chars, name[i] ) ) {
			return false;
		}
	}

	return true;
}


/*******************************************************************
 Add a shell escape character '\' to any character not in a known list
 of characters. UNIX charset format.
*******************************************************************/

#define INCLUDE_LIST "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_/ \t.,"
#define INSIDE_DQUOTE_LIST "$`\n\"\\"

char *escape_shell_string(const char *src)
{
	size_t srclen = strlen(src);
	char *ret = SMB_MALLOC_ARRAY(char, (srclen * 2) + 1);
	char *dest = ret;
	bool in_s_quote = false;
	bool in_d_quote = false;
	bool next_escaped = false;

	if (!ret) {
		return NULL;
	}

	while (*src) {
		size_t c_size;
		codepoint_t c = next_codepoint(src, &c_size);

		if (c == INVALID_CODEPOINT) {
			SAFE_FREE(ret);
			return NULL;
		}

		if (c_size > 1) {
			memcpy(dest, src, c_size);
			src += c_size;
			dest += c_size;
			next_escaped = false;
			continue;
		}

		/*
		 * Deal with backslash escaped state.
		 * This only lasts for one character.
		 */

		if (next_escaped) {
			*dest++ = *src++;
			next_escaped = false;
			continue;
		}

		/*
		 * Deal with single quote state. The
		 * only thing we care about is exiting
		 * this state.
		 */

		if (in_s_quote) {
			if (*src == '\'') {
				in_s_quote = false;
			}
			*dest++ = *src++;
			continue;
		}

		/*
		 * Deal with double quote state. The most
		 * complex state. We must cope with \, meaning
		 * possibly escape next char (depending what it
		 * is), ", meaning exit this state, and possibly
		 * add an \ escape to any unprotected character
		 * (listed in INSIDE_DQUOTE_LIST).
		 */

		if (in_d_quote) {
			if (*src == '\\') {
				/*
				 * Next character might be escaped.
				 * We have to peek. Inside double
				 * quotes only INSIDE_DQUOTE_LIST
				 * characters are escaped by a \.
				 */

				char nextchar;

				c = next_codepoint(&src[1], &c_size);
				if (c == INVALID_CODEPOINT) {
					SAFE_FREE(ret);
					return NULL;
				}
				if (c_size > 1) {
					/*
					 * Don't escape the next char.
					 * Just copy the \.
					 */
					*dest++ = *src++;
					continue;
				}

				nextchar = src[1];

				if (nextchar && strchr(INSIDE_DQUOTE_LIST,
							(int)nextchar)) {
					next_escaped = true;
				}
				*dest++ = *src++;
				continue;
			}

			if (*src == '\"') {
				/* Exit double quote state. */
				in_d_quote = false;
				*dest++ = *src++;
				continue;
			}

			/*
			 * We know the character isn't \ or ",
			 * so escape it if it's any of the other
			 * possible unprotected characters.
			 */

	       		if (strchr(INSIDE_DQUOTE_LIST, (int)*src)) {
				*dest++ = '\\';
			}
			*dest++ = *src++;
			continue;
		}

		/*
		 * From here to the end of the loop we're
		 * not in the single or double quote state.
		 */

		if (*src == '\\') {
			/* Next character must be escaped. */
			next_escaped = true;
			*dest++ = *src++;
			continue;
		}

		if (*src == '\'') {
			/* Go into single quote state. */
			in_s_quote = true;
			*dest++ = *src++;
			continue;
		}

		if (*src == '\"') {
			/* Go into double quote state. */
			in_d_quote = true;
			*dest++ = *src++;
			continue;
		}

		/* Check if we need to escape the character. */

	       	if (!strchr(INCLUDE_LIST, (int)*src)) {
			*dest++ = '\\';
		}
		*dest++ = *src++;
	}
	*dest++ = '\0';
	return ret;
}

/*
 * This routine improves performance for operations temporarily acting on a
 * full path. It is equivalent to the much more expensive
 *
 * talloc_asprintf(talloc_tos(), "%s/%s", dir, name)
 *
 * This actually does make a difference in metadata-heavy workloads (i.e. the
 * "standard" client.txt nbench run.
 */

ssize_t full_path_tos(const char *dir, const char *name,
		      char *tmpbuf, size_t tmpbuf_len,
		      char **pdst, char **to_free)
{
	size_t dirlen, namelen, len;
	char *dst;

	dirlen = strlen(dir);
	namelen = strlen(name);
	len = dirlen + namelen + 1;

	if (len < tmpbuf_len) {
		dst = tmpbuf;
		*to_free = NULL;
	} else {
		dst = talloc_array(talloc_tos(), char, len+1);
		if (dst == NULL) {
			return -1;
		}
		*to_free = dst;
	}

	memcpy(dst, dir, dirlen);
	dst[dirlen] = '/';
	memcpy(dst+dirlen+1, name, namelen+1);
	*pdst = dst;
	return len;
}
