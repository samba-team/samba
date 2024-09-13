/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Simo Sorce 2001

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
#include "charset.h"
#include "lib/util/byteorder.h"
#include "lib/util/fault.h"
#include "lib/util/tsort.h"

/**
 String replace.
 NOTE: oldc and newc must be 7 bit characters
**/
_PUBLIC_ void string_replace_m(char *s, char oldc, char newc)
{
	struct smb_iconv_handle *ic = get_iconv_handle();
	while (s && *s) {
		size_t size;
		codepoint_t c = next_codepoint_handle(ic, s, &size);
		if (c == oldc) {
			*s = newc;
		}
		s += size;
	}
}

/**
 Convert a string to lower case, allocated with talloc
**/
_PUBLIC_ char *strlower_talloc_handle(struct smb_iconv_handle *iconv_handle,
				      TALLOC_CTX *ctx, const char *src)
{
	size_t size=0;
	char *dest;

	if(src == NULL) {
		return NULL;
	}

	/* this takes advantage of the fact that upper/lower can't
	   change the length of a character by more than 1 byte */
	dest = talloc_array(ctx, char, 2*(strlen(src))+1);
	if (dest == NULL) {
		return NULL;
	}

	while (*src) {
		size_t c_size;
		codepoint_t c = next_codepoint_handle(iconv_handle, src, &c_size);
		src += c_size;

		c = tolower_m(c);

		c_size = push_codepoint_handle(iconv_handle, dest+size, c);
		if (c_size == -1) {
			talloc_free(dest);
			return NULL;
		}
		size += c_size;
	}

	dest[size] = 0;

	/* trim it so talloc_append_string() works */
	dest = talloc_realloc(ctx, dest, char, size+1);

	talloc_set_name_const(dest, dest);

	return dest;
}

_PUBLIC_ char *strlower_talloc(TALLOC_CTX *ctx, const char *src)
{
	struct smb_iconv_handle *iconv_handle = get_iconv_handle();
	return strlower_talloc_handle(iconv_handle, ctx, src);
}

/**
 Convert a string to UPPER case, allocated with talloc
 source length limited to n bytes, iconv handle supplied
**/
_PUBLIC_ char *strupper_talloc_n_handle(struct smb_iconv_handle *iconv_handle,
					TALLOC_CTX *ctx, const char *src, size_t n)
{
	size_t size=0;
	char *dest;

	if (!src) {
		return NULL;
	}

	/* this takes advantage of the fact that upper/lower can't
	   change the length of a character by more than 1 byte */
	dest = talloc_array(ctx, char, 2*(n+1));
	if (dest == NULL) {
		return NULL;
	}

	while (n && *src) {
		size_t c_size;
		codepoint_t c = next_codepoint_handle_ext(iconv_handle, src, n,
							  CH_UNIX, &c_size);
		src += c_size;
		n -= c_size;

		c = toupper_m(c);

		c_size = push_codepoint_handle(iconv_handle, dest+size, c);
		if (c_size == -1) {
			talloc_free(dest);
			return NULL;
		}
		size += c_size;
	}

	dest[size] = 0;

	/* trim it so talloc_append_string() works */
	dest = talloc_realloc(ctx, dest, char, size+1);

	talloc_set_name_const(dest, dest);

	return dest;
}

/**
 Convert a string to UPPER case, allocated with talloc
 source length limited to n bytes
**/
_PUBLIC_ char *strupper_talloc_n(TALLOC_CTX *ctx, const char *src, size_t n)
{
	struct smb_iconv_handle *iconv_handle = get_iconv_handle();
	return strupper_talloc_n_handle(iconv_handle, ctx, src, n);
}
/**
 Convert a string to UPPER case, allocated with talloc
**/
_PUBLIC_ char *strupper_talloc(TALLOC_CTX *ctx, const char *src)
{
	return strupper_talloc_n(ctx, src, src?strlen(src):0);
}

/**
 talloc_strdup() a unix string to upper case.
**/
_PUBLIC_ char *talloc_strdup_upper(TALLOC_CTX *ctx, const char *src)
{
	return strupper_talloc(ctx, src);
}


/*
 * strncasecmp_ldb() works like a *bit* like strncasecmp, with various
 * tricks to suit the way LDB compares strings. The differences are:
 *
 * 0. each string has it's own length.
 *
 * 1. consecutive spaces are collapsed down to one space, so that
 *    "a  b" equals "a b". (this is why each string needs its own
 *    length). Leading and trailing spaces are removed altogether.
 *
 * 2. Comparisons are done in UPPER CASE, as Windows does, not in
 *    lowercase as POSIX would have it.
 *
 * 3. An invalid byte compares higher than any real character. For example,
 *    "hello\xc2\xff" would sort higher than "hello\xcd\xb6", because CD
 *    B6 is a valid sequence and C2 FF is not.
 *
 * 4. If two strings become invalid on the same character, the rest
 *    of the string is compared via ldb ASCII case fold rules.
 *
 *    For example, "hellō\xC2\xFFworld" < " hElLŌ\xFE ", because the
 *    strings are equal up to 'ō' by utf-8 casefold, but the "\xc2\xff" and
 *    "\xfe" are invalid sequences. At that point, we skip to the byte-by-byte
 *    (but space-eating, casefolding) comparison, and 0xc2 < 0xff.
 */

#define EAT_SPACE(s, len, ends_in_space)			 \
	do {							 \
		while (len) {					 \
			if (*s != ' ') {			 \
				break;				 \
			}					 \
			s++;					 \
			len--;					 \
		}						 \
		ends_in_space = (len == 0 || *s == '\0');	 \
	} while(0)


_PUBLIC_ int strncasecmp_ldb(const char *s1,
			     size_t len1,
			     const char *s2,
			     size_t len2)
{
	struct smb_iconv_handle *iconv_handle = get_iconv_handle();
	codepoint_t c1, c2;
	size_t cs1, cs2;
	bool ends_in_space1, ends_in_space2;
	int ret;
	bool end1, end2;

	EAT_SPACE(s1, len1, ends_in_space1);
	EAT_SPACE(s2, len2, ends_in_space2);
	/*
	 * if ends_in_space was set, the string was empty or only
	 * spaces (which we treat as equivalent).
	 */
	if (ends_in_space1 && ends_in_space2) {
		return 0;
	}
	if (ends_in_space1) {
		return -1;
	}
	if (ends_in_space2) {
		return 1;
	}

	while (true) {
		/*
		 * If the next byte is a space, we eat all the spaces,
		 * and say we found a single codepoint. If the spaces
		 * were at the end of the string, the codepoint is 0,
		 * as if there were no spaces. Otherwise it is 0x20,
		 * as if there was one space.
		 *
		 * Setting the codepoint to 0 will break the loop, but
		 * only after codepoints have been found in both strings.
		 */
		if (len1 == 0 || *s1 == 0) {
			c1 = 0;
		} else if (*s1 == ' ') {
			EAT_SPACE(s1, len1, ends_in_space1);
			c1 = ends_in_space1 ? 0 : ' ';
		} else if ((*s1 & 0x80) == 0) {
			c1 = *s1;
			s1++;
			len1--;
		} else {
			c1 = next_codepoint_handle_ext(iconv_handle, s1, len1,
						       CH_UNIX, &cs1);
			if (c1 != INVALID_CODEPOINT) {
				s1 += cs1;
				len1 -= cs1;
			}
		}

		if (len2 == 0 || *s2 == 0) {
			c2 = 0;
		} else if (*s2 == ' ') {
			EAT_SPACE(s2, len2, ends_in_space2);
			c2 = ends_in_space2 ? 0 : ' ';
		} else if ((*s2 & 0x80) == 0) {
			c2 = *s2;
			s2++;
			len2--;
		} else {
			c2 = next_codepoint_handle_ext(iconv_handle, s2, len2,
						       CH_UNIX, &cs2);
			if (c2 != INVALID_CODEPOINT) {
				s2 += cs2;
				len2 -= cs2;
			}
		}

		if (c1 == 0 || c2 == 0 ||
		    c1 == INVALID_CODEPOINT || c2 == INVALID_CODEPOINT) {
			break;
		}

		if (c1 == c2) {
			continue;
		}
		c1 = toupper_m(c1);
		c2 = toupper_m(c2);
		if (c1 != c2) {
			break;
		}
	}

	/*
	 * Either a difference has been found, or one or both strings have
	 * ended or hit invalid codepoints.
	 */
	ret = NUMERIC_CMP(c1, c2);

	if (ret != 0) {
		return ret;
	}
	/*
	 * the strings are equal up to here, but one might be longer.
	 */
	end1 = len1 == 0 || *s1 == 0;
	end2 = len2 == 0 || *s2 == 0;

	if (end1 && end2) {
		return 0;
	}
	if (end1) {
		return -1;
	}
	if (end2) {
		return -1;
	}

	/*
	 * By elimination, if we got here, we have INVALID_CODEPOINT on both
	 * sides.
	 *
	 * THere is no perfect option, but what we choose to do is continue on
	 * with ascii case fold (as if calling ldb_comparison_fold_ascii()
	 * which is private to ldb, so we can't just defer to it).
	 */
	while (true) {
		if (len1 == 0 || *s1 == 0) {
			c1 = 0;
		} else if (*s1 == ' ') {
			EAT_SPACE(s1, len1, ends_in_space1);
			c1 = ends_in_space1 ? 0 : ' ';
		} else {
			c1 = *s1;
			s1++;
			len1--;
			c1 = ('a' <= c1 && c1 <= 'z') ? c1 ^ 0x20 : c1;
		}

		if (len2 == 0 || *s2 == 0) {
			c2 = 0;
		} else if (*s2 == ' ') {
			EAT_SPACE(s2, len2, ends_in_space2);
			c2 = ends_in_space2 ? 0 : ' ';
		} else {
			c2 = *s2;
			s2++;
			len2--;
			c2 = ('a' <= c2 && c2 <= 'z') ? c2 ^ 0x20 : c2;
		}

		if (c1 == 0 || c2 == 0 || c1 != c2) {
			break;
		}
	}
	return NUMERIC_CMP(c1, c2);
}

#undef EAT_SPACE


/**
 Find the number of 'c' chars in a string
**/
_PUBLIC_ size_t count_chars_m(const char *s, char c)
{
	struct smb_iconv_handle *ic = get_iconv_handle();
	size_t count = 0;

	while (*s) {
		size_t size;
		codepoint_t c2 = next_codepoint_handle(ic, s, &size);
		if (c2 == c) count++;
		s += size;
	}

	return count;
}

size_t ucs2_align(const void *base_ptr, const void *p, int flags)
{
	if (flags & (STR_NOALIGN|STR_ASCII)) {
		return 0;
	}
	return PTR_DIFF(p, base_ptr) & 1;
}

/**
return the number of bytes occupied by a buffer in CH_UTF16 format
**/
size_t utf16_len(const void *buf)
{
	size_t len;

	for (len = 0; PULL_LE_U16(buf,len); len += 2) ;

	return len;
}

/**
return the number of bytes occupied by a buffer in CH_UTF16 format
the result includes the null termination
**/
size_t utf16_null_terminated_len(const void *buf)
{
	return utf16_len(buf) + 2;
}

/**
return the number of bytes occupied by a buffer in CH_UTF16 format
limited by 'n' bytes
**/
size_t utf16_len_n(const void *src, size_t n)
{
	size_t len;

	for (len = 0; (len+2 <= n) && PULL_LE_U16(src, len); len += 2) ;

	return len;
}

/**
return the number of bytes occupied by a buffer in CH_UTF16 format
the result includes the null termination
limited by 'n' bytes
**/
size_t utf16_null_terminated_len_n(const void *src, size_t n)
{
	size_t len;

	len = utf16_len_n(src, n);

	if (len+2 <= n) {
		len += 2;
	}

	return len;
}

unsigned char *talloc_utf16_strlendup(TALLOC_CTX *mem_ctx, const char *str, size_t len)
{
	unsigned char *new_str = NULL;

	/* Check for overflow. */
	if (len > SIZE_MAX - 2) {
		return NULL;
	}

	/*
	 * Allocate the new string, including space for the
	 * UTF‐16 null terminator.
	 */
	new_str = talloc_size(mem_ctx, len + 2);
	if (new_str == NULL) {
		return NULL;
	}

	memcpy(new_str, str, len);

	/*
	 * Ensure that the UTF‐16 string is
	 * null‐terminated.
	 */
	new_str[len] = '\0';
	new_str[len + 1] = '\0';

	return new_str;
}

unsigned char *talloc_utf16_strdup(TALLOC_CTX *mem_ctx, const char *str)
{
	if (str == NULL) {
		return NULL;
	}
	return talloc_utf16_strlendup(mem_ctx, str, utf16_len(str));
}

unsigned char *talloc_utf16_strndup(TALLOC_CTX *mem_ctx, const char *str, size_t n)
{
	if (str == NULL) {
		return NULL;
	}
	return talloc_utf16_strlendup(mem_ctx, str, utf16_len_n(str, n));
}

/**
 * Determine the length and validity of a utf-8 string.
 *
 * @param input the string pointer
 * @param maxlen maximum size of the string
 * @param byte_len receives the length of the valid section
 * @param char_len receives the number of unicode characters in the valid section
 * @param utf16_len receives the number of bytes the string would need in UTF16 encoding.
 *
 * @return true if the input is valid up to maxlen, or a '\0' byte, otherwise false.
 */
bool utf8_check(const char *input, size_t maxlen,
		size_t *byte_len,
		size_t *char_len,
		size_t *utf16_len)
{
	const uint8_t *s = (const uint8_t *)input;
	size_t i;
	size_t chars = 0;
	size_t long_chars = 0;
	uint32_t codepoint;
	uint8_t a, b, c, d;
	for (i = 0; i < maxlen; i++, chars++) {
		if (s[i] == 0) {
			break;
		}
		if (s[i] < 0x80) {
			continue;
		}
		if ((s[i] & 0xe0) == 0xc0) {
			/* 110xxxxx 10xxxxxx */
			a = s[i];
			if (maxlen - i < 2) {
				goto error;
			}
			b = s[i + 1];
			if ((b & 0xc0) != 0x80) {
				goto error;
			}
			codepoint = (a & 31) << 6 | (b & 63);
			if (codepoint < 0x80) {
				goto error;
			}
			i++;
			continue;
		}
		if ((s[i] & 0xf0) == 0xe0) {
			/* 1110xxxx 10xxxxxx 10xxxxxx */
			if (maxlen - i < 3) {
				goto error;
			}
			a = s[i];
			b = s[i + 1];
			c = s[i + 2];
			if ((b & 0xc0) != 0x80 || (c & 0xc0) != 0x80) {
				goto error;
			}
			codepoint = (c & 63) | (b & 63) << 6 | (a & 15) << 12;

			if (codepoint < 0x800) {
				goto error;
			}
			if (codepoint >= 0xd800 && codepoint <= 0xdfff) {
				/*
				 * This is an invalid codepoint, per
				 * RFC3629, as it encodes part of a
				 * UTF-16 surrogate pair for a
				 * character over U+10000, which ought
				 * to have been encoded as a four byte
				 * utf-8 sequence.
				 */
				goto error;
			}
			i += 2;
			continue;
		}

		if ((s[i] & 0xf8) == 0xf0) {
			/* 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
			if (maxlen - i < 4) {
				goto error;
			}
			a = s[i];
			b = s[i + 1];
			c = s[i + 2];
			d = s[i + 3];

			if ((b & 0xc0) != 0x80 ||
			    (c & 0xc0) != 0x80 ||
			    (d & 0xc0) != 0x80) {
				goto error;
			}
			codepoint = (d & 63) | (c & 63) << 6 | (b & 63) << 12 | (a & 7) << 18;

			if (codepoint < 0x10000 || codepoint > 0x10ffff) {
				goto error;
			}
			/* this one will need two UTF16 characters */
			long_chars++;
			i += 3;
			continue;
		}
		/*
		 * If it wasn't handled yet, it's wrong.
		 */
		goto error;
	}
	*byte_len = i;
	*char_len = chars;
	*utf16_len = chars + long_chars;
	return true;

error:
	*byte_len = i;
	*char_len = chars;
	*utf16_len = chars + long_chars;
	return false;
}


/**
 * Copy a string from a char* unix src to a dos codepage string destination.
 *
 * @converted_size the number of bytes occupied by the string in the destination.
 * @return bool true if success.
 *
 * @param flags can include
 * <dl>
 * <dt>STR_TERMINATE</dt> <dd>means include the null termination</dd>
 * <dt>STR_UPPER</dt> <dd>means uppercase in the destination</dd>
 * </dl>
 *
 * @param dest_len the maximum length in bytes allowed in the
 * destination.  If @p dest_len is -1 then no maximum is used.
 **/
static bool push_ascii_string(void *dest, const char *src, size_t dest_len, int flags, size_t *converted_size)
{
	size_t src_len;
	bool ret;

	if (flags & STR_UPPER) {
		char *tmpbuf = strupper_talloc(NULL, src);
		if (tmpbuf == NULL) {
			return false;
		}
		ret = push_ascii_string(dest, tmpbuf, dest_len, flags & ~STR_UPPER, converted_size);
		talloc_free(tmpbuf);
		return ret;
	}

	src_len = strlen(src);

	if (flags & (STR_TERMINATE | STR_TERMINATE_ASCII))
		src_len++;

	return convert_string(CH_UNIX, CH_DOS, src, src_len, dest, dest_len, converted_size);
}

/**
 * Copy a string from a dos codepage source to a unix char* destination.
 *
 * The resulting string in "dest" is always null terminated.
 *
 * @param flags can have:
 * <dl>
 * <dt>STR_TERMINATE</dt>
 * <dd>STR_TERMINATE means the string in @p src
 * is null terminated, and src_len is ignored.</dd>
 * </dl>
 *
 * @param src_len is the length of the source area in bytes.
 * @returns the number of bytes occupied by the string in @p src.
 **/
static ssize_t pull_ascii_string(char *dest, const void *src, size_t dest_len, size_t src_len, int flags)
{
	size_t size = 0;

	if (flags & (STR_TERMINATE | STR_TERMINATE_ASCII)) {
		if (src_len == (size_t)-1) {
			src_len = strlen((const char *)src) + 1;
		} else {
			size_t len = strnlen((const char *)src, src_len);
			if (len < src_len)
				len++;
			src_len = len;
		}
	}

	/* We're ignoring the return here.. */
	(void)convert_string(CH_DOS, CH_UNIX, src, src_len, dest, dest_len, &size);

	if (dest_len)
		dest[MIN(size, dest_len-1)] = 0;

	return src_len;
}

/**
 * Copy a string from a char* src to a unicode destination.
 *
 * @returns the number of bytes occupied by the string in the destination.
 *
 * @param flags can have:
 *
 * <dl>
 * <dt>STR_TERMINATE <dd>means include the null termination.
 * <dt>STR_UPPER     <dd>means uppercase in the destination.
 * <dt>STR_NOALIGN   <dd>means don't do alignment.
 * </dl>
 *
 * @param dest_len is the maximum length allowed in the
 * destination. If dest_len is -1 then no maximum is used.
 **/
static ssize_t push_ucs2(void *dest, const char *src, size_t dest_len, int flags)
{
	size_t len=0;
	size_t src_len = strlen(src);
	size_t size = 0;
	bool ret;

	if (flags & STR_UPPER) {
		char *tmpbuf = strupper_talloc(NULL, src);
		ssize_t retval;
		if (tmpbuf == NULL) {
			return -1;
		}
		retval = push_ucs2(dest, tmpbuf, dest_len, flags & ~STR_UPPER);
		talloc_free(tmpbuf);
		return retval;
	}

	if (flags & STR_TERMINATE)
		src_len++;

	if (ucs2_align(NULL, dest, flags)) {
		*(char *)dest = 0;
		dest = (void *)((char *)dest + 1);
		if (dest_len) dest_len--;
		len++;
	}

	/* ucs2 is always a multiple of 2 bytes */
	dest_len &= ~1;

	ret = convert_string(CH_UNIX, CH_UTF16, src, src_len, dest, dest_len, &size);
	if (ret == false) {
		return 0;
	}

	len += size;

	return (ssize_t)len;
}


/**
 Copy a string from a ucs2 source to a unix char* destination.
 Flags can have:
  STR_TERMINATE means the string in src is null terminated.
  STR_NOALIGN   means don't try to align.
 if STR_TERMINATE is set then src_len is ignored if it is -1.
 src_len is the length of the source area in bytes
 Return the number of bytes occupied by the string in src.
 The resulting string in "dest" is always null terminated.
**/

static size_t pull_ucs2(char *dest, const void *src, size_t dest_len, size_t src_len, int flags)
{
	size_t size = 0;

	if (ucs2_align(NULL, src, flags)) {
		src = (const void *)((const char *)src + 1);
		if (src_len > 0)
			src_len--;
	}

	if (flags & STR_TERMINATE) {
		if (src_len == (size_t)-1) {
			src_len = utf16_null_terminated_len(src);
		} else {
			src_len = utf16_null_terminated_len_n(src, src_len);
		}
	}

	/* ucs2 is always a multiple of 2 bytes */
	if (src_len != (size_t)-1)
		src_len &= ~1;

	/* We're ignoring the return here.. */
	(void)convert_string(CH_UTF16, CH_UNIX, src, src_len, dest, dest_len, &size);
	if (dest_len)
		dest[MIN(size, dest_len-1)] = 0;

	return src_len;
}

/**
 Copy a string from a char* src to a unicode or ascii
 dos codepage destination choosing unicode or ascii based on the
 flags in the SMB buffer starting at base_ptr.
 Return the number of bytes occupied by the string in the destination.
 flags can have:
  STR_TERMINATE means include the null termination.
  STR_UPPER     means uppercase in the destination.
  STR_ASCII     use ascii even with unicode packet.
  STR_NOALIGN   means don't do alignment.
 dest_len is the maximum length allowed in the destination. If dest_len
 is -1 then no maximum is used.
**/

_PUBLIC_ ssize_t push_string(void *dest, const char *src, size_t dest_len, int flags)
{
	if (flags & STR_ASCII) {
		size_t size = 0;
		if (push_ascii_string(dest, src, dest_len, flags, &size)) {
			return (ssize_t)size;
		} else {
			return (ssize_t)-1;
		}
	} else if (flags & STR_UNICODE) {
		return push_ucs2(dest, src, dest_len, flags);
	} else {
		smb_panic("push_string requires either STR_ASCII or STR_UNICODE flag to be set");
		return -1;
	}
}


/**
 Copy a string from a unicode or ascii source (depending on
 the packet flags) to a char* destination.
 Flags can have:
  STR_TERMINATE means the string in src is null terminated.
  STR_UNICODE   means to force as unicode.
  STR_ASCII     use ascii even with unicode packet.
  STR_NOALIGN   means don't do alignment.
 if STR_TERMINATE is set then src_len is ignored is it is -1
 src_len is the length of the source area in bytes.
 Return the number of bytes occupied by the string in src.
 The resulting string in "dest" is always null terminated.
**/

_PUBLIC_ ssize_t pull_string(char *dest, const void *src, size_t dest_len, size_t src_len, int flags)
{
	if (flags & STR_ASCII) {
		return pull_ascii_string(dest, src, dest_len, src_len, flags);
	} else if (flags & STR_UNICODE) {
		return pull_ucs2(dest, src, dest_len, src_len, flags);
	} else {
		smb_panic("pull_string requires either STR_ASCII or STR_UNICODE flag to be set");
		return -1;
	}
}
