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

uint16_t *talloc_utf16_strlendup(TALLOC_CTX *mem_ctx, const char *str, size_t len)
{
	uint16_t *new_str = NULL;

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

	{
		/*
		 * Ensure that the UTF‐16 string is
		 * null‐terminated.
		 */

		char *new_bytes = (char *)new_str;

		new_bytes[len] = '\0';
		new_bytes[len + 1] = '\0';
	}

	return new_str;
}

uint16_t *talloc_utf16_strdup(TALLOC_CTX *mem_ctx, const char *str)
{
	return talloc_utf16_strlendup(mem_ctx, str, utf16_len(str));
}

uint16_t *talloc_utf16_strndup(TALLOC_CTX *mem_ctx, const char *str, size_t n)
{
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
