/*
   Unix SMB/CIFS implementation.

   fixed string functions

   Copyright (C) Igor Vergeichik <iverg@mail.ru> 2001
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Simo Sorce 2001
   Copyright (C) Martin Pool 2003

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

size_t push_ascii_fstring(void *dest, const char *src)
{
	return push_ascii(dest, src, sizeof(fstring), STR_TERMINATE);
}

/********************************************************************
 Push an nstring - ensure null terminated. Written by
 moriyama@miraclelinux.com (MORIYAMA Masayuki).
********************************************************************/

size_t push_ascii_nstring(void *dest, const char *src)
{
	size_t i, buffer_len, dest_len;
	smb_ucs2_t *buffer;

	conv_silent = True;
	if (!push_ucs2_talloc(talloc_tos(), &buffer, src, &buffer_len)) {
		smb_panic("failed to create UCS2 buffer");
	}

	/* We're using buffer_len below to count ucs2 characters, not bytes. */
	buffer_len /= sizeof(smb_ucs2_t);

	dest_len = 0;
	for (i = 0; buffer[i] != 0 && (i < buffer_len); i++) {
		unsigned char mb[10];
		/* Convert one smb_ucs2_t character at a time. */
		size_t mb_len = convert_string(CH_UTF16LE, CH_DOS, buffer+i, sizeof(smb_ucs2_t), mb, sizeof(mb));
		if ((mb_len != (size_t)-1) && (dest_len + mb_len <= MAX_NETBIOSNAME_LEN - 1)) {
			memcpy((char *)dest + dest_len, mb, mb_len);
			dest_len += mb_len;
		} else {
			errno = E2BIG;
			break;
		}
	}
	((char *)dest)[dest_len] = '\0';

	conv_silent = False;
	TALLOC_FREE(buffer);
	return dest_len;
}

size_t pull_ascii_fstring(char *dest, const void *src)
{
	return pull_ascii(dest, src, sizeof(fstring), -1, STR_TERMINATE);
}

/* When pulling an nstring it can expand into a larger size (dos cp -> utf8). Cope with this. */

size_t pull_ascii_nstring(char *dest, size_t dest_len, const void *src)
{
	return pull_ascii(dest, src, dest_len, sizeof(nstring)-1, STR_TERMINATE);
}

/**
 Copy a string from a char* src to a UTF-8 destination.
 Return the number of bytes occupied by the string in the destination
 Flags can have:
  STR_TERMINATE means include the null termination
  STR_UPPER     means uppercase in the destination
 dest_len is the maximum length allowed in the destination. If dest_len
 is -1 then no maxiumum is used.
**/

static size_t push_utf8(void *dest, const char *src, size_t dest_len, int flags)
{
	size_t src_len = 0;
	size_t ret;
	char *tmpbuf = NULL;

	if (dest_len == (size_t)-1) {
		/* No longer allow dest_len of -1. */
		smb_panic("push_utf8 - invalid dest_len of -1");
	}

	if (flags & STR_UPPER) {
		tmpbuf = strupper_talloc(talloc_tos(), src);
		if (!tmpbuf) {
			return (size_t)-1;
		}
		src = tmpbuf;
		src_len = strlen(src);
	}

	src_len = strlen(src);
	if (flags & STR_TERMINATE) {
		src_len++;
	}

	ret = convert_string(CH_UNIX, CH_UTF8, src, src_len, dest, dest_len);
	TALLOC_FREE(tmpbuf);
	return ret;
}

size_t push_utf8_fstring(void *dest, const char *src)
{
	return push_utf8(dest, src, sizeof(fstring), STR_TERMINATE);
}

size_t pull_ucs2_fstring(char *dest, const void *src)
{
	return pull_ucs2(NULL, dest, src, sizeof(fstring), -1, STR_TERMINATE);
}
