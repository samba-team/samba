/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   client string routines
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Jeremy Allison 2001
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#define NO_SYSLOG

#include "includes.h"

#define UNICODE_FLAG(cli, flags) (!(flags & STR_ASCII) && \
                                  ((flags & STR_UNICODE || \
                                   (SVAL(cli->outbuf, smb_flg2) & FLAGS2_UNICODE_STRINGS))))

/****************************************************************************
copy a string from a char* src to a unicode or ascii
dos code page destination choosing unicode or ascii based on the 
cli->capabilities flag
return the number of bytes occupied by the string in the destination
flags can have:
  STR_TERMINATE means include the null termination
  STR_CONVERT   means convert from unix to dos codepage
  STR_UPPER     means uppercase in the destination
  STR_ASCII     use ascii even with unicode servers
  STR_NOALIGN   means don't do alignment
dest_len is the maximum length allowed in the destination. If dest_len
is -1 then no maxiumum is used
****************************************************************************/

int clistr_push(struct cli_state *cli, void *dest, const char *src, int dest_len, int flags)
{
	int len=0;

	/* treat a pstring as "unlimited" length */
	if (dest_len == -1)
		dest_len = sizeof(pstring);

	if (clistr_align_out(cli, dest, flags)) {
		*(char *)dest = 0;
		dest = (void *)((char *)dest + 1);
		dest_len--;
		len++;
	}

	if (!UNICODE_FLAG(cli, flags)) {
		/* the server doesn't want unicode */
		safe_strcpy(dest, src, dest_len);
		len = strlen(dest);
		if (flags & STR_TERMINATE)
			len++;
		if (flags & STR_CONVERT)
			unix_to_dos(dest);
		if (flags & STR_UPPER)
			strupper(dest);
		return len;
	}

	/* the server likes unicode. give it the works */
	if (flags & STR_CONVERT)
		dos_PutUniCode(dest, unix_to_dos_static(src), dest_len, flags & STR_TERMINATE);
	else
		unix_PutUniCode(dest, src, dest_len, flags & STR_TERMINATE);

	if (flags & STR_UPPER)
		strupper_w(dest);

	len += strlen(src)*2;
	if (flags & STR_TERMINATE)
		len += 2;
	return len;
}

/****************************************************************************
copy a string from a unicode or dos codepage source (depending on
cli->capabilities) to a unix char* destination
flags can have:
  STR_TERMINATE means the string in src is null terminated
  STR_UNICODE   means to force as unicode
  STR_NOALIGN   means don't do alignment
if STR_TERMINATE is set then src_len is ignored
src_len is the length of the source area in bytes
return the number of bytes occupied by the string in src
****************************************************************************/

int clistr_pull(struct cli_state *cli, char *dest, const void *src, int dest_len, int src_len, int flags)
{
	int len;

	if (dest_len == -1)
		dest_len = sizeof(pstring);

	if (clistr_align_in(cli, src, flags)) {
		src = (const void *)((const char *)src + 1);
		if (src_len > 0)
			src_len--;
	}

	if (!UNICODE_FLAG(cli, flags)) {
		/* the server doesn't want unicode */
		if (flags & STR_TERMINATE) {
			safe_strcpy(dest, src, dest_len);
			len = strlen(src)+1;
		} else {
			if (src_len > dest_len)
				src_len = dest_len;
			len = src_len;
			memcpy(dest, src, len);
			dest[len] = 0;
		}
		safe_strcpy(dest,dos_to_unix_static(dest),dest_len);
		return len;
	}

	if (flags & STR_TERMINATE) {
		int i;
		src_len = strlen_w(src)*2+2;
		for (i=0; i < src_len; i += 2) {
			const smb_ucs2_t c = (smb_ucs2_t)SVAL(src, i);
			if (c == (smb_ucs2_t)0 || (dest_len - i < 3))
				break;
			dest += unicode_to_unix_char(dest, c);
		}
		*dest++ = 0;
		len = src_len;
	} else {
		int i;
		if (dest_len*2 < src_len)
			src_len = 2*dest_len;
		for (i=0; i < src_len; i += 2) {
			const smb_ucs2_t c = (smb_ucs2_t)SVAL(src, i);
			dest += unicode_to_unix_char(dest, c);
		}
		*dest++ = 0;
		len = src_len;
	}
	return len;
}

/****************************************************************************
 Return an alignment of either 0 or 1.
 If unicode is not negotiated then return 0
 otherwise return 1 if offset is off.
****************************************************************************/

static int clistr_align(struct cli_state *cli, char *buf, const void *p, int flags)
{
	if ((flags & STR_NOALIGN) || !UNICODE_FLAG(cli, flags))
		return 0;
	return PTR_DIFF(p, buf) & 1;
}

int clistr_align_out(struct cli_state *cli, const void *p, int flags)
{
	return clistr_align(cli, cli->outbuf, p, flags);
}

int clistr_align_in(struct cli_state *cli, const void *p, int flags)
{
	return clistr_align(cli, cli->inbuf, p, flags);
}
