/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   client string routines
   Copyright (C) Andrew Tridgell 2001
   
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
dest_len is the maximum length allowed in the destination. If dest_len
is -1 then no maxiumum is used
****************************************************************************/
int clistr_push(struct cli_state *cli, void *dest, const char *src, int dest_len, int flags)
{
	int len=0;

	/* treat a pstring as "unlimited" length */
	if (dest_len == -1) {
		dest_len = sizeof(pstring);
	}

	if (!(flags & STR_ASCII) && clistr_align(cli, PTR_DIFF(dest, cli->outbuf))) {
		*(char *)dest = 0;
		dest++;
		dest_len--;
		len++;
	}

	if ((flags & STR_ASCII) || !(cli->capabilities & CAP_UNICODE)) {
		/* the server doesn't want unicode */
		safe_strcpy(dest, src, dest_len);
		len = strlen(dest);
		if (flags & STR_TERMINATE) len++;
		if (flags & STR_CONVERT) unix_to_dos(dest,True);
		if (flags & STR_UPPER) strupper(dest);
		return len;
	}

	/* the server likes unicode. give it the works */
	if (flags & STR_CONVERT) {
		dos_PutUniCode(dest, src, dest_len, flags & STR_TERMINATE);
	} else {
		ascii_to_unistr(dest, src, dest_len);
	}
	if (flags & STR_UPPER) {
		strupper_w(dest);
	}
	len += strlen(src)*2;
	if (flags & STR_TERMINATE) len += 2;
	return len;
}


/****************************************************************************
return the length that a string would occupy when copied with clistr_push()
  STR_TERMINATE means include the null termination
  STR_CONVERT   means convert from unix to dos codepage
  STR_UPPER     means uppercase in the destination
note that dest is only used for alignment purposes. No data is written.
****************************************************************************/
int clistr_push_size(struct cli_state *cli, const void *dest, const char *src, int dest_len, int flags)
{
	int len = strlen(src);
	if (flags & STR_TERMINATE) len++;
	if (!(flags & STR_ASCII) && (cli->capabilities & CAP_UNICODE)) len *= 2;

	if (!(flags & STR_ASCII) && dest && clistr_align(cli, PTR_DIFF(cli->outbuf, dest))) {
		len++;
	}

	return len;
}

/****************************************************************************
copy a string from a unicode or ascii source (depending on
cli->capabilities) to a char* destination
flags can have:
  STR_CONVERT   means convert from dos to unix codepage
  STR_TERMINATE means the string in src is null terminated
  STR_UNICODE   means to force as unicode
if STR_TERMINATE is set then src_len is ignored
src_len is the length of the source area in bytes
return the number of bytes occupied by the string in src
****************************************************************************/
int clistr_pull(struct cli_state *cli, char *dest, const void *src, int dest_len, int src_len, int flags)
{
	int len;

	if (dest_len == -1) {
		dest_len = sizeof(pstring);
	}

	if (clistr_align(cli, PTR_DIFF(src, cli->inbuf))) {
		src++;
		if (src_len > 0) src_len--;
	}

	if (!(flags & STR_UNICODE) && !(cli->capabilities & CAP_UNICODE)) {
		/* the server doesn't want unicode */
		if (flags & STR_TERMINATE) {
			safe_strcpy(dest, src, dest_len);
			len = strlen(src)+1;
		} else {
			if (src_len > dest_len) src_len = dest_len;
			len = src_len;
			memcpy(dest, src, len);
			dest[len] = 0;
		}
		if (flags & STR_CONVERT) dos_to_unix(dest,True);
		return len;
	}

	if (flags & STR_TERMINATE) {
		unistr_to_ascii(dest, src, dest_len);
		len = strlen(dest)*2 + 2;
	} else {
		int i, c;
		if (dest_len*2 < src_len) src_len = 2*dest_len;
		for (i=0; i < src_len; i += 2) {
			c = SVAL(src, i);
			*dest++ = c;
		}
		*dest++ = 0;
		len = src_len;
	}
	if (flags & STR_CONVERT) dos_to_unix(dest,True);
	return len;
}

/****************************************************************************
return the length that a string would occupy (not including the null)
when copied with clistr_pull()
if src_len is -1 then assume the source is null terminated
****************************************************************************/
int clistr_pull_size(struct cli_state *cli, const void *src, int src_len)
{
	if (clistr_align(cli, PTR_DIFF(src, cli->inbuf))) {
		src++;
		if (src_len > 0) src_len--;
	}

	if (!(cli->capabilities & CAP_UNICODE)) {
		return strlen(src);
	}	
	return strlen_w(src);
}

/****************************************************************************
return an alignment of either 0 or 1
if unicode is not negotiated then return 0
otherwise return 1 if offset is off
****************************************************************************/
int clistr_align(struct cli_state *cli, int offset)
{
	if (!(cli->capabilities & CAP_UNICODE)) return 0;
	return offset & 1;
}
