/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   
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

#include "includes.h"

/*******************************************************************
 Put an ASCII string into a UNICODE buffer (little endian).
 ********************************************************************/

char *ascii_to_unibuf(char *dest, const char *src, int maxlen)
{
	char *destend = dest + maxlen;
	register char c;

	while (dest < destend)
	{
		c = *(src++);
		if (c == 0)
		{
			break;
		}

		*(dest++) = c;
		*(dest++) = 0;
	}

	*dest++ = 0;
	*dest++ = 0;
	return dest;
}


/*******************************************************************
 Pull an ASCII string out of a UNICODE buffer (little endian).
 ********************************************************************/
const char *unibuf_to_ascii(char *dest, const char *src, int maxlen)
{
	char *destend = dest + maxlen;
	register char c;

	while (dest < destend)
	{
		c = *(src++);
		if ((c == 0) && (*src == 0))
		{
			break;
		}

		*dest++ = c;
		src++;
	}

	*dest = 0;

	return src;
}


/*******************************************************************
 Put an ASCII string into a UNICODE array (uint16's).
 ********************************************************************/

void ascii_to_unistr(uint16 *dest, const char *src, int maxlen)
{
	uint16 *destend = dest + maxlen;
	register char c;

	while (dest < destend)
	{
		c = *(src++);
		if (c == 0)
		{
			break;
		}

		*(dest++) = (uint16)c;
	}

	*dest = 0;
}


/*******************************************************************
 Pull an ASCII string out of a UNICODE array (uint16's).
 ********************************************************************/

void unistr_to_ascii(char *dest, const uint16 *src, int len)
{
	char *destend = dest + len;
	register uint16 c;

	while (dest < destend)
	{
		c = *(src++);
		if (c == 0)
		{
			break;
		}

		*(dest++) = (char)c;
	}

	*dest = 0;
}


/*******************************************************************
 Convert a UNISTR2 structure to an ASCII string
 ********************************************************************/

void unistr2_to_ascii(char *dest, const UNISTR2 *str, int maxlen)
{
	char *destend;
	const uint16 *src;
	int len;
	register uint16 c;

	src = str->buffer;
	len = MIN(str->uni_str_len, maxlen);
	destend = dest + len;

	while (dest < destend)
	{
		c = *(src++);
		if (c == 0)
		{
			break;
		}

		*(dest++) = (char)c;
	}

	*dest = 0;
}


/*******************************************************************
 Skip a UNICODE string in a little endian buffer.
 ********************************************************************/

char *skip_unibuf(char *srcbuf, int len)
{
	uint16 *src = (uint16 *)srcbuf;
	uint16 *srcend = src + len/2;

	while ((src < srcend) && (*(src++) != 0))
	{
	}

	return (char *)src;
}


/*******************************************************************
 UNICODE strcpy between buffers.
 ********************************************************************/

char *uni_strncpy(char *destbuf, const char *srcbuf, int len)
{
	const uint16 *src = (const uint16 *)srcbuf;
	uint16 *dest = (uint16 *)destbuf;
	uint16 *destend = dest + len/2;
	register uint16 c;

	while (dest < destend)
	{
		c = *(src++);
		if (c == 0)
		{
			break;
		}

		*(dest++) = c;
	}

	*dest++ = 0;
	return (char *)dest;
}


/*******************************************************************
 Return a number stored in a buffer
 ********************************************************************/

uint32 buffer2_to_uint32(const BUFFER2 *str)
{
	if (str->buf_len == 4)
	{
		const char *src = str->buffer;
		return IVAL(src, 0);
	}
	else
	{
		return 0;
	}
}


/*******************************************************************
  Convert a 'multi-string' buffer to space-separated ASCII.
 ********************************************************************/

void buffer2_to_multistr(char *dest, const BUFFER2 *str, int maxlen)
{
	char *destend;
	const char *src;
	int len;
	register uint16 c;

	src = str->buffer;
	len = MIN(str->buf_len/2, maxlen);
	destend = dest + len;

	while (dest < destend)
	{
		c = *(src++);
		*(dest++) = (c == 0) ? ' ' : (char)c;
		src++;
	}

	*dest = 0;
}
