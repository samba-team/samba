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

const char* unibuf_to_ascii(char *dest, const char *src, int maxlen)
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

void unistr2_to_ascii(char *dest, const UNISTR2 *str, size_t maxlen)
{
	char *destend;
	const uint16 *src;
	size_t len;
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
		const uchar *src = str->buffer;
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
void buffer2_to_multistr(char *dest, const BUFFER2 *str, size_t maxlen)
{
	char *destend;
	const uchar *src;
	size_t len;
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

/*******************************************************************
  Convert a buffer4 to space-separated ASCII.
 ********************************************************************/
void buffer4_to_str(char *dest, const BUFFER4 *str, size_t maxlen)
{
	char *destend;
	const uchar *src;
	size_t len;
	register uint16 c;

	src = str->buffer;
	len = MIN(str->buf_len, maxlen);
	destend = dest + len;

	while (dest < destend)
	{
		c = *(src++);
		*(dest++) = (char)c;
	}

	*dest = 0;
}

/*******************************************************************
copies a UNISTR2 structure.
********************************************************************/
BOOL unistr2upper(UNISTR2 *str, const UNISTR2 *from)
{
	if (from != NULL)
	{
		int i;

		ZERO_STRUCTP(str);

		/* copy up string lengths*/
		str->uni_max_len = from->uni_max_len;
		str->undoc       = from->undoc;
		str->uni_str_len = from->uni_str_len;

		/* copy the string */
		for (i = 0; i < from->uni_str_len; i++)
		{
			str->buffer[i] = toupper(from->buffer[i]);
		}
	}
	else
	{
		str->uni_max_len = 1;
		str->undoc = 0;
		str->uni_str_len = 1;
		str->buffer[0] = 0;
	}

	return True;
}

/*******************************************************************
copies a UNISTR2 structure.
********************************************************************/
BOOL copy_unistr2(UNISTR2 *str, const UNISTR2 *from)
{
	if (from != NULL)
	{
		ZERO_STRUCTP(str);

		/* set up string lengths. add one if string is not null-terminated */
		str->uni_max_len = from->uni_max_len;
		str->undoc       = from->undoc;
		str->uni_str_len = from->uni_str_len;

		/* copy the string */
		memcpy(str->buffer, from->buffer, str->uni_str_len * 2);
	}
	else
	{
		str->uni_max_len = 1;
		str->undoc = 0;
		str->uni_str_len = 1;
		str->buffer[0] = 0;
	}

	return True;
}

/*******************************************************************
duplicates a UNISTR2 structure.
********************************************************************/
UNISTR2 *unistr2_dup(const UNISTR2 *name)
{
	UNISTR2 *copy = (UNISTR2*)malloc(sizeof(*copy));
	copy_unistr2(copy, name);
	return copy;
}

/*******************************************************************
frees a UNISTR2 structure.
********************************************************************/
void unistr2_free(UNISTR2 *name)
{
	free(name);
}
