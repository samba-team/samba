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

#ifndef MAXUNI
#define MAXUNI 1024
#endif

/*******************************************************************
write a string in (little-endian) unicoode format
********************************************************************/

int PutUniCode(char *dst,char *src)
{
  int ret = 0;
  while (*src) {
    SSVAL(dst,ret,(*src) & 0xFF);
    ret += 2;
    src++;
  }
  SSVAL(dst,ret,0);
  ret += 2;
  return(ret);
}

/*******************************************************************
skip past some unicode strings in a buffer
********************************************************************/

char *skip_unicode_string(char *buf,int n)
{
  while (n--)
  {
    while (*buf)
      buf += 2;
    buf += 2;
  }
  return(buf);
}

/*******************************************************************
Return a ascii version of a little-endian unicode string.
Hack alert: uses fixed buffer(s) and only handles ascii strings
********************************************************************/

char *unistrn2(uint16 *src, int len)
{
	static char lbufs[8][MAXUNI];
	static int nexti;
	char *lbuf = lbufs[nexti];
	char *p;

	nexti = (nexti+1)%8;

	for (p = lbuf; *src && p-lbuf < MAXUNI-2 && len > 0; len--, src++)
	{
		*p++ = (SVAL(src,0) & 0xff);
	}

	*p = 0;
	return lbuf;
}

static char lbufs[8][MAXUNI];
static int nexti;

/*******************************************************************
Return a ascii version of a little-endian unicode string.
Hack alert: uses fixed buffer(s) and only handles ascii strings
********************************************************************/

char *unistr2(uint16 *src)
{
	char *lbuf = lbufs[nexti];
	char *p;

	nexti = (nexti+1)%8;

	for (p = lbuf; *src && p-lbuf < MAXUNI-2; p++, src++)
	{
		*p = (SVAL(src,0) & 0xff);
	}

	*p = 0;
	return lbuf;
}

/*******************************************************************
Return a ascii version of a little-endian unicode string
********************************************************************/

char *unistr2_to_str(UNISTR2 *str)
{
	char *lbuf = lbufs[nexti];
	char *p;
	uint16 *src = str->buffer;
	int max_size = MIN(sizeof(str->buffer)-2, str->uni_str_len);

	nexti = (nexti+1)%8;

	for (p = lbuf; *src && p-lbuf < max_size; p++, src++)
	{
		*p = (SVAL(src,0) & 0xff);
	}

	*p = 0;
	return lbuf;
}

/*******************************************************************
Return a number stored in a buffer
********************************************************************/

uint32 buffer2_to_uint32(BUFFER2 *str)
{
	if (str->buf_len == 4)
	{
		return IVAL(str->buffer, 0);
	}
	else
	{
		return 0;
	}
}

/*******************************************************************
Return a ascii version of a NOTunicode string
********************************************************************/

char *buffer2_to_str(BUFFER2 *str)
{
	char *lbuf = lbufs[nexti];
	char *p;
	uint16 *src = str->buffer;
	int max_size = MIN(sizeof(str->buffer)-2, str->buf_len/2);

	nexti = (nexti+1)%8;

	for (p = lbuf; *src && p-lbuf < max_size; p++, src++)
	{
		*p = (SVAL(src,0) & 0xff);
	}

	*p = 0;
	return lbuf;
}

/*******************************************************************
Return a ascii version of a NOTunicode string
********************************************************************/

char *buffer2_to_multistr(BUFFER2 *str)
{
	char *lbuf = lbufs[nexti];
	char *p;
	uint16 *src = str->buffer;
	int max_size = MIN(sizeof(str->buffer)-2, str->buf_len/2);

	nexti = (nexti+1)%8;

	for (p = lbuf; p-lbuf < max_size; p++, src++)
	{
		if (*src == 0)
		{
			*p = ' ';
		}
		else
		{
			*p = (SVAL(src,0) & 0xff);
		}
	}

	*p = 0;
	return lbuf;
}

/*******************************************************************
create a null-terminated unicode string from a null-terminated ascii string.
return number of unicode chars copied, excluding the null character.
only handles ascii strings
Unicode strings created are in little-endian format.
********************************************************************/

int struni2(char *dst, const char *src)
{
	size_t len = 0;

	if (dst == NULL)
		return 0;

	if (src != NULL)
	{
		for (; *src && len < MAXUNI-2; len++, dst +=2, src++)
		{
			SSVAL(dst,0,(*src) & 0xFF);
		}
	}

	SSVAL(dst,0,0);

	return len;
}

/*******************************************************************
Return a ascii version of a little-endian unicode string.
Hack alert: uses fixed buffer(s) and only handles ascii strings
********************************************************************/

char *unistr(char *buf)
{
	char *lbuf = lbufs[nexti];
	char *p;

	nexti = (nexti+1)%8;

	for (p = lbuf; *buf && p-lbuf < MAXUNI-2; p++, buf += 2)
	{
		*p = (SVAL(buf,0) & 0xff);
	}
	*p = 0;
	return lbuf;
}


/*******************************************************************
strcpy for unicode strings.  returns length (in num of wide chars)
********************************************************************/

int unistrcpy(char *dst, char *src)
{
	int num_wchars = 0;

	while (*src)
	{
		*dst++ = *src++;
		*dst++ = *src++;
		num_wchars++;
	}
	*dst++ = 0;
	*dst++ = 0;

	return num_wchars;
}
