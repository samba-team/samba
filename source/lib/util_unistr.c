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
write a string in unicoode format
********************************************************************/
int PutUniCode(char *dst,char *src)
{
  int ret = 0;
  while (*src) {
    dst[ret++] = src[0];
    dst[ret++] = 0;    
    src++;
  }
  dst[ret++]=0;
  dst[ret++]=0;
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
Return a ascii version of a unicode string
Hack alert: uses fixed buffer(s) and only handles ascii strings
********************************************************************/
#define MAXUNI 1024
char *unistrn2(char *buf, int len)
{
	static char lbufs[8][MAXUNI];
	static int nexti;
	char *lbuf = lbufs[nexti];
	char *p;

	nexti = (nexti+1)%8;

	for (p = lbuf; *buf && p-lbuf < MAXUNI-2 && len > 0; len--, p++, buf+=2)
	{
		SSVAL(p, 0, *buf);
	}

	*p = 0;
	return lbuf;
}

static char lbufs[8][MAXUNI];
static int nexti;
/*******************************************************************
Return a ascii version of a unicode string
Hack alert: uses fixed buffer(s) and only handles ascii strings
********************************************************************/
#define MAXUNI 1024
char *unistr2(uint16 *buf)
{
	char *lbuf = lbufs[nexti];
	char *p;

	nexti = (nexti+1)%8;

	for (p = lbuf; *buf && p-lbuf < MAXUNI-2; p++, buf++)
	{
		*p = *buf;
	}

	*p = 0;
	return lbuf;
}

/*******************************************************************
Return a ascii version of a unicode string
********************************************************************/
char *unistr2_to_str(UNISTR2 *str)
{
	char *lbuf = lbufs[nexti];
	char *p;
	uint16 *buf = str->buffer;
	int max_size = MIN(sizeof(str->buffer)-2, str->uni_str_len);

	nexti = (nexti+1)%8;

	for (p = lbuf; *buf && p-lbuf < max_size; p++, buf++)
	{
		*p = *buf;
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
	uint16 *buf = str->buffer;
	int max_size = MIN(sizeof(str->buffer)-2, str->buf_len/2);

	nexti = (nexti+1)%8;

	for (p = lbuf; *buf && p-lbuf < max_size; p++, buf++)
	{
		*p = *buf;
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
	uint16 *buf = str->buffer;
	int max_size = MIN(sizeof(str->buffer)-2, str->buf_len/2);

	nexti = (nexti+1)%8;

	for (p = lbuf; p-lbuf < max_size; p++, buf++)
	{
		if (*buf == 0)
		{
			*p = ' ';
		}
		else
		{
			*p = *buf;
		}
	}

	*p = 0;
	return lbuf;
}

/*******************************************************************
create a null-terminated unicode string from a null-terminated ascii string.
return number of unicode chars copied, excluding the null character.

only handles ascii strings
********************************************************************/
#define MAXUNI 1024
int struni2(char *p, const char *buf)
{
	int len = 0;

	if (p == NULL) return 0;

	if (buf != NULL)
	{
		for (; *buf && len < MAXUNI-2; len++, p += 2, buf++)
		{
			SSVAL(p, 0, *buf);
		}
	}

	*p = 0;

	return len;
}

/*******************************************************************
Return a ascii version of a unicode string
Hack alert: uses fixed buffer(s) and only handles ascii strings
********************************************************************/
#define MAXUNI 1024
char *unistr(char *buf)
{
	char *lbuf = lbufs[nexti];
	char *p;

	nexti = (nexti+1)%8;

	for (p = lbuf; *buf && p-lbuf < MAXUNI-2; p++, buf += 2)
	{
		*p = *buf;
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

