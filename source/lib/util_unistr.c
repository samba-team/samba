/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   
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

extern int DEBUGLEVEL;

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
char *unistr2_to_ascii(char *dest, const UNISTR2 *str, size_t maxlen)
{
	char *destend;
	const uint16 *src;
	char *origdest;
	size_t len;
	register uint16 c;

	if (str == NULL)
		return NULL;

	src = str->buffer;

	if (dest == NULL)
	{
		if (maxlen == 0)
		{
			maxlen = str->uni_str_len;
		}
		dest = g_new(char, maxlen + 1);
		if (dest == NULL)
		{
			DEBUG(2, ("malloc(%d) problem in unistr2_to_ascii\n",
				  maxlen + 1));
			return NULL;
		}
	}

	len = MIN(str->uni_str_len, maxlen);
	origdest = dest;
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

	return origdest;
}

/*******************************************************************
 Skip past some unicode strings in a buffer.
********************************************************************/

char *skip_unicode_string(char *buf,int n)
{
	while (n--) {
		while (*buf)
			buf += 2;
		buf += 2;
	}
	return(buf);
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
 Strcpy for unicode strings.  returns length (in num of wide chars)
********************************************************************/

int unistrcpy(char *dst, char *src)
{
	int num_wchars = 0;
	uint16 *wsrc = (uint16 *)src;
	uint16 *wdst = (uint16 *)dst;

	while (*wsrc) {
		*wdst++ = *wsrc++;
		num_wchars++;
	}
	*wdst = 0;

	return num_wchars;
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
creates a new UNISTR2.
********************************************************************/
UNISTR2 *unistr2_new(const char *init)
{
	UNISTR2 *str;
	str = g_new(UNISTR2, 1);
	if (str == NULL)
	{
		DEBUG(1, ("malloc problem in unistr2_new\n"));
		return NULL;
	}

	str->uni_max_len = 0;
	str->undoc       = 0;
	str->uni_str_len = 0;

	if (init != NULL)
	{
		unistr2_assign_ascii_str(str, init);
	}

	return str;
}

UNISTR2 *unistr2_assign(UNISTR2 *str, const uint16 *src, size_t len)
{
	if (str == NULL)
	{
		DEBUG(1, ("NULL unistr2\n"));
		return NULL;
	}

	if (src == NULL)
	{
		len = 0;
	}

	if (len >= MAX_UNISTRLEN)
	{
		len = MAX_UNISTRLEN - 1;
	}

	unistr2_grow(str, len + 1);

	/* set up string lengths. */
	str->uni_max_len = len;
	str->undoc       = 0;
	str->uni_str_len = len;

	if (len != 0)
	{
		memcpy(str->buffer, src, len * sizeof(uint16));
	}
	str->buffer[len] = 0;

	return str;
}

UNISTR2 *unistr2_assign_ascii(UNISTR2 *str, const char *buf, int len)
{
	if (str == NULL)
	{
		DEBUG(1, ("NULL unistr2\n"));
		return NULL;
	}

	if (buf == NULL)
	{
		len = 0;
	}

	if (len >= MAX_UNISTRLEN)
	{
		len = MAX_UNISTRLEN - 1;
	}

	unistr2_grow(str, len + 1);

	/* set up string lengths. */
	str->uni_max_len = len;
	str->undoc       = 0;
	str->uni_str_len = len;

	/* store the string (wide chars) */
	ascii_to_unistr(str->buffer, buf, len);

	return str;
}

UNISTR2 *unistr2_assign_ascii_str(UNISTR2 *str, const char *buf)
{
	return unistr2_assign_ascii(str, buf, (buf ? strlen(buf) : 0));
}

/*******************************************************************
grows the buffer of a UNISTR2.
  doesn't shrink
  doesn't modify lengh
********************************************************************/
UNISTR2 *unistr2_grow(UNISTR2 *str, size_t new_size)
{
	if (str == NULL)
	{
		DEBUG(1, ("NULL unistr2\n"));
		return NULL;
	}
	/* It's currently a fake, yes */
	if (new_size > MAX_UNISTRLEN)
	{
		DEBUG(3, ("Growing buffer beyond its current static size\n"));
	}
	return str;
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
	if (str == NULL)
	{
		return False;
	}
	if (from != NULL)
	{
		ZERO_STRUCTP(str);

		/* set up string lengths. add one if string is not null-terminated */
		str->uni_max_len = from->uni_max_len;
		str->undoc       = from->undoc;
		str->uni_str_len = from->uni_str_len;

		/* copy the string */
		memcpy(str->buffer, from->buffer, str->uni_str_len * 2);
		DEBUG(10,("copy_unistr2: string len %d\n", str->uni_str_len));
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
	safe_free(name);
}

/*******************************************************************
  case insensitive string compararison
********************************************************************/
int StrCaseCmpW(const UNISTR2 *ws, const UNISTR2 *wt)
{
	int len = MIN(ws->uni_str_len, wt->uni_str_len);
	uint16 *s = ws->buffer;
	uint16 *t = wt->buffer;
	uint16 sc;
	uint16 tc;

    while (len > 0 && *s && *t && toupper(*s) == toupper(*t))
    {
      s++;
      t++;
	len--;
    }

	if (len == 0 && ws->uni_str_len == wt->uni_str_len)
	{
		return 0;
	}

    sc = toupper(*s);
    tc = toupper(*t);

	if (wt->uni_str_len > ws->uni_str_len)
	{
		/* wt is longer, therefore last ws char must be 0 */
		sc = 0;
	}

	if (ws->uni_str_len > wt->uni_str_len)
	{
		/* ws is longer, therefore last wt char must be 0 */
		tc = 0;
	}

    return sc - tc;
}

/*******************************************************************
  compare 2 UNISTR2 strings .  first implementation, unicode string
  comparison isn't simple, you don't necessarily have a NULL-termination
  character but it's the same string...
********************************************************************/
BOOL unistr2equal(const UNISTR2 *s1, const UNISTR2 *s2)
{
#if 0
	DEBUG(20,("unistr2equal:\n"));
	dump_data(20, s1, sizeof(*s1));
	dump_data(20, s2, sizeof(*s2));
#endif

  if (s1 == s2) return(True);
  if (!s1 || !s2) return(False);
  
  return(StrCaseCmpW(s1,s2)==0);
}
