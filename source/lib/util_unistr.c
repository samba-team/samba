/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-2001
   
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

 smb_ucs2_t wchar_list_sep[] = { (smb_ucs2_t)' ', (smb_ucs2_t)'\t', (smb_ucs2_t)',',
								(smb_ucs2_t)';', (smb_ucs2_t)':', (smb_ucs2_t)'\n',
								(smb_ucs2_t)'\r', 0 };
/*
 * The following are the codepage to ucs2 and vica versa maps.
 * These are dynamically loaded from a unicode translation file.
 */

#define CONV_DEBUGLEVEL		83

#ifndef MAXUNI
#define MAXUNI 1024
#endif

/*******************************************************************
 Write a string in (little-endian) unicode format. src is in
 the current DOS codepage. len is the length in bytes of the
 string pointed to by dst.

 if null_terminate is True then null terminate the packet (adds 2 bytes)

 the return value is the length in bytes consumed by the string, including the
 null termination if applied
********************************************************************/

size_t dos_PutUniCode(char *dst,const char *src, ssize_t len, BOOL null_terminate)
{
	return push_ucs2(NULL, dst, src, len, 
			 STR_UNICODE|STR_NOALIGN | (null_terminate?STR_TERMINATE:0));
}


/*******************************************************************
 Skip past a unicode string, but not more than len. Always move
 past a terminating zero if found.
********************************************************************/

char *skip_unibuf(char *src, size_t len)
{
    char *srcend = src + len;

    while (src < srcend && SVAL(src,0))
        src += 2;

    if(!SVAL(src,0))
        src += 2;

    return src;
}

/* Copy a string from little-endian or big-endian unicode source (depending
 * on flags) to internal samba format destination
 */ 
int rpcstr_pull(char* dest, void *src, int dest_len, int src_len, int flags)
{
	if(dest_len==-1) dest_len=MAXUNI-3;
	return pull_ucs2(NULL, dest, src, dest_len, src_len, flags|STR_UNICODE|STR_NOALIGN);
}

/* Converts a string from internal samba format to unicode
 */ 
int rpcstr_push(void* dest, const char *src, int dest_len, int flags)
{
	return push_ucs2(NULL, dest, src, dest_len, flags|STR_UNICODE|STR_NOALIGN);
}

/*******************************************************************
 Return a DOS codepage version of a little-endian unicode string.
 len is the filename length (ignoring any terminating zero) in uin16
 units. Always null terminates.
 Hack alert: uses fixed buffer(s).
********************************************************************/
char *dos_unistrn2(uint16 *src, int len)
{
	static char lbufs[8][MAXUNI];
	static int nexti;
	char *lbuf = lbufs[nexti];
	nexti = (nexti+1)%8;
	pull_ucs2(NULL, lbuf, src, MAXUNI-3, len*2, STR_NOALIGN);
	return lbuf;
}

/*******************************************************************
 Convert a (little-endian) UNISTR2 structure to an ASCII string
********************************************************************/
void unistr2_to_ascii(char *dest, const UNISTR2 *str, size_t maxlen)
{
	if (str == NULL) {
		*dest='\0';
		return;
	}
	pull_ucs2(NULL, dest, str->buffer, maxlen, str->uni_str_len*2, STR_NOALIGN);
}


/*******************************************************************
Return a number stored in a buffer
********************************************************************/

uint32 buffer2_to_uint32(BUFFER2 *str)
{
	if (str->buf_len == 4)
		return IVAL(str->buffer, 0);
	else
		return 0;
}

/*******************************************************************
 Mapping tables for UNICODE character. Allows toupper/tolower and
 isXXX functions to work.

 tridge: split into 2 pieces. This saves us 5/6 of the memory
 with a small speed penalty
 The magic constants are the lower/upper range of the tables two
 parts
********************************************************************/

typedef struct {
	smb_ucs2_t lower;
	smb_ucs2_t upper;
	unsigned char flags;
} smb_unicode_table_t;

#define TABLE1_BOUNDARY 9450
#define TABLE2_BOUNDARY 64256

static smb_unicode_table_t map_table1[] = {
#include "unicode_map_table1.h"
};

static smb_unicode_table_t map_table2[] = {
#include "unicode_map_table2.h"
};

static unsigned char map_table_flags(smb_ucs2_t v)
{
	if (v < TABLE1_BOUNDARY) return map_table1[v].flags;
	if (v >= TABLE2_BOUNDARY) return map_table2[v - TABLE2_BOUNDARY].flags;
	return 0;
}

static smb_ucs2_t map_table_lower(smb_ucs2_t v)
{
	if (v < TABLE1_BOUNDARY) return map_table1[v].lower;
	if (v >= TABLE2_BOUNDARY) return map_table2[v - TABLE2_BOUNDARY].lower;
	return v;
}

static smb_ucs2_t map_table_upper(smb_ucs2_t v)
{
	if (v < TABLE1_BOUNDARY) return map_table1[v].upper;
	if (v >= TABLE2_BOUNDARY) return map_table2[v - TABLE2_BOUNDARY].upper;
	return v;
}

/*******************************************************************
 Is an upper case wchar.
********************************************************************/

int isupper_w( smb_ucs2_t val)
{
	return (map_table_flags(val) & UNI_UPPER);
}

/*******************************************************************
 Is a lower case wchar.
********************************************************************/

int islower_w( smb_ucs2_t val)
{
	return (map_table_flags(val) & UNI_LOWER);
}

/*******************************************************************
 Convert a wchar to upper case.
********************************************************************/

smb_ucs2_t toupper_w( smb_ucs2_t val )
{
	return map_table_upper(val);
}

/*******************************************************************
 Convert a wchar to lower case.
********************************************************************/

smb_ucs2_t tolower_w( smb_ucs2_t val )
{
	return map_table_lower(val);
}

/*******************************************************************
 Count the number of characters in a smb_ucs2_t string.
********************************************************************/
size_t strlen_w(const smb_ucs2_t *src)
{
	size_t len;

	for(len = 0; *src++; len++) ;

	return len;
}

/*******************************************************************
wide strchr()
********************************************************************/
smb_ucs2_t *strchr_w(const smb_ucs2_t *s, smb_ucs2_t c)
{
	while (*s != 0) {
		if (c == *s) return (smb_ucs2_t *)s;
		s++;
	}
	return NULL;
}


/*******************************************************************
 Convert a string to lower case.
********************************************************************/
void strlower_w(smb_ucs2_t *s)
{
	while (*s) {
		if (isupper_w(*s))
			*s = tolower_w(*s);
		s++;
	}
}

/*******************************************************************
 Convert a string to upper case.
********************************************************************/
void strupper_w(smb_ucs2_t *s)
{
	while (*s) {
		if (islower_w(*s))
			*s = toupper_w(*s);
		s++;
	}
}

/*******************************************************************
case insensitive string comparison
********************************************************************/
int strcasecmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b)
{
	while (*b && tolower_w(*a) == tolower_w(*b)) { a++; b++; }
	return (tolower_w(*a) - tolower_w(*b));
}


/*
  The *_wa() functions take a combination of 7 bit ascii
  and wide characters They are used so that you can use string
  functions combining C string constants with ucs2 strings

  The char* arguments must NOT be multibyte - to be completely sure
  of this only pass string constants */


void pstrcpy_wa(smb_ucs2_t *dest, const char *src)
{
	int i;
	for (i=0;i<PSTRING_LEN;i++) {
		dest[i] = UCS2_CHAR(src[i]);
		if (src[i] == 0) return;
	}
}

int strcmp_wa(const smb_ucs2_t *a, const char *b)
{
	while (*b && *a == UCS2_CHAR(*b)) { a++; b++; }
	return (*a - UCS2_CHAR(*b));
}

smb_ucs2_t *strchr_wa(const smb_ucs2_t *s, char c)
{
	while (*s != 0) {
		if (UCS2_CHAR(c) == *s) return (smb_ucs2_t *)s;
		s++;
	}
	return NULL;
}

smb_ucs2_t *strrchr_wa(const smb_ucs2_t *s, char c)
{
	const smb_ucs2_t *p = s;
	int len = strlen_w(s);
	if (len == 0) return NULL;
	p += (len-1);
	while (p != s) {
		if (UCS2_CHAR(c) == *p) return (smb_ucs2_t *)p;
		p--;
	}
	return NULL;
}

smb_ucs2_t *strpbrk_wa(const smb_ucs2_t *s, const char *p)
{
	while (*s != 0) {
		int i;
		for (i=0; p[i] && *s != UCS2_CHAR(p[i]); i++) 
			;
		if (p[i]) return (smb_ucs2_t *)s;
		s++;
	}
	return NULL;
}

