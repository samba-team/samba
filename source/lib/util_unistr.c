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

#ifndef MAXUNI
#define MAXUNI 1024
#endif

/* these 3 tables define the unicode case handling.  They are loaded
   at startup either via mmap() or read() from the lib directory */
static smb_ucs2_t *upcase_table;
static smb_ucs2_t *lowcase_table;
static uint8 *valid_table;

/*******************************************************************
load the case handling tables
********************************************************************/
void load_case_tables(void)
{
	static int initialised;
	int i;

	if (initialised) return;
	initialised = 1;

	upcase_table = map_file(lib_path("upcase.dat"), 0x20000);
	lowcase_table = map_file(lib_path("lowcase.dat"), 0x20000);
	valid_table = map_file(lib_path("valid.dat"), 0x10000);

	/* we would like Samba to limp along even if these tables are
	   not available */
	if (!upcase_table) {
		DEBUG(1,("creating lame upcase table\n"));
		upcase_table = malloc(0x20000);
		for (i=0;i<256;i++) upcase_table[i] = islower(i)?toupper(i):i;
		for (;i<0x10000;i++) upcase_table[i] = i;
	}

	if (!lowcase_table) {
		DEBUG(1,("creating lame lowcase table\n"));
		lowcase_table = malloc(0x20000);
		for (i=0;i<256;i++) lowcase_table[i] = isupper(i)?tolower(i):i;
		for (;i<0x10000;i++) lowcase_table[i] = i;
	}

	if (!valid_table) {
		const char *allowed = "!#$%&'()_-@^`~";
		DEBUG(1,("creating lame valid table\n"));
		valid_table = malloc(0x10000);
		for (i=0;i<256;i++) valid_table[i] = isalnum(i) || strchr(allowed,i);
		for (;i<0x10000;i++) valid_table[i] = 0;
	}
}


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

/* Copy a string from a unistr2 source to internal samba format
   destination.  Use this instead of direct calls to rpcstr_pull() to avoid
   having to determine whether the source string is null terminated. */

int rpcstr_pull_unistr2_fstring(char *dest, UNISTR2 *src)
{
        return pull_ucs2(NULL, dest, src->buffer, sizeof(fstring),
                         src->uni_str_len * 2, 0);
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
char *dos_unistrn2(const uint16 *src, int len)
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
 Convert a wchar to upper case.
********************************************************************/

smb_ucs2_t toupper_w(smb_ucs2_t val)
{
	return upcase_table[SVAL(&val,0)];
}

/*******************************************************************
 Convert a wchar to lower case.
********************************************************************/

smb_ucs2_t tolower_w( smb_ucs2_t val )
{
	return lowcase_table[SVAL(&val,0)];
}

/*******************************************************************
determine if a character is lowercase
********************************************************************/
BOOL islower_w(smb_ucs2_t c)
{
	return upcase_table[SVAL(&c,0)] != c;
}

/*******************************************************************
determine if a character is uppercase
********************************************************************/
BOOL isupper_w(smb_ucs2_t c)
{
	return lowcase_table[SVAL(&c,0)] != c;
}


/*******************************************************************
determine if a character is valid in a 8.3 name
********************************************************************/
BOOL isvalid83_w(smb_ucs2_t c)
{
	return valid_table[SVAL(&c,0)] != 0;
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
 return True if any char is converted
********************************************************************/
BOOL strlower_w(smb_ucs2_t *s)
{
	BOOL ret = False;
	while (*s) {
		smb_ucs2_t v = tolower_w(*s);
		if (v != *s) {
			*s = v;
			ret = True;
		}
		s++;
	}
	return ret;
}

/*******************************************************************
 Convert a string to upper case.
 return True if any char is converted
********************************************************************/
BOOL strupper_w(smb_ucs2_t *s)
{
	BOOL ret = False;
	while (*s) {
		smb_ucs2_t v = toupper_w(*s);
		if (v != *s) {
			*s = v;
			ret = True;
		}
		s++;
	}
	return ret;
}

/*******************************************************************
case insensitive string comparison
********************************************************************/
int strcasecmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b)
{
	while (*b && toupper_w(*a) == toupper_w(*b)) { a++; b++; }
	return (tolower_w(*a) - tolower_w(*b));
}


/*******************************************************************
duplicate string
********************************************************************/
smb_ucs2_t *strdup_w(const smb_ucs2_t *src)
{
	smb_ucs2_t *dest;
	uint32 len;
	
	len = strlen_w(src) + 1;
	dest = (smb_ucs2_t *)malloc(len*sizeof(smb_ucs2_t));
	if (!dest) {
		DEBUG(0,("strdup_w: out of memory!\n"));
		return NULL;
	}

	memcpy(dest, src, len*sizeof(smb_ucs2_t));
	
	return dest;
}

/*******************************************************************
copy a string with max len
********************************************************************/

smb_ucs2_t *strncpy_w(smb_ucs2_t *dest, const smb_ucs2_t *src, const size_t max)
{
	size_t len;
	
	if (!dest || !src) return NULL;
	
	for (len = 0; (src[len] != 0) && (len < max); len++)
		dest[len] = src[len];
	while (len < max)
		dest[len++] = 0;
	
	return dest;
}


/*******************************************************************
append a string of len bytes and add a terminator
********************************************************************/

smb_ucs2_t *strncat_w(smb_ucs2_t *dest, const smb_ucs2_t *src, const size_t max)
{	
	size_t start;
	size_t len;	
	
	if (!dest || !src) return NULL;
	
	start = strlen_w(dest);
	len = strlen_w(src);
	if (len > max) len = max;

	memcpy(&dest[start], src, len*sizeof(smb_ucs2_t));			
	dest[start+len] = 0;
	
	return dest;
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
	do {
		if (UCS2_CHAR(c) == *p) return (smb_ucs2_t *)p;
	} while (p-- != s);
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


/*******************************************************************
copy a string with max len
********************************************************************/

smb_ucs2_t *strncpy_wa(smb_ucs2_t *dest, const char *src, const size_t max)
{
	smb_ucs2_t *ucs2_src;

	if (!dest || !src) return NULL;
	ucs2_src = (smb_ucs2_t *)malloc((strlen(src)+1)*sizeof(smb_ucs2_t));
	if (!ucs2_src) {
		DEBUG(0,("strncpy_wa: out of memory!\n"));
		return NULL;
	}
	push_ucs2(NULL, ucs2_src, src, -1, STR_TERMINATE|STR_NOALIGN);
	
	strncpy_w(dest, ucs2_src, max);
	SAFE_FREE(ucs2_src);
	return dest;
}


/*******************************************************************
append a string of len bytes and add a terminator
********************************************************************/

smb_ucs2_t *strncat_wa(smb_ucs2_t *dest, const char *src, const size_t max)
{
	smb_ucs2_t *ucs2_src;

	if (!dest || !src) return NULL;
	ucs2_src = (smb_ucs2_t *)malloc((strlen(src)+1)*sizeof(smb_ucs2_t));
	if (!ucs2_src) {
		DEBUG(0,("strncat_wa: out of memory!\n"));
		return NULL;
	}
	push_ucs2(NULL, ucs2_src, src, -1, STR_TERMINATE|STR_NOALIGN);
	
	strncat_w(dest, ucs2_src, max);
	SAFE_FREE(ucs2_src);
	return dest;
}
