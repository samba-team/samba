/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Simo Sorce 2001
   
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

/* these 3 tables define the unicode case handling.  They are loaded
   at startup either via mmap() or read() from the lib directory */
static smb_ucs2_t *upcase_table;
static smb_ucs2_t *lowcase_table;
static uint8_t *valid_table;


/*******************************************************************
load the case handling tables
********************************************************************/
void load_case_tables(void)
{
	static int initialised;
	int i;
	TALLOC_CTX *mem_ctx;

	if (initialised) return;
	initialised = 1;

	mem_ctx = talloc_init("load_case_tables");
	if (!mem_ctx) {
		smb_panic("No memory for case_tables");
	}
	upcase_table = map_file(lib_path(mem_ctx, "upcase.dat"), 0x20000);
	lowcase_table = map_file(lib_path(mem_ctx, "lowcase.dat"), 0x20000);
	talloc_destroy(mem_ctx);
	
	/* we would like Samba to limp along even if these tables are
	   not available */
	if (!upcase_table) {
		DEBUG(1,("creating lame upcase table\n"));
		upcase_table = malloc(0x20000);
		if (!upcase_table) {
			smb_panic("No memory for upcase tables");
		}
		for (i=0;i<0x10000;i++) {
			smb_ucs2_t v;
			SSVAL(&v, 0, i);
			upcase_table[v] = i;
		}
		for (i=0;i<256;i++) {
			smb_ucs2_t v;
			SSVAL(&v, 0, UCS2_CHAR(i));
			upcase_table[v] = UCS2_CHAR(islower(i)?toupper(i):i);
		}
	}

	if (!lowcase_table) {
		DEBUG(1,("creating lame lowcase table\n"));
		lowcase_table = malloc(0x20000);
		if (!lowcase_table) {
			smb_panic("No memory for lowcase tables");
		}
		for (i=0;i<0x10000;i++) {
			smb_ucs2_t v;
			SSVAL(&v, 0, i);
			lowcase_table[v] = i;
		}
		for (i=0;i<256;i++) {
			smb_ucs2_t v;
			SSVAL(&v, 0, UCS2_CHAR(i));
			lowcase_table[v] = UCS2_CHAR(isupper(i)?tolower(i):i);
		}
	}
}

/*
  see if a ucs2 character can be mapped correctly to a dos character
  and mapped back to the same character in ucs2
*/
static int check_dos_char(smb_ucs2_t c)
{
	char buf[10];
	smb_ucs2_t c2 = 0;
	int len1, len2;
	len1 = convert_string(CH_UTF16, CH_DOS, &c, 2, buf, sizeof(buf));
	if (len1 == 0) return 0;
	len2 = convert_string(CH_DOS, CH_UTF16, buf, len1, &c2, 2);
	if (len2 != 2) return 0;
	return (c == c2);
}

/**
 * Load the valid character map table from <tt>valid.dat</tt> or
 * create from the configured codepage.
 *
 * This function is called whenever the configuration is reloaded.
 * However, the valid character table is not changed if it's loaded
 * from a file, because we can't unmap files.
 **/
void init_valid_table(void)
{
	static int mapped_file;
	int i;
	const char *allowed = ".!#$%&'()_-@^`~";
	uint8_t *valid_file;
	TALLOC_CTX *mem_ctx;

	if (mapped_file) {
		/* Can't unmap files, so stick with what we have */
		return;
	}

	mem_ctx = talloc_init("init_valid_table");
	if (!mem_ctx) {
		smb_panic("No memory for valid_table");
	}
	valid_file = map_file(lib_path(mem_ctx, "valid.dat"), 0x10000);
	talloc_destroy(mem_ctx);
	if (valid_file) {
		valid_table = valid_file;
		mapped_file = 1;
		return;
	}

	/* Otherwise, we're using a dynamically created valid_table.
	 * It might need to be regenerated if the code page changed.
	 * We know that we're not using a mapped file, so we can
	 * free() the old one. */
	if (valid_table) free(valid_table);

	DEBUG(2,("creating default valid table\n"));
	valid_table = malloc(0x10000);
	if (!valid_table) {
		smb_panic("No memory for valid_table");
	}
	for (i=0;i<128;i++)
		valid_table[i] = isalnum(i) || strchr(allowed,i);
	
	for (;i<0x10000;i++) {
		smb_ucs2_t c;
		SSVAL(&c, 0, i);
		valid_table[i] = check_dos_char(c);
	}
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

static smb_ucs2_t tolower_w( smb_ucs2_t val )
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
 Count the number of characters in a smb_ucs2_t string.
********************************************************************/
size_t strlen_w(const smb_ucs2_t *src)
{
	size_t len;

	for (len = 0; SVAL(src,0); len++, src++) ;

	return len;
}

/*******************************************************************
 Count up to max number of characters in a smb_ucs2_t string.
********************************************************************/
size_t strnlen_w(const smb_ucs2_t *src, size_t max)
{
	size_t len;

	for (len = 0; (len < max) && SVAL(src, 0); len++, src++) ;

	return len;
}

/*******************************************************************
wide strchr()
********************************************************************/
smb_ucs2_t *strchr_w(const smb_ucs2_t *s, smb_ucs2_t c)
{
	while (*s != 0) {
		if (c == *s) return discard_const_p(smb_ucs2_t, s);
		s++;
	}
	if (c == *s) return discard_const_p(smb_ucs2_t, s);

	return NULL;
}

smb_ucs2_t *strchr_wa(const smb_ucs2_t *s, char c)
{
	return strchr_w(s, UCS2_CHAR(c));
}

smb_ucs2_t *strrchr_w(const smb_ucs2_t *s, smb_ucs2_t c)
{
	const smb_ucs2_t *p = s;
	int len = strlen_w(s);
	if (len == 0) return NULL;
	p += (len - 1);
	do {
		if (c == *p) return discard_const_p(smb_ucs2_t, p);
	} while (p-- != s);
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
replace any occurence of oldc with newc in unicode string
********************************************************************/

void string_replace_w(smb_ucs2_t *s, smb_ucs2_t oldc, smb_ucs2_t newc)
{
	for(;*s;s++) {
		if(*s==oldc) *s=newc;
	}
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

const smb_ucs2_t *strpbrk_wa(const smb_ucs2_t *s, const char *p)
{
	while (*s != 0) {
		int i;
		for (i=0; p[i] && *s != UCS2_CHAR(p[i]); i++) 
			;
		if (p[i]) return s;
		s++;
	}
	return NULL;
}

size_t ucs2_align(const void *base_ptr, const void *p, int flags)
{
	if (flags & (STR_NOALIGN|STR_ASCII))
		return 0;
	return PTR_DIFF(p, base_ptr) & 1;
}

