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

#ifndef MAXUNI
#define MAXUNI 1024
#endif

/* these 3 tables define the unicode case handling.  They are loaded
   at startup either via mmap() or read() from the lib directory */
static smb_ucs2_t *upcase_table;
static smb_ucs2_t *lowcase_table;
static uint8 *valid_table;

/**
 * This table says which Unicode characters are valid dos
 * characters.
 *
 * Each value is just a single bit.
 **/
static uint8 doschar_table[8192]; /* 65536 characters / 8 bits/byte */


/**
 * Load or generate the case handling tables.
 *
 * The case tables are defined in UCS2 and don't depend on any
 * configured parameters, so they never need to be reloaded.
 **/
void load_case_tables(void)
{
	static int initialised;
	int i;

	if (initialised) return;
	initialised = 1;

	upcase_table = map_file(lib_path("upcase.dat"), 0x20000);
	lowcase_table = map_file(lib_path("lowcase.dat"), 0x20000);

	/* we would like Samba to limp along even if these tables are
	   not available */
	if (!upcase_table) {
		DEBUG(1,("creating lame upcase table\n"));
		upcase_table = malloc(0x20000);
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
int check_dos_char(smb_ucs2_t c)
{
	lazy_initialize_conv();
	
	/* Find the right byte, and right bit within the byte; return
	 * 1 or 0 */
	return (doschar_table[(c & 0xffff) / 8] & (1 << (c & 7))) != 0;
}


static int check_dos_char_slowly(smb_ucs2_t c)
{
	char buf[10];
	smb_ucs2_t c2 = 0;
	int len1, len2;
	len1 = convert_string(CH_UCS2, CH_DOS, &c, 2, buf, sizeof(buf),False);
	if (len1 == 0) return 0;
	len2 = convert_string(CH_DOS, CH_UCS2, buf, len1, &c2, 2,False);
	if (len2 != 2) return 0;
	return (c == c2);
}


/**
 * Fill out doschar table the hard way, by examining each character
 **/
void init_doschar_table(void)
{
	int i, j, byteval;

	/* For each byte of packed table */
	
	for (i = 0; i <= 0xffff; i += 8) {
		byteval = 0;
		for (j = 0; j <= 7; j++) {
			smb_ucs2_t c;

			c = i + j;
			
			if (check_dos_char_slowly(c))
				byteval |= 1 << j;
		}
		doschar_table[i/8] = byteval;
	}
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
	uint8 *valid_file;

	if (mapped_file) {
		/* Can't unmap files, so stick with what we have */
		return;
	}

	valid_file = map_file(lib_path("valid.dat"), 0x10000);
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
	for (i=0;i<128;i++)
		valid_table[i] = isalnum(i) || strchr(allowed,i);
	
	for (;i<0x10000;i++) {
		smb_ucs2_t c;
		SSVAL(&c, 0, i);
		valid_table[i] = check_dos_char(c);
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
	if (!src) {
		dest[0] = 0;
		return 0;
	}
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
give a static string for displaying a UNISTR2
********************************************************************/
const char *unistr2_static(const UNISTR2 *str)
{
	static pstring ret;
	unistr2_to_ascii(ret, str, sizeof(ret));
	return ret;
}


/*******************************************************************
 duplicate a UNISTR2 string into a null terminated char*
 using a talloc context
********************************************************************/
char *unistr2_tdup(TALLOC_CTX *ctx, const UNISTR2 *str)
{
	char *s;
	int maxlen = (str->uni_str_len+1)*4;
	if (!str->buffer) return NULL;
	s = (char *)talloc(ctx, maxlen); /* convervative */
	if (!s) return NULL;
	pull_ucs2(NULL, s, str->buffer, maxlen, str->uni_str_len*2, 
		  STR_NOALIGN);
	return s;
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
 Count up to max number of characters in a smb_ucs2_t string.
********************************************************************/
size_t strnlen_w(const smb_ucs2_t *src, size_t max)
{
	size_t len;

	for(len = 0; *src++ && (len < max); len++) ;

	return len;
}

/*******************************************************************
 Wide strchr().
********************************************************************/

smb_ucs2_t *strchr_w(const smb_ucs2_t *s, smb_ucs2_t c)
{
	while (*s != 0) {
		if (c == *s) return (smb_ucs2_t *)s;
		s++;
	}
	if (c == *s) return (smb_ucs2_t *)s;

	return NULL;
}

smb_ucs2_t *strchr_wa(const smb_ucs2_t *s, char c)
{
	return strchr_w(s, UCS2_CHAR(c));
}

/*******************************************************************
 Wide strrchr().
********************************************************************/

smb_ucs2_t *strrchr_w(const smb_ucs2_t *s, smb_ucs2_t c)
{
	const smb_ucs2_t *p = s;
	int len = strlen_w(s);
	if (len == 0) return NULL;
	p += (len - 1);
	do {
		if (c == *p) return (smb_ucs2_t *)p;
	} while (p-- != s);
	return NULL;
}

/*******************************************************************
 Wide version of strrchr that returns after doing strrchr 'n' times.
********************************************************************/

smb_ucs2_t *strnrchr_w(const smb_ucs2_t *s, smb_ucs2_t c, unsigned int n)
{
	const smb_ucs2_t *p = s;
	int len = strlen_w(s);
	if (len == 0 || !n)
		return NULL;
	p += (len - 1);
	do {
		if (c == *p)
			n--;

		if (!n)
			return (smb_ucs2_t *)p;
	} while (p-- != s);
	return NULL;
}

/*******************************************************************
 Wide strstr().
********************************************************************/

smb_ucs2_t *strstr_w(const smb_ucs2_t *s, const smb_ucs2_t *ins)
{
	smb_ucs2_t *r;
	size_t slen, inslen;

	if (!s || !*s || !ins || !*ins) return NULL;
	slen = strlen_w(s);
	inslen = strlen_w(ins);
	r = (smb_ucs2_t *)s;
	while ((r = strchr_w(r, *ins))) {
		if (strncmp_w(r, ins, inslen) == 0) return r;
		r++;
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
  convert a string to "normal" form
********************************************************************/
void strnorm_w(smb_ucs2_t *s)
{
  extern int case_default;
  if (case_default == CASE_UPPER)
    strupper_w(s);
  else
    strlower_w(s);
}

int strcmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b)
{
	while (*b && *a == *b) { a++; b++; }
	return (*a - *b);
	/* warning: if *a != *b and both are not 0 we retrun a random
		greater or lesser than 0 number not realted to which
		string is longer */
}

int strncmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b, size_t len)
{
	size_t n = 0;
	while ((n < len) && *b && *a == *b) { a++; b++; n++;}
	return (len - n)?(*a - *b):0;	
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
case insensitive string comparison, lenght limited
********************************************************************/
int strncasecmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b, size_t len)
{
	size_t n = 0;
	while ((n < len) && *b && (toupper_w(*a) == toupper_w(*b))) { a++; b++; n++; }
	return (len - n)?(tolower_w(*a) - tolower_w(*b)):0;
}

/*******************************************************************
  compare 2 strings 
********************************************************************/
BOOL strequal_w(const smb_ucs2_t *s1, const smb_ucs2_t *s2)
{
	if (s1 == s2) return(True);
	if (!s1 || !s2) return(False);
  
	return(strcasecmp_w(s1,s2)==0);
}

/*******************************************************************
  compare 2 strings up to and including the nth char.
  ******************************************************************/
BOOL strnequal_w(const smb_ucs2_t *s1,const smb_ucs2_t *s2,size_t n)
{
  if (s1 == s2) return(True);
  if (!s1 || !s2 || !n) return(False);
  
  return(strncasecmp_w(s1,s2,n)==0);
}

/*******************************************************************
duplicate string
********************************************************************/
smb_ucs2_t *strdup_w(const smb_ucs2_t *src)
{
	return strndup_w(src, 0);
}

/* if len == 0 then duplicate the whole string */
smb_ucs2_t *strndup_w(const smb_ucs2_t *src, size_t len)
{
	smb_ucs2_t *dest;
	
	if (!len) len = strlen_w(src);
	dest = (smb_ucs2_t *)malloc((len + 1) * sizeof(smb_ucs2_t));
	if (!dest) {
		DEBUG(0,("strdup_w: out of memory!\n"));
		return NULL;
	}

	memcpy(dest, src, len * sizeof(smb_ucs2_t));
	dest[len] = 0;
	
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
	len = strnlen_w(src, max);

	memcpy(&dest[start], src, len*sizeof(smb_ucs2_t));			
	dest[start+len] = 0;
	
	return dest;
}

smb_ucs2_t *strcat_w(smb_ucs2_t *dest, const smb_ucs2_t *src)
{	
	size_t start;
	size_t len;	
	
	if (!dest || !src) return NULL;
	
	start = strlen_w(dest);
	len = strlen_w(src);

	memcpy(&dest[start], src, len*sizeof(smb_ucs2_t));			
	dest[start+len] = 0;
	
	return dest;
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

/*******************************************************************
trim unicode string
********************************************************************/

BOOL trim_string_w(smb_ucs2_t *s, const smb_ucs2_t *front,
				  const smb_ucs2_t *back)
{
	BOOL ret = False;
	size_t len, front_len, back_len;

	if (!s || !*s) return False;

	len = strlen_w(s);

	if (front && *front) {
		front_len = strlen_w(front);
		while (len && strncmp_w(s, front, front_len) == 0) {
			memmove(s, (s + front_len), (len - front_len + 1) * sizeof(smb_ucs2_t));
			len -= front_len;
			ret = True;
		}
	}
	
	if (back && *back) {
		back_len = strlen_w(back);
		while (len && strncmp_w((s + (len - back_len)), back, back_len) == 0) {
			s[len - back_len] = 0;
			len -= back_len;
			ret = True;
		}
	}

	return ret;
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

int strncmp_wa(const smb_ucs2_t *a, const char *b, size_t len)
{
	size_t n = 0;
	while ((n < len) && *b && *a == UCS2_CHAR(*b)) { a++; b++; n++;}
	return (len - n)?(*a - UCS2_CHAR(*b)):0;
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

smb_ucs2_t *strstr_wa(const smb_ucs2_t *s, const char *ins)
{
	smb_ucs2_t *r;
	size_t slen, inslen;

	if (!s || !*s || !ins || !*ins) return NULL;
	slen = strlen_w(s);
	inslen = strlen(ins);
	r = (smb_ucs2_t *)s;
	while ((r = strchr_w(r, UCS2_CHAR(*ins)))) {
		if (strncmp_wa(r, ins, inslen) == 0) return r;
		r++;
	}
	return NULL;
}

BOOL trim_string_wa(smb_ucs2_t *s, const char *front,
				  const char *back)
{
	wpstring f, b;

	if (front) push_ucs2(NULL, f, front, sizeof(wpstring) - 1, STR_TERMINATE);
	else *f = 0;
	if (back) push_ucs2(NULL, b, back, sizeof(wpstring) - 1, STR_TERMINATE);
	else *b = 0;
	return trim_string_w(s, f, b);
}

/*******************************************************************
 returns the length in number of wide characters
 ******************************************************************/
int unistrlen(uint16 *s)
{
	int len;

	if (!s)
		return -1;

	for (len=0; *s; s++,len++);

	return len;
}

/*******************************************************************
 Strcpy for unicode strings.  returns length (in num of wide chars)
********************************************************************/

int unistrcpy(uint16 *dst, uint16 *src)
{
	int num_wchars = 0;

	while (*src) {
		*dst++ = *src++;
		num_wchars++;
	}
	*dst = 0;

	return num_wchars;
}

/**
 * Samba ucs2 type to UNISTR2 conversion
 *
 * @param ctx Talloc context to create the dst strcture (if null) and the 
 *            contents of the unicode string.
 * @param dst UNISTR2 destination. If equals null, then it's allocated.
 * @param src smb_ucs2_t source.
 * @param max_len maximum number of unicode characters to copy. If equals
 *        null, then null-termination of src is taken
 *
 * @return copied UNISTR2 destination
 **/
UNISTR2* ucs2_to_unistr2(TALLOC_CTX *ctx, UNISTR2* dst, smb_ucs2_t* src)
{
	size_t len;

	if (!src)
		return NULL;
	len = strlen_w(src);
	
	/* allocate UNISTR2 destination if not given */
	if (!dst) {
		dst = (UNISTR2*) talloc(ctx, sizeof(UNISTR2));
		if (!dst)
			return NULL;
	}
	if (!dst->buffer) {
		dst->buffer = (uint16*) talloc(ctx, sizeof(uint16) * (len + 1));
		if (!dst->buffer)
			return NULL;
	}
	
	/* set UNISTR2 parameters */
	dst->uni_max_len = len + 1;
	dst->offset = 0;
	dst->uni_str_len = len;
	
	/* copy the actual unicode string */
	strncpy_w(dst->buffer, src, dst->uni_max_len);
	
	return dst;
}
