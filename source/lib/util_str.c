/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Simo Sorce      2001-2002
   
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

/**
 * Get the next token from a string, return False if none found.
 * Handles double-quotes.
 * 
 * Based on a routine by GJC@VILLAGE.COM. 
 * Extensively modified by Andrew.Tridgell@anu.edu.au
 **/
BOOL next_token(const char **ptr,char *buff, const char *sep, size_t bufsize)
{
	const char *s;
	BOOL quoted;
	size_t len=1;

	if (!ptr)
		return(False);

	s = *ptr;

	/* default to simple separators */
	if (!sep)
		sep = " \t\n\r";

	/* find the first non sep char */
	while (*s && strchr_m(sep,*s))
		s++;
	
	/* nothing left? */
	if (! *s)
		return(False);
	
	/* copy over the token */
	for (quoted = False; len < bufsize && *s && (quoted || !strchr_m(sep,*s)); s++) {
		if (*s == '\"') {
			quoted = !quoted;
		} else {
			len++;
			*buff++ = *s;
		}
	}
	
	*ptr = (*s) ? s+1 : s;  
	*buff = 0;
	
	return(True);
}

static uint16_t tmpbuf[sizeof(pstring)];

/**
 Convert list of tokens to array; dependent on above routine.
 Uses last_ptr from above - bit of a hack.
**/

char **toktocliplist(const char *ptr, int *ctok, const char *sep)
{
	char *s = ptr;
	int ictok=0;
	char **ret, **iret;

	if (!sep)
		sep = " \t\n\r";

	while(*s && strchr_m(sep,*s))
		s++;

	/* nothing left? */
	if (!*s)
		return(NULL);

	do {
		ictok++;
		while(*s && (!strchr_m(sep,*s)))
			s++;
		while(*s && strchr_m(sep,*s))
			*s++=0;
	} while(*s);
	
	*ctok=ictok;
	s = ptr;
	
	if (!(ret=iret=malloc(ictok*sizeof(char *))))
		return NULL;
	
	while(ictok--) {    
		*iret++=s;
		while(*s++)
			;
		while(!*s)
			s++;
	}

	return ret;
}

/**
 Case insensitive string compararison.
**/
static int StrCaseCmp_slow(const char *s1, const char *s2)
{
	smb_ucs2_t *u1, *u2;
	int ret;

	if (convert_string_allocate(CH_UNIX, CH_UTF16, s1, strlen(s1)+1, &u1) == -1 ||
	    convert_string_allocate(CH_UNIX, CH_UTF16, s2, strlen(s2)+1, &u2) == -1) {
		/* fallback to a simple comparison */
		return strcasecmp(s1, s2);
	}

	ret = strcasecmp_w(u1, u2);

	free(u1);
	free(u2);

	return ret;
}

/**
 Case insensitive string compararison, accelerated version
**/
int StrCaseCmp(const char *s1, const char *s2)
{
	while (*s1 && *s2 &&
	       (*s1 & 0x80) == 0 && 
	       (*s2 & 0x80) == 0) {
		char u1 = toupper(*s1);
		char u2 = toupper(*s2);
		if (u1 != u2) {
			return u2 - u1;
		}
		s1++;
		s2++;
	}

	if (*s1 == 0 || *s2 == 0) {
		return *s2 - *s1;
	}

	return StrCaseCmp_slow(s1, s2);
}

/**
 * Compare 2 strings.
 *
 * @note The comparison is case-insensitive.
 **/
BOOL strequal(const char *s1, const char *s2)
{
	if (s1 == s2)
		return(True);
	if (!s1 || !s2)
		return(False);
  
	return(StrCaseCmp(s1,s2)==0);
}

/**
 Compare 2 strings (case sensitive).
**/

BOOL strcsequal(const char *s1,const char *s2)
{
  if (s1 == s2)
	  return(True);
  if (!s1 || !s2)
	  return(False);
  
  return(strcmp(s1,s2)==0);
}

/**
Do a case-insensitive, whitespace-ignoring string compare.
**/

int strwicmp(const char *psz1, const char *psz2)
{
	/* if BOTH strings are NULL, return TRUE, if ONE is NULL return */
	/* appropriate value. */
	if (psz1 == psz2)
		return (0);
	else if (psz1 == NULL)
		return (-1);
	else if (psz2 == NULL)
		return (1);

	/* sync the strings on first non-whitespace */
	while (1) {
		while (isspace((int)*psz1))
			psz1++;
		while (isspace((int)*psz2))
			psz2++;
		if (toupper(*psz1) != toupper(*psz2) || *psz1 == '\0'
		    || *psz2 == '\0')
			break;
		psz1++;
		psz2++;
	}
	return (*psz1 - *psz2);
}

/**
 Convert a string to upper case, but don't modify it.
**/

char *strupper_talloc(TALLOC_CTX *mem_ctx, const char *s)
{
	char *str;

	str = talloc_strdup(mem_ctx, s);
	strupper(str);

	return str;
}


/**
 String replace.
 NOTE: oldc and newc must be 7 bit characters
**/

void string_replace(char *s,char oldc,char newc)
{
	if (strchr(s, oldc)) {
		push_ucs2(NULL, tmpbuf,s, sizeof(tmpbuf), STR_TERMINATE);
		string_replace_w(tmpbuf, UCS2_CHAR(oldc), UCS2_CHAR(newc));
		pull_ucs2(NULL, s, tmpbuf, strlen(s)+1, sizeof(tmpbuf), STR_TERMINATE);
	}
}

/**
 Count the number of characters in a string. Normally this will
 be the same as the number of bytes in a string for single byte strings,
 but will be different for multibyte.
**/

size_t str_charnum(const char *s)
{
	uint16_t tmpbuf2[sizeof(pstring)];
	push_ucs2(NULL, tmpbuf2,s, sizeof(tmpbuf2), STR_TERMINATE);
	return strlen_w(tmpbuf2);
}

/**
 Count the number of characters in a string. Normally this will
 be the same as the number of bytes in a string for single byte strings,
 but will be different for multibyte.
**/

size_t str_ascii_charnum(const char *s)
{
	pstring tmpbuf2;
	push_ascii(tmpbuf2, s, sizeof(tmpbuf2), STR_TERMINATE);
	return strlen(tmpbuf2);
}

/**
 Trim the specified elements off the front and back of a string.
**/

BOOL trim_string(char *s,const char *front,const char *back)
{
	BOOL ret = False;
	size_t front_len;
	size_t back_len;
	size_t len;

	/* Ignore null or empty strings. */
	if (!s || (s[0] == '\0'))
		return False;

	front_len	= front? strlen(front) : 0;
	back_len	= back? strlen(back) : 0;

	len = strlen(s);

	if (front_len) {
		while (len && strncmp(s, front, front_len)==0) {
			memcpy(s, s+front_len, (len-front_len)+1);
			len -= front_len;
			ret=True;
		}
	}
	
	if (back_len) {
		while ((len >= back_len) && strncmp(s+len-back_len,back,back_len)==0) {
			s[len-back_len]='\0';
			len -= back_len;
			ret=True;
		}
	}
	return ret;
}

/**
 Does a string have any uppercase chars in it?
**/

BOOL strhasupper(const char *s)
{
	smb_ucs2_t *ptr;
	push_ucs2(NULL, tmpbuf,s, sizeof(tmpbuf), STR_TERMINATE);
	for(ptr=tmpbuf;*ptr;ptr++)
		if(isupper_w(*ptr))
			return True;
	return(False);
}

/**
 Does a string have any lowercase chars in it?
**/

BOOL strhaslower(const char *s)
{
	smb_ucs2_t *ptr;
	push_ucs2(NULL, tmpbuf,s, sizeof(tmpbuf), STR_TERMINATE);
	for(ptr=tmpbuf;*ptr;ptr++)
		if(islower_w(*ptr))
			return True;
	return(False);
}

/**
 Find the number of 'c' chars in a string
**/

size_t count_chars(const char *s,char c)
{
	smb_ucs2_t *ptr;
	int count;
	push_ucs2(NULL, tmpbuf,s, sizeof(tmpbuf), STR_TERMINATE);
	for(count=0,ptr=tmpbuf;*ptr;ptr++)
		if(*ptr==UCS2_CHAR(c))
			count++;
	return(count);
}

/**
 Safe string copy into a known length string. maxlength does not
 include the terminating zero.
**/

char *safe_strcpy(char *dest,const char *src, size_t maxlength)
{
	size_t len;

	if (!dest) {
		DEBUG(0,("ERROR: NULL dest in safe_strcpy\n"));
		return NULL;
	}

#ifdef DEVELOPER
	/* We intentionally write out at the extremity of the destination
	 * string.  If the destination is too short (e.g. pstrcpy into mallocd
	 * or fstring) then this should cause an error under a memory
	 * checker. */
	dest[maxlength] = '\0';
	if (PTR_DIFF(&len, dest) > 0) {  /* check if destination is on the stack, ok if so */
		log_suspicious_usage("safe_strcpy", src);
	}
#endif

	if (!src) {
		*dest = 0;
		return dest;
	}  

	len = strlen(src);

	if (len > maxlength) {
		DEBUG(0,("ERROR: string overflow by %u (%u - %u) in safe_strcpy [%.50s]\n",
			 (uint_t)(len-maxlength), len, maxlength, src));
		len = maxlength;
	}
      
	memmove(dest, src, len);
	dest[len] = 0;
	return dest;
}  

/**
 Safe string cat into a string. maxlength does not
 include the terminating zero.
**/

char *safe_strcat(char *dest, const char *src, size_t maxlength)
{
	size_t src_len, dest_len;

	if (!dest) {
		DEBUG(0,("ERROR: NULL dest in safe_strcat\n"));
		return NULL;
	}

	if (!src)
		return dest;
	
#ifdef DEVELOPER
	if (PTR_DIFF(&src_len, dest) > 0) {  /* check if destination is on the stack, ok if so */
		log_suspicious_usage("safe_strcat", src);
	}
#endif
	src_len = strlen(src);
	dest_len = strlen(dest);

	if (src_len + dest_len > maxlength) {
		DEBUG(0,("ERROR: string overflow by %d in safe_strcat [%.50s]\n",
			 (int)(src_len + dest_len - maxlength), src));
		if (maxlength > dest_len) {
			memcpy(&dest[dest_len], src, maxlength - dest_len);
		}
		dest[maxlength] = 0;
		return NULL;
	}
	
	memcpy(&dest[dest_len], src, src_len);
	dest[dest_len + src_len] = 0;
	return dest;
}

/**
 Paranoid strcpy into a buffer of given length (includes terminating
 zero. Strips out all but 'a-Z0-9' and the character in other_safe_chars
 and replaces with '_'. Deliberately does *NOT* check for multibyte
 characters. Don't change it !
**/

char *alpha_strcpy(char *dest, const char *src, const char *other_safe_chars, size_t maxlength)
{
	size_t len, i;

	if (maxlength == 0) {
		/* can't fit any bytes at all! */
		return NULL;
	}

	if (!dest) {
		DEBUG(0,("ERROR: NULL dest in alpha_strcpy\n"));
		return NULL;
	}

	if (!src) {
		*dest = 0;
		return dest;
	}  

	len = strlen(src);
	if (len >= maxlength)
		len = maxlength - 1;

	if (!other_safe_chars)
		other_safe_chars = "";

	for(i = 0; i < len; i++) {
		int val = (src[i] & 0xff);
		if (isupper(val) || islower(val) || isdigit(val) || strchr_m(other_safe_chars, val))
			dest[i] = src[i];
		else
			dest[i] = '_';
	}

	dest[i] = '\0';

	return dest;
}

/**
 Like strncpy but always null terminates. Make sure there is room!
 The variable n should always be one less than the available size.
**/

char *StrnCpy(char *dest,const char *src,size_t n)
{
	char *d = dest;
	if (!dest)
		return(NULL);
	if (!src) {
		*dest = 0;
		return(dest);
	}
	while (n-- && (*d++ = *src++))
		;
	*d = 0;
	return(dest);
}


/**
 Check if a string is part of a list.
**/

BOOL in_list(const char *s, const char *list, BOOL casesensitive)
{
	pstring tok;
	const char *p=list;

	if (!list)
		return(False);

	while (next_token(&p,tok,LIST_SEP,sizeof(tok))) {
		if (casesensitive) {
			if (strcmp(tok,s) == 0)
				return(True);
		} else {
			if (StrCaseCmp(tok,s) == 0)
				return(True);
		}
	}
	return(False);
}

/**
 Set a string value, allocing the space for the string
**/
static BOOL string_init(char **dest,const char *src)
{
	if (!src) src = "";

	(*dest) = strdup(src);
	if ((*dest) == NULL) {
		DEBUG(0,("Out of memory in string_init\n"));
		return False;
	}
	return True;
}

/**
 Free a string value.
**/
void string_free(char **s)
{
	if (s) SAFE_FREE(*s);
}

/**
 Set a string value, deallocating any existing space, and allocing the space
 for the string
**/
BOOL string_set(char **dest, const char *src)
{
	string_free(dest);
	return string_init(dest,src);
}

/**
 Substitute a string for a pattern in another string. Make sure there is 
 enough room!

 This routine looks for pattern in s and replaces it with 
 insert. It may do multiple replacements.

 Any of " ; ' $ or ` in the insert string are replaced with _
 if len==0 then the string cannot be extended. This is different from the old
 use of len==0 which was for no length checks to be done.
**/

void string_sub(char *s,const char *pattern, const char *insert, size_t len)
{
	char *p;
	ssize_t ls,lp,li, i;

	if (!insert || !pattern || !*pattern || !s)
		return;

	ls = (ssize_t)strlen(s);
	lp = (ssize_t)strlen(pattern);
	li = (ssize_t)strlen(insert);

	if (len == 0)
		len = ls + 1; /* len is number of *bytes* */

	while (lp <= ls && (p = strstr(s,pattern))) {
		if (ls + (li-lp) >= len) {
			DEBUG(0,("ERROR: string overflow by %d in string_sub(%.50s, %d)\n", 
				 (int)(ls + (li-lp) - len),
				 pattern, (int)len));
			break;
		}
		if (li != lp) {
			memmove(p+li,p+lp,strlen(p+lp)+1);
		}
		for (i=0;i<li;i++) {
			switch (insert[i]) {
			case '`':
			case '"':
			case '\'':
			case ';':
			case '$':
			case '%':
			case '\r':
			case '\n':
				p[i] = '_';
				break;
			default:
				p[i] = insert[i];
			}
		}
		s = p + li;
		ls += (li-lp);
	}
}


/**
 Similar to string_sub() but allows for any character to be substituted. 
 Use with caution!
 if len==0 then the string cannot be extended. This is different from the old
 use of len==0 which was for no length checks to be done.
**/

void all_string_sub(char *s,const char *pattern,const char *insert, size_t len)
{
	char *p;
	ssize_t ls,lp,li;

	if (!insert || !pattern || !s)
		return;

	ls = (ssize_t)strlen(s);
	lp = (ssize_t)strlen(pattern);
	li = (ssize_t)strlen(insert);

	if (!*pattern)
		return;
	
	if (len == 0)
		len = ls + 1; /* len is number of *bytes* */
	
	while (lp <= ls && (p = strstr(s,pattern))) {
		if (ls + (li-lp) >= len) {
			DEBUG(0,("ERROR: string overflow by %d in all_string_sub(%.50s, %d)\n", 
				 (int)(ls + (li-lp) - len),
				 pattern, (int)len));
			break;
		}
		if (li != lp) {
			memmove(p+li,p+lp,strlen(p+lp)+1);
		}
		memcpy(p, insert, li);
		s = p + li;
		ls += (li-lp);
	}
}

/**
 Write an octal as a string.
**/

const char *octal_string(int i)
{
	static char ret[64];
	if (i == -1)
		return "-1";
	slprintf(ret, sizeof(ret)-1, "0%o", i);
	return ret;
}


/**
 Strchr and strrchr_m are very hard to do on general multi-byte strings. 
 We convert via ucs2 for now.
**/

char *strchr_m(const char *s, char c)
{
	wpstring ws;
	pstring s2;
	smb_ucs2_t *p;

	push_ucs2(NULL, ws, s, sizeof(ws), STR_TERMINATE);
	p = strchr_w(ws, UCS2_CHAR(c));
	if (!p)
		return NULL;
	*p = 0;
	pull_ucs2_pstring(s2, ws);
	return (char *)(s+strlen(s2));
}

char *strrchr_m(const char *s, char c)
{
	wpstring ws;
	pstring s2;
	smb_ucs2_t *p;

	push_ucs2(NULL, ws, s, sizeof(ws), STR_TERMINATE);
	p = strrchr_w(ws, UCS2_CHAR(c));
	if (!p)
		return NULL;
	*p = 0;
	pull_ucs2_pstring(s2, ws);
	return (char *)(s+strlen(s2));
}

/**
 Convert a string to lower case.
**/

void strlower_m(char *s)
{
	/* this is quite a common operation, so we want it to be
	   fast. We optimise for the ascii case, knowing that all our
	   supported multi-byte character sets are ascii-compatible
	   (ie. they match for the first 128 chars) */

	while (*s && !(((uint8_t)s[0]) & 0x7F)) {
		*s = tolower((uint8_t)*s);
		s++;
	}

	if (!*s)
		return;

	/* I assume that lowercased string takes the same number of bytes
	 * as source string even in UTF-8 encoding. (VIV) */
	unix_strlower(s,strlen(s)+1,s,strlen(s)+1);	
}

/**
 Convert a string to upper case.
**/

void strupper_m(char *s)
{
	/* this is quite a common operation, so we want it to be
	   fast. We optimise for the ascii case, knowing that all our
	   supported multi-byte character sets are ascii-compatible
	   (ie. they match for the first 128 chars) */

	while (*s && !(((uint8_t)s[0]) & 0x7F)) {
		*s = toupper((uint8_t)*s);
		s++;
	}

	if (!*s)
		return;

	/* I assume that lowercased string takes the same number of bytes
	 * as source string even in multibyte encoding. (VIV) */
	unix_strupper(s,strlen(s)+1,s,strlen(s)+1);	
}


/**
   work out the number of multibyte chars in a string
**/
size_t strlen_m(const char *s)
{
	size_t count = 0;

	if (!s) {
		return 0;
	}

	while (*s && !(((uint8_t)s[0]) & 0x7F)) {
		s++;
		count++;
	}

	if (!*s) {
		return count;
	}

	push_ucs2(NULL,tmpbuf,s, sizeof(tmpbuf), STR_TERMINATE);
	return count + strlen_w(tmpbuf);
}

/**
   Work out the number of multibyte chars in a string, including the NULL
   terminator.
**/
size_t strlen_m_term(const char *s)
{
	if (!s) {
		return 0;
	}

	return strlen_m(s) + 1;
}

/**
 Convert a string to upper case.
**/

char *strdup_upper(const char *s)
{
	char *t = strdup(s);
	if (t == NULL) {
		DEBUG(0, ("strdup_upper: Out of memory!\n"));
		return NULL;
	}
	strupper_m(t);
	return t;
}

/**
 Return a RFC2254 binary string representation of a buffer.
 Used in LDAP filters.
 Caller must free.
**/

char *binary_string(char *buf, int len)
{
	char *s;
	int i, j;
	const char *hex = "0123456789ABCDEF";
	s = malloc(len * 3 + 1);
	if (!s)
		return NULL;
	for (j=i=0;i<len;i++) {
		s[j] = '\\';
		s[j+1] = hex[((uint8_t)buf[i]) >> 4];
		s[j+2] = hex[((uint8_t)buf[i]) & 0xF];
		j += 3;
	}
	s[j] = 0;
	return s;
}

/**
 Just a typesafety wrapper for snprintf into a pstring.
**/

 int pstr_sprintf(pstring s, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vsnprintf(s, PSTRING_LEN, fmt, ap);
	va_end(ap);
	return ret;
}

#ifndef HAVE_STRNDUP
/**
 Some platforms don't have strndup.
**/
 char *strndup(const char *s, size_t n)
{
	char *ret;
	
	n = strnlen(s, n);
	ret = malloc(n+1);
	if (!ret)
		return NULL;
	memcpy(ret, s, n);
	ret[n] = 0;

	return ret;
}
#endif

#ifndef HAVE_STRNLEN
/**
 Some platforms don't have strnlen
**/
 size_t strnlen(const char *s, size_t n)
{
	int i;
	for (i=0; s[i] && i<n; i++)
		/* noop */ ;
	return i;
}
#endif

/**
 List of Strings manipulation functions
**/

#define S_LIST_ABS 16 /* List Allocation Block Size */

char **str_list_make(const char *string, const char *sep)
{
	char **list, **rlist;
	const char *str;
	char *s;
	int num, lsize;
	pstring tok;
	
	if (!string || !*string)
		return NULL;
	s = strdup(string);
	if (!s) {
		DEBUG(0,("str_list_make: Unable to allocate memory"));
		return NULL;
	}
	if (!sep) sep = LIST_SEP;
	
	num = lsize = 0;
	list = NULL;
	
	str = s;
	while (next_token(&str, tok, sep, sizeof(tok))) {		
		if (num == lsize) {
			lsize += S_LIST_ABS;
			rlist = (char **)Realloc(list, ((sizeof(char **)) * (lsize +1)));
			if (!rlist) {
				DEBUG(0,("str_list_make: Unable to allocate memory"));
				str_list_free(&list);
				SAFE_FREE(s);
				return NULL;
			} else
				list = rlist;
			memset (&list[num], 0, ((sizeof(char**)) * (S_LIST_ABS +1)));
		}
		
		list[num] = strdup(tok);
		if (!list[num]) {
			DEBUG(0,("str_list_make: Unable to allocate memory"));
			str_list_free(&list);
			SAFE_FREE(s);
			return NULL;
		}
	
		num++;	
	}
	
	SAFE_FREE(s);
	return list;
}

BOOL str_list_copy(char ***dest, const char **src)
{
	char **list, **rlist;
	int num, lsize;
	
	*dest = NULL;
	if (!src)
		return False;
	
	num = lsize = 0;
	list = NULL;
		
	while (src[num]) {
		if (num == lsize) {
			lsize += S_LIST_ABS;
			rlist = (char **)Realloc(list, ((sizeof(char **)) * (lsize +1)));
			if (!rlist) {
				DEBUG(0,("str_list_copy: Unable to re-allocate memory"));
				str_list_free(&list);
				return False;
			} else
				list = rlist;
			memset (&list[num], 0, ((sizeof(char **)) * (S_LIST_ABS +1)));
		}
		
		list[num] = strdup(src[num]);
		if (!list[num]) {
			DEBUG(0,("str_list_copy: Unable to allocate memory"));
			str_list_free(&list);
			return False;
		}

		num++;
	}
	
	*dest = list;
	return True;	
}

/**
 * Return true if all the elements of the list match exactly.
 **/
BOOL str_list_compare(char **list1, char **list2)
{
	int num;
	
	if (!list1 || !list2)
		return (list1 == list2); 
	
	for (num = 0; list1[num]; num++) {
		if (!list2[num])
			return False;
		if (!strcsequal(list1[num], list2[num]))
			return False;
	}
	if (list2[num])
		return False; /* if list2 has more elements than list1 fail */
	
	return True;
}

void str_list_free(char ***list)
{
	char **tlist;
	
	if (!list || !*list)
		return;
	tlist = *list;
	for(; *tlist; tlist++)
		SAFE_FREE(*tlist);
	SAFE_FREE(*list);
}

BOOL str_list_substitute(char **list, const char *pattern, const char *insert)
{
	char *p, *s, *t;
	ssize_t ls, lp, li, ld, i, d;

	if (!list)
		return False;
	if (!pattern)
		return False;
	if (!insert)
		return False;

	lp = (ssize_t)strlen(pattern);
	li = (ssize_t)strlen(insert);
	ld = li -lp;
			
	while (*list) {
		s = *list;
		ls = (ssize_t)strlen(s);

		while ((p = strstr(s, pattern))) {
			t = *list;
			d = p -t;
			if (ld) {
				t = (char *) malloc(ls +ld +1);
				if (!t) {
					DEBUG(0,("str_list_substitute: Unable to allocate memory"));
					return False;
				}
				memcpy(t, *list, d);
				memcpy(t +d +li, p +lp, ls -d -lp +1);
				SAFE_FREE(*list);
				*list = t;
				ls += ld;
				s = t +d +li;
			}
			
			for (i = 0; i < li; i++) {
				switch (insert[i]) {
					case '`':
					case '"':
					case '\'':
					case ';':
					case '$':
					case '%':
					case '\r':
					case '\n':
						t[d +i] = '_';
						break;
					default:
						t[d +i] = insert[i];
				}
			}	
		}
		
		list++;
	}
	
	return True;
}


#define IPSTR_LIST_SEP	","

/**
 * Add ip string representation to ipstr list. Used also
 * as part of @function ipstr_list_make
 *
 * @param ipstr_list pointer to string containing ip list;
 *        MUST BE already allocated and IS reallocated if necessary
 * @param ipstr_size pointer to current size of ipstr_list (might be changed
 *        as a result of reallocation)
 * @param ip IP address which is to be added to list
 * @return pointer to string appended with new ip and possibly
 *         reallocated to new length
 **/

char* ipstr_list_add(char** ipstr_list, const struct in_addr *ip)
{
	char* new_ipstr = NULL;
	
	/* arguments checking */
	if (!ipstr_list || !ip) return NULL;

	/* attempt to convert ip to a string and append colon separator to it */
	if (*ipstr_list) {
		asprintf(&new_ipstr, "%s%s%s", *ipstr_list, IPSTR_LIST_SEP,inet_ntoa(*ip));
		SAFE_FREE(*ipstr_list);
	} else {
		asprintf(&new_ipstr, "%s", inet_ntoa(*ip));
	}
	*ipstr_list = new_ipstr;
	return *ipstr_list;
}

/**
 * Allocate and initialise an ipstr list using ip adresses
 * passed as arguments.
 *
 * @param ipstr_list pointer to string meant to be allocated and set
 * @param ip_list array of ip addresses to place in the list
 * @param ip_count number of addresses stored in ip_list
 * @return pointer to allocated ip string
 **/
 
char* ipstr_list_make(char** ipstr_list, const struct in_addr* ip_list, int ip_count)
{
	int i;
	
	/* arguments checking */
	if (!ip_list && !ipstr_list) return 0;

	*ipstr_list = NULL;
	
	/* process ip addresses given as arguments */
	for (i = 0; i < ip_count; i++)
		*ipstr_list = ipstr_list_add(ipstr_list, &ip_list[i]);
	
	return (*ipstr_list);
}


/**
 * Parse given ip string list into array of ip addresses
 * (as in_addr structures)
 *
 * @param ipstr ip string list to be parsed 
 * @param ip_list pointer to array of ip addresses which is
 *        allocated by this function and must be freed by caller
 * @return number of succesfully parsed addresses
 **/
 
int ipstr_list_parse(const char* ipstr_list, struct in_addr** ip_list)
{
	fstring token_str;
	int count;

	if (!ipstr_list || !ip_list) return 0;
	
	for (*ip_list = NULL, count = 0;
	     next_token(&ipstr_list, token_str, IPSTR_LIST_SEP, FSTRING_LEN);
	     count++) {
	     
		struct in_addr addr;

		/* convert single token to ip address */
		if ( (addr.s_addr = inet_addr(token_str)) == INADDR_NONE )
			break;
		
		/* prepare place for another in_addr structure */
		*ip_list = Realloc(*ip_list, (count + 1) * sizeof(struct in_addr));
		if (!*ip_list) return -1;
		
		(*ip_list)[count] = addr;
	}
	
	return count;
}


/**
 * Safely free ip string list
 *
 * @param ipstr_list ip string list to be freed
 **/

void ipstr_list_free(char* ipstr_list)
{
	SAFE_FREE(ipstr_list);
}

/**
 Routine to get hex characters and turn them into a 16 byte array.
 the array can be variable length, and any non-hex-numeric
 characters are skipped.  "0xnn" or "0Xnn" is specially catered
 for.

 valid examples: "0A5D15"; "0x15, 0x49, 0xa2"; "59\ta9\te3\n"

**/

size_t strhex_to_str(char *p, size_t len, const char *strhex)
{
	size_t i;
	size_t num_chars = 0;
	uint8_t   lonybble, hinybble;
	const char     *hexchars = "0123456789ABCDEF";
	char           *p1 = NULL, *p2 = NULL;

	for (i = 0; i < len && strhex[i] != 0; i++) {
		if (strncasecmp(hexchars, "0x", 2) == 0) {
			i++; /* skip two chars */
			continue;
		}

		if (!(p1 = strchr_m(hexchars, toupper(strhex[i]))))
			break;

		i++; /* next hex digit */

		if (!(p2 = strchr_m(hexchars, toupper(strhex[i]))))
			break;

		/* get the two nybbles */
		hinybble = PTR_DIFF(p1, hexchars);
		lonybble = PTR_DIFF(p2, hexchars);

		p[num_chars] = (hinybble << 4) | lonybble;
		num_chars++;

		p1 = NULL;
		p2 = NULL;
	}
	return num_chars;
}

DATA_BLOB strhex_to_data_blob(const char *strhex) 
{
	DATA_BLOB ret_blob = data_blob(NULL, strlen(strhex)/2+1);

	ret_blob.length = strhex_to_str(ret_blob.data, 	
					strlen(strhex), 
					strhex);

	return ret_blob;
}

/**
 * Routine to print a buffer as HEX digits, into an allocated string.
 */

void hex_encode(const unsigned char *buff_in, size_t len, char **out_hex_buffer)
{
	int i;
	char *hex_buffer;

	*out_hex_buffer = smb_xmalloc((len*2)+1);
	hex_buffer = *out_hex_buffer;

	for (i = 0; i < len; i++)
		slprintf(&hex_buffer[i*2], 3, "%02X", buff_in[i]);
}


/**
 Unescape a URL encoded string, in place.
**/

void rfc1738_unescape(char *buf)
{
	char *p=buf;

	while ((p=strchr_m(p,'+')))
		*p = ' ';

	p = buf;

	while (p && *p && (p=strchr_m(p,'%'))) {
		int c1 = p[1];
		int c2 = p[2];

		if (c1 >= '0' && c1 <= '9')
			c1 = c1 - '0';
		else if (c1 >= 'A' && c1 <= 'F')
			c1 = 10 + c1 - 'A';
		else if (c1 >= 'a' && c1 <= 'f')
			c1 = 10 + c1 - 'a';
		else {p++; continue;}

		if (c2 >= '0' && c2 <= '9')
			c2 = c2 - '0';
		else if (c2 >= 'A' && c2 <= 'F')
			c2 = 10 + c2 - 'A';
		else if (c2 >= 'a' && c2 <= 'f')
			c2 = 10 + c2 - 'a';
		else {p++; continue;}
			
		*p = (c1<<4) | c2;

		memmove(p+1, p+3, strlen(p+3)+1);
		p++;
	}
}

static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Decode a base64 string into a DATA_BLOB - simple and slow algorithm
 **/
DATA_BLOB base64_decode_data_blob(const char *s)
{
	int bit_offset, byte_offset, idx, i, n;
	DATA_BLOB decoded = data_blob(s, strlen(s)+1);
	uint8_t *d = decoded.data;
	char *p;

	n=i=0;

	while (*s && (p=strchr_m(b64,*s))) {
		idx = (int)(p - b64);
		byte_offset = (i*6)/8;
		bit_offset = (i*6)%8;
		d[byte_offset] &= ~((1<<(8-bit_offset))-1);
		if (bit_offset < 3) {
			d[byte_offset] |= (idx << (2-bit_offset));
			n = byte_offset+1;
		} else {
			d[byte_offset] |= (idx >> (bit_offset-2));
			d[byte_offset+1] = 0;
			d[byte_offset+1] |= (idx << (8-(bit_offset-2))) & 0xFF;
			n = byte_offset+2;
		}
		s++; i++;
	}

	/* fix up length */
	decoded.length = n;
	return decoded;
}

/**
 * Decode a base64 string in-place - wrapper for the above
 **/
void base64_decode_inplace(char *s)
{
	DATA_BLOB decoded = base64_decode_data_blob(s);
	memcpy(s, decoded.data, decoded.length);
	data_blob_free(&decoded);

	/* null terminate */
	s[decoded.length] = '\0';
}

/**
 * Encode a base64 string into a malloc()ed string caller to free.
 *
 *From SQUID: adopted from http://ftp.sunet.se/pub2/gnu/vm/base64-encode.c with adjustments
 **/
char * base64_encode_data_blob(DATA_BLOB data)
{
	int bits = 0;
	int char_count = 0;
	size_t out_cnt = 0;
	size_t len = data.length;
	size_t output_len = data.length * 2;
	char *result = malloc(output_len); /* get us plenty of space */

	while (len-- && out_cnt < (data.length * 2) - 5) {
		int c = (uint8_t) *(data.data++);
		bits += c;
		char_count++;
		if (char_count == 3) {
			result[out_cnt++] = b64[bits >> 18];
			result[out_cnt++] = b64[(bits >> 12) & 0x3f];
			result[out_cnt++] = b64[(bits >> 6) & 0x3f];
	    result[out_cnt++] = b64[bits & 0x3f];
	    bits = 0;
	    char_count = 0;
	} else {
	    bits <<= 8;
	}
    }
    if (char_count != 0) {
	bits <<= 16 - (8 * char_count);
	result[out_cnt++] = b64[bits >> 18];
	result[out_cnt++] = b64[(bits >> 12) & 0x3f];
	if (char_count == 1) {
	    result[out_cnt++] = '=';
	    result[out_cnt++] = '=';
	} else {
	    result[out_cnt++] = b64[(bits >> 6) & 0x3f];
	    result[out_cnt++] = '=';
	}
    }
    result[out_cnt] = '\0';	/* terminate */
    return result;
}

#ifdef VALGRIND
size_t valgrind_strlen(const char *s)
{
	size_t count;
	for(count = 0; *s++; count++)
		;
	return count;
}
#endif


/*
  format a string into length-prefixed dotted domain format, as used in NBT
  and in some ADS structures
*/
const char *str_format_nbt_domain(TALLOC_CTX *mem_ctx, const char *s)
{
	char *ret;
	int i;
	if (!s || !*s) {
		return talloc_strdup(mem_ctx, "");
	}
	ret = talloc(mem_ctx, strlen(s)+2);
	if (!ret) {
		return ret;
	}
	
	memcpy(ret+1, s, strlen(s)+1);
	ret[0] = '.';

	for (i=0;ret[i];i++) {
		if (ret[i] == '.') {
			char *p = strchr(ret+i+1, '.');
			if (p) {
				ret[i] = p-(ret+i+1);
			} else {
				ret[i] = strlen(ret+i+1);
			}
		}
	}

	return ret;
}

BOOL add_string_to_array(TALLOC_CTX *mem_ctx,
			 const char *str, const char ***strings, int *num)
{
	char *dup_str = talloc_strdup(mem_ctx, str);

	*strings = talloc_realloc(*strings,
				  ((*num)+1) * sizeof(**strings));

	if ((*strings == NULL) || (dup_str == NULL))
		return False;

	(*strings)[*num] = dup_str;
	*num += 1;

	return True;
}



/*
  varient of strcmp() that handles NULL ptrs
*/
int strcmp_safe(const char *s1, const char *s2)
{
	if (s1 == s2) {
		return 0;
	}
	if (s1 == NULL || s2 == NULL) {
		return s1?-1:1;
	}
	return strcmp(s1, s2);
}


/*******************************************************************
 Return a string representing a CIFS attribute for a file.
********************************************************************/
char *attrib_string(TALLOC_CTX *mem_ctx, uint32_t attrib)
{
	int i, len;
	const struct {
		char c;
		uint16_t attr;
	} attr_strs[] = {
		{'V', FILE_ATTRIBUTE_VOLUME},
		{'D', FILE_ATTRIBUTE_DIRECTORY},
		{'A', FILE_ATTRIBUTE_ARCHIVE},
		{'H', FILE_ATTRIBUTE_HIDDEN},
		{'S', FILE_ATTRIBUTE_SYSTEM},
		{'R', FILE_ATTRIBUTE_READONLY},
		{'d', FILE_ATTRIBUTE_DEVICE},
		{'t', FILE_ATTRIBUTE_TEMPORARY},
		{'s', FILE_ATTRIBUTE_SPARSE},
		{'r', FILE_ATTRIBUTE_REPARSE_POINT},
		{'c', FILE_ATTRIBUTE_COMPRESSED},
		{'o', FILE_ATTRIBUTE_OFFLINE},
		{'n', FILE_ATTRIBUTE_NONINDEXED},
		{'e', FILE_ATTRIBUTE_ENCRYPTED}
	};
	char *ret;

	ret = talloc(mem_ctx, ARRAY_SIZE(attr_strs)+1);
	if (!ret) {
		return NULL;
	}

	for (len=i=0; i<ARRAY_SIZE(attr_strs); i++) {
		if (attrib & attr_strs[i].attr) {
			ret[len++] = attr_strs[i].c;
		}
	}

	ret[len] = 0;

	return ret;
}

