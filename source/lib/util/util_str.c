/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Simo Sorce      2001-2002
   Copyright (C) Martin Pool     2003
   Copyright (C) James Peach	 2005
   
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
#include "libcli/raw/smb.h"
#include "pstring.h"
#include "lib/ldb/include/ldb.h"
#include "system/locale.h"

/**
 * @file
 * @brief String utilities.
 **/


/**
 Trim the specified elements off the front and back of a string.
**/
_PUBLIC_ BOOL trim_string(char *s,const char *front,const char *back)
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
			/* Must use memmove here as src & dest can
			 * easily overlap. Found by valgrind. JRA. */
			memmove(s, s+front_len, (len-front_len)+1);
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
 Find the number of 'c' chars in a string
**/
_PUBLIC_ size_t count_chars(const char *s, char c)
{
	size_t count = 0;

	while (*s) {
		if (*s == c) count++;
		s ++;
	}

	return count;
}



/**
 Safe string copy into a known length string. maxlength does not
 include the terminating zero.
**/
_PUBLIC_ char *safe_strcpy(char *dest,const char *src, size_t maxlength)
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
			 (uint_t)(len-maxlength), (unsigned)len, (unsigned)maxlength, src));
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
_PUBLIC_ char *safe_strcat(char *dest, const char *src, size_t maxlength)
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
 Routine to get hex characters and turn them into a 16 byte array.
 the array can be variable length, and any non-hex-numeric
 characters are skipped.  "0xnn" or "0Xnn" is specially catered
 for.

 valid examples: "0A5D15"; "0x15, 0x49, 0xa2"; "59\ta9\te3\n"


**/
_PUBLIC_ size_t strhex_to_str(char *p, size_t len, const char *strhex)
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

		if (!(p1 = strchr(hexchars, toupper((unsigned char)strhex[i]))))
			break;

		i++; /* next hex digit */

		if (!(p2 = strchr(hexchars, toupper((unsigned char)strhex[i]))))
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

/** 
 * Parse a hex string and return a data blob. 
 */
_PUBLIC_ DATA_BLOB strhex_to_data_blob(const char *strhex) 
{
	DATA_BLOB ret_blob = data_blob(NULL, strlen(strhex)/2+1);

	ret_blob.length = strhex_to_str((char *)ret_blob.data, 	
					strlen(strhex), 
					strhex);

	return ret_blob;
}


/**
 * Routine to print a buffer as HEX digits, into an allocated string.
 */
_PUBLIC_ void hex_encode(const unsigned char *buff_in, size_t len, char **out_hex_buffer)
{
	int i;
	char *hex_buffer;

	*out_hex_buffer = smb_xmalloc((len*2)+1);
	hex_buffer = *out_hex_buffer;

	for (i = 0; i < len; i++)
		slprintf(&hex_buffer[i*2], 3, "%02X", buff_in[i]);
}

/**
 Check if a string is part of a list.
**/
_PUBLIC_ BOOL in_list(const char *s, const char *list, BOOL casesensitive)
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
			if (strcasecmp_m(tok,s) == 0)
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
_PUBLIC_ void string_free(char **s)
{
	if (s) SAFE_FREE(*s);
}

/**
 Set a string value, deallocating any existing space, and allocing the space
 for the string
**/
_PUBLIC_ BOOL string_set(char **dest, const char *src)
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

_PUBLIC_ void string_sub(char *s,const char *pattern, const char *insert, size_t len)
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

_PUBLIC_ void all_string_sub(char *s,const char *pattern,const char *insert, size_t len)
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
 Unescape a URL encoded string, in place.
**/

_PUBLIC_ void rfc1738_unescape(char *buf)
{
	char *p=buf;

	while ((p=strchr(p,'+')))
		*p = ' ';

	p = buf;

	while (p && *p && (p=strchr(p,'%'))) {
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

#ifdef VALGRIND
size_t valgrind_strlen(const char *s)
{
	size_t count;
	for(count = 0; *s++; count++)
		;
	return count;
}
#endif


/**
  format a string into length-prefixed dotted domain format, as used in NBT
  and in some ADS structures
**/
_PUBLIC_ const char *str_format_nbt_domain(TALLOC_CTX *mem_ctx, const char *s)
{
	char *ret;
	int i;
	if (!s || !*s) {
		return talloc_strdup(mem_ctx, "");
	}
	ret = talloc_size(mem_ctx, strlen(s)+2);
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

/**
 * Add a string to an array of strings.
 *
 * num should be a pointer to an integer that holds the current 
 * number of elements in strings. It will be updated by this function.
 */
_PUBLIC_ BOOL add_string_to_array(TALLOC_CTX *mem_ctx,
			 const char *str, const char ***strings, int *num)
{
	char *dup_str = talloc_strdup(mem_ctx, str);

	*strings = talloc_realloc(mem_ctx,
				    *strings,
				    const char *, ((*num)+1));

	if ((*strings == NULL) || (dup_str == NULL))
		return False;

	(*strings)[*num] = dup_str;
	*num += 1;

	return True;
}



/**
  varient of strcmp() that handles NULL ptrs
**/
_PUBLIC_ int strcmp_safe(const char *s1, const char *s2)
{
	if (s1 == s2) {
		return 0;
	}
	if (s1 == NULL || s2 == NULL) {
		return s1?-1:1;
	}
	return strcmp(s1, s2);
}


/**
return the number of bytes occupied by a buffer in ASCII format
the result includes the null termination
limited by 'n' bytes
**/
_PUBLIC_ size_t ascii_len_n(const char *src, size_t n)
{
	size_t len;

	len = strnlen(src, n);
	if (len+1 <= n) {
		len += 1;
	}

	return len;
}


/**
 Return a string representing a CIFS attribute for a file.
**/
_PUBLIC_ char *attrib_string(TALLOC_CTX *mem_ctx, uint32_t attrib)
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
		{'N', FILE_ATTRIBUTE_NORMAL},
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

	ret = talloc_size(mem_ctx, ARRAY_SIZE(attr_strs)+1);
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

/**
 Set a boolean variable from the text value stored in the passed string.
 Returns True in success, False if the passed string does not correctly 
 represent a boolean.
**/

_PUBLIC_ BOOL set_boolean(const char *boolean_string, BOOL *boolean)
{
	if (strwicmp(boolean_string, "yes") == 0 ||
	    strwicmp(boolean_string, "true") == 0 ||
	    strwicmp(boolean_string, "on") == 0 ||
	    strwicmp(boolean_string, "1") == 0) {
		*boolean = True;
		return True;
	} else if (strwicmp(boolean_string, "no") == 0 ||
		   strwicmp(boolean_string, "false") == 0 ||
		   strwicmp(boolean_string, "off") == 0 ||
		   strwicmp(boolean_string, "0") == 0) {
		*boolean = False;
		return True;
	}
	return False;
}

/**
 * Parse a string containing a boolean value.
 *
 * val will be set to the read value.
 *
 * @retval True if a boolean value was parsed, False otherwise.
 */
_PUBLIC_ BOOL conv_str_bool(const char * str, BOOL * val)
{
	char *	end = NULL;
	long	lval;

	if (str == NULL || *str == '\0') {
		return False;
	}

	lval = strtol(str, &end, 10 /* base */);
	if (end == NULL || *end != '\0' || end == str) {
		return set_boolean(str, val);
	}

	*val = (lval) ? True : False;
	return True;
}

/**
 * Convert a size specification like 16K into an integral number of bytes. 
 **/
_PUBLIC_ BOOL conv_str_size(const char * str, uint64_t * val)
{
	char *		    end = NULL;
	unsigned long long  lval;

	if (str == NULL || *str == '\0') {
		return False;
	}

	lval = strtoull(str, &end, 10 /* base */);
	if (end == NULL || end == str) {
		return False;
	}

	if (*end) {
		if (strwicmp(end, "K") == 0) {
			lval *= 1024ULL;
		} else if (strwicmp(end, "M") == 0) {
			lval *= (1024ULL * 1024ULL);
		} else if (strwicmp(end, "G") == 0) {
			lval *= (1024ULL * 1024ULL * 1024ULL);
		} else if (strwicmp(end, "T") == 0) {
			lval *= (1024ULL * 1024ULL * 1024ULL * 1024ULL);
		} else if (strwicmp(end, "P") == 0) {
			lval *= (1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL);
		} else {
			return False;
		}
	}

	*val = (uint64_t)lval;
	return True;
}

/**
 * Parse a uint64_t value from a string
 *
 * val will be set to the value read.
 *
 * @retval True if parsing was successful, False otherwise
 */
_PUBLIC_ BOOL conv_str_u64(const char * str, uint64_t * val)
{
	char *		    end = NULL;
	unsigned long long  lval;

	if (str == NULL || *str == '\0') {
		return False;
	}

	lval = strtoull(str, &end, 10 /* base */);
	if (end == NULL || *end != '\0' || end == str) {
		return False;
	}

	*val = (uint64_t)lval;
	return True;
}

/**
return the number of bytes occupied by a buffer in CH_UTF16 format
the result includes the null termination
**/
_PUBLIC_ size_t utf16_len(const void *buf)
{
	size_t len;

	for (len = 0; SVAL(buf,len); len += 2) ;

	return len + 2;
}

/**
return the number of bytes occupied by a buffer in CH_UTF16 format
the result includes the null termination
limited by 'n' bytes
**/
_PUBLIC_ size_t utf16_len_n(const void *src, size_t n)
{
	size_t len;

	for (len = 0; (len+2 < n) && SVAL(src, len); len += 2) ;

	if (len+2 <= n) {
		len += 2;
	}

	return len;
}

_PUBLIC_ size_t ucs2_align(const void *base_ptr, const void *p, int flags)
{
	if (flags & (STR_NOALIGN|STR_ASCII))
		return 0;
	return PTR_DIFF(p, base_ptr) & 1;
}

/**
Do a case-insensitive, whitespace-ignoring string compare.
**/
_PUBLIC_ int strwicmp(const char *psz1, const char *psz2)
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
		if (toupper((unsigned char)*psz1) != toupper((unsigned char)*psz2) 
		    || *psz1 == '\0'
		    || *psz2 == '\0')
			break;
		psz1++;
		psz2++;
	}
	return (*psz1 - *psz2);
}

/**
 String replace.
**/
_PUBLIC_ void string_replace(char *s, char oldc, char newc)
{
	while (*s) {
		if (*s == oldc) *s = newc;
		s++;
	}
}

/**
 * Compare 2 strings.
 *
 * @note The comparison is case-insensitive.
 **/
_PUBLIC_ BOOL strequal(const char *s1, const char *s2)
{
	if (s1 == s2)
		return(True);
	if (!s1 || !s2)
		return(False);
  
	return strcasecmp(s1,s2) == 0;
}
