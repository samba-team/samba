/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Simo Sorce      2001-2002
   Copyright (C) Martin Pool     2003
   
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
#include "system/iconv.h"

/**
 * @file
 * @brief String utilities.
 **/

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

/**
 Case insensitive string compararison
**/
int StrCaseCmp(const char *s1, const char *s2)
{
	codepoint_t c1=0, c2=0;
	size_t size1, size2;

	while (*s1 && *s2) {
		c1 = next_codepoint(s1, &size1);
		c2 = next_codepoint(s2, &size2);

		s1 += size1;
		s2 += size2;

		if (c1 == c2) {
			continue;
		}

		if (c1 == INVALID_CODEPOINT ||
		    c2 == INVALID_CODEPOINT) {
			/* what else can we do?? */
			return c1 - c2;
		}

		if (toupper_w(c1) != toupper_w(c2)) {
			return c1 - c2;
		}
	}

	return *s1 - *s2;
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
  
	return StrCaseCmp(s1,s2) == 0;
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
	
	return strcmp(s1,s2) == 0;
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
 String replace.
 NOTE: oldc and newc must be 7 bit characters
**/
void string_replace(char *s, char oldc, char newc)
{
	while (*s) {
		size_t size;
		codepoint_t c = next_codepoint(s, &size);
		if (c == oldc) {
			*s = newc;
		}
		s += size;
	}
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
size_t count_chars(const char *s, char c)
{
	size_t count = 0;

	while (*s) {
		size_t size;
		codepoint_t c2 = next_codepoint(s, &size);
		if (c2 == c) count++;
		s += size;
	}

	return count;
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
 Strchr and strrchr_m are a bit complex on general multi-byte strings. 
**/
char *strchr_m(const char *s, char c)
{
	/* characters below 0x3F are guaranteed to not appear in
	   non-initial position in multi-byte charsets */
	if ((c & 0xC0) == 0) {
		return strchr(s, c);
	}

	while (*s) {
		size_t size;
		codepoint_t c2 = next_codepoint(s, &size);
		if (c2 == c) {
			return discard_const(s);
		}
		s += size;
	}

	return NULL;
}

char *strrchr_m(const char *s, char c)
{
	char *ret = NULL;

	/* characters below 0x3F are guaranteed to not appear in
	   non-initial position in multi-byte charsets */
	if ((c & 0xC0) == 0) {
		return strrchr(s, c);
	}

	while (*s) {
		size_t size;
		codepoint_t c2 = next_codepoint(s, &size);
		if (c2 == c) {
			ret = discard_const(s);
		}
		s += size;
	}

	return ret;
}

/**
 Convert a string to lower case, allocated with talloc
**/
char *strlower_talloc(TALLOC_CTX *ctx, const char *src)
{
	size_t size=0;
	char *dest;

	/* this takes advantage of the fact that upper/lower can't
	   change the length of a character by more than 1 byte */
	dest = talloc(ctx, 2*(strlen(src))+1);
	if (dest == NULL) {
		return NULL;
	}

	while (*src) {
		size_t c_size;
		codepoint_t c = next_codepoint(src, &c_size);
		src += c_size;

		c = tolower_w(c);

		c_size = push_codepoint(dest+size, c);
		if (c_size == -1) {
			talloc_free(dest);
			return NULL;
		}
		size += c_size;
	}

	dest[size] = 0;

	return dest;
}

/**
 Convert a string to UPPER case, allocated with talloc
**/
char *strupper_talloc(TALLOC_CTX *ctx, const char *src)
{
	size_t size=0;
	char *dest;

	/* this takes advantage of the fact that upper/lower can't
	   change the length of a character by more than 1 byte */
	dest = talloc(ctx, 2*(strlen(src))+1);
	if (dest == NULL) {
		return NULL;
	}

	while (*src) {
		size_t c_size;
		codepoint_t c = next_codepoint(src, &c_size);
		src += c_size;

		c = toupper_w(c);

		c_size = push_codepoint(dest+size, c);
		if (c_size == -1) {
			talloc_free(dest);
			return NULL;
		}
		size += c_size;
	}

	dest[size] = 0;

	return dest;
}

/**
 Convert a string to lower case.
**/
void strlower_m(char *s)
{
	char *d;

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

	d = s;

	while (*s) {
		size_t c_size, c_size2;
		codepoint_t c = next_codepoint(s, &c_size);
		c_size2 = push_codepoint(d, tolower_w(c));
		if (c_size2 > c_size) {
			DEBUG(0,("FATAL: codepoint 0x%x (0x%x) expanded from %d to %d bytes in strlower_m\n",
				 c, tolower_w(c), c_size, c_size2));
			smb_panic("codepoint expansion in strlower_m\n");
		}
		s += c_size;
		d += c_size2;
	}
	*d = 0;
}

/**
 Convert a string to UPPER case.
**/
void strupper_m(char *s)
{
	char *d;

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

	d = s;

	while (*s) {
		size_t c_size, c_size2;
		codepoint_t c = next_codepoint(s, &c_size);
		c_size2 = push_codepoint(d, toupper_w(c));
		if (c_size2 > c_size) {
			DEBUG(0,("FATAL: codepoint 0x%x (0x%x) expanded from %d to %d bytes in strupper_m\n",
				 c, toupper_w(c), c_size, c_size2));
			smb_panic("codepoint expansion in strupper_m\n");
		}
		s += c_size;
		d += c_size2;
	}
	*d = 0;
}

/**
 Count the number of UCS2 characters in a string. Normally this will
 be the same as the number of bytes in a string for single byte strings,
 but will be different for multibyte.
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

	while (*s) {
		size_t c_size;
		codepoint_t c = next_codepoint(s, &c_size);
		if (c < 0x10000) {
			count += 1;
		} else {
			count += 2;
		}
		s += c_size;
	}

	return count;
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

/**
 * Decode a base64 string into a DATA_BLOB - simple and slow algorithm
 **/
DATA_BLOB base64_decode_data_blob(const char *s)
{
	const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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
	const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

	*strings = talloc_realloc_p(mem_ctx,
				    *strings,
				    const char *, ((*num)+1));

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
return the number of bytes occupied by a buffer in ASCII format
the result includes the null termination
limited by 'n' bytes
********************************************************************/
size_t ascii_len_n(const char *src, size_t n)
{
	size_t len;

	len = strnlen(src, n);
	if (len+1 <= n) {
		len += 1;
	}

	return len;
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

