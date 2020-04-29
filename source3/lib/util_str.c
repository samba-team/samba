/*
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Simo Sorce      2001-2002
   Copyright (C) Martin Pool     2003
   Copyright (C) James Peach	 2006
   Copyright (C) Jeremy Allison  1992-2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "lib/param/loadparm.h"

static const char toupper_ascii_fast_table[128] = {
	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
	0x60, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f
};

/**
 * Compare 2 strings up to and including the nth char.
 *
 * @note The comparison is case-insensitive.
 **/
bool strnequal(const char *s1,const char *s2,size_t n)
{
	if (s1 == s2)
		return(true);
	if (!s1 || !s2 || !n)
		return(false);

	return(strncasecmp_m(s1,s2,n)==0);
}

/**
 Convert a string to "normal" form.
**/

bool strnorm(char *s, int case_default)
{
	if (case_default == CASE_UPPER)
		return strupper_m(s);
	else
		return strlower_m(s);
}

/**
 Skip past a string in a buffer. Buffer may not be
 null terminated. end_ptr points to the first byte after
 then end of the buffer.
**/

char *skip_string(const char *base, size_t len, char *buf)
{
	const char *end_ptr = base + len;

	if (end_ptr < base || !base || !buf || buf >= end_ptr) {
		return NULL;
	}

	/* Skip the string */
	while (*buf) {
		buf++;
		if (buf >= end_ptr) {
			return NULL;
		}
	}
	/* Skip the '\0' */
	buf++;
	return buf;
}

/**
 Count the number of characters in a string. Normally this will
 be the same as the number of bytes in a string for single byte strings,
 but will be different for multibyte.
**/

size_t str_charnum(const char *s)
{
	size_t ret, converted_size;
	smb_ucs2_t *tmpbuf2 = NULL;
	if (!push_ucs2_talloc(talloc_tos(), &tmpbuf2, s, &converted_size)) {
		return 0;
	}
	ret = strlen_w(tmpbuf2);
	TALLOC_FREE(tmpbuf2);
	return ret;
}

bool trim_char(char *s,char cfront,char cback)
{
	bool ret = false;
	char *ep;
	char *fp = s;

	/* Ignore null or empty strings. */
	if (!s || (s[0] == '\0'))
		return false;

	if (cfront) {
		while (*fp && *fp == cfront)
			fp++;
		if (!*fp) {
			/* We ate the string. */
			s[0] = '\0';
			return true;
		}
		if (fp != s)
			ret = true;
	}

	ep = fp + strlen(fp) - 1;
	if (cback) {
		/* Attempt ascii only. Bail for mb strings. */
		while ((ep >= fp) && (*ep == cback)) {
			ret = true;
			if ((ep > fp) && (((unsigned char)ep[-1]) & 0x80)) {
				/* Could be mb... bail back to tim_string. */
				char fs[2], bs[2];
				if (cfront) {
					fs[0] = cfront;
					fs[1] = '\0';
				}
				bs[0] = cback;
				bs[1] = '\0';
				return trim_string(s, cfront ? fs : NULL, bs);
			} else {
				ep--;
			}
		}
		if (ep < fp) {
			/* We ate the string. */
			s[0] = '\0';
			return true;
		}
	}

	ep[1] = '\0';
	memmove(s, fp, ep-fp+2);
	return ret;
}

/**
 Check if a string is part of a list.
**/

bool in_list(const char *s, const char *list, bool casesensitive)
{
	char *tok = NULL;
	bool ret = false;
	TALLOC_CTX *frame;

	if (!list) {
		return false;
	}

	frame = talloc_stackframe();
	while (next_token_talloc(frame, &list, &tok,LIST_SEP)) {
		if (casesensitive) {
			if (strcmp(tok,s) == 0) {
				ret = true;
				break;
			}
		} else {
			if (strcasecmp_m(tok,s) == 0) {
				ret = true;
				break;
			}
		}
	}
	TALLOC_FREE(frame);
	return ret;
}

/*
 * Internal guts of talloc_string_sub and talloc_all_string_sub.
 * talloc version of string_sub2.
 */

char *talloc_string_sub2(TALLOC_CTX *mem_ctx, const char *src,
			const char *pattern,
			const char *insert,
			bool remove_unsafe_characters,
			bool replace_once,
			bool allow_trailing_dollar)
{
	char *p, *in;
	char *s;
	char *string;
	ssize_t ls,lp,li,ld, i;

	if (!insert || !pattern || !*pattern || !src) {
		return NULL;
	}

	string = talloc_strdup(mem_ctx, src);
	if (string == NULL) {
		DEBUG(0, ("talloc_string_sub2: "
			"talloc_strdup failed\n"));
		return NULL;
	}

	s = string;

	in = talloc_strdup(mem_ctx, insert);
	if (!in) {
		DEBUG(0, ("talloc_string_sub2: ENOMEM\n"));
		return NULL;
	}
	ls = (ssize_t)strlen(s);
	lp = (ssize_t)strlen(pattern);
	li = (ssize_t)strlen(insert);
	ld = li - lp;

	for (i=0;i<li;i++) {
		switch (in[i]) {
			case '$':
				/* allow a trailing $
				 * (as in machine accounts) */
				if (allow_trailing_dollar && (i == li - 1 )) {
					break;
				}

				FALL_THROUGH;
			case '`':
			case '"':
			case '\'':
			case ';':
			case '%':
			case '\r':
			case '\n':
				if (remove_unsafe_characters) {
					in[i] = '_';
					break;
				}

				FALL_THROUGH;
			default:
				/* ok */
				break;
		}
	}

	while ((p = strstr_m(s,pattern))) {
		if (ld > 0) {
			int offset = PTR_DIFF(s,string);
			string = (char *)TALLOC_REALLOC(mem_ctx, string,
							ls + ld + 1);
			if (!string) {
				DEBUG(0, ("talloc_string_sub: out of "
					  "memory!\n"));
				TALLOC_FREE(in);
				return NULL;
			}
			p = string + offset + (p - s);
		}
		if (li != lp) {
			memmove(p+li,p+lp,strlen(p+lp)+1);
		}
		memcpy(p, in, li);
		s = p + li;
		ls += ld;

		if (replace_once) {
			break;
		}
	}
	TALLOC_FREE(in);
	return string;
}

/* Same as string_sub, but returns a talloc'ed string */

char *talloc_string_sub(TALLOC_CTX *mem_ctx,
			const char *src,
			const char *pattern,
			const char *insert)
{
	return talloc_string_sub2(mem_ctx, src, pattern, insert,
			true, false, false);
}

char *talloc_all_string_sub(TALLOC_CTX *ctx,
				const char *src,
				const char *pattern,
				const char *insert)
{
	return talloc_string_sub2(ctx, src, pattern, insert,
			false, false, false);
}

/**
 Write an octal as a string.
**/

char *octal_string(int i)
{
	char *result;
	if (i == -1) {
		result = talloc_strdup(talloc_tos(), "-1");
	}
	else {
		result = talloc_asprintf(talloc_tos(), "0%o", i);
	}
	SMB_ASSERT(result != NULL);
	return result;
}


/**
 Truncate a string at a specified length.
**/

char *string_truncate(char *s, unsigned int length)
{
	if (s && strlen(s) > length)
		s[length] = 0;
	return s;
}


/***********************************************************************
 Return the equivalent of doing strrchr 'n' times - always going
 backwards.
***********************************************************************/

char *strnrchr_m(const char *s, char c, unsigned int n)
{
	smb_ucs2_t *ws = NULL;
	char *s2 = NULL;
	smb_ucs2_t *p;
	char *ret;
	size_t converted_size;

	if (!push_ucs2_talloc(talloc_tos(), &ws, s, &converted_size)) {
		/* Too hard to try and get right. */
		return NULL;
	}
	p = strnrchr_w(ws, UCS2_CHAR(c), n);
	if (!p) {
		TALLOC_FREE(ws);
		return NULL;
	}
	*p = 0;
	if (!pull_ucs2_talloc(talloc_tos(), &s2, ws, &converted_size)) {
		TALLOC_FREE(ws);
		/* Too hard to try and get right. */
		return NULL;
	}
	ret = discard_const_p(char, (s+strlen(s2)));
	TALLOC_FREE(ws);
	TALLOC_FREE(s2);
	return ret;
}

static bool unix_strlower(const char *src, size_t srclen, char *dest, size_t destlen)
{
	size_t size;
	smb_ucs2_t *buffer = NULL;
	bool ret;

	if (!convert_string_talloc(talloc_tos(), CH_UNIX, CH_UTF16LE, src, srclen,
				   (void **)(void *)&buffer, &size))
	{
		return false;
	}
	if (!strlower_w(buffer) && (dest == src)) {
		TALLOC_FREE(buffer);
		return true;
	}
	ret = convert_string(CH_UTF16LE, CH_UNIX, buffer, size, dest, destlen, &size);
	TALLOC_FREE(buffer);
	return ret;
}

#if 0 /* Alternate function that avoid talloc calls for ASCII and non ASCII */

/**
 Convert a string to lower case.
**/
_PUBLIC_ void strlower_m(char *s)
{
	char *d;
	struct smb_iconv_handle *iconv_handle;

	iconv_handle = get_iconv_handle();

	d = s;

	while (*s) {
		size_t c_size, c_size2;
		codepoint_t c = next_codepoint_handle(iconv_handle, s, &c_size);
		c_size2 = push_codepoint_handle(iconv_handle, d, tolower_m(c));
		if (c_size2 > c_size) {
			DEBUG(0,("FATAL: codepoint 0x%x (0x%x) expanded from %d to %d bytes in strlower_m\n",
				 c, tolower_m(c), (int)c_size, (int)c_size2));
			smb_panic("codepoint expansion in strlower_m\n");
		}
		s += c_size;
		d += c_size2;
	}
	*d = 0;
}

#endif

/**
 Convert a string to lower case.
**/

bool strlower_m(char *s)
{
	size_t len;
	int errno_save;
	bool ret = false;

	/* this is quite a common operation, so we want it to be
	   fast. We optimise for the ascii case, knowing that all our
	   supported multi-byte character sets are ascii-compatible
	   (ie. they match for the first 128 chars) */

	while (*s && !(((unsigned char)s[0]) & 0x80)) {
		*s = tolower_m((unsigned char)*s);
		s++;
	}

	if (!*s)
		return true;

	/* I assume that lowercased string takes the same number of bytes
	 * as source string even in UTF-8 encoding. (VIV) */
	len = strlen(s) + 1;
	errno_save = errno;
	errno = 0;
	ret = unix_strlower(s,len,s,len);
	/* Catch mb conversion errors that may not terminate. */
	if (errno) {
		s[len-1] = '\0';
	}
	errno = errno_save;
	return ret;
}

static bool unix_strupper(const char *src, size_t srclen, char *dest, size_t destlen)
{
	size_t size;
	smb_ucs2_t *buffer;
	bool ret;

	if (!push_ucs2_talloc(talloc_tos(), &buffer, src, &size)) {
		return false;
	}

	if (!strupper_w(buffer) && (dest == src)) {
		TALLOC_FREE(buffer);
		return true;
	}

	ret = convert_string(CH_UTF16LE, CH_UNIX, buffer, size, dest, destlen, &size);
	TALLOC_FREE(buffer);
	return ret;
}

#if 0 /* Alternate function that avoid talloc calls for ASCII and non ASCII */

/**
 Convert a string to UPPER case.
**/
_PUBLIC_ void strupper_m(char *s)
{
	char *d;
	struct smb_iconv_handle *iconv_handle;

	iconv_handle = get_iconv_handle();

	d = s;

	while (*s) {
		size_t c_size, c_size2;
		codepoint_t c = next_codepoint_handle(iconv_handle, s, &c_size);
		c_size2 = push_codepoint_handle(iconv_handle, d, toupper_m(c));
		if (c_size2 > c_size) {
			DEBUG(0,("FATAL: codepoint 0x%x (0x%x) expanded from %d to %d bytes in strupper_m\n",
				 c, toupper_m(c), (int)c_size, (int)c_size2));
			smb_panic("codepoint expansion in strupper_m\n");
		}
		s += c_size;
		d += c_size2;
	}
	*d = 0;
}

#endif

/**
 Convert a string to upper case.
**/

bool strupper_m(char *s)
{
	size_t len;
	bool ret = false;

	/* this is quite a common operation, so we want it to be
	   fast. We optimise for the ascii case, knowing that all our
	   supported multi-byte character sets are ascii-compatible
	   (ie. they match for the first 128 chars) */

	while (*s && !(((unsigned char)s[0]) & 0x80)) {
		*s = toupper_ascii_fast_table[(unsigned char)s[0]];
		s++;
	}

	if (!*s)
		return true;

	/* I assume that uppercased string takes the same number of bytes
	 * as source string even in multibyte encoding. (VIV) */
	len = strlen(s) + 1;
	ret = unix_strupper(s,len,s,len);
	/* Catch mb conversion errors that may not terminate. */
	if (!ret) {
		s[len-1] = '\0';
	}
	return ret;
}

/**
 Just a typesafety wrapper for snprintf into a fstring.
**/

int fstr_sprintf(fstring s, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vsnprintf(s, FSTRING_LEN, fmt, ap);
	va_end(ap);
	return ret;
}

#define IPSTR_LIST_SEP	","
#define IPSTR_LIST_CHAR	','

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

static char *ipstr_list_add(char **ipstr_list, const struct ip_service *service)
{
	char *new_ipstr = NULL;
	char addr_buf[INET6_ADDRSTRLEN];
	int ret;

	/* arguments checking */
	if (!ipstr_list || !service) {
		return NULL;
	}

	print_sockaddr(addr_buf,
			sizeof(addr_buf),
			&service->ss);

	/* attempt to convert ip to a string and append colon separator to it */
	if (*ipstr_list) {
		if (service->ss.ss_family == AF_INET) {
			/* IPv4 */
			ret = asprintf(&new_ipstr, "%s%s%s:%d",	*ipstr_list,
				       IPSTR_LIST_SEP, addr_buf,
				       service->port);
		} else {
			/* IPv6 */
			ret = asprintf(&new_ipstr, "%s%s[%s]:%d", *ipstr_list,
				       IPSTR_LIST_SEP, addr_buf,
				       service->port);
		}
		SAFE_FREE(*ipstr_list);
	} else {
		if (service->ss.ss_family == AF_INET) {
			/* IPv4 */
			ret = asprintf(&new_ipstr, "%s:%d", addr_buf,
				       service->port);
		} else {
			/* IPv6 */
			ret = asprintf(&new_ipstr, "[%s]:%d", addr_buf,
				       service->port);
		}
	}
	if (ret == -1) {
		return NULL;
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

char *ipstr_list_make(char **ipstr_list,
			const struct ip_service *ip_list,
			int ip_count)
{
	int i;

	/* arguments checking */
	if (!ip_list || !ipstr_list) {
		return 0;
	}

	*ipstr_list = NULL;

	/* process ip addresses given as arguments */
	for (i = 0; i < ip_count; i++) {
		*ipstr_list = ipstr_list_add(ipstr_list, &ip_list[i]);
	}

	return (*ipstr_list);
}


/**
 * Parse given ip string list into array of ip addresses
 * (as ip_service structures)
 *    e.g. [IPv6]:port,192.168.1.100:389,192.168.1.78, ...
 *
 * @param ipstr ip string list to be parsed
 * @param ip_list pointer to array of ip addresses which is
 *        allocated by this function and must be freed by caller
 * @return number of successfully parsed addresses
 **/

int ipstr_list_parse(const char *ipstr_list, struct ip_service **ip_list)
{
	TALLOC_CTX *frame;
	char *token_str = NULL;
	size_t i, count;

	if (!ipstr_list || !ip_list)
		return 0;

	count = count_chars(ipstr_list, IPSTR_LIST_CHAR) + 1;
	if ( (*ip_list = SMB_MALLOC_ARRAY(struct ip_service, count)) == NULL ) {
		DEBUG(0,("ipstr_list_parse: malloc failed for %lu entries\n",
					(unsigned long)count));
		return 0;
	}

	frame = talloc_stackframe();
	for ( i=0; next_token_talloc(frame, &ipstr_list, &token_str,
				IPSTR_LIST_SEP) && i<count; i++ ) {
		char *s = token_str;
		char *p = strrchr(token_str, ':');

		if (p) {
			*p = 0;
			(*ip_list)[i].port = atoi(p+1);
		}

		/* convert single token to ip address */
		if (token_str[0] == '[') {
			/* IPv6 address. */
			s++;
			p = strchr(token_str, ']');
			if (!p) {
				continue;
			}
			*p = '\0';
		}
		if (!interpret_string_addr(&(*ip_list)[i].ss,
					s,
					AI_NUMERICHOST)) {
			continue;
		}
	}
	TALLOC_FREE(frame);
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

/* read a SMB_BIG_UINT from a string */
uint64_t STR_TO_SMB_BIG_UINT(const char *nptr, const char **entptr)
{

	uint64_t val = (uint64_t)-1;
	const char *p = nptr;

	if (!p) {
		if (entptr) {
			*entptr = p;
		}
		return val;
	}

	while (*p && isspace(*p))
		p++;

	sscanf(p,"%"SCNu64,&val);
	if (entptr) {
		while (*p && isdigit(*p))
			p++;
		*entptr = p;
	}

	return val;
}

/* Convert a size specification to a count of bytes. We accept the following
 * suffixes:
 *	    bytes if there is no suffix
 *	kK  kibibytes
 *	mM  mebibytes
 *	gG  gibibytes
 *	tT  tibibytes
 *	pP  whatever the ISO name for petabytes is
 *
 *  Returns 0 if the string can't be converted.
 */
uint64_t conv_str_size(const char * str)
{
        uint64_t lval;
        char *end;
	int error = 0;

        if (str == NULL || *str == '\0') {
                return 0;
        }

	lval = smb_strtoull(str, &end, 10, &error, SMB_STR_STANDARD);

        if (error != 0) {
                return 0;
        }

	if (*end == '\0') {
		return lval;
	}

	if (strwicmp(end, "K") == 0) {
		lval *= 1024ULL;
	} else if (strwicmp(end, "M") == 0) {
		lval *= (1024ULL * 1024ULL);
	} else if (strwicmp(end, "G") == 0) {
		lval *= (1024ULL * 1024ULL *
			 1024ULL);
	} else if (strwicmp(end, "T") == 0) {
		lval *= (1024ULL * 1024ULL *
			 1024ULL * 1024ULL);
	} else if (strwicmp(end, "P") == 0) {
		lval *= (1024ULL * 1024ULL *
			 1024ULL * 1024ULL *
			 1024ULL);
	} else {
		return 0;
	}

	return lval;
}

/*
 * asprintf into a string and strupper_m it after that.
 */

int asprintf_strupper_m(char **strp, const char *fmt, ...)
{
	va_list ap;
	char *result;
	int ret;

	va_start(ap, fmt);
	ret = vasprintf(&result, fmt, ap);
	va_end(ap);

	if (ret == -1)
		return -1;

	if (!strupper_m(result)) {
		SAFE_FREE(result);
		return -1;
	}

	*strp = result;
	return ret;
}

char *talloc_asprintf_strupper_m(TALLOC_CTX *t, const char *fmt, ...)
{
	va_list ap;
	char *ret;

	va_start(ap, fmt);
	ret = talloc_vasprintf(t, fmt, ap);
	va_end(ap);

	if (ret == NULL) {
		return NULL;
	}
	if (!strupper_m(ret)) {
		TALLOC_FREE(ret);
		return NULL;
	}
	return ret;
}

char *talloc_asprintf_strlower_m(TALLOC_CTX *t, const char *fmt, ...)
{
	va_list ap;
	char *ret;

	va_start(ap, fmt);
	ret = talloc_vasprintf(t, fmt, ap);
	va_end(ap);

	if (ret == NULL) {
		return NULL;
	}
	if (!strlower_m(ret)) {
		TALLOC_FREE(ret);
		return NULL;
	}
	return ret;
}


/********************************************************************
 Check a string for any occurrences of a specified list of invalid
 characters.
********************************************************************/

bool validate_net_name( const char *name,
		const char *invalid_chars,
		int max_len)
{
	int i;

	if (!name) {
		return false;
	}

	for ( i=0; i<max_len && name[i]; i++ ) {
		/* fail if strchr_m() finds one of the invalid characters */
		if ( name[i] && strchr_m( invalid_chars, name[i] ) ) {
			return false;
		}
	}

	return true;
}


/*******************************************************************
 Add a shell escape character '\' to any character not in a known list
 of characters. UNIX charset format.
*******************************************************************/

#define INCLUDE_LIST "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_/ \t.,"
#define INSIDE_DQUOTE_LIST "$`\n\"\\"

char *escape_shell_string(const char *src)
{
	size_t srclen = strlen(src);
	char *ret = SMB_MALLOC_ARRAY(char, (srclen * 2) + 1);
	char *dest = ret;
	bool in_s_quote = false;
	bool in_d_quote = false;
	bool next_escaped = false;

	if (!ret) {
		return NULL;
	}

	while (*src) {
		size_t c_size;
		codepoint_t c = next_codepoint(src, &c_size);

		if (c == INVALID_CODEPOINT) {
			SAFE_FREE(ret);
			return NULL;
		}

		if (c_size > 1) {
			memcpy(dest, src, c_size);
			src += c_size;
			dest += c_size;
			next_escaped = false;
			continue;
		}

		/*
		 * Deal with backslash escaped state.
		 * This only lasts for one character.
		 */

		if (next_escaped) {
			*dest++ = *src++;
			next_escaped = false;
			continue;
		}

		/*
		 * Deal with single quote state. The
		 * only thing we care about is exiting
		 * this state.
		 */

		if (in_s_quote) {
			if (*src == '\'') {
				in_s_quote = false;
			}
			*dest++ = *src++;
			continue;
		}

		/*
		 * Deal with double quote state. The most
		 * complex state. We must cope with \, meaning
		 * possibly escape next char (depending what it
		 * is), ", meaning exit this state, and possibly
		 * add an \ escape to any unprotected character
		 * (listed in INSIDE_DQUOTE_LIST).
		 */

		if (in_d_quote) {
			if (*src == '\\') {
				/*
				 * Next character might be escaped.
				 * We have to peek. Inside double
				 * quotes only INSIDE_DQUOTE_LIST
				 * characters are escaped by a \.
				 */

				char nextchar;

				c = next_codepoint(&src[1], &c_size);
				if (c == INVALID_CODEPOINT) {
					SAFE_FREE(ret);
					return NULL;
				}
				if (c_size > 1) {
					/*
					 * Don't escape the next char.
					 * Just copy the \.
					 */
					*dest++ = *src++;
					continue;
				}

				nextchar = src[1];

				if (nextchar && strchr(INSIDE_DQUOTE_LIST,
							(int)nextchar)) {
					next_escaped = true;
				}
				*dest++ = *src++;
				continue;
			}

			if (*src == '\"') {
				/* Exit double quote state. */
				in_d_quote = false;
				*dest++ = *src++;
				continue;
			}

			/*
			 * We know the character isn't \ or ",
			 * so escape it if it's any of the other
			 * possible unprotected characters.
			 */

	       		if (strchr(INSIDE_DQUOTE_LIST, (int)*src)) {
				*dest++ = '\\';
			}
			*dest++ = *src++;
			continue;
		}

		/*
		 * From here to the end of the loop we're
		 * not in the single or double quote state.
		 */

		if (*src == '\\') {
			/* Next character must be escaped. */
			next_escaped = true;
			*dest++ = *src++;
			continue;
		}

		if (*src == '\'') {
			/* Go into single quote state. */
			in_s_quote = true;
			*dest++ = *src++;
			continue;
		}

		if (*src == '\"') {
			/* Go into double quote state. */
			in_d_quote = true;
			*dest++ = *src++;
			continue;
		}

		/* Check if we need to escape the character. */

	       	if (!strchr(INCLUDE_LIST, (int)*src)) {
			*dest++ = '\\';
		}
		*dest++ = *src++;
	}
	*dest++ = '\0';
	return ret;
}

/*
 * This routine improves performance for operations temporarily acting on a
 * full path. It is equivalent to the much more expensive
 *
 * talloc_asprintf(talloc_tos(), "%s/%s", dir, name)
 *
 * This actually does make a difference in metadata-heavy workloads (i.e. the
 * "standard" client.txt nbench run.
 */

ssize_t full_path_tos(const char *dir, const char *name,
		      char *tmpbuf, size_t tmpbuf_len,
		      char **pdst, char **to_free)
{
	size_t dirlen, namelen, len;
	char *dst;

	dirlen = strlen(dir);
	namelen = strlen(name);
	len = dirlen + namelen + 1;

	if (len < tmpbuf_len) {
		dst = tmpbuf;
		*to_free = NULL;
	} else {
		dst = talloc_array(talloc_tos(), char, len+1);
		if (dst == NULL) {
			return -1;
		}
		*to_free = dst;
	}

	memcpy(dst, dir, dirlen);
	dst[dirlen] = '/';
	memcpy(dst+dirlen+1, name, namelen+1);
	*pdst = dst;
	return len;
}
