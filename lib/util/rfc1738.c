/*
 * Functions for RFC 3986 percent-encoding.
 *
 * NOTE:
 *
 * This file was originally imported from the Squid project but has been
 * significantly altered. The licence below is reproduced intact, but refers
 * to files in Squid's repository, not in Samba. See COPYING for the GPLv3
 * notice (being the later version mentioned below).
 */

/*
 * $Id$
 *
 * DEBUG:
 * AUTHOR: Harvest Derived
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "replace.h"
#include <talloc.h>
#include "lib/util/samba_util.h"
#include "lib/util/util_str_hex.h"

#define RFC1738_ENCODE 1
#define RFC1738_RESERVED 2

/*
 * According to RFC 1738, "$-_.+!*'()," are not reserved or unsafe, but as
 * that has been obsolete since 2004, we sm instead for RFC 3986, where:
 *
 *  reserved =    : / ? # [ ] @ ! $ & ' ( ) * + , ; =
 *  unreserved = ALPHA DIGIT - . _ ~
 *
 * and whatever is not in either of those are what RFC 1738 called "unsafe",
 * meaning that they should are canonically but not mandatorily escaped.
 *
 * Characters below 0x20 or above 0x7E are always enocded.
 */

static const unsigned char escapees[127] = {
	[' '] = RFC1738_ENCODE,
	['"'] = RFC1738_ENCODE,
	['%'] = RFC1738_ENCODE,
	['<'] = RFC1738_ENCODE,
	['>'] = RFC1738_ENCODE,
	['\\'] = RFC1738_ENCODE,
	['^'] = RFC1738_ENCODE,
	['`'] = RFC1738_ENCODE,
	['{'] = RFC1738_ENCODE,
	['|'] = RFC1738_ENCODE,
	['}'] = RFC1738_ENCODE,
	/* reserved : / ? # [ ] @ ! $ & ' ( ) * + , ; = */
	[':'] = RFC1738_RESERVED,
	['/'] = RFC1738_RESERVED,
	['?'] = RFC1738_RESERVED,
	['#'] = RFC1738_RESERVED,
	['['] = RFC1738_RESERVED,
	[']'] = RFC1738_RESERVED,
	['@'] = RFC1738_RESERVED,
	['!'] = RFC1738_RESERVED,
	['$'] = RFC1738_RESERVED,
	['&'] = RFC1738_RESERVED,
	['\''] = RFC1738_RESERVED,
	['('] = RFC1738_RESERVED,
	[')'] = RFC1738_RESERVED,
	['*'] = RFC1738_RESERVED,
	['+'] = RFC1738_RESERVED,
	[','] = RFC1738_RESERVED,
	[';'] = RFC1738_RESERVED,
	['='] = RFC1738_RESERVED,
};

/*
 *  rfc1738_do_escape - fills a preallocated buffer with an escaped version of
 *  the given string.
 *
 *  For canonical escaping, mask should be RFC1738_ENCODE | RFC1738_RESERVED.
 *  For mandatory escaping, mask should be RFC1738_RESERVED.
 */
static char *
rfc1738_do_escape(char *buf, size_t bufsize,
		  const char *url, size_t len, unsigned char mask)
{
	size_t i;
	size_t j = 0;
	for (i = 0; i < len; i++) {
		unsigned int c = (unsigned char) url[i];
		if (c > 126 || c < 32 || (escapees[c] & mask)) {
			if (j + 3 >= bufsize) {
				return NULL;
			}
			(void) snprintf(&buf[j], 4, "%%%02X", c);
			j += 3;
		} else {
			if (j + 1 >= bufsize) {
				return NULL;
			}
			buf[j] = c;
			j++;
		}
	}
	buf[j] = '\0';
	return buf;
}

/*
 * rfc1738_escape_part - Returns a talloced buffer that contains the RFC 3986
 * compliant, escaped version of the given url segment.
 */
char *
rfc1738_escape_part(TALLOC_CTX *mem_ctx, const char *url)
{
	size_t bufsize = 0;
	char *buf = NULL;

	size_t len = strlen(url);
	if (len >= SIZE_MAX / 3) {
		return NULL;
	}

	bufsize = len * 3 + 1;
	buf = talloc_array(mem_ctx, char, bufsize);
	if (buf == NULL) {
		return NULL;
	}

	talloc_set_name_const(buf, buf);

	return rfc1738_do_escape(buf, bufsize, url, len,
				 RFC1738_ENCODE | RFC1738_RESERVED);
}

/*
 * rfc1738_unescape() - Converts url-escaped characters in the string.
 *
 * The two characters following a '%' in a string should be hex digits that
 * describe an encoded byte. For example, "%25" is hex 0x25 or '%' in ASCII;
 * this is the only way to include a % in the unescaped string. Any character
 * can be escaped, including plain letters (e.g. "%61" for "a"). Anything
 * other than 2 hex characters following the % is an error.
 *
 * The conversion is done in-place, which is always safe as unescapes can only
 * shorten the string.
 *
 * Returns a pointer to the end of the string (that is, the '\0' byte), or
 * NULL on error, at which point s is in an undefined state.
 *
 * Note that after `char *e = rfc_unescape(s)`, `strlen(s)` will not equal
 * `e - s` if s originally contained "%00". You might want to check for this.
 */

_PUBLIC_ char *rfc1738_unescape(char *s)
{
	size_t i, j;	    /* i is write, j is read */
	uint64_t x;
	NTSTATUS status;
	for (i = 0, j = 0; s[j] != '\0'; i++, j++) {
		if (s[j] == '%') {
			status = read_hex_bytes(&s[j + 1], 2, &x);
			if (! NT_STATUS_IS_OK(status)) {
				return NULL;
			}
			j += 2; /* OK; read_hex_bytes() has checked ahead */
			s[i] = (unsigned char)x;
		} else {
			s[i] = s[j];
		}
	}
	s[i] = '\0';
	return s + i;
}
