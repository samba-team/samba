/*
   Samba string escaping routines

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017

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
#include "lib/util/util_str_escape.h"


/*
 * Calculate the encoded length of a character for log_escape
 *
 */
static size_t encoded_length(char c)
{
	if (c != '\\' &&  c > 0x1F) {
		return 1;
	} else {
		switch (c) {
		case '\a':
		case '\b':
		case '\f':
		case '\n':
		case '\r':
		case '\t':
		case '\v':
		case '\\':
			return 2;  /* C escape sequence */
		default:
			return 4;  /* hex escape \xhh   */
		}
	}
}

/*
 * Escape any control characters in the inputs to prevent them from
 * interfering with the log output.
 */
char *log_escape(TALLOC_CTX *frame, const char *in)
{
	size_t size = 0;        /* Space to allocate for the escaped data */
	char *encoded = NULL;   /* The encoded string                     */
	const char *c;
	char *e;

	if (in == NULL) {
		return NULL;
	}

	/* Calculate the size required for the escaped array */
	c = in;
	while (*c) {
		size += encoded_length( *c);
		c++;
	}
	size++;

	encoded = talloc_array( frame, char, size);
	if (encoded == NULL) {
		DBG_ERR( "Out of memory allocating encoded string");
		return NULL;
	}

	c = in;
	e = encoded;
	while (*c) {
		if (*c != '\\' && *c > 0x1F) {
			*e++ = *c++;
		} else {
			switch (*c) {
			case '\a':
				*e++ = '\\';
				*e++ = 'a';
				break;
			case '\b':
				*e++ = '\\';
				*e++ = 'b';
				break;
			case '\f':
				*e++ = '\\';
				*e++ = 'f';
				break;
			case '\n':
				*e++ = '\\';
				*e++ = 'n';
				break;
			case '\r':
				*e++ = '\\';
				*e++ = 'r';
				break;
			case '\t':
				*e++ = '\\';
				*e++ = 't';
				break;
			case '\v':
				*e++ = '\\';
				*e++ = 'v';
				break;
			case '\\':
				*e++ = '\\';
				*e++ = '\\';
				break;
			default:
				snprintf(e, 5, "\\x%02X", *c);
				e += 4;
			}
			c++;
		}
	}
	*e = '\0';
	return encoded;
}
