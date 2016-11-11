/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jeremy Allison       2001

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

#include "replace.h"
#include <talloc.h>
#include "lib/util/talloc_stack.h"
#include "lib/util/charset/charset.h"
#include "lib/util/unix_match.h"

/*********************************************************
 Recursive routine that is called by unix_wild_match.
*********************************************************/

static bool unix_do_match(const char *regexp, const char *str)
{
	const char *p;

	for( p = regexp; *p && *str; ) {

		switch(*p) {
			case '?':
				str++;
				p++;
				break;

			case '*':

				/*
				 * Look for a character matching
				 * the one after the '*'.
				 */
				p++;
				if(!*p) {
					return true; /* Automatic match */
				}
				while(*str) {

					while(*str && (*p != *str)) {
						str++;
					}

					/*
					 * Patch from weidel@multichart.de.
					 * In the case of the regexp
					 * '*XX*' we want to ensure there are
					 * at least 2 'X' characters in the
					 * string after the '*' for a match to
					 * be made.
					 */

					{
						int matchcount=0;

						/*
						 * Eat all the characters that
						 * match, but count how many
						 * there were.
						 */

						while(*str && (*p == *str)) {
							str++;
							matchcount++;
						}

						/*
						 * Now check that if the regexp
						 * had n identical characters
						 * that matchcount had at least
						 * that many matches.
						 */

						while (*(p+1) && (*(p+1)==*p)) {
							p++;
							matchcount--;
						}

						if ( matchcount <= 0 ) {
							return false;
						}
					}

					/*
					 * We've eaten the match char
					 * after the '*'
					 */
					str--;

					if(unix_do_match(p, str)) {
						return true;
					}

					if(!*str) {
						return false;
					} else {
						str++;
					}
				}
				return false;

			default:
				if(*str != *p) {
					return false;
				}
				str++;
				p++;
				break;
		}
	}

	if(!*p && !*str) {
		return true;
	}

	if (!*p && str[0] == '.' && str[1] == 0) {
		return true;
	}

	if (!*str && *p == '?') {
		while (*p == '?') {
			p++;
		}
		return(!*p);
	}

	if(!*str && (*p == '*' && p[1] == '\0')) {
		return true;
	}

	return false;
}

/*******************************************************************
 Simple case insensitive interface to a UNIX wildcard matcher.
 Returns True if match, False if not.
*******************************************************************/

bool unix_wild_match(const char *pattern, const char *string)
{
	TALLOC_CTX *ctx = talloc_stackframe();
	char *p2;
	char *s2;
	char *p;
	bool ret = false;

	p2 = strlower_talloc(ctx, pattern);
	s2 = strlower_talloc(ctx, string);
	if (!p2 || !s2) {
		TALLOC_FREE(ctx);
		return false;
	}

	/* Remove any *? and ** from the pattern as they are meaningless */
	for(p = p2; *p; p++) {
		while( *p == '*' && (p[1] == '?' ||p[1] == '*')) {
			memmove(&p[1], &p[2], strlen(&p[2])+1);
		}
	}

	if (p2[0] == '*' && p2[1] == '\0') {
		TALLOC_FREE(ctx);
		return true;
	}

	ret = unix_do_match(p2, s2);
	TALLOC_FREE(ctx);
	return ret;
}
