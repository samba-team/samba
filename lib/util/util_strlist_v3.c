/*
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Jelmer Vernooij 2005

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
#include "system/locale.h"
#include "lib/util/tsort.h"

#undef strcasecmp

/**
 * @file
 * @brief String list manipulation v3
 */

/**
 * Needed for making an "unconst" list "const"
 */
_PUBLIC_ const char **const_str_list(char **list)
{
	return discard_const_p(const char *, list);
}

/**
 * str_list_make, v3 version. The v4 version does not
 * look at quoted strings with embedded blanks, so
 * do NOT merge this function please!
 */
#define S_LIST_ABS 16 /* List Allocation Block Size */

char **str_list_make_v3(TALLOC_CTX *mem_ctx, const char *string,
	const char *sep)
{
	char **list;
	const char *str;
	char *s, *tok;
	int num, lsize;

	if (!string || !*string)
		return NULL;

	list = talloc_array(mem_ctx, char *, S_LIST_ABS+1);
	if (list == NULL) {
		return NULL;
	}
	lsize = S_LIST_ABS;

	s = talloc_strdup(list, string);
	if (s == NULL) {
		DEBUG(0,("str_list_make: Unable to allocate memory"));
		TALLOC_FREE(list);
		return NULL;
	}

	/*
	 * DON'T REPLACE THIS BY "LIST_SEP". The common version of
	 * LIST_SEP does not contain the ;, which used to be accepted
	 * by Samba 4.0 before param merges. It would be the far
	 * better solution to split the _v3 version again to source3/
	 * where it belongs, see the _v3 in its name.
	 *
	 * Unfortunately it is referenced in /lib/param/loadparm.c,
	 * which depends on the version that the AD-DC mandates,
	 * namely without the ; as part of the list separator. I am
	 * missing the waf fu to properly work around the wrong
	 * include paths here for this defect.
	 */
	if (sep == NULL) {
		sep = " \t,;\n\r";
	}

	num = 0;
	str = s;

	while (next_token_talloc(list, &str, &tok, sep)) {

		if (num == lsize) {
			char **tmp;

			lsize += S_LIST_ABS;

			tmp = talloc_realloc(mem_ctx, list, char *,
						   lsize + 1);
			if (tmp == NULL) {
				DEBUG(0,("str_list_make: "
					"Unable to allocate memory"));
				TALLOC_FREE(list);
				return NULL;
			}

			list = tmp;

			memset (&list[num], 0,
				((sizeof(char*)) * (S_LIST_ABS +1)));
		}

		list[num] = tok;
		num += 1;
	}

	list[num] = NULL;

	TALLOC_FREE(s);
	return list;
}

const char **str_list_make_v3_const(TALLOC_CTX *mem_ctx,
				    const char *string,
				    const char *sep)
{
	return const_str_list(str_list_make_v3(mem_ctx, string, sep));
}
