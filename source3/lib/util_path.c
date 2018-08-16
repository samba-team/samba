/*
 * Unix SMB/CIFS implementation.
 * Samba utility functions
 * Copyright (C) Andrew Tridgell 1992-1998
 * Copyright (C) Jeremy Allison 2001-2007
 * Copyright (C) Simo Sorce 2001
 * Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
 * Copyright (C) James Peach 2006
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include <talloc.h>
#include "lib/util/samba_util.h"
#include "lib/util_path.h"

struct share_params;
#include "source3/param/param_proto.h"

/**
 * @brief Returns an absolute path to a file concatenating the provided
 * @a rootpath and @a basename
 *
 * @param name Filename, relative to @a rootpath
 *
 * @retval Pointer to a string containing the full path.
 **/

static char *xx_path(TALLOC_CTX *mem_ctx,
		     const char *name,
		     const char *rootpath)
{
	char *fname = NULL;

	fname = talloc_strdup(mem_ctx, rootpath);
	if (!fname) {
		return NULL;
	}
	trim_string(fname,"","/");

	if (!directory_create_or_exist(fname, 0755)) {
		return NULL;
	}

	return talloc_asprintf_append(fname, "/%s", name);
}

/**
 * @brief Returns an absolute path to a file in the Samba lock directory.
 *
 * @param name File to find, relative to LOCKDIR.
 *
 * @retval Pointer to a talloc'ed string containing the full path.
 **/

char *lock_path(TALLOC_CTX *mem_ctx, const char *name)
{
	return xx_path(mem_ctx, name, lp_lock_directory());
}

/**
 * @brief Returns an absolute path to a file in the Samba state directory.
 *
 * @param name File to find, relative to STATEDIR.
 *
 * @retval Pointer to a talloc'ed string containing the full path.
 **/

char *state_path(TALLOC_CTX *mem_ctx, const char *name)
{
	return xx_path(mem_ctx, name, lp_state_directory());
}

/**
 * @brief Returns an absolute path to a file in the Samba cache directory.
 *
 * @param name File to find, relative to CACHEDIR.
 *
 * @retval Pointer to a talloc'ed string containing the full path.
 **/

char *cache_path(TALLOC_CTX *mem_ctx, const char *name)
{
	return xx_path(mem_ctx, name, lp_cache_directory());
}

/**
 * @brief Removes any invalid path components in an absolute POSIX path.
 *
 * @param ctx Talloc context to return string.
 *
 * @param abs_path Absolute path string to process.
 *
 * @retval Pointer to a talloc'ed string containing the absolute full path.
 **/

char *canonicalize_absolute_path(TALLOC_CTX *ctx, const char *abs_path)
{
	char *destname;
	char *d;
	const char *s = abs_path;
	bool start_of_name_component = true;

	/* Allocate for strlen + '\0' + possible leading '/' */
	destname = (char *)talloc_size(ctx, strlen(abs_path) + 2);
	if (destname == NULL) {
		return NULL;
        }
	d = destname;

	*d++ = '/'; /* Always start with root. */

	while (*s) {
		if (*s == '/') {
			/* Eat multiple '/' */
			while (*s == '/') {
				s++;
			}
			if ((d > destname + 1) && (*s != '\0')) {
				*d++ = '/';
			}
			start_of_name_component = true;
			continue;
		}

		if (start_of_name_component) {
			if ((s[0] == '.') && (s[1] == '.') &&
					(s[2] == '/' || s[2] == '\0')) {
				/* Uh oh - "/../" or "/..\0" ! */

				/* Go past the .. leaving us on the / or '\0' */
				s += 2;

				/* If  we just added a '/' - delete it */
				if ((d > destname) && (*(d-1) == '/')) {
					*(d-1) = '\0';
					d--;
				}

				/*
				 * Are we at the start ?
				 * Can't go back further if so.
				 */
				if (d <= destname) {
					*d++ = '/'; /* Can't delete root */
					continue;
				}
				/* Go back one level... */
				/*
				 * Decrement d first as d points to
				 * the *next* char to write into.
				 */
				for (d--; d > destname; d--) {
					if (*d == '/') {
						break;
					}
				}

				/*
				 * Are we at the start ?
				 * Can't go back further if so.
				 */
				if (d <= destname) {
					*d++ = '/'; /* Can't delete root */
					continue;
				}

				/*
				 * We're still at the start of a name
				 * component, just the previous one.
				 */
				continue;
			} else if ((s[0] == '.') &&
					((s[1] == '\0') || s[1] == '/')) {
				/*
				 * Component of pathname can't be "." only.
				 * Skip the '.' .
				 */
				if (s[1] == '/') {
					s += 2;
				} else {
					s++;
				}
				continue;
			}
		}

		if (!(*s & 0x80)) {
			*d++ = *s++;
		} else {
			size_t siz;
			/* Get the size of the next MB character. */
			next_codepoint(s,&siz);
			switch(siz) {
				case 5:
					*d++ = *s++;

					FALL_THROUGH;
				case 4:
					*d++ = *s++;

					FALL_THROUGH;
				case 3:
					*d++ = *s++;

					FALL_THROUGH;
				case 2:
					*d++ = *s++;

					FALL_THROUGH;
				case 1:
					*d++ = *s++;
					break;
				default:
					break;
			}
		}
		start_of_name_component = false;
	}
	*d = '\0';

	/* And must not end in '/' */
	if (d > destname + 1 && (*(d-1) == '/')) {
		*(d-1) = '\0';
	}

	return destname;
}
