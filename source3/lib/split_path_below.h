/*
 * Unix SMB/CIFS implementation.
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

#ifndef _SOURCE3_LIB_SPLIT_PATH_BELOW_H_
#define _SOURCE3_LIB_SPLIT_PATH_BELOW_H_

#include "replace.h"

/*
 * A "dir/name" path, given as two separate parts joined by an
 * implicit '/', with "len" (dirlen + 1 + namelen) precomputed.
 */
struct split_path {
	const char *dir;
	const char *name;
	size_t dirlen;
	size_t namelen;
	size_t len;
};

bool split_path_init(const char *dir,
		     const char *name,
		     struct split_path *path);

/*
 * Returns true if the path "sub_dir/sub_name" starts with
 * "base->dir/base->name/". case_sensitive selects memcmp() or a
 * case-insensitive comparison with strnequal_bytes().
 */
bool split_path_below(const struct split_path *base,
		      const char *sub_dir,
		      const char *sub_name,
		      bool case_sensitive);

#endif
