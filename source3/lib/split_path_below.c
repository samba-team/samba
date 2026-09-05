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

#include "replace.h"
#include "util/charset/charset.h"
#include "source3/lib/split_path_below.h"

/*
 * Get a pointer to and the length of a contiguous run of bytes
 * starting at logical offset "off" into the path that would be built
 * by "dir/name".
 */
static bool split_path_run(const struct split_path *path,
			   size_t off,
			   const char **pbuf,
			   size_t *plen)
{
	if (off < path->dirlen) {
		*pbuf = path->dir + off;
		*plen = path->dirlen - off;
		return true;
	}
	off -= path->dirlen;

	if (off == 0) {
		static const char slash[] = "/";
		*pbuf = slash;
		*plen = 1;
		return true;
	}
	off -= 1;

	if (off >= path->namelen) {
		return false;
	}

	*pbuf = path->name + off;
	*plen = path->namelen - off;
	return true;
}

/*
 * Compare the first "n" bytes of two split_path paths for equality,
 * chunk by chunk, never across a dir/name boundary.
 */
static bool split_path_prefix_equal(const struct split_path *a,
				    const struct split_path *b,
				    size_t n,
				    bool case_sensitive)
{
	size_t off = 0;

	while (off < n) {
		const char *pa = NULL, *pb = NULL;
		size_t len_a, len_b, chunk;
		bool ok, equal;

		ok = split_path_run(a, off, &pa, &len_a);
		if (!ok) {
			return false;
		}
		ok = split_path_run(b, off, &pb, &len_b);
		if (!ok) {
			return false;
		}

		chunk = MIN(len_a, len_b);

		/*
		 * Only compare up to the length given, which is
		 * supposed to be the overall length of "a".
		 */
		chunk = MIN(chunk, n - off);

		if (case_sensitive) {
			equal = (memcmp(pa, pb, chunk) == 0);
		} else {
			equal = strnequal_bytes(pa, pb, chunk);
		}

		if (!equal) {
			return false;
		}

		off += chunk;
	}

	return true;
}

bool split_path_init(const char *dir,
		     const char *name,
		     struct split_path *path)
{
	size_t dirlen = strlen(dir);
	size_t namelen = strlen(name);
	size_t len;

	len = dirlen + 1;
	if (len < 1) {
		return false;
	}
	len += namelen;
	if (len < namelen) {
		return false;
	}

	*path = (struct split_path){
		.dir = dir,
		.name = name,
		.dirlen = dirlen,
		.namelen = namelen,
		.len = len,
	};

	return true;
}

bool split_path_below(const struct split_path *base,
		      const char *sub_dir,
		      const char *sub_name,
		      bool case_sensitive)
{
	struct split_path sub_path = {};
	const char *psep = NULL;
	size_t seplen;
	bool ok;

	ok = split_path_init(sub_dir, sub_name, &sub_path);
	if (!ok) {
		return false;
	}

	/*
	 * Check the separator right after where "base" would end
	 * first: it's a single byte, much cheaper than comparing the
	 * whole prefix only to find out afterwards that sub_path
	 * doesn't even end in a '/'.
	 *
	 * split_path_run() fails if base->len runs beyond sub_path,
	 * so this implicitly also checks that sub_path is longer than
	 * the base directory.
	 */
	ok = split_path_run(&sub_path, base->len, &psep, &seplen);
	if (!ok) {
		return false;
	}
	if (psep[0] != '/') {
		return false;
	}

	ok = split_path_prefix_equal(
		base, &sub_path, base->len, case_sensitive);
	return ok;
}
