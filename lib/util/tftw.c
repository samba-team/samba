/*
 * Copyright (c) 2008-2018 by Andreas Schneider <asn@samba.org>
 *
 * Adopted from the csync source code
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
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
#include "system/filesys.h"
#include "system/dir.h"
#include "lib/util/debug.h"

#include "tftw.h"


int tftw(TALLOC_CTX *mem_ctx, const char *fpath, tftw_walker_fn fn, size_t depth, void *userdata)
{
	char *filename = NULL;
	char *d_name = NULL;
	DIR *dh = NULL;
	struct dirent *dirent = NULL;
	struct stat sb = {0};
	int rc = 0;

	if (fpath[0] == '\0') {
		errno = ENOENT;
		goto error;
	}

	if ((dh = opendir(fpath)) == NULL) {
		/* permission denied */
		if (errno == EACCES) {
			return 0;
		} else {
			DBG_ERR("opendir failed for: [%s]\n", strerror(errno));
			goto error;
		}
	}

	while ((dirent = readdir(dh))) {
		int flag;

		d_name = dirent->d_name;
		if (d_name == NULL) {
			goto error;
		}

		/* skip "." and ".." */
		if (d_name[0] == '.' && (d_name[1] == '\0'
					|| (d_name[1] == '.' && d_name[2] == '\0'))) {
			dirent = NULL;
			continue;
		}

		filename = talloc_asprintf(mem_ctx, "%s/%s", fpath, d_name);
		if (filename == NULL) {
			goto error;
		}

		rc = lstat(filename, &sb);
		if (rc < 0) {
			dirent = NULL;
			goto error;
		}

		switch (sb.st_mode & S_IFMT) {
			case S_IFLNK:
				flag = TFTW_FLAG_SLINK;
				break;
			case S_IFDIR:
				flag = TFTW_FLAG_DIR;
				break;
			case S_IFBLK:
			case S_IFCHR:
			case S_IFSOCK:
			case S_IFIFO:
				flag = TFTW_FLAG_SPEC;
				break;
			default:
				flag = TFTW_FLAG_FILE;
				break;
		}

		DBG_INFO("walk: [%s]\n", filename);

		/* Call walker function for each file */
		rc = fn(mem_ctx, filename, &sb, flag, userdata);

		if (rc < 0) {
			DBG_ERR("provided callback fn() failed: [%s]\n",
				strerror(errno));
			closedir(dh);
			goto done;
		}

		if (flag == TFTW_FLAG_DIR && depth) {
			rc = tftw(mem_ctx, filename, fn, depth - 1, userdata);
			if (rc < 0) {
				closedir(dh);
				goto done;
			}
		}
		TALLOC_FREE(filename);
		dirent = NULL;
	}
	closedir(dh);

done:
	TALLOC_FREE(filename);
	return rc;
error:
	if (dh != NULL) {
		closedir(dh);
	}
	TALLOC_FREE(filename);
	return -1;
}
