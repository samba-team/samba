/*
   mkdir -p

   Copyright (C) Amitay Isaacs  2014
   Copyright (C) Martin Schwenke  2014

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#include "replace.h"
#include <sys/stat.h>
#include <libgen.h>
#include "mkdir_p.h"

int mkdir_p(const char *dir, int mode)
{
	char t[PATH_MAX];
	ssize_t len;
	int ret;

	if (strcmp(dir, "/") == 0) {
		return 0;
	}

	if (strcmp(dir, ".") == 0) {
		return 0;
	}

	/* Try to create directory */
	ret = mkdir(dir, mode);
	/* Succeed if that worked or if it already existed */
	if (ret == 0 || errno == EEXIST) {
		return 0;
	}
	/* Fail on anything else except ENOENT */
	if (errno != ENOENT) {
		return ret;
	}

	/* Create ancestors */
	len = strlen(dir);
	ret = snprintf(t, sizeof(t), "%s", dir);
	if (ret != len) {
		errno = ENAMETOOLONG;
		return -1;
	}

	ret = mkdir_p(dirname(t), mode);
	if (ret != 0) {
		return ret;
	}

	/* Create directory */
	ret = mkdir(dir, mode);
	if ((ret == -1) && (errno == EEXIST)) {
		ret = 0;
	}

	return ret;
}
