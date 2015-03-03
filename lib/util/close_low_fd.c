/*
 * Unix SMB/CIFS implementation.
 * Samba utility functions
 * Copyright (C) Volker Lendecke 2014
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
#include "system/filesys.h"
#include "close_low_fd.h"

_PUBLIC_ int close_low_fd(int fd)
{
#ifndef VALGRIND
	int ret, dev_null;

	dev_null = open("/dev/null", O_RDWR, 0);

	if ((dev_null == -1) && (errno == ENFILE)) {
		/*
		 * Try to free up an fd
		 */
		ret = close(fd);
		if (ret != 0) {
			return errno;
		}
	}

	dev_null = open("/dev/null", O_RDWR, 0);
	if (dev_null == -1) {
		dev_null = open("/dev/null", O_WRONLY, 0);
	}
	if (dev_null == -1) {
		return errno;
	}

	if (dev_null == fd) {
		/*
		 * This can happen in the ENFILE case above
		 */
		return 0;
	}

	ret = dup2(dev_null, fd);
	if (ret == -1) {
		int err = errno;
		close(dev_null);
		return err;
	}
	close(dev_null);
#endif
	return 0;
}
