/*
 * Unix SMB/CIFS implementation.
 * Samba system utilities
 * Copyright (C) Andrew Tridgell 1992-1998
 * Copyright (C) Jeremy Allison  1998-2005
 * Copyright (C) Timur Bakeyev        2005
 * Copyright (C) Bjoern Jacke    2006-2007
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
#include "lib/sys_rw_data.h"
#include "lib/sys_rw.h"
#include "lib/iov_buf.h"

/****************************************************************************
 Write all data from an iov array
 NB. This can be called with a non-socket fd, don't add dependencies
 on socket calls.
****************************************************************************/

ssize_t write_data_iov(int fd, const struct iovec *orig_iov, int iovcnt)
{
	ssize_t to_send;
	ssize_t thistime;
	size_t sent;
	struct iovec iov_copy[iovcnt];
	struct iovec *iov;

	to_send = iov_buflen(orig_iov, iovcnt);
	if (to_send == -1) {
		errno = EINVAL;
		return -1;
	}

	thistime = sys_writev(fd, orig_iov, iovcnt);
	if ((thistime <= 0) || (thistime == to_send)) {
		return thistime;
	}
	sent = thistime;

	/*
	 * We could not send everything in one call. Make a copy of iov that
	 * we can mess with. We keep a copy of the array start in iov_copy for
	 * the TALLOC_FREE, because we're going to modify iov later on,
	 * discarding elements.
	 */

	memcpy(iov_copy, orig_iov, sizeof(struct iovec) * iovcnt);
	iov = iov_copy;

	while (sent < to_send) {
		/*
		 * We have to discard "thistime" bytes from the beginning
		 * iov array, "thistime" contains the number of bytes sent
		 * via writev last.
		 */
		while (thistime > 0) {
			if (thistime < iov[0].iov_len) {
				char *new_base =
					(char *)iov[0].iov_base + thistime;
				iov[0].iov_base = (void *)new_base;
				iov[0].iov_len -= thistime;
				break;
			}
			thistime -= iov[0].iov_len;
			iov += 1;
			iovcnt -= 1;
		}

		thistime = sys_writev(fd, iov, iovcnt);
		if (thistime <= 0) {
			break;
		}
		sent += thistime;
	}

	return sent;
}

/****************************************************************************
 Write data to a fd.
 NB. This can be called with a non-socket fd, don't add dependencies
 on socket calls.
****************************************************************************/

ssize_t write_data(int fd, const void *buffer, size_t n)
{
	struct iovec iov;

	iov.iov_base = discard_const_p(void, buffer);
	iov.iov_len = n;
	return write_data_iov(fd, &iov, 1);
}
