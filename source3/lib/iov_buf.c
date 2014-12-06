/*
 * Unix SMB/CIFS implementation.
 * Samba system utilities
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
#include "iov_buf.h"

ssize_t iov_buflen(const struct iovec *iov, int iovcnt)
{
	return iov_buf(iov, iovcnt, NULL, 0);
}

ssize_t iov_buf(const struct iovec *iov, int iovcnt,
		uint8_t *buf, size_t buflen)
{
	size_t needed = 0;
	uint8_t *p = buf;
	int i;

	for (i=0; i<iovcnt; i++) {
		size_t thislen = iov[i].iov_len;
		size_t tmp;

		tmp = needed + thislen;

		if ((tmp < needed) || (tmp < thislen)) {
			/* overflow */
			return -1;
		}
		needed = tmp;

		if (needed <= buflen) {
			memcpy(p, iov[i].iov_base, thislen);
			p += thislen;
		}
	}

	return needed;
}
