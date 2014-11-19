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
	size_t buflen = 0;
	int i;

	for (i=0; i<iovcnt; i++) {
		size_t thislen = iov[i].iov_len;
		size_t tmp = buflen + thislen;

		if ((tmp < buflen) || (tmp < thislen)) {
			/* overflow */
			return -1;
		}
		buflen = tmp;
	}
	return buflen;
}

uint8_t *iov_buf(TALLOC_CTX *mem_ctx, const struct iovec *iov, int iovcnt)
{
	int i;
	ssize_t buflen;
	uint8_t *buf, *p;

	buflen = iov_buflen(iov, iovcnt);
	if (buflen == -1) {
		return NULL;
	}
	buf = talloc_array(mem_ctx, uint8_t, buflen);
	if (buf == NULL) {
		return NULL;
	}

	p = buf;
	for (i=0; i<iovcnt; i++) {
		size_t len = iov[i].iov_len;

		memcpy(p, iov[i].iov_base, len);
		p += len;
	}
	return buf;
}
