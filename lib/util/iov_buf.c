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
#include <talloc.h>

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

		if (tmp < needed) {
			/* wrap */
			return -1;
		}
		needed = tmp;

		if ((p != NULL) && needed <= buflen && thislen > 0) {
			memcpy(p, iov[i].iov_base, thislen);
			p += thislen;
		}
	}

	return needed;
}

bool iov_advance(struct iovec **iov, int *iovcnt, size_t n)
{
	struct iovec *v = *iov;
	int cnt = *iovcnt;

	while (n > 0) {
		if (cnt == 0) {
			return false;
		}
		if (n < v->iov_len) {
			v->iov_base = (char *)v->iov_base + n;
			v->iov_len -= n;
			break;
		}
		n -= v->iov_len;
		v += 1;
		cnt -= 1;
	}

	/*
	 * Skip 0-length iovec's
	 *
	 * There might be empty buffers at the end of iov. Next time we do a
	 * readv/writev based on this iov would give 0 transferred bytes, also
	 * known as EPIPE. So we need to be careful discarding them.
	 */

	while ((cnt > 0) && (v->iov_len == 0)) {
		v += 1;
		cnt -= 1;
	}

	*iov = v;
	*iovcnt = cnt;
	return true;
}

uint8_t *iov_concat(TALLOC_CTX *mem_ctx, const struct iovec *iov, int count)
{
	ssize_t buflen;
	uint8_t *buf;

	buflen = iov_buflen(iov, count);
	if (buflen == -1) {
		return NULL;
	}

	buf = talloc_array(mem_ctx, uint8_t, buflen);
	if (buf == NULL) {
		return NULL;
	}

	iov_buf(iov, count, buf, buflen);

	return buf;
}
