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

#ifndef __LIB_IOV_BUF_H__
#define __LIB_IOV_BUF_H__

#include "replace.h"
#include <talloc.h>

ssize_t iov_buflen(const struct iovec *iov, int iovlen);
ssize_t iov_buf(const struct iovec *iov, int iovcnt,
		uint8_t *buf, size_t buflen);
bool iov_advance(struct iovec **iov, int *iovcnt, size_t n);
uint8_t *iov_concat(TALLOC_CTX *mem_ctx, const struct iovec *iov, int count);

#endif
