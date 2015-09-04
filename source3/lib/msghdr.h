/*
 * Unix SMB/CIFS implementation.
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

#ifndef __LIB_MSGHDR_H__
#define __LIB_MSGHDR_H__

#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>
#include <sys/socket.h>

ssize_t msghdr_prep_fds(struct msghdr *msg, uint8_t *buf, size_t bufsize,
			const int *fds, size_t num_fds);

struct msghdr_buf;

ssize_t msghdr_copy(struct msghdr_buf *msg, size_t msgsize,
		    const void *addr, socklen_t addrlen,
		    const struct iovec *iov, int iovcnt,
		    const int *fds, size_t num_fds);
struct msghdr *msghdr_buf_msghdr(struct msghdr_buf *msg);

size_t msghdr_prep_recv_fds(struct msghdr *msg, uint8_t *buf, size_t bufsize,
			    size_t num_fds);
size_t msghdr_extract_fds(struct msghdr *msg, int *fds, size_t num_fds);

#endif
