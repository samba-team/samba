/*
   Unix SMB/CIFS implementation.
   async socket operations
   Copyright (C) Volker Lendecke 2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ASYNC_SOCK_H__
#define __ASYNC_SOCK_H__

#include "includes.h"

ssize_t async_syscall_result_ssize_t(struct async_req **req, int *perrno);
size_t  async_syscall_result_size_t (struct async_req **req, int *perrno);
ssize_t async_syscall_result_int    (struct async_req **req, int *perrno);

struct async_req *async_send(TALLOC_CTX *mem_ctx, struct event_context *ev,
			     int fd, const void *buffer, size_t length,
			     int flags);
struct async_req *async_sendall(TALLOC_CTX *mem_ctx, struct event_context *ev,
				int fd, const void *buffer, size_t length,
				int flags);
struct async_req *async_recv(TALLOC_CTX *mem_ctx, struct event_context *ev,
			     int fd, void *buffer, size_t length,
			     int flags);
struct async_req *async_recvall(TALLOC_CTX *mem_ctx, struct event_context *ev,
				int fd, void *buffer, size_t length,
				int flags);
struct async_req *async_connect(TALLOC_CTX *mem_ctx, struct event_context *ev,
				int fd, const struct sockaddr *address,
				socklen_t address_len);

#endif
