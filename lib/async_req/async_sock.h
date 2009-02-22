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

bool async_req_is_errno(struct async_req *req, int *err);
int async_req_simple_recv_errno(struct async_req *req);

ssize_t async_syscall_result_ssize_t(struct async_req *req, int *perrno);
size_t async_syscall_result_size_t(struct async_req *req, int *perrno);
int async_syscall_result_int(struct async_req *req, int *perrno);

struct async_req *async_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     int fd, const void *buffer, size_t length,
			     int flags);
struct async_req *async_recv(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     int fd, void *buffer, size_t length,
			     int flags);

struct tevent_req *async_connect_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      int fd, const struct sockaddr *address,
				      socklen_t address_len);
int async_connect_recv(struct tevent_req *req, int *perrno);

struct tevent_req *writev_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       int fd, struct iovec *iov, int count);
ssize_t writev_recv(struct tevent_req *req, int *perrno);

struct tevent_req *read_packet_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    int fd, size_t initial,
				    ssize_t (*more)(uint8_t *buf,
						    size_t buflen,
						    void *private_data),
				    void *private_data);
ssize_t read_packet_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			 uint8_t **pbuf, int *perrno);

#endif
