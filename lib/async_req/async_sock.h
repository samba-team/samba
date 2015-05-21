/*
   Unix SMB/CIFS implementation.
   async socket operations
   Copyright (C) Volker Lendecke 2008

     ** NOTE! The following LGPL license applies to the async_sock
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ASYNC_SOCK_H__
#define __ASYNC_SOCK_H__

#include <talloc.h>
#include <tevent.h>
#include "system/network.h"

struct tevent_req *async_connect_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev, int fd,
	const struct sockaddr *address, socklen_t address_len,
	void (*before_connect)(void *private_data),
	void (*after_connect)(void *private_data),
	void *private_data);
int async_connect_recv(struct tevent_req *req, int *perrno);

struct tevent_req *writev_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       struct tevent_queue *queue, int fd,
			       bool err_on_readability,
			       struct iovec *iov, int count);
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

struct tevent_req *wait_for_read_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      int fd);
bool wait_for_read_recv(struct tevent_req *req, int *perr);

#endif
