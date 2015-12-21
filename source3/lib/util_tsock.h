/*
   Unix SMB/CIFS implementation.
   Utilities around tsocket
   Copyright (C) Volker Lendecke 2009

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

#ifndef __UTIL_TSOCK_H__
#define __UTIL_TSOCK_H__

#include "replace.h"
#include <tevent.h>

struct tstream_context;
struct tevent_req *tstream_read_packet_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct tstream_context *stream,
					    size_t initial,
					    ssize_t (*more)(uint8_t *buf,
							    size_t buflen,
							    void *private_data),
					    void *private_data);
ssize_t tstream_read_packet_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				 uint8_t **pbuf, int *perrno);

#endif
