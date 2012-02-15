/*
   Unix SMB/CIFS implementation.
   Samba3 message streams
   Copyright (C) Volker Lendecke 2012

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

#ifndef _MSG_STREAM_H_
#define _MSG_STREAM_H_

#include <talloc.h>
#include <tevent.h>
#include "messages.h"
#include "librpc/gen_ndr/messaging.h"

struct msg_channel;

struct tevent_req *msg_channel_init_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct messaging_context *msg,
					 uint32_t msgtype);
int msg_channel_init_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			  struct msg_channel **pchannel);
int msg_channel_init(TALLOC_CTX *mem_ctx, struct messaging_context *msg,
		     uint32_t msgtype, struct msg_channel **pchannel);

struct tevent_req *msg_read_send(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 struct msg_channel *channel);
int msg_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
		  struct messaging_rec **prec);

#endif
