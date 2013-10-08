/*
   Unix SMB/CIFS implementation.
   Samba3 ctdb connection handling
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

#ifndef _CTDB_CONN_H
#define _CTDB_CONN_H

#include "tevent.h"
#include "librpc/gen_ndr/messaging.h"

struct ctdb_conn;
struct ctdb_reply_control;

struct tevent_req *ctdb_conn_control_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct ctdb_conn *conn,
					  uint32_t vnn, uint32_t opcode,
					  uint64_t srvid, uint32_t flags,
					  uint8_t *data, size_t datalen);
int ctdb_conn_control_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   struct ctdb_reply_control **preply);

struct tevent_req *ctdb_conn_init_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       const char *sock);
int ctdb_conn_init_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			struct ctdb_conn **pconn);

struct tevent_req *ctdb_conn_msg_write_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct ctdb_conn *conn,
					    uint32_t vnn, uint64_t srvid,
					    uint8_t *msg, size_t msg_len);
int ctdb_conn_msg_write_recv(struct tevent_req *req);

struct ctdb_msg_channel;

struct tevent_req *ctdb_msg_channel_init_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	const char *sock, uint64_t srvid);
int ctdb_msg_channel_init_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			       struct ctdb_msg_channel **pchannel);

struct tevent_req *ctdb_msg_read_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct ctdb_msg_channel *channel);
int ctdb_msg_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
		       uint8_t **pmsg, size_t *pmsg_len);

#endif /* _CTDB_CONN_H */
