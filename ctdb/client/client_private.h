/*
   CTDB client code

   Copyright (C) Amitay Isaacs  2015

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __CTDB_CLIENT_PRIVATE_H__
#define __CTDB_CLIENT_PRIVATE_H__

#include "protocol/protocol.h"
#include "client/client.h"

struct ctdb_db_context {
	struct ctdb_db_context *prev, *next;
	uint32_t db_id;
	uint8_t db_flags;
	const char *db_name;
	const char *db_path;
	struct tdb_wrap *ltdb;
};

struct ctdb_client_context {
	struct reqid_context *idr;
	struct srvid_context *srv;
	struct srvid_context *tunnels;
	struct comm_context *comm;
	ctdb_client_callback_func_t callback;
	void *private_data;
	int fd;
	uint32_t pnn;
	struct ctdb_db_context *db;
};

struct ctdb_record_handle {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct ctdb_db_context *db;
	struct ctdb_ltdb_header header;
	TDB_DATA key;
	TDB_DATA data; /* This is returned from tdb_fetch() */
	bool readonly;
};

struct ctdb_transaction_handle {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct ctdb_db_context *db, *db_g_lock;
	struct ctdb_rec_buffer *recbuf;
	struct ctdb_server_id sid;
	const char *lock_name;
	bool readonly;
	bool updated;
};

struct ctdb_tunnel_context {
	struct ctdb_client_context *client;
	uint64_t tunnel_id;
	ctdb_tunnel_callback_func_t callback;
	void *private_data;
};

/* From client_call.c */

void ctdb_client_reply_call(struct ctdb_client_context *client,
			    uint8_t *buf, size_t buflen, uint32_t reqid);

/* From client_db.c */

struct tdb_context *client_db_tdb(struct ctdb_db_context *db);

/* From client_message.c */

void ctdb_client_req_message(struct ctdb_client_context *client,
			     uint8_t *buf, size_t buflen, uint32_t reqid);

/* From client_control.c */

void ctdb_client_reply_control(struct ctdb_client_context *client,
			       uint8_t *buf, size_t buflen, uint32_t reqid);

/* From client_tunnel.c */

void ctdb_client_req_tunnel(struct ctdb_client_context *client,
			    uint8_t *buf, size_t buflen, uint32_t reqid);

#endif /* __CTDB_CLIENT_PRIVATE_H__ */
