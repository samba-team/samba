/*
   Unix SMB/CIFS implementation.
   Copyright (C) 2014 Björn Baumbach
   Copyright (C) 2014 Stefan Metzmacher

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

#include "includes.h"
#include "messages.h"
#include "ctdb_conn.h"
#include "ctdbd_conn.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_ctdb.h"
#include "torture/proto.h"

NTSTATUS ctdbd_probe(void)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS ctdbd_messaging_send_blob(struct ctdbd_connection *conn,
				   uint32_t dst_vnn, uint64_t dst_srvid,
				   const uint8_t *buf, size_t buflen)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS register_with_ctdbd(struct ctdbd_connection *conn, uint64_t srvid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS ctdbd_register_reconfigure(struct ctdbd_connection *conn)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS ctdbd_register_ips(struct ctdbd_connection *conn,
			    const struct sockaddr_storage *_server,
			    const struct sockaddr_storage *_client,
			    bool (*release_ip_handler)(const char *ip_addr,
						       void *private_data),
			    void *private_data)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

const char *lp_ctdbd_socket(void)
{
	return "";
}

bool ctdb_serverids_exist_supported(struct ctdbd_connection *conn)
{
	return false;
}

bool ctdb_serverids_exist(struct ctdbd_connection *conn,
			  const struct server_id *pids, unsigned num_pids,
			  bool *results)
{
	return false;
}

bool ctdb_processes_exist(struct ctdbd_connection *conn,
			  const struct server_id *pids, int num_pids,
			  bool *results)
{
	return false;
}

struct dummy_state {
	uint8_t dummy;
};

static struct tevent_req *dummy_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev)
{
	struct tevent_req *req;
	struct dummy_state *state;
	req = tevent_req_create(mem_ctx, &state, struct dummy_state);
	if (req == NULL) {
		return NULL;
	}
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

struct tevent_req *ctdb_conn_init_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       const char *sock)
{
	return dummy_send(mem_ctx, ev);
}

int ctdb_conn_init_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			struct ctdb_conn **pconn)
{
	return ENOSYS;
}

struct tevent_req *ctdb_conn_msg_write_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct ctdb_conn *conn,
					    uint32_t vnn, uint64_t srvid,
					    uint8_t *msg, size_t msg_len)
{
	return dummy_send(mem_ctx, ev);
}

int ctdb_conn_msg_write_recv(struct tevent_req *req)
{
	return ENOSYS;
}

struct tevent_req *ctdb_msg_channel_init_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	const char *sock, uint64_t srvid)
{
	return dummy_send(mem_ctx, ev);
}

int ctdb_msg_channel_init_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			       struct ctdb_msg_channel **pchannel)
{
	return ENOSYS;
}

struct tevent_req *ctdb_msg_read_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct ctdb_msg_channel *channel)
{
	return dummy_send(mem_ctx, ev);
}

int ctdb_msg_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
		       uint8_t **pmsg, size_t *pmsg_len)
{
	return ENOSYS;
}

struct db_context *db_open_ctdb(TALLOC_CTX *mem_ctx,
				const char *name,
				int hash_size, int tdb_flags,
				int open_flags, mode_t mode,
				enum dbwrap_lock_order lock_order,
				uint64_t dbwrap_flags)
{
	errno = ENOSYS;
	return NULL;
}

NTSTATUS messaging_ctdbd_init(struct messaging_context *msg_ctx,
			      TALLOC_CTX *mem_ctx,
			      struct messaging_backend **presult)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

struct ctdbd_connection *messaging_ctdbd_connection(void)
{
	return NULL;
}

bool run_ctdb_conn(int dummy)
{
	return true;
}
