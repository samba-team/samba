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
#include "ctdbd_conn.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_ctdb.h"
#include "torture/proto.h"

NTSTATUS ctdbd_probe(void)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS ctdbd_messaging_send_iov(struct ctdbd_connection *conn,
				  uint32_t dst_vnn, uint64_t dst_srvid,
				  const struct iovec *iov, int iovlen)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS register_with_ctdbd(struct ctdbd_connection *conn, uint64_t srvid,
			     int (*cb)(uint32_t src_vnn, uint32_t dst_vnn,
				       uint64_t dst_srvid,
				       const uint8_t *msg, size_t msglen,
				       void *private_data),
			     void *private_data)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS ctdbd_register_ips(struct ctdbd_connection *conn,
			    const struct sockaddr_storage *_server,
			    const struct sockaddr_storage *_client,
			    int (*cb)(uint32_t src_vnn, uint32_t dst_vnn,
				      uint64_t dst_srvid,
				      const uint8_t *msg, size_t msglen,
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
