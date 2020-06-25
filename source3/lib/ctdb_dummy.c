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
#include "lib/messages_ctdb.h"
#include "lib/messages_ctdb_ref.h"
#include "ctdbd_conn.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_ctdb.h"
#include "torture/proto.h"

int ctdbd_probe(const char *sockname, int timeout)
{
	return ENOSYS;
}

int ctdbd_messaging_send_iov(struct ctdbd_connection *conn,
			     uint32_t dst_vnn, uint64_t dst_srvid,
			     const struct iovec *iov, int iovlen)
{
	return ENOSYS;
}

int register_with_ctdbd(struct ctdbd_connection *conn, uint64_t srvid,
			int (*cb)(struct tevent_context *ev,
				  uint32_t src_vnn, uint32_t dst_vnn,
				  uint64_t dst_srvid,
				  const uint8_t *msg, size_t msglen,
				  void *private_data),
			void *private_data)
{
	return ENOSYS;
}

int ctdbd_register_ips(struct ctdbd_connection *conn,
		       const struct sockaddr_storage *_server,
		       const struct sockaddr_storage *_client,
		       int (*cb)(struct tevent_context *ev,
				 uint32_t src_vnn, uint32_t dst_vnn,
				 uint64_t dst_srvid,
				 const uint8_t *msg, size_t msglen,
				 void *private_data),
		       void *private_data)
{
	return ENOSYS;
}

int ctdbd_control_get_public_ips(struct ctdbd_connection *conn,
				 uint32_t flags,
				 TALLOC_CTX *mem_ctx,
				 struct ctdb_public_ip_list_old **_ips)
{
	*_ips = NULL;
	return ENOSYS;
}

bool ctdbd_find_in_public_ips(const struct ctdb_public_ip_list_old *ips,
			      const struct sockaddr_storage *ip)
{
	return false;
}

bool ctdbd_process_exists(struct ctdbd_connection *conn, uint32_t vnn,
			  pid_t pid, uint64_t unique_id)
{
	return false;
}

struct db_context *db_open_ctdb(TALLOC_CTX *mem_ctx,
				struct messaging_context *msg_ctx,
				const char *name,
				int hash_size, int tdb_flags,
				int open_flags, mode_t mode,
				enum dbwrap_lock_order lock_order,
				uint64_t dbwrap_flags)
{
	errno = ENOSYS;
	return NULL;
}

int messaging_ctdb_send(uint32_t dst_vnn, uint64_t dst_srvid,
			const struct iovec *iov, int iovlen)
{
	return ENOSYS;
}

void *messaging_ctdb_ref(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			 const char *sockname, int timeout, uint64_t unique_id,
			 void (*recv_cb)(struct tevent_context *ev,
					 const uint8_t *msg, size_t msg_len,
					 int *fds, size_t num_fds,
					 void *private_data),
			 void *private_data,
			 int *err)
{
	return NULL;
}

struct messaging_ctdb_fde *messaging_ctdb_register_tevent_context(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev)
{
	return NULL;
}

struct ctdbd_connection *messaging_ctdb_connection(void)
{
	return NULL;
}

int ctdb_async_ctx_reinit(TALLOC_CTX *mem_ctx, struct tevent_context *ev)
{
	return ENOSYS;
}
