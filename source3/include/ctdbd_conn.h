/* 
   Unix SMB/CIFS implementation.
   Samba3 ctdb connection handling
   Copyright (C) Volker Lendecke 2007

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

#ifndef _CTDBD_CONN_H
#define _CTDBD_CONN_H

#include "replace.h"
#include "system/filesys.h"
#include "system/network.h"
#include "lib/dbwrap/dbwrap.h"
#include <tdb.h>
#include <tevent.h>

struct ctdbd_connection;
struct messaging_context;
struct messaging_rec;

int ctdbd_init_connection(TALLOC_CTX *mem_ctx,
			  const char *sockname, int timeout,
			  struct ctdbd_connection **pconn);
int ctdbd_init_async_connection(
	TALLOC_CTX *mem_ctx,
	const char *sockname,
	int timeout,
	struct ctdbd_connection **pconn);
int ctdbd_reinit_connection(TALLOC_CTX *mem_ctx,
			    const char *sockname, int timeout,
			    struct ctdbd_connection *conn);

uint32_t ctdbd_vnn(const struct ctdbd_connection *conn);

int ctdbd_conn_get_fd(struct ctdbd_connection *conn);
void ctdbd_socket_readable(struct tevent_context *ev,
			   struct ctdbd_connection *conn);

int ctdbd_messaging_send_iov(struct ctdbd_connection *conn,
			     uint32_t dst_vnn, uint64_t dst_srvid,
			     const struct iovec *iov, int iovlen);

bool ctdbd_process_exists(struct ctdbd_connection *conn, uint32_t vnn,
			  pid_t pid, uint64_t unique_id);

char *ctdbd_dbpath(struct ctdbd_connection *conn,
		   TALLOC_CTX *mem_ctx, uint32_t db_id);

int ctdbd_db_attach(struct ctdbd_connection *conn, const char *name,
		    uint32_t *db_id, bool persistent);

int ctdbd_migrate(struct ctdbd_connection *conn, uint32_t db_id, TDB_DATA key);

int ctdbd_parse(struct ctdbd_connection *conn, uint32_t db_id,
		TDB_DATA key, bool local_copy,
		void (*parser)(TDB_DATA key, TDB_DATA data,
			       void *private_data),
		void *private_data);

int ctdbd_traverse(struct ctdbd_connection *master, uint32_t db_id,
		   void (*fn)(TDB_DATA key, TDB_DATA data,
			      void *private_data),
		   void *private_data);

int ctdbd_register_ips(struct ctdbd_connection *conn,
		       const struct sockaddr_storage *server,
		       const struct sockaddr_storage *client,
		       int (*cb)(struct tevent_context *ev,
				 uint32_t src_vnn, uint32_t dst_vnn,
				 uint64_t dst_srvid,
				 const uint8_t *msg, size_t msglen,
				 void *private_data),
		       void *private_data);

struct ctdb_public_ip_list_old;
int ctdbd_control_get_public_ips(struct ctdbd_connection *conn,
				 uint32_t flags,
				 TALLOC_CTX *mem_ctx,
				 struct ctdb_public_ip_list_old **_ips);
bool ctdbd_find_in_public_ips(const struct ctdb_public_ip_list_old *ips,
			      const struct sockaddr_storage *ip);

int ctdbd_control_local(struct ctdbd_connection *conn, uint32_t opcode,
			uint64_t srvid, uint32_t flags, TDB_DATA data,
			TALLOC_CTX *mem_ctx, TDB_DATA *outdata,
			int32_t *cstatus);
int ctdb_watch_us(struct ctdbd_connection *conn);
int ctdb_unwatch(struct ctdbd_connection *conn);

struct ctdb_req_message_old;

int register_with_ctdbd(struct ctdbd_connection *conn, uint64_t srvid,
			int (*cb)(struct tevent_context *ev,
				  uint32_t src_vnn, uint32_t dst_vnn,
				  uint64_t dst_srvid,
				  const uint8_t *msg, size_t msglen,
				  void *private_data),
			void *private_data);
int ctdbd_probe(const char *sockname, int timeout);

struct ctdb_req_header;
void ctdbd_prep_hdr_next_reqid(
	struct ctdbd_connection *conn, struct ctdb_req_header *hdr);

/*
 * Async ctdb_request. iov[0] must start with an initialized
 * struct ctdb_req_header
 */
struct tevent_req *ctdbd_req_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct ctdbd_connection *conn,
	struct iovec *iov,
	size_t num_iov);
int ctdbd_req_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct ctdb_req_header **reply);

struct tevent_req *ctdbd_parse_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdbd_connection *conn,
				    uint32_t db_id,
				    TDB_DATA key,
				    bool local_copy,
				    void (*parser)(TDB_DATA key,
						   TDB_DATA data,
						   void *private_data),
				    void *private_data,
				    enum dbwrap_req_state *req_state);
int ctdbd_parse_recv(struct tevent_req *req);

#endif /* _CTDBD_CONN_H */
