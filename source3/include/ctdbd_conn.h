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

#include <tdb.h>

struct ctdbd_connection;
struct messaging_context;
struct messaging_rec;

int ctdbd_messaging_connection(TALLOC_CTX *mem_ctx,
			       const char *sockname, int timeout,
			       struct ctdbd_connection **pconn);

uint32_t ctdbd_vnn(const struct ctdbd_connection *conn);

int ctdbd_register_msg_ctx(struct ctdbd_connection *conn,
			   struct messaging_context *msg_ctx,
			   struct tevent_context *ev);
struct messaging_context *ctdb_conn_msg_ctx(struct ctdbd_connection *conn);

int ctdbd_conn_get_fd(struct ctdbd_connection *conn);

int ctdbd_messaging_send_iov(struct ctdbd_connection *conn,
			     uint32_t dst_vnn, uint64_t dst_srvid,
			     const struct iovec *iov, int iovlen);

bool ctdbd_process_exists(struct ctdbd_connection *conn, uint32_t vnn,
			  pid_t pid);
bool ctdb_processes_exist(struct ctdbd_connection *conn,
			  const struct server_id *pids, int num_pids,
			  bool *results);

char *ctdbd_dbpath(struct ctdbd_connection *conn,
		   TALLOC_CTX *mem_ctx, uint32_t db_id);

int ctdbd_db_attach(struct ctdbd_connection *conn, const char *name,
		    uint32_t *db_id, int tdb_flags);

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
		       int (*cb)(uint32_t src_vnn, uint32_t dst_vnn,
				 uint64_t dst_srvid,
				 const uint8_t *msg, size_t msglen,
				 void *private_data),
		       void *private_data);

int ctdbd_control_local(struct ctdbd_connection *conn, uint32_t opcode,
			uint64_t srvid, uint32_t flags, TDB_DATA data,
			TALLOC_CTX *mem_ctx, TDB_DATA *outdata,
			int *cstatus);
int ctdb_watch_us(struct ctdbd_connection *conn);
int ctdb_unwatch(struct ctdbd_connection *conn);

struct ctdb_req_message_old;

int register_with_ctdbd(struct ctdbd_connection *conn, uint64_t srvid,
			int (*cb)(uint32_t src_vnn, uint32_t dst_vnn,
				  uint64_t dst_srvid,
				  const uint8_t *msg, size_t msglen,
				  void *private_data),
			void *private_data);
int ctdbd_probe(const char *sockname, int timeout);

#endif /* _CTDBD_CONN_H */
