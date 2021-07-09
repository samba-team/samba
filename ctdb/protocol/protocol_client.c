/*
   CTDB protocol marshalling

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

#include "replace.h"
#include "system/network.h"

#include <talloc.h>
#include <tdb.h>

#include "protocol.h"
#include "protocol_api.h"
#include "protocol_private.h"

/*
void ctdb_req_call_fill(struct ctdb_req_call *c,
			uint32_t db_id, uint32_t flags,
			uint32_t call_id, TDB_DATA key)
{
	request->flags = flags;
	c->db_id = db_id;
	c->call_id = call_id;
	c->key = key;
	c->calldata = tdb_null;
}
*/

static int ctdb_reply_control_generic(struct ctdb_reply_control *reply,
				      uint32_t opcode)
{
	if (reply->rdata.opcode != opcode) {
		return EPROTO;
	}

	return reply->status;
}

/* CTDB_CONTROL_PROCESS_EXISTS */

void ctdb_req_control_process_exists(struct ctdb_req_control *request,
				     pid_t pid)
{
	request->opcode = CTDB_CONTROL_PROCESS_EXISTS;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_PROCESS_EXISTS;
	request->rdata.data.pid = pid;

}

int ctdb_reply_control_process_exists(struct ctdb_reply_control *reply,
				      int *status)
{
	if (reply->rdata.opcode != CTDB_CONTROL_PROCESS_EXISTS) {
		return EPROTO;
	}

	*status = reply->status;
	reply->status = 0;

	return reply->status;
}

/* CTDB_CONTROL_STATISTICS */

void ctdb_req_control_statistics(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_STATISTICS;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_STATISTICS;
}

int ctdb_reply_control_statistics(struct ctdb_reply_control *reply,
				  TALLOC_CTX *mem_ctx,
				  struct ctdb_statistics **stats)
{
	if (reply->rdata.opcode != CTDB_CONTROL_STATISTICS) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*stats = talloc_steal(mem_ctx, reply->rdata.data.stats);
	}
	return reply->status;
}

/* CTDB_CONTROL_PING */

void ctdb_req_control_ping(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_PING;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_PING;
}

int ctdb_reply_control_ping(struct ctdb_reply_control *reply,
			    int *num_clients)
{
	if (reply->rdata.opcode != CTDB_CONTROL_PING) {
		return EPROTO;
	}

	if (reply->status >= 0) {
		*num_clients = reply->status;
		reply->status = 0;
	}
	return reply->status;
}

/* CTDB_CONTROL_GETDBPATH */

void ctdb_req_control_getdbpath(struct ctdb_req_control *request,
				uint32_t db_id)
{
	request->opcode = CTDB_CONTROL_GETDBPATH;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GETDBPATH;
	request->rdata.data.db_id = db_id;
}

int ctdb_reply_control_getdbpath(struct ctdb_reply_control *reply,
				 TALLOC_CTX *mem_ctx, const char **db_path)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GETDBPATH) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*db_path = talloc_steal(mem_ctx, reply->rdata.data.db_path);
	}
	return reply->status;
}

/* CTDB_CONTROL_GETVNNMAP */

void ctdb_req_control_getvnnmap(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_GETVNNMAP;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GETVNNMAP;
}

int ctdb_reply_control_getvnnmap(struct ctdb_reply_control *reply,
				 TALLOC_CTX *mem_ctx,
				 struct ctdb_vnn_map **vnnmap)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GETVNNMAP) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*vnnmap = talloc_steal(mem_ctx, reply->rdata.data.vnnmap);
	}
	return reply->status;
}

/* CTDB_CONTROL_SETVNNMAP */

void ctdb_req_control_setvnnmap(struct ctdb_req_control *request,
				struct ctdb_vnn_map *vnnmap)
{
	request->opcode = CTDB_CONTROL_SETVNNMAP;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_SETVNNMAP;
	request->rdata.data.vnnmap = vnnmap;
}

int ctdb_reply_control_setvnnmap(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_SETVNNMAP);
}

/* CTDB_CONTROL_GET_DEBUG */

void ctdb_req_control_get_debug(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_GET_DEBUG;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_DEBUG;
}

int ctdb_reply_control_get_debug(struct ctdb_reply_control *reply,
				 int *loglevel)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_DEBUG) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*loglevel = (int)reply->rdata.data.loglevel;
	}
	return reply->status;
}

/* CTDB_CONTROL_SET_DEBUG */

void ctdb_req_control_set_debug(struct ctdb_req_control *request,
				int loglevel)
{
	request->opcode = CTDB_CONTROL_SET_DEBUG;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_SET_DEBUG;
	request->rdata.data.loglevel = (uint32_t)loglevel;
}

int ctdb_reply_control_set_debug(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_SET_DEBUG);
}

/* CTDB_CONTROL_GET_DBMAP */

void ctdb_req_control_get_dbmap(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_GET_DBMAP;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_DBMAP;
}

int ctdb_reply_control_get_dbmap(struct ctdb_reply_control *reply,
				 TALLOC_CTX *mem_ctx,
				 struct ctdb_dbid_map **dbmap)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_DBMAP) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*dbmap = talloc_steal(mem_ctx, reply->rdata.data.dbmap);
	}
	return reply->status;
}

/* CTDB_CONTROL_PULL_DB */

void ctdb_req_control_pull_db(struct ctdb_req_control *request,
			      struct ctdb_pulldb *pulldb)
{
	request->opcode = CTDB_CONTROL_PULL_DB;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_PULL_DB;
	request->rdata.data.pulldb = pulldb;
}

int ctdb_reply_control_pull_db(struct ctdb_reply_control *reply,
			       TALLOC_CTX *mem_ctx,
			       struct ctdb_rec_buffer **recbuf)
{
	if (reply->rdata.opcode != CTDB_CONTROL_PULL_DB) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*recbuf = talloc_steal(mem_ctx, reply->rdata.data.recbuf);
	}
	return reply->status;
}

/* CTDB_CONTROL_PUSH_DB */

void ctdb_req_control_push_db(struct ctdb_req_control *request,
			      struct ctdb_rec_buffer *recbuf)
{
	request->opcode = CTDB_CONTROL_PUSH_DB;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_PUSH_DB;
	request->rdata.data.recbuf = recbuf;
}

int ctdb_reply_control_push_db(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_PUSH_DB);
}

/* CTDB_CONTROL_GET_RECMODE */

void ctdb_req_control_get_recmode(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_GET_RECMODE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_RECMODE;
}

int ctdb_reply_control_get_recmode(struct ctdb_reply_control *reply,
				   int *recmode)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_RECMODE) {
		return EPROTO;
	}

	if (reply->status >= 0) {
		*recmode = reply->status;
		reply->status = 0;
	}
	return reply->status;
}

/* CTDB_CONTROL_SET_RECMODE */

void ctdb_req_control_set_recmode(struct ctdb_req_control *request,
				  int recmode)
{
	request->opcode = CTDB_CONTROL_SET_RECMODE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_SET_RECMODE;
	request->rdata.data.recmode = recmode;
}

int ctdb_reply_control_set_recmode(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_SET_RECMODE);
}

/* CTDB_CONTROL_STATISTICS_RESET */

void ctdb_req_control_statistics_reset(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_STATISTICS_RESET;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_STATISTICS_RESET;
}

int ctdb_reply_control_statistics_reset(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply,
					  CTDB_CONTROL_STATISTICS_RESET);
}

/* CTDB_CONTROL_DB_ATTACH */

void ctdb_req_control_db_attach(struct ctdb_req_control *request,
				const char *db_name)
{
	request->opcode = CTDB_CONTROL_DB_ATTACH;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DB_ATTACH;
	request->rdata.data.db_name = db_name;
}

int ctdb_reply_control_db_attach(struct ctdb_reply_control *reply,
				 uint32_t *db_id)
{
	if (reply->rdata.opcode != CTDB_CONTROL_DB_ATTACH) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*db_id = reply->rdata.data.db_id;
	}
	return reply->status;
}

/* CTDB_CONTROL_TRAVERSE_START */

void ctdb_req_control_traverse_start(struct ctdb_req_control *request,
				     struct ctdb_traverse_start *traverse)
{
	request->opcode = CTDB_CONTROL_TRAVERSE_START;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_TRAVERSE_START;
	request->rdata.data.traverse_start = traverse;
}

int ctdb_reply_control_traverse_start(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_TRAVERSE_START);
}

/* CTDB_CONTROL_TRAVERSE_ALL */
/* CTDB_CONTROL_TRAVERSE_DATA */

/* CTDB_CONTROL_REGISTER_SRVID */

void ctdb_req_control_register_srvid(struct ctdb_req_control *request,
				     uint64_t srvid)
{
	request->opcode = CTDB_CONTROL_REGISTER_SRVID;
	request->pad = 0;
	request->srvid = srvid;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_REGISTER_SRVID;
}

int ctdb_reply_control_register_srvid(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_REGISTER_SRVID);
}

/* CTDB_CONTROL_DEREGISTER_SRVID */

void ctdb_req_control_deregister_srvid(struct ctdb_req_control *request,
				       uint64_t srvid)
{
	request->opcode = CTDB_CONTROL_DEREGISTER_SRVID;
	request->pad = 0;
	request->srvid = srvid;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DEREGISTER_SRVID;
}

int ctdb_reply_control_deregister_srvid(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply,
					  CTDB_CONTROL_DEREGISTER_SRVID);
}

/* CTDB_CONTROL_GET_DBNAME */

void ctdb_req_control_get_dbname(struct ctdb_req_control *request,
				 uint32_t db_id)
{
	request->opcode = CTDB_CONTROL_GET_DBNAME;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_DBNAME;
	request->rdata.data.db_id = db_id;
}

int ctdb_reply_control_get_dbname(struct ctdb_reply_control *reply,
				  TALLOC_CTX *mem_ctx, const char **db_name)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_DBNAME) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*db_name = talloc_steal(mem_ctx, reply->rdata.data.db_name);
	}
	return reply->status;
}

/* CTDB_CONTROL_ENABLE_SEQNUM */

void ctdb_req_control_enable_seqnum(struct ctdb_req_control *request,
				    uint32_t db_id)
{
	request->opcode = CTDB_CONTROL_ENABLE_SEQNUM;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_ENABLE_SEQNUM;
	request->rdata.data.db_id = db_id;
}

int ctdb_reply_control_enable_seqnum(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_ENABLE_SEQNUM);
}

/* CTDB_CONTROL_UPDATE_SEQNUM */

void ctdb_req_control_update_seqnum(struct ctdb_req_control *request,
				    uint32_t db_id)
{
	request->opcode = CTDB_CONTROL_UPDATE_SEQNUM;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_UPDATE_SEQNUM;
	request->rdata.data.db_id = db_id;
}

int ctdb_reply_control_update_seqnum(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_UPDATE_SEQNUM);
}

/* CTDB_CONTROL_DUMP_MEMORY */

void ctdb_req_control_dump_memory(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_DUMP_MEMORY;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DUMP_MEMORY;
}

int ctdb_reply_control_dump_memory(struct ctdb_reply_control *reply,
				   TALLOC_CTX *mem_ctx, const char **mem_str)
{
	if (reply->rdata.opcode != CTDB_CONTROL_DUMP_MEMORY) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*mem_str = talloc_steal(mem_ctx, reply->rdata.data.mem_str);
	}
	return reply->status;
}

/* CTDB_CONTROL_GET_PID */

void ctdb_req_control_get_pid(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_GET_PID;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_PID;
}

int ctdb_reply_control_get_pid(struct ctdb_reply_control *reply,
			       pid_t *pid)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_PID) {
		return EPROTO;
	}

	*pid = reply->status;
	reply->status = 0;

	return reply->status;
}

/* CTDB_CONTROL_GET_RECMASTER */

void ctdb_req_control_get_recmaster(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_GET_RECMASTER;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_RECMASTER;
}

int ctdb_reply_control_get_recmaster(struct ctdb_reply_control *reply,
				     uint32_t *recmaster)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_RECMASTER) {
		return EPROTO;
	}

	*recmaster = reply->status;
	reply->status = 0;

	return reply->status;
}

/* CTDB_CONTROL_SET_RECMASTER */

void ctdb_req_control_set_recmaster(struct ctdb_req_control *request,
				    int recmaster)
{
	request->opcode = CTDB_CONTROL_SET_RECMASTER;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_SET_RECMASTER;
	request->rdata.data.recmaster = recmaster;
}

int ctdb_reply_control_set_recmaster(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_SET_RECMASTER);
}

/* CTDB_CONTROL_FREEZE */

void ctdb_req_control_freeze(struct ctdb_req_control *request,
			     uint32_t priority)
{
	request->opcode = CTDB_CONTROL_FREEZE;
	request->pad = 0;
	request->srvid = priority;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_FREEZE;
}

int ctdb_reply_control_freeze(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_FREEZE);
}

/* CTDB_CONTROL_GET_PNN */

void ctdb_req_control_get_pnn(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_GET_PNN;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_PNN;
}

int ctdb_reply_control_get_pnn(struct ctdb_reply_control *reply,
			       uint32_t *pnn)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_PNN) {
		return EPROTO;
	}

	if (reply->status >= 0) {
		*pnn = reply->status;
		reply->status = 0;
	}
	return reply->status;
}

/* CTDB_CONTROL_SHUTDOWN */

void ctdb_req_control_shutdown(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_SHUTDOWN;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = CTDB_CTRL_FLAG_NOREPLY;

	request->rdata.opcode = CTDB_CONTROL_SHUTDOWN;
}

int ctdb_reply_control_shutdown(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_SHUTDOWN);
}

/* CTDB_CONTROL_TCP_CLIENT */

void ctdb_req_control_tcp_client(struct ctdb_req_control *request,
				 struct ctdb_connection *conn)
{
	request->opcode = CTDB_CONTROL_TCP_CLIENT;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_TCP_CLIENT;
	request->rdata.data.conn = conn;
}

int ctdb_reply_control_tcp_client(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_TCP_CLIENT);
}

/* CTDB_CONTROL_TCP_ADD */

void ctdb_req_control_tcp_add(struct ctdb_req_control *request,
			      struct ctdb_connection *conn)
{
	request->opcode = CTDB_CONTROL_TCP_ADD;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_TCP_ADD;
	request->rdata.data.conn = conn;
}

int ctdb_reply_control_tcp_add(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_TCP_ADD);
}

/* CTDB_CONTROL_TCP_REMOVE */

void ctdb_req_control_tcp_remove(struct ctdb_req_control *request,
				 struct ctdb_connection *conn)
{
	request->opcode = CTDB_CONTROL_TCP_REMOVE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_TCP_REMOVE;
	request->rdata.data.conn = conn;
}

int ctdb_reply_control_tcp_remove(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_TCP_REMOVE);
}

/* CTDB_CONTROL_STARTUP */

void ctdb_req_control_startup(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_STARTUP;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_STARTUP;
}

int ctdb_reply_control_startup(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_STARTUP);
}

/* CTDB_CONTROL_SET_TUNABLE */

void ctdb_req_control_set_tunable(struct ctdb_req_control *request,
				  struct ctdb_tunable *tunable)
{
	request->opcode = CTDB_CONTROL_SET_TUNABLE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_SET_TUNABLE;
	request->rdata.data.tunable = tunable;
}

int ctdb_reply_control_set_tunable(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_SET_TUNABLE);
}

/* CTDB_CONTROL_GET_TUNABLE */

void ctdb_req_control_get_tunable(struct ctdb_req_control *request,
				  const char *name)
{
	request->opcode = CTDB_CONTROL_GET_TUNABLE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_TUNABLE;
	request->rdata.data.tun_var = discard_const(name);
}

int ctdb_reply_control_get_tunable(struct ctdb_reply_control *reply,
				   uint32_t *value)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_TUNABLE) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*value = reply->rdata.data.tun_value;
	}
	return reply->status;
}

/* CTDB_CONTROL_LIST_TUNABLES */

void ctdb_req_control_list_tunables(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_LIST_TUNABLES;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_LIST_TUNABLES;
}

int ctdb_reply_control_list_tunables(struct ctdb_reply_control *reply,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_var_list **tun_var_list)
{
	if (reply->rdata.opcode != CTDB_CONTROL_LIST_TUNABLES) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*tun_var_list = talloc_steal(mem_ctx,
					     reply->rdata.data.tun_var_list);
	}
	return reply->status;
}

/* CTDB_CONTROL_MODIFY_FLAGS */

void ctdb_req_control_modify_flags(struct ctdb_req_control *request,
				   struct ctdb_node_flag_change *flag_change)
{
	request->opcode = CTDB_CONTROL_MODIFY_FLAGS;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_MODIFY_FLAGS;
	request->rdata.data.flag_change = flag_change;
}

int ctdb_reply_control_modify_flags(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_MODIFY_FLAGS);
}

/* CTDB_CONTROL_GET_ALL_TUNABLES */

void ctdb_req_control_get_all_tunables(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_GET_ALL_TUNABLES;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_ALL_TUNABLES;
}

int ctdb_reply_control_get_all_tunables(struct ctdb_reply_control *reply,
					TALLOC_CTX *mem_ctx,
					struct ctdb_tunable_list **tun_list)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_ALL_TUNABLES) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*tun_list = talloc_steal(mem_ctx, reply->rdata.data.tun_list);
	}
	return reply->status;
}

/* CTDB_CONTROL_GET_TCP_TICKLE_LIST */

void ctdb_req_control_get_tcp_tickle_list(struct ctdb_req_control *request,
					  ctdb_sock_addr *addr)
{
	request->opcode = CTDB_CONTROL_GET_TCP_TICKLE_LIST;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_TCP_TICKLE_LIST;
	request->rdata.data.addr = addr;
}

int ctdb_reply_control_get_tcp_tickle_list(struct ctdb_reply_control *reply,
					   TALLOC_CTX *mem_ctx,
					   struct ctdb_tickle_list **tickles)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_TCP_TICKLE_LIST) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*tickles = talloc_steal(mem_ctx, reply->rdata.data.tickles);
	}
	return reply->status;
}

/* CTDB_CONTROL_SET_TCP_TICKLE_LIST */

void ctdb_req_control_set_tcp_tickle_list(struct ctdb_req_control *request,
					  struct ctdb_tickle_list *tickles)
{
	request->opcode = CTDB_CONTROL_SET_TCP_TICKLE_LIST;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_SET_TCP_TICKLE_LIST;
	request->rdata.data.tickles = tickles;
}

int ctdb_reply_control_set_tcp_tickle_list(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply,
					  CTDB_CONTROL_SET_TCP_TICKLE_LIST);
}

/* CTDB_CONTROL_DB_ATTACH_PERSISTENT */

void ctdb_req_control_db_attach_persistent(struct ctdb_req_control *request,
					   const char *db_name)
{
	request->opcode = CTDB_CONTROL_DB_ATTACH_PERSISTENT;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DB_ATTACH_PERSISTENT;
	request->rdata.data.db_name = db_name;
}

int ctdb_reply_control_db_attach_persistent(struct ctdb_reply_control *reply,
					    uint32_t *db_id)
{
	if (reply->rdata.opcode != CTDB_CONTROL_DB_ATTACH_PERSISTENT) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*db_id = reply->rdata.data.db_id;
	}
	return reply->status;
}

/* CTDB_CONTROL_UPDATE_RECORD */

void ctdb_req_control_update_record(struct ctdb_req_control *request,
				    struct ctdb_rec_buffer *recbuf)
{
	request->opcode = CTDB_CONTROL_UPDATE_RECORD;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_UPDATE_RECORD;
	request->rdata.data.recbuf = recbuf;
}

int ctdb_reply_control_update_record(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_UPDATE_RECORD);
}

/* CTDB_CONTROL_SEND_GRATUITOUS_ARP */

void ctdb_req_control_send_gratuitous_arp(struct ctdb_req_control *request,
					  struct ctdb_addr_info *addr_info)
{
	request->opcode = CTDB_CONTROL_SEND_GRATUITOUS_ARP;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_SEND_GRATUITOUS_ARP;
	request->rdata.data.addr_info = addr_info;
}

int ctdb_reply_control_send_gratuitous_arp(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply,
					  CTDB_CONTROL_SEND_GRATUITOUS_ARP);
}

/* CTDB_CONTROL_WIPE_DATABASE */

void ctdb_req_control_wipe_database(struct ctdb_req_control *request,
				    struct ctdb_transdb *transdb)
{
	request->opcode = CTDB_CONTROL_WIPE_DATABASE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_WIPE_DATABASE;
	request->rdata.data.transdb = transdb;
}

int ctdb_reply_control_wipe_database(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_WIPE_DATABASE);
}

/* CTDB_CONTROL_UPTIME */

void ctdb_req_control_uptime(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_UPTIME;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_UPTIME;
}

int ctdb_reply_control_uptime(struct ctdb_reply_control *reply,
			      TALLOC_CTX *mem_ctx, struct ctdb_uptime **uptime)
{
	if (reply->rdata.opcode != CTDB_CONTROL_UPTIME) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*uptime = talloc_steal(mem_ctx, reply->rdata.data.uptime);
	}
	return reply->status;
}

/* CTDB_CONTROL_START_RECOVERY */

void ctdb_req_control_start_recovery(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_START_RECOVERY;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_START_RECOVERY;
}

int ctdb_reply_control_start_recovery(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_START_RECOVERY);
}

/* CTDB_CONTROL_END_RECOVERY */

void ctdb_req_control_end_recovery(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_END_RECOVERY;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_END_RECOVERY;
}

int ctdb_reply_control_end_recovery(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_END_RECOVERY);
}

/* CTDB_CONTROL_RELOAD_NODES_FILE */

void ctdb_req_control_reload_nodes_file(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_RELOAD_NODES_FILE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_RELOAD_NODES_FILE;
}

int ctdb_reply_control_reload_nodes_file(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply,
					  CTDB_CONTROL_RELOAD_NODES_FILE);
}

/* CTDB_CONTROL_TRY_DELETE_RECORDS */

void ctdb_req_control_try_delete_records(struct ctdb_req_control *request,
					 struct ctdb_rec_buffer *recbuf)
{
	request->opcode = CTDB_CONTROL_TRY_DELETE_RECORDS;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_TRY_DELETE_RECORDS;
	request->rdata.data.recbuf = recbuf;
}

int ctdb_reply_control_try_delete_records(struct ctdb_reply_control *reply,
					  TALLOC_CTX *mem_ctx,
					  struct ctdb_rec_buffer **recbuf)
{
	if (reply->rdata.opcode != CTDB_CONTROL_TRY_DELETE_RECORDS) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*recbuf = talloc_steal(mem_ctx, reply->rdata.data.recbuf);
	}
	return reply->status;
}

/* CTDB_CONTROL_ADD_PUBLIC_IP */

void ctdb_req_control_add_public_ip(struct ctdb_req_control *request,
				    struct ctdb_addr_info *addr_info)
{
	request->opcode = CTDB_CONTROL_ADD_PUBLIC_IP;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_ADD_PUBLIC_IP;
	request->rdata.data.addr_info = addr_info;
}

int ctdb_reply_control_add_public_ip(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_ADD_PUBLIC_IP);
}

/* CTDB_CONTROL_DEL_PUBLIC_IP */

void ctdb_req_control_del_public_ip(struct ctdb_req_control *request,
				    struct ctdb_addr_info *addr_info)
{
	request->opcode = CTDB_CONTROL_DEL_PUBLIC_IP;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DEL_PUBLIC_IP;
	request->rdata.data.addr_info = addr_info;
}

int ctdb_reply_control_del_public_ip(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_DEL_PUBLIC_IP);
}

/* CTDB_CONTROL_GET_CAPABILITIES */

void ctdb_req_control_get_capabilities(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_GET_CAPABILITIES;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_CAPABILITIES;
}

int ctdb_reply_control_get_capabilities(struct ctdb_reply_control *reply,
					uint32_t *caps)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_CAPABILITIES) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*caps = reply->rdata.data.caps;
	}
	return reply->status;
}

/* CTDB_CONTROL_RECD_PING */

void ctdb_req_control_recd_ping(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_RECD_PING;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_RECD_PING;
}

int ctdb_reply_control_recd_ping(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_RECD_PING);
}

/* CTDB_CONTROL_RELEASE_IP */

void ctdb_req_control_release_ip(struct ctdb_req_control *request,
				 struct ctdb_public_ip *pubip)
{
	request->opcode = CTDB_CONTROL_RELEASE_IP;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_RELEASE_IP;
	request->rdata.data.pubip = pubip;
}

int ctdb_reply_control_release_ip(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_RELEASE_IP);
}

/* CTDB_CONTROL_TAKEOVER_IP */

void ctdb_req_control_takeover_ip(struct ctdb_req_control *request,
				  struct ctdb_public_ip *pubip)
{
	request->opcode = CTDB_CONTROL_TAKEOVER_IP;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_TAKEOVER_IP;
	request->rdata.data.pubip = pubip;
}

int ctdb_reply_control_takeover_ip(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_TAKEOVER_IP);
}

/* CTDB_CONTROL_GET_PUBLIC_IPS */

void ctdb_req_control_get_public_ips(struct ctdb_req_control *request,
				     bool available_only)
{
	request->opcode = CTDB_CONTROL_GET_PUBLIC_IPS;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_PUBLIC_IPS;
	if (available_only) {
		request->flags = CTDB_PUBLIC_IP_FLAGS_ONLY_AVAILABLE;
	}
}

int ctdb_reply_control_get_public_ips(struct ctdb_reply_control *reply,
				      TALLOC_CTX *mem_ctx,
				      struct ctdb_public_ip_list **pubip_list)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_PUBLIC_IPS) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*pubip_list = talloc_steal(mem_ctx,
					   reply->rdata.data.pubip_list);
	}
	return reply->status;
}

/* CTDB_CONTROL_GET_NODEMAP */

void ctdb_req_control_get_nodemap(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_GET_NODEMAP;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_NODEMAP;
}

int ctdb_reply_control_get_nodemap(struct ctdb_reply_control *reply,
				   TALLOC_CTX *mem_ctx,
				   struct ctdb_node_map **nodemap)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_NODEMAP) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*nodemap = talloc_steal(mem_ctx, reply->rdata.data.nodemap);
	}
	return reply->status;
}

/* CTDB_CONTROL_TRAVERSE_KILL */

void ctdb_req_control_traverse_kill(struct ctdb_req_control *request,
				    struct ctdb_traverse_start *traverse)
{
	request->opcode = CTDB_CONTROL_TRAVERSE_KILL;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_TRAVERSE_KILL;
	request->rdata.data.traverse_start = traverse;
}

int ctdb_reply_control_traverse_kill(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_TRAVERSE_KILL);
}

/* CTDB_CONTROL_RECD_RECLOCK_LATENCY */

void ctdb_req_control_recd_reclock_latency(struct ctdb_req_control *request,
					   double reclock_latency)
{
	request->opcode = CTDB_CONTROL_RECD_RECLOCK_LATENCY;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_RECD_RECLOCK_LATENCY;
	request->rdata.data.reclock_latency = reclock_latency;
}

int ctdb_reply_control_recd_reclock_latency(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply,
					  CTDB_CONTROL_RECD_RECLOCK_LATENCY);
}

/* CTDB_CONTROL_GET_RECLOCK_FILE */

void ctdb_req_control_get_reclock_file(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_GET_RECLOCK_FILE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_RECLOCK_FILE;
}

int ctdb_reply_control_get_reclock_file(struct ctdb_reply_control *reply,
					TALLOC_CTX *mem_ctx,
					const char **reclock_file)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_RECLOCK_FILE) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*reclock_file = talloc_steal(mem_ctx,
					     reply->rdata.data.reclock_file);
	}
	return reply->status;
}

/* CTDB_CONTROL_STOP_NODE */

void ctdb_req_control_stop_node(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_STOP_NODE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_STOP_NODE;
}

int ctdb_reply_control_stop_node(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_STOP_NODE);
}

/* CTDB_CONTROL_CONTINUE_NODE */

void ctdb_req_control_continue_node(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_CONTINUE_NODE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_CONTINUE_NODE;
}

int ctdb_reply_control_continue_node(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_CONTINUE_NODE);
}

/* CTDB_CONTROL_SET_LMASTERROLE */

void ctdb_req_control_set_lmasterrole(struct ctdb_req_control *request,
				      uint32_t lmaster_role)
{
	request->opcode = CTDB_CONTROL_SET_LMASTERROLE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_SET_LMASTERROLE;
	request->rdata.data.role = lmaster_role;
}

int ctdb_reply_control_set_lmasterrole(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_SET_LMASTERROLE);
}

/* CTDB_CONTROL_SET_RECMASTERROLE */

void ctdb_req_control_set_recmasterrole(struct ctdb_req_control *request,
					uint32_t recmaster_role)
{
	request->opcode = CTDB_CONTROL_SET_RECMASTERROLE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_SET_RECMASTERROLE;
	request->rdata.data.role = recmaster_role;
}

int ctdb_reply_control_set_recmasterrole(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply,
					  CTDB_CONTROL_SET_RECMASTERROLE);
}

/* CTDB_CONTROL_SET_BAN_STATE */

void ctdb_req_control_set_ban_state(struct ctdb_req_control *request,
				    struct ctdb_ban_state *ban_state)
{
	request->opcode = CTDB_CONTROL_SET_BAN_STATE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_SET_BAN_STATE;
	request->rdata.data.ban_state = ban_state;
}

int ctdb_reply_control_set_ban_state(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_SET_BAN_STATE);
}

/* CTDB_CONTROL_GET_BAN_STATE */

void ctdb_req_control_get_ban_state(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_GET_BAN_STATE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_BAN_STATE;
}

int ctdb_reply_control_get_ban_state(struct ctdb_reply_control *reply,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_ban_state **ban_state)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_BAN_STATE) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*ban_state = talloc_steal(mem_ctx,
					  reply->rdata.data.ban_state);
	}
	return reply->status;
}

/* CTDB_CONTROL_REGISTER_NOTIFY */

void ctdb_req_control_register_notify(struct ctdb_req_control *request,
				      struct ctdb_notify_data *notify)
{
	request->opcode = CTDB_CONTROL_REGISTER_NOTIFY;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_REGISTER_NOTIFY;
	request->rdata.data.notify = notify;
}

int ctdb_reply_control_register_notify(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_REGISTER_NOTIFY);
}

/* CTDB_CONTROL_DEREGISTER_NOTIFY */

void ctdb_req_control_deregister_notify(struct ctdb_req_control *request,
					uint64_t srvid)
{
	request->opcode = CTDB_CONTROL_DEREGISTER_NOTIFY;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DEREGISTER_NOTIFY;
	request->rdata.data.srvid = srvid;
}

int ctdb_reply_control_deregister_notify(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply,
					  CTDB_CONTROL_DEREGISTER_NOTIFY);
}

/* CTDB_CONTROL_TRANS3_COMMIT */

void ctdb_req_control_trans3_commit(struct ctdb_req_control *request,
				    struct ctdb_rec_buffer *recbuf)
{
	request->opcode = CTDB_CONTROL_TRANS3_COMMIT;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_TRANS3_COMMIT;
	request->rdata.data.recbuf = recbuf;
}

int ctdb_reply_control_trans3_commit(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_TRANS3_COMMIT);
}

/* CTDB_CONTROL_GET_DB_SEQNUM */

void ctdb_req_control_get_db_seqnum(struct ctdb_req_control *request,
				    uint32_t db_id)
{
	request->opcode = CTDB_CONTROL_GET_DB_SEQNUM;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_DB_SEQNUM;
	request->rdata.data.db_id = db_id;
}

int ctdb_reply_control_get_db_seqnum(struct ctdb_reply_control *reply,
				     uint64_t *seqnum)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_DB_SEQNUM) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*seqnum = reply->rdata.data.seqnum;
	}
	return reply->status;
}

/* CTDB_CONTROL_DB_SET_HEALTHY */

void ctdb_req_control_db_set_healthy(struct ctdb_req_control *request,
				     uint32_t db_id)
{
	request->opcode = CTDB_CONTROL_DB_SET_HEALTHY;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DB_SET_HEALTHY;
	request->rdata.data.db_id = db_id;
}

int ctdb_reply_control_db_set_healthy(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_DB_SET_HEALTHY);
}

/* CTDB_CONTROL_DB_GET_HEALTH */

void ctdb_req_control_db_get_health(struct ctdb_req_control *request,
				    uint32_t db_id)
{
	request->opcode = CTDB_CONTROL_DB_GET_HEALTH;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DB_GET_HEALTH;
	request->rdata.data.db_id = db_id;
}

int ctdb_reply_control_db_get_health(struct ctdb_reply_control *reply,
				     TALLOC_CTX *mem_ctx, const char **reason)
{
	if (reply->rdata.opcode != CTDB_CONTROL_DB_GET_HEALTH) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*reason = talloc_steal(mem_ctx, reply->rdata.data.reason);
	}
	return reply->status;
}

/* CTDB_CONTROL_GET_PUBLIC_IP_INFO */

void ctdb_req_control_get_public_ip_info(struct ctdb_req_control *request,
					 ctdb_sock_addr *addr)
{
	request->opcode = CTDB_CONTROL_GET_PUBLIC_IP_INFO;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_PUBLIC_IP_INFO;
	request->rdata.data.addr = addr;
}

int ctdb_reply_control_get_public_ip_info(struct ctdb_reply_control *reply,
					  TALLOC_CTX *mem_ctx,
					  struct ctdb_public_ip_info **ipinfo)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_PUBLIC_IP_INFO) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*ipinfo = talloc_steal(mem_ctx, reply->rdata.data.ipinfo);
	}
	return reply->status;
}

/* CTDB_CONTROL_GET_IFACES */

void ctdb_req_control_get_ifaces(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_GET_IFACES;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_IFACES;
}

int ctdb_reply_control_get_ifaces(struct ctdb_reply_control *reply,
				  TALLOC_CTX *mem_ctx,
				  struct ctdb_iface_list **iface_list)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_IFACES) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*iface_list = talloc_steal(mem_ctx,
					   reply->rdata.data.iface_list);
	}
	return reply->status;
}

/* CTDB_CONTROL_SET_IFACE_LINK_STATE */

void ctdb_req_control_set_iface_link_state(struct ctdb_req_control *request,
					   struct ctdb_iface *iface)
{
	request->opcode = CTDB_CONTROL_SET_IFACE_LINK_STATE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_SET_IFACE_LINK_STATE;
	request->rdata.data.iface = iface;
}

int ctdb_reply_control_set_iface_link_state(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply,
					  CTDB_CONTROL_SET_IFACE_LINK_STATE);
}

/* CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE */

void ctdb_req_control_tcp_add_delayed_update(struct ctdb_req_control *request,
					     struct ctdb_connection *conn)
{
	request->opcode = CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE;
	request->rdata.data.conn = conn;
}

int ctdb_reply_control_tcp_add_delayed_update(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply,
					  CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE);
}

/* CTDB_CONTROL_GET_STAT_HISTORY */

void ctdb_req_control_get_stat_history(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_GET_STAT_HISTORY;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_STAT_HISTORY;
}

int ctdb_reply_control_get_stat_history(struct ctdb_reply_control *reply,
					TALLOC_CTX *mem_ctx,
					struct ctdb_statistics_list **stats_list)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_STAT_HISTORY) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*stats_list = talloc_steal(mem_ctx,
					   reply->rdata.data.stats_list);
	}
	return reply->status;
}

/* CTDB_CONTROL_SCHEDULE_FOR_DELETION */

void ctdb_req_control_schedule_for_deletion(struct ctdb_req_control *request,
					    struct ctdb_key_data *key)
{
	request->opcode = CTDB_CONTROL_SCHEDULE_FOR_DELETION;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_SCHEDULE_FOR_DELETION;
	request->rdata.data.key = key;
}

int ctdb_reply_control_schedule_for_deletion(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply,
					  CTDB_CONTROL_SCHEDULE_FOR_DELETION);
}

/* CTDB_CONTROL_SET_DB_READONLY */

void ctdb_req_control_set_db_readonly(struct ctdb_req_control *request,
				      uint32_t db_id)
{
	request->opcode = CTDB_CONTROL_SET_DB_READONLY;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_SET_DB_READONLY;
	request->rdata.data.db_id = db_id;
}

int ctdb_reply_control_set_db_readonly(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_SET_DB_READONLY);
}

/* CTDB_CONTROL_TRAVERSE_START_EXT */

void ctdb_req_control_traverse_start_ext(struct ctdb_req_control *request,
					 struct ctdb_traverse_start_ext *traverse)
{
	request->opcode = CTDB_CONTROL_TRAVERSE_START_EXT;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_TRAVERSE_START_EXT;
	request->rdata.data.traverse_start_ext = traverse;
}

int ctdb_reply_control_traverse_start_ext(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply,
					  CTDB_CONTROL_TRAVERSE_START_EXT);
}

/* CTDB_CONTROL_GET_DB_STATISTICS */

void ctdb_req_control_get_db_statistics(struct ctdb_req_control *request,
					uint32_t db_id)
{
	request->opcode = CTDB_CONTROL_GET_DB_STATISTICS;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_DB_STATISTICS;
	request->rdata.data.db_id = db_id;
}

int ctdb_reply_control_get_db_statistics(struct ctdb_reply_control *reply,
					 TALLOC_CTX *mem_ctx,
					 struct ctdb_db_statistics **dbstats)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_DB_STATISTICS) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*dbstats = talloc_steal(mem_ctx, reply->rdata.data.dbstats);
	}
	return reply->status;
}

/* CTDB_CONTROL_SET_DB_STICKY */

void ctdb_req_control_set_db_sticky(struct ctdb_req_control *request,
				    uint32_t db_id)
{
	request->opcode = CTDB_CONTROL_SET_DB_STICKY;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_SET_DB_STICKY;
	request->rdata.data.db_id = db_id;
}

int ctdb_reply_control_set_db_sticky(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_SET_DB_STICKY);
}

/* CTDB_CONTROL_RELOAD_PUBLIC_IPS */

void ctdb_req_control_reload_public_ips(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_RELOAD_PUBLIC_IPS;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_RELOAD_PUBLIC_IPS;
}

int ctdb_reply_control_reload_public_ips(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply,
					  CTDB_CONTROL_RELOAD_PUBLIC_IPS);
}

/* CTDB_CONTROL_TRAVERSE_ALL_EXT */

/* CTDB_CONTROL_IPREALLOCATED */

void ctdb_req_control_ipreallocated(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_IPREALLOCATED;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_IPREALLOCATED;
}

int ctdb_reply_control_ipreallocated(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_IPREALLOCATED);
}

/* CTDB_CONTROL_GET_RUNSTATE */

void ctdb_req_control_get_runstate(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_GET_RUNSTATE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_RUNSTATE;
}

int ctdb_reply_control_get_runstate(struct ctdb_reply_control *reply,
				    enum ctdb_runstate *runstate)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_RUNSTATE) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*runstate = reply->rdata.data.runstate;
	}
	return reply->status;
}

/* CTDB_CONTROL_DB_DETACH */

void ctdb_req_control_db_detach(struct ctdb_req_control *request,
				uint32_t db_id)
{
	request->opcode = CTDB_CONTROL_DB_DETACH;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DB_DETACH;
	request->rdata.data.db_id = db_id;
}

int ctdb_reply_control_db_detach(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_DB_DETACH);
}

/* CTDB_CONTROL_GET_NODES_FILE */

void ctdb_req_control_get_nodes_file(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_GET_NODES_FILE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_GET_NODES_FILE;
}

int ctdb_reply_control_get_nodes_file(struct ctdb_reply_control *reply,
				      TALLOC_CTX *mem_ctx,
				      struct ctdb_node_map **nodemap)
{
	if (reply->rdata.opcode != CTDB_CONTROL_GET_NODES_FILE) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*nodemap = talloc_steal(mem_ctx, reply->rdata.data.nodemap);
	}
	return reply->status;
}

/* CTDB_CONTROL_DB_FREEZE */

void ctdb_req_control_db_freeze(struct ctdb_req_control *request,
				uint32_t db_id)
{
	request->opcode = CTDB_CONTROL_DB_FREEZE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DB_FREEZE;
	request->rdata.data.db_id = db_id;
}

int ctdb_reply_control_db_freeze(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_DB_FREEZE);
}

/* CTDB_CONTROL_DB_THAW */

void ctdb_req_control_db_thaw(struct ctdb_req_control *request,
			      uint32_t db_id)
{
	request->opcode = CTDB_CONTROL_DB_THAW;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DB_THAW;
	request->rdata.data.db_id = db_id;
}

int ctdb_reply_control_db_thaw(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_DB_THAW);
}

/* CTDB_CONTROL_DB_TRANSACTION_START */

void ctdb_req_control_db_transaction_start(struct ctdb_req_control *request,
					   struct ctdb_transdb *transdb)
{
	request->opcode = CTDB_CONTROL_DB_TRANSACTION_START;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DB_TRANSACTION_START;
	request->rdata.data.transdb = transdb;
}

int ctdb_reply_control_db_transaction_start(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply,
					  CTDB_CONTROL_DB_TRANSACTION_START);
}

/* CTDB_CONTROL_DB_TRANSACTION_COMMIT */

void ctdb_req_control_db_transaction_commit(struct ctdb_req_control *request,
					    struct ctdb_transdb *transdb)
{
	request->opcode = CTDB_CONTROL_DB_TRANSACTION_COMMIT;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DB_TRANSACTION_COMMIT;
	request->rdata.data.transdb = transdb;
}

int ctdb_reply_control_db_transaction_commit(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply,
					  CTDB_CONTROL_DB_TRANSACTION_COMMIT);
}

/* CTDB_CONTROL_DB_TRANSACTION_CANCEL */

void ctdb_req_control_db_transaction_cancel(struct ctdb_req_control *request,
					    uint32_t db_id)
{
	request->opcode = CTDB_CONTROL_DB_TRANSACTION_CANCEL;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DB_TRANSACTION_CANCEL;
	request->rdata.data.db_id = db_id;
}

int ctdb_reply_control_db_transaction_cancel(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply,
					  CTDB_CONTROL_DB_TRANSACTION_CANCEL);
}

/* CTDB_CONTROL_DB_PULL */

void ctdb_req_control_db_pull(struct ctdb_req_control *request,
			      struct ctdb_pulldb_ext *pulldb_ext)
{
	request->opcode = CTDB_CONTROL_DB_PULL;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DB_PULL;
	request->rdata.data.pulldb_ext = pulldb_ext;
}

int ctdb_reply_control_db_pull(struct ctdb_reply_control *reply,
			       uint32_t *num_records)
{
	if (reply->rdata.opcode != CTDB_CONTROL_DB_PULL) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*num_records = reply->rdata.data.num_records;
	}
	return reply->status;
}

/* CTDB_CONTROL_DB_PUSH_START */

void ctdb_req_control_db_push_start(struct ctdb_req_control *request,
				    struct ctdb_pulldb_ext *pulldb_ext)
{
	request->opcode = CTDB_CONTROL_DB_PUSH_START;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DB_PUSH_START;
	request->rdata.data.pulldb_ext = pulldb_ext;
}

int ctdb_reply_control_db_push_start(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_DB_PUSH_START);
}

/* CTDB_CONTROL_DB_PUSH_CONFIRM */

void ctdb_req_control_db_push_confirm(struct ctdb_req_control *request,
				      uint32_t db_id)
{
	request->opcode = CTDB_CONTROL_DB_PUSH_CONFIRM;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DB_PUSH_CONFIRM;
	request->rdata.data.db_id = db_id;
}

int ctdb_reply_control_db_push_confirm(struct ctdb_reply_control *reply,
				       uint32_t *num_records)
{
	if (reply->rdata.opcode != CTDB_CONTROL_DB_PUSH_CONFIRM) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*num_records = reply->rdata.data.num_records;
	}
	return reply->status;
}

/* CTDB_CONTROL_DB_OPEN_FLAGS */

void ctdb_req_control_db_open_flags(struct ctdb_req_control *request,
				    uint32_t db_id)
{
	request->opcode = CTDB_CONTROL_DB_OPEN_FLAGS;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DB_OPEN_FLAGS;
	request->rdata.data.db_id = db_id;
}

int ctdb_reply_control_db_open_flags(struct ctdb_reply_control *reply,
				     int *tdb_flags)
{
	if (reply->rdata.opcode != CTDB_CONTROL_DB_OPEN_FLAGS) {
		return EPROTO;
	}

	if (reply->status == 0) {
		*tdb_flags = reply->rdata.data.tdb_flags;
	}
	return reply->status;
}

/* CTDB_CONTROL_DB_ATTACH_REPLICATED */

void ctdb_req_control_db_attach_replicated(struct ctdb_req_control *request,
					   const char *db_name)
{
	request->opcode = CTDB_CONTROL_DB_ATTACH_REPLICATED;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DB_ATTACH_REPLICATED;
	request->rdata.data.db_name = db_name;
}

int ctdb_reply_control_db_attach_replicated(struct ctdb_reply_control *reply,
					    uint32_t *db_id)
{
	if (reply->rdata.opcode != CTDB_CONTROL_DB_ATTACH_REPLICATED) {
		return EPROTO;
	}
	if (reply->status == 0) {
		*db_id = reply->rdata.data.db_id;
	}
	return reply->status;
}

/* CTDB_CONTROL_CHECK_PID_SRVID */

void ctdb_req_control_check_pid_srvid(struct ctdb_req_control *request,
				      struct ctdb_pid_srvid *pid_srvid)
{
	request->opcode = CTDB_CONTROL_CHECK_PID_SRVID;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_CHECK_PID_SRVID;
	request->rdata.data.pid_srvid = pid_srvid;
}

int ctdb_reply_control_check_pid_srvid(struct ctdb_reply_control *reply,
				       int *status)
{
	if (reply->rdata.opcode != CTDB_CONTROL_CHECK_PID_SRVID) {
		return EPROTO;
	}

	*status = reply->status;
	reply->status = 0;

	return reply->status;
}

/* CTDB_CONTROL_TUNNEL_REGISTER */

void ctdb_req_control_tunnel_register(struct ctdb_req_control *request,
				      uint64_t tunnel_id)
{
	request->opcode = CTDB_CONTROL_TUNNEL_REGISTER;
	request->pad = 0;
	request->srvid = tunnel_id;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_TUNNEL_REGISTER;
}

int ctdb_reply_control_tunnel_register(struct ctdb_reply_control *reply)
{
	if (reply->rdata.opcode != CTDB_CONTROL_TUNNEL_REGISTER) {
		return EPROTO;
	}

	return reply->status;
}

/* CTDB_CONTROL_TUNNEL_DEREGISTER */

void ctdb_req_control_tunnel_deregister(struct ctdb_req_control *request,
					uint64_t tunnel_id)
{
	request->opcode = CTDB_CONTROL_TUNNEL_DEREGISTER;
	request->pad = 0;
	request->srvid = tunnel_id;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_TUNNEL_DEREGISTER;
}

int ctdb_reply_control_tunnel_deregister(struct ctdb_reply_control *reply)
{
	if (reply->rdata.opcode != CTDB_CONTROL_TUNNEL_DEREGISTER) {
		return EPROTO;
	}

	return reply->status;
}

/* CTDB_CONTROL_VACUUM_FETCH */

void ctdb_req_control_vacuum_fetch(struct ctdb_req_control *request,
				   struct ctdb_rec_buffer *recbuf)
{
	request->opcode = CTDB_CONTROL_VACUUM_FETCH;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_VACUUM_FETCH;
	request->rdata.data.recbuf = recbuf;
}

int ctdb_reply_control_vacuum_fetch(struct ctdb_reply_control *reply)
{
	if (reply->rdata.opcode != CTDB_CONTROL_VACUUM_FETCH) {
		return EPROTO;
	}

	return reply->status;
}

/* CTDB_CONTROL_DB_VACUUM */

void ctdb_req_control_db_vacuum(struct ctdb_req_control *request,
				struct ctdb_db_vacuum *db_vacuum)
{
	request->opcode = CTDB_CONTROL_DB_VACUUM;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DB_VACUUM;
	request->rdata.data.db_vacuum = db_vacuum;
}

int ctdb_reply_control_db_vacuum(struct ctdb_reply_control *reply)
{
	if (reply->rdata.opcode != CTDB_CONTROL_DB_VACUUM) {
		return EPROTO;
	}

	return reply->status;
}

/* CTDB_CONTROL_ECHO_DATA */

void ctdb_req_control_echo_data(struct ctdb_req_control *request,
				struct ctdb_echo_data *echo_data)
{
	request->opcode = CTDB_CONTROL_ECHO_DATA;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_ECHO_DATA;
	request->rdata.data.echo_data = echo_data;
}

int ctdb_reply_control_echo_data(struct ctdb_reply_control *reply)
{
	if (reply->rdata.opcode != CTDB_CONTROL_ECHO_DATA) {
		return EPROTO;
	}

	return reply->status;
}

/* CTDB_CONTROL_DISABLE_NODE */

void ctdb_req_control_disable_node(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_DISABLE_NODE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_DISABLE_NODE;
}

int ctdb_reply_control_disable_node(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_DISABLE_NODE);
}

/* CTDB_CONTROL_ENABLE_NODE */

void ctdb_req_control_enable_node(struct ctdb_req_control *request)
{
	request->opcode = CTDB_CONTROL_ENABLE_NODE;
	request->pad = 0;
	request->srvid = 0;
	request->client_id = 0;
	request->flags = 0;

	request->rdata.opcode = CTDB_CONTROL_ENABLE_NODE;
}

int ctdb_reply_control_enable_node(struct ctdb_reply_control *reply)
{
	return ctdb_reply_control_generic(reply, CTDB_CONTROL_ENABLE_NODE);
}
