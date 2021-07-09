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

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"

#include <talloc.h>
#include <tevent.h>
#include <tdb.h>

#include "common/logging.h"

#include "lib/util/debug.h"

#include "protocol/protocol.h"
#include "protocol/protocol_api.h"
#include "client/client_private.h"
#include "client/client.h"
#include "client/client_sync.h"

int ctdb_ctrl_process_exists(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     struct ctdb_client_context *client,
			     int destnode, struct timeval timeout,
			     pid_t pid, int *status)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_process_exists(&request, pid);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control PROCESS_EXISTS failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_process_exists(reply, status);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control PROCESS_EXISTS failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_statistics(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			 struct ctdb_client_context *client,
			 int destnode, struct timeval timeout,
			 struct ctdb_statistics **stats)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_statistics(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control STATISTICS failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_statistics(reply, mem_ctx, stats);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control STATISTICS failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_ping(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		   struct ctdb_client_context *client,
		   int destnode, struct timeval timeout,
		   int *num_clients)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_ping(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control PING failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_ping(reply, num_clients);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control PING failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_getdbpath(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			int destnode, struct timeval timeout,
			uint32_t db_id,
			const char **db_path)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_getdbpath(&request, db_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GETDBPATH failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_getdbpath(reply, mem_ctx, db_path);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GETDBPATH failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_getvnnmap(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			int destnode, struct timeval timeout,
			struct ctdb_vnn_map **vnnmap)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_getvnnmap(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GETVNNMAP failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_getvnnmap(reply, mem_ctx, vnnmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GETVNNMAP failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_getdebug(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		       struct ctdb_client_context *client,
		       int destnode, struct timeval timeout,
		       int *loglevel)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_debug(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_DEBUG failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_debug(reply, loglevel);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_DEBUG failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_setdebug(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		       struct ctdb_client_context *client,
		       int destnode, struct timeval timeout,
		       int loglevel)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_set_debug(&request, loglevel);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_DEBUG failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_set_debug(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_DEBUG failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_dbmap(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			int destnode, struct timeval timeout,
			struct ctdb_dbid_map **dbmap)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_dbmap(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_DBMAP failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_dbmap(reply, mem_ctx, dbmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_DBMAP failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_pull_db(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_client_context *client, int destnode,
		      struct timeval timeout, struct ctdb_pulldb *pulldb,
		      struct ctdb_rec_buffer **recbuf)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_pull_db(&request, pulldb);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control PULL_DB failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_pull_db(reply, mem_ctx, recbuf);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control PULL_DB failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_push_db(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_client_context *client, int destnode,
		      struct timeval timeout, struct ctdb_rec_buffer *recbuf)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_push_db(&request, recbuf);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control PUSH_DB failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_push_db(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control PUSH_DB failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}


int ctdb_ctrl_get_recmode(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct timeval timeout,
			  int *recmode)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_recmode(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_RECMODE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_recmode(reply, recmode);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_RECMODE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_set_recmode(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct timeval timeout,
			  int recmode)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_set_recmode(&request, recmode);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_RECMODE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_set_recmode(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_RECMODE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_statistics_reset(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       struct ctdb_client_context *client,
			       int destnode, struct timeval timeout)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_statistics_reset(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control STATISTICS_RESET failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_statistics_reset(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control STATISTICS_RESET failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_db_attach(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			int destnode, struct timeval timeout,
			const char *db_name, uint32_t *db_id)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_db_attach(&request, db_name);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_ATTACH failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_db_attach(reply, db_id);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_ATTACH failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_traverse_start(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     struct ctdb_client_context *client,
			     int destnode, struct timeval timeout,
			     struct ctdb_traverse_start *traverse)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_traverse_start(&request, traverse);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TRAVERSE_START failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_traverse_start(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TRAVERSE_START failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_register_srvid(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     struct ctdb_client_context *client,
			     int destnode, struct timeval timeout,
			     uint64_t srvid)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_register_srvid(&request, srvid);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control REGISTER_SRVID failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_register_srvid(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control REGISTER_SRVID failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_deregister_srvid(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       struct ctdb_client_context *client,
			       int destnode, struct timeval timeout,
			       uint64_t srvid)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_deregister_srvid(&request, srvid);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DEREGISTER_SRVID failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_deregister_srvid(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DEREGISTER_SRVID failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_dbname(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			 struct ctdb_client_context *client,
			 int destnode, struct timeval timeout,
			 uint32_t db_id, const char **db_name)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_dbname(&request, db_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_DBNAME failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_dbname(reply, mem_ctx, db_name);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_DBNAME failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_enable_seqnum(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t db_id)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_enable_seqnum(&request, db_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control ENABLE_SEQNUM failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_enable_seqnum(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control ENABLE_SEQNUM failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_update_seqnum(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t db_id)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_update_seqnum(&request, db_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control UPDATE_SEQNUM failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_update_seqnum(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control UPDATE_SEQNUM failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_dump_memory(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct timeval timeout,
			  const char **mem_str)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_dump_memory(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DUMP_MEMORY failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_dump_memory(reply, mem_ctx, mem_str);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DUMP_MEMORY failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_pid(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_client_context *client,
		      int destnode, struct timeval timeout,
		      pid_t *pid)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_pid(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_PID failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_pid(reply, pid);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_PID failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_recmaster(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t *recmaster)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_recmaster(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_RECMASTER failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_recmaster(reply, recmaster);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_RECMASTER failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_set_recmaster(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t recmaster)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_set_recmaster(&request, recmaster);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_RECMASTER failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_set_recmaster(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_RECMASTER failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_freeze(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		     struct ctdb_client_context *client,
		     int destnode, struct timeval timeout,
		     int priority)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_freeze(&request, priority);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control FREEZE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_freeze(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control FREEZE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_pnn(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_client_context *client,
		      int destnode, struct timeval timeout,
		      uint32_t *pnn)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_pnn(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_PNN failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_pnn(reply, pnn);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_PNN failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_shutdown(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		       struct ctdb_client_context *client,
		       int destnode, struct timeval timeout)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_shutdown(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SHUTDOWN failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_shutdown(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SHUTDOWN failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_tcp_add(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_client_context *client,
		      int destnode, struct timeval timeout,
		      struct ctdb_connection *conn)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_tcp_add(&request, conn);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TCP_ADD failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_tcp_add(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TCP_ADD failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_tcp_remove(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			 struct ctdb_client_context *client,
			 int destnode, struct timeval timeout,
			 struct ctdb_connection *conn)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_tcp_remove(&request, conn);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TCP_REMOVE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_tcp_remove(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TCP_REMOVE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_set_tunable(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct timeval timeout,
			  struct ctdb_tunable *tunable)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_set_tunable(&request, tunable);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_TUNABLE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_set_tunable(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_TUNABLE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_tunable(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct timeval timeout,
			  const char *var, uint32_t *value)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_tunable(&request, var);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_TUNABLE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_tunable(reply, value);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_TUNABLE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_list_tunables(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    struct ctdb_var_list **var_list)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_list_tunables(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control LIST_TUNABLES failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_list_tunables(reply, mem_ctx, var_list);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control LIST_TUNABLES failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_modify_flags(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			   struct ctdb_client_context *client,
			   int destnode, struct timeval timeout,
			   uint32_t pnn, uint32_t old_flags,
			   uint32_t new_flags)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	struct ctdb_node_flag_change flag_change;
	int ret;

	flag_change.pnn = pnn;
	flag_change.old_flags = old_flags;
	flag_change.new_flags = new_flags;

	ctdb_req_control_modify_flags(&request, &flag_change);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control MODIFY_FLAGS failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_modify_flags(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control MODIFY_FLAGS failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_all_tunables(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       struct ctdb_client_context *client,
			       int destnode, struct timeval timeout,
			       struct ctdb_tunable_list **tun_list)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_all_tunables(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_ALL_TUNABLES failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_all_tunables(reply, mem_ctx, tun_list);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_ALL_TUNABLES failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_tcp_tickle_list(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct ctdb_client_context *client,
				  int destnode, struct timeval timeout,
				  ctdb_sock_addr *addr,
				  struct ctdb_tickle_list **tickles)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_tcp_tickle_list(&request, addr);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_TCP_TICKLE_LIST failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_tcp_tickle_list(reply, mem_ctx, tickles);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_TCP_TICKLE_LIST failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_set_tcp_tickle_list(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct ctdb_client_context *client,
				  int destnode, struct timeval timeout,
				  struct ctdb_tickle_list *tickles)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_set_tcp_tickle_list(&request, tickles);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_TCP_TICKLE_LIST failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_set_tcp_tickle_list(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_TCP_TICKLE_LIST failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_db_attach_persistent(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct ctdb_client_context *client,
				   int destnode, struct timeval timeout,
				   const char *db_name, uint32_t *db_id)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_db_attach_persistent(&request, db_name);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_ATTACH_PERSISTENT failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_db_attach_persistent(reply, db_id);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_ATTACH_PERSISTENT failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_send_gratuitous_arp(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct ctdb_client_context *client,
				  int destnode, struct timeval timeout,
				  struct ctdb_addr_info *addr_info)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_send_gratuitous_arp(&request, addr_info);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SEND_GRATUITOUS_ARP failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_send_gratuitous_arp(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SEND_GRATUITOUS_ARP failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_wipe_database(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t db_id, uint32_t tid)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	struct ctdb_transdb transdb;
	int ret;

	transdb.db_id = db_id;
	transdb.tid = tid;

	ctdb_req_control_wipe_database(&request, &transdb);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control WIPE_DATABASE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_wipe_database(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control WIPE_DATABASE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_uptime(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		     struct ctdb_client_context *client,
		     int destnode, struct timeval timeout,
		     struct ctdb_uptime **uptime)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_uptime(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control UPTIME failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_uptime(reply, mem_ctx, uptime);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control UPTIME failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_start_recovery(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     struct ctdb_client_context *client,
			     int destnode, struct timeval timeout)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_start_recovery(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control START_RECOVERY failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_start_recovery(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control START_RECOVERY failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_end_recovery(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			   struct ctdb_client_context *client,
			   int destnode, struct timeval timeout)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_end_recovery(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control END_RECOVERY failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_end_recovery(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control END_RECOVERY failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_reload_nodes_file(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct ctdb_client_context *client,
				int destnode, struct timeval timeout)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_reload_nodes_file(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control RELOAD_NODES_FILE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_reload_nodes_file(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control RELOAD_NODES_FILE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_add_public_ip(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    struct ctdb_addr_info *addr_info)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_add_public_ip(&request, addr_info);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control ADD_PUBLIC_IP failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_add_public_ip(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control ADD_PUBLIC_IP failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_del_public_ip(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    struct ctdb_addr_info *addr_info)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_del_public_ip(&request, addr_info);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DEL_PUBLIC_IP failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_del_public_ip(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DEL_PUBLIC_IP failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_capabilities(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       struct ctdb_client_context *client,
			       int destnode, struct timeval timeout,
			       uint32_t *caps)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_capabilities(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_CAPABILITIES failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_capabilities(reply, caps);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_CAPABILITIES failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_release_ip(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			 struct ctdb_client_context *client,
			 int destnode, struct timeval timeout,
			 struct ctdb_public_ip *pubip)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_release_ip(&request, pubip);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control RELEASE_IP failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_release_ip(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control RELEASE_IP failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_takeover_ip(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct timeval timeout,
			  struct ctdb_public_ip *pubip)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_takeover_ip(&request, pubip);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TAKEOVER_IP failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_takeover_ip(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TAKEOVER_IP failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_public_ips(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     struct ctdb_client_context *client,
			     int destnode, struct timeval timeout,
			     bool available_only,
			     struct ctdb_public_ip_list **pubip_list)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_public_ips(&request, available_only);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_PUBLIC_IPS failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_public_ips(reply, mem_ctx, pubip_list);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_PUBLIC_IPS failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_nodemap(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct timeval timeout,
			  struct ctdb_node_map **nodemap)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_nodemap(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_NODEMAP failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_nodemap(reply, mem_ctx, nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_NODEMAP failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_traverse_kill(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    struct ctdb_traverse_start *traverse)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_traverse_kill(&request, traverse);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TRAVERSE_KILL failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_traverse_kill(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TRAVERSE_KILL failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_reclock_file(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       struct ctdb_client_context *client,
			       int destnode, struct timeval timeout,
			       const char **reclock_file)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_reclock_file(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_RECLOCK_FILE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_reclock_file(reply, mem_ctx, reclock_file);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_RECLOCK_FILE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_stop_node(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			int destnode, struct timeval timeout)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_stop_node(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control STOP_NODE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_stop_node(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control STOP_NODE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_continue_node(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_continue_node(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control CONTINUE_NODE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_continue_node(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control CONTINUE_NODE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_set_lmasterrole(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      int destnode, struct timeval timeout,
			      uint32_t lmaster_role)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_set_lmasterrole(&request, lmaster_role);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_LMASTERROLE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_set_lmasterrole(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_LMASTERROLE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_set_recmasterrole(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct ctdb_client_context *client,
				int destnode, struct timeval timeout,
				uint32_t recmaster_role)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_set_recmasterrole(&request, recmaster_role);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_RECMASTERROLE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_set_recmasterrole(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_RECMASTERROLE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_set_ban_state(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    struct ctdb_ban_state *ban_state)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_set_ban_state(&request, ban_state);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_BAN_STATE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_set_ban_state(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_BAN_STATE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_ban_state(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    struct ctdb_ban_state **ban_state)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_ban_state(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_BAN_STATE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_ban_state(reply, mem_ctx, ban_state);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_BAN_STATE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_register_notify(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      int destnode, struct timeval timeout,
			      struct ctdb_notify_data *notify)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_register_notify(&request, notify);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control REGISTER_NOTIFY failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_register_notify(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control REGISTER_NOTIFY failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_deregister_notify(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct ctdb_client_context *client,
				int destnode, struct timeval timeout,
				uint64_t srvid)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_deregister_notify(&request, srvid);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DEREGISTER_NOTIFY failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_deregister_notify(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DEREGISTER_NOTIFY failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_trans3_commit(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    struct ctdb_rec_buffer *recbuf)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_trans3_commit(&request, recbuf);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TRANS3_COMMIT failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_trans3_commit(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TRANS3_COMMIT failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_db_seqnum(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t db_id, uint64_t *seqnum)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_db_seqnum(&request, db_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_DB_SEQNUM failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_db_seqnum(reply, seqnum);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_DB_SEQNUM failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_db_set_healthy(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     struct ctdb_client_context *client,
			     int destnode, struct timeval timeout,
			     uint32_t db_id)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_db_set_healthy(&request, db_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_SET_HEALTHY failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_db_set_healthy(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_SET_HEALTHY failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_db_get_health(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t db_id, const char **reason)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_db_get_health(&request, db_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_GET_HEALTH failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_db_get_health(reply, mem_ctx, reason);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_GET_HEALTH failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_public_ip_info(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 struct ctdb_client_context *client,
				 int destnode, struct timeval timeout,
				 ctdb_sock_addr *addr,
				 struct ctdb_public_ip_info **ipinfo)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_public_ip_info(&request, addr);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_PUBLIC_IP_INFO failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_public_ip_info(reply, mem_ctx, ipinfo);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_PUBLIC_IP_INFO failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_ifaces(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			 struct ctdb_client_context *client,
			 int destnode, struct timeval timeout,
			 struct ctdb_iface_list **iface_list)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_ifaces(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_IFACES failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_ifaces(reply, mem_ctx, iface_list);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_IFACES failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_set_iface_link_state(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct ctdb_client_context *client,
				   int destnode, struct timeval timeout,
				   struct ctdb_iface *iface)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_set_iface_link_state(&request, iface);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_IFACE_LINK_STATE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_set_iface_link_state(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_IFACE_LINK_STATE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_tcp_add_delayed_update(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct ctdb_client_context *client,
				     int destnode, struct timeval timeout,
				     struct ctdb_connection *conn)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_tcp_add_delayed_update(&request, conn);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TCP_ADD_DELAYED_UPDATE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_tcp_add_delayed_update(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TCP_ADD_DELAYED_UPDATE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_stat_history(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       struct ctdb_client_context *client,
			       int destnode, struct timeval timeout,
			       struct ctdb_statistics_list **stats_list)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_stat_history(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_STAT_HISTORY failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_stat_history(reply, mem_ctx, stats_list);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_STAT_HISTORY failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_schedule_for_deletion(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    int destnode, struct timeval timeout,
				    struct ctdb_key_data *key)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_schedule_for_deletion(&request, key);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SCHEDULE_FOR_DELETION failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_schedule_for_deletion(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SCHEDULE_FOR_DELETION failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_set_db_readonly(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      int destnode, struct timeval timeout,
			      uint32_t db_id)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_set_db_readonly(&request, db_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_DB_READONY failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_set_db_readonly(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_DB_READONY failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_traverse_start_ext(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 struct ctdb_client_context *client,
				 int destnode, struct timeval timeout,
				 struct ctdb_traverse_start_ext *traverse)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_traverse_start_ext(&request, traverse);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TRAVERSE_START_EXT failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_traverse_start_ext(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TRAVERSE_START_EXT failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_db_statistics(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct ctdb_client_context *client,
				int destnode, struct timeval timeout,
				uint32_t db_id,
				struct ctdb_db_statistics **dbstats)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_db_statistics(&request, db_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_DB_STATISTICS failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_db_statistics(reply, mem_ctx, dbstats);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_DB_STATISTICS failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_set_db_sticky(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t db_id)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_set_db_sticky(&request, db_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_DB_STICKY failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_set_db_sticky(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control SET_DB_STICKY failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_reload_public_ips(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct ctdb_client_context *client,
				int destnode, struct timeval timeout)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_reload_public_ips(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control RELOAD_PUBLIC_IPS failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_reload_public_ips(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control RELOAD_PUBLIC_IPS failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_ipreallocated(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_ipreallocated(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control IPREALLOCATED failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_ipreallocated(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control IPREALLOCATED failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_runstate(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			   struct ctdb_client_context *client,
			   int destnode, struct timeval timeout,
			   enum ctdb_runstate *runstate)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_runstate(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_RUNSTATE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_runstate(reply, runstate);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_RUNSTATE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_db_detach(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			int destnode, struct timeval timeout,
			uint32_t db_id)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_db_detach(&request, db_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_DETACH failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_db_detach(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_DETACH failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_get_nodes_file(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     struct ctdb_client_context *client,
			     int destnode, struct timeval timeout,
			     struct ctdb_node_map **nodemap)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_get_nodes_file(&request);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_NODES_FILE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_get_nodes_file(reply, mem_ctx, nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control GET_NODES_FILE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_db_freeze(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			int destnode, struct timeval timeout, uint32_t db_id)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_db_freeze(&request, db_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_FREEZE failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_db_freeze(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_FREEZE failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_db_thaw(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_client_context *client,
		      int destnode, struct timeval timeout, uint32_t db_id)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_db_thaw(&request, db_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_THAW failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_db_thaw(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_THAW failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_db_transaction_start(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct ctdb_client_context *client,
				   int destnode, struct timeval timeout,
				   struct ctdb_transdb *transdb)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_db_transaction_start(&request, transdb);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_TRANSACTION_START failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_db_transaction_start(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_TRANSACTION_START failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_db_transaction_commit(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    int destnode, struct timeval timeout,
				    struct ctdb_transdb *transdb)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_db_transaction_commit(&request, transdb);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_TRANSACTION_COMMIT failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_db_transaction_commit(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_TRANSACTION_COMMIT failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_db_transaction_cancel(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    int destnode, struct timeval timeout,
				    uint32_t db_id)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_db_transaction_cancel(&request, db_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_TRANSACTION_CANCEL failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_db_transaction_cancel(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_TRANSACTION_CANCEL failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_db_pull(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_client_context *client,
		      int destnode, struct timeval timeout,
		      struct ctdb_pulldb_ext *pulldb, uint32_t *num_records)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_db_pull(&request, pulldb);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_PULL failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_db_pull(reply, num_records);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Control DB_PULL failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_db_push_start(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    struct ctdb_pulldb_ext *pulldb)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_db_push_start(&request, pulldb);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_PUSH_START failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_db_push_start(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_PUSH_START failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_db_push_confirm(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      int destnode, struct timeval timeout,
			      uint32_t db_id, uint32_t *num_records)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_db_push_confirm(&request, db_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_PUSH_CONFIRM failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_db_push_confirm(reply, num_records);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_PUSH_CONFIRM failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_db_open_flags(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t db_id, int *tdb_flags)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_db_open_flags(&request, db_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_OPEN_FLAGS failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_db_open_flags(reply, tdb_flags);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_OPEN_FLAGS failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_db_attach_replicated(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct ctdb_client_context *client,
				   int destnode, struct timeval timeout,
				   const char *db_name, uint32_t *db_id)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_db_attach_replicated(&request, db_name);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_ATTACH_REPLICATED failed to node %u,"
		       " ret=%d\n", destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_db_attach_replicated(reply, db_id);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control DB_ATTACH_REPLICATED failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_check_pid_srvid(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      int destnode, struct timeval timeout,
			      struct ctdb_pid_srvid *pid_srvid, int *status)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_check_pid_srvid(&request, pid_srvid);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control CHECK_PID_SRVID failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_check_pid_srvid(reply, status);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control CHECK_PID_SRVID failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_tunnel_register(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      int destnode, struct timeval timeout,
			      uint64_t tunnel_id)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_tunnel_register(&request, tunnel_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TUNNEL_REGISTER failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_tunnel_register(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TUNNEL_REGISTER failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_tunnel_deregister(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct ctdb_client_context *client,
				int destnode, struct timeval timeout,
				uint64_t tunnel_id)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_tunnel_deregister(&request, tunnel_id);
	ret = ctdb_client_control(mem_ctx, ev, client, destnode, timeout,
				  &request, &reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TUNNEL_DEREGISTER failed to node %u, ret=%d\n",
		       destnode, ret));
		return ret;
	}

	ret = ctdb_reply_control_tunnel_deregister(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Control TUNNEL_DEREGISTER failed, ret=%d\n", ret));
		return ret;
	}

	return 0;
}

int ctdb_ctrl_disable_node(TALLOC_CTX *mem_ctx,
			   struct tevent_context *ev,
			   struct ctdb_client_context *client,
			   int destnode,
			   struct timeval timeout)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_disable_node(&request);
	ret = ctdb_client_control(mem_ctx,
				  ev,
				  client,
				  destnode,
				  timeout,
				  &request,
				  &reply);
	if (ret != 0) {
		D_ERR("Control DISABLE_NODE failed to node %u, ret=%d\n",
		      destnode,
		      ret);
		return ret;
	}

	ret = ctdb_reply_control_disable_node(reply);
	if (ret != 0) {
		D_ERR("Control DISABLE_NODE failed, ret=%d\n", ret);
		return ret;
	}

	return 0;
}

int ctdb_ctrl_enable_node(TALLOC_CTX *mem_ctx,
			  struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode,
			  struct timeval timeout)
{
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	int ret;

	ctdb_req_control_enable_node(&request);
	ret = ctdb_client_control(mem_ctx,
				  ev,
				  client,
				  destnode,
				  timeout,
				  &request,
				  &reply);
	if (ret != 0) {
		D_ERR("Control ENABLE_NODE failed to node %u, ret=%d\n",
		      destnode,
		      ret);
		return ret;
	}

	ret = ctdb_reply_control_enable_node(reply);
	if (ret != 0) {
		D_ERR("Control ENABLE_NODE failed, ret=%d\n", ret);
		return ret;
	}

	return 0;
}
