/* 
   ctdb_control protocol code

   Copyright (C) Andrew Tridgell  2007

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
#include "system/wait.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/dlinklist.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "lib/util/talloc_report.h"

#include "ctdb_private.h"
#include "ctdb_client.h"

#include "protocol/protocol_private.h"

#include "common/reqid.h"
#include "common/common.h"
#include "common/logging.h"


struct ctdb_control_state {
	struct ctdb_context *ctdb;
	uint32_t reqid;
	ctdb_control_callback_fn_t callback;
	void *private_data;
	unsigned flags;
};


/*
  dump talloc memory hierarchy, returning it as a blob to the client
 */
int32_t ctdb_dump_memory(struct ctdb_context *ctdb, TDB_DATA *outdata)
{
	char *report;
	size_t reportlen;

	report = talloc_report_str(outdata, NULL);
	if (report == NULL) {
		DEBUG(DEBUG_ERR,
		      (__location__ " talloc_report_str failed\n"));
		return -1;
	}
	reportlen = talloc_get_size(report);

	if (reportlen > 0) {
		reportlen -= 1;	/* strip trailing zero */
	}

	outdata->dptr = (uint8_t *)report;
	outdata->dsize = reportlen;
	return 0;
}

static int32_t control_not_implemented(const char *unsupported,
				       const char *alternate)
{
	if (alternate == NULL) {
		DEBUG(DEBUG_ERR,
		      ("Control %s is not implemented any more\n",
		       unsupported));
	} else {
		DEBUG(DEBUG_ERR,
		      ("Control %s is not implemented any more, use %s instead\n",
		       unsupported, alternate));
	}
	return -1;
}

struct ctdb_echo_data_state {
	struct ctdb_context *ctdb;
	struct ctdb_req_control_old *c;
	struct ctdb_echo_data *data;
};

static void ctdb_echo_data_timeout(
	struct tevent_context *ev,
	struct tevent_timer *te,
	struct timeval now,
	void *private_data);

static int32_t ctdb_control_echo_data(
	struct ctdb_context *ctdb,
	struct ctdb_req_control_old *c,
	TDB_DATA indata,
	bool *async_reply)
{
	struct ctdb_echo_data_state *state = NULL;
	struct tevent_timer *te = NULL;
	uint32_t delay = 0;
	size_t np = 0;
	int ret;

	state = talloc_zero(ctdb, struct ctdb_echo_data_state);
	CTDB_NO_MEMORY(ctdb, state);
	state->ctdb = ctdb;

	ret = ctdb_echo_data_pull(
		indata.dptr, indata.dsize, state, &state->data, &np);
	if (ret != 0) {
		DBG_DEBUG("ctdb_echo_data_pull failed: %s\n",
			  strerror(ret));
		TALLOC_FREE(state);
		return -1;
	}

	te = tevent_add_timer(
		ctdb->ev,
		state,
		timeval_current_ofs_msec(delay),
		ctdb_echo_data_timeout,
		state);
	if (te == NULL) {
		DBG_DEBUG("tevent_add_timer failed\n");
		TALLOC_FREE(state);
		return -1;
	}

	state->c = talloc_move(state, &c);
	*async_reply = true;

	return 0;
}

static void ctdb_echo_data_timeout(
	struct tevent_context *ev,
	struct tevent_timer *te,
	struct timeval now,
	void *private_data)
{
	struct ctdb_echo_data_state *state = talloc_get_type_abort(
		private_data, struct ctdb_echo_data_state);
	size_t len = ctdb_echo_data_len(state->data);
	uint8_t *buf = NULL;
	size_t np;
	TDB_DATA data;

	DBG_DEBUG("reqid=%"PRIu32" len=%zu\n", state->c->hdr.reqid, len);

	buf = talloc_array(state, uint8_t, len);
	if (buf == NULL) {
		DBG_WARNING("talloc_array(%zu) failed\n", len);
		goto done;
	}
	ctdb_echo_data_push(state->data, buf, &np);
	data = (TDB_DATA) { .dptr = buf, .dsize = np };

	ctdb_request_control_reply(state->ctdb, state->c, &data, 0, NULL);

done:
	TALLOC_FREE(state);
}

static int ctdb_control_disable_node(struct ctdb_context *ctdb)
{
	struct ctdb_node *node;

	node = ctdb_find_node(ctdb, CTDB_CURRENT_NODE);
	if (node == NULL) {
		/* Can't happen */
		DBG_ERR("Unable to find current node\n");
		return -1;
	}

	D_ERR("Disable node\n");
	node->flags |= NODE_FLAGS_PERMANENTLY_DISABLED;

	return 0;
}

static int ctdb_control_enable_node(struct ctdb_context *ctdb)
{
	struct ctdb_node *node;

	node = ctdb_find_node(ctdb, CTDB_CURRENT_NODE);
	if (node == NULL) {
		/* Can't happen */
		DBG_ERR("Unable to find current node\n");
		return -1;
	}

	D_ERR("Enable node\n");
	node->flags &= ~NODE_FLAGS_PERMANENTLY_DISABLED;

	return 0;
}

/*
  process a control request
 */
static int32_t ctdb_control_dispatch(struct ctdb_context *ctdb, 
				     struct ctdb_req_control_old *c,
				     TDB_DATA indata,
				     TDB_DATA *outdata, uint32_t srcnode,
				     const char **errormsg,
				     bool *async_reply)
{
	uint32_t opcode = c->opcode;
	uint64_t srvid = c->srvid;
	uint32_t client_id = c->client_id;
	static int level = DEBUG_ERR;

	switch (opcode) {
	case CTDB_CONTROL_PROCESS_EXISTS: {
		CHECK_CONTROL_DATA_SIZE(sizeof(pid_t));
		return ctdb_control_process_exists(ctdb, *(pid_t *)indata.dptr);
	}

	case CTDB_CONTROL_SET_DEBUG: {
		union {
			uint8_t *ptr;
			int32_t *level;
		} debug;
		CHECK_CONTROL_DATA_SIZE(sizeof(int32_t));
		debug.ptr = indata.dptr;
		debuglevel_set(*debug.level);
		return 0;
	}

	case CTDB_CONTROL_GET_DEBUG: {
		CHECK_CONTROL_DATA_SIZE(0);
		level = debuglevel_get();
		outdata->dptr = (uint8_t *)&(level);
		outdata->dsize = sizeof(DEBUGLEVEL);
		return 0;
	}

	case CTDB_CONTROL_STATISTICS: {
		CHECK_CONTROL_DATA_SIZE(0);
		ctdb->statistics.memory_used = talloc_total_size(NULL);
		ctdb->statistics.num_clients = ctdb->num_clients;
		ctdb->statistics.frozen = (ctdb_db_all_frozen(ctdb) ? 1 : 0);
		ctdb->statistics.recovering = (ctdb->recovery_mode == CTDB_RECOVERY_ACTIVE);
		ctdb->statistics.statistics_current_time = timeval_current();

		outdata->dptr = (uint8_t *)&ctdb->statistics;
		outdata->dsize = sizeof(ctdb->statistics);
		return 0;
	}

	case CTDB_CONTROL_GET_ALL_TUNABLES: {
		CHECK_CONTROL_DATA_SIZE(0);
		outdata->dptr = (uint8_t *)&ctdb->tunable;
		outdata->dsize = sizeof(ctdb->tunable);
		return 0;
	}

	case CTDB_CONTROL_DUMP_MEMORY: {
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_dump_memory(ctdb, outdata);
	}

	case CTDB_CONTROL_STATISTICS_RESET: {
		struct ctdb_db_context *ctdb_db;

		CHECK_CONTROL_DATA_SIZE(0);
		ZERO_STRUCT(ctdb->statistics);
		for (ctdb_db = ctdb->db_list;
		     ctdb_db != NULL;
		     ctdb_db = ctdb_db->next) {
			ctdb_db_statistics_reset(ctdb_db);
		}
		ctdb->statistics.statistics_start_time = timeval_current();
		return 0;
	}

	case CTDB_CONTROL_GETVNNMAP:
		return ctdb_control_getvnnmap(ctdb, opcode, indata, outdata);

	case CTDB_CONTROL_GET_DBMAP:
		return ctdb_control_getdbmap(ctdb, opcode, indata, outdata);

	case CTDB_CONTROL_GET_NODEMAPv4:
		return control_not_implemented("GET_NODEMAPv4", "GET_NODEMAP");

	case CTDB_CONTROL_GET_NODEMAP:
		return ctdb_control_getnodemap(ctdb, opcode, indata, outdata);

	case CTDB_CONTROL_GET_NODES_FILE:
		return ctdb_control_getnodesfile(ctdb, opcode, indata, outdata);

	case CTDB_CONTROL_RELOAD_NODES_FILE:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_reload_nodes_file(ctdb, opcode);

	case CTDB_CONTROL_SET_DB_STICKY: {
		uint32_t db_id;
		struct ctdb_db_context *ctdb_db;

		CHECK_CONTROL_DATA_SIZE(sizeof(db_id));
		db_id = *(uint32_t *)indata.dptr;
		ctdb_db = find_ctdb_db(ctdb, db_id);
		if (ctdb_db == NULL) return -1;
		return ctdb_set_db_sticky(ctdb, ctdb_db);
	}

	case CTDB_CONTROL_SETVNNMAP:
		return ctdb_control_setvnnmap(ctdb, opcode, indata, outdata);

	case CTDB_CONTROL_PULL_DB: 
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_pulldb));
		return ctdb_control_pull_db(ctdb, indata, outdata);

	case CTDB_CONTROL_SET_DMASTER: 
		return control_not_implemented("SET_DMASTER", NULL);

	case CTDB_CONTROL_PUSH_DB:
		return ctdb_control_push_db(ctdb, indata);

	case CTDB_CONTROL_GET_RECMODE: {
		return ctdb->recovery_mode;
	}

	case CTDB_CONTROL_SET_RECMASTER: {
		return ctdb_control_set_recmaster(ctdb, opcode, indata);
	}

	case CTDB_CONTROL_GET_RECMASTER:
		return ctdb->recovery_master;

	case CTDB_CONTROL_GET_PID:
		return getpid();

	case CTDB_CONTROL_GET_PNN:
		return ctdb->pnn;

	case CTDB_CONTROL_PING:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb->num_clients;

	case CTDB_CONTROL_GET_RUNSTATE:
		CHECK_CONTROL_DATA_SIZE(0);
		outdata->dptr = (uint8_t *)&ctdb->runstate;
		outdata->dsize = sizeof(uint32_t);
		return 0;


	case CTDB_CONTROL_SET_DB_READONLY: {
		uint32_t db_id;
		struct ctdb_db_context *ctdb_db;

		CHECK_CONTROL_DATA_SIZE(sizeof(db_id));
		db_id = *(uint32_t *)indata.dptr;
		ctdb_db = find_ctdb_db(ctdb, db_id);
		if (ctdb_db == NULL) return -1;
		return ctdb_set_db_readonly(ctdb, ctdb_db);
	}
	case CTDB_CONTROL_GET_DBNAME: {
		uint32_t db_id;
		struct ctdb_db_context *ctdb_db;

		CHECK_CONTROL_DATA_SIZE(sizeof(db_id));
		db_id = *(uint32_t *)indata.dptr;
		ctdb_db = find_ctdb_db(ctdb, db_id);
		if (ctdb_db == NULL) return -1;
		outdata->dptr = discard_const(ctdb_db->db_name);
		outdata->dsize = strlen(ctdb_db->db_name)+1;
		return 0;
	}

	case CTDB_CONTROL_GETDBPATH: {
		uint32_t db_id;
		struct ctdb_db_context *ctdb_db;

		CHECK_CONTROL_DATA_SIZE(sizeof(db_id));
		db_id = *(uint32_t *)indata.dptr;
		ctdb_db = find_ctdb_db(ctdb, db_id);
		if (ctdb_db == NULL) return -1;
		outdata->dptr = discard_const(ctdb_db->db_path);
		outdata->dsize = strlen(ctdb_db->db_path)+1;
		return 0;
	}

	case CTDB_CONTROL_DB_ATTACH:
	  return ctdb_control_db_attach(ctdb,
					indata,
					outdata,
					0,
					srcnode,
					client_id,
					c,
					async_reply);

	case CTDB_CONTROL_DB_ATTACH_PERSISTENT:
	  return ctdb_control_db_attach(ctdb,
					indata,
					outdata,
					CTDB_DB_FLAGS_PERSISTENT,
					srcnode,
					client_id,
					c,
					async_reply);

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
	  return ctdb_control_db_attach(ctdb,
					indata,
					outdata,
					CTDB_DB_FLAGS_REPLICATED,
					srcnode,
					client_id,
					c,
					async_reply);

	case CTDB_CONTROL_SET_CALL:
		return control_not_implemented("SET_CALL", NULL);

	case CTDB_CONTROL_TRAVERSE_START:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_traverse_start));
		return ctdb_control_traverse_start(ctdb, indata, outdata, srcnode, client_id);

	case CTDB_CONTROL_TRAVERSE_START_EXT:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_traverse_start_ext));
		return ctdb_control_traverse_start_ext(ctdb, indata, outdata, srcnode, client_id);

	case CTDB_CONTROL_TRAVERSE_ALL:
		return ctdb_control_traverse_all(ctdb, indata, outdata);

	case CTDB_CONTROL_TRAVERSE_ALL_EXT:
		return ctdb_control_traverse_all_ext(ctdb, indata, outdata);

	case CTDB_CONTROL_TRAVERSE_DATA:
		return ctdb_control_traverse_data(ctdb, indata, outdata);

	case CTDB_CONTROL_TRAVERSE_KILL:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_traverse_start));
		return ctdb_control_traverse_kill(ctdb, indata, outdata, srcnode);

	case CTDB_CONTROL_REGISTER_SRVID:
		return daemon_register_message_handler(ctdb, client_id, srvid);

	case CTDB_CONTROL_DEREGISTER_SRVID:
		return daemon_deregister_message_handler(ctdb, client_id, srvid);

	case CTDB_CONTROL_CHECK_SRVIDS:
		return control_not_implemented("CHECK_SRVIDS", NULL);

	case CTDB_CONTROL_ENABLE_SEQNUM:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));
		return ctdb_ltdb_enable_seqnum(ctdb, *(uint32_t *)indata.dptr);

	case CTDB_CONTROL_UPDATE_SEQNUM:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));		
		return ctdb_ltdb_update_seqnum(ctdb, *(uint32_t *)indata.dptr, srcnode);

	case CTDB_CONTROL_FREEZE:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_freeze(ctdb, c, async_reply);

	case CTDB_CONTROL_THAW:
		return control_not_implemented("THAW", NULL);

	case CTDB_CONTROL_SET_RECMODE:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));		
		return ctdb_control_set_recmode(ctdb, c, indata, async_reply, errormsg);

	case CTDB_CONTROL_GET_MONMODE:
		return control_not_implemented("GET_MONMODE", NULL);

	case CTDB_CONTROL_ENABLE_MONITOR:
		return control_not_implemented("ENABLE_MONITOR", NULL);

	case CTDB_CONTROL_RUN_EVENTSCRIPTS:
		return control_not_implemented("RUN_EVENTSCRIPTS", NULL);

	case CTDB_CONTROL_DISABLE_MONITOR:
		return control_not_implemented("DISABLE_MONITOR", NULL);

	case CTDB_CONTROL_SHUTDOWN:
		DEBUG(DEBUG_NOTICE,("Received SHUTDOWN command.\n"));
		ctdb_shutdown_sequence(ctdb, 0);
		/* In case above returns due to duplicate shutdown */
		return 0;

	case CTDB_CONTROL_TAKEOVER_IPv4:
		return control_not_implemented("TAKEOVER_IPv4", "TAKEOVER_IP");

	case CTDB_CONTROL_TAKEOVER_IP:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_public_ip));
		return ctdb_control_takeover_ip(ctdb, c, indata, async_reply);

	case CTDB_CONTROL_RELEASE_IPv4:
		return control_not_implemented("RELEASE_IPv4", "RELEASE_IP");

	case CTDB_CONTROL_RELEASE_IP:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_public_ip));
		return ctdb_control_release_ip(ctdb, c, indata, async_reply);

	case CTDB_CONTROL_IPREALLOCATED:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_ipreallocated(ctdb, c, async_reply);

	case CTDB_CONTROL_GET_PUBLIC_IPSv4:
		return control_not_implemented("GET_PUBLIC_IPSv4",
					       "GET_PUBLIC_IPS");

	case CTDB_CONTROL_GET_PUBLIC_IPS:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_get_public_ips(ctdb, c, outdata);

	case CTDB_CONTROL_TCP_CLIENT:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_connection));
		return ctdb_control_tcp_client(ctdb, client_id, indata);

	case CTDB_CONTROL_STARTUP: 
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_startup(ctdb, srcnode);

	case CTDB_CONTROL_TCP_ADD: 
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_connection));
		return ctdb_control_tcp_add(ctdb, indata, false);

	case CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE: 
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_connection));
		return ctdb_control_tcp_add(ctdb, indata, true);

	case CTDB_CONTROL_TCP_REMOVE: 
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_connection));
		return ctdb_control_tcp_remove(ctdb, indata);

	case CTDB_CONTROL_SET_TUNABLE:
		return ctdb_control_set_tunable(ctdb, indata);

	case CTDB_CONTROL_GET_TUNABLE:
		return ctdb_control_get_tunable(ctdb, indata, outdata);

	case CTDB_CONTROL_LIST_TUNABLES:
		return ctdb_control_list_tunables(ctdb, outdata);

	case CTDB_CONTROL_MODIFY_FLAGS:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_node_flag_change));
		return ctdb_control_modflags(ctdb, indata);

	case CTDB_CONTROL_KILL_TCP:
		return control_not_implemented("KILL_TCP", NULL);

	case CTDB_CONTROL_GET_TCP_TICKLE_LIST:
		CHECK_CONTROL_DATA_SIZE(sizeof(ctdb_sock_addr));
		return ctdb_control_get_tcp_tickle_list(ctdb, indata, outdata);

	case CTDB_CONTROL_SET_TCP_TICKLE_LIST:
		/* data size is verified in the called function */
		return ctdb_control_set_tcp_tickle_list(ctdb, indata);

	case CTDB_CONTROL_REGISTER_SERVER_ID:
		return control_not_implemented("REGISTER_SERVER_ID", NULL);

	case CTDB_CONTROL_UNREGISTER_SERVER_ID:
		return control_not_implemented("UNREGISTER_SERVER_ID", NULL);

	case CTDB_CONTROL_CHECK_SERVER_ID:
		return control_not_implemented("CHECK_SERVER_ID", NULL);

	case CTDB_CONTROL_GET_SERVER_ID_LIST:
		return control_not_implemented("SERVER_ID_LIST", NULL);

	case CTDB_CONTROL_PERSISTENT_STORE:
		return control_not_implemented("PERSISTENT_STORE", NULL);

	case CTDB_CONTROL_UPDATE_RECORD:
		return ctdb_control_update_record(ctdb, c, indata, async_reply);

	case CTDB_CONTROL_SEND_GRATUITOUS_ARP:
		return ctdb_control_send_gratious_arp(ctdb, indata);

	case CTDB_CONTROL_TRANSACTION_START:
		return control_not_implemented("TRANSACTION_START", NULL);

	case CTDB_CONTROL_TRANSACTION_COMMIT:
		return control_not_implemented("TRANSACTION_COMMIT", NULL);

	case CTDB_CONTROL_WIPE_DATABASE:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_transdb));
		return ctdb_control_wipe_database(ctdb, indata);

	case CTDB_CONTROL_UPTIME:
		return ctdb_control_uptime(ctdb, outdata);

	case CTDB_CONTROL_START_RECOVERY:
		return ctdb_control_start_recovery(ctdb, c, async_reply);

	case CTDB_CONTROL_END_RECOVERY:
		return ctdb_control_end_recovery(ctdb, c, async_reply);

	case CTDB_CONTROL_TRY_DELETE_RECORDS:
		return ctdb_control_try_delete_records(ctdb, indata, outdata);

	case CTDB_CONTROL_ADD_PUBLIC_IP:
		return ctdb_control_add_public_address(ctdb, indata);

	case CTDB_CONTROL_DEL_PUBLIC_IP:
		return ctdb_control_del_public_address(ctdb, indata);

	case CTDB_CONTROL_GET_CAPABILITIES:
		return ctdb_control_get_capabilities(ctdb, outdata);

	case CTDB_CONTROL_START_PERSISTENT_UPDATE:
		return ctdb_control_start_persistent_update(ctdb, c, indata);

	case CTDB_CONTROL_CANCEL_PERSISTENT_UPDATE:
		return ctdb_control_cancel_persistent_update(ctdb, c, indata);

	case CTDB_CONTROL_TRANS2_COMMIT:
	case CTDB_CONTROL_TRANS2_COMMIT_RETRY:
		return control_not_implemented("TRANS2_COMMIT", "TRANS3_COMMIT");

	case CTDB_CONTROL_TRANS2_ERROR:
		return control_not_implemented("TRANS2_ERROR", NULL);

	case CTDB_CONTROL_TRANS2_FINISHED:
		return control_not_implemented("TRANS2_FINISHED", NULL);

	case CTDB_CONTROL_TRANS2_ACTIVE:
		return control_not_implemented("TRANS2_ACTIVE", NULL);

	case CTDB_CONTROL_TRANS3_COMMIT:
		return ctdb_control_trans3_commit(ctdb, c, indata, async_reply);

	case CTDB_CONTROL_RECD_PING:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_recd_ping(ctdb);

	case CTDB_CONTROL_GET_EVENT_SCRIPT_STATUS:
		return control_not_implemented("GET_EVENT_SCRIPT_STATUS", NULL);

	case CTDB_CONTROL_RECD_RECLOCK_LATENCY:
		CHECK_CONTROL_DATA_SIZE(sizeof(double));
		CTDB_UPDATE_RECLOCK_LATENCY(ctdb, "recd reclock", reclock.recd, *((double *)indata.dptr));
		return 0;
	case CTDB_CONTROL_GET_RECLOCK_FILE:
		CHECK_CONTROL_DATA_SIZE(0);
		if (ctdb->recovery_lock != NULL) {
			outdata->dptr  = discard_const(ctdb->recovery_lock);
			outdata->dsize = strlen(ctdb->recovery_lock) + 1;
		}
		return 0;
	case CTDB_CONTROL_SET_RECLOCK_FILE:
		return control_not_implemented("SET_RECLOCK", NULL);

	case CTDB_CONTROL_STOP_NODE:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_stop_node(ctdb);

	case CTDB_CONTROL_CONTINUE_NODE:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_continue_node(ctdb);

	case CTDB_CONTROL_SET_NATGWSTATE:
		return control_not_implemented("SET_NATGWSTATE", NULL);

	case CTDB_CONTROL_SET_LMASTERROLE: {
		uint32_t lmasterrole;

		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));		
		lmasterrole = *(uint32_t *)indata.dptr;
		if (lmasterrole == 0) {
			ctdb->capabilities &= ~CTDB_CAP_LMASTER;
		} else {
			ctdb->capabilities |= CTDB_CAP_LMASTER;
		}
		return 0;
	}

	case CTDB_CONTROL_SET_RECMASTERROLE: {
		uint32_t recmasterrole;

		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));		
		recmasterrole = *(uint32_t *)indata.dptr;
		if (recmasterrole == 0) {
			ctdb->capabilities &= ~CTDB_CAP_RECMASTER;
		} else {
			ctdb->capabilities |= CTDB_CAP_RECMASTER;
		}
		return 0;
	}

	case CTDB_CONTROL_ENABLE_SCRIPT:
		return control_not_implemented("ENABLE_SCRIPT", NULL);

	case CTDB_CONTROL_DISABLE_SCRIPT:
		return control_not_implemented("DISABLE_SCRIPT", NULL);

	case CTDB_CONTROL_SET_BAN_STATE:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_ban_state));
		return ctdb_control_set_ban_state(ctdb, indata);

	case CTDB_CONTROL_GET_BAN_STATE:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_get_ban_state(ctdb, outdata);

	case CTDB_CONTROL_SET_DB_PRIORITY:
		return control_not_implemented("SET_DB_PRIORITY", NULL);

	case CTDB_CONTROL_GET_DB_PRIORITY:
		return control_not_implemented("GET_DB_PRIORITY", NULL);

	case CTDB_CONTROL_TRANSACTION_CANCEL:
		return control_not_implemented("TRANSACTION_CANCEL", NULL);

	case CTDB_CONTROL_REGISTER_NOTIFY:
		return ctdb_control_register_notify(ctdb, client_id, indata);

	case CTDB_CONTROL_DEREGISTER_NOTIFY:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint64_t));
		return ctdb_control_deregister_notify(ctdb, client_id, indata);

	case CTDB_CONTROL_GET_LOG:
		return control_not_implemented("GET_LOG", NULL);

	case CTDB_CONTROL_CLEAR_LOG:
		return control_not_implemented("CLEAR_LOG", NULL);

	case CTDB_CONTROL_GET_DB_SEQNUM:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint64_t));
		return ctdb_control_get_db_seqnum(ctdb, indata, outdata);

	case CTDB_CONTROL_DB_SET_HEALTHY:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));
		return ctdb_control_db_set_healthy(ctdb, indata);

	case CTDB_CONTROL_DB_GET_HEALTH:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));
		return ctdb_control_db_get_health(ctdb, indata, outdata);

	case CTDB_CONTROL_GET_PUBLIC_IP_INFO:
		CHECK_CONTROL_DATA_SIZE(sizeof(ctdb_sock_addr));
		return ctdb_control_get_public_ip_info(ctdb, c, indata, outdata);

	case CTDB_CONTROL_GET_IFACES:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_get_ifaces(ctdb, c, outdata);

	case CTDB_CONTROL_SET_IFACE_LINK_STATE:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_iface));
		return ctdb_control_set_iface_link(ctdb, c, indata);

	case CTDB_CONTROL_GET_STAT_HISTORY:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_get_stat_history(ctdb, c, outdata);

	case CTDB_CONTROL_SCHEDULE_FOR_DELETION: {
		struct ctdb_control_schedule_for_deletion *d;
		size_t size = offsetof(struct ctdb_control_schedule_for_deletion, key);
		CHECK_CONTROL_MIN_DATA_SIZE(size);
		d = (struct ctdb_control_schedule_for_deletion *)indata.dptr;
		size += d->keylen;
		CHECK_CONTROL_DATA_SIZE(size);
		return ctdb_control_schedule_for_deletion(ctdb, indata);
	}
	case CTDB_CONTROL_GET_DB_STATISTICS:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));
		return ctdb_control_get_db_statistics(ctdb, *(uint32_t *)indata.dptr, outdata);

	case CTDB_CONTROL_RELOAD_PUBLIC_IPS:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_reload_public_ips(ctdb, c, async_reply);

	case CTDB_CONTROL_RECEIVE_RECORDS:
		return control_not_implemented("RECEIVE_RECORDS", NULL);

	case CTDB_CONTROL_DB_DETACH:
		return ctdb_control_db_detach(ctdb, indata, client_id);

	case CTDB_CONTROL_DB_FREEZE:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));
		return ctdb_control_db_freeze(ctdb, c, *(uint32_t *)indata.dptr,
					      async_reply);

	case CTDB_CONTROL_DB_THAW:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));
		return ctdb_control_db_thaw(ctdb, *(uint32_t *)indata.dptr);

	case CTDB_CONTROL_DB_TRANSACTION_START:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_transdb));
		return ctdb_control_db_transaction_start(ctdb, indata);

	case CTDB_CONTROL_DB_TRANSACTION_COMMIT:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_transdb));
		return ctdb_control_db_transaction_commit(ctdb, indata);

	case CTDB_CONTROL_DB_TRANSACTION_CANCEL:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));
		return ctdb_control_db_transaction_cancel(ctdb, indata);

	case CTDB_CONTROL_DB_PULL:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_pulldb_ext));
		return ctdb_control_db_pull(ctdb, c, indata, outdata);

	case CTDB_CONTROL_DB_PUSH_START:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_pulldb_ext));
		return ctdb_control_db_push_start(ctdb, indata);

	case CTDB_CONTROL_DB_PUSH_CONFIRM:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));
		return ctdb_control_db_push_confirm(ctdb, indata, outdata);

	case CTDB_CONTROL_DB_OPEN_FLAGS: {
		uint32_t db_id;
		struct ctdb_db_context *ctdb_db;
		int tdb_flags;

		CHECK_CONTROL_DATA_SIZE(sizeof(db_id));
		db_id = *(uint32_t *)indata.dptr;
		ctdb_db = find_ctdb_db(ctdb, db_id);
		if (ctdb_db == NULL) {
			return -1;
		}

		tdb_flags = tdb_get_flags(ctdb_db->ltdb->tdb);

		outdata->dptr = talloc_size(outdata, sizeof(tdb_flags));
		if (outdata->dptr == NULL) {
			return -1;
		}

		outdata->dsize = sizeof(tdb_flags);
		memcpy(outdata->dptr, &tdb_flags, outdata->dsize);
		return 0;
	}

	case CTDB_CONTROL_CHECK_PID_SRVID:
		CHECK_CONTROL_DATA_SIZE((sizeof(pid_t) + sizeof(uint64_t)));
		return ctdb_control_check_pid_srvid(ctdb, indata);

	case CTDB_CONTROL_TUNNEL_REGISTER:
		return ctdb_control_tunnel_register(ctdb, client_id, srvid);

	case CTDB_CONTROL_TUNNEL_DEREGISTER:
		return ctdb_control_tunnel_deregister(ctdb, client_id, srvid);

	case CTDB_CONTROL_VACUUM_FETCH:
		return ctdb_control_vacuum_fetch(ctdb, indata);

	case CTDB_CONTROL_DB_VACUUM: {
		struct ctdb_db_vacuum db_vacuum;

		CHECK_CONTROL_DATA_SIZE(ctdb_db_vacuum_len(&db_vacuum));
		return ctdb_control_db_vacuum(ctdb, c, indata, async_reply);
	}
	case CTDB_CONTROL_ECHO_DATA: {
		return ctdb_control_echo_data(ctdb, c, indata, async_reply);
	}

	case CTDB_CONTROL_DISABLE_NODE:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_disable_node(ctdb);

	case CTDB_CONTROL_ENABLE_NODE:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_enable_node(ctdb);

	default:
		DEBUG(DEBUG_CRIT,(__location__ " Unknown CTDB control opcode %u\n", opcode));
		return -1;
	}
}

/*
  send a reply for a ctdb control
 */
void ctdb_request_control_reply(struct ctdb_context *ctdb, struct ctdb_req_control_old *c,
				TDB_DATA *outdata, int32_t status, const char *errormsg)
{
	struct ctdb_reply_control_old *r;
	size_t len;
	
	/* some controls send no reply */
	if (c->flags & CTDB_CTRL_FLAG_NOREPLY) {
		return;
	}

	len = offsetof(struct ctdb_reply_control_old, data) + (outdata?outdata->dsize:0);
	if (errormsg) {
		len += strlen(errormsg);
	}
	r = ctdb_transport_allocate(ctdb, ctdb, CTDB_REPLY_CONTROL, len, struct ctdb_reply_control_old);
	if (r == NULL) {
		DEBUG(DEBUG_ERR,(__location__ "Unable to allocate transport - OOM or transport is down\n"));
		return;
	}

	r->hdr.destnode     = c->hdr.srcnode;
	r->hdr.reqid        = c->hdr.reqid;
	r->status           = status;
	r->datalen          = outdata?outdata->dsize:0;
	if (outdata && outdata->dsize) {
		memcpy(&r->data[0], outdata->dptr, outdata->dsize);
	}
	if (errormsg) {
		r->errorlen = strlen(errormsg);
		memcpy(&r->data[r->datalen], errormsg, r->errorlen);
	}

	ctdb_queue_packet_opcode(ctdb, &r->hdr, c->opcode);	

	talloc_free(r);
}

/*
  called when a CTDB_REQ_CONTROL packet comes in
*/
void ctdb_request_control(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_req_control_old *c = (struct ctdb_req_control_old *)hdr;
	TDB_DATA data, *outdata;
	int32_t status;
	bool async_reply = false;
	const char *errormsg = NULL;

	data.dptr = &c->data[0];
	data.dsize = c->datalen;

	outdata = talloc_zero(c, TDB_DATA);

	status = ctdb_control_dispatch(ctdb, c, data, outdata, hdr->srcnode, 
				       &errormsg, &async_reply);

	if (!async_reply) {
		ctdb_request_control_reply(ctdb, c, outdata, status, errormsg);
	}
}

/*
  called when a CTDB_REPLY_CONTROL packet comes in
*/
void ctdb_reply_control(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_reply_control_old *c = (struct ctdb_reply_control_old *)hdr;
	TDB_DATA data;
	struct ctdb_control_state *state;
	const char *errormsg = NULL;

	state = reqid_find(ctdb->idr, hdr->reqid, struct ctdb_control_state);
	if (state == NULL) {
		DEBUG(DEBUG_ERR,("pnn %u Invalid reqid %u in ctdb_reply_control\n",
			 ctdb->pnn, hdr->reqid));
		return;
	}

	if (hdr->reqid != state->reqid) {
		/* we found a record  but it was the wrong one */
		DEBUG(DEBUG_ERR, ("Dropped orphaned control reply with reqid:%u\n", hdr->reqid));
		return;
	}

	data.dptr = &c->data[0];
	data.dsize = c->datalen;
	if (c->errorlen) {
		errormsg = talloc_strndup(state, 
					  (char *)&c->data[c->datalen], c->errorlen);
	}

	/* make state a child of the packet, so it goes away when the packet
	   is freed. */
	talloc_steal(hdr, state);

	state->callback(ctdb, c->status, data, errormsg, state->private_data);
}

static int ctdb_control_destructor(struct ctdb_control_state *state)
{
	reqid_remove(state->ctdb->idr, state->reqid);
	return 0;
}

/*
  handle a timeout of a control
 */
static void ctdb_control_timeout(struct tevent_context *ev,
				 struct tevent_timer *te,
				 struct timeval t, void *private_data)
{
	struct ctdb_control_state *state = talloc_get_type(private_data, struct ctdb_control_state);
	TALLOC_CTX *tmp_ctx = talloc_new(ev);

	CTDB_INCREMENT_STAT(state->ctdb, timeouts.control);

	talloc_steal(tmp_ctx, state);

	state->callback(state->ctdb, -1, tdb_null,
			"ctdb_control timed out", 
			state->private_data);
	talloc_free(tmp_ctx);
}


/*
  send a control message to a node
 */
int ctdb_daemon_send_control(struct ctdb_context *ctdb, uint32_t destnode,
			     uint64_t srvid, uint32_t opcode, uint32_t client_id,
			     uint32_t flags,
			     TDB_DATA data,
			     ctdb_control_callback_fn_t callback,
			     void *private_data)
{
	struct ctdb_req_control_old *c;
	struct ctdb_control_state *state;
	size_t len;

	if (ctdb->methods == NULL) {
		DEBUG(DEBUG_INFO,(__location__ " Failed to send control. Transport is DOWN\n"));
		return -1;
	}

	if (((destnode == CTDB_BROADCAST_ACTIVE) ||
	     (destnode == CTDB_BROADCAST_ALL) ||
	     (destnode == CTDB_BROADCAST_CONNECTED)) && 
	    !(flags & CTDB_CTRL_FLAG_NOREPLY)) {
		DEBUG(DEBUG_CRIT,("Attempt to broadcast control without NOREPLY\n"));
		return -1;
	}

	if (destnode != CTDB_BROADCAST_ACTIVE &&
	    destnode != CTDB_BROADCAST_ALL && 
	    destnode != CTDB_BROADCAST_CONNECTED && 
	    (!ctdb_validate_pnn(ctdb, destnode) || 
	     (ctdb->nodes[destnode]->flags & NODE_FLAGS_DISCONNECTED))) {
		if (!(flags & CTDB_CTRL_FLAG_NOREPLY)) {
			callback(ctdb, -1, tdb_null, "ctdb_control to disconnected node", private_data);
		}
		return 0;
	}

	/* the state is made a child of private_data if possible. This means any reply
	   will be discarded if the private_data goes away */
	state = talloc(private_data?private_data:ctdb, struct ctdb_control_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->reqid = reqid_new(ctdb->idr, state);
	state->callback = callback;
	state->private_data = private_data;
	state->ctdb = ctdb;
	state->flags = flags;

	talloc_set_destructor(state, ctdb_control_destructor);

	len = offsetof(struct ctdb_req_control_old, data) + data.dsize;
	c = ctdb_transport_allocate(ctdb, state, CTDB_REQ_CONTROL, len, 
				    struct ctdb_req_control_old);
	CTDB_NO_MEMORY(ctdb, c);
	talloc_set_name_const(c, "ctdb_req_control packet");

	c->hdr.destnode     = destnode;
	c->hdr.reqid        = state->reqid;
	c->opcode           = opcode;
	c->client_id        = client_id;
	c->flags            = flags;
	c->srvid            = srvid;
	c->datalen          = data.dsize;
	if (data.dsize) {
		memcpy(&c->data[0], data.dptr, data.dsize);
	}

	ctdb_queue_packet(ctdb, &c->hdr);	

	if (flags & CTDB_CTRL_FLAG_NOREPLY) {
		talloc_free(state);
		return 0;
	}

	if (ctdb->tunable.control_timeout) {
		tevent_add_timer(ctdb->ev, state,
				 timeval_current_ofs(ctdb->tunable.control_timeout, 0),
				 ctdb_control_timeout, state);
	}

	talloc_free(c);
	return 0;
}
