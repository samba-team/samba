/*
   CTDB protocol marshalling

   Copyright (C) Amitay Isaacs  2016

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
#include "system/locale.h"

#include <talloc.h>
#include <tdb.h>

#include <protocol/protocol.h>
#include <protocol/protocol_api.h>

/*
 * Utility functions
 */
struct uint32_map {
	uint32_t key;
#define MAP_END		0xffffffff
	const char *name;
};


static void uint32_map_print(struct uint32_map *map, uint32_t key, FILE *fp)
{
	int i = 0;

	while (map[i].key != MAP_END) {
		if (key == map[i].key) {
			fprintf(fp, "%s", map[i].name);
			return;
		}
		i = i+1;
	}

	fprintf(fp, "UNKNOWN(%u)", key);
}

static void tdb_data_print(TDB_DATA d, FILE *fp)
{
        unsigned char *p = (unsigned char *)d.dptr;
        int len = d.dsize;
        while (len--) {
                if (isprint(*p) && !strchr("\"\\", *p)) {
                        fputc(*p, fp);
                } else {
                        fprintf(fp, "\\%02X", *p);
                }
                p++;
        }
}

/*
 * Data types
 */

static void ctdb_operation_print(uint32_t operation, FILE *fp)
{
	struct uint32_map map[] = {
		{ CTDB_REQ_CALL, "REQ_CALL" },
		{ CTDB_REPLY_CALL, "REPLY_CALL" },
		{ CTDB_REQ_DMASTER, "REQ_DMASTER" },
		{ CTDB_REPLY_DMASTER, "REPLY_DMASTER" },
		{ CTDB_REPLY_ERROR, "REPLY_ERROR" },
		{ CTDB_REQ_MESSAGE, "REQ_MESSAGE" },
		{ CTDB_REQ_CONTROL, "REQ_CONTROL", },
		{ CTDB_REPLY_CONTROL, "REPLY_CONTROL" },
		{ CTDB_REQ_KEEPALIVE, "REQ_KEEPALIVE" },
		{ MAP_END, "" },
	};

	uint32_map_print(map, operation, fp);
}

static void ctdb_callid_print(uint32_t callid, FILE *fp)
{
	struct uint32_map map[] = {
		{ CTDB_NULL_FUNC, "NULL" },
		{ CTDB_FETCH_FUNC, "FETCH" },
		{ CTDB_FETCH_WITH_HEADER_FUNC, "FETCH_WITH_HEADER" },
		{ MAP_END, "" },
	};

	uint32_map_print(map, callid, fp);
}

static void ctdb_opcode_print(uint32_t opcode, FILE *fp)
{
	struct uint32_map map[] = {
		{ CTDB_CONTROL_PROCESS_EXISTS, "PROCESS_EXISTS" },
		{ CTDB_CONTROL_STATISTICS, "STATISTICS" },
		{ CTDB_CONTROL_PING, "PING" },
		{ CTDB_CONTROL_GETDBPATH, "GETDBPATH" },
		{ CTDB_CONTROL_GETVNNMAP, "GETVNNMAP" },
		{ CTDB_CONTROL_SETVNNMAP, "SETVNNMAP" },
		{ CTDB_CONTROL_GET_DEBUG, "GET_DEBUG" },
		{ CTDB_CONTROL_SET_DEBUG, "SET_DEBUG" },
		{ CTDB_CONTROL_GET_DBMAP, "GET_DBMAP" },
		{ CTDB_CONTROL_GET_NODEMAPv4, "GET_NODEMAPv4" },
		{ CTDB_CONTROL_SET_DMASTER, "SET_DMASTER" },
		{ CTDB_CONTROL_PULL_DB, "PULL_DB" },
		{ CTDB_CONTROL_PUSH_DB, "PUSH_DB" },
		{ CTDB_CONTROL_GET_RECMODE, "GET_RECMODE" },
		{ CTDB_CONTROL_SET_RECMODE, "SET_RECMODE" },
		{ CTDB_CONTROL_STATISTICS_RESET, "STATISTICS_RESET" },
		{ CTDB_CONTROL_DB_ATTACH, "DB_ATTACH" },
		{ CTDB_CONTROL_SET_CALL, "SET_CALL" },
		{ CTDB_CONTROL_TRAVERSE_START, "TRAVERSE_START" },
		{ CTDB_CONTROL_TRAVERSE_ALL, "TRAVERSE_ALL" },
		{ CTDB_CONTROL_TRAVERSE_DATA, "TRAVERSE_DATA" },
		{ CTDB_CONTROL_REGISTER_SRVID, "REGISTER_SRVID" },
		{ CTDB_CONTROL_DEREGISTER_SRVID, "DEREGISTER_SRVID" },
		{ CTDB_CONTROL_GET_DBNAME, "GET_DBNAME" },
		{ CTDB_CONTROL_ENABLE_SEQNUM, "ENABLE_SEQNUM" },
		{ CTDB_CONTROL_UPDATE_SEQNUM, "UPDATE_SEQNUM" },
		{ CTDB_CONTROL_DUMP_MEMORY, "DUMP_MEMORY" },
		{ CTDB_CONTROL_GET_PID, "GET_PID" },
		{ CTDB_CONTROL_GET_RECMASTER, "GET_RECMASTER" },
		{ CTDB_CONTROL_SET_RECMASTER, "SET_RECMASTER" },
		{ CTDB_CONTROL_FREEZE, "FREEZE" },
		{ CTDB_CONTROL_THAW, "THAW" },
		{ CTDB_CONTROL_GET_PNN, "GET_PNN" },
		{ CTDB_CONTROL_SHUTDOWN, "SHUTDOWN" },
		{ CTDB_CONTROL_GET_MONMODE, "GET_MONMODE" },
		{ CTDB_CONTROL_TAKEOVER_IPv4, "TAKEOVER_IPv4" },
		{ CTDB_CONTROL_RELEASE_IPv4, "RELEASE_IPv4" },
		{ CTDB_CONTROL_TCP_CLIENT, "TCP_CLIENT" },
		{ CTDB_CONTROL_TCP_ADD, "TCP_ADD" },
		{ CTDB_CONTROL_TCP_REMOVE, "TCP_REMOVE" },
		{ CTDB_CONTROL_STARTUP, "STARTUP" },
		{ CTDB_CONTROL_SET_TUNABLE, "SET_TUNABLE" },
		{ CTDB_CONTROL_GET_TUNABLE, "GET_TUNABLE" },
		{ CTDB_CONTROL_LIST_TUNABLES, "LIST_TUNABLES" },
		{ CTDB_CONTROL_GET_PUBLIC_IPSv4, "GET_PUBLIC_IPSv4" },
		{ CTDB_CONTROL_MODIFY_FLAGS, "MODIFY_FLAGS" },
		{ CTDB_CONTROL_GET_ALL_TUNABLES, "GET_ALL_TUNABLES" },
		{ CTDB_CONTROL_KILL_TCP, "KILL_TCP" },
		{ CTDB_CONTROL_GET_TCP_TICKLE_LIST, "GET_TCP_TICKLE_LIST" },
		{ CTDB_CONTROL_SET_TCP_TICKLE_LIST, "SET_TCP_TICKLE_LIST" },
		{ CTDB_CONTROL_REGISTER_SERVER_ID, "REGISTER_SERVER_ID" },
		{ CTDB_CONTROL_UNREGISTER_SERVER_ID, "UNREGISTER_SERVER_ID" },
		{ CTDB_CONTROL_CHECK_SERVER_ID, "CHECK_SERVER_ID" },
		{ CTDB_CONTROL_GET_SERVER_ID_LIST, "GET_SERVER_ID_LIST" },
		{ CTDB_CONTROL_DB_ATTACH_PERSISTENT, "DB_ATTACH_PERSISTENT" },
		{ CTDB_CONTROL_PERSISTENT_STORE, "PERSISTENT_STORE" },
		{ CTDB_CONTROL_UPDATE_RECORD, "UPDATE_RECORD" },
		{ CTDB_CONTROL_SEND_GRATUITOUS_ARP, "SEND_GRATUITOUS_ARP" },
		{ CTDB_CONTROL_TRANSACTION_START, "TRANSACTION_START" },
		{ CTDB_CONTROL_TRANSACTION_COMMIT, "TRANSACTION_COMMIT" },
		{ CTDB_CONTROL_WIPE_DATABASE, "WIPE_DATABASE" },
		{ CTDB_CONTROL_UPTIME, "UPTIME" },
		{ CTDB_CONTROL_START_RECOVERY, "START_RECOVERY" },
		{ CTDB_CONTROL_END_RECOVERY, "END_RECOVERY" },
		{ CTDB_CONTROL_RELOAD_NODES_FILE, "RELOAD_NODES_FILE" },
		{ CTDB_CONTROL_TRY_DELETE_RECORDS, "TRY_DELETE_RECORDS" },
		{ CTDB_CONTROL_ENABLE_MONITOR, "ENABLE_MONITOR" },
		{ CTDB_CONTROL_DISABLE_MONITOR, "DISABLE_MONITOR" },
		{ CTDB_CONTROL_ADD_PUBLIC_IP, "ADD_PUBLIC_IP" },
		{ CTDB_CONTROL_DEL_PUBLIC_IP, "DEL_PUBLIC_IP" },
		{ CTDB_CONTROL_RUN_EVENTSCRIPTS, "RUN_EVENTSCRIPTS" },
		{ CTDB_CONTROL_GET_CAPABILITIES, "GET_CAPABILITIES" },
		{ CTDB_CONTROL_START_PERSISTENT_UPDATE, "START_PERSISTENT_UPDATE" },
		{ CTDB_CONTROL_CANCEL_PERSISTENT_UPDATE, "CANCEL_PERSISTENT_UPDATE" },
		{ CTDB_CONTROL_TRANS2_COMMIT, "TRANS2_COMMIT" },
		{ CTDB_CONTROL_TRANS2_FINISHED, "TRANS2_FINISHED" },
		{ CTDB_CONTROL_TRANS2_ERROR, "TRANS2_ERROR" },
		{ CTDB_CONTROL_TRANS2_COMMIT_RETRY, "TRANS2_COMMIT_RETRY" },
		{ CTDB_CONTROL_RECD_PING, "RECD_PING" },
		{ CTDB_CONTROL_RELEASE_IP, "RELEASE_IP" },
		{ CTDB_CONTROL_TAKEOVER_IP, "TAKEOVER_IP" },
		{ CTDB_CONTROL_GET_PUBLIC_IPS, "GET_PUBLIC_IPS" },
		{ CTDB_CONTROL_GET_NODEMAP, "GET_NODEMAP" },
		{ CTDB_CONTROL_GET_EVENT_SCRIPT_STATUS, "GET_EVENT_SCRIPT_STATUS" },
		{ CTDB_CONTROL_TRAVERSE_KILL, "TRAVERSE_KILL" },
		{ CTDB_CONTROL_RECD_RECLOCK_LATENCY, "RECD_RECLOCK_LATENCY" },
		{ CTDB_CONTROL_GET_RECLOCK_FILE, "GET_RECLOCK_FILE" },
		{ CTDB_CONTROL_STOP_NODE, "STOP_NODE" },
		{ CTDB_CONTROL_CONTINUE_NODE, "CONTINUE_NODE" },
		{ CTDB_CONTROL_SET_NATGWSTATE, "SET_NATGWSTATE" },
		{ CTDB_CONTROL_SET_LMASTERROLE, "SET_LMASTERROLE" },
		{ CTDB_CONTROL_SET_RECMASTERROLE, "SET_RECMASTERROLE" },
		{ CTDB_CONTROL_ENABLE_SCRIPT, "ENABLE_SCRIPT" },
		{ CTDB_CONTROL_DISABLE_SCRIPT, "DISABLE_SCRIPT" },
		{ CTDB_CONTROL_SET_BAN_STATE, "SET_BAN_STATE" },
		{ CTDB_CONTROL_GET_BAN_STATE, "GET_BAN_STATE" },
		{ CTDB_CONTROL_SET_DB_PRIORITY, "SET_DB_PRIORITY" },
		{ CTDB_CONTROL_GET_DB_PRIORITY, "GET_DB_PRIORITY" },
		{ CTDB_CONTROL_TRANSACTION_CANCEL, "TRANSACTION_CANCEL" },
		{ CTDB_CONTROL_REGISTER_NOTIFY, "REGISTER_NOTIFY" },
		{ CTDB_CONTROL_DEREGISTER_NOTIFY, "DEREGISTER_NOTIFY" },
		{ CTDB_CONTROL_TRANS2_ACTIVE, "TRANS2_ACTIVE" },
		{ CTDB_CONTROL_GET_LOG, "GET_LOG" },
		{ CTDB_CONTROL_CLEAR_LOG, "CLEAR_LOG" },
		{ CTDB_CONTROL_TRANS3_COMMIT, "TRANS3_COMMIT" },
		{ CTDB_CONTROL_GET_DB_SEQNUM, "GET_DB_SEQNUM" },
		{ CTDB_CONTROL_DB_SET_HEALTHY, "DB_SET_HEALTHY" },
		{ CTDB_CONTROL_DB_GET_HEALTH, "DB_GET_HEALTH" },
		{ CTDB_CONTROL_GET_PUBLIC_IP_INFO, "GET_PUBLIC_IP_INFO" },
		{ CTDB_CONTROL_GET_IFACES, "GET_IFACES" },
		{ CTDB_CONTROL_SET_IFACE_LINK_STATE, "SET_IFACE_LINK_STATE" },
		{ CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE, "TCP_ADD_DELAYED_UPDATE" },
		{ CTDB_CONTROL_GET_STAT_HISTORY, "GET_STAT_HISTORY" },
		{ CTDB_CONTROL_SCHEDULE_FOR_DELETION, "SCHEDULE_FOR_DELETION" },
		{ CTDB_CONTROL_SET_DB_READONLY, "SET_DB_READONLY" },
		{ CTDB_CONTROL_CHECK_SRVIDS, "CHECK_SRVIDS" },
		{ CTDB_CONTROL_TRAVERSE_START_EXT, "TRAVERSE_START_EXT" },
		{ CTDB_CONTROL_GET_DB_STATISTICS, "GET_DB_STATISTICS" },
		{ CTDB_CONTROL_SET_DB_STICKY, "SET_DB_STICKY" },
		{ CTDB_CONTROL_RELOAD_PUBLIC_IPS, "RELOAD_PUBLIC_IPS" },
		{ CTDB_CONTROL_TRAVERSE_ALL_EXT, "TRAVERSE_ALL_EXT" },
		{ CTDB_CONTROL_RECEIVE_RECORDS, "RECEIVE_RECORDS" },
		{ CTDB_CONTROL_IPREALLOCATED, "IPREALLOCATED" },
		{ CTDB_CONTROL_GET_RUNSTATE, "GET_RUNSTATE" },
		{ CTDB_CONTROL_DB_DETACH, "DB_DETACH" },
		{ CTDB_CONTROL_GET_NODES_FILE, "GET_NODES_FILE" },
		{ CTDB_CONTROL_DB_FREEZE, "DB_FREEZE" },
		{ CTDB_CONTROL_DB_THAW, "DB_THAW" },
		{ CTDB_CONTROL_DB_TRANSACTION_START, "DB_TRANSACTION_START" },
		{ CTDB_CONTROL_DB_TRANSACTION_COMMIT, "DB_TRANSACTION_COMMIT" },
		{ CTDB_CONTROL_DB_TRANSACTION_CANCEL, "DB_TRANSACTION_CANCEL" },
		{ CTDB_CONTROL_DB_PULL, "DB_PULL" },
		{ CTDB_CONTROL_DB_PUSH_START, "DB_PUSH_START" },
		{ CTDB_CONTROL_DB_PUSH_CONFIRM, "DB_PUSH_CONFIRM" },
		{ CTDB_CONTROL_DB_OPEN_FLAGS, "DB_OPEN_FLAGS" },
		{ CTDB_CONTROL_DB_ATTACH_REPLICATED, "DB_ATTACH_REPLICATED" },
		{ CTDB_CONTROL_CHECK_PID_SRVID, "CHECK_PID_SRVID" },
		{ CTDB_CONTROL_TUNNEL_REGISTER, "TUNNEL_REGISTER" },
		{ CTDB_CONTROL_TUNNEL_DEREGISTER, "TUNNEL_DEREGISTER" },
		{ CTDB_CONTROL_VACUUM_FETCH, "VACUUM_FETCH" },
		{ CTDB_CONTROL_DB_VACUUM, "DB_VACUUM" },
		{ CTDB_CONTROL_ECHO_DATA, "ECHO_DATA" },
		{ CTDB_CONTROL_DISABLE_NODE, "DISABLE_NODE" },
		{ CTDB_CONTROL_ENABLE_NODE, "ENABLE_NODE" },
		{ MAP_END, "" },
	};

	uint32_map_print(map, opcode, fp);
}

static void ctdb_control_flags_print(uint32_t flags, FILE *fp)
{
	if (flags & CTDB_CTRL_FLAG_NOREPLY) {
		fprintf(fp, "NOREPLY ");
	}
	if (flags & CTDB_CTRL_FLAG_OPCODE_SPECIFIC) {
		fprintf(fp, "OPCODE_SPECIFIC ");
	}
}

static void ctdb_pnn_print(uint32_t pnn, FILE *fp)
{
	if (pnn == CTDB_CURRENT_NODE) {
		fprintf(fp, "CURRENT");
	} else if (pnn == CTDB_BROADCAST_ALL) {
		fprintf(fp, "ALL");
	} else if (pnn == CTDB_BROADCAST_ACTIVE) {
		fprintf(fp, "ACTIVE");
	} else  if (pnn == CTDB_BROADCAST_CONNECTED) {
		fprintf(fp, "CONNECTED");
	} else if (pnn == CTDB_MULTICAST) {
		fprintf(fp, "MULTICAST");
	} else if (pnn == CTDB_UNKNOWN_PNN) {
		fprintf(fp, "UNKNOWN");
	} else {
		fprintf(fp, "%u", pnn);
	}
}

static void ctdb_srvid_print(uint64_t srvid, FILE *fp)
{
	uint64_t prefix = 0xFFFF000000000000LL;

	if (srvid == CTDB_SRVID_ALL) {
		fprintf(fp, "ALL");
	} else if ((srvid & prefix) == CTDB_SRVID_RECOVERY) {
		srvid = srvid & ~CTDB_SRVID_RECOVERY;
		fprintf(fp, "RECOVERY-%"PRIx64"", srvid);
	} else if (srvid == CTDB_SRVID_BANNING) {
		fprintf(fp, "BANNING");
	} else if (srvid == CTDB_SRVID_ELECTION) {
		fprintf(fp, "ELECTION");
	} else if (srvid == CTDB_SRVID_RECONFIGURE) {
		fprintf(fp, "RECONFIGURE");
	} else if (srvid == CTDB_SRVID_RELEASE_IP) {
		fprintf(fp, "RELEASE_IP");
	} else if (srvid == CTDB_SRVID_TAKE_IP) {
		fprintf(fp, "TAKE_IP");
	} else if (srvid == CTDB_SRVID_SET_NODE_FLAGS) {
		fprintf(fp, "SET_NODE_FLAGS");
	} else if (srvid == CTDB_SRVID_RECD_UPDATE_IP) {
		fprintf(fp, "RECD_UPDATE_IP");
	} else if (srvid == CTDB_SRVID_VACUUM_FETCH) {
		fprintf(fp, "VACUUM_FETCH");
	} else if (srvid == CTDB_SRVID_DETACH_DATABASE) {
		fprintf(fp, "DETACH_DATABASE");
	} else if (srvid == CTDB_SRVID_MEM_DUMP) {
		fprintf(fp, "MEM_DUMP");
	} else if (srvid == CTDB_SRVID_GETLOG) {
		fprintf(fp, "GETLOG");
	} else if (srvid == CTDB_SRVID_CLEARLOG) {
		fprintf(fp, "CLEARLOG");
	} else if (srvid == CTDB_SRVID_PUSH_NODE_FLAGS) {
		fprintf(fp, "PUSH_NODE_FLAGS");
	} else if (srvid == CTDB_SRVID_RELOAD_NODES) {
		fprintf(fp, "RELOAD_NODES");
	} else if (srvid == CTDB_SRVID_TAKEOVER_RUN) {
		fprintf(fp, "TAKEOVER_RUN");
	} else if (srvid == CTDB_SRVID_REBALANCE_NODE) {
		fprintf(fp, "REBALANCE_NODE");
	} else if (srvid == CTDB_SRVID_DISABLE_TAKEOVER_RUNS) {
		fprintf(fp, "DISABLE_TAKEOVER_RUNS");
	} else if (srvid == CTDB_SRVID_DISABLE_RECOVERIES) {
		fprintf(fp, "DISABLE_RECOVERIES");
	} else if (srvid == CTDB_SRVID_DISABLE_IP_CHECK) {
		fprintf(fp, "DISABLE_IP_CHECK");
	} else if ((srvid & prefix) == CTDB_SRVID_SAMBA_RANGE) {
		if (srvid == CTDB_SRVID_SAMBA_NOTIFY) {
			fprintf(fp, "SAMBA_NOTIFY");
		} else {
			srvid &= ~CTDB_SRVID_SAMBA_RANGE;
			fprintf(fp, "samba-0x%"PRIx64"", srvid);
		}
	} else if ((srvid & prefix) == CTDB_SRVID_NFSD_RANGE) {
		srvid &= ~CTDB_SRVID_NFSD_RANGE;
		fprintf(fp, "nfsd-0x%"PRIx64"", srvid);
	} else if ((srvid & prefix) == CTDB_SRVID_ISCSID_RANGE) {
		srvid &= ~CTDB_SRVID_ISCSID_RANGE;
		fprintf(fp, "iscsi-0x%"PRIx64"", srvid);
	} else if ((srvid & prefix) == CTDB_SRVID_TOOL_RANGE) {
		srvid &= ~CTDB_SRVID_TOOL_RANGE;
		fprintf(fp, "tool-0x%"PRIx64"", srvid);
	} else if ((srvid & prefix) == CTDB_SRVID_TEST_RANGE) {
		srvid &= ~CTDB_SRVID_TEST_RANGE;
		fprintf(fp, "test-0x%"PRIx64"", srvid);
	} else if ((srvid & prefix) == CTDB_SRVID_PID_RANGE) {
		if (srvid < UINT16_MAX) {
			fprintf(fp, "pid-%"PRIu64, srvid);
		} else {
			fprintf(fp, "pid-0x%"PRIx64, srvid);
		}
	} else {
		fprintf(fp, "0x%"PRIx64, srvid);
	}
}

static void ctdb_tunnel_id_print(uint64_t tunnel_id, FILE *fp)
{
	if ((tunnel_id & CTDB_TUNNEL_TEST) == CTDB_TUNNEL_TEST) {
		fprintf(fp, "TEST-%"PRIx64, tunnel_id);
	} else {
		fprintf(fp, "0x%"PRIx64, tunnel_id);
	}
}

static void ctdb_tunnel_flags_print(uint32_t flags, FILE *fp)
{
	if (flags & CTDB_TUNNEL_FLAG_REQUEST) {
		fprintf(fp, "REQUEST ");
	}
	if (flags & CTDB_TUNNEL_FLAG_REPLY) {
		fprintf(fp, "REPLY ");
	}
	if (flags & CTDB_TUNNEL_FLAG_NOREPLY) {
		fprintf(fp, "NOREPLY ");
	}
}

/*
 * Print routines
 */

static void ctdb_req_header_print(struct ctdb_req_header *h, FILE *fp)
{
	fprintf(fp, "Header\n");
	fprintf(fp, "  length:%u magic:0x%"PRIx32" version:%u generation:0x%"PRIx32"\n",
		h->length, h->ctdb_magic, h->ctdb_version, h->generation);
	fprintf(fp, "  ");
	ctdb_operation_print(h->operation, fp);
	fprintf(fp, " dst:");
	ctdb_pnn_print(h->destnode, fp);
	fprintf(fp, " src:");
	ctdb_pnn_print(h->srcnode, fp);
	fprintf(fp, " reqid:0x%"PRIx32"\n", h->reqid);
}

static void ctdb_req_call_print(struct ctdb_req_call *c, FILE *fp)
{
	fprintf(fp, "Data\n");
	fprintf(fp, "  db:0x%"PRIx32" ", c->db_id);
	ctdb_callid_print(c->callid, fp);
	fprintf(fp, "\n");
	fprintf(fp, "  key:");
	tdb_data_print(c->key, fp);
	fprintf(fp, "\n");
}

static void ctdb_reply_call_print(struct ctdb_reply_call *c, FILE *fp)
{
	fprintf(fp, "Data\n");
	fprintf(fp, "  status:%d\n", c->status);
	if (c->status == 0) {
		fprintf(fp, "  data:");
		tdb_data_print(c->data, fp);
		fprintf(fp, "\n");
	}
}

static void ctdb_req_dmaster_print(struct ctdb_req_dmaster *c, FILE *fp)
{
	fprintf(fp, "Data\n");
	fprintf(fp, "  db:0x%"PRIx32" rsn:0x%"PRIx64" dmaster:%u\n",
		c->db_id, c->rsn, c->dmaster);
	fprintf(fp, "  key:");
	tdb_data_print(c->key, fp);
	fprintf(fp, "\n");
	fprintf(fp, "  data:");
	tdb_data_print(c->data, fp);
	fprintf(fp, "\n");
}

static void ctdb_reply_dmaster_print(struct ctdb_reply_dmaster *c, FILE *fp)
{
	fprintf(fp, "Data\n");
	fprintf(fp, "  db:0x%"PRIx32" rsn:0x%"PRIx64"\n", c->db_id, c->rsn);
	fprintf(fp, "  key:");
	tdb_data_print(c->key, fp);
	fprintf(fp, "\n");
	fprintf(fp, "  data:");
	tdb_data_print(c->data, fp);
	fprintf(fp, "\n");
}

static void ctdb_reply_error_print(struct ctdb_reply_error *c, FILE *fp)
{
	fprintf(fp, "Data\n");
	fprintf(fp, "  status:%d\n", c->status);
	if (c->status != 0) {
		fprintf(fp, "  msg:");
		tdb_data_print(c->msg, fp);
		fprintf(fp, "\n");
	}
}

static void ctdb_req_message_data_print(struct ctdb_req_message_data *c,
					FILE *fp)
{
	fprintf(fp, "Data\n");
	fprintf(fp, "  srvid:");
	ctdb_srvid_print(c->srvid, fp);
	fprintf(fp, "\n");
	fprintf(fp, "  data:");
	tdb_data_print(c->data, fp);
	fprintf(fp, "\n");
}

static void ctdb_req_control_print(struct ctdb_req_control *c, FILE *fp)
{
	fprintf(fp, "Data\n");
	fprintf(fp, "  ");
	ctdb_opcode_print(c->opcode, fp);
	fprintf(fp, " srvid:");
	ctdb_srvid_print(c->srvid, fp);
	fprintf(fp, " client_id:0x%"PRIx32" ", c->client_id);
	ctdb_control_flags_print(c->flags, fp);
	fprintf(fp, "\n");
}

static void ctdb_reply_control_print(struct ctdb_reply_control *c, FILE *fp)
{
	fprintf(fp, "Data\n");
	fprintf(fp, "  status:%d ", c->status);
	if (c->errmsg != NULL) {
		fprintf(fp, "errmsg: %s", c->errmsg);
	}
	fprintf(fp, "\n");
}

static void ctdb_req_keepalive_print(struct ctdb_req_keepalive *c, FILE *fp)
{
	fprintf(fp, "Data\n");
	fprintf(fp, "  version:0x%"PRIx32, c->version);
	fprintf(fp, "  uptime:%"PRIu32, c->uptime);
	fprintf(fp, "\n");
}

static void ctdb_req_tunnel_print(struct ctdb_req_tunnel *c, FILE *fp)
{
	fprintf(fp, "Data\n");
	fprintf(fp, "  tunnel_id:");
	ctdb_tunnel_id_print(c->tunnel_id, fp);
	ctdb_tunnel_flags_print(c->flags, fp);
	tdb_data_print(c->data, fp);
	fprintf(fp, "\n");
}

/*
 * Parse routines
 */

static void ctdb_req_call_parse(uint8_t *buf, size_t buflen, FILE *fp,
				TALLOC_CTX *mem_ctx)
{
	struct ctdb_req_call c;
	int ret;

	ret = ctdb_req_call_pull(buf, buflen, NULL, mem_ctx, &c);
	if (ret != 0) {
		fprintf(fp, "Failed to parse CTDB_REQ_CALL\n");
		return;
	}

	ctdb_req_call_print(&c, fp);
}

static void ctdb_reply_call_parse(uint8_t *buf, size_t buflen, FILE *fp,
				  TALLOC_CTX *mem_ctx)
{
	struct ctdb_reply_call c;
	int ret;

	ret = ctdb_reply_call_pull(buf, buflen, NULL, mem_ctx, &c);
	if (ret != 0) {
		fprintf(fp, "Failed to parse CTDB_REPLY_CALL\n");
		return;
	}

	ctdb_reply_call_print(&c, fp);
}

static void ctdb_req_dmaster_parse(uint8_t *buf, size_t buflen, FILE *fp,
				   TALLOC_CTX *mem_ctx)
{
	struct ctdb_req_dmaster c;
	int ret;

	ret = ctdb_req_dmaster_pull(buf, buflen, NULL, mem_ctx, &c);
	if (ret != 0) {
		fprintf(fp, "Failed to parse CTDB_REQ_DMASTER\n");
		return;
	}

	ctdb_req_dmaster_print(&c, fp);
}

static void ctdb_reply_dmaster_parse(uint8_t *buf, size_t buflen, FILE *fp,
				     TALLOC_CTX *mem_ctx)
{
	struct ctdb_reply_dmaster c;
	int ret;

	ret = ctdb_reply_dmaster_pull(buf, buflen, NULL, mem_ctx, &c);
	if (ret != 0) {
		fprintf(fp, "Failed to parse CTDB_REPLY_DMASTER\n");
		return;
	}

	ctdb_reply_dmaster_print(&c, fp);
}

static void ctdb_reply_error_parse(uint8_t *buf, size_t buflen, FILE *fp,
				   TALLOC_CTX *mem_ctx)
{
	struct ctdb_reply_error c;
	int ret;

	ret = ctdb_reply_error_pull(buf, buflen, NULL, mem_ctx, &c);
	if (ret != 0) {
		fprintf(fp, "Failed to parse CTDB_REPLY_ERROR\n");
		return;
	}

	ctdb_reply_error_print(&c, fp);
}

static void ctdb_req_message_parse(uint8_t *buf, size_t buflen, FILE *fp,
				   TALLOC_CTX *mem_ctx)
{
	struct ctdb_req_message_data c;
	int ret;

	ret = ctdb_req_message_data_pull(buf, buflen, NULL, mem_ctx, &c);
	if (ret != 0) {
		fprintf(fp, "Failed to parse CTDB_REQ_MESSAGE\n");
		return;
	}

	ctdb_req_message_data_print(&c, fp);
}

static void ctdb_req_control_parse(uint8_t *buf, size_t buflen, FILE *fp,
				   TALLOC_CTX *mem_ctx)
{
	struct ctdb_req_control c;
	int ret;

	ret = ctdb_req_control_pull(buf, buflen, NULL, mem_ctx, &c);
	if (ret != 0) {
		fprintf(fp, "Failed to parse CTDB_REQ_CONTROL\n");
		return;
	}

	ctdb_req_control_print(&c, fp);
}

static void ctdb_reply_control_parse(uint8_t *buf, size_t buflen, FILE *fp,
				     TALLOC_CTX *mem_ctx)
{
	struct ctdb_reply_control c;
	int ret;

	ret = ctdb_reply_control_pull(buf, buflen, -1, NULL, mem_ctx, &c);
	if (ret != 0) {
		fprintf(fp, "Failed to parse CTDB_REPLY_CONTROL\n");
		return;
	}

	ctdb_reply_control_print(&c, fp);
}

static void ctdb_req_keepalive_parse(uint8_t *buf, size_t buflen, FILE *fp,
				     TALLOC_CTX *mem_ctx)
{
	struct ctdb_req_keepalive c;
	int ret;

	ret = ctdb_req_keepalive_pull(buf, buflen, NULL, mem_ctx, &c);
	if (ret != 0) {
		fprintf(fp, "Failed to parse CTDB_REQ_KEEPALIVE\n");
		return;
	}

	ctdb_req_keepalive_print(&c, fp);
}

static void ctdb_req_tunnel_parse(uint8_t *buf, size_t buflen, FILE *fp,
				  TALLOC_CTX *mem_ctx)
{
	struct ctdb_req_tunnel c;
	int ret;

	ret = ctdb_req_tunnel_pull(buf, buflen, NULL, mem_ctx, &c);
	if (ret != 0) {
		fprintf(fp, "Failed to parse CTDB_REQ_TUNNEL\n");
		return;
	}

	ctdb_req_tunnel_print(&c, fp);
}

/*
 * Packet print
 */

void ctdb_packet_print(uint8_t *buf, size_t buflen, FILE *fp)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct ctdb_req_header h;
	size_t np;
	int ret;

	fprintf(fp, "Buffer len:%zu\n", buflen);

	ret = ctdb_req_header_pull(buf, buflen, &h, &np);
	if (ret != 0) {
		fprintf(fp, "Failed to parse ctdb packet header\n");
		return;
	}

	ctdb_req_header_print(&h, fp);

	if (h.length > buflen) {
		fprintf(fp, "Packet length mismatch\n");
	}

	ret = ctdb_req_header_verify(&h, 0);
	if (ret != 0) {
		fprintf(fp, "Invalid ctdb packet header\n");
		return;
	}

	switch (h.operation) {
		case CTDB_REQ_CALL:
			ctdb_req_call_parse(buf, buflen, fp, mem_ctx);
			break;

		case CTDB_REPLY_CALL:
			ctdb_reply_call_parse(buf, buflen, fp, mem_ctx);
			break;

		case CTDB_REQ_DMASTER:
			ctdb_req_dmaster_parse(buf, buflen, fp, mem_ctx);
			break;

		case CTDB_REPLY_DMASTER:
			ctdb_reply_dmaster_parse(buf, buflen, fp, mem_ctx);
			break;

		case CTDB_REPLY_ERROR:
			ctdb_reply_error_parse(buf, buflen, fp, mem_ctx);
			break;

		case CTDB_REQ_MESSAGE:
			ctdb_req_message_parse(buf, buflen, fp, mem_ctx);
			break;

		case CTDB_REQ_CONTROL:
			ctdb_req_control_parse(buf, buflen, fp, mem_ctx);
			break;

		case CTDB_REPLY_CONTROL:
			ctdb_reply_control_parse(buf, buflen, fp, mem_ctx);
			break;

		case CTDB_REQ_KEEPALIVE:
			ctdb_req_keepalive_parse(buf, buflen, fp, mem_ctx);
			break;

		case CTDB_REQ_TUNNEL:
			ctdb_req_tunnel_parse(buf, buflen, fp, mem_ctx);
			break;

		default:
			fprintf(fp, "Invalid ctdb operation\n");
			break;
	}

	talloc_free(mem_ctx);
}
