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

struct ctdb_req_control_wire {
	struct ctdb_req_header hdr;
	uint32_t opcode;
	uint32_t pad;
	uint64_t srvid;
	uint32_t client_id;
	uint32_t flags;
	uint32_t datalen;
	uint8_t data[1];
};

struct ctdb_reply_control_wire {
	struct ctdb_req_header hdr;
	int32_t status;
	uint32_t datalen;
	uint32_t errorlen;
	uint8_t data[1];
};

static size_t ctdb_req_control_data_len(struct ctdb_req_control_data *cd)
{
	size_t len = 0;

	if (cd == NULL) {
		return 0;
	}

	switch (cd->opcode) {
	case CTDB_CONTROL_PROCESS_EXISTS:
		len = ctdb_pid_len(cd->data.pid);
		break;

	case CTDB_CONTROL_STATISTICS:
		break;

	case CTDB_CONTROL_PING:
		break;

	case CTDB_CONTROL_GETDBPATH:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_GETVNNMAP:
		break;

	case CTDB_CONTROL_SETVNNMAP:
		len = ctdb_vnn_map_len(cd->data.vnnmap);
		break;

	case CTDB_CONTROL_GET_DEBUG:
		break;

	case CTDB_CONTROL_SET_DEBUG:
		len = ctdb_uint32_len(cd->data.loglevel);
		break;

	case CTDB_CONTROL_GET_DBMAP:
		break;

	case CTDB_CONTROL_PULL_DB:
		len = ctdb_pulldb_len(cd->data.pulldb);
		break;

	case CTDB_CONTROL_PUSH_DB:
		len = ctdb_rec_buffer_len(cd->data.recbuf);
		break;

	case CTDB_CONTROL_GET_RECMODE:
		break;

	case CTDB_CONTROL_SET_RECMODE:
		len = ctdb_uint32_len(cd->data.recmode);
		break;

	case CTDB_CONTROL_STATISTICS_RESET:
		break;

	case CTDB_CONTROL_DB_ATTACH:
		len = ctdb_string_len(cd->data.db_name);
		break;

	case CTDB_CONTROL_SET_CALL:
		break;

	case CTDB_CONTROL_TRAVERSE_START:
		len = ctdb_traverse_start_len(cd->data.traverse_start);
		break;

	case CTDB_CONTROL_TRAVERSE_ALL:
		len = ctdb_traverse_all_len(cd->data.traverse_all);
		break;

	case CTDB_CONTROL_TRAVERSE_DATA:
		len = ctdb_rec_data_len(cd->data.rec_data);
		break;

	case CTDB_CONTROL_REGISTER_SRVID:
		break;

	case CTDB_CONTROL_DEREGISTER_SRVID:
		break;

	case CTDB_CONTROL_GET_DBNAME:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_ENABLE_SEQNUM:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_UPDATE_SEQNUM:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_DUMP_MEMORY:
		break;

	case CTDB_CONTROL_GET_PID:
		break;

	case CTDB_CONTROL_GET_RECMASTER:
		break;

	case CTDB_CONTROL_SET_RECMASTER:
		len = ctdb_uint32_len(cd->data.recmaster);
		break;

	case CTDB_CONTROL_FREEZE:
		break;

	case CTDB_CONTROL_GET_PNN:
		break;

	case CTDB_CONTROL_SHUTDOWN:
		break;

	case CTDB_CONTROL_GET_MONMODE:
		break;

	case CTDB_CONTROL_TCP_CLIENT:
		len = ctdb_connection_len(cd->data.conn);
		break;

	case CTDB_CONTROL_TCP_ADD:
		len = ctdb_connection_len(cd->data.conn);
		break;

	case CTDB_CONTROL_TCP_REMOVE:
		len = ctdb_connection_len(cd->data.conn);
		break;

	case CTDB_CONTROL_STARTUP:
		break;

	case CTDB_CONTROL_SET_TUNABLE:
		len = ctdb_tunable_len(cd->data.tunable);
		break;

	case CTDB_CONTROL_GET_TUNABLE:
		len = ctdb_stringn_len(cd->data.tun_var);
		break;

	case CTDB_CONTROL_LIST_TUNABLES:
		break;

	case CTDB_CONTROL_MODIFY_FLAGS:
		len = ctdb_node_flag_change_len(cd->data.flag_change);
		break;

	case CTDB_CONTROL_GET_ALL_TUNABLES:
		break;

	case CTDB_CONTROL_GET_TCP_TICKLE_LIST:
		len = ctdb_sock_addr_len(cd->data.addr);
		break;

	case CTDB_CONTROL_SET_TCP_TICKLE_LIST:
		len = ctdb_tickle_list_len(cd->data.tickles);
		break;

	case CTDB_CONTROL_DB_ATTACH_PERSISTENT:
		len = ctdb_string_len(cd->data.db_name);
		break;

	case CTDB_CONTROL_UPDATE_RECORD:
		len = ctdb_rec_buffer_len(cd->data.recbuf);
		break;

	case CTDB_CONTROL_SEND_GRATUITOUS_ARP:
		len = ctdb_addr_info_len(cd->data.addr_info);
		break;

	case CTDB_CONTROL_WIPE_DATABASE:
		len = ctdb_transdb_len(cd->data.transdb);
		break;

	case CTDB_CONTROL_UPTIME:
		break;

	case CTDB_CONTROL_START_RECOVERY:
		break;

	case CTDB_CONTROL_END_RECOVERY:
		break;

	case CTDB_CONTROL_RELOAD_NODES_FILE:
		break;

	case CTDB_CONTROL_TRY_DELETE_RECORDS:
		len = ctdb_rec_buffer_len(cd->data.recbuf);
		break;

	case CTDB_CONTROL_ENABLE_MONITOR:
		break;

	case CTDB_CONTROL_DISABLE_MONITOR:
		break;

	case CTDB_CONTROL_ADD_PUBLIC_IP:
		len = ctdb_addr_info_len(cd->data.addr_info);
		break;

	case CTDB_CONTROL_DEL_PUBLIC_IP:
		len = ctdb_addr_info_len(cd->data.addr_info);
		break;

	case CTDB_CONTROL_GET_CAPABILITIES:
		break;

	case CTDB_CONTROL_RECD_PING:
		break;

	case CTDB_CONTROL_RELEASE_IP:
		len = ctdb_public_ip_len(cd->data.pubip);
		break;

	case CTDB_CONTROL_TAKEOVER_IP:
		len = ctdb_public_ip_len(cd->data.pubip);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IPS:
		break;

	case CTDB_CONTROL_GET_NODEMAP:
		break;

	case CTDB_CONTROL_TRAVERSE_KILL:
		len = ctdb_traverse_start_len(cd->data.traverse_start);
		break;

	case CTDB_CONTROL_RECD_RECLOCK_LATENCY:
		len = ctdb_double_len(cd->data.reclock_latency);
		break;

	case CTDB_CONTROL_GET_RECLOCK_FILE:
		break;

	case CTDB_CONTROL_STOP_NODE:
		break;

	case CTDB_CONTROL_CONTINUE_NODE:
		break;

	case CTDB_CONTROL_SET_LMASTERROLE:
		len = ctdb_uint32_len(cd->data.role);
		break;

	case CTDB_CONTROL_SET_RECMASTERROLE:
		len = ctdb_uint32_len(cd->data.role);
		break;

	case CTDB_CONTROL_SET_BAN_STATE:
		len = ctdb_ban_state_len(cd->data.ban_state);
		break;

	case CTDB_CONTROL_GET_BAN_STATE:
		break;

	case CTDB_CONTROL_REGISTER_NOTIFY:
		len = ctdb_notify_data_len(cd->data.notify);
		break;

	case CTDB_CONTROL_DEREGISTER_NOTIFY:
		len = ctdb_uint64_len(cd->data.srvid);
		break;

	case CTDB_CONTROL_TRANS3_COMMIT:
		len = ctdb_rec_buffer_len(cd->data.recbuf);
		break;

	case CTDB_CONTROL_GET_DB_SEQNUM:
		len = ctdb_uint64_len((uint64_t)cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_SET_HEALTHY:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_GET_HEALTH:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IP_INFO:
		len = ctdb_sock_addr_len(cd->data.addr);
		break;

	case CTDB_CONTROL_GET_IFACES:
		break;

	case CTDB_CONTROL_SET_IFACE_LINK_STATE:
		len = ctdb_iface_len(cd->data.iface);
		break;

	case CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE:
		len = ctdb_connection_len(cd->data.conn);
		break;

	case CTDB_CONTROL_GET_STAT_HISTORY:
		break;

	case CTDB_CONTROL_SCHEDULE_FOR_DELETION:
		len = ctdb_key_data_len(cd->data.key);
		break;

	case CTDB_CONTROL_SET_DB_READONLY:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_CHECK_SRVIDS:
		len = ctdb_uint64_array_len(cd->data.u64_array);
		break;

	case CTDB_CONTROL_TRAVERSE_START_EXT:
		len = ctdb_traverse_start_ext_len(cd->data.traverse_start_ext);
		break;

	case CTDB_CONTROL_GET_DB_STATISTICS:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_SET_DB_STICKY:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_RELOAD_PUBLIC_IPS:
		break;

	case CTDB_CONTROL_TRAVERSE_ALL_EXT:
		len = ctdb_traverse_all_ext_len(cd->data.traverse_all_ext);
		break;

	case CTDB_CONTROL_RECEIVE_RECORDS:
		len = ctdb_rec_buffer_len(cd->data.recbuf);
		break;

	case CTDB_CONTROL_IPREALLOCATED:
		break;

	case CTDB_CONTROL_GET_RUNSTATE:
		break;

	case CTDB_CONTROL_DB_DETACH:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_GET_NODES_FILE:
		break;

	case CTDB_CONTROL_DB_FREEZE:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_THAW:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_START:
		len = ctdb_transdb_len(cd->data.transdb);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_COMMIT:
		len = ctdb_transdb_len(cd->data.transdb);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_CANCEL:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_PULL:
		len = ctdb_pulldb_ext_len(cd->data.pulldb_ext);
		break;

	case CTDB_CONTROL_DB_PUSH_START:
		len = ctdb_pulldb_ext_len(cd->data.pulldb_ext);
		break;

	case CTDB_CONTROL_DB_PUSH_CONFIRM:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_OPEN_FLAGS:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
		len = ctdb_string_len(cd->data.db_name);
		break;

	case CTDB_CONTROL_CHECK_PID_SRVID:
		len = ctdb_pid_srvid_len(cd->data.pid_srvid);
		break;
	}

	return len;
}

static void ctdb_req_control_data_push(struct ctdb_req_control_data *cd,
				       uint8_t *buf)
{
	switch (cd->opcode) {
	case CTDB_CONTROL_PROCESS_EXISTS:
		ctdb_pid_push(cd->data.pid, buf);
		break;

	case CTDB_CONTROL_GETDBPATH:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_SETVNNMAP:
		ctdb_vnn_map_push(cd->data.vnnmap, buf);
		break;

	case CTDB_CONTROL_SET_DEBUG:
		ctdb_uint32_push(cd->data.loglevel, buf);
		break;

	case CTDB_CONTROL_PULL_DB:
		ctdb_pulldb_push(cd->data.pulldb, buf);
		break;

	case CTDB_CONTROL_PUSH_DB:
		ctdb_rec_buffer_push(cd->data.recbuf, buf);
		break;

	case CTDB_CONTROL_SET_RECMODE:
		ctdb_uint32_push(cd->data.recmode, buf);
		break;

	case CTDB_CONTROL_DB_ATTACH:
		ctdb_string_push(cd->data.db_name, buf);
		break;

	case CTDB_CONTROL_SET_CALL:
		break;

	case CTDB_CONTROL_TRAVERSE_START:
		ctdb_traverse_start_push(cd->data.traverse_start, buf);
		break;

	case CTDB_CONTROL_TRAVERSE_ALL:
		ctdb_traverse_all_push(cd->data.traverse_all, buf);
		break;

	case CTDB_CONTROL_TRAVERSE_DATA:
		ctdb_rec_data_push(cd->data.rec_data, buf);
		break;

	case CTDB_CONTROL_GET_DBNAME:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_ENABLE_SEQNUM:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_UPDATE_SEQNUM:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_SET_RECMASTER:
		ctdb_uint32_push(cd->data.recmaster, buf);
		break;

	case CTDB_CONTROL_TCP_CLIENT:
		ctdb_connection_push(cd->data.conn, buf);
		break;

	case CTDB_CONTROL_TCP_ADD:
		ctdb_connection_push(cd->data.conn, buf);
		break;

	case CTDB_CONTROL_TCP_REMOVE:
		ctdb_connection_push(cd->data.conn, buf);
		break;

	case CTDB_CONTROL_SET_TUNABLE:
		ctdb_tunable_push(cd->data.tunable, buf);
		break;

	case CTDB_CONTROL_GET_TUNABLE:
		ctdb_stringn_push(cd->data.tun_var, buf);
		break;

	case CTDB_CONTROL_MODIFY_FLAGS:
		ctdb_node_flag_change_push(cd->data.flag_change, buf);
		break;

	case CTDB_CONTROL_GET_TCP_TICKLE_LIST:
		ctdb_sock_addr_push(cd->data.addr, buf);
		break;

	case CTDB_CONTROL_SET_TCP_TICKLE_LIST:
		ctdb_tickle_list_push(cd->data.tickles, buf);
		break;

	case CTDB_CONTROL_DB_ATTACH_PERSISTENT:
		ctdb_string_push(cd->data.db_name, buf);
		break;

	case CTDB_CONTROL_UPDATE_RECORD:
		ctdb_rec_buffer_push(cd->data.recbuf, buf);
		break;

	case CTDB_CONTROL_SEND_GRATUITOUS_ARP:
		ctdb_addr_info_push(cd->data.addr_info, buf);
		break;

	case CTDB_CONTROL_WIPE_DATABASE:
		ctdb_transdb_push(cd->data.transdb, buf);
		break;

	case CTDB_CONTROL_TRY_DELETE_RECORDS:
		ctdb_rec_buffer_push(cd->data.recbuf, buf);
		break;

	case CTDB_CONTROL_ADD_PUBLIC_IP:
		ctdb_addr_info_push(cd->data.addr_info, buf);
		break;

	case CTDB_CONTROL_DEL_PUBLIC_IP:
		ctdb_addr_info_push(cd->data.addr_info, buf);
		break;

	case CTDB_CONTROL_RELEASE_IP:
		ctdb_public_ip_push(cd->data.pubip, buf);
		break;

	case CTDB_CONTROL_TAKEOVER_IP:
		ctdb_public_ip_push(cd->data.pubip, buf);
		break;

	case CTDB_CONTROL_TRAVERSE_KILL:
		ctdb_traverse_start_push(cd->data.traverse_start, buf);
		break;

	case CTDB_CONTROL_RECD_RECLOCK_LATENCY:
		ctdb_double_push(cd->data.reclock_latency, buf);
		break;

	case CTDB_CONTROL_SET_LMASTERROLE:
		ctdb_uint32_push(cd->data.role, buf);
		break;

	case CTDB_CONTROL_SET_RECMASTERROLE:
		ctdb_uint32_push(cd->data.role, buf);
		break;

	case CTDB_CONTROL_SET_BAN_STATE:
		ctdb_ban_state_push(cd->data.ban_state, buf);
		break;

	case CTDB_CONTROL_REGISTER_NOTIFY:
		ctdb_notify_data_push(cd->data.notify, buf);
		break;

	case CTDB_CONTROL_DEREGISTER_NOTIFY:
		ctdb_uint64_push(cd->data.srvid, buf);
		break;

	case CTDB_CONTROL_TRANS3_COMMIT:
		ctdb_rec_buffer_push(cd->data.recbuf, buf);
		break;

	case CTDB_CONTROL_GET_DB_SEQNUM:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_DB_SET_HEALTHY:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_DB_GET_HEALTH:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IP_INFO:
		ctdb_sock_addr_push(cd->data.addr, buf);
		break;

	case CTDB_CONTROL_SET_IFACE_LINK_STATE:
		ctdb_iface_push(cd->data.iface, buf);
		break;

	case CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE:
		ctdb_connection_push(cd->data.conn, buf);
		break;

	case CTDB_CONTROL_SCHEDULE_FOR_DELETION:
		ctdb_key_data_push(cd->data.key, buf);
		break;

	case CTDB_CONTROL_SET_DB_READONLY:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_CHECK_SRVIDS:
		ctdb_uint64_array_push(cd->data.u64_array, buf);
		break;

	case CTDB_CONTROL_TRAVERSE_START_EXT:
		ctdb_traverse_start_ext_push(cd->data.traverse_start_ext, buf);
		break;

	case CTDB_CONTROL_GET_DB_STATISTICS:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_SET_DB_STICKY:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_TRAVERSE_ALL_EXT:
		ctdb_traverse_all_ext_push(cd->data.traverse_all_ext, buf);
		break;

	case CTDB_CONTROL_RECEIVE_RECORDS:
		ctdb_rec_buffer_push(cd->data.recbuf, buf);
		break;

	case CTDB_CONTROL_DB_DETACH:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_DB_FREEZE:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_DB_THAW:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_START:
		ctdb_transdb_push(cd->data.transdb, buf);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_COMMIT:
		ctdb_transdb_push(cd->data.transdb, buf);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_CANCEL:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_DB_PULL:
		ctdb_pulldb_ext_push(cd->data.pulldb_ext, buf);
		break;

	case CTDB_CONTROL_DB_PUSH_START:
		ctdb_pulldb_ext_push(cd->data.pulldb_ext, buf);
		break;

	case CTDB_CONTROL_DB_PUSH_CONFIRM:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_DB_OPEN_FLAGS:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
		ctdb_string_push(cd->data.db_name, buf);
		break;

	case CTDB_CONTROL_CHECK_PID_SRVID:
		ctdb_pid_srvid_push(cd->data.pid_srvid, buf);
		break;
	}
}

static int ctdb_req_control_data_pull(uint8_t *buf, size_t buflen,
				      uint32_t opcode,
				      TALLOC_CTX *mem_ctx,
				      struct ctdb_req_control_data *cd)
{
	int ret = 0;

	cd->opcode = opcode;

	switch (opcode) {
	case CTDB_CONTROL_PROCESS_EXISTS:
		ret = ctdb_pid_pull(buf, buflen, mem_ctx,
				    &cd->data.pid);
		break;

	case CTDB_CONTROL_GETDBPATH:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				     &cd->data.db_id);
		break;

	case CTDB_CONTROL_SETVNNMAP:
		ret = ctdb_vnn_map_pull(buf, buflen, mem_ctx,
					&cd->data.vnnmap);
		break;

	case CTDB_CONTROL_SET_DEBUG:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				     &cd->data.loglevel);
		break;

	case CTDB_CONTROL_PULL_DB:
		ret = ctdb_pulldb_pull(buf, buflen, mem_ctx,
				       &cd->data.pulldb);
		break;

	case CTDB_CONTROL_PUSH_DB:
		ret = ctdb_rec_buffer_pull(buf, buflen, mem_ctx,
					   &cd->data.recbuf);
		break;

	case CTDB_CONTROL_SET_RECMODE:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				     &cd->data.recmode);
		break;

	case CTDB_CONTROL_DB_ATTACH:
		ret = ctdb_string_pull(buf, buflen, mem_ctx,
				       &cd->data.db_name);
		break;

	case CTDB_CONTROL_SET_CALL:
		break;

	case CTDB_CONTROL_TRAVERSE_START:
		ret = ctdb_traverse_start_pull(buf, buflen, mem_ctx,
					       &cd->data.traverse_start);
		break;

	case CTDB_CONTROL_TRAVERSE_ALL:
		ret = ctdb_traverse_all_pull(buf, buflen, mem_ctx,
					     &cd->data.traverse_all);
		break;

	case CTDB_CONTROL_TRAVERSE_DATA:
		ret = ctdb_rec_data_pull(buf, buflen, mem_ctx,
					 &cd->data.rec_data);
		break;

	case CTDB_CONTROL_GET_DBNAME:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				     &cd->data.db_id);
		break;

	case CTDB_CONTROL_ENABLE_SEQNUM:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				     &cd->data.db_id);
		break;

	case CTDB_CONTROL_UPDATE_SEQNUM:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				     &cd->data.db_id);
		break;

	case CTDB_CONTROL_SET_RECMASTER:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				     &cd->data.recmaster);
		break;

	case CTDB_CONTROL_TCP_CLIENT:
		ret = ctdb_connection_pull(buf, buflen, mem_ctx,
					   &cd->data.conn);
		break;

	case CTDB_CONTROL_TCP_ADD:
		ret = ctdb_connection_pull(buf, buflen, mem_ctx,
					   &cd->data.conn);
		break;

	case CTDB_CONTROL_TCP_REMOVE:
		ret = ctdb_connection_pull(buf, buflen, mem_ctx,
					   &cd->data.conn);
		break;

	case CTDB_CONTROL_SET_TUNABLE:
		ret = ctdb_tunable_pull(buf, buflen, mem_ctx,
					&cd->data.tunable);
		break;

	case CTDB_CONTROL_GET_TUNABLE:
		ret = ctdb_stringn_pull(buf, buflen, mem_ctx,
					&cd->data.tun_var);
		break;

	case CTDB_CONTROL_MODIFY_FLAGS:
		ret = ctdb_node_flag_change_pull(buf, buflen, mem_ctx,
						 &cd->data.flag_change);
		break;

	case CTDB_CONTROL_GET_TCP_TICKLE_LIST:
		ret = ctdb_sock_addr_pull(buf, buflen, mem_ctx,
					  &cd->data.addr);
		break;

	case CTDB_CONTROL_SET_TCP_TICKLE_LIST:
		ret = ctdb_tickle_list_pull(buf, buflen, mem_ctx,
					    &cd->data.tickles);
		break;

	case CTDB_CONTROL_DB_ATTACH_PERSISTENT:
		ret = ctdb_string_pull(buf, buflen, mem_ctx,
				       &cd->data.db_name);
		break;

	case CTDB_CONTROL_UPDATE_RECORD:
		ret = ctdb_rec_buffer_pull(buf, buflen, mem_ctx,
					   &cd->data.recbuf);
		break;

	case CTDB_CONTROL_SEND_GRATUITOUS_ARP:
		ret = ctdb_addr_info_pull(buf, buflen, mem_ctx,
					  &cd->data.addr_info);
		break;

	case CTDB_CONTROL_WIPE_DATABASE:
		ret = ctdb_transdb_pull(buf, buflen, mem_ctx,
				       &cd->data.transdb);
		break;

	case CTDB_CONTROL_TRY_DELETE_RECORDS:
		ret = ctdb_rec_buffer_pull(buf, buflen, mem_ctx,
					   &cd->data.recbuf);
		break;

	case CTDB_CONTROL_ADD_PUBLIC_IP:
		ret = ctdb_addr_info_pull(buf, buflen, mem_ctx,
					  &cd->data.addr_info);
		break;

	case CTDB_CONTROL_DEL_PUBLIC_IP:
		ret = ctdb_addr_info_pull(buf, buflen, mem_ctx,
					  &cd->data.addr_info);
		break;

	case CTDB_CONTROL_RELEASE_IP:
		ret = ctdb_public_ip_pull(buf, buflen, mem_ctx,
					  &cd->data.pubip);
		break;

	case CTDB_CONTROL_TAKEOVER_IP:
		ret = ctdb_public_ip_pull(buf, buflen, mem_ctx,
					  &cd->data.pubip);
		break;

	case CTDB_CONTROL_TRAVERSE_KILL:
		ret = ctdb_traverse_start_pull(buf, buflen, mem_ctx,
					       &cd->data.traverse_start);
		break;

	case CTDB_CONTROL_RECD_RECLOCK_LATENCY:
		ret = ctdb_double_pull(buf, buflen, mem_ctx,
				       &cd->data.reclock_latency);
		break;

	case CTDB_CONTROL_SET_LMASTERROLE:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				     &cd->data.role);
		break;

	case CTDB_CONTROL_SET_RECMASTERROLE:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				     &cd->data.role);
		break;

	case CTDB_CONTROL_SET_BAN_STATE:
		ret = ctdb_ban_state_pull(buf, buflen, mem_ctx,
					  &cd->data.ban_state);
		break;

	case CTDB_CONTROL_REGISTER_NOTIFY:
		ret = ctdb_notify_data_pull(buf, buflen, mem_ctx,
					    &cd->data.notify);
		break;

	case CTDB_CONTROL_DEREGISTER_NOTIFY:
		ctdb_uint64_pull(buf, buflen, mem_ctx,
				 &cd->data.srvid);
		break;

	case CTDB_CONTROL_TRANS3_COMMIT:
		ret = ctdb_rec_buffer_pull(buf, buflen, mem_ctx,
					   &cd->data.recbuf);
		break;

	case CTDB_CONTROL_GET_DB_SEQNUM:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				       &cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_SET_HEALTHY:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				     &cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_GET_HEALTH:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				     &cd->data.db_id);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IP_INFO:
		ret = ctdb_sock_addr_pull(buf, buflen, mem_ctx,
					  &cd->data.addr);
		break;

	case CTDB_CONTROL_SET_IFACE_LINK_STATE:
		ret = ctdb_iface_pull(buf, buflen, mem_ctx,
				      &cd->data.iface);
		break;

	case CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE:
		ret = ctdb_connection_pull(buf, buflen, mem_ctx,
					   &cd->data.conn);
		break;

	case CTDB_CONTROL_SCHEDULE_FOR_DELETION:
		ret = ctdb_key_data_pull(buf, buflen, mem_ctx,
					 &cd->data.key);
		break;

	case CTDB_CONTROL_SET_DB_READONLY:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				     &cd->data.db_id);
		break;

	case CTDB_CONTROL_CHECK_SRVIDS:
		ret = ctdb_uint64_array_pull(buf, buflen, mem_ctx,
					     &cd->data.u64_array);
		break;

	case CTDB_CONTROL_TRAVERSE_START_EXT:
		ret = ctdb_traverse_start_ext_pull(buf, buflen, mem_ctx,
						   &cd->data.traverse_start_ext);
		break;

	case CTDB_CONTROL_GET_DB_STATISTICS:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				       &cd->data.db_id);
		break;

	case CTDB_CONTROL_SET_DB_STICKY:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				       &cd->data.db_id);
		break;

	case CTDB_CONTROL_TRAVERSE_ALL_EXT:
		ret = ctdb_traverse_all_ext_pull(buf, buflen, mem_ctx,
						 &cd->data.traverse_all_ext);
		break;

	case CTDB_CONTROL_RECEIVE_RECORDS:
		ret = ctdb_rec_buffer_pull(buf, buflen, mem_ctx,
					   &cd->data.recbuf);
		break;

	case CTDB_CONTROL_DB_DETACH:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				       &cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_FREEZE:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				       &cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_THAW:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				       &cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_START:
		ret = ctdb_transdb_pull(buf, buflen, mem_ctx,
					&cd->data.transdb);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_COMMIT:
		ret = ctdb_transdb_pull(buf, buflen, mem_ctx,
					&cd->data.transdb);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_CANCEL:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
					&cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_PULL:
		ret = ctdb_pulldb_ext_pull(buf, buflen, mem_ctx,
					   &cd->data.pulldb_ext);
		break;

	case CTDB_CONTROL_DB_PUSH_START:
		ret = ctdb_pulldb_ext_pull(buf, buflen, mem_ctx,
					   &cd->data.pulldb_ext);
		break;

	case CTDB_CONTROL_DB_PUSH_CONFIRM:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				       &cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_OPEN_FLAGS:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				       &cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
		ret = ctdb_string_pull(buf, buflen, mem_ctx,
				       &cd->data.db_name);
		break;

	case CTDB_CONTROL_CHECK_PID_SRVID:
		ret = ctdb_pid_srvid_pull(buf, buflen, mem_ctx,
					  &cd->data.pid_srvid);
		break;
	}

	return ret;
}

static size_t ctdb_reply_control_data_len(struct ctdb_reply_control_data *cd)
{
	size_t len = 0;

	if (cd == NULL) {
		return 0;
	}

	switch (cd->opcode) {
	case CTDB_CONTROL_PROCESS_EXISTS:
		break;

	case CTDB_CONTROL_STATISTICS:
		len = ctdb_statistics_len(cd->data.stats);
		break;

	case CTDB_CONTROL_PING:
		break;

	case CTDB_CONTROL_GETDBPATH:
		len = ctdb_string_len(cd->data.db_path);
		break;

	case CTDB_CONTROL_GETVNNMAP:
		len = ctdb_vnn_map_len(cd->data.vnnmap);
		break;

	case CTDB_CONTROL_SETVNNMAP:
		break;

	case CTDB_CONTROL_GET_DEBUG:
		len = ctdb_uint32_len(cd->data.loglevel);
		break;

	case CTDB_CONTROL_SET_DEBUG:
		break;

	case CTDB_CONTROL_GET_DBMAP:
		len = ctdb_dbid_map_len(cd->data.dbmap);
		break;

	case CTDB_CONTROL_PULL_DB:
		len = ctdb_rec_buffer_len(cd->data.recbuf);
		break;

	case CTDB_CONTROL_PUSH_DB:
		break;

	case CTDB_CONTROL_GET_RECMODE:
		break;

	case CTDB_CONTROL_SET_RECMODE:
		break;

	case CTDB_CONTROL_STATISTICS_RESET:
		break;

	case CTDB_CONTROL_DB_ATTACH:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_SET_CALL:
		break;

	case CTDB_CONTROL_TRAVERSE_START:
		break;

	case CTDB_CONTROL_TRAVERSE_ALL:
		break;

	case CTDB_CONTROL_TRAVERSE_DATA:
		break;

	case CTDB_CONTROL_REGISTER_SRVID:
		break;

	case CTDB_CONTROL_DEREGISTER_SRVID:
		break;

	case CTDB_CONTROL_GET_DBNAME:
		len = ctdb_string_len(cd->data.db_name);
		break;

	case CTDB_CONTROL_ENABLE_SEQNUM:
		break;

	case CTDB_CONTROL_UPDATE_SEQNUM:
		break;

	case CTDB_CONTROL_DUMP_MEMORY:
		len = ctdb_string_len(cd->data.mem_str);
		break;

	case CTDB_CONTROL_GET_PID:
		break;

	case CTDB_CONTROL_GET_RECMASTER:
		break;

	case CTDB_CONTROL_SET_RECMASTER:
		break;

	case CTDB_CONTROL_FREEZE:
		break;

	case CTDB_CONTROL_GET_PNN:
		break;

	case CTDB_CONTROL_SHUTDOWN:
		break;

	case CTDB_CONTROL_GET_MONMODE:
		break;

	case CTDB_CONTROL_TCP_CLIENT:
		break;

	case CTDB_CONTROL_TCP_ADD:
		break;

	case CTDB_CONTROL_TCP_REMOVE:
		break;

	case CTDB_CONTROL_STARTUP:
		break;

	case CTDB_CONTROL_SET_TUNABLE:
		break;

	case CTDB_CONTROL_GET_TUNABLE:
		len = ctdb_uint32_len(cd->data.tun_value);
		break;

	case CTDB_CONTROL_LIST_TUNABLES:
		len = ctdb_var_list_len(cd->data.tun_var_list);
		break;

	case CTDB_CONTROL_MODIFY_FLAGS:
		break;

	case CTDB_CONTROL_GET_ALL_TUNABLES:
		len = ctdb_tunable_list_len(cd->data.tun_list);
		break;

	case CTDB_CONTROL_GET_TCP_TICKLE_LIST:
		len = ctdb_tickle_list_len(cd->data.tickles);
		break;

	case CTDB_CONTROL_SET_TCP_TICKLE_LIST:
		break;

	case CTDB_CONTROL_DB_ATTACH_PERSISTENT:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_UPDATE_RECORD:
		break;

	case CTDB_CONTROL_SEND_GRATUITOUS_ARP:
		break;

	case CTDB_CONTROL_WIPE_DATABASE:
		break;

	case CTDB_CONTROL_UPTIME:
		len = ctdb_uptime_len(cd->data.uptime);
		break;

	case CTDB_CONTROL_START_RECOVERY:
		break;

	case CTDB_CONTROL_END_RECOVERY:
		break;

	case CTDB_CONTROL_RELOAD_NODES_FILE:
		break;

	case CTDB_CONTROL_TRY_DELETE_RECORDS:
		len = ctdb_rec_buffer_len(cd->data.recbuf);
		break;

	case CTDB_CONTROL_ENABLE_MONITOR:
		break;

	case CTDB_CONTROL_DISABLE_MONITOR:
		break;

	case CTDB_CONTROL_ADD_PUBLIC_IP:
		break;

	case CTDB_CONTROL_DEL_PUBLIC_IP:
		break;

	case CTDB_CONTROL_GET_CAPABILITIES:
		len = ctdb_uint32_len(cd->data.caps);
		break;

	case CTDB_CONTROL_RECD_PING:
		break;

	case CTDB_CONTROL_RELEASE_IP:
		break;

	case CTDB_CONTROL_TAKEOVER_IP:
		break;

	case CTDB_CONTROL_GET_PUBLIC_IPS:
		len = ctdb_public_ip_list_len(cd->data.pubip_list);
		break;

	case CTDB_CONTROL_GET_NODEMAP:
		len = ctdb_node_map_len(cd->data.nodemap);
		break;

	case CTDB_CONTROL_TRAVERSE_KILL:
		break;

	case CTDB_CONTROL_RECD_RECLOCK_LATENCY:
		break;

	case CTDB_CONTROL_GET_RECLOCK_FILE:
		len = ctdb_string_len(cd->data.reclock_file);
		break;

	case CTDB_CONTROL_STOP_NODE:
		break;

	case CTDB_CONTROL_CONTINUE_NODE:
		break;

	case CTDB_CONTROL_SET_LMASTERROLE:
		break;

	case CTDB_CONTROL_SET_RECMASTERROLE:
		break;

	case CTDB_CONTROL_SET_BAN_STATE:
		break;

	case CTDB_CONTROL_GET_BAN_STATE:
		len = ctdb_ban_state_len(cd->data.ban_state);
		break;

	case CTDB_CONTROL_SET_DB_PRIORITY:
		break;

	case CTDB_CONTROL_GET_DB_PRIORITY:
		break;

	case CTDB_CONTROL_REGISTER_NOTIFY:
		break;

	case CTDB_CONTROL_DEREGISTER_NOTIFY:
		break;

	case CTDB_CONTROL_TRANS3_COMMIT:
		break;

	case CTDB_CONTROL_GET_DB_SEQNUM:
		len = ctdb_uint64_len(cd->data.seqnum);
		break;

	case CTDB_CONTROL_DB_SET_HEALTHY:
		break;

	case CTDB_CONTROL_DB_GET_HEALTH:
		len = ctdb_string_len(cd->data.reason);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IP_INFO:
		len = ctdb_public_ip_info_len(cd->data.ipinfo);
		break;

	case CTDB_CONTROL_GET_IFACES:
		len = ctdb_iface_list_len(cd->data.iface_list);
		break;

	case CTDB_CONTROL_SET_IFACE_LINK_STATE:
		break;

	case CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE:
		break;

	case CTDB_CONTROL_GET_STAT_HISTORY:
		len = ctdb_statistics_list_len(cd->data.stats_list);
		break;

	case CTDB_CONTROL_SCHEDULE_FOR_DELETION:
		break;

	case CTDB_CONTROL_SET_DB_READONLY:
		break;

	case CTDB_CONTROL_CHECK_SRVIDS:
		len = ctdb_uint8_array_len(cd->data.u8_array);
		break;

	case CTDB_CONTROL_TRAVERSE_START_EXT:
		break;

	case CTDB_CONTROL_GET_DB_STATISTICS:
		len = ctdb_db_statistics_len(cd->data.dbstats);
		break;

	case CTDB_CONTROL_SET_DB_STICKY:
		break;

	case CTDB_CONTROL_RELOAD_PUBLIC_IPS:
		break;

	case CTDB_CONTROL_TRAVERSE_ALL_EXT:
		break;

	case CTDB_CONTROL_RECEIVE_RECORDS:
		len = ctdb_rec_buffer_len(cd->data.recbuf);
		break;

	case CTDB_CONTROL_IPREALLOCATED:
		break;

	case CTDB_CONTROL_GET_RUNSTATE:
		len = ctdb_uint32_len(cd->data.runstate);
		break;

	case CTDB_CONTROL_DB_DETACH:
		break;

	case CTDB_CONTROL_GET_NODES_FILE:
		len = ctdb_node_map_len(cd->data.nodemap);
		break;

	case CTDB_CONTROL_DB_FREEZE:
		break;

	case CTDB_CONTROL_DB_THAW:
		break;

	case CTDB_CONTROL_DB_TRANSACTION_START:
		break;

	case CTDB_CONTROL_DB_TRANSACTION_COMMIT:
		break;

	case CTDB_CONTROL_DB_TRANSACTION_CANCEL:
		break;

	case CTDB_CONTROL_DB_PULL:
		len = ctdb_uint32_len(cd->data.num_records);
		break;

	case CTDB_CONTROL_DB_PUSH_START:
		break;

	case CTDB_CONTROL_DB_PUSH_CONFIRM:
		len = ctdb_uint32_len(cd->data.num_records);
		break;

	case CTDB_CONTROL_DB_OPEN_FLAGS:
		len = ctdb_int32_len(cd->data.tdb_flags);
		break;

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
		len = ctdb_uint32_len(cd->data.db_id);
		break;

	case CTDB_CONTROL_CHECK_PID_SRVID:
		break;
	}

	return len;
}

static void ctdb_reply_control_data_push(struct ctdb_reply_control_data *cd,
					 uint8_t *buf)
{
	switch (cd->opcode) {
	case CTDB_CONTROL_STATISTICS:
		ctdb_statistics_push(cd->data.stats, buf);
		break;

	case CTDB_CONTROL_GETDBPATH:
		ctdb_string_push(cd->data.db_path, buf);
		break;

	case CTDB_CONTROL_GETVNNMAP:
		ctdb_vnn_map_push(cd->data.vnnmap, buf);
		break;

	case CTDB_CONTROL_GET_DEBUG:
		ctdb_uint32_push(cd->data.loglevel, buf);
		break;

	case CTDB_CONTROL_GET_DBMAP:
		ctdb_dbid_map_push(cd->data.dbmap, buf);
		break;

	case CTDB_CONTROL_PULL_DB:
		ctdb_rec_buffer_push(cd->data.recbuf, buf);
		break;

	case CTDB_CONTROL_PUSH_DB:
		break;

	case CTDB_CONTROL_DB_ATTACH:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_GET_DBNAME:
		ctdb_string_push(cd->data.db_name, buf);
		break;

	case CTDB_CONTROL_DUMP_MEMORY:
		ctdb_string_push(cd->data.mem_str, buf);
		break;

	case CTDB_CONTROL_GET_PID:
		break;

	case CTDB_CONTROL_GET_RECMASTER:
		break;

	case CTDB_CONTROL_GET_TUNABLE:
		ctdb_uint32_push(cd->data.tun_value, buf);
		break;

	case CTDB_CONTROL_LIST_TUNABLES:
		ctdb_var_list_push(cd->data.tun_var_list, buf);
		break;

	case CTDB_CONTROL_GET_ALL_TUNABLES:
		ctdb_tunable_list_push(cd->data.tun_list, buf);
		break;

	case CTDB_CONTROL_GET_TCP_TICKLE_LIST:
		ctdb_tickle_list_push(cd->data.tickles, buf);
		break;

	case CTDB_CONTROL_DB_ATTACH_PERSISTENT:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_UPTIME:
		ctdb_uptime_push(cd->data.uptime, buf);
		break;

	case CTDB_CONTROL_TRY_DELETE_RECORDS:
		ctdb_rec_buffer_push(cd->data.recbuf, buf);
		break;

	case CTDB_CONTROL_GET_CAPABILITIES:
		ctdb_uint32_push(cd->data.caps, buf);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IPS:
		ctdb_public_ip_list_push(cd->data.pubip_list, buf);
		break;

	case CTDB_CONTROL_GET_NODEMAP:
		ctdb_node_map_push(cd->data.nodemap, buf);
		break;

	case CTDB_CONTROL_GET_RECLOCK_FILE:
		ctdb_string_push(cd->data.reclock_file, buf);
		break;

	case CTDB_CONTROL_GET_BAN_STATE:
		ctdb_ban_state_push(cd->data.ban_state, buf);
		break;

	case CTDB_CONTROL_GET_DB_PRIORITY:
		break;

	case CTDB_CONTROL_GET_DB_SEQNUM:
		ctdb_uint64_push(cd->data.seqnum, buf);
		break;

	case CTDB_CONTROL_DB_GET_HEALTH:
		ctdb_string_push(cd->data.reason, buf);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IP_INFO:
		ctdb_public_ip_info_push(cd->data.ipinfo, buf);
		break;

	case CTDB_CONTROL_GET_IFACES:
		ctdb_iface_list_push(cd->data.iface_list, buf);
		break;

	case CTDB_CONTROL_GET_STAT_HISTORY:
		ctdb_statistics_list_push(cd->data.stats_list, buf);
		break;

	case CTDB_CONTROL_CHECK_SRVIDS:
		ctdb_uint8_array_push(cd->data.u8_array, buf);
		break;

	case CTDB_CONTROL_GET_DB_STATISTICS:
		ctdb_db_statistics_push(cd->data.dbstats, buf);
		break;

	case CTDB_CONTROL_RECEIVE_RECORDS:
		ctdb_rec_buffer_push(cd->data.recbuf, buf);
		break;

	case CTDB_CONTROL_GET_RUNSTATE:
		ctdb_uint32_push(cd->data.runstate, buf);
		break;

	case CTDB_CONTROL_GET_NODES_FILE:
		ctdb_node_map_push(cd->data.nodemap, buf);
		break;

	case CTDB_CONTROL_DB_PULL:
		ctdb_uint32_push(cd->data.num_records, buf);
		break;

	case CTDB_CONTROL_DB_PUSH_CONFIRM:
		ctdb_uint32_push(cd->data.num_records, buf);
		break;

	case CTDB_CONTROL_DB_OPEN_FLAGS:
		ctdb_int32_push(cd->data.tdb_flags, buf);
		break;

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
		ctdb_uint32_push(cd->data.db_id, buf);
		break;

	case CTDB_CONTROL_CHECK_PID_SRVID:
		break;
	}
}

static int ctdb_reply_control_data_pull(uint8_t *buf, size_t buflen,
					uint32_t opcode, TALLOC_CTX *mem_ctx,
					struct ctdb_reply_control_data *cd)
{
	int ret = 0;
	cd->opcode = opcode;

	switch (opcode) {
	case CTDB_CONTROL_STATISTICS:
		ret = ctdb_statistics_pull(buf, buflen, mem_ctx,
					   &cd->data.stats);
		break;

	case CTDB_CONTROL_GETDBPATH:
		ret = ctdb_string_pull(buf, buflen, mem_ctx,
				       &cd->data.db_path);
		break;

	case CTDB_CONTROL_GETVNNMAP:
		ret = ctdb_vnn_map_pull(buf, buflen, mem_ctx,
					&cd->data.vnnmap);
		break;

	case CTDB_CONTROL_GET_DEBUG:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				     &cd->data.loglevel);
		break;

	case CTDB_CONTROL_GET_DBMAP:
		ret = ctdb_dbid_map_pull(buf, buflen, mem_ctx,
					 &cd->data.dbmap);
		break;

	case CTDB_CONTROL_PULL_DB:
		ret = ctdb_rec_buffer_pull(buf, buflen, mem_ctx,
					   &cd->data.recbuf);
		break;

	case CTDB_CONTROL_PUSH_DB:
		break;

	case CTDB_CONTROL_DB_ATTACH:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				       &cd->data.db_id);
		break;

	case CTDB_CONTROL_GET_DBNAME:
		ret = ctdb_string_pull(buf, buflen, mem_ctx,
				       &cd->data.db_name);
		break;

	case CTDB_CONTROL_DUMP_MEMORY:
		ret = ctdb_string_pull(buf, buflen, mem_ctx,
				       &cd->data.mem_str);
		break;

	case CTDB_CONTROL_GET_PID:
		break;

	case CTDB_CONTROL_GET_RECMASTER:
		break;

	case CTDB_CONTROL_GET_TUNABLE:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				     &cd->data.tun_value);
		break;

	case CTDB_CONTROL_LIST_TUNABLES:
		ret = ctdb_var_list_pull(buf, buflen, mem_ctx,
					 &cd->data.tun_var_list);
		break;

	case CTDB_CONTROL_GET_ALL_TUNABLES:
		ret = ctdb_tunable_list_pull(buf, buflen, mem_ctx,
					     &cd->data.tun_list);
		break;

	case CTDB_CONTROL_GET_TCP_TICKLE_LIST:
		ret = ctdb_tickle_list_pull(buf, buflen, mem_ctx,
					    &cd->data.tickles);
		break;

	case CTDB_CONTROL_DB_ATTACH_PERSISTENT:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				       &cd->data.db_id);
		break;

	case CTDB_CONTROL_UPTIME:
		ret = ctdb_uptime_pull(buf, buflen, mem_ctx,
				       &cd->data.uptime);
		break;

	case CTDB_CONTROL_TRY_DELETE_RECORDS:
		ctdb_rec_buffer_pull(buf, buflen, mem_ctx,
				     &cd->data.recbuf);
		break;

	case CTDB_CONTROL_GET_CAPABILITIES:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				     &cd->data.caps);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IPS:
		ret = ctdb_public_ip_list_pull(buf, buflen, mem_ctx,
					       &cd->data.pubip_list);
		break;

	case CTDB_CONTROL_GET_NODEMAP:
		ret = ctdb_node_map_pull(buf, buflen, mem_ctx,
					 &cd->data.nodemap);
		break;

	case CTDB_CONTROL_GET_RECLOCK_FILE:
		ret = ctdb_string_pull(buf, buflen, mem_ctx,
				       &cd->data.reclock_file);
		break;

	case CTDB_CONTROL_GET_BAN_STATE:
		ret = ctdb_ban_state_pull(buf, buflen, mem_ctx,
					  &cd->data.ban_state);
		break;

	case CTDB_CONTROL_GET_DB_PRIORITY:
		break;

	case CTDB_CONTROL_GET_DB_SEQNUM:
		ret = ctdb_uint64_pull(buf, buflen, mem_ctx,
				       &cd->data.seqnum);
		break;

	case CTDB_CONTROL_DB_GET_HEALTH:
		ret = ctdb_string_pull(buf, buflen, mem_ctx,
				       &cd->data.reason);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IP_INFO:
		ret = ctdb_public_ip_info_pull(buf, buflen, mem_ctx,
					       &cd->data.ipinfo);
		break;

	case CTDB_CONTROL_GET_IFACES:
		ret = ctdb_iface_list_pull(buf, buflen, mem_ctx,
					   &cd->data.iface_list);
		break;

	case CTDB_CONTROL_GET_STAT_HISTORY:
		ret = ctdb_statistics_list_pull(buf, buflen, mem_ctx,
						&cd->data.stats_list);
		break;

	case CTDB_CONTROL_CHECK_SRVIDS:
		ret = ctdb_uint8_array_pull(buf, buflen, mem_ctx,
					    &cd->data.u8_array);
		break;

	case CTDB_CONTROL_GET_DB_STATISTICS:
		ret = ctdb_db_statistics_pull(buf, buflen, mem_ctx,
					      &cd->data.dbstats);
		break;

	case CTDB_CONTROL_RECEIVE_RECORDS:
		ret = ctdb_rec_buffer_pull(buf, buflen, mem_ctx,
					   &cd->data.recbuf);
		break;

	case CTDB_CONTROL_GET_RUNSTATE:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				       &cd->data.runstate);
		break;

	case CTDB_CONTROL_GET_NODES_FILE:
		ret = ctdb_node_map_pull(buf, buflen, mem_ctx,
					 &cd->data.nodemap);
		break;

	case CTDB_CONTROL_DB_PULL:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				       &cd->data.num_records);
		break;

	case CTDB_CONTROL_DB_PUSH_CONFIRM:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				       &cd->data.num_records);
		break;

	case CTDB_CONTROL_DB_OPEN_FLAGS:
		ret = ctdb_int32_pull(buf, buflen, mem_ctx,
				      &cd->data.tdb_flags);
		break;

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx,
				       &cd->data.db_id);
		break;

	case CTDB_CONTROL_CHECK_PID_SRVID:
		break;
	}

	return ret;
}

size_t ctdb_req_control_len(struct ctdb_req_header *h,
			    struct ctdb_req_control *c)
{
	return offsetof(struct ctdb_req_control_wire, data) +
		ctdb_req_control_data_len(&c->rdata);
}

int ctdb_req_control_push(struct ctdb_req_header *h,
			  struct ctdb_req_control *request,
			  uint8_t *buf, size_t *buflen)
{
	struct ctdb_req_control_wire *wire =
		(struct ctdb_req_control_wire *)buf;
	size_t length;

	length = ctdb_req_control_len(h, request);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, (uint8_t *)&wire->hdr);

	wire->opcode = request->opcode;
	wire->pad = request->pad;
	wire->srvid = request->srvid;
	wire->client_id = request->client_id;
	wire->flags = request->flags;

	wire->datalen = ctdb_req_control_data_len(&request->rdata);
	ctdb_req_control_data_push(&request->rdata, wire->data);

	return 0;
}

int ctdb_req_control_pull(uint8_t *buf, size_t buflen,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_req_control *c)
{
	struct ctdb_req_control_wire *wire =
		(struct ctdb_req_control_wire *)buf;
	size_t length;
	int ret;

	length = offsetof(struct ctdb_req_control_wire, data);
	if (buflen < length) {
		return EMSGSIZE;
	}
	if (wire->datalen > buflen) {
		return EMSGSIZE;
	}
	if (length + wire->datalen < length) {
		return EMSGSIZE;
	}
	if (buflen < length + wire->datalen) {
		return EMSGSIZE;
	}

	if (h != NULL) {
		ret = ctdb_req_header_pull((uint8_t *)&wire->hdr, buflen, h);
		if (ret != 0) {
			return ret;
		}
	}

	c->opcode = wire->opcode;
	c->pad = wire->pad;
	c->srvid = wire->srvid;
	c->client_id = wire->client_id;
	c->flags = wire->flags;

	ret = ctdb_req_control_data_pull(wire->data, wire->datalen,
					 c->opcode, mem_ctx, &c->rdata);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

size_t ctdb_reply_control_len(struct ctdb_req_header *h,
			      struct ctdb_reply_control *c)
{
	return offsetof(struct ctdb_reply_control_wire, data) +
		(c->status == 0 ?
			ctdb_reply_control_data_len(&c->rdata) :
			ctdb_string_len(c->errmsg));
}

int ctdb_reply_control_push(struct ctdb_req_header *h,
			    struct ctdb_reply_control *reply,
			    uint8_t *buf, size_t *buflen)
{
	struct ctdb_reply_control_wire *wire =
		(struct ctdb_reply_control_wire *)buf;
	size_t length;

	length = ctdb_reply_control_len(h, reply);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, (uint8_t *)&wire->hdr);

	wire->status = reply->status;

	if (reply->status == 0) {
		wire->datalen = ctdb_reply_control_data_len(&reply->rdata);
		wire->errorlen = 0;
		ctdb_reply_control_data_push(&reply->rdata, wire->data);
	} else {
		wire->datalen = 0;
		wire->errorlen = ctdb_string_len(reply->errmsg);
		ctdb_string_push(reply->errmsg, wire->data + wire->datalen);
	}

	return 0;
}

int ctdb_reply_control_pull(uint8_t *buf, size_t buflen, uint32_t opcode,
			    struct ctdb_req_header *h,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_reply_control *c)
{
	struct ctdb_reply_control_wire *wire =
		(struct ctdb_reply_control_wire *)buf;
	size_t length;
	int ret;

	length = offsetof(struct ctdb_reply_control_wire, data);
	if (buflen < length) {
		return EMSGSIZE;
	}
	if (wire->datalen > buflen || wire->errorlen > buflen) {
		return EMSGSIZE;
	}
	if (length + wire->datalen < length) {
		return EMSGSIZE;
	}
	if (length + wire->datalen + wire->errorlen < length) {
		return EMSGSIZE;
	}
	if (buflen < length + wire->datalen + wire->errorlen) {
		return EMSGSIZE;
	}

	if (h != NULL) {
		ret = ctdb_req_header_pull((uint8_t *)&wire->hdr, buflen, h);
		if (ret != 0) {
			return ret;
		}
	}

	c->status = wire->status;

	if (c->status != -1) {
		ret = ctdb_reply_control_data_pull(wire->data, wire->datalen,
						   opcode, mem_ctx,
						   &c->rdata);
		if (ret != 0) {
			return ret;
		}
	}

	ret = ctdb_string_pull(wire->data + wire->datalen, wire->errorlen,
			       mem_ctx, &c->errmsg);
	if (ret != 0) {
		return ret;
	}

	return 0;
}
