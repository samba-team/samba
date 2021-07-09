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

static size_t ctdb_req_control_data_len(struct ctdb_req_control_data *cd)
{
	size_t len = 0;
	uint32_t u32;

	if (cd == NULL) {
		return 0;
	}

	switch (cd->opcode) {
	case CTDB_CONTROL_PROCESS_EXISTS:
		len = ctdb_pid_len(&cd->data.pid);
		break;

	case CTDB_CONTROL_STATISTICS:
		break;

	case CTDB_CONTROL_PING:
		break;

	case CTDB_CONTROL_GETDBPATH:
		len = ctdb_uint32_len(&cd->data.db_id);
		break;

	case CTDB_CONTROL_GETVNNMAP:
		break;

	case CTDB_CONTROL_SETVNNMAP:
		len = ctdb_vnn_map_len(cd->data.vnnmap);
		break;

	case CTDB_CONTROL_GET_DEBUG:
		break;

	case CTDB_CONTROL_SET_DEBUG:
		len = ctdb_uint32_len(&cd->data.loglevel);
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
		len = ctdb_uint32_len(&cd->data.recmode);
		break;

	case CTDB_CONTROL_STATISTICS_RESET:
		break;

	case CTDB_CONTROL_DB_ATTACH:
		len = ctdb_string_len(&cd->data.db_name);
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
		len = ctdb_uint32_len(&cd->data.db_id);
		break;

	case CTDB_CONTROL_ENABLE_SEQNUM:
		len = ctdb_uint32_len(&cd->data.db_id);
		break;

	case CTDB_CONTROL_UPDATE_SEQNUM:
		len = ctdb_uint32_len(&cd->data.db_id);
		break;

	case CTDB_CONTROL_DUMP_MEMORY:
		break;

	case CTDB_CONTROL_GET_PID:
		break;

	case CTDB_CONTROL_GET_RECMASTER:
		break;

	case CTDB_CONTROL_SET_RECMASTER:
		len = ctdb_uint32_len(&cd->data.recmaster);
		break;

	case CTDB_CONTROL_FREEZE:
		break;

	case CTDB_CONTROL_GET_PNN:
		break;

	case CTDB_CONTROL_SHUTDOWN:
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
		len = ctdb_stringn_len(&cd->data.tun_var);
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
		len = ctdb_string_len(&cd->data.db_name);
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
		len = ctdb_double_len(&cd->data.reclock_latency);
		break;

	case CTDB_CONTROL_GET_RECLOCK_FILE:
		break;

	case CTDB_CONTROL_STOP_NODE:
		break;

	case CTDB_CONTROL_CONTINUE_NODE:
		break;

	case CTDB_CONTROL_SET_LMASTERROLE:
		len = ctdb_uint32_len(&cd->data.role);
		break;

	case CTDB_CONTROL_SET_RECMASTERROLE:
		len = ctdb_uint32_len(&cd->data.role);
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
		len = ctdb_uint64_len(&cd->data.srvid);
		break;

	case CTDB_CONTROL_TRANS3_COMMIT:
		len = ctdb_rec_buffer_len(cd->data.recbuf);
		break;

	case CTDB_CONTROL_GET_DB_SEQNUM:
		u32 = 0;
		len = ctdb_uint32_len(&cd->data.db_id) + ctdb_uint32_len(&u32);
		break;

	case CTDB_CONTROL_DB_SET_HEALTHY:
		len = ctdb_uint32_len(&cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_GET_HEALTH:
		len = ctdb_uint32_len(&cd->data.db_id);
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
		len = ctdb_uint32_len(&cd->data.db_id);
		break;

	case CTDB_CONTROL_TRAVERSE_START_EXT:
		len = ctdb_traverse_start_ext_len(cd->data.traverse_start_ext);
		break;

	case CTDB_CONTROL_GET_DB_STATISTICS:
		len = ctdb_uint32_len(&cd->data.db_id);
		break;

	case CTDB_CONTROL_SET_DB_STICKY:
		len = ctdb_uint32_len(&cd->data.db_id);
		break;

	case CTDB_CONTROL_RELOAD_PUBLIC_IPS:
		break;

	case CTDB_CONTROL_TRAVERSE_ALL_EXT:
		len = ctdb_traverse_all_ext_len(cd->data.traverse_all_ext);
		break;

	case CTDB_CONTROL_IPREALLOCATED:
		break;

	case CTDB_CONTROL_GET_RUNSTATE:
		break;

	case CTDB_CONTROL_DB_DETACH:
		len = ctdb_uint32_len(&cd->data.db_id);
		break;

	case CTDB_CONTROL_GET_NODES_FILE:
		break;

	case CTDB_CONTROL_DB_FREEZE:
		len = ctdb_uint32_len(&cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_THAW:
		len = ctdb_uint32_len(&cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_START:
		len = ctdb_transdb_len(cd->data.transdb);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_COMMIT:
		len = ctdb_transdb_len(cd->data.transdb);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_CANCEL:
		len = ctdb_uint32_len(&cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_PULL:
		len = ctdb_pulldb_ext_len(cd->data.pulldb_ext);
		break;

	case CTDB_CONTROL_DB_PUSH_START:
		len = ctdb_pulldb_ext_len(cd->data.pulldb_ext);
		break;

	case CTDB_CONTROL_DB_PUSH_CONFIRM:
		len = ctdb_uint32_len(&cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_OPEN_FLAGS:
		len = ctdb_uint32_len(&cd->data.db_id);
		break;

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
		len = ctdb_string_len(&cd->data.db_name);
		break;

	case CTDB_CONTROL_CHECK_PID_SRVID:
		len = ctdb_pid_srvid_len(cd->data.pid_srvid);
		break;

	case CTDB_CONTROL_TUNNEL_REGISTER:
		break;

	case CTDB_CONTROL_TUNNEL_DEREGISTER:
		break;

	case CTDB_CONTROL_VACUUM_FETCH:
		len = ctdb_rec_buffer_len(cd->data.recbuf);
		break;

	case CTDB_CONTROL_DB_VACUUM:
		len = ctdb_db_vacuum_len(cd->data.db_vacuum);
		break;

	case CTDB_CONTROL_ECHO_DATA:
		len = ctdb_echo_data_len(cd->data.echo_data);
		break;

	case CTDB_CONTROL_DISABLE_NODE:
		break;

	case CTDB_CONTROL_ENABLE_NODE:
		break;
	}

	return len;
}

static void ctdb_req_control_data_push(struct ctdb_req_control_data *cd,
				       uint8_t *buf, size_t *npush)
{
	size_t np = 0, offset;
	uint32_t u32;

	switch (cd->opcode) {
	case CTDB_CONTROL_PROCESS_EXISTS:
		ctdb_pid_push(&cd->data.pid, buf, &np);
		break;

	case CTDB_CONTROL_GETDBPATH:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_SETVNNMAP:
		ctdb_vnn_map_push(cd->data.vnnmap, buf, &np);
		break;

	case CTDB_CONTROL_SET_DEBUG:
		ctdb_uint32_push(&cd->data.loglevel, buf, &np);
		break;

	case CTDB_CONTROL_PULL_DB:
		ctdb_pulldb_push(cd->data.pulldb, buf, &np);
		break;

	case CTDB_CONTROL_PUSH_DB:
		ctdb_rec_buffer_push(cd->data.recbuf, buf, &np);
		break;

	case CTDB_CONTROL_SET_RECMODE:
		ctdb_uint32_push(&cd->data.recmode, buf, &np);
		break;

	case CTDB_CONTROL_DB_ATTACH:
		ctdb_string_push(&cd->data.db_name, buf, &np);
		break;

	case CTDB_CONTROL_TRAVERSE_START:
		ctdb_traverse_start_push(cd->data.traverse_start, buf, &np);
		break;

	case CTDB_CONTROL_TRAVERSE_ALL:
		ctdb_traverse_all_push(cd->data.traverse_all, buf, &np);
		break;

	case CTDB_CONTROL_TRAVERSE_DATA:
		ctdb_rec_data_push(cd->data.rec_data, buf, &np);
		break;

	case CTDB_CONTROL_GET_DBNAME:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_ENABLE_SEQNUM:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_UPDATE_SEQNUM:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_SET_RECMASTER:
		ctdb_uint32_push(&cd->data.recmaster, buf, &np);
		break;

	case CTDB_CONTROL_TCP_CLIENT:
		ctdb_connection_push(cd->data.conn, buf, &np);
		break;

	case CTDB_CONTROL_TCP_ADD:
		ctdb_connection_push(cd->data.conn, buf, &np);
		break;

	case CTDB_CONTROL_TCP_REMOVE:
		ctdb_connection_push(cd->data.conn, buf, &np);
		break;

	case CTDB_CONTROL_SET_TUNABLE:
		ctdb_tunable_push(cd->data.tunable, buf, &np);
		break;

	case CTDB_CONTROL_GET_TUNABLE:
		ctdb_stringn_push(&cd->data.tun_var, buf, &np);
		break;

	case CTDB_CONTROL_MODIFY_FLAGS:
		ctdb_node_flag_change_push(cd->data.flag_change, buf, &np);
		break;

	case CTDB_CONTROL_GET_TCP_TICKLE_LIST:
		ctdb_sock_addr_push(cd->data.addr, buf, &np);
		break;

	case CTDB_CONTROL_SET_TCP_TICKLE_LIST:
		ctdb_tickle_list_push(cd->data.tickles, buf, &np);
		break;

	case CTDB_CONTROL_DB_ATTACH_PERSISTENT:
		ctdb_string_push(&cd->data.db_name, buf, &np);
		break;

	case CTDB_CONTROL_UPDATE_RECORD:
		ctdb_rec_buffer_push(cd->data.recbuf, buf, &np);
		break;

	case CTDB_CONTROL_SEND_GRATUITOUS_ARP:
		ctdb_addr_info_push(cd->data.addr_info, buf, &np);
		break;

	case CTDB_CONTROL_WIPE_DATABASE:
		ctdb_transdb_push(cd->data.transdb, buf, &np);
		break;

	case CTDB_CONTROL_TRY_DELETE_RECORDS:
		ctdb_rec_buffer_push(cd->data.recbuf, buf, &np);
		break;

	case CTDB_CONTROL_ADD_PUBLIC_IP:
		ctdb_addr_info_push(cd->data.addr_info, buf, &np);
		break;

	case CTDB_CONTROL_DEL_PUBLIC_IP:
		ctdb_addr_info_push(cd->data.addr_info, buf, &np);
		break;

	case CTDB_CONTROL_RELEASE_IP:
		ctdb_public_ip_push(cd->data.pubip, buf, &np);
		break;

	case CTDB_CONTROL_TAKEOVER_IP:
		ctdb_public_ip_push(cd->data.pubip, buf, &np);
		break;

	case CTDB_CONTROL_TRAVERSE_KILL:
		ctdb_traverse_start_push(cd->data.traverse_start, buf, &np);
		break;

	case CTDB_CONTROL_RECD_RECLOCK_LATENCY:
		ctdb_double_push(&cd->data.reclock_latency, buf, &np);
		break;

	case CTDB_CONTROL_SET_LMASTERROLE:
		ctdb_uint32_push(&cd->data.role, buf, &np);
		break;

	case CTDB_CONTROL_SET_RECMASTERROLE:
		ctdb_uint32_push(&cd->data.role, buf, &np);
		break;

	case CTDB_CONTROL_SET_BAN_STATE:
		ctdb_ban_state_push(cd->data.ban_state, buf, &np);
		break;

	case CTDB_CONTROL_REGISTER_NOTIFY:
		ctdb_notify_data_push(cd->data.notify, buf, &np);
		break;

	case CTDB_CONTROL_DEREGISTER_NOTIFY:
		ctdb_uint64_push(&cd->data.srvid, buf, &np);
		break;

	case CTDB_CONTROL_TRANS3_COMMIT:
		ctdb_rec_buffer_push(cd->data.recbuf, buf, &np);
		break;

	case CTDB_CONTROL_GET_DB_SEQNUM:
		u32 = 0;
		offset = 0;
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		offset += np;
		ctdb_uint32_push(&u32, buf+offset, &np);
		offset += np;
		np = offset;
		break;

	case CTDB_CONTROL_DB_SET_HEALTHY:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_DB_GET_HEALTH:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IP_INFO:
		ctdb_sock_addr_push(cd->data.addr, buf, &np);
		break;

	case CTDB_CONTROL_SET_IFACE_LINK_STATE:
		ctdb_iface_push(cd->data.iface, buf, &np);
		break;

	case CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE:
		ctdb_connection_push(cd->data.conn, buf, &np);
		break;

	case CTDB_CONTROL_SCHEDULE_FOR_DELETION:
		ctdb_key_data_push(cd->data.key, buf, &np);
		break;

	case CTDB_CONTROL_SET_DB_READONLY:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_TRAVERSE_START_EXT:
		ctdb_traverse_start_ext_push(cd->data.traverse_start_ext, buf,
					     &np);
		break;

	case CTDB_CONTROL_GET_DB_STATISTICS:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_SET_DB_STICKY:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_TRAVERSE_ALL_EXT:
		ctdb_traverse_all_ext_push(cd->data.traverse_all_ext, buf,
					   &np);
		break;

	case CTDB_CONTROL_DB_DETACH:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_DB_FREEZE:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_DB_THAW:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_START:
		ctdb_transdb_push(cd->data.transdb, buf, &np);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_COMMIT:
		ctdb_transdb_push(cd->data.transdb, buf, &np);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_CANCEL:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_DB_PULL:
		ctdb_pulldb_ext_push(cd->data.pulldb_ext, buf, &np);
		break;

	case CTDB_CONTROL_DB_PUSH_START:
		ctdb_pulldb_ext_push(cd->data.pulldb_ext, buf, &np);
		break;

	case CTDB_CONTROL_DB_PUSH_CONFIRM:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_DB_OPEN_FLAGS:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
		ctdb_string_push(&cd->data.db_name, buf, &np);
		break;

	case CTDB_CONTROL_CHECK_PID_SRVID:
		ctdb_pid_srvid_push(cd->data.pid_srvid, buf, &np);
		break;

	case CTDB_CONTROL_VACUUM_FETCH:
		ctdb_rec_buffer_push(cd->data.recbuf, buf, &np);
		break;

	case CTDB_CONTROL_DB_VACUUM:
		ctdb_db_vacuum_push(cd->data.db_vacuum, buf, &np);
		break;

	case CTDB_CONTROL_ECHO_DATA:
		ctdb_echo_data_push(cd->data.echo_data, buf, &np);
		break;
	}

	*npush = np;
}

static int ctdb_req_control_data_pull(uint8_t *buf, size_t buflen,
				      uint32_t opcode,
				      TALLOC_CTX *mem_ctx,
				      struct ctdb_req_control_data *cd,
				      size_t *npull)
{
	size_t np = 0, offset;
	uint32_t u32;
	int ret = 0;

	cd->opcode = opcode;

	switch (opcode) {
	case CTDB_CONTROL_PROCESS_EXISTS:
		ret = ctdb_pid_pull(buf, buflen, &cd->data.pid, &np);
		break;

	case CTDB_CONTROL_GETDBPATH:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_SETVNNMAP:
		ret = ctdb_vnn_map_pull(buf, buflen, mem_ctx,
					&cd->data.vnnmap, &np);
		break;

	case CTDB_CONTROL_SET_DEBUG:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.loglevel, &np);
		break;

	case CTDB_CONTROL_PULL_DB:
		ret = ctdb_pulldb_pull(buf, buflen, mem_ctx,
				       &cd->data.pulldb, &np);
		break;

	case CTDB_CONTROL_PUSH_DB:
		ret = ctdb_rec_buffer_pull(buf, buflen, mem_ctx,
					   &cd->data.recbuf, &np);
		break;

	case CTDB_CONTROL_SET_RECMODE:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.recmode, &np);
		break;

	case CTDB_CONTROL_DB_ATTACH:
		ret = ctdb_string_pull(buf, buflen, mem_ctx,
				       &cd->data.db_name, &np);
		break;

	case CTDB_CONTROL_TRAVERSE_START:
		ret = ctdb_traverse_start_pull(buf, buflen, mem_ctx,
					       &cd->data.traverse_start, &np);
		break;

	case CTDB_CONTROL_TRAVERSE_ALL:
		ret = ctdb_traverse_all_pull(buf, buflen, mem_ctx,
					     &cd->data.traverse_all, &np);
		break;

	case CTDB_CONTROL_TRAVERSE_DATA:
		ret = ctdb_rec_data_pull(buf, buflen, mem_ctx,
					 &cd->data.rec_data, &np);
		break;

	case CTDB_CONTROL_GET_DBNAME:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_ENABLE_SEQNUM:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_UPDATE_SEQNUM:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_SET_RECMASTER:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.recmaster, &np);
		break;

	case CTDB_CONTROL_TCP_CLIENT:
		ret = ctdb_connection_pull(buf, buflen, mem_ctx,
					   &cd->data.conn, &np);
		break;

	case CTDB_CONTROL_TCP_ADD:
		ret = ctdb_connection_pull(buf, buflen, mem_ctx,
					   &cd->data.conn, &np);
		break;

	case CTDB_CONTROL_TCP_REMOVE:
		ret = ctdb_connection_pull(buf, buflen, mem_ctx,
					   &cd->data.conn, &np);
		break;

	case CTDB_CONTROL_SET_TUNABLE:
		ret = ctdb_tunable_pull(buf, buflen, mem_ctx,
					&cd->data.tunable, &np);
		break;

	case CTDB_CONTROL_GET_TUNABLE:
		ret = ctdb_stringn_pull(buf, buflen, mem_ctx,
					&cd->data.tun_var, &np);
		break;

	case CTDB_CONTROL_MODIFY_FLAGS:
		ret = ctdb_node_flag_change_pull(buf, buflen, mem_ctx,
						 &cd->data.flag_change, &np);
		break;

	case CTDB_CONTROL_GET_TCP_TICKLE_LIST:
		ret = ctdb_sock_addr_pull(buf, buflen, mem_ctx,
					  &cd->data.addr, &np);
		break;

	case CTDB_CONTROL_SET_TCP_TICKLE_LIST:
		ret = ctdb_tickle_list_pull(buf, buflen, mem_ctx,
					    &cd->data.tickles, &np);
		break;

	case CTDB_CONTROL_DB_ATTACH_PERSISTENT:
		ret = ctdb_string_pull(buf, buflen, mem_ctx,
				       &cd->data.db_name, &np);
		break;

	case CTDB_CONTROL_UPDATE_RECORD:
		ret = ctdb_rec_buffer_pull(buf, buflen, mem_ctx,
					   &cd->data.recbuf, &np);
		break;

	case CTDB_CONTROL_SEND_GRATUITOUS_ARP:
		ret = ctdb_addr_info_pull(buf, buflen, mem_ctx,
					  &cd->data.addr_info, &np);
		break;

	case CTDB_CONTROL_WIPE_DATABASE:
		ret = ctdb_transdb_pull(buf, buflen, mem_ctx,
				       &cd->data.transdb, &np);
		break;

	case CTDB_CONTROL_TRY_DELETE_RECORDS:
		ret = ctdb_rec_buffer_pull(buf, buflen, mem_ctx,
					   &cd->data.recbuf, &np);
		break;

	case CTDB_CONTROL_ADD_PUBLIC_IP:
		ret = ctdb_addr_info_pull(buf, buflen, mem_ctx,
					  &cd->data.addr_info, &np);
		break;

	case CTDB_CONTROL_DEL_PUBLIC_IP:
		ret = ctdb_addr_info_pull(buf, buflen, mem_ctx,
					  &cd->data.addr_info, &np);
		break;

	case CTDB_CONTROL_RELEASE_IP:
		ret = ctdb_public_ip_pull(buf, buflen, mem_ctx,
					  &cd->data.pubip, &np);
		break;

	case CTDB_CONTROL_TAKEOVER_IP:
		ret = ctdb_public_ip_pull(buf, buflen, mem_ctx,
					  &cd->data.pubip, &np);
		break;

	case CTDB_CONTROL_TRAVERSE_KILL:
		ret = ctdb_traverse_start_pull(buf, buflen, mem_ctx,
					       &cd->data.traverse_start, &np);
		break;

	case CTDB_CONTROL_RECD_RECLOCK_LATENCY:
		ret = ctdb_double_pull(buf, buflen, &cd->data.reclock_latency,
				       &np);
		break;

	case CTDB_CONTROL_SET_LMASTERROLE:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.role, &np);
		break;

	case CTDB_CONTROL_SET_RECMASTERROLE:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.role, &np);
		break;

	case CTDB_CONTROL_SET_BAN_STATE:
		ret = ctdb_ban_state_pull(buf, buflen, mem_ctx,
					  &cd->data.ban_state, &np);
		break;

	case CTDB_CONTROL_REGISTER_NOTIFY:
		ret = ctdb_notify_data_pull(buf, buflen, mem_ctx,
					    &cd->data.notify, &np);
		break;

	case CTDB_CONTROL_DEREGISTER_NOTIFY:
		ret = ctdb_uint64_pull(buf, buflen, &cd->data.srvid, &np);
		break;

	case CTDB_CONTROL_TRANS3_COMMIT:
		ret = ctdb_rec_buffer_pull(buf, buflen, mem_ctx,
					   &cd->data.recbuf, &np);
		break;

	case CTDB_CONTROL_GET_DB_SEQNUM:
		offset = 0;
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		if (ret != 0) {
			break;
		}
		offset += np;
		ret = ctdb_uint32_pull(buf+offset, buflen-offset, &u32, &np);
		offset += np;
		np = offset;
		break;

	case CTDB_CONTROL_DB_SET_HEALTHY:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_DB_GET_HEALTH:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IP_INFO:
		ret = ctdb_sock_addr_pull(buf, buflen, mem_ctx,
					  &cd->data.addr, &np);
		break;

	case CTDB_CONTROL_SET_IFACE_LINK_STATE:
		ret = ctdb_iface_pull(buf, buflen, mem_ctx,
				      &cd->data.iface, &np);
		break;

	case CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE:
		ret = ctdb_connection_pull(buf, buflen, mem_ctx,
					   &cd->data.conn, &np);
		break;

	case CTDB_CONTROL_SCHEDULE_FOR_DELETION:
		ret = ctdb_key_data_pull(buf, buflen, mem_ctx,
					 &cd->data.key, &np);
		break;

	case CTDB_CONTROL_SET_DB_READONLY:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_TRAVERSE_START_EXT:
		ret = ctdb_traverse_start_ext_pull(buf, buflen, mem_ctx,
						   &cd->data.traverse_start_ext,
						   &np);
		break;

	case CTDB_CONTROL_GET_DB_STATISTICS:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_SET_DB_STICKY:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_TRAVERSE_ALL_EXT:
		ret = ctdb_traverse_all_ext_pull(buf, buflen, mem_ctx,
						 &cd->data.traverse_all_ext,
						 &np);
		break;

	case CTDB_CONTROL_DB_DETACH:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_DB_FREEZE:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_DB_THAW:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_START:
		ret = ctdb_transdb_pull(buf, buflen, mem_ctx,
					&cd->data.transdb, &np);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_COMMIT:
		ret = ctdb_transdb_pull(buf, buflen, mem_ctx,
					&cd->data.transdb, &np);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_CANCEL:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_DB_PULL:
		ret = ctdb_pulldb_ext_pull(buf, buflen, mem_ctx,
					   &cd->data.pulldb_ext, &np);
		break;

	case CTDB_CONTROL_DB_PUSH_START:
		ret = ctdb_pulldb_ext_pull(buf, buflen, mem_ctx,
					   &cd->data.pulldb_ext, &np);
		break;

	case CTDB_CONTROL_DB_PUSH_CONFIRM:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_DB_OPEN_FLAGS:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
		ret = ctdb_string_pull(buf, buflen, mem_ctx,
				       &cd->data.db_name, &np);
		break;

	case CTDB_CONTROL_CHECK_PID_SRVID:
		ret = ctdb_pid_srvid_pull(buf, buflen, mem_ctx,
					  &cd->data.pid_srvid, &np);
		break;

	case CTDB_CONTROL_VACUUM_FETCH:
		ret = ctdb_rec_buffer_pull(buf, buflen, mem_ctx,
					   &cd->data.recbuf, &np);
		break;

	case CTDB_CONTROL_DB_VACUUM:
		ret = ctdb_db_vacuum_pull(buf,
					  buflen,
					  mem_ctx,
					  &cd->data.db_vacuum,
					  &np);
		break;

	case CTDB_CONTROL_ECHO_DATA:
		ret = ctdb_echo_data_pull(buf,
					  buflen,
					  mem_ctx,
					  &cd->data.echo_data,
					  &np);
		break;
	}

	if (ret != 0) {
		return ret;
	}

	*npull = np;
	return 0;
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
		len = ctdb_string_len(&cd->data.db_path);
		break;

	case CTDB_CONTROL_GETVNNMAP:
		len = ctdb_vnn_map_len(cd->data.vnnmap);
		break;

	case CTDB_CONTROL_SETVNNMAP:
		break;

	case CTDB_CONTROL_GET_DEBUG:
		len = ctdb_uint32_len(&cd->data.loglevel);
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
		len = ctdb_uint32_len(&cd->data.db_id);
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
		len = ctdb_string_len(&cd->data.db_name);
		break;

	case CTDB_CONTROL_ENABLE_SEQNUM:
		break;

	case CTDB_CONTROL_UPDATE_SEQNUM:
		break;

	case CTDB_CONTROL_DUMP_MEMORY:
		len = ctdb_string_len(&cd->data.mem_str);
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
		len = ctdb_uint32_len(&cd->data.tun_value);
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
		len = ctdb_uint32_len(&cd->data.db_id);
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

	case CTDB_CONTROL_ADD_PUBLIC_IP:
		break;

	case CTDB_CONTROL_DEL_PUBLIC_IP:
		break;

	case CTDB_CONTROL_GET_CAPABILITIES:
		len = ctdb_uint32_len(&cd->data.caps);
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
		len = ctdb_string_len(&cd->data.reclock_file);
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

	case CTDB_CONTROL_REGISTER_NOTIFY:
		break;

	case CTDB_CONTROL_DEREGISTER_NOTIFY:
		break;

	case CTDB_CONTROL_TRANS3_COMMIT:
		break;

	case CTDB_CONTROL_GET_DB_SEQNUM:
		len = ctdb_uint64_len(&cd->data.seqnum);
		break;

	case CTDB_CONTROL_DB_SET_HEALTHY:
		break;

	case CTDB_CONTROL_DB_GET_HEALTH:
		len = ctdb_string_len(&cd->data.reason);
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

	case CTDB_CONTROL_IPREALLOCATED:
		break;

	case CTDB_CONTROL_GET_RUNSTATE:
		len = ctdb_uint32_len(&cd->data.runstate);
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
		len = ctdb_uint32_len(&cd->data.num_records);
		break;

	case CTDB_CONTROL_DB_PUSH_START:
		break;

	case CTDB_CONTROL_DB_PUSH_CONFIRM:
		len = ctdb_uint32_len(&cd->data.num_records);
		break;

	case CTDB_CONTROL_DB_OPEN_FLAGS:
		len = ctdb_int32_len(&cd->data.tdb_flags);
		break;

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
		len = ctdb_uint32_len(&cd->data.db_id);
		break;

	case CTDB_CONTROL_CHECK_PID_SRVID:
		break;

	case CTDB_CONTROL_TUNNEL_REGISTER:
		break;

	case CTDB_CONTROL_TUNNEL_DEREGISTER:
		break;

	case CTDB_CONTROL_VACUUM_FETCH:
		break;

	case CTDB_CONTROL_DB_VACUUM:
		break;

	case CTDB_CONTROL_ECHO_DATA:
		len = ctdb_echo_data_len(cd->data.echo_data);
		break;

	case CTDB_CONTROL_DISABLE_NODE:
		break;

	case CTDB_CONTROL_ENABLE_NODE:
		break;
	}

	return len;
}

static void ctdb_reply_control_data_push(struct ctdb_reply_control_data *cd,
					 uint8_t *buf, size_t *npush)
{
	size_t np = 0;

	switch (cd->opcode) {
	case CTDB_CONTROL_STATISTICS:
		ctdb_statistics_push(cd->data.stats, buf, &np);
		break;

	case CTDB_CONTROL_GETDBPATH:
		ctdb_string_push(&cd->data.db_path, buf, &np);
		break;

	case CTDB_CONTROL_GETVNNMAP:
		ctdb_vnn_map_push(cd->data.vnnmap, buf, &np);
		break;

	case CTDB_CONTROL_GET_DEBUG:
		ctdb_uint32_push(&cd->data.loglevel, buf, &np);
		break;

	case CTDB_CONTROL_GET_DBMAP:
		ctdb_dbid_map_push(cd->data.dbmap, buf, &np);
		break;

	case CTDB_CONTROL_PULL_DB:
		ctdb_rec_buffer_push(cd->data.recbuf, buf, &np);
		break;

	case CTDB_CONTROL_PUSH_DB:
		break;

	case CTDB_CONTROL_DB_ATTACH:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_GET_DBNAME:
		ctdb_string_push(&cd->data.db_name, buf, &np);
		break;

	case CTDB_CONTROL_DUMP_MEMORY:
		ctdb_string_push(&cd->data.mem_str, buf, &np);
		break;

	case CTDB_CONTROL_GET_PID:
		break;

	case CTDB_CONTROL_GET_RECMASTER:
		break;

	case CTDB_CONTROL_GET_TUNABLE:
		ctdb_uint32_push(&cd->data.tun_value, buf, &np);
		break;

	case CTDB_CONTROL_LIST_TUNABLES:
		ctdb_var_list_push(cd->data.tun_var_list, buf, &np);
		break;

	case CTDB_CONTROL_GET_ALL_TUNABLES:
		ctdb_tunable_list_push(cd->data.tun_list, buf, &np);
		break;

	case CTDB_CONTROL_GET_TCP_TICKLE_LIST:
		ctdb_tickle_list_push(cd->data.tickles, buf, &np);
		break;

	case CTDB_CONTROL_DB_ATTACH_PERSISTENT:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_UPTIME:
		ctdb_uptime_push(cd->data.uptime, buf, &np);
		break;

	case CTDB_CONTROL_TRY_DELETE_RECORDS:
		ctdb_rec_buffer_push(cd->data.recbuf, buf, &np);
		break;

	case CTDB_CONTROL_GET_CAPABILITIES:
		ctdb_uint32_push(&cd->data.caps, buf, &np);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IPS:
		ctdb_public_ip_list_push(cd->data.pubip_list, buf, &np);
		break;

	case CTDB_CONTROL_GET_NODEMAP:
		ctdb_node_map_push(cd->data.nodemap, buf, &np);
		break;

	case CTDB_CONTROL_GET_RECLOCK_FILE:
		ctdb_string_push(&cd->data.reclock_file, buf, &np);
		break;

	case CTDB_CONTROL_GET_BAN_STATE:
		ctdb_ban_state_push(cd->data.ban_state, buf, &np);
		break;

	case CTDB_CONTROL_GET_DB_SEQNUM:
		ctdb_uint64_push(&cd->data.seqnum, buf, &np);
		break;

	case CTDB_CONTROL_DB_GET_HEALTH:
		ctdb_string_push(&cd->data.reason, buf, &np);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IP_INFO:
		ctdb_public_ip_info_push(cd->data.ipinfo, buf, &np);
		break;

	case CTDB_CONTROL_GET_IFACES:
		ctdb_iface_list_push(cd->data.iface_list, buf, &np);
		break;

	case CTDB_CONTROL_GET_STAT_HISTORY:
		ctdb_statistics_list_push(cd->data.stats_list, buf, &np);
		break;

	case CTDB_CONTROL_GET_DB_STATISTICS:
		ctdb_db_statistics_push(cd->data.dbstats, buf, &np);
		break;

	case CTDB_CONTROL_GET_RUNSTATE:
		ctdb_uint32_push(&cd->data.runstate, buf, &np);
		break;

	case CTDB_CONTROL_GET_NODES_FILE:
		ctdb_node_map_push(cd->data.nodemap, buf, &np);
		break;

	case CTDB_CONTROL_DB_PULL:
		ctdb_uint32_push(&cd->data.num_records, buf, &np);
		break;

	case CTDB_CONTROL_DB_PUSH_CONFIRM:
		ctdb_uint32_push(&cd->data.num_records, buf, &np);
		break;

	case CTDB_CONTROL_DB_OPEN_FLAGS:
		ctdb_int32_push(&cd->data.tdb_flags, buf, &np);
		break;

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
		ctdb_uint32_push(&cd->data.db_id, buf, &np);
		break;

	case CTDB_CONTROL_CHECK_PID_SRVID:
		break;

	case CTDB_CONTROL_VACUUM_FETCH:
		break;

	case CTDB_CONTROL_DB_VACUUM:
		break;

	case CTDB_CONTROL_ECHO_DATA:
		ctdb_echo_data_push(cd->data.echo_data, buf, &np);
		break;
	}

	*npush = np;
}

static int ctdb_reply_control_data_pull(uint8_t *buf, size_t buflen,
					uint32_t opcode, TALLOC_CTX *mem_ctx,
					struct ctdb_reply_control_data *cd,
					size_t *npull)
{
	size_t np = 0;
	int ret = 0;

	cd->opcode = opcode;

	switch (opcode) {
	case CTDB_CONTROL_STATISTICS:
		ret = ctdb_statistics_pull(buf, buflen, mem_ctx,
					   &cd->data.stats, &np);
		break;

	case CTDB_CONTROL_GETDBPATH:
		ret = ctdb_string_pull(buf, buflen, mem_ctx,
				       &cd->data.db_path, &np);
		break;

	case CTDB_CONTROL_GETVNNMAP:
		ret = ctdb_vnn_map_pull(buf, buflen, mem_ctx,
					&cd->data.vnnmap, &np);
		break;

	case CTDB_CONTROL_GET_DEBUG:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.loglevel, &np);
		break;

	case CTDB_CONTROL_GET_DBMAP:
		ret = ctdb_dbid_map_pull(buf, buflen, mem_ctx,
					 &cd->data.dbmap, &np);
		break;

	case CTDB_CONTROL_PULL_DB:
		ret = ctdb_rec_buffer_pull(buf, buflen, mem_ctx,
					   &cd->data.recbuf, &np);
		break;

	case CTDB_CONTROL_PUSH_DB:
		break;

	case CTDB_CONTROL_DB_ATTACH:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_GET_DBNAME:
		ret = ctdb_string_pull(buf, buflen, mem_ctx,
				       &cd->data.db_name, &np);
		break;

	case CTDB_CONTROL_DUMP_MEMORY:
		ret = ctdb_string_pull(buf, buflen, mem_ctx,
				       &cd->data.mem_str, &np);
		break;

	case CTDB_CONTROL_GET_PID:
		break;

	case CTDB_CONTROL_GET_RECMASTER:
		break;

	case CTDB_CONTROL_GET_TUNABLE:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.tun_value,
				       &np);
		break;

	case CTDB_CONTROL_LIST_TUNABLES:
		ret = ctdb_var_list_pull(buf, buflen, mem_ctx,
					 &cd->data.tun_var_list, &np);
		break;

	case CTDB_CONTROL_GET_ALL_TUNABLES:
		ret = ctdb_tunable_list_pull(buf, buflen, mem_ctx,
					     &cd->data.tun_list, &np);
		break;

	case CTDB_CONTROL_GET_TCP_TICKLE_LIST:
		ret = ctdb_tickle_list_pull(buf, buflen, mem_ctx,
					    &cd->data.tickles, &np);
		break;

	case CTDB_CONTROL_DB_ATTACH_PERSISTENT:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_UPTIME:
		ret = ctdb_uptime_pull(buf, buflen, mem_ctx,
				       &cd->data.uptime, &np);
		break;

	case CTDB_CONTROL_TRY_DELETE_RECORDS:
		ret = ctdb_rec_buffer_pull(buf, buflen, mem_ctx,
					   &cd->data.recbuf, &np);
		break;

	case CTDB_CONTROL_GET_CAPABILITIES:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.caps, &np);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IPS:
		ret = ctdb_public_ip_list_pull(buf, buflen, mem_ctx,
					       &cd->data.pubip_list, &np);
		break;

	case CTDB_CONTROL_GET_NODEMAP:
		ret = ctdb_node_map_pull(buf, buflen, mem_ctx,
					 &cd->data.nodemap, &np);
		break;

	case CTDB_CONTROL_GET_RECLOCK_FILE:
		ret = ctdb_string_pull(buf, buflen, mem_ctx,
				       &cd->data.reclock_file, &np);
		break;

	case CTDB_CONTROL_GET_BAN_STATE:
		ret = ctdb_ban_state_pull(buf, buflen, mem_ctx,
					  &cd->data.ban_state, &np);
		break;

	case CTDB_CONTROL_GET_DB_SEQNUM:
		ret = ctdb_uint64_pull(buf, buflen, &cd->data.seqnum, &np);
		break;

	case CTDB_CONTROL_DB_GET_HEALTH:
		ret = ctdb_string_pull(buf, buflen, mem_ctx,
				       &cd->data.reason, &np);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IP_INFO:
		ret = ctdb_public_ip_info_pull(buf, buflen, mem_ctx,
					       &cd->data.ipinfo, &np);
		break;

	case CTDB_CONTROL_GET_IFACES:
		ret = ctdb_iface_list_pull(buf, buflen, mem_ctx,
					   &cd->data.iface_list, &np);
		break;

	case CTDB_CONTROL_GET_STAT_HISTORY:
		ret = ctdb_statistics_list_pull(buf, buflen, mem_ctx,
						&cd->data.stats_list, &np);
		break;

	case CTDB_CONTROL_GET_DB_STATISTICS:
		ret = ctdb_db_statistics_pull(buf, buflen, mem_ctx,
					      &cd->data.dbstats, &np);
		break;

	case CTDB_CONTROL_GET_RUNSTATE:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.runstate, &np);
		break;

	case CTDB_CONTROL_GET_NODES_FILE:
		ret = ctdb_node_map_pull(buf, buflen, mem_ctx,
					 &cd->data.nodemap, &np);
		break;

	case CTDB_CONTROL_DB_PULL:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.num_records,
				       &np);
		break;

	case CTDB_CONTROL_DB_PUSH_CONFIRM:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.num_records,
				       &np);
		break;

	case CTDB_CONTROL_DB_OPEN_FLAGS:
		ret = ctdb_int32_pull(buf, buflen, &cd->data.tdb_flags, &np);
		break;

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
		ret = ctdb_uint32_pull(buf, buflen, &cd->data.db_id, &np);
		break;

	case CTDB_CONTROL_CHECK_PID_SRVID:
		break;

	case CTDB_CONTROL_VACUUM_FETCH:
		break;

	case CTDB_CONTROL_DB_VACUUM:
		break;

	case CTDB_CONTROL_ECHO_DATA:
		ret = ctdb_echo_data_pull(buf,
					  buflen,
					  mem_ctx,
					  &cd->data.echo_data,
					  &np);
		break;
	}

	if (ret != 0) {
		return ret;
	}

	*npull = np;
	return 0;
}

size_t ctdb_req_control_len(struct ctdb_req_header *h,
			    struct ctdb_req_control *c)
{
	uint32_t u32 = 0;

	return ctdb_req_header_len(h) +
		ctdb_uint32_len(&c->opcode) +
		ctdb_uint32_len(&c->pad) +
		ctdb_uint64_len(&c->srvid) +
		ctdb_uint32_len(&c->client_id) +
		ctdb_uint32_len(&c->flags) +
		ctdb_uint32_len(&u32) +
		ctdb_req_control_data_len(&c->rdata);
}

int ctdb_req_control_push(struct ctdb_req_header *h,
			  struct ctdb_req_control *c,
			  uint8_t *buf, size_t *buflen)
{
	size_t offset = 0, np;
	size_t length;
	uint32_t u32;

	length = ctdb_req_control_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&c->opcode, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&c->pad, buf+offset, &np);
	offset += np;

	ctdb_uint64_push(&c->srvid, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&c->client_id, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&c->flags, buf+offset, &np);
	offset += np;

	u32 = ctdb_req_control_data_len(&c->rdata);
	ctdb_uint32_push(&u32, buf+offset, &np);
	offset += np;

	ctdb_req_control_data_push(&c->rdata, buf+offset, &np);
	offset += np;

	if (offset > *buflen) {
		return EMSGSIZE;
	}

	return 0;
}

int ctdb_req_control_pull(uint8_t *buf, size_t buflen,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_req_control *c)
{
	struct ctdb_req_header header;
	size_t offset = 0, np;
	uint32_t u32;
	int ret;

	ret = ctdb_req_header_pull(buf+offset, buflen-offset, &header, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (h != NULL) {
		*h = header;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &c->opcode, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &c->pad, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint64_pull(buf+offset, buflen-offset, &c->srvid, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &c->client_id, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &c->flags, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &u32, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (u32 > buflen-offset) {
		return EMSGSIZE;
	}

	ret = ctdb_req_control_data_pull(buf+offset, u32, c->opcode, mem_ctx,
					 &c->rdata, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (offset > buflen) {
		return EMSGSIZE;
	}

	return 0;
}

size_t ctdb_reply_control_len(struct ctdb_req_header *h,
			      struct ctdb_reply_control *c)
{
	uint32_t dsize, esize;

	if (c->status == 0) {
		dsize = ctdb_reply_control_data_len(&c->rdata);
		esize = 0;
	} else {
		dsize = 0;
		esize = ctdb_string_len(&c->errmsg);
	}

	return ctdb_req_header_len(h) +
		ctdb_int32_len(&c->status) +
		ctdb_uint32_len(&dsize) +
		ctdb_uint32_len(&esize) +
		dsize + esize;
}

int ctdb_reply_control_push(struct ctdb_req_header *h,
			    struct ctdb_reply_control *c,
			    uint8_t *buf, size_t *buflen)
{
	size_t offset = 0, np;
	size_t length;
	uint32_t dsize, esize;

	length = ctdb_reply_control_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, buf+offset, &np);
	offset += np;

	ctdb_int32_push(&c->status, buf+offset, &np);
	offset += np;

	if (c->status == 0) {
		dsize = ctdb_reply_control_data_len(&c->rdata);
		esize = 0;
	} else {
		dsize = 0;
		esize = ctdb_string_len(&c->errmsg);
	}

	ctdb_uint32_push(&dsize, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&esize, buf+offset, &np);
	offset += np;

	if (c->status == 0) {
		ctdb_reply_control_data_push(&c->rdata, buf+offset, &np);
	} else {
		ctdb_string_push(&c->errmsg, buf+offset, &np);
	}
	offset += np;

	return 0;
}

int ctdb_reply_control_pull(uint8_t *buf, size_t buflen, uint32_t opcode,
			    struct ctdb_req_header *h,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_reply_control *c)
{
	struct ctdb_req_header header;
	size_t offset = 0, np;
	uint32_t dsize, esize;
	int ret;

	ret = ctdb_req_header_pull(buf+offset, buflen-offset, &header, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (h != NULL) {
		*h = header;
	}

	ret = ctdb_int32_pull(buf+offset, buflen-offset, &c->status, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &dsize, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &esize, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	c->errmsg = NULL;

	if (c->status == 0) {
		if (buflen-offset < dsize) {
			return EMSGSIZE;
		}

		ret = ctdb_reply_control_data_pull(buf+offset, dsize,
						   opcode, mem_ctx, &c->rdata,
						   &np);
		if (ret != 0) {
			return ret;
		}
		offset += np;

	} else {
		if (buflen-offset < esize) {
			return EMSGSIZE;
		}

		ret = ctdb_string_pull(buf+offset, esize, mem_ctx, &c->errmsg,
				       &np);
		if (ret != 0) {
			return ret;
		}
		offset += np;
	}

	return 0;
}
