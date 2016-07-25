/*
   protocol tests

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

#include <assert.h>

#define PROTOCOL_TEST

#include "protocol_types_test.c"


#define GENERATION	0xabcdef12
#define OPERATION	CTDB_REQ_KEEPALIVE
#define REQID		0x34567890
#define SRCNODE		7
#define DESTNODE	13

/*
 * Functions to fill and verify protocol structures
 */

static void verify_ctdb_req_header(struct ctdb_req_header *h,
				   struct ctdb_req_header *h2)
{
	verify_buffer(h, h2, ctdb_req_header_len(h));
}

static void fill_ctdb_req_call(TALLOC_CTX *mem_ctx,
			       struct ctdb_req_call *c)
{
	c->flags = rand32();
	c->db_id = rand32();
	c->callid = rand32();
	c->hopcount = rand32();
	fill_tdb_data_nonnull(mem_ctx, &c->key);
	fill_tdb_data(mem_ctx, &c->calldata);
}

static void verify_ctdb_req_call(struct ctdb_req_call *c,
				 struct ctdb_req_call *c2)
{
	assert(c->flags == c2->flags);
	assert(c->db_id == c2->db_id);
	assert(c->callid == c2->callid);
	assert(c->hopcount == c2->hopcount);
	verify_tdb_data(&c->key, &c2->key);
	verify_tdb_data(&c->calldata, &c2->calldata);
}

static void fill_ctdb_reply_call(TALLOC_CTX *mem_ctx,
				 struct ctdb_reply_call *c)
{
	c->status = rand32();
	fill_tdb_data(mem_ctx, &c->data);
}

static void verify_ctdb_reply_call(struct ctdb_reply_call *c,
				   struct ctdb_reply_call *c2)
{
	assert(c->status == c2->status);
	verify_tdb_data(&c->data, &c2->data);
}

static void fill_ctdb_reply_error(TALLOC_CTX *mem_ctx,
				  struct ctdb_reply_error *c)
{
	c->status = rand32();
	fill_tdb_data(mem_ctx, &c->msg);
}

static void verify_ctdb_reply_error(struct ctdb_reply_error *c,
				    struct ctdb_reply_error *c2)
{
	assert(c->status == c2->status);
	verify_tdb_data(&c->msg, &c2->msg);
}

static void fill_ctdb_req_dmaster(TALLOC_CTX *mem_ctx,
				  struct ctdb_req_dmaster *c)
{
	c->db_id = rand32();
	c->rsn = rand64();
	c->dmaster = rand32();
	fill_tdb_data_nonnull(mem_ctx, &c->key);
	fill_tdb_data(mem_ctx, &c->data);
}

static void verify_ctdb_req_dmaster(struct ctdb_req_dmaster *c,
				    struct ctdb_req_dmaster *c2)
{
	assert(c->db_id == c2->db_id);
	assert(c->rsn == c2->rsn);
	assert(c->dmaster == c2->dmaster);
	verify_tdb_data(&c->key, &c2->key);
	verify_tdb_data(&c->data, &c2->data);
}

static void fill_ctdb_reply_dmaster(TALLOC_CTX *mem_ctx,
				    struct ctdb_reply_dmaster *c)
{
	c->db_id = rand32();
	c->rsn = rand64();
	fill_tdb_data_nonnull(mem_ctx, &c->key);
	fill_tdb_data(mem_ctx, &c->data);
}

static void verify_ctdb_reply_dmaster(struct ctdb_reply_dmaster *c,
				      struct ctdb_reply_dmaster *c2)
{
	assert(c->db_id == c2->db_id);
	assert(c->rsn == c2->rsn);
	verify_tdb_data(&c->key, &c2->key);
	verify_tdb_data(&c->data, &c2->data);
}

static void fill_ctdb_req_control_data(TALLOC_CTX *mem_ctx,
				       struct ctdb_req_control_data *cd,
				       uint32_t opcode)
{
	cd->opcode = opcode;
	switch (opcode) {
	case CTDB_CONTROL_PROCESS_EXISTS:
		cd->data.pid = rand32();
		break;

	case CTDB_CONTROL_STATISTICS:
		break;

	case CTDB_CONTROL_PING:
		break;

	case CTDB_CONTROL_GETDBPATH:
		cd->data.db_id = rand32();
		break;

	case CTDB_CONTROL_GETVNNMAP:
		break;

	case CTDB_CONTROL_SETVNNMAP:
		cd->data.vnnmap = talloc(mem_ctx, struct ctdb_vnn_map);
		assert(cd->data.vnnmap != NULL);
		fill_ctdb_vnn_map(mem_ctx, cd->data.vnnmap);
		break;

	case CTDB_CONTROL_GET_DEBUG:
		break;

	case CTDB_CONTROL_SET_DEBUG:
		cd->data.loglevel = rand_int(5);
		break;

	case CTDB_CONTROL_GET_DBMAP:
		break;

	case CTDB_CONTROL_PULL_DB:
		cd->data.pulldb = talloc(mem_ctx, struct ctdb_pulldb);
		assert(cd->data.pulldb != NULL);
		fill_ctdb_pulldb(mem_ctx, cd->data.pulldb);
		break;

	case CTDB_CONTROL_PUSH_DB:
		cd->data.recbuf = talloc(mem_ctx, struct ctdb_rec_buffer);
		assert(cd->data.recbuf != NULL);
		fill_ctdb_rec_buffer(mem_ctx, cd->data.recbuf);
		break;

	case CTDB_CONTROL_GET_RECMODE:
		break;

	case CTDB_CONTROL_SET_RECMODE:
		cd->data.recmode = rand_int(2);
		break;

	case CTDB_CONTROL_STATISTICS_RESET:
		break;

	case CTDB_CONTROL_DB_ATTACH:
		fill_ctdb_string(mem_ctx, &cd->data.db_name);
		assert(cd->data.db_name != NULL);
		break;

	case CTDB_CONTROL_SET_CALL:
		break;

	case CTDB_CONTROL_TRAVERSE_START:
		cd->data.traverse_start = talloc(mem_ctx, struct ctdb_traverse_start);
		assert(cd->data.traverse_start != NULL);
		fill_ctdb_traverse_start(mem_ctx, cd->data.traverse_start);
		break;

	case CTDB_CONTROL_TRAVERSE_ALL:
		cd->data.traverse_all = talloc(mem_ctx, struct ctdb_traverse_all);
		assert(cd->data.traverse_all != NULL);
		fill_ctdb_traverse_all(mem_ctx, cd->data.traverse_all);
		break;

	case CTDB_CONTROL_TRAVERSE_DATA:
		cd->data.rec_data = talloc(mem_ctx, struct ctdb_rec_data);
		assert(cd->data.rec_data != NULL);
		fill_ctdb_rec_data(mem_ctx, cd->data.rec_data);
		break;

	case CTDB_CONTROL_REGISTER_SRVID:
		break;

	case CTDB_CONTROL_DEREGISTER_SRVID:
		break;

	case CTDB_CONTROL_GET_DBNAME:
		cd->data.db_id = rand32();
		break;

	case CTDB_CONTROL_ENABLE_SEQNUM:
		cd->data.db_id = rand32();
		break;

	case CTDB_CONTROL_UPDATE_SEQNUM:
		cd->data.db_id = rand32();
		break;

	case CTDB_CONTROL_DUMP_MEMORY:
		break;

	case CTDB_CONTROL_GET_PID:
		break;

	case CTDB_CONTROL_GET_RECMASTER:
		break;

	case CTDB_CONTROL_SET_RECMASTER:
		cd->data.recmaster = rand_int(32);
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
		cd->data.conn = talloc(mem_ctx, struct ctdb_connection);
		assert(cd->data.conn != NULL);
		fill_ctdb_connection(mem_ctx, cd->data.conn);
		break;

	case CTDB_CONTROL_TCP_ADD:
		cd->data.conn = talloc(mem_ctx, struct ctdb_connection);
		assert(cd->data.conn != NULL);
		fill_ctdb_connection(mem_ctx, cd->data.conn);
		break;

	case CTDB_CONTROL_TCP_REMOVE:
		cd->data.conn = talloc(mem_ctx, struct ctdb_connection);
		assert(cd->data.conn != NULL);
		fill_ctdb_connection(mem_ctx, cd->data.conn);
		break;

	case CTDB_CONTROL_STARTUP:
		break;

	case CTDB_CONTROL_SET_TUNABLE:
		cd->data.tunable = talloc(mem_ctx, struct ctdb_tunable);
		assert(cd->data.tunable != NULL);
		fill_ctdb_tunable(mem_ctx, cd->data.tunable);
		break;

	case CTDB_CONTROL_GET_TUNABLE:
		fill_ctdb_string(mem_ctx, &cd->data.tun_var);
		assert(cd->data.tun_var != NULL);
		break;

	case CTDB_CONTROL_LIST_TUNABLES:
		break;

	case CTDB_CONTROL_MODIFY_FLAGS:
		cd->data.flag_change = talloc(mem_ctx, struct ctdb_node_flag_change);
		assert(cd->data.flag_change != NULL);
		fill_ctdb_node_flag_change(mem_ctx, cd->data.flag_change);
		break;

	case CTDB_CONTROL_GET_ALL_TUNABLES:
		break;

	case CTDB_CONTROL_GET_TCP_TICKLE_LIST:
		cd->data.addr = talloc(mem_ctx, ctdb_sock_addr);
		assert(cd->data.addr != NULL);
		fill_ctdb_sock_addr(mem_ctx, cd->data.addr);
		break;

	case CTDB_CONTROL_SET_TCP_TICKLE_LIST:
		cd->data.tickles = talloc(mem_ctx, struct ctdb_tickle_list);
		assert(cd->data.tickles != NULL);
		fill_ctdb_tickle_list(mem_ctx, cd->data.tickles);
		break;

	case CTDB_CONTROL_DB_ATTACH_PERSISTENT:
		fill_ctdb_string(mem_ctx, &cd->data.db_name);
		assert(cd->data.db_name != NULL);
		break;

	case CTDB_CONTROL_UPDATE_RECORD:
		cd->data.recbuf = talloc(mem_ctx, struct ctdb_rec_buffer);
		assert(cd->data.recbuf != NULL);
		fill_ctdb_rec_buffer(mem_ctx, cd->data.recbuf);
		break;

	case CTDB_CONTROL_SEND_GRATUITOUS_ARP:
		cd->data.addr_info = talloc(mem_ctx, struct ctdb_addr_info);
		assert(cd->data.addr_info != NULL);
		fill_ctdb_addr_info(mem_ctx, cd->data.addr_info);
		break;

	case CTDB_CONTROL_WIPE_DATABASE:
		cd->data.transdb = talloc(mem_ctx, struct ctdb_transdb);
		assert(cd->data.transdb != NULL);
		fill_ctdb_transdb(mem_ctx, cd->data.transdb);
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
		cd->data.recbuf = talloc(mem_ctx, struct ctdb_rec_buffer);
		assert(cd->data.recbuf != NULL);
		fill_ctdb_rec_buffer(mem_ctx, cd->data.recbuf);
		break;

	case CTDB_CONTROL_ENABLE_MONITOR:
		break;

	case CTDB_CONTROL_DISABLE_MONITOR:
		break;

	case CTDB_CONTROL_ADD_PUBLIC_IP:
		cd->data.addr_info = talloc(mem_ctx, struct ctdb_addr_info);
		assert(cd->data.addr_info != NULL);
		fill_ctdb_addr_info(mem_ctx, cd->data.addr_info);
		break;

	case CTDB_CONTROL_DEL_PUBLIC_IP:
		cd->data.addr_info = talloc(mem_ctx, struct ctdb_addr_info);
		assert(cd->data.addr_info != NULL);
		fill_ctdb_addr_info(mem_ctx, cd->data.addr_info);
		break;

	case CTDB_CONTROL_RUN_EVENTSCRIPTS:
		fill_ctdb_string(mem_ctx, &cd->data.event_str);
		assert(cd->data.event_str != NULL);
		break;

	case CTDB_CONTROL_GET_CAPABILITIES:
		break;

	case CTDB_CONTROL_START_PERSISTENT_UPDATE:
		break;

	case CTDB_CONTROL_CANCEL_PERSISTENT_UPDATE:
		break;

	case CTDB_CONTROL_RECD_PING:
		break;

	case CTDB_CONTROL_RELEASE_IP:
		cd->data.pubip = talloc(mem_ctx, struct ctdb_public_ip);
		assert(cd->data.pubip != NULL);
		fill_ctdb_public_ip(mem_ctx, cd->data.pubip);
		break;

	case CTDB_CONTROL_TAKEOVER_IP:
		cd->data.pubip = talloc(mem_ctx, struct ctdb_public_ip);
		assert(cd->data.pubip != NULL);
		fill_ctdb_public_ip(mem_ctx, cd->data.pubip);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IPS:
		break;

	case CTDB_CONTROL_GET_NODEMAP:
		break;

	case CTDB_CONTROL_GET_EVENT_SCRIPT_STATUS:
		cd->data.event = rand_int(CTDB_EVENT_MAX);
		break;

	case CTDB_CONTROL_TRAVERSE_KILL:
		cd->data.traverse_start = talloc(mem_ctx, struct ctdb_traverse_start);
		assert(cd->data.traverse_start != NULL);
		fill_ctdb_traverse_start(mem_ctx, cd->data.traverse_start);
		break;

	case CTDB_CONTROL_RECD_RECLOCK_LATENCY:
		cd->data.reclock_latency = rand_double();
		break;

	case CTDB_CONTROL_GET_RECLOCK_FILE:
		break;

	case CTDB_CONTROL_STOP_NODE:
		break;

	case CTDB_CONTROL_CONTINUE_NODE:
		break;

	case CTDB_CONTROL_SET_LMASTERROLE:
		cd->data.role = rand_int(2);
		break;

	case CTDB_CONTROL_SET_RECMASTERROLE:
		cd->data.role = rand_int(2);
		break;

	case CTDB_CONTROL_ENABLE_SCRIPT:
		fill_ctdb_string(mem_ctx, &cd->data.script);
		assert(cd->data.script != NULL);
		break;

	case CTDB_CONTROL_DISABLE_SCRIPT:
		fill_ctdb_string(mem_ctx, &cd->data.script);
		assert(cd->data.script != NULL);
		break;

	case CTDB_CONTROL_SET_BAN_STATE:
		cd->data.ban_state = talloc(mem_ctx, struct ctdb_ban_state);
		assert(cd->data.ban_state != NULL);
		fill_ctdb_ban_state(mem_ctx, cd->data.ban_state);
		break;

	case CTDB_CONTROL_GET_BAN_STATE:
		break;

	case CTDB_CONTROL_REGISTER_NOTIFY:
		cd->data.notify = talloc(mem_ctx, struct ctdb_notify_data);
		assert(cd->data.notify != NULL);
		fill_ctdb_notify_data(mem_ctx, cd->data.notify);
		break;

	case CTDB_CONTROL_DEREGISTER_NOTIFY:
		cd->data.srvid = rand64();
		break;

	case CTDB_CONTROL_TRANS3_COMMIT:
		cd->data.recbuf = talloc(mem_ctx, struct ctdb_rec_buffer);
		assert(cd->data.recbuf != NULL);
		fill_ctdb_rec_buffer(mem_ctx, cd->data.recbuf);
		break;

	case CTDB_CONTROL_GET_DB_SEQNUM:
		cd->data.db_id = rand32();
		break;

	case CTDB_CONTROL_DB_SET_HEALTHY:
		cd->data.db_id = rand32();
		break;

	case CTDB_CONTROL_DB_GET_HEALTH:
		cd->data.db_id = rand32();
		break;

	case CTDB_CONTROL_GET_PUBLIC_IP_INFO:
		cd->data.addr = talloc(mem_ctx, ctdb_sock_addr);
		assert(cd->data.addr != NULL);
		fill_ctdb_sock_addr(mem_ctx, cd->data.addr);
		break;

	case CTDB_CONTROL_GET_IFACES:
		break;

	case CTDB_CONTROL_SET_IFACE_LINK_STATE:
		cd->data.iface = talloc(mem_ctx, struct ctdb_iface);
		assert(cd->data.iface != NULL);
		fill_ctdb_iface(mem_ctx, cd->data.iface);
		break;

	case CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE:
		cd->data.conn = talloc(mem_ctx, struct ctdb_connection);
		assert(cd->data.conn != NULL);
		fill_ctdb_connection(mem_ctx, cd->data.conn);
		break;

	case CTDB_CONTROL_GET_STAT_HISTORY:
		break;

	case CTDB_CONTROL_SCHEDULE_FOR_DELETION:
		cd->data.key = talloc(mem_ctx, struct ctdb_key_data);
		assert(cd->data.key != NULL);
		fill_ctdb_key_data(mem_ctx, cd->data.key);
		break;

	case CTDB_CONTROL_SET_DB_READONLY:
		cd->data.db_id = rand32();
		break;

	case CTDB_CONTROL_CHECK_SRVIDS:
		cd->data.u64_array = talloc(mem_ctx, struct ctdb_uint64_array);
		assert(cd->data.u64_array != NULL);
		fill_ctdb_uint64_array(mem_ctx, cd->data.u64_array);
		break;

	case CTDB_CONTROL_TRAVERSE_START_EXT:
		cd->data.traverse_start_ext = talloc(mem_ctx, struct ctdb_traverse_start_ext);
		assert(cd->data.traverse_start_ext != NULL);
		fill_ctdb_traverse_start_ext(mem_ctx, cd->data.traverse_start_ext);
		break;

	case CTDB_CONTROL_GET_DB_STATISTICS:
		cd->data.db_id = rand32();
		break;

	case CTDB_CONTROL_SET_DB_STICKY:
		cd->data.db_id = rand32();
		break;

	case CTDB_CONTROL_RELOAD_PUBLIC_IPS:
		break;

	case CTDB_CONTROL_TRAVERSE_ALL_EXT:
		cd->data.traverse_all_ext = talloc(mem_ctx, struct ctdb_traverse_all_ext);
		assert(cd->data.traverse_all_ext != NULL);
		fill_ctdb_traverse_all_ext(mem_ctx, cd->data.traverse_all_ext);
		break;

	case CTDB_CONTROL_RECEIVE_RECORDS:
		cd->data.recbuf = talloc(mem_ctx, struct ctdb_rec_buffer);
		assert(cd->data.recbuf != NULL);
		fill_ctdb_rec_buffer(mem_ctx, cd->data.recbuf);
		break;

	case CTDB_CONTROL_IPREALLOCATED:
		break;

	case CTDB_CONTROL_GET_RUNSTATE:
		break;

	case CTDB_CONTROL_DB_DETACH:
		cd->data.db_id = rand32();
		break;

	case CTDB_CONTROL_GET_NODES_FILE:
		break;

	case CTDB_CONTROL_DB_FREEZE:
		cd->data.db_id = rand32();
		break;

	case CTDB_CONTROL_DB_THAW:
		cd->data.db_id = rand32();
		break;

	case CTDB_CONTROL_DB_TRANSACTION_START:
		cd->data.transdb = talloc(mem_ctx, struct ctdb_transdb);
		assert(cd->data.transdb != NULL);
		fill_ctdb_transdb(mem_ctx, cd->data.transdb);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_COMMIT:
		cd->data.transdb = talloc(mem_ctx, struct ctdb_transdb);
		assert(cd->data.transdb != NULL);
		fill_ctdb_transdb(mem_ctx, cd->data.transdb);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_CANCEL:
		cd->data.db_id = rand32();
		break;

	case CTDB_CONTROL_DB_PULL:
		cd->data.pulldb_ext = talloc(mem_ctx, struct ctdb_pulldb_ext);
		assert(cd->data.pulldb_ext != NULL);
		fill_ctdb_pulldb_ext(mem_ctx, cd->data.pulldb_ext);
		break;

	case CTDB_CONTROL_DB_PUSH_START:
		cd->data.pulldb_ext = talloc(mem_ctx, struct ctdb_pulldb_ext);
		assert(cd->data.pulldb_ext != NULL);
		fill_ctdb_pulldb_ext(mem_ctx, cd->data.pulldb_ext);
		break;

	case CTDB_CONTROL_DB_PUSH_CONFIRM:
		cd->data.db_id = rand32();
		break;

	}
}

static void verify_ctdb_req_control_data(struct ctdb_req_control_data *cd,
					 struct ctdb_req_control_data *cd2)
{
	assert(cd->opcode == cd2->opcode);

	switch (cd->opcode) {
	case CTDB_CONTROL_PROCESS_EXISTS:
		assert(cd->data.pid == cd2->data.pid);
		break;

	case CTDB_CONTROL_STATISTICS:
		break;

	case CTDB_CONTROL_PING:
		break;

	case CTDB_CONTROL_GETDBPATH:
		assert(cd->data.db_id == cd2->data.db_id);
		break;

	case CTDB_CONTROL_GETVNNMAP:
		break;

	case CTDB_CONTROL_SETVNNMAP:
		verify_ctdb_vnn_map(cd->data.vnnmap, cd2->data.vnnmap);
		break;

	case CTDB_CONTROL_GET_DEBUG:
		break;

	case CTDB_CONTROL_SET_DEBUG:
		assert(cd->data.loglevel == cd2->data.loglevel);
		break;

	case CTDB_CONTROL_GET_DBMAP:
		break;

	case CTDB_CONTROL_PULL_DB:
		verify_ctdb_pulldb(cd->data.pulldb, cd2->data.pulldb);
		break;

	case CTDB_CONTROL_PUSH_DB:
		verify_ctdb_rec_buffer(cd->data.recbuf, cd2->data.recbuf);
		break;

	case CTDB_CONTROL_GET_RECMODE:
		break;

	case CTDB_CONTROL_SET_RECMODE:
		assert(cd->data.recmode == cd2->data.recmode);
		break;

	case CTDB_CONTROL_STATISTICS_RESET:
		break;

	case CTDB_CONTROL_DB_ATTACH:
		verify_ctdb_string(cd->data.db_name, cd2->data.db_name);
		break;

	case CTDB_CONTROL_SET_CALL:
		break;

	case CTDB_CONTROL_TRAVERSE_START:
		verify_ctdb_traverse_start(cd->data.traverse_start,
					   cd2->data.traverse_start);
		break;

	case CTDB_CONTROL_TRAVERSE_ALL:
		verify_ctdb_traverse_all(cd->data.traverse_all,
					 cd2->data.traverse_all);
		break;

	case CTDB_CONTROL_TRAVERSE_DATA:
		verify_ctdb_rec_data(cd->data.rec_data, cd2->data.rec_data);
		break;

	case CTDB_CONTROL_REGISTER_SRVID:
		break;

	case CTDB_CONTROL_DEREGISTER_SRVID:
		break;

	case CTDB_CONTROL_GET_DBNAME:
		assert(cd->data.db_id == cd2->data.db_id);
		break;

	case CTDB_CONTROL_ENABLE_SEQNUM:
		assert(cd->data.db_id == cd2->data.db_id);
		break;

	case CTDB_CONTROL_UPDATE_SEQNUM:
		assert(cd->data.db_id == cd2->data.db_id);
		break;

	case CTDB_CONTROL_DUMP_MEMORY:
		break;

	case CTDB_CONTROL_GET_PID:
		break;

	case CTDB_CONTROL_GET_RECMASTER:
		break;

	case CTDB_CONTROL_SET_RECMASTER:
		assert(cd->data.recmaster == cd2->data.recmaster);
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
		verify_ctdb_connection(cd->data.conn, cd2->data.conn);
		break;

	case CTDB_CONTROL_TCP_ADD:
		verify_ctdb_connection(cd->data.conn, cd2->data.conn);
		break;

	case CTDB_CONTROL_TCP_REMOVE:
		verify_ctdb_connection(cd->data.conn, cd2->data.conn);
		break;

	case CTDB_CONTROL_STARTUP:
		break;

	case CTDB_CONTROL_SET_TUNABLE:
		verify_ctdb_tunable(cd->data.tunable, cd2->data.tunable);
		break;

	case CTDB_CONTROL_GET_TUNABLE:
		verify_ctdb_string(cd->data.tun_var, cd2->data.tun_var);
		break;

	case CTDB_CONTROL_LIST_TUNABLES:
		break;

	case CTDB_CONTROL_MODIFY_FLAGS:
		verify_ctdb_node_flag_change(cd->data.flag_change,
					     cd2->data.flag_change);
		break;

	case CTDB_CONTROL_GET_ALL_TUNABLES:
		break;

	case CTDB_CONTROL_GET_TCP_TICKLE_LIST:
		verify_ctdb_sock_addr(cd->data.addr, cd2->data.addr);
		break;

	case CTDB_CONTROL_SET_TCP_TICKLE_LIST:
		verify_ctdb_tickle_list(cd->data.tickles, cd2->data.tickles);
		break;

	case CTDB_CONTROL_DB_ATTACH_PERSISTENT:
		verify_ctdb_string(cd->data.db_name, cd2->data.db_name);
		break;

	case CTDB_CONTROL_UPDATE_RECORD:
		verify_ctdb_rec_buffer(cd->data.recbuf, cd2->data.recbuf);
		break;

	case CTDB_CONTROL_SEND_GRATUITOUS_ARP:
		verify_ctdb_addr_info(cd->data.addr_info, cd2->data.addr_info);
		break;

	case CTDB_CONTROL_WIPE_DATABASE:
		verify_ctdb_transdb(cd->data.transdb, cd2->data.transdb);
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
		verify_ctdb_rec_buffer(cd->data.recbuf, cd2->data.recbuf);
		break;

	case CTDB_CONTROL_ENABLE_MONITOR:
		break;

	case CTDB_CONTROL_DISABLE_MONITOR:
		break;

	case CTDB_CONTROL_ADD_PUBLIC_IP:
		verify_ctdb_addr_info(cd->data.addr_info, cd2->data.addr_info);
		break;

	case CTDB_CONTROL_DEL_PUBLIC_IP:
		verify_ctdb_addr_info(cd->data.addr_info, cd2->data.addr_info);
		break;

	case CTDB_CONTROL_RUN_EVENTSCRIPTS:
		verify_ctdb_string(cd->data.event_str, cd2->data.event_str);
		break;

	case CTDB_CONTROL_GET_CAPABILITIES:
		break;

	case CTDB_CONTROL_START_PERSISTENT_UPDATE:
		break;

	case CTDB_CONTROL_CANCEL_PERSISTENT_UPDATE:
		break;

	case CTDB_CONTROL_RECD_PING:
		break;

	case CTDB_CONTROL_RELEASE_IP:
		verify_ctdb_public_ip(cd->data.pubip, cd2->data.pubip);
		break;

	case CTDB_CONTROL_TAKEOVER_IP:
		verify_ctdb_public_ip(cd->data.pubip, cd2->data.pubip);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IPS:
		break;

	case CTDB_CONTROL_GET_NODEMAP:
		break;

	case CTDB_CONTROL_GET_EVENT_SCRIPT_STATUS:
		assert(cd->data.event == cd2->data.event);
		break;

	case CTDB_CONTROL_TRAVERSE_KILL:
		verify_ctdb_traverse_start(cd->data.traverse_start,
					   cd2->data.traverse_start);
		break;

	case CTDB_CONTROL_RECD_RECLOCK_LATENCY:
		assert(cd->data.reclock_latency == cd2->data.reclock_latency);
		break;

	case CTDB_CONTROL_GET_RECLOCK_FILE:
		break;

	case CTDB_CONTROL_STOP_NODE:
		break;

	case CTDB_CONTROL_CONTINUE_NODE:
		break;

	case CTDB_CONTROL_SET_LMASTERROLE:
		assert(cd->data.role == cd2->data.role);
		break;

	case CTDB_CONTROL_SET_RECMASTERROLE:
		assert(cd->data.role == cd2->data.role);
		break;

	case CTDB_CONTROL_ENABLE_SCRIPT:
		verify_ctdb_string(cd->data.script, cd2->data.script);
		break;

	case CTDB_CONTROL_DISABLE_SCRIPT:
		verify_ctdb_string(cd->data.script, cd2->data.script);
		break;

	case CTDB_CONTROL_SET_BAN_STATE:
		verify_ctdb_ban_state(cd->data.ban_state, cd2->data.ban_state);
		break;

	case CTDB_CONTROL_GET_BAN_STATE:
		break;

	case CTDB_CONTROL_REGISTER_NOTIFY:
		verify_ctdb_notify_data(cd->data.notify, cd2->data.notify);
		break;

	case CTDB_CONTROL_DEREGISTER_NOTIFY:
		assert(cd->data.srvid == cd2->data.srvid);
		break;

	case CTDB_CONTROL_TRANS3_COMMIT:
		verify_ctdb_rec_buffer(cd->data.recbuf, cd2->data.recbuf);
		break;

	case CTDB_CONTROL_GET_DB_SEQNUM:
		assert(cd->data.db_id == cd2->data.db_id);
		break;

	case CTDB_CONTROL_DB_SET_HEALTHY:
		assert(cd->data.db_id == cd2->data.db_id);
		break;

	case CTDB_CONTROL_DB_GET_HEALTH:
		assert(cd->data.db_id == cd2->data.db_id);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IP_INFO:
		verify_ctdb_sock_addr(cd->data.addr, cd2->data.addr);
		break;

	case CTDB_CONTROL_GET_IFACES:
		break;

	case CTDB_CONTROL_SET_IFACE_LINK_STATE:
		verify_ctdb_iface(cd->data.iface, cd2->data.iface);
		break;

	case CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE:
		verify_ctdb_connection(cd->data.conn, cd2->data.conn);
		break;

	case CTDB_CONTROL_GET_STAT_HISTORY:
		break;

	case CTDB_CONTROL_SCHEDULE_FOR_DELETION:
		verify_ctdb_key_data(cd->data.key, cd2->data.key);
		break;

	case CTDB_CONTROL_SET_DB_READONLY:
		assert(cd->data.db_id == cd2->data.db_id);
		break;

	case CTDB_CONTROL_CHECK_SRVIDS:
		verify_ctdb_uint64_array(cd->data.u64_array,
					 cd2->data.u64_array);
		break;

	case CTDB_CONTROL_TRAVERSE_START_EXT:
		verify_ctdb_traverse_start_ext(cd->data.traverse_start_ext,
					       cd2->data.traverse_start_ext);
		break;

	case CTDB_CONTROL_GET_DB_STATISTICS:
		assert(cd->data.db_id == cd2->data.db_id);
		break;

	case CTDB_CONTROL_SET_DB_STICKY:
		assert(cd->data.db_id == cd2->data.db_id);
		break;

	case CTDB_CONTROL_RELOAD_PUBLIC_IPS:
		break;

	case CTDB_CONTROL_TRAVERSE_ALL_EXT:
		verify_ctdb_traverse_all_ext(cd->data.traverse_all_ext,
					     cd2->data.traverse_all_ext);
		break;

	case CTDB_CONTROL_RECEIVE_RECORDS:
		verify_ctdb_rec_buffer(cd->data.recbuf, cd2->data.recbuf);
		break;

	case CTDB_CONTROL_IPREALLOCATED:
		break;

	case CTDB_CONTROL_GET_RUNSTATE:
		break;

	case CTDB_CONTROL_DB_DETACH:
		assert(cd->data.db_id == cd2->data.db_id);
		break;

	case CTDB_CONTROL_GET_NODES_FILE:
		break;

	case CTDB_CONTROL_DB_FREEZE:
		assert(cd->data.db_id == cd2->data.db_id);
		break;

	case CTDB_CONTROL_DB_THAW:
		assert(cd->data.db_id == cd2->data.db_id);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_START:
		verify_ctdb_transdb(cd->data.transdb, cd2->data.transdb);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_COMMIT:
		verify_ctdb_transdb(cd->data.transdb, cd2->data.transdb);
		break;

	case CTDB_CONTROL_DB_TRANSACTION_CANCEL:
		assert(cd->data.db_id == cd2->data.db_id);
		break;

	case CTDB_CONTROL_DB_PULL:
		verify_ctdb_pulldb_ext(cd->data.pulldb_ext,
				       cd2->data.pulldb_ext);
		break;

	case CTDB_CONTROL_DB_PUSH_START:
		verify_ctdb_pulldb_ext(cd->data.pulldb_ext,
				       cd2->data.pulldb_ext);
		break;

	case CTDB_CONTROL_DB_PUSH_CONFIRM:
		assert(cd->data.db_id == cd2->data.db_id);
		break;

	}
}

static void fill_ctdb_req_control(TALLOC_CTX *mem_ctx,
				  struct ctdb_req_control *c,
				  uint32_t opcode)
{
	c->opcode = opcode;
	c->pad = rand32();
	c->srvid = rand64();
	c->client_id = rand32();
	c->flags = rand32();

	fill_ctdb_req_control_data(mem_ctx, &c->rdata, opcode);
}

static void verify_ctdb_req_control(struct ctdb_req_control *c,
				    struct ctdb_req_control *c2)
{
	assert(c->opcode == c2->opcode);
	assert(c->pad == c2->pad);
	assert(c->srvid == c2->srvid);
	assert(c->client_id == c2->client_id);
	assert(c->flags == c2->flags);

	verify_ctdb_req_control_data(&c->rdata, &c2->rdata);
}

static void fill_ctdb_reply_control_data(TALLOC_CTX *mem_ctx,
					 struct ctdb_reply_control_data *cd,
					 uint32_t opcode)
{
	cd->opcode = opcode;

	switch (opcode) {
	case CTDB_CONTROL_PROCESS_EXISTS:
		break;

	case CTDB_CONTROL_STATISTICS:
		cd->data.stats = talloc(mem_ctx, struct ctdb_statistics);
		assert(cd->data.stats != NULL);
		fill_ctdb_statistics(mem_ctx, cd->data.stats);
		break;

	case CTDB_CONTROL_PING:
		break;

	case CTDB_CONTROL_GETDBPATH:
		fill_ctdb_string(mem_ctx, &cd->data.db_path);
		assert(cd->data.db_path != NULL);
		break;

	case CTDB_CONTROL_GETVNNMAP:
		cd->data.vnnmap = talloc(mem_ctx, struct ctdb_vnn_map);
		assert(cd->data.vnnmap != NULL);
		fill_ctdb_vnn_map(mem_ctx, cd->data.vnnmap);
		break;

	case CTDB_CONTROL_SETVNNMAP:
		break;

	case CTDB_CONTROL_GET_DEBUG:
		cd->data.loglevel = rand_int(5);
		break;

	case CTDB_CONTROL_SET_DEBUG:
		break;

	case CTDB_CONTROL_GET_DBMAP:
		cd->data.dbmap = talloc(mem_ctx, struct ctdb_dbid_map);
		assert(cd->data.dbmap != NULL);
		fill_ctdb_dbid_map(mem_ctx, cd->data.dbmap);
		break;

	case CTDB_CONTROL_PULL_DB:
		cd->data.recbuf = talloc(mem_ctx, struct ctdb_rec_buffer);
		assert(cd->data.recbuf != NULL);
		fill_ctdb_rec_buffer(mem_ctx, cd->data.recbuf);
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
		cd->data.db_id = rand32();
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
		fill_ctdb_string(mem_ctx, &cd->data.db_name);
		assert(cd->data.db_name);
		break;

	case CTDB_CONTROL_ENABLE_SEQNUM:
		break;

	case CTDB_CONTROL_UPDATE_SEQNUM:
		break;

	case CTDB_CONTROL_DUMP_MEMORY:
		fill_ctdb_string(mem_ctx, &cd->data.mem_str);
		assert(cd->data.mem_str);
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
		cd->data.tun_value = rand32();
		break;

	case CTDB_CONTROL_LIST_TUNABLES:
		cd->data.tun_var_list = talloc(mem_ctx, struct ctdb_var_list);
		assert(cd->data.tun_var_list != NULL);
		fill_ctdb_var_list(mem_ctx, cd->data.tun_var_list);
		break;

	case CTDB_CONTROL_MODIFY_FLAGS:
		break;

	case CTDB_CONTROL_GET_ALL_TUNABLES:
		cd->data.tun_list = talloc(mem_ctx, struct ctdb_tunable_list);
		assert(cd->data.tun_list != NULL);
		fill_ctdb_tunable_list(mem_ctx, cd->data.tun_list);
		break;

	case CTDB_CONTROL_GET_TCP_TICKLE_LIST:
		cd->data.tickles = talloc(mem_ctx, struct ctdb_tickle_list);
		assert(cd->data.tickles != NULL);
		fill_ctdb_tickle_list(mem_ctx, cd->data.tickles);
		break;

	case CTDB_CONTROL_SET_TCP_TICKLE_LIST:
		break;

	case CTDB_CONTROL_DB_ATTACH_PERSISTENT:
		break;

	case CTDB_CONTROL_UPDATE_RECORD:
		break;

	case CTDB_CONTROL_SEND_GRATUITOUS_ARP:
		break;

	case CTDB_CONTROL_WIPE_DATABASE:
		break;

	case CTDB_CONTROL_UPTIME:
		cd->data.uptime = talloc(mem_ctx, struct ctdb_uptime);
		assert(cd->data.uptime != NULL);
		fill_ctdb_uptime(mem_ctx, cd->data.uptime);
		break;

	case CTDB_CONTROL_START_RECOVERY:
		break;

	case CTDB_CONTROL_END_RECOVERY:
		break;

	case CTDB_CONTROL_RELOAD_NODES_FILE:
		break;

	case CTDB_CONTROL_TRY_DELETE_RECORDS:
		cd->data.recbuf = talloc(mem_ctx, struct ctdb_rec_buffer);
		assert(cd->data.recbuf != NULL);
		fill_ctdb_rec_buffer(mem_ctx, cd->data.recbuf);
		break;

	case CTDB_CONTROL_ENABLE_MONITOR:
		break;

	case CTDB_CONTROL_DISABLE_MONITOR:
		break;

	case CTDB_CONTROL_ADD_PUBLIC_IP:
		break;

	case CTDB_CONTROL_DEL_PUBLIC_IP:
		break;

	case CTDB_CONTROL_RUN_EVENTSCRIPTS:
		break;

	case CTDB_CONTROL_GET_CAPABILITIES:
		cd->data.caps = rand32();
		break;

	case CTDB_CONTROL_START_PERSISTENT_UPDATE:
		break;

	case CTDB_CONTROL_CANCEL_PERSISTENT_UPDATE:
		break;

	case CTDB_CONTROL_RECD_PING:
		break;

	case CTDB_CONTROL_RELEASE_IP:
		break;

	case CTDB_CONTROL_TAKEOVER_IP:
		break;

	case CTDB_CONTROL_GET_PUBLIC_IPS:
		cd->data.pubip_list = talloc(mem_ctx, struct ctdb_public_ip_list);
		assert(cd->data.pubip_list != NULL);
		fill_ctdb_public_ip_list(mem_ctx, cd->data.pubip_list);
		break;

	case CTDB_CONTROL_GET_NODEMAP:
		cd->data.nodemap = talloc(mem_ctx, struct ctdb_node_map);
		assert(cd->data.nodemap != NULL);
		fill_ctdb_node_map(mem_ctx, cd->data.nodemap);
		break;

	case CTDB_CONTROL_GET_EVENT_SCRIPT_STATUS:
		cd->data.script_list = talloc(mem_ctx, struct ctdb_script_list);
		assert(cd->data.script_list != NULL);
		fill_ctdb_script_list(mem_ctx, cd->data.script_list);
		break;

	case CTDB_CONTROL_TRAVERSE_KILL:
		break;

	case CTDB_CONTROL_RECD_RECLOCK_LATENCY:
		break;

	case CTDB_CONTROL_GET_RECLOCK_FILE:
		fill_ctdb_string(mem_ctx, &cd->data.reclock_file);
		assert(cd->data.reclock_file != NULL);
		break;

	case CTDB_CONTROL_STOP_NODE:
		break;

	case CTDB_CONTROL_CONTINUE_NODE:
		break;

	case CTDB_CONTROL_SET_LMASTERROLE:
		break;

	case CTDB_CONTROL_SET_RECMASTERROLE:
		break;

	case CTDB_CONTROL_ENABLE_SCRIPT:
		break;

	case CTDB_CONTROL_DISABLE_SCRIPT:
		break;

	case CTDB_CONTROL_SET_BAN_STATE:
		break;

	case CTDB_CONTROL_GET_BAN_STATE:
		cd->data.ban_state = talloc(mem_ctx, struct ctdb_ban_state);
		assert(cd->data.ban_state != NULL);
		fill_ctdb_ban_state(mem_ctx, cd->data.ban_state);
		break;

	case CTDB_CONTROL_REGISTER_NOTIFY:
		break;

	case CTDB_CONTROL_DEREGISTER_NOTIFY:
		break;

	case CTDB_CONTROL_TRANS3_COMMIT:
		break;

	case CTDB_CONTROL_GET_DB_SEQNUM:
		cd->data.seqnum = rand64();
		break;

	case CTDB_CONTROL_DB_SET_HEALTHY:
		break;

	case CTDB_CONTROL_DB_GET_HEALTH:
		fill_ctdb_string(mem_ctx, &cd->data.reason);
		assert(cd->data.reason != NULL);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IP_INFO:
		cd->data.ipinfo = talloc(mem_ctx, struct ctdb_public_ip_info);
		assert(cd->data.ipinfo != NULL);
		fill_ctdb_public_ip_info(mem_ctx, cd->data.ipinfo);
		break;

	case CTDB_CONTROL_GET_IFACES:
		cd->data.iface_list = talloc(mem_ctx, struct ctdb_iface_list);
		assert(cd->data.iface_list != NULL);
		fill_ctdb_iface_list(mem_ctx, cd->data.iface_list);
		break;

	case CTDB_CONTROL_SET_IFACE_LINK_STATE:
		break;

	case CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE:
		break;

	case CTDB_CONTROL_GET_STAT_HISTORY:
		cd->data.stats_list = talloc(mem_ctx, struct ctdb_statistics_list);
		assert(cd->data.stats_list != NULL);
		fill_ctdb_statistics_list(mem_ctx, cd->data.stats_list);
		break;

	case CTDB_CONTROL_SCHEDULE_FOR_DELETION:
		break;

	case CTDB_CONTROL_SET_DB_READONLY:
		break;

	case CTDB_CONTROL_CHECK_SRVIDS:
		cd->data.u8_array = talloc(mem_ctx, struct ctdb_uint8_array);
		assert(cd->data.u8_array != NULL);
		fill_ctdb_uint8_array(mem_ctx, cd->data.u8_array);
		break;

	case CTDB_CONTROL_TRAVERSE_START_EXT:
		break;

	case CTDB_CONTROL_GET_DB_STATISTICS:
		cd->data.dbstats = talloc(mem_ctx, struct ctdb_db_statistics);
		assert(cd->data.dbstats != NULL);
		fill_ctdb_db_statistics(mem_ctx, cd->data.dbstats);
		break;

	case CTDB_CONTROL_SET_DB_STICKY:
		break;

	case CTDB_CONTROL_RELOAD_PUBLIC_IPS:
		break;

	case CTDB_CONTROL_TRAVERSE_ALL_EXT:
		break;

	case CTDB_CONTROL_RECEIVE_RECORDS:
		cd->data.recbuf = talloc(mem_ctx, struct ctdb_rec_buffer);
		assert(cd->data.recbuf != NULL);
		fill_ctdb_rec_buffer(mem_ctx, cd->data.recbuf);
		break;

	case CTDB_CONTROL_IPREALLOCATED:
		break;

	case CTDB_CONTROL_GET_RUNSTATE:
		cd->data.runstate = rand32();
		break;

	case CTDB_CONTROL_DB_DETACH:
		break;

	case CTDB_CONTROL_GET_NODES_FILE:
		cd->data.nodemap = talloc(mem_ctx, struct ctdb_node_map);
		assert(cd->data.nodemap != NULL);
		fill_ctdb_node_map(mem_ctx, cd->data.nodemap);
		break;

	case CTDB_CONTROL_DB_PULL:
		cd->data.num_records = rand32();
		break;

	case CTDB_CONTROL_DB_PUSH_CONFIRM:
		cd->data.num_records = rand32();
		break;

	}
}

static void verify_ctdb_reply_control_data(struct ctdb_reply_control_data *cd,
					   struct ctdb_reply_control_data *cd2)
{
	assert(cd->opcode == cd2->opcode);

	switch (cd->opcode) {
	case CTDB_CONTROL_PROCESS_EXISTS:
		break;

	case CTDB_CONTROL_STATISTICS:
		verify_ctdb_statistics(cd->data.stats, cd2->data.stats);
		break;

	case CTDB_CONTROL_PING:
		break;

	case CTDB_CONTROL_GETDBPATH:
		verify_ctdb_string(cd->data.db_path, cd2->data.db_path);
		break;

	case CTDB_CONTROL_GETVNNMAP:
		verify_ctdb_vnn_map(cd->data.vnnmap, cd2->data.vnnmap);
		break;

	case CTDB_CONTROL_SETVNNMAP:
		break;

	case CTDB_CONTROL_GET_DEBUG:
		assert(cd->data.loglevel == cd2->data.loglevel);
		break;

	case CTDB_CONTROL_SET_DEBUG:
		break;

	case CTDB_CONTROL_GET_DBMAP:
		verify_ctdb_dbid_map(cd->data.dbmap, cd2->data.dbmap);
		break;

	case CTDB_CONTROL_PULL_DB:
		verify_ctdb_rec_buffer(cd->data.recbuf, cd2->data.recbuf);
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
		assert(cd->data.db_id == cd2->data.db_id);
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
		verify_ctdb_string(cd->data.db_name, cd2->data.db_name);
		break;

	case CTDB_CONTROL_ENABLE_SEQNUM:
		break;

	case CTDB_CONTROL_UPDATE_SEQNUM:
		break;

	case CTDB_CONTROL_DUMP_MEMORY:
		verify_ctdb_string(cd->data.mem_str, cd2->data.mem_str);
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
		assert(cd->data.tun_value == cd2->data.tun_value);
		break;

	case CTDB_CONTROL_LIST_TUNABLES:
		verify_ctdb_var_list(cd->data.tun_var_list,
				     cd2->data.tun_var_list);
		break;

	case CTDB_CONTROL_MODIFY_FLAGS:
		break;

	case CTDB_CONTROL_GET_ALL_TUNABLES:
		verify_ctdb_tunable_list(cd->data.tun_list, cd2->data.tun_list);
		break;

	case CTDB_CONTROL_GET_TCP_TICKLE_LIST:
		verify_ctdb_tickle_list(cd->data.tickles, cd2->data.tickles);
		break;

	case CTDB_CONTROL_SET_TCP_TICKLE_LIST:
		break;

	case CTDB_CONTROL_DB_ATTACH_PERSISTENT:
		break;

	case CTDB_CONTROL_UPDATE_RECORD:
		break;

	case CTDB_CONTROL_SEND_GRATUITOUS_ARP:
		break;

	case CTDB_CONTROL_WIPE_DATABASE:
		break;

	case CTDB_CONTROL_UPTIME:
		verify_ctdb_uptime(cd->data.uptime, cd2->data.uptime);
		break;

	case CTDB_CONTROL_START_RECOVERY:
		break;

	case CTDB_CONTROL_END_RECOVERY:
		break;

	case CTDB_CONTROL_RELOAD_NODES_FILE:
		break;

	case CTDB_CONTROL_TRY_DELETE_RECORDS:
		verify_ctdb_rec_buffer(cd->data.recbuf, cd2->data.recbuf);
		break;

	case CTDB_CONTROL_ENABLE_MONITOR:
		break;

	case CTDB_CONTROL_DISABLE_MONITOR:
		break;

	case CTDB_CONTROL_ADD_PUBLIC_IP:
		break;

	case CTDB_CONTROL_DEL_PUBLIC_IP:
		break;

	case CTDB_CONTROL_RUN_EVENTSCRIPTS:
		break;

	case CTDB_CONTROL_GET_CAPABILITIES:
		assert(cd->data.caps == cd2->data.caps);
		break;

	case CTDB_CONTROL_RECD_PING:
		break;

	case CTDB_CONTROL_RELEASE_IP:
		break;

	case CTDB_CONTROL_TAKEOVER_IP:
		break;

	case CTDB_CONTROL_GET_PUBLIC_IPS:
		verify_ctdb_public_ip_list(cd->data.pubip_list,
					   cd2->data.pubip_list);
		break;

	case CTDB_CONTROL_GET_NODEMAP:
		verify_ctdb_node_map(cd->data.nodemap, cd2->data.nodemap);
		break;

	case CTDB_CONTROL_GET_EVENT_SCRIPT_STATUS:
		verify_ctdb_script_list(cd->data.script_list,
					cd2->data.script_list);
		break;

	case CTDB_CONTROL_TRAVERSE_KILL:
		break;

	case CTDB_CONTROL_RECD_RECLOCK_LATENCY:
		break;

	case CTDB_CONTROL_GET_RECLOCK_FILE:
		verify_ctdb_string(cd->data.reclock_file,
				   cd2->data.reclock_file);
		break;

	case CTDB_CONTROL_STOP_NODE:
		break;

	case CTDB_CONTROL_CONTINUE_NODE:
		break;

	case CTDB_CONTROL_SET_LMASTERROLE:
		break;

	case CTDB_CONTROL_SET_RECMASTERROLE:
		break;

	case CTDB_CONTROL_ENABLE_SCRIPT:
		break;

	case CTDB_CONTROL_DISABLE_SCRIPT:
		break;

	case CTDB_CONTROL_SET_BAN_STATE:
		break;

	case CTDB_CONTROL_GET_BAN_STATE:
		verify_ctdb_ban_state(cd->data.ban_state, cd2->data.ban_state);
		break;

	case CTDB_CONTROL_REGISTER_NOTIFY:
		break;

	case CTDB_CONTROL_DEREGISTER_NOTIFY:
		break;

	case CTDB_CONTROL_TRANS3_COMMIT:
		break;

	case CTDB_CONTROL_GET_DB_SEQNUM:
		assert(cd->data.seqnum == cd2->data.seqnum);
		break;

	case CTDB_CONTROL_DB_SET_HEALTHY:
		break;

	case CTDB_CONTROL_DB_GET_HEALTH:
		verify_ctdb_string(cd->data.reason, cd2->data.reason);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IP_INFO:
		verify_ctdb_public_ip_info(cd->data.ipinfo, cd2->data.ipinfo);
		break;

	case CTDB_CONTROL_GET_IFACES:
		verify_ctdb_iface_list(cd->data.iface_list,
				       cd2->data.iface_list);
		break;

	case CTDB_CONTROL_SET_IFACE_LINK_STATE:
		break;

	case CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE:
		break;

	case CTDB_CONTROL_GET_STAT_HISTORY:
		verify_ctdb_statistics_list(cd->data.stats_list,
					    cd2->data.stats_list);
		break;

	case CTDB_CONTROL_SCHEDULE_FOR_DELETION:
		break;

	case CTDB_CONTROL_SET_DB_READONLY:
		break;

	case CTDB_CONTROL_CHECK_SRVIDS:
		verify_ctdb_uint8_array(cd->data.u8_array, cd2->data.u8_array);
		break;

	case CTDB_CONTROL_TRAVERSE_START_EXT:
		break;

	case CTDB_CONTROL_GET_DB_STATISTICS:
		verify_ctdb_db_statistics(cd->data.dbstats, cd2->data.dbstats);
		break;

	case CTDB_CONTROL_SET_DB_STICKY:
		break;

	case CTDB_CONTROL_RELOAD_PUBLIC_IPS:
		break;

	case CTDB_CONTROL_TRAVERSE_ALL_EXT:
		break;

	case CTDB_CONTROL_RECEIVE_RECORDS:
		verify_ctdb_rec_buffer(cd->data.recbuf, cd2->data.recbuf);
		break;

	case CTDB_CONTROL_IPREALLOCATED:
		break;

	case CTDB_CONTROL_GET_RUNSTATE:
		assert(cd->data.runstate == cd2->data.runstate);
		break;

	case CTDB_CONTROL_DB_DETACH:
		break;

	case CTDB_CONTROL_GET_NODES_FILE:
		verify_ctdb_node_map(cd->data.nodemap, cd2->data.nodemap);
		break;

	case CTDB_CONTROL_DB_PULL:
		assert(cd->data.num_records == cd2->data.num_records);
		break;

	case CTDB_CONTROL_DB_PUSH_CONFIRM:
		assert(cd->data.num_records == cd2->data.num_records);
		break;

	}
}

static void fill_ctdb_reply_control(TALLOC_CTX *mem_ctx,
				    struct ctdb_reply_control *c,
				    uint32_t opcode)
{
	c->status = -rand_int(2);
	if (c->status == 0) {
		c->errmsg = NULL;
		fill_ctdb_reply_control_data(mem_ctx, &c->rdata, opcode);
	} else {
		fill_ctdb_string(mem_ctx, &c->errmsg);
	}
}

static void verify_ctdb_reply_control(struct ctdb_reply_control *c,
				      struct ctdb_reply_control *c2)
{
	assert(c->status == c2->status);
	verify_ctdb_string(c->errmsg, c2->errmsg);
	if (c->status == 0) {
		verify_ctdb_reply_control_data(&c->rdata, &c2->rdata);
	}
}

static void fill_ctdb_req_message_data(TALLOC_CTX *mem_ctx,
				       struct ctdb_req_message_data *c)
{
	c->srvid = rand64();
	fill_tdb_data(mem_ctx, &c->data);
}

static void verify_ctdb_req_message_data(struct ctdb_req_message_data *c,
					 struct ctdb_req_message_data *c2)
{
	assert(c->srvid == c2->srvid);
	verify_tdb_data(&c->data, &c2->data);
}

/*
 * Functions to test marshalling
 */

static void test_ctdb_req_header(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t pkt_len;
	struct ctdb_req_header h, h2;
	int ret;

	printf("ctdb_req_header\n");
	fflush(stdout);

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ctdb_req_header_fill(&h, GENERATION, OPERATION, DESTNODE, SRCNODE,
			     REQID);

	ret = ctdb_allocate_pkt(mem_ctx, ctdb_req_header_len(&h),
				&pkt, &pkt_len);
	assert(ret == 0);
	assert(pkt != NULL);
	assert(pkt_len >= ctdb_req_header_len(&h));

	ctdb_req_header_push(&h, pkt);

	ret = ctdb_req_header_pull(pkt, pkt_len, &h2);
	assert(ret == 0);

	verify_ctdb_req_header(&h, &h2);

	talloc_free(mem_ctx);
}

static void test_req_call_test(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t datalen, pkt_len, len;
	int ret;
	struct ctdb_req_header h, h2;
	struct ctdb_req_call c, c2;

	printf("ctdb_req_call\n");
	fflush(stdout);

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ctdb_req_header_fill(&h, GENERATION, CTDB_REQ_CALL,
			     DESTNODE, SRCNODE, REQID);

	fill_ctdb_req_call(mem_ctx, &c);
	datalen = ctdb_req_call_len(&h, &c);
	ret = ctdb_allocate_pkt(mem_ctx, datalen, &pkt, &pkt_len);
	assert(ret == 0);
	assert(pkt != NULL);
	assert(pkt_len >= datalen);
	len = 0;
	ret = ctdb_req_call_push(&h, &c, pkt, &len);
	assert(ret == EMSGSIZE);
	assert(len == datalen);
	ret = ctdb_req_call_push(&h, &c, pkt, &pkt_len);
	assert(ret == 0);
	ret = ctdb_req_call_pull(pkt, pkt_len, &h2, mem_ctx, &c2);
	assert(ret == 0);
	verify_ctdb_req_header(&h, &h2);
	assert(h2.length == pkt_len);
	verify_ctdb_req_call(&c, &c2);

	talloc_free(mem_ctx);
}

static void test_reply_call_test(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t datalen, pkt_len, len;
	int ret;
	struct ctdb_req_header h, h2;
	struct ctdb_reply_call c, c2;

	printf("ctdb_reply_call\n");
	fflush(stdout);

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ctdb_req_header_fill(&h, GENERATION, CTDB_REPLY_CALL,
			     DESTNODE, SRCNODE, REQID);

	fill_ctdb_reply_call(mem_ctx, &c);
	datalen = ctdb_reply_call_len(&h, &c);
	ret = ctdb_allocate_pkt(mem_ctx, datalen, &pkt, &pkt_len);
	assert(ret == 0);
	assert(pkt != NULL);
	assert(pkt_len >= datalen);
	len = 0;
	ret = ctdb_reply_call_push(&h, &c, pkt, &len);
	assert(ret == EMSGSIZE);
	assert(len == datalen);
	ret = ctdb_reply_call_push(&h, &c, pkt, &pkt_len);
	assert(ret == 0);
	ret = ctdb_reply_call_pull(pkt, pkt_len, &h2, mem_ctx, &c2);
	assert(ret == 0);
	verify_ctdb_req_header(&h, &h2);
	assert(h2.length == pkt_len);
	verify_ctdb_reply_call(&c, &c2);

	talloc_free(mem_ctx);
}

static void test_reply_error_test(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t datalen, pkt_len, len;
	int ret;
	struct ctdb_req_header h, h2;
	struct ctdb_reply_error c, c2;

	printf("ctdb_reply_error\n");
	fflush(stdout);

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ctdb_req_header_fill(&h, GENERATION, CTDB_REPLY_ERROR,
			     DESTNODE, SRCNODE, REQID);

	fill_ctdb_reply_error(mem_ctx, &c);
	datalen = ctdb_reply_error_len(&h, &c);
	ret = ctdb_allocate_pkt(mem_ctx, datalen, &pkt, &pkt_len);
	assert(ret == 0);
	assert(pkt != NULL);
	assert(pkt_len >= datalen);
	len = 0;
	ret = ctdb_reply_error_push(&h, &c, pkt, &len);
	assert(ret == EMSGSIZE);
	assert(len == datalen);
	ret = ctdb_reply_error_push(&h, &c, pkt, &pkt_len);
	assert(ret == 0);
	ret = ctdb_reply_error_pull(pkt, pkt_len, &h2, mem_ctx, &c2);
	assert(ret == 0);
	verify_ctdb_req_header(&h, &h2);
	assert(h2.length == pkt_len);
	verify_ctdb_reply_error(&c, &c2);

	talloc_free(mem_ctx);
}

static void test_req_dmaster_test(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t datalen, pkt_len, len;
	int ret;
	struct ctdb_req_header h, h2;
	struct ctdb_req_dmaster c, c2;

	printf("ctdb_req_dmaster\n");
	fflush(stdout);

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ctdb_req_header_fill(&h, GENERATION, CTDB_REQ_DMASTER,
			     DESTNODE, SRCNODE, REQID);

	fill_ctdb_req_dmaster(mem_ctx, &c);
	datalen = ctdb_req_dmaster_len(&h, &c);
	ret = ctdb_allocate_pkt(mem_ctx, datalen, &pkt, &pkt_len);
	assert(ret == 0);
	assert(pkt != NULL);
	assert(pkt_len >= datalen);
	len = 0;
	ret = ctdb_req_dmaster_push(&h, &c, pkt, &len);
	assert(ret == EMSGSIZE);
	assert(len == datalen);
	ret = ctdb_req_dmaster_push(&h, &c, pkt, &pkt_len);
	assert(ret == 0);
	ret = ctdb_req_dmaster_pull(pkt, pkt_len, &h2, mem_ctx, &c2);
	assert(ret == 0);
	verify_ctdb_req_header(&h, &h2);
	assert(h2.length == pkt_len);
	verify_ctdb_req_dmaster(&c, &c2);

	talloc_free(mem_ctx);
}

static void test_reply_dmaster_test(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t datalen, pkt_len, len;
	int ret;
	struct ctdb_req_header h, h2;
	struct ctdb_reply_dmaster c, c2;

	printf("ctdb_reply_dmaster\n");
	fflush(stdout);

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ctdb_req_header_fill(&h, GENERATION, CTDB_REPLY_DMASTER,
			     DESTNODE, SRCNODE, REQID);

	fill_ctdb_reply_dmaster(mem_ctx, &c);
	datalen = ctdb_reply_dmaster_len(&h, &c);
	ret = ctdb_allocate_pkt(mem_ctx, datalen, &pkt, &pkt_len);
	assert(ret == 0);
	assert(pkt != NULL);
	assert(pkt_len >= datalen);
	len = 0;
	ret = ctdb_reply_dmaster_push(&h, &c, pkt, &len);
	assert(ret == EMSGSIZE);
	assert(len == datalen);
	ret = ctdb_reply_dmaster_push(&h, &c, pkt, &pkt_len);
	assert(ret == 0);
	ret = ctdb_reply_dmaster_pull(pkt, pkt_len, &h2, mem_ctx, &c2);
	assert(ret == 0);
	verify_ctdb_req_header(&h, &h2);
	assert(h2.length == pkt_len);
	verify_ctdb_reply_dmaster(&c, &c2);

	talloc_free(mem_ctx);
}

#define NUM_CONTROLS	149

static void test_req_control_data_test(void)
{
	TALLOC_CTX *mem_ctx;
	size_t buflen;
	int ret;
	struct ctdb_req_control_data cd, cd2;
	uint32_t opcode;

	printf("ctdb_req_control_data\n");
	fflush(stdout);

	for (opcode=0; opcode<NUM_CONTROLS; opcode++) {
		mem_ctx = talloc_new(NULL);
		assert(mem_ctx != NULL);

		printf("%u.. ", opcode);
		fflush(stdout);
		fill_ctdb_req_control_data(mem_ctx, &cd, opcode);
		buflen = ctdb_req_control_data_len(&cd);
		ctdb_req_control_data_push(&cd, BUFFER);
		ret = ctdb_req_control_data_pull(BUFFER, buflen, opcode, mem_ctx, &cd2);
		assert(ret == 0);
		verify_ctdb_req_control_data(&cd, &cd2);
		talloc_free(mem_ctx);
	}

	printf("\n");
	fflush(stdout);
}

static void test_reply_control_data_test(void)
{
	TALLOC_CTX *mem_ctx;
	size_t buflen;
	int ret;
	struct ctdb_reply_control_data cd, cd2;
	uint32_t opcode;

	printf("ctdb_reply_control_data\n");
	fflush(stdout);

	for (opcode=0; opcode<NUM_CONTROLS; opcode++) {
		mem_ctx = talloc_new(NULL);
		assert(mem_ctx != NULL);

		printf("%u.. ", opcode);
		fflush(stdout);
		fill_ctdb_reply_control_data(mem_ctx, &cd, opcode);
		buflen = ctdb_reply_control_data_len(&cd);
		ctdb_reply_control_data_push(&cd, BUFFER);
		ret = ctdb_reply_control_data_pull(BUFFER, buflen, opcode, mem_ctx, &cd2);
		assert(ret == 0);
		verify_ctdb_reply_control_data(&cd, &cd2);
		talloc_free(mem_ctx);
	}

	printf("\n");
	fflush(stdout);
}

static void test_req_control_test(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t datalen, pkt_len, len;
	int ret;
	struct ctdb_req_header h, h2;
	struct ctdb_req_control c, c2;
	uint32_t opcode;

	printf("ctdb_req_control\n");
	fflush(stdout);

	ctdb_req_header_fill(&h, GENERATION, CTDB_REQ_CONTROL,
			     DESTNODE, SRCNODE, REQID);

	for (opcode=0; opcode<NUM_CONTROLS; opcode++) {
		mem_ctx = talloc_new(NULL);
		assert(mem_ctx != NULL);

		printf("%u.. ", opcode);
		fflush(stdout);
		fill_ctdb_req_control(mem_ctx, &c, opcode);
		datalen = ctdb_req_control_len(&h, &c);
		ret = ctdb_allocate_pkt(mem_ctx, datalen, &pkt, &pkt_len);
		assert(ret == 0);
		assert(pkt != NULL);
		assert(pkt_len >= datalen);
		len = 0;
		ret = ctdb_req_control_push(&h, &c, pkt, &len);
		assert(ret == EMSGSIZE);
		assert(len == datalen);
		ret = ctdb_req_control_push(&h, &c, pkt, &pkt_len);
		assert(ret == 0);
		ret = ctdb_req_control_pull(pkt, pkt_len, &h2, mem_ctx, &c2);
		assert(ret == 0);
		verify_ctdb_req_header(&h, &h2);
		assert(h2.length == pkt_len);
		verify_ctdb_req_control(&c, &c2);

		talloc_free(mem_ctx);
	}

	printf("\n");
	fflush(stdout);
}

static void test_reply_control_test(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t datalen, pkt_len, len;
	int ret;
	struct ctdb_req_header h, h2;
	struct ctdb_reply_control c, c2;
	uint32_t opcode;

	printf("ctdb_reply_control\n");
	fflush(stdout);

	ctdb_req_header_fill(&h, GENERATION, CTDB_REPLY_CONTROL,
			     DESTNODE, SRCNODE, REQID);

	for (opcode=0; opcode<NUM_CONTROLS; opcode++) {
		mem_ctx = talloc_new(NULL);
		assert(mem_ctx != NULL);

		printf("%u.. ", opcode);
		fflush(stdout);
		fill_ctdb_reply_control(mem_ctx, &c, opcode);
		datalen = ctdb_reply_control_len(&h, &c);
		ret = ctdb_allocate_pkt(mem_ctx, datalen, &pkt, &pkt_len);
		assert(ret == 0);
		assert(pkt != NULL);
		assert(pkt_len >= datalen);
		len = 0;
		ret = ctdb_reply_control_push(&h, &c, pkt, &len);
		assert(ret == EMSGSIZE);
		assert(len == datalen);
		ret = ctdb_reply_control_push(&h, &c, pkt, &pkt_len);
		assert(ret == 0);
		ret = ctdb_reply_control_pull(pkt, pkt_len, opcode, &h2, mem_ctx, &c2);
		assert(ret == 0);
		verify_ctdb_req_header(&h, &h2);
		assert(h2.length == pkt_len);
		verify_ctdb_reply_control(&c, &c2);

		talloc_free(mem_ctx);
	}

	printf("\n");
	fflush(stdout);
}

static void test_req_message_test(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t datalen, pkt_len, len;
	int ret;
	struct ctdb_req_header h, h2;
	struct ctdb_req_message_data c, c2;

	printf("ctdb_req_message\n");
	fflush(stdout);

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ctdb_req_header_fill(&h, GENERATION, CTDB_REQ_MESSAGE,
			     DESTNODE, SRCNODE, REQID);

	fill_ctdb_req_message_data(mem_ctx, &c);
	datalen = ctdb_req_message_data_len(&h, &c);
	ret = ctdb_allocate_pkt(mem_ctx, datalen, &pkt, &pkt_len);
	assert(ret == 0);
	assert(pkt != NULL);
	assert(pkt_len >= datalen);
	len = 0;
	ret = ctdb_req_message_data_push(&h, &c, pkt, &len);
	assert(ret == EMSGSIZE);
	assert(len == datalen);
	ret = ctdb_req_message_data_push(&h, &c, pkt, &pkt_len);
	assert(ret == 0);
	ret = ctdb_req_message_data_pull(pkt, pkt_len, &h2, mem_ctx, &c2);
	assert(ret == 0);
	verify_ctdb_req_header(&h, &h2);
	assert(h2.length == pkt_len);
	verify_ctdb_req_message_data(&c, &c2);

	talloc_free(mem_ctx);
}

int main(int argc, char *argv[])
{
	if (argc == 2) {
		int seed = atoi(argv[1]);
		srandom(seed);
	}

	test_ctdb_req_header();

	test_req_call_test();
	test_reply_call_test();
	test_reply_error_test();
	test_req_dmaster_test();
	test_reply_dmaster_test();

	test_req_control_data_test();
	test_reply_control_data_test();

	test_req_control_test();
	test_reply_control_test();

	test_req_message_test();

	return 0;
}
