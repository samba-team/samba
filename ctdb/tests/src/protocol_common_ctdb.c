/*
   protocol tests - ctdb protocol

   Copyright (C) Amitay Isaacs  2017

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

#include "tests/src/protocol_common.h"
#include "tests/src/protocol_common_ctdb.h"

/*
 * Functions to fill and verify protocol structures
 */

void fill_ctdb_req_header(struct ctdb_req_header *h)
{
	h->length = rand32();
	h->ctdb_magic = rand32();
	h->ctdb_version = rand32();
	h->generation = rand32();
	h->operation = rand32();
	h->destnode = rand32();
	h->srcnode = rand32();
	h->reqid = rand32();
}

void verify_ctdb_req_header(struct ctdb_req_header *h,
			    struct ctdb_req_header *h2)
{
	assert(h->length == h2->length);
	assert(h->ctdb_magic == h2->ctdb_magic);
	assert(h->ctdb_version == h2->ctdb_version);
	assert(h->generation == h2->generation);
	assert(h->operation == h2->operation);
	assert(h->destnode == h2->destnode);
	assert(h->srcnode == h2->srcnode);
	assert(h->reqid == h2->reqid);
}

void fill_ctdb_req_call(TALLOC_CTX *mem_ctx, struct ctdb_req_call *c)
{
	c->flags = rand32();
	c->db_id = rand32();
	c->callid = rand32();
	c->hopcount = rand32();
	fill_tdb_data_nonnull(mem_ctx, &c->key);
	fill_tdb_data(mem_ctx, &c->calldata);
}

void verify_ctdb_req_call(struct ctdb_req_call *c, struct ctdb_req_call *c2)
{
	assert(c->flags == c2->flags);
	assert(c->db_id == c2->db_id);
	assert(c->callid == c2->callid);
	assert(c->hopcount == c2->hopcount);
	verify_tdb_data(&c->key, &c2->key);
	verify_tdb_data(&c->calldata, &c2->calldata);
}

void fill_ctdb_reply_call(TALLOC_CTX *mem_ctx, struct ctdb_reply_call *c)
{
	c->status = rand32();
	fill_tdb_data(mem_ctx, &c->data);
}

void verify_ctdb_reply_call(struct ctdb_reply_call *c,
			    struct ctdb_reply_call *c2)
{
	assert(c->status == c2->status);
	verify_tdb_data(&c->data, &c2->data);
}

void fill_ctdb_reply_error(TALLOC_CTX *mem_ctx, struct ctdb_reply_error *c)
{
	c->status = rand32();
	fill_tdb_data(mem_ctx, &c->msg);
}

void verify_ctdb_reply_error(struct ctdb_reply_error *c,
			     struct ctdb_reply_error *c2)
{
	assert(c->status == c2->status);
	verify_tdb_data(&c->msg, &c2->msg);
}

void fill_ctdb_req_dmaster(TALLOC_CTX *mem_ctx, struct ctdb_req_dmaster *c)
{
	c->db_id = rand32();
	c->rsn = rand64();
	c->dmaster = rand32();
	fill_tdb_data_nonnull(mem_ctx, &c->key);
	fill_tdb_data(mem_ctx, &c->data);
}

void verify_ctdb_req_dmaster(struct ctdb_req_dmaster *c,
			     struct ctdb_req_dmaster *c2)
{
	assert(c->db_id == c2->db_id);
	assert(c->rsn == c2->rsn);
	assert(c->dmaster == c2->dmaster);
	verify_tdb_data(&c->key, &c2->key);
	verify_tdb_data(&c->data, &c2->data);
}

void fill_ctdb_reply_dmaster(TALLOC_CTX *mem_ctx,
			     struct ctdb_reply_dmaster *c)
{
	c->db_id = rand32();
	c->rsn = rand64();
	fill_tdb_data_nonnull(mem_ctx, &c->key);
	fill_tdb_data(mem_ctx, &c->data);
}

void verify_ctdb_reply_dmaster(struct ctdb_reply_dmaster *c,
			       struct ctdb_reply_dmaster *c2)
{
	assert(c->db_id == c2->db_id);
	assert(c->rsn == c2->rsn);
	verify_tdb_data(&c->key, &c2->key);
	verify_tdb_data(&c->data, &c2->data);
}

void fill_ctdb_req_control_data(TALLOC_CTX *mem_ctx,
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

	case CTDB_CONTROL_GET_CAPABILITIES:
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

	case CTDB_CONTROL_DB_OPEN_FLAGS:
		cd->data.db_id = rand32();
		break;

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
		fill_ctdb_string(mem_ctx, &cd->data.db_name);
		assert(cd->data.db_name != NULL);
		break;

	case CTDB_CONTROL_CHECK_PID_SRVID:
		cd->data.pid_srvid = talloc(mem_ctx, struct ctdb_pid_srvid);
		assert(cd->data.pid_srvid != NULL);
		fill_ctdb_pid_srvid(mem_ctx, cd->data.pid_srvid);
		break;

	case CTDB_CONTROL_TUNNEL_REGISTER:
		break;

	case CTDB_CONTROL_TUNNEL_DEREGISTER:
		break;

	case CTDB_CONTROL_VACUUM_FETCH:
		cd->data.recbuf = talloc(mem_ctx, struct ctdb_rec_buffer);
		assert(cd->data.recbuf != NULL);
		fill_ctdb_rec_buffer(mem_ctx, cd->data.recbuf);
		break;

	case CTDB_CONTROL_DB_VACUUM:
		cd->data.db_vacuum = talloc(mem_ctx, struct ctdb_db_vacuum);
		assert(cd->data.db_vacuum != NULL);
		fill_ctdb_db_vacuum(mem_ctx, cd->data.db_vacuum);
		break;

	case CTDB_CONTROL_ECHO_DATA:
		cd->data.echo_data = talloc(mem_ctx, struct ctdb_echo_data);
		assert(cd->data.echo_data != NULL);
		fill_ctdb_echo_data(mem_ctx, cd->data.echo_data);
		break;

	case CTDB_CONTROL_DISABLE_NODE:
		break;

	case CTDB_CONTROL_ENABLE_NODE:
		break;
	}
}

void verify_ctdb_req_control_data(struct ctdb_req_control_data *cd,
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
		verify_ctdb_string(&cd->data.db_name, &cd2->data.db_name);
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
		verify_ctdb_string(&cd->data.tun_var, &cd2->data.tun_var);
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
		verify_ctdb_string(&cd->data.db_name, &cd2->data.db_name);
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

	case CTDB_CONTROL_ADD_PUBLIC_IP:
		verify_ctdb_addr_info(cd->data.addr_info, cd2->data.addr_info);
		break;

	case CTDB_CONTROL_DEL_PUBLIC_IP:
		verify_ctdb_addr_info(cd->data.addr_info, cd2->data.addr_info);
		break;

	case CTDB_CONTROL_GET_CAPABILITIES:
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

	case CTDB_CONTROL_DB_OPEN_FLAGS:
		assert(cd->data.db_id == cd2->data.db_id);
		break;

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
		verify_ctdb_string(&cd->data.db_name, &cd2->data.db_name);
		break;

	case CTDB_CONTROL_CHECK_PID_SRVID:
		verify_ctdb_pid_srvid(cd->data.pid_srvid, cd2->data.pid_srvid);
		break;

	case CTDB_CONTROL_TUNNEL_REGISTER:
		break;

	case CTDB_CONTROL_TUNNEL_DEREGISTER:
		break;

	case CTDB_CONTROL_VACUUM_FETCH:
		verify_ctdb_rec_buffer(cd->data.recbuf, cd2->data.recbuf);
		break;

	case CTDB_CONTROL_DB_VACUUM:
		verify_ctdb_db_vacuum(cd->data.db_vacuum, cd2->data.db_vacuum);
		break;

	case CTDB_CONTROL_ECHO_DATA:
		verify_ctdb_echo_data(cd->data.echo_data, cd2->data.echo_data);
		break;

	case CTDB_CONTROL_DISABLE_NODE:
		break;

	case CTDB_CONTROL_ENABLE_NODE:
		break;
	}
}

void fill_ctdb_req_control(TALLOC_CTX *mem_ctx, struct ctdb_req_control *c,
			   uint32_t opcode)
{
	c->opcode = opcode;
	c->pad = rand32();
	c->srvid = rand64();
	c->client_id = rand32();
	c->flags = rand32();

	fill_ctdb_req_control_data(mem_ctx, &c->rdata, opcode);
}

void verify_ctdb_req_control(struct ctdb_req_control *c,
			     struct ctdb_req_control *c2)
{
	assert(c->opcode == c2->opcode);
	assert(c->pad == c2->pad);
	assert(c->srvid == c2->srvid);
	assert(c->client_id == c2->client_id);
	assert(c->flags == c2->flags);

	verify_ctdb_req_control_data(&c->rdata, &c2->rdata);
}

void fill_ctdb_reply_control_data(TALLOC_CTX *mem_ctx,
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
		cd->data.db_id = rand32();
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

	case CTDB_CONTROL_ADD_PUBLIC_IP:
		break;

	case CTDB_CONTROL_DEL_PUBLIC_IP:
		break;

	case CTDB_CONTROL_GET_CAPABILITIES:
		cd->data.caps = rand32();
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

	case CTDB_CONTROL_DB_OPEN_FLAGS:
		cd->data.tdb_flags = rand32();
		break;

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
		cd->data.db_id = rand32();
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
		cd->data.echo_data = talloc(mem_ctx, struct ctdb_echo_data);
		assert(cd->data.echo_data != NULL);
		fill_ctdb_echo_data(mem_ctx, cd->data.echo_data);
		break;

	case CTDB_CONTROL_DISABLE_NODE:
		break;

	case CTDB_CONTROL_ENABLE_NODE:
		break;
	}
}

void verify_ctdb_reply_control_data(struct ctdb_reply_control_data *cd,
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
		verify_ctdb_string(&cd->data.db_path, &cd2->data.db_path);
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
		verify_ctdb_string(&cd->data.db_name, &cd2->data.db_name);
		break;

	case CTDB_CONTROL_ENABLE_SEQNUM:
		break;

	case CTDB_CONTROL_UPDATE_SEQNUM:
		break;

	case CTDB_CONTROL_DUMP_MEMORY:
		verify_ctdb_string(&cd->data.mem_str, &cd2->data.mem_str);
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
		assert(cd->data.db_id == cd2->data.db_id);
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

	case CTDB_CONTROL_ADD_PUBLIC_IP:
		break;

	case CTDB_CONTROL_DEL_PUBLIC_IP:
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

	case CTDB_CONTROL_TRAVERSE_KILL:
		break;

	case CTDB_CONTROL_RECD_RECLOCK_LATENCY:
		break;

	case CTDB_CONTROL_GET_RECLOCK_FILE:
		verify_ctdb_string(&cd->data.reclock_file,
				   &cd2->data.reclock_file);
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
		verify_ctdb_string(&cd->data.reason, &cd2->data.reason);
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

	case CTDB_CONTROL_DB_OPEN_FLAGS:
		assert(cd->data.tdb_flags == cd2->data.tdb_flags);
		break;

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
		assert(cd->data.db_id == cd2->data.db_id);
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
		verify_ctdb_echo_data(cd->data.echo_data, cd2->data.echo_data);
		break;

	case CTDB_CONTROL_DISABLE_NODE:
		break;

	case CTDB_CONTROL_ENABLE_NODE:
		break;
	}
}

void fill_ctdb_reply_control(TALLOC_CTX *mem_ctx,
			     struct ctdb_reply_control *c, uint32_t opcode)
{
	c->status = -rand_int(2);
	if (c->status == 0) {
		c->errmsg = NULL;
		fill_ctdb_reply_control_data(mem_ctx, &c->rdata, opcode);
	} else {
		fill_ctdb_string(mem_ctx, &c->errmsg);
	}
}

void verify_ctdb_reply_control(struct ctdb_reply_control *c,
			       struct ctdb_reply_control *c2)
{
	assert(c->status == c2->status);
	verify_ctdb_string(&c->errmsg, &c2->errmsg);
	if (c->status == 0) {
		verify_ctdb_reply_control_data(&c->rdata, &c2->rdata);
	}
}

void fill_ctdb_message_data(TALLOC_CTX *mem_ctx, union ctdb_message_data *md,
			    uint64_t srvid)
{
	switch (srvid) {
	case CTDB_SRVID_RECONFIGURE:
	case CTDB_SRVID_GETLOG:
	case CTDB_SRVID_CLEARLOG:
	case CTDB_SRVID_RELOAD_NODES:
		break;

	case CTDB_SRVID_ELECTION:
		md->election = talloc(mem_ctx, struct ctdb_election_message);
		assert(md->election != NULL);
		fill_ctdb_election_message(md->election, md->election);
		break;

	case CTDB_SRVID_RELEASE_IP:
	case CTDB_SRVID_TAKE_IP:
		fill_ctdb_string(mem_ctx, &md->ipaddr);
		break;

	case CTDB_SRVID_SET_NODE_FLAGS:
	case CTDB_SRVID_PUSH_NODE_FLAGS:
		md->flag_change = talloc(mem_ctx,
					 struct ctdb_node_flag_change);
		assert(md->flag_change != NULL);
		fill_ctdb_node_flag_change(md->flag_change, md->flag_change);
		break;

	case CTDB_SRVID_RECD_UPDATE_IP:
		md->pubip = talloc(mem_ctx, struct ctdb_public_ip);
		assert(md->pubip != NULL);
		fill_ctdb_public_ip(md->pubip, md->pubip);
		break;

	case CTDB_SRVID_VACUUM_FETCH:
		md->recbuf = talloc(mem_ctx, struct ctdb_rec_buffer);
		assert(md->recbuf != NULL);
		fill_ctdb_rec_buffer(md->recbuf, md->recbuf);
		break;

	case CTDB_SRVID_DETACH_DATABASE:
		md->db_id = rand32();
		break;

	case CTDB_SRVID_MEM_DUMP:
	case CTDB_SRVID_TAKEOVER_RUN:
		md->msg = talloc(mem_ctx, struct ctdb_srvid_message);
		assert(md->msg != NULL);
		fill_ctdb_srvid_message(md->msg, md->msg);
		break;

	case CTDB_SRVID_BANNING:
	case CTDB_SRVID_REBALANCE_NODE:
		md->pnn = rand32();
		break;

	case CTDB_SRVID_DISABLE_TAKEOVER_RUNS:
	case CTDB_SRVID_DISABLE_RECOVERIES:
		md->disable = talloc(mem_ctx, struct ctdb_disable_message);
		assert(md->disable != NULL);
		fill_ctdb_disable_message(md->disable, md->disable);
		break;

	case CTDB_SRVID_DISABLE_IP_CHECK:
		md->timeout = rand32();
		break;

	default:
		abort();
	}
}

void verify_ctdb_message_data(union ctdb_message_data *md,
			      union ctdb_message_data *md2, uint64_t srvid)
{
	switch (srvid) {
	case CTDB_SRVID_RECONFIGURE:
	case CTDB_SRVID_GETLOG:
	case CTDB_SRVID_CLEARLOG:
	case CTDB_SRVID_RELOAD_NODES:
		break;

	case CTDB_SRVID_ELECTION:
		verify_ctdb_election_message(md->election, md2->election);
		break;

	case CTDB_SRVID_RELEASE_IP:
	case CTDB_SRVID_TAKE_IP:
		verify_ctdb_string(&md->ipaddr, &md2->ipaddr);
		break;

	case CTDB_SRVID_SET_NODE_FLAGS:
	case CTDB_SRVID_PUSH_NODE_FLAGS:
		verify_ctdb_node_flag_change(md->flag_change,
					     md2->flag_change);
		break;

	case CTDB_SRVID_RECD_UPDATE_IP:
		verify_ctdb_public_ip(md->pubip, md2->pubip);
		break;

	case CTDB_SRVID_VACUUM_FETCH:
		verify_ctdb_rec_buffer(md->recbuf, md2->recbuf);
		break;

	case CTDB_SRVID_DETACH_DATABASE:
		assert(md->db_id == md2->db_id);
		break;

	case CTDB_SRVID_MEM_DUMP:
	case CTDB_SRVID_TAKEOVER_RUN:
		verify_ctdb_srvid_message(md->msg, md2->msg);
		break;

	case CTDB_SRVID_BANNING:
	case CTDB_SRVID_REBALANCE_NODE:
		assert(md->pnn == md2->pnn);
		break;

	case CTDB_SRVID_DISABLE_TAKEOVER_RUNS:
	case CTDB_SRVID_DISABLE_RECOVERIES:
		verify_ctdb_disable_message(md->disable, md2->disable);
		break;

	case CTDB_SRVID_DISABLE_IP_CHECK:
		assert(md->timeout == md2->timeout);
		break;

	default:
		abort();
	}
}

void fill_ctdb_req_message(TALLOC_CTX *mem_ctx, struct ctdb_req_message *c,
			   uint64_t srvid)
{
	c->srvid = srvid;
	fill_ctdb_message_data(mem_ctx, &c->data, srvid);
}

void verify_ctdb_req_message(struct ctdb_req_message *c,
			     struct ctdb_req_message *c2)
{
	assert(c->srvid == c2->srvid);
	verify_ctdb_message_data(&c->data, &c2->data, c->srvid);
}

void fill_ctdb_req_message_data(TALLOC_CTX *mem_ctx,
				struct ctdb_req_message_data *c)
{
	c->srvid = rand64();
	fill_tdb_data(mem_ctx, &c->data);
}

void verify_ctdb_req_message_data(struct ctdb_req_message_data *c,
				  struct ctdb_req_message_data *c2)
{
	assert(c->srvid == c2->srvid);
	verify_tdb_data(&c->data, &c2->data);
}

void fill_ctdb_req_keepalive(TALLOC_CTX *mem_ctx,
				    struct ctdb_req_keepalive *c)
{
	c->version = rand32();
	c->uptime = rand32();
}

void verify_ctdb_req_keepalive(struct ctdb_req_keepalive *c,
				      struct ctdb_req_keepalive *c2)
{
	assert(c->version == c2->version);
	assert(c->uptime == c2->uptime);
}

void fill_ctdb_req_tunnel(TALLOC_CTX *mem_ctx, struct ctdb_req_tunnel *c)
{
	c->tunnel_id = rand64();
	c->flags = rand32();
	fill_tdb_data(mem_ctx, &c->data);
}

void verify_ctdb_req_tunnel(struct ctdb_req_tunnel *c,
			    struct ctdb_req_tunnel *c2)
{
	assert(c->tunnel_id == c2->tunnel_id);
	assert(c->flags == c2->flags);
	verify_tdb_data(&c->data, &c2->data);
}
