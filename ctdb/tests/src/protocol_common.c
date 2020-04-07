/*
   protocol tests - common functions

   Copyright (C) Amitay Isaacs  2015-2017

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

#include "protocol/protocol_api.h"

#include "tests/src/protocol_common_basic.h"
#include "tests/src/protocol_common.h"

void fill_tdb_data_nonnull(TALLOC_CTX *mem_ctx, TDB_DATA *p)
{
	p->dsize = rand_int(1024) + 1;
	p->dptr = talloc_array(mem_ctx, uint8_t, p->dsize);
	assert(p->dptr != NULL);
	fill_buffer(p->dptr, p->dsize);
}

void fill_tdb_data(TALLOC_CTX *mem_ctx, TDB_DATA *p)
{
	if (rand_int(5) == 0) {
		p->dsize = 0;
		p->dptr = NULL;
	} else {
		fill_tdb_data_nonnull(mem_ctx, p);
	}
}

void verify_tdb_data(TDB_DATA *p1, TDB_DATA *p2)
{
	assert(p1->dsize == p2->dsize);
	verify_buffer(p1->dptr, p2->dptr, p1->dsize);
}

void fill_ctdb_tdb_data(TALLOC_CTX *mem_ctx, TDB_DATA *p)
{
	fill_tdb_data(mem_ctx, p);
}

void verify_ctdb_tdb_data(TDB_DATA *p1, TDB_DATA *p2)
{
	verify_tdb_data(p1, p2);
}

void fill_ctdb_tdb_datan(TALLOC_CTX *mem_ctx, TDB_DATA *p)
{
	fill_tdb_data(mem_ctx, p);
}

void verify_ctdb_tdb_datan(TDB_DATA *p1, TDB_DATA *p2)
{
	verify_tdb_data(p1, p2);
}

void fill_ctdb_latency_counter(struct ctdb_latency_counter *p)
{
	p->num = rand32i();
	p->min = rand_double();
	p->max = rand_double();
	p->total = rand_double();
}

void verify_ctdb_latency_counter(struct ctdb_latency_counter *p1,
				 struct ctdb_latency_counter *p2)
{
	assert(p1->num == p2->num);
	assert(p1->min == p2->min);
	assert(p1->max == p2->max);
	assert(p1->total == p2->total);
}

void fill_ctdb_statistics(TALLOC_CTX *mem_ctx, struct ctdb_statistics *p)
{
	int i;

	p->num_clients = rand32();
	p->frozen = rand32();
	p->recovering = rand32();
	p->client_packets_sent = rand32();
	p->client_packets_recv = rand32();
	p->node_packets_sent = rand32();
	p->node_packets_recv = rand32();
	p->keepalive_packets_sent = rand32();
	p->keepalive_packets_recv = rand32();

	p->node.req_call = rand32();
	p->node.reply_call = rand32();
	p->node.req_dmaster = rand32();
	p->node.reply_dmaster = rand32();
	p->node.reply_error = rand32();
	p->node.req_message = rand32();
	p->node.req_control = rand32();
	p->node.reply_control = rand32();

	p->client.req_call = rand32();
	p->client.req_message = rand32();
	p->client.req_control = rand32();

	p->timeouts.call = rand32();
	p->timeouts.control = rand32();
	p->timeouts.traverse = rand32();

	fill_ctdb_latency_counter(&p->reclock.ctdbd);
	fill_ctdb_latency_counter(&p->reclock.recd);

	p->locks.num_calls = rand32();
	p->locks.num_current = rand32();
	p->locks.num_pending = rand32();
	p->locks.num_failed = rand32();
	fill_ctdb_latency_counter(&p->locks.latency);
	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		p->locks.buckets[i] = rand32();
	}

	p->total_calls = rand32();
	p->pending_calls = rand32();
	p->childwrite_calls = rand32();
	p->pending_childwrite_calls = rand32();
	p->memory_used = rand32();
	p->__last_counter = rand32();
	p->max_hop_count = rand32();
	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		p->hop_count_bucket[i] = rand32();
	}
	fill_ctdb_latency_counter(&p->call_latency);
	fill_ctdb_latency_counter(&p->childwrite_latency);
	p->num_recoveries = rand32();
	fill_ctdb_timeval(&p->statistics_start_time);
	fill_ctdb_timeval(&p->statistics_current_time);
	p->total_ro_delegations = rand32();
	p->total_ro_revokes = rand32();
}

void verify_ctdb_statistics(struct ctdb_statistics *p1,
			    struct ctdb_statistics *p2)
{
	int i;

	assert(p1->num_clients == p2->num_clients);
	assert(p1->frozen == p2->frozen);
	assert(p1->recovering == p2->recovering);
	assert(p1->client_packets_sent == p2->client_packets_sent);
	assert(p1->client_packets_recv == p2->client_packets_recv);
	assert(p1->node_packets_sent == p2->node_packets_sent);
	assert(p1->node_packets_recv == p2->node_packets_recv);
	assert(p1->keepalive_packets_sent == p2->keepalive_packets_sent);
	assert(p1->keepalive_packets_recv == p2->keepalive_packets_recv);

	assert(p1->node.req_call == p2->node.req_call);
	assert(p1->node.reply_call == p2->node.reply_call);
	assert(p1->node.req_dmaster == p2->node.req_dmaster);
	assert(p1->node.reply_dmaster == p2->node.reply_dmaster);
	assert(p1->node.reply_error == p2->node.reply_error);
	assert(p1->node.req_message == p2->node.req_message);
	assert(p1->node.req_control == p2->node.req_control);
	assert(p1->node.reply_control == p2->node.reply_control);

	assert(p1->client.req_call == p2->client.req_call);
	assert(p1->client.req_message == p2->client.req_message);
	assert(p1->client.req_control == p2->client.req_control);

	assert(p1->timeouts.call == p2->timeouts.call);
	assert(p1->timeouts.control == p2->timeouts.control);
	assert(p1->timeouts.traverse == p2->timeouts.traverse);

	verify_ctdb_latency_counter(&p1->reclock.ctdbd, &p2->reclock.ctdbd);
	verify_ctdb_latency_counter(&p1->reclock.recd, &p2->reclock.recd);

	assert(p1->locks.num_calls == p2->locks.num_calls);
	assert(p1->locks.num_current == p2->locks.num_current);
	assert(p1->locks.num_pending == p2->locks.num_pending);
	assert(p1->locks.num_failed == p2->locks.num_failed);
	verify_ctdb_latency_counter(&p1->locks.latency, &p2->locks.latency);
	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		assert(p1->locks.buckets[i] == p2->locks.buckets[i]);
	}

	assert(p1->total_calls == p2->total_calls);
	assert(p1->pending_calls == p2->pending_calls);
	assert(p1->childwrite_calls == p2->childwrite_calls);
	assert(p1->pending_childwrite_calls == p2->pending_childwrite_calls);
	assert(p1->memory_used == p2->memory_used);
	assert(p1->__last_counter == p2->__last_counter);
	assert(p1->max_hop_count == p2->max_hop_count);
	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		assert(p1->hop_count_bucket[i] == p2->hop_count_bucket[i]);
	}
	verify_ctdb_latency_counter(&p1->call_latency, &p2->call_latency);
	verify_ctdb_latency_counter(&p1->childwrite_latency,
				    &p2->childwrite_latency);
	assert(p1->num_recoveries == p2->num_recoveries);
	verify_ctdb_timeval(&p1->statistics_start_time,
			    &p2->statistics_start_time);
	verify_ctdb_timeval(&p1->statistics_current_time,
			    &p2->statistics_current_time);
	assert(p1->total_ro_delegations == p2->total_ro_delegations);
	assert(p1->total_ro_revokes == p2->total_ro_revokes);
}

void fill_ctdb_vnn_map(TALLOC_CTX *mem_ctx, struct ctdb_vnn_map *p)
{
	unsigned int i;

	p->generation = rand32();
	p->size = rand_int(20);
	if (p->size > 0) {
		p->map = talloc_array(mem_ctx, uint32_t, p->size);
		assert(p->map != NULL);

		for (i=0; i<p->size; i++) {
			p->map[i] = rand32();
		}
	} else {
		p->map = NULL;
	}
}

void verify_ctdb_vnn_map(struct ctdb_vnn_map *p1, struct ctdb_vnn_map *p2)
{
	unsigned int i;

	assert(p1->generation == p2->generation);
	assert(p1->size == p2->size);
	for (i=0; i<p1->size; i++) {
		assert(p1->map[i] == p2->map[i]);
	}
}

void fill_ctdb_dbid(TALLOC_CTX *mem_ctx, struct ctdb_dbid *p)
{
	p->db_id = rand32();
	p->flags = rand8();
}

void verify_ctdb_dbid(struct ctdb_dbid *p1, struct ctdb_dbid *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->flags == p2->flags);
}

void fill_ctdb_dbid_map(TALLOC_CTX *mem_ctx, struct ctdb_dbid_map *p)
{
	unsigned int i;

	p->num = rand_int(40);
	if (p->num > 0) {
		p->dbs = talloc_zero_array(mem_ctx, struct ctdb_dbid, p->num);
		assert(p->dbs != NULL);
		for (i=0; i<p->num; i++) {
			fill_ctdb_dbid(mem_ctx, &p->dbs[i]);
		}
	} else {
		p->dbs = NULL;
	}
}

void verify_ctdb_dbid_map(struct ctdb_dbid_map *p1, struct ctdb_dbid_map *p2)
{
	unsigned int i;

	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		verify_ctdb_dbid(&p1->dbs[i], &p2->dbs[i]);
	}
}

void fill_ctdb_pulldb(TALLOC_CTX *mem_ctx, struct ctdb_pulldb *p)
{
	p->db_id = rand32();
	p->lmaster = rand32();
}

void verify_ctdb_pulldb(struct ctdb_pulldb *p1, struct ctdb_pulldb *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->lmaster == p2->lmaster);
}

void fill_ctdb_pulldb_ext(TALLOC_CTX *mem_ctx, struct ctdb_pulldb_ext *p)
{
	p->db_id = rand32();
	p->lmaster = rand32();
	p->srvid = rand64();
}

void verify_ctdb_pulldb_ext(struct ctdb_pulldb_ext *p1,
			    struct ctdb_pulldb_ext *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->lmaster == p2->lmaster);
	assert(p1->srvid == p2->srvid);
}

void fill_ctdb_db_vacuum(TALLOC_CTX *mem_ctx, struct ctdb_db_vacuum *p)
{
	fill_ctdb_uint32(&p->db_id);
	fill_ctdb_bool(&p->full_vacuum_run);
}

void verify_ctdb_db_vacuum(struct ctdb_db_vacuum *p1,
			    struct ctdb_db_vacuum *p2)
{
	verify_ctdb_uint32(&p1->db_id, &p2->db_id);
	verify_ctdb_bool(&p1->full_vacuum_run, &p2->full_vacuum_run);
}

void fill_ctdb_echo_data(TALLOC_CTX *mem_ctx, struct ctdb_echo_data *p)
{
	fill_ctdb_uint32(&p->timeout);
	fill_tdb_data(mem_ctx, &p->buf);
}

void verify_ctdb_echo_data(struct ctdb_echo_data *p1,
			    struct ctdb_echo_data *p2)
{
	verify_ctdb_uint32(&p1->timeout, &p2->timeout);
	verify_tdb_data(&p1->buf, &p2->buf);
}

void fill_ctdb_ltdb_header(struct ctdb_ltdb_header *p)
{
	p->rsn = rand64();
	p->dmaster = rand32();
	p->reserved1 = rand32();
	p->flags = rand32();
}

void verify_ctdb_ltdb_header(struct ctdb_ltdb_header *p1,
			     struct ctdb_ltdb_header *p2)
{
	assert(p1->rsn == p2->rsn);
	assert(p1->dmaster == p2->dmaster);
	assert(p1->reserved1 == p2->reserved1);
	assert(p1->flags == p2->flags);
}

void fill_ctdb_rec_data(TALLOC_CTX *mem_ctx, struct ctdb_rec_data *p)
{
	p->reqid = rand32();
	if (p->reqid % 5 == 0) {
		p->header = talloc(mem_ctx, struct ctdb_ltdb_header);
		assert(p->header != NULL);
		fill_ctdb_ltdb_header(p->header);
	} else {
		p->header = NULL;
	}
	fill_tdb_data_nonnull(mem_ctx, &p->key);
	fill_tdb_data(mem_ctx, &p->data);
}

void verify_ctdb_rec_data(struct ctdb_rec_data *p1, struct ctdb_rec_data *p2)
{
	struct ctdb_ltdb_header header;

	assert(p1->reqid == p2->reqid);
	if (p1->header != NULL) {
		assert(ctdb_ltdb_header_extract(&p2->data, &header) == 0);
		verify_ctdb_ltdb_header(p1->header, &header);
	}
	verify_tdb_data(&p1->key, &p2->key);
	verify_tdb_data(&p1->data, &p2->data);
}

void fill_ctdb_rec_buffer(TALLOC_CTX *mem_ctx, struct ctdb_rec_buffer *p)
{
	struct ctdb_rec_data rec;
	int ret, i;
	int count;

	p->db_id = rand32();
	p->count = 0;
	p->buf = NULL;
	p->buflen = 0;

	count = rand_int(100);
	if (count > 0) {
		for (i=0; i<count; i++) {
			fill_ctdb_rec_data(mem_ctx, &rec);
			ret = ctdb_rec_buffer_add(mem_ctx, p, rec.reqid,
						  rec.header,
						  rec.key, rec.data);
			assert(ret == 0);
		}
	}
}

void verify_ctdb_rec_buffer(struct ctdb_rec_buffer *p1,
			    struct ctdb_rec_buffer *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->count == p2->count);
	assert(p1->buflen == p2->buflen);
	verify_buffer(p1->buf, p2->buf, p1->buflen);
}

void fill_ctdb_traverse_start(TALLOC_CTX *mem_ctx,
			      struct ctdb_traverse_start *p)
{
	p->db_id = rand32();
	p->reqid = rand32();
	p->srvid = rand64();
}

void verify_ctdb_traverse_start(struct ctdb_traverse_start *p1,
				struct ctdb_traverse_start *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->reqid == p2->reqid);
	assert(p1->srvid == p2->srvid);
}

void fill_ctdb_traverse_all(TALLOC_CTX *mem_ctx,
			    struct ctdb_traverse_all *p)
{
	p->db_id = rand32();
	p->reqid = rand32();
	p->pnn = rand32();
	p->client_reqid = rand32();
	p->srvid = rand64();
}

void verify_ctdb_traverse_all(struct ctdb_traverse_all *p1,
			      struct ctdb_traverse_all *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->reqid == p2->reqid);
	assert(p1->pnn == p2->pnn);
	assert(p1->client_reqid == p2->client_reqid);
	assert(p1->srvid == p2->srvid);
}

void fill_ctdb_traverse_start_ext(TALLOC_CTX *mem_ctx,
				  struct ctdb_traverse_start_ext *p)
{
	p->db_id = rand32();
	p->reqid = rand32();
	p->srvid = rand64();
	p->withemptyrecords = rand_int(2);
}

void verify_ctdb_traverse_start_ext(struct ctdb_traverse_start_ext *p1,
				    struct ctdb_traverse_start_ext *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->reqid == p2->reqid);
	assert(p1->srvid == p2->srvid);
	assert(p1->withemptyrecords == p2->withemptyrecords);
}

void fill_ctdb_traverse_all_ext(TALLOC_CTX *mem_ctx,
				struct ctdb_traverse_all_ext *p)
{
	p->db_id = rand32();
	p->reqid = rand32();
	p->pnn = rand32();
	p->client_reqid = rand32();
	p->srvid = rand64();
	p->withemptyrecords = rand_int(2);
}

void verify_ctdb_traverse_all_ext(struct ctdb_traverse_all_ext *p1,
				  struct ctdb_traverse_all_ext *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->reqid == p2->reqid);
	assert(p1->pnn == p2->pnn);
	assert(p1->client_reqid == p2->client_reqid);
	assert(p1->srvid == p2->srvid);
	assert(p1->withemptyrecords == p2->withemptyrecords);
}

void fill_ctdb_sock_addr(TALLOC_CTX *mem_ctx, ctdb_sock_addr *p)
{
	if (rand_int(2) == 0) {
		p->ip.sin_family = AF_INET;
		p->ip.sin_port = rand_int(65535);
		fill_buffer(&p->ip.sin_addr, sizeof(struct in_addr));
	} else {
		p->ip6.sin6_family = AF_INET6;
		p->ip6.sin6_port = rand_int(65535);
		fill_buffer(&p->ip6.sin6_addr, sizeof(struct in6_addr));
	}
}

void verify_ctdb_sock_addr(ctdb_sock_addr *p1, ctdb_sock_addr *p2)
{
	assert(p1->sa.sa_family == p2->sa.sa_family);
	if (p1->sa.sa_family == AF_INET) {
		assert(p1->ip.sin_port == p2->ip.sin_port);
		verify_buffer(&p1->ip.sin_addr, &p2->ip.sin_addr,
				   sizeof(struct in_addr));
	} else {
		assert(p1->ip6.sin6_port == p2->ip6.sin6_port);
		verify_buffer(&p1->ip6.sin6_addr, &p2->ip6.sin6_addr,
				   sizeof(struct in6_addr));
	}
}

void fill_ctdb_connection(TALLOC_CTX *mem_ctx, struct ctdb_connection *p)
{
	fill_ctdb_sock_addr(mem_ctx, &p->src);
	fill_ctdb_sock_addr(mem_ctx, &p->dst);
}

void verify_ctdb_connection(struct ctdb_connection *p1,
			    struct ctdb_connection *p2)
{
	verify_ctdb_sock_addr(&p1->src, &p2->src);
	verify_ctdb_sock_addr(&p1->dst, &p2->dst);
}

void fill_ctdb_connection_list(TALLOC_CTX *mem_ctx,
			       struct ctdb_connection_list *p)
{
	uint32_t i;

	p->num = rand_int(1000);
	if (p->num > 0) {
		p->conn = talloc_array(mem_ctx, struct ctdb_connection, p->num);
		assert(p->conn != NULL);
		for (i=0; i<p->num; i++) {
			fill_ctdb_connection(mem_ctx, &p->conn[i]);
		}
	} else {
		p->conn = NULL;
	}
}

void verify_ctdb_connection_list(struct ctdb_connection_list *p1,
				 struct ctdb_connection_list *p2)
{
	uint32_t i;

	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		verify_ctdb_connection(&p1->conn[i], &p2->conn[i]);
	}
}

void fill_ctdb_tunable(TALLOC_CTX *mem_ctx, struct ctdb_tunable *p)
{
	fill_ctdb_string(mem_ctx, &p->name);
	p->value = rand32();
}

void verify_ctdb_tunable(struct ctdb_tunable *p1, struct ctdb_tunable *p2)
{
	verify_ctdb_string(&p1->name, &p2->name);
	assert(p1->value == p2->value);
}

void fill_ctdb_node_flag_change(TALLOC_CTX *mem_ctx,
				struct ctdb_node_flag_change *p)
{
	p->pnn = rand32();
	p->new_flags = rand32();
	p->old_flags = rand32();
}

void verify_ctdb_node_flag_change(struct ctdb_node_flag_change *p1,
				  struct ctdb_node_flag_change *p2)
{
	assert(p1->pnn == p2->pnn);
	assert(p1->new_flags == p2->new_flags);
	assert(p1->old_flags == p2->old_flags);
}

void fill_ctdb_var_list(TALLOC_CTX *mem_ctx, struct ctdb_var_list *p)
{
	int i;

	p->count = rand_int(100) + 1;
	p->var = talloc_array(mem_ctx, const char *, p->count);
	for (i=0; i<p->count; i++) {
		fill_ctdb_string(p->var, &p->var[i]);
	}
}

void verify_ctdb_var_list(struct ctdb_var_list *p1, struct ctdb_var_list *p2)
{
	int i;

	assert(p1->count == p2->count);
	for (i=0; i<p1->count; i++) {
		verify_ctdb_string(&p1->var[i], &p2->var[i]);
	}
}

void fill_ctdb_tunable_list(TALLOC_CTX *mem_ctx, struct ctdb_tunable_list *p)
{
	p->max_redirect_count = rand32();
	p->seqnum_interval = rand32();
	p->control_timeout = rand32();
	p->traverse_timeout = rand32();
	p->keepalive_interval = rand32();
	p->keepalive_limit = rand32();
	p->recover_timeout = rand32();
	p->recover_interval = rand32();
	p->election_timeout = rand32();
	p->takeover_timeout = rand32();
	p->monitor_interval = rand32();
	p->tickle_update_interval = rand32();
	p->script_timeout = rand32();
	p->monitor_timeout_count = rand32();
	p->script_unhealthy_on_timeout = rand32();
	p->recovery_grace_period = rand32();
	p->recovery_ban_period = rand32();
	p->database_hash_size = rand32();
	p->database_max_dead = rand32();
	p->rerecovery_timeout = rand32();
	p->enable_bans = rand32();
	p->deterministic_public_ips = rand32();
	p->reclock_ping_period = rand32();
	p->no_ip_failback = rand32();
	p->disable_ip_failover = rand32();
	p->verbose_memory_names = rand32();
	p->recd_ping_timeout = rand32();
	p->recd_ping_failcount = rand32();
	p->log_latency_ms = rand32();
	p->reclock_latency_ms = rand32();
	p->recovery_drop_all_ips = rand32();
	p->verify_recovery_lock = rand32();
	p->vacuum_interval = rand32();
	p->vacuum_max_run_time = rand32();
	p->repack_limit = rand32();
	p->vacuum_limit = rand32();
	p->max_queue_depth_drop_msg = rand32();
	p->allow_unhealthy_db_read = rand32();
	p->stat_history_interval = rand32();
	p->deferred_attach_timeout = rand32();
	p->vacuum_fast_path_count = rand32();
	p->lcp2_public_ip_assignment = rand32();
	p->allow_client_db_attach = rand32();
	p->recover_pdb_by_seqnum = rand32();
	p->deferred_rebalance_on_node_add = rand32();
	p->fetch_collapse = rand32();
	p->hopcount_make_sticky = rand32();
	p->sticky_duration = rand32();
	p->sticky_pindown = rand32();
	p->no_ip_takeover = rand32();
	p->db_record_count_warn = rand32();
	p->db_record_size_warn = rand32();
	p->db_size_warn = rand32();
	p->pulldb_preallocation_size = rand32();
	p->no_ip_host_on_all_disabled = rand32();
	p->samba3_hack = rand32();
	p->mutex_enabled = rand32();
	p->lock_processes_per_db = rand32();
	p->rec_buffer_size_limit = rand32();
	p->queue_buffer_size = rand32();
	p->ip_alloc_algorithm = rand32();
	p->allow_mixed_versions = rand32();
}

void verify_ctdb_tunable_list(struct ctdb_tunable_list *p1,
			      struct ctdb_tunable_list *p2)
{
	assert(p1->max_redirect_count == p2->max_redirect_count);
	assert(p1->seqnum_interval == p2->seqnum_interval);
	assert(p1->control_timeout == p2->control_timeout);
	assert(p1->traverse_timeout == p2->traverse_timeout);
	assert(p1->keepalive_interval == p2->keepalive_interval);
	assert(p1->keepalive_limit == p2->keepalive_limit);
	assert(p1->recover_timeout == p2->recover_timeout);
	assert(p1->recover_interval == p2->recover_interval);
	assert(p1->election_timeout == p2->election_timeout);
	assert(p1->takeover_timeout == p2->takeover_timeout);
	assert(p1->monitor_interval == p2->monitor_interval);
	assert(p1->tickle_update_interval == p2->tickle_update_interval);
	assert(p1->script_timeout == p2->script_timeout);
	assert(p1->monitor_timeout_count == p2->monitor_timeout_count);
	assert(p1->script_unhealthy_on_timeout == p2->script_unhealthy_on_timeout);
	assert(p1->recovery_grace_period == p2->recovery_grace_period);
	assert(p1->recovery_ban_period == p2->recovery_ban_period);
	assert(p1->database_hash_size == p2->database_hash_size);
	assert(p1->database_max_dead == p2->database_max_dead);
	assert(p1->rerecovery_timeout == p2->rerecovery_timeout);
	assert(p1->enable_bans == p2->enable_bans);
	assert(p1->deterministic_public_ips == p2->deterministic_public_ips);
	assert(p1->reclock_ping_period == p2->reclock_ping_period);
	assert(p1->no_ip_failback == p2->no_ip_failback);
	assert(p1->disable_ip_failover == p2->disable_ip_failover);
	assert(p1->verbose_memory_names == p2->verbose_memory_names);
	assert(p1->recd_ping_timeout == p2->recd_ping_timeout);
	assert(p1->recd_ping_failcount == p2->recd_ping_failcount);
	assert(p1->log_latency_ms == p2->log_latency_ms);
	assert(p1->reclock_latency_ms == p2->reclock_latency_ms);
	assert(p1->recovery_drop_all_ips == p2->recovery_drop_all_ips);
	assert(p1->verify_recovery_lock == p2->verify_recovery_lock);
	assert(p1->vacuum_interval == p2->vacuum_interval);
	assert(p1->vacuum_max_run_time == p2->vacuum_max_run_time);
	assert(p1->repack_limit == p2->repack_limit);
	assert(p1->vacuum_limit == p2->vacuum_limit);
	assert(p1->max_queue_depth_drop_msg == p2->max_queue_depth_drop_msg);
	assert(p1->allow_unhealthy_db_read == p2->allow_unhealthy_db_read);
	assert(p1->stat_history_interval == p2->stat_history_interval);
	assert(p1->deferred_attach_timeout == p2->deferred_attach_timeout);
	assert(p1->vacuum_fast_path_count == p2->vacuum_fast_path_count);
	assert(p1->lcp2_public_ip_assignment == p2->lcp2_public_ip_assignment);
	assert(p1->allow_client_db_attach == p2->allow_client_db_attach);
	assert(p1->recover_pdb_by_seqnum == p2->recover_pdb_by_seqnum);
	assert(p1->deferred_rebalance_on_node_add == p2->deferred_rebalance_on_node_add);
	assert(p1->fetch_collapse == p2->fetch_collapse);
	assert(p1->hopcount_make_sticky == p2->hopcount_make_sticky);
	assert(p1->sticky_duration == p2->sticky_duration);
	assert(p1->sticky_pindown == p2->sticky_pindown);
	assert(p1->no_ip_takeover == p2->no_ip_takeover);
	assert(p1->db_record_count_warn == p2->db_record_count_warn);
	assert(p1->db_record_size_warn == p2->db_record_size_warn);
	assert(p1->db_size_warn == p2->db_size_warn);
	assert(p1->pulldb_preallocation_size == p2->pulldb_preallocation_size);
	assert(p1->no_ip_host_on_all_disabled == p2->no_ip_host_on_all_disabled);
	assert(p1->samba3_hack == p2->samba3_hack);
	assert(p1->mutex_enabled == p2->mutex_enabled);
	assert(p1->lock_processes_per_db == p2->lock_processes_per_db);
	assert(p1->rec_buffer_size_limit == p2->rec_buffer_size_limit);
	assert(p1->queue_buffer_size == p2->queue_buffer_size);
	assert(p1->ip_alloc_algorithm == p2->ip_alloc_algorithm);
	assert(p1->allow_mixed_versions == p2->allow_mixed_versions);
}

void fill_ctdb_tickle_list(TALLOC_CTX *mem_ctx, struct ctdb_tickle_list *p)
{
	unsigned int i;

	fill_ctdb_sock_addr(mem_ctx, &p->addr);
	p->num = rand_int(1000);
	if (p->num > 0) {
		p->conn = talloc_array(mem_ctx, struct ctdb_connection, p->num);
		assert(p->conn != NULL);
		for (i=0; i<p->num; i++) {
			fill_ctdb_connection(mem_ctx, &p->conn[i]);
		}
	} else {
		p->conn = NULL;
	}
}

void verify_ctdb_tickle_list(struct ctdb_tickle_list *p1,
			     struct ctdb_tickle_list *p2)
{
	unsigned int i;

	verify_ctdb_sock_addr(&p1->addr, &p2->addr);
	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		verify_ctdb_connection(&p1->conn[i], &p2->conn[i]);
	}
}

void fill_ctdb_addr_info(TALLOC_CTX *mem_ctx, struct ctdb_addr_info *p)
{
	fill_ctdb_sock_addr(mem_ctx, &p->addr);
	p->mask = rand_int(33);
	if (rand_int(2) == 0) {
		p->iface = NULL;
	} else {
		fill_ctdb_string(mem_ctx, &p->iface);
	}
}

void verify_ctdb_addr_info(struct ctdb_addr_info *p1,
			   struct ctdb_addr_info *p2)
{
	verify_ctdb_sock_addr(&p1->addr, &p2->addr);
	assert(p1->mask == p2->mask);
	verify_ctdb_string(&p1->iface, &p2->iface);
}

void fill_ctdb_transdb(TALLOC_CTX *mem_ctx, struct ctdb_transdb *p)
{
	p->db_id = rand32();
	p->tid = rand32();
}

void verify_ctdb_transdb(struct ctdb_transdb *p1, struct ctdb_transdb *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->tid == p2->tid);
}

void fill_ctdb_uptime(TALLOC_CTX *mem_ctx, struct ctdb_uptime *p)
{
	fill_ctdb_timeval(&p->current_time);
	fill_ctdb_timeval(&p->ctdbd_start_time);
	fill_ctdb_timeval(&p->last_recovery_started);
	fill_ctdb_timeval(&p->last_recovery_finished);
}

void verify_ctdb_uptime(struct ctdb_uptime *p1, struct ctdb_uptime *p2)
{
	verify_ctdb_timeval(&p1->current_time, &p2->current_time);
	verify_ctdb_timeval(&p1->ctdbd_start_time, &p2->ctdbd_start_time);
	verify_ctdb_timeval(&p1->last_recovery_started,
			    &p2->last_recovery_started);
	verify_ctdb_timeval(&p1->last_recovery_finished,
			    &p2->last_recovery_finished);
}

void fill_ctdb_public_ip(TALLOC_CTX *mem_ctx, struct ctdb_public_ip *p)
{
	p->pnn = rand32();
	fill_ctdb_sock_addr(mem_ctx, &p->addr);
}

void verify_ctdb_public_ip(struct ctdb_public_ip *p1,
			   struct ctdb_public_ip *p2)
{
	assert(p1->pnn == p2->pnn);
	verify_ctdb_sock_addr(&p1->addr, &p2->addr);
}

void fill_ctdb_public_ip_list(TALLOC_CTX *mem_ctx,
			      struct ctdb_public_ip_list *p)
{
	unsigned int i;

	p->num = rand_int(32);
	if (p->num > 0) {
		p->ip = talloc_array(mem_ctx, struct ctdb_public_ip, p->num);
		assert(p->ip != NULL);
		for (i=0; i<p->num; i++) {
			fill_ctdb_public_ip(mem_ctx, &p->ip[i]);
		}
	} else {
		p->ip = NULL;
	}
}

void verify_ctdb_public_ip_list(struct ctdb_public_ip_list *p1,
				struct ctdb_public_ip_list *p2)
{
	unsigned int i;

	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		verify_ctdb_public_ip(&p1->ip[i], &p2->ip[i]);
	}
}

void fill_ctdb_node_and_flags(TALLOC_CTX *mem_ctx,
			      struct ctdb_node_and_flags *p)
{
	p->pnn = rand32();
	p->flags = rand32();
	fill_ctdb_sock_addr(mem_ctx, &p->addr);
}

void verify_ctdb_node_and_flags(struct ctdb_node_and_flags *p1,
				struct ctdb_node_and_flags *p2)
{
	assert(p1->pnn == p2->pnn);
	assert(p1->flags == p2->flags);
	verify_ctdb_sock_addr(&p1->addr, &p2->addr);
}

void fill_ctdb_node_map(TALLOC_CTX *mem_ctx, struct ctdb_node_map *p)
{
	unsigned int i;

	p->num = rand_int(32);
	if (p->num > 0) {
		p->node = talloc_array(mem_ctx, struct ctdb_node_and_flags,
				       p->num);
		assert(p->node != NULL);
		for (i=0; i<p->num; i++) {
			fill_ctdb_node_and_flags(mem_ctx, &p->node[i]);
		}
	} else {
		p->node = NULL;
	}
}

void verify_ctdb_node_map(struct ctdb_node_map *p1, struct ctdb_node_map *p2)
{
	unsigned int i;

	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		verify_ctdb_node_and_flags(&p1->node[i], &p2->node[i]);
	}
}

void fill_ctdb_script(TALLOC_CTX *mem_ctx, struct ctdb_script *p)
{
	fill_string(p->name, MAX_SCRIPT_NAME+1);
	fill_ctdb_timeval(&p->start);
	fill_ctdb_timeval(&p->finished);
	p->status = rand32i();
	fill_string(p->output, MAX_SCRIPT_OUTPUT+1);
}

void verify_ctdb_script(struct ctdb_script *p1, struct ctdb_script *p2)
{
	verify_string(p1->name, p2->name);
	verify_ctdb_timeval(&p1->start, &p2->start);
	verify_ctdb_timeval(&p1->finished, &p2->finished);
	assert(p1->status == p2->status);
	verify_string(p1->output, p2->output);
}

void fill_ctdb_script_list(TALLOC_CTX *mem_ctx, struct ctdb_script_list *p)
{
	unsigned int i;

	p->num_scripts = rand_int(32);
	if (p->num_scripts > 0) {
		p->script = talloc_zero_array(mem_ctx, struct ctdb_script,
					      p->num_scripts);
		assert(p->script != NULL);
		for (i=0; i<p->num_scripts; i++) {
			fill_ctdb_script(mem_ctx, &p->script[i]);
		}
	} else {
		p->script = NULL;
	}
}

void verify_ctdb_script_list(struct ctdb_script_list *p1,
			     struct ctdb_script_list *p2)
{
	unsigned int i;

	assert(p1->num_scripts == p2->num_scripts);
	for (i=0; i<p1->num_scripts; i++) {
		verify_ctdb_script(&p1->script[i], &p2->script[i]);
	}
}

void fill_ctdb_ban_state(TALLOC_CTX *mem_ctx, struct ctdb_ban_state *p)
{
	p->pnn = rand32();
	p->time = rand32();
}

void verify_ctdb_ban_state(struct ctdb_ban_state *p1,
			   struct ctdb_ban_state *p2)
{
	assert(p1->pnn == p2->pnn);
	assert(p1->time == p2->time);
}

void fill_ctdb_notify_data(TALLOC_CTX *mem_ctx, struct ctdb_notify_data *p)
{
	p->srvid = rand64();
	fill_tdb_data(mem_ctx, &p->data);
}

void verify_ctdb_notify_data(struct ctdb_notify_data *p1,
			     struct ctdb_notify_data *p2)
{
	assert(p1->srvid == p2->srvid);
	verify_tdb_data(&p1->data, &p2->data);
}

void fill_ctdb_iface(TALLOC_CTX *mem_ctx, struct ctdb_iface *p)
{
	fill_string(p->name, CTDB_IFACE_SIZE+2);
	p->link_state = rand16();
	p->references = rand32();
}

void verify_ctdb_iface(struct ctdb_iface *p1, struct ctdb_iface *p2)
{
	verify_string(p1->name, p2->name);
	assert(p1->link_state == p2->link_state);
	assert(p1->references == p2->references);
}

void fill_ctdb_iface_list(TALLOC_CTX *mem_ctx, struct ctdb_iface_list *p)
{
	unsigned int i;

	p->num = rand_int(32);
	if (p->num > 0) {
		p->iface = talloc_array(mem_ctx, struct ctdb_iface, p->num);
		assert(p->iface != NULL);
		for (i=0; i<p->num; i++) {
			fill_ctdb_iface(mem_ctx, &p->iface[i]);
		}
	} else {
		p->iface = NULL;
	}
}

void verify_ctdb_iface_list(struct ctdb_iface_list *p1,
			    struct ctdb_iface_list *p2)
{
	unsigned int i;

	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		verify_ctdb_iface(&p1->iface[i], &p2->iface[i]);
	}
}

void fill_ctdb_public_ip_info(TALLOC_CTX *mem_ctx,
			      struct ctdb_public_ip_info *p)
{
	fill_ctdb_public_ip(mem_ctx, &p->ip);
	p->active_idx = rand_int(32) + 1;
	p->ifaces = talloc(mem_ctx, struct ctdb_iface_list);
	assert(p->ifaces != NULL);
	fill_ctdb_iface_list(mem_ctx, p->ifaces);
}

void verify_ctdb_public_ip_info(struct ctdb_public_ip_info *p1,
				struct ctdb_public_ip_info *p2)
{
	verify_ctdb_public_ip(&p1->ip, &p2->ip);
	assert(p1->active_idx == p2->active_idx);
	verify_ctdb_iface_list(p1->ifaces, p2->ifaces);
}

void fill_ctdb_statistics_list(TALLOC_CTX *mem_ctx,
			       struct ctdb_statistics_list *p)
{
	int i;

	p->num = rand_int(10);
	if (p->num > 0) {
		p->stats = talloc_zero_array(mem_ctx, struct ctdb_statistics,
					     p->num);
		assert(p->stats != NULL);

		for (i=0; i<p->num; i++) {
			fill_ctdb_statistics(mem_ctx, &p->stats[i]);
		}
	} else {
		p->stats = NULL;
	}
}

void verify_ctdb_statistics_list(struct ctdb_statistics_list *p1,
				 struct ctdb_statistics_list *p2)
{
	int i;

	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		verify_ctdb_statistics(&p1->stats[i], &p2->stats[i]);
	}
}

void fill_ctdb_key_data(TALLOC_CTX *mem_ctx, struct ctdb_key_data *p)
{
	p->db_id = rand32();
	fill_ctdb_ltdb_header(&p->header);
	fill_tdb_data_nonnull(mem_ctx, &p->key);
}

void verify_ctdb_key_data(struct ctdb_key_data *p1, struct ctdb_key_data *p2)
{
	assert(p1->db_id == p2->db_id);
	verify_ctdb_ltdb_header(&p1->header, &p2->header);
	verify_tdb_data(&p1->key, &p2->key);
}

void fill_ctdb_db_statistics(TALLOC_CTX *mem_ctx,
			     struct ctdb_db_statistics *p)
{
	unsigned int i;

	p->locks.num_calls = rand32();
	p->locks.num_current = rand32();
	p->locks.num_pending = rand32();
	p->locks.num_failed = rand32();
	fill_ctdb_latency_counter(&p->locks.latency);
	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		p->locks.buckets[i] = rand32();
	}

	fill_ctdb_latency_counter(&p->vacuum.latency);

	p->db_ro_delegations = rand32();
	p->db_ro_revokes = rand32();
	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		p->hop_count_bucket[i] = rand32();
	}

	p->num_hot_keys = MAX_HOT_KEYS;
	for (i=0; i<p->num_hot_keys; i++) {
		p->hot_keys[i].count = rand32();
		fill_tdb_data(mem_ctx, &p->hot_keys[i].key);
	}
}

void verify_ctdb_db_statistics(struct ctdb_db_statistics *p1,
			       struct ctdb_db_statistics *p2)
{
	unsigned int i;

	assert(p1->locks.num_calls == p2->locks.num_calls);
	assert(p1->locks.num_current == p2->locks.num_current);
	assert(p1->locks.num_pending == p2->locks.num_pending);
	assert(p1->locks.num_failed == p2->locks.num_failed);
	verify_ctdb_latency_counter(&p1->locks.latency, &p2->locks.latency);
	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		assert(p1->locks.buckets[i] == p2->locks.buckets[i]);
	}

	verify_ctdb_latency_counter(&p1->vacuum.latency, &p2->vacuum.latency);

	assert(p1->db_ro_delegations == p2->db_ro_delegations);
	assert(p1->db_ro_revokes == p2->db_ro_revokes);
	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		assert(p1->hop_count_bucket[i] == p2->hop_count_bucket[i]);
	}

	assert(p1->num_hot_keys == p2->num_hot_keys);
	for (i=0; i<p1->num_hot_keys; i++) {
		assert(p1->hot_keys[i].count == p2->hot_keys[i].count);
		verify_tdb_data(&p1->hot_keys[i].key, &p2->hot_keys[i].key);
	}
}

void fill_ctdb_pid_srvid(TALLOC_CTX *mem_ctx, struct ctdb_pid_srvid *p)
{
	p->pid = rand32();
	p->srvid = rand64();
}

void verify_ctdb_pid_srvid(struct ctdb_pid_srvid *p1,
			   struct ctdb_pid_srvid *p2)
{
	assert(p1->pid == p2->pid);
	assert(p1->srvid == p2->srvid);
}

void fill_ctdb_election_message(TALLOC_CTX *mem_ctx,
				struct ctdb_election_message *p)
{
	p->num_connected = rand_int(32);
	fill_ctdb_timeval(&p->priority_time);
	p->pnn = rand_int(32);
	p->node_flags = rand32();
}

void verify_ctdb_election_message(struct ctdb_election_message *p1,
				  struct ctdb_election_message *p2)
{
	assert(p1->num_connected == p2->num_connected);
	verify_ctdb_timeval(&p1->priority_time, &p2->priority_time);
	assert(p1->pnn == p2->pnn);
	assert(p1->node_flags == p2->node_flags);
}

void fill_ctdb_srvid_message(TALLOC_CTX *mem_ctx,
			     struct ctdb_srvid_message *p)
{
	p->pnn = rand_int(32);
	p->srvid = rand64();
}

void verify_ctdb_srvid_message(struct ctdb_srvid_message *p1,
			       struct ctdb_srvid_message *p2)
{
	assert(p1->pnn == p2->pnn);
	assert(p1->srvid == p2->srvid);
}

void fill_ctdb_disable_message(TALLOC_CTX *mem_ctx,
			       struct ctdb_disable_message *p)
{
	p->pnn = rand_int(32);
	p->srvid = rand64();
	p->timeout = rand32();
}

void verify_ctdb_disable_message(struct ctdb_disable_message *p1,
				 struct ctdb_disable_message *p2)
{
	assert(p1->pnn == p2->pnn);
	assert(p1->srvid == p2->srvid);
	assert(p1->timeout == p2->timeout);
}

void fill_ctdb_server_id(struct ctdb_server_id *p)
{
	p->pid = rand64();
	p->task_id = rand32();
	p->vnn = rand_int(32);
	p->unique_id = rand64();
}

void verify_ctdb_server_id(struct ctdb_server_id *p1,
			   struct ctdb_server_id *p2)
{
	assert(p1->pid == p2->pid);
	assert(p1->task_id == p2->task_id);
	assert(p1->vnn == p2->vnn);
	assert(p1->unique_id == p2->unique_id);
}

void fill_ctdb_g_lock(struct ctdb_g_lock *p)
{
	p->type = rand_int(2);
	fill_ctdb_server_id(&p->sid);
}

void verify_ctdb_g_lock(struct ctdb_g_lock *p1, struct ctdb_g_lock *p2)
{
	assert(p1->type == p2->type);
	verify_ctdb_server_id(&p1->sid, &p2->sid);
}

void fill_ctdb_g_lock_list(TALLOC_CTX *mem_ctx, struct ctdb_g_lock_list *p)
{
	unsigned int i;

	p->num = rand_int(20) + 1;
	p->lock = talloc_zero_array(mem_ctx, struct ctdb_g_lock, p->num);
	assert(p->lock != NULL);
	for (i=0; i<p->num; i++) {
		fill_ctdb_g_lock(&p->lock[i]);
	}
}

void verify_ctdb_g_lock_list(struct ctdb_g_lock_list *p1,
			     struct ctdb_g_lock_list *p2)
{
	unsigned int i;

	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		verify_ctdb_g_lock(&p1->lock[i], &p2->lock[i]);
	}
}

void fill_sock_packet_header(struct sock_packet_header *p)
{
	p->length = rand32();
	p->reqid = rand32();
}

void verify_sock_packet_header(struct sock_packet_header *p1,
			       struct sock_packet_header *p2)
{
	assert(p1->length == p2->length);
	assert(p1->reqid == p2->reqid);
}
