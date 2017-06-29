/*
   CTDB protocol marshalling

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

#include <talloc.h>
#include <tdb.h>

#include "protocol.h"
#include "protocol_private.h"
#include "protocol_api.h"

size_t ctdb_tdb_data_len(TDB_DATA *in)
{
	return in->dsize > UINT32_MAX ? UINT32_MAX : in->dsize;
}

void ctdb_tdb_data_push(TDB_DATA *in, uint8_t *buf, size_t *npush)
{
	size_t len = ctdb_tdb_data_len(in);

	if (len > 0) {
		memcpy(buf, in->dptr, len);
	}

	*npush = len;
}

int ctdb_tdb_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       TDB_DATA *out, size_t *npull)
{
	TDB_DATA val;

	if (buflen > UINT32_MAX) {
		return EMSGSIZE;
	}

	val.dsize = buflen;
	if (val.dsize > 0) {
		val.dptr = talloc_memdup(mem_ctx, buf, buflen);
		if (val.dptr == NULL) {
			return ENOMEM;
		}
	} else {
		val.dptr = NULL;
	}

	*out = val;
	*npull = buflen;
	return 0;
}

size_t ctdb_tdb_datan_len(TDB_DATA *in)
{
	uint32_t u32 = ctdb_tdb_data_len(in);

	return ctdb_uint32_len(&u32) + u32;
}

void ctdb_tdb_datan_push(TDB_DATA *in, uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;
	uint32_t u32 = ctdb_tdb_data_len(in);

	ctdb_uint32_push(&u32, buf+offset, &np);
	offset += np;

	ctdb_tdb_data_push(in, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_tdb_datan_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			TDB_DATA *out, size_t *npull)
{
	size_t offset = 0, np;
	uint32_t u32;
	int ret;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &u32, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (buflen-offset < u32) {
		return EMSGSIZE;
	}

	ret = ctdb_tdb_data_pull(buf+offset, u32, mem_ctx, out, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	*npull = offset;
	return 0;
}

size_t ctdb_latency_counter_len(struct ctdb_latency_counter *in)
{
	return ctdb_int32_len(&in->num) +
		ctdb_padding_len(4) +
		ctdb_double_len(&in->min) +
		ctdb_double_len(&in->max) +
		ctdb_double_len(&in->total);
}

void ctdb_latency_counter_push(struct ctdb_latency_counter *in, uint8_t *buf,
			       size_t *npush)
{
	size_t offset = 0, np;

	ctdb_int32_push(&in->num, buf+offset, &np);
	offset += np;

	ctdb_padding_push(4, buf+offset, &np);
	offset += np;

	ctdb_double_push(&in->min, buf+offset, &np);
	offset += np;

	ctdb_double_push(&in->max, buf+offset, &np);
	offset += np;

	ctdb_double_push(&in->total, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_latency_counter_pull(uint8_t *buf, size_t buflen,
			      struct ctdb_latency_counter *out, size_t *npull)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_int32_pull(buf+offset, buflen-offset, &out->num, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 4, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_double_pull(buf+offset, buflen-offset, &out->min, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_double_pull(buf+offset, buflen-offset, &out->max, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_double_pull(buf+offset, buflen-offset, &out->total, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	*npull = offset;
	return 0;
}

size_t ctdb_statistics_len(struct ctdb_statistics *in)
{
	return ctdb_uint32_len(&in->num_clients) +
		ctdb_uint32_len(&in->frozen) +
		ctdb_uint32_len(&in->recovering) +
		ctdb_uint32_len(&in->client_packets_sent) +
		ctdb_uint32_len(&in->client_packets_recv) +
		ctdb_uint32_len(&in->node_packets_sent) +
		ctdb_uint32_len(&in->node_packets_recv) +
		ctdb_uint32_len(&in->keepalive_packets_sent) +
		ctdb_uint32_len(&in->keepalive_packets_recv) +
		ctdb_uint32_len(&in->node.req_call) +
		ctdb_uint32_len(&in->node.reply_call) +
		ctdb_uint32_len(&in->node.req_dmaster) +
		ctdb_uint32_len(&in->node.reply_dmaster) +
		ctdb_uint32_len(&in->node.reply_error) +
		ctdb_uint32_len(&in->node.req_message) +
		ctdb_uint32_len(&in->node.req_control) +
		ctdb_uint32_len(&in->node.reply_control) +
		ctdb_uint32_len(&in->client.req_call) +
		ctdb_uint32_len(&in->client.req_message) +
		ctdb_uint32_len(&in->client.req_control) +
		ctdb_uint32_len(&in->timeouts.call) +
		ctdb_uint32_len(&in->timeouts.control) +
		ctdb_uint32_len(&in->timeouts.traverse) +
		ctdb_padding_len(4) +
		ctdb_latency_counter_len(&in->reclock.ctdbd) +
		ctdb_latency_counter_len(&in->reclock.recd) +
		ctdb_uint32_len(&in->locks.num_calls) +
		ctdb_uint32_len(&in->locks.num_current) +
		ctdb_uint32_len(&in->locks.num_pending) +
		ctdb_uint32_len(&in->locks.num_failed) +
		ctdb_latency_counter_len(&in->locks.latency) +
		MAX_COUNT_BUCKETS * ctdb_uint32_len(&in->locks.buckets[0]) +
		ctdb_uint32_len(&in->total_calls) +
		ctdb_uint32_len(&in->pending_calls) +
		ctdb_uint32_len(&in->childwrite_calls) +
		ctdb_uint32_len(&in->pending_childwrite_calls) +
		ctdb_uint32_len(&in->memory_used) +
		ctdb_uint32_len(&in->__last_counter) +
		ctdb_uint32_len(&in->max_hop_count) +
		MAX_COUNT_BUCKETS *
			ctdb_uint32_len(&in->hop_count_bucket[0]) +
		ctdb_padding_len(4) +
		ctdb_latency_counter_len(&in->call_latency) +
		ctdb_latency_counter_len(&in->childwrite_latency) +
		ctdb_uint32_len(&in->num_recoveries) +
		ctdb_padding_len(4) +
		ctdb_timeval_len(&in->statistics_start_time) +
		ctdb_timeval_len(&in->statistics_current_time) +
		ctdb_uint32_len(&in->total_ro_delegations) +
		ctdb_uint32_len(&in->total_ro_revokes);
}

void ctdb_statistics_push(struct ctdb_statistics *in, uint8_t *buf,
			  size_t *npush)
{
	size_t offset = 0, np;
	int i;

	ctdb_uint32_push(&in->num_clients, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->frozen, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->recovering, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->client_packets_sent, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->client_packets_recv, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->node_packets_sent, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->node_packets_recv, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->keepalive_packets_sent, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->keepalive_packets_recv, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->node.req_call, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->node.reply_call, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->node.req_dmaster, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->node.reply_dmaster, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->node.reply_error, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->node.req_message, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->node.req_control, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->node.reply_control, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->client.req_call, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->client.req_message, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->client.req_control, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->timeouts.call, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->timeouts.control, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->timeouts.traverse, buf+offset, &np);
	offset += np;

	ctdb_padding_push(4, buf+offset, &np);
	offset += np;

	ctdb_latency_counter_push(&in->reclock.ctdbd, buf+offset, &np);
	offset += np;

	ctdb_latency_counter_push(&in->reclock.recd, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->locks.num_calls, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->locks.num_current, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->locks.num_pending, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->locks.num_failed, buf+offset, &np);
	offset += np;

	ctdb_latency_counter_push(&in->locks.latency, buf+offset, &np);
	offset += np;

	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		ctdb_uint32_push(&in->locks.buckets[i], buf+offset, &np);
		offset += np;
	}

	ctdb_uint32_push(&in->total_calls, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->pending_calls, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->childwrite_calls, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->pending_childwrite_calls, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->memory_used, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->__last_counter, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->max_hop_count, buf+offset, &np);
	offset += np;

	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		ctdb_uint32_push(&in->hop_count_bucket[i], buf+offset, &np);
		offset += np;
	}

	ctdb_padding_push(4, buf+offset, &np);
	offset += np;

	ctdb_latency_counter_push(&in->call_latency, buf+offset, &np);
	offset += np;

	ctdb_latency_counter_push(&in->childwrite_latency, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->num_recoveries, buf+offset, &np);
	offset += np;

	ctdb_padding_push(4, buf+offset, &np);
	offset += np;

	ctdb_timeval_push(&in->statistics_start_time, buf+offset, &np);
	offset += np;

	ctdb_timeval_push(&in->statistics_current_time, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->total_ro_delegations, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->total_ro_revokes, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_statistics_pull_elems(uint8_t *buf, size_t buflen,
				      TALLOC_CTX *mem_ctx,
				      struct ctdb_statistics *out,
				      size_t *npull)
{
	size_t offset = 0, np;
	int ret, i;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->num_clients,
			       &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->frozen, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->recovering,
			       &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->client_packets_sent, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->client_packets_recv, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->node_packets_sent, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->node_packets_recv, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->keepalive_packets_sent, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->keepalive_packets_recv, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->node.req_call, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->node.reply_call, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->node.req_dmaster, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->node.reply_dmaster, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->node.reply_error, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->node.req_message, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->node.req_control, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->node.reply_control, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->client.req_call, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->client.req_message, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->client.req_control, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->timeouts.call, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->timeouts.control, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->timeouts.traverse, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 4, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_latency_counter_pull(buf+offset, buflen-offset,
					&out->reclock.ctdbd, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_latency_counter_pull(buf+offset, buflen-offset,
					&out->reclock.recd, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->locks.num_calls, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->locks.num_current, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->locks.num_pending, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->locks.num_failed, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_latency_counter_pull(buf+offset, buflen-offset,
					&out->locks.latency, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	for (i=0;  i<MAX_COUNT_BUCKETS; i++) {
		ret = ctdb_uint32_pull(buf+offset, buflen-offset,
				       &out->locks.buckets[i], &np);
		if (ret != 0) {
			return ret;
		}
		offset += np;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->total_calls, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->pending_calls, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->childwrite_calls, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->pending_childwrite_calls, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->memory_used,
			       &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->__last_counter, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->max_hop_count, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	for (i=0;  i<MAX_COUNT_BUCKETS; i++) {
		ret = ctdb_uint32_pull(buf+offset, buflen-offset,
				       &out->hop_count_bucket[i], &np);
		if (ret != 0) {
			return ret;
		}
		offset += np;
	}

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 4, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_latency_counter_pull(buf+offset, buflen-offset,
					&out->call_latency, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_latency_counter_pull(buf+offset, buflen-offset,
					&out->childwrite_latency, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->num_recoveries, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 4, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_timeval_pull(buf+offset, buflen-offset,
				&out->statistics_start_time, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_timeval_pull(buf+offset, buflen-offset,
				&out->statistics_current_time, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->total_ro_delegations, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->total_ro_revokes, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	*npull = offset;
	return 0;
}

int ctdb_statistics_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_statistics **out, size_t *npull)
{
	struct ctdb_statistics *val;
	size_t np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_statistics);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_statistics_pull_elems(buf, buflen, val, val, &np);
	if (ret != 0) {
		talloc_free(val);
		return ret;
	}

	*out = val;
	*npull = np;
	return 0;
}

struct ctdb_statistics_list_wire {
	uint32_t num;
	struct ctdb_statistics stats[1];
};

size_t ctdb_statistics_list_len(struct ctdb_statistics_list *stats_list)
{
	return offsetof(struct ctdb_statistics_list_wire, stats) +
	       stats_list->num * sizeof(struct ctdb_statistics);
}

void ctdb_statistics_list_push(struct ctdb_statistics_list *stats_list,
			       uint8_t *buf)
{
	struct ctdb_statistics_list_wire *wire =
		(struct ctdb_statistics_list_wire *)buf;

	wire->num = stats_list->num;
	memcpy(wire->stats, stats_list->stats,
	       stats_list->num * sizeof(struct ctdb_statistics));
}

int ctdb_statistics_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			      struct ctdb_statistics_list **out)
{
	struct ctdb_statistics_list *stats_list;
	struct ctdb_statistics_list_wire *wire =
		(struct ctdb_statistics_list_wire *)buf;

	if (buflen < offsetof(struct ctdb_statistics_list_wire, stats)) {
		return EMSGSIZE;
	}
	if (wire->num > buflen / sizeof(struct ctdb_statistics)) {
		return EMSGSIZE;
	}
	if (offsetof(struct ctdb_statistics_list_wire, stats) +
	    wire->num * sizeof(struct ctdb_statistics) <
	    offsetof(struct ctdb_statistics_list_wire, stats)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_statistics_list_wire, stats) +
		     wire->num * sizeof(struct ctdb_statistics)) {
		return EMSGSIZE;
	}

	stats_list = talloc(mem_ctx, struct ctdb_statistics_list);
	if (stats_list == NULL) {
		return ENOMEM;
	}

	stats_list->num = wire->num;

	stats_list->stats = talloc_array(stats_list, struct ctdb_statistics,
					 wire->num);
	if (stats_list->stats == NULL) {
		talloc_free(stats_list);
		return ENOMEM;
	}

	memcpy(stats_list->stats, wire->stats,
	       wire->num * sizeof(struct ctdb_statistics));

	*out = stats_list;
	return 0;
}

size_t ctdb_vnn_map_len(struct ctdb_vnn_map *in)
{
	size_t len;

	len = ctdb_uint32_len(&in->generation) + ctdb_uint32_len(&in->size);
	if (in->size > 0) {
		len += in->size * ctdb_uint32_len(&in->map[0]);
	}

	return len;
}

void ctdb_vnn_map_push(struct ctdb_vnn_map *in, uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;
	uint32_t i;

	ctdb_uint32_push(&in->generation, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->size, buf+offset, &np);
	offset += np;

	for (i=0; i<in->size; i++) {
		ctdb_uint32_push(&in->map[i], buf+offset, &np);
		offset += np;
	}

	*npush = offset;
}

int ctdb_vnn_map_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		      struct ctdb_vnn_map **out, size_t *npull)
{
	struct ctdb_vnn_map *val;
	size_t offset = 0, np;
	uint32_t i;
	int ret;

	val = talloc(mem_ctx, struct ctdb_vnn_map);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->generation,
			       &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->size, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	if (val->size == 0) {
		val->map = NULL;
		goto done;
	}

	val->map = talloc_array(val, uint32_t, val->size);
	if (val->map == NULL) {
		ret = ENOMEM;
		goto fail;
	}

	for (i=0; i<val->size; i++) {
		ret = ctdb_uint32_pull(buf+offset, buflen-offset,
				       &val->map[i], &np);
		if (ret != 0) {
			goto fail;
		}
		offset += np;
	}

done:
	*out = val;
	*npull = offset;
	return 0;

fail:
	talloc_free(val);
	return ret;
}

size_t ctdb_dbid_len(struct ctdb_dbid *in)
{
	return ctdb_uint32_len(&in->db_id) +
		ctdb_uint8_len(&in->flags) +
		ctdb_padding_len(3);
}

void ctdb_dbid_push(struct ctdb_dbid *in, uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->db_id, buf+offset, &np);
	offset += np;

	ctdb_uint8_push(&in->flags, buf+offset, &np);
	offset += np;

	ctdb_padding_push(3, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_dbid_pull_elems(uint8_t *buf, size_t buflen,
				TALLOC_CTX *mem_ctx, struct ctdb_dbid *out,
				size_t *npull)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->db_id, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint8_pull(buf+offset, buflen-offset, &out->flags, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 3, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	*npull = offset;
	return 0;
}

int ctdb_dbid_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		   struct ctdb_dbid **out, size_t *npull)
{
	struct ctdb_dbid *val;
	size_t np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_dbid);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_dbid_pull_elems(buf, buflen, val, val, &np);
	if (ret != 0) {
		talloc_free(val);
		return ret;
	}

	*out = val;
	*npull = np;
	return 0;
}

size_t ctdb_dbid_map_len(struct ctdb_dbid_map *in)
{
	size_t len;

	len = ctdb_uint32_len(&in->num);
	if (in->num > 0) {
		len += in->num * ctdb_dbid_len(&in->dbs[0]);
	}

	return len;
}

void ctdb_dbid_map_push(struct ctdb_dbid_map *in, uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;
	uint32_t i;

	ctdb_uint32_push(&in->num, buf+offset, &np);
	offset += np;

	for (i=0; i<in->num; i++) {
		ctdb_dbid_push(&in->dbs[i], buf+offset, &np);
		offset += np;
	}

	*npush = offset;
}

int ctdb_dbid_map_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_dbid_map **out, size_t *npull)
{
	struct ctdb_dbid_map *val;
	size_t offset = 0, np;
	uint32_t i;
	int ret;

	val = talloc(mem_ctx, struct ctdb_dbid_map);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->num, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	if (val->num == 0) {
		val->dbs = NULL;
		goto done;
	}

	val->dbs = talloc_array(val, struct ctdb_dbid, val->num);
	if (val->dbs == NULL) {
		ret = ENOMEM;
		goto fail;
	}

	for (i=0; i<val->num; i++) {
		ret = ctdb_dbid_pull_elems(buf+offset, buflen-offset, val,
					   &val->dbs[i], &np);
		if (ret != 0) {
			goto fail;
		}
		offset += np;
	}

done:
	*out = val;
	*npull = offset;
	return 0;

fail:
	talloc_free(val);
	return ret;
}

size_t ctdb_pulldb_len(struct ctdb_pulldb *in)
{
	return ctdb_uint32_len(&in->db_id) +
		ctdb_uint32_len(&in->lmaster);
}

void ctdb_pulldb_push(struct ctdb_pulldb *in, uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->db_id, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->lmaster, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_pulldb_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_pulldb **out, size_t *npull)
{
	struct ctdb_pulldb *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_pulldb);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->db_id, &np);
	if (ret != 0) {
		talloc_free(val);
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->lmaster, &np);
	if (ret != 0) {
		talloc_free(val);
		return ret;
	}
	offset += np;

	*out = val;
	*npull = offset;
	return 0;
}

size_t ctdb_pulldb_ext_len(struct ctdb_pulldb_ext *in)
{
	return ctdb_uint32_len(&in->db_id) +
		ctdb_uint32_len(&in->lmaster) +
		ctdb_uint64_len(&in->srvid);
}

void ctdb_pulldb_ext_push(struct ctdb_pulldb_ext *in, uint8_t *buf,
			  size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->db_id, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->lmaster, buf+offset, &np);
	offset += np;

	ctdb_uint64_push(&in->srvid, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_pulldb_ext_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_pulldb_ext **out, size_t *npull)
{
	struct ctdb_pulldb_ext *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_pulldb_ext);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->db_id, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->lmaster, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint64_pull(buf+offset, buflen-offset, &val->srvid, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	*out = val;
	*npull = offset;
	return 0;

fail:
	talloc_free(val);
	return ret;
}

size_t ctdb_ltdb_header_len(struct ctdb_ltdb_header *in)
{
	return ctdb_uint64_len(&in->rsn) +
		ctdb_uint32_len(&in->dmaster) +
		ctdb_uint32_len(&in->reserved1) +
		ctdb_uint32_len(&in->flags) +
		ctdb_padding_len(4);
}

void ctdb_ltdb_header_push(struct ctdb_ltdb_header *in, uint8_t *buf,
			   size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint64_push(&in->rsn, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->dmaster, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->reserved1, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->flags, buf+offset, &np);
	offset += np;

	ctdb_padding_push(4, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_ltdb_header_pull(uint8_t *buf, size_t buflen,
			  struct ctdb_ltdb_header *out, size_t *npull)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_uint64_pull(buf+offset, buflen-offset, &out->rsn, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->dmaster, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->reserved1,
			       &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->flags, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 4, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	*npull = offset;
	return 0;
}

int ctdb_ltdb_header_extract(TDB_DATA *data, struct ctdb_ltdb_header *header)
{
	size_t np;
	int ret;

	ret = ctdb_ltdb_header_pull(data->dptr, data->dsize, header, &np);
	if (ret != 0) {
		return ret;
	}

	data->dptr += np;
	data->dsize -= np;

	return 0;
}

size_t ctdb_rec_data_len(struct ctdb_rec_data *in)
{
	uint32_t u32;

	u32 = ctdb_uint32_len(&in->reqid) +
		ctdb_tdb_datan_len(&in->key) +
		ctdb_tdb_datan_len(&in->data);

	if (in->header != NULL) {
		u32 += ctdb_ltdb_header_len(in->header);
	}

	return ctdb_uint32_len(&u32) + u32;
}

void ctdb_rec_data_push(struct ctdb_rec_data *in, uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;
	uint32_t u32;

	u32 = ctdb_rec_data_len(in);
	ctdb_uint32_push(&u32, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->reqid, buf+offset, &np);
	offset += np;

	u32 = ctdb_tdb_data_len(&in->key);
	ctdb_uint32_push(&u32, buf+offset, &np);
	offset += np;

	u32 = ctdb_tdb_data_len(&in->data);
	if (in->header != NULL) {
		u32 += ctdb_ltdb_header_len(in->header);
	}

	ctdb_uint32_push(&u32, buf+offset, &np);
	offset += np;

	ctdb_tdb_data_push(&in->key, buf+offset, &np);
	offset += np;

	/* If ltdb header is not NULL, then it is pushed as part of the data */
	if (in->header != NULL) {
		ctdb_ltdb_header_push(in->header, buf+offset, &np);
		offset += np;
	}
	ctdb_tdb_data_push(&in->data, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_rec_data_pull_data(uint8_t *buf, size_t buflen,
				   uint32_t *reqid,
				   TDB_DATA *key, TDB_DATA *data,
				   size_t *npull)
{
	size_t offset = 0, np;
	size_t len;
	uint32_t u32;
	int ret;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &u32, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (buflen < u32) {
		return EMSGSIZE;
	}
	len = u32;

	ret = ctdb_uint32_pull(buf+offset, len-offset, reqid, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, len-offset, &u32, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;
	key->dsize = u32;

	ret = ctdb_uint32_pull(buf+offset, len-offset, &u32, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;
	data->dsize = u32;

	if (len-offset < key->dsize) {
		return EMSGSIZE;
	}

	key->dptr = buf+offset;
	offset += key->dsize;

	if (len-offset < data->dsize) {
		return EMSGSIZE;
	}

	data->dptr = buf+offset;
	offset += data->dsize;

	*npull = offset;
	return 0;
}

static int ctdb_rec_data_pull_elems(uint8_t *buf, size_t buflen,
				    TALLOC_CTX *mem_ctx,
				    struct ctdb_rec_data *out,
				    size_t *npull)
{
	uint32_t reqid;
	TDB_DATA key, data;
	size_t np;
	int ret;

	ret = ctdb_rec_data_pull_data(buf, buflen, &reqid, &key, &data, &np);
	if (ret != 0) {
		return ret;
	}

	out->reqid = reqid;

	/* Always set header to NULL.  If it is required, extract it using
	 * ctdb_rec_data_extract_header()
	 */
	out->header = NULL;

	out->key.dsize = key.dsize;
	if (key.dsize > 0) {
		out->key.dptr = talloc_memdup(mem_ctx, key.dptr, key.dsize);
		if (out->key.dptr == NULL) {
			return ENOMEM;
		}
	}

	out->data.dsize = data.dsize;
	if (data.dsize > 0) {
		out->data.dptr = talloc_memdup(mem_ctx, data.dptr, data.dsize);
		if (out->data.dptr == NULL) {
			return ENOMEM;
		}
	}

	*npull = np;
	return 0;
}

int ctdb_rec_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_rec_data **out, size_t *npull)
{
	struct ctdb_rec_data *val;
	size_t np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_rec_data);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_rec_data_pull_elems(buf, buflen, val, val, &np);
	if (ret != 0) {
		TALLOC_FREE(val);
		return ret;
	}

	*out = val;
	*npull = np;
	return ret;
}

size_t ctdb_rec_buffer_len(struct ctdb_rec_buffer *in)
{
	return ctdb_uint32_len(&in->db_id) +
		ctdb_uint32_len(&in->count) +
		in->buflen;
}

void ctdb_rec_buffer_push(struct ctdb_rec_buffer *in, uint8_t *buf,
			  size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->db_id, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->count, buf+offset, &np);
	offset += np;

	memcpy(buf+offset, in->buf, in->buflen);
	offset += in->buflen;

	*npush = offset;
}

int ctdb_rec_buffer_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_rec_buffer **out, size_t *npull)
{
	struct ctdb_rec_buffer *val;
	size_t offset = 0, np;
	size_t length;
	int ret;

	val = talloc(mem_ctx, struct ctdb_rec_buffer);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->db_id, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->count, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	/* Since there is no buflen provided, walk the records to
	 * validate the length of the buffer.
	 */
	val->buf = buf+offset;
	val->buflen = buflen-offset;

	length = 0;
	ret = ctdb_rec_buffer_traverse(val, NULL, &length);
	if (ret != 0) {
		goto fail;
	}

	if (length > buflen-offset) {
		ret = EMSGSIZE;
		goto fail;
	}

	val->buf = talloc_memdup(val, buf+offset, length);
	if (val->buf == NULL) {
		ret = ENOMEM;
		goto fail;
	}
	val->buflen = length;
	offset += length;

	*out = val;
	*npull = offset;
	return 0;

fail:
	talloc_free(val);
	return ret;
}

struct ctdb_rec_buffer *ctdb_rec_buffer_init(TALLOC_CTX *mem_ctx,
					     uint32_t db_id)
{
	struct ctdb_rec_buffer *recbuf;

	recbuf = talloc_zero(mem_ctx, struct ctdb_rec_buffer);
	if (recbuf == NULL) {
		return recbuf;
	}

	recbuf->db_id = db_id;

	return recbuf;
}

int ctdb_rec_buffer_add(TALLOC_CTX *mem_ctx, struct ctdb_rec_buffer *recbuf,
			uint32_t reqid, struct ctdb_ltdb_header *header,
			TDB_DATA key, TDB_DATA data)
{
	struct ctdb_rec_data recdata;
	size_t len, np;
	uint8_t *ptr;

	recdata.reqid = reqid;
	recdata.header = header;
	recdata.key = key;
	recdata.data = data;

	len = ctdb_rec_data_len(&recdata);

	ptr = talloc_realloc(mem_ctx, recbuf->buf, uint8_t,
			     recbuf->buflen + len);
	if (ptr == NULL) {
		return ENOMEM;
	}

	ctdb_rec_data_push(&recdata, &ptr[recbuf->buflen], &np);

	recbuf->count++;
	recbuf->buf = ptr;
	recbuf->buflen += np;
	return 0;
}

int ctdb_rec_buffer_traverse(struct ctdb_rec_buffer *recbuf,
			     ctdb_rec_parser_func_t func,
			     void *private_data)
{
	TDB_DATA key, data;
	uint32_t reqid;
	size_t offset, reclen;
	int ret = 0, i;

	offset = 0;
	for (i=0; i<recbuf->count; i++) {
		ret = ctdb_rec_data_pull_data(&recbuf->buf[offset],
					      recbuf->buflen - offset,
					      &reqid, &key, &data, &reclen);
		if (ret != 0) {
			return ret;
		}

		if (func != NULL) {
			ret = func(reqid, NULL, key, data, private_data);
			if (ret != 0) {
				break;
			}
		}

		offset += reclen;
	}

	if (ret != 0) {
		return ret;
	}

	if (func == NULL) {
		size_t *length = (size_t *)private_data;

		*length = offset;
	}

	return 0;
}

int ctdb_rec_buffer_write(struct ctdb_rec_buffer *recbuf, int fd)
{
	ssize_t n;

	n = write(fd, &recbuf->db_id, sizeof(uint32_t));
	if (n == -1 || n != sizeof(uint32_t)) {
		return (errno != 0 ? errno : EIO);
	}
	n = write(fd, &recbuf->count, sizeof(uint32_t));
	if (n == -1 || n != sizeof(uint32_t)) {
		return (errno != 0 ? errno : EIO);
	}
	n = write(fd, &recbuf->buflen, sizeof(size_t));
	if (n == -1 || n != sizeof(size_t)) {
		return (errno != 0 ? errno : EIO);
	}
	n = write(fd, recbuf->buf, recbuf->buflen);
	if (n == -1 || n != recbuf->buflen) {
		return (errno != 0 ? errno : EIO);
	}

	return 0;
}

int ctdb_rec_buffer_read(int fd, TALLOC_CTX *mem_ctx,
			 struct ctdb_rec_buffer **out)
{
	struct ctdb_rec_buffer *recbuf;
	ssize_t n;

	recbuf = talloc(mem_ctx, struct ctdb_rec_buffer);
	if (recbuf == NULL) {
		return ENOMEM;
	}

	n = read(fd, &recbuf->db_id, sizeof(uint32_t));
	if (n == -1 || n != sizeof(uint32_t)) {
		return (errno != 0 ? errno : EIO);
	}
	n = read(fd, &recbuf->count, sizeof(uint32_t));
	if (n == -1 || n != sizeof(uint32_t)) {
		return (errno != 0 ? errno : EIO);
	}
	n = read(fd, &recbuf->buflen, sizeof(size_t));
	if (n == -1 || n != sizeof(size_t)) {
		return (errno != 0 ? errno : EIO);
	}

	recbuf->buf = talloc_size(recbuf, recbuf->buflen);
	if (recbuf->buf == NULL) {
		return ENOMEM;
	}

	n = read(fd, recbuf->buf, recbuf->buflen);
	if (n == -1 || n != recbuf->buflen) {
		return (errno != 0 ? errno : EIO);
	}

	*out = recbuf;
	return 0;
}

size_t ctdb_traverse_start_len(struct ctdb_traverse_start *in)
{
	return ctdb_uint32_len(&in->db_id) +
		ctdb_uint32_len(&in->reqid) +
		ctdb_uint64_len(&in->srvid);
}

void ctdb_traverse_start_push(struct ctdb_traverse_start *in, uint8_t *buf,
			      size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->db_id, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->reqid, buf+offset, &np);
	offset += np;

	ctdb_uint64_push(&in->srvid, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_traverse_start_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_traverse_start **out, size_t *npull)
{
	struct ctdb_traverse_start *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_traverse_start);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->db_id, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->reqid, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint64_pull(buf+offset, buflen-offset, &val->srvid, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	*out = val;
	*npull = offset;
	return 0;

fail:
	talloc_free(val);
	return ret;
}

size_t ctdb_traverse_all_len(struct ctdb_traverse_all *in)
{
	return ctdb_uint32_len(&in->db_id) +
		ctdb_uint32_len(&in->reqid) +
		ctdb_uint32_len(&in->pnn) +
		ctdb_uint32_len(&in->client_reqid) +
		ctdb_uint64_len(&in->srvid);
}

void ctdb_traverse_all_push(struct ctdb_traverse_all *in, uint8_t *buf,
			    size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->db_id, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->reqid, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->pnn, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->client_reqid, buf+offset, &np);
	offset += np;

	ctdb_uint64_push(&in->srvid, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_traverse_all_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			   struct ctdb_traverse_all **out, size_t *npull)
{
	struct ctdb_traverse_all *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_traverse_all);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->db_id, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->reqid, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->pnn, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->client_reqid,
			       &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint64_pull(buf+offset, buflen-offset, &val->srvid, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	*out = val;
	*npull = offset;
	return 0;

fail:
	talloc_free(val);
	return ret;
}

size_t ctdb_traverse_start_ext_len(struct ctdb_traverse_start_ext *traverse)
{
	return sizeof(struct ctdb_traverse_start_ext);
}

void ctdb_traverse_start_ext_push(struct ctdb_traverse_start_ext *traverse,
				  uint8_t *buf)
{
	memcpy(buf, traverse, sizeof(struct ctdb_traverse_start_ext));
}

int ctdb_traverse_start_ext_pull(uint8_t *buf, size_t buflen,
				 TALLOC_CTX *mem_ctx,
				 struct ctdb_traverse_start_ext **out)
{
	struct ctdb_traverse_start_ext *traverse;

	if (buflen < sizeof(struct ctdb_traverse_start_ext)) {
		return EMSGSIZE;
	}

	traverse = talloc_memdup(mem_ctx, buf,
				 sizeof(struct ctdb_traverse_start_ext));
	if (traverse == NULL) {
		return ENOMEM;
	}

	*out = traverse;
	return 0;
}

size_t ctdb_traverse_all_ext_len(struct ctdb_traverse_all_ext *traverse)
{
	return sizeof(struct ctdb_traverse_all_ext);
}

void ctdb_traverse_all_ext_push(struct ctdb_traverse_all_ext *traverse,
				uint8_t *buf)
{
	memcpy(buf, traverse, sizeof(struct ctdb_traverse_all_ext));
}

int ctdb_traverse_all_ext_pull(uint8_t *buf, size_t buflen,
			       TALLOC_CTX *mem_ctx,
			       struct ctdb_traverse_all_ext **out)
{
	struct ctdb_traverse_all_ext *traverse;

	if (buflen < sizeof(struct ctdb_traverse_all_ext)) {
		return EMSGSIZE;
	}

	traverse = talloc_memdup(mem_ctx, buf,
				 sizeof(struct ctdb_traverse_all_ext));
	if (traverse == NULL) {
		return ENOMEM;
	}

	*out = traverse;
	return 0;
}

size_t ctdb_sock_addr_len(ctdb_sock_addr *addr)
{
	return sizeof(ctdb_sock_addr);
}

void ctdb_sock_addr_push(ctdb_sock_addr *addr, uint8_t *buf)
{
	memcpy(buf, addr, sizeof(ctdb_sock_addr));
}

static int ctdb_sock_addr_pull_elems(uint8_t *buf, size_t buflen,
				     TALLOC_CTX *mem_ctx, ctdb_sock_addr *out)
{
	if (buflen < sizeof(ctdb_sock_addr)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(ctdb_sock_addr));

	return 0;
}

int ctdb_sock_addr_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			ctdb_sock_addr **out)
{
	ctdb_sock_addr *addr;
	int ret;

	addr = talloc(mem_ctx, ctdb_sock_addr);
	if (addr == NULL) {
		return false;
	}

	ret = ctdb_sock_addr_pull_elems(buf, buflen, addr, addr);
	if (ret != 0) {
		TALLOC_FREE(addr);
	}

	*out = addr;
	return ret;
}

size_t ctdb_connection_len(struct ctdb_connection *conn)
{
	return sizeof(struct ctdb_connection);
}

void ctdb_connection_push(struct ctdb_connection *conn, uint8_t *buf)
{
	memcpy(buf, conn, sizeof(struct ctdb_connection));
}

static int ctdb_connection_pull_elems(uint8_t *buf, size_t buflen,
				      TALLOC_CTX *mem_ctx,
				      struct ctdb_connection *out)
{
	if (buflen < sizeof(struct ctdb_connection)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_connection));

	return 0;
}

int ctdb_connection_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_connection **out)
{
	struct ctdb_connection *conn;
	int ret;

	conn = talloc(mem_ctx, struct ctdb_connection);
	if (conn == NULL) {
		return ENOMEM;
	}

	ret = ctdb_connection_pull_elems(buf, buflen, conn, conn);
	if (ret != 0) {
		TALLOC_FREE(conn);
	}

	*out = conn;
	return ret;
}

struct ctdb_tunable_wire {
	uint32_t value;
	uint32_t length;
	uint8_t name[1];
};

size_t ctdb_tunable_len(struct ctdb_tunable *tunable)
{
	return offsetof(struct ctdb_tunable_wire, name) +
	       strlen(tunable->name) + 1;
}

void ctdb_tunable_push(struct ctdb_tunable *tunable, uint8_t *buf)
{
	struct ctdb_tunable_wire *wire = (struct ctdb_tunable_wire *)buf;

	wire->value = tunable->value;
	wire->length = strlen(tunable->name) + 1;
	memcpy(wire->name, tunable->name, wire->length);
}

int ctdb_tunable_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		      struct ctdb_tunable **out)
{
	struct ctdb_tunable *tunable;
	struct ctdb_tunable_wire *wire = (struct ctdb_tunable_wire *)buf;

	if (buflen < offsetof(struct ctdb_tunable_wire, name)) {
		return EMSGSIZE;
	}
	if (wire->length > buflen) {
		return EMSGSIZE;
	}
	if (offsetof(struct ctdb_tunable_wire, name) + wire->length <
	    offsetof(struct ctdb_tunable_wire, name)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_tunable_wire, name) + wire->length) {
		return EMSGSIZE;
	}

	tunable = talloc(mem_ctx, struct ctdb_tunable);
	if (tunable == NULL) {
		return ENOMEM;
	}

	tunable->value = wire->value;
	tunable->name = talloc_memdup(tunable, wire->name, wire->length);
	if (tunable->name == NULL) {
		talloc_free(tunable);
		return ENOMEM;
	}

	*out = tunable;
	return 0;
}

size_t ctdb_node_flag_change_len(struct ctdb_node_flag_change *flag_change)
{
	return sizeof(struct ctdb_node_flag_change);
}

void ctdb_node_flag_change_push(struct ctdb_node_flag_change *flag_change,
				uint8_t *buf)
{
	memcpy(buf, flag_change, sizeof(struct ctdb_node_flag_change));
}

int ctdb_node_flag_change_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			       struct ctdb_node_flag_change **out)
{
	struct ctdb_node_flag_change *flag_change;

	if (buflen < sizeof(struct ctdb_node_flag_change)) {
		return EMSGSIZE;
	}

	flag_change = talloc_memdup(mem_ctx, buf,
				    sizeof(struct ctdb_node_flag_change));
	if (flag_change == NULL) {
		return ENOMEM;
	}

	*out = flag_change;
	return 0;
}

struct ctdb_var_list_wire {
	uint32_t length;
	char list_str[1];
};

size_t ctdb_var_list_len(struct ctdb_var_list *var_list)
{
	int i;
	size_t len = sizeof(uint32_t);

	for (i=0; i<var_list->count; i++) {
		len += strlen(var_list->var[i]) + 1;
	}
	return len;
}

void ctdb_var_list_push(struct ctdb_var_list *var_list, uint8_t *buf)
{
	struct ctdb_var_list_wire *wire = (struct ctdb_var_list_wire *)buf;
	int i, n;
	size_t offset = 0;

	if (var_list->count > 0) {
		n = sprintf(wire->list_str, "%s", var_list->var[0]);
		offset += n;
	}
	for (i=1; i<var_list->count; i++) {
		n = sprintf(&wire->list_str[offset], ":%s", var_list->var[i]);
		offset += n;
	}
	wire->length = offset + 1;
}

int ctdb_var_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_var_list **out)
{
	struct ctdb_var_list *var_list = NULL;
	struct ctdb_var_list_wire *wire = (struct ctdb_var_list_wire *)buf;
	char *str, *s, *tok, *ptr;
	const char **list;

	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (wire->length > buflen) {
		return EMSGSIZE;
	}
	if (sizeof(uint32_t) + wire->length < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(uint32_t) + wire->length) {
		return EMSGSIZE;
	}

	str = talloc_strndup(mem_ctx, (char *)wire->list_str, wire->length);
	if (str == NULL) {
		return ENOMEM;
	}

	var_list = talloc_zero(mem_ctx, struct ctdb_var_list);
	if (var_list == NULL) {
		goto fail;
	}

	s = str;
	while ((tok = strtok_r(s, ":", &ptr)) != NULL) {
		s = NULL;
		list = talloc_realloc(var_list, var_list->var, const char *,
				      var_list->count+1);
		if (list == NULL) {
			goto fail;
		}

		var_list->var = list;
		var_list->var[var_list->count] = talloc_strdup(var_list, tok);
		if (var_list->var[var_list->count] == NULL) {
			goto fail;
		}
		var_list->count++;
	}

	talloc_free(str);
	*out = var_list;
	return 0;

fail:
	talloc_free(str);
	talloc_free(var_list);
	return ENOMEM;
}

size_t ctdb_tunable_list_len(struct ctdb_tunable_list *tun_list)
{
	return sizeof(struct ctdb_tunable_list);
}

void ctdb_tunable_list_push(struct ctdb_tunable_list *tun_list, uint8_t *buf)
{
	memcpy(buf, tun_list, sizeof(struct ctdb_tunable_list));
}

int ctdb_tunable_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			   struct ctdb_tunable_list **out)
{
	struct ctdb_tunable_list *tun_list;

	if (buflen < sizeof(struct ctdb_tunable_list)) {
		return EMSGSIZE;
	}

	tun_list = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_tunable_list));
	if (tun_list == NULL) {
		return ENOMEM;
	}

	*out = tun_list;
	return 0;
}

struct ctdb_tickle_list_wire {
	ctdb_sock_addr addr;
	uint32_t num;
	struct ctdb_connection conn[1];
};

size_t ctdb_tickle_list_len(struct ctdb_tickle_list *tickles)
{
	return offsetof(struct ctdb_tickle_list, conn) +
	       tickles->num * sizeof(struct ctdb_connection);
}

void ctdb_tickle_list_push(struct ctdb_tickle_list *tickles, uint8_t *buf)
{
	struct ctdb_tickle_list_wire *wire =
		(struct ctdb_tickle_list_wire *)buf;
	size_t offset;
	int i;

	memcpy(&wire->addr, &tickles->addr, sizeof(ctdb_sock_addr));
	wire->num = tickles->num;

	offset = offsetof(struct ctdb_tickle_list_wire, conn);
	for (i=0; i<tickles->num; i++) {
		ctdb_connection_push(&tickles->conn[i], &buf[offset]);
		offset += ctdb_connection_len(&tickles->conn[i]);
	}
}

int ctdb_tickle_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			   struct ctdb_tickle_list **out)
{
	struct ctdb_tickle_list *tickles;
	struct ctdb_tickle_list_wire *wire =
		(struct ctdb_tickle_list_wire *)buf;
	size_t offset;
	int i, ret;

	if (buflen < offsetof(struct ctdb_tickle_list_wire, conn)) {
		return EMSGSIZE;
	}
	if (wire->num > buflen / sizeof(struct ctdb_connection)) {
		return EMSGSIZE;
	}
	if (offsetof(struct ctdb_tickle_list_wire, conn) +
	    wire->num * sizeof(struct ctdb_connection) <
	    offsetof(struct ctdb_tickle_list_wire, conn)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_tickle_list_wire, conn) +
		     wire->num * sizeof(struct ctdb_connection)) {
		return EMSGSIZE;
	}

	tickles = talloc(mem_ctx, struct ctdb_tickle_list);
	if (tickles == NULL) {
		return ENOMEM;
	}

	offset = offsetof(struct ctdb_tickle_list, conn);
	memcpy(tickles, wire, offset);

	tickles->conn = talloc_array(tickles, struct ctdb_connection,
				     wire->num);
	if (tickles->conn == NULL) {
		talloc_free(tickles);
		return ENOMEM;
	}

	for (i=0; i<wire->num; i++) {
		ret = ctdb_connection_pull_elems(&buf[offset], buflen-offset,
						 tickles->conn,
						 &tickles->conn[i]);
		if (ret != 0) {
			talloc_free(tickles);
			return ret;
		}
		offset += ctdb_connection_len(&tickles->conn[i]);
	}

	*out = tickles;
	return 0;
}

struct ctdb_addr_info_wire {
	ctdb_sock_addr addr;
	uint32_t mask;
	uint32_t len;
	char iface[1];
};

size_t ctdb_addr_info_len(struct ctdb_addr_info *arp)
{
	uint32_t len;

	len = offsetof(struct ctdb_addr_info_wire, iface);
	if (arp->iface != NULL) {
	       len += strlen(arp->iface)+1;
	}

	return len;
}

void ctdb_addr_info_push(struct ctdb_addr_info *addr_info, uint8_t *buf)
{
	struct ctdb_addr_info_wire *wire = (struct ctdb_addr_info_wire *)buf;

	wire->addr = addr_info->addr;
	wire->mask = addr_info->mask;
	if (addr_info->iface == NULL) {
		wire->len = 0;
	} else {
		wire->len = strlen(addr_info->iface)+1;
		memcpy(wire->iface, addr_info->iface, wire->len);
	}
}

int ctdb_addr_info_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_addr_info **out)
{
	struct ctdb_addr_info *addr_info;
	struct ctdb_addr_info_wire *wire = (struct ctdb_addr_info_wire *)buf;

	if (buflen < offsetof(struct ctdb_addr_info_wire, iface)) {
		return EMSGSIZE;
	}
	if (wire->len > buflen) {
		return EMSGSIZE;
	}
	if (offsetof(struct ctdb_addr_info_wire, iface) + wire->len <
	    offsetof(struct ctdb_addr_info_wire, iface)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_addr_info_wire, iface) + wire->len) {
		return EMSGSIZE;
	}

	addr_info = talloc(mem_ctx, struct ctdb_addr_info);
	if (addr_info == NULL) {
		return ENOMEM;
	}

	addr_info->addr = wire->addr;
	addr_info->mask = wire->mask;

	if (wire->len == 0) {
		addr_info->iface = NULL;
	} else {
		addr_info->iface = talloc_strndup(addr_info, wire->iface,
						  wire->len);
		if (addr_info->iface == NULL) {
			talloc_free(addr_info);
			return ENOMEM;
		}
	}

	*out = addr_info;
	return 0;
}

size_t ctdb_transdb_len(struct ctdb_transdb *transdb)
{
	return sizeof(struct ctdb_transdb);
}

void ctdb_transdb_push(struct ctdb_transdb *transdb, uint8_t *buf)
{
	memcpy(buf, transdb, sizeof(struct ctdb_transdb));
}

int ctdb_transdb_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_transdb **out)
{
	struct ctdb_transdb *transdb;

	if (buflen < sizeof(struct ctdb_transdb)) {
		return EMSGSIZE;
	}

	transdb = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_transdb));
	if (transdb == NULL) {
		return ENOMEM;
	}

	*out = transdb;
	return 0;
}

size_t ctdb_uptime_len(struct ctdb_uptime *uptime)
{
	return sizeof(struct ctdb_uptime);
}

void ctdb_uptime_push(struct ctdb_uptime *uptime, uint8_t *buf)
{
	memcpy(buf, uptime, sizeof(struct ctdb_uptime));
}

int ctdb_uptime_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_uptime **out)
{
	struct ctdb_uptime *uptime;

	if (buflen < sizeof(struct ctdb_uptime)) {
		return EMSGSIZE;
	}

	uptime = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_uptime));
	if (uptime == NULL) {
		return ENOMEM;
	}

	*out = uptime;
	return 0;
}

size_t ctdb_public_ip_len(struct ctdb_public_ip *pubip)
{
	return sizeof(struct ctdb_public_ip);
}

void ctdb_public_ip_push(struct ctdb_public_ip *pubip, uint8_t *buf)
{
	memcpy(buf, pubip, sizeof(struct ctdb_public_ip));
}

static int ctdb_public_ip_pull_elems(uint8_t *buf, size_t buflen,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_public_ip *out)
{
	if (buflen < sizeof(struct ctdb_public_ip)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_public_ip));

	return 0;
}

int ctdb_public_ip_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_public_ip **out)
{
	struct ctdb_public_ip *pubip;
	int ret;

	pubip = talloc(mem_ctx, struct ctdb_public_ip);
	if (pubip == NULL) {
		return ENOMEM;
	}

	ret = ctdb_public_ip_pull_elems(buf, buflen, pubip, pubip);
	if (ret != 0) {
		TALLOC_FREE(pubip);
	}

	*out = pubip;
	return ret;
}

struct ctdb_public_ip_list_wire {
	uint32_t num;
	struct ctdb_public_ip ip[1];
};

size_t ctdb_public_ip_list_len(struct ctdb_public_ip_list *pubip_list)
{
	int i;
	size_t len;

	len = sizeof(uint32_t);
	for (i=0; i<pubip_list->num; i++) {
		len += ctdb_public_ip_len(&pubip_list->ip[i]);
	}
	return len;
}

void ctdb_public_ip_list_push(struct ctdb_public_ip_list *pubip_list,
			      uint8_t *buf)
{
	struct ctdb_public_ip_list_wire *wire =
		(struct ctdb_public_ip_list_wire *)buf;
	size_t offset;
	int i;

	wire->num = pubip_list->num;

	offset = offsetof(struct ctdb_public_ip_list_wire, ip);
	for (i=0; i<pubip_list->num; i++) {
		ctdb_public_ip_push(&pubip_list->ip[i], &buf[offset]);
		offset += ctdb_public_ip_len(&pubip_list->ip[i]);
	}
}

int ctdb_public_ip_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_public_ip_list **out)
{
	struct ctdb_public_ip_list *pubip_list;
	struct ctdb_public_ip_list_wire *wire =
		(struct ctdb_public_ip_list_wire *)buf;
	size_t offset;
	int i;
	bool ret;

	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (wire->num > buflen / sizeof(struct ctdb_public_ip)) {
		return EMSGSIZE;
	}
	if (sizeof(uint32_t) + wire->num * sizeof(struct ctdb_public_ip) <
	    sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(uint32_t) +
		     wire->num * sizeof(struct ctdb_public_ip)) {
		return EMSGSIZE;
	}

	pubip_list = talloc(mem_ctx, struct ctdb_public_ip_list);
	if (pubip_list == NULL) {
		return ENOMEM;
	}

	pubip_list->num = wire->num;
	if (wire->num == 0) {
		pubip_list->ip = NULL;
		*out = pubip_list;
		return 0;
	}
	pubip_list->ip = talloc_array(pubip_list, struct ctdb_public_ip,
				      wire->num);
	if (pubip_list->ip == NULL) {
		talloc_free(pubip_list);
		return ENOMEM;
	}

	offset = offsetof(struct ctdb_public_ip_list_wire, ip);
	for (i=0; i<wire->num; i++) {
		ret = ctdb_public_ip_pull_elems(&buf[offset], buflen-offset,
						pubip_list->ip,
						&pubip_list->ip[i]);
		if (ret != 0) {
			talloc_free(pubip_list);
			return ret;
		}
		offset += ctdb_public_ip_len(&pubip_list->ip[i]);
	}

	*out = pubip_list;
	return 0;
}

size_t ctdb_node_and_flags_len(struct ctdb_node_and_flags *node)
{
	return sizeof(struct ctdb_node_and_flags);
}

void ctdb_node_and_flags_push(struct ctdb_node_and_flags *node, uint8_t *buf)
{
	memcpy(buf, node, sizeof(struct ctdb_node_and_flags));
}

static int ctdb_node_and_flags_pull_elems(TALLOC_CTX *mem_ctx,
					  uint8_t *buf, size_t buflen,
					  struct ctdb_node_and_flags *out)
{
	if (buflen < sizeof(struct ctdb_node_and_flags)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_node_and_flags));

	return 0;
}

int ctdb_node_and_flags_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			      struct ctdb_node_and_flags **out)
{
	struct ctdb_node_and_flags *node;
	int ret;

	node = talloc(mem_ctx, struct ctdb_node_and_flags);
	if (node == NULL) {
		return ENOMEM;
	}

	ret = ctdb_node_and_flags_pull_elems(node, buf, buflen, node);
	if (ret != 0) {
		TALLOC_FREE(node);
	}

	*out = node;
	return ret;
}

struct ctdb_node_map_wire {
	uint32_t num;
	struct ctdb_node_and_flags node[1];
};

size_t ctdb_node_map_len(struct ctdb_node_map *nodemap)
{
	return sizeof(uint32_t) +
	       nodemap->num * sizeof(struct ctdb_node_and_flags);
}

void ctdb_node_map_push(struct ctdb_node_map *nodemap, uint8_t *buf)
{
	struct ctdb_node_map_wire *wire = (struct ctdb_node_map_wire *)buf;
	size_t offset;
	int i;

	wire->num = nodemap->num;

	offset = offsetof(struct ctdb_node_map_wire, node);
	for (i=0; i<nodemap->num; i++) {
		ctdb_node_and_flags_push(&nodemap->node[i], &buf[offset]);
		offset += ctdb_node_and_flags_len(&nodemap->node[i]);
	}
}

int ctdb_node_map_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_node_map **out)
{
	struct ctdb_node_map *nodemap;
	struct ctdb_node_map_wire *wire = (struct ctdb_node_map_wire *)buf;
	size_t offset;
	int i;
	bool ret;

	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (wire->num > buflen / sizeof(struct ctdb_node_and_flags)) {
		return EMSGSIZE;
	}
	if (sizeof(uint32_t) + wire->num * sizeof(struct ctdb_node_and_flags) <
	    sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(uint32_t) +
		     wire->num * sizeof(struct ctdb_node_and_flags)) {
		return EMSGSIZE;
	}

	nodemap = talloc(mem_ctx, struct ctdb_node_map);
	if (nodemap == NULL) {
		return ENOMEM;
	}

	nodemap->num = wire->num;
	nodemap->node = talloc_array(nodemap, struct ctdb_node_and_flags,
				     wire->num);
	if (nodemap->node == NULL) {
		talloc_free(nodemap);
		return ENOMEM;
	}

	offset = offsetof(struct ctdb_node_map_wire, node);
	for (i=0; i<wire->num; i++) {
		ret = ctdb_node_and_flags_pull_elems(nodemap->node,
						     &buf[offset],
						     buflen-offset,
						     &nodemap->node[i]);
		if (ret != 0) {
			talloc_free(nodemap);
			return ret;
		}
		offset += ctdb_node_and_flags_len(&nodemap->node[i]);
	}

	*out = nodemap;
	return 0;
}

size_t ctdb_script_len(struct ctdb_script *script)
{
	return sizeof(struct ctdb_script);
}

void ctdb_script_push(struct ctdb_script *script, uint8_t *buf)
{
	memcpy(buf, script, sizeof(struct ctdb_script));
}

static int ctdb_script_pull_elems(uint8_t *buf, size_t buflen,
				  TALLOC_CTX *mem_ctx,
				  struct ctdb_script *out)
{
	if (buflen < sizeof(struct ctdb_script)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_script));

	return 0;
}

int ctdb_script_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_script **out)
{
	struct ctdb_script *script;
	int ret;

	script = talloc(mem_ctx, struct ctdb_script);
	if (script == NULL) {
		return ENOMEM;
	}

	ret = ctdb_script_pull_elems(buf, buflen, script, script);
	if (ret != 0) {
		TALLOC_FREE(script);
	}

	*out = script;
	return ret;
}

struct ctdb_script_list_wire {
	uint32_t num_scripts;
	struct ctdb_script script[1];
};

size_t ctdb_script_list_len(struct ctdb_script_list *script_list)
{
	int i;
	size_t len;

	if (script_list == NULL) {
		return 0;
	}

	len = offsetof(struct ctdb_script_list_wire, script);
	for (i=0; i<script_list->num_scripts; i++) {
		len += ctdb_script_len(&script_list->script[i]);
	}
	return len;
}

void ctdb_script_list_push(struct ctdb_script_list *script_list, uint8_t *buf)
{
	struct ctdb_script_list_wire *wire =
		(struct ctdb_script_list_wire *)buf;
	size_t offset;
	int i;

	if (script_list == NULL) {
		return;
	}

	wire->num_scripts = script_list->num_scripts;

	offset = offsetof(struct ctdb_script_list_wire, script);
	for (i=0; i<script_list->num_scripts; i++) {
		ctdb_script_push(&script_list->script[i], &buf[offset]);
		offset += ctdb_script_len(&script_list->script[i]);
	}
}

int ctdb_script_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_script_list **out)
{
	struct ctdb_script_list *script_list;
	struct ctdb_script_list_wire *wire =
		(struct ctdb_script_list_wire *)buf;
	size_t offset;
	int i;
	bool ret;

	/* If event scripts have never been run, the result will be NULL */
	if (buflen == 0) {
		*out = NULL;
		return 0;
	}

	offset = offsetof(struct ctdb_script_list_wire, script);

	if (buflen < offset) {
		return EMSGSIZE;
	}
	if (wire->num_scripts > buflen / sizeof(struct ctdb_script)) {
		return EMSGSIZE;
	}
	if (offset + wire->num_scripts * sizeof(struct ctdb_script) < offset) {
		return EMSGSIZE;
	}
	if (buflen < offset + wire->num_scripts * sizeof(struct ctdb_script)) {
		return EMSGSIZE;
	}

	script_list = talloc(mem_ctx, struct ctdb_script_list);
	if (script_list == NULL) {
		return ENOMEM;

	}

	script_list->num_scripts = wire->num_scripts;
	script_list->script = talloc_array(script_list, struct ctdb_script,
					   wire->num_scripts);
	if (script_list->script == NULL) {
		talloc_free(script_list);
		return ENOMEM;
	}

	for (i=0; i<wire->num_scripts; i++) {
		ret = ctdb_script_pull_elems(&buf[offset], buflen-offset,
					     script_list->script,
					     &script_list->script[i]);
		if (ret != 0) {
			talloc_free(script_list);
			return ret;
		}
		offset += ctdb_script_len(&script_list->script[i]);
	}

	*out = script_list;
	return 0;
}

size_t ctdb_ban_state_len(struct ctdb_ban_state *ban_state)
{
	return sizeof(struct ctdb_ban_state);
}

void ctdb_ban_state_push(struct ctdb_ban_state *ban_state, uint8_t *buf)
{
	memcpy(buf, ban_state, sizeof(struct ctdb_ban_state));
}

int ctdb_ban_state_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_ban_state **out)
{
	struct ctdb_ban_state *ban_state;

	if (buflen < sizeof(struct ctdb_ban_state)) {
		return EMSGSIZE;
	}

	ban_state = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_ban_state));
	if (ban_state == NULL) {
		return ENOMEM;
	}

	*out = ban_state;
	return 0;
}

struct ctdb_notify_data_wire {
	uint64_t srvid;
	uint32_t len;
	uint8_t data[1];
};

size_t ctdb_notify_data_len(struct ctdb_notify_data *notify)
{
	return offsetof(struct ctdb_notify_data_wire, data) +
	       notify->data.dsize;
}

void ctdb_notify_data_push(struct ctdb_notify_data *notify, uint8_t *buf)
{
	struct ctdb_notify_data_wire *wire =
		(struct ctdb_notify_data_wire *)buf;

	wire->srvid = notify->srvid;
	wire->len = notify->data.dsize;
	memcpy(wire->data, notify->data.dptr, notify->data.dsize);
}

int ctdb_notify_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_notify_data **out)
{
	struct ctdb_notify_data *notify;
	struct ctdb_notify_data_wire *wire =
		(struct ctdb_notify_data_wire *)buf;

	if (buflen < offsetof(struct ctdb_notify_data_wire, data)) {
		return EMSGSIZE;
	}
	if (wire->len > buflen) {
		return EMSGSIZE;
	}
	if (offsetof(struct ctdb_notify_data_wire, data) + wire->len <
	    offsetof(struct ctdb_notify_data_wire, data)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_notify_data_wire, data) + wire->len) {
		return EMSGSIZE;
	}

	notify = talloc(mem_ctx, struct ctdb_notify_data);
	if (notify == NULL) {
		return ENOMEM;
	}

	notify->srvid = wire->srvid;
	notify->data.dsize = wire->len;
	notify->data.dptr = talloc_memdup(notify, wire->data, wire->len);
	if (notify->data.dptr == NULL) {
		talloc_free(notify);
		return ENOMEM;
	}

	*out = notify;
	return 0;
}

size_t ctdb_iface_len(struct ctdb_iface *iface)
{
	return sizeof(struct ctdb_iface);
}

void ctdb_iface_push(struct ctdb_iface *iface, uint8_t *buf)
{
	memcpy(buf, iface, sizeof(struct ctdb_iface));
}

static int ctdb_iface_pull_elems(uint8_t *buf, size_t buflen,
				 TALLOC_CTX *mem_ctx,
				 struct ctdb_iface *out)
{
	if (buflen < sizeof(struct ctdb_iface)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_iface));

	return 0;
}

int ctdb_iface_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		    struct ctdb_iface **out)
{
	struct ctdb_iface *iface;
	int ret;

	iface = talloc(mem_ctx, struct ctdb_iface);
	if (iface == NULL) {
		return ENOMEM;
	}

	ret = ctdb_iface_pull_elems(buf, buflen, iface, iface);
	if (ret != 0) {
		TALLOC_FREE(iface);
	}

	*out = iface;
	return ret;
}

struct ctdb_iface_list_wire {
	uint32_t num;
	struct ctdb_iface iface[1];
};

size_t ctdb_iface_list_len(struct ctdb_iface_list *iface_list)
{
	return sizeof(uint32_t) +
	       iface_list->num * sizeof(struct ctdb_iface);
}

void ctdb_iface_list_push(struct ctdb_iface_list *iface_list, uint8_t *buf)
{
	struct ctdb_iface_list_wire *wire =
		(struct ctdb_iface_list_wire *)buf;

	wire->num = iface_list->num;
	memcpy(wire->iface, iface_list->iface,
	       iface_list->num * sizeof(struct ctdb_iface));
}

int ctdb_iface_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_iface_list **out)
{
	struct ctdb_iface_list *iface_list;
	struct ctdb_iface_list_wire *wire =
		(struct ctdb_iface_list_wire *)buf;

	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (wire->num > buflen / sizeof(struct ctdb_iface)) {
		return EMSGSIZE;
	}
	if (sizeof(uint32_t) + wire->num * sizeof(struct ctdb_iface) <
	    sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(uint32_t) + wire->num * sizeof(struct ctdb_iface)) {
		return EMSGSIZE;
	}

	iface_list = talloc(mem_ctx, struct ctdb_iface_list);
	if (iface_list == NULL) {
		return ENOMEM;
	}

	iface_list->num = wire->num;
	iface_list->iface = talloc_array(iface_list, struct ctdb_iface,
					 wire->num);
	if (iface_list->iface == NULL) {
		talloc_free(iface_list);
		return ENOMEM;
	}

	memcpy(iface_list->iface, wire->iface,
	       wire->num * sizeof(struct ctdb_iface));

	*out = iface_list;
	return 0;
}

struct ctdb_public_ip_info_wire {
	struct ctdb_public_ip ip;
	uint32_t active_idx;
	uint32_t num;
	struct ctdb_iface ifaces[1];
};

size_t ctdb_public_ip_info_len(struct ctdb_public_ip_info *ipinfo)
{
	return offsetof(struct ctdb_public_ip_info_wire, num) +
	       ctdb_iface_list_len(ipinfo->ifaces);
}

void ctdb_public_ip_info_push(struct ctdb_public_ip_info *ipinfo, uint8_t *buf)
{
	struct ctdb_public_ip_info_wire *wire =
		(struct ctdb_public_ip_info_wire *)buf;
	size_t offset;

	offset = offsetof(struct ctdb_public_ip_info_wire, num);
	memcpy(wire, ipinfo, offset);
	wire->num = ipinfo->ifaces->num;
	memcpy(wire->ifaces, ipinfo->ifaces->iface,
	       ipinfo->ifaces->num * sizeof(struct ctdb_iface));
}

int ctdb_public_ip_info_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_public_ip_info **out)
{
	struct ctdb_public_ip_info *ipinfo;
	struct ctdb_public_ip_info_wire *wire =
		(struct ctdb_public_ip_info_wire *)buf;

	if (buflen < offsetof(struct ctdb_public_ip_info_wire, ifaces)) {
		return EMSGSIZE;
	}
	if (wire->num > buflen / sizeof(struct ctdb_iface)) {
		return EMSGSIZE;
	}
	if (offsetof(struct ctdb_public_ip_info_wire, ifaces) +
	    wire->num * sizeof(struct ctdb_iface) <
	    offsetof(struct ctdb_public_ip_info_wire, ifaces)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_public_ip_info_wire, ifaces) +
		     wire->num * sizeof(struct ctdb_iface)) {
		return EMSGSIZE;
	}

	ipinfo = talloc(mem_ctx, struct ctdb_public_ip_info);
	if (ipinfo == NULL) {
		return ENOMEM;
	}

	memcpy(ipinfo, wire, offsetof(struct ctdb_public_ip_info_wire, num));

	ipinfo->ifaces = talloc(ipinfo, struct ctdb_iface_list);
	if (ipinfo->ifaces == NULL) {
		talloc_free(ipinfo);
		return ENOMEM;
	}

	ipinfo->ifaces->num = wire->num;
	ipinfo->ifaces->iface = talloc_array(ipinfo->ifaces, struct ctdb_iface,
					     wire->num);
	if (ipinfo->ifaces->iface == NULL) {
		talloc_free(ipinfo);
		return ENOMEM;
	}

	memcpy(ipinfo->ifaces->iface, wire->ifaces,
	       wire->num * sizeof(struct ctdb_iface));

	*out = ipinfo;
	return 0;
}

struct ctdb_key_data_wire {
	uint32_t db_id;
	struct ctdb_ltdb_header header;
	uint32_t keylen;
	uint8_t key[1];
};

size_t ctdb_key_data_len(struct ctdb_key_data *key)
{
	return offsetof(struct ctdb_key_data_wire, key) + key->key.dsize;
}

void ctdb_key_data_push(struct ctdb_key_data *key, uint8_t *buf)
{
	struct ctdb_key_data_wire *wire = (struct ctdb_key_data_wire *)buf;

	memcpy(wire, key, offsetof(struct ctdb_key_data, key));
	wire->keylen = key->key.dsize;
	memcpy(wire->key, key->key.dptr, key->key.dsize);
}

int ctdb_key_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_key_data **out)
{
	struct ctdb_key_data *key_data;
	struct ctdb_key_data_wire *wire = (struct ctdb_key_data_wire *)buf;

	if (buflen < offsetof(struct ctdb_key_data_wire, key)) {
		return EMSGSIZE;
	}
	if (wire->keylen > buflen) {
		return EMSGSIZE;
	}
	if (offsetof(struct ctdb_key_data_wire, key) + wire->keylen <
	    offsetof(struct ctdb_key_data_wire, key)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_key_data_wire, key) + wire->keylen) {
		return EMSGSIZE;
	}

	key_data = talloc(mem_ctx, struct ctdb_key_data);
	if (key_data == NULL) {
		return ENOMEM;
	}

	memcpy(key_data, wire, offsetof(struct ctdb_key_data, key));

	key_data->key.dsize = wire->keylen;
	key_data->key.dptr = talloc_memdup(key_data, wire->key, wire->keylen);
	if (key_data->key.dptr == NULL) {
		talloc_free(key_data);
		return ENOMEM;
	}

	*out = key_data;
	return 0;
}

struct ctdb_db_statistics_wire {
	struct ctdb_db_statistics dbstats;
	char hot_keys_wire[1];
};

size_t ctdb_db_statistics_len(struct ctdb_db_statistics *dbstats)
{
	size_t len;
	int i;

	len = sizeof(struct ctdb_db_statistics);
	for (i=0; i<MAX_HOT_KEYS; i++) {
		len += dbstats->hot_keys[i].key.dsize;
	}
	return len;
}

void ctdb_db_statistics_push(struct ctdb_db_statistics *dbstats, void *buf)
{
	struct ctdb_db_statistics_wire *wire =
		(struct ctdb_db_statistics_wire *)buf;
	size_t offset;
	int i;

	dbstats->num_hot_keys = MAX_HOT_KEYS;
	memcpy(wire, dbstats, sizeof(struct ctdb_db_statistics));

	offset = 0;
	for (i=0; i<MAX_HOT_KEYS; i++) {
		memcpy(&wire->hot_keys_wire[offset],
		       dbstats->hot_keys[i].key.dptr,
		       dbstats->hot_keys[i].key.dsize);
		offset += dbstats->hot_keys[i].key.dsize;
	}
}

int ctdb_db_statistics_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			    struct ctdb_db_statistics **out)
{
	struct ctdb_db_statistics *dbstats;
	struct ctdb_db_statistics_wire *wire =
		(struct ctdb_db_statistics_wire *)buf;
	size_t offset;
	int i;

	if (buflen < sizeof(struct ctdb_db_statistics)) {
		return EMSGSIZE;
	}

	offset = 0;
	for (i=0; i<wire->dbstats.num_hot_keys; i++) {
		if (wire->dbstats.hot_keys[i].key.dsize > buflen) {
			return EMSGSIZE;
		}
		if (offset + wire->dbstats.hot_keys[i].key.dsize < offset) {
			return EMSGSIZE;
		}
		offset += wire->dbstats.hot_keys[i].key.dsize;
		if (offset > buflen) {
			return EMSGSIZE;
		}
	}
	if (sizeof(struct ctdb_db_statistics) + offset <
	    sizeof(struct ctdb_db_statistics)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(struct ctdb_db_statistics) + offset) {
		return EMSGSIZE;
	}

	dbstats = talloc(mem_ctx, struct ctdb_db_statistics);
	if (dbstats == NULL) {
		return ENOMEM;
	}

	memcpy(dbstats, wire, sizeof(struct ctdb_db_statistics));

	offset = 0;
	for (i=0; i<wire->dbstats.num_hot_keys; i++) {
		uint8_t *ptr;
		size_t key_size;

		key_size = dbstats->hot_keys[i].key.dsize;
		ptr = talloc_memdup(mem_ctx, &wire->hot_keys_wire[offset],
				    key_size);
		if (ptr == NULL) {
			talloc_free(dbstats);
			return ENOMEM;
		}
		dbstats->hot_keys[i].key.dptr = ptr;
		offset += key_size;
	}

	*out = dbstats;
	return 0;
}

size_t ctdb_election_message_len(struct ctdb_election_message *election)
{
	return sizeof(struct ctdb_election_message);
}

void ctdb_election_message_push(struct ctdb_election_message *election,
				uint8_t *buf)
{
	memcpy(buf, election, sizeof(struct ctdb_election_message));
}

int ctdb_election_message_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			       struct ctdb_election_message **out)
{
	struct ctdb_election_message *election;

	if (buflen < sizeof(struct ctdb_election_message)) {
		return EMSGSIZE;
	}

	election = talloc_memdup(mem_ctx, buf,
				 sizeof(struct ctdb_election_message));
	if (election == NULL) {
		return ENOMEM;
	}

	*out = election;
	return 0;
}

size_t ctdb_srvid_message_len(struct ctdb_srvid_message *msg)
{
	return sizeof(struct ctdb_srvid_message);
}

void ctdb_srvid_message_push(struct ctdb_srvid_message *msg, uint8_t *buf)
{
	memcpy(buf, msg, sizeof(struct ctdb_srvid_message));
}

int ctdb_srvid_message_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			    struct ctdb_srvid_message **out)
{
	struct ctdb_srvid_message *msg;

	if (buflen < sizeof(struct ctdb_srvid_message)) {
		return EMSGSIZE;
	}

	msg = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_srvid_message));
	if (msg == NULL) {
		return ENOMEM;
	}

	*out = msg;
	return 0;
}

size_t ctdb_disable_message_len(struct ctdb_disable_message *disable)
{
	return sizeof(struct ctdb_disable_message);
}

void ctdb_disable_message_push(struct ctdb_disable_message *disable,
			       uint8_t *buf)
{
	memcpy(buf, disable, sizeof(struct ctdb_disable_message));
}

int ctdb_disable_message_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			      struct ctdb_disable_message **out)
{
	struct ctdb_disable_message *disable;

	if (buflen < sizeof(struct ctdb_disable_message)) {
		return EMSGSIZE;
	}

	disable = talloc_memdup(mem_ctx, buf,
				sizeof(struct ctdb_disable_message));
	if (disable == NULL) {
		return ENOMEM;
	}

	*out = disable;
	return 0;
}

size_t ctdb_server_id_len(struct ctdb_server_id *sid)
{
	return sizeof(struct ctdb_server_id);
}

void ctdb_server_id_push(struct ctdb_server_id *sid, uint8_t *buf)
{
	memcpy(buf, sid, sizeof(struct ctdb_server_id));
}

int ctdb_server_id_pull(uint8_t *buf, size_t buflen,
			struct ctdb_server_id *sid)
{
	if (buflen < sizeof(struct ctdb_server_id)) {
		return EMSGSIZE;
	}

	memcpy(sid, buf, sizeof(struct ctdb_server_id));
	return 0;
}

size_t ctdb_g_lock_len(struct ctdb_g_lock *lock)
{
	return sizeof(struct ctdb_g_lock);
}

void ctdb_g_lock_push(struct ctdb_g_lock *lock, uint8_t *buf)
{
	memcpy(buf, lock, sizeof(struct ctdb_g_lock));
}

int ctdb_g_lock_pull(uint8_t *buf, size_t buflen, struct ctdb_g_lock *lock)
{
	if (buflen < sizeof(struct ctdb_g_lock)) {
		return EMSGSIZE;
	}

	memcpy(lock, buf, sizeof(struct ctdb_g_lock));
	return 0;
}

size_t ctdb_g_lock_list_len(struct ctdb_g_lock_list *lock_list)
{
	return lock_list->num * sizeof(struct ctdb_g_lock);
}

void ctdb_g_lock_list_push(struct ctdb_g_lock_list *lock_list, uint8_t *buf)
{
	size_t offset = 0;
	int i;

	for (i=0; i<lock_list->num; i++) {
		ctdb_g_lock_push(&lock_list->lock[i], &buf[offset]);
		offset += sizeof(struct ctdb_g_lock);
	}
}

int ctdb_g_lock_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_g_lock_list **out)
{
	struct ctdb_g_lock_list *lock_list;
	unsigned count;
	size_t offset;
	int ret, i;

	lock_list = talloc_zero(mem_ctx, struct ctdb_g_lock_list);
	if (lock_list == NULL) {
		return ENOMEM;
	}

	count = buflen / sizeof(struct ctdb_g_lock);
	lock_list->lock = talloc_array(lock_list, struct ctdb_g_lock, count);
	if (lock_list->lock == NULL) {
		talloc_free(lock_list);
		return ENOMEM;
	}

	offset = 0;
	for (i=0; i<count; i++) {
		ret = ctdb_g_lock_pull(&buf[offset], buflen-offset,
				       &lock_list->lock[i]);
		if (ret != 0) {
			talloc_free(lock_list);
			return ret;
		}
		offset += sizeof(struct ctdb_g_lock);
	}

	lock_list->num = count;

	*out = lock_list;
	return 0;
}
