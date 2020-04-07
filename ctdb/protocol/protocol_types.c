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
		ctdb_uint32_len(&in->node.req_tunnel) +
		ctdb_uint32_len(&in->client.req_call) +
		ctdb_uint32_len(&in->client.req_message) +
		ctdb_uint32_len(&in->client.req_control) +
		ctdb_uint32_len(&in->client.req_tunnel) +
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

	ctdb_uint32_push(&in->node.req_tunnel, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->client.req_call, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->client.req_message, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->client.req_control, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->client.req_tunnel, buf+offset, &np);
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
			       &out->node.req_tunnel, &np);
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
			       &out->client.req_tunnel, &np);
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

size_t ctdb_statistics_list_len(struct ctdb_statistics_list *in)
{
	size_t len;

	len = ctdb_int32_len(&in->num) + ctdb_padding_len(4);
	if (in->num > 0) {
		len += in->num * ctdb_statistics_len(&in->stats[0]);
	}

	return len;
}

void ctdb_statistics_list_push(struct ctdb_statistics_list *in,
			       uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;
	int i;

	ctdb_int32_push(&in->num, buf+offset, &np);
	offset += np;

	ctdb_padding_push(4, buf+offset, &np);
	offset += np;

	for (i=0; i<in->num; i++) {
		ctdb_statistics_push(&in->stats[i], buf+offset, &np);
		offset += np;
	}

	*npush = offset;
}

int ctdb_statistics_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			      struct ctdb_statistics_list **out,
			      size_t *npull)
{
	struct ctdb_statistics_list *val;
	size_t offset = 0, np;
	int ret, i;

	val = talloc(mem_ctx, struct ctdb_statistics_list);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_int32_pull(buf+offset, buflen-offset, &val->num, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 4, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	if (val->num == 0) {
		val->stats = NULL;
		goto done;
	}

	val->stats = talloc_array(val, struct ctdb_statistics, val->num);
	if (val->stats == NULL) {
		ret = ENOMEM;
		goto fail;
	}

	for (i=0; i<val->num; i++) {
		ret = ctdb_statistics_pull_elems(buf+offset, buflen-offset,
						 val, &val->stats[i], &np);
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

size_t ctdb_db_vacuum_len(struct ctdb_db_vacuum *in)
{
	return ctdb_uint32_len(&in->db_id) +
		ctdb_bool_len(&in->full_vacuum_run);
}

void ctdb_db_vacuum_push(struct ctdb_db_vacuum *in,
			 uint8_t *buf,
			 size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->db_id, buf+offset, &np);
	offset += np;

	ctdb_bool_push(&in->full_vacuum_run, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_db_vacuum_pull(uint8_t *buf,
			size_t buflen,
			TALLOC_CTX *mem_ctx,
			struct ctdb_db_vacuum **out,
			size_t *npull)
{
	struct ctdb_db_vacuum *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_db_vacuum);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset,
			       buflen-offset,
			       &val->db_id,
			       &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_bool_pull(buf+offset,
			     buflen-offset,
			     &val->full_vacuum_run,
			     &np);
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

size_t ctdb_echo_data_len(struct ctdb_echo_data *in)
{
	/*
	 * No overflow check, none of the routines in this file do it
	 * and there's no way to report it anyway.
	 */
	return ctdb_uint32_len(&in->timeout) + ctdb_tdb_datan_len(&in->buf);
}

void ctdb_echo_data_push(struct ctdb_echo_data *in,
			 uint8_t *buf,
			 size_t *npush)
{
	size_t offset = 0, np;

	/*
	 * No overflow check, none of the routines in this file do it
	 * and there's no way to report it anyway.
	 */

	ctdb_uint32_push(&in->timeout, buf+offset, &np);
	offset += np;

	ctdb_tdb_datan_push(&in->buf, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_echo_data_pull(uint8_t *buf,
			size_t buflen,
			TALLOC_CTX *mem_ctx,
			struct ctdb_echo_data **out,
			size_t *npull)
{
	struct ctdb_echo_data *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_echo_data);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset,
			       buflen-offset,
			       &val->timeout,
			       &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_tdb_datan_pull(buf+offset,
				  buflen-offset,
				  val,
				  &val->buf,
				  &np);
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
	unsigned int i;
	int ret = 0;

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
	if (n == -1 || (size_t)n != sizeof(uint32_t)) {
		return (errno != 0 ? errno : EIO);
	}
	n = write(fd, &recbuf->count, sizeof(uint32_t));
	if (n == -1 || (size_t)n != sizeof(uint32_t)) {
		return (errno != 0 ? errno : EIO);
	}
	n = write(fd, &recbuf->buflen, sizeof(size_t));
	if (n == -1 || (size_t)n != sizeof(size_t)) {
		return (errno != 0 ? errno : EIO);
	}
	n = write(fd, recbuf->buf, recbuf->buflen);
	if (n == -1 || (size_t)n != recbuf->buflen) {
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
	if (n == -1 || (size_t)n != sizeof(uint32_t)) {
		return (errno != 0 ? errno : EIO);
	}
	n = read(fd, &recbuf->count, sizeof(uint32_t));
	if (n == -1 || (size_t)n != sizeof(uint32_t)) {
		return (errno != 0 ? errno : EIO);
	}
	n = read(fd, &recbuf->buflen, sizeof(size_t));
	if (n == -1 || (size_t)n != sizeof(size_t)) {
		return (errno != 0 ? errno : EIO);
	}

	recbuf->buf = talloc_size(recbuf, recbuf->buflen);
	if (recbuf->buf == NULL) {
		return ENOMEM;
	}

	n = read(fd, recbuf->buf, recbuf->buflen);
	if (n == -1 || (size_t)n != recbuf->buflen) {
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

size_t ctdb_traverse_start_ext_len(struct ctdb_traverse_start_ext *in)
{
	return ctdb_uint32_len(&in->db_id) +
		ctdb_uint32_len(&in->reqid) +
		ctdb_uint64_len(&in->srvid) +
		ctdb_bool_len(&in->withemptyrecords) +
		ctdb_padding_len(7);
}

void ctdb_traverse_start_ext_push(struct ctdb_traverse_start_ext *in,
				  uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->db_id, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->reqid, buf+offset, &np);
	offset += np;

	ctdb_uint64_push(&in->srvid, buf+offset, &np);
	offset += np;

	ctdb_bool_push(&in->withemptyrecords, buf+offset, &np);
	offset += np;

	ctdb_padding_push(7, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_traverse_start_ext_pull(uint8_t *buf, size_t buflen,
				 TALLOC_CTX *mem_ctx,
				 struct ctdb_traverse_start_ext **out,
				 size_t *npull)
{
	struct ctdb_traverse_start_ext *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_traverse_start_ext);
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

	ret = ctdb_bool_pull(buf+offset, buflen-offset,
			     &val->withemptyrecords, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 7, &np);
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

size_t ctdb_traverse_all_ext_len(struct ctdb_traverse_all_ext *in)
{
	return ctdb_uint32_len(&in->db_id) +
		ctdb_uint32_len(&in->reqid) +
		ctdb_uint32_len(&in->pnn) +
		ctdb_uint32_len(&in->client_reqid) +
		ctdb_uint64_len(&in->srvid) +
		ctdb_bool_len(&in->withemptyrecords) +
		ctdb_padding_len(7);
}

void ctdb_traverse_all_ext_push(struct ctdb_traverse_all_ext *in,
				uint8_t *buf, size_t *npush)
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

	ctdb_bool_push(&in->withemptyrecords, buf+offset, &np);
	offset += np;

	ctdb_padding_push(7, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_traverse_all_ext_pull(uint8_t *buf, size_t buflen,
			       TALLOC_CTX *mem_ctx,
			       struct ctdb_traverse_all_ext **out,
			       size_t *npull)
{
	struct ctdb_traverse_all_ext *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_traverse_all_ext);
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

	ret = ctdb_bool_pull(buf+offset, buflen-offset,
			     &val->withemptyrecords, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 7, &np);
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

size_t ctdb_sock_addr_len(ctdb_sock_addr *in)
{
	return sizeof(ctdb_sock_addr);
}

void ctdb_sock_addr_push(ctdb_sock_addr *in, uint8_t *buf, size_t *npush)
{
	memcpy(buf, in, sizeof(ctdb_sock_addr));
	*npush = sizeof(ctdb_sock_addr);
}

int ctdb_sock_addr_pull_elems(uint8_t *buf, size_t buflen,
			      TALLOC_CTX *mem_ctx, ctdb_sock_addr *out,
			      size_t *npull)
{
	if (buflen < sizeof(ctdb_sock_addr)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(ctdb_sock_addr));
	*npull = sizeof(ctdb_sock_addr);

	return 0;
}

int ctdb_sock_addr_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			ctdb_sock_addr **out, size_t *npull)
{
	ctdb_sock_addr *val;
	size_t np;
	int ret;

	val = talloc(mem_ctx, ctdb_sock_addr);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_sock_addr_pull_elems(buf, buflen, val, val, &np);
	if (ret != 0) {
		talloc_free(val);
		return ret;
	}

	*out = val;
	*npull = np;
	return ret;
}

size_t ctdb_connection_len(struct ctdb_connection *in)
{
	return ctdb_sock_addr_len(&in->src) +
		ctdb_sock_addr_len(&in->dst);
}

void ctdb_connection_push(struct ctdb_connection *in, uint8_t *buf,
			  size_t *npush)
{
	size_t offset = 0, np;

	ctdb_sock_addr_push(&in->src, buf+offset, &np);
	offset += np;

	ctdb_sock_addr_push(&in->dst, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_connection_pull_elems(uint8_t *buf, size_t buflen,
				      TALLOC_CTX *mem_ctx,
				      struct ctdb_connection *out,
				      size_t *npull)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_sock_addr_pull_elems(buf+offset, buflen-offset,
					mem_ctx, &out->src, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_sock_addr_pull_elems(buf+offset, buflen-offset,
					mem_ctx, &out->dst, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	*npull = offset;
	return 0;
}

int ctdb_connection_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_connection **out, size_t *npull)
{
	struct ctdb_connection *val;
	size_t np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_connection);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_connection_pull_elems(buf, buflen, val, val, &np);
	if (ret != 0) {
		talloc_free(val);
		return ret;
	}

	*out = val;
	*npull = np;
	return ret;
}

size_t ctdb_connection_list_len(struct ctdb_connection_list *in)
{
	size_t len;

	len = ctdb_uint32_len(&in->num);
	if (in->num > 0) {
		len += in->num * ctdb_connection_len(&in->conn[0]);
	}

	return len;
}

void ctdb_connection_list_push(struct ctdb_connection_list *in, uint8_t *buf,
			       size_t *npush)
{
	size_t offset = 0, np;
	uint32_t i;

	ctdb_uint32_push(&in->num, buf+offset, &np);
	offset += np;

	for (i=0; i<in->num; i++) {
		ctdb_connection_push(&in->conn[i], buf+offset, &np);
		offset += np;
	}

	*npush = offset;
}

int ctdb_connection_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			      struct ctdb_connection_list **out, size_t *npull)
{
	struct ctdb_connection_list *val;
	size_t offset = 0, np;
	uint32_t i;
	int ret;

	val = talloc(mem_ctx, struct ctdb_connection_list);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->num, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	if (val->num == 0) {
		val->conn = NULL;
		goto done;
	}

	val->conn = talloc_array(val, struct ctdb_connection, val->num);
	if (val->conn == NULL) {
		ret = ENOMEM;
		goto fail;
	}

	for (i=0; i<val->num; i++) {
		ret = ctdb_connection_pull_elems(buf+offset, buflen-offset,
						 val, &val->conn[i], &np);
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

size_t ctdb_tunable_len(struct ctdb_tunable *in)
{
	return ctdb_uint32_len(&in->value) +
		ctdb_stringn_len(&in->name);
}

void ctdb_tunable_push(struct ctdb_tunable *in, uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->value, buf+offset, &np);
	offset += np;

	ctdb_stringn_push(&in->name, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_tunable_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		      struct ctdb_tunable **out, size_t *npull)
{
	struct ctdb_tunable *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_tunable);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->value, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_stringn_pull(buf+offset, buflen-offset, mem_ctx,
				&val->name, &np);
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

size_t ctdb_node_flag_change_len(struct ctdb_node_flag_change *in)
{
	return ctdb_uint32_len(&in->pnn) +
		ctdb_uint32_len(&in->new_flags) +
		ctdb_uint32_len(&in->old_flags);
}

void ctdb_node_flag_change_push(struct ctdb_node_flag_change *in,
				uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->pnn, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->new_flags, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->old_flags, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_node_flag_change_pull(uint8_t *buf, size_t buflen,
			       TALLOC_CTX *mem_ctx,
			       struct ctdb_node_flag_change **out,
			       size_t *npull)
{
	struct ctdb_node_flag_change *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_node_flag_change);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->pnn, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->new_flags,
			       &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->old_flags,
			       &np);
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

size_t ctdb_var_list_len(struct ctdb_var_list *in)
{
	uint32_t u32 = 0;
	int i;

	for (i=0; i<in->count; i++) {
		u32 += ctdb_string_len(&in->var[i]);
	}

	return ctdb_uint32_len(&u32) + u32;
}

void ctdb_var_list_push(struct ctdb_var_list *in, uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;
	uint32_t u32;
	int i;
	uint8_t sep = ':';

	/* The length only corresponds to the payload size */
	u32 = ctdb_var_list_len(in);
	u32 -= ctdb_uint32_len(&u32);

	ctdb_uint32_push(&u32, buf+offset, &np);
	offset += np;

	/* The variables are separated by ':' and the complete string is null
	 * terminated.
	 */
	for (i=0; i<in->count; i++) {
		ctdb_string_push(&in->var[i], buf+offset, &np);
		offset += np;

		if (i < in->count - 1) {
			/* Replace '\0' with ':' */
			ctdb_uint8_push(&sep, buf+offset-1, &np);
		}
	}

	*npush = offset;
}

int ctdb_var_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_var_list **out, size_t *npull)
{
	struct ctdb_var_list *val;
	const char *str, **list;
	char *s, *tok, *ptr = NULL;
	size_t offset = 0, np;
	uint32_t u32;
	int ret;

	val = talloc_zero(mem_ctx, struct ctdb_var_list);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &u32, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	if (buflen-offset < u32) {
		ret = EMSGSIZE;
		goto fail;
	}

	ret = ctdb_string_pull(buf+offset, u32, val, &str, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	s = discard_const(str);
	while ((tok = strtok_r(s, ":", &ptr)) != NULL) {
		list = talloc_realloc(val, val->var, const char *,
				      val->count+1);
		if (list == NULL) {
			ret = ENOMEM;
			goto fail;
		}

		val->var = list;

		s = talloc_strdup(val, tok);
		if (s == NULL) {
			ret = ENOMEM;
			goto fail;
		}

		val->var[val->count] = s;
		val->count += 1;
		s = NULL;
	}

	talloc_free(discard_const(str));
	*out = val;
	*npull = offset;
	return 0;

fail:
	talloc_free(val);
	return ret;
}

size_t ctdb_tunable_list_len(struct ctdb_tunable_list *in)
{
	return ctdb_uint32_len(&in->max_redirect_count) +
		ctdb_uint32_len(&in->seqnum_interval) +
		ctdb_uint32_len(&in->control_timeout) +
		ctdb_uint32_len(&in->traverse_timeout) +
		ctdb_uint32_len(&in->keepalive_interval) +
		ctdb_uint32_len(&in->keepalive_limit) +
		ctdb_uint32_len(&in->recover_timeout) +
		ctdb_uint32_len(&in->recover_interval) +
		ctdb_uint32_len(&in->election_timeout) +
		ctdb_uint32_len(&in->takeover_timeout) +
		ctdb_uint32_len(&in->monitor_interval) +
		ctdb_uint32_len(&in->tickle_update_interval) +
		ctdb_uint32_len(&in->script_timeout) +
		ctdb_uint32_len(&in->monitor_timeout_count) +
		ctdb_uint32_len(&in->script_unhealthy_on_timeout) +
		ctdb_uint32_len(&in->recovery_grace_period) +
		ctdb_uint32_len(&in->recovery_ban_period) +
		ctdb_uint32_len(&in->database_hash_size) +
		ctdb_uint32_len(&in->database_max_dead) +
		ctdb_uint32_len(&in->rerecovery_timeout) +
		ctdb_uint32_len(&in->enable_bans) +
		ctdb_uint32_len(&in->deterministic_public_ips) +
		ctdb_uint32_len(&in->reclock_ping_period) +
		ctdb_uint32_len(&in->no_ip_failback) +
		ctdb_uint32_len(&in->disable_ip_failover) +
		ctdb_uint32_len(&in->verbose_memory_names) +
		ctdb_uint32_len(&in->recd_ping_timeout) +
		ctdb_uint32_len(&in->recd_ping_failcount) +
		ctdb_uint32_len(&in->log_latency_ms) +
		ctdb_uint32_len(&in->reclock_latency_ms) +
		ctdb_uint32_len(&in->recovery_drop_all_ips) +
		ctdb_uint32_len(&in->verify_recovery_lock) +
		ctdb_uint32_len(&in->vacuum_interval) +
		ctdb_uint32_len(&in->vacuum_max_run_time) +
		ctdb_uint32_len(&in->repack_limit) +
		ctdb_uint32_len(&in->vacuum_limit) +
		ctdb_uint32_len(&in->max_queue_depth_drop_msg) +
		ctdb_uint32_len(&in->allow_unhealthy_db_read) +
		ctdb_uint32_len(&in->stat_history_interval) +
		ctdb_uint32_len(&in->deferred_attach_timeout) +
		ctdb_uint32_len(&in->vacuum_fast_path_count) +
		ctdb_uint32_len(&in->lcp2_public_ip_assignment) +
		ctdb_uint32_len(&in->allow_client_db_attach) +
		ctdb_uint32_len(&in->recover_pdb_by_seqnum) +
		ctdb_uint32_len(&in->deferred_rebalance_on_node_add) +
		ctdb_uint32_len(&in->fetch_collapse) +
		ctdb_uint32_len(&in->hopcount_make_sticky) +
		ctdb_uint32_len(&in->sticky_duration) +
		ctdb_uint32_len(&in->sticky_pindown) +
		ctdb_uint32_len(&in->no_ip_takeover) +
		ctdb_uint32_len(&in->db_record_count_warn) +
		ctdb_uint32_len(&in->db_record_size_warn) +
		ctdb_uint32_len(&in->db_size_warn) +
		ctdb_uint32_len(&in->pulldb_preallocation_size) +
		ctdb_uint32_len(&in->no_ip_host_on_all_disabled) +
		ctdb_uint32_len(&in->samba3_hack) +
		ctdb_uint32_len(&in->mutex_enabled) +
		ctdb_uint32_len(&in->lock_processes_per_db) +
		ctdb_uint32_len(&in->rec_buffer_size_limit) +
		ctdb_uint32_len(&in->queue_buffer_size) +
		ctdb_uint32_len(&in->ip_alloc_algorithm) +
		ctdb_uint32_len(&in->allow_mixed_versions);
}

void ctdb_tunable_list_push(struct ctdb_tunable_list *in, uint8_t *buf,
			    size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->max_redirect_count, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->seqnum_interval, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->control_timeout, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->traverse_timeout, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->keepalive_interval, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->keepalive_limit, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->recover_timeout, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->recover_interval, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->election_timeout, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->takeover_timeout, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->monitor_interval, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->tickle_update_interval, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->script_timeout, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->monitor_timeout_count, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->script_unhealthy_on_timeout, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->recovery_grace_period, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->recovery_ban_period, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->database_hash_size, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->database_max_dead, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->rerecovery_timeout, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->enable_bans, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->deterministic_public_ips, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->reclock_ping_period, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->no_ip_failback, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->disable_ip_failover, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->verbose_memory_names, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->recd_ping_timeout, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->recd_ping_failcount, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->log_latency_ms, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->reclock_latency_ms, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->recovery_drop_all_ips, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->verify_recovery_lock, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->vacuum_interval, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->vacuum_max_run_time, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->repack_limit, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->vacuum_limit, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->max_queue_depth_drop_msg, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->allow_unhealthy_db_read, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->stat_history_interval, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->deferred_attach_timeout, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->vacuum_fast_path_count, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->lcp2_public_ip_assignment, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->allow_client_db_attach, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->recover_pdb_by_seqnum, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->deferred_rebalance_on_node_add, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->fetch_collapse, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->hopcount_make_sticky, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->sticky_duration, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->sticky_pindown, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->no_ip_takeover, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->db_record_count_warn, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->db_record_size_warn, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->db_size_warn, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->pulldb_preallocation_size, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->no_ip_host_on_all_disabled, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->samba3_hack, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->mutex_enabled, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->lock_processes_per_db, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->rec_buffer_size_limit, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->queue_buffer_size, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->ip_alloc_algorithm, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->allow_mixed_versions, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_tunable_list_pull_elems(uint8_t *buf, size_t buflen,
					TALLOC_CTX *mem_ctx,
					struct ctdb_tunable_list *out,
					size_t *npull)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->max_redirect_count, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->seqnum_interval, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->control_timeout, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->traverse_timeout, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->keepalive_interval, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->keepalive_limit, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->recover_timeout, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->recover_interval, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->election_timeout, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->takeover_timeout, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->monitor_interval, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->tickle_update_interval, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->script_timeout, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->monitor_timeout_count, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->script_unhealthy_on_timeout, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->recovery_grace_period, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->recovery_ban_period, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->database_hash_size, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->database_max_dead, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->rerecovery_timeout, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->enable_bans, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->deterministic_public_ips, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->reclock_ping_period, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->no_ip_failback, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->disable_ip_failover, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->verbose_memory_names, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->recd_ping_timeout, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->recd_ping_failcount, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->log_latency_ms, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->reclock_latency_ms, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->recovery_drop_all_ips, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->verify_recovery_lock, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->vacuum_interval, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->vacuum_max_run_time, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->repack_limit, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->vacuum_limit, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->max_queue_depth_drop_msg, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->allow_unhealthy_db_read, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->stat_history_interval, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->deferred_attach_timeout, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->vacuum_fast_path_count, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->lcp2_public_ip_assignment, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->allow_client_db_attach, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->recover_pdb_by_seqnum, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->deferred_rebalance_on_node_add, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->fetch_collapse, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->hopcount_make_sticky, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->sticky_duration, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->sticky_pindown, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->no_ip_takeover, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->db_record_count_warn, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->db_record_size_warn, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->db_size_warn, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->pulldb_preallocation_size, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->no_ip_host_on_all_disabled, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->samba3_hack, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->mutex_enabled, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->lock_processes_per_db, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->rec_buffer_size_limit, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->queue_buffer_size, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->ip_alloc_algorithm, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->allow_mixed_versions, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	*npull = offset;
	return 0;
}

int ctdb_tunable_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			   struct ctdb_tunable_list **out, size_t *npull)
{
	struct ctdb_tunable_list *val;
	size_t np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_tunable_list);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_tunable_list_pull_elems(buf, buflen, val, val, &np);
	if (ret != 0) {
		talloc_free(val);
		return ret;
	}

	*out = val;
	*npull = np;
	return 0;
}

size_t ctdb_tickle_list_len(struct ctdb_tickle_list *in)
{
	size_t len;

	len = ctdb_sock_addr_len(&in->addr) +
		ctdb_uint32_len(&in->num);
	if (in->num > 0) {
		len += in->num * ctdb_connection_len(&in->conn[0]);
	}

	return len;
}

void ctdb_tickle_list_push(struct ctdb_tickle_list *in, uint8_t *buf,
			   size_t *npush)
{
	size_t offset = 0, np;
	uint32_t i;

	ctdb_sock_addr_push(&in->addr, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->num, buf+offset, &np);
	offset += np;

	for (i=0; i<in->num; i++) {
		ctdb_connection_push(&in->conn[i], buf+offset, &np);
		offset += np;
	}

	*npush = offset;
}

int ctdb_tickle_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			   struct ctdb_tickle_list **out, size_t *npull)
{
	struct ctdb_tickle_list *val;
	size_t offset = 0, np;
	uint32_t i;
	int ret;

	val = talloc(mem_ctx, struct ctdb_tickle_list);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_sock_addr_pull_elems(buf+offset, buflen-offset, val,
					&val->addr, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->num, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	if (val->num == 0) {
		val->conn = NULL;
		goto done;
	}

	val->conn = talloc_array(val, struct ctdb_connection, val->num);
	if (val->conn == NULL) {
		ret = ENOMEM;
		goto fail;
	}

	for (i=0; i<val->num; i++) {
		ret = ctdb_connection_pull_elems(buf+offset, buflen-offset,
						 val, &val->conn[i], &np);
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

size_t ctdb_addr_info_len(struct ctdb_addr_info *in)
{
	return ctdb_sock_addr_len(&in->addr) +
		ctdb_uint32_len(&in->mask) +
		ctdb_stringn_len(&in->iface);
}

void ctdb_addr_info_push(struct ctdb_addr_info *in, uint8_t *buf,
			 size_t *npush)
{
	size_t offset = 0, np;

	ctdb_sock_addr_push(&in->addr, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->mask, buf+offset, &np);
	offset += np;

	ctdb_stringn_push(&in->iface, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_addr_info_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_addr_info **out, size_t *npull)
{
	struct ctdb_addr_info *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_addr_info);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_sock_addr_pull_elems(buf+offset, buflen-offset, val,
					&val->addr, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->mask, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_stringn_pull(buf+offset, buflen-offset, val, &val->iface,
				&np);
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

size_t ctdb_transdb_len(struct ctdb_transdb *in)
{
	return ctdb_uint32_len(&in->db_id) +
		ctdb_uint32_len(&in->tid);
}

void ctdb_transdb_push(struct ctdb_transdb *in, uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->db_id, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->tid, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_transdb_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_transdb **out, size_t *npull)
{
	struct ctdb_transdb *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_transdb);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->db_id, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->tid, &np);
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

size_t ctdb_uptime_len(struct ctdb_uptime *in)
{
	return ctdb_timeval_len(&in->current_time) +
		ctdb_timeval_len(&in->ctdbd_start_time) +
		ctdb_timeval_len(&in->last_recovery_started) +
		ctdb_timeval_len(&in->last_recovery_finished);
}

void ctdb_uptime_push(struct ctdb_uptime *in, uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;

	ctdb_timeval_push(&in->current_time, buf+offset, &np);
	offset += np;

	ctdb_timeval_push(&in->ctdbd_start_time, buf+offset, &np);
	offset += np;

	ctdb_timeval_push(&in->last_recovery_started, buf+offset, &np);
	offset += np;

	ctdb_timeval_push(&in->last_recovery_finished, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_uptime_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_uptime **out, size_t *npull)
{
	struct ctdb_uptime *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_uptime);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_timeval_pull(buf+offset, buflen-offset, &val->current_time,
				&np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_timeval_pull(buf+offset, buflen-offset,
				&val->ctdbd_start_time, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_timeval_pull(buf+offset, buflen-offset,
				&val->last_recovery_started, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_timeval_pull(buf+offset, buflen-offset,
				&val->last_recovery_finished, &np);
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

size_t ctdb_public_ip_len(struct ctdb_public_ip *in)
{
	return ctdb_uint32_len(&in->pnn) +
		ctdb_sock_addr_len(&in->addr);
}

void ctdb_public_ip_push(struct ctdb_public_ip *in, uint8_t *buf,
			 size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->pnn, buf+offset, &np);
	offset += np;

	ctdb_sock_addr_push(&in->addr, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_public_ip_pull_elems(uint8_t *buf, size_t buflen,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_public_ip *out, size_t *npull)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->pnn, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_sock_addr_pull_elems(buf+offset, buflen-offset, mem_ctx,
					&out->addr, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	*npull = offset;
	return 0;
}

int ctdb_public_ip_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_public_ip **out, size_t *npull)
{
	struct ctdb_public_ip *val;
	size_t np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_public_ip);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_public_ip_pull_elems(buf, buflen, val, val, &np);
	if (ret != 0) {
		TALLOC_FREE(val);
		return ret;
	}

	*out = val;
	*npull = np;
	return ret;
}

size_t ctdb_public_ip_list_len(struct ctdb_public_ip_list *in)
{
	size_t len;

	len = ctdb_uint32_len(&in->num);
	if (in->num > 0) {
		len += in->num * ctdb_public_ip_len(&in->ip[0]);
	}

	return len;
}

void ctdb_public_ip_list_push(struct ctdb_public_ip_list *in, uint8_t *buf,
			      size_t *npush)
{
	size_t offset = 0, np;
	uint32_t i;

	ctdb_uint32_push(&in->num, buf+offset, &np);
	offset += np;

	for (i=0; i<in->num; i++) {
		ctdb_public_ip_push(&in->ip[i], buf+offset, &np);
		offset += np;
	}

	*npush = offset;
}

int ctdb_public_ip_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_public_ip_list **out, size_t *npull)
{
	struct ctdb_public_ip_list *val;
	size_t offset = 0, np;
	uint32_t i;
	int ret;

	val = talloc(mem_ctx, struct ctdb_public_ip_list);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->num, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	if (val->num == 0) {
		val->ip = NULL;
		goto done;
	}

	val->ip = talloc_array(val, struct ctdb_public_ip, val->num);
	if (val->ip == NULL) {
		ret = ENOMEM;
		goto fail;
	}

	for (i=0; i<val->num; i++) {
		ret = ctdb_public_ip_pull_elems(buf+offset, buflen-offset,
						val->ip, &val->ip[i], &np);
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

size_t ctdb_node_and_flags_len(struct ctdb_node_and_flags *in)
{
	return ctdb_uint32_len(&in->pnn) +
		ctdb_uint32_len(&in->flags) +
		ctdb_sock_addr_len(&in->addr);
}

void ctdb_node_and_flags_push(struct ctdb_node_and_flags *in, uint8_t *buf,
			      size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->pnn, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->flags, buf+offset, &np);
	offset += np;

	ctdb_sock_addr_push(&in->addr, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_node_and_flags_pull_elems(uint8_t *buf, size_t buflen,
					  TALLOC_CTX *mem_ctx,
					  struct ctdb_node_and_flags *out,
					  size_t *npull)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->pnn, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->flags, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_sock_addr_pull_elems(buf+offset, buflen-offset, mem_ctx,
					&out->addr, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	*npull = offset;
	return 0;
}

int ctdb_node_and_flags_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			      struct ctdb_node_and_flags **out, size_t *npull)
{
	struct ctdb_node_and_flags *val;
	size_t np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_node_and_flags);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_node_and_flags_pull_elems(buf, buflen, val, val, &np);
	if (ret != 0) {
		TALLOC_FREE(val);
		return ret;
	}

	*out = val;
	*npull = np;
	return ret;
}

size_t ctdb_node_map_len(struct ctdb_node_map *in)
{
	size_t len;

	len = ctdb_uint32_len(&in->num);
	if (in->num > 0) {
		len += in->num * ctdb_node_and_flags_len(&in->node[0]);
	}

	return len;
}

void ctdb_node_map_push(struct ctdb_node_map *in, uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;
	uint32_t i;

	ctdb_uint32_push(&in->num, buf+offset, &np);
	offset += np;

	for (i=0; i<in->num; i++) {
		ctdb_node_and_flags_push(&in->node[i], buf+offset, &np);
		offset += np;
	}

	*npush = offset;
}

int ctdb_node_map_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_node_map **out, size_t *npull)
{
	struct ctdb_node_map *val;
	size_t offset = 0, np;
	uint32_t i;
	int ret;

	val = talloc(mem_ctx, struct ctdb_node_map);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->num, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	if (val->num == 0) {
		val->node = NULL;
		goto done;
	}

	val->node = talloc_array(val, struct ctdb_node_and_flags, val->num);
	if (val->node == NULL) {
		ret = ENOMEM;
		goto fail;
	}

	for (i=0; i<val->num; i++) {
		ret = ctdb_node_and_flags_pull_elems(buf+offset,
						     buflen-offset,
						     val->node, &val->node[i],
						     &np);
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

size_t ctdb_script_len(struct ctdb_script *in)
{
	return ctdb_chararray_len(in->name, MAX_SCRIPT_NAME+1) +
		ctdb_timeval_len(&in->start) +
		ctdb_timeval_len(&in->finished) +
		ctdb_int32_len(&in->status) +
		ctdb_chararray_len(in->output, MAX_SCRIPT_OUTPUT+1) +
		ctdb_padding_len(4);
}

void ctdb_script_push(struct ctdb_script *in, uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;

	ctdb_chararray_push(in->name, MAX_SCRIPT_NAME+1, buf+offset, &np);
	offset += np;

	ctdb_timeval_push(&in->start, buf+offset, &np);
	offset += np;

	ctdb_timeval_push(&in->finished, buf+offset, &np);
	offset += np;

	ctdb_int32_push(&in->status, buf+offset, &np);
	offset += np;

	ctdb_chararray_push(in->output, MAX_SCRIPT_OUTPUT+1, buf+offset, &np);
	offset += np;

	ctdb_padding_push(4, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_script_pull_elems(uint8_t *buf, size_t buflen,
				  TALLOC_CTX *mem_ctx,
				  struct ctdb_script *out, size_t *npull)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_chararray_pull(buf+offset, buflen-offset,
				  out->name, MAX_SCRIPT_NAME+1, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_timeval_pull(buf+offset, buflen-offset, &out->start, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_timeval_pull(buf+offset, buflen-offset, &out->finished,
				&np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_int32_pull(buf+offset, buflen-offset, &out->status, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_chararray_pull(buf+offset, buflen-offset,
				  out->output, MAX_SCRIPT_OUTPUT+1, &np);
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

int ctdb_script_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_script **out, size_t *npull)
{
	struct ctdb_script *val;
	size_t np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_script);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_script_pull_elems(buf, buflen, val, val, &np);
	if (ret != 0) {
		TALLOC_FREE(val);
		return ret;
	}

	*out = val;
	*npull = np;
	return ret;
}

size_t ctdb_script_list_len(struct ctdb_script_list *in)
{
	size_t len;

	if (in == NULL) {
		return 0;
	}

	len = ctdb_uint32_len(&in->num_scripts) + ctdb_padding_len(4);
	if (in->num_scripts > 0) {
		len += in->num_scripts * ctdb_script_len(&in->script[0]);
	}

	return len;
}

void ctdb_script_list_push(struct ctdb_script_list *in, uint8_t *buf,
			   size_t *npush)
{
	size_t offset = 0, np;
	uint32_t i;

	if (in == NULL) {
		*npush = 0;
		return;
	}

	ctdb_uint32_push(&in->num_scripts, buf+offset, &np);
	offset += np;

	ctdb_padding_push(4, buf+offset, &np);
	offset += np;

	for (i=0; i<in->num_scripts; i++) {
		ctdb_script_push(&in->script[i], buf+offset, &np);
		offset += np;
	}

	*npush = offset;
}

int ctdb_script_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_script_list **out, size_t *npull)
{
	struct ctdb_script_list *val;
	size_t offset = 0, np;
	uint32_t i;
	int ret;

	/* If event scripts have never been run, the result will be NULL */
	if (buflen == 0) {
		val = NULL;
		goto done;
	}

	val = talloc(mem_ctx, struct ctdb_script_list);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->num_scripts,
			       &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 4, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	if (val->num_scripts == 0) {
		val->script = NULL;
		goto done;
	}

	val->script = talloc_array(val, struct ctdb_script, val->num_scripts);
	if (val->script == NULL) {
		ret = ENOMEM;
		goto fail;
	}

	for (i=0; i<val->num_scripts; i++) {
		ret = ctdb_script_pull_elems(buf+offset, buflen-offset,
					     val, &val->script[i], &np);
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

size_t ctdb_ban_state_len(struct ctdb_ban_state *in)
{
	return ctdb_uint32_len(&in->pnn) +
		ctdb_uint32_len(&in->time);
}

void ctdb_ban_state_push(struct ctdb_ban_state *in, uint8_t *buf,
			 size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->pnn, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->time, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_ban_state_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_ban_state **out, size_t *npull)
{
	struct ctdb_ban_state *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_ban_state);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->pnn, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->time, &np);
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

size_t ctdb_notify_data_len(struct ctdb_notify_data *in)
{
	return ctdb_uint64_len(&in->srvid) +
		ctdb_tdb_datan_len(&in->data);
}

void ctdb_notify_data_push(struct ctdb_notify_data *in, uint8_t *buf,
			   size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint64_push(&in->srvid, buf+offset, &np);
	offset += np;

	ctdb_tdb_datan_push(&in->data, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_notify_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_notify_data **out, size_t *npull)
{
	struct ctdb_notify_data *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_notify_data);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint64_pull(buf+offset, buflen-offset, &val->srvid, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_tdb_datan_pull(buf+offset, buflen-offset, val, &val->data,
				  &np);
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

size_t ctdb_iface_len(struct ctdb_iface *in)
{
	return ctdb_chararray_len(in->name, CTDB_IFACE_SIZE+2) +
		ctdb_uint16_len(&in->link_state) +
		ctdb_uint32_len(&in->references);
}

void ctdb_iface_push(struct ctdb_iface *in, uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;

	ctdb_chararray_push(in->name, CTDB_IFACE_SIZE+2, buf+offset, &np);
	offset += np;

	ctdb_uint16_push(&in->link_state, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->references, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_iface_pull_elems(uint8_t *buf, size_t buflen,
				 TALLOC_CTX *mem_ctx,
				 struct ctdb_iface *out, size_t *npull)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_chararray_pull(buf+offset, buflen-offset,
				  out->name, CTDB_IFACE_SIZE+2, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint16_pull(buf+offset, buflen-offset, &out->link_state,
			       &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->references,
			       &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	*npull = offset;
	return 0;
}

int ctdb_iface_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		    struct ctdb_iface **out, size_t *npull)
{
	struct ctdb_iface *val;
	size_t np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_iface);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_iface_pull_elems(buf, buflen, val, val, &np);
	if (ret != 0) {
		talloc_free(val);
		return ret;
	}

	*out = val;
	*npull = np;
	return ret;
}

size_t ctdb_iface_list_len(struct ctdb_iface_list *in)
{
	size_t len;

	len = ctdb_uint32_len(&in->num);
	if (in->num > 0) {
		len += in->num * ctdb_iface_len(&in->iface[0]);
	}

	return len;
}

void ctdb_iface_list_push(struct ctdb_iface_list *in, uint8_t *buf,
			  size_t *npush)
{
	size_t offset = 0, np;
	uint32_t i;

	ctdb_uint32_push(&in->num, buf+offset, &np);
	offset += np;

	for (i=0; i<in->num; i++) {
		ctdb_iface_push(&in->iface[i], buf+offset, &np);
		offset += np;
	}

	*npush = offset;
}

int ctdb_iface_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_iface_list **out, size_t *npull)
{
	struct ctdb_iface_list *val;
	size_t offset = 0, np;
	uint32_t i;
	int ret;

	val = talloc(mem_ctx, struct ctdb_iface_list);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->num, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	if (val->num == 0) {
		val->iface = NULL;
		goto done;
	}

	val->iface = talloc_array(val, struct ctdb_iface, val->num);
	if (val->iface == NULL) {
		ret = ENOMEM;
		goto fail;
	}

	for (i=0; i<val->num; i++) {
		ret = ctdb_iface_pull_elems(buf+offset, buflen-offset,
					    val, &val->iface[i], &np);
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

size_t ctdb_public_ip_info_len(struct ctdb_public_ip_info *in)
{
	return ctdb_public_ip_len(&in->ip) +
		ctdb_uint32_len(&in->active_idx) +
		ctdb_iface_list_len(in->ifaces);
}

void ctdb_public_ip_info_push(struct ctdb_public_ip_info *in, uint8_t *buf,
			      size_t  *npush)
{
	size_t offset = 0, np;

	ctdb_public_ip_push(&in->ip, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->active_idx, buf+offset, &np);
	offset += np;

	ctdb_iface_list_push(in->ifaces, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_public_ip_info_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_public_ip_info **out, size_t *npull)
{
	struct ctdb_public_ip_info *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_public_ip_info);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_public_ip_pull_elems(buf+offset, buflen-offset, val,
					&val->ip, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->active_idx,
			       &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_iface_list_pull(buf+offset, buflen-offset, val,
				   &val->ifaces, &np);
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

size_t ctdb_key_data_len(struct ctdb_key_data *in)
{
	return ctdb_uint32_len(&in->db_id) +
		ctdb_padding_len(4) +
		ctdb_ltdb_header_len(&in->header) +
		ctdb_tdb_datan_len(&in->key);
}

void ctdb_key_data_push(struct ctdb_key_data *in, uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->db_id, buf+offset, &np);
	offset += np;

	ctdb_padding_push(4, buf+offset, &np);
	offset += np;

	ctdb_ltdb_header_push(&in->header, buf+offset, &np);
	offset += np;

	ctdb_tdb_datan_push(&in->key, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_key_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_key_data **out, size_t *npull)
{
	struct ctdb_key_data *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_key_data);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->db_id, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 4, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_ltdb_header_pull(buf+offset, buflen-offset, &val->header,
				    &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_tdb_datan_pull(buf+offset, buflen-offset, val, &val->key,
				  &np);
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

/* In the tdb_data structure marshalling, we are only interested in dsize.
 * The dptr value is ignored.  The actual tdb_data blob is stored separately.
 *
 * This is only required for ctdb_db_statistics and will be dropped in future.
 */

static size_t tdb_data_struct_len(TDB_DATA *data)
{
	return sizeof(void *) + sizeof(size_t);
}

static void tdb_data_struct_push(TDB_DATA *data, uint8_t *buf, size_t *npush)
{
	size_t offset = 0;

	memcpy(buf+offset, &data->dptr, sizeof(void *));
	offset += sizeof(void *);

	memcpy(buf+offset, &data->dsize, sizeof(size_t));
	offset += sizeof(size_t);

	*npush = offset;
}

static int tdb_data_struct_pull(uint8_t *buf, size_t buflen, TDB_DATA *data,
				size_t *npull)
{
	size_t offset = 0;
	void *ptr;

	if (buflen-offset < sizeof(void *)) {
		return EMSGSIZE;
	}

	memcpy(&ptr, buf+offset, sizeof(void *));
	offset += sizeof(void *);
	data->dptr = NULL;

	if (buflen-offset < sizeof(size_t)) {
		return EMSGSIZE;
	}

	memcpy(&data->dsize, buf+offset, sizeof(size_t));
	offset += sizeof(size_t);

	*npull = offset;
	return 0;
}

size_t ctdb_db_statistics_len(struct ctdb_db_statistics *in)
{
	TDB_DATA data = { 0 };
	size_t len;
	uint32_t u32 = 0;
	int i;

	len = ctdb_uint32_len(&in->locks.num_calls) +
		ctdb_uint32_len(&in->locks.num_current) +
		ctdb_uint32_len(&in->locks.num_pending) +
		ctdb_uint32_len(&in->locks.num_failed) +
		ctdb_latency_counter_len(&in->locks.latency) +
		MAX_COUNT_BUCKETS *
			ctdb_uint32_len(&in->locks.buckets[0]) +
		ctdb_latency_counter_len(&in->vacuum.latency) +
		ctdb_uint32_len(&in->db_ro_delegations) +
		ctdb_uint32_len(&in->db_ro_revokes) +
		MAX_COUNT_BUCKETS *
			ctdb_uint32_len(&in->hop_count_bucket[0]) +
		ctdb_uint32_len(&in->num_hot_keys) +
		ctdb_padding_len(4) +
		MAX_HOT_KEYS *
			(ctdb_uint32_len(&u32) + ctdb_padding_len(4) +
			 tdb_data_struct_len(&data));

	for (i=0; i<MAX_HOT_KEYS; i++) {
		len += ctdb_tdb_data_len(&in->hot_keys[i].key);
	}

	return len;
}

void ctdb_db_statistics_push(struct ctdb_db_statistics *in, uint8_t *buf,
			     size_t *npush)
{
	size_t offset = 0, np;
	uint32_t num_hot_keys;
	int i;

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

	ctdb_latency_counter_push(&in->vacuum.latency, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->db_ro_delegations, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->db_ro_revokes, buf+offset, &np);
	offset += np;

	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		ctdb_uint32_push(&in->hop_count_bucket[i], buf+offset, &np);
		offset += np;
	}

	num_hot_keys = MAX_HOT_KEYS;
	ctdb_uint32_push(&num_hot_keys, buf+offset, &np);
	offset += np;

	ctdb_padding_push(4, buf+offset, &np);
	offset += np;

	for (i=0; i<MAX_HOT_KEYS; i++) {
		ctdb_uint32_push(&in->hot_keys[i].count, buf+offset, &np);
		offset += np;

		ctdb_padding_push(4, buf+offset, &np);
		offset += np;

		tdb_data_struct_push(&in->hot_keys[i].key, buf+offset, &np);
		offset += np;
	}

	for (i=0; i<MAX_HOT_KEYS; i++) {
		ctdb_tdb_data_push(&in->hot_keys[i].key, buf+offset, &np);
		offset += np;
	}

	*npush = offset;
}

static int ctdb_db_statistics_pull_elems(uint8_t *buf, size_t buflen,
					 TALLOC_CTX *mem_ctx,
					 struct ctdb_db_statistics *out,
					 size_t *npull)
{
	size_t offset = 0, np;
	int ret, i;

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

	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		ret = ctdb_uint32_pull(buf+offset, buflen-offset,
				       &out->locks.buckets[i], &np);
		if (ret != 0) {
			return ret;
		}
		offset += np;
	}

	ret = ctdb_latency_counter_pull(buf+offset, buflen-offset,
					&out->vacuum.latency, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->db_ro_delegations, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->db_ro_revokes, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		ret = ctdb_uint32_pull(buf+offset, buflen-offset,
				       &out->hop_count_bucket[i], &np);
		if (ret != 0) {
			return ret;
		}
		offset += np;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset,
			       &out->num_hot_keys, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 4, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	for (i=0; i<MAX_HOT_KEYS; i++) {
		ret = ctdb_uint32_pull(buf+offset, buflen-offset,
				       &out->hot_keys[i].count, &np);
		if (ret != 0) {
			return ret;
		}
		offset += np;

		ret = ctdb_padding_pull(buf+offset, buflen-offset, 4, &np);
		if (ret != 0) {
			return ret;
		}
		offset += np;

		ret = tdb_data_struct_pull(buf+offset, buflen-offset,
					   &out->hot_keys[i].key, &np);
		if (ret != 0) {
			return ret;
		}
		offset += np;
	}

	for (i=0; i<MAX_HOT_KEYS; i++) {
		ret = ctdb_tdb_data_pull(buf+offset,
					 out->hot_keys[i].key.dsize,
					 out, &out->hot_keys[i].key, &np);
		if (ret != 0) {
			return ret;
		}
		offset += np;
	}

	*npull = offset;
	return 0;
}

int ctdb_db_statistics_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			    struct ctdb_db_statistics **out, size_t *npull)
{
	struct ctdb_db_statistics *val;
	size_t np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_db_statistics);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_db_statistics_pull_elems(buf, buflen, val, val, &np);
	if (ret != 0) {
		talloc_free(val);
		return ret;
	}

	*out = val;
	*npull = np;
	return 0;
}

size_t ctdb_pid_srvid_len(struct ctdb_pid_srvid *in)
{
	return ctdb_pid_len(&in->pid) +
		ctdb_uint64_len(&in->srvid);
}

void ctdb_pid_srvid_push(struct ctdb_pid_srvid *in, uint8_t *buf,
			 size_t *npush)
{
	size_t offset = 0, np;

	ctdb_pid_push(&in->pid, buf+offset, &np);
	offset += np;

	ctdb_uint64_push(&in->srvid, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_pid_srvid_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_pid_srvid **out, size_t *npull)
{
	struct ctdb_pid_srvid *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_pid_srvid);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_pid_pull(buf+offset, buflen-offset, &val->pid, &np);
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

size_t ctdb_election_message_len(struct ctdb_election_message *in)
{
	return ctdb_uint32_len(&in->num_connected) +
		ctdb_padding_len(4) +
		ctdb_timeval_len(&in->priority_time) +
		ctdb_uint32_len(&in->pnn) +
		ctdb_uint32_len(&in->node_flags);
}

void ctdb_election_message_push(struct ctdb_election_message *in,
				uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->num_connected, buf+offset, &np);
	offset += np;

	ctdb_padding_push(4, buf+offset, &np);
	offset += np;

	ctdb_timeval_push(&in->priority_time, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->pnn, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->node_flags, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_election_message_pull(uint8_t *buf, size_t buflen,
			       TALLOC_CTX *mem_ctx,
			       struct ctdb_election_message **out,
			       size_t *npull)
{
	struct ctdb_election_message *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_election_message);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->num_connected,
			       &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 4, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_timeval_pull(buf+offset, buflen-offset,
				&val->priority_time, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->pnn, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->node_flags,
			       &np);
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

size_t ctdb_srvid_message_len(struct ctdb_srvid_message *in)
{
	return ctdb_uint32_len(&in->pnn) +
		ctdb_padding_len(4) +
		ctdb_uint64_len(&in->srvid);
}

void ctdb_srvid_message_push(struct ctdb_srvid_message *in, uint8_t *buf,
			     size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->pnn, buf+offset, &np);
	offset += np;

	ctdb_padding_push(4, buf+offset, &np);
	offset += np;

	ctdb_uint64_push(&in->srvid, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_srvid_message_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			    struct ctdb_srvid_message **out, size_t *npull)
{
	struct ctdb_srvid_message *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_srvid_message);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->pnn, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 4, &np);
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

size_t ctdb_disable_message_len(struct ctdb_disable_message *in)
{
	return ctdb_uint32_len(&in->pnn) +
		ctdb_padding_len(4) +
		ctdb_uint64_len(&in->srvid) +
		ctdb_uint32_len(&in->timeout) +
		ctdb_padding_len(4);
}

void ctdb_disable_message_push(struct ctdb_disable_message *in, uint8_t *buf,
			       size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->pnn, buf+offset, &np);
	offset += np;

	ctdb_padding_push(4, buf+offset, &np);
	offset += np;

	ctdb_uint64_push(&in->srvid, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->timeout, buf+offset, &np);
	offset += np;

	ctdb_padding_push(4, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_disable_message_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			      struct ctdb_disable_message **out,
			      size_t *npull)
{
	struct ctdb_disable_message *val;
	size_t offset = 0, np;
	int ret;

	val = talloc(mem_ctx, struct ctdb_disable_message);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->pnn, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 4, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint64_pull(buf+offset, buflen-offset, &val->srvid, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &val->timeout, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 4, &np);
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

size_t ctdb_server_id_len(struct ctdb_server_id *in)
{
	return ctdb_uint64_len(&in->pid) +
		ctdb_uint32_len(&in->task_id) +
		ctdb_uint32_len(&in->vnn) +
		ctdb_uint64_len(&in->unique_id);
}

void ctdb_server_id_push(struct ctdb_server_id *in, uint8_t *buf,
			 size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint64_push(&in->pid, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->task_id, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->vnn, buf+offset, &np);
	offset += np;

	ctdb_uint64_push(&in->unique_id, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_server_id_pull(uint8_t *buf, size_t buflen,
			struct ctdb_server_id *out, size_t *npull)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_uint64_pull(buf+offset, buflen-offset, &out->pid, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->task_id, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->vnn, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint64_pull(buf+offset, buflen-offset, &out->unique_id,
			       &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	*npull = offset;
	return 0;
}

size_t ctdb_g_lock_len(struct ctdb_g_lock *in)
{
	return ctdb_uint32_len(&in->type) +
		ctdb_padding_len(4) +
		ctdb_server_id_len(&in->sid);
}

void ctdb_g_lock_push(struct ctdb_g_lock *in, uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;
	uint32_t type;

	type = in->type;
	ctdb_uint32_push(&type, buf+offset, &np);
	offset += np;

	ctdb_padding_push(4, buf+offset, &np);
	offset += np;

	ctdb_server_id_push(&in->sid, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_g_lock_pull(uint8_t *buf, size_t buflen, struct ctdb_g_lock *out,
		     size_t *npull)
{
	size_t offset = 0, np;
	int ret;
	uint32_t type;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &type, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (type == 0) {
		out->type = CTDB_G_LOCK_READ;
	} else if (type == 1) {
		out->type = CTDB_G_LOCK_WRITE;
	} else {
		return EPROTO;
	}

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 4, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_server_id_pull(buf+offset, buflen-offset, &out->sid, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	*npull = offset;
	return 0;
}

size_t ctdb_g_lock_list_len(struct ctdb_g_lock_list *in)
{
	size_t len = 0;

	if (in->num > 0) {
		len += in->num * ctdb_g_lock_len(&in->lock[0]);
	}

	return len;
}

void ctdb_g_lock_list_push(struct ctdb_g_lock_list *in, uint8_t *buf,
			   size_t *npush)
{
	size_t offset = 0, np;
	uint32_t i;

	for (i=0; i<in->num; i++) {
		ctdb_g_lock_push(&in->lock[i], buf+offset, &np);
		offset += np;
	}

	*npush = offset;
}

int ctdb_g_lock_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_g_lock_list **out, size_t *npull)
{
	struct ctdb_g_lock_list *val;
	struct ctdb_g_lock lock = { 0 };
	size_t offset = 0, np;
	uint32_t i;
	int ret;

	val = talloc(mem_ctx, struct ctdb_g_lock_list);
	if (val == NULL) {
		return ENOMEM;
	}

	if (buflen == 0) {
		val->lock = NULL;
		val->num = 0;
		goto done;
	}

	val->num = buflen / ctdb_g_lock_len(&lock);

	val->lock = talloc_array(val, struct ctdb_g_lock, val->num);
	if (val->lock == NULL) {
		ret = ENOMEM;
		goto fail;
	}

	for (i=0; i<val->num; i++) {
		ret = ctdb_g_lock_pull(buf+offset, buflen-offset,
				       &val->lock[i], &np);
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
