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

struct ctdb_req_message_wire {
	struct ctdb_req_header hdr;
	uint64_t srvid;
	uint32_t datalen;
	uint8_t data[1];
};

static size_t ctdb_message_data_len(union ctdb_message_data *mdata,
				    uint64_t srvid)
{
	size_t len = 0;

	switch (srvid) {
	case CTDB_SRVID_BANNING:
		len = ctdb_uint32_len(mdata->pnn);
		break;

	case CTDB_SRVID_ELECTION:
		len = ctdb_election_message_len(mdata->election);
		break;

	case CTDB_SRVID_RECONFIGURE:
		break;

	case CTDB_SRVID_RELEASE_IP:
		len = ctdb_string_len(mdata->ipaddr);
		break;

	case CTDB_SRVID_TAKE_IP:
		len = ctdb_string_len(mdata->ipaddr);
		break;

	case CTDB_SRVID_SET_NODE_FLAGS:
		len = ctdb_node_flag_change_len(mdata->flag_change);
		break;

	case CTDB_SRVID_RECD_UPDATE_IP:
		len = ctdb_public_ip_len(mdata->pubip);
		break;

	case CTDB_SRVID_VACUUM_FETCH:
		len = ctdb_rec_buffer_len(mdata->recbuf);
		break;

	case CTDB_SRVID_DETACH_DATABASE:
		len = ctdb_uint32_len(mdata->db_id);
		break;

	case CTDB_SRVID_MEM_DUMP:
		len = ctdb_srvid_message_len(mdata->msg);
		break;

	case CTDB_SRVID_PUSH_NODE_FLAGS:
		len = ctdb_node_flag_change_len(mdata->flag_change);
		break;

	case CTDB_SRVID_RELOAD_NODES:
		break;

	case CTDB_SRVID_TAKEOVER_RUN:
		len = ctdb_srvid_message_len(mdata->msg);
		break;

	case CTDB_SRVID_REBALANCE_NODE:
		len = ctdb_uint32_len(mdata->pnn);
		break;

	case CTDB_SRVID_DISABLE_TAKEOVER_RUNS:
		len = ctdb_disable_message_len(mdata->disable);
		break;

	case CTDB_SRVID_DISABLE_RECOVERIES:
		len = ctdb_disable_message_len(mdata->disable);
		break;

	case CTDB_SRVID_DISABLE_IP_CHECK:
		len = ctdb_uint32_len(mdata->timeout);
		break;

	default:
		len = ctdb_tdb_data_len(mdata->data);
		break;
	}

	return len;
}

static void ctdb_message_data_push(union ctdb_message_data *mdata,
				   uint64_t srvid, uint8_t *buf)
{
	switch (srvid) {
	case CTDB_SRVID_BANNING:
		ctdb_uint32_push(mdata->pnn, buf);
		break;

	case CTDB_SRVID_ELECTION:
		ctdb_election_message_push(mdata->election, buf);
		break;

	case CTDB_SRVID_RECONFIGURE:
		break;

	case CTDB_SRVID_RELEASE_IP:
		ctdb_string_push(mdata->ipaddr, buf);
		break;

	case CTDB_SRVID_TAKE_IP:
		ctdb_string_push(mdata->ipaddr, buf);
		break;

	case CTDB_SRVID_SET_NODE_FLAGS:
		ctdb_node_flag_change_push(mdata->flag_change, buf);
		break;

	case CTDB_SRVID_RECD_UPDATE_IP:
		ctdb_public_ip_push(mdata->pubip, buf);
		break;

	case CTDB_SRVID_VACUUM_FETCH:
		ctdb_rec_buffer_push(mdata->recbuf, buf);
		break;

	case CTDB_SRVID_DETACH_DATABASE:
		ctdb_uint32_push(mdata->db_id, buf);
		break;

	case CTDB_SRVID_MEM_DUMP:
		ctdb_srvid_message_push(mdata->msg, buf);
		break;

	case CTDB_SRVID_PUSH_NODE_FLAGS:
		ctdb_node_flag_change_push(mdata->flag_change, buf);
		break;

	case CTDB_SRVID_RELOAD_NODES:
		break;

	case CTDB_SRVID_TAKEOVER_RUN:
		ctdb_srvid_message_push(mdata->msg, buf);
		break;

	case CTDB_SRVID_REBALANCE_NODE:
		ctdb_uint32_push(mdata->pnn, buf);
		break;

	case CTDB_SRVID_DISABLE_TAKEOVER_RUNS:
		ctdb_disable_message_push(mdata->disable, buf);
		break;

	case CTDB_SRVID_DISABLE_RECOVERIES:
		ctdb_disable_message_push(mdata->disable, buf);
		break;

	case CTDB_SRVID_DISABLE_IP_CHECK:
		ctdb_uint32_push(mdata->timeout, buf);
		break;

	default:
		ctdb_tdb_data_push(mdata->data, buf);
		break;
	}
}

static int ctdb_message_data_pull(uint8_t *buf, size_t buflen,
				  uint64_t srvid, TALLOC_CTX *mem_ctx,
				  union ctdb_message_data *mdata)
{
	int ret = 0;

	switch (srvid) {
	case CTDB_SRVID_BANNING:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx, &mdata->pnn);
		break;

	case CTDB_SRVID_ELECTION:
		ret = ctdb_election_message_pull(buf, buflen, mem_ctx,
						 &mdata->election);
		break;

	case CTDB_SRVID_RECONFIGURE:
		break;

	case CTDB_SRVID_RELEASE_IP:
		ret = ctdb_string_pull(buf, buflen, mem_ctx, &mdata->ipaddr);
		break;

	case CTDB_SRVID_TAKE_IP:
		ret = ctdb_string_pull(buf, buflen, mem_ctx, &mdata->ipaddr);
		break;

	case CTDB_SRVID_SET_NODE_FLAGS:
		ret = ctdb_node_flag_change_pull(buf, buflen, mem_ctx,
						 &mdata->flag_change);
		break;

	case CTDB_SRVID_RECD_UPDATE_IP:
		ret = ctdb_public_ip_pull(buf, buflen, mem_ctx,
					  &mdata->pubip);
		break;

	case CTDB_SRVID_VACUUM_FETCH:
		ret = ctdb_rec_buffer_pull(buf, buflen, mem_ctx,
					   &mdata->recbuf);
		break;

	case CTDB_SRVID_DETACH_DATABASE:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx, &mdata->db_id);
		break;

	case CTDB_SRVID_MEM_DUMP:
		ret = ctdb_srvid_message_pull(buf, buflen, mem_ctx,
					      &mdata->msg);
		break;

	case CTDB_SRVID_PUSH_NODE_FLAGS:
		ret = ctdb_node_flag_change_pull(buf, buflen, mem_ctx,
						 &mdata->flag_change);
		break;

	case CTDB_SRVID_RELOAD_NODES:
		break;

	case CTDB_SRVID_TAKEOVER_RUN:
		ret = ctdb_srvid_message_pull(buf, buflen, mem_ctx,
					      &mdata->msg);
		break;

	case CTDB_SRVID_REBALANCE_NODE:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx, &mdata->pnn);
		break;

	case CTDB_SRVID_DISABLE_TAKEOVER_RUNS:
		ret = ctdb_disable_message_pull(buf, buflen, mem_ctx,
						&mdata->disable);
		break;

	case CTDB_SRVID_DISABLE_RECOVERIES:
		ret = ctdb_disable_message_pull(buf, buflen, mem_ctx,
						&mdata->disable);
		break;

	case CTDB_SRVID_DISABLE_IP_CHECK:
		ret = ctdb_uint32_pull(buf, buflen, mem_ctx, &mdata->timeout);
		break;

	default:
		ret = ctdb_tdb_data_pull(buf, buflen, mem_ctx, &mdata->data);
		break;
	}

	return ret;
}

size_t ctdb_req_message_len(struct ctdb_req_header *h,
			    struct ctdb_req_message *c)
{
	return offsetof(struct ctdb_req_message_wire, data) +
		ctdb_message_data_len(&c->data, c->srvid);
}

int ctdb_req_message_push(struct ctdb_req_header *h,
			  struct ctdb_req_message *message,
			  uint8_t *buf, size_t *buflen)
{
	struct ctdb_req_message_wire *wire =
		(struct ctdb_req_message_wire *)buf;
	size_t length;

	length = ctdb_req_message_len(h, message);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, (uint8_t *)&wire->hdr);

	wire->srvid = message->srvid;
	wire->datalen = ctdb_message_data_len(&message->data, message->srvid);
	ctdb_message_data_push(&message->data, message->srvid, wire->data);

	return 0;
}

int ctdb_req_message_pull(uint8_t *buf, size_t buflen,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_req_message *c)
{
	struct ctdb_req_message_wire *wire =
		(struct ctdb_req_message_wire *)buf;
	size_t length;
	int ret;

	length = offsetof(struct ctdb_req_message_wire, data);
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

	c->srvid = wire->srvid;
	ret = ctdb_message_data_pull(wire->data, wire->datalen, wire->srvid,
				     mem_ctx, &c->data);
	return ret;
}

size_t ctdb_req_message_data_len(struct ctdb_req_header *h,
				 struct ctdb_req_message_data *c)
{
	return offsetof(struct ctdb_req_message_wire, data) +
		ctdb_tdb_data_len(c->data);
}

int ctdb_req_message_data_push(struct ctdb_req_header *h,
			       struct ctdb_req_message_data *message,
			       uint8_t *buf, size_t *buflen)
{
	struct ctdb_req_message_wire *wire =
		(struct ctdb_req_message_wire *)buf;
	size_t length;

	length = ctdb_req_message_data_len(h, message);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, (uint8_t *)&wire->hdr);

	wire->srvid = message->srvid;
	wire->datalen = ctdb_tdb_data_len(message->data);
	ctdb_tdb_data_push(message->data, wire->data);

	return 0;
}

int ctdb_req_message_data_pull(uint8_t *buf, size_t buflen,
			       struct ctdb_req_header *h,
			       TALLOC_CTX *mem_ctx,
			       struct ctdb_req_message_data *c)
{
	struct ctdb_req_message_wire *wire =
		(struct ctdb_req_message_wire *)buf;
	size_t length;
	int ret;

	length = offsetof(struct ctdb_req_message_wire, data);
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

	c->srvid = wire->srvid;

	ret = ctdb_tdb_data_pull(wire->data, wire->datalen,
				 mem_ctx, &c->data);
	if (ret != 0) {
		return ret;
	}

	return 0;
}
