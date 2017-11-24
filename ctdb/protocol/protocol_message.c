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


static size_t ctdb_message_data_len(union ctdb_message_data *mdata,
				    uint64_t srvid)
{
	size_t len = 0;

	switch (srvid) {
	case CTDB_SRVID_BANNING:
		len = ctdb_uint32_len(&mdata->pnn);
		break;

	case CTDB_SRVID_ELECTION:
		len = ctdb_election_message_len(mdata->election);
		break;

	case CTDB_SRVID_RECONFIGURE:
		break;

	case CTDB_SRVID_RELEASE_IP:
		len = ctdb_string_len(&mdata->ipaddr);
		break;

	case CTDB_SRVID_TAKE_IP:
		len = ctdb_string_len(&mdata->ipaddr);
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
		len = ctdb_uint32_len(&mdata->db_id);
		break;

	case CTDB_SRVID_MEM_DUMP:
		len = ctdb_srvid_message_len(mdata->msg);
		break;

	case CTDB_SRVID_GETLOG:
		break;

	case CTDB_SRVID_CLEARLOG:
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
		len = ctdb_uint32_len(&mdata->pnn);
		break;

	case CTDB_SRVID_DISABLE_TAKEOVER_RUNS:
		len = ctdb_disable_message_len(mdata->disable);
		break;

	case CTDB_SRVID_DISABLE_RECOVERIES:
		len = ctdb_disable_message_len(mdata->disable);
		break;

	case CTDB_SRVID_DISABLE_IP_CHECK:
		len = ctdb_uint32_len(&mdata->timeout);
		break;

	default:
		len = ctdb_tdb_data_len(&mdata->data);
		break;
	}

	return len;
}

static void ctdb_message_data_push(union ctdb_message_data *mdata,
				   uint64_t srvid, uint8_t *buf,
				   size_t *npush)
{
	size_t np = 0;

	switch (srvid) {
	case CTDB_SRVID_BANNING:
		ctdb_uint32_push(&mdata->pnn, buf, &np);
		break;

	case CTDB_SRVID_ELECTION:
		ctdb_election_message_push(mdata->election, buf, &np);
		break;

	case CTDB_SRVID_RECONFIGURE:
		break;

	case CTDB_SRVID_RELEASE_IP:
		ctdb_string_push(&mdata->ipaddr, buf, &np);
		break;

	case CTDB_SRVID_TAKE_IP:
		ctdb_string_push(&mdata->ipaddr, buf, &np);
		break;

	case CTDB_SRVID_SET_NODE_FLAGS:
		ctdb_node_flag_change_push(mdata->flag_change, buf, &np);
		break;

	case CTDB_SRVID_RECD_UPDATE_IP:
		ctdb_public_ip_push(mdata->pubip, buf, &np);
		break;

	case CTDB_SRVID_VACUUM_FETCH:
		ctdb_rec_buffer_push(mdata->recbuf, buf, &np);
		break;

	case CTDB_SRVID_DETACH_DATABASE:
		ctdb_uint32_push(&mdata->db_id, buf, &np);
		break;

	case CTDB_SRVID_MEM_DUMP:
		ctdb_srvid_message_push(mdata->msg, buf, &np);
		break;

	case CTDB_SRVID_GETLOG:
		break;

	case CTDB_SRVID_CLEARLOG:
		break;

	case CTDB_SRVID_PUSH_NODE_FLAGS:
		ctdb_node_flag_change_push(mdata->flag_change, buf, &np);
		break;

	case CTDB_SRVID_RELOAD_NODES:
		break;

	case CTDB_SRVID_TAKEOVER_RUN:
		ctdb_srvid_message_push(mdata->msg, buf, &np);
		break;

	case CTDB_SRVID_REBALANCE_NODE:
		ctdb_uint32_push(&mdata->pnn, buf, &np);
		break;

	case CTDB_SRVID_DISABLE_TAKEOVER_RUNS:
		ctdb_disable_message_push(mdata->disable, buf, &np);
		break;

	case CTDB_SRVID_DISABLE_RECOVERIES:
		ctdb_disable_message_push(mdata->disable, buf, &np);
		break;

	case CTDB_SRVID_DISABLE_IP_CHECK:
		ctdb_uint32_push(&mdata->timeout, buf, &np);
		break;

	default:
		ctdb_tdb_data_push(&mdata->data, buf, &np);
		break;
	}

	*npush = np;
}

static int ctdb_message_data_pull(uint8_t *buf, size_t buflen,
				  uint64_t srvid, TALLOC_CTX *mem_ctx,
				  union ctdb_message_data *mdata,
				  size_t *npull)
{
	int ret = 0;
	size_t np = 0;

	switch (srvid) {
	case CTDB_SRVID_BANNING:
		ret = ctdb_uint32_pull(buf, buflen, &mdata->pnn, &np);
		break;

	case CTDB_SRVID_ELECTION:
		ret = ctdb_election_message_pull(buf, buflen, mem_ctx,
						 &mdata->election, &np);
		break;

	case CTDB_SRVID_RECONFIGURE:
		break;

	case CTDB_SRVID_RELEASE_IP:
		ret = ctdb_string_pull(buf, buflen, mem_ctx, &mdata->ipaddr,
				       &np);
		break;

	case CTDB_SRVID_TAKE_IP:
		ret = ctdb_string_pull(buf, buflen, mem_ctx, &mdata->ipaddr,
				       &np);
		break;

	case CTDB_SRVID_SET_NODE_FLAGS:
		ret = ctdb_node_flag_change_pull(buf, buflen, mem_ctx,
						 &mdata->flag_change, &np);
		break;

	case CTDB_SRVID_RECD_UPDATE_IP:
		ret = ctdb_public_ip_pull(buf, buflen, mem_ctx,
					  &mdata->pubip, &np);
		break;

	case CTDB_SRVID_VACUUM_FETCH:
		ret = ctdb_rec_buffer_pull(buf, buflen, mem_ctx,
					   &mdata->recbuf, &np);
		break;

	case CTDB_SRVID_DETACH_DATABASE:
		ret = ctdb_uint32_pull(buf, buflen, &mdata->db_id, &np);
		break;

	case CTDB_SRVID_MEM_DUMP:
		ret = ctdb_srvid_message_pull(buf, buflen, mem_ctx,
					      &mdata->msg, &np);
		break;

	case CTDB_SRVID_GETLOG:
		break;

	case CTDB_SRVID_CLEARLOG:
		break;

	case CTDB_SRVID_PUSH_NODE_FLAGS:
		ret = ctdb_node_flag_change_pull(buf, buflen, mem_ctx,
						 &mdata->flag_change, &np);
		break;

	case CTDB_SRVID_RELOAD_NODES:
		break;

	case CTDB_SRVID_TAKEOVER_RUN:
		ret = ctdb_srvid_message_pull(buf, buflen, mem_ctx,
					      &mdata->msg, &np);
		break;

	case CTDB_SRVID_REBALANCE_NODE:
		ret = ctdb_uint32_pull(buf, buflen, &mdata->pnn, &np);
		break;

	case CTDB_SRVID_DISABLE_TAKEOVER_RUNS:
		ret = ctdb_disable_message_pull(buf, buflen, mem_ctx,
						&mdata->disable, &np);
		break;

	case CTDB_SRVID_DISABLE_RECOVERIES:
		ret = ctdb_disable_message_pull(buf, buflen, mem_ctx,
						&mdata->disable, &np);
		break;

	case CTDB_SRVID_DISABLE_IP_CHECK:
		ret = ctdb_uint32_pull(buf, buflen, &mdata->timeout, &np);
		break;

	default:
		ret = ctdb_tdb_data_pull(buf, buflen, mem_ctx, &mdata->data,
					 &np);
		break;
	}

	if (ret != 0) {
		return ret;
	}

	*npull = np;
	return 0;
}

size_t ctdb_req_message_len(struct ctdb_req_header *h,
			    struct ctdb_req_message *c)
{
	uint32_t u32 = ctdb_message_data_len(&c->data, c->srvid);

	return ctdb_req_header_len(h) +
		ctdb_uint64_len(&c->srvid) +
		ctdb_uint32_len(&u32) + u32;
}

int ctdb_req_message_push(struct ctdb_req_header *h,
			  struct ctdb_req_message *c,
			  uint8_t *buf, size_t *buflen)
{
	size_t offset = 0, np;
	size_t length;
	uint32_t u32;

	length = ctdb_req_message_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, buf+offset, &np);
	offset += np;

	ctdb_uint64_push(&c->srvid, buf+offset, &np);
	offset += np;

	u32 = ctdb_message_data_len(&c->data, c->srvid);
	ctdb_uint32_push(&u32, buf+offset, &np);
	offset += np;

	ctdb_message_data_push(&c->data, c->srvid, buf+offset, &np);
	offset += np;

	return 0;
}

int ctdb_req_message_pull(uint8_t *buf, size_t buflen,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_req_message *c)
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

	ret = ctdb_uint64_pull(buf+offset, buflen-offset, &c->srvid, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &u32, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (buflen-offset < u32) {
		return EMSGSIZE;
	}

	ret = ctdb_message_data_pull(buf+offset, u32, c->srvid,
				     mem_ctx, &c->data, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	return ret;
}

size_t ctdb_req_message_data_len(struct ctdb_req_header *h,
				 struct ctdb_req_message_data *c)
{
	return ctdb_req_header_len(h) +
		ctdb_uint64_len(&c->srvid) +
		ctdb_tdb_datan_len(&c->data);
}

int ctdb_req_message_data_push(struct ctdb_req_header *h,
			       struct ctdb_req_message_data *c,
			       uint8_t *buf, size_t *buflen)
{
	size_t offset = 0, np;
	size_t length;

	length = ctdb_req_message_data_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, buf+offset, &np);
	offset += np;

	ctdb_uint64_push(&c->srvid, buf+offset, &np);
	offset += np;

	ctdb_tdb_datan_push(&c->data, buf+offset, &np);
	offset += np;

	return 0;
}

int ctdb_req_message_data_pull(uint8_t *buf, size_t buflen,
			       struct ctdb_req_header *h,
			       TALLOC_CTX *mem_ctx,
			       struct ctdb_req_message_data *c)
{
	struct ctdb_req_header header;
	size_t offset = 0, np;
	int ret;

	ret = ctdb_req_header_pull(buf+offset, buflen-offset, &header, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (h != NULL) {
		*h = header;
	}

	ret = ctdb_uint64_pull(buf+offset, buflen-offset, &c->srvid, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_tdb_datan_pull(buf+offset, buflen-offset,
				  mem_ctx, &c->data, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	return 0;
}
