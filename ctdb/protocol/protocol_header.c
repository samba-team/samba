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

int ctdb_req_header_verify(struct ctdb_req_header *h, uint32_t operation)
{
	if (h->length < sizeof(struct ctdb_req_header)) {
		return EMSGSIZE;
	}

	if (h->ctdb_magic != CTDB_MAGIC) {
		return EPROTO;
	}

	if (h->ctdb_version != CTDB_PROTOCOL) {
		return EPROTO;
	}

	if (operation != 0 && h->operation != operation) {
		return EPROTO;
	}

	return 0;
}

void ctdb_req_header_fill(struct ctdb_req_header *h, uint32_t generation,
			  uint32_t operation, uint32_t destnode,
			  uint32_t srcnode, uint32_t reqid)
{
	h->length = sizeof(struct ctdb_req_header);
	h->ctdb_magic = CTDB_MAGIC;
	h->ctdb_version = CTDB_PROTOCOL;
	h->generation = generation;
	h->operation = operation;
	h->destnode = destnode;
	h->srcnode = srcnode;
	h->reqid = reqid;
}

size_t ctdb_req_header_len(struct ctdb_req_header *in)
{
	return ctdb_uint32_len(&in->length) +
		ctdb_uint32_len(&in->ctdb_magic) +
		ctdb_uint32_len(&in->ctdb_version) +
		ctdb_uint32_len(&in->generation) +
		ctdb_uint32_len(&in->operation) +
		ctdb_uint32_len(&in->destnode) +
		ctdb_uint32_len(&in->srcnode) +
		ctdb_uint32_len(&in->reqid);
}

void ctdb_req_header_push(struct ctdb_req_header *in, uint8_t *buf,
			  size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->length, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->ctdb_magic, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->ctdb_version, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->generation, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->operation, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->destnode, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->srcnode, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->reqid, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_req_header_pull(uint8_t *buf, size_t buflen,
			 struct ctdb_req_header *out, size_t *npull)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->length, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->ctdb_magic,
			       &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->ctdb_version,
			       &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->generation,
			       &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->operation,
			       &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->destnode, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->srcnode, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->reqid, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	*npull = offset;
	return 0;
}
