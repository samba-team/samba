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

int ctdb_req_header_pull(uint8_t *pkt, size_t pkt_len,
			 struct ctdb_req_header *h)
{
	if (pkt_len < sizeof(struct ctdb_req_header)) {
		return EMSGSIZE;
	}

	memcpy(h, pkt, sizeof(struct ctdb_req_header));
	return 0;
}
