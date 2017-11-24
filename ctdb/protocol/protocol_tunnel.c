/*
   CTDB protocol marshalling

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

#include <talloc.h>
#include <tdb.h>

#include "protocol.h"
#include "protocol_api.h"
#include "protocol_private.h"

size_t ctdb_req_tunnel_len(struct ctdb_req_header *h,
			   struct ctdb_req_tunnel *c)
{
	return ctdb_req_header_len(h) +
		ctdb_uint64_len(&c->tunnel_id) +
		ctdb_uint32_len(&c->flags) +
		ctdb_tdb_datan_len(&c->data);
}

int ctdb_req_tunnel_push(struct ctdb_req_header *h,
			 struct ctdb_req_tunnel *c,
			 uint8_t *buf, size_t *buflen)
{
	size_t length, offset = 0, np;

	length = ctdb_req_tunnel_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, buf, &np);
	offset += np;

	ctdb_uint64_push(&c->tunnel_id, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&c->flags, buf+offset, &np);
	offset += np;

	ctdb_tdb_datan_push(&c->data, buf+offset, &np);
	offset += np;

	if (offset > *buflen) {
		return EMSGSIZE;
	}

	return 0;
}

int ctdb_req_tunnel_pull(uint8_t *buf, size_t buflen,
			 struct ctdb_req_header *h,
			 TALLOC_CTX *mem_ctx,
			 struct ctdb_req_tunnel *c)
{
	struct ctdb_req_header header;
	size_t offset = 0, np;
	int ret;

	ret = ctdb_req_header_pull(buf, buflen, &header, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (h != NULL) {
		*h = header;
	}

	ret = ctdb_uint64_pull(buf+offset, buflen-offset, &c->tunnel_id, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &c->flags, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_tdb_datan_pull(buf+offset, buflen-offset, mem_ctx,
				  &c->data, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (offset > buflen) {
		return EMSGSIZE;
	}

	return 0;
}
