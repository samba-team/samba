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

size_t ctdb_req_keepalive_len(struct ctdb_req_header *h,
			      struct ctdb_req_keepalive *c)
{
	return ctdb_req_header_len(h) +
		ctdb_uint32_len(&c->version) +
		ctdb_uint32_len(&c->uptime);
}

int ctdb_req_keepalive_push(struct ctdb_req_header *h,
			    struct ctdb_req_keepalive *c,
			    uint8_t *buf, size_t *buflen)
{
	size_t length, offset = 0, np;

	length = ctdb_req_keepalive_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&c->version, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&c->uptime, buf+offset, &np);
	offset += np;

	return 0;
}

int ctdb_req_keepalive_pull(uint8_t *buf, size_t buflen,
			    struct ctdb_req_header *h,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_req_keepalive *c)
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

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &c->version, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &c->uptime, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	return 0;
}
