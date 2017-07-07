/*
   CTDB generic sock packet marshalling

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

#include "protocol.h"
#include "protocol_private.h"
#include "protocol_api.h"

size_t sock_packet_header_len(struct sock_packet_header *in)
{
	return ctdb_uint32_len(&in->length) +
		ctdb_uint32_len(&in->reqid);
}

void sock_packet_header_push(struct sock_packet_header *in, uint8_t *buf,
			     size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->length, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->reqid, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int sock_packet_header_pull(uint8_t *buf, size_t buflen,
			    struct sock_packet_header *out, size_t *npull)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->length, &np);
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

void sock_packet_header_set_reqid(struct sock_packet_header *h,
				  uint32_t reqid)
{
	h->reqid = reqid;
}

void sock_packet_header_set_length(struct sock_packet_header *h,
				   uint32_t length)
{
	h->length = length;
}
