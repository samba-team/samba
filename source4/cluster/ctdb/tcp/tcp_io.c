/* 
   ctdb over TCP

   Copyright (C) Andrew Tridgell  2006

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "lib/events/events.h"
#include "lib/util/dlinklist.h"
#include "lib/tdb/include/tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "../include/ctdb_private.h"
#include "ctdb_tcp.h"


/*
  called when a complete packet has come in
 */
void ctdb_tcp_read_cb(uint8_t *data, size_t cnt, void *args)
{
	struct ctdb_incoming *in = talloc_get_type(args, struct ctdb_incoming);
	struct ctdb_req_header *hdr;

	if (data == NULL) {
		/* incoming socket has died */
		talloc_free(in);
		return;
	}

	if (cnt < sizeof(*hdr)) {
		ctdb_set_error(in->ctdb, "Bad packet length %d\n", cnt);
		return;
	}
	hdr = (struct ctdb_req_header *)data;
	if (cnt != hdr->length) {
		ctdb_set_error(in->ctdb, "Bad header length %d expected %d\n", 
			       hdr->length, cnt);
		return;
	}

	if (hdr->ctdb_magic != CTDB_MAGIC) {
		ctdb_set_error(in->ctdb, "Non CTDB packet rejected\n");
		return;
	}

	if (hdr->ctdb_version != CTDB_VERSION) {
		ctdb_set_error(in->ctdb, "Bad CTDB version 0x%x rejected\n", hdr->ctdb_version);
		return;
	}

	/* most common case - we got a whole packet in one go
	   tell the ctdb layer above that we have a packet */
	in->ctdb->upcalls->recv_pkt(in->ctdb, data, cnt);
}

/*
  queue a packet for sending
*/
int ctdb_tcp_queue_pkt(struct ctdb_node *node, uint8_t *data, uint32_t length)
{
	struct ctdb_tcp_node *tnode = talloc_get_type(node->private_data,
						      struct ctdb_tcp_node);
	return ctdb_queue_send(tnode->queue, data, length);
}
