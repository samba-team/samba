/* 
   ctdb over TCP

   Copyright (C) Andrew Tridgell  2006

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

#include "includes.h"
#include "lib/util/dlinklist.h"
#include "tdb.h"
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
	struct ctdb_req_header *hdr = (struct ctdb_req_header *)data;

	if (data == NULL) {
		/* incoming socket has died */
		goto failed;
	}

	if (cnt < sizeof(*hdr)) {
		DEBUG(DEBUG_ALERT,(__location__ " Bad packet length %u\n", (unsigned)cnt));
		goto failed;
	}

	if (cnt & (CTDB_TCP_ALIGNMENT-1)) {
		DEBUG(DEBUG_ALERT,(__location__ " Length 0x%x not multiple of alignment\n", 
			 (unsigned)cnt));
		goto failed;
	}


	if (cnt != hdr->length) {
		DEBUG(DEBUG_ALERT,(__location__ " Bad header length %u expected %u\n", 
			 (unsigned)hdr->length, (unsigned)cnt));
		goto failed;
	}

	if (hdr->ctdb_magic != CTDB_MAGIC) {
		DEBUG(DEBUG_ALERT,(__location__ " Non CTDB packet 0x%x rejected\n", 
			 hdr->ctdb_magic));
		goto failed;
	}

	if (hdr->ctdb_version != CTDB_PROTOCOL) {
		DEBUG(DEBUG_ALERT, (__location__ " Bad CTDB version 0x%x rejected\n", 
			  hdr->ctdb_version));
		goto failed;
	}

	/* tell the ctdb layer above that we have a packet */
	in->ctdb->upcalls->recv_pkt(in->ctdb, data, cnt);
	return;

failed:
	talloc_free(in);
}

/*
  queue a packet for sending
*/
int ctdb_tcp_queue_pkt(struct ctdb_node *node, uint8_t *data, uint32_t length)
{
	struct ctdb_tcp_node *tnode = talloc_get_type(node->private_data,
						      struct ctdb_tcp_node);
	return ctdb_queue_send(tnode->out_queue, data, length);
}
