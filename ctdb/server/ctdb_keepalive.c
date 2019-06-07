/* 
   monitoring links to all other nodes to detect dead nodes


   Copyright (C) Ronnie Sahlberg 2007

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
#include "system/filesys.h"
#include "system/network.h"
#include "system/time.h"
#include "system/wait.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/debug.h"
#include "lib/util/samba_util.h"

#include "ctdb_private.h"
#include "version.h"

#include "common/common.h"
#include "common/logging.h"


static uint32_t keepalive_version(void)
{
	static uint32_t version = 0;

	if (version == 0) {
		const char *t;

		version = (SAMBA_VERSION_MAJOR << 16) | SAMBA_VERSION_MINOR;

		t = getenv("CTDB_TEST_SAMBA_VERSION");
		if (t != NULL) {
			int v;

			v = atoi(t);
			if (v <= 0) {
				DBG_WARNING("Failed to parse env var: %s\n", t);
			} else {
				version = v;
			}
		}
	}

	return version;
}

static uint32_t keepalive_uptime(struct ctdb_context *ctdb)
{
	struct timeval current = tevent_timeval_current();

	return current.tv_sec - ctdb->ctdbd_start_time.tv_sec;
}

/*
   send a keepalive packet to the other node
*/
static void ctdb_send_keepalive(struct ctdb_context *ctdb, uint32_t destnode)
{
	struct ctdb_req_keepalive_old *r;

	if (ctdb->methods == NULL) {
		DEBUG(DEBUG_INFO,
		      ("Failed to send keepalive. Transport is DOWN\n"));
		return;
	}

	r = ctdb_transport_allocate(ctdb, ctdb, CTDB_REQ_KEEPALIVE,
				    sizeof(struct ctdb_req_keepalive_old),
				    struct ctdb_req_keepalive_old);
	CTDB_NO_MEMORY_FATAL(ctdb, r);
	r->hdr.destnode  = destnode;
	r->hdr.reqid     = 0;

	r->version = keepalive_version();
	r->uptime = keepalive_uptime(ctdb);

	CTDB_INCREMENT_STAT(ctdb, keepalive_packets_sent);

	ctdb_queue_packet(ctdb, &r->hdr);

	talloc_free(r);
}

/*
  see if any nodes are dead
 */
static void ctdb_check_for_dead_nodes(struct tevent_context *ev,
				      struct tevent_timer *te,
				      struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);
	unsigned int i;

	/* send a keepalive to all other nodes, unless */
	for (i=0;i<ctdb->num_nodes;i++) {
		struct ctdb_node *node = ctdb->nodes[i];

		if (node->flags & NODE_FLAGS_DELETED) {
			continue;
		}

		if (node->pnn == ctdb->pnn) {
			continue;
		}
		
		if (node->flags & NODE_FLAGS_DISCONNECTED) {
			/* it might have come alive again */
			if (node->rx_cnt != 0) {
				ctdb_node_connected(node);
			}
			continue;
		}


		if (node->rx_cnt == 0) {
			node->dead_count++;
		} else {
			node->dead_count = 0;
		}

		node->rx_cnt = 0;

		if (node->dead_count >= ctdb->tunable.keepalive_limit) {
			DEBUG(DEBUG_NOTICE,("dead count reached for node %u\n", node->pnn));
			ctdb_node_dead(node);
			ctdb_send_keepalive(ctdb, node->pnn);
			/* maybe tell the transport layer to kill the
			   sockets as well?
			*/
			continue;
		}
		
		DEBUG(DEBUG_DEBUG,("sending keepalive to %u\n", node->pnn));
		ctdb_send_keepalive(ctdb, node->pnn);

		node->tx_cnt = 0;
	}

	tevent_add_timer(ctdb->ev, ctdb->keepalive_ctx,
			 timeval_current_ofs(ctdb->tunable.keepalive_interval, 0),
			 ctdb_check_for_dead_nodes, ctdb);
}


void ctdb_start_keepalive(struct ctdb_context *ctdb)
{
	struct tevent_timer *te;

	ctdb->keepalive_ctx = talloc_new(ctdb);
	CTDB_NO_MEMORY_FATAL(ctdb, ctdb->keepalive_ctx);

	te = tevent_add_timer(ctdb->ev, ctdb->keepalive_ctx,
			      timeval_current_ofs(ctdb->tunable.keepalive_interval, 0),
			      ctdb_check_for_dead_nodes, ctdb);
	CTDB_NO_MEMORY_FATAL(ctdb, te);

	DEBUG(DEBUG_NOTICE,("Keepalive monitoring has been started\n"));

	if (ctdb->tunable.allow_mixed_versions == 1) {
		DEBUG(DEBUG_WARNING,
		      ("CTDB cluster with mixed versions configured\n"));
	}
}

void ctdb_stop_keepalive(struct ctdb_context *ctdb)
{
	talloc_free(ctdb->keepalive_ctx);
	ctdb->keepalive_ctx = NULL;
}

void ctdb_request_keepalive(struct ctdb_context *ctdb,
			    struct ctdb_req_header *hdr)
{
	struct ctdb_req_keepalive_old *c =
		(struct ctdb_req_keepalive_old *)hdr;
	uint32_t my_version = keepalive_version();
	uint32_t my_uptime = keepalive_uptime(ctdb);

	/* Don't check anything if mixed versions are allowed */
	if (ctdb->tunable.allow_mixed_versions == 1) {
		return;
	}

	if (hdr->length == sizeof(struct ctdb_req_header)) {
		/* Old keepalive */
		goto fail1;
	}

	if (c->version != my_version) {
		if (c->uptime > my_uptime) {
			goto fail2;
		} else if (c->uptime == my_uptime) {
			if (c->version > my_version) {
				goto fail2;
			}
		}
	}

	return;

fail1:
	DEBUG(DEBUG_ERR,
	      ("Keepalive version missing from node %u\n", hdr->srcnode));
	goto shutdown;

fail2:
	DEBUG(DEBUG_ERR,
	      ("Keepalive version mismatch 0x%08x != 0x%08x from node %u\n",
	       my_version, c->version, hdr->srcnode));
	goto shutdown;

shutdown:
	DEBUG(DEBUG_ERR,
	      ("CTDB Cluster with mixed versions, cannot continue\n"));
	ctdb_shutdown_sequence(ctdb, 0);
}
