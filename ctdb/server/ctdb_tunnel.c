/*
   ctdb_tunnel protocol code

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
#include <tevent.h>
#include <tdb.h>

#include "lib/util/debug.h"

#include "common/logging.h"
#include "common/reqid.h"
#include "common/srvid.h"

#include "ctdb_private.h"

int32_t ctdb_control_tunnel_register(struct ctdb_context *ctdb,
				     uint32_t client_id, uint64_t tunnel_id)
{
	struct ctdb_client *client;
	int ret;

	client = reqid_find(ctdb->idr, client_id, struct ctdb_client);
	if (client == NULL) {
		DEBUG(DEBUG_ERR, ("Bad client_id in ctdb_tunnel_register\n"));
		return -1;
	}

	ret = srvid_exists(ctdb->tunnels, tunnel_id, NULL);
	if (ret == 0) {
		DEBUG(DEBUG_ERR,
		      ("Tunnel id 0x%"PRIx64" already registered\n",
		       tunnel_id));
		return -1;
	}

	ret = srvid_register(ctdb->tunnels, client, tunnel_id,
			     daemon_tunnel_handler, client);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Failed to register tunnel id 0x%"PRIx64"\n",
		       tunnel_id));
		return -1;
	}

	DEBUG(DEBUG_INFO, ("Registered tunnel for id 0x%"PRIx64"\n",
			   tunnel_id));
	return 0;
}

int32_t ctdb_control_tunnel_deregister(struct ctdb_context *ctdb,
				       uint32_t client_id, uint64_t tunnel_id)
{
	struct ctdb_client *client;
	int ret;

	client = reqid_find(ctdb->idr, client_id, struct ctdb_client);
	if (client == NULL) {
		DEBUG(DEBUG_ERR, ("Bad client_id in ctdb_tunnel_deregister\n"));
		return -1;
	}

	ret = srvid_deregister(ctdb->tunnels, tunnel_id, client);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Failed to deregister tunnel id 0x%"PRIx64"\n",
		       tunnel_id));
		return -1;
	}

	return 0;
}

int ctdb_daemon_send_tunnel(struct ctdb_context *ctdb, uint32_t destnode,
			    uint64_t tunnel_id, uint32_t flags, TDB_DATA data)
{
	struct ctdb_req_tunnel_old *c;
	size_t len;

	if (ctdb->methods == NULL) {
		DEBUG(DEBUG_INFO,
		      ("Failed to send tunnel. Transport is DOWN\n"));
		return -1;
	}

	len = offsetof(struct ctdb_req_tunnel_old, data) + data.dsize;
	c = ctdb_transport_allocate(ctdb, ctdb, CTDB_REQ_TUNNEL, len,
				    struct ctdb_req_tunnel_old);
	if (c == NULL) {
		DEBUG(DEBUG_ERR,
		      ("Memory error in ctdb_daemon_send_tunnel()\n"));
		return -1;
	}

	c->hdr.destnode = destnode;
	c->tunnel_id = tunnel_id;
	c->flags = flags;
	c->datalen = data.dsize;
	memcpy(c->data, data.dptr, data.dsize);

	ctdb_queue_packet(ctdb, &c->hdr);

	talloc_free(c);
	return 0;
}

void ctdb_request_tunnel(struct ctdb_context *ctdb,
			 struct ctdb_req_header *hdr)
{
	struct ctdb_req_tunnel_old *c =
		(struct ctdb_req_tunnel_old *)hdr;
	TDB_DATA data;
	int ret;

	data.dsize = hdr->length;
	data.dptr = (uint8_t *)c;

	ret = srvid_dispatch(ctdb->tunnels, c->tunnel_id, 0, data);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Tunnel id 0x%"PRIx64" not registered\n",
				  c->tunnel_id));
	}
}
