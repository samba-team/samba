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
