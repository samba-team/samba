/* 
   Unix SMB/CIFS implementation.

   ctdb clustering hooks

   Copyright (C) Andrew Tridgell 2006
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "lib/events/events.h"
#include "cluster/cluster.h"
#include "system/filesys.h"
#include "cluster/cluster_private.h"
#include "lib/tdb/include/tdb.h"
#include "cluster/ctdb/include/ctdb.h"

struct cluster_state {
	struct ctdb_context *ctdb;
};


/*
  return a server_id for a ctdb node
*/
static struct server_id ctdb_id(struct cluster_ops *ops, uint32_t id)
{
	struct ctdb_context *ctdb = ops->private;
	struct server_id server_id;
	server_id.node = ctdb_get_vnn(ctdb);
	server_id.id = id;
	return server_id;
}


/*
  return a server_id as a string
*/
static const char *ctdb_id_string(struct cluster_ops *ops, 
				  TALLOC_CTX *mem_ctx, struct server_id id)
{
	return talloc_asprintf(mem_ctx, "%u.%u", id.node, id.id);
}

static struct cluster_ops cluster_ctdb_ops = {
	.cluster_id        = ctdb_id,
	.cluster_id_string = ctdb_id_string,
	.private           = NULL
};

/* initialise ctdb */
void cluster_ctdb_init(struct event_context *ev)
{
	const char *nlist;
	const char *address;
	const char *transport;
	struct cluster_state *state;
	int ret;

	nlist = lp_parm_string(-1, "ctdb", "nlist");
	if (nlist == NULL) return;

	address = lp_parm_string(-1, "ctdb", "address");
	if (address == NULL) return;

	transport = lp_parm_string(-1, "ctdb", "transport");
	if (transport == NULL) {
		transport = "tcp";
	}

	state = talloc(ev, struct cluster_state);
	if (state == NULL) goto failed;

	state->ctdb = ctdb_init(ev);
	if (state->ctdb == NULL) goto failed;

	cluster_ctdb_ops.private = state->ctdb;

	ret = ctdb_set_transport(state->ctdb, transport);
	if (ret == -1) {
		DEBUG(0,("ctdb_set_transport failed - %s\n",
			 ctdb_errstr(state->ctdb)));
		goto failed;
	}
	
//	ctdb_set_flags(state->ctdb, CTDB_FLAG_SELF_CONNECT);

	/* tell ctdb what address to listen on */
        ret = ctdb_set_address(state->ctdb, address);
        if (ret == -1) {
                DEBUG(0,("ctdb_set_address failed - %s\n", ctdb_errstr(state->ctdb)));
		goto failed;
        }

        /* tell ctdb what nodes are available */
        ret = ctdb_set_nlist(state->ctdb, nlist);
        if (ret == -1) {
                DEBUG(0,("ctdb_set_nlist failed - %s\n", ctdb_errstr(state->ctdb)));
		goto failed;
        }

	ret = ctdb_attach(state->ctdb, "cluster.tdb", TDB_DEFAULT, O_RDWR|O_CREAT|O_TRUNC, 0666);
	if (ret == -1) {
		DEBUG(0,("ctdb_attach failed - %s\n", ctdb_errstr(state->ctdb)));
		goto failed;
	}

	/* start the protocol running */
	ret = ctdb_start(state->ctdb);
        if (ret == -1) {
                DEBUG(0,("ctdb_start failed - %s\n", ctdb_errstr(state->ctdb)));
		goto failed;
        }

	/* wait until all nodes are connected (should not be needed
	   outide of test code) */
	ctdb_connect_wait(state->ctdb);

	cluster_set_ops(&cluster_ctdb_ops);
	return;
	
failed:
	DEBUG(0,("cluster_ctdb_init failed\n"));
	talloc_free(state);
}
