/* 
   ctdb banning code

   Copyright (C) Ronnie Sahlberg  2009

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
#include "lib/events/events.h"
#include "lib/tdb/include/tdb.h"
#include "system/time.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "../include/ctdb.h"
#include "../include/ctdb_private.h"


static void
ctdb_ban_node_event(struct event_context *ev, struct timed_event *te, 
			       struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);

	DEBUG(DEBUG_ERR,("Banning timedout\n"));
	ctdb->nodes[ctdb->pnn]->flags &= ~NODE_FLAGS_BANNED;

	if (ctdb->banning_ctx != NULL) {
		talloc_free(ctdb->banning_ctx);
		ctdb->banning_ctx = NULL;
	}
}

int32_t ctdb_control_set_ban_state(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_ban_time *bantime = (struct ctdb_ban_time *)indata.dptr;

	DEBUG(DEBUG_INFO,("SET BAN STATE\n"));

	if (bantime->pnn != ctdb->pnn) {
		if (bantime->pnn < 0 || bantime->pnn >= ctdb->num_nodes) {
			DEBUG(DEBUG_ERR,(__location__ " ERROR: Invalid ban request. PNN:%d is invalid. Max nodes %d\n", bantime->pnn, ctdb->num_nodes));
			return -1;
		}
		if (bantime->time == 0) {
			DEBUG(DEBUG_INFO,("unbanning node %d\n", bantime->pnn));
			ctdb->nodes[bantime->pnn]->flags &= ~NODE_FLAGS_BANNED;
		} else {
			DEBUG(DEBUG_INFO,("banning node %d\n", bantime->pnn));
			if (ctdb->tunable.enable_bans == 0) {
				DEBUG(DEBUG_INFO,("Bans are disabled - ignoring ban of node %u\n", bantime->pnn));
				return 0;
			}

			ctdb->nodes[bantime->pnn]->flags |= NODE_FLAGS_BANNED;
		}
		return 0;
	}

	if (ctdb->banning_ctx != NULL) {
		talloc_free(ctdb->banning_ctx);
		ctdb->banning_ctx = NULL;
	}

	if (bantime->time == 0) {
		DEBUG(DEBUG_ERR,("Unbanning this node\n"));
		ctdb->nodes[bantime->pnn]->flags &= ~NODE_FLAGS_BANNED;
		return 0;
	}

	if (ctdb->tunable.enable_bans == 0) {
		DEBUG(DEBUG_ERR,("Bans are disabled - ignoring ban of node %u\n", bantime->pnn));
		return 0;
	}

	ctdb->banning_ctx = talloc(ctdb, struct ctdb_ban_time);
	if (ctdb->banning_ctx == NULL) {
		DEBUG(DEBUG_CRIT,(__location__ " ERROR Failed to allocate new banning state\n"));
		return -1;
	}
	*((struct ctdb_ban_time *)(ctdb->banning_ctx)) = *bantime;


	DEBUG(DEBUG_ERR,("Banning this node for %d seconds\n", bantime->time));
	ctdb->nodes[bantime->pnn]->flags |= NODE_FLAGS_BANNED;

	event_add_timed(ctdb->ev, ctdb->banning_ctx, timeval_current_ofs(bantime->time,0), ctdb_ban_node_event, ctdb);
	
	return 0;
}

int32_t ctdb_control_get_ban_state(struct ctdb_context *ctdb, TDB_DATA *outdata)
{
	struct ctdb_ban_time *bantime;

	bantime = talloc(outdata, struct ctdb_ban_time);
	CTDB_NO_MEMORY(ctdb, bantime);

	if (ctdb->banning_ctx != NULL) {
		*bantime = *(struct ctdb_ban_time *)(ctdb->banning_ctx);
	} else {
		bantime->pnn = ctdb->pnn;
		bantime->time = 0;
	}

	outdata->dptr  = (uint8_t *)bantime;
	outdata->dsize = sizeof(struct ctdb_ban_time);

	return 0;
}
