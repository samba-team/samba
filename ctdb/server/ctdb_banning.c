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
#include "tdb.h"
#include "system/time.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "../include/ctdb_client.h"
#include "../include/ctdb_private.h"


static void
ctdb_ban_node_event(struct event_context *ev, struct timed_event *te, 
			       struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);
	bool freeze_failed = false;
	int i;

	/* Make sure we were able to freeze databases during banning */
	for (i=1; i<=NUM_DB_PRIORITIES; i++) {
		if (ctdb->freeze_mode[i] != CTDB_FREEZE_FROZEN) {
			freeze_failed = true;
			break;
		}
	}
	if (freeze_failed) {
		DEBUG(DEBUG_ERR, ("Banning timedout, but still unable to freeze databases\n"));
		ctdb_ban_self(ctdb);
		return;
	}

	DEBUG(DEBUG_ERR,("Banning timedout\n"));
	ctdb->nodes[ctdb->pnn]->flags &= ~NODE_FLAGS_BANNED;

	if (ctdb->banning_ctx != NULL) {
		talloc_free(ctdb->banning_ctx);
		ctdb->banning_ctx = NULL;
	}
}

void ctdb_local_node_got_banned(struct ctdb_context *ctdb)
{
	uint32_t i;

	/* make sure we are frozen */
	DEBUG(DEBUG_NOTICE,("This node has been banned - forcing freeze and recovery\n"));

	/* Reset the generation id to 1 to make us ignore any
	   REQ/REPLY CALL/DMASTER someone sends to us.
	   We are now banned so we shouldnt service database calls
	   anymore.
	*/
	ctdb->vnn_map->generation = INVALID_GENERATION;

	ctdb->recovery_mode = CTDB_RECOVERY_ACTIVE;
	for (i=1; i<=NUM_DB_PRIORITIES; i++) {
		ctdb_start_freeze(ctdb, i);
	}
	ctdb_release_all_ips(ctdb);
}

int32_t ctdb_control_set_ban_state(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_ban_time *bantime = (struct ctdb_ban_time *)indata.dptr;

	DEBUG(DEBUG_INFO,("SET BAN STATE\n"));

	if (bantime->pnn != ctdb->pnn) {
		if (bantime->pnn >= ctdb->num_nodes) {
			DEBUG(DEBUG_ERR,(__location__ " ERROR: Invalid ban request. PNN:%d is invalid. Max nodes %d\n", bantime->pnn, ctdb->num_nodes));
			return -1;
		}
		if (bantime->time == 0) {
			DEBUG(DEBUG_NOTICE,("unbanning node %d\n", bantime->pnn));
			ctdb->nodes[bantime->pnn]->flags &= ~NODE_FLAGS_BANNED;
		} else {
			DEBUG(DEBUG_NOTICE,("banning node %d\n", bantime->pnn));
			if (ctdb->tunable.enable_bans == 0) {
				/* FIXME: This is bogus. We really should be
				 * taking decision based on the tunables on
				 * the banned node and not local node.
				 */
				DEBUG(DEBUG_WARNING,("Bans are disabled - ignoring ban of node %u\n", bantime->pnn));
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

	ctdb_local_node_got_banned(ctdb);
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

/* Routine to ban ourselves for a while when trouble strikes. */
void ctdb_ban_self(struct ctdb_context *ctdb)
{
	TDB_DATA data;
	struct ctdb_ban_time bantime;

	bantime.pnn  = ctdb->pnn;
	bantime.time = ctdb->tunable.recovery_ban_period;

	data.dsize = sizeof(bantime);
	data.dptr  = (uint8_t *)&bantime;

	ctdb_control_set_ban_state(ctdb, data);
}
