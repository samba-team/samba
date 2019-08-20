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
#include "replace.h"
#include "system/time.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/debug.h"
#include "lib/util/samba_util.h"

#include "ctdb_private.h"
#include "ctdb_client.h"

#include "common/common.h"
#include "common/logging.h"

static void ctdb_ban_node_event(struct tevent_context *ev,
				struct tevent_timer *te,
				struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);

	/* Make sure we were able to freeze databases during banning */
	if (!ctdb_db_all_frozen(ctdb)) {
		DEBUG(DEBUG_ERR, ("Banning timed out, but not all databases "
				  "frozen yet - banning this node again.\n"));
		ctdb_ban_self(ctdb);
		return;
	}

	DEBUG(DEBUG_ERR,("Banning timed out\n"));
	ctdb->nodes[ctdb->pnn]->flags &= ~NODE_FLAGS_BANNED;

	if (ctdb->banning_ctx != NULL) {
		talloc_free(ctdb->banning_ctx);
		ctdb->banning_ctx = NULL;
	}
}

int32_t ctdb_control_set_ban_state(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_ban_state *bantime = (struct ctdb_ban_state *)indata.dptr;
	bool already_banned;

	DEBUG(DEBUG_INFO,("SET BAN STATE\n"));

	if (bantime->pnn != ctdb->pnn) {
		DEBUG(DEBUG_WARNING,
		      ("SET_BAN_STATE control for PNN %d ignored\n",
		       bantime->pnn));
		return -1;
	}

	already_banned = false;
	if (ctdb->banning_ctx != NULL) {
		talloc_free(ctdb->banning_ctx);
		ctdb->banning_ctx = NULL;
		already_banned = true;
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

	ctdb->banning_ctx = talloc(ctdb, struct ctdb_ban_state);
	if (ctdb->banning_ctx == NULL) {
		DEBUG(DEBUG_CRIT,(__location__ " ERROR Failed to allocate new banning state\n"));
		return -1;
	}
	*((struct ctdb_ban_state *)(ctdb->banning_ctx)) = *bantime;


	DEBUG(DEBUG_ERR,("Banning this node for %d seconds\n", bantime->time));
	ctdb->nodes[bantime->pnn]->flags |= NODE_FLAGS_BANNED;

	tevent_add_timer(ctdb->ev, ctdb->banning_ctx,
			 timeval_current_ofs(bantime->time,0),
			 ctdb_ban_node_event, ctdb);

	if (!already_banned) {
		ctdb_node_become_inactive(ctdb);
	}
	return 0;
}

int32_t ctdb_control_get_ban_state(struct ctdb_context *ctdb, TDB_DATA *outdata)
{
	struct ctdb_ban_state *bantime;

	bantime = talloc(outdata, struct ctdb_ban_state);
	CTDB_NO_MEMORY(ctdb, bantime);

	if (ctdb->banning_ctx != NULL) {
		*bantime = *(struct ctdb_ban_state *)(ctdb->banning_ctx);
	} else {
		bantime->pnn = ctdb->pnn;
		bantime->time = 0;
	}

	outdata->dptr  = (uint8_t *)bantime;
	outdata->dsize = sizeof(struct ctdb_ban_state);

	return 0;
}

/* Routine to ban ourselves for a while when trouble strikes. */
void ctdb_ban_self(struct ctdb_context *ctdb)
{
	TDB_DATA data;
	struct ctdb_ban_state bantime;

	bantime.pnn  = ctdb->pnn;
	bantime.time = ctdb->tunable.recovery_ban_period;

	data.dsize = sizeof(bantime);
	data.dptr  = (uint8_t *)&bantime;

	ctdb_control_set_ban_state(ctdb, data);
}
