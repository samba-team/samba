/* 
   persistent store logic

   Copyright (C) Andrew Tridgell  2007
   Copyright (C) Ronnie Sahlberg  2007

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
#include "system/filesys.h"
#include "system/wait.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include "tdb.h"
#include "../include/ctdb_private.h"

struct ctdb_persistent_state {
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db; /* used by trans3_commit */
	struct ctdb_client *client; /* used by trans3_commit */
	struct ctdb_req_control *c;
	const char *errormsg;
	uint32_t num_pending;
	int32_t status;
	uint32_t num_failed, num_sent;
};

/*
  1) all nodes fail, and all nodes reply
  2) some nodes fail, all nodes reply
  3) some nodes timeout
  4) all nodes succeed
 */

/*
  called when a node has acknowledged a ctdb_control_update_record call
 */
static void ctdb_persistent_callback(struct ctdb_context *ctdb,
				     int32_t status, TDB_DATA data, 
				     const char *errormsg,
				     void *private_data)
{
	struct ctdb_persistent_state *state = talloc_get_type(private_data, 
							      struct ctdb_persistent_state);

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) {
		DEBUG(DEBUG_INFO, ("ctdb_persistent_callback: ignoring reply "
				   "during recovery\n"));
		return;
	}

	if (status != 0) {
		DEBUG(DEBUG_ERR,("ctdb_persistent_callback failed with status %d (%s)\n",
			 status, errormsg?errormsg:"no error message given"));
		state->status = status;
		state->errormsg = errormsg;
		state->num_failed++;

		/*
		 * If a node failed to complete the update_record control,
		 * then either a recovery is already running or something
		 * bad is going on. So trigger a recovery and let the
		 * recovery finish the transaction, sending back the reply
		 * for the trans3_commit control to the client.
		 */
		ctdb->recovery_mode = CTDB_RECOVERY_ACTIVE;
		return;
	}

	state->num_pending--;

	if (state->num_pending != 0) {
		return;
	}

	ctdb_request_control_reply(state->ctdb, state->c, NULL, 0, state->errormsg);
	talloc_free(state);
}

/*
  called if persistent store times out
 */
static void ctdb_persistent_store_timeout(struct event_context *ev, struct timed_event *te, 
					 struct timeval t, void *private_data)
{
	struct ctdb_persistent_state *state = talloc_get_type(private_data, struct ctdb_persistent_state);

	if (state->ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) {
		DEBUG(DEBUG_INFO, ("ctdb_persistent_store_timeout: ignoring "
				   "timeout during recovery\n"));
		return;
	}

	ctdb_request_control_reply(state->ctdb, state->c, NULL, 1,
				   "timeout in ctdb_persistent_state");

	talloc_free(state);
}

/**
 * Finish pending trans3 commit controls, i.e. send
 * reply to the client. This is called by the end-recovery
 * control to fix the situation when a recovery interrupts
 * the usual progress of a transaction.
 */
void ctdb_persistent_finish_trans3_commits(struct ctdb_context *ctdb)
{
	struct ctdb_db_context *ctdb_db;

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) {
		DEBUG(DEBUG_INFO, ("ctdb_persistent_finish_trans3_commits: "
				   "skipping execution when recovery is "
				   "active\n"));
		return;
	}

	for (ctdb_db = ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
		struct ctdb_persistent_state *state;

		if (ctdb_db->persistent_state == NULL) {
			continue;
		}

		state = ctdb_db->persistent_state;

		ctdb_request_control_reply(ctdb, state->c, NULL, 2,
					   "trans3 commit ended by recovery");

		/* The destructor sets ctdb_db->persistent_state to NULL. */
		talloc_free(state);
	}
}

static int ctdb_persistent_state_destructor(struct ctdb_persistent_state *state)
{
	if (state->client != NULL) {
		state->client->db_id = 0;
	}

	if (state->ctdb_db != NULL) {
		state->ctdb_db->persistent_state = NULL;
	}

	return 0;
}

/*
 * Store a set of persistent records.
 * This is used to roll out a transaction to all nodes.
 */
int32_t ctdb_control_trans3_commit(struct ctdb_context *ctdb,
				   struct ctdb_req_control *c,
				   TDB_DATA recdata, bool *async_reply)
{
	struct ctdb_client *client;
	struct ctdb_persistent_state *state;
	int i;
	struct ctdb_marshall_buffer *m = (struct ctdb_marshall_buffer *)recdata.dptr;
	struct ctdb_db_context *ctdb_db;

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) {
		DEBUG(DEBUG_INFO,("rejecting ctdb_control_trans3_commit when recovery active\n"));
		return -1;
	}

	client = ctdb_reqid_find(ctdb, c->client_id, struct ctdb_client);
	if (client == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " can not match persistent_store "
				 "to a client. Returning error\n"));
		return -1;
	}

	if (client->db_id != 0) {
		DEBUG(DEBUG_ERR,(__location__ " ERROR: trans3_commit: "
				 "client-db_id[0x%08x] != 0 "
				 "(client_id[0x%08x]): trans3_commit active?\n",
				 client->db_id, client->client_id));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, m->db_id);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control_trans3_commit: "
				 "Unknown database db_id[0x%08x]\n", m->db_id));
		return -1;
	}

	if (ctdb_db->persistent_state != NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Error: "
				  "ctdb_control_trans3_commit "
				  "called while a transaction commit is "
				  "active. db_id[0x%08x]\n", m->db_id));
		return -1;
	}

	ctdb_db->persistent_state = talloc_zero(ctdb_db,
						struct ctdb_persistent_state);
	CTDB_NO_MEMORY(ctdb, ctdb_db->persistent_state);

	client->db_id = m->db_id;

	state = ctdb_db->persistent_state;
	state->ctdb = ctdb;
	state->ctdb_db = ctdb_db;
	state->c    = c;
	state->client = client;

	talloc_set_destructor(state, ctdb_persistent_state_destructor);

	for (i = 0; i < ctdb->vnn_map->size; i++) {
		struct ctdb_node *node = ctdb->nodes[ctdb->vnn_map->map[i]];
		int ret;

		/* only send to active nodes */
		if (node->flags & NODE_FLAGS_INACTIVE) {
			continue;
		}

		ret = ctdb_daemon_send_control(ctdb, node->pnn, 0,
					       CTDB_CONTROL_UPDATE_RECORD,
					       c->client_id, 0, recdata,
					       ctdb_persistent_callback,
					       state);
		if (ret == -1) {
			DEBUG(DEBUG_ERR,("Unable to send "
					 "CTDB_CONTROL_UPDATE_RECORD "
					 "to pnn %u\n", node->pnn));
			talloc_free(state);
			return -1;
		}

		state->num_pending++;
		state->num_sent++;
	}

	if (state->num_pending == 0) {
		talloc_free(state);
		return 0;
	}

	/* we need to wait for the replies */
	*async_reply = true;

	/* need to keep the control structure around */
	talloc_steal(state, c);

	/* but we won't wait forever */
	event_add_timed(ctdb->ev, state,
			timeval_current_ofs(ctdb->tunable.control_timeout, 0),
			ctdb_persistent_store_timeout, state);

	return 0;
}


/*
  backwards compatibility:

  start a persistent store operation. passing both the key, header and
  data to the daemon. If the client disconnects before it has issued
  a persistent_update call to the daemon we trigger a full recovery
  to ensure the databases are brought back in sync.
  for now we ignore the recdata that the client has passed to us.
 */
int32_t ctdb_control_start_persistent_update(struct ctdb_context *ctdb, 
				      struct ctdb_req_control *c,
				      TDB_DATA recdata)
{
	struct ctdb_client *client = ctdb_reqid_find(ctdb, c->client_id, struct ctdb_client);

	if (client == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " can not match start_persistent_update to a client. Returning error\n"));
		return -1;
	}

	client->num_persistent_updates++;

	return 0;
}

/* 
  backwards compatibility:

  called to tell ctdbd that it is no longer doing a persistent update 
*/
int32_t ctdb_control_cancel_persistent_update(struct ctdb_context *ctdb, 
					      struct ctdb_req_control *c,
					      TDB_DATA recdata)
{
	struct ctdb_client *client = ctdb_reqid_find(ctdb, c->client_id, struct ctdb_client);

	if (client == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " can not match cancel_persistent_update to a client. Returning error\n"));
		return -1;
	}

	if (client->num_persistent_updates > 0) {
		client->num_persistent_updates--;
	}

	return 0;
}

static int32_t ctdb_get_db_seqnum(struct ctdb_context *ctdb,
				  uint32_t db_id,
				  uint64_t *seqnum)
{
	int32_t ret;
	struct ctdb_db_context *ctdb_db;
	const char *keyname = CTDB_DB_SEQNUM_KEY;
	TDB_DATA key;
	TDB_DATA data;
	TALLOC_CTX *mem_ctx = talloc_new(ctdb);
	struct ctdb_ltdb_header header;

	ctdb_db = find_ctdb_db(ctdb, db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR,(__location__ " Unknown db 0x%08x\n", db_id));
		ret = -1;
		goto done;
	}

	key.dptr = (uint8_t *)discard_const(keyname);
	key.dsize = strlen(keyname) + 1;

	ret = (int32_t)ctdb_ltdb_fetch(ctdb_db, key, &header, mem_ctx, &data);
	if (ret != 0) {
		goto done;
	}

	if (data.dsize != sizeof(uint64_t)) {
		*seqnum = 0;
		goto done;
	}

	*seqnum = *(uint64_t *)data.dptr;

done:
	talloc_free(mem_ctx);
	return ret;
}

/**
 * Get the sequence number of a persistent database.
 */
int32_t ctdb_control_get_db_seqnum(struct ctdb_context *ctdb,
				   TDB_DATA indata,
				   TDB_DATA *outdata)
{
	uint32_t db_id;
	int32_t ret;
	uint64_t seqnum;

	db_id = *(uint32_t *)indata.dptr;
	ret = ctdb_get_db_seqnum(ctdb, db_id, &seqnum);
	if (ret != 0) {
		goto done;
	}

	outdata->dsize = sizeof(uint64_t);
	outdata->dptr = (uint8_t *)talloc_zero(outdata, uint64_t);
	if (outdata->dptr == NULL) {
		ret = -1;
		goto done;
	}

	*(outdata->dptr) = seqnum;

done:
	return ret;
}
