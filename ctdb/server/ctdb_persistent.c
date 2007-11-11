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
#include "lib/events/events.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "db_wrap.h"
#include "lib/tdb/include/tdb.h"
#include "../include/ctdb_private.h"

struct ctdb_persistent_state {
	struct ctdb_context *ctdb;
	struct ctdb_req_control *c;
	const char *errormsg;
	uint32_t num_pending;
	int32_t status;
};

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

	if (status != 0) {
		DEBUG(0,("ctdb_persistent_callback failed with status %d (%s)\n",
			 status, errormsg));
		state->status = status;
		state->errormsg = errormsg;
	}
	state->num_pending--;
	if (state->num_pending == 0) {
		ctdb_request_control_reply(state->ctdb, state->c, NULL, state->status, state->errormsg);
		talloc_free(state);
	}
}

/*
  called if persistent store times out
 */
static void ctdb_persistent_store_timeout(struct event_context *ev, struct timed_event *te, 
					 struct timeval t, void *private_data)
{
	struct ctdb_persistent_state *state = talloc_get_type(private_data, struct ctdb_persistent_state);
	
	ctdb_request_control_reply(state->ctdb, state->c, NULL, -1, "timeout in ctdb_persistent_state");

	talloc_free(state);
}

/*
  store a persistent record - called from a ctdb client when it has updated
  a record in a persistent database. The client will have the record
  locked for the duration of this call. The client is the dmaster when 
  this call is made
 */
int32_t ctdb_control_persistent_store(struct ctdb_context *ctdb, 
				      struct ctdb_req_control *c, 
				      TDB_DATA recdata, bool *async_reply)
{
	struct ctdb_persistent_state *state;
	int i;

	state = talloc_zero(c, struct ctdb_persistent_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->ctdb = ctdb;
	state->c    = c;

	for (i=0;i<ctdb->vnn_map->size;i++) {
		struct ctdb_node *node = ctdb->nodes[ctdb->vnn_map->map[i]];
		int ret;

		/* only send to active nodes */
		if (node->flags & NODE_FLAGS_INACTIVE) {
			continue;
		}

		/* don't send to ourselves */
		if (node->pnn == ctdb->pnn) {
			continue;
		}
		
		ret = ctdb_daemon_send_control(ctdb, node->pnn, 0, CTDB_CONTROL_UPDATE_RECORD,
					       c->client_id, 0, recdata, 
					       ctdb_persistent_callback, state);
		if (ret == -1) {
			DEBUG(0,("Unable to send CTDB_CONTROL_UPDATE_RECORD to pnn %u\n", node->pnn));
			talloc_free(state);
			return -1;
		}

		state->num_pending++;
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


struct ctdb_persistent_lock_state {
	struct ctdb_db_context *ctdb_db;
	TDB_DATA key;
	TDB_DATA data;
	struct ctdb_ltdb_header *header;
	struct tdb_context *tdb;
	struct ctdb_req_control *c;
};


/*
  called with a lock held in the current process
 */
static int ctdb_persistent_store(struct ctdb_persistent_lock_state *state)
{
	struct ctdb_ltdb_header oldheader;
	int ret;

	/* fetch the old header and ensure the rsn is less than the new rsn */
	ret = ctdb_ltdb_fetch(state->ctdb_db, state->key, &oldheader, NULL, NULL);
	if (ret != 0) {
		DEBUG(0,("Failed to fetch old record for db_id 0x%08x in ctdb_persistent_store\n",
			 state->ctdb_db->db_id));
		return -1;
	}

	if (oldheader.rsn >= state->header->rsn) {
		DEBUG(0,("existing header for db_id 0x%08x has larger RSN %llu than new RSN %llu in ctdb_persistent_store\n",
			 state->ctdb_db->db_id, 
			 (unsigned long long)oldheader.rsn, (unsigned long long)state->header->rsn));
		return -1;
	}

	ret = ctdb_ltdb_store(state->ctdb_db, state->key, state->header, state->data);
	if (ret != 0) {
		DEBUG(0,("Failed to store record for db_id 0x%08x in ctdb_persistent_store\n", 
			 state->ctdb_db->db_id));
		return -1;
	}

	return 0;
}


/*
  called when we get the lock on the given record
  at this point the lockwait child holds a lock on our behalf
 */
static void ctdb_persistent_lock_callback(void *private_data)
{
	struct ctdb_persistent_lock_state *state = talloc_get_type(private_data, 
								   struct ctdb_persistent_lock_state);
	int ret;

	ret = tdb_chainlock_mark(state->tdb, state->key);
	if (ret != 0) {
		DEBUG(0,("Failed to mark lock in ctdb_persistent_lock_callback\n"));
		ctdb_request_control_reply(state->ctdb_db->ctdb, state->c, NULL, ret, NULL);
		return;
	}

	ret = ctdb_persistent_store(state);
	ctdb_request_control_reply(state->ctdb_db->ctdb, state->c, NULL, ret, NULL);
	tdb_chainlock_unmark(state->tdb, state->key);
}

/*
  called if our lockwait child times out
 */
static void ctdb_persistent_lock_timeout(struct event_context *ev, struct timed_event *te, 
					 struct timeval t, void *private_data)
{
	struct ctdb_persistent_lock_state *state = talloc_get_type(private_data, 
								   struct ctdb_persistent_lock_state);
	ctdb_request_control_reply(state->ctdb_db->ctdb, state->c, NULL, -1, "timeout in ctdb_persistent_lock");
	talloc_free(state);
}


/* 
   update a record on this node if the new record has a higher rsn than the
   current record
 */
int32_t ctdb_control_update_record(struct ctdb_context *ctdb, 
				   struct ctdb_req_control *c, TDB_DATA recdata, 
				   bool *async_reply)
{
	struct ctdb_rec_data *rec = (struct ctdb_rec_data *)&recdata.dptr[0];
	int ret;
	struct ctdb_db_context *ctdb_db;
	uint32_t db_id = rec->reqid;
	struct lockwait_handle *handle;
	struct ctdb_persistent_lock_state *state;

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) {
		DEBUG(0,("rejecting ctdb_control_update_record when recovery active\n"));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, db_id);
	if (ctdb_db == NULL) {
		DEBUG(0,("Unknown database 0x%08x in ctdb_control_update_record\n", db_id));
		return -1;
	}

	state = talloc(c, struct ctdb_persistent_lock_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->ctdb_db = ctdb_db;
	state->c       = c;
	state->tdb     = ctdb_db->ltdb->tdb;
	state->key.dptr   = &rec->data[0];
	state->key.dsize  = rec->keylen;
	state->data.dptr  = &rec->data[rec->keylen];
	state->data.dsize = rec->datalen;

	if (state->data.dsize < sizeof(struct ctdb_ltdb_header)) {
		DEBUG(0,("Invalid data size %u in ctdb_control_update_record\n", 
			 (unsigned)state->data.dsize));
		return -1;
	}

	state->header = (struct ctdb_ltdb_header *)&state->data.dptr[0];
	state->data.dptr  += sizeof(struct ctdb_ltdb_header);
	state->data.dsize -= sizeof(struct ctdb_ltdb_header);

	/* try and do it without a lockwait */
	ret = tdb_chainlock_nonblock(state->tdb, state->key);
	if (ret == 0) {
		ret = ctdb_persistent_store(state);
		tdb_chainunlock(state->tdb, state->key);
		return ret;
	}

	/* wait until we have a lock on this record */
	handle = ctdb_lockwait(ctdb_db, state->key, ctdb_persistent_lock_callback, state);
	if (handle == NULL) {
		DEBUG(0,("Failed to setup lockwait handler in ctdb_control_update_record\n"));
		return -1;
	}

	*async_reply = true;

	event_add_timed(ctdb->ev, state, timeval_current_ofs(ctdb->tunable.control_timeout, 0),
			ctdb_persistent_lock_timeout, state);

	return 0;
}
