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

	if (status != 0) {
		DEBUG(DEBUG_ERR,("ctdb_persistent_callback failed with status %d (%s)\n",
			 status, errormsg));
		state->status = status;
		state->errormsg = errormsg;
		state->num_failed++;
	}
	state->num_pending--;
	if (state->num_pending == 0) {
		enum ctdb_trans2_commit_error etype;
		if (state->num_failed == state->num_sent) {
			etype = CTDB_TRANS2_COMMIT_ALLFAIL;
		} else if (state->num_failed != 0) {
			etype = CTDB_TRANS2_COMMIT_SOMEFAIL;
		} else {
			etype = CTDB_TRANS2_COMMIT_SUCCESS;
		}
		ctdb_request_control_reply(state->ctdb, state->c, NULL, etype, state->errormsg);
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
	
	ctdb_request_control_reply(state->ctdb, state->c, NULL, CTDB_TRANS2_COMMIT_TIMEOUT, 
				   "timeout in ctdb_persistent_state");

	talloc_free(state);
}

/*
  store a set of persistent records - called from a ctdb client when it has updated
  some records in a persistent database. The client will have the record
  locked for the duration of this call. The client is the dmaster when 
  this call is made
 */
int32_t ctdb_control_trans2_commit(struct ctdb_context *ctdb, 
				   struct ctdb_req_control *c, 
				   TDB_DATA recdata, bool *async_reply)
{
	struct ctdb_client *client = ctdb_reqid_find(ctdb, c->client_id, struct ctdb_client);
	struct ctdb_persistent_state *state;
	int i;
	struct ctdb_marshall_buffer *m = (struct ctdb_marshall_buffer *)recdata.dptr;
	struct ctdb_db_context *ctdb_db;

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) {
		DEBUG(DEBUG_INFO,("rejecting ctdb_control_trans2_commit when recovery active\n"));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, m->db_id);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control_trans2_commit: "
				 "Unknown database 0x%08x\n", m->db_id));
		return -1;
	}

	if (client == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " can not match persistent_store to a client. Returning error\n"));
		return -1;
	}

	/* handling num_persistent_updates is a bit strange - 
	   there are 3 cases
	     1) very old clients, which never called CTDB_CONTROL_START_PERSISTENT_UPDATE
	        They don't expect num_persistent_updates to be used at all

	     2) less old clients, which uses CTDB_CONTROL_START_PERSISTENT_UPDATE, and expected
	        this commit to then decrement it

             3) new clients which use TRANS2 commit functions, and
	        expect this function to increment the counter, and
	        then have it decremented in ctdb_control_trans2_error
	        or ctdb_control_trans2_finished
	*/
	switch (c->opcode) {
	case CTDB_CONTROL_PERSISTENT_STORE:
		if (ctdb_db->transaction_active) {
			DEBUG(DEBUG_ERR, (__location__ " trans2_commit client db_id[%d] transaction active - refusing persistent store\n",
				client->db_id));
			return -1;
		}
		if (client->num_persistent_updates > 0) {
			client->num_persistent_updates--;
		}
		break;
	case CTDB_CONTROL_TRANS2_COMMIT:
		if (ctdb_db->transaction_active) {
			DEBUG(DEBUG_ERR,(__location__ " trans2_commit: client "
					 "already has a transaction commit "
					 "active on db_id[%d]\n",
					 client->db_id));
			return -1;
		}
		if (client->db_id != 0) {
			DEBUG(DEBUG_ERR,(__location__ " ERROR: trans2_commit: "
					 "client-db_id[%d] != 0\n",
					 client->db_id));
			return -1;
		}
		client->num_persistent_updates++;
		ctdb_db->transaction_active = true;
		client->db_id = m->db_id;
		DEBUG(DEBUG_DEBUG, (__location__ " client id[0x%08x] started to"
				  " commit transaction on db id[0x%08x]\n",
				  client->client_id, client->db_id));
		break;
	case CTDB_CONTROL_TRANS2_COMMIT_RETRY:
		/* already updated from the first commit */
		if (client->db_id != m->db_id) {
			DEBUG(DEBUG_ERR,(__location__ " ERROR: trans2_commit "
					 "retry: client-db_id[%d] != db_id[%d]"
					 "\n", client->db_id, m->db_id));
			return -1;
		}
		DEBUG(DEBUG_DEBUG, (__location__ " client id[0x%08x] started "
				    "transaction commit retry on "
				    "db_id[0x%08x]\n",
				    client->client_id, client->db_id));
		break;
	}

	state = talloc_zero(ctdb, struct ctdb_persistent_state);
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
			DEBUG(DEBUG_ERR,("Unable to send CTDB_CONTROL_UPDATE_RECORD to pnn %u\n", node->pnn));
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


struct ctdb_persistent_write_state {
	struct ctdb_db_context *ctdb_db;
	struct ctdb_marshall_buffer *m;
	struct ctdb_req_control *c;
};


/*
  called from a child process to write the data
 */
static int ctdb_persistent_store(struct ctdb_persistent_write_state *state)
{
	int ret, i;
	struct ctdb_rec_data *rec = NULL;
	struct ctdb_marshall_buffer *m = state->m;

	ret = tdb_transaction_start(state->ctdb_db->ltdb->tdb);
	if (ret == -1) {
		DEBUG(DEBUG_ERR,("Failed to start transaction for db_id 0x%08x in ctdb_persistent_store\n",
				 state->ctdb_db->db_id));
		return -1;
	}

	for (i=0;i<m->count;i++) {
		struct ctdb_ltdb_header oldheader;
		struct ctdb_ltdb_header header;
		TDB_DATA key, data, olddata;
		TALLOC_CTX *tmp_ctx = talloc_new(state);

		rec = ctdb_marshall_loop_next(m, rec, NULL, &header, &key, &data);
		
		if (rec == NULL) {
			DEBUG(DEBUG_ERR,("Failed to get next record %d for db_id 0x%08x in ctdb_persistent_store\n",
					 i, state->ctdb_db->db_id));
			talloc_free(tmp_ctx);
			goto failed;			
		}

		/* fetch the old header and ensure the rsn is less than the new rsn */
		ret = ctdb_ltdb_fetch(state->ctdb_db, key, &oldheader, tmp_ctx, &olddata);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,("Failed to fetch old record for db_id 0x%08x in ctdb_persistent_store\n",
					 state->ctdb_db->db_id));
			talloc_free(tmp_ctx);
			goto failed;
		}

		if (oldheader.rsn >= header.rsn &&
		    (olddata.dsize != data.dsize || 
		     memcmp(olddata.dptr, data.dptr, data.dsize) != 0)) {
			DEBUG(DEBUG_CRIT,("existing header for db_id 0x%08x has larger RSN %llu than new RSN %llu in ctdb_persistent_store\n",
					  state->ctdb_db->db_id, 
					  (unsigned long long)oldheader.rsn, (unsigned long long)header.rsn));
			talloc_free(tmp_ctx);
			goto failed;
		}

		talloc_free(tmp_ctx);

		ret = ctdb_ltdb_store(state->ctdb_db, key, &header, data);
		if (ret != 0) {
			DEBUG(DEBUG_CRIT,("Failed to store record for db_id 0x%08x in ctdb_persistent_store\n", 
					  state->ctdb_db->db_id));
			goto failed;
		}
	}

	ret = tdb_transaction_commit(state->ctdb_db->ltdb->tdb);
	if (ret == -1) {
		DEBUG(DEBUG_ERR,("Failed to commit transaction for db_id 0x%08x in ctdb_persistent_store\n",
				 state->ctdb_db->db_id));
		return -1;
	}

	return 0;
	
failed:
	tdb_transaction_cancel(state->ctdb_db->ltdb->tdb);
	return -1;
}


/*
  called when we the child has completed the persistent write
  on our behalf
 */
static void ctdb_persistent_write_callback(int status, void *private_data)
{
	struct ctdb_persistent_write_state *state = talloc_get_type(private_data, 
								   struct ctdb_persistent_write_state);


	ctdb_request_control_reply(state->ctdb_db->ctdb, state->c, NULL, status, NULL);

	talloc_free(state);
}

/*
  called if our lockwait child times out
 */
static void ctdb_persistent_lock_timeout(struct event_context *ev, struct timed_event *te, 
					 struct timeval t, void *private_data)
{
	struct ctdb_persistent_write_state *state = talloc_get_type(private_data, 
								   struct ctdb_persistent_write_state);
	ctdb_request_control_reply(state->ctdb_db->ctdb, state->c, NULL, -1, "timeout in ctdb_persistent_lock");
	talloc_free(state);
}

struct childwrite_handle {
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	struct fd_event *fde;
	int fd[2];
	pid_t child;
	void *private_data;
	void (*callback)(int, void *);
	struct timeval start_time;
};

static int childwrite_destructor(struct childwrite_handle *h)
{
	h->ctdb->statistics.pending_childwrite_calls--;
	kill(h->child, SIGKILL);
	return 0;
}

/* called when the child process has finished writing the record to the
   database
*/
static void childwrite_handler(struct event_context *ev, struct fd_event *fde, 
			     uint16_t flags, void *private_data)
{
	struct childwrite_handle *h = talloc_get_type(private_data, 
						     struct childwrite_handle);
	void *p = h->private_data;
	void (*callback)(int, void *) = h->callback;
	pid_t child = h->child;
	TALLOC_CTX *tmp_ctx = talloc_new(ev);
	int ret;
	char c;

	ctdb_latency(h->ctdb_db, "persistent", &h->ctdb->statistics.max_childwrite_latency, h->start_time);
	h->ctdb->statistics.pending_childwrite_calls--;

	/* the handle needs to go away when the context is gone - when
	   the handle goes away this implicitly closes the pipe, which
	   kills the child */
	talloc_steal(tmp_ctx, h);

	talloc_set_destructor(h, NULL);

	ret = read(h->fd[0], &c, 1);
	if (ret < 1) {
		DEBUG(DEBUG_ERR, (__location__ " Read returned %d. Childwrite failed\n", ret));
		c = 1;
	}

	callback(c, p);

	kill(child, SIGKILL);
	talloc_free(tmp_ctx);
}

/* this creates a child process which will take out a tdb transaction
   and write the record to the database.
*/
struct childwrite_handle *ctdb_childwrite(struct ctdb_db_context *ctdb_db,
				void (*callback)(int, void *private_data),
				struct ctdb_persistent_write_state *state)
{
	struct childwrite_handle *result;
	int ret;
	pid_t parent = getpid();

	ctdb_db->ctdb->statistics.childwrite_calls++;
	ctdb_db->ctdb->statistics.pending_childwrite_calls++;

	if (!(result = talloc_zero(state, struct childwrite_handle))) {
		ctdb_db->ctdb->statistics.pending_childwrite_calls--;
		return NULL;
	}

	ret = pipe(result->fd);

	if (ret != 0) {
		talloc_free(result);
		ctdb_db->ctdb->statistics.pending_childwrite_calls--;
		return NULL;
	}

	result->child = fork();

	if (result->child == (pid_t)-1) {
		close(result->fd[0]);
		close(result->fd[1]);
		talloc_free(result);
		ctdb_db->ctdb->statistics.pending_childwrite_calls--;
		return NULL;
	}

	result->callback = callback;
	result->private_data = state;
	result->ctdb = ctdb_db->ctdb;
	result->ctdb_db = ctdb_db;

	if (result->child == 0) {
		char c = 0;

		close(result->fd[0]);
		ret = ctdb_persistent_store(state);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, (__location__ " Failed to write persistent data\n"));
			c = 1;
		}

		write(result->fd[1], &c, 1);

		/* make sure we die when our parent dies */
		while (kill(parent, 0) == 0 || errno != ESRCH) {
			sleep(5);
		}
		_exit(0);
	}

	close(result->fd[1]);
	set_close_on_exec(result->fd[0]);

	talloc_set_destructor(result, childwrite_destructor);

	DEBUG(DEBUG_NOTICE, (__location__ " Created PIPE FD:%d for ctdb_childwrite\n", result->fd[0]));

	result->fde = event_add_fd(ctdb_db->ctdb->ev, result, result->fd[0],
				   EVENT_FD_READ|EVENT_FD_AUTOCLOSE, childwrite_handler,
				   (void *)result);
	if (result->fde == NULL) {
		talloc_free(result);
		ctdb_db->ctdb->statistics.pending_childwrite_calls--;
		return NULL;
	}

	result->start_time = timeval_current();

	return result;
}

/* 
   update a record on this node if the new record has a higher rsn than the
   current record
 */
int32_t ctdb_control_update_record(struct ctdb_context *ctdb, 
				   struct ctdb_req_control *c, TDB_DATA recdata, 
				   bool *async_reply)
{
	struct ctdb_db_context *ctdb_db;
	struct ctdb_persistent_write_state *state;
	struct childwrite_handle *handle;
	struct ctdb_marshall_buffer *m = (struct ctdb_marshall_buffer *)recdata.dptr;

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) {
		DEBUG(DEBUG_INFO,("rejecting ctdb_control_update_record when recovery active\n"));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, m->db_id);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,("Unknown database 0x%08x in ctdb_control_update_record\n", m->db_id));
		return -1;
	}

	state = talloc(ctdb, struct ctdb_persistent_write_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->ctdb_db = ctdb_db;
	state->c       = c;
	state->m       = m;

	/* create a child process to take out a transaction and 
	   write the data.
	*/
	handle = ctdb_childwrite(ctdb_db, ctdb_persistent_write_callback, state);
	if (handle == NULL) {
		DEBUG(DEBUG_ERR,("Failed to setup childwrite handler in ctdb_control_update_record\n"));
		talloc_free(state);
		return -1;
	}

	/* we need to wait for the replies */
	*async_reply = true;

	/* need to keep the control structure around */
	talloc_steal(state, c);

	/* but we won't wait forever */
	event_add_timed(ctdb->ev, state, timeval_current_ofs(ctdb->tunable.control_timeout, 0),
			ctdb_persistent_lock_timeout, state);

	return 0;
}


/*
  called when a client has finished a local commit in a transaction to 
  a persistent database
 */
int32_t ctdb_control_trans2_finished(struct ctdb_context *ctdb, 
				     struct ctdb_req_control *c)
{
	struct ctdb_client *client = ctdb_reqid_find(ctdb, c->client_id, struct ctdb_client);
	struct ctdb_db_context *ctdb_db;

	ctdb_db = find_ctdb_db(ctdb, client->db_id);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control_trans2_finish "
				 "Unknown database 0x%08x\n", client->db_id));
		return -1;
	}
	if (!ctdb_db->transaction_active) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control_trans2_finish: "
				 "Database 0x%08x has no transaction commit "
				 "started\n", client->db_id));
		return -1;
	}

	ctdb_db->transaction_active = false;
	client->db_id = 0;

	if (client->num_persistent_updates == 0) {
		DEBUG(DEBUG_ERR, (__location__ " ERROR: num_persistent_updates == 0\n"));
		DEBUG(DEBUG_ERR,(__location__ " Forcing recovery\n"));
		client->ctdb->recovery_mode = CTDB_RECOVERY_ACTIVE;
		return -1;
	}
	client->num_persistent_updates--;

	DEBUG(DEBUG_DEBUG, (__location__ " client id[0x%08x] finished "
			    "transaction commit db_id[0x%08x]\n",
			    client->client_id, ctdb_db->db_id));

	return 0;
}

/*
  called when a client gets an error committing its database
  during a transaction commit
 */
int32_t ctdb_control_trans2_error(struct ctdb_context *ctdb, 
				  struct ctdb_req_control *c)
{
	struct ctdb_client *client = ctdb_reqid_find(ctdb, c->client_id, struct ctdb_client);
	struct ctdb_db_context *ctdb_db;

	ctdb_db = find_ctdb_db(ctdb, client->db_id);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control_trans2_error: "
				 "Unknown database 0x%08x\n", client->db_id));
		return -1;
	}
	if (!ctdb_db->transaction_active) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control_trans2_error: "
				 "Database 0x%08x has no transaction commit "
				 "started\n", client->db_id));
		return -1;
	}

	ctdb_db->transaction_active = false;
	client->db_id = 0;

	if (client->num_persistent_updates == 0) {
		DEBUG(DEBUG_ERR, (__location__ " ERROR: num_persistent_updates == 0\n"));
	} else {
		client->num_persistent_updates--;
	}

	DEBUG(DEBUG_ERR,(__location__ " Forcing recovery\n"));
	client->ctdb->recovery_mode = CTDB_RECOVERY_ACTIVE;

	return 0;
}

/**
 * Tell whether a transaction is active on this node on the give DB.
 */
int32_t ctdb_control_trans2_active(struct ctdb_context *ctdb,
				   struct ctdb_req_control *c,
				   uint32_t db_id)
{
	struct ctdb_db_context *ctdb_db;
	struct ctdb_client *client = ctdb_reqid_find(ctdb, c->client_id, struct ctdb_client);

	ctdb_db = find_ctdb_db(ctdb, db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR,(__location__ " Unknown db 0x%08x\n", db_id));
		return -1;
	}

	if (client->db_id == db_id) {
		return 0;
	}

	if (ctdb_db->transaction_active) {
		return 1;
	} else {
		return 0;
	}
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


/*
  backwards compatibility:

  single record varient of ctdb_control_trans2_commit for older clients
 */
int32_t ctdb_control_persistent_store(struct ctdb_context *ctdb, 
				      struct ctdb_req_control *c, 
				      TDB_DATA recdata, bool *async_reply)
{
	struct ctdb_marshall_buffer *m;
	struct ctdb_rec_data *rec = (struct ctdb_rec_data *)recdata.dptr;
	TDB_DATA key, data;

	if (recdata.dsize != offsetof(struct ctdb_rec_data, data) + 
	    rec->keylen + rec->datalen) {
		DEBUG(DEBUG_ERR, (__location__ " Bad data size in recdata\n"));
		return -1;
	}

	key.dptr = &rec->data[0];
	key.dsize = rec->keylen;
	data.dptr = &rec->data[rec->keylen];
	data.dsize = rec->datalen;

	m = ctdb_marshall_add(c, NULL, rec->reqid, rec->reqid, key, NULL, data);
	CTDB_NO_MEMORY(ctdb, m);

	return ctdb_control_trans2_commit(ctdb, c, ctdb_marshall_finish(m), async_reply);
}


