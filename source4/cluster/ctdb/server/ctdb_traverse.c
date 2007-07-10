/* 
   efficient async ctdb traverse

   Copyright (C) Andrew Tridgell  2007

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

typedef void (*ctdb_traverse_fn_t)(void *private_data, TDB_DATA key, TDB_DATA data);

/*
  handle returned to caller - freeing this handler will kill the child and 
  terminate the traverse
 */
struct ctdb_traverse_local_handle {
	struct ctdb_db_context *ctdb_db;
	int fd[2];
	pid_t child;
	void *private_data;
	ctdb_traverse_fn_t callback;
	struct timeval start_time;
	struct ctdb_queue *queue;
};

/*
  called when data is available from the child
 */
static void ctdb_traverse_local_handler(uint8_t *rawdata, size_t length, void *private_data)
{
	struct ctdb_traverse_local_handle *h = talloc_get_type(private_data, 
							       struct ctdb_traverse_local_handle);
	TDB_DATA key, data;
	ctdb_traverse_fn_t callback = h->callback;
	void *p = h->private_data;
	struct ctdb_rec_data *tdata = (struct ctdb_rec_data *)rawdata;

	if (rawdata == NULL || length < 4 || length != tdata->length) {
		/* end of traverse */
		talloc_free(h);
		callback(p, tdb_null, tdb_null);
		return;
	}

	key.dsize = tdata->keylen;
	key.dptr  = &tdata->data[0];
	data.dsize = tdata->datalen;
	data.dptr = &tdata->data[tdata->keylen];

	callback(p, key, data);	
}

/*
  destroy a in-flight traverse operation
 */
static int traverse_local_destructor(struct ctdb_traverse_local_handle *h)
{
	kill(h->child, SIGKILL);
	waitpid(h->child, NULL, 0);
	return 0;
}

/*
  callback from tdb_traverse_read()
 */
static int ctdb_traverse_local_fn(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *p)
{
	struct ctdb_traverse_local_handle *h = talloc_get_type(p, 
							       struct ctdb_traverse_local_handle);
	struct ctdb_rec_data *d;
	struct ctdb_ltdb_header *hdr;

	/* filter out non-authoritative and zero-length records */
	hdr = (struct ctdb_ltdb_header *)data.dptr;
	if (data.dsize <= sizeof(struct ctdb_ltdb_header) ||
	    hdr->dmaster != h->ctdb_db->ctdb->vnn) {
		return 0;
	}

	d = ctdb_marshall_record(h, 0, key, data);
	if (d == NULL) {
		/* error handling is tricky in this child code .... */
		return -1;
	}

	if (write(h->fd[1], (uint8_t *)d, d->length) != d->length) {
		return -1;
	}
	return 0;
}


/*
  setup a non-blocking traverse of a local ltdb. The callback function
  will be called on every record in the local ltdb. To stop the
  travserse, talloc_free() the travserse_handle.

  The traverse is finished when the callback is called with tdb_null for key and data
 */
static struct ctdb_traverse_local_handle *ctdb_traverse_local(struct ctdb_db_context *ctdb_db,
							      ctdb_traverse_fn_t callback,
							      void *private_data)
{
	struct ctdb_traverse_local_handle *h;
	int ret;

	h = talloc_zero(ctdb_db, struct ctdb_traverse_local_handle);
	if (h == NULL) {
		return NULL;
	}

	ret = pipe(h->fd);

	if (ret != 0) {
		talloc_free(h);
		return NULL;
	}

	h->child = fork();

	if (h->child == (pid_t)-1) {
		close(h->fd[0]);
		close(h->fd[1]);
		talloc_free(h);
		return NULL;
	}

	h->callback = callback;
	h->private_data = private_data;
	h->ctdb_db = ctdb_db;

	if (h->child == 0) {
		/* start the traverse in the child */
		close(h->fd[0]);
		tdb_traverse_read(ctdb_db->ltdb->tdb, ctdb_traverse_local_fn, h);
		_exit(0);
	}

	close(h->fd[1]);
	talloc_set_destructor(h, traverse_local_destructor);

	/*
	  setup a packet queue between the child and the parent. This
	  copes with all the async and packet boundary issues
	 */
	h->queue = ctdb_queue_setup(ctdb_db->ctdb, h, h->fd[0], 0, ctdb_traverse_local_handler, h);
	if (h->queue == NULL) {
		talloc_free(h);
		return NULL;
	}

	h->start_time = timeval_current();

	return h;
}


struct ctdb_traverse_all_handle {
	struct ctdb_context *ctdb;
	uint32_t reqid;
	ctdb_traverse_fn_t callback;
	void *private_data;
	uint32_t null_count;
};

/*
  destroy a traverse_all op
 */
static int ctdb_traverse_all_destructor(struct ctdb_traverse_all_handle *state)
{
	ctdb_reqid_remove(state->ctdb, state->reqid);
	return 0;
}

struct ctdb_traverse_all {
	uint32_t db_id;
	uint32_t reqid;
	uint32_t vnn;
};

/* called when a traverse times out */
static void ctdb_traverse_all_timeout(struct event_context *ev, struct timed_event *te, 
				      struct timeval t, void *private_data)
{
	struct ctdb_traverse_all_handle *state = talloc_get_type(private_data, struct ctdb_traverse_all_handle);

	state->ctdb->statistics.timeouts.traverse++;

	state->callback(state->private_data, tdb_null, tdb_null);
	talloc_free(state);
}

/*
  setup a cluster-wide non-blocking traverse of a ctdb. The
  callback function will be called on every record in the local
  ltdb. To stop the travserse, talloc_free() the traverse_handle.

  The traverse is finished when the callback is called with tdb_null
  for key and data
 */
static struct ctdb_traverse_all_handle *ctdb_daemon_traverse_all(struct ctdb_db_context *ctdb_db,
								 ctdb_traverse_fn_t callback,
								 void *private_data)
{
	struct ctdb_traverse_all_handle *state;
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	int ret;
	TDB_DATA data;
	struct ctdb_traverse_all r;

	state = talloc(ctdb_db, struct ctdb_traverse_all_handle);
	if (state == NULL) {
		return NULL;
	}

	state->ctdb = ctdb;
	state->reqid = ctdb_reqid_new(ctdb_db->ctdb, state);
	state->callback = callback;
	state->private_data = private_data;
	state->null_count = 0;
	
	talloc_set_destructor(state, ctdb_traverse_all_destructor);

	r.db_id = ctdb_db->db_id;
	r.reqid = state->reqid;
	r.vnn   = ctdb->vnn;

	data.dptr = (uint8_t *)&r;
	data.dsize = sizeof(r);

	/* tell all the nodes in the cluster to start sending records to this node */
	ret = ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_VNNMAP, 0, 
				       CTDB_CONTROL_TRAVERSE_ALL,
				       0, CTDB_CTRL_FLAG_NOREPLY, data, NULL, NULL);
	if (ret != 0) {
		talloc_free(state);
		return NULL;
	}

	/* timeout the traverse */
	event_add_timed(ctdb->ev, state, 
			timeval_current_ofs(ctdb->tunable.traverse_timeout, 0), 
			ctdb_traverse_all_timeout, state);

	return state;
}

struct traverse_all_state {
	struct ctdb_context *ctdb;
	struct ctdb_traverse_local_handle *h;
	uint32_t reqid;
	uint32_t srcnode;
};

/*
  called for each record during a traverse all 
 */
static void traverse_all_callback(void *p, TDB_DATA key, TDB_DATA data)
{
	struct traverse_all_state *state = talloc_get_type(p, struct traverse_all_state);
	int ret;
	struct ctdb_rec_data *d;
	TDB_DATA cdata;

	d = ctdb_marshall_record(state, state->reqid, key, data);
	if (d == NULL) {
		/* darn .... */
		DEBUG(0,("Out of memory in traverse_all_callback\n"));
		return;
	}

	cdata.dptr = (uint8_t *)d;
	cdata.dsize = d->length;

	ret = ctdb_daemon_send_control(state->ctdb, state->srcnode, 0, CTDB_CONTROL_TRAVERSE_DATA,
				       0, CTDB_CTRL_FLAG_NOREPLY, cdata, NULL, NULL);
	if (ret != 0) {
		DEBUG(0,("Failed to send traverse data\n"));
	}

	if (key.dsize == 0 && data.dsize == 0) {
		/* we're done */
		talloc_free(state);
	}
}

/*
  called when a CTDB_CONTROL_TRAVERSE_ALL control comes in. We then
  setup a traverse of our local ltdb, sending the records as
  CTDB_CONTROL_TRAVERSE_DATA records back to the originator
 */
int32_t ctdb_control_traverse_all(struct ctdb_context *ctdb, TDB_DATA data, TDB_DATA *outdata)
{
	struct ctdb_traverse_all *c = (struct ctdb_traverse_all *)data.dptr;
	struct traverse_all_state *state;
	struct ctdb_db_context *ctdb_db;

	if (data.dsize != sizeof(struct ctdb_traverse_all)) {
		DEBUG(0,("Invalid size in ctdb_control_traverse_all\n"));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, c->db_id);
	if (ctdb_db == NULL) {
		return -1;
	}

	state = talloc(ctdb_db, struct traverse_all_state);
	if (state == NULL) {
		return -1;
	}

	state->reqid = c->reqid;
	state->srcnode = c->vnn;
	state->ctdb = ctdb;

	state->h = ctdb_traverse_local(ctdb_db, traverse_all_callback, state);
	if (state->h == NULL) {
		talloc_free(state);
		return -1;
	}

	return 0;
}


/*
  called when a CTDB_CONTROL_TRAVERSE_DATA control comes in. We then
  call the traverse_all callback with the record
 */
int32_t ctdb_control_traverse_data(struct ctdb_context *ctdb, TDB_DATA data, TDB_DATA *outdata)
{
	struct ctdb_rec_data *d = (struct ctdb_rec_data *)data.dptr;
	struct ctdb_traverse_all_handle *state;
	TDB_DATA key;
	ctdb_traverse_fn_t callback;
	void *private_data;

	if (data.dsize < sizeof(uint32_t) || data.dsize != d->length) {
		DEBUG(0,("Bad record size in ctdb_control_traverse_data\n"));
		return -1;
	}

	state = ctdb_reqid_find(ctdb, d->reqid, struct ctdb_traverse_all_handle);
	if (state == NULL || d->reqid != state->reqid) {
		/* traverse might have been terminated already */
		return -1;
	}

	key.dsize = d->keylen;
	key.dptr  = &d->data[0];
	data.dsize = d->datalen;
	data.dptr = &d->data[d->keylen];

	if (key.dsize == 0 && data.dsize == 0) {
		state->null_count++;
		if (state->null_count != ctdb_get_num_active_nodes(ctdb)) {
			return 0;
		}
	}

	callback = state->callback;
	private_data = state->private_data;

	callback(private_data, key, data);
	if (key.dsize == 0 && data.dsize == 0) {
		/* we've received all of the null replies, so all
		   nodes are finished */
		talloc_free(state);
	}
	return 0;
}	

struct traverse_start_state {
	struct ctdb_context *ctdb;
	struct ctdb_traverse_all_handle *h;
	uint32_t srcnode;
	uint32_t reqid;
	uint64_t srvid;
};

/*
  callback which sends records as messages to the client
 */
static void traverse_start_callback(void *p, TDB_DATA key, TDB_DATA data)
{
	struct traverse_start_state *state;
	struct ctdb_rec_data *d;
	TDB_DATA cdata;

	state = talloc_get_type(p, struct traverse_start_state);

	d = ctdb_marshall_record(state, state->reqid, key, data);
	if (d == NULL) {
		return;
	}

	cdata.dptr = (uint8_t *)d;
	cdata.dsize = d->length;

	ctdb_dispatch_message(state->ctdb, state->srvid, cdata);
	if (key.dsize == 0 && data.dsize == 0) {
		/* end of traverse */
		talloc_free(state);
	}
}

/*
  start a traverse_all - called as a control from a client
 */
int32_t ctdb_control_traverse_start(struct ctdb_context *ctdb, TDB_DATA data, 
				    TDB_DATA *outdata, uint32_t srcnode)
{
	struct ctdb_traverse_start *d = (struct ctdb_traverse_start *)data.dptr;
	struct traverse_start_state *state;
	struct ctdb_db_context *ctdb_db;

	if (data.dsize != sizeof(*d)) {
		DEBUG(0,("Bad record size in ctdb_control_traverse_start\n"));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, d->db_id);
	if (ctdb_db == NULL) {
		return -1;
	}

	state = talloc(ctdb_db, struct traverse_start_state);
	if (state == NULL) {
		return -1;
	}
	
	state->srcnode = srcnode;
	state->reqid = d->reqid;
	state->srvid = d->srvid;
	state->ctdb = ctdb;

	state->h = ctdb_daemon_traverse_all(ctdb_db, traverse_start_callback, state);
	if (state->h == NULL) {
		talloc_free(state);
		return -1;
	}

	return 0;
}
