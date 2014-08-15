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
#include "system/filesys.h"
#include "system/wait.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include "tdb.h"
#include "../include/ctdb_private.h"
#include "lib/util/dlinklist.h"

typedef void (*ctdb_traverse_fn_t)(void *private_data, TDB_DATA key, TDB_DATA data);

/*
  handle returned to caller - freeing this handler will kill the child and 
  terminate the traverse
 */
struct ctdb_traverse_local_handle {
	struct ctdb_traverse_local_handle *next, *prev;
	struct ctdb_db_context *ctdb_db;
	int fd[2];
	pid_t child;
	uint64_t srvid;
	uint32_t client_reqid;
	uint32_t reqid;
	int srcnode;
	void *private_data;
	ctdb_traverse_fn_t callback;
	bool withemptyrecords;
	struct tevent_fd *fde;
	int records_failed;
	int records_sent;
};

/*
 * called when traverse is completed by child or on error
 */
static void ctdb_traverse_child_handler(struct tevent_context *ev, struct tevent_fd *fde,
					uint16_t flags, void *private_data)
{
	struct ctdb_traverse_local_handle *h = talloc_get_type(private_data,
							struct ctdb_traverse_local_handle);
	ctdb_traverse_fn_t callback = h->callback;
	void *p = h->private_data;
	int res;
	ssize_t n;

	/* Read the number of records sent by traverse child */
	n = sys_read(h->fd[0], &res, sizeof(res));
	if (n < 0 || n != sizeof(res)) {
		/* Traverse child failed */
		DEBUG(DEBUG_ERR, ("Local traverse failed db:%s reqid:%d\n",
				  h->ctdb_db->db_name, h->reqid));
	} else if (res < 0) {
		/* Traverse failed */
		res = -res;
		DEBUG(DEBUG_ERR, ("Local traverse failed db:%s reqid:%d records:%d\n",
				  h->ctdb_db->db_name, h->reqid, res));
	} else {
		DEBUG(DEBUG_INFO, ("Local traverse end db:%s reqid:%d records:%d\n",
				   h->ctdb_db->db_name, h->reqid, res));
	}

	callback(p, tdb_null, tdb_null);
}

/*
  destroy a in-flight traverse operation
 */
static int traverse_local_destructor(struct ctdb_traverse_local_handle *h)
{
	DLIST_REMOVE(h->ctdb_db->traverse, h);
	ctdb_kill(h->ctdb_db->ctdb, h->child, SIGKILL);
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
	int res, status;
	TDB_DATA outdata;

	hdr = (struct ctdb_ltdb_header *)data.dptr;

	if (h->ctdb_db->persistent == 0) {
		/* filter out zero-length records */
		if (!h->withemptyrecords &&
		    data.dsize <= sizeof(struct ctdb_ltdb_header))
		{
			return 0;
		}

		/* filter out non-authoritative records */
		if (hdr->dmaster != h->ctdb_db->ctdb->pnn) {
			return 0;
		}
	}

	d = ctdb_marshall_record(h, h->reqid, key, NULL, data);
	if (d == NULL) {
		/* error handling is tricky in this child code .... */
		h->records_failed++;
		return -1;
	}

	outdata.dptr = (uint8_t *)d;
	outdata.dsize = d->length;

	res = ctdb_control(h->ctdb_db->ctdb, h->srcnode, 0, CTDB_CONTROL_TRAVERSE_DATA,
			   CTDB_CTRL_FLAG_NOREPLY, outdata, NULL, NULL, &status, NULL, NULL);
	if (res != 0 || status != 0) {
		h->records_failed++;
		return -1;
	}

	h->records_sent++;
	return 0;
}

struct traverse_all_state {
	struct ctdb_context *ctdb;
	struct ctdb_traverse_local_handle *h;
	uint32_t reqid;
	uint32_t srcnode;
	uint32_t client_reqid;
	uint64_t srvid;
	bool withemptyrecords;
};

/*
  setup a non-blocking traverse of a local ltdb. The callback function
  will be called on every record in the local ltdb. To stop the
  traverse, talloc_free() the traverse_handle.

  The traverse is finished when the callback is called with tdb_null for key and data
 */
static struct ctdb_traverse_local_handle *ctdb_traverse_local(struct ctdb_db_context *ctdb_db,
							      ctdb_traverse_fn_t callback,
							      struct traverse_all_state *all_state)
{
	struct ctdb_traverse_local_handle *h;
	int ret;

	h = talloc_zero(all_state, struct ctdb_traverse_local_handle);
	if (h == NULL) {
		return NULL;
	}

	ret = pipe(h->fd);

	if (ret != 0) {
		talloc_free(h);
		return NULL;
	}

	h->child = ctdb_fork(ctdb_db->ctdb);

	if (h->child == (pid_t)-1) {
		close(h->fd[0]);
		close(h->fd[1]);
		talloc_free(h);
		return NULL;
	}

	h->callback = callback;
	h->private_data = all_state;
	h->ctdb_db = ctdb_db;
	h->client_reqid = all_state->client_reqid;
	h->reqid = all_state->reqid;
	h->srvid = all_state->srvid;
	h->srcnode = all_state->srcnode;
	h->withemptyrecords = all_state->withemptyrecords;

	if (h->child == 0) {
		/* start the traverse in the child */
		int res, status;
		pid_t parent = getpid();
		struct ctdb_context *ctdb = ctdb_db->ctdb;
		struct ctdb_rec_data *d;
		TDB_DATA outdata;

		close(h->fd[0]);

		ctdb_set_process_name("ctdb_traverse");
		if (switch_from_server_to_client(ctdb, "traverse_local-%s:",
						 ctdb_db->db_name) != 0) {
			DEBUG(DEBUG_CRIT, ("Failed to switch traverse child into client mode\n"));
			_exit(0);
		}

		d = ctdb_marshall_record(h, h->reqid, tdb_null, NULL, tdb_null);
		if (d == NULL) {
			res = 0;
			sys_write(h->fd[1], &res, sizeof(int));
			_exit(0);
		}

		res = tdb_traverse_read(ctdb_db->ltdb->tdb, ctdb_traverse_local_fn, h);
		if (res == -1 || h->records_failed > 0) {
			/* traverse failed */
			res = -(h->records_sent);
		} else {
			res = h->records_sent;
		}

		/* Wait till all the data is flushed from output queue */
		while (ctdb_queue_length(ctdb->daemon.queue) > 0) {
			tevent_loop_once(ctdb->ev);
		}

		/* End traverse by sending empty record */
		outdata.dptr = (uint8_t *)d;
		outdata.dsize = d->length;
		ret = ctdb_control(ctdb, h->srcnode, 0,
				   CTDB_CONTROL_TRAVERSE_DATA,
				   CTDB_CTRL_FLAG_NOREPLY, outdata,
				   NULL, NULL, &status, NULL, NULL);
		if (ret == -1 || status == -1) {
			if (res > 0) {
				res = -res;
			}
		}

		sys_write(h->fd[1], &res, sizeof(res));

		while (ctdb_kill(ctdb, parent, 0) == 0 || errno != ESRCH) {
			sleep(5);
		}
		_exit(0);
	}

	close(h->fd[1]);
	set_close_on_exec(h->fd[0]);

	talloc_set_destructor(h, traverse_local_destructor);

	DLIST_ADD(ctdb_db->traverse, h);

	h->fde = tevent_add_fd(ctdb_db->ctdb->ev, h, h->fd[0], EVENT_FD_READ,
			       ctdb_traverse_child_handler, h);
	if (h->fde == NULL) {
		close(h->fd[0]);
		talloc_free(h);
		return NULL;
	}
	tevent_fd_set_auto_close(h->fde);

	return h;
}


struct ctdb_traverse_all_handle {
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	uint32_t reqid;
	ctdb_traverse_fn_t callback;
	void *private_data;
	uint32_t null_count;
	bool timedout;
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
	uint32_t pnn;
	uint32_t client_reqid;
	uint64_t srvid;
};

struct ctdb_traverse_all_ext {
	uint32_t db_id;
	uint32_t reqid;
	uint32_t pnn;
	uint32_t client_reqid;
	uint64_t srvid;
	bool withemptyrecords;
};

/* called when a traverse times out */
static void ctdb_traverse_all_timeout(struct event_context *ev, struct timed_event *te, 
				      struct timeval t, void *private_data)
{
	struct ctdb_traverse_all_handle *state = talloc_get_type(private_data, struct ctdb_traverse_all_handle);

	DEBUG(DEBUG_ERR,(__location__ " Traverse all timeout on database:%s\n", state->ctdb_db->db_name));
	CTDB_INCREMENT_STAT(state->ctdb, timeouts.traverse);

	state->timedout = true;
	state->callback(state->private_data, tdb_null, tdb_null);
}


struct traverse_start_state {
	struct ctdb_context *ctdb;
	struct ctdb_traverse_all_handle *h;
	uint32_t srcnode;
	uint32_t reqid;
	uint32_t db_id;
	uint64_t srvid;
	bool withemptyrecords;
	int num_records;
};


/*
  setup a cluster-wide non-blocking traverse of a ctdb. The
  callback function will be called on every record in the local
  ltdb. To stop the traverse, talloc_free() the traverse_handle.

  The traverse is finished when the callback is called with tdb_null
  for key and data
 */
static struct ctdb_traverse_all_handle *ctdb_daemon_traverse_all(struct ctdb_db_context *ctdb_db,
								 ctdb_traverse_fn_t callback,
								 struct traverse_start_state *start_state)
{
	struct ctdb_traverse_all_handle *state;
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	int ret;
	TDB_DATA data;
	struct ctdb_traverse_all r;
	struct ctdb_traverse_all_ext r_ext;
	uint32_t destination;

	state = talloc(start_state, struct ctdb_traverse_all_handle);
	if (state == NULL) {
		return NULL;
	}

	state->ctdb         = ctdb;
	state->ctdb_db      = ctdb_db;
	state->reqid        = ctdb_reqid_new(ctdb_db->ctdb, state);
	state->callback     = callback;
	state->private_data = start_state;
	state->null_count   = 0;
	state->timedout     = false;
	
	talloc_set_destructor(state, ctdb_traverse_all_destructor);

	if (start_state->withemptyrecords) {
		r_ext.db_id = ctdb_db->db_id;
		r_ext.reqid = state->reqid;
		r_ext.pnn   = ctdb->pnn;
		r_ext.client_reqid = start_state->reqid;
		r_ext.srvid = start_state->srvid;
		r_ext.withemptyrecords = start_state->withemptyrecords;

		data.dptr = (uint8_t *)&r_ext;
		data.dsize = sizeof(r_ext);
	} else {
		r.db_id = ctdb_db->db_id;
		r.reqid = state->reqid;
		r.pnn   = ctdb->pnn;
		r.client_reqid = start_state->reqid;
		r.srvid = start_state->srvid;

		data.dptr = (uint8_t *)&r;
		data.dsize = sizeof(r);
	}

	if (ctdb_db->persistent == 0) {
		/* normal database, traverse all nodes */	  
		destination = CTDB_BROADCAST_VNNMAP;
	} else {
		int i;
		/* persistent database, traverse one node, preferably
		 * the local one
		 */
		destination = ctdb->pnn;
		/* check we are in the vnnmap */
		for (i=0; i < ctdb->vnn_map->size; i++) {
			if (ctdb->vnn_map->map[i] == ctdb->pnn) {
				break;
			}
		}
		/* if we are not in the vnn map we just pick the first
		 * node instead
		 */
		if (i == ctdb->vnn_map->size) {
			destination = ctdb->vnn_map->map[0];
		}
	}

	/* tell all the nodes in the cluster to start sending records to this
	 * node, or if it is a persistent database, just tell the local
	 * node
	 */

	if (start_state->withemptyrecords) {
		ret = ctdb_daemon_send_control(ctdb, destination, 0,
				       CTDB_CONTROL_TRAVERSE_ALL_EXT,
				       0, CTDB_CTRL_FLAG_NOREPLY, data, NULL, NULL);
	} else {
		ret = ctdb_daemon_send_control(ctdb, destination, 0,
				       CTDB_CONTROL_TRAVERSE_ALL,
				       0, CTDB_CTRL_FLAG_NOREPLY, data, NULL, NULL);
	}

	if (ret != 0) {
		talloc_free(state);
		return NULL;
	}

	DEBUG(DEBUG_NOTICE,("Starting traverse on DB %s (id %d)\n",
			    ctdb_db->db_name, state->reqid));

	/* timeout the traverse */
	event_add_timed(ctdb->ev, state, 
			timeval_current_ofs(ctdb->tunable.traverse_timeout, 0), 
			ctdb_traverse_all_timeout, state);

	return state;
}

/*
  called when local traverse ends
 */
static void traverse_all_callback(void *p, TDB_DATA key, TDB_DATA data)
{
	struct traverse_all_state *state = talloc_get_type(p, struct traverse_all_state);

	/* we're done */
	talloc_free(state);
}

/*
 * extended version to take the "withemptyrecords" parameter"
 */
int32_t ctdb_control_traverse_all_ext(struct ctdb_context *ctdb, TDB_DATA data, TDB_DATA *outdata)
{
	struct ctdb_traverse_all_ext *c = (struct ctdb_traverse_all_ext *)data.dptr;
	struct traverse_all_state *state;
	struct ctdb_db_context *ctdb_db;

	if (data.dsize != sizeof(struct ctdb_traverse_all_ext)) {
		DEBUG(DEBUG_ERR,(__location__ " Invalid size in ctdb_control_traverse_all_ext\n"));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, c->db_id);
	if (ctdb_db == NULL) {
		return -1;
	}

	if (ctdb_db->unhealthy_reason) {
		if (ctdb->tunable.allow_unhealthy_db_read == 0) {
			DEBUG(DEBUG_ERR,("db(%s) unhealty in ctdb_control_traverse_all: %s\n",
					ctdb_db->db_name, ctdb_db->unhealthy_reason));
			return -1;
		}
		DEBUG(DEBUG_WARNING,("warn: db(%s) unhealty in ctdb_control_traverse_all: %s\n",
				     ctdb_db->db_name, ctdb_db->unhealthy_reason));
	}

	state = talloc(ctdb_db, struct traverse_all_state);
	if (state == NULL) {
		return -1;
	}

	state->reqid = c->reqid;
	state->srcnode = c->pnn;
	state->ctdb = ctdb;
	state->client_reqid = c->client_reqid;
	state->srvid = c->srvid;
	state->withemptyrecords = c->withemptyrecords;

	state->h = ctdb_traverse_local(ctdb_db, traverse_all_callback, state);
	if (state->h == NULL) {
		talloc_free(state);
		return -1;
	}

	return 0;
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
		DEBUG(DEBUG_ERR,(__location__ " Invalid size in ctdb_control_traverse_all\n"));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, c->db_id);
	if (ctdb_db == NULL) {
		return -1;
	}

	if (ctdb_db->unhealthy_reason) {
		if (ctdb->tunable.allow_unhealthy_db_read == 0) {
			DEBUG(DEBUG_ERR,("db(%s) unhealty in ctdb_control_traverse_all: %s\n",
					ctdb_db->db_name, ctdb_db->unhealthy_reason));
			return -1;
		}
		DEBUG(DEBUG_WARNING,("warn: db(%s) unhealty in ctdb_control_traverse_all: %s\n",
				     ctdb_db->db_name, ctdb_db->unhealthy_reason));
	}

	state = talloc(ctdb_db, struct traverse_all_state);
	if (state == NULL) {
		return -1;
	}

	state->reqid = c->reqid;
	state->srcnode = c->pnn;
	state->ctdb = ctdb;
	state->client_reqid = c->client_reqid;
	state->srvid = c->srvid;
	state->withemptyrecords = false;

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
		DEBUG(DEBUG_ERR,("Bad record size in ctdb_control_traverse_data\n"));
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
		/* Persistent databases are only scanned on one node (the local
		 * node)
		 */
		if (state->ctdb_db->persistent == 0) {
			if (state->null_count != ctdb_get_num_active_nodes(ctdb)) {
				return 0;
			}
		}
	}

	callback = state->callback;
	private_data = state->private_data;

	callback(private_data, key, data);
	return 0;
}	

/*
  kill a in-progress traverse, used when a client disconnects
 */
int32_t ctdb_control_traverse_kill(struct ctdb_context *ctdb, TDB_DATA data, 
				   TDB_DATA *outdata, uint32_t srcnode)
{
	struct ctdb_traverse_start *d = (struct ctdb_traverse_start *)data.dptr;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_traverse_local_handle *t;

	ctdb_db = find_ctdb_db(ctdb, d->db_id);
	if (ctdb_db == NULL) {
		return -1;
	}

	for (t=ctdb_db->traverse; t; t=t->next) {
		if (t->client_reqid == d->reqid &&
		    t->srvid == d->srvid) {
			talloc_free(t);
			break;
		}
	}

	return 0;
}


/*
  this is called when a client disconnects during a traverse
  we need to notify all the nodes taking part in the search that they
  should kill their traverse children
 */
static int ctdb_traverse_start_destructor(struct traverse_start_state *state)
{
	struct ctdb_traverse_start r;
	TDB_DATA data;

	DEBUG(DEBUG_ERR,(__location__ " Traverse cancelled by client disconnect for database:0x%08x\n", state->db_id));
	r.db_id = state->db_id;
	r.reqid = state->reqid;
	r.srvid = state->srvid;

	data.dptr = (uint8_t *)&r;
	data.dsize = sizeof(r);

	ctdb_daemon_send_control(state->ctdb, CTDB_BROADCAST_CONNECTED, 0, 
				 CTDB_CONTROL_TRAVERSE_KILL, 
				 0, CTDB_CTRL_FLAG_NOREPLY, data, NULL, NULL);
	return 0;
}

/*
  callback which sends records as messages to the client
 */
static void traverse_start_callback(void *p, TDB_DATA key, TDB_DATA data)
{
	struct traverse_start_state *state;
	struct ctdb_rec_data *d;
	TDB_DATA cdata;

	state = talloc_get_type(p, struct traverse_start_state);

	d = ctdb_marshall_record(state, state->reqid, key, NULL, data);
	if (d == NULL) {
		return;
	}

	cdata.dptr = (uint8_t *)d;
	cdata.dsize = d->length;

	ctdb_dispatch_message(state->ctdb, state->srvid, cdata);
	if (key.dsize == 0 && data.dsize == 0) {
		DEBUG(DEBUG_NOTICE, ("Ending traverse on DB %s (id %d), records %d\n",
				     state->h->ctdb_db->db_name, state->h->reqid,
				     state->num_records));

	    	if (state->h->timedout) {
		    	/* timed out, send TRAVERSE_KILL control */
			talloc_free(state);
		} else {
			/* end of traverse */
			talloc_set_destructor(state, NULL);
			talloc_free(state);
		}
	} else {
		state->num_records++;
	}
}


/**
 * start a traverse_all - called as a control from a client.
 * extended version to take the "withemptyrecords" parameter.
 */
int32_t ctdb_control_traverse_start_ext(struct ctdb_context *ctdb,
					TDB_DATA data,
					TDB_DATA *outdata,
					uint32_t srcnode,
					uint32_t client_id)
{
	struct ctdb_traverse_start_ext *d = (struct ctdb_traverse_start_ext *)data.dptr;
	struct traverse_start_state *state;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_client *client = ctdb_reqid_find(ctdb, client_id, struct ctdb_client);

	if (client == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " No client found\n"));
		return -1;		
	}

	if (data.dsize != sizeof(*d)) {
		DEBUG(DEBUG_ERR,("Bad record size in ctdb_control_traverse_start\n"));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, d->db_id);
	if (ctdb_db == NULL) {
		return -1;
	}

	if (ctdb_db->unhealthy_reason) {
		if (ctdb->tunable.allow_unhealthy_db_read == 0) {
			DEBUG(DEBUG_ERR,("db(%s) unhealty in ctdb_control_traverse_start: %s\n",
					ctdb_db->db_name, ctdb_db->unhealthy_reason));
			return -1;
		}
		DEBUG(DEBUG_WARNING,("warn: db(%s) unhealty in ctdb_control_traverse_start: %s\n",
				     ctdb_db->db_name, ctdb_db->unhealthy_reason));
	}

	state = talloc(client, struct traverse_start_state);
	if (state == NULL) {
		return -1;
	}
	
	state->srcnode = srcnode;
	state->reqid = d->reqid;
	state->srvid = d->srvid;
	state->db_id = d->db_id;
	state->ctdb = ctdb;
	state->withemptyrecords = d->withemptyrecords;
	state->num_records = 0;

	state->h = ctdb_daemon_traverse_all(ctdb_db, traverse_start_callback, state);
	if (state->h == NULL) {
		talloc_free(state);
		return -1;
	}

	talloc_set_destructor(state, ctdb_traverse_start_destructor);

	return 0;
}

/**
 * start a traverse_all - called as a control from a client.
 */
int32_t ctdb_control_traverse_start(struct ctdb_context *ctdb,
				    TDB_DATA data,
				    TDB_DATA *outdata,
				    uint32_t srcnode,
				    uint32_t client_id)
{
	struct ctdb_traverse_start *d = (struct ctdb_traverse_start *)data.dptr;
	struct ctdb_traverse_start_ext d2;
	TDB_DATA data2;

	ZERO_STRUCT(d2);
	d2.db_id = d->db_id;
	d2.reqid = d->reqid;
	d2.srvid = d->srvid;
	d2.withemptyrecords = false;

	data2.dsize = sizeof(d2);
	data2.dptr = (uint8_t *)&d2;

	return ctdb_control_traverse_start_ext(ctdb, data2, outdata, srcnode, client_id);
}
