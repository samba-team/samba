/* 
   ctdb ltdb code

   Copyright (C) Andrew Tridgell  2006

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "lib/events/events.h"
#include "lib/tdb/include/tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "../include/ctdb_private.h"
#include "db_wrap.h"
#include "lib/util/dlinklist.h"

/*
  find an attached ctdb_db handle given a name
 */
struct ctdb_db_context *ctdb_db_handle(struct ctdb_context *ctdb, const char *name)
{
	struct ctdb_db_context *tmp_db;
	for (tmp_db=ctdb->db_list;tmp_db;tmp_db=tmp_db->next) {
		if (strcmp(name, tmp_db->db_name) == 0) {
			return tmp_db;
		}
	}
	return NULL;
}


/*
  this is the dummy null procedure that all databases support
*/
static int ctdb_null_func(struct ctdb_call_info *call)
{
	return 0;
}

/*
  this is a plain fetch procedure that all databases support
*/
static int ctdb_fetch_func(struct ctdb_call_info *call)
{
	call->reply_data = &call->record_data;
	return 0;
}


/*
  return the lmaster given a key
*/
uint32_t ctdb_lmaster(struct ctdb_context *ctdb, const TDB_DATA *key)
{
	uint32_t idx, lmaster;

	idx = ctdb_hash(key) % ctdb->vnn_map->size;
	lmaster = ctdb->vnn_map->map[idx];

	return lmaster;
}


/*
  construct an initial header for a record with no ltdb header yet
*/
static void ltdb_initial_header(struct ctdb_db_context *ctdb_db, 
				TDB_DATA key,
				struct ctdb_ltdb_header *header)
{
	header->rsn = 0;
	/* initial dmaster is the lmaster */
	header->dmaster = ctdb_lmaster(ctdb_db->ctdb, &key);
	header->laccessor = header->dmaster;
	header->lacount = 0;
}


/*
  fetch a record from the ltdb, separating out the header information
  and returning the body of the record. A valid (initial) header is
  returned if the record is not present
*/
int ctdb_ltdb_fetch(struct ctdb_db_context *ctdb_db, 
		    TDB_DATA key, struct ctdb_ltdb_header *header, 
		    TALLOC_CTX *mem_ctx, TDB_DATA *data)
{
	TDB_DATA rec;
	struct ctdb_context *ctdb = ctdb_db->ctdb;

	rec = tdb_fetch(ctdb_db->ltdb->tdb, key);
	if (rec.dsize < sizeof(*header)) {
		TDB_DATA d2;
		/* return an initial header */
		if (rec.dptr) free(rec.dptr);
		ltdb_initial_header(ctdb_db, key, header);
		ZERO_STRUCT(d2);
		if (data) {
			*data = d2;
		}
		ctdb_ltdb_store(ctdb_db, key, header, d2);
		return 0;
	}

	*header = *(struct ctdb_ltdb_header *)rec.dptr;

	if (data) {
		data->dsize = rec.dsize - sizeof(struct ctdb_ltdb_header);
		data->dptr = talloc_memdup(mem_ctx, 
					   sizeof(struct ctdb_ltdb_header)+rec.dptr,
					   data->dsize);
	}

	free(rec.dptr);
	if (data) {
		CTDB_NO_MEMORY(ctdb, data->dptr);
	}

	return 0;
}


/*
  fetch a record from the ltdb, separating out the header information
  and returning the body of the record. A valid (initial) header is
  returned if the record is not present
*/
int ctdb_ltdb_store(struct ctdb_db_context *ctdb_db, TDB_DATA key, 
		    struct ctdb_ltdb_header *header, TDB_DATA data)
{
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	TDB_DATA rec;
	int ret;

	rec.dsize = sizeof(*header) + data.dsize;
	rec.dptr = talloc_size(ctdb, rec.dsize);
	CTDB_NO_MEMORY(ctdb, rec.dptr);

	memcpy(rec.dptr, header, sizeof(*header));
	memcpy(rec.dptr + sizeof(*header), data.dptr, data.dsize);

	ret = tdb_store(ctdb_db->ltdb->tdb, key, rec, TDB_REPLACE);
	talloc_free(rec.dptr);

	return ret;
}


/*
  lock a record in the ltdb, given a key
 */
int ctdb_ltdb_lock(struct ctdb_db_context *ctdb_db, TDB_DATA key)
{
	return tdb_chainlock(ctdb_db->ltdb->tdb, key);
}

/*
  unlock a record in the ltdb, given a key
 */
int ctdb_ltdb_unlock(struct ctdb_db_context *ctdb_db, TDB_DATA key)
{
	int ret = tdb_chainunlock(ctdb_db->ltdb->tdb, key);
	if (ret != 0) {
		DEBUG(0,("tdb_chainunlock failed\n"));
	}
	return ret;
}

struct lock_fetch_state {
	struct ctdb_context *ctdb;
	void (*recv_pkt)(void *, uint8_t *, uint32_t);
	void *recv_context;
	struct ctdb_req_header *hdr;
};

/*
  called when we should retry the operation
 */
static void lock_fetch_callback(void *p)
{
	struct lock_fetch_state *state = talloc_get_type(p, struct lock_fetch_state);
	state->recv_pkt(state->recv_context, (uint8_t *)state->hdr, state->hdr->length);
	DEBUG(2,(__location__ " PACKET REQUEUED\n"));
}


/*
  do a non-blocking ltdb_lock, deferring this ctdb request until we
  have the chainlock

  It does the following:

   1) tries to get the chainlock. If it succeeds, then it returns 0

   2) if it fails to get a chainlock immediately then it sets up a
   non-blocking chainlock via ctdb_lockwait, and when it gets the
   chainlock it re-submits this ctdb request to the main packet
   receive function

   This effectively queues all ctdb requests that cannot be
   immediately satisfied until it can get the lock. This means that
   the main ctdb daemon will not block waiting for a chainlock held by
   a client

   There are 3 possible return values:

       0:    means that it got the lock immediately.
      -1:    means that it failed to get the lock, and won't retry
      -2:    means that it failed to get the lock immediately, but will retry
 */
int ctdb_ltdb_lock_requeue(struct ctdb_db_context *ctdb_db, 
			   TDB_DATA key, struct ctdb_req_header *hdr,
			   void (*recv_pkt)(void *, uint8_t *, uint32_t ),
			   void *recv_context)
{
	int ret;
	struct tdb_context *tdb = ctdb_db->ltdb->tdb;
	struct lockwait_handle *h;
	struct lock_fetch_state *state;
	
	ret = tdb_chainlock_nonblock(tdb, key);

	if (ret != 0 &&
	    !(errno == EACCES || errno == EAGAIN || errno == EDEADLK)) {
		/* a hard failure - don't try again */
		return -1;
	}

	/* when torturing, ensure we test the contended path */
	if ((ctdb_db->ctdb->flags & CTDB_FLAG_TORTURE) &&
	    random() % 5 == 0) {
		ret = -1;
		tdb_chainunlock(tdb, key);
	}

	/* first the non-contended path */
	if (ret == 0) {
		return 0;
	}

	state = talloc(hdr, struct lock_fetch_state);
	state->ctdb = ctdb_db->ctdb;
	state->hdr = hdr;
	state->recv_pkt = recv_pkt;
	state->recv_context = recv_context;

	/* now the contended path */
	h = ctdb_lockwait(ctdb_db, key, lock_fetch_callback, state);
	if (h == NULL) {
		tdb_chainunlock(tdb, key);
		return -1;
	}

	/* we need to move the packet off the temporary context in ctdb_recv_pkt(),
	   so it won't be freed yet */
	talloc_steal(state, hdr);
	talloc_steal(state, h);

	/* now tell the caller than we will retry asynchronously */
	return -2;
}

/*
  a varient of ctdb_ltdb_lock_requeue that also fetches the record
 */
int ctdb_ltdb_lock_fetch_requeue(struct ctdb_db_context *ctdb_db, 
				 TDB_DATA key, struct ctdb_ltdb_header *header, 
				 struct ctdb_req_header *hdr, TDB_DATA *data,
				 void (*recv_pkt)(void *, uint8_t *, uint32_t ),
				 void *recv_context)
{
	int ret;

	ret = ctdb_ltdb_lock_requeue(ctdb_db, key, hdr, recv_pkt, recv_context);
	if (ret == 0) {
		ret = ctdb_ltdb_fetch(ctdb_db, key, header, hdr, data);
		if (ret != 0) {
			ctdb_ltdb_unlock(ctdb_db, key);
		}
	}
	return ret;
}


/*
  a client has asked to attach a new database
 */
int32_t ctdb_control_db_attach(struct ctdb_context *ctdb, TDB_DATA indata,
			       TDB_DATA *outdata)
{
	const char *db_name = (const char *)indata.dptr;
	struct ctdb_db_context *ctdb_db, *tmp_db;
	int ret;

	/* see if we already have this name */
	for (tmp_db=ctdb->db_list;tmp_db;tmp_db=tmp_db->next) {
		if (strcmp(db_name, tmp_db->db_name) == 0) {
			/* this is not an error */
			outdata->dptr  = (uint8_t *)&tmp_db->db_id;
			outdata->dsize = sizeof(tmp_db->db_id);
			return 0;
		}
	}

	ctdb_db = talloc_zero(ctdb, struct ctdb_db_context);
	CTDB_NO_MEMORY(ctdb, ctdb_db);

	ctdb_db->ctdb = ctdb;
	ctdb_db->db_name = talloc_strdup(ctdb_db, db_name);
	CTDB_NO_MEMORY(ctdb, ctdb_db->db_name);

	ctdb_db->db_id = ctdb_hash(&indata);

	outdata->dptr  = (uint8_t *)&ctdb_db->db_id;
	outdata->dsize = sizeof(ctdb_db->db_id);

	/* check for hash collisions */
	for (tmp_db=ctdb->db_list;tmp_db;tmp_db=tmp_db->next) {
		if (tmp_db->db_id == ctdb_db->db_id) {
			DEBUG(0,("db_id 0x%x hash collision. name1='%s' name2='%s'\n",
				 db_name, tmp_db->db_name));
			talloc_free(ctdb_db);
			return -1;
		}
	}

	if (ctdb->db_directory == NULL) {
		ctdb->db_directory = VARDIR "/ctdb";
	}

	/* make sure the db directory exists */
	if (mkdir(ctdb->db_directory, 0700) == -1 && errno != EEXIST) {
		DEBUG(0,(__location__ " Unable to create ctdb directory '%s'\n", 
			 ctdb->db_directory));
		talloc_free(ctdb_db);
		return -1;
	}

	/* open the database */
	ctdb_db->db_path = talloc_asprintf(ctdb_db, "%s/%s.%u", 
					   ctdb->db_directory, 
					   db_name, ctdb->vnn);

	ctdb_db->ltdb = tdb_wrap_open(ctdb, ctdb_db->db_path, 0, 
				      TDB_CLEAR_IF_FIRST, O_CREAT|O_RDWR, 0666);
	if (ctdb_db->ltdb == NULL) {
		DEBUG(0,("Failed to open tdb '%s'\n", ctdb_db->db_path));
		talloc_free(ctdb_db);
		return -1;
	}

	DLIST_ADD(ctdb->db_list, ctdb_db);

	/* 
	   all databases support the "null" function. we need this in
	   order to do forced migration of records
	*/
	ret = ctdb_daemon_set_call(ctdb, ctdb_db->db_id, ctdb_null_func, CTDB_NULL_FUNC);
	if (ret != 0) {
		DEBUG(0,("Failed to setup null function for '%s'\n", ctdb_db->db_name));
		talloc_free(ctdb_db);
		return -1;
	}

	/* 
	   all databases support the "fetch" function. we need this
	   for efficient Samba3 ctdb fetch
	*/
	ret = ctdb_daemon_set_call(ctdb, ctdb_db->db_id, ctdb_fetch_func, CTDB_FETCH_FUNC);
	if (ret != 0) {
		DEBUG(0,("Failed to setup fetch function for '%s'\n", ctdb_db->db_name));
		talloc_free(ctdb_db);
		return -1;
	}
	
	/* tell all the other nodes about this database */
	ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_VNNMAP, 0,
				 CTDB_CONTROL_DB_ATTACH, 0, CTDB_CTRL_FLAG_NOREPLY,
				 indata, NULL, NULL);

	DEBUG(1,("Attached to database '%s'\n", ctdb_db->db_path));

	/* success */
	return 0;
}

/*
  called when a broadcast seqnum update comes in
 */
int32_t ctdb_ltdb_update_seqnum(struct ctdb_context *ctdb, uint32_t db_id, uint32_t srcnode)
{
	struct ctdb_db_context *ctdb_db;
	if (srcnode == ctdb->vnn) {
		/* don't update ourselves! */
		return 0;
	}

	ctdb_db = find_ctdb_db(ctdb, db_id);
	if (!ctdb_db) {
		DEBUG(0,("Unknown db_id 0x%x in ctdb_ltdb_update_seqnum\n"));
		return -1;
	}

	tdb_increment_seqnum_nonblock(ctdb_db->ltdb->tdb);
	ctdb_db->seqnum = tdb_get_seqnum(ctdb_db->ltdb->tdb);
	return 0;
}

/*
  timer to check for seqnum changes in a ltdb and propogate them
 */
static void ctdb_ltdb_seqnum_check(struct event_context *ev, struct timed_event *te, 
				   struct timeval t, void *p)
{
	struct ctdb_db_context *ctdb_db = talloc_get_type(p, struct ctdb_db_context);
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	uint32_t new_seqnum = tdb_get_seqnum(ctdb_db->ltdb->tdb);
	if (new_seqnum != ctdb_db->seqnum) {
		/* something has changed - propogate it */
		TDB_DATA data;
		data.dptr = (uint8_t *)&ctdb_db->db_id;
		data.dsize = sizeof(uint32_t);
		ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_VNNMAP, 0,
					 CTDB_CONTROL_UPDATE_SEQNUM, 0, CTDB_CTRL_FLAG_NOREPLY,
					 data, NULL, NULL);		
	}
	ctdb_db->seqnum = new_seqnum;

	/* setup a new timer */
	ctdb_db->te = event_add_timed(ctdb->ev, ctdb_db, 
				      timeval_current_ofs(ctdb->seqnum_frequency, 0),
				      ctdb_ltdb_seqnum_check, ctdb_db);
}

/*
  enable seqnum handling on this db
 */
int32_t ctdb_ltdb_enable_seqnum(struct ctdb_context *ctdb, uint32_t db_id)
{
	struct ctdb_db_context *ctdb_db;
	ctdb_db = find_ctdb_db(ctdb, db_id);
	if (!ctdb_db) {
		DEBUG(0,("Unknown db_id 0x%x in ctdb_ltdb_enable_seqnum\n"));
		return -1;
	}

	if (ctdb_db->te == NULL) {
		ctdb_db->te = event_add_timed(ctdb->ev, ctdb_db, 
					      timeval_current_ofs(ctdb->seqnum_frequency, 0),
					      ctdb_ltdb_seqnum_check, ctdb_db);
	}

	tdb_enable_seqnum(ctdb_db->ltdb->tdb);
	ctdb_db->seqnum = tdb_get_seqnum(ctdb_db->ltdb->tdb);
	return 0;
}

/*
  enable seqnum handling on this db
 */
int32_t ctdb_ltdb_set_seqnum_frequency(struct ctdb_context *ctdb, uint32_t frequency)
{
	ctdb->seqnum_frequency = frequency;
	return 0;
}
