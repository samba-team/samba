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
static int ctdb_fetch_func(struct ctdb_call_info *call)
{
	call->reply_data = &call->record_data;
	return 0;
}


/*
  attach to a specific database
*/
struct ctdb_db_context *ctdb_attach(struct ctdb_context *ctdb, const char *name, int tdb_flags, 
				    int open_flags, mode_t mode)
{
	struct ctdb_db_context *ctdb_db, *tmp_db;
	TDB_DATA data;
	int ret;

	ctdb_db = talloc_zero(ctdb, struct ctdb_db_context);
	CTDB_NO_MEMORY_NULL(ctdb, ctdb_db);

	ctdb_db->ctdb = ctdb;
	ctdb_db->db_name = talloc_strdup(ctdb_db, name);
	CTDB_NO_MEMORY_NULL(ctdb, ctdb_db->db_name);

	data.dptr = discard_const(name);
	data.dsize = strlen(name);
	ctdb_db->db_id = ctdb_hash(&data);

	for (tmp_db=ctdb->db_list;tmp_db;tmp_db=tmp_db->next) {
		if (tmp_db->db_id == ctdb_db->db_id) {
			ctdb_set_error(ctdb, "CTDB database hash collission '%s' : '%s'",
					name, tmp_db->db_name);
			talloc_free(ctdb_db);
			return NULL;
		}
	}

	/* add the node id to the database name, so when we run on loopback
	   we don't conflict in the local filesystem */
	name = talloc_asprintf(ctdb_db, "%s.%u", name, ctdb_get_vnn(ctdb));

	/* when we have a separate daemon this will need to be a real
	   file, not a TDB_INTERNAL, so the parent can access it to
	   for ltdb bypass */
	ctdb_db->ltdb = tdb_wrap_open(ctdb, name, 0, TDB_DEFAULT, open_flags, mode);
	if (ctdb_db->ltdb == NULL) {
		ctdb_set_error(ctdb, "Failed to open tdb %s\n", name);
		talloc_free(ctdb_db);
		return NULL;
	}


	/* 
	  all databases support the "fetch" function. we need this in order to do forced migration of records
	 */
	ret = ctdb_set_call(ctdb_db, ctdb_fetch_func, CTDB_FETCH_FUNC);
	if (ret != 0) {
		talloc_free(ctdb_db);
		return NULL;
	}

	DLIST_ADD(ctdb->db_list, ctdb_db);

	return ctdb_db;
}

/*
  return the lmaster given a key
*/
uint32_t ctdb_lmaster(struct ctdb_context *ctdb, const TDB_DATA *key)
{
	return ctdb_hash(key) % ctdb->num_nodes;
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
		/* return an initial header */
		free(rec.dptr);
		ltdb_initial_header(ctdb_db, key, header);
		if (data) {
			data->dptr = NULL;
			data->dsize = 0;
		}
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
	return tdb_chainunlock(ctdb_db->ltdb->tdb, key);
}

/*
  called when we should retry the operation
 */
static void lock_fetch_callback(void *p)
{
	struct ctdb_req_header *hdr = p;
	struct ctdb_context *ctdb = talloc_find_parent_bytype(p, struct ctdb_context);
	ctdb_recv_pkt(ctdb, (uint8_t *)hdr, hdr->length);
	printf("PACKET REQUEUED\n");
}

/*
  do a non-blocking ltdb_fetch with a locked record, deferring this
  ctdb request until we have the chainlock

  It does the following:

   1) tries to get the chainlock. If it succeeds, then it fetches the record, and 
      returns 0

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
int ctdb_ltdb_lock_fetch_requeue(struct ctdb_db_context *ctdb_db, 
				 TDB_DATA key, struct ctdb_ltdb_header *header, 
				 struct ctdb_req_header *hdr, TDB_DATA *data)
{
	int ret;
	struct tdb_context *tdb = ctdb_db->ltdb->tdb;
	struct lockwait_handle *h;
	
	ret = tdb_chainlock_nonblock(tdb, key);

	if (ret != 0 &&
	    !(errno == EACCES || errno == EAGAIN || errno == EDEADLK)) {
		/* a hard failure - don't try again */
		return -1;
	}

	/* first the non-contended path */
	if (ret == 0) {
		ret = ctdb_ltdb_fetch(ctdb_db, key, header, hdr, data);
		if (ret != 0) {
			tdb_chainunlock(tdb, key);
		}	
		return ret;
	}

	/* now the contended path */
	h = ctdb_lockwait(ctdb_db, key, lock_fetch_callback, hdr);
	if (h == NULL) {
		tdb_chainunlock(tdb, key);
		return -1;
	}

	/* we get an extra reference to the packet here, to 
	   stop it being freed in the top level packet handler */
	if (talloc_reference(ctdb_db, hdr) == NULL) {
		talloc_free(h);
		return -1;
	}

	/* now tell the caller than we will retry asynchronously */
	return -2;
}
