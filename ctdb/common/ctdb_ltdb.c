/* 
   ctdb ltdb code

   Copyright (C) Andrew Tridgell  2006
   Copyright (C) Ronnie sahlberg  2011

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
#include "system/network.h"
#include "system/filesys.h"
#include "../include/ctdb_private.h"
#include "lib/tdb_wrap/tdb_wrap.h"
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
	ZERO_STRUCTP(header);
	/* initial dmaster is the lmaster */
	header->dmaster = ctdb_lmaster(ctdb_db->ctdb, &key);
	header->flags = CTDB_REC_FLAG_AUTOMATIC;
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
		if (rec.dptr) free(rec.dptr);
		if (ctdb->vnn_map == NULL) {
			/* called from the client */
			ZERO_STRUCTP(data);
			header->dmaster = (uint32_t)-1;
			return -1;
		}
		ltdb_initial_header(ctdb_db, key, header);
		if (data) {
			*data = tdb_null;
		}
		if (ctdb_db->persistent || header->dmaster == ctdb_db->ctdb->pnn) {
			if (ctdb_ltdb_store(ctdb_db, key, header, tdb_null) != 0) {
				DEBUG(DEBUG_NOTICE,
				      (__location__ "failed to store initial header\n"));
			}
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
  and returning the body of the record.
  if the record does not exist, *header will be NULL
  and data = {0, NULL}
*/
int ctdb_ltdb_fetch_with_header(struct ctdb_db_context *ctdb_db, 
		    TDB_DATA key, struct ctdb_ltdb_header *header, 
		    TALLOC_CTX *mem_ctx, TDB_DATA *data)
{
	TDB_DATA rec;

	rec = tdb_fetch(ctdb_db->ltdb->tdb, key);
	if (rec.dsize < sizeof(*header)) {
		free(rec.dptr);

		data->dsize = 0;
		data->dptr = NULL;
		return -1;
	}

	*header = *(struct ctdb_ltdb_header *)rec.dptr;
	if (data) {
		data->dsize = rec.dsize - sizeof(struct ctdb_ltdb_header);
		data->dptr = talloc_memdup(mem_ctx, 
					   sizeof(struct ctdb_ltdb_header)+rec.dptr,
					   data->dsize);
	}

	free(rec.dptr);

	return 0;
}


/*
  write a record to a normal database
*/
int ctdb_ltdb_store(struct ctdb_db_context *ctdb_db, TDB_DATA key, 
		    struct ctdb_ltdb_header *header, TDB_DATA data)
{
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	TDB_DATA rec;
	int ret;
	bool seqnum_suppressed = false;

	if (ctdb_db->ctdb_ltdb_store_fn) {
		return ctdb_db->ctdb_ltdb_store_fn(ctdb_db, key, header, data);
	}

	if (ctdb->flags & CTDB_FLAG_TORTURE) {
		struct ctdb_ltdb_header *h2;
		rec = tdb_fetch(ctdb_db->ltdb->tdb, key);
		h2 = (struct ctdb_ltdb_header *)rec.dptr;
		if (rec.dptr && rec.dsize >= sizeof(h2) && h2->rsn > header->rsn) {
			DEBUG(DEBUG_CRIT,("RSN regression! %llu %llu\n",
				 (unsigned long long)h2->rsn, (unsigned long long)header->rsn));
		}
		if (rec.dptr) free(rec.dptr);
	}

	rec.dsize = sizeof(*header) + data.dsize;
	rec.dptr = talloc_size(ctdb, rec.dsize);
	CTDB_NO_MEMORY(ctdb, rec.dptr);

	memcpy(rec.dptr, header, sizeof(*header));
	memcpy(rec.dptr + sizeof(*header), data.dptr, data.dsize);

	/* Databases with seqnum updates enabled only get their seqnum
	   changes when/if we modify the data */
	if (ctdb_db->seqnum_update != NULL) {
		TDB_DATA old;
		old = tdb_fetch(ctdb_db->ltdb->tdb, key);

		if ( (old.dsize == rec.dsize)
		&& !memcmp(old.dptr+sizeof(struct ctdb_ltdb_header),
			  rec.dptr+sizeof(struct ctdb_ltdb_header),
			  rec.dsize-sizeof(struct ctdb_ltdb_header)) ) {
			tdb_remove_flags(ctdb_db->ltdb->tdb, TDB_SEQNUM);
			seqnum_suppressed = true;
		}
		if (old.dptr) free(old.dptr);
	}
	ret = tdb_store(ctdb_db->ltdb->tdb, key, rec, TDB_REPLACE);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to store dynamic data\n"));
	}
	if (seqnum_suppressed) {
		tdb_add_flags(ctdb_db->ltdb->tdb, TDB_SEQNUM);
	}

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
 		DEBUG(DEBUG_ERR,("tdb_chainunlock failed on db %s [%s]\n", ctdb_db->db_name, tdb_errorstr(ctdb_db->ltdb->tdb)));
	}
	return ret;
}


/*
  delete a record from a normal database
*/
int ctdb_ltdb_delete(struct ctdb_db_context *ctdb_db, TDB_DATA key)
{
	if (ctdb_db->persistent != 0) {
		DEBUG(DEBUG_ERR,("Trying to delete emty record in persistent database\n"));
		return 0;
	}
	if (tdb_delete(ctdb_db->ltdb->tdb, key) != 0) {
		DEBUG(DEBUG_ERR,("Failed to delete empty record."));
		return -1;
	}
	return 0;
}

int ctdb_trackingdb_add_pnn(struct ctdb_context *ctdb, TDB_DATA *data, uint32_t pnn)
{
	int byte_pos = pnn / 8;
	int bit_mask   = 1 << (pnn % 8);

	if (byte_pos + 1 > data->dsize) {
		char *buf;

		buf = malloc(byte_pos + 1);
		memset(buf, 0, byte_pos + 1);
		if (buf == NULL) {
			DEBUG(DEBUG_ERR, ("Out of memory when allocating buffer of %d bytes for trackingdb\n", byte_pos + 1));
			return -1;
		}
		if (data->dptr != NULL) {
			memcpy(buf, data->dptr, data->dsize);
			free(data->dptr);
		}
		data->dptr  = (uint8_t *)buf;
		data->dsize = byte_pos + 1;
	}

	data->dptr[byte_pos] |= bit_mask;
	return 0;
}

void ctdb_trackingdb_traverse(struct ctdb_context *ctdb, TDB_DATA data, ctdb_trackingdb_cb cb, void *private_data)
{
	int i;

	for(i = 0; i < data.dsize; i++) {
		int j;

		for (j=0; j<8; j++) {
			int mask = 1<<j;

			if (data.dptr[i] & mask) {
				cb(ctdb, i * 8 + j, private_data);
			}
		}
	}
}

/*
  this is the dummy null procedure that all databases support
*/
int ctdb_null_func(struct ctdb_call_info *call)
{
	return 0;
}

/*
  this is a plain fetch procedure that all databases support
*/
int ctdb_fetch_func(struct ctdb_call_info *call)
{
	call->reply_data = &call->record_data;
	return 0;
}

/*
  this is a plain fetch procedure that all databases support
  this returns the full record including the ltdb header
*/
int ctdb_fetch_with_header_func(struct ctdb_call_info *call)
{
	call->reply_data = talloc(call, TDB_DATA);
	if (call->reply_data == NULL) {
		return -1;
	}
	call->reply_data->dsize = sizeof(struct ctdb_ltdb_header) + call->record_data.dsize;
	call->reply_data->dptr  = talloc_size(call->reply_data, call->reply_data->dsize);
	if (call->reply_data->dptr == NULL) {
		return -1;
	}
	memcpy(call->reply_data->dptr, call->header, sizeof(struct ctdb_ltdb_header));
	memcpy(&call->reply_data->dptr[sizeof(struct ctdb_ltdb_header)], call->record_data.dptr, call->record_data.dsize);

	return 0;
}

