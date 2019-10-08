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

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"

#include <tdb.h>

#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/dlinklist.h"
#include "lib/util/debug.h"

#include "ctdb_private.h"

#include "common/common.h"
#include "common/logging.h"


/*
 * Calculate tdb flags based on databse type
 */
int ctdb_db_tdb_flags(uint8_t db_flags, bool with_valgrind, bool with_mutex)
{
	int tdb_flags = 0;

	if (db_flags & CTDB_DB_FLAGS_PERSISTENT) {
		tdb_flags = TDB_DEFAULT;

	} else if (db_flags & CTDB_DB_FLAGS_REPLICATED) {
		tdb_flags = TDB_NOSYNC |
			    TDB_CLEAR_IF_FIRST |
			    TDB_INCOMPATIBLE_HASH;

	} else {
		tdb_flags = TDB_NOSYNC |
			    TDB_CLEAR_IF_FIRST |
			    TDB_INCOMPATIBLE_HASH;

#ifdef TDB_MUTEX_LOCKING
		if (with_mutex && tdb_runtime_check_for_robust_mutexes()) {
			tdb_flags |= TDB_MUTEX_LOCKING;
		}
#endif

	}

	tdb_flags |= TDB_DISALLOW_NESTING;
	if (with_valgrind) {
		tdb_flags |= TDB_NOMMAP;
	}

	return tdb_flags;
}

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

bool ctdb_db_persistent(struct ctdb_db_context *ctdb_db)
{
	if (ctdb_db->db_flags & CTDB_DB_FLAGS_PERSISTENT) {
		return true;
	}
	return false;
}

bool ctdb_db_replicated(struct ctdb_db_context *ctdb_db)
{
	if (ctdb_db->db_flags & CTDB_DB_FLAGS_REPLICATED) {
		return true;
	}
	return false;
}

bool ctdb_db_volatile(struct ctdb_db_context *ctdb_db)
{
	if ((ctdb_db->db_flags & CTDB_DB_FLAGS_PERSISTENT) ||
	    (ctdb_db->db_flags & CTDB_DB_FLAGS_REPLICATED)) {
		return false;
	}
	return true;
}

bool ctdb_db_readonly(struct ctdb_db_context *ctdb_db)
{
	if (ctdb_db->db_flags & CTDB_DB_FLAGS_READONLY) {
		return true;
	}
	return false;
}

void ctdb_db_set_readonly(struct ctdb_db_context *ctdb_db)
{
	ctdb_db->db_flags |= CTDB_DB_FLAGS_READONLY;
}

void ctdb_db_reset_readonly(struct ctdb_db_context *ctdb_db)
{
	ctdb_db->db_flags &= ~CTDB_DB_FLAGS_READONLY;
}

bool ctdb_db_sticky(struct ctdb_db_context *ctdb_db)
{
	if (ctdb_db->db_flags & CTDB_DB_FLAGS_STICKY) {
		return true;
	}
	return false;
}

void ctdb_db_set_sticky(struct ctdb_db_context *ctdb_db)
{
	ctdb_db->db_flags |= CTDB_DB_FLAGS_STICKY;
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

struct ctdb_ltdb_fetch_state {
	struct ctdb_ltdb_header *header;
	TALLOC_CTX *mem_ctx;
	TDB_DATA *data;
	int ret;
	bool found;
};

static int ctdb_ltdb_fetch_fn(TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct ctdb_ltdb_fetch_state *state = private_data;
	struct ctdb_ltdb_header *header = state->header;
	TDB_DATA *dstdata = state->data;

	if (data.dsize < sizeof(*header)) {
		return 0;
	}

	state->found = true;
	memcpy(header, data.dptr, sizeof(*header));

	if (dstdata != NULL) {
		dstdata->dsize = data.dsize - sizeof(struct ctdb_ltdb_header);
		dstdata->dptr = talloc_memdup(
			state->mem_ctx,
			data.dptr + sizeof(struct ctdb_ltdb_header),
			dstdata->dsize);
		if (dstdata->dptr == NULL) {
			state->ret = -1;
		}
	}

	return 0;
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
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	struct ctdb_ltdb_fetch_state state = {
		.header = header,
		.mem_ctx = mem_ctx,
		.data = data,
		.found = false,
	};
	int ret;

	ret = tdb_parse_record(
		ctdb_db->ltdb->tdb, key, ctdb_ltdb_fetch_fn, &state);

	if (ret == -1) {
		enum TDB_ERROR err = tdb_error(ctdb_db->ltdb->tdb);
		if (err != TDB_ERR_NOEXIST) {
			return -1;
		}
	}

	if (state.ret != 0) {
		DBG_DEBUG("ctdb_ltdb_fetch_fn failed\n");
		return state.ret;
	}

	if (state.found) {
		return 0;
	}

	if (data != NULL) {
		*data = tdb_null;
	}

	if (ctdb->vnn_map == NULL) {
		/* called from the client */
		header->dmaster = (uint32_t)-1;
		return -1;
	}

	ltdb_initial_header(ctdb_db, key, header);
	if (ctdb_db_persistent(ctdb_db) ||
	    header->dmaster == ctdb_db->ctdb->pnn) {

		ret = ctdb_ltdb_store(ctdb_db, key, header, tdb_null);
		if (ret != 0) {
			DBG_NOTICE("failed to store initial header\n");
		}
	}

	return 0;
}

/*
  write a record to a normal database
*/
int ctdb_ltdb_store(struct ctdb_db_context *ctdb_db, TDB_DATA key, 
		    struct ctdb_ltdb_header *header, TDB_DATA data)
{
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	TDB_DATA rec[2];
	uint32_t hsize = sizeof(struct ctdb_ltdb_header);
	int ret;

	if (ctdb_db->ctdb_ltdb_store_fn) {
		return ctdb_db->ctdb_ltdb_store_fn(ctdb_db, key, header, data);
	}

	if (ctdb->flags & CTDB_FLAG_TORTURE) {
		TDB_DATA old;
		struct ctdb_ltdb_header *h2;

		old = tdb_fetch(ctdb_db->ltdb->tdb, key);
		h2 = (struct ctdb_ltdb_header *)old.dptr;
		if (old.dptr != NULL && old.dsize >= hsize &&
		    h2->rsn > header->rsn) {
			DEBUG(DEBUG_ERR,
			      ("RSN regression! %"PRIu64" %"PRIu64"\n",
			       h2->rsn, header->rsn));
		}
		if (old.dptr != NULL) {
			free(old.dptr);
		}
	}

	rec[0].dsize = hsize;
	rec[0].dptr = (uint8_t *)header;

	rec[1].dsize = data.dsize;
	rec[1].dptr = data.dptr;

	ret = tdb_storev(ctdb_db->ltdb->tdb, key, rec, 2, TDB_REPLACE);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to store dynamic data\n"));
	}

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
	if (! ctdb_db_volatile(ctdb_db)) {
		DEBUG(DEBUG_WARNING,
		      ("Ignored deletion of empty record from "
		       "non-volatile database\n"));
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
	unsigned int byte_pos = pnn / 8;
	unsigned char bit_mask = 1 << (pnn % 8);

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
	unsigned int i;

	for(i = 0; i < data.dsize; i++) {
		unsigned int j;

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

