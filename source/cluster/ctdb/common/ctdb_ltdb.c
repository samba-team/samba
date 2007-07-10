/* 
   ctdb ltdb code

   Copyright (C) Andrew Tridgell  2006

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
		if (ctdb->vnn_map == NULL) {
			/* called from the client */
			ZERO_STRUCTP(data);
			header->dmaster = (uint32_t)-1;
			return -1;
		}
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

	if (ctdb->flags & CTDB_FLAG_TORTURE) {
		struct ctdb_ltdb_header *h2;
		rec = tdb_fetch(ctdb_db->ltdb->tdb, key);
		h2 = (struct ctdb_ltdb_header *)rec.dptr;
		if (rec.dptr && rec.dsize >= sizeof(h2) && h2->rsn > header->rsn) {
			DEBUG(0,("RSN regression! %llu %llu\n",
				 (unsigned long long)h2->rsn, (unsigned long long)header->rsn));
		}
		if (rec.dptr) free(rec.dptr);
	}

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
