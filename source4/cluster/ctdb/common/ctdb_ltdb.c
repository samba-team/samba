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
  attach to a specific database
*/
struct ctdb_db_context *ctdb_attach(struct ctdb_context *ctdb, const char *name, int tdb_flags, 
				    int open_flags, mode_t mode)
{
	struct ctdb_db_context *ctdb_db, *tmp_db;
	TDB_DATA data;

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

	/* when we have a separate daemon this will need to be a real
	   file, not a TDB_INTERNAL, so the parent can access it to
	   for ltdb bypass */
	ctdb_db->ltdb = tdb_wrap_open(ctdb, name, 0, TDB_INTERNAL, open_flags, mode);
	if (ctdb_db->ltdb == NULL) {
		ctdb_set_error(ctdb, "Failed to open tdb %s\n", name);
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
		    TDB_DATA key, struct ctdb_ltdb_header *header, TDB_DATA *data)
{
	TDB_DATA rec;
	struct ctdb_context *ctdb = ctdb_db->ctdb;

	rec = tdb_fetch(ctdb_db->ltdb->tdb, key);
	if (rec.dsize < sizeof(*header)) {
		/* return an initial header */
		free(rec.dptr);
		ltdb_initial_header(ctdb_db, key, header);
		data->dptr = NULL;
		data->dsize = 0;
		return 0;
	}

	*header = *(struct ctdb_ltdb_header *)rec.dptr;

	data->dsize = rec.dsize - sizeof(struct ctdb_ltdb_header);
	data->dptr = talloc_memdup(ctdb_db, sizeof(struct ctdb_ltdb_header)+rec.dptr,
				   data->dsize);
	free(rec.dptr);
	CTDB_NO_MEMORY(ctdb, data->dptr);

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
