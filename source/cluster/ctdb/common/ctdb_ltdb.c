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
#include "cluster/ctdb/include/ctdb_private.h"

/*
  attach to a specific database
*/
int ctdb_attach(struct ctdb_context *ctdb, const char *name, int tdb_flags, 
		int open_flags, mode_t mode)
{
	/* when we have a separate daemon this will need to be a real
	   file, not a TDB_INTERNAL, so the parent can access it to
	   for ltdb bypass */
	ctdb->ltdb = tdb_open(name, 0, /* tdb_flags */ TDB_INTERNAL, open_flags, mode);
	if (ctdb->ltdb == NULL) {
		ctdb_set_error(ctdb, "Failed to open tdb %s\n", name);
		return -1;
	}
	return 0;
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
static void ltdb_initial_header(struct ctdb_context *ctdb, 
				TDB_DATA key,
				struct ctdb_ltdb_header *header)
{
	header->rsn = 0;
	/* initial dmaster is the lmaster */
	header->dmaster = ctdb_lmaster(ctdb, &key);
	header->laccessor = header->dmaster;
	header->lacount = 0;
}


/*
  fetch a record from the ltdb, separating out the header information
  and returning the body of the record. A valid (initial) header is
  returned if the record is not present
*/
int ctdb_ltdb_fetch(struct ctdb_context *ctdb, 
		    TDB_DATA key, struct ctdb_ltdb_header *header, TDB_DATA *data)
{
	TDB_DATA rec;

	rec = tdb_fetch(ctdb->ltdb, key);
	if (rec.dsize < sizeof(*header)) {
		/* return an initial header */
		free(rec.dptr);
		ltdb_initial_header(ctdb, key, header);
		data->dptr = NULL;
		data->dsize = 0;
		return 0;
	}

	*header = *(struct ctdb_ltdb_header *)rec.dptr;

	data->dsize = rec.dsize - sizeof(struct ctdb_ltdb_header);
	data->dptr = talloc_memdup(ctdb, sizeof(struct ctdb_ltdb_header)+rec.dptr,
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
int ctdb_ltdb_store(struct ctdb_context *ctdb, TDB_DATA key, 
		    struct ctdb_ltdb_header *header, TDB_DATA data)
{
	TDB_DATA rec;
	int ret;

	rec.dsize = sizeof(*header) + data.dsize;
	rec.dptr = talloc_size(ctdb, rec.dsize);
	CTDB_NO_MEMORY(ctdb, rec.dptr);

	memcpy(rec.dptr, header, sizeof(*header));
	memcpy(rec.dptr + sizeof(*header), data.dptr, data.dsize);

	ret = tdb_store(ctdb->ltdb, key, rec, TDB_REPLACE);
	talloc_free(rec.dptr);

	return ret;
}
