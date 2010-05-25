/*
   libctdb local tdb access code

   Copyright (C) Andrew Tridgell  2006
   Copyright (C) Rusty Russell  2010

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

#include <ctdb.h>
#include <tdb.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctdb_protocol.h> // For struct ctdb_ltdb_header
#include "local_tdb.h"

/*
  fetch a record from the ltdb, separating out the header information
  and returning the body of the record.  The caller should free() the
  header when done, rather than the (optional) data->dptr.
*/
struct ctdb_ltdb_header *ctdb_local_fetch(struct tdb_context *tdb,
					  TDB_DATA key, TDB_DATA *data)
{
	TDB_DATA rec;

	rec = tdb_fetch(tdb, key);
	if (rec.dsize < sizeof(struct ctdb_ltdb_header)) {
		free(rec.dptr);
		return NULL;
	}

	if (data) {
		data->dsize = rec.dsize - sizeof(struct ctdb_ltdb_header);
		data->dptr = rec.dptr + sizeof(struct ctdb_ltdb_header);
	}
	return (struct ctdb_ltdb_header *)rec.dptr;
}


/*
  write a record to a normal database
*/
int ctdb_local_store(struct tdb_context *tdb, TDB_DATA key,
		     struct ctdb_ltdb_header *header, TDB_DATA data)
{
	TDB_DATA rec;
	int ret;
	bool seqnum_suppressed = false;

	rec.dsize = sizeof(*header) + data.dsize;
	rec.dptr = malloc(rec.dsize);
	if (!rec.dptr) {
		return -1;
	}

	memcpy(rec.dptr, header, sizeof(*header));
	memcpy(rec.dptr + sizeof(*header), data.dptr, data.dsize);

	/* Databases with seqnum updates enabled only get their seqnum
	   changes when/if we modify the data */
	if (tdb_get_flags(tdb) & TDB_SEQNUM) {
		TDB_DATA old;
		old = tdb_fetch(tdb, key);

		if ( (old.dsize == rec.dsize)
		&& !memcmp(old.dptr+sizeof(struct ctdb_ltdb_header),
			  rec.dptr+sizeof(struct ctdb_ltdb_header),
			  rec.dsize-sizeof(struct ctdb_ltdb_header)) ) {
			tdb_remove_flags(tdb, TDB_SEQNUM);
			seqnum_suppressed = true;
		}
		free(old.dptr);
	}
	ret = tdb_store(tdb, key, rec, TDB_REPLACE);
	if (seqnum_suppressed) {
		tdb_add_flags(tdb, TDB_SEQNUM);
	}
	free(rec.dptr);

	return ret;
}
