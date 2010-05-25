#ifndef _LIBCTDB_LOCAL_TDB_H
#define _LIBCTDB_LOCAL_TDB_H

struct ctdb_ltdb_header *ctdb_local_fetch(struct tdb_context *tdb,
					  TDB_DATA key, TDB_DATA *data);

int ctdb_local_store(struct tdb_context *tdb, TDB_DATA key,
		     struct ctdb_ltdb_header *header, TDB_DATA data);

#endif /* _LIBCTDB_LOCAL_TDB_H */
