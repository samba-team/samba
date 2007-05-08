/* 
   Unix SMB/CIFS implementation.
   Low-level connections.tdb access functions
   Copyright (C) Volker Lendecke 2007
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

TDB_CONTEXT *conn_tdb_ctx(BOOL rw)
{
	static TDB_CONTEXT *tdb;

	if (tdb != NULL) {
		return tdb;
	}

	if (rw) {
		tdb = tdb_open_log(lock_path("connections.tdb"), 0,
				   TDB_CLEAR_IF_FIRST|TDB_DEFAULT, 
				   O_RDWR | O_CREAT, 0644);
	}
	else {
		tdb = tdb_open_log(lock_path("connections.tdb"), 0,
				   TDB_DEFAULT, O_RDONLY, 0);
	}

	if (tdb == NULL) {
		DEBUG(0, ("Could not open connections.tdb: %s\n",
			  strerror(errno)));
	}

	return tdb;
}

struct conn_traverse_state {
	int (*fn)(TDB_CONTEXT *tdb,
		  const struct connections_key *key,
		  const struct connections_data *data,
		  void *private_data);
	void *private_data;
};

static int conn_traverse_fn(TDB_CONTEXT *tdb, TDB_DATA key,
			    TDB_DATA data, void *private_data)
{
	struct conn_traverse_state *state =
		(struct conn_traverse_state *)private_data;

	if ((key.dsize != sizeof(struct connections_key))
	    || (data.dsize != sizeof(struct connections_data))) {
		return 0;
	}

	return state->fn(
		tdb, (const struct connections_key *)key.dptr,
		(const struct connections_data *)data.dptr,
		state->private_data);
}

int connections_traverse(int (*fn)(TDB_CONTEXT *tdb, TDB_DATA key,
				   TDB_DATA data, void *private_data),
			 void *private_data)
{
	TDB_CONTEXT *tdb = conn_tdb_ctx(True);

	if (tdb == NULL) {
		DEBUG(5, ("Could not open connections.tdb r/w, trying r/o\n"));
		tdb = conn_tdb_ctx(False);
	}

	if (tdb == NULL) {
		return -1;
	}

	return tdb_traverse(tdb, fn, private_data);
}

int connections_forall(int (*fn)(TDB_CONTEXT *tdb,
				 const struct connections_key *key,
				 const struct connections_data *data,
				 void *private_data),
		       void *private_data)
{
	struct conn_traverse_state state;

	state.fn = fn;
	state.private_data = private_data;

	return connections_traverse(conn_traverse_fn, (void *)&state);
}

BOOL connections_init(BOOL rw)
{
	return (conn_tdb_ctx(rw) != NULL);
}
