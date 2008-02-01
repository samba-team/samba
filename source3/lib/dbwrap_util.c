/* 
   Unix SMB/CIFS implementation.
   Utility functions for the dbwrap API
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

int32_t dbwrap_fetch_int32(struct db_context *db, const char *keystr)
{
	TDB_DATA dbuf;
	int32 ret;

	if (db->fetch(db, NULL, string_term_tdb_data(keystr), &dbuf) != 0) {
		return -1;
	}

	if ((dbuf.dptr == NULL) || (dbuf.dsize != sizeof(int32_t))) {
		TALLOC_FREE(dbuf.dptr);
		return -1;
	}

	ret = IVAL(dbuf.dptr, 0);
	TALLOC_FREE(dbuf.dptr);
	return ret;
}

int dbwrap_store_int32(struct db_context *db, const char *keystr, int32_t v)
{
	struct db_record *rec;
	int32 v_store;
	NTSTATUS status;

	rec = db->fetch_locked(db, NULL, string_term_tdb_data(keystr));
	if (rec == NULL) {
		return -1;
	}

	SIVAL(&v_store, 0, v);

	status = rec->store(rec, make_tdb_data((const uint8 *)&v_store,
					       sizeof(v_store)),
			    TDB_REPLACE);
	TALLOC_FREE(rec);
	return NT_STATUS_IS_OK(status) ? 0 : -1;
}

uint32_t dbwrap_change_uint32_atomic(struct db_context *db, const char *keystr,
				     uint32_t *oldval, uint32_t change_val)
{
	struct db_record *rec;
	uint32 val = -1;
	TDB_DATA data;

	if (!(rec = db->fetch_locked(db, NULL,
				     string_term_tdb_data(keystr)))) {
		return -1;
	}

	if ((rec->value.dptr != NULL)
	    && (rec->value.dsize == sizeof(val))) {
		val = IVAL(rec->value.dptr, 0);
	}

	val += change_val;

	data.dsize = sizeof(val);
	data.dptr = (uint8 *)&val;

	rec->store(rec, data, TDB_REPLACE);

	TALLOC_FREE(rec);

	return 0;
}

