/* 
   Unix SMB/CIFS implementation.
   Database interface wrapper
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2006

   Major code contributions from Aleksey Fedoseev (fedoseev@ru.ibm.com)
   
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

/*
 * Fall back using fetch_locked if no genuine fetch operation is provided
 */

static int dbwrap_fallback_fetch(struct db_context *db, TALLOC_CTX *mem_ctx,
				 TDB_DATA key, TDB_DATA *data)
{
	struct db_record *rec;

	if (!(rec = db->fetch_locked(db, mem_ctx, key))) {
		return -1;
	}

	data->dsize = rec->value.dsize;
	data->dptr = talloc_move(mem_ctx, &rec->value.dptr);
	TALLOC_FREE(rec);
	return 0;
}

struct db_context *db_open(TALLOC_CTX *mem_ctx,
			   const char *name,
			   int hash_size, int tdb_flags,
			   int open_flags, mode_t mode)
{
	struct db_context *result = NULL;

	if (result == NULL) {
		result = db_open_tdb(mem_ctx, name, hash_size,
				     tdb_flags, open_flags, mode);
	}

	if ((result != NULL) && (result->fetch == NULL)) {
		result->fetch = dbwrap_fallback_fetch;
	}

	return result;
}
