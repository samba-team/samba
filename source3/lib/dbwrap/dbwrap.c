/* 
   Unix SMB/CIFS implementation.
   Database interface wrapper
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2006

   Major code contributions from Aleksey Fedoseev (fedoseev@ru.ibm.com)
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_private.h"

/*
 * Fall back using fetch_locked if no genuine fetch operation is provided
 */

int dbwrap_fallback_fetch(struct db_context *db, TALLOC_CTX *mem_ctx,
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

/*
 * Fall back using fetch if no genuine parse operation is provided
 */

int dbwrap_fallback_parse_record(struct db_context *db, TDB_DATA key,
				 int (*parser)(TDB_DATA key,
					       TDB_DATA data,
					       void *private_data),
				 void *private_data)
{
	TDB_DATA data;
	int res;

	res = db->fetch(db, talloc_tos(), key, &data);
	if (res != 0) {
		return res;
	}

	res = parser(key, data, private_data);
	TALLOC_FREE(data.dptr);
	return res;
}
