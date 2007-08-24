/* 
   Unix SMB/CIFS implementation.

   database wrapper code

   Copyright (C) Andrew Tridgell 2007
   Copyright (C) Volker Lendecke 2005
   
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
#include "lib/tdb/include/tdb.h"
#include "lib/dbwrap/dbwrap.h"

/*
  open a temporary database
 */
struct db_context *db_tmp_open(TALLOC_CTX *mem_ctx, const char *name, int tdb_flags)
{
	if (lp_parm_bool(-1, "ctdb", "enable", False) &&
	    lp_parm_bool(-1, "ctdb", name, True)) {
		    return db_tmp_open_ctdb(mem_ctx, name, tdb_flags);
	}

	return db_tmp_open_tdb(mem_ctx, name, tdb_flags);
}
