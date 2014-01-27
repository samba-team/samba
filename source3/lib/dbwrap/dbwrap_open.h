/* 
   Unix SMB/CIFS implementation.
   Database interface wrapper around tdb

   Copyright (C) Volker Lendecke 2005-2007

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

#ifndef __DBWRAP_OPEN_H__
#define __DBWRAP_OPEN_H__

struct db_context;

/**
 * Convenience function to check whether a tdb database
 * is local or clustered (ctdb) in a clustered environment.
 */
bool db_is_local(const char *name);

/**
 * Convenience function that will determine whether to
 * open a tdb database via the tdb backend or via the ctdb
 * backend, based on lp_clustering() and a db-specific
 * settings.
 */
struct db_context *db_open(TALLOC_CTX *mem_ctx,
			   const char *name,
			   int hash_size, int tdb_flags,
			   int open_flags, mode_t mode,
			   enum dbwrap_lock_order lock_order,
			   uint64_t dbwrap_flags);

#endif /* __DBWRAP_OPEN_H__ */
