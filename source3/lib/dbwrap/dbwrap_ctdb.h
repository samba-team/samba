/* 
   Unix SMB/CIFS implementation.
   Database interface wrapper around ctdbd
   Copyright (C) Volker Lendecke 2007-2009
   Copyright (C) Michael Adam 2009

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

#ifndef __DBWRAP_CTDB_H__
#define __DBWRAP_CTDB_H__

#include <talloc.h>

#include "dbwrap/dbwrap_private.h"

struct db_context;

struct db_context *db_open_ctdb(TALLOC_CTX *mem_ctx,
				const char *name,
				int hash_size, int tdb_flags,
				int open_flags, mode_t mode,
				enum dbwrap_lock_order lock_order);

#endif /* __DBWRAP_CTDB_H__ */
