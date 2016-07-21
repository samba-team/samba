/*
   Unix SMB/CIFS implementation.
   Implementation of reliable cleanup events
   Copyright (C) Ralph Boehme 2016

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
#include "system/filesys.h"
#include "util_tdb.h"
#include "lib/tdb_wrap/tdb_wrap.h"

bool cleanupdb_store_child(const pid_t pid, const bool unclean);
bool cleanupdb_delete_child(const pid_t pid);
int cleanupdb_traverse_read(int (*fn)(const pid_t pid,
				      const bool cleanup,
				      void *private_data),
			    void *private_data);
