/*
   Unix SMB/CIFS implementation.

   handle removal of deleted objects

   Copyright (C) 2009 Andrew Tridgell

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
#include "param/param.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"


NTSTATUS dsdb_garbage_collect_tombstones(TALLOC_CTX *mem_ctx,
					 struct ldb_context *samdb,
					 struct dsdb_ldb_dn_list_node *part,
					 time_t current_time,
					 uint32_t tombstoneLifetime,
					 unsigned int *num_objects_removed,
					 unsigned int *num_links_removed,
					 char **error_string);
