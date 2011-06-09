/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Bartlett 2011

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
#include "librpc/gen_ndr/server_id.h"

char *server_id_str(TALLOC_CTX *mem_ctx, const struct server_id *id)
{
	if (id->vnn == NONCLUSTER_VNN && id->task_id == 0) {
		return talloc_asprintf(mem_ctx,
				       "%llu",
				       (unsigned long long)id->pid);
	} else if (id->vnn == NONCLUSTER_VNN) {
		return talloc_asprintf(mem_ctx,
				       "%llu.%u",
				       (unsigned long long)id->pid,
				       (unsigned)id->task_id);
	} else {
		return talloc_asprintf(mem_ctx,
				       "%u:%llu.%u",
				       (unsigned)id->vnn,
				       (unsigned long long)id->pid,
				       (unsigned)id->task_id);
	}
}
