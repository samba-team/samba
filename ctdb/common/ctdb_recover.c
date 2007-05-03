/* 
   ctdb_control protocol code

   Copyright (C) Andrew Tridgell  2007
   Copyright (C) Ronnie Sahlberg  2007

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#include "includes.h"
#include "lib/events/events.h"
#include "lib/tdb/include/tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "../include/ctdb_private.h"
#include "lib/util/dlinklist.h"
#include "db_wrap.h"

int 
ctdb_control_getvnnmap(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata)
{
	CHECK_CONTROL_DATA_SIZE(0);

	outdata->dsize = offsetof(struct ctdb_vnn_map, map) + 4*ctdb->vnn_map->size;
	outdata->dptr  = (unsigned char *)ctdb->vnn_map;

	return 0;
}

int 
ctdb_control_setvnnmap(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata)
{
	if (ctdb->vnn_map) {
		talloc_free(ctdb->vnn_map);
		ctdb->vnn_map = NULL;
	}

	ctdb->vnn_map = (struct ctdb_vnn_map *)talloc_memdup(ctdb, indata.dptr, indata.dsize);

	return 0;
}

