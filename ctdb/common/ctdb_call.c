/* 
   ctdb_call protocol code

   Copyright (C) Andrew Tridgell  2006

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
#include "system/network.h"
#include "system/filesys.h"
#include "ctdb_private.h"


/*
  local version of ctdb_call
*/
static int ctdb_call_local(struct ctdb_context *ctdb, TDB_DATA key, int call_id, 
			   TDB_DATA *call_data, TDB_DATA *reply_data)
{
	return -1;
}

/*
  make a remote ctdb call
*/
int ctdb_call(struct ctdb_context *ctdb, TDB_DATA key, int call_id, 
	      TDB_DATA *call_data, TDB_DATA *reply_data)
{
	uint32_t dest;

	dest = ctdb_hash(&key) % ctdb->num_nodes;
	if (dest == ctdb->vnn) {
		return ctdb_call_local(ctdb, key, call_id, call_data, reply_data);
	}

	
	return -1;
}

