/* 
   ctdb ltdb code

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
  attach to a specific database
*/
int ctdb_attach(struct ctdb_context *ctdb, const char *name, int tdb_flags, 
		int open_flags, mode_t mode)
{
	/* when we have a separate daemon this will need to be a real
	   file, not a TDB_INTERNAL, so the parent can access it to
	   for ltdb bypass */
	ctdb->ltdb = tdb_open(name, 0, TDB_INTERNAL, 0, 0);
	if (ctdb->ltdb == NULL) {
		ctdb_set_error(ctdb, "Failed to open tdb %s\n", name);
		return -1;
	}
	return 0;
}
