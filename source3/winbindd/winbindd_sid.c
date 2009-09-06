/* 
   Unix SMB/CIFS implementation.

   Winbind daemon - sid related functions

   Copyright (C) Tim Potter 2000
   
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
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

static void set_hwm_recv(void *private_data, bool success)
{
	struct winbindd_cli_state *state =
		talloc_get_type_abort(private_data, struct winbindd_cli_state);

	if (!success) {
		DEBUG(5, ("Could not set sid mapping\n"));
		request_error(state);
		return;
	}

	request_ok(state);
}

void winbindd_set_hwm(struct winbindd_cli_state *state)
{
	struct unixid xid;

	DEBUG(3, ("[%5lu]: set hwm\n", (unsigned long)state->pid));

	if ( ! state->privileged) {
		DEBUG(0, ("Only root is allowed to set mappings!\n"));
		request_error(state);
		return;
	}

	xid.id = state->request->data.dual_idmapset.id;
	xid.type = state->request->data.dual_idmapset.type;

	winbindd_set_hwm_async(state->mem_ctx, &xid, set_hwm_recv, state);
}
