/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Andrew Tridgell 2003
   
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
#define TEVENT_DEPRECATED 1
#include "lib/events/events.h"

/*
  create a event_context structure. This must be the first events
  call, and all subsequent calls pass this event_context as the first
  element. Event handlers also receive this as their first argument.

  This samba4 specific call sets the samba4 debug handler.
*/
struct tevent_context *s4_event_context_init(TALLOC_CTX *mem_ctx)
{
	struct tevent_context *ev;

	ev = tevent_context_init_byname(mem_ctx, NULL);
	if (ev) {
		samba_tevent_set_debug(ev, "s4_tevent");
		tevent_loop_allow_nesting(ev);
	}
	return ev;
}

