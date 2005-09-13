/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Tridgell 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/
/*
  composite API helper functions
*/

#include "includes.h"
#include "lib/events/events.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"


/*
  block until a composite function has completed, then return the status
*/
NTSTATUS composite_wait(struct composite_context *c)
{
	if (c == NULL) return NT_STATUS_NO_MEMORY;

	while (c->state < SMBCLI_REQUEST_DONE) {
		if (event_loop_once(c->event_ctx) != 0) {
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	return c->status;
}


/* 
   callback from composite_trigger_done() 
*/
static void composite_trigger(struct event_context *ev, struct timed_event *te,
			      struct timeval t, void *ptr)
{
	struct composite_context *c = talloc_get_type(ptr, struct composite_context);
	c->state = SMBCLI_REQUEST_DONE;
	if (c->async.fn) {
		c->async.fn(c);
	}
}


/*
  trigger an immediate 'done' event on a composite context
  this is used when the composite code works out that the call
  can be completed without waiting for any external event
*/
void composite_trigger_done(struct composite_context *c)
{
	/* a zero timeout means immediate */
	event_add_timed(c->event_ctx, c, timeval_zero(), composite_trigger, c);
}
