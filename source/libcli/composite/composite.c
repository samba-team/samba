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


