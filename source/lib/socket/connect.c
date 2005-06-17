/* 
   Unix SMB/CIFS implementation.

   implements a non-blocking connect operation that is aware of the samba4 events
   system

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

#include "includes.h"
#include "lib/socket/socket.h"
#include "lib/events/events.h"


/*
  handle write events on connect completion
*/
static void socket_connect_handler(struct event_context *ev, struct fd_event *fde, 
				   uint16_t flags, void *private)
{
	NTSTATUS *status = (NTSTATUS *)private;
	*status = NT_STATUS_OK;
}


/*
  just like socket_connect() but other events can happen while the
  connect is ongoing. This isn't as good as making the calling code
  fully async during its connect phase, but at least it means that any
  calling code that uses this won't interfere with code that is
  properly async
 */
NTSTATUS socket_connect_ev(struct socket_context *sock,
			   const char *my_address, int my_port,
			   const char *server_address, int server_port,
			   uint32_t flags, struct event_context *ev)
{
	TALLOC_CTX *tmp_ctx = talloc_new(sock);
	NTSTATUS status;
	
	set_blocking(socket_get_fd(sock), False);

	status = socket_connect(sock, my_address, my_port, 
				server_address, server_port, flags);
	if (NT_STATUS_IS_ERR(status) && 
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		return status;
	}

	event_add_fd(ev, tmp_ctx, socket_get_fd(sock), EVENT_FD_WRITE, 
		     socket_connect_handler, &status);

	while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
		if (event_loop_once(ev) != 0) {
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	status = socket_connect_complete(sock, flags);

	talloc_free(tmp_ctx);
	return status;
}
