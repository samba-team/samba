/* 
   Unix SMB/CIFS implementation.

   process model: process (1 process handles all client connections)

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) James J Myers 2003 <myersjj@samba.org>
   Copyright (C) Stefan (metze) Metzmacher 2004
   
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
#include "events.h"
#include "dlinklist.h"
#include "smb_server/smb_server.h"


/*
  called when the process model is selected
*/
static void single_model_init(struct event_context *ev)
{
}

/*
  called when a listening socket becomes readable. 
*/
static void single_accept_connection(struct event_context *ev, 
				     struct socket_context *sock,
				     void (*new_conn)(struct event_context *, struct socket_context *, 
						      uint32_t , void *), 
				     void *private)
{
	NTSTATUS status;
	struct socket_context *sock2;

	/* accept an incoming connection. */
	status = socket_accept(sock, &sock2);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("accept_connection_single: accept: %s\n", nt_errstr(status)));
		return;
	}

	talloc_steal(private, sock);

	new_conn(ev, sock2, socket_get_fd(sock), private);
}


/* called when a connection goes down */
static void single_terminate_connection(struct event_context *ev, const char *reason) 
{
}

static const struct model_ops single_ops = {
	.name			= "single",
	.model_init		= single_model_init,
	.accept_connection	= single_accept_connection,
	.terminate_connection	= single_terminate_connection,
};

/*
  initialise the single process model, registering ourselves with the
  process model subsystem
 */
NTSTATUS process_model_single_init(void)
{
	return register_process_model(&single_ops);
}
