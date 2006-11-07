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
#include "smbd/process_model.h"

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
		DEBUG(0,("single_accept_connection: accept: %s\n", nt_errstr(status)));
		/* this looks strange, but is correct. We need to
		   throttle things until the system clears enough
		   resources to handle this new socket. If we don't
		   then we will spin filling the log and causing more
		   problems. We don't panic as this is probably a
		   temporary resource constraint */
		sleep(1);
		return;
	}

	talloc_steal(private, sock);

	new_conn(ev, sock2, socket_get_fd(sock2), private);
}

/*
  called to startup a new task
*/
static void single_new_task(struct event_context *ev, 
			    void (*new_task)(struct event_context *, uint32_t, void *), 
			    void *private)
{
	static uint32_t taskid = 0x10000000;
	new_task(ev, taskid++, private);
}


/* called when a task goes down */
static void single_terminate(struct event_context *ev, const char *reason) 
{
	DEBUG(2,("single_terminate: reason[%s]\n",reason));
}

/* called to set a title of a task or connection */
static void single_set_title(struct event_context *ev, const char *title) 
{
}

static const struct model_ops single_ops = {
	.name			= "single",
	.model_init		= single_model_init,
	.new_task               = single_new_task,
	.accept_connection	= single_accept_connection,
	.terminate              = single_terminate,
	.set_title		= single_set_title,
};

/*
  initialise the single process model, registering ourselves with the
  process model subsystem
 */
NTSTATUS process_model_single_init(void)
{
	return register_process_model(&single_ops);
}
