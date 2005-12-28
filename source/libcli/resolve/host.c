/* 
   Unix SMB/CIFS implementation.

   async gethostbyname() name resolution module

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
  this module uses a fork() per gethostbyname() call. At first that
  might seem crazy, but it is actually very fast, and solves many of
  the tricky problems of keeping a child hanging around in a library
  (like what happens when the parent forks). We use a talloc
  destructor to ensure that the child is cleaned up when we have
  finished with this name resolution.
*/

#include "includes.h"
#include "lib/events/events.h"
#include "system/network.h"
#include "system/filesys.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"
#include "libcli/nbt/libnbt.h"

struct host_state {
	struct nbt_name name;
	const char *reply_addr;
	pid_t child;
	int child_fd;
	struct fd_event *fde;
	struct event_context *event_ctx;
};


/*
  kill off a wayward child if needed. This allows us to stop an async
  name resolution without leaving a potentially blocking call running
  in a child
*/
static int host_destructor(void *ptr)
{
	struct host_state *state = talloc_get_type(ptr, struct host_state);
	close(state->child_fd);
	if (state->child != (pid_t)-1) {
		kill(state->child, SIGTERM);
	}
	return 0;
}

/*
  the blocking child
*/
static void run_child(struct composite_context *c, int fd)
{
	struct host_state *state = talloc_get_type(c->private_data, struct host_state);
	struct ipv4_addr ip;
	const char *address;

	/* this is the blocking call we are going to lots of trouble
	   to avoid in the parent */
	ip = interpret_addr2(state->name.name);

	address = sys_inet_ntoa(ip);
	if (address != NULL) {
		write(fd, address, strlen(address)+1);
	}
}

/*
  handle a read event on the pipe
*/
static void pipe_handler(struct event_context *ev, struct fd_event *fde, 
			 uint16_t flags, void *private_data)
{
	struct composite_context *c = talloc_get_type(private_data, struct composite_context);
	struct host_state *state = talloc_get_type(c->private_data, struct host_state);
	char address[128];
	int ret;

	/* if we get any event from the child then we know that we
	   won't need to kill it off */
	state->child = (pid_t)-1;

	/* yes, we don't care about EAGAIN or other niceities
	   here. They just can't happen with this parent/child
	   relationship, and even if they did then giving an error is
	   the right thing to do */
	ret = read(state->child_fd, address, sizeof(address)-1);
	if (ret <= 0) goto failed;

	/* enusre the address looks good */
	address[ret] = 0;
	if (strcmp(address, "0.0.0.0") == 0 ||
	    inet_addr(address) == INADDR_NONE) {
		goto failed;
	}

	state->reply_addr = talloc_strdup(state, address);
	if (state->reply_addr == NULL) goto failed;

	c->status = NT_STATUS_OK;
	c->state = COMPOSITE_STATE_DONE;
	if (c->async.fn) {
		c->async.fn(c);
	}
	return;

failed:
	c->status = NT_STATUS_BAD_NETWORK_NAME;
	c->state = COMPOSITE_STATE_ERROR;
	if (c->async.fn) {
		c->async.fn(c);
	}
}

/*
  gethostbyname name resolution method - async send
 */
struct composite_context *resolve_name_host_send(struct nbt_name *name, 
						struct event_context *event_ctx)
{
	struct composite_context *c;
	struct host_state *state;
	NTSTATUS status;
	int fd[2] = { -1, -1 };
	int ret;

	c = talloc_zero(NULL, struct composite_context);
	if (c == NULL) goto failed;

	state = talloc(c, struct host_state);
	if (state == NULL) goto failed;

	status = nbt_name_dup(state, name, &state->name);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = state;
	c->event_ctx = talloc_reference(c, event_ctx);

	/* setup a pipe to chat to our child */
	ret = pipe(fd);
	if (ret == -1) goto failed;

	state->child_fd = fd[0];
	state->event_ctx = c->event_ctx;

	/* we need to put the child in our event context so
	   we know when the gethostbyname() has finished */
	state->fde = event_add_fd(c->event_ctx, c, state->child_fd, EVENT_FD_READ, 
				  pipe_handler, c);
	if (state->fde == NULL) {
		close(fd[0]);
		close(fd[1]);
		goto failed;
	}

	/* signal handling in posix really sucks - doing this in a library
	   affects the whole app, but what else to do?? */
	signal(SIGCHLD, SIG_IGN);

	state->child = fork();
	if (state->child == (pid_t)-1) {
		goto failed;
	}

	if (state->child == 0) {
		close(fd[0]);
		run_child(c, fd[1]);
		_exit(0);
	}
	close(fd[1]);

	/* cleanup wayward children */
	talloc_set_destructor(state, host_destructor);

	return c;	

failed:
	talloc_free(c);
	return NULL;
}

/*
  gethostbyname name resolution method - recv side
*/
NTSTATUS resolve_name_host_recv(struct composite_context *c, 
				 TALLOC_CTX *mem_ctx, const char **reply_addr)
{
	NTSTATUS status;

	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status)) {
		struct host_state *state = talloc_get_type(c->private_data, struct host_state);
		*reply_addr = talloc_steal(mem_ctx, state->reply_addr);
	}

	talloc_free(c);
	return status;
}

/*
  gethostbyname name resolution method - sync call
 */
NTSTATUS resolve_name_host(struct nbt_name *name, 
			    TALLOC_CTX *mem_ctx,
			    const char **reply_addr)
{
	struct composite_context *c = resolve_name_host_send(name, NULL);
	return resolve_name_host_recv(c, mem_ctx, reply_addr);
}

