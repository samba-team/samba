/* 
   Unix SMB/CIFS implementation.

   Winbind background daemon

   Copyright (C) Andrew Tridgell 2002
   
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
  the idea of the optional dual daemon mode is ot prevent slow domain
  responses from clagging up the rest of the system. When in dual
  daemon mode winbindd always responds to requests from cache if the
  request is in cache, and if the cached answer is stale then it asks
  the "dual daemon" to update the cache for that request

 */

#include "includes.h"
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

extern BOOL opt_dual_daemon;
BOOL background_process = False;
int dual_daemon_pipe = -1;


/* a list of requests ready to be sent to the dual daemon */
struct dual_list {
	struct dual_list *next, *prev;
	char *data;
	int length;
};

struct dual_child {
	struct dual_child *next, *prev;
	BOOL busy;
	pid_t pid;
	int fd;
	char *data;
	int length;
	int offset;
};

static struct dual_child *child_list;

static struct dual_list *dual_list;

static BOOL dual_schedule_request(void)
{
	struct dual_child *child;
	int busy_children = 0;

	if (dual_list == NULL)
		return False;

	for (child = child_list; child != NULL; child = child->next) {
		struct dual_list *this;

		if (child->busy) {
			extern int max_busy_children;
			busy_children += 1;
			if (busy_children > max_busy_children)
				max_busy_children = busy_children;
			continue;
		}

		SMB_ASSERT(child->data == NULL);

		DEBUG(10, ("scheduling %d\n",
			   ((struct winbindd_request *)(dual_list->data))->cmd));

		child->data = dual_list->data;
		child->length = dual_list->length;
		child->offset = 0;
		child->busy = True;

		this = dual_list;

		DLIST_REMOVE(dual_list, this);
		free(this);

		return True;
	}
	return False;
}

void dual_finished(pid_t pid)
{
	struct dual_child *child;

	for (child = child_list; child != NULL; child = child->next) {
		if (child->pid == pid) {
			child->busy = False;
			return;
		}
	}
}

/*
  setup a select() including the dual daemon pipe
 */
int dual_select_setup(fd_set *fds, int maxfd)
{
	struct dual_child *child;

	while (dual_schedule_request())
		;

	for (child = child_list; child != NULL; child = child->next) {
		if (child->length == 0)
			continue;

		FD_SET(child->fd, fds);
		if (child->fd > maxfd)
			maxfd = child->fd;
	}

	return maxfd;
}

static void resend_request(char *data, int length)
{
	struct dual_list *req;

	req = malloc(sizeof(*req));
	req->data = data;
	req->length = length;
	DLIST_ADD(dual_list, req);
}

/*
  a hook called from the main winbindd select() loop to handle writes
  to the dual daemon pipe 
*/
void dual_select(fd_set *fds)
{
	int n;
	struct dual_child *child;

	for (child = child_list; child != NULL; child = child->next) {
		if (child->length == 0)
			continue;

		if (!FD_ISSET(child->fd, fds))
			continue;

		n = sys_write(child->fd,
			      &child->data[child->offset],
			      child->length - child->offset);

		if (n <= 0) {
			/* the pipe is dead! */
			resend_request(child->data, child->length);
			child->fd = -1;
			continue;
		}

		child->offset += n;

		if (child->offset < child->length)
			continue;

		/* Data fully sent, discard it */

		SAFE_FREE(child->data);
		child->length = 0;
	}

	/* Remove dead children */
	child = child_list;

	while (child != NULL) {
		struct dual_child *next;
		next = child->next;
		if (child->fd == -1) {
			DLIST_REMOVE(child_list, child);
			free(child);
		}
		child = next;
	}

	if (child_list == NULL) {
		extern BOOL opt_dual_daemon;
		DEBUG(0, ("All children died -- normal operation\n"));
		opt_dual_daemon = False;
	}
}

/* 
   send a request to the background daemon 
   this is called for stale cached entries
*/
void dual_send_request(struct winbindd_cli_state *state)
{
	struct dual_list *req, *tmp;

	if (!background_process) return;

	DEBUG(10, ("dual_send_request: cmd=%d, msgid=%d\n",
		   state->request.cmd, state->request.msgid));

	req = malloc(sizeof(*req));
	if (!req) return;

	req->next = NULL;
	req->data = memdup(&state->request, sizeof(state->request));
	req->length = sizeof(state->request);
	DLIST_ADD_END(dual_list, req, tmp);

	background_process = False;
}


/* 
the main dual daemon 
*/
void do_dual_daemon(void)
{
	int fdpair[2];
	struct winbindd_cli_state state;
	struct dual_child *child;
	
	if (pipe(fdpair) != 0) {
		return;
	}

	ZERO_STRUCT(state);
	state.pid = getpid();

	child = malloc(sizeof(*child));

	if (child == NULL)
		return;

	child->busy = False;
	child->data = NULL;
	child->length = 0;
	child->offset = 0;

	child->fd = fdpair[1];
	state.sock = fdpair[0];
	child->pid = sys_fork();

	DLIST_ADD(child_list, child)

	if (child->pid != 0) {
		close(fdpair[0]);
		return;
	}
	close(fdpair[1]);

	/* tdb needs special fork handling */
	if (tdb_reopen_all() == -1) {
		DEBUG(0,("tdb_reopen_all failed.\n"));
		_exit(0);
	}

	if (!message_init()) {
		DEBUG(0, ("message_init failed\n"));
		_exit(0);
	}
	
	dual_daemon_pipe = -1;
	opt_dual_daemon = False;

	while (1) {
		/* free up any talloc memory */
		lp_talloc_free();
		main_loop_talloc_free();

		/* fetch a request from the main daemon */
		winbind_client_read(&state);

		if (state.finished) {
			/* we lost contact with our parent */
			exit(0);
		}

		/* process full rquests */
		if (state.read_buf_len == sizeof(state.request)) {
			DEBUG(4,("dual daemon request %d\n", (int)state.request.cmd));

			/* special handling for the stateful requests */
			switch (state.request.cmd) {
			case WINBINDD_GETPWENT:
				winbindd_setpwent(&state);
				break;
				
			case WINBINDD_GETGRENT:
			case WINBINDD_GETGRLST:
				winbindd_setgrent(&state);
				break;
			default:
				break;
			}

			winbind_process_packet(&state);

			if (state.request.flags & WBFLAG_CACHE_RESPONSE)
				cache_store_response(getpid(),
						     &state.response);

			message_send_pid(getppid(), MSG_WINBIND_FINISHED,
					 &state.request.msgid,
					 sizeof(state.request.msgid),
					 True);
			SAFE_FREE(state.response.extra_data);

			free_getent_state(state.getpwent_state);
			free_getent_state(state.getgrent_state);
			state.getpwent_state = NULL;
			state.getgrent_state = NULL;
		}
	}
}

