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
	struct dual_list *next;
	char *data;
	int length;
	int offset;
};

static struct dual_list *dual_list;
static struct dual_list *dual_list_end;

/*
  setup a select() including the dual daemon pipe
 */
int dual_select_setup(fd_set *fds, int maxfd)
{
	if (dual_daemon_pipe == -1 ||
	    !dual_list) {
		return maxfd;
	}

	FD_SET(dual_daemon_pipe, fds);
	if (dual_daemon_pipe > maxfd) {
		maxfd = dual_daemon_pipe;
	}
	return maxfd;
}


/*
  a hook called from the main winbindd select() loop to handle writes
  to the dual daemon pipe 
*/
void dual_select(fd_set *fds)
{
	int n;

	if (dual_daemon_pipe == -1 ||
	    !dual_list ||
	    !FD_ISSET(dual_daemon_pipe, fds)) {
		return;
	}

	n = sys_write(dual_daemon_pipe, 
		  &dual_list->data[dual_list->offset],
		  dual_list->length - dual_list->offset);

	if (n <= 0) {
		/* the pipe is dead! fall back to normal operation */
		dual_daemon_pipe = -1;
		return;
	}

	dual_list->offset += n;

	if (dual_list->offset == dual_list->length) {
		struct dual_list *next;
		next = dual_list->next;
		free(dual_list->data);
		free(dual_list);
		dual_list = next;
		if (!dual_list) {
			dual_list_end = NULL;
		}
	}
}

/* 
   send a request to the background daemon 
   this is called for stale cached entries
*/
void dual_send_request(struct winbindd_cli_state *state)
{
	struct dual_list *list;

	if (!background_process) return;

	list = malloc(sizeof(*list));
	if (!list) return;

	list->next = NULL;
	list->data = memdup(&state->request, sizeof(state->request));
	list->length = sizeof(state->request);
	list->offset = 0;
	
	if (!dual_list_end) {
		dual_list = list;
		dual_list_end = list;
	} else {
		dual_list_end->next = list;
		dual_list_end = list;
	}

	background_process = False;
}


/* 
the main dual daemon 
*/
void do_dual_daemon(void)
{
	int fdpair[2];
	struct winbindd_cli_state state;
	
	if (pipe(fdpair) != 0) {
		return;
	}

	ZERO_STRUCT(state);
	state.pid = getpid();

	dual_daemon_pipe = fdpair[1];
	state.sock = fdpair[0];

	if (fork() != 0) {
		close(fdpair[0]);
		return;
	}
	close(fdpair[1]);

	/* tdb needs special fork handling */
	if (tdb_reopen_all() == -1) {
		DEBUG(0,("tdb_reopen_all failed.\n"));
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
			SAFE_FREE(state.response.extra_data);

			free_getent_state(state.getpwent_state);
			free_getent_state(state.getgrent_state);
			state.getpwent_state = NULL;
			state.getgrent_state = NULL;
		}
	}
}

