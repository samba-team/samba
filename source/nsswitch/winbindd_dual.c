/* 
   Unix SMB/CIFS implementation.

   Winbind background daemon

   Copyright (C) Andrew Tridgell 2002
   Copyright (C) Volker Lendecke 2004
   
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

static struct winbindd_cli_state child_state;

static void msg_forget_state(int msg_type, pid_t src, void *buf, size_t len)
{
	free_getent_state(child_state.getpwent_state);
	child_state.getpwent_state = NULL;
	child_state.getpwent_initialized = False;

	free_getent_state(child_state.getgrent_state);
	child_state.getgrent_state = NULL;
	child_state.getgrent_initialized = False;
}

/* Handle the signal by unlinking socket and exiting */

static void terminate(void)
{
	idmap_close();
	exit(0);
}

static BOOL do_sigterm = False;

static void termination_handler(int signum)
{
	do_sigterm = True;
	sys_select_signal();
}

/* 
the main dual daemon 
*/
static BOOL do_dual_daemon(struct winbindd_child *child)
{
	int fdpair[2];
	
	if (pipe(fdpair) != 0) {
		return False;
	}

	ZERO_STRUCT(child_state);
	child_state.pid = getpid();

	child->fd = fdpair[1];
	child_state.sock = fdpair[0];

	child->pid = sys_fork();

	if (child->pid != 0) {
		close(fdpair[0]);
		return True;
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

	CatchSignal(SIGTERM, termination_handler);

	message_register(MSG_WINBIND_FORGET_STATE, msg_forget_state);

	opt_dual_daemon = False;

	while (1) {
		int selret;
		fd_set r_fds;

		/* free up any talloc memory */
		lp_talloc_free();
		main_loop_talloc_free();

		message_dispatch();

		FD_ZERO(&r_fds);
		FD_SET(child_state.sock, &r_fds);

		selret = sys_select(child_state.sock+1, &r_fds, NULL, NULL,
				    NULL);

		if (selret == 0)
			continue;

		if ((selret == -1) && (errno != EINTR))
			exit(1);

		if (FD_ISSET(child_state.sock, &r_fds)) 
			winbind_client_read(&child_state);

		if (child_state.finished) {
			/* we lost contact with our parent */
			exit(0);
		}

		/* process full rquests */
		if (child_state.read_buf_len == sizeof(child_state.request)) {
			DEBUG(4,("dual daemon request %d\n",
				 (int)child_state.request.cmd));

			if (child_state.request.flags & WBFLAG_IS_PRIVILEGED)
				child_state.privileged = True;

			winbind_process_packet(&child_state);

			child_state.privileged = False;

			cache_store_response(getpid(), &child_state.response);

			message_send_pid(getppid(), MSG_WINBIND_FINISHED,
					 &child_state.request.msgid,
					 sizeof(child_state.request.msgid),
					 True);

			SAFE_FREE(child_state.response.extra_data);
		}

		if (do_sigterm)
			terminate();
	}
}

static int num_idle_children = 0;
static int num_winbind_children = 0;
static struct winbindd_child *winbindd_children;
static struct winbindd_child *retired_children;

static struct winbindd_child *netlogon_child;

static BOOL netlogon_child_busy(void)
{
	return ((netlogon_child != NULL) &&
		(winbindd_children != netlogon_child) &&
		(netlogon_child->prev == NULL) &&
		(netlogon_child->next == NULL));
}

struct winbindd_child *claim_child(BOOL need_netlogon_child)
{
	struct winbindd_child *child;

	if (num_winbind_children >= WINBINDD_MAX_SIMULTANEOUS_CLIENTS) {
		DEBUG(0, ("More children than MAX_SIMULTANEOUS_CLIENTS\n"));
		return NULL;
	}

	if (need_netlogon_child) {

		if (netlogon_child_busy())
			return NULL;

		child = netlogon_child;
	} else {
		child = winbindd_children;

		if ((child != NULL) && (child == netlogon_child))
			child = child->next;
	}

	if (child != NULL) {
		DLIST_REMOVE(winbindd_children, child);
		DEBUG(10, ("Fetching existing child %d\n", child->pid));
		num_idle_children -= 1;
		return child;
	}

	child = malloc(sizeof(*winbindd_children));
	ZERO_STRUCTP(child);

	if (!do_dual_daemon(child)) {
		SAFE_FREE(child);
		return False;
	}

	num_winbind_children += 1;

	if (need_netlogon_child)
		netlogon_child = child;

	DEBUG(10, ("Created new child, now got %d children\n",
		   num_winbind_children));

	return child;
}

void release_child(struct winbindd_child *child)
{
	if (num_idle_children >= lp_winbind_max_idle_children()) {
		close(child->fd);
		child->fd = -1;

		/* Under my Linux 2.4 box the read() system call on a pipe
		 * sometimes does not return if the other end is closed. Is
		 * that standard? Anyway, kill the child */

		kill(child->pid, SIGTERM);

		DLIST_ADD(retired_children, child);
		return;
	}

	DLIST_ADD(winbindd_children, child);
	num_idle_children += 1;
	return;
}

static void busy_child_died(struct winbindd_child *child)
{
	if (child->fd >= 0)
		close(child->fd);
	num_winbind_children -= 1;
	if (child == netlogon_child)
		netlogon_child = NULL;
	SAFE_FREE(child);
	DEBUG(10, ("Now got %d children\n", num_winbind_children));
}

void idle_child_died(pid_t pid)
{
	struct winbindd_child *child;

	DEBUG(10, ("Child %d died\n", pid));

	for (child = winbindd_children; child != NULL; child = child->next) {
		/* If it's in the idle list, remove it */
		if (child->pid == pid) {
			num_idle_children -= 1;
			DLIST_REMOVE(winbindd_children, child);
			break;
		}
	}

	if (child == NULL) {
		/* Maybe it's retired */
		for (child = retired_children; child != NULL;
		     child = child->next) {
			/* If it's in the idle list, remove it */
			if (child->pid == pid) {
				DLIST_REMOVE(retired_children, child);
				break;
			}
		}
	}

	if (child == NULL) {
		DEBUG(0, ("Could not find child %d\n", pid));
		return;
	}

	busy_child_died(child);
}

void child_write(struct winbindd_cli_state *state)
{
	char *data;
	int written;

	if (state->child->pid == 0) {
		busy_child_died(state->child);
		state->child = NULL;
		/* Child process died. Report this sad event to the client */
		state->finished = True;
		return;
	}

	data = ((char *)&state->request) + sizeof(struct winbindd_request) -
		state->child->to_write;

	if (state->privileged)
		state->request.flags |= WBFLAG_IS_PRIVILEGED;

	written = write(state->child->fd, data, state->child->to_write);

	state->request.flags &= ~WBFLAG_IS_PRIVILEGED;

	if (written < 0) {
		state->finished = True;
		return;
	}

	state->child->to_write -= written;

	return;
}

BOOL init_children(void)
{
	winbindd_children = NULL;
	retired_children = NULL;
	netlogon_child = NULL;
	return True;
}
