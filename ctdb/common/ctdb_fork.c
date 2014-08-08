/* 
   functions to track and manage processes

   Copyright (C) Ronnie Sahlberg 2012

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/wait.h"
#include "../include/ctdb_client.h"
#include "../include/ctdb_private.h"
#include "../common/rb_tree.h"

void ctdb_set_child_info(TALLOC_CTX *mem_ctx, const char *child_name_fmt, ...)
{
	if (child_name_fmt != NULL) {
		va_list ap;
		char *t;

		va_start(ap, child_name_fmt);
		t = talloc_vasprintf(mem_ctx, child_name_fmt, ap);
		debug_extra = talloc_asprintf(mem_ctx, "%s:", t);
		talloc_free(t);
		va_end(ap);
	}
}

void ctdb_track_child(struct ctdb_context *ctdb, pid_t pid)
{
	char *process;

	/* Only CTDB main daemon should track child processes */
	if (getpid() != ctdb->ctdbd_pid) {
		return;
	}

	process = talloc_asprintf(ctdb->child_processes, "process:%d", (int)pid);
	trbt_insert32(ctdb->child_processes, pid, process);
}

/*
 * This function forks a child process and drops the realtime 
 * scheduler for the child process.
 */
pid_t ctdb_fork(struct ctdb_context *ctdb)
{
	pid_t pid;

	pid = fork();
	if (pid == -1) {
		return -1;
	}
	if (pid == 0) {
		ctdb_set_child_info(ctdb, NULL);

		/* Close the Unix Domain socket and the TCP socket.
		 * This ensures that none of the child processes will
		 * look like the main daemon when it is not running.
		 * tevent needs to be stopped before closing sockets.
		 */
		if (ctdb->ev != NULL) {
			talloc_free(ctdb->ev);
			ctdb->ev = NULL;
		}
		if (ctdb->daemon.sd != -1) {
			close(ctdb->daemon.sd);
			ctdb->daemon.sd = -1;
		}
		if (ctdb->methods != NULL) {
			ctdb->methods->shutdown(ctdb);
		}

		/* The child does not need to be realtime */
		if (ctdb->do_setsched) {
			reset_scheduler();
		}
		ctdb->can_send_controls = false;

		return 0;
	}

	ctdb_track_child(ctdb, pid);
	return pid;
}

static void ctdb_sigchld_handler(struct tevent_context *ev,
	struct tevent_signal *te, int signum, int count,
	void *dont_care, 
	void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);
	int status;
	pid_t pid = -1;

	while (pid != 0) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid == -1) {
			DEBUG(DEBUG_ERR, (__location__ " waitpid() returned error. errno:%d\n", errno));
			return;
		}
		if (pid > 0) {
			char *process;

			if (getpid() != ctdb->ctdbd_pid) {
				continue;
			}

			process = trbt_lookup32(ctdb->child_processes, pid);
			if (process == NULL) {
				DEBUG(DEBUG_ERR,("Got SIGCHLD from pid:%d we didn not spawn with ctdb_fork\n", pid));
			}

			DEBUG(DEBUG_DEBUG, ("SIGCHLD from %d %s\n", (int)pid, process));
			talloc_free(process);
		}
	}
}


struct tevent_signal *
ctdb_init_sigchld(struct ctdb_context *ctdb)
{
	struct tevent_signal *se;

	ctdb->child_processes = trbt_create(ctdb, 0);

	se = tevent_add_signal(ctdb->ev, ctdb, SIGCHLD, 0, ctdb_sigchld_handler, ctdb);
	return se;
}

int
ctdb_kill(struct ctdb_context *ctdb, pid_t pid, int signum)
{
	char *process;

	if (signum == 0) {
		return kill(pid, signum);
	}

	if (getpid() != ctdb->ctdbd_pid) {
		return kill(pid, signum);
	}

	process = trbt_lookup32(ctdb->child_processes, pid);
	if (process == NULL) {
		DEBUG(DEBUG_ERR,("ctdb_kill: trying to kill(%d, %d) a process that does not exist\n", pid, signum));
		return 0;
	}

	return kill(pid, signum);
}
