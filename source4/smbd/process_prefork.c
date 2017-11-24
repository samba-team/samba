/*
   Unix SMB/CIFS implementation.

   process model: prefork (n client connections per process)

   Copyright (C) Andrew Tridgell 1992-2005
   Copyright (C) James J Myers 2003 <myersjj@samba.org>
   Copyright (C) Stefan (metze) Metzmacher 2004
   Copyright (C) Andrew Bartlett 2008 <abartlet@samba.org>
   Copyright (C) David Disseldorp 2008 <ddiss@sgi.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include <unistd.h>

#include "lib/events/events.h"
#include "lib/messaging/messaging.h"
#include "lib/socket/socket.h"
#include "smbd/process_model.h"
#include "cluster/cluster.h"
#include "param/param.h"
#include "ldb_wrap.h"
#include "lib/util/tfork.h"

NTSTATUS process_model_prefork_init(void);

static void sighup_signal_handler(struct tevent_context *ev,
				struct tevent_signal *se,
				int signum, int count, void *siginfo,
				void *private_data)
{
	debug_schedule_reopen_logs();
}

static void sigterm_signal_handler(struct tevent_context *ev,
				struct tevent_signal *se,
				int signum, int count, void *siginfo,
				void *private_data)
{
#if HAVE_GETPGRP
	if (getpgrp() == getpid()) {
		/*
		 * We're the process group leader, send
		 * SIGTERM to our process group.
		 */
		DBG_NOTICE("SIGTERM: killing children\n");
		kill(-getpgrp(), SIGTERM);
	}
#endif
	DBG_NOTICE("Exiting pid %d on SIGTERM\n", getpid());
	talloc_free(ev);
	exit(127);
}

/*
  called when the process model is selected
*/
static void prefork_model_init(void)
{
}

static void prefork_reload_after_fork(void)
{
	NTSTATUS status;

	ldb_wrap_fork_hook();
	/* Must be done after a fork() to reset messaging contexts. */
	status = imessaging_reinit_all();
	if (!NT_STATUS_IS_OK(status)) {
		smb_panic("Failed to re-initialise imessaging after fork");
	}
}

/*
  handle EOF on the parent-to-all-children pipe in the child
*/
static void prefork_pipe_handler(struct tevent_context *event_ctx,
		                 struct tevent_fd *fde, uint16_t flags,
				 void *private_data)
{
	/* free the fde which removes the event and stops it firing again */
	TALLOC_FREE(fde);
	DBG_NOTICE("Child %d exiting\n", getpid());
	talloc_free(event_ctx);
	exit(0);
}

/*
  handle EOF on the child pipe in the parent, so we know when a
  process terminates without using SIGCHLD or waiting on all possible pids.

  We need to ensure we do not ignore SIGCHLD because we need it to
  work to get a valid error code from samba_runcmd_*().
 */
static void prefork_child_pipe_handler(struct tevent_context *ev,
				       struct tevent_fd *fde,
				       uint16_t flags,
				       void *private_data)
{
	struct tfork *t = NULL;
	int status = 0;
	pid_t pid = 0;

	/* free the fde which removes the event and stops it firing again */
	TALLOC_FREE(fde);

	/* the child has closed the pipe, assume its dead */

	/* tfork allocates tfork structures with malloc  */
	t = (struct tfork*)private_data;
	pid = tfork_child_pid(t);
	errno = 0;
	status = tfork_status(&t, false);
	if (status == -1) {
		DBG_ERR("Parent %d, Child %d terminated, "
			"unable to get status code from tfork\n",
			getpid(), pid);
	} else if (WIFEXITED(status)) {
		status = WEXITSTATUS(status);
		DBG_ERR("Parent %d, Child %d exited with status %d\n",
			 getpid(), pid,  status);
	} else if (WIFSIGNALED(status)) {
		status = WTERMSIG(status);
		DBG_ERR("Parent %d, Child %d terminated with signal %d\n",
			getpid(), pid, status);
	}
	/* tfork allocates tfork structures with malloc */
	free(t);
	return;
}

/*
  called when a listening socket becomes readable.
*/
static void prefork_accept_connection(
	struct tevent_context *ev,
	struct loadparm_context *lp_ctx,
	struct socket_context *listen_socket,
	void (*new_conn)(struct tevent_context *,
			struct loadparm_context *,
			struct socket_context *,
			struct server_id,
			void *,
			void *),
	void *private_data,
	void *process_context)
{
	NTSTATUS status;
	struct socket_context *connected_socket;
	pid_t pid = getpid();

	/* accept an incoming connection. */
	status = socket_accept(listen_socket, &connected_socket);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * For prefork we can ignore STATUS_MORE_ENTRIES, as  once a
		 * connection becomes available all waiting processes are
		 * woken, but only one gets work to  process.
		 * AKA the thundering herd.
		 * In the short term this should not be an issue as the number
		 * of workers should be a small multiple of the number of cpus
		 * In the longer term socket_accept needs to implement a
		 * mutex/semaphore (like apache does) to serialise the accepts
		 */
		if (!NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
			DBG_ERR("Worker process (%d), error in accept [%s]\n",
				getpid(), nt_errstr(status));
		}
		return;
	}

	talloc_steal(private_data, connected_socket);

	new_conn(ev, lp_ctx, connected_socket,
		 cluster_id(pid, socket_get_fd(connected_socket)),
		 private_data, process_context);
}

static void setup_handlers(struct tevent_context *ev, int from_parent_fd) {
	struct tevent_fd *fde = NULL;
	struct tevent_signal *se = NULL;

	fde = tevent_add_fd(ev, ev, from_parent_fd, TEVENT_FD_READ,
		      prefork_pipe_handler, NULL);
	if (fde == NULL) {
		smb_panic("Failed to add fd handler after fork");
	}

	se = tevent_add_signal(ev,
			       ev,
			       SIGHUP,
			       0,
			       sighup_signal_handler,
			       NULL);
	if (se == NULL) {
		smb_panic("Failed to add SIGHUP handler after fork");
	}

	se = tevent_add_signal(ev,
			       ev,
			       SIGTERM,
			       0,
			       sigterm_signal_handler,
			       NULL);
	if (se == NULL) {
		smb_panic("Failed to add SIGTERM handler after fork");
	}
}

/*
 * called to create a new server task
 */
static void prefork_new_task(
	struct tevent_context *ev,
	struct loadparm_context *lp_ctx,
	const char *service_name,
	void (*new_task_fn)(struct tevent_context *,
			    struct loadparm_context *lp_ctx,
			    struct server_id , void *, void *),
	void *private_data,
	const struct service_details *service_details,
	int from_parent_fd)
{
	pid_t pid;
	struct tfork* t = NULL;
	int i, num_children;

	struct tevent_context *ev2;

	t = tfork_create();
	if (t == NULL) {
		smb_panic("failure in tfork\n");
	}

	pid = tfork_child_pid(t);
	if (pid != 0) {
		struct tevent_fd *fde = NULL;
		int fd = tfork_event_fd(t);

		/* Register a pipe handler that gets called when the prefork
		 * master process terminates.
		 */
		fde = tevent_add_fd(ev, ev, fd, TEVENT_FD_READ,
				    prefork_child_pipe_handler, t);
		if (fde == NULL) {
			smb_panic("Failed to add child pipe handler, "
				  "after fork");
		}
		tevent_fd_set_auto_close(fde);
		return;
	}

	pid = getpid();
	setproctitle("task[%s] pre-fork master", service_name);

	/*
	 * this will free all the listening sockets and all state that
	 * is not associated with this new connection
	 */
	if (tevent_re_initialise(ev) != 0) {
		smb_panic("Failed to re-initialise tevent after fork");
	}
	prefork_reload_after_fork();
	setup_handlers(ev, from_parent_fd);

	if (service_details->inhibit_pre_fork) {
		new_task_fn(ev, lp_ctx, cluster_id(pid, 0), private_data, NULL);
		/* The task does not support pre-fork */
		tevent_loop_wait(ev);
		TALLOC_FREE(ev);
		exit(0);
	}

	/*
	 * This is now the child code. We need a completely new event_context
	 * to work with
	 */
	ev2 = s4_event_context_init(NULL);

	/* setup this new connection: process will bind to it's sockets etc
	 *
	 * While we can use ev for the child, which has been re-initialised
	 * above we must run the new task under ev2 otherwise the children would
	 * be listening on the sockets.  Also we don't want the top level
	 * process accepting and handling requests, it's responsible for
	 * monitoring and controlling the child work processes.
	 */
	new_task_fn(ev2, lp_ctx, cluster_id(pid, 0), private_data, NULL);

	{
		int default_children;
		default_children = lpcfg_prefork_children(lp_ctx);
		num_children = lpcfg_parm_int(lp_ctx, NULL, "prefork children",
			                      service_name, default_children);
	}
	if (num_children == 0) {
		DBG_WARNING("Number of pre-fork children for %s is zero, "
			    "NO worker processes will be started for %s\n",
			    service_name, service_name);
	}
	DBG_NOTICE("Forking %d %s worker processes\n",
		   num_children, service_name);
	/* We are now free to spawn some worker processes */
	for (i=0; i < num_children; i++) {
		struct tfork* w = NULL;

		w = tfork_create();
		if (w == NULL) {
			smb_panic("failure in tfork\n");
		}

		pid = tfork_child_pid(w);
		if (pid != 0) {
			struct tevent_fd *fde = NULL;
			int fd = tfork_event_fd(w);

			fde = tevent_add_fd(ev, ev, fd, TEVENT_FD_READ,
					    prefork_child_pipe_handler, w);
			if (fde == NULL) {
				smb_panic("Failed to add child pipe handler, "
					  "after fork");
			}
			tevent_fd_set_auto_close(fde);
		} else {
			/* tfork uses malloc */
			free(w);

			TALLOC_FREE(ev);
			setproctitle("task[%s] pre-forked worker",
				     service_name);
			prefork_reload_after_fork();
			setup_handlers(ev2, from_parent_fd);
			tevent_loop_wait(ev2);
			talloc_free(ev2);
			exit(0);
		}
	}

	/* Don't listen on the sockets we just gave to the children */
	tevent_loop_wait(ev);
	TALLOC_FREE(ev);
	/* We need to keep ev2 until we're finished for the messaging to work */
	TALLOC_FREE(ev2);
	exit(0);

}


/* called when a task goes down */
static void prefork_terminate(struct tevent_context *ev,
			      struct loadparm_context *lp_ctx,
			      const char *reason,
			      void *process_context)
{
	DBG_DEBUG("called with reason[%s]\n", reason);
}

/* called to set a title of a task or connection */
static void prefork_set_title(struct tevent_context *ev, const char *title)
{
}

static const struct model_ops prefork_ops = {
	.name			= "prefork",
	.model_init		= prefork_model_init,
	.accept_connection	= prefork_accept_connection,
	.new_task		= prefork_new_task,
	.terminate		= prefork_terminate,
	.set_title		= prefork_set_title,
};

/*
 * initialise the prefork process model, registering ourselves with the
 * process model subsystem
 */
NTSTATUS process_model_prefork_init(void)
{
	return register_process_model(&prefork_ops);
}
