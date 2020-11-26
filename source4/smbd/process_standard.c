/* 
   Unix SMB/CIFS implementation.

   process model: standard (1 process per client connection)

   Copyright (C) Andrew Tridgell 1992-2005
   Copyright (C) James J Myers 2003 <myersjj@samba.org>
   Copyright (C) Stefan (metze) Metzmacher 2004
   
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
#include "lib/events/events.h"
#include "smbd/process_model.h"
#include "system/filesys.h"
#include "cluster/cluster.h"
#include "param/param.h"
#include "ldb_wrap.h"
#include "lib/messaging/messaging.h"
#include "lib/util/debug.h"
#include "lib/messaging/messages_dgm.h"
#include "lib/util/util_process.h"

static unsigned connections_active = 0;
static unsigned smbd_max_processes = 0;

struct standard_child_state {
	const char *name;
	pid_t pid;
	int to_parent_fd;
	int from_child_fd;
	struct tevent_fd *from_child_fde;
};

NTSTATUS process_model_standard_init(TALLOC_CTX *);
struct process_context {
	char *name;
	int from_parent_fd;
	bool inhibit_fork_on_accept;
	bool forked_on_accept;
};

/*
  called when the process model is selected
*/
static void standard_model_init(void)
{
}

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
#ifdef HAVE_GETPGRP
	if (getpgrp() == getpid()) {
		/*
		 * We're the process group leader, send
		 * SIGTERM to our process group.
		 */
		DBG_ERR("SIGTERM: killing children\n");
		kill(-getpgrp(), SIGTERM);
	}
#endif
	DBG_ERR("Exiting pid %u on SIGTERM\n", (unsigned int)getpid());
	talloc_free(ev);
	exit(127);
}

/*
  handle EOF on the parent-to-all-children pipe in the child
*/
static void standard_pipe_handler(struct tevent_context *event_ctx, struct tevent_fd *fde, 
				  uint16_t flags, void *private_data)
{
	DBG_DEBUG("Child %d exiting\n", (int)getpid());
	talloc_free(event_ctx);
	exit(0);
}

/*
  handle EOF on the child pipe in the parent, so we know when a
  process terminates without using SIGCHLD or waiting on all possible pids.

  We need to ensure we do not ignore SIGCHLD because we need it to
  work to get a valid error code from samba_runcmd_*().
 */
static void standard_child_pipe_handler(struct tevent_context *ev,
					struct tevent_fd *fde,
					uint16_t flags,
					void *private_data)
{
	struct standard_child_state *state
		= talloc_get_type_abort(private_data, struct standard_child_state);
	int status = 0;
	pid_t pid;

	messaging_dgm_cleanup(state->pid);

	/* the child has closed the pipe, assume its dead */
	errno = 0;
	pid = waitpid(state->pid, &status, 0);

	if (pid != state->pid) {
		if (errno == ECHILD) {
			/*
			 * this happens when the
			 * parent has set SIGCHLD to
			 * SIG_IGN. In that case we
			 * can only get error
			 * information for the child
			 * via its logging. We should
			 * stop using SIG_IGN on
			 * SIGCHLD in the standard
			 * process model.
			 */
			DBG_ERR("Error in waitpid() unexpectedly got ECHILD "
				"for child %d (%s) - %s, someone has set SIGCHLD "
				"to SIG_IGN!\n",
				(int)state->pid, state->name,
				strerror(errno));
			TALLOC_FREE(state);
			return;
		}
		DBG_ERR("Error in waitpid() for child %d (%s) - %s \n",
			(int)state->pid, state->name, strerror(errno));
		if (errno == 0) {
			errno = ECHILD;
		}
		goto done;
	}
	if (WIFEXITED(status)) {
		status = WEXITSTATUS(status);
		if (status != 0) {
			DBG_ERR("Child %d (%s) exited with status %d\n",
				(int)state->pid, state->name, status);
		}
	} else if (WIFSIGNALED(status)) {
		status = WTERMSIG(status);
		DBG_ERR("Child %d (%s) terminated with signal %d\n",
			(int)state->pid, state->name, status);
	}
done:
	TALLOC_FREE(state);
	if (smbd_max_processes > 0) {
		if (connections_active < 1) {
			DBG_ERR("Number of active connections "
				"less than 1 (%d)\n",
				connections_active);
			connections_active = 1;
		}
		connections_active--;
	}
	return;
}

static struct standard_child_state *setup_standard_child_pipe(struct tevent_context *ev,
							      const char *name)
{
	struct standard_child_state *state;
	int parent_child_pipe[2];
	int ret;

	/*
	 * Prepare a pipe to allow us to know when the child exits,
	 * because it will trigger a read event on this private
	 * pipe.
	 *
	 * We do all this before the accept and fork(), so we can
	 * clean up if it fails.
	 */
	state = talloc_zero(ev, struct standard_child_state);
	if (state == NULL) {
		return NULL;
	}

	if (name == NULL) {
		name = "";
	}

	state->name = talloc_strdup(state, name);
	if (state->name == NULL) {
		TALLOC_FREE(state);
		return NULL;
	}

	ret = pipe(parent_child_pipe);
	if (ret == -1) {
		DBG_ERR("Failed to create parent-child pipe to handle "
			"SIGCHLD to track new process for socket\n");
		TALLOC_FREE(state);
		return NULL;
	}

	smb_set_close_on_exec(parent_child_pipe[0]);
	smb_set_close_on_exec(parent_child_pipe[1]);

	state->from_child_fd = parent_child_pipe[0];
	state->to_parent_fd = parent_child_pipe[1];

	/*
	 * The basic purpose of calling this handler is to ensure we
	 * call waitpid() and so avoid zombies (now that we no longer
	 * user SIGIGN on for SIGCHLD), but it also allows us to clean
	 * up other resources in the future.
	 */
	state->from_child_fde = tevent_add_fd(ev, state,
					      state->from_child_fd,
					      TEVENT_FD_READ,
					      standard_child_pipe_handler,
					      state);
	if (state->from_child_fde == NULL) {
		TALLOC_FREE(state);
		return NULL;
	}
	tevent_fd_set_auto_close(state->from_child_fde);

	return state;
}

/*
  called when a listening socket becomes readable. 
*/
static void standard_accept_connection(
		struct tevent_context *ev,
		struct loadparm_context *lp_ctx,
		struct socket_context *sock,
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
	struct socket_context *sock2;
	pid_t pid;
	struct socket_address *c, *s;
	struct standard_child_state *state;
	struct tevent_fd *fde = NULL;
	struct tevent_signal *se = NULL;
	struct process_context *proc_ctx = NULL;


	/* accept an incoming connection. */
	status = socket_accept(sock, &sock2);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("standard_accept_connection: accept: %s\n",
			  nt_errstr(status));
		/* this looks strange, but is correct. We need to throttle
		 * things until the system clears enough resources to handle
		 * this new socket
		 */
		sleep(1);
		return;
	}

	proc_ctx = talloc_get_type_abort(process_context,
					 struct process_context);

	if (proc_ctx->inhibit_fork_on_accept) {
		pid = getpid();
		/*
		 * Service does not support forking a new process on a
		 * new connection, either it's maintaining shared
		 * state or the overhead of forking a new process is a
		 * significant fraction of the response time.
		 */
		talloc_steal(private_data, sock2);
		new_conn(ev, lp_ctx, sock2,
			 cluster_id(pid, socket_get_fd(sock2)), private_data,
			 process_context);
		return;
	}

	if (smbd_max_processes > 0) {
		if (connections_active >= smbd_max_processes) {
			DBG_ERR("(%d) connections already active, "
				"maximum is (%d). Dropping request\n",
				connections_active,
				smbd_max_processes);
			/*
			 * Drop the connection as we're overloaded at the moment
			 */
			talloc_free(sock2);
			return;
		}
		connections_active++;
	}

	state = setup_standard_child_pipe(ev, NULL);
	if (state == NULL) {
		return;
	}
	pid = fork();

	if (pid != 0) {
		close(state->to_parent_fd);
		state->to_parent_fd = -1;

		if (pid > 0) {
			state->pid = pid;
		} else {
			TALLOC_FREE(state);
		}

		/* parent or error code ... */
		talloc_free(sock2);
		/* go back to the event loop */
		return;
	}

	/* this leaves state->to_parent_fd open */
	TALLOC_FREE(state);

	/* Now in the child code so indicate that we forked
	 * so the terminate code knows what to do
	 */
	proc_ctx->forked_on_accept = true;

	pid = getpid();
	setproctitle("task[%s] standard worker", proc_ctx->name);

	/*
	 * We must fit within 15 chars of text or we will truncate, so
	 * we put the constant part last
	 */
	prctl_set_comment("%s[work]", proc_ctx->name);

	/* This is now the child code. We need a completely new event_context to work with */

	if (tevent_re_initialise(ev) != 0) {
		smb_panic("Failed to re-initialise tevent after fork");
	}

	/* this will free all the listening sockets and all state that
	   is not associated with this new connection */
	talloc_free(sock);

	/* we don't care if the dup fails, as its only a select()
	   speed optimisation */
	socket_dup(sock2);
			
	/* tdb needs special fork handling */
	ldb_wrap_fork_hook();

	/* Must be done after a fork() to reset messaging contexts. */
	status = imessaging_reinit_all();
	if (!NT_STATUS_IS_OK(status)) {
		smb_panic("Failed to re-initialise imessaging after fork");
	}

	fde = tevent_add_fd(ev, ev, proc_ctx->from_parent_fd, TEVENT_FD_READ,
		      standard_pipe_handler, NULL);
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

	/* setup the process title */
	c = socket_get_peer_addr(sock2, ev);
	s = socket_get_my_addr(sock2, ev);
	if (s && c) {
		setproctitle("conn c[%s:%u] s[%s:%u] server_id[%d]",
			     c->addr, c->port, s->addr, s->port, (int)pid);
	}
	talloc_free(c);
	talloc_free(s);

	force_check_log_size();

	/* setup this new connection.  Cluster ID is PID based for this process model */
	new_conn(ev, lp_ctx, sock2, cluster_id(pid, 0), private_data,
		 process_context);

	/* we can't return to the top level here, as that event context is gone,
	   so we now process events in the new event context until there are no
	   more to process */	   
	tevent_loop_wait(ev);

	talloc_free(ev);
	exit(0);
}

/*
  called to create a new server task
*/
static void standard_new_task(struct tevent_context *ev,
			      struct loadparm_context *lp_ctx,
			      const char *service_name,
			      struct task_server *(*new_task)(struct tevent_context *, struct loadparm_context *lp_ctx, struct server_id , void *, void *),
			      void *private_data,
			      const struct service_details *service_details,
			      int from_parent_fd)
{
	pid_t pid;
	NTSTATUS status;
	struct standard_child_state *state;
	struct tevent_fd *fde = NULL;
	struct tevent_signal *se = NULL;
	struct process_context *proc_ctx = NULL;
	struct task_server* task = NULL;

	state = setup_standard_child_pipe(ev, service_name);
	if (state == NULL) {
		return;
	}

	pid = fork();

	if (pid != 0) {
		close(state->to_parent_fd);
		state->to_parent_fd = -1;

		if (pid > 0) {
			state->pid = pid;
		} else {
			TALLOC_FREE(state);
		}

		/* parent or error code ... go back to the event loop */
		return;
	}

	/* this leaves state->to_parent_fd open */
	TALLOC_FREE(state);

	pid = getpid();

	/* this will free all the listening sockets and all state that
	   is not associated with this new connection */
	if (tevent_re_initialise(ev) != 0) {
		smb_panic("Failed to re-initialise tevent after fork");
	}

	/* ldb/tdb need special fork handling */
	ldb_wrap_fork_hook();

	/* Must be done after a fork() to reset messaging contexts. */
	status = imessaging_reinit_all();
	if (!NT_STATUS_IS_OK(status)) {
		smb_panic("Failed to re-initialise imessaging after fork");
	}

	fde = tevent_add_fd(ev, ev, from_parent_fd, TEVENT_FD_READ,
		      standard_pipe_handler, NULL);
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

	setproctitle("task[%s]", service_name);
	/*
	 * We must fit within 15 chars of text or we will truncate, so
	 * we put the constant part last
	 */
	prctl_set_comment("%s[task]", service_name);

	force_check_log_size();

	/*
	 * Set up the process context to be passed through to the terminate
	 * and accept_connection functions
	 */
	proc_ctx = talloc(ev, struct process_context);
	proc_ctx->name = talloc_strdup(ev, service_name);
	proc_ctx->from_parent_fd = from_parent_fd;
	proc_ctx->inhibit_fork_on_accept  =
		service_details->inhibit_fork_on_accept;
	proc_ctx->forked_on_accept = false;

	smbd_max_processes = lpcfg_max_smbd_processes(lp_ctx);

	/* setup this new task.  Cluster ID is PID based for this process model */
	task = new_task(ev, lp_ctx, cluster_id(pid, 0), private_data, proc_ctx);
	/*
	 * Currently we don't support the post_fork functionality in the
	 * standard model, i.e. it is only called here not after a new process
	 * is forked in standard_accept_connection.
	 */
	if (task != NULL && service_details->post_fork != NULL) {
		struct process_details pd = initial_process_details;
		service_details->post_fork(task, &pd);
	}


	/* we can't return to the top level here, as that event context is gone,
	   so we now process events in the new event context until there are no
	   more to process */
	tevent_loop_wait(ev);

	talloc_free(ev);
	exit(0);
}


/* called when a task goes down */
static void standard_terminate_task(struct tevent_context *ev,
				    struct loadparm_context *lp_ctx,
				    const char *reason,
				    bool fatal,
				    void *process_context)
{
	if (fatal == true) {
		exit(127);
	}
	exit(0);
}

/* called when a connection terminates*/
static void standard_terminate_connection(struct tevent_context *ev,
					  struct loadparm_context *lp_ctx,
					  const char *reason,
					  void *process_context)
{
	struct process_context *proc_ctx = NULL;

	DBG_DEBUG("connection terminating reason[%s]\n", reason);
	if (process_context == NULL) {
		smb_panic("Panicking process_context is NULL");
	}

	proc_ctx = talloc_get_type(process_context, struct process_context);
	if (proc_ctx->forked_on_accept == false) {
		/*
		 * The current task was not forked on accept, so it needs to
		 * keep running and process requests from other connections
		 */
		return;
	}
	/*
	 * The current process was forked on accept to handle a single
	 * connection/request. That request has now finished and the process
	 * should terminate
	 */

	/* this reload_charcnv() has the effect of freeing the iconv context memory,
	   which makes leak checking easier */
	reload_charcnv(lp_ctx);

	/* Always free event context last before exit. */
	talloc_free(ev);

	/* terminate this process */
	exit(0);
}
/* called to set a title of a task or connection */
static void standard_set_title(struct tevent_context *ev, const char *title) 
{
	if (title) {
		setproctitle("%s", title);
	} else {
		setproctitle(NULL);
	}
}

static const struct model_ops standard_ops = {
	.name			= "standard",
	.model_init		= standard_model_init,
	.accept_connection	= standard_accept_connection,
	.new_task		= standard_new_task,
	.terminate_task		= standard_terminate_task,
	.terminate_connection	= standard_terminate_connection,
	.set_title		= standard_set_title,
};

/*
  initialise the standard process model, registering ourselves with the process model subsystem
 */
NTSTATUS process_model_standard_init(TALLOC_CTX *ctx)
{
	return register_process_model(&standard_ops);
}
