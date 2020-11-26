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
/*
 * The pre-fork process model distributes the server workload amongst several
 * designated worker threads (e.g. 'prefork-worker-ldap-0',
 * 'prefork-worker-ldap-1', etc). The number of worker threads is controlled
 * by the 'prefork children' conf setting. The worker threads are controlled
 * by a prefork master process (e.g. 'prefork-master-ldap'). The prefork master
 * doesn't handle the server workload (i.e. processing messages) itself, but is
 * responsible for restarting workers if they exit unexpectedly. The top-level
 * samba process is responsible for restarting the master process if it exits.
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
#include "lib/messaging/irpc.h"
#include "lib/util/util_process.h"
#include "server_util.h"

#define min(a, b) (((a) < (b)) ? (a) : (b))

NTSTATUS process_model_prefork_init(void);
static void prefork_new_task(
    struct tevent_context *ev,
    struct loadparm_context *lp_ctx,
    const char *service_name,
    struct task_server *(*new_task_fn)(struct tevent_context *,
				       struct loadparm_context *lp_ctx,
				       struct server_id,
				       void *,
				       void *),
    void *private_data,
    const struct service_details *service_details,
    int from_parent_fd);
static void prefork_fork_worker(struct task_server *task,
				struct tevent_context *ev,
				struct tevent_context *ev2,
				struct loadparm_context *lp_ctx,
				const struct service_details *service_details,
				const char *service_name,
				int control_pipe[2],
				unsigned restart_delay,
				struct process_details *pd);
static void prefork_child_pipe_handler(struct tevent_context *ev,
				       struct tevent_fd *fde,
				       uint16_t flags,
				       void *private_data);
static void setup_handlers(struct tevent_context *ev,
			   struct loadparm_context *lp_ctx,
                           int from_parent_fd);

/*
 * State needed to restart the master process or a worker process if they
 * terminate early.
 */
struct master_restart_context {
	struct task_server *(*new_task_fn)(struct tevent_context *,
					   struct loadparm_context *lp_ctx,
					   struct server_id,
					   void *,
					   void *);
	void *private_data;
};

struct worker_restart_context {
	unsigned int instance;
	struct task_server *task;
	struct tevent_context *ev2;
	int control_pipe[2];
};

struct restart_context {
	struct loadparm_context *lp_ctx;
	struct tfork *t;
	int from_parent_fd;
	const struct service_details *service_details;
	const char *service_name;
	unsigned restart_delay;
	struct master_restart_context *master;
	struct worker_restart_context *worker;
};

static void sighup_signal_handler(struct tevent_context *ev,
				struct tevent_signal *se,
				int signum, int count, void *siginfo,
				void *private_data)
{
	reopen_logs_internal();
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
		DBG_NOTICE("SIGTERM: killing children\n");
		kill(-getpgrp(), SIGTERM);
	}
#endif
	DBG_NOTICE("Exiting pid %d on SIGTERM\n", getpid());
	TALLOC_FREE(ev);
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
	force_check_log_size();
}

/*
 * clean up any messaging associated with the old process.
 *
 */
static void irpc_cleanup(
	struct loadparm_context *lp_ctx,
	struct tevent_context *ev,
	pid_t pid)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct imessaging_context *msg_ctx = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (mem_ctx == NULL) {
		DBG_ERR("OOM cleaning up irpc\n");
		return;
	}
	msg_ctx = imessaging_client_init(mem_ctx, lp_ctx, ev);
	if (msg_ctx == NULL) {
		DBG_ERR("Unable to create imessaging_context\n");
		TALLOC_FREE(mem_ctx);
		return;
	}
	status = imessaging_process_cleanup(msg_ctx, pid);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("imessaging_process_cleanup returned (%s)\n",
			nt_errstr(status));
		TALLOC_FREE(mem_ctx);
		return;
	}

	TALLOC_FREE(mem_ctx);
}

/*
 * handle EOF on the parent-to-all-children pipe in the child, i.e.
 * the parent has died and its end of the pipe has been closed.
 * The child handles this by exiting as well.
 */
static void prefork_pipe_handler(struct tevent_context *event_ctx,
		                 struct tevent_fd *fde, uint16_t flags,
				 void *private_data)
{
	struct loadparm_context *lp_ctx = NULL;
	pid_t pid;

	/*
	 * free the fde which removes the event and stops it firing again
	 */
	TALLOC_FREE(fde);

	/*
	 * Clean up any irpc end points this process had.
	 */
	pid = getpid();
	lp_ctx = talloc_get_type_abort(private_data, struct loadparm_context);
	irpc_cleanup(lp_ctx, event_ctx, pid);

	DBG_NOTICE("Child %d exiting\n", getpid());
	TALLOC_FREE(event_ctx);
	exit(0);
}


/*
 * Called by the top-level samba process to create a new prefork master process
 */
static void prefork_fork_master(
    struct tevent_context *ev,
    struct loadparm_context *lp_ctx,
    const char *service_name,
    struct task_server *(*new_task_fn)(struct tevent_context *,
				       struct loadparm_context *lp_ctx,
				       struct server_id,
				       void *,
				       void *),
    void *private_data,
    const struct service_details *service_details,
    unsigned restart_delay,
    int from_parent_fd)
{
	pid_t pid;
	struct tfork* t = NULL;
	int i, num_children;

	struct tevent_context *ev2;
	struct task_server *task = NULL;
	struct process_details pd = initial_process_details;
	struct samba_tevent_trace_state *samba_tevent_trace_state = NULL;
	int control_pipe[2];

	t = tfork_create();
	if (t == NULL) {
		smb_panic("failure in tfork\n");
	}

	DBG_NOTICE("Forking [%s] pre-fork master process\n", service_name);
	pid = tfork_child_pid(t);
	if (pid != 0) {
		struct tevent_fd *fde = NULL;
		int fd = tfork_event_fd(t);
		struct restart_context *rc = NULL;

		/* Register a pipe handler that gets called when the prefork
		 * master process terminates.
		 */
		rc = talloc_zero(ev, struct restart_context);
		if (rc == NULL) {
			smb_panic("OOM allocating restart context\n");
		}
		rc->t = t;
		rc->lp_ctx = lp_ctx;
		rc->service_name = service_name;
		rc->service_details = service_details;
		rc->from_parent_fd = from_parent_fd;
		rc->restart_delay = restart_delay;
		rc->master = talloc_zero(rc, struct master_restart_context);
		if (rc->master == NULL) {
			smb_panic("OOM allocating master restart context\n");
		}

		rc->master->new_task_fn = new_task_fn;
		rc->master->private_data = private_data;

		fde = tevent_add_fd(
		    ev, ev, fd, TEVENT_FD_READ, prefork_child_pipe_handler, rc);
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
	 * We must fit within 15 chars of text or we will truncate, so
	 * we put the constant part last
	 */
	prctl_set_comment("%s[master]", service_name);

	/*
	 * this will free all the listening sockets and all state that
	 * is not associated with this new connection
	 */
	if (tevent_re_initialise(ev) != 0) {
		smb_panic("Failed to re-initialise tevent after fork");
	}
	prefork_reload_after_fork();
	setup_handlers(ev, lp_ctx, from_parent_fd);

	if (service_details->inhibit_pre_fork) {
		task = new_task_fn(
		    ev, lp_ctx, cluster_id(pid, 0), private_data, NULL);
		/*
		 * The task does not support pre-fork
		 */
		if (task != NULL && service_details->post_fork != NULL) {
			service_details->post_fork(task, &pd);
		}
		tevent_loop_wait(ev);
		TALLOC_FREE(ev);
		exit(0);
	}

	/*
	 * This is now the child code. We need a completely new event_context
	 * to work with
	 */
	ev2 = s4_event_context_init(NULL);

	samba_tevent_trace_state = create_samba_tevent_trace_state(ev2);
	if (samba_tevent_trace_state == NULL) {
		TALLOC_FREE(ev);
		TALLOC_FREE(ev2);
		exit(127);
	}

	tevent_set_trace_callback(ev2,
				  samba_tevent_trace_callback,
				  samba_tevent_trace_state);

	/* setup this new connection: process will bind to it's sockets etc
	 *
	 * While we can use ev for the child, which has been re-initialised
	 * above we must run the new task under ev2 otherwise the children would
	 * be listening on the sockets.  Also we don't want the top level
	 * process accepting and handling requests, it's responsible for
	 * monitoring and controlling the child work processes.
	 */
	task = new_task_fn(ev2, lp_ctx, cluster_id(pid, 0), private_data, NULL);
	if (task == NULL) {
		TALLOC_FREE(ev);
		TALLOC_FREE(ev2);
		exit(127);
	}

	/*
	 * Register an irpc name that can be used by the samba-tool processes
	 * command
	 */
	{
		struct talloc_ctx *ctx = talloc_new(NULL);
		char *name = NULL;
		if (ctx == NULL) {
			DBG_ERR("Out of memory");
			exit(127);
		}
		name = talloc_asprintf(ctx, "prefork-master-%s", service_name);
		irpc_add_name(task->msg_ctx, name);
		TALLOC_FREE(ctx);
	}

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

	/*
	 * the prefork master creates its own control pipe, so the prefork
	 * workers can detect if the master exits (in which case an EOF gets
	 * written). (Whereas from_parent_fd is the control pipe from the
	 * top-level process that the prefork master listens on)
	 */
	{
		int ret;
		ret = pipe(control_pipe);
		if (ret != 0) {
			smb_panic("Unable to create worker control pipe\n");
		}
		smb_set_close_on_exec(control_pipe[0]);
		smb_set_close_on_exec(control_pipe[1]);
	}

	/*
	 * We are now free to spawn some worker processes
	 */
	for (i=0; i < num_children; i++) {
		prefork_fork_worker(task,
				    ev,
				    ev2,
				    lp_ctx,
				    service_details,
				    service_name,
				    control_pipe,
				    0,
				    &pd);
		pd.instances++;
	}

	/* Don't listen on the sockets we just gave to the children */
	tevent_loop_wait(ev);
	TALLOC_FREE(ev);
	/* We need to keep ev2 until we're finished for the messaging to work */
	TALLOC_FREE(ev2);
	exit(0);
}

/*
 * Restarts a child process if it exits unexpectedly
 */
static void prefork_restart(struct tevent_context *ev,
			    struct restart_context *rc)
{
	unsigned max_backoff = 0;
	unsigned backoff = 0;
	unsigned restart_delay = rc->restart_delay;
	unsigned default_value = 0;

	/*
	 * If the child process is constantly exiting, then restarting it can
	 * consume a lot of resources. In which case, we want to backoff a bit
	 * before respawning it
	 */
	default_value = lpcfg_prefork_backoff_increment(rc->lp_ctx);
	backoff = lpcfg_parm_int(rc->lp_ctx,
				 NULL,
				 "prefork backoff increment",
				 rc->service_name,
				 default_value);

	default_value = lpcfg_prefork_maximum_backoff(rc->lp_ctx);
	max_backoff = lpcfg_parm_int(rc->lp_ctx,
				     NULL,
				     "prefork maximum backoff",
				     rc->service_name,
				     default_value);

	if (restart_delay > 0) {
		DBG_ERR("Restarting [%s] pre-fork %s in (%d) seconds\n",
			rc->service_name,
			(rc->master == NULL) ? "worker" : "master",
			restart_delay);
		sleep(restart_delay);
	}
	restart_delay += backoff;
	restart_delay = min(restart_delay, max_backoff);

	if (rc->master != NULL) {
		DBG_ERR("Restarting [%s] pre-fork master\n", rc->service_name);
		prefork_fork_master(ev,
				    rc->lp_ctx,
				    rc->service_name,
				    rc->master->new_task_fn,
				    rc->master->private_data,
				    rc->service_details,
				    restart_delay,
				    rc->from_parent_fd);
	} else if (rc->worker != NULL) {
		struct process_details pd = initial_process_details;
		DBG_ERR("Restarting [%s] pre-fork worker(%d)\n",
			rc->service_name,
			rc->worker->instance);
		pd.instances = rc->worker->instance;
		prefork_fork_worker(rc->worker->task,
				    ev,
				    rc->worker->ev2,
				    rc->lp_ctx,
				    rc->service_details,
				    rc->service_name,
				    rc->worker->control_pipe,
				    restart_delay,
				    &pd);
	}
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
	struct restart_context *rc = NULL;
	int status = 0;
	pid_t pid = 0;

	/* free the fde which removes the event and stops it firing again */
	TALLOC_FREE(fde);

	/* the child has closed the pipe, assume its dead */

	rc = talloc_get_type_abort(private_data, struct restart_context);
	pid = tfork_child_pid(rc->t);
	errno = 0;

	irpc_cleanup(rc->lp_ctx, ev, pid);
	status = tfork_status(&rc->t, false);
	if (status == -1) {
		DBG_ERR("Parent %d, Child %d terminated, "
			"unable to get status code from tfork\n",
			getpid(), pid);
		prefork_restart(ev, rc);
	} else if (WIFEXITED(status)) {
		status = WEXITSTATUS(status);
		DBG_ERR("Parent %d, Child %d exited with status %d\n",
			 getpid(), pid,  status);
		if (status != 0) {
			prefork_restart(ev, rc);
		}
	} else if (WIFSIGNALED(status)) {
		status = WTERMSIG(status);
		DBG_ERR("Parent %d, Child %d terminated with signal %d\n",
			getpid(), pid, status);
		if (status == SIGABRT || status == SIGBUS || status == SIGFPE ||
		    status == SIGILL || status == SIGSYS || status == SIGSEGV ||
		    status == SIGKILL) {

			prefork_restart(ev, rc);
		}
	}
	/* tfork allocates tfork structures with malloc */
	tfork_destroy(&rc->t);
	free(rc->t);
	TALLOC_FREE(rc);
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

static void setup_handlers(
	struct tevent_context *ev,
	struct loadparm_context *lp_ctx,
	int from_parent_fd)
{
	struct tevent_fd *fde = NULL;
	struct tevent_signal *se = NULL;

	fde = tevent_add_fd(ev, ev, from_parent_fd, TEVENT_FD_READ,
		      prefork_pipe_handler, lp_ctx);
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
 * Called by the prefork master to create a new prefork worker process
 */
static void prefork_fork_worker(struct task_server *task,
				struct tevent_context *ev,
				struct tevent_context *ev2,
				struct loadparm_context *lp_ctx,
				const struct service_details *service_details,
				const char *service_name,
				int control_pipe[2],
				unsigned restart_delay,
				struct process_details *pd)
{
	struct tfork *w = NULL;
	pid_t pid;

	w = tfork_create();
	if (w == NULL) {
		smb_panic("failure in tfork\n");
	}

	pid = tfork_child_pid(w);
	if (pid != 0) {
		struct tevent_fd *fde = NULL;
		int fd = tfork_event_fd(w);
		struct restart_context *rc = NULL;

		/*
		 * we're the parent (prefork master), so store enough info to
		 * restart the worker/child if it exits unexpectedly
		 */
		rc = talloc_zero(ev, struct restart_context);
		if (rc == NULL) {
			smb_panic("OOM allocating restart context\n");
		}
		rc->t = w;
		rc->lp_ctx = lp_ctx;
		rc->service_name = service_name;
		rc->service_details = service_details;
		rc->restart_delay = restart_delay;
		rc->master = NULL;
		rc->worker = talloc_zero(rc, struct worker_restart_context);
		if (rc->worker == NULL) {
			smb_panic("OOM allocating master restart context\n");
		}
		rc->worker->ev2 = ev2;
		rc->worker->instance = pd->instances;
		rc->worker->task = task;
		rc->worker->control_pipe[0] = control_pipe[0];
		rc->worker->control_pipe[1] = control_pipe[1];

		fde = tevent_add_fd(
		    ev, ev, fd, TEVENT_FD_READ, prefork_child_pipe_handler, rc);
		if (fde == NULL) {
			smb_panic("Failed to add child pipe handler, "
				  "after fork");
		}
		tevent_fd_set_auto_close(fde);
	} else {

		/*
		 * we're the child (prefork-worker). We never write to the
		 * control pipe, but listen on the read end in case our parent
		 * (the pre-fork master) exits
		 */
		close(control_pipe[1]);
		setup_handlers(ev2, lp_ctx, control_pipe[0]);

		/*
		 * tfork uses malloc
		 */
		free(w);

		TALLOC_FREE(ev);
		setproctitle("task[%s] pre-forked worker(%d)",
			     service_name,
			     pd->instances);
		/*
		 * We must fit within 15 chars of text or we will truncate, so
		 * we put child number last
		 */
		prctl_set_comment("%s(%d)",
				  service_name,
				  pd->instances);
		prefork_reload_after_fork();
		if (service_details->post_fork != NULL) {
			service_details->post_fork(task, pd);
		}
		{
			struct talloc_ctx *ctx = talloc_new(NULL);
			char *name = NULL;
			if (ctx == NULL) {
				smb_panic("OOM allocating talloc context\n");
			}
			name = talloc_asprintf(ctx,
					       "prefork-worker-%s-%d",
					       service_name,
					       pd->instances);
			irpc_add_name(task->msg_ctx, name);
			TALLOC_FREE(ctx);
		}
		tevent_loop_wait(ev2);
		talloc_free(ev2);
		exit(0);
	}
}
/*
 * called to create a new server task
 */
static void prefork_new_task(
	struct tevent_context *ev,
	struct loadparm_context *lp_ctx,
	const char *service_name,
	struct task_server *(*new_task_fn)(struct tevent_context *,
			    struct loadparm_context *lp_ctx,
			    struct server_id , void *, void *),
	void *private_data,
	const struct service_details *service_details,
	int from_parent_fd)
{
	prefork_fork_master(ev,
			    lp_ctx,
			    service_name,
			    new_task_fn,
			    private_data,
			    service_details,
			    0,
			    from_parent_fd);

}

/*
 * called when a task terminates
 */
static void prefork_terminate_task(struct tevent_context *ev,
				   struct loadparm_context *lp_ctx,
				   const char *reason,
				   bool fatal,
				   void *process_context)
{
	DBG_DEBUG("called with reason[%s]\n", reason);
	TALLOC_FREE(ev);
	if (fatal == true) {
		exit(127);
	} else {
		exit(0);
	}
}

/*
 * called when a connection completes
 */
static void prefork_terminate_connection(struct tevent_context *ev,
					 struct loadparm_context *lp_ctx,
					 const char *reason,
					 void *process_context)
{
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
	.terminate_task		= prefork_terminate_task,
	.terminate_connection	= prefork_terminate_connection,
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
