/*
   Unix SMB/Netbios implementation.
   SPOOLSS Daemon
   Copyright (C) Simo Sorce 2010

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
#include "serverid.h"
#include "smbd/smbd.h"

#include "messages.h"
#include "include/printing.h"
#include "printing/nt_printing_migrate_internal.h"
#include "ntdomain.h"
#include "librpc/gen_ndr/srv_winreg.h"
#include "librpc/gen_ndr/srv_spoolss.h"
#include "rpc_server/rpc_server.h"
#include "rpc_server/rpc_ep_register.h"
#include "rpc_server/spoolss/srv_spoolss_nt.h"
#include "librpc/rpc/dcerpc_ep.h"
#include "lib/server_prefork.h"

#define SPOOLSS_PIPE_NAME "spoolss"
#define DAEMON_NAME "spoolssd"

#define SPOOLSS_MIN_CHILDREN 5
#define SPOOLSS_MAX_CHILDREN 25
#define SPOOLSS_SPAWN_RATE 5
#define SPOOLSS_MIN_LIFE 60 /* 1 minute minimum life time */

void start_spoolssd(struct tevent_context *ev_ctx,
		    struct messaging_context *msg_ctx);

static void spoolss_reopen_logs(void)
{
	char *lfile = lp_logfile();
	int rc;

	if (lfile == NULL || lfile[0] == '\0') {
		rc = asprintf(&lfile, "%s/log.%s", get_dyn_LOGFILEBASE(), DAEMON_NAME);
		if (rc > 0) {
			lp_set_logfile(lfile);
			SAFE_FREE(lfile);
		}
	} else {
		if (strstr(lfile, DAEMON_NAME) == NULL) {
			rc = asprintf(&lfile, "%s.%s", lp_logfile(), DAEMON_NAME);
			if (rc > 0) {
				lp_set_logfile(lfile);
				SAFE_FREE(lfile);
			}
		}
	}

	reopen_logs();
}

static void smb_conf_updated(struct messaging_context *msg,
			     void *private_data,
			     uint32_t msg_type,
			     struct server_id server_id,
			     DATA_BLOB *data)
{
	struct tevent_context *ev_ctx = talloc_get_type_abort(private_data,
							     struct tevent_context);

	DEBUG(10, ("Got message saying smb.conf was updated. Reloading.\n"));
	change_to_root_user();
	reload_printers(ev_ctx, msg);
	spoolss_reopen_logs();
}

static void spoolss_sig_term_handler(struct tevent_context *ev,
				     struct tevent_signal *se,
				     int signum,
				     int count,
				     void *siginfo,
				     void *private_data)
{
	exit_server_cleanly("termination signal");
}

static void spoolss_setup_sig_term_handler(struct tevent_context *ev_ctx)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev_ctx,
			       ev_ctx,
			       SIGTERM, 0,
			       spoolss_sig_term_handler,
			       NULL);
	if (!se) {
		exit_server("failed to setup SIGTERM handler");
	}
}

static void spoolss_sig_hup_handler(struct tevent_context *ev,
				    struct tevent_signal *se,
				    int signum,
				    int count,
				    void *siginfo,
				    void *pvt)
{
	struct messaging_context *msg_ctx;

	msg_ctx = talloc_get_type_abort(pvt, struct messaging_context);

	change_to_root_user();
	DEBUG(1,("Reloading printers after SIGHUP\n"));
	reload_printers(ev, msg_ctx);
	spoolss_reopen_logs();
}

static void spoolss_setup_sig_hup_handler(struct tevent_context *ev_ctx,
					  struct messaging_context *msg_ctx)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev_ctx,
			       ev_ctx,
			       SIGHUP, 0,
			       spoolss_sig_hup_handler,
			       msg_ctx);
	if (!se) {
		exit_server("failed to setup SIGHUP handler");
	}
}

static bool spoolss_init_cb(void *ptr)
{
	struct messaging_context *msg_ctx = talloc_get_type_abort(
		ptr, struct messaging_context);

	return nt_printing_tdb_migrate(msg_ctx);
}

static bool spoolss_shutdown_cb(void *ptr)
{
	srv_spoolss_cleanup();

	return true;
}

/* Childrens */

struct spoolss_chld_sig_hup_ctx {
	struct messaging_context *msg_ctx;
	struct pf_worker_data *pf;
};

static void spoolss_chld_sig_hup_handler(struct tevent_context *ev,
					 struct tevent_signal *se,
					 int signum,
					 int count,
					 void *siginfo,
					 void *pvt)
{
	struct spoolss_chld_sig_hup_ctx *shc;

	shc = talloc_get_type_abort(pvt, struct spoolss_chld_sig_hup_ctx);

	/* avoid wasting CPU cycles if we are going to exit soon anyways */
	if (shc->pf != NULL &&
	    shc->pf->cmds == PF_SRV_MSG_EXIT) {
		return;
	}

	change_to_root_user();
	DEBUG(1,("Reloading printers after SIGHUP\n"));
	reload_printers(ev, shc->msg_ctx);
	spoolss_reopen_logs();
}

static bool spoolss_setup_chld_hup_handler(struct tevent_context *ev_ctx,
					   struct pf_worker_data *pf,
					   struct messaging_context *msg_ctx)
{
	struct spoolss_chld_sig_hup_ctx *shc;
	struct tevent_signal *se;

	shc = talloc(ev_ctx, struct spoolss_chld_sig_hup_ctx);
	if (!shc) {
		DEBUG(1, ("failed to setup SIGHUP handler"));
		return false;
	}
	shc->pf = pf;
	shc->msg_ctx = msg_ctx;

	se = tevent_add_signal(ev_ctx,
			       ev_ctx,
			       SIGHUP, 0,
			       spoolss_chld_sig_hup_handler,
			       shc);
	if (!se) {
		DEBUG(1, ("failed to setup SIGHUP handler"));
		return false;
	}

	return true;
}

static bool spoolss_child_init(struct tevent_context *ev_ctx,
					struct pf_worker_data *pf)
{
	NTSTATUS status;
	struct rpc_srv_callbacks spoolss_cb;
	struct messaging_context *msg_ctx = server_messaging_context();
	bool ok;

	status = reinit_after_fork(msg_ctx, ev_ctx,
				   procid_self(), true);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		smb_panic("reinit_after_fork() failed");
	}

	spoolss_reopen_logs();

	ok = spoolss_setup_chld_hup_handler(ev_ctx, pf, msg_ctx);
	if (!ok) {
		return false;
	}

	if (!serverid_register(procid_self(), FLAG_MSG_GENERAL)) {
		return false;
	}

	if (!locking_init()) {
		return false;
	}

	messaging_register(msg_ctx, ev_ctx,
			   MSG_SMB_CONF_UPDATED, smb_conf_updated);

	/* try to reinit rpc queues */
	spoolss_cb.init = spoolss_init_cb;
	spoolss_cb.shutdown = spoolss_shutdown_cb;
	spoolss_cb.private_data = msg_ctx;

	status = rpc_winreg_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register winreg rpc inteface! (%s)\n",
			  nt_errstr(status)));
		return false;
	}

	status = rpc_spoolss_init(&spoolss_cb);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register spoolss rpc inteface! (%s)\n",
			  nt_errstr(status)));
		return false;
	}

	reload_printers(ev_ctx, msg_ctx);

	return true;
}

struct spoolss_children_data {
	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;
	struct pf_worker_data *pf;
	int listen_fd;
	int lock_fd;
};

static void spoolss_schedule_loop(void *pvt);
static void spoolss_children_loop(struct tevent_context *ev_ctx,
				  struct tevent_immediate *im,
				  void *pvt);

static int spoolss_children_main(struct tevent_context *ev_ctx,
				 struct pf_worker_data *pf,
				 int listen_fd, int lock_fd,
				 void *private_data)
{
	struct messaging_context *msg_ctx = server_messaging_context();
	struct spoolss_children_data *data;
	bool ok;
	int ret;

	ok = spoolss_child_init(ev_ctx, pf);
	if (!ok) {
		return 1;
	}

	data = talloc(ev_ctx, struct spoolss_children_data);
	if (!data) {
		return 1;
	}
	data->pf = pf;
	data->ev_ctx = ev_ctx;
	data->msg_ctx = msg_ctx;
	data->lock_fd = lock_fd;
	data->listen_fd = listen_fd;

	spoolss_schedule_loop(data);

	/* loop until it is time to exit */
	while (pf->status != PF_WORKER_EXITING) {
		ret = tevent_loop_once(ev_ctx);
		if (ret != 0) {
			DEBUG(0, ("tevent_loop_once() exited with %d: %s\n",
				  ret, strerror(errno)));
			pf->status = PF_WORKER_EXITING;
		}
	}

	return ret;
}

static void spoolss_client_terminated(void *pvt)
{
	struct spoolss_children_data *data;

	data = talloc_get_type_abort(pvt, struct spoolss_children_data);

	if (data->pf->num_clients) {
		data->pf->num_clients--;
	} else {
		DEBUG(2, ("Invalid num clients, aborting!\n"));
		data->pf->status = PF_WORKER_EXITING;
		return;
	}

	spoolss_schedule_loop(pvt);
}

static void spoolss_schedule_loop(void *pvt)
{
	struct spoolss_children_data *data;
	struct tevent_immediate *im;

	data = talloc_get_type_abort(pvt, struct spoolss_children_data);

	if (data->pf->num_clients == 0) {
		data->pf->status = PF_WORKER_IDLE;
	}

	if (data->pf->cmds == PF_SRV_MSG_EXIT) {
		DEBUG(2, ("Parent process commands we terminate!\n"));
		return;
	}

	im = tevent_create_immediate(data);
	if (!im) {
		DEBUG(1, ("Failed to create immediate event!\n"));
		return;
	}

	tevent_schedule_immediate(im, data->ev_ctx,
				  spoolss_children_loop, data);
}

static void spoolss_children_loop(struct tevent_context *ev_ctx,
				  struct tevent_immediate *im,
				  void *pvt)
{
	struct spoolss_children_data *data;
	struct sockaddr_un sunaddr;
	socklen_t addrlen = sizeof(sunaddr);
	int ret;
	int sd;

	data = talloc_get_type_abort(pvt, struct spoolss_children_data);


	/* FIXME: this call is blocking. */
	ret = prefork_wait_for_client(data->pf, data->lock_fd, data->listen_fd,
					(struct sockaddr *)(void *)&sunaddr,
					&addrlen, &sd);
	if (ret > 0) {
		DEBUG(1, ("Failed to accept connection!\n"));
		return;
	}

	if (ret == -2) {
		DEBUG(1, ("Server asks us to die!\n"));
		data->pf->status = PF_WORKER_EXITING;
		return;
	}

	DEBUG(2, ("Spoolss preforked child %d activated!\n",
		  (int)(data->pf->pid)));

	named_pipe_accept_function(data->ev_ctx, data->msg_ctx,
				   SPOOLSS_PIPE_NAME, sd,
				   spoolss_client_terminated, data);
}

/* ==== Main Process Functions ==== */

static void spoolssd_sig_chld_handler(struct tevent_context *ev_ctx,
				      struct tevent_signal *se,
				      int signum, int count,
				      void *siginfo, void *pvt)
{
	struct prefork_pool *pfp;
	pid_t pid;
	int status;
	bool ok;
	int active, total;
	int n, r;

	pfp = talloc_get_type_abort(pvt, struct prefork_pool);

	while ((pid = sys_waitpid(-1, &status, WNOHANG)) > 0) {
		ok = prefork_mark_pid_dead(pfp, pid);
		if (!ok) {
			DEBUG(1, ("Pid %d was not found in children pool!\n",
				  (int)pid));
		}
	}

	/* now check we do not descent below the minimum */
	active = prefork_count_active_children(pfp, &total);

	n = 0;
	if (total < SPOOLSS_MIN_CHILDREN) {
		n = total - SPOOLSS_MIN_CHILDREN;
	} else if (total - active < (total / 4)) {
		n = SPOOLSS_MIN_CHILDREN;
	}

	if (n > 0) {
		r = prefork_add_children(ev_ctx, pfp, n);
		if (r < n) {
			DEBUG(10, ("Tried to start %d children but only,"
				   "%d were actually started.!\n", n, r));
		}
	}


}

static bool spoolssd_setup_sig_chld_handler(struct tevent_context *ev_ctx,
					    struct prefork_pool *pfp)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev_ctx, ev_ctx, SIGCHLD, 0,
				spoolssd_sig_chld_handler, pfp);
	if (!se) {
		DEBUG(0, ("Failed to setup SIGCHLD handler!\n"));
		return false;
	}

	return true;
}

static bool spoolssd_schedule_check(struct tevent_context *ev_ctx,
				    struct prefork_pool *pfp,
				    struct timeval current_time);
static void spoolssd_check_children(struct tevent_context *ev_ctx,
				    struct tevent_timer *te,
				    struct timeval current_time,
				    void *pvt);

static bool spoolssd_setup_children_monitor(struct tevent_context *ev_ctx,
					    struct prefork_pool *pfp)
{
	bool ok;

	ok = spoolssd_setup_sig_chld_handler(ev_ctx, pfp);
	if (!ok) {
		return false;
	}

	ok = spoolssd_schedule_check(ev_ctx, pfp, tevent_timeval_current());
	return ok;
}

static bool spoolssd_schedule_check(struct tevent_context *ev_ctx,
				    struct prefork_pool *pfp,
				    struct timeval current_time)
{
	struct tevent_timer *te;
	struct timeval next_event;

	/* check situation again in 10 seconds */
	next_event = tevent_timeval_current_ofs(10, 0);

	/* check when the socket becomes readable, so that children
	 * are checked only when there is some activity */
	te = tevent_add_timer(ev_ctx, pfp, next_event,
				spoolssd_check_children, pfp);
	if (!te) {
		DEBUG(2, ("Failed to set up children monitoring!\n"));
		return false;
	}

	return true;
}

static void spoolssd_check_children(struct tevent_context *ev_ctx,
				    struct tevent_timer *te,
				    struct timeval current_time,
				    void *pvt)
{
	struct prefork_pool *pfp;
	int active, total;
	int ret, n;

	pfp = talloc_get_type_abort(pvt, struct prefork_pool);

	active = prefork_count_active_children(pfp, &total);

	if (total - active < SPOOLSS_SPAWN_RATE) {
		n = prefork_add_children(ev_ctx, pfp, SPOOLSS_SPAWN_RATE);
		if (n < SPOOLSS_SPAWN_RATE) {
			DEBUG(10, ("Tried to start 5 children but only,"
				   "%d were actually started.!\n", n));
		}
	}

	if (total - active > SPOOLSS_MIN_CHILDREN) {
		if ((total - SPOOLSS_MIN_CHILDREN) >= SPOOLSS_SPAWN_RATE) {
			prefork_retire_children(pfp, SPOOLSS_SPAWN_RATE,
						time(NULL) - SPOOLSS_MIN_LIFE);
		}
	}

	ret = spoolssd_schedule_check(ev_ctx, pfp, current_time);
}

void start_spoolssd(struct tevent_context *ev_ctx,
		    struct messaging_context *msg_ctx)
{
	struct prefork_pool *pool;
	struct rpc_srv_callbacks spoolss_cb;
	struct dcerpc_binding_vector *v;
	TALLOC_CTX *mem_ctx;
	pid_t pid;
	NTSTATUS status;
	int listen_fd;
	int ret;
	bool ok;

	DEBUG(1, ("Forking SPOOLSS Daemon\n"));

	pid = sys_fork();

	if (pid == -1) {
		DEBUG(0, ("Failed to fork SPOOLSS [%s], aborting ...\n",
			   strerror(errno)));
		exit(1);
	}

	if (pid) {
		/* parent */
		return;
	}

	/* child */
	close_low_fds(false);

	status = reinit_after_fork(msg_ctx,
				   ev_ctx,
				   procid_self(), true);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		smb_panic("reinit_after_fork() failed");
	}

	spoolss_reopen_logs();

	/* the listening fd must be created before the children are actually
	 * forked out. */
	listen_fd = create_named_pipe_socket(SPOOLSS_PIPE_NAME);
	if (listen_fd == -1) {
		exit(1);
	}

	ret = listen(listen_fd, SPOOLSS_MAX_CHILDREN);
	if (ret == -1) {
		DEBUG(0, ("Failed to listen on spoolss pipe - %s\n",
			  strerror(errno)));
		exit(1);
	}


	/* start children before any more initialization is done */
	ok = prefork_create_pool(ev_ctx, ev_ctx, listen_fd,
				 SPOOLSS_MIN_CHILDREN,
				 SPOOLSS_MAX_CHILDREN,
				 &spoolss_children_main, NULL,
				 &pool);

	spoolss_setup_sig_term_handler(ev_ctx);
	spoolss_setup_sig_hup_handler(ev_ctx, msg_ctx);

	if (!serverid_register(procid_self(),
				FLAG_MSG_GENERAL|FLAG_MSG_SMBD
				|FLAG_MSG_PRINT_GENERAL)) {
		exit(1);
	}

	if (!locking_init()) {
		exit(1);
	}

	messaging_register(msg_ctx, NULL,
			   MSG_PRINTER_UPDATE, print_queue_receive);
	messaging_register(msg_ctx, ev_ctx,
			   MSG_SMB_CONF_UPDATED, smb_conf_updated);

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		exit(1);
	}

	/*
	 * Initialize spoolss with an init function to convert printers first.
	 * static_init_rpc will try to initialize the spoolss server too but you
	 * can't register it twice.
	 */
	spoolss_cb.init = spoolss_init_cb;
	spoolss_cb.shutdown = spoolss_shutdown_cb;
	spoolss_cb.private_data = msg_ctx;

	status = rpc_winreg_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register winreg rpc inteface! (%s)\n",
			  nt_errstr(status)));
		exit(1);
	}

	status = rpc_spoolss_init(&spoolss_cb);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register spoolss rpc inteface! (%s)\n",
			  nt_errstr(status)));
		exit(1);
	}

	status = dcerpc_binding_vector_new(mem_ctx, &v);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to create binding vector (%s)\n",
			  nt_errstr(status)));
		exit(1);
	}

	status = dcerpc_binding_vector_add_np_default(&ndr_table_spoolss, v);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to add np to binding vector (%s)\n",
			  nt_errstr(status)));
		exit(1);
	}

	status = rpc_ep_register(ev_ctx, msg_ctx, &ndr_table_spoolss, v);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register spoolss endpoint! (%s)\n",
			  nt_errstr(status)));
		exit(1);
	}

	talloc_free(mem_ctx);

	ok = spoolssd_setup_children_monitor(ev_ctx, pool);
	if (!ok) {
		DEBUG(0, ("Failed to setup children monitoring!\n"));
		exit(1);
	}

	reload_printers(ev_ctx, msg_ctx);

	DEBUG(1, ("SPOOLSS Daemon Started (%d)\n", getpid()));

	/* loop forever */
	ret = tevent_loop_wait(ev_ctx);

	/* should not be reached */
	DEBUG(0,("background_queue: tevent_loop_wait() exited with %d - %s\n",
		 ret, (ret == 0) ? "out of events" : strerror(errno)));
	exit(1);
}
