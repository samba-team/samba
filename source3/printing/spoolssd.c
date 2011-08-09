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
#include "printing/queue_process.h"
#include "printing/pcap.h"
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

#define SPOOLSS_INIT     0x00
#define SPOOLSS_NEW_MAX  0x01
#define SPOLLSS_ENOSPC   0x02

static struct prefork_pool *spoolss_pool;
static int spoolss_min_children;
static int spoolss_max_children;
static int spoolss_spawn_rate;
static int spoolss_prefork_status;
static int spoolss_child_id = 0;

static void spoolss_prefork_config(void)
{
	static int spoolss_prefork_config_init = false;
	const char *prefork_str;
	int min, max, rate;
	bool use_defaults = false;
	int ret;

	if (!spoolss_prefork_config_init) {
		spoolss_pool = NULL;
		spoolss_prefork_status = SPOOLSS_INIT;
		spoolss_min_children = 0;
		spoolss_max_children = 0;
		spoolss_spawn_rate = 0;
		spoolss_prefork_config_init = true;
	}

	prefork_str = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "spoolssd", "prefork", "none");
	if (strcmp(prefork_str, "none") == 0) {
		use_defaults = true;
	} else {
		ret = sscanf(prefork_str, "%d:%d:%d", &min, &max, &rate);
		if (ret != 3) {
			DEBUG(0, ("invalid format for spoolssd:prefork!\n"));
			use_defaults = true;
		}
	}

	if (use_defaults) {
		min = SPOOLSS_MIN_CHILDREN;
		max = SPOOLSS_MAX_CHILDREN;
		rate = SPOOLSS_SPAWN_RATE;
	}

	if (max > spoolss_max_children && spoolss_max_children != 0) {
		spoolss_prefork_status |= SPOOLSS_NEW_MAX;
	}

	spoolss_min_children = min;
	spoolss_max_children = max;
	spoolss_spawn_rate = rate;
}

static void spoolss_reopen_logs(int child_id)
{
	char *lfile = lp_logfile();
	char *ext;
	int rc;

	if (child_id) {
		rc = asprintf(&ext, ".%s.%d", DAEMON_NAME, child_id);
	} else {
		rc = asprintf(&ext, ".%s", DAEMON_NAME);
	}

	if (rc == -1) {
		/* if we can't allocate, set it to NULL
		 * and logging will flow in the original file */
		ext = NULL;
	}

	rc = 0;
	if (lfile == NULL || lfile[0] == '\0') {
		rc = asprintf(&lfile, "%s/log%s",
			      get_dyn_LOGFILEBASE(), ext?ext:"");
	} else {
		if (ext && strstr(lfile, ext) == NULL) {
			if (strstr(lfile, DAEMON_NAME) == NULL) {
				rc = asprintf(&lfile, "%s%s",
					      lp_logfile(), ext?ext:"");
			} else {
				rc = asprintf(&lfile, "%s.%d",
					      lp_logfile(), child_id);
			}
		}
	}

	if (rc > 0) {
		lp_set_logfile(lfile);
		SAFE_FREE(lfile);
	}

	SAFE_FREE(ext);

	reopen_logs();
}

static void update_conf(struct tevent_context *ev,
			struct messaging_context *msg)
{
	change_to_root_user();
	lp_load(get_dyn_CONFIGFILE(), true, false, false, true);
	reload_printers(ev, msg);

	spoolss_reopen_logs(spoolss_child_id);
	if (spoolss_child_id == 0) {
		spoolss_prefork_config();
	}
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
	update_conf(ev_ctx, msg);
}

static void update_pcap(struct tevent_context *ev_ctx,
			struct messaging_context *msg_ctx)
{
	change_to_root_user();
	reload_printers(ev_ctx, msg_ctx);
}

static void pcap_updated(struct messaging_context *msg,
			 void *private_data,
			 uint32_t msg_type,
			 struct server_id server_id,
			 DATA_BLOB *data)
{
	struct tevent_context *ev_ctx;

	ev_ctx = talloc_get_type_abort(private_data, struct tevent_context);

	DEBUG(10, ("Got message that pcap updated. Reloading.\n"));
	update_pcap(ev_ctx, msg);
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

	DEBUG(1,("Reloading printers after SIGHUP\n"));
	update_conf(ev, msg_ctx);

	/* relay to all children */
	if (spoolss_pool) {
		prefork_send_signal_to_all(spoolss_pool, SIGHUP);
	}
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

/* Children */

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
	spoolss_reopen_logs(spoolss_child_id);
}

static bool spoolss_setup_chld_hup_handler(struct tevent_context *ev_ctx,
					   struct messaging_context *msg_ctx,
					   struct pf_worker_data *pf)
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
			       int child_id, struct pf_worker_data *pf)
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

	spoolss_child_id = child_id;
	spoolss_reopen_logs(child_id);

	ok = spoolss_setup_chld_hup_handler(ev_ctx, msg_ctx, pf);
	if (!ok) {
		return false;
	}

	if (!serverid_register(procid_self(),
				FLAG_MSG_GENERAL |
				FLAG_MSG_PRINT_NOTIFY |
				FLAG_MSG_PRINT_GENERAL)) {
		return false;
	}

	if (!locking_init()) {
		return false;
	}

	messaging_register(msg_ctx, ev_ctx,
			   MSG_SMB_CONF_UPDATED, smb_conf_updated);
	messaging_register(msg_ctx, ev_ctx, MSG_PRINTER_PCAP,
			   pcap_updated);

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

	pcap_cache_reload(ev_ctx, msg_ctx, &update_pcap);

	return true;
}

struct spoolss_children_data {
	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;
	struct pf_worker_data *pf;
	int listen_fd_size;
	int *listen_fds;
	int lock_fd;

	bool listening;
};

static void spoolss_next_client(void *pvt);

static int spoolss_children_main(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx,
				 struct pf_worker_data *pf,
				 int child_id,
				 int listen_fd_size,
				 int *listen_fds,
				 int lock_fd,
				 void *private_data)
{
	struct spoolss_children_data *data;
	bool ok;
	int ret;

	ok = spoolss_child_init(ev_ctx, child_id, pf);
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
	data->listen_fd_size = listen_fd_size;
	data->listen_fds = listen_fds;
	data->listening = false;

	/* loop until it is time to exit */
	while (pf->status != PF_WORKER_EXITING) {
		/* try to see if it is time to schedule the next client */
		spoolss_next_client(data);

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

	spoolss_next_client(pvt);
}

struct spoolss_new_client {
	struct spoolss_children_data *data;
	struct tsocket_address *srv_addr;
	struct tsocket_address *cli_addr;
};

static void spoolss_handle_client(struct tevent_req *req);

static void spoolss_next_client(void *pvt)
{
	struct tevent_req *req;
	struct spoolss_children_data *data;
	struct spoolss_new_client *next;

	data = talloc_get_type_abort(pvt, struct spoolss_children_data);

	if (data->pf->num_clients == 0) {
		data->pf->status = PF_WORKER_IDLE;
	}

	if (data->pf->cmds == PF_SRV_MSG_EXIT) {
		DEBUG(2, ("Parent process commands we terminate!\n"));
		return;
	}

	if (data->listening ||
	    data->pf->num_clients >= data->pf->allowed_clients) {
		/* nothing to do for now we are already listening
		 * or reached the number of clients we are allowed
		 * to handle in parallel */
		return;
	}

	next = talloc_zero(data, struct spoolss_new_client);
	if (!next) {
		DEBUG(1, ("Out of memory!?\n"));
		return;
	}
	next->data = data;

	req = prefork_listen_send(next, data->ev_ctx, data->pf,
				  data->listen_fd_size,
				  data->listen_fds,
				  data->lock_fd);
	if (!req) {
		DEBUG(1, ("Failed to make listening request!?\n"));
		talloc_free(next);
		return;
	}
	tevent_req_set_callback(req, spoolss_handle_client, next);

	data->listening = true;
}

static void spoolss_handle_client(struct tevent_req *req)
{
	struct spoolss_children_data *data;
	struct spoolss_new_client *client;
	int ret;
	int sd;

	client = tevent_req_callback_data(req, struct spoolss_new_client);
	data = client->data;

	ret = prefork_listen_recv(req, client, &sd,
				  &client->srv_addr, &client->cli_addr);

	/* this will free the request too */
	talloc_free(client);
	/* we are done listening */
	data->listening = false;

	if (ret > 0) {
		DEBUG(1, ("Failed to accept client connection!\n"));
		/* bail out if we are not serving any other client */
		if (data->pf->num_clients == 0) {
			data->pf->status = PF_WORKER_EXITING;
		}
		return;
	}

	if (ret == -2) {
		DEBUG(1, ("Server asks us to die!\n"));
		data->pf->status = PF_WORKER_EXITING;
		return;
	}

	DEBUG(2, ("Spoolss preforked child %d got client connection!\n",
		  (int)(data->pf->pid)));

	named_pipe_accept_function(data->ev_ctx, data->msg_ctx,
				   SPOOLSS_PIPE_NAME, sd,
				   spoolss_client_terminated, data);
}

/* ==== Main Process Functions ==== */

extern pid_t background_lpq_updater_pid;
static char *bq_logfile;

static void check_updater_child(void)
{
	int status;
	pid_t pid;

	if (background_lpq_updater_pid == -1) {
		return;
	}

	pid = sys_waitpid(background_lpq_updater_pid, &status, WNOHANG);
	if (pid > 0) {
		DEBUG(2, ("The background queue child died... Restarting!\n"));
		pid = start_background_queue(server_event_context(),
					     server_messaging_context(),
					     bq_logfile);
		background_lpq_updater_pid = pid;
	}
}

static bool spoolssd_schedule_check(struct tevent_context *ev_ctx,
				    struct messaging_context *msg_ctx,
				    struct timeval current_time);
static void spoolssd_check_children(struct tevent_context *ev_ctx,
				    struct tevent_timer *te,
				    struct timeval current_time,
				    void *pvt);

static void spoolssd_sigchld_handler(struct tevent_context *ev_ctx,
				     struct prefork_pool *pfp,
				     void *pvt)
{
	struct messaging_context *msg_ctx;
	int active, total;
	int n, r;

	msg_ctx = talloc_get_type_abort(pvt, struct messaging_context);

	/* now check we do not descend below the minimum */
	active = prefork_count_active_children(pfp, &total);

	n = 0;
	if (total < spoolss_min_children) {
		n = total - spoolss_min_children;
	} else if (total - active < (total / 4)) {
		n = spoolss_min_children;
	}

	if (n > 0) {
		r = prefork_add_children(ev_ctx, msg_ctx, pfp, n);
		if (r < n) {
			DEBUG(10, ("Tried to start %d children but only,"
				   "%d were actually started.!\n", n, r));
		}
	}

	/* also check if the updater child is alive and well */
	check_updater_child();
}

static bool spoolssd_setup_children_monitor(struct tevent_context *ev_ctx,
					    struct messaging_context *msg_ctx)
{
	bool ok;

	/* add our oun sigchld callback */
	prefork_set_sigchld_callback(spoolss_pool,
				     spoolssd_sigchld_handler, msg_ctx);

	ok = spoolssd_schedule_check(ev_ctx, msg_ctx,
				     tevent_timeval_current());
	return ok;
}

static bool spoolssd_schedule_check(struct tevent_context *ev_ctx,
				    struct messaging_context *msg_ctx,
				    struct timeval current_time)
{
	struct tevent_timer *te;
	struct timeval next_event;

	/* check situation again in 10 seconds */
	next_event = tevent_timeval_current_ofs(10, 0);

	/* TODO: check when the socket becomes readable, so that children
	 * are checked only when there is some activity ? */
	te = tevent_add_timer(ev_ctx, spoolss_pool, next_event,
				spoolssd_check_children, msg_ctx);
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
	struct messaging_context *msg_ctx;
	time_t now = time(NULL);
	int active, total;
	int ret, n;

	msg_ctx = talloc_get_type_abort(pvt, struct messaging_context);

	if ((spoolss_prefork_status & SPOOLSS_NEW_MAX) &&
	    !(spoolss_prefork_status & SPOLLSS_ENOSPC)) {
		ret = prefork_expand_pool(spoolss_pool, spoolss_max_children);
		if (ret == ENOSPC) {
			spoolss_prefork_status |= SPOLLSS_ENOSPC;
		}
		spoolss_prefork_status &= ~SPOOLSS_NEW_MAX;
	}

	active = prefork_count_active_children(spoolss_pool, &total);

	if (total - active < spoolss_spawn_rate) {
		n = prefork_add_children(ev_ctx, msg_ctx,
					 spoolss_pool, spoolss_spawn_rate);
		if (n < spoolss_spawn_rate) {
			DEBUG(10, ("Tried to start 5 children but only,"
				   "%d were actually started.!\n", n));
		}
	}

	if (total - active > spoolss_min_children) {
		if ((total - spoolss_min_children) >= spoolss_spawn_rate) {
			prefork_retire_children(spoolss_pool,
						spoolss_spawn_rate,
						now - SPOOLSS_MIN_LIFE);
		}
	}

	ret = spoolssd_schedule_check(ev_ctx, msg_ctx, current_time);
}

static void print_queue_forward(struct messaging_context *msg,
				void *private_data,
				uint32_t msg_type,
				struct server_id server_id,
				DATA_BLOB *data)
{
	messaging_send_buf(msg, pid_to_procid(background_lpq_updater_pid),
			   MSG_PRINTER_UPDATE, data->data, data->length);
}

char *get_bq_logfile(void)
{
	char *lfile = lp_logfile();
	int rc;

	if (lfile == NULL || lfile[0] == '\0') {
		rc = asprintf(&lfile, "%s/log.%s.bq",
					get_dyn_LOGFILEBASE(), DAEMON_NAME);
	} else {
		rc = asprintf(&lfile, "%s.bq", lp_logfile());
	}
	if (rc == -1) {
		lfile = NULL;
	}
	return lfile;
}

pid_t start_spoolssd(struct tevent_context *ev_ctx,
		    struct messaging_context *msg_ctx)
{
	struct rpc_srv_callbacks spoolss_cb;
	struct dcerpc_binding_vector *v;
	TALLOC_CTX *mem_ctx;
	pid_t pid;
	NTSTATUS status;
	int listen_fd;
	int ret;
	bool ok;

	DEBUG(1, ("Forking SPOOLSS Daemon\n"));

	/*
	 * Block signals before forking child as it will have to
	 * set its own handlers. Child will re-enable SIGHUP as
	 * soon as the handlers are set up.
	 */
	BlockSignals(true, SIGTERM);
	BlockSignals(true, SIGHUP);

	pid = sys_fork();

	if (pid == -1) {
		DEBUG(0, ("Failed to fork SPOOLSS [%s]\n",
			   strerror(errno)));
	}

	/* parent or error */
	if (pid != 0) {

		/* Re-enable SIGHUP before returnig */
		BlockSignals(false, SIGTERM);
		BlockSignals(false, SIGHUP);
		return pid;
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

	spoolss_reopen_logs(0);
	spoolss_prefork_config();

	spoolss_setup_sig_term_handler(ev_ctx);
	spoolss_setup_sig_hup_handler(ev_ctx, msg_ctx);

	BlockSignals(false, SIGTERM);
	BlockSignals(false, SIGHUP);

	/* Publish nt printers, this requires a working winreg pipe */
	pcap_cache_reload(ev_ctx, msg_ctx, &reload_printers);

	/* always start the backgroundqueue listner in spoolssd */
	bq_logfile = get_bq_logfile();
	pid = start_background_queue(ev_ctx, msg_ctx, bq_logfile);
	if (pid > 0) {
		background_lpq_updater_pid = pid;
	}

	/* the listening fd must be created before the children are actually
	 * forked out. */
	listen_fd = create_named_pipe_socket(SPOOLSS_PIPE_NAME);
	if (listen_fd == -1) {
		exit(1);
	}

	ret = listen(listen_fd, spoolss_max_children);
	if (ret == -1) {
		DEBUG(0, ("Failed to listen on spoolss pipe - %s\n",
			  strerror(errno)));
		exit(1);
	}

	/* start children before any more initialization is done */
	ok = prefork_create_pool(ev_ctx, /* mem_ctx */
				 ev_ctx, msg_ctx,
				 1, &listen_fd,
				 spoolss_min_children,
				 spoolss_max_children,
				 &spoolss_children_main, NULL,
				 &spoolss_pool);

	if (!serverid_register(procid_self(),
				FLAG_MSG_GENERAL |
				FLAG_MSG_SMBD |
				FLAG_MSG_PRINT_NOTIFY |
				FLAG_MSG_PRINT_GENERAL)) {
		exit(1);
	}

	if (!locking_init()) {
		exit(1);
	}

	messaging_register(msg_ctx, ev_ctx,
			   MSG_SMB_CONF_UPDATED, smb_conf_updated);
	messaging_register(msg_ctx, NULL, MSG_PRINTER_UPDATE,
			   print_queue_forward);
	messaging_register(msg_ctx, ev_ctx, MSG_PRINTER_PCAP,
			   pcap_updated);

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

	ok = spoolssd_setup_children_monitor(ev_ctx, msg_ctx);
	if (!ok) {
		DEBUG(0, ("Failed to setup children monitoring!\n"));
		exit(1);
	}

	DEBUG(1, ("SPOOLSS Daemon Started (%d)\n", getpid()));

	/* loop forever */
	ret = tevent_loop_wait(ev_ctx);

	/* should not be reached */
	DEBUG(0,("background_queue: tevent_loop_wait() exited with %d - %s\n",
		 ret, (ret == 0) ? "out of events" : strerror(errno)));
	exit(1);
}
