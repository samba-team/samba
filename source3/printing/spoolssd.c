/*
   Unix SMB/Netbios implementation.
   SPOOLSS Daemon
   Copyright (C) Simo Sorce <idra@samba.org> 2010-2011

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
#include "printing/load.h"
#include "ntdomain.h"
#include "librpc/gen_ndr/srv_winreg.h"
#include "librpc/gen_ndr/srv_spoolss.h"
#include "rpc_server/rpc_server.h"
#include "rpc_server/rpc_ep_register.h"
#include "rpc_server/spoolss/srv_spoolss_nt.h"
#include "librpc/rpc/dcerpc_ep.h"
#include "lib/server_prefork.h"
#include "lib/server_prefork_util.h"

#define SPOOLSS_PIPE_NAME "spoolss"
#define DAEMON_NAME "spoolssd"

static struct server_id parent_id;
static struct prefork_pool *spoolss_pool = NULL;
static int spoolss_child_id = 0;

static struct pf_daemon_config default_pf_spoolss_cfg = {
	.prefork_status = PFH_INIT,
	.min_children = 5,
	.max_children = 25,
	.spawn_rate = 5,
	.max_allowed_clients = 100,
	.child_min_life = 60 /* 1 minute minimum life time */
};
static struct pf_daemon_config pf_spoolss_cfg = { 0 };

pid_t start_spoolssd(struct tevent_context *ev_ctx,
		     struct messaging_context *msg_ctx);

static void spoolss_reopen_logs(int child_id)
{
	char *lfile = lp_logfile(talloc_tos());
	char *ext;
	int rc;

	if (child_id) {
		rc = asprintf(&ext, "%s.%d", DAEMON_NAME, child_id);
	} else {
		rc = asprintf(&ext, "%s", DAEMON_NAME);
	}

	if (rc == -1) {
		return;
	}

	rc = 0;
	if (lfile == NULL || lfile[0] == '\0') {
		rc = asprintf(&lfile, "%s/log.%s",
			      get_dyn_LOGFILEBASE(), ext);
	} else {
		if (strstr(lfile, ext) == NULL) {
			if (child_id) {
				rc = asprintf(&lfile, "%s.%d",
					      lp_logfile(talloc_tos()),
					      child_id);
			} else {
				rc = asprintf(&lfile, "%s.%s",
					      lp_logfile(talloc_tos()),
					      ext);
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
	load_printers(ev, msg);

	spoolss_reopen_logs(spoolss_child_id);
	if (spoolss_child_id == 0) {
		pfh_daemon_config(DAEMON_NAME,
				  &pf_spoolss_cfg,
				  &default_pf_spoolss_cfg);
		pfh_manage_pool(ev, msg, &pf_spoolss_cfg, spoolss_pool);
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
	delete_and_reload_printers(ev_ctx, msg_ctx);
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

static void spoolss_chld_sig_hup_handler(struct tevent_context *ev,
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
	load_printers(ev, msg_ctx);
	spoolss_reopen_logs(spoolss_child_id);
}

static bool spoolss_setup_chld_hup_handler(struct tevent_context *ev_ctx,
					   struct messaging_context *msg_ctx,
					   struct pf_worker_data *pf)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev_ctx,
			       ev_ctx,
			       SIGHUP, 0,
			       spoolss_chld_sig_hup_handler,
			       msg_ctx);
	if (!se) {
		DEBUG(1, ("failed to setup SIGHUP handler"));
		return false;
	}

	return true;
}

static void parent_ping(struct messaging_context *msg_ctx,
			void *private_data,
			uint32_t msg_type,
			struct server_id server_id,
			DATA_BLOB *data)
{

	/* The fact we received this message is enough to let make the event
	 * loop if it was idle. spoolss_children_main will cycle through
	 * spoolss_next_client at least once. That function will take whatever
	 * action is necessary */

	DEBUG(10, ("Got message that the parent changed status.\n"));
	return;
}

static bool spoolss_child_init(struct tevent_context *ev_ctx,
			       int child_id, struct pf_worker_data *pf)
{
	NTSTATUS status;
	struct rpc_srv_callbacks spoolss_cb;
	struct messaging_context *msg_ctx = messaging_init(NULL, ev_ctx);
	bool ok;

	status = reinit_after_fork(msg_ctx, ev_ctx,
				   true);
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
	messaging_register(msg_ctx, ev_ctx,
			   MSG_PREFORK_PARENT_EVENT, parent_ping);

	/* As soon as messaging is up check if pcap has been loaded already.
	 * If so then we probably missed a message and should load_printers()
	 * ourselves. If pcap has not been loaded yet, then ignore, we will get
	 * a message as soon as the bq process completes the reload. */
	if (pcap_cache_loaded()) {
		load_printers(ev_ctx, msg_ctx);
	}

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

	return true;
}

struct spoolss_children_data {
	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;
	struct pf_worker_data *pf;
	int listen_fd_size;
	int *listen_fds;
};

static void spoolss_next_client(void *pvt);

static int spoolss_children_main(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx,
				 struct pf_worker_data *pf,
				 int child_id,
				 int listen_fd_size,
				 int *listen_fds,
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
	data->listen_fd_size = listen_fd_size;
	data->listen_fds = listen_fds;

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

	pfh_client_terminated(data->pf);

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

	if (!pfh_child_allowed_to_accept(data->pf)) {
		/* nothing to do for now we are already listening
		 * or we are not allowed to listen further */
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
				  data->listen_fds);
	if (!req) {
		DEBUG(1, ("Failed to make listening request!?\n"));
		talloc_free(next);
		return;
	}
	tevent_req_set_callback(req, spoolss_handle_client, next);
}

static void spoolss_handle_client(struct tevent_req *req)
{
	struct spoolss_children_data *data;
	struct spoolss_new_client *client;
	const DATA_BLOB ping = data_blob_null;
	int ret;
	int sd;

	client = tevent_req_callback_data(req, struct spoolss_new_client);
	data = client->data;

	ret = prefork_listen_recv(req, client, &sd,
				  &client->srv_addr, &client->cli_addr);

	/* this will free the request too */
	talloc_free(client);

	if (ret != 0) {
		DEBUG(6, ("No client connection was available after all!\n"));
		return;
	}

	/* Warn parent that our status changed */
	messaging_send(data->msg_ctx, parent_id,
			MSG_PREFORK_CHILD_EVENT, &ping);

	DEBUG(2, ("Spoolss preforked child %d got client connection!\n",
		  (int)(data->pf->pid)));

	named_pipe_accept_function(data->ev_ctx, data->msg_ctx,
				   SPOOLSS_PIPE_NAME, sd,
				   spoolss_client_terminated, data);
}

/* ==== Main Process Functions ==== */

extern pid_t background_lpq_updater_pid;
static char *bq_logfile;

static void check_updater_child(struct tevent_context *ev_ctx,
				struct messaging_context *msg_ctx)
{
	int status;
	pid_t pid;

	if (background_lpq_updater_pid == -1) {
		return;
	}

	pid = sys_waitpid(background_lpq_updater_pid, &status, WNOHANG);
	if (pid > 0) {
		DEBUG(2, ("The background queue child died... Restarting!\n"));
		pid = start_background_queue(ev_ctx, msg_ctx, bq_logfile);
		background_lpq_updater_pid = pid;
	}
}

static void child_ping(struct messaging_context *msg_ctx,
			void *private_data,
			uint32_t msg_type,
			struct server_id server_id,
			DATA_BLOB *data)
{
	struct tevent_context *ev_ctx;

	ev_ctx = talloc_get_type_abort(private_data, struct tevent_context);

	DEBUG(10, ("Got message that a child changed status.\n"));
	pfh_manage_pool(ev_ctx, msg_ctx, &pf_spoolss_cfg, spoolss_pool);
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

	msg_ctx = talloc_get_type_abort(pvt, struct messaging_context);

	/* run pool management so we can fork/retire or increase
	 * the allowed connections per child based on load */
	pfh_manage_pool(ev_ctx, msg_ctx, &pf_spoolss_cfg, spoolss_pool);

	/* also check if the updater child is alive and well */
	check_updater_child(ev_ctx, msg_ctx);
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

	msg_ctx = talloc_get_type_abort(pvt, struct messaging_context);

	pfh_manage_pool(ev_ctx, msg_ctx, &pf_spoolss_cfg, spoolss_pool);

	spoolssd_schedule_check(ev_ctx, msg_ctx, current_time);
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

static char *get_bq_logfile(void)
{
	char *lfile = lp_logfile(talloc_tos());
	int rc;

	if (lfile == NULL || lfile[0] == '\0') {
		rc = asprintf(&lfile, "%s/log.%s.bq",
					get_dyn_LOGFILEBASE(), DAEMON_NAME);
	} else {
		rc = asprintf(&lfile, "%s.bq", lp_logfile(talloc_tos()));
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

	pid = fork();

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

	status = reinit_after_fork(msg_ctx,
				   ev_ctx,
				   true);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		smb_panic("reinit_after_fork() failed");
	}

	/* save the parent process id so the children can use it later */
	parent_id = procid_self();

	spoolss_reopen_logs(0);
	pfh_daemon_config(DAEMON_NAME,
			  &pf_spoolss_cfg,
			  &default_pf_spoolss_cfg);

	spoolss_setup_sig_term_handler(ev_ctx);
	spoolss_setup_sig_hup_handler(ev_ctx, msg_ctx);

	BlockSignals(false, SIGTERM);
	BlockSignals(false, SIGHUP);

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

	ret = listen(listen_fd, pf_spoolss_cfg.max_allowed_clients);
	if (ret == -1) {
		DEBUG(0, ("Failed to listen on spoolss pipe - %s\n",
			  strerror(errno)));
		exit(1);
	}

	/* start children before any more initialization is done */
	ok = prefork_create_pool(ev_ctx, /* mem_ctx */
				 ev_ctx, msg_ctx,
				 1, &listen_fd,
				 pf_spoolss_cfg.min_children,
				 pf_spoolss_cfg.max_children,
				 &spoolss_children_main, NULL,
				 &spoolss_pool);
	if (!ok) {
		exit(1);
	}

	if (!serverid_register(procid_self(),
				FLAG_MSG_GENERAL |
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
	messaging_register(msg_ctx, ev_ctx,
			   MSG_PREFORK_CHILD_EVENT, child_ping);

	/* As soon as messaging is up check if pcap has been loaded already.
	 * If so then we probably missed a message and should load_printers()
	 * ourselves. If pcap has not been loaded yet, then ignore, we will get
	 * a message as soon as the bq process completes the reload. */
	if (pcap_cache_loaded()) {
		load_printers(ev_ctx, msg_ctx);
	}

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

	pfh_manage_pool(ev_ctx, msg_ctx, &pf_spoolss_cfg, spoolss_pool);

	/* loop forever */
	ret = tevent_loop_wait(ev_ctx);

	/* should not be reached */
	DEBUG(0,("spoolssd tevent_loop_wait() exited with %d - %s\n",
		 ret, (ret == 0) ? "out of events" : strerror(errno)));
	exit(1);
}
