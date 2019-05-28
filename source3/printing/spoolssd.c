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
#include "smbd/smbd.h"

#include "messages.h"
#include "include/printing.h"
#include "printing/nt_printing_migrate_internal.h"
#include "printing/queue_process.h"
#include "printing/pcap.h"
#include "printing/load.h"
#include "printing/spoolssd.h"
#include "ntdomain.h"
#include "librpc/gen_ndr/ndr_winreg_scompat.h"
#include "librpc/gen_ndr/ndr_spoolss_scompat.h"
#include "rpc_server/rpc_server.h"
#include "rpc_server/rpc_service_setup.h"
#include "rpc_server/rpc_ep_register.h"
#include "rpc_server/rpc_config.h"
#include "rpc_server/spoolss/srv_spoolss_nt.h"
#include "librpc/rpc/dcerpc_ep.h"
#include "librpc/rpc/dcesrv_core.h"
#include "lib/server_prefork.h"
#include "lib/server_prefork_util.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

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

static void spoolss_reopen_logs(int child_id)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *lfile = lp_logfile(talloc_tos(), lp_sub);
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
					      lp_logfile(talloc_tos(), lp_sub),
					      child_id);
			} else {
				rc = asprintf(&lfile, "%s.%s",
					      lp_logfile(talloc_tos(), lp_sub),
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
	lp_load_global(get_dyn_CONFIGFILE());
	load_printers();

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

/* Children */

static void spoolss_chld_sig_hup_handler(struct tevent_context *ev,
					 struct tevent_signal *se,
					 int signum,
					 int count,
					 void *siginfo,
					 void *pvt)
{
	change_to_root_user();
	DEBUG(1,("Reloading printers after SIGHUP\n"));
	load_printers();
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
	struct messaging_context *msg_ctx = global_messaging_context();
	bool ok;

	status = reinit_after_fork(msg_ctx, ev_ctx, true, "spoolssd-child");
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

	if (!locking_init()) {
		return false;
	}

	messaging_register(msg_ctx, ev_ctx,
			   MSG_SMB_CONF_UPDATED, smb_conf_updated);
	messaging_register(msg_ctx, ev_ctx,
			   MSG_PREFORK_PARENT_EVENT, parent_ping);

	/* As soon as messaging is up check if pcap has been loaded already.
	 * If so then we probably missed a message and should load_printers()
	 * ourselves. If pcap has not been loaded yet, then ignore, we will get
	 * a message as soon as the bq process completes the reload. */
	load_printers();

	return true;
}

struct spoolss_children_data {
	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;
	struct dcesrv_context *dce_ctx;
	struct pf_worker_data *pf;
	int listen_fd_size;
	struct pf_listen_fd *listen_fds;
};

static void spoolss_next_client(void *pvt);

static int spoolss_children_main(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx,
				 struct pf_worker_data *pf,
				 int child_id,
				 int listen_fd_size,
				 struct pf_listen_fd *listen_fds,
				 void *private_data)
{
	struct spoolss_children_data *data;
	bool ok;
	int ret = 0;
	struct dcesrv_context *dce_ctx = NULL;

	dce_ctx = talloc_get_type_abort(private_data, struct dcesrv_context);

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
	data->dce_ctx = dce_ctx;
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

static void spoolss_client_terminated(struct dcesrv_connection *conn,
				      void *pvt)
{
	struct spoolss_children_data *data;

	data = talloc_get_type_abort(pvt, struct spoolss_children_data);

	pfh_client_terminated(data->pf);

	spoolss_next_client(pvt);
}

struct spoolss_new_client {
	struct spoolss_children_data *data;
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
	struct tsocket_address *srv_addr = NULL;
	struct tsocket_address *cli_addr = NULL;
	void *listen_fd_data = NULL;
	struct dcesrv_endpoint *ep = NULL;

	client = tevent_req_callback_data(req, struct spoolss_new_client);
	data = client->data;

	ret = prefork_listen_recv(req, data, &sd, &listen_fd_data,
				  &srv_addr, &cli_addr);

	/* this will free the request too */
	talloc_free(client);

	if (ret != 0) {
		DEBUG(6, ("No client connection was available after all!\n"));
		return;
	}

	ep = talloc_get_type_abort(listen_fd_data, struct dcesrv_endpoint);

	/* Warn parent that our status changed */
	messaging_send(data->msg_ctx, parent_id,
			MSG_PREFORK_CHILD_EVENT, &ping);

	DEBUG(2, ("Spoolss preforked child %d got client connection!\n",
		  (int)(data->pf->pid)));

	dcerpc_ncacn_accept(data->ev_ctx,
			    data->msg_ctx,
			    data->dce_ctx,
			    ep,
			    cli_addr,
			    srv_addr,
			    sd,
			    spoolss_client_terminated,
			    data);
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

	pid = waitpid(background_lpq_updater_pid, &status, WNOHANG);
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
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *lfile = lp_logfile(talloc_tos(), lp_sub);
	int rc;

	if (lfile == NULL || lfile[0] == '\0') {
		rc = asprintf(&lfile, "%s/log.%s.bq",
					get_dyn_LOGFILEBASE(), DAEMON_NAME);
	} else {
		rc = asprintf(&lfile, "%s.bq", lp_logfile(talloc_tos(), lp_sub));
	}
	if (rc == -1) {
		lfile = NULL;
	}
	return lfile;
}

static NTSTATUS spoolssd_create_sockets(struct tevent_context *ev_ctx,
		struct messaging_context *msg_ctx,
		struct dcesrv_context *dce_ctx,
		struct pf_listen_fd *listen_fd,
		int *listen_fd_size)
{
	NTSTATUS status;
	int fd = -1;
	int rc;
	enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();
	uint32_t i;
	struct dcesrv_endpoint *e = NULL;

	DBG_INFO("Initializing DCE/RPC connection endpoints\n");

	for (e = dce_ctx->endpoint_list; e; e = e->next) {
		status = dcesrv_create_endpoint_sockets(ev_ctx,
							msg_ctx,
							dce_ctx,
							e,
							listen_fd,
							listen_fd_size);
		if (!NT_STATUS_IS_OK(status)) {
			char *ep_string = dcerpc_binding_string(
					dce_ctx, e->ep_description);
			DBG_ERR("Failed to create endpoint '%s': %s\n",
				ep_string, nt_errstr(status));
			TALLOC_FREE(ep_string);
			goto done;
		}
	}

	for (i = 0; i < *listen_fd_size; i++) {
		rc = listen(listen_fd[i].fd, pf_spoolss_cfg.max_allowed_clients);
		if (rc == -1) {
			char *ep_string = dcerpc_binding_string(
					dce_ctx, e->ep_description);
			DBG_ERR("Failed to listen on endpoint '%s': %s\n",
				ep_string, strerror(errno));
			status = map_nt_error_from_unix(errno);
			TALLOC_FREE(ep_string);
			goto done;
		}
	}

	if (epm_mode != RPC_SERVICE_MODE_DISABLED &&
	    (lp_parm_bool(-1, "rpc_server", "register_embedded_np", false))) {
		for (e = dce_ctx->endpoint_list; e; e = e->next) {
			struct dcesrv_if_list *ifl = NULL;
			for (ifl = e->interface_list; ifl; ifl = ifl->next) {
				status = rpc_ep_register(ev_ctx,
							 msg_ctx,
							 dce_ctx,
							 ifl->iface);
				if (!NT_STATUS_IS_OK(status)) {
					DBG_ERR("Failed to register interface"
						" in endpoint mapper: %s\n",
						nt_errstr(status));
					goto done;
				}
			}
		}
	}

	status = NT_STATUS_OK;
done:
	if (fd != -1) {
		close(fd);
	}

	return status;
}

pid_t start_spoolssd(struct tevent_context *ev_ctx,
		     struct messaging_context *msg_ctx,
		     struct dcesrv_context *dce_ctx)
{
	pid_t pid;
	NTSTATUS status;
	struct pf_listen_fd listen_fds[1];
	int listen_fds_size = 0;
	int ret;
	bool ok;
	const struct dcesrv_endpoint_server *ep_server = NULL;
	const char *ep_servers[] = { "winreg", "spoolss", NULL };

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
		exit(1);
	}

	/* parent or error */
	if (pid != 0) {

		/* Re-enable SIGHUP before returnig */
		BlockSignals(false, SIGTERM);
		BlockSignals(false, SIGHUP);
		return pid;
	}

	status = smbd_reinit_after_fork(msg_ctx, ev_ctx, true,
					"spoolssd-master");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		smb_panic("reinit_after_fork() failed");
	}

	/* save the parent process id so the children can use it later */
	parent_id = messaging_server_id(msg_ctx);

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

	DBG_INFO("Registering DCE/RPC endpoint servers\n");

	ep_server = winreg_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'winreg' endpoint server\n");
		exit(1);
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_COLLISION)) {
		DBG_ERR("Failed to register 'winreg' endpoint server: %s\n",
			nt_errstr(status));
		exit(1);
	}

	ep_server = spoolss_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'spoolss' endpoint server\n");
		exit(1);
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register 'spoolss' endpoint server: %s\n",
			nt_errstr(status));
		exit(1);
	}

	DBG_INFO("Reinitializing DCE/RPC server context\n");

	status = dcesrv_reinit_context(dce_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to reinit DCE/RPC context: %s\n",
			nt_errstr(status));
		exit(1);
	}

	DBG_INFO("Initializing DCE/RPC registered endpoint servers\n");

	/* Init ep servers */
	status = dcesrv_init_ep_servers(dce_ctx, ep_servers);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to init DCE/RPC endpoint server: %s\n",
			nt_errstr(status));
		exit(1);
	}

	/* the listening fd must be created before the children are actually
	 * forked out. */
	status = spoolssd_create_sockets(ev_ctx,
					 msg_ctx,
					 dce_ctx,
					 listen_fds,
					 &listen_fds_size);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to create sockets: %s\n",
			nt_errstr(status));
		exit(1);
	}

	/* start children before any more initialization is done */
	ok = prefork_create_pool(ev_ctx, /* mem_ctx */
				 ev_ctx, msg_ctx,
				 listen_fds_size, listen_fds,
				 pf_spoolss_cfg.min_children,
				 pf_spoolss_cfg.max_children,
				 &spoolss_children_main, dce_ctx,
				 &spoolss_pool);
	if (!ok) {
		exit(1);
	}

	if (!locking_init()) {
		exit(1);
	}

	messaging_register(msg_ctx, ev_ctx,
			   MSG_SMB_CONF_UPDATED, smb_conf_updated);
	messaging_register(msg_ctx, NULL, MSG_PRINTER_UPDATE,
			   print_queue_forward);
	messaging_register(msg_ctx, ev_ctx,
			   MSG_PREFORK_CHILD_EVENT, child_ping);

	/*
	 * As soon as messaging is up check if pcap has been loaded already.
	 * If pcap has not been loaded yet, then ignore, as we will reload on
	 * client enumeration anyway.
	 */
	load_printers();

	ok = spoolssd_setup_children_monitor(ev_ctx, msg_ctx);
	if (!ok) {
		DEBUG(0, ("Failed to setup children monitoring!\n"));
		exit(1);
	}

	DEBUG(1, ("SPOOLSS Daemon Started (%u)\n", (unsigned int)getpid()));

	pfh_manage_pool(ev_ctx, msg_ctx, &pf_spoolss_cfg, spoolss_pool);

	/* loop forever */
	ret = tevent_loop_wait(ev_ctx);

	/* should not be reached */
	DEBUG(0,("spoolssd tevent_loop_wait() exited with %d - %s\n",
		 ret, (ret == 0) ? "out of events" : strerror(errno)));
	exit(1);
}
