/*
 *  Unix SMB/CIFS implementation.
 *
 *  LSA service daemon
 *
 *  Copyright (c) 2011      Andreas Schneider <asn@samba.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "messages.h"
#include "ntdomain.h"
#include "passdb.h"

#include "lib/id_cache.h"

#include "../lib/tsocket/tsocket.h"
#include "lib/server_prefork.h"
#include "lib/server_prefork_util.h"
#include "librpc/rpc/dcerpc_ep.h"
#include "librpc/rpc/dcesrv_core.h"

#include "rpc_server/rpc_server.h"
#include "rpc_server/rpc_ep_register.h"
#include "rpc_server/rpc_sock_helper.h"
#include "rpc_server/rpc_service_setup.h"

#include "rpc_server/lsasd.h"

#include "librpc/gen_ndr/ndr_lsa_scompat.h"
#include "librpc/gen_ndr/ndr_samr_scompat.h"
#include "librpc/gen_ndr/ndr_netlogon_scompat.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

#define DAEMON_NAME "lsasd"
#define LSASD_MAX_SOCKETS 64

static struct server_id parent_id;
static struct prefork_pool *lsasd_pool = NULL;
static int lsasd_child_id = 0;

static struct pf_daemon_config default_pf_lsasd_cfg = {
	.prefork_status = PFH_INIT,
	.min_children = 5,
	.max_children = 25,
	.spawn_rate = 5,
	.max_allowed_clients = 100,
	.child_min_life = 60 /* 1 minute minimum life time */
};
static struct pf_daemon_config pf_lsasd_cfg = { 0 };

static void lsasd_reopen_logs(int child_id)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *lfile = lp_logfile(talloc_tos(), lp_sub);
	char *extension;
	int rc;

	if (child_id) {
		rc = asprintf(&extension, "%s.%d", DAEMON_NAME, child_id);
	} else {
		rc = asprintf(&extension, "%s", DAEMON_NAME);
	}
	if (rc == -1) {
		return;
	}

	rc = 0;
	if (lfile == NULL || lfile[0] == '\0') {
		rc = asprintf(&lfile, "%s/log.%s",
			      get_dyn_LOGFILEBASE(), extension);
	} else {
		if (strstr(lfile, extension) == NULL) {
			if (child_id) {
				rc = asprintf(&lfile, "%s.%d",
						lp_logfile(talloc_tos(), lp_sub),
						child_id);
			} else {
				rc = asprintf(&lfile, "%s.%s",
						lp_logfile(talloc_tos(), lp_sub),
						extension);
			}
		}
	}

	if (rc > 0) {
		lp_set_logfile(lfile);
		SAFE_FREE(lfile);
	}

	SAFE_FREE(extension);

	reopen_logs();
}

static void lsasd_smb_conf_updated(struct messaging_context *msg,
				  void *private_data,
				  uint32_t msg_type,
				  struct server_id server_id,
				  DATA_BLOB *data)
{
	struct tevent_context *ev_ctx;

	DEBUG(10, ("Got message saying smb.conf was updated. Reloading.\n"));
	ev_ctx = talloc_get_type_abort(private_data, struct tevent_context);

	change_to_root_user();
	lp_load_global(get_dyn_CONFIGFILE());

	lsasd_reopen_logs(lsasd_child_id);
	if (lsasd_child_id == 0) {
		pfh_daemon_config(DAEMON_NAME,
				  &pf_lsasd_cfg,
				  &default_pf_lsasd_cfg);
		pfh_manage_pool(ev_ctx, msg, &pf_lsasd_cfg, lsasd_pool);
	}
}

static void lsasd_sig_term_handler(struct tevent_context *ev,
				  struct tevent_signal *se,
				  int signum,
				  int count,
				  void *siginfo,
				  void *private_data)
{
	exit_server_cleanly("termination signal");
}

static void lsasd_setup_sig_term_handler(struct tevent_context *ev_ctx)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev_ctx,
			       ev_ctx,
			       SIGTERM, 0,
			       lsasd_sig_term_handler,
			       NULL);
	if (!se) {
		exit_server("failed to setup SIGTERM handler");
	}
}

static void lsasd_sig_hup_handler(struct tevent_context *ev,
				    struct tevent_signal *se,
				    int signum,
				    int count,
				    void *siginfo,
				    void *pvt)
{

	change_to_root_user();
	lp_load_global(get_dyn_CONFIGFILE());

	lsasd_reopen_logs(lsasd_child_id);
	pfh_daemon_config(DAEMON_NAME,
			  &pf_lsasd_cfg,
			  &default_pf_lsasd_cfg);

	/* relay to all children */
	prefork_send_signal_to_all(lsasd_pool, SIGHUP);
}

static void lsasd_setup_sig_hup_handler(struct tevent_context *ev_ctx)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev_ctx,
			       ev_ctx,
			       SIGHUP, 0,
			       lsasd_sig_hup_handler,
			       NULL);
	if (!se) {
		DEBUG(0, ("failed to setup SIGHUP handler\n"));
		exit(1);
	}
}

/**********************************************************
 * Children
 **********************************************************/

static void lsasd_chld_sig_hup_handler(struct tevent_context *ev,
					 struct tevent_signal *se,
					 int signum,
					 int count,
					 void *siginfo,
					 void *pvt)
{
	change_to_root_user();
	lsasd_reopen_logs(lsasd_child_id);
}

static bool lsasd_setup_chld_hup_handler(struct tevent_context *ev_ctx)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev_ctx,
			       ev_ctx,
			       SIGHUP, 0,
			       lsasd_chld_sig_hup_handler,
			       NULL);
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
	 * loop if it was idle. lsasd_children_main will cycle through
	 * lsasd_next_client at least once. That function will take whatever
	 * action is necessary */

	DEBUG(10, ("Got message that the parent changed status.\n"));
	return;
}

static bool lsasd_child_init(struct tevent_context *ev_ctx,
			     int child_id,
			     struct pf_worker_data *pf)
{
	NTSTATUS status;
	struct messaging_context *msg_ctx = global_messaging_context();
	bool ok;

	status = reinit_after_fork(msg_ctx, ev_ctx,
				   true, "lsasd-child");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		smb_panic("reinit_after_fork() failed");
	}
	initialize_password_db(true, ev_ctx);

	lsasd_child_id = child_id;
	lsasd_reopen_logs(child_id);

	ok = lsasd_setup_chld_hup_handler(ev_ctx);
	if (!ok) {
		return false;
	}

	messaging_register(msg_ctx, ev_ctx,
			   MSG_SMB_CONF_UPDATED, lsasd_smb_conf_updated);
	messaging_register(msg_ctx, ev_ctx,
			   MSG_PREFORK_PARENT_EVENT, parent_ping);
	id_cache_register_msgs(msg_ctx);

	return true;
}

struct lsasd_children_data {
	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;
	struct dcesrv_context *dce_ctx;
	struct pf_worker_data *pf;
	int listen_fd_size;
	struct pf_listen_fd *listen_fds;
};

static void lsasd_next_client(void *pvt);

static int lsasd_children_main(struct tevent_context *ev_ctx,
			       struct messaging_context *msg_ctx,
			       struct pf_worker_data *pf,
			       int child_id,
			       int listen_fd_size,
			       struct pf_listen_fd *listen_fds,
			       void *private_data)
{
	struct lsasd_children_data *data;
	bool ok;
	int ret = 0;
	struct dcesrv_context *dce_ctx = NULL;

	dce_ctx = talloc_get_type_abort(private_data, struct dcesrv_context);

	ok = lsasd_child_init(ev_ctx, child_id, pf);
	if (!ok) {
		return 1;
	}

	data = talloc(ev_ctx, struct lsasd_children_data);
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
		lsasd_next_client(data);

		ret = tevent_loop_once(ev_ctx);
		if (ret != 0) {
			DEBUG(0, ("tevent_loop_once() exited with %d: %s\n",
				  ret, strerror(errno)));
			pf->status = PF_WORKER_EXITING;
		}
	}

	return ret;
}

static void lsasd_client_terminated(struct dcesrv_connection *conn, void *pvt)
{
	struct lsasd_children_data *data;

	data = talloc_get_type_abort(pvt, struct lsasd_children_data);

	pfh_client_terminated(data->pf);

	lsasd_next_client(pvt);
}

struct lsasd_new_client {
	struct lsasd_children_data *data;
};

static void lsasd_handle_client(struct tevent_req *req);

static void lsasd_next_client(void *pvt)
{
	struct tevent_req *req;
	struct lsasd_children_data *data;
	struct lsasd_new_client *next;

	data = talloc_get_type_abort(pvt, struct lsasd_children_data);

	if (!pfh_child_allowed_to_accept(data->pf)) {
		/* nothing to do for now we are already listening
		 * or we are not allowed to listen further */
		return;
	}

	next = talloc_zero(data, struct lsasd_new_client);
	if (!next) {
		DEBUG(1, ("Out of memory!?\n"));
		return;
	}
	next->data = data;

	req = prefork_listen_send(next,
				  data->ev_ctx,
				  data->pf,
				  data->listen_fd_size,
				  data->listen_fds);
	if (!req) {
		DEBUG(1, ("Failed to make listening request!?\n"));
		talloc_free(next);
		return;
	}
	tevent_req_set_callback(req, lsasd_handle_client, next);
}

static void lsasd_handle_client(struct tevent_req *req)
{
	struct lsasd_children_data *data;
	struct lsasd_new_client *client;
	const DATA_BLOB ping = data_blob_null;
	int rc;
	int sd;
	TALLOC_CTX *tmp_ctx;
	struct tsocket_address *srv_addr;
	struct tsocket_address *cli_addr;
	void *listen_fd_data = NULL;
	struct dcesrv_endpoint *ep = NULL;
	enum dcerpc_transport_t transport;
	dcerpc_ncacn_termination_fn term_fn = NULL;
	void *term_fn_data = NULL;

	client = tevent_req_callback_data(req, struct lsasd_new_client);
	data = client->data;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		DEBUG(1, ("Failed to allocate stackframe!\n"));
		return;
	}

	rc = prefork_listen_recv(req,
				 tmp_ctx,
				 &sd,
				 &listen_fd_data,
				 &srv_addr,
				 &cli_addr);

	/* this will free the request too */
	talloc_free(client);

	if (rc != 0) {
		DEBUG(6, ("No client connection was available after all!\n"));
		goto done;
	}

	ep = talloc_get_type_abort(listen_fd_data, struct dcesrv_endpoint);
	transport = dcerpc_binding_get_transport(ep->ep_description);
	if (transport == NCACN_NP) {
		term_fn = lsasd_client_terminated;
		term_fn_data = data;
	}

	/* Warn parent that our status changed */
	messaging_send(data->msg_ctx, parent_id,
			MSG_PREFORK_CHILD_EVENT, &ping);

	DBG_INFO("LSASD preforked child %d got client connection on '%s'\n",
		  (int)(data->pf->pid), dcerpc_binding_string(tmp_ctx,
			  ep->ep_description));

	dcerpc_ncacn_accept(data->ev_ctx,
			    data->msg_ctx,
			    data->dce_ctx,
			    ep,
			    cli_addr,
			    srv_addr,
			    sd,
			    term_fn,
			    term_fn_data);

done:
	talloc_free(tmp_ctx);
}

/*
 * MAIN
 */

static void child_ping(struct messaging_context *msg_ctx,
			void *private_data,
			uint32_t msg_type,
			struct server_id server_id,
			DATA_BLOB *data)
{
	struct tevent_context *ev_ctx;

	ev_ctx = talloc_get_type_abort(private_data, struct tevent_context);

	DEBUG(10, ("Got message that a child changed status.\n"));
	pfh_manage_pool(ev_ctx, msg_ctx, &pf_lsasd_cfg, lsasd_pool);
}

static bool lsasd_schedule_check(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx,
				 struct timeval current_time);

static void lsasd_check_children(struct tevent_context *ev_ctx,
				    struct tevent_timer *te,
				    struct timeval current_time,
				    void *pvt);

static void lsasd_sigchld_handler(struct tevent_context *ev_ctx,
				  struct prefork_pool *pfp,
				  void *pvt)
{
	struct messaging_context *msg_ctx;

	msg_ctx = talloc_get_type_abort(pvt, struct messaging_context);

	/* run pool management so we can fork/retire or increase
	 * the allowed connections per child based on load */
	pfh_manage_pool(ev_ctx, msg_ctx, &pf_lsasd_cfg, lsasd_pool);
}

static bool lsasd_setup_children_monitor(struct tevent_context *ev_ctx,
					 struct messaging_context *msg_ctx)
{
	bool ok;

	/* add our oun sigchld callback */
	prefork_set_sigchld_callback(lsasd_pool, lsasd_sigchld_handler, msg_ctx);

	ok = lsasd_schedule_check(ev_ctx, msg_ctx, tevent_timeval_current());

	return ok;
}

static bool lsasd_schedule_check(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx,
				 struct timeval current_time)
{
	struct tevent_timer *te;
	struct timeval next_event;

	/* check situation again in 10 seconds */
	next_event = tevent_timeval_current_ofs(10, 0);

	/* TODO: check when the socket becomes readable, so that children
	 * are checked only when there is some activity ? */
	te = tevent_add_timer(ev_ctx, lsasd_pool, next_event,
			      lsasd_check_children, msg_ctx);
	if (!te) {
		DEBUG(2, ("Failed to set up children monitoring!\n"));
		return false;
	}

	return true;
}

static void lsasd_check_children(struct tevent_context *ev_ctx,
				 struct tevent_timer *te,
				 struct timeval current_time,
				 void *pvt)
{
	struct messaging_context *msg_ctx;

	msg_ctx = talloc_get_type_abort(pvt, struct messaging_context);

	pfh_manage_pool(ev_ctx, msg_ctx, &pf_lsasd_cfg, lsasd_pool);

	lsasd_schedule_check(ev_ctx, msg_ctx, current_time);
}

/*
 * start it up
 */

static NTSTATUS lsasd_create_sockets(struct tevent_context *ev_ctx,
				     struct messaging_context *msg_ctx,
				     struct dcesrv_context *dce_ctx,
				     struct pf_listen_fd *listen_fd,
				     int *listen_fd_size)
{
	NTSTATUS status;
	int i;
	int fd = -1;
	int rc;
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
		rc = listen(listen_fd[i].fd, pf_lsasd_cfg.max_allowed_clients);
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

	for (e = dce_ctx->endpoint_list; e; e = e->next) {
		struct dcesrv_if_list *ifl = NULL;
		for (ifl = e->interface_list; ifl; ifl = ifl->next) {
			status = rpc_ep_register(ev_ctx,
						 msg_ctx,
						 dce_ctx,
						 ifl->iface);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_ERR("Failed to register interface in "
					"endpoint mapper: %s",
					nt_errstr(status));
				goto done;
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

void start_lsasd(struct tevent_context *ev_ctx,
		 struct messaging_context *msg_ctx,
		 struct dcesrv_context *dce_ctx)
{
	NTSTATUS status;
	struct pf_listen_fd listen_fd[LSASD_MAX_SOCKETS];
	int listen_fd_size = 0;
	pid_t pid;
	int rc;
	bool ok;
	const struct dcesrv_endpoint_server *ep_server = NULL;
	const char *ep_servers[] = { "lsarpc", "samr", "netlogon", NULL };

	DEBUG(1, ("Forking LSA Service Daemon\n"));

	/*
	 * Block signals before forking child as it will have to
	 * set its own handlers. Child will re-enable SIGHUP as
	 * soon as the handlers are set up.
	 */
	BlockSignals(true, SIGTERM);
	BlockSignals(true, SIGHUP);

	pid = fork();
	if (pid == -1) {
		DEBUG(0, ("Failed to fork LSASD [%s], aborting ...\n",
			   strerror(errno)));
		exit(1);
	}

	/* parent or error */
	if (pid != 0) {

		/* Re-enable SIGHUP before returnig */
		BlockSignals(false, SIGTERM);
		BlockSignals(false, SIGHUP);

		return;
	}

	status = smbd_reinit_after_fork(msg_ctx, ev_ctx, true, "lsasd-master");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		smb_panic("reinit_after_fork() failed");
	}
	initialize_password_db(true, ev_ctx);

	/* save the parent process id so the children can use it later */
	parent_id = messaging_server_id(msg_ctx);

	lsasd_reopen_logs(0);
	pfh_daemon_config(DAEMON_NAME,
			  &pf_lsasd_cfg,
			  &default_pf_lsasd_cfg);

	lsasd_setup_sig_term_handler(ev_ctx);
	lsasd_setup_sig_hup_handler(ev_ctx);

	BlockSignals(false, SIGTERM);
	BlockSignals(false, SIGHUP);

	DBG_INFO("Registering DCE/RPC endpoint servers\n");

	ep_server = lsarpc_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'lsarpc' endpoint server\n");
		exit(1);
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register 'lsarpc' endpoint server: %s\n",
			nt_errstr(status));
		exit(1);
	}

	ep_server = samr_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'samr' endpoint server\n");
		exit(1);
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register 'samr' endpoint server: %s\n",
			nt_errstr(status));
		exit(1);
	}

	ep_server = netlogon_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'netlogon' endpoint server\n");
		exit(1);
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register 'netlogon' endpoint server: %s\n",
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

	status = lsasd_create_sockets(ev_ctx,
				      msg_ctx,
				      dce_ctx,
				      listen_fd,
				      &listen_fd_size);
	if (!NT_STATUS_IS_OK(status)) {
		exit(1);
	}

	/* start children before any more initialization is done */
	ok = prefork_create_pool(ev_ctx, /* mem_ctx */
				 ev_ctx,
				 msg_ctx,
				 listen_fd_size,
				 listen_fd,
				 pf_lsasd_cfg.min_children,
				 pf_lsasd_cfg.max_children,
				 &lsasd_children_main,
				 dce_ctx,
				 &lsasd_pool);
	if (!ok) {
		exit(1);
	}

	messaging_register(msg_ctx,
			   ev_ctx,
			   MSG_SMB_CONF_UPDATED,
			   lsasd_smb_conf_updated);
	messaging_register(msg_ctx, ev_ctx,
			   MSG_PREFORK_CHILD_EVENT, child_ping);

	ok = lsasd_setup_children_monitor(ev_ctx, msg_ctx);
	if (!ok) {
		DEBUG(0, ("Failed to setup children monitoring!\n"));
		exit(1);
	}

	DEBUG(1, ("LSASD Daemon Started (%u)\n", (unsigned int)getpid()));

	/* loop forever */
	rc = tevent_loop_wait(ev_ctx);

	/* should not be reached */
	DEBUG(0,("lsasd: tevent_loop_wait() exited with %d - %s\n",
		 rc, (rc == 0) ? "out of events" : strerror(errno)));
	exit(1);
}
