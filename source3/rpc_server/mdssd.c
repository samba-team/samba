/*
 *  Unix SMB/CIFS implementation.
 *
 *  mds service daemon
 *
 *  Copyright (c) 2014      Ralph Boehme <rb@sernet.de>
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

#include "lib/id_cache.h"

#include "../lib/tsocket/tsocket.h"
#include "lib/server_prefork.h"
#include "lib/server_prefork_util.h"
#include "librpc/rpc/dcerpc_ep.h"
#include "librpc/rpc/dcesrv_core.h"

#include "rpc_server/rpc_server.h"
#include "rpc_server/rpc_service_setup.h"
#include "rpc_server/rpc_ep_register.h"
#include "rpc_server/rpc_sock_helper.h"
#include "rpc_server/rpc_modules.h"

#include "rpc_server/mdssvc/srv_mdssvc_nt.h"
#include "rpc_server/mdssd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

#define DAEMON_NAME "mdssd"
#define MDSSD_MAX_SOCKETS 64

static struct server_id parent_id;
static struct prefork_pool *mdssd_pool = NULL;
static int mdssd_child_id = 0;

static struct pf_daemon_config default_pf_mdssd_cfg = {
	.prefork_status = PFH_INIT,
	.min_children = 5,
	.max_children = 25,
	.spawn_rate = 5,
	.max_allowed_clients = 1000,
	.child_min_life = 60 /* 1 minute minimum life time */
};
static struct pf_daemon_config pf_mdssd_cfg = { 0 };

static void mdssd_smb_conf_updated(struct messaging_context *msg,
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

	reopen_logs();
	if (mdssd_child_id == 0) {
		pfh_daemon_config(DAEMON_NAME,
				  &pf_mdssd_cfg,
				  &default_pf_mdssd_cfg);
		pfh_manage_pool(ev_ctx, msg, &pf_mdssd_cfg, mdssd_pool);
	}
}

static void mdssd_sig_term_handler(struct tevent_context *ev,
				   struct tevent_signal *se,
				   int signum,
				   int count,
				   void *siginfo,
				   void *private_data)
{
	exit_server_cleanly("termination signal");
}

static void mdssd_setup_sig_term_handler(struct tevent_context *ev_ctx)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev_ctx,
			       ev_ctx,
			       SIGTERM, 0,
			       mdssd_sig_term_handler,
			       NULL);
	if (!se) {
		exit_server("failed to setup SIGTERM handler");
	}
}

static void mdssd_sig_hup_handler(struct tevent_context *ev,
				  struct tevent_signal *se,
				  int signum,
				  int count,
				  void *siginfo,
				  void *pvt)
{

	change_to_root_user();
	lp_load_global(get_dyn_CONFIGFILE());

	reopen_logs();
	pfh_daemon_config(DAEMON_NAME,
			  &pf_mdssd_cfg,
			  &default_pf_mdssd_cfg);

	/* relay to all children */
	prefork_send_signal_to_all(mdssd_pool, SIGHUP);
}

static void mdssd_setup_sig_hup_handler(struct tevent_context *ev_ctx)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev_ctx,
			       ev_ctx,
			       SIGHUP, 0,
			       mdssd_sig_hup_handler,
			       NULL);
	if (!se) {
		DEBUG(0, ("failed to setup SIGHUP handler\n"));
		exit(1);
	}
}

/**********************************************************
 * Children
 **********************************************************/

static void mdssd_chld_sig_hup_handler(struct tevent_context *ev,
				       struct tevent_signal *se,
				       int signum,
				       int count,
				       void *siginfo,
				       void *pvt)
{
	change_to_root_user();
	reopen_logs();
}

static bool mdssd_setup_chld_hup_handler(struct tevent_context *ev_ctx)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev_ctx,
			       ev_ctx,
			       SIGHUP, 0,
			       mdssd_chld_sig_hup_handler,
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
	/*
	 * The fact we received this message is enough to let make the
	 * event loop if it was idle. mdssd_children_main will cycle
	 * through mdssd_next_client at least once. That function will
	 * take whatever action is necessary
	 */
	DEBUG(10, ("Got message that the parent changed status.\n"));
	return;
}

static bool mdssd_child_init(struct tevent_context *ev_ctx,
			     int child_id,
			     struct pf_worker_data *pf)
{
	NTSTATUS status;
	struct messaging_context *msg_ctx = global_messaging_context();
	bool ok;

	status = reinit_after_fork(msg_ctx, ev_ctx,
				   true, "mdssd-child");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		smb_panic("reinit_after_fork() failed");
	}

	mdssd_child_id = child_id;
	reopen_logs();

	ok = mdssd_setup_chld_hup_handler(ev_ctx);
	if (!ok) {
		return false;
	}

	messaging_register(msg_ctx, ev_ctx,
			   MSG_SMB_CONF_UPDATED, mdssd_smb_conf_updated);
	messaging_register(msg_ctx, ev_ctx,
			   MSG_PREFORK_PARENT_EVENT, parent_ping);

	return true;
}

struct mdssd_children_data {
	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;
	struct dcesrv_context *dce_ctx;
	struct pf_worker_data *pf;
	int listen_fd_size;
	struct pf_listen_fd *listen_fds;
};

static void mdssd_next_client(void *pvt);

static int mdssd_children_main(struct tevent_context *ev_ctx,
			       struct messaging_context *msg_ctx,
			       struct pf_worker_data *pf,
			       int child_id,
			       int listen_fd_size,
			       struct pf_listen_fd *listen_fds,
			       void *private_data)
{
	struct mdssd_children_data *data;
	bool ok;
	int ret = 0;
	struct dcesrv_context *dce_ctx = NULL;

	dce_ctx = talloc_get_type_abort(private_data, struct dcesrv_context);

	ok = mdssd_child_init(ev_ctx, child_id, pf);
	if (!ok) {
		return 1;
	}

	data = talloc(ev_ctx, struct mdssd_children_data);
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
		mdssd_next_client(data);

		ret = tevent_loop_once(ev_ctx);
		if (ret != 0) {
			DEBUG(0, ("tevent_loop_once() exited with %d: %s\n",
				  ret, strerror(errno)));
			pf->status = PF_WORKER_EXITING;
		}
	}

	return ret;
}

static void mdssd_client_terminated(struct dcesrv_connection *conn, void *pvt)
{
	struct mdssd_children_data *data;

	data = talloc_get_type_abort(pvt, struct mdssd_children_data);

	pfh_client_terminated(data->pf);

	mdssd_next_client(pvt);
}

struct mdssd_new_client {
	struct mdssd_children_data *data;
};

static void mdssd_handle_client(struct tevent_req *req);

static void mdssd_next_client(void *pvt)
{
	struct tevent_req *req;
	struct mdssd_children_data *data;
	struct mdssd_new_client *next;

	data = talloc_get_type_abort(pvt, struct mdssd_children_data);

	if (!pfh_child_allowed_to_accept(data->pf)) {
		/* nothing to do for now we are already listening
		 * or we are not allowed to listen further */
		return;
	}

	next = talloc_zero(data, struct mdssd_new_client);
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
	tevent_req_set_callback(req, mdssd_handle_client, next);
}

static void mdssd_handle_client(struct tevent_req *req)
{
	struct mdssd_children_data *data;
	struct mdssd_new_client *client;
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

	client = tevent_req_callback_data(req, struct mdssd_new_client);
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
		term_fn = mdssd_client_terminated;
		term_fn_data = data;
	}

	/* Warn parent that our status changed */
	messaging_send(data->msg_ctx, parent_id,
			MSG_PREFORK_CHILD_EVENT, &ping);

	DBG_INFO("MDSSD preforked child %d got client connection on '%s'\n",
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
	pfh_manage_pool(ev_ctx, msg_ctx, &pf_mdssd_cfg, mdssd_pool);
}

static bool mdssd_schedule_check(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx,
				 struct timeval current_time);

static void mdssd_check_children(struct tevent_context *ev_ctx,
				    struct tevent_timer *te,
				    struct timeval current_time,
				    void *pvt);

static void mdssd_sigchld_handler(struct tevent_context *ev_ctx,
				  struct prefork_pool *pfp,
				  void *pvt)
{
	struct messaging_context *msg_ctx;

	msg_ctx = talloc_get_type_abort(pvt, struct messaging_context);

	/* run pool management so we can fork/retire or increase
	 * the allowed connections per child based on load */
	pfh_manage_pool(ev_ctx, msg_ctx, &pf_mdssd_cfg, mdssd_pool);
}

static bool mdssd_setup_children_monitor(struct tevent_context *ev_ctx,
					 struct messaging_context *msg_ctx)
{
	bool ok;

	/* add our oun sigchld callback */
	prefork_set_sigchld_callback(mdssd_pool, mdssd_sigchld_handler, msg_ctx);

	ok = mdssd_schedule_check(ev_ctx, msg_ctx, tevent_timeval_current());

	return ok;
}

static bool mdssd_schedule_check(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx,
				 struct timeval current_time)
{
	struct tevent_timer *te;
	struct timeval next_event;

	/* check situation again in 10 seconds */
	next_event = tevent_timeval_current_ofs(10, 0);

	/* TODO: check when the socket becomes readable, so that children
	 * are checked only when there is some activity ? */
	te = tevent_add_timer(ev_ctx, mdssd_pool, next_event,
			      mdssd_check_children, msg_ctx);
	if (!te) {
		DEBUG(2, ("Failed to set up children monitoring!\n"));
		return false;
	}

	return true;
}

static void mdssd_check_children(struct tevent_context *ev_ctx,
				 struct tevent_timer *te,
				 struct timeval current_time,
				 void *pvt)
{
	struct messaging_context *msg_ctx;

	msg_ctx = talloc_get_type_abort(pvt, struct messaging_context);

	pfh_manage_pool(ev_ctx, msg_ctx, &pf_mdssd_cfg, mdssd_pool);

	mdssd_schedule_check(ev_ctx, msg_ctx, current_time);
}

/*
 * start it up
 */

static NTSTATUS mdssd_create_sockets(struct tevent_context *ev_ctx,
				     struct messaging_context *msg_ctx,
				     struct dcesrv_context *dce_ctx,
				     struct pf_listen_fd *listen_fd,
				     int *listen_fd_size)
{
	NTSTATUS status;
	int fd = -1;
	int rc;
	int i;
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
		rc = listen(listen_fd[i].fd, pf_mdssd_cfg.max_allowed_clients);
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

void start_mdssd(struct tevent_context *ev_ctx,
		 struct messaging_context *msg_ctx,
		 struct dcesrv_context *dce_ctx)
{
	NTSTATUS status;
	struct pf_listen_fd listen_fd[MDSSD_MAX_SOCKETS];
	int listen_fd_size = 0;
	pid_t pid;
	int rc;
	bool ok;

	DEBUG(1, ("Forking Metadata Service Daemon\n"));

	/*
	 * Block signals before forking child as it will have to
	 * set its own handlers. Child will re-enable SIGHUP as
	 * soon as the handlers are set up.
	 */
	BlockSignals(true, SIGTERM);
	BlockSignals(true, SIGHUP);

	pid = fork();
	if (pid == -1) {
		DEBUG(0, ("Failed to fork mdssd [%s], aborting ...\n",
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

	status = smbd_reinit_after_fork(msg_ctx, ev_ctx, true, "mdssd-master");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		smb_panic("reinit_after_fork() failed");
	}

	reopen_logs();

	/* save the parent process id so the children can use it later */
	parent_id = messaging_server_id(msg_ctx);

	pfh_daemon_config(DAEMON_NAME,
			  &pf_mdssd_cfg,
			  &default_pf_mdssd_cfg);

	mdssd_setup_sig_term_handler(ev_ctx);
	mdssd_setup_sig_hup_handler(ev_ctx);

	BlockSignals(false, SIGTERM);
	BlockSignals(false, SIGHUP);

	/* The module setup function will register the endpoint server,
	 * necessary to setup the endpoints below. It is not possible to
	 * register it here because MDS service is built as a module.
	 */
	ok = setup_rpc_module(ev_ctx, msg_ctx, "mdssvc");
	if (!ok) {
		DBG_ERR("Failed to setup DCE/RPC module\n");
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
	status = dcesrv_init_ep_server(dce_ctx, "mdssvc");
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to init DCE/RPC endpoint server: %s\n",
			nt_errstr(status));
		exit(1);
	}

	status = mdssd_create_sockets(ev_ctx,
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
				 pf_mdssd_cfg.min_children,
				 pf_mdssd_cfg.max_children,
				 &mdssd_children_main,
				 dce_ctx,
				 &mdssd_pool);
	if (!ok) {
		exit(1);
	}

	messaging_register(msg_ctx,
			   ev_ctx,
			   MSG_SMB_CONF_UPDATED,
			   mdssd_smb_conf_updated);
	messaging_register(msg_ctx, ev_ctx,
			   MSG_PREFORK_CHILD_EVENT, child_ping);

	ok = mdssd_setup_children_monitor(ev_ctx, msg_ctx);
	if (!ok) {
		exit(1);
	}

	DEBUG(1, ("mdssd Daemon Started (%u)\n", (unsigned int)getpid()));

	/* loop forever */
	rc = tevent_loop_wait(ev_ctx);

	/* should not be reached */
	DEBUG(0,("mdssd: tevent_loop_wait() exited with %d - %s\n",
		 rc, (rc == 0) ? "out of events" : strerror(errno)));
	exit(1);
}
