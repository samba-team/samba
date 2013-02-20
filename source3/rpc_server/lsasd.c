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
#include "serverid.h"
#include "messages.h"
#include "ntdomain.h"

#include "lib/id_cache.h"

#include "../lib/tsocket/tsocket.h"
#include "lib/server_prefork.h"
#include "lib/server_prefork_util.h"
#include "librpc/rpc/dcerpc_ep.h"

#include "rpc_server/rpc_server.h"
#include "rpc_server/rpc_ep_register.h"
#include "rpc_server/rpc_sock_helper.h"

#include "librpc/gen_ndr/srv_lsa.h"
#include "librpc/gen_ndr/srv_samr.h"
#include "librpc/gen_ndr/srv_netlogon.h"

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

void start_lsasd(struct tevent_context *ev_ctx,
		 struct messaging_context *msg_ctx);

static void lsasd_reopen_logs(int child_id)
{
	char *lfile = lp_logfile(talloc_tos());
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
						lp_logfile(talloc_tos()),
						child_id);
			} else {
				rc = asprintf(&lfile, "%s.%s",
						lp_logfile(talloc_tos()),
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
	lp_load(get_dyn_CONFIGFILE(), true, false, false, true);

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
	rpc_netlogon_shutdown();
	rpc_samr_shutdown();
	rpc_lsarpc_shutdown();

	DEBUG(0, ("termination signal\n"));
	exit(0);
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
		DEBUG(0, ("failed to setup SIGTERM handler\n"));
		exit(1);
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
	lp_load(get_dyn_CONFIGFILE(), true, false, false, true);

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
	struct messaging_context *msg_ctx = server_messaging_context();
	bool ok;

	status = reinit_after_fork(msg_ctx, ev_ctx,
				   true);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		smb_panic("reinit_after_fork() failed");
	}

	lsasd_child_id = child_id;
	lsasd_reopen_logs(child_id);

	ok = lsasd_setup_chld_hup_handler(ev_ctx);
	if (!ok) {
		return false;
	}

	if (!serverid_register(procid_self(), FLAG_MSG_GENERAL)) {
		return false;
	}

	messaging_register(msg_ctx, ev_ctx,
			   MSG_SMB_CONF_UPDATED, lsasd_smb_conf_updated);
	messaging_register(msg_ctx, ev_ctx,
			   MSG_PREFORK_PARENT_EVENT, parent_ping);
	id_cache_register_msgs(msg_ctx);

	status = rpc_lsarpc_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register lsarpc rpc inteface! (%s)\n",
			  nt_errstr(status)));
		return false;
	}

	status = rpc_samr_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register samr rpc inteface! (%s)\n",
			  nt_errstr(status)));
		return false;
	}

	status = rpc_netlogon_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register netlogon rpc inteface! (%s)\n",
			  nt_errstr(status)));
		return false;
	}

	return true;
}

struct lsasd_children_data {
	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;
	struct pf_worker_data *pf;
	int listen_fd_size;
	int *listen_fds;
};

static void lsasd_next_client(void *pvt);

static int lsasd_children_main(struct tevent_context *ev_ctx,
			       struct messaging_context *msg_ctx,
			       struct pf_worker_data *pf,
			       int child_id,
			       int listen_fd_size,
			       int *listen_fds,
			       void *private_data)
{
	struct lsasd_children_data *data;
	bool ok;
	int ret = 0;

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

static void lsasd_client_terminated(void *pvt)
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
				 &srv_addr,
				 &cli_addr);

	/* this will free the request too */
	talloc_free(client);

	if (rc != 0) {
		DEBUG(6, ("No client connection was available after all!\n"));
		goto done;
	}

	/* Warn parent that our status changed */
	messaging_send(data->msg_ctx, parent_id,
			MSG_PREFORK_CHILD_EVENT, &ping);

	DEBUG(2, ("LSASD preforked child %d got client connection!\n",
		  (int)(data->pf->pid)));

	if (tsocket_address_is_inet(srv_addr, "ip")) {
		DEBUG(3, ("Got a tcpip client connection from %s on inteface %s\n",
			   tsocket_address_string(cli_addr, tmp_ctx),
			   tsocket_address_string(srv_addr, tmp_ctx)));

		dcerpc_ncacn_accept(data->ev_ctx,
				    data->msg_ctx,
				    NCACN_IP_TCP,
				    "IP",
				    cli_addr,
				    srv_addr,
				    sd,
				    NULL);
	} else if (tsocket_address_is_unix(srv_addr)) {
		const char *p;
		const char *b;

		p = tsocket_address_unix_path(srv_addr, tmp_ctx);
		if (p == NULL) {
			talloc_free(tmp_ctx);
			return;
		}

		b = strrchr(p, '/');
		if (b != NULL) {
			b++;
		} else {
			b = p;
		}

		if (strstr(p, "/np/")) {
			named_pipe_accept_function(data->ev_ctx,
						   data->msg_ctx,
						   b,
						   sd,
						   lsasd_client_terminated,
						   data);
		} else {
			dcerpc_ncacn_accept(data->ev_ctx,
					    data->msg_ctx,
					    NCALRPC,
					    b,
					    cli_addr,
					    srv_addr,
					    sd,
					    NULL);
		}
	} else {
		DEBUG(0, ("ERROR: Unsupported socket!\n"));
	}

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

static bool lsasd_create_sockets(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx,
				 int *listen_fd,
				 int *listen_fd_size)
{
	struct dcerpc_binding_vector *v, *v_orig;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	uint32_t i;
	int fd = -1;
	int rc;
	bool ok = true;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return false;
	}

	status = dcerpc_binding_vector_new(tmp_ctx, &v_orig);
	if (!NT_STATUS_IS_OK(status)) {
		ok = false;
		goto done;
	}

	/* Create only one tcpip listener for all services */
	status = rpc_create_tcpip_sockets(&ndr_table_lsarpc,
					  v_orig,
					  0,
					  listen_fd,
					  listen_fd_size);
	if (!NT_STATUS_IS_OK(status)) {
		ok = false;
		goto done;
	}

	/* Start to listen on tcpip sockets */
	for (i = 0; i < *listen_fd_size; i++) {
		rc = listen(listen_fd[i], pf_lsasd_cfg.max_allowed_clients);
		if (rc == -1) {
			DEBUG(0, ("Failed to listen on tcpip socket - %s\n",
				  strerror(errno)));
			ok = false;
			goto done;
		}
	}

	/* LSARPC */
	fd = create_named_pipe_socket("lsarpc");
	if (fd < 0) {
		ok = false;
		goto done;
	}

	rc = listen(fd, pf_lsasd_cfg.max_allowed_clients);
	if (rc == -1) {
		DEBUG(0, ("Failed to listen on lsarpc pipe - %s\n",
			  strerror(errno)));
		ok = false;
		goto done;
	}
	listen_fd[*listen_fd_size] = fd;
	(*listen_fd_size)++;

	fd = create_named_pipe_socket("lsass");
	if (fd < 0) {
		ok = false;
		goto done;
	}

	rc = listen(fd, pf_lsasd_cfg.max_allowed_clients);
	if (rc == -1) {
		DEBUG(0, ("Failed to listen on lsass pipe - %s\n",
			  strerror(errno)));
		ok = false;
		goto done;
	}
	listen_fd[*listen_fd_size] = fd;
	(*listen_fd_size)++;

	fd = create_dcerpc_ncalrpc_socket("lsarpc");
	if (fd < 0) {
		ok = false;
		goto done;
	}

	rc = listen(fd, pf_lsasd_cfg.max_allowed_clients);
	if (rc == -1) {
		DEBUG(0, ("Failed to listen on lsarpc ncalrpc - %s\n",
			  strerror(errno)));
		ok = false;
		goto done;
	}
	listen_fd[*listen_fd_size] = fd;
	(*listen_fd_size)++;
	fd = -1;

	v = dcerpc_binding_vector_dup(tmp_ctx, v_orig);
	if (v == NULL) {
		ok = false;
		goto done;
	}

	status = dcerpc_binding_vector_replace_iface(&ndr_table_lsarpc, v);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	status = dcerpc_binding_vector_add_np_default(&ndr_table_lsarpc, v);
	if (!NT_STATUS_IS_OK(status)) {
		ok = false;
		goto done;
	}

	status = dcerpc_binding_vector_add_unix(&ndr_table_lsarpc, v, "lsarpc");
	if (!NT_STATUS_IS_OK(status)) {
		ok = false;
		goto done;
	}

	status = rpc_ep_register(ev_ctx, msg_ctx, &ndr_table_lsarpc, v);
	if (!NT_STATUS_IS_OK(status)) {
		ok = false;
		goto done;
	}

	/* SAMR */
	fd = create_named_pipe_socket("samr");
	if (fd < 0) {
		ok = false;
		goto done;
	}

	rc = listen(fd, pf_lsasd_cfg.max_allowed_clients);
	if (rc == -1) {
		DEBUG(0, ("Failed to listen on samr pipe - %s\n",
			  strerror(errno)));
		ok = false;
		goto done;
	}
	listen_fd[*listen_fd_size] = fd;
	(*listen_fd_size)++;

	fd = create_dcerpc_ncalrpc_socket("samr");
	if (fd < 0) {
		ok = false;
		goto done;
	}

	rc = listen(fd, pf_lsasd_cfg.max_allowed_clients);
	if (rc == -1) {
		DEBUG(0, ("Failed to listen on samr ncalrpc - %s\n",
			  strerror(errno)));
		ok = false;
		goto done;
	}
	listen_fd[*listen_fd_size] = fd;
	(*listen_fd_size)++;
	fd = -1;

	v = dcerpc_binding_vector_dup(tmp_ctx, v_orig);
	if (v == NULL) {
		ok = false;
		goto done;
	}

	status = dcerpc_binding_vector_replace_iface(&ndr_table_samr, v);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	status = dcerpc_binding_vector_add_np_default(&ndr_table_samr, v);
	if (!NT_STATUS_IS_OK(status)) {
		ok = false;
		goto done;
	}

	status = dcerpc_binding_vector_add_unix(&ndr_table_lsarpc, v, "samr");
	if (!NT_STATUS_IS_OK(status)) {
		ok = false;
		goto done;
	}

	status = rpc_ep_register(ev_ctx, msg_ctx, &ndr_table_samr, v);
	if (!NT_STATUS_IS_OK(status)) {
		ok = false;
		goto done;
	}

	/* NETLOGON */
	fd = create_named_pipe_socket("netlogon");
	if (fd < 0) {
		ok = false;
		goto done;
	}

	rc = listen(fd, pf_lsasd_cfg.max_allowed_clients);
	if (rc == -1) {
		DEBUG(0, ("Failed to listen on samr pipe - %s\n",
			  strerror(errno)));
		ok = false;
		goto done;
	}
	listen_fd[*listen_fd_size] = fd;
	(*listen_fd_size)++;

	fd = create_dcerpc_ncalrpc_socket("netlogon");
	if (fd < 0) {
		ok = false;
		goto done;
	}

	rc = listen(fd, pf_lsasd_cfg.max_allowed_clients);
	if (rc == -1) {
		DEBUG(0, ("Failed to listen on netlogon ncalrpc - %s\n",
			  strerror(errno)));
		close(fd);
		ok = false;
		goto done;
	}
	listen_fd[*listen_fd_size] = fd;
	(*listen_fd_size)++;
	fd = -1;

	v = dcerpc_binding_vector_dup(tmp_ctx, v_orig);
	if (v == NULL) {
		ok = false;
		goto done;
	}

	status = dcerpc_binding_vector_replace_iface(&ndr_table_netlogon, v);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	status = dcerpc_binding_vector_add_np_default(&ndr_table_netlogon, v);
	if (!NT_STATUS_IS_OK(status)) {
		ok = false;
		goto done;
	}

	status = dcerpc_binding_vector_add_unix(&ndr_table_lsarpc, v, "netlogon");
	if (!NT_STATUS_IS_OK(status)) {
		ok = false;
		goto done;
	}

	status = rpc_ep_register(ev_ctx, msg_ctx, &ndr_table_netlogon, v);
	if (!NT_STATUS_IS_OK(status)) {
		ok = false;
		goto done;
	}

done:
	if (fd != -1) {
		close(fd);
	}
	talloc_free(tmp_ctx);
	return ok;
}

void start_lsasd(struct tevent_context *ev_ctx,
		 struct messaging_context *msg_ctx)
{
	NTSTATUS status;
	int listen_fd[LSASD_MAX_SOCKETS];
	int listen_fd_size = 0;
	pid_t pid;
	int rc;
	bool ok;

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

	/* save the parent process id so the children can use it later */
	parent_id = procid_self();

	status = reinit_after_fork(msg_ctx,
				   ev_ctx,
				   true);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		smb_panic("reinit_after_fork() failed");
	}

	lsasd_reopen_logs(0);
	pfh_daemon_config(DAEMON_NAME,
			  &pf_lsasd_cfg,
			  &default_pf_lsasd_cfg);

	lsasd_setup_sig_term_handler(ev_ctx);
	lsasd_setup_sig_hup_handler(ev_ctx);

	BlockSignals(false, SIGTERM);
	BlockSignals(false, SIGHUP);

	ok = lsasd_create_sockets(ev_ctx, msg_ctx, listen_fd, &listen_fd_size);
	if (!ok) {
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
				 NULL,
				 &lsasd_pool);
	if (!ok) {
		exit(1);
	}

	if (!serverid_register(procid_self(), FLAG_MSG_GENERAL)) {
		exit(1);
	}

	messaging_register(msg_ctx,
			   ev_ctx,
			   MSG_SMB_CONF_UPDATED,
			   lsasd_smb_conf_updated);
	messaging_register(msg_ctx, ev_ctx,
			   MSG_PREFORK_CHILD_EVENT, child_ping);

	status = rpc_lsarpc_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register lsarpc rpc inteface in lsasd! (%s)\n",
			  nt_errstr(status)));
		exit(1);
	}

	status = rpc_samr_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register samr rpc inteface in lsasd! (%s)\n",
			  nt_errstr(status)));
		exit(1);
	}

	status = rpc_netlogon_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register netlogon rpc inteface in lsasd! (%s)\n",
			  nt_errstr(status)));
		exit(1);
	}

	ok = lsasd_setup_children_monitor(ev_ctx, msg_ctx);
	if (!ok) {
		DEBUG(0, ("Failed to setup children monitoring!\n"));
		exit(1);
	}

	DEBUG(1, ("LSASD Daemon Started (%d)\n", getpid()));

	/* loop forever */
	rc = tevent_loop_wait(ev_ctx);

	/* should not be reached */
	DEBUG(0,("lsasd: tevent_loop_wait() exited with %d - %s\n",
		 rc, (rc == 0) ? "out of events" : strerror(errno)));
	exit(1);
}
