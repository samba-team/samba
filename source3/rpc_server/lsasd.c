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

#include "../lib/tsocket/tsocket.h"
#include "lib/server_prefork.h"
#include "librpc/rpc/dcerpc_ep.h"

#include "rpc_server/rpc_server.h"
#include "rpc_server/rpc_ep_register.h"
#include "rpc_server/rpc_sock_helper.h"

#include "librpc/gen_ndr/srv_lsa.h"
#include "librpc/gen_ndr/srv_samr.h"
#include "librpc/gen_ndr/srv_netlogon.h"

#define DAEMON_NAME "lsasd"

#define LSASD_MIN_CHILDREN 5
#define LSASD_MAX_CHILDREN 25
#define LSASD_SPAWN_RATE   5
#define LSASD_MIN_LIFE     60 /* 1 minute minimum life time */

#define LSASD_MAX_SOCKETS 64

#define LSASD_ALL_FINE 0x00
#define LSASD_NEW_MAX  0x01
#define LSASD_ENOSPC   0x02

static int lsasd_min_children;
static int lsasd_max_children;
static int lsasd_spawn_rate;
static int lsasd_prefork_status;

void start_lsasd(struct tevent_context *ev_ctx,
		 struct messaging_context *msg_ctx);

static void lsasd_prefork_config(void)
{
	static int lsasd_prefork_config_init = false;
	const char *prefork_str;
	int min, max, rate;
	bool use_defaults = false;
	int ret;

	if (!lsasd_prefork_config_init) {
		lsasd_prefork_status = LSASD_ALL_FINE;
		lsasd_min_children = 0;
		lsasd_max_children = 0;
		lsasd_spawn_rate = 0;
		lsasd_prefork_config_init = true;
	}

	prefork_str = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "lsasd", "prefork", "none");
	if (strcmp(prefork_str, "none") == 0) {
		use_defaults = true;
	} else {
		ret = sscanf(prefork_str, "%d:%d:%d", &min, &max, &rate);
		if (ret != 3) {
			DEBUG(0, ("invalid format for lsasd:prefork!\n"));
			use_defaults = true;
		}
	}

	if (use_defaults) {
		min = LSASD_MIN_CHILDREN;
		max = LSASD_MAX_CHILDREN;
		rate = LSASD_SPAWN_RATE;
	}

	if (max > lsasd_max_children && lsasd_max_children != 0) {
		lsasd_prefork_status |= LSASD_NEW_MAX;
	}

	lsasd_min_children = min;
	lsasd_max_children = max;
	lsasd_spawn_rate = rate;
}

static void lsasd_reopen_logs(int child_id)
{
	char *lfile = lp_logfile();
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
						lp_logfile(),
						child_id);
			} else {
				rc = asprintf(&lfile, "%s.%s",
						lp_logfile(),
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
	DEBUG(10, ("Got message saying smb.conf was updated. Reloading.\n"));
	change_to_root_user();
	lp_load(get_dyn_CONFIGFILE(), true, false, false, true);

	lsasd_reopen_logs(0);
	lsasd_prefork_config();
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

struct lsasd_hup_ctx {
	struct messaging_context *msg_ctx;
	struct prefork_pool *pfp;
};

static void lsasd_sig_hup_handler(struct tevent_context *ev,
				    struct tevent_signal *se,
				    int signum,
				    int count,
				    void *siginfo,
				    void *pvt)
{
	struct lsasd_hup_ctx *hup_ctx;

	hup_ctx = talloc_get_type_abort(pvt, struct lsasd_hup_ctx);

	change_to_root_user();
	lp_load(get_dyn_CONFIGFILE(), true, false, false, true);

	lsasd_reopen_logs(0);
	lsasd_prefork_config();

	/* relay to all children */
	prefork_send_signal_to_all(hup_ctx->pfp, SIGHUP);
}

static void lsasd_setup_sig_hup_handler(struct tevent_context *ev_ctx,
					struct prefork_pool *pfp,
					struct messaging_context *msg_ctx)
{
	struct lsasd_hup_ctx *hup_ctx;
	struct tevent_signal *se;

	hup_ctx = talloc(ev_ctx, struct lsasd_hup_ctx);
	if (!hup_ctx) {
		DEBUG(0, ("failed to setup SIGHUP handler\n"));
		exit(1);
	}
	hup_ctx->pfp = pfp;
	hup_ctx->msg_ctx = msg_ctx;

	se = tevent_add_signal(ev_ctx,
			       ev_ctx,
			       SIGHUP, 0,
			       lsasd_sig_hup_handler,
			       hup_ctx);
	if (!se) {
		DEBUG(0, ("failed to setup SIGHUP handler\n"));
		exit(1);
	}
}

/**********************************************************
 * Children
 **********************************************************/

struct lsasd_chld_sig_hup_ctx {
	struct messaging_context *msg_ctx;
	struct pf_worker_data *pf;
	int child_id;
};

static void lsasd_chld_sig_hup_handler(struct tevent_context *ev,
					 struct tevent_signal *se,
					 int signum,
					 int count,
					 void *siginfo,
					 void *pvt)
{
	struct lsasd_chld_sig_hup_ctx *shc;

	shc = talloc_get_type_abort(pvt, struct lsasd_chld_sig_hup_ctx);

	/* avoid wasting CPU cycles if we are going to exit soon anyways */
	if (shc->pf != NULL &&
	    shc->pf->cmds == PF_SRV_MSG_EXIT) {
		return;
	}

	change_to_root_user();
	lsasd_reopen_logs(shc->child_id);
}

static bool lsasd_setup_chld_hup_handler(struct tevent_context *ev_ctx,
					 struct pf_worker_data *pf,
					 struct messaging_context *msg_ctx,
					 int child_id)
{
	struct lsasd_chld_sig_hup_ctx *shc;
	struct tevent_signal *se;

	shc = talloc(ev_ctx, struct lsasd_chld_sig_hup_ctx);
	if (!shc) {
		DEBUG(1, ("failed to setup SIGHUP handler"));
		return false;
	}
	shc->child_id = child_id;
	shc->pf = pf;
	shc->msg_ctx = msg_ctx;

	se = tevent_add_signal(ev_ctx,
			       ev_ctx,
			       SIGHUP, 0,
			       lsasd_chld_sig_hup_handler,
			       shc);
	if (!se) {
		DEBUG(1, ("failed to setup SIGHUP handler"));
		return false;
	}

	return true;
}

static bool lsasd_child_init(struct tevent_context *ev_ctx,
			     int child_id,
			     struct pf_worker_data *pf)
{
	NTSTATUS status;
	struct messaging_context *msg_ctx = server_messaging_context();
	bool ok;

	status = reinit_after_fork(msg_ctx, ev_ctx,
				   procid_self(), true);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		smb_panic("reinit_after_fork() failed");
	}

	lsasd_reopen_logs(child_id);

	ok = lsasd_setup_chld_hup_handler(ev_ctx, pf, msg_ctx, child_id);
	if (!ok) {
		return false;
	}

	if (!serverid_register(procid_self(), FLAG_MSG_GENERAL)) {
		return false;
	}

	messaging_register(msg_ctx, ev_ctx,
			   MSG_SMB_CONF_UPDATED, lsasd_smb_conf_updated);

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
	int child_id;
	struct pf_worker_data *pf;
	int listen_fd_size;
	int *listen_fds;
	int lock_fd;

	bool listening;
};

static void lsasd_next_client(void *pvt);

static int lsasd_children_main(struct tevent_context *ev_ctx,
			       struct messaging_context *msg_ctx,
			       struct pf_worker_data *pf,
			       int child_id,
			       int listen_fd_size,
			       int *listen_fds,
			       int lock_fd,
			       void *private_data)
{
	struct lsasd_children_data *data;
	bool ok;
	int ret;

	ok = lsasd_child_init(ev_ctx, child_id, pf);
	if (!ok) {
		return 1;
	}

	data = talloc(ev_ctx, struct lsasd_children_data);
	if (!data) {
		return 1;
	}
	data->child_id = child_id;
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

	if (data->pf->num_clients) {
		data->pf->num_clients--;
	} else {
		DEBUG(2, ("Invalid num clients, aborting!\n"));
		data->pf->status = PF_WORKER_EXITING;
		return;
	}

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
				  data->listen_fds,
				  data->lock_fd);
	if (!req) {
		DEBUG(1, ("Failed to make listening request!?\n"));
		talloc_free(next);
		return;
	}
	tevent_req_set_callback(req, lsasd_handle_client, next);

	data->listening = true;
}

static void lsasd_handle_client(struct tevent_req *req)
{
	struct lsasd_children_data *data;
	struct lsasd_new_client *client;
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
	/* we are done listening */
	data->listening = false;

	if (rc > 0) {
		DEBUG(1, ("Failed to accept client connection!\n"));
		/* bail out if we are not serving any other client */
		if (data->pf->num_clients == 0) {
			data->pf->status = PF_WORKER_EXITING;
		}
		return;
	}

	if (rc == -2) {
		DEBUG(1, ("Server asks us to die!\n"));
		data->pf->status = PF_WORKER_EXITING;
		return;
	}

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
		char *p;

		p = tsocket_address_unix_path(srv_addr, tmp_ctx);
		if (p == NULL) {
			talloc_free(tmp_ctx);
			return;
		}

		if (strstr(p, "/np/")) {
			p = basename(p);

			named_pipe_accept_function(data->ev_ctx,
						   data->msg_ctx,
						   p,
						   sd,
						   lsasd_client_terminated,
						   data);
		} else {
			p = basename(p);

			dcerpc_ncacn_accept(data->ev_ctx,
					    data->msg_ctx,
					    NCALRPC,
					    p,
					    cli_addr,
					    srv_addr,
					    sd,
					    NULL);
		}
	} else {
		DEBUG(0, ("ERROR: Unsupported socket!\n"));
	}

	talloc_free(tmp_ctx);
}

/*
 * MAIN
 */

static bool lsasd_schedule_check(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx,
				 struct prefork_pool *pfp,
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
	int active, total;
	int n, r;

	msg_ctx = talloc_get_type_abort(pvt, struct messaging_context);

	/* now check we do not descend below the minimum */
	active = prefork_count_active_children(pfp, &total);

	n = 0;
	if (total < lsasd_min_children) {
		n = total - lsasd_min_children;
	} else if (total - active < (total / 4)) {
		n = lsasd_min_children;
	}

	if (n > 0) {
		r = prefork_add_children(ev_ctx, msg_ctx, pfp, n);
		if (r < n) {
			DEBUG(10, ("Tried to start %d children but only,"
				   "%d were actually started.!\n", n, r));
		}
	}
}

static bool lsasd_setup_children_monitor(struct tevent_context *ev_ctx,
					 struct messaging_context *msg_ctx,
					 struct prefork_pool *pfp)
{
	bool ok;

	/* add our oun sigchld callback */
	prefork_set_sigchld_callback(pfp, lsasd_sigchld_handler, msg_ctx);

	ok = lsasd_schedule_check(ev_ctx,
				  msg_ctx,
				  pfp,
				  tevent_timeval_current());

	return ok;
}

struct schedule_check_state {
	struct messaging_context *msg_ctx;
	struct prefork_pool *pfp;
};

static bool lsasd_schedule_check(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx,
				 struct prefork_pool *pfp,
				 struct timeval current_time)
{
	struct tevent_timer *te;
	struct timeval next_event;
	struct schedule_check_state *state;

	state = talloc(ev_ctx, struct schedule_check_state);
	if (!state) {
		DEBUG(0, ("Out of memory!\n"));
		return false;
	}
	state->msg_ctx = msg_ctx;
	state->pfp = pfp;

	/* check situation again in 10 seconds */
	next_event = tevent_timeval_current_ofs(10, 0);

	/* TODO: check when the socket becomes readable, so that children
	 * are checked only when there is some activity ? */
	te = tevent_add_timer(ev_ctx,
			      pfp,
			      next_event,
			      lsasd_check_children,
			      state);
	if (!te) {
		DEBUG(2, ("Failed to set up children monitoring!\n"));
		talloc_free(state);
		return false;
	}
	talloc_steal(te, state);

	return true;
}

static void lsasd_check_children(struct tevent_context *ev_ctx,
				 struct tevent_timer *te,
				 struct timeval current_time,
				 void *pvt)
{
	struct schedule_check_state *state;
	int active, total;
	int rc, n;
	bool ok;

	state = talloc_get_type_abort(pvt, struct schedule_check_state);

	if ((lsasd_prefork_status & LSASD_NEW_MAX) &&
	    !(lsasd_prefork_status & LSASD_ENOSPC)) {
		rc = prefork_expand_pool(state->pfp, lsasd_max_children);
		if (rc == ENOSPC) {
			lsasd_prefork_status |= LSASD_ENOSPC;
		}
		lsasd_prefork_status &= ~LSASD_NEW_MAX;
	}

	active = prefork_count_active_children(state->pfp, &total);

	if (total - active < lsasd_spawn_rate) {
		n = prefork_add_children(ev_ctx,
					 state->msg_ctx,
					 state->pfp,
					 lsasd_spawn_rate);
		if (n < lsasd_spawn_rate) {
			DEBUG(10, ("Tried to start 5 children but only,"
				   "%d were actually started.!\n", n));
		}
	}

	if (total - active > lsasd_min_children) {
		if ((total - lsasd_min_children) >= lsasd_spawn_rate) {
			prefork_retire_children(state->pfp,
						lsasd_spawn_rate,
						time(NULL) - LSASD_MIN_LIFE);
		}
	}

	ok = lsasd_schedule_check(ev_ctx,
				  state->msg_ctx,
				  state->pfp,
				  current_time);
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
	int fd;
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
		rc = listen(listen_fd[i], lsasd_max_children);
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
	listen_fd[*listen_fd_size] = fd;
	(*listen_fd_size)++;

	rc = listen(fd, lsasd_max_children);
	if (rc == -1) {
		DEBUG(0, ("Failed to listen on lsarpc pipe - %s\n",
			  strerror(errno)));
		ok = false;
		goto done;
	}

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

	rc = listen(fd, lsasd_max_children);
	if (rc == -1) {
		DEBUG(0, ("Failed to listen on samr pipe - %s\n",
			  strerror(errno)));
		ok = false;
		goto done;
	}
	listen_fd[*listen_fd_size] = fd;
	(*listen_fd_size)++;

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

	rc = listen(fd, lsasd_max_children);
	if (rc == -1) {
		DEBUG(0, ("Failed to listen on samr pipe - %s\n",
			  strerror(errno)));
		ok = false;
		goto done;
	}
	listen_fd[*listen_fd_size] = fd;
	(*listen_fd_size)++;

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

	status = rpc_ep_register(ev_ctx, msg_ctx, &ndr_table_netlogon, v);
	if (!NT_STATUS_IS_OK(status)) {
		ok = false;
		goto done;
	}

done:
	talloc_free(tmp_ctx);
	return ok;
}

void start_lsasd(struct tevent_context *ev_ctx,
		 struct messaging_context *msg_ctx)
{
	struct prefork_pool *pool;
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

	pid = sys_fork();
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

	/* child */
	close_low_fds(false);

	status = reinit_after_fork(msg_ctx,
				   ev_ctx,
				   procid_self(), true);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		smb_panic("reinit_after_fork() failed");
	}

	lsasd_reopen_logs(0);
	lsasd_prefork_config();

	lsasd_setup_sig_term_handler(ev_ctx);
	lsasd_setup_sig_hup_handler(ev_ctx, pool, msg_ctx);

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
				 lsasd_min_children,
				 lsasd_max_children,
				 &lsasd_children_main,
				 NULL,
				 &pool);
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

	status = rpc_lsarpc_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register winreg rpc inteface! (%s)\n",
			  nt_errstr(status)));
		exit(1);
	}

	status = rpc_samr_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register lsasd rpc inteface! (%s)\n",
			  nt_errstr(status)));
		exit(1);
	}

	status = rpc_netlogon_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register lsasd rpc inteface! (%s)\n",
			  nt_errstr(status)));
		exit(1);
	}

	ok = lsasd_setup_children_monitor(ev_ctx, msg_ctx, pool);
	if (!ok) {
		DEBUG(0, ("Failed to setup children monitoring!\n"));
		exit(1);
	}

	DEBUG(1, ("LSASD Daemon Started (%d)\n", getpid()));

	/* loop forever */
	rc = tevent_loop_wait(ev_ctx);

	/* should not be reached */
	DEBUG(0,("background_queue: tevent_loop_wait() exited with %d - %s\n",
		 rc, (rc == 0) ? "out of events" : strerror(errno)));
	exit(1);
}
