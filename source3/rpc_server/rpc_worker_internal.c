/*
 *  Unix SMB/CIFS implementation.
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

#include "source3/include/includes.h"
#include "lib/cmdline/cmdline.h"
#include "rpc_worker_internal.h"
#include "lib/util/debug.h"
#include "lib/util/fault.h"
#include "lib/util/util_file.h"
#include "lib/util/time_basic.h"
#include "source3/smbd/proto.h"
#include "source3/lib/smbd_shim.h"
#include "source3/lib/global_contexts.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/named_pipe_auth/npa_tstream.h"
#include "lib/param/param.h"
#include "lib/util/tevent_unix.h"
#include "lib/async_req/async_sock.h"
#include "lib/util/dlinklist.h"
#include "source3/include/auth.h"
#include "nsswitch/winbind_client.h"
#include "source3/include/messages.h"
#include "libcli/security/security_token.h"
#include "libcli/security/dom_sid.h"
#include "source3/lib/substitute.h"

/*
 * This is the generic code that becomes the
 * template that all services invoked by samba-dcerpcd.
 *
 * This provides rpc_worker() which takes an argc/argv list,
 * the daemon_config_name, a number of workers, idle_seconds
 * and 4 functions and a private_data for them:
 *
 * get_interfaces() - List all interfaces that this server provides
 * setup_servers() - Initialize the service before accepting connections.
 * accept_client() - A function called when a new connection arrived.
 * shutdown_servers() - Shutdown the service global state.
 *
 * This is internal code which should be a wrapped into
 * higher level functions like rpc_worker_main(), which
 * is used for dcerpc services.
 */

static NTSTATUS rpc_worker_report_status(struct rpc_worker *worker)
{
	uint8_t buf[16];
	DATA_BLOB blob = { .data = buf, .length = sizeof(buf), };
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(rpc_worker_status, &worker->status);
	}

	ndr_err = ndr_push_struct_into_fixed_blob(
		&blob,
		&worker->status,
		(ndr_push_flags_fn_t)ndr_push_rpc_worker_status);
	SMB_ASSERT(NDR_ERR_CODE_IS_SUCCESS(ndr_err));

	status = messaging_send(
		worker->msg_ctx,
		worker->rpc_host_pid,
		MSG_RPC_WORKER_STATUS,
		&blob);
	return status;
}

static int rpc_worker_connection_destructor(struct rpc_worker_connection *conn)
{
	struct rpc_worker *worker = conn->worker;
	NTSTATUS status;

	DLIST_REMOVE(worker->conns, conn);

	SMB_ASSERT(worker->status.num_connections > 0);
	worker->status.num_connections -= 1;

	/*
	 * rpc_worker_report_status() below,
	 * expects worker->status.num_association_groups to be
	 * updated already.
	 *
	 * So dcesrv_connection_destructor() should be triggered
	 * before and synced worker->dce_ctx->assoc_groups_num to
	 * worker->status.num_association_groups.
	 *
	 * For npsd services we just sync num_association_groups
	 * with num_connections.
	 */
	if (worker->is_npsd) {
		worker->status.num_association_groups =
			worker->status.num_connections;
	}
	SMB_ASSERT(worker->status.num_connections >=
		   worker->status.num_association_groups);

	GetTimeOfDay(&worker->last_disconnect);
	status = rpc_worker_report_status(worker);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpc_worker_report_status returned %s\n",
			  nt_errstr(status));
	}

	return 0;
}

/*
 * A new client has been passed to us from samba-dcerpcd.
 */
static void rpc_worker_new_client(
	struct rpc_worker *worker,
	struct rpc_host_client *client,
	int sock)
{
	struct named_pipe_auth_req_info8 *info8 = client->npa_info8;
	struct tsocket_address *remote_client_addr = NULL;
	struct tsocket_address *local_server_addr = NULL;
	struct dcerpc_binding *b = NULL;
	enum dcerpc_transport_t transport;
	struct tstream_context *tstream = NULL;
	struct rpc_worker_connection *worker_conn = NULL;
	struct security_token *token = NULL;
	NTSTATUS status;
	int ret;

	DBG_DEBUG("Got new conn sock %d for binding %s\n",
		  sock,
		  client->binding);

	status = dcerpc_parse_binding(client, client->binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dcerpc_parse_binding(%s) failed: %s\n",
			  client->binding,
			  nt_errstr(status));
		goto fail;
	}
	transport = dcerpc_binding_get_transport(b);

	worker_conn = talloc(worker, struct rpc_worker_connection);
	if (worker_conn == NULL) {
		DBG_DEBUG("talloc failed\n");
		goto fail;
	}
	*worker_conn = (struct rpc_worker_connection) {
		.worker = worker,
	};
	GetTimeOfDay(&worker_conn->tv);

	worker_conn->endpoint = talloc_strdup(worker_conn, client->binding);
	if (worker_conn->endpoint == NULL) {
		DBG_DEBUG("talloc_strdup failed\n");
		goto fail;
	}

	if (transport == NCALRPC) {
		ret = tsocket_address_unix_from_path(worker_conn,
						     info8->remote_client_addr,
						     &remote_client_addr);
		if (ret == -1) {
			DBG_DEBUG("tsocket_address_unix_from_path"
				  "(%s) failed: %s\n",
				  info8->remote_client_addr,
				  strerror(errno));
			goto fail;
		}

		worker_conn->remote_client_name =
			talloc_strdup(worker_conn, info8->remote_client_name);
		if (worker_conn->remote_client_name == NULL) {
			DBG_DEBUG("talloc_strdup(%s) failed\n",
				  info8->remote_client_name);
			goto fail;
		}

		ret = tsocket_address_unix_from_path(worker_conn,
						     info8->local_server_addr,
						     &local_server_addr);
		if (ret == -1) {
			DBG_DEBUG("tsocket_address_unix_from_path"
				  "(%s) failed: %s\n",
				  info8->local_server_addr,
				  strerror(errno));
			goto fail;
		}

		worker_conn->local_server_name =
			talloc_strdup(worker_conn, info8->local_server_name);
		if (worker_conn->local_server_name == NULL) {
			DBG_DEBUG("talloc_strdup(%s) failed\n",
				  info8->local_server_name);
			goto fail;
		}
	} else {
		ret = tsocket_address_inet_from_strings(
			worker_conn,
			"ip",
			info8->remote_client_addr,
			info8->remote_client_port,
			&remote_client_addr);
		if (ret == -1) {
			DBG_DEBUG("tsocket_address_inet_from_strings"
				  "(%s, %" PRIu16 ") failed: %s\n",
				  info8->remote_client_addr,
				  info8->remote_client_port,
				  strerror(errno));
			goto fail;
		}
		worker_conn->remote_client_name =
			talloc_strdup(worker_conn, info8->remote_client_name);
		if (worker_conn->remote_client_name == NULL) {
			DBG_DEBUG("talloc_strdup(%s) failed\n",
				  info8->remote_client_name);
			goto fail;
		}

		ret = tsocket_address_inet_from_strings(
			worker_conn,
			"ip",
			info8->local_server_addr,
			info8->local_server_port,
			&local_server_addr);
		if (ret == -1) {
			DBG_DEBUG("tsocket_address_inet_from_strings"
				  "(%s, %" PRIu16 ") failed: %s\n",
				  info8->local_server_addr,
				  info8->local_server_port,
				  strerror(errno));
			goto fail;
		}
		worker_conn->local_server_name =
			talloc_strdup(worker_conn, info8->local_server_name);
		if (worker_conn->local_server_name == NULL) {
			DBG_DEBUG("talloc_strdup(%s) failed\n",
				  info8->local_server_name);
			goto fail;
		}

		worker_conn->remote_client_addr = talloc_strdup(
			worker_conn, info8->remote_client_addr);
		if (worker_conn->remote_client_addr == NULL) {
			DBG_DEBUG("talloc_strdup(%s) failed\n",
				  info8->remote_client_addr);
			goto fail;
		}
	}

	if (transport == NCACN_NP) {
		ret = tstream_npa_existing_socket(worker_conn,
						  sock,
						  client->np_info.file_type,
						  &tstream);
		if (ret == -1) {
			DBG_DEBUG("tstream_npa_existing_socket failed: %s\n",
				  strerror(errno));
			goto fail;
		}

		/*
		 * "transport" so far is implicitly assigned by the
		 * socket that the client connected to, passed in from
		 * samba-dcerpcd via the binding. For NCACN_NP (root
		 * only by unix permissions) we got a
		 * named_pipe_auth_req_info8 where the transport can
		 * be overridden.
		 */
		transport = info8->transport;
	} else {
		ret = tstream_bsd_existing_socket(
			worker_conn, sock, &tstream);
		if (ret == -1) {
			DBG_DEBUG("tstream_bsd_existing_socket failed: %s\n",
				  strerror(errno));
			goto fail;
		}
		/* as server we want to fail early */
		tstream_bsd_fail_readv_first_error(tstream, true);
	}
	sock = -1;

	token = info8->session_info->session_info->security_token;

	if (security_token_is_system(token) && (transport != NCALRPC)) {
		DBG_DEBUG("System token only allowed on NCALRPC\n");
		goto fail;
	}

	status = worker->accept_client(worker,
				       worker->private_data,
				       worker_conn,
				       &info8->session_info->session_info,
				       &b,
				       transport,
				       &client->bind_packet,
				       &tstream,
				       &remote_client_addr,
				       &local_server_addr);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("worker->accept_client() failed %s\n",
			    nt_errstr(status));
		goto fail;
	}

	TALLOC_FREE(client);
	DLIST_ADD(worker->conns, worker_conn);
	worker->status.num_connections += 1;
	if (worker->is_npsd) {
		worker->status.num_association_groups =
			worker->status.num_connections;
	}
	worker->last_connect = worker_conn->tv;
	talloc_set_destructor(worker_conn, rpc_worker_connection_destructor);
	return;
fail:
	TALLOC_FREE(worker_conn);
	TALLOC_FREE(client);
	if (sock != -1) {
		close(sock);
	}

	/*
	 * Parent thinks it successfully sent us a client. Tell it
	 * that we declined.
	 */
	status = rpc_worker_report_status(worker);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpc_worker_report_status returned %s\n",
			  nt_errstr(status));
	}
}

/*
 * New client message processing.
 */
static bool rpc_worker_new_client_filter(
	struct messaging_rec *rec, void *private_data)
{
	struct rpc_worker *worker = talloc_get_type_abort(
		private_data, struct rpc_worker);
	struct rpc_host_client *client = NULL;
	enum ndr_err_code ndr_err;
	int sock;

	if (rec->msg_type != MSG_RPC_HOST_NEW_CLIENT) {
		return false;
	}

	if (rec->num_fds != 1) {
		DBG_DEBUG("Got %"PRIu8" fds\n", rec->num_fds);
		return false;
	}

	client = talloc(worker, struct rpc_host_client);
	if (client == NULL) {
		DBG_DEBUG("talloc failed\n");
		return false;
	}

	ndr_err = ndr_pull_struct_blob_all(
		&rec->buf,
		client,
		client,
		(ndr_pull_flags_fn_t)ndr_pull_rpc_host_client);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_DEBUG("ndr_pull_rpc_host_client failed: %s\n",
			  ndr_errstr(ndr_err));
		TALLOC_FREE(client);
		return false;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(rpc_host_client, client);
	}

	sock = rec->fds[0];
	rec->fds[0] = -1;

	rpc_worker_new_client(worker, client, sock);

	return false;
}

static void dump_worker_client_info(TALLOC_CTX *root,
				    struct rpc_worker *worker,
				    FILE *f)
{
	struct rpc_worker_connection *conn = NULL;
	struct timeval_buf buf_con = {0};
	struct timeval_buf buf_discon = {0};
	int i = 1;
	fprintf(f,
		"%s pid %u:\n"
		"      num_connections = %" PRIu32 "\n"
		"      num_association_groups = %" PRIu32 "\n"
		"      last client connection %s\n"
		"      last client disconnection %s\n",
		getprogname(),
		(unsigned int)getpid(),
		worker->status.num_connections,
		worker->status.num_association_groups,
		(worker->last_connect.tv_sec != 0)
			? timeval_str_buf(
				  &worker->last_connect, false, true, &buf_con)
			: "N/A",
		(worker->last_disconnect.tv_sec != 0)
			? timeval_str_buf(&worker->last_disconnect,
					  false,
					  true,
					  &buf_discon)
			: "N/A");
	for (conn = worker->conns; conn != NULL; conn = conn->next) {
		struct timeval_buf tvbuf = {0};
		timeval_str_buf(&conn->tv, false, true, &tvbuf);
		if (i == 1) {
			fprintf(f, "   active connections:\n");
		}
		fprintf(f,
			"      [%d] endpoint=%s client addr=%s server=%s "
			"connected at %s\n",
			i++,
			conn->endpoint,
			conn->remote_client_addr,
			conn->local_server_name,
			tvbuf.buf);
	}
}

static bool rpc_worker_client_info(struct messaging_rec *rec,
				   void *private_data)
{
	struct rpc_worker *worker = talloc_get_type_abort(private_data,
							  struct rpc_worker);
	FILE *f = NULL;

	if (rec->msg_type != MSG_RPC_WORKER_INFO) {
		return false;
	}

	DBG_DEBUG("Got MSG_RPC_WORKER_INFO\n");
	if (rec->num_fds != 1) {
		DBG_DEBUG("Got %" PRIu8 " fds, expected one\n", rec->num_fds);
		return false;
	}

	f = fdopen_keepfd(rec->fds[0], "w");
	if (f == NULL) {
		DBG_DEBUG("fdopen failed: %s\n", strerror(errno));
		return false;
	}
	dump_worker_client_info(NULL, worker, f);
	fclose(f);
	return false;
}

/*
 * Return your status message processing.
 */
static bool rpc_worker_status_filter(
	struct messaging_rec *rec, void *private_data)
{
	struct rpc_worker *worker = talloc_get_type_abort(
		private_data, struct rpc_worker);
	struct rpc_worker_connection *conn = NULL;
	FILE *f = NULL;

	if (rec->msg_type != MSG_RPC_DUMP_STATUS) {
		return false;
	}

	if (rec->num_fds != 1) {
		DBG_DEBUG("Got %"PRIu8" fds\n", rec->num_fds);
		return false;
	}

	f = fdopen_keepfd(rec->fds[0], "w");
	if (f == NULL) {
		DBG_DEBUG("fdopen_keepfd failed: %s\n", strerror(errno));
		return false;
	}

	for (conn = worker->conns; conn != NULL; conn = conn->next) {
		fprintf(f,
			"endpoint=%s client=%s server=%s\n",
			conn->endpoint,
			conn->remote_client_name,
			conn->local_server_name);
	}

	fclose(f);

	return false;
}

static struct rpc_worker *rpc_worker_new(
	TALLOC_CTX *mem_ctx,
	struct messaging_context *msg_ctx)
{
	struct rpc_worker *worker = NULL;

	worker = talloc_zero(mem_ctx, struct rpc_worker);
	if (worker == NULL) {
		return NULL;
	}

	worker->rpc_host_pid = (struct server_id) { .pid = 0 };
	worker->msg_ctx = msg_ctx;

	return worker;
}

struct rpc_worker_state {
	struct tevent_context *ev;
	struct rpc_worker *w;
	struct tevent_req *new_client_req;
	struct tevent_req *status_req;
	struct tevent_req *finish_req;
};

static void rpc_worker_done(struct tevent_req *subreq);
static void rpc_worker_shutdown(
	struct messaging_context *msg,
	void *private_data,
	uint32_t msg_type,
	struct server_id server_id,
	DATA_BLOB *data);

static struct tevent_req *rpc_worker_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct rpc_worker *w,
	pid_t rpc_host_pid,
	int server_index,
	int worker_index)
{
	struct tevent_req *req = NULL;
	struct rpc_worker_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct rpc_worker_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->w = w;

	if ((server_index < 0) || ((unsigned)server_index > UINT32_MAX)) {
		DBG_ERR("Invalid server index %d\n", server_index);
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}
	if ((worker_index < 0) || ((unsigned)worker_index > UINT16_MAX)) {
		DBG_ERR("Invalid worker index %d\n", worker_index);
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}
	w->rpc_host_pid = pid_to_procid(rpc_host_pid);

	w->status = (struct rpc_worker_status) {
		.server_index = server_index,
		.worker_index = worker_index,
	};

	/* Wait for new client messages. */
	state->new_client_req = messaging_filtered_read_send(
		w,
		messaging_tevent_context(w->msg_ctx),
		w->msg_ctx,
		rpc_worker_new_client_filter,
		w);
	if (tevent_req_nomem(state->new_client_req, req)) {
		return tevent_req_post(req, ev);
	}

	state->new_client_req = messaging_filtered_read_send(
		w,
		messaging_tevent_context(w->msg_ctx),
		w->msg_ctx,
		rpc_worker_client_info,
		w);
	if (tevent_req_nomem(state->new_client_req, req)) {
		return tevent_req_post(req, ev);
	}

	/* Wait for report your status messages. */
	state->status_req = messaging_filtered_read_send(
		w,
		messaging_tevent_context(w->msg_ctx),
		w->msg_ctx,
		rpc_worker_status_filter,
		w);
	if (tevent_req_nomem(state->status_req, req)) {
		return tevent_req_post(req, ev);
	}

	/* Wait for shutdown messages. */
	status = messaging_register(
		w->msg_ctx, req, MSG_SHUTDOWN, rpc_worker_shutdown);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("messaging_register failed: %s\n",
			  nt_errstr(status));
		tevent_req_error(req, map_errno_from_nt_status(status));
		return tevent_req_post(req, ev);
	}

	state->finish_req = wait_for_read_send(state, ev, 0, false);
	if (tevent_req_nomem(state->finish_req, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(state->finish_req, rpc_worker_done, req);

	rpc_worker_report_status(w);

	return req;
}

static void rpc_worker_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int err = 0;
	bool ok;

	ok = wait_for_read_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, err);
		return;
	}
	tevent_req_done(req);
}

static void rpc_worker_shutdown(
	struct messaging_context *msg,
	void *private_data,
	uint32_t msg_type,
	struct server_id server_id,
	DATA_BLOB *data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	tevent_req_done(req);
}

static int rpc_worker_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}

static void sig_term_handler(
	struct tevent_context *ev,
	struct tevent_signal *se,
	int signum,
	int count,
	void *siginfo,
	void *private_data)
{
	exit(0);
}

static void sig_hup_handler(
	struct tevent_context *ev,
	struct tevent_signal *se,
	int signum,
	int count,
	void *siginfo,
	void *private_data)
{
	change_to_root_user();
	lp_load_with_shares(get_dyn_CONFIGFILE());
}

int rpc_worker_internal(
	int argc,
	const char *argv[],
	const char *daemon_config_name,
	int num_workers,
	int idle_seconds,
	NTSTATUS (*get_interfaces)(
		void *private_data,
		TALLOC_CTX *mem_ctx,
		char **ifaces),
	NTSTATUS (*setup_servers)(
		struct rpc_worker *worker,
		void *private_data),
	NTSTATUS (*accept_client)(
		struct rpc_worker *worker,
		void *private_data,
		struct rpc_worker_connection *worker_conn,
		struct auth_session_info **transport_session_info,
		struct dcerpc_binding **binding,
		uint8_t _effective_transport,
		DATA_BLOB *first_pdu,
		struct tstream_context **tstream,
		struct tsocket_address **remote_client_addr,
		struct tsocket_address **local_server_addr),
	NTSTATUS (*shutdown_servers)(
		struct rpc_worker *worker,
		void *private_data),
	void *private_data)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	const char *progname = getprogname();
	TALLOC_CTX *frame = NULL;
	struct tevent_context *ev_ctx = NULL;
	struct tevent_req *req = NULL;
	struct messaging_context *msg_ctx = NULL;
	struct tevent_signal *se = NULL;
	poptContext pc;
	int opt;
	NTSTATUS status;
	int ret;
	int worker_group = -1;
	int worker_index = -1;
	bool log_stdout;
	int list_interfaces = 0;
	struct rpc_worker *worker = NULL;
	bool ok;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{
			.longName   = "list-interfaces",
			.argInfo    = POPT_ARG_NONE,
			.arg        = &list_interfaces,
			.descrip    = "List the interfaces provided",
		},
		{
			.longName   = "worker-group",
			.argInfo    = POPT_ARG_INT,
			.arg        = &worker_group,
			.descrip    = "Group index in status message",
		},
		{
			.longName   = "worker-index",
			.argInfo    = POPT_ARG_INT,
			.arg        = &worker_index,
			.descrip    = "Worker index in status message",
		},
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};
	static const struct smbd_shim smbd_shim_fns = {
		.become_authenticated_pipe_user =
		smbd_become_authenticated_pipe_user,
		.unbecome_authenticated_pipe_user =
		smbd_unbecome_authenticated_pipe_user,
		.become_root = smbd_become_root,
		.unbecome_root = smbd_unbecome_root,
	};

	closefrom(3);
	talloc_enable_null_tracking();
	frame = talloc_stackframe();
	umask(0);
	smb_init_locale();

	ok = samba_cmdline_init(frame,
				SAMBA_CMDLINE_CONFIG_SERVER,
				true /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to init cmdline parser!\n");
		TALLOC_FREE(frame);
		exit(ENOMEM);
	}

	pc = samba_popt_get_context(progname, argc, argv, long_options, 0);
	if (pc == NULL) {
		DBG_ERR("Failed to setup popt context!\n");
		TALLOC_FREE(frame);
		exit(1);
	}

	while ((opt = poptGetNextOpt(pc)) != -1) {
		d_fprintf(stderr,
			  "\nInvalid option %s: %s\n\n",
			  poptBadOption(pc, 0),
			  poptStrerror(opt));
		poptPrintUsage(pc, stderr, 0);
		TALLOC_FREE(frame);
		exit(1);
	};
	poptFreeContext(pc);

	if (list_interfaces != 0) {
		char *ifaces = NULL;

		status = get_interfaces(private_data, frame, &ifaces);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("get_interfaces failed: %s\n", nt_errstr(status));
			TALLOC_FREE(frame);
			exit(1);
		}

		num_workers = lp_parm_int(
			-1, daemon_config_name, "num_workers", num_workers);
		idle_seconds = lp_parm_int(
			-1, daemon_config_name, "idle_seconds", idle_seconds);

		DBG_DEBUG("daemon=%s, num_workers=%d, idle_seconds=%d\n",
			  daemon_config_name,
			  num_workers,
			  idle_seconds);

		fprintf(stdout, "%d\n%d\n%s", num_workers, idle_seconds, ifaces);

		TALLOC_FREE(frame);
		exit(0);
	}

	log_stdout = (debug_get_log_type() == DEBUG_STDOUT);
	if (log_stdout != 0) {
		setup_logging(argv[0], DEBUG_STDOUT);
	} else {
		setup_logging(argv[0], DEBUG_FILE);
	}

	set_smbd_shim(&smbd_shim_fns);

	dump_core_setup(progname, lp_logfile(talloc_tos(), lp_sub));

	/* POSIX demands that signals are inherited. If the invoking
	 * process has these signals masked, we will have problems, as
	 * we won't receive them. */
	BlockSignals(False, SIGHUP);
	BlockSignals(False, SIGUSR1);
	BlockSignals(False, SIGTERM);

#if defined(SIGFPE)
	/* we are never interested in SIGFPE */
	BlockSignals(True,SIGFPE);
#endif
	/* We no longer use USR2... */
#if defined(SIGUSR2)
	BlockSignals(True, SIGUSR2);
#endif
	/* Ignore children - no zombies. */
	CatchChild();

	set_remote_machine_name(progname, false);

	reopen_logs();

	DBG_STARTUP_NOTICE("%s version %s started.\n%s\n",
			   progname,
			   samba_version_string(),
			   samba_copyright_string());

	msg_ctx = global_messaging_context();
	if (msg_ctx == NULL) {
		DBG_ERR("global_messaging_context() failed\n");
		TALLOC_FREE(frame);
		exit(1);
	}
	ev_ctx = messaging_tevent_context(msg_ctx);

	worker = rpc_worker_new(ev_ctx, msg_ctx);
	if (worker == NULL) {
		DBG_ERR("rpc_worker_new failed\n");
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}
	worker->accept_client = accept_client;
	worker->private_data = private_data;

	se = tevent_add_signal(
		ev_ctx, ev_ctx, SIGTERM, 0, sig_term_handler, NULL);
	if (se == NULL) {
		DBG_ERR("tevent_add_signal failed\n");
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}
	BlockSignals(false, SIGTERM);

	se = tevent_add_signal(
		ev_ctx, ev_ctx, SIGHUP, 0, sig_hup_handler, NULL);
	if (se == NULL) {
		DBG_ERR("tevent_add_signal failed\n");
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}
	BlockSignals(false, SIGHUP);

	(void)winbind_off();
	ok = init_guest_session_info(NULL);
	(void)winbind_on();
	if (!ok) {
		DBG_WARNING("init_guest_session_info failed\n");
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}

	status = init_system_session_info(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("init_system_session_info failed: %s\n",
			    nt_errstr(status));
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}

	status = setup_servers(worker, private_data);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("setup_servers failed: %s\n", nt_errstr(status));
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}

	req = rpc_worker_send(
		ev_ctx, ev_ctx, worker, getppid(), worker_group, worker_index);
	if (req == NULL) {
		DBG_ERR("rpc_worker_send failed\n");
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}

	DBG_DEBUG("%s worker running\n", progname);

	while (tevent_req_is_in_progress(req)) {
		TALLOC_CTX *loop_frame = NULL;

		loop_frame = talloc_stackframe();

		ret = tevent_loop_once(ev_ctx);

		TALLOC_FREE(loop_frame);

		if (ret != 0) {
			DBG_WARNING("tevent_req_once() failed: %s\n",
				    strerror(errno));
			global_messaging_context_free();
			TALLOC_FREE(frame);
			exit(1);
		}
	}

	status = shutdown_servers(worker, private_data);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("shutdown_servers failed: %s\n", nt_errstr(status));
	}

	ret = rpc_worker_recv(req);
	if (ret != 0) {
		DBG_DEBUG("rpc_worker_recv returned %s\n", strerror(ret));
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}

	TALLOC_FREE(frame);
	return 0;
}
