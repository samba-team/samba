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
#include <spawn.h>
#include "local_np.h"
#include "lib/async_req/async_sock.h"
#include "librpc/gen_ndr/ndr_named_pipe_auth.h"
#include "libcli/named_pipe_auth/npa_tstream.h"
#include "libcli/named_pipe_auth/tstream_u32_read.h"
#include "lib/util/tevent_unix.h"
#include "auth/auth_util.h"
#include "libcli/security/dom_sid.h"
#include "libcli/security/security_token.h"
#include "nsswitch/winbind_client.h"

/**
 * @file local_np.c
 *
 * Connect to a local named pipe by connecting to
 * samba-dcerpcd. Start samba-dcerpcd if it isn't
 * already running.
 */

extern bool override_logfile;

struct np_sock_connect_state {
	struct tevent_context *ev;
	struct samba_sockaddr addr;
	const struct named_pipe_auth_req *npa_req;
	struct named_pipe_auth_rep *npa_rep;

	DATA_BLOB npa_blob;
	struct iovec iov;

	int sock;
	struct tevent_req *subreq;
	struct tstream_context *transport;
	struct tstream_context *npa_stream;
};

static void np_sock_connect_cleanup(
	struct tevent_req *req, enum tevent_req_state req_state);
static void np_sock_connect_before(int fd, void *private_data);
static void np_sock_connect_after(int fd, void *private_data);
static void np_sock_connect_connected(struct tevent_req *subreq);
static void np_sock_connect_written(struct tevent_req *subreq);
static void np_sock_connect_read_done(struct tevent_req *subreq);

static struct tevent_req *np_sock_connect_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	const char *sockpath,
	const struct named_pipe_auth_req *npa_req)
{
	struct tevent_req *req = NULL;
	struct np_sock_connect_state *state = NULL;
	size_t len;
	int ret;
	bool ok;

	req = tevent_req_create(mem_ctx, &state, struct np_sock_connect_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->npa_req = npa_req;
	state->sock = -1;
	state->addr.u.un.sun_family = AF_UNIX;

	state->npa_rep = talloc_zero(state, struct named_pipe_auth_rep);
	if (tevent_req_nomem(state->npa_rep, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_cleanup_fn(req, np_sock_connect_cleanup);

	state->addr.sa_socklen = sizeof(struct sockaddr_un);
	len = strlcpy(state->addr.u.un.sun_path,
		      sockpath,
		      sizeof(state->addr.u.un.sun_path));
	if (len >= sizeof(state->addr.u.un.sun_path)) {
		tevent_req_error(req, ENAMETOOLONG);
		return tevent_req_post(req, ev);
	}

	state->sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (state->sock == -1) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	ret = set_blocking(state->sock, true);
	if (ret == -1) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}
	ok = set_close_on_exec(state->sock);
	if (!ok) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	state->subreq = async_connect_send(
		state,
		ev,
		state->sock,
		&state->addr.u.sa,
		state->addr.sa_socklen,
		np_sock_connect_before,
		np_sock_connect_after,
		NULL);
	if (tevent_req_nomem(state->subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(state->subreq, np_sock_connect_connected, req);

	return req;
}

static void np_sock_connect_cleanup(
	struct tevent_req *req, enum tevent_req_state req_state)
{
	struct np_sock_connect_state *state = tevent_req_data(
		req, struct np_sock_connect_state);

	TALLOC_FREE(state->subreq);
	TALLOC_FREE(state->transport);

	if (state->sock != -1) {
		close(state->sock);
		state->sock = -1;
	}
}

static void np_sock_connect_before(int fd, void *private_data)
{
	become_root();
}

static void np_sock_connect_after(int fd, void *private_data)
{
	unbecome_root();
}

static void np_sock_connect_connected(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct np_sock_connect_state *state = tevent_req_data(
		req, struct np_sock_connect_state);
	enum ndr_err_code ndr_err;
	int ret, err;

	SMB_ASSERT(subreq == state->subreq);

	ret = async_connect_recv(subreq, &err);
	TALLOC_FREE(subreq);
	state->subreq = NULL;
	if (ret == -1) {
		DBG_DEBUG("async_connect_recv returned %s\n", strerror(err));
		tevent_req_error(req, err);
		return;
	}

	/*
	 * As a quick workaround for bug 15310 we have done the
	 * connect in blocking mode (see np_sock_connect_send()). The
	 * rest of our code expects a nonblocking socket, activate
	 * this after the connect succeeded.
	 */
	ret = set_blocking(state->sock, false);
	if (ret == -1) {
		tevent_req_error(req, errno);
		return;
	}

	ret = tstream_bsd_existing_socket(
		state, state->sock, &state->transport);
	if (ret == -1) {
		err = errno;
		DBG_DEBUG("tstream_bsd_existing_socket failed: %s\n",
			  strerror(err));
		tevent_req_error(req, err);
		return;
	}
	state->sock = -1;

	ndr_err = ndr_push_struct_blob(
		&state->npa_blob,
		state,
		state->npa_req,
		(ndr_push_flags_fn_t)ndr_push_named_pipe_auth_req);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_DEBUG("ndr_push_struct_blob failed: %s\n",
			  ndr_errstr(ndr_err));
		tevent_req_error(req, ndr_map_error2errno(ndr_err));
		return;
	}
	state->iov = (struct iovec) {
		.iov_base = state->npa_blob.data,
		.iov_len = state->npa_blob.length,
	};

	subreq = tstream_writev_send(
		state, state->ev, state->transport, &state->iov, 1);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, np_sock_connect_written, req);
}

static void np_sock_connect_written(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct np_sock_connect_state *state = tevent_req_data(
		req, struct np_sock_connect_state);
	int ret, err;

	ret = tstream_writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		DBG_DEBUG("tstream_writev_recv returned %s\n", strerror(err));
		tevent_req_error(req, err);
		return;
	}

	subreq = tstream_u32_read_send(
		state, state->ev, 0x00FFFFFF, state->transport);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, np_sock_connect_read_done, req);
}

static void np_sock_connect_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct np_sock_connect_state *state = tevent_req_data(
		req, struct np_sock_connect_state);
	DATA_BLOB in;
	int ret;
	enum ndr_err_code ndr_err;

	ret = tstream_u32_read_recv(subreq, state, &in.data, &in.length);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}

	ndr_err = ndr_pull_struct_blob_all(
		&in,
		state->npa_rep,
		state->npa_rep,
		(ndr_pull_flags_fn_t)ndr_pull_named_pipe_auth_rep);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_DEBUG("ndr_pull_named_pipe_auth_rep failed: %s\n",
			  ndr_errstr(ndr_err));
		tevent_req_error(req, ndr_map_error2errno(ndr_err));
		return;
	}
	if (state->npa_rep->level != 8) {
		DBG_DEBUG("npa level = %" PRIu32 ", expected 8\n",
			  state->npa_rep->level);
		tevent_req_error(req, EIO);
		return;
	}

	ret = tstream_npa_existing_stream(state,
					  &state->transport,
					  state->npa_rep->info.info8.file_type,
					  &state->npa_stream);
	if (ret == -1) {
		ret = errno;
		DBG_DEBUG("tstream_npa_existing_stream failed: %s\n",
			  strerror(ret));
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

static int np_sock_connect_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct tstream_context **stream)
{
	struct np_sock_connect_state *state = tevent_req_data(
		req, struct np_sock_connect_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		tevent_req_received(req);
		return err;
	}
	*stream = talloc_move(mem_ctx, &state->npa_stream);
	tevent_req_received(req);
	return 0;
}

struct start_rpc_host_state {
	int ready_fd;
	struct tevent_req *read_ready_req;
};

static void start_rpc_host_cleanup(
	struct tevent_req *req, enum tevent_req_state req_state);
static void start_rpc_host_ready(struct tevent_req *subreq);

/*
 * Start samba-dcerpcd and wait for it to report ready.
 */
static struct tevent_req *start_rpc_host_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct start_rpc_host_state *state = NULL;
	int ret;
	int ready_fds[2] = { -1, -1 };
	char **argv = NULL;
	pid_t pid;
	bool ok;

	req = tevent_req_create(
		mem_ctx, &state, struct start_rpc_host_state);
	if (req == NULL) {
		return NULL;
	}

	ret = pipe(ready_fds);
	if (ret == -1) {
		ret = errno;
		DBG_DEBUG("pipe() failed: %s\n", strerror(ret));
		goto fail;
	}

	ok = smb_set_close_on_exec(ready_fds[0]);
	if (!ok) {
		ret = errno;
		DBG_DEBUG("smb_set_close_on_exec failed: %s\n",
			  strerror(ret));
		goto fail;
	}

	argv = str_list_make_empty(mem_ctx);
	str_list_add_printf(
		&argv, "%s/samba-dcerpcd", get_dyn_SAMBA_LIBEXECDIR());
	if (!is_default_dyn_CONFIGFILE()) {
		str_list_add_printf(
			&argv, "--configfile=%s", get_dyn_CONFIGFILE());
	}
	str_list_add_printf(&argv, "--libexec-rpcds");
	str_list_add_printf(&argv, "--ready-signal-fd=%d", ready_fds[1]);
	str_list_add_printf(&argv, "--np-helper");
	str_list_add_printf(
		&argv, "--debuglevel=%d", debuglevel_get_class(DBGC_RPC_SRV));
	if (!is_default_dyn_LOGFILEBASE()) {
		str_list_add_printf(
			&argv, "--log-basename=%s", get_dyn_LOGFILEBASE());
	}
	if (argv == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	become_root();
	ret = posix_spawn(&pid, argv[0], NULL, NULL, argv, environ);
	unbecome_root();
	if (ret != 0) {
		DBG_DEBUG("posix_spawn() failed: %s\n", strerror(ret));
		goto fail;
	}

	state->ready_fd = ready_fds[0];
	ready_fds[0] = -1;
	tevent_req_set_cleanup_fn(req, start_rpc_host_cleanup);

	close(ready_fds[1]);
	ready_fds[1] = -1;

	subreq = read_packet_send(state, ev, state->ready_fd, 1, NULL, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, start_rpc_host_ready, req);
	return req;

fail:
	if (ready_fds[0] != -1) {
		close(ready_fds[0]);
		ready_fds[0] = -1;
	}
	if (ready_fds[1] != -1) {
		close(ready_fds[1]);
		ready_fds[1] = -1;
	}
	tevent_req_error(req, ret);
	return tevent_req_post(req, ev);
}

static void start_rpc_host_cleanup(
	struct tevent_req *req, enum tevent_req_state req_state)
{
	struct start_rpc_host_state *state = tevent_req_data(
		req, struct start_rpc_host_state);

	if (state->ready_fd != -1) {
		close(state->ready_fd);
		state->ready_fd = -1;
	}
}

static void start_rpc_host_ready(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct start_rpc_host_state *state = tevent_req_data(
		req, struct start_rpc_host_state);
	uint8_t *buf;
	int err;
	ssize_t nread;

	nread = read_packet_recv(subreq, state, &buf, &err);
	TALLOC_FREE(subreq);
	if (nread == -1) {
		tevent_req_error(req, err);
		return;
	}

	close(state->ready_fd);
	state->ready_fd = -1;

	tevent_req_done(req);
}

static int start_rpc_host_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}

struct local_np_connect_state {
	struct tevent_context *ev;
	const char *socketpath;
	struct named_pipe_auth_req *npa_req;
	struct tstream_context *npa_stream;
};

static void local_np_connect_connected(struct tevent_req *subreq);
static void local_np_connect_started(struct tevent_req *subreq);
static void local_np_connect_retried(struct tevent_req *subreq);

/**
 * @brief Async connect to a local named pipe RPC interface
 *
 * Start "samba-dcerpcd" on demand if it does not exist
 *
 * @param[in] mem_ctx  The memory context to use.
 * @param[in] ev       The tevent context to use.
 *
 * @param[in] pipename The raw pipename to connect to without path
 * @param[in] remote_client_name The client name to transmit
 * @param[in] remote_client_addr The client addr to transmit
 * @param[in] local_server_name The server name to transmit
 * @param[in] local_server_addr The server addr to transmit
 * @param[in] session_info The authorization info to use
 * @param[in] need_idle_server Does this need to be an exclusive server?
 * @return The tevent_req that was started
 */

struct tevent_req *local_np_connect_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	const char *pipename,
	enum dcerpc_transport_t transport,
	const char *remote_client_name,
	const struct tsocket_address *remote_client_addr,
	const char *local_server_name,
	const struct tsocket_address *local_server_addr,
	const struct auth_session_info *session_info,
	bool need_idle_server)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct local_np_connect_state *state = NULL;
	struct named_pipe_auth_req_info8 *i8 = NULL;
	const char *socket_dir = NULL;
	char *lower_case_pipename = NULL;
	struct dom_sid npa_sid = global_sid_Samba_NPA_Flags;
	uint32_t npa_flags = 0;
	struct security_token *token = NULL;
	NTSTATUS status;
	size_t num_npa_sids;
	bool ok;

	req = tevent_req_create(
		mem_ctx, &state, struct local_np_connect_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;

	num_npa_sids =
		security_token_count_flag_sids(session_info->security_token,
					       &npa_sid,
					       1,
					       NULL);
	if (num_npa_sids != 0) {
		DBG_ERR("ERROR: %zu NPA Flags SIDs have already been "
			"detected in the security token!\n",
			num_npa_sids);
		tevent_req_error(req, EACCES);
		return tevent_req_post(req, ev);
	}

	socket_dir = lp_parm_const_string(
		GLOBAL_SECTION_SNUM, "external_rpc_pipe", "socket_dir",
		lp_ncalrpc_dir());
	if (socket_dir == NULL) {
		DBG_DEBUG("external_rpc_pipe:socket_dir not set\n");
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	lower_case_pipename = strlower_talloc(state, pipename);
	if (tevent_req_nomem(lower_case_pipename, req)) {
		return tevent_req_post(req, ev);
	}

	/*
	 * Ensure we cannot process a path that exits
	 * the socket_dir.
	 */
	if (ISDOTDOT(lower_case_pipename) ||
	    (strchr(lower_case_pipename, '/')!=NULL))
	{
		DBG_DEBUG("attempt to connect to invalid pipe pathname %s\n",
			lower_case_pipename);
		tevent_req_error(req, ENOENT);
		return tevent_req_post(req, ev);
	}

	state->socketpath = talloc_asprintf(
		state, "%s/np/%s", socket_dir, lower_case_pipename);
	if (tevent_req_nomem(state->socketpath, req)) {
		return tevent_req_post(req, ev);
	}
	TALLOC_FREE(lower_case_pipename);

	state->npa_req = talloc_zero(state, struct named_pipe_auth_req);
	if (tevent_req_nomem(state->npa_req, req)) {
		return tevent_req_post(req, ev);
	}
	state->npa_req->level = 8;

	i8 = &state->npa_req->info.info8;

	i8->transport = transport;

	/* we don't have "int" in IDL, make sure we don't overflow */
	SMB_ASSERT(i8->transport == transport);

	if (remote_client_name == NULL) {
		remote_client_name = get_myname(state->npa_req);
		if (remote_client_name == NULL) {
			tevent_req_error(req, errno);
			return tevent_req_post(req, ev);
		}
	}
	i8->remote_client_name = remote_client_name;

	if (remote_client_addr == NULL) {
		struct tsocket_address *addr = NULL;
		int ret = tsocket_address_inet_from_strings(
			state->npa_req, "ip", NULL, 0, &addr);
		if (ret != 0) {
			tevent_req_error(req, errno);
			return tevent_req_post(req, ev);
		}
		remote_client_addr = addr;
	}
	i8->remote_client_addr =
		tsocket_address_inet_addr_string(remote_client_addr,
						 state->npa_req);
	if (i8->remote_client_addr == NULL) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}
	i8->remote_client_port = tsocket_address_inet_port(remote_client_addr);

	if (local_server_name == NULL) {
		local_server_name = remote_client_name;
	}
	i8->local_server_name = local_server_name;

	if (local_server_addr == NULL) {
		struct tsocket_address *addr = NULL;
		int ret = tsocket_address_inet_from_strings(
			state->npa_req, "ip", NULL, 0, &addr);
		if (ret != 0) {
			tevent_req_error(req, errno);
			return tevent_req_post(req, ev);
		}
		local_server_addr = addr;
	}
	i8->local_server_addr =
		tsocket_address_inet_addr_string(local_server_addr,
						 state->npa_req);
	if (i8->local_server_addr == NULL) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}
	i8->local_server_port = tsocket_address_inet_port(local_server_addr);

	i8->session_info = talloc_zero(state->npa_req,
				       struct auth_session_info_transport);
	if (tevent_req_nomem(i8->session_info, req)) {
		return tevent_req_post(req, ev);
	}

	i8->session_info->session_info =
		copy_session_info(i8->session_info, session_info);
	if (tevent_req_nomem(i8->session_info->session_info, req)) {
		return tevent_req_post(req, ev);
	}

	if (need_idle_server) {
		npa_flags |= SAMBA_NPA_FLAGS_NEED_IDLE;
	}

	ok = winbind_env_set();
	if (ok) {
		npa_flags |= SAMBA_NPA_FLAGS_WINBIND_OFF;
	}

	ok = sid_append_rid(&npa_sid, npa_flags);
	if (!ok) {
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	token = i8->session_info->session_info->security_token;

	status = add_sid_to_array_unique(token,
					 &npa_sid,
					 &token->sids,
					 &token->num_sids);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}

	subreq = np_sock_connect_send(
		state, state->ev, state->socketpath, state->npa_req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, local_np_connect_connected, req);

	return req;
}

static void local_np_connect_connected(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct local_np_connect_state *state = tevent_req_data(
		req, struct local_np_connect_state);
	int ret;

	ret = np_sock_connect_recv(subreq, state, &state->npa_stream);
	TALLOC_FREE(subreq);

	if (ret == 0) {
		tevent_req_done(req);
		return;
	}

	DBG_DEBUG("np_sock_connect failed: %s\n", strerror(ret));

	if (!lp_rpc_start_on_demand_helpers()) {
		/*
		 * samba-dcerpcd should already be started in
		 * daemon/standalone mode when "rpc start on demand
		 * helpers = false". We are prohibited from starting
		 * on demand as a named-pipe helper.
		 */
		DBG_ERR("Can't connect to a running samba-dcerpcd. smb.conf "
			"config prohibits starting as named pipe helper as "
			"the [global] section contains "
			"\"rpc start on demand helpers = false\".\n");
		tevent_req_error(req, ret);
		return;
	}

	/*
	 * samba-dcerpcd isn't running. We need to start it.
	 * Note if it doesn't start we treat this as a fatal
	 * error for connecting to the named pipe and don't
	 * keep trying to restart for this connection.
	 */
	subreq = start_rpc_host_send(state, state->ev);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, local_np_connect_started, req);
}

static void local_np_connect_started(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct local_np_connect_state *state = tevent_req_data(
		req, struct local_np_connect_state);
	int ret;

	ret = start_rpc_host_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		DBG_DEBUG("start_rpc_host_recv failed: %s\n",
			  strerror(ret));
		return;
	}

	subreq = np_sock_connect_send(
		state, state->ev, state->socketpath, state->npa_req);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, local_np_connect_retried, req);
}

static void local_np_connect_retried(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct local_np_connect_state *state = tevent_req_data(
		req, struct local_np_connect_state);
	int ret;

	ret = np_sock_connect_recv(subreq, state, &state->npa_stream);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	tevent_req_done(req);
}

/**
 * @brief Receive handle to a local named pipe RPC interface
 *
 * @param[in] req The tevent_req that started the operation
 * @param[in] ev      The tevent context to use.
 * @param[in] mem_ctx The memory context to put pstream on
 * @param[out] pstream The established connection to the RPC server
 *
 * @return 0/errno
 */

int local_np_connect_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct tstream_context **pstream)
{
	struct local_np_connect_state *state = tevent_req_data(
		req, struct local_np_connect_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		tevent_req_received(req);
		return err;
	}

	*pstream = talloc_move(mem_ctx, &state->npa_stream);
	return 0;
}

/**
 * @brief Sync connect to a local named pipe RPC interface
 *
 * Start "samba-dcerpcd" on demand if it does not exist
 *
 * @param[in] pipename The raw pipename to connect to without path
 * @param[in] remote_client_name The client name to transmit
 * @param[in] remote_client_addr The client addr to transmit
 * @param[in] local_server_name The server name to transmit
 * @param[in] local_server_addr The server addr to transmit
 * @param[in] session_info The authorization info to use
 * @param[in] need_idle_server Does this need to be an exclusive server?
 * @param[in] mem_ctx  The memory context to use.
 * @param[out] pstream The established connection to the RPC server
 * @return 0/errno
 */

int local_np_connect(
	const char *pipename,
	enum dcerpc_transport_t transport,
	const char *remote_client_name,
	const struct tsocket_address *remote_client_addr,
	const char *local_server_name,
	const struct tsocket_address *local_server_addr,
	const struct auth_session_info *session_info,
	bool need_idle_server,
	TALLOC_CTX *mem_ctx,
	struct tstream_context **pstream)
{
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	int ret = ENOMEM;

	ev = samba_tevent_context_init(mem_ctx);
	if (ev == NULL) {
		goto fail;
	}
	req = local_np_connect_send(
		ev,
		ev,
		pipename,
		transport,
		remote_client_name,
		remote_client_addr,
		local_server_name,
		local_server_addr,
		session_info,
		need_idle_server);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_unix(req, ev, &ret)) {
		goto fail;
	}
	ret = local_np_connect_recv(req, mem_ctx, pstream);
 fail:
	TALLOC_FREE(req);
	TALLOC_FREE(ev);
	return ret;
}
