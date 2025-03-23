/*
 *  RPC host
 *
 *  Implements samba-dcerpcd service.
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

/*
 * This binary has two usage modes:
 *
 * In the normal case when invoked from smbd or winbind it is given a
 * directory to scan via --libexec-rpcds and will invoke on demand any
 * binaries it finds there starting with rpcd_ when a named pipe
 * connection is requested.
 *
 * In the second mode it can be started explicitly from system startup
 * scripts.
 *
 * When Samba is set up as an Active Directory Domain Controller the
 * normal samba binary overrides and provides DCERPC services, whilst
 * allowing samba-dcerpcd to provide the services that smbd used to
 * provide in that set-up, such as SRVSVC.
 *
 * The second mode can also be useful for use outside of the Samba framework,
 * for example, use with the Linux kernel SMB2 server ksmbd. In this mode
 * it behaves like inetd and listens on sockets on behalf of RPC server
 * implementations.
 */

#include "replace.h"
#include <fnmatch.h>
#include "lib/cmdline/cmdline.h"
#include "lib/cmdline/closefrom_except.h"
#include "source3/include/includes.h"
#include "source3/include/auth.h"
#include "rpc_sock_helper.h"
#include "messages.h"
#include "lib/util_file.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/smb_strtox.h"
#include "lib/util/debug.h"
#include "lib/util/server_id.h"
#include "lib/util/util_tdb.h"
#include "lib/util/util_file.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/async_req/async_sock.h"
#include "librpc/rpc/dcerpc_util.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/named_pipe_auth/npa_tstream.h"
#include "librpc/gen_ndr/ndr_rpc_host.h"
#include "source3/param/loadparm.h"
#include "source3/lib/global_contexts.h"
#include "lib/util/strv.h"
#include "lib/util/pidfile.h"
#include "source3/rpc_client/cli_pipe.h"
#include "librpc/gen_ndr/ndr_epmapper.h"
#include "librpc/gen_ndr/ndr_epmapper_c.h"
#include "nsswitch/winbind_client.h"
#include "libcli/security/dom_sid.h"
#include "libcli/security/security_token.h"

extern bool override_logfile;

struct rpc_server;
struct rpc_work_process;

/*
 * samba-dcerpcd state to keep track of rpcd_* servers.
 */
struct rpc_host {
	struct messaging_context *msg_ctx;
	struct rpc_server **servers;
	struct tdb_wrap *epmdb;

	int worker_stdin[2];

	bool np_helper;

	/*
	 * If we're started with --np-helper but nobody contacts us,
	 * we need to exit after a while. This will be deleted once
	 * the first real client connects and our self-exit mechanism
	 * when we don't have any worker processes left kicks in.
	 */
	struct tevent_timer *np_helper_shutdown;
};

/*
 * Map a RPC interface to a name. Used when filling the endpoint
 * mapper database
 */
struct rpc_host_iface_name {
	struct ndr_syntax_id iface;
	char *name;
};

/*
 * rpc_host representation for listening sockets. ncacn_ip_tcp might
 * listen on multiple explicit IPs, all with the same port.
 */
struct rpc_host_endpoint {
	struct rpc_server *server;
	struct dcerpc_binding *binding;
	struct ndr_syntax_id *interfaces;
	int *fds;
	size_t num_fds;
};

/*
 * Staging area until we sent the socket plus bind to the helper
 */
struct rpc_host_pending_client {
	struct rpc_host_pending_client *prev, *next;

	/*
	 * Pointer for the destructor to remove us from the list of
	 * pending clients
	 */
	struct rpc_server *server;

	/*
	 * Waiter for client exit before a helper accepted the request
	 */
	struct tevent_req *hangup_wait;

	/*
	 * Info to pick the worker
	 */
	struct ncacn_packet *bind_pkt;

	/*
	 * This is what we send down to the worker
	 */
	int sock;
	struct rpc_host_client *client;
};

/*
 * Representation of one worker process. For each rpcd_* executable
 * there will be more of than one of these.
 */
struct rpc_work_process {
	pid_t pid;

	/*
	 * !available means:
	 *
	 * Worker forked but did not send its initial status yet (not
	 * yet initialized)
	 *
	 * Worker died, but we did not receive SIGCHLD yet. We noticed
	 * it because we couldn't send it a message.
	 */
	bool available;

	/*
	 * Incremented by us when sending a client, decremented by
	 * MSG_RPC_HOST_WORKER_STATUS sent by workers whenever a
	 * client exits.
	 */
	uint32_t num_associations;
	uint32_t num_connections;

	/*
	 * Send SHUTDOWN to an idle child after a while
	 */
	struct tevent_timer *exit_timer;
};

/*
 * State for a set of running instances of an rpcd_* server executable
 */
struct rpc_server {
	struct rpc_host *host;
	/*
	 * Index into the rpc_host->servers array
	 */
	uint32_t server_index;

	const char *rpc_server_exe;

	struct rpc_host_endpoint **endpoints;
	struct rpc_host_iface_name *iface_names;

	size_t max_workers;
	size_t idle_seconds;

	/*
	 * "workers" can be larger than "max_workers": Internal
	 * connections require an idle worker to avoid deadlocks
	 * between RPC servers: netlogon requires samr, everybody
	 * requires winreg. And if a deep call in netlogon asks for a
	 * samr connection, this must never end up in the same
	 * process. named_pipe_auth_req_info8->need_idle_server is set
	 * in those cases.
	 */
	struct rpc_work_process *workers;

	struct rpc_host_pending_client *pending_clients;
};

struct rpc_server_get_endpoints_state {
	char **argl;
	char *ncalrpc_endpoint;
	enum dcerpc_transport_t only_transport;

	struct rpc_host_iface_name *iface_names;
	struct rpc_host_endpoint **endpoints;

	unsigned long num_workers;
	unsigned long idle_seconds;
};

static void rpc_server_get_endpoints_done(struct tevent_req *subreq);

/**
 * @brief Query interfaces from an rpcd helper
 *
 * Spawn a rpcd helper, ask it for the interfaces it serves via
 * --list-interfaces, parse the output
 *
 * @param[in] mem_ctx Memory context for the tevent_req
 * @param[in] ev Event context to run this on
 * @param[in] rpc_server_exe Binary to ask with --list-interfaces
 * @param[in] only_transport Filter out anything but this
 * @return The tevent_req representing this process
 */

static struct tevent_req *rpc_server_get_endpoints_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	const char *rpc_server_exe,
	enum dcerpc_transport_t only_transport)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct rpc_server_get_endpoints_state *state = NULL;
	const char *progname = NULL;

	req = tevent_req_create(
		mem_ctx, &state, struct rpc_server_get_endpoints_state);
	if (req == NULL) {
		return NULL;
	}
	state->only_transport = only_transport;

	progname = strrchr(rpc_server_exe, '/');
	if (progname != NULL) {
		progname += 1;
	} else {
		progname = rpc_server_exe;
	}

	state->ncalrpc_endpoint = talloc_strdup(state, progname);
	if (tevent_req_nomem(state->ncalrpc_endpoint, req)) {
		return tevent_req_post(req, ev);
	}

	state->argl = str_list_make_empty(state);
	str_list_add_printf(&state->argl, "%s", rpc_server_exe);
	str_list_add_printf(&state->argl, "--list-interfaces");
	str_list_add_printf(
		&state->argl, "--configfile=%s", get_dyn_CONFIGFILE());

	if (tevent_req_nomem(state->argl, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = file_ploadv_send(state, ev, state->argl, 65536);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, rpc_server_get_endpoints_done, req);
	return req;
}

/*
 * Parse a line of format
 *
 * 338cd001-2244-31f1-aaaa-900038001003/0x00000001 winreg
 *
 * and add it to the "piface_names" array.
 */

static struct rpc_host_iface_name *rpc_exe_parse_iface_line(
	TALLOC_CTX *mem_ctx,
	struct rpc_host_iface_name **piface_names,
	const char *line)
{
	struct rpc_host_iface_name *iface_names = *piface_names;
	struct rpc_host_iface_name *tmp = NULL, *result = NULL;
	size_t i, num_ifaces = talloc_array_length(iface_names);
	struct ndr_syntax_id iface;
	char *name = NULL;
	bool ok;

	ok = ndr_syntax_id_from_string(line, &iface);
	if (!ok) {
		DBG_WARNING("ndr_syntax_id_from_string() failed for: [%s]\n",
			    line);
		return NULL;
	}

	name = strchr(line, ' ');
	if (name == NULL) {
		return NULL;
	}
	name += 1;

	for (i=0; i<num_ifaces; i++) {
		result = &iface_names[i];

		if (ndr_syntax_id_equal(&result->iface, &iface)) {
			return result;
		}
	}

	if (num_ifaces + 1 < num_ifaces) {
		return NULL;
	}

	name = talloc_strdup(mem_ctx, name);
	if (name == NULL) {
		return NULL;
	}

	tmp = talloc_realloc(
		mem_ctx,
		iface_names,
		struct rpc_host_iface_name,
		num_ifaces + 1);
	if (tmp == NULL) {
		TALLOC_FREE(name);
		return NULL;
	}
	iface_names = tmp;

	result = &iface_names[num_ifaces];

	*result = (struct rpc_host_iface_name) {
		.iface = iface,
		.name = talloc_move(iface_names, &name),
	};

	*piface_names = iface_names;

	return result;
}

static struct rpc_host_iface_name *rpc_host_iface_names_find(
	struct rpc_host_iface_name *iface_names,
	const struct ndr_syntax_id *iface)
{
	size_t i, num_iface_names = talloc_array_length(iface_names);

	for (i=0; i<num_iface_names; i++) {
		struct rpc_host_iface_name *iface_name = &iface_names[i];

		if (ndr_syntax_id_equal(iface, &iface_name->iface)) {
			return iface_name;
		}
	}

	return NULL;
}

static bool dcerpc_binding_same_endpoint(
	const struct dcerpc_binding *b1, const struct dcerpc_binding *b2)
{
	enum dcerpc_transport_t t1 = dcerpc_binding_get_transport(b1);
	enum dcerpc_transport_t t2 = dcerpc_binding_get_transport(b2);
	const char *e1 = NULL, *e2 = NULL;
	int cmp;

	if (t1 != t2) {
		return false;
	}

	e1 = dcerpc_binding_get_string_option(b1, "endpoint");
	e2 = dcerpc_binding_get_string_option(b2, "endpoint");

	if ((e1 == NULL) && (e2 == NULL)) {
		return true;
	}
	if ((e1 == NULL) || (e2 == NULL)) {
		return false;
	}
	cmp = strcmp(e1, e2);
	return (cmp == 0);
}

/**
 * @brief Filter whether we want to serve an endpoint
 *
 * samba-dcerpcd might want to serve all endpoints a rpcd reported to
 * us via --list-interfaces.
 *
 * In member mode, we only serve named pipes. Indicated by NCACN_NP
 * passed in via "only_transport".
 *
 * @param[in] binding Which binding is in question?
 * @param[in] only_transport Exclusive transport to serve
 * @return Do we want to serve "binding" from samba-dcerpcd?
 */

static bool rpc_host_serve_endpoint(
	struct dcerpc_binding *binding,
	enum dcerpc_transport_t only_transport)
{
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(binding);

	if (only_transport == NCA_UNKNOWN) {
		/* no filter around */
		return true;
	}

	if (transport != only_transport) {
		/* filter out */
		return false;
	}

	return true;
}

static struct rpc_host_endpoint *rpc_host_endpoint_find(
	struct rpc_server_get_endpoints_state *state,
	const char *binding_string)
{
	size_t i, num_endpoints = talloc_array_length(state->endpoints);
	struct rpc_host_endpoint **tmp = NULL, *ep = NULL;
	enum dcerpc_transport_t transport;
	NTSTATUS status;
	bool serve_this;

	ep = talloc_zero(state, struct rpc_host_endpoint);
	if (ep == NULL) {
		goto fail;
	}

	status = dcerpc_parse_binding(ep, binding_string, &ep->binding);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dcerpc_parse_binding(%s) failed: %s\n",
			  binding_string,
			  nt_errstr(status));
		goto fail;
	}

	serve_this = rpc_host_serve_endpoint(
		ep->binding, state->only_transport);
	if (!serve_this) {
		goto fail;
	}

	transport = dcerpc_binding_get_transport(ep->binding);

	if (transport == NCALRPC) {
		const char *ncalrpc_sock = dcerpc_binding_get_string_option(
			ep->binding, "endpoint");

		if (ncalrpc_sock == NULL) {
			/*
			 * generic ncalrpc:, set program-specific
			 * socket name. epmapper will redirect clients
			 * properly.
			 */
			status = dcerpc_binding_set_string_option(
				ep->binding,
				"endpoint",
				state->ncalrpc_endpoint);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_DEBUG("dcerpc_binding_set_string_option "
					  "failed: %s\n",
					  nt_errstr(status));
				goto fail;
			}
		}
	}

	for (i=0; i<num_endpoints; i++) {

		bool ok = dcerpc_binding_same_endpoint(
			ep->binding, state->endpoints[i]->binding);

		if (ok) {
			TALLOC_FREE(ep);
			return state->endpoints[i];
		}
	}

	if (num_endpoints + 1 < num_endpoints) {
		goto fail;
	}

	tmp = talloc_realloc(
		state,
		state->endpoints,
		struct rpc_host_endpoint *,
		num_endpoints + 1);
	if (tmp == NULL) {
		goto fail;
	}
	state->endpoints = tmp;
	state->endpoints[num_endpoints] = talloc_move(state->endpoints, &ep);

	return state->endpoints[num_endpoints];
fail:
	TALLOC_FREE(ep);
	return NULL;
}

static bool ndr_interfaces_add_unique(
	TALLOC_CTX *mem_ctx,
	struct ndr_syntax_id **pifaces,
	const struct ndr_syntax_id *iface)
{
	struct ndr_syntax_id *ifaces = *pifaces;
	size_t i, num_ifaces = talloc_array_length(ifaces);

	for (i=0; i<num_ifaces; i++) {
		if (ndr_syntax_id_equal(iface, &ifaces[i])) {
			return true;
		}
	}

	if (num_ifaces + 1 < num_ifaces) {
		return false;
	}
	ifaces = talloc_realloc(
		mem_ctx,
		ifaces,
		struct ndr_syntax_id,
		num_ifaces + 1);
	if (ifaces == NULL) {
		return false;
	}
	ifaces[num_ifaces] = *iface;

	*pifaces = ifaces;
	return true;
}

/*
 * Read the text reply from the rpcd_* process telling us what
 * endpoints it will serve when asked with --list-interfaces.
 */
static void rpc_server_get_endpoints_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_server_get_endpoints_state *state = tevent_req_data(
		req, struct rpc_server_get_endpoints_state);
	struct rpc_host_iface_name *iface = NULL;
	uint8_t *buf = NULL;
	size_t buflen;
	char **lines = NULL;
	int ret, i, num_lines;

	ret = file_ploadv_recv(subreq, state, &buf);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}

	buflen = talloc_get_size(buf);
	if (buflen == 0) {
		tevent_req_done(req);
		return;
	}

	lines = file_lines_parse((char *)buf, buflen, &num_lines, state);
	if (tevent_req_nomem(lines, req)) {
		return;
	}

	if (num_lines < 2) {
		DBG_DEBUG("Got %d lines, expected at least 2\n", num_lines);
		tevent_req_error(req, EINVAL);
		return;
	}

	state->num_workers = smb_strtoul(
		lines[0], NULL, 10, &ret, SMB_STR_FULL_STR_CONV);
	if (ret != 0) {
		DBG_DEBUG("Could not parse num_workers(%s): %s\n",
			  lines[0],
			  strerror(ret));
		tevent_req_error(req, ret);
		return;
	}
	/*
	 * We need to limit the number of workers in order
	 * to put the worker index into a 16-bit space,
	 * in order to use a 16-bit association group space
	 * per worker.
	 */
	state->num_workers = MIN(state->num_workers, UINT16_MAX);

	state->idle_seconds = smb_strtoul(
		lines[1], NULL, 10, &ret, SMB_STR_FULL_STR_CONV);
	if (ret != 0) {
		DBG_DEBUG("Could not parse idle_seconds (%s): %s\n",
			  lines[1],
			  strerror(ret));
		tevent_req_error(req, ret);
		return;
	}

	DBG_DEBUG("num_workers=%lu, idle_seconds=%lu for %s\n",
		  state->num_workers,
		  state->idle_seconds,
		  state->argl[0]);

	for (i=2; i<num_lines; i++) {
		char *line = lines[i];
		struct rpc_host_endpoint *endpoint = NULL;
		bool ok;

		if (line[0] != ' ') {
			iface = rpc_exe_parse_iface_line(
				state, &state->iface_names, line);
			if (iface == NULL) {
				DBG_WARNING(
					"rpc_exe_parse_iface_line failed "
					"for: [%s] from %s\n",
					line,
					state->argl[0]);
				tevent_req_oom(req);
				return;
			}
			continue;
		}

		if (iface == NULL) {
			DBG_DEBUG("Interface GUID line missing\n");
			tevent_req_error(req, EINVAL);
			return;
		}

		endpoint = rpc_host_endpoint_find(state, line+1);
		if (endpoint == NULL) {
			DBG_DEBUG("rpc_host_endpoint_find for %s failed\n",
				  line+1);
			continue;
		}

		ok = ndr_interfaces_add_unique(
			endpoint,
			&endpoint->interfaces,
			&iface->iface);
		if (!ok) {
			DBG_DEBUG("ndr_interfaces_add_unique failed\n");
			tevent_req_oom(req);
			return;
		}
	}

	tevent_req_done(req);
}

/**
 * @brief Receive output from --list-interfaces
 *
 * @param[in] req The async req that just finished
 * @param[in] mem_ctx Where to put the output on
 * @param[out] endpoints The endpoints to be listened on
 * @param[out] iface_names Annotation for epm_Lookup's epm_entry_t
 * @return 0/errno
 */
static int rpc_server_get_endpoints_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct rpc_host_endpoint ***endpoints,
	struct rpc_host_iface_name **iface_names,
	size_t *num_workers,
	size_t *idle_seconds)
{
	struct rpc_server_get_endpoints_state *state = tevent_req_data(
		req, struct rpc_server_get_endpoints_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		tevent_req_received(req);
		return err;
	}

	*endpoints = talloc_move(mem_ctx, &state->endpoints);
	*iface_names = talloc_move(mem_ctx, &state->iface_names);
	*num_workers = state->num_workers;
	*idle_seconds = state->idle_seconds;
	tevent_req_received(req);
	return 0;
}

/*
 * For NCACN_NP we get the named pipe auth info from smbd, if a client
 * comes in via TCP or NCALPRC we need to invent it ourselves with
 * anonymous session info.
 */

static NTSTATUS rpc_host_generate_npa_info8_from_sock(
	TALLOC_CTX *mem_ctx,
	enum dcerpc_transport_t transport,
	int sock,
	const struct samba_sockaddr *peer_addr,
	struct named_pipe_auth_req_info8 **pinfo8)
{
	struct named_pipe_auth_req_info8 *info8 = NULL;
	struct samba_sockaddr local_addr = {
		.sa_socklen = sizeof(struct sockaddr_storage),
	};
	struct tsocket_address *taddr = NULL;
	char *remote_client_name = NULL;
	char *remote_client_addr = NULL;
	char *local_server_name = NULL;
	char *local_server_addr = NULL;
	char *(*tsocket_address_to_name_fn)(
		const struct tsocket_address *addr,
		TALLOC_CTX *mem_ctx) = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	int ret;

	/*
	 * For NCACN_NP we get the npa info from smbd
	 */
	SMB_ASSERT((transport == NCACN_IP_TCP) || (transport == NCALRPC));

	tsocket_address_to_name_fn = (transport == NCACN_IP_TCP) ?
		tsocket_address_inet_addr_string : tsocket_address_unix_path;

	info8 = talloc_zero(mem_ctx, struct named_pipe_auth_req_info8);
	if (info8 == NULL) {
		goto fail;
	}
	info8->session_info =
		talloc_zero(info8, struct auth_session_info_transport);
	if (info8->session_info == NULL) {
		goto fail;
	}

	status = make_session_info_anonymous(
		info8->session_info,
		&info8->session_info->session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("make_session_info_anonymous failed: %s\n",
			  nt_errstr(status));
		goto fail;
	}

	ret = tsocket_address_bsd_from_samba_sockaddr(info8,
						      peer_addr,
						      &taddr);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		DBG_DEBUG("tsocket_address_bsd_from_samba_sockaddr failed: "
			  "%s\n",
			  strerror(errno));
		goto fail;
	}
	remote_client_addr = tsocket_address_to_name_fn(taddr, info8);
	if (remote_client_addr == NULL) {
		DBG_DEBUG("tsocket_address_to_name_fn failed\n");
		goto nomem;
	}
	TALLOC_FREE(taddr);

	remote_client_name = talloc_strdup(info8, remote_client_addr);
	if (remote_client_name == NULL) {
		DBG_DEBUG("talloc_strdup failed\n");
		goto nomem;
	}

	if (transport == NCACN_IP_TCP) {
		bool ok = samba_sockaddr_get_port(peer_addr,
						  &info8->remote_client_port);
		if (!ok) {
			DBG_DEBUG("samba_sockaddr_get_port failed\n");
			status = NT_STATUS_INVALID_PARAMETER;
			goto fail;
		}
	}

	ret = getsockname(sock, &local_addr.u.sa, &local_addr.sa_socklen);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		DBG_DEBUG("getsockname failed: %s\n", strerror(errno));
		goto fail;
	}

	ret = tsocket_address_bsd_from_samba_sockaddr(info8,
						      &local_addr,
						      &taddr);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		DBG_DEBUG("tsocket_address_bsd_from_samba_sockaddr failed: "
			  "%s\n",
			  strerror(errno));
		goto fail;
	}
	local_server_addr = tsocket_address_to_name_fn(taddr, info8);
	if (local_server_addr == NULL) {
		DBG_DEBUG("tsocket_address_to_name_fn failed\n");
		goto nomem;
	}
	TALLOC_FREE(taddr);

	local_server_name = talloc_strdup(info8, local_server_addr);
	if (local_server_name == NULL) {
		DBG_DEBUG("talloc_strdup failed\n");
		goto nomem;
	}

	if (transport == NCACN_IP_TCP) {
		bool ok = samba_sockaddr_get_port(&local_addr,
						  &info8->local_server_port);
		if (!ok) {
			DBG_DEBUG("samba_sockaddr_get_port failed\n");
			status = NT_STATUS_INVALID_PARAMETER;
			goto fail;
		}
	}

	if (transport == NCALRPC) {
		uid_t uid;
		gid_t gid;

		ret = getpeereid(sock, &uid, &gid);
		if (ret < 0) {
			status = map_nt_error_from_unix(errno);
			DBG_DEBUG("getpeereid failed: %s\n", strerror(errno));
			goto fail;
		}

		if (uid == sec_initial_uid()) {

			/*
			 * Indicate "root" to gensec
			 */

			TALLOC_FREE(remote_client_addr);
			TALLOC_FREE(remote_client_name);

			ret = tsocket_address_unix_from_path(
				info8,
				AS_SYSTEM_MAGIC_PATH_TOKEN,
				&taddr);
			if (ret == -1) {
				DBG_DEBUG("tsocket_address_unix_from_path "
					  "failed\n");
				goto nomem;
			}

			remote_client_addr =
				tsocket_address_unix_path(taddr, info8);
			if (remote_client_addr == NULL) {
				DBG_DEBUG("tsocket_address_unix_path "
					  "failed\n");
				goto nomem;
			}
			remote_client_name =
				talloc_strdup(info8, remote_client_addr);
			if (remote_client_name == NULL) {
				DBG_DEBUG("talloc_strdup failed\n");
				goto nomem;
			}
		}
	}

	info8->remote_client_addr = remote_client_addr;
	info8->remote_client_name = remote_client_name;
	info8->local_server_addr = local_server_addr;
	info8->local_server_name = local_server_name;

	*pinfo8 = info8;
	return NT_STATUS_OK;

nomem:
	status = NT_STATUS_NO_MEMORY;
fail:
	TALLOC_FREE(info8);
	return status;
}

struct rpc_host_bind_read_state {
	struct tevent_context *ev;

	int sock;
	struct tstream_context *plain;
	struct tstream_context *npa_stream;

	struct ncacn_packet *pkt;
	struct rpc_host_client *client;
};

static void rpc_host_bind_read_cleanup(
	struct tevent_req *req, enum tevent_req_state req_state);
static void rpc_host_bind_read_got_npa(struct tevent_req *subreq);
static void rpc_host_bind_read_got_bind(struct tevent_req *subreq);

/*
 * Wait for a bind packet from a client.
 */
static struct tevent_req *rpc_host_bind_read_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	enum dcerpc_transport_t transport,
	int *psock,
	const struct samba_sockaddr *peer_addr)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct rpc_host_bind_read_state *state = NULL;
	int rc, sock_dup;
	NTSTATUS status;

	req = tevent_req_create(
		mem_ctx, &state, struct rpc_host_bind_read_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;

	state->sock = *psock;
	*psock = -1;

	tevent_req_set_cleanup_fn(req, rpc_host_bind_read_cleanup);

	state->client = talloc_zero(state, struct rpc_host_client);
	if (tevent_req_nomem(state->client, req)) {
		return tevent_req_post(req, ev);
	}

	/*
	 * Dup the socket to read the first RPC packet:
	 * tstream_bsd_existing_socket() takes ownership with
	 * autoclose, but we need to send "sock" down to our worker
	 * process later.
	 */
	sock_dup = dup(state->sock);
	if (sock_dup == -1) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	rc = tstream_bsd_existing_socket(state, sock_dup, &state->plain);
	if (rc == -1) {
		DBG_DEBUG("tstream_bsd_existing_socket failed: %s\n",
			  strerror(errno));
		tevent_req_error(req, errno);
		close(sock_dup);
		return tevent_req_post(req, ev);
	}
	/* as server we want to fail early */
	tstream_bsd_fail_readv_first_error(state->plain, true);

	if (transport == NCACN_NP) {
		subreq = tstream_npa_accept_existing_send(
			state,
			ev,
			state->plain,
			FILE_TYPE_MESSAGE_MODE_PIPE,
			0xff | 0x0400 | 0x0100,
			4096);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			subreq, rpc_host_bind_read_got_npa, req);
		return req;
	}

	status = rpc_host_generate_npa_info8_from_sock(
		state->client,
		transport,
		state->sock,
		peer_addr,
		&state->client->npa_info8);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}

	subreq = dcerpc_read_ncacn_packet_send(state, ev, state->plain);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, rpc_host_bind_read_got_bind, req);
	return req;
}

static void rpc_host_bind_read_cleanup(
	struct tevent_req *req, enum tevent_req_state req_state)
{
	struct rpc_host_bind_read_state *state = tevent_req_data(
		req, struct rpc_host_bind_read_state);

	if ((req_state == TEVENT_REQ_RECEIVED) && (state->sock != -1)) {
		close(state->sock);
		state->sock = -1;
	}
}

static void rpc_host_bind_read_got_npa(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_host_bind_read_state *state = tevent_req_data(
		req, struct rpc_host_bind_read_state);
	struct named_pipe_auth_req_info8 *info8 = NULL;
	int ret, err;

	ret = tstream_npa_accept_existing_recv(subreq,
					       &err,
					       state,
					       &state->npa_stream,
					       &info8,
					       NULL,  /* transport */
					       NULL,  /* remote_client_addr */
					       NULL,  /* remote_client_name */
					       NULL,  /* local_server_addr */
					       NULL,  /* local_server_name */
					       NULL); /* session_info */
	if (ret == -1) {
		tevent_req_error(req, err);
		return;
	}

	state->client->npa_info8 = talloc_move(state->client, &info8);

	subreq = dcerpc_read_ncacn_packet_send(
		state, state->ev, state->npa_stream);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, rpc_host_bind_read_got_bind, req);
}

static void rpc_host_bind_read_got_bind(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_host_bind_read_state *state = tevent_req_data(
		req, struct rpc_host_bind_read_state);
	struct ncacn_packet *pkt = NULL;
	NTSTATUS status;

	status = dcerpc_read_ncacn_packet_recv(
		subreq,
		state->client,
		&pkt,
		&state->client->bind_packet);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dcerpc_read_ncacn_packet_recv failed: %s\n",
			  nt_errstr(status));
		tevent_req_error(req, EINVAL); /* TODO */
		return;
	}
	state->pkt = talloc_move(state, &pkt);

	tevent_req_done(req);
}

static int rpc_host_bind_read_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	int *sock,
	struct rpc_host_client **client,
	struct ncacn_packet **bind_pkt)
{
	struct rpc_host_bind_read_state *state = tevent_req_data(
		req, struct rpc_host_bind_read_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		tevent_req_received(req);
		return err;
	}

	*sock = state->sock;
	state->sock = -1;

	*client = talloc_move(mem_ctx, &state->client);
	*bind_pkt = talloc_move(mem_ctx, &state->pkt);
	tevent_req_received(req);
	return 0;
}

/*
 * Start the given rpcd_* binary.
 */
static int rpc_host_exec_worker(struct rpc_server *server, size_t idx)
{
	struct rpc_work_process *worker = &server->workers[idx];
	char **argv = NULL;
	int ret = ENOMEM;

	argv = str_list_make_empty(server);
	str_list_add_printf(
		&argv, "%s", server->rpc_server_exe);
	str_list_add_printf(
		&argv, "--configfile=%s", get_dyn_CONFIGFILE());
	str_list_add_printf(
		&argv, "--worker-group=%"PRIu32, server->server_index);
	str_list_add_printf(
		&argv, "--worker-index=%zu", idx);
	str_list_add_printf(
		&argv, "--debuglevel=%d", debuglevel_get_class(DBGC_RPC_SRV));
	if (!is_default_dyn_LOGFILEBASE()) {
		str_list_add_printf(
			&argv, "--log-basename=%s", get_dyn_LOGFILEBASE());
	}
	if (argv == NULL) {
		ret = ENOMEM;
		goto fail;
	}

	worker->pid = fork();
	if (worker->pid == -1) {
		ret = errno;
		goto fail;
	}
	if (worker->pid == 0) {
		/* Child. */
		close(server->host->worker_stdin[1]);
		ret = dup2(server->host->worker_stdin[0], 0);
		if (ret != 0) {
			exit(1);
		}
		execv(argv[0], argv);
		_exit(1);
	}

	DBG_DEBUG("Creating worker %s for index %zu: pid=%d\n",
		  server->rpc_server_exe,
		  idx,
		  (int)worker->pid);

	ret = 0;
fail:
	TALLOC_FREE(argv);
	return ret;
}

/*
 * Find an rpcd_* worker for an external client, respect server->max_workers
 */
static struct rpc_work_process *rpc_host_find_worker(struct rpc_server *server)
{
	struct rpc_work_process *worker = NULL;
	struct rpc_work_process *perfect_worker = NULL;
	struct rpc_work_process *best_worker = NULL;
	size_t empty_slot = SIZE_MAX;
	size_t i;

	for (i=0; i<server->max_workers; i++) {
		worker = &server->workers[i];

		if (worker->pid == -1) {
			empty_slot = MIN(empty_slot, i);
			continue;
		}
		if (!worker->available) {
			continue;
		}
		if (worker->num_associations == 0) {
			/*
			 * We have an idle worker...
			 */
			perfect_worker = worker;
			break;
		}
		if (best_worker == NULL) {
			/*
			 * It's busy, but the best so far...
			 */
			best_worker = worker;
			continue;
		}
		if (worker->num_associations < best_worker->num_associations) {
			/*
			 * It's also busy, but has less association groups
			 * (logical clients)
			 */
			best_worker = worker;
			continue;
		}
		if (worker->num_associations > best_worker->num_associations) {
			/*
			 * It's not better
			 */
			continue;
		}
		/*
		 * Ok, with the same number of association groups
		 * we pick the one with the lowest number of connections
		 */
		if (worker->num_connections < best_worker->num_connections) {
			best_worker = worker;
			continue;
		}
	}

	if (perfect_worker != NULL) {
		return perfect_worker;
	}

	if (empty_slot < SIZE_MAX) {
		int ret = rpc_host_exec_worker(server, empty_slot);
		if (ret != 0) {
			DBG_WARNING("Could not fork worker: %s\n",
				    strerror(ret));
		}
		return NULL;
	}

	if (best_worker != NULL) {
		return best_worker;
	}

	return NULL;
}

/*
 * Find an rpcd_* worker for an internal connection, possibly go beyond
 * server->max_workers
 */
static struct rpc_work_process *rpc_host_find_idle_worker(
	struct rpc_server *server)
{
	struct rpc_work_process *worker = NULL, *tmp = NULL;
	size_t i, num_workers = talloc_array_length(server->workers);
	size_t empty_slot = SIZE_MAX;
	int ret;

	for (i=server->max_workers; i<num_workers; i++) {
		worker = &server->workers[i];

		if (worker->pid == -1) {
			empty_slot = MIN(empty_slot, i);
			continue;
		}
		if (!worker->available) {
			continue;
		}
		if (worker->num_associations == 0) {
			return &server->workers[i];
		}
	}

	if (empty_slot < SIZE_MAX) {
		ret = rpc_host_exec_worker(server, empty_slot);
		if (ret != 0) {
			DBG_WARNING("Could not fork worker: %s\n",
				    strerror(ret));
		}
		return NULL;
	}

	/*
	 * All workers are busy. We need to expand the number of
	 * workers because we were asked for an idle worker.
	 */
	if (num_workers >= UINT16_MAX) {
		/*
		 * The worker index would not fit into 16-bits
		 */
		return NULL;
	}
	tmp = talloc_realloc(
		server,
		server->workers,
		struct rpc_work_process,
		num_workers+1);
	if (tmp == NULL) {
		return NULL;
	}
	server->workers = tmp;

	server->workers[num_workers] = (struct rpc_work_process) { .pid=-1, };

	ret = rpc_host_exec_worker(server, num_workers);
	if (ret != 0) {
		DBG_WARNING("Could not exec worker: %s\n", strerror(ret));
	}

	return NULL;
}

/*
 * Find an rpcd_* process to talk to. Start a new one if necessary.
 */
static void rpc_host_distribute_clients(struct rpc_server *server)
{
	struct rpc_work_process *worker = NULL;
	struct rpc_host_pending_client *pending_client = NULL;
	uint32_t assoc_group_id;
	DATA_BLOB blob;
	struct iovec iov;
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	const char *client_type = NULL;

again:
	pending_client = server->pending_clients;
	if (pending_client == NULL) {
		DBG_DEBUG("No pending clients\n");
		return;
	}

	assoc_group_id = pending_client->bind_pkt->u.bind.assoc_group_id;

	if (assoc_group_id != 0) {
		size_t num_workers = talloc_array_length(server->workers);
		uint16_t worker_index = assoc_group_id >> 16;

		client_type = "associated";

		if (worker_index >= num_workers) {
			DBG_DEBUG("Invalid assoc group id %"PRIu32"\n",
				  assoc_group_id);
			goto done;
		}
		worker = &server->workers[worker_index];

		if ((worker->pid == -1) || !worker->available) {
			DBG_DEBUG("Requested worker index %"PRIu16": "
				  "pid=%d, available=%d\n",
				  worker_index,
				  (int)worker->pid,
				  (int)worker->available);
			/*
			 * Pick a random one for a proper bind nack
			 */
			client_type = "associated+lost";
			worker = rpc_host_find_worker(server);
		}
	} else {
		struct auth_session_info_transport *session_info =
			pending_client->client->npa_info8->session_info;
		uint32_t flags = 0;
		bool found;

		client_type = "new";

		found = security_token_find_npa_flags(
			session_info->session_info->security_token,
			&flags);

		/* fresh assoc group requested */
		if (found & (flags & SAMBA_NPA_FLAGS_NEED_IDLE)) {
			client_type = "new+exclusive";
			worker = rpc_host_find_idle_worker(server);
		} else {
			client_type = "new";
			worker = rpc_host_find_worker(server);
		}
	}

	if (worker == NULL) {
		DBG_DEBUG("No worker found for %s client\n", client_type);
		return;
	}

	DLIST_REMOVE(server->pending_clients, pending_client);

	ndr_err = ndr_push_struct_blob(
		&blob,
		pending_client,
		pending_client->client,
		(ndr_push_flags_fn_t)ndr_push_rpc_host_client);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("ndr_push_rpc_host_client failed: %s\n",
			    ndr_errstr(ndr_err));
		goto done;
	}

	DBG_INFO("Sending %s client %s to %d with "
		 "%"PRIu32" associations and %"PRIu32" connections\n",
		 client_type,
		 server->rpc_server_exe,
		 worker->pid,
		 worker->num_associations,
		 worker->num_connections);

	iov = (struct iovec) {
		.iov_base = blob.data, .iov_len = blob.length,
	};

	status = messaging_send_iov(
		server->host->msg_ctx,
		pid_to_procid(worker->pid),
		MSG_RPC_HOST_NEW_CLIENT,
		&iov,
		1,
		&pending_client->sock,
		1);
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		DBG_DEBUG("worker %d died, sigchld not yet received?\n",
			  worker->pid);
		DLIST_ADD(server->pending_clients, pending_client);
		worker->available = false;
		goto again;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("messaging_send_iov failed: %s\n",
			  nt_errstr(status));
		goto done;
	}
	if (assoc_group_id == 0) {
		worker->num_associations += 1;
	}
	worker->num_connections += 1;
	TALLOC_FREE(worker->exit_timer);

	TALLOC_FREE(server->host->np_helper_shutdown);

done:
	TALLOC_FREE(pending_client);
}

static int rpc_host_pending_client_destructor(
	struct rpc_host_pending_client *p)
{
	TALLOC_FREE(p->hangup_wait);
	if (p->sock != -1) {
		close(p->sock);
		p->sock = -1;
	}
	DLIST_REMOVE(p->server->pending_clients, p);
	return 0;
}

/*
 * Exception condition handler before rpcd_* worker
 * is handling the socket. Either the client exited or
 * sent unexpected data after the initial bind.
 */
static void rpc_host_client_exited(struct tevent_req *subreq)
{
	struct rpc_host_pending_client *pending = tevent_req_callback_data(
		subreq, struct rpc_host_pending_client);
	bool ok;
	int err;

	ok = wait_for_read_recv(subreq, &err);

	TALLOC_FREE(subreq);
	pending->hangup_wait = NULL;

	if (ok) {
		DBG_DEBUG("client on sock %d sent data\n", pending->sock);
	} else {
		DBG_DEBUG("client exited with %s\n", strerror(err));
	}
	TALLOC_FREE(pending);
}

struct rpc_iface_binding_map {
	struct ndr_syntax_id iface;
	char *bindings;
};

static bool rpc_iface_binding_map_add_endpoint(
	TALLOC_CTX *mem_ctx,
	const struct rpc_host_endpoint *ep,
	struct rpc_host_iface_name *iface_names,
	struct rpc_iface_binding_map **pmaps)
{
	const struct ndr_syntax_id mgmt_iface = {
		{0xafa8bd80,
		 0x7d8a,
		 0x11c9,
		 {0xbe,0xf4},
		 {0x08,0x00,0x2b,0x10,0x29,0x89}
		},
		1.0};

	struct rpc_iface_binding_map *maps = *pmaps;
	size_t i, num_ifaces = talloc_array_length(ep->interfaces);
	char *binding_string = NULL;
	bool ok = false;

	binding_string = dcerpc_binding_string(mem_ctx, ep->binding);
	if (binding_string == NULL) {
		return false;
	}

	for (i=0; i<num_ifaces; i++) {
		const struct ndr_syntax_id *iface = &ep->interfaces[i];
		size_t j, num_maps = talloc_array_length(maps);
		struct rpc_iface_binding_map *map = NULL;
		char *p = NULL;

		if (ndr_syntax_id_equal(iface, &mgmt_iface)) {
			/*
			 * mgmt is offered everywhere, don't put it
			 * into epmdb.tdb.
			 */
			continue;
		}

		for (j=0; j<num_maps; j++) {
			map = &maps[j];
			if (ndr_syntax_id_equal(&map->iface, iface)) {
				break;
			}
		}

		if (j == num_maps) {
			struct rpc_iface_binding_map *tmp = NULL;
			struct rpc_host_iface_name *iface_name = NULL;

			iface_name = rpc_host_iface_names_find(
				iface_names, iface);
			if (iface_name == NULL) {
				goto fail;
			}

			tmp = talloc_realloc(
				mem_ctx,
				maps,
				struct rpc_iface_binding_map,
				num_maps+1);
			if (tmp == NULL) {
				goto fail;
			}
			maps = tmp;

			map = &maps[num_maps];
			*map = (struct rpc_iface_binding_map) {
				.iface = *iface,
				.bindings = talloc_move(
					maps, &iface_name->name),
			};
		}

		p = strv_find(map->bindings, binding_string);
		if (p == NULL) {
			int ret = strv_add(
				maps, &map->bindings, binding_string);
			if (ret != 0) {
				goto fail;
			}
		}
	}

	ok = true;
fail:
	*pmaps = maps;
	return ok;
}

static bool rpc_iface_binding_map_add_endpoints(
	TALLOC_CTX *mem_ctx,
	struct rpc_host_endpoint **endpoints,
	struct rpc_host_iface_name *iface_names,
	struct rpc_iface_binding_map **pbinding_maps)
{
	size_t i, num_endpoints = talloc_array_length(endpoints);

	for (i=0; i<num_endpoints; i++) {
		bool ok = rpc_iface_binding_map_add_endpoint(
			mem_ctx, endpoints[i], iface_names, pbinding_maps);
		if (!ok) {
			return false;
		}
	}
	return true;
}

static bool rpc_host_fill_epm_db(
	struct tdb_wrap *db,
	struct rpc_host_endpoint **endpoints,
	struct rpc_host_iface_name *iface_names)
{
	struct rpc_iface_binding_map *maps = NULL;
	size_t i, num_maps;
	bool ret = false;
	bool ok;

	ok = rpc_iface_binding_map_add_endpoints(
		talloc_tos(), endpoints, iface_names, &maps);
	if (!ok) {
		goto fail;
	}

	num_maps = talloc_array_length(maps);

	for (i=0; i<num_maps; i++) {
		struct rpc_iface_binding_map *map = &maps[i];
		struct ndr_syntax_id_buf buf;
		char *keystr = ndr_syntax_id_buf_string(&map->iface, &buf);
		TDB_DATA value = {
			.dptr = (uint8_t *)map->bindings,
			.dsize = talloc_array_length(map->bindings),
		};
		int rc;

		rc = tdb_store(
			db->tdb, string_term_tdb_data(keystr), value, 0);
		if (rc == -1) {
			DBG_DEBUG("tdb_store() failed: %s\n",
				  tdb_errorstr(db->tdb));
			goto fail;
		}
	}

	ret = true;
fail:
	TALLOC_FREE(maps);
	return ret;
}

struct rpc_server_setup_state {
	struct rpc_server *server;
};

static void rpc_server_setup_got_endpoints(struct tevent_req *subreq);

/*
 * Async initialize state for all possible rpcd_* servers.
 * Note this does not start them.
 */
static struct tevent_req *rpc_server_setup_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct rpc_host *host,
	const char *rpc_server_exe)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct rpc_server_setup_state *state = NULL;
	struct rpc_server *server = NULL;

	req = tevent_req_create(
		mem_ctx, &state, struct rpc_server_setup_state);
	if (req == NULL) {
		return NULL;
	}
	state->server = talloc_zero(state, struct rpc_server);
	if (tevent_req_nomem(state->server, req)) {
		return tevent_req_post(req, ev);
	}

	server = state->server;

	*server = (struct rpc_server) {
		.host = host,
		.server_index = UINT32_MAX,
		.rpc_server_exe = talloc_strdup(server, rpc_server_exe),
	};
	if (tevent_req_nomem(server->rpc_server_exe, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = rpc_server_get_endpoints_send(
		state,
		ev,
		rpc_server_exe,
		host->np_helper ? NCACN_NP : NCA_UNKNOWN);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, rpc_server_setup_got_endpoints, req);
	return req;
}

static void rpc_server_setup_got_endpoints(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_server_setup_state *state = tevent_req_data(
		req, struct rpc_server_setup_state);
	struct rpc_server *server = state->server;
	int ret;
	size_t i, num_endpoints;
	bool ok;

	ret = rpc_server_get_endpoints_recv(
		subreq,
		server,
		&server->endpoints,
		&server->iface_names,
		&server->max_workers,
		&server->idle_seconds);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_nterror(req, map_nt_error_from_unix(ret));
		return;
	}

	server->workers = talloc_array(
		server, struct rpc_work_process, server->max_workers);
	if (tevent_req_nomem(server->workers, req)) {
		return;
	}

	for (i=0; i<server->max_workers; i++) {
		/* mark as not yet created */
		server->workers[i] = (struct rpc_work_process) { .pid=-1, };
	}

	num_endpoints = talloc_array_length(server->endpoints);

	for (i=0; i<num_endpoints; i++) {
		struct rpc_host_endpoint *e = server->endpoints[i];
		NTSTATUS status;
		size_t j;

		e->server = server;

		status = dcesrv_create_binding_sockets(
			e->binding, e, &e->num_fds, &e->fds);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
			continue;
		}
		if (tevent_req_nterror(req, status)) {
			DBG_DEBUG("dcesrv_create_binding_sockets failed: %s\n",
				  nt_errstr(status));
			return;
		}

		for (j=0; j<e->num_fds; j++) {
			ret = listen(e->fds[j], 256);
			if (ret == -1) {
				tevent_req_nterror(
					req, map_nt_error_from_unix(errno));
				return;
			}
		}
	}

	ok = rpc_host_fill_epm_db(
		server->host->epmdb, server->endpoints, server->iface_names);
	if (!ok) {
		DBG_DEBUG("rpc_host_fill_epm_db failed\n");
	}

	tevent_req_done(req);
}

static NTSTATUS rpc_server_setup_recv(
	struct tevent_req *req, TALLOC_CTX *mem_ctx, struct rpc_server **server)
{
	struct rpc_server_setup_state *state = tevent_req_data(
		req, struct rpc_server_setup_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*server = talloc_move(mem_ctx, &state->server);
	tevent_req_received(req);
	return NT_STATUS_OK;
}

/*
 * rpcd_* died. Called from SIGCHLD handler.
 */
static void rpc_worker_exited(struct rpc_host *host, pid_t pid)
{
	size_t i, num_servers = talloc_array_length(host->servers);
	struct rpc_work_process *worker = NULL;
	bool found_pid = false;
	bool have_active_worker = false;

	for (i=0; i<num_servers; i++) {
		struct rpc_server *server = host->servers[i];
		size_t j, num_workers;

		if (server == NULL) {
			/* SIGCHLD for --list-interfaces run */
			continue;
		}

		num_workers = talloc_array_length(server->workers);

		for (j=0; j<num_workers; j++) {
			worker = &server->workers[j];
			if (worker->pid == pid) {
				found_pid = true;
				worker->pid = -1;
				worker->available = false;
			}

			if (worker->pid != -1) {
				have_active_worker = true;
			}
		}
	}

	if (!found_pid) {
		DBG_WARNING("No worker with PID %d\n", (int)pid);
		return;
	}

	if (!have_active_worker && host->np_helper) {
		/*
		 * We have nothing left to do as an np_helper.
		 * Terminate ourselves (samba-dcerpcd). We will
		 * be restarted on demand anyway.
		 */
		DBG_DEBUG("Exiting idle np helper\n");
		exit(0);
	}
}

/*
 * rpcd_* died.
 */
static void rpc_host_sigchld(
	struct tevent_context *ev,
	struct tevent_signal *se,
	int signum,
	int count,
	void *siginfo,
	void *private_data)
{
	struct rpc_host *state = talloc_get_type_abort(
		private_data, struct rpc_host);
	pid_t pid;
	int wstatus;

	while ((pid = waitpid(-1, &wstatus, WNOHANG)) > 0) {
		DBG_DEBUG("pid=%d, wstatus=%d\n", (int)pid, wstatus);
		rpc_worker_exited(state, pid);
	}
}

/*
 * Idle timer fired for a rcpd_* worker. Ask it to terminate.
 */
static void rpc_host_exit_worker(
	struct tevent_context *ev,
	struct tevent_timer *te,
	struct timeval current_time,
	void *private_data)
{
	struct rpc_server *server = talloc_get_type_abort(
		private_data, struct rpc_server);
	size_t i, num_workers = talloc_array_length(server->workers);

	/*
	 * Scan for the right worker. We don't have too many of those,
	 * and maintaining an index would be more data structure effort.
	 */

	for (i=0; i<num_workers; i++) {
		struct rpc_work_process *w = &server->workers[i];
		NTSTATUS status;

		if (w->exit_timer != te) {
			continue;
		}
		w->exit_timer = NULL;

		SMB_ASSERT(w->num_associations == 0);

		status = messaging_send(
			server->host->msg_ctx,
			pid_to_procid(w->pid),
			MSG_SHUTDOWN,
			NULL);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("Could not send SHUTDOWN msg: %s\n",
				  nt_errstr(status));
		}

		w->available = false;
		break;
	}
}

/*
 * rcpd_* worker replied with its status.
 */
static void rpc_host_child_status_recv(
	struct messaging_context *msg,
	void *private_data,
	uint32_t msg_type,
	struct server_id server_id,
	DATA_BLOB *data)
{
	struct rpc_host *host = talloc_get_type_abort(
		private_data, struct rpc_host);
	size_t num_servers = talloc_array_length(host->servers);
	struct rpc_server *server = NULL;
	size_t num_workers;
	pid_t src_pid = procid_to_pid(&server_id);
	struct rpc_work_process *worker = NULL;
	struct rpc_worker_status status_message;
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob_all_noalloc(
		data,
		&status_message,
		(ndr_pull_flags_fn_t)ndr_pull_rpc_worker_status);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		struct server_id_buf buf;
		DBG_WARNING("Got invalid message from pid %s\n",
			    server_id_str_buf(server_id, &buf));
		return;
	}
	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(rpc_worker_status, &status_message);
	}

	if (status_message.server_index >= num_servers) {
		DBG_WARNING("Got invalid server_index=%"PRIu32", "
			    "num_servers=%zu\n",
			    status_message.server_index,
			    num_servers);
		return;
	}

	server = host->servers[status_message.server_index];

	num_workers = talloc_array_length(server->workers);
	if (status_message.worker_index >= num_workers) {
		DBG_WARNING("Got invalid worker_index=%"PRIu32", "
			    "num_workers=%zu\n",
			    status_message.worker_index,
			    num_workers);
		return;
	}
	worker = &server->workers[status_message.worker_index];

	if (src_pid != worker->pid) {
		DBG_WARNING("Got idx=%"PRIu32" from %d, expected %d\n",
			    status_message.worker_index,
			    (int)src_pid,
			    worker->pid);
		return;
	}

	worker->available = true;
	worker->num_associations = status_message.num_association_groups;
	worker->num_connections = status_message.num_connections;

	if (worker->num_associations != 0) {
		TALLOC_FREE(worker->exit_timer);
	} else {
		worker->exit_timer = tevent_add_timer(
			messaging_tevent_context(msg),
			server->workers,
			tevent_timeval_current_ofs(server->idle_seconds, 0),
			rpc_host_exit_worker,
			server);
		/* No NULL check, it's not fatal if this does not work */
	}

	rpc_host_distribute_clients(server);
}

/*
 * samba-dcerpcd has been asked to shutdown.
 * Mark the initial tevent_req as done so we
 * exit the event loop.
 */
static void rpc_host_msg_shutdown(
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

/*
 * Only match directory entries starting in rpcd_
 */
static int rpcd_filter(const struct dirent *d)
{
	int match = fnmatch("rpcd_*", d->d_name, 0);
	return (match == 0) ? 1 : 0;
}

/*
 * Scan the given libexecdir for rpcd_* services
 * and return them as a strv list.
 */
static int rpc_host_list_servers(
	const char *libexecdir, TALLOC_CTX *mem_ctx, char **pservers)
{
	char *servers = NULL;
	struct dirent **namelist = NULL;
	int i, num_servers;
	int ret = ENOMEM;

	num_servers = scandir(libexecdir, &namelist, rpcd_filter, alphasort);
	if (num_servers == -1) {
		DBG_DEBUG("scandir failed: %s\n", strerror(errno));
		return errno;
	}

	for (i=0; i<num_servers; i++) {
		char *exe = talloc_asprintf(
			mem_ctx, "%s/%s", libexecdir, namelist[i]->d_name);
		if (exe == NULL) {
			goto fail;
		}

		ret = strv_add(mem_ctx, &servers, exe);
		TALLOC_FREE(exe);
		if (ret != 0) {
			goto fail;
		}
	}
fail:
	for (i=0; i<num_servers; i++) {
		SAFE_FREE(namelist[i]);
	}
	SAFE_FREE(namelist);

	if (ret != 0) {
		TALLOC_FREE(servers);
		return ret;
	}
	*pservers = servers;
	return 0;
}

struct rpc_host_endpoint_accept_state {
	struct tevent_context *ev;
	struct rpc_host_endpoint *endpoint;
};

static void rpc_host_endpoint_accept_accepted(struct tevent_req *subreq);
static void rpc_host_endpoint_accept_got_bind(struct tevent_req *subreq);

/*
 * Asynchronously wait for a DCERPC connection from a client.
 */
static struct tevent_req *rpc_host_endpoint_accept_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct rpc_host_endpoint *endpoint)
{
	struct tevent_req *req = NULL;
	struct rpc_host_endpoint_accept_state *state = NULL;
	size_t i;

	req = tevent_req_create(
		mem_ctx, &state, struct rpc_host_endpoint_accept_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->endpoint = endpoint;

	for (i=0; i<endpoint->num_fds; i++) {
		struct tevent_req *subreq = NULL;

		subreq = accept_send(state, ev, endpoint->fds[i]);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			subreq, rpc_host_endpoint_accept_accepted, req);
	}

	return req;
}

/*
 * Accept a DCERPC connection from a client.
 */
static void rpc_host_endpoint_accept_accepted(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_host_endpoint_accept_state *state = tevent_req_data(
		req, struct rpc_host_endpoint_accept_state);
	struct rpc_host_endpoint *endpoint = state->endpoint;
	int sock, listen_sock, err;
	struct samba_sockaddr peer_addr;

	sock = accept_recv(subreq, &listen_sock, &peer_addr, &err);
	TALLOC_FREE(subreq);
	if (sock == -1) {
		/* What to do here? Just ignore the error and retry? */
		DBG_DEBUG("accept_recv failed: %s\n", strerror(err));
		tevent_req_error(req, err);
		return;
	}

	subreq = accept_send(state, state->ev, listen_sock);
	if (tevent_req_nomem(subreq, req)) {
		close(sock);
		sock = -1;
		return;
	}
	tevent_req_set_callback(
		subreq, rpc_host_endpoint_accept_accepted, req);

	subreq = rpc_host_bind_read_send(
		state,
		state->ev,
		dcerpc_binding_get_transport(endpoint->binding),
		&sock,
		&peer_addr);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(
		subreq, rpc_host_endpoint_accept_got_bind, req);
}

/*
 * Client sent us a DCERPC bind packet.
 */
static void rpc_host_endpoint_accept_got_bind(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_host_endpoint_accept_state *state = tevent_req_data(
		req, struct rpc_host_endpoint_accept_state);
	struct rpc_host_endpoint *endpoint = state->endpoint;
	struct rpc_server *server = endpoint->server;
	struct rpc_host_pending_client *pending = NULL;
	struct rpc_host_client *client = NULL;
	struct ncacn_packet *bind_pkt = NULL;
	int ret;
	int sock=-1;

	ret = rpc_host_bind_read_recv(
		subreq, state, &sock, &client, &bind_pkt);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		DBG_DEBUG("rpc_host_bind_read_recv returned %s\n",
			  strerror(ret));
		goto fail;
	}

	client->binding = dcerpc_binding_string(client, endpoint->binding);
	if (client->binding == NULL) {
		DBG_WARNING("dcerpc_binding_string failed, dropping client\n");
		goto fail;
	}

	pending = talloc_zero(server, struct rpc_host_pending_client);
	if (pending == NULL) {
		DBG_WARNING("talloc failed, dropping client\n");
		goto fail;
	}
	pending->server = server;
	pending->sock = sock;
	pending->bind_pkt = talloc_move(pending, &bind_pkt);
	pending->client = talloc_move(pending, &client);
	talloc_set_destructor(pending, rpc_host_pending_client_destructor);
	sock = -1;

	pending->hangup_wait = wait_for_read_send(
		pending, state->ev, pending->sock, true);
	if (pending->hangup_wait == NULL) {
		DBG_WARNING("wait_for_read_send failed, dropping client\n");
		TALLOC_FREE(pending);
		return;
	}
	tevent_req_set_callback(
		pending->hangup_wait, rpc_host_client_exited, pending);

	DLIST_ADD_END(server->pending_clients, pending);
	rpc_host_distribute_clients(server);
	return;

fail:
	TALLOC_FREE(client);
	if (sock != -1) {
		close(sock);
	}
}

static int rpc_host_endpoint_accept_recv(
	struct tevent_req *req, struct rpc_host_endpoint **ep)
{
	struct rpc_host_endpoint_accept_state *state = tevent_req_data(
		req, struct rpc_host_endpoint_accept_state);

	*ep = state->endpoint;

	return tevent_req_simple_recv_unix(req);
}

/*
 * Full state for samba-dcerpcd. Everything else
 * is hung off this.
 */
struct rpc_host_state {
	struct tevent_context *ev;
	struct rpc_host *host;

	bool is_ready;
	const char *daemon_ready_progname;
	struct tevent_immediate *ready_signal_immediate;
	int *ready_signal_fds;

	size_t num_servers;
	size_t num_prepared;
};

/*
 * Tell whoever invoked samba-dcerpcd we're ready to
 * serve.
 */
static void rpc_host_report_readiness(
	struct tevent_context *ev,
	struct tevent_immediate *im,
	void *private_data)
{
	struct rpc_host_state *state = talloc_get_type_abort(
		private_data, struct rpc_host_state);
	size_t i, num_fds = talloc_array_length(state->ready_signal_fds);

	if (!state->is_ready) {
		DBG_DEBUG("Not yet ready\n");
		return;
	}

	for (i=0; i<num_fds; i++) {
		uint8_t byte = 0;
		ssize_t nwritten;

		do {
			nwritten = write(
				state->ready_signal_fds[i],
				(void *)&byte,
				sizeof(byte));
		} while ((nwritten == -1) && (errno == EINTR));

		close(state->ready_signal_fds[i]);
	}

	TALLOC_FREE(state->ready_signal_fds);
}

/*
 * Respond to a "are you ready" message.
 */
static bool rpc_host_ready_signal_filter(
	struct messaging_rec *rec, void *private_data)
{
	struct rpc_host_state *state = talloc_get_type_abort(
		private_data, struct rpc_host_state);
	size_t num_fds = talloc_array_length(state->ready_signal_fds);
	int *tmp = NULL;

	if (rec->msg_type != MSG_DAEMON_READY_FD) {
		return false;
	}
	if (rec->num_fds != 1) {
		DBG_DEBUG("Got %"PRIu8" fds\n", rec->num_fds);
		return false;
	}

	if (num_fds + 1 < num_fds) {
		return false;
	}
	tmp = talloc_realloc(state, state->ready_signal_fds, int, num_fds+1);
	if (tmp == NULL) {
		return false;
	}
	state->ready_signal_fds = tmp;

	state->ready_signal_fds[num_fds] = rec->fds[0];
	rec->fds[0] = -1;

	tevent_schedule_immediate(
		state->ready_signal_immediate,
		state->ev,
		rpc_host_report_readiness,
		state);

	return false;
}

/*
 * Respond to a "what is your status" message.
 */
static bool rpc_host_dump_status_filter(
	struct messaging_rec *rec, void *private_data)
{
	struct rpc_host_state *state = talloc_get_type_abort(
		private_data, struct rpc_host_state);
	struct rpc_host *host = state->host;
	struct rpc_server **servers = host->servers;
	size_t i, num_servers = talloc_array_length(servers);
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
		DBG_DEBUG("fdopen failed: %s\n", strerror(errno));
		return false;
	}

	for (i=0; i<num_servers; i++) {
		struct rpc_server *server = servers[i];
		size_t j, num_workers = talloc_array_length(server->workers);
		size_t active_workers = 0;

		for (j=0; j<num_workers; j++) {
			if (server->workers[j].pid != -1) {
				active_workers += 1;
			}
		}

		fprintf(f,
			"%s: active_workers=%zu\n",
			server->rpc_server_exe,
			active_workers);

		for (j=0; j<num_workers; j++) {
			struct rpc_work_process *w = &server->workers[j];

			if (w->pid == (pid_t)-1) {
				continue;
			}

			fprintf(f,
				" worker[%zu]: pid=%d, num_associations=%"PRIu32", num_connections=%"PRIu32"\n",
				j,
				(int)w->pid,
				w->num_associations,
				w->num_connections);
		}
	}

	fclose(f);

	return false;
}

static void rpc_host_server_setup_done(struct tevent_req *subreq);
static void rpc_host_endpoint_failed(struct tevent_req *subreq);

/*
 * Async startup for samba-dcerpcd.
 */
static struct tevent_req *rpc_host_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct messaging_context *msg_ctx,
	char *servers,
	int ready_signal_fd,
	const char *daemon_ready_progname,
	bool is_np_helper)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct rpc_host_state *state = NULL;
	struct rpc_host *host = NULL;
	struct tevent_signal *se = NULL;
	char *epmdb_path = NULL;
	char *exe = NULL;
	size_t i, num_servers = strv_count(servers);
	NTSTATUS status;
	int ret;

	req = tevent_req_create(req, &state, struct rpc_host_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->daemon_ready_progname = daemon_ready_progname;

	state->ready_signal_immediate = tevent_create_immediate(state);
	if (tevent_req_nomem(state->ready_signal_immediate, req)) {
		return tevent_req_post(req, ev);
	}

	if (ready_signal_fd != -1) {
		state->ready_signal_fds = talloc_array(state, int, 1);
		if (tevent_req_nomem(state->ready_signal_fds, req)) {
			return tevent_req_post(req, ev);
		}
		state->ready_signal_fds[0] = ready_signal_fd;
	}

	state->host = talloc_zero(state, struct rpc_host);
	if (tevent_req_nomem(state->host, req)) {
		return tevent_req_post(req, ev);
	}
	host = state->host;

	host->msg_ctx = msg_ctx;
	host->np_helper = is_np_helper;

	ret = pipe(host->worker_stdin);
	if (ret == -1) {
		tevent_req_nterror(req, map_nt_error_from_unix(errno));
		return tevent_req_post(req, ev);
	}

	host->servers = talloc_zero_array(
		host, struct rpc_server *, num_servers);
	if (tevent_req_nomem(host->servers, req)) {
		return tevent_req_post(req, ev);
	}

	se = tevent_add_signal(ev, state, SIGCHLD, 0, rpc_host_sigchld, host);
	if (tevent_req_nomem(se, req)) {
		return tevent_req_post(req, ev);
	}
	BlockSignals(false, SIGCHLD);

	status = messaging_register(
		msg_ctx,
		host,
		MSG_RPC_WORKER_STATUS,
		rpc_host_child_status_recv);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = messaging_register(
		msg_ctx, req, MSG_SHUTDOWN, rpc_host_msg_shutdown);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	subreq = messaging_filtered_read_send(
		state, ev, msg_ctx, rpc_host_ready_signal_filter, state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = messaging_filtered_read_send(
		state, ev, msg_ctx, rpc_host_dump_status_filter, state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	epmdb_path = lock_path(state, "epmdb.tdb");
	if (tevent_req_nomem(epmdb_path, req)) {
		return tevent_req_post(req, ev);
	}

	host->epmdb = tdb_wrap_open(
		host,
		epmdb_path,
		0,
		TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH,
		O_RDWR|O_CREAT,
		0644);
	if (host->epmdb == NULL) {
		DBG_DEBUG("tdb_wrap_open(%s) failed: %s\n",
			  epmdb_path,
			  strerror(errno));
		tevent_req_nterror(req, map_nt_error_from_unix(errno));
		return tevent_req_post(req, ev);
	}
	TALLOC_FREE(epmdb_path);

	for (exe = strv_next(servers, exe), i = 0;
	     exe != NULL;
	     exe = strv_next(servers, exe), i++) {

		DBG_DEBUG("server_setup for %s index %zu\n", exe, i);

		subreq = rpc_server_setup_send(
			state,
			ev,
			host,
			exe);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			subreq, rpc_host_server_setup_done, req);
	}

	return req;
}

/*
 * Timer function called after we were initialized but no one
 * connected. Shutdown.
 */
static void rpc_host_shutdown(
	struct tevent_context *ev,
	struct tevent_timer *te,
	struct timeval current_time,
	void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	DBG_DEBUG("Nobody connected -- shutting down\n");
	tevent_req_done(req);
}

static void rpc_host_server_setup_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_host_state *state = tevent_req_data(
		req, struct rpc_host_state);
	struct rpc_server *server = NULL;
	struct rpc_host *host = state->host;
	size_t i, num_servers = talloc_array_length(host->servers);
	NTSTATUS status;

	status = rpc_server_setup_recv(subreq, host, &server);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpc_server_setup_recv returned %s, ignoring\n",
			  nt_errstr(status));
		host->servers = talloc_realloc(
			host,
			host->servers,
			struct rpc_server *,
			num_servers-1);
		return;
	}

	server->server_index = state->num_prepared;
	host->servers[state->num_prepared] = server;

	state->num_prepared += 1;

	if (state->num_prepared < num_servers) {
		return;
	}

	for (i=0; i<num_servers; i++) {
		size_t j, num_endpoints;

		server = host->servers[i];
		num_endpoints = talloc_array_length(server->endpoints);

		for (j=0; j<num_endpoints; j++) {
			subreq = rpc_host_endpoint_accept_send(
				state, state->ev, server->endpoints[j]);
			if (tevent_req_nomem(subreq, req)) {
				return;
			}
			tevent_req_set_callback(
				subreq, rpc_host_endpoint_failed, req);
		}
	}

	state->is_ready = true;

	if (state->daemon_ready_progname != NULL) {
		daemon_ready(state->daemon_ready_progname);
	}

	if (host->np_helper) {
		/*
		 * If we're started as an np helper, and no one talks to
		 * us within 10 seconds, just shut ourselves down.
		 */
		host->np_helper_shutdown = tevent_add_timer(
			state->ev,
			state,
			timeval_current_ofs(10, 0),
			rpc_host_shutdown,
			req);
		if (tevent_req_nomem(host->np_helper_shutdown, req)) {
			return;
		}
	}

	tevent_schedule_immediate(
		state->ready_signal_immediate,
		state->ev,
		rpc_host_report_readiness,
		state);
}

/*
 * Log accept fail on an endpoint.
 */
static void rpc_host_endpoint_failed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_host_state *state = tevent_req_data(
		req, struct rpc_host_state);
	struct rpc_host_endpoint *endpoint = NULL;
	char *binding_string = NULL;
	int ret;

	ret = rpc_host_endpoint_accept_recv(subreq, &endpoint);
	TALLOC_FREE(subreq);

	binding_string = dcerpc_binding_string(state, endpoint->binding);
	DBG_DEBUG("rpc_host_endpoint_accept_recv for %s returned %s\n",
		  binding_string,
		  strerror(ret));
	TALLOC_FREE(binding_string);
}

static NTSTATUS rpc_host_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static int rpc_host_pidfile_create(
	struct messaging_context *msg_ctx,
	const char *progname,
	int ready_signal_fd)
{
	const char *piddir = lp_pid_directory();
	size_t len = strlen(piddir) + strlen(progname) + 6;
	char pidFile[len];
	pid_t existing_pid;
	int fd, ret;

	snprintf(pidFile,
		 sizeof(pidFile),
		 "%s/%s.pid",
		 piddir, progname);

	ret = pidfile_path_create(pidFile, &fd, &existing_pid);
	if (ret == 0) {
		/* leak fd */
		return 0;
	}

	if (ret != EAGAIN) {
		DBG_DEBUG("pidfile_path_create() failed: %s\n",
			  strerror(ret));
		return ret;
	}

	DBG_DEBUG("%s pid %d exists\n", progname, (int)existing_pid);

	if (ready_signal_fd != -1) {
		NTSTATUS status = messaging_send_iov(
			msg_ctx,
			pid_to_procid(existing_pid),
			MSG_DAEMON_READY_FD,
			NULL,
			0,
			&ready_signal_fd,
			1);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("Could not send ready_signal_fd: %s\n",
				  nt_errstr(status));
		}
	}

	return EAGAIN;
}

static void samba_dcerpcd_stdin_handler(
	struct tevent_context *ev,
	struct tevent_fd *fde,
	uint16_t flags,
	void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	char c;

	if (read(0, &c, 1) != 1) {
		/* we have reached EOF on stdin, which means the
		   parent has exited. Shutdown the server */
		tevent_req_done(req);
	}
}

/*
 * samba-dcerpcd microservice startup !
 */
int main(int argc, const char *argv[])
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	const char *progname = getprogname();
	TALLOC_CTX *frame = NULL;
	struct tevent_context *ev_ctx = NULL;
	struct messaging_context *msg_ctx = NULL;
	struct tevent_req *req = NULL;
	char *servers = NULL;
	const char *arg = NULL;
	size_t num_servers;
	poptContext pc;
	int ret, err;
	NTSTATUS status;
	bool log_stdout;
	bool ok;

	int libexec_rpcds = 0;
	int np_helper = 0;
	int ready_signal_fd = -1;

	struct samba_cmdline_daemon_cfg *cmdline_daemon_cfg = NULL;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{
			.longName   = "libexec-rpcds",
			.argInfo    = POPT_ARG_NONE,
			.arg        = &libexec_rpcds,
			.descrip    = "Use all rpcds in libexec",
		},
		{
			.longName   = "ready-signal-fd",
			.argInfo    = POPT_ARG_INT,
			.arg        = &ready_signal_fd,
			.descrip    = "fd to close when initialized",
		},
		{
			.longName   = "np-helper",
			.argInfo    = POPT_ARG_NONE,
			.arg        = &np_helper,
			.descrip    = "Internal named pipe server",
		},
		POPT_COMMON_SAMBA
		POPT_COMMON_DAEMON
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};

	{
		const char *fd_params[] = { "ready-signal-fd", };

		closefrom_except_fd_params(
			3, ARRAY_SIZE(fd_params), fd_params, argc, argv);
	}

	talloc_enable_null_tracking();
	frame = talloc_stackframe();
	umask(0);
	sec_init();
	smb_init_locale();

	ok = samba_cmdline_init(frame,
				SAMBA_CMDLINE_CONFIG_SERVER,
				true /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to init cmdline parser!\n");
		TALLOC_FREE(frame);
		exit(ENOMEM);
	}

	pc = samba_popt_get_context(getprogname(),
				    argc,
				    argv,
				    long_options,
				    0);
	if (pc == NULL) {
		DBG_ERR("Failed to setup popt context!\n");
		TALLOC_FREE(frame);
		exit(1);
	}

	poptSetOtherOptionHelp(
		pc, "[OPTIONS] [SERVICE_1 SERVICE_2 .. SERVICE_N]");

	ret = poptGetNextOpt(pc);

	if (ret != -1) {
		if (ret >= 0) {
			fprintf(stderr,
				"\nGot unexpected option %d\n",
				ret);
		} else if (ret == POPT_ERROR_BADOPT) {
			fprintf(stderr,
				"\nInvalid option %s: %s\n\n",
				poptBadOption(pc, 0),
				poptStrerror(ret));
		} else {
			fprintf(stderr,
				"\npoptGetNextOpt returned %s\n",
				poptStrerror(ret));
		}

		poptFreeContext(pc);
		TALLOC_FREE(frame);
		exit(1);
	}

	while ((arg = poptGetArg(pc)) != NULL) {
		ret = strv_add(frame, &servers, arg);
		if (ret != 0) {
			DBG_ERR("strv_add() failed\n");
			poptFreeContext(pc);
			TALLOC_FREE(frame);
			exit(1);
		}
	}

	log_stdout = (debug_get_log_type() == DEBUG_STDOUT);
	if (log_stdout) {
		setup_logging(progname, DEBUG_STDOUT);
	} else {
		setup_logging(progname, DEBUG_FILE);
	}

	/*
	 * If "rpc start on demand helpers = true" in smb.conf we must
	 * not start as standalone, only on demand from
	 * local_np_connect() functions. Log an error message telling
	 * the admin how to fix and then exit.
	 */
	if (lp_rpc_start_on_demand_helpers() && np_helper == 0) {
		DBG_ERR("Cannot start in standalone mode if smb.conf "
			"[global] setting "
			"\"rpc start on demand helpers = true\" - "
			"exiting\n");
			TALLOC_FREE(frame);
			exit(1);
	}

	if (libexec_rpcds != 0) {
		ret = rpc_host_list_servers(
			dyn_SAMBA_LIBEXECDIR, frame, &servers);
		if (ret != 0) {
			DBG_ERR("Could not list libexec: %s\n",
				strerror(ret));
			poptFreeContext(pc);
			TALLOC_FREE(frame);
			exit(1);
		}
	}

	num_servers = strv_count(servers);
	if (num_servers == 0) {
		poptPrintUsage(pc, stderr, 0);
		poptFreeContext(pc);
		TALLOC_FREE(frame);
		exit(1);
	}

	poptFreeContext(pc);

	cmdline_daemon_cfg = samba_cmdline_get_daemon_cfg();

	if (log_stdout && cmdline_daemon_cfg->fork) {
		DBG_ERR("Can't log to stdout unless in foreground\n");
		TALLOC_FREE(frame);
		exit(1);
	}

	msg_ctx = global_messaging_context();
	if (msg_ctx == NULL) {
		DBG_ERR("messaging_init() failed\n");
		TALLOC_FREE(frame);
		exit(1);
	}
	ev_ctx = messaging_tevent_context(msg_ctx);

	if (cmdline_daemon_cfg->fork) {
		become_daemon(
			true,
			cmdline_daemon_cfg->no_process_group,
			log_stdout);

		status = reinit_after_fork(msg_ctx, ev_ctx, false);
		if (!NT_STATUS_IS_OK(status)) {
			exit_daemon("reinit_after_fork() failed",
				    map_errno_from_nt_status(status));
		}
	} else {
		DBG_DEBUG("Calling daemon_status\n");
		daemon_status(progname, "Starting process ... ");
	}

	BlockSignals(true, SIGPIPE);

	dump_core_setup(progname, lp_logfile(frame, lp_sub));

	reopen_logs();

	DBG_STARTUP_NOTICE("%s version %s started.\n%s\n",
			   progname,
			   samba_version_string(),
			   samba_copyright_string());

	(void)winbind_off();
	ok = init_guest_session_info(frame);
	(void)winbind_on();
	if (!ok) {
		DBG_ERR("init_guest_session_info failed\n");
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}

	ret = rpc_host_pidfile_create(msg_ctx, progname, ready_signal_fd);
	if (ret != 0) {
		DBG_DEBUG("rpc_host_pidfile_create failed: %s\n",
			  strerror(ret));
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}

	req = rpc_host_send(
		ev_ctx,
		ev_ctx,
		msg_ctx,
		servers,
		ready_signal_fd,
		cmdline_daemon_cfg->fork ? NULL : progname,
		np_helper != 0);
	if (req == NULL) {
		DBG_ERR("rpc_host_send failed\n");
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}

	if (!cmdline_daemon_cfg->fork) {
		struct stat st;
		if (fstat(0, &st) != 0) {
			DBG_DEBUG("fstat(0) failed: %s\n",
				  strerror(errno));
			global_messaging_context_free();
			TALLOC_FREE(frame);
			exit(1);
		}
		if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode)) {
			tevent_add_fd(
				ev_ctx,
				ev_ctx,
				0,
				TEVENT_FD_READ,
				samba_dcerpcd_stdin_handler,
				req);
		}
	}

	ok = tevent_req_poll_unix(req, ev_ctx, &err);
	if (!ok) {
		DBG_ERR("tevent_req_poll_unix failed: %s\n",
			strerror(err));
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}

	status = rpc_host_recv(req);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("rpc_host_recv returned %s\n", nt_errstr(status));
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}

	TALLOC_FREE(frame);

	return 0;
}
