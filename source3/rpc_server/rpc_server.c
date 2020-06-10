/*
   Unix SMB/Netbios implementation.
   Generic infrstructure for RPC Daemons
   Copyright (C) Simo Sorce 2010
   Copyright (C) Andrew Bartlett 2011
   Copyright (C) Andreas Schneider 2011

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
#include "librpc/rpc/dcesrv_core.h"
#include "rpc_server/rpc_pipes.h"
#include "rpc_server/rpc_server.h"
#include "rpc_server/rpc_config.h"
#include "rpc_dce.h"
#include "librpc/gen_ndr/netlogon.h"
#include "librpc/gen_ndr/auth.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/named_pipe_auth/npa_tstream.h"
#include "../auth/auth_sam_reply.h"
#include "auth.h"
#include "rpc_server/rpc_ncacn_np.h"
#include "rpc_server/srv_pipe_hnd.h"
#include "rpc_server/srv_pipe.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/* Creates a pipes_struct and initializes it with the information
 * sent from the client */
int make_server_pipes_struct(TALLOC_CTX *mem_ctx,
			     struct messaging_context *msg_ctx,
			     const char *pipe_name,
			     enum dcerpc_transport_t transport,
			     const struct tsocket_address *remote_address,
			     const struct tsocket_address *local_address,
			     struct pipes_struct **_p,
			     int *perrno)
{
	struct pipes_struct *p;
	int ret;

	ret = make_base_pipes_struct(mem_ctx, msg_ctx, pipe_name,
				     transport,
				     remote_address, local_address, &p);
	if (ret) {
		*perrno = ret;
		return -1;
	}

	*_p = p;
	return 0;
}

/* Start listening on the appropriate unix socket and setup all is needed to
 * dispatch requests to the pipes rpc implementation */

struct dcerpc_ncacn_listen_state {
	int fd;

	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;
	struct dcesrv_context *dce_ctx;
	struct dcesrv_endpoint *endpoint;
	dcerpc_ncacn_termination_fn termination_fn;
	void *termination_data;
};

static void dcesrv_ncacn_np_listener(struct tevent_context *ev,
				     struct tevent_fd *fde,
				     uint16_t flags,
				     void *private_data);

NTSTATUS dcesrv_create_ncacn_np_socket(struct dcesrv_endpoint *e, int *out_fd)
{
	char *np_dir = NULL;
	int fd = -1;
	NTSTATUS status;
	const char *endpoint;
	char *endpoint_normalized = NULL;
	char *p = NULL;

	endpoint = dcerpc_binding_get_string_option(e->ep_description,
						    "endpoint");
	if (endpoint == NULL) {
		DBG_ERR("Endpoint mandatory for named pipes\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* The endpoint string from IDL can be mixed uppercase and case is
	 * normalized by smbd on connection */
	endpoint_normalized = strlower_talloc(talloc_tos(), endpoint);
	if (endpoint_normalized == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* The endpoint string from IDL can be prefixed by \pipe\ */
	p = endpoint_normalized;
	if (strncmp(p, "\\pipe\\", 6) == 0) {
		p += 6;
	}

	/*
	 * As lp_ncalrpc_dir() should have 0755, but
	 * lp_ncalrpc_dir()/np should have 0700, we need to
	 * create lp_ncalrpc_dir() first.
	 */
	if (!directory_create_or_exist(lp_ncalrpc_dir(), 0755)) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to create pipe directory %s - %s\n",
			lp_ncalrpc_dir(), strerror(errno));
		goto out;
	}

	np_dir = talloc_asprintf(talloc_tos(), "%s/np", lp_ncalrpc_dir());
	if (!np_dir) {
		status = NT_STATUS_NO_MEMORY;
		DBG_ERR("Out of memory\n");
		goto out;
	}

	if (!directory_create_or_exist_strict(np_dir, geteuid(), 0700)) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to create pipe directory %s - %s\n",
			np_dir, strerror(errno));
		goto out;
	}

	fd = create_pipe_sock(np_dir, p, 0700);
	if (fd == -1) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to create ncacn_np socket! '%s/%s': %s\n",
			np_dir, p, strerror(errno));
		goto out;
	}

	DBG_DEBUG("Opened pipe socket fd %d for %s\n", fd, p);

	*out_fd = fd;

	status = NT_STATUS_OK;

out:
	TALLOC_FREE(endpoint_normalized);
	TALLOC_FREE(np_dir);
	return status;
}

NTSTATUS dcesrv_setup_ncacn_np_socket(struct tevent_context *ev_ctx,
				      struct messaging_context *msg_ctx,
				      struct dcesrv_context *dce_ctx,
				      struct dcesrv_endpoint *e,
				      dcerpc_ncacn_termination_fn term_fn,
				      void *term_data)
{
	struct dcerpc_ncacn_listen_state *state;
	struct tevent_fd *fde;
	int rc;
	NTSTATUS status;
	const char *endpoint = NULL;

	endpoint = dcerpc_binding_get_string_option(e->ep_description,
						    "endpoint");
	if (endpoint == NULL) {
		DBG_ERR("Endpoint mandatory for named pipes\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Alloc in endpoint context. If the endpoint is freed (for example
	 * when forked daemons reinit the dcesrv_context, the tevent_fd
	 * listener will be stopped and the socket closed */
	state = talloc_zero(e, struct dcerpc_ncacn_listen_state);
	if (state == NULL) {
		DBG_ERR("Out of memory\n");
		return NT_STATUS_NO_MEMORY;
	}
	state->fd = -1;
	state->ev_ctx = ev_ctx;
	state->msg_ctx = msg_ctx;
	state->endpoint = e;
	state->dce_ctx = dce_ctx;
	state->termination_fn = term_fn;
	state->termination_data = term_data;

	status = dcesrv_create_ncacn_np_socket(e, &state->fd);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	rc = listen(state->fd, 5);
	if (rc < 0) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to listen on ncacn_np socket %s: %s\n",
			endpoint, strerror(errno));
		goto out;
	}

	DBG_DEBUG("Opened pipe socket fd %d for %s\n",
		  state->fd, endpoint);

	errno = 0;
	fde = tevent_add_fd(ev_ctx,
			    state, state->fd, TEVENT_FD_READ,
			    dcesrv_ncacn_np_listener, state);
	if (fde == NULL) {
		if (errno == 0) {
			errno = ENOMEM;
		}
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to add event handler for ncacn_np: %s\n",
			strerror(errno));
		goto out;
	}

	tevent_fd_set_auto_close(fde);

	return NT_STATUS_OK;

out:
	if (state->fd != -1) {
		close(state->fd);
	}
	TALLOC_FREE(state);
	return status;
}

static void dcesrv_ncacn_np_listener(struct tevent_context *ev,
				     struct tevent_fd *fde,
				     uint16_t flags,
				     void *private_data)
{
	struct dcerpc_ncacn_listen_state *state =
			talloc_get_type_abort(private_data,
					      struct dcerpc_ncacn_listen_state);
	struct samba_sockaddr addr = {
		.sa_socklen = sizeof(struct sockaddr_un),
	};
	int sd = -1;
	const char *endpoint = NULL;

	/* TODO: should we have a limit to the number of clients ? */

	sd = accept(state->fd, &addr.u.sa, &addr.sa_socklen);

	if (sd == -1) {
		if (errno != EINTR) {
			DEBUG(6, ("Failed to get a valid socket [%s]\n",
				  strerror(errno)));
		}
		return;
	}
	smb_set_close_on_exec(sd);

	endpoint = dcerpc_binding_get_string_option(
			state->endpoint->ep_description, "endpoint");
	if (endpoint == NULL) {
		DBG_ERR("Failed to get endpoint from binding description\n");
		close(sd);
		return;
	}

	DBG_DEBUG("Accepted ncacn_np socket %s (fd: %d)\n",
		   addr.u.un.sun_path, sd);

	dcerpc_ncacn_accept(state->ev_ctx,
			    state->msg_ctx,
			    state->dce_ctx,
			    state->endpoint,
			    NULL, /* remote client address */
			    NULL, /* local server address */
			    sd,
			    state->termination_fn,
			    state->termination_data);
}

/********************************************************************
 * Start listening on the tcp/ip socket
 ********************************************************************/

static void dcesrv_ncacn_ip_tcp_listener(struct tevent_context *ev,
					 struct tevent_fd *fde,
					 uint16_t flags,
					 void *private_data);

NTSTATUS dcesrv_create_ncacn_ip_tcp_socket(const struct sockaddr_storage *ifss,
					   uint16_t *port,
					   int *out_fd)
{
	int fd = -1;

	if (*port == 0) {
		uint16_t i;

		for (i = lp_rpc_low_port(); i <= lp_rpc_high_port(); i++) {
			fd = open_socket_in(SOCK_STREAM,
					    i,
					    0,
					    ifss,
					    false);
			if (fd >= 0) {
				*port = i;
				break;
			}
		}
	} else {
		fd = open_socket_in(SOCK_STREAM,
				    *port,
				    0,
				    ifss,
				    true);
	}
	if (fd == -1) {
		DBG_ERR("Failed to create socket on port %u!\n", *port);
		return NT_STATUS_UNSUCCESSFUL;
	}

	DBG_DEBUG("Opened ncacn_ip_tcp socket fd %d for port %u\n", fd, *port);

	*out_fd = fd;

	return NT_STATUS_OK;
}

NTSTATUS dcesrv_setup_ncacn_ip_tcp_socket(struct tevent_context *ev_ctx,
					  struct messaging_context *msg_ctx,
					  struct dcesrv_context *dce_ctx,
					  struct dcesrv_endpoint *e,
					  const struct sockaddr_storage *ifss,
					  dcerpc_ncacn_termination_fn term_fn,
					  void *term_data)
{
	struct dcerpc_ncacn_listen_state *state = NULL;
	struct tevent_fd *fde = NULL;
	const char *endpoint = NULL;
	uint16_t port = 0;
	char port_str[6];
	int rc;
	NTSTATUS status;

	endpoint = dcerpc_binding_get_string_option(e->ep_description,
						    "endpoint");
	if (endpoint != NULL) {
		port = atoi(endpoint);
	}

	/* Alloc in endpoint context. If the endpoint is freed (for example
	 * when forked daemons reinit the dcesrv_context, the tevent_fd
	 * listener will be stopped and the socket closed */
	state = talloc_zero(e, struct dcerpc_ncacn_listen_state);
	if (state == NULL) {
		DBG_ERR("Out of memory\n");
		return NT_STATUS_NO_MEMORY;
	}

	state->fd = -1;
	state->ev_ctx = ev_ctx;
	state->msg_ctx = msg_ctx;
	state->endpoint = e;
	state->dce_ctx = dce_ctx;
	state->termination_fn = term_fn;
	state->termination_data = term_data;

	status = dcesrv_create_ncacn_ip_tcp_socket(ifss, &port, &state->fd);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	/* ready to listen */
	set_socket_options(state->fd, "SO_KEEPALIVE");
	set_socket_options(state->fd, lp_socket_options());

	/* Set server socket to non-blocking for the accept. */
	rc = set_blocking(state->fd, false);
	if (rc < 0) {
		status = map_nt_error_from_unix_common(errno);
		goto out;
	}

	rc = listen(state->fd, SMBD_LISTEN_BACKLOG);
	if (rc == -1) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to listen on ncacn_ip_tcp socket: %s\n",
			strerror(errno));
		goto out;
	}

	DBG_DEBUG("Opened socket fd %d for port %u\n",
		  state->fd, port);

	errno = 0;
	fde = tevent_add_fd(state->ev_ctx,
			    state,
			    state->fd,
			    TEVENT_FD_READ,
			    dcesrv_ncacn_ip_tcp_listener,
			    state);
	if (fde == NULL) {
		if (errno == 0) {
			errno = ENOMEM;
		}
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to add event handler for ncacn_ip_tcp: %s\n",
			strerror(errno));
		goto out;
	}

	tevent_fd_set_auto_close(fde);

	/* Set the port in the endpoint */
	snprintf(port_str, sizeof(port_str), "%u", port);

	status = dcerpc_binding_set_string_option(e->ep_description,
						  "endpoint", port_str);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to set binding endpoint '%s': %s\n",
			port_str, nt_errstr(status));
		goto out;
	}

	return NT_STATUS_OK;

out:
	if (state->fd != -1) {
		close(state->fd);
	}
	TALLOC_FREE(state);

	return status;
}

static void dcesrv_ncacn_ip_tcp_listener(struct tevent_context *ev,
					 struct tevent_fd *fde,
					 uint16_t flags,
					 void *private_data)
{
	struct dcerpc_ncacn_listen_state *state =
		talloc_get_type_abort(private_data,
				      struct dcerpc_ncacn_listen_state);
	struct tsocket_address *cli_addr = NULL;
	struct tsocket_address *srv_addr = NULL;
	struct samba_sockaddr addr = {
		.sa_socklen = sizeof(struct sockaddr_storage),
	};
	int s = -1;
	int rc;

	s = accept(state->fd, &addr.u.sa, &addr.sa_socklen);
	if (s == -1) {
		if (errno != EINTR) {
			DBG_ERR("Failed to accept: %s\n", strerror(errno));
		}
		return;
	}
	smb_set_close_on_exec(s);

	rc = tsocket_address_bsd_from_samba_sockaddr(state, &addr, &cli_addr);
	if (rc < 0) {
		close(s);
		return;
	}

	rc = getsockname(s, &addr.u.sa, &addr.sa_socklen);
	if (rc < 0) {
		close(s);
		return;
	}

	rc = tsocket_address_bsd_from_samba_sockaddr(state, &addr, &srv_addr);
	if (rc < 0) {
		close(s);
		return;
	}

	DBG_DEBUG("Accepted ncacn_ip_tcp socket %d\n", s);

	dcerpc_ncacn_accept(state->ev_ctx,
			    state->msg_ctx,
			    state->dce_ctx,
			    state->endpoint,
			    cli_addr,
			    srv_addr,
			    s,
			    state->termination_fn,
			    state->termination_data);
}

/********************************************************************
 * Start listening on the ncalrpc socket
 ********************************************************************/

static void dcesrv_ncalrpc_listener(struct tevent_context *ev,
				    struct tevent_fd *fde,
				    uint16_t flags,
				    void *private_data);

NTSTATUS dcesrv_create_ncalrpc_socket(struct dcesrv_endpoint *e, int *out_fd)
{
	int fd = -1;
	const char *endpoint = NULL;
	NTSTATUS status;

	endpoint = dcerpc_binding_get_string_option(e->ep_description,
						    "endpoint");
	if (endpoint == NULL) {
		/*
		 * No identifier specified: use DEFAULT or SMBD.
		 *
		 * When role is AD DC we run two rpc server instances, the one
		 * started by 'samba' and the one embedded in 'smbd'.
		 * Avoid listening in DEFAULT socket for NCALRPC as both
		 * servers will race to accept connections. In this case smbd
		 * will listen in SMBD socket and rpcint binding handle
		 * implementation will pick the right socket to use.
		 *
		 * TODO: DO NOT hardcode this value anywhere else. Rather,
		 * specify no endpoint and let the epmapper worry about it.
		 */
		if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC) {
			endpoint = "SMBD";
		} else {
			endpoint = "DEFAULT";
		}
		status = dcerpc_binding_set_string_option(e->ep_description,
							  "endpoint",
							  endpoint);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed to set ncalrpc 'endpoint' binding "
				"string option to '%s': %s\n",
				endpoint, nt_errstr(status));
			return status;
		}
	}

	if (!directory_create_or_exist(lp_ncalrpc_dir(), 0755)) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to create ncalrpc directory '%s': %s\n",
			lp_ncalrpc_dir(), strerror(errno));
		goto out;
	}

	fd = create_pipe_sock(lp_ncalrpc_dir(), endpoint, 0755);
	if (fd == -1) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to create ncalrpc socket '%s/%s': %s\n",
			lp_ncalrpc_dir(), endpoint, strerror(errno));
		goto out;
	}

	DBG_DEBUG("Opened ncalrpc socket fd '%d' for '%s/%s'\n",
		  fd, lp_ncalrpc_dir(), endpoint);

	*out_fd = fd;

	return NT_STATUS_OK;

out:
	return status;
}

NTSTATUS dcesrv_setup_ncalrpc_socket(struct tevent_context *ev_ctx,
				     struct messaging_context *msg_ctx,
				     struct dcesrv_context *dce_ctx,
				     struct dcesrv_endpoint *e,
				     dcerpc_ncacn_termination_fn term_fn,
				     void *termination_data)
{
	struct dcerpc_ncacn_listen_state *state;
	struct tevent_fd *fde;
	int rc;
	NTSTATUS status;

	/* Alloc in endpoint context. If the endpoint is freed (for example
	 * when forked daemons reinit the dcesrv_context, the tevent_fd
	 * listener will be stopped and the socket closed */
	state = talloc_zero(e, struct dcerpc_ncacn_listen_state);
	if (state == NULL) {
		DBG_ERR("Out of memory\n");
		return NT_STATUS_NO_MEMORY;
	}

	state->fd = -1;
	state->ev_ctx = ev_ctx;
	state->msg_ctx = msg_ctx;
	state->dce_ctx = dce_ctx;
	state->endpoint = e;
	state->termination_fn = term_fn;
	state->termination_data = termination_data;

	status = dcesrv_create_ncalrpc_socket(e, &state->fd);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to create ncalrpc socket: %s\n",
			nt_errstr(status));
		goto out;
	}

	rc = listen(state->fd, 5);
	if (rc < 0) {
		const char *endpoint = dcerpc_binding_get_string_option(
				e->ep_description, "endpoint");
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to listen on ncalrpc socket %s: %s\n",
			endpoint, strerror(errno));
		goto out;
	}

	/* Set server socket to non-blocking for the accept. */
	rc = set_blocking(state->fd, false);
	if (rc < 0) {
		status = map_nt_error_from_unix_common(errno);
		goto out;
	}

	errno = 0;
	fde = tevent_add_fd(state->ev_ctx,
			    state,
			    state->fd,
			    TEVENT_FD_READ,
			    dcesrv_ncalrpc_listener,
			    state);
	if (fde == NULL) {
		if (errno == 0) {
			errno = ENOMEM;
		}
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to add event handler for ncalrpc: %s\n",
			strerror(errno));
		goto out;
	}

	tevent_fd_set_auto_close(fde);

	return NT_STATUS_OK;
out:
	if (state->fd != -1) {
		close(state->fd);
	}
	TALLOC_FREE(state);

	return status;
}

static void dcesrv_ncalrpc_listener(struct tevent_context *ev,
					struct tevent_fd *fde,
					uint16_t flags,
					void *private_data)
{
	struct dcerpc_ncacn_listen_state *state =
		talloc_get_type_abort(private_data,
				      struct dcerpc_ncacn_listen_state);
	struct tsocket_address *cli_addr = NULL, *srv_addr = NULL;
	struct samba_sockaddr addr = {
		.sa_socklen = sizeof(struct sockaddr_un),
	};
	struct samba_sockaddr addr_server = {
		.sa_socklen = sizeof(struct sockaddr_un),
	};
	int sd = -1;
	int rc;
	const char *endpoint = NULL;

	sd = accept(state->fd, &addr.u.sa, &addr.sa_socklen);
	if (sd == -1) {
		if (errno != EINTR) {
			DBG_ERR("Failed to accept: %s\n", strerror(errno));
		}
		return;
	}
	smb_set_close_on_exec(sd);

	rc = tsocket_address_bsd_from_samba_sockaddr(state, &addr, &cli_addr);
	if (rc < 0) {
		close(sd);
		return;
	}

	rc = getsockname(sd, &addr_server.u.sa, &addr_server.sa_socklen);
	if (rc < 0) {
		close(sd);
		return;
	}

	rc = tsocket_address_bsd_from_samba_sockaddr(state,
						     &addr_server,
						     &srv_addr);
	if (rc < 0) {
		close(sd);
		return;
	}

	endpoint = dcerpc_binding_get_string_option(
			state->endpoint->ep_description, "endpoint");
	if (endpoint == NULL) {
		DBG_ERR("Failed to get endpoint from binding description\n");
		close(sd);
		return;
	}

	DBG_DEBUG("Accepted ncalrpc socket %s (fd: %d)\n",
		   addr.u.un.sun_path, sd);

	dcerpc_ncacn_accept(state->ev_ctx,
			    state->msg_ctx,
			    state->dce_ctx,
			    state->endpoint,
			    cli_addr, srv_addr, sd,
			    state->termination_fn,
			    state->termination_data);
}

static int dcesrv_connection_destructor(struct dcesrv_connection *conn)
{
	struct dcerpc_ncacn_conn *ncacn_conn = talloc_get_type_abort(
			conn->transport.private_data,
			struct dcerpc_ncacn_conn);

	if (ncacn_conn->termination_fn != NULL) {
		ncacn_conn->termination_fn(conn, ncacn_conn->termination_data);
	}

	return 0;
}

NTSTATUS dcerpc_ncacn_conn_init(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev_ctx,
				struct messaging_context *msg_ctx,
				struct dcesrv_context *dce_ctx,
				struct dcesrv_endpoint *endpoint,
				dcerpc_ncacn_termination_fn term_fn,
				void *termination_data,
				struct dcerpc_ncacn_conn **out)
{
	struct dcerpc_ncacn_conn *ncacn_conn = NULL;

	ncacn_conn = talloc_zero(mem_ctx, struct dcerpc_ncacn_conn);
	if (ncacn_conn == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ncacn_conn->ev_ctx = ev_ctx;
	ncacn_conn->msg_ctx = msg_ctx;
	ncacn_conn->dce_ctx = dce_ctx;
	ncacn_conn->endpoint = endpoint;
	ncacn_conn->sock = -1;
	ncacn_conn->termination_fn = term_fn;
	ncacn_conn->termination_data = termination_data;

	*out = ncacn_conn;

	return NT_STATUS_OK;
}

static void dcesrv_ncacn_np_accept_done(struct tevent_req *subreq);
static void dcesrv_ncacn_accept_step2(struct dcerpc_ncacn_conn *ncacn_conn);

static void ncacn_terminate_connection(struct dcerpc_ncacn_conn *conn,
				       const char *reason);

void dcerpc_ncacn_accept(struct tevent_context *ev_ctx,
			 struct messaging_context *msg_ctx,
			 struct dcesrv_context *dce_ctx,
			 struct dcesrv_endpoint *e,
			 struct tsocket_address *cli_addr,
			 struct tsocket_address *srv_addr,
			 int s,
			 dcerpc_ncacn_termination_fn termination_fn,
			 void *termination_data)
{
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(e->ep_description);
	struct dcerpc_ncacn_conn *ncacn_conn;
	NTSTATUS status;
	int rc;

	DBG_DEBUG("dcerpc_ncacn_accept\n");

	status = dcerpc_ncacn_conn_init(ev_ctx,
					ev_ctx,
					msg_ctx,
					dce_ctx,
					e,
					termination_fn,
					termination_data,
					&ncacn_conn);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to initialize dcerpc_ncacn_connection: %s\n",
			nt_errstr(status));
		close(s);
		return;
	}

	ncacn_conn->sock = s;

	if (cli_addr != NULL) {
		ncacn_conn->remote_client_addr = talloc_move(ncacn_conn, &cli_addr);

		if (tsocket_address_is_inet(ncacn_conn->remote_client_addr, "ip")) {
			ncacn_conn->remote_client_name =
				tsocket_address_inet_addr_string(ncacn_conn->remote_client_addr,
								 ncacn_conn);
		} else {
			ncacn_conn->remote_client_name =
				tsocket_address_unix_path(ncacn_conn->remote_client_addr,
							  ncacn_conn);
		}

		if (ncacn_conn->remote_client_name == NULL) {
			DBG_ERR("Out of memory obtaining remote socket address as a string!\n");
			ncacn_terminate_connection(ncacn_conn, "No memory");
			close(s);
			return;
		}
	}

	if (srv_addr != NULL) {
		ncacn_conn->local_server_addr = talloc_move(ncacn_conn, &srv_addr);

		if (tsocket_address_is_inet(ncacn_conn->local_server_addr, "ip")) {
			ncacn_conn->local_server_name =
				tsocket_address_inet_addr_string(ncacn_conn->local_server_addr,
								 ncacn_conn);
		} else {
			ncacn_conn->local_server_name =
				tsocket_address_unix_path(ncacn_conn->local_server_addr,
							  ncacn_conn);
		}
		if (ncacn_conn->local_server_name == NULL) {
			DBG_ERR("No memory\n");
			ncacn_terminate_connection(ncacn_conn, "No memory");
			close(s);
			return;
		}
	}

	rc = set_blocking(s, false);
	if (rc < 0) {
		DBG_WARNING("Failed to set dcerpc socket to non-blocking\n");
		ncacn_terminate_connection(ncacn_conn, strerror(errno));
		close(s);
		return;
	}

	/*
	 * As soon as we have tstream_bsd_existing_socket set up it will
	 * take care of closing the socket.
	 */
	rc = tstream_bsd_existing_socket(ncacn_conn, s, &ncacn_conn->tstream);
	if (rc < 0) {
		DBG_WARNING("Failed to create tstream socket for dcerpc\n");
		ncacn_terminate_connection(ncacn_conn, "No memory");
		close(s);
		return;
	}

	if (transport == NCACN_NP) {
		struct tevent_req *subreq = NULL;
		uint64_t allocation_size = 4096;
		uint16_t device_state = 0xff | 0x0400 | 0x0100;
		uint16_t file_type = FILE_TYPE_MESSAGE_MODE_PIPE;

		subreq = tstream_npa_accept_existing_send(ncacn_conn,
							  ncacn_conn->ev_ctx,
							  ncacn_conn->tstream,
							  file_type,
							  device_state,
							  allocation_size);
		if (subreq == NULL) {
			ncacn_terminate_connection(ncacn_conn, "No memory");
			return;
		}
		tevent_req_set_callback(subreq, dcesrv_ncacn_np_accept_done,
					ncacn_conn);
		return;
	}

	dcesrv_ncacn_accept_step2(ncacn_conn);
}

static void dcesrv_ncacn_np_accept_done(struct tevent_req *subreq)
{
	struct auth_session_info_transport *session_info_transport = NULL;
	struct dcerpc_ncacn_conn *ncacn_conn = NULL;
	int error;
	int ret;

	ncacn_conn = tevent_req_callback_data(subreq,
					      struct dcerpc_ncacn_conn);

	ret = tstream_npa_accept_existing_recv(subreq, &error, ncacn_conn,
					       &ncacn_conn->tstream,
					       &ncacn_conn->remote_client_addr,
					       &ncacn_conn->remote_client_name,
					       &ncacn_conn->local_server_addr,
					       &ncacn_conn->local_server_name,
					       &session_info_transport);
	ncacn_conn->session_info = talloc_move(ncacn_conn,
			&session_info_transport->session_info);

	TALLOC_FREE(subreq);
	if (ret != 0) {
		DBG_ERR("Failed to accept named pipe connection: %s\n",
			strerror(error));
		ncacn_terminate_connection(ncacn_conn, strerror(errno));
		return;
	}

	dcesrv_ncacn_accept_step2(ncacn_conn);
}

static void dcesrv_ncacn_accept_step2(struct dcerpc_ncacn_conn *ncacn_conn)
{
	char *pipe_name = NULL;
	uid_t uid;
	gid_t gid;
	int rc;
	int sys_errno;
	enum dcerpc_transport_t transport = dcerpc_binding_get_transport(
			ncacn_conn->endpoint->ep_description);
	const char *endpoint = dcerpc_binding_get_string_option(
			ncacn_conn->endpoint->ep_description, "endpoint");
	struct dcesrv_connection *dcesrv_conn = NULL;
	NTSTATUS status;

	switch (transport) {
		case NCACN_IP_TCP:
			pipe_name = tsocket_address_string(ncacn_conn->remote_client_addr,
							   ncacn_conn);
			if (pipe_name == NULL) {
				DBG_ERR("No memory\n");
				ncacn_terminate_connection(ncacn_conn, "No memory");
				return;
			}

			break;
		case NCALRPC:
			rc = getpeereid(ncacn_conn->sock, &uid, &gid);
			if (rc < 0) {
				DEBUG(2, ("Failed to get ncalrpc connecting "
					  "uid - %s!\n", strerror(errno)));
			} else {
				if (uid == sec_initial_uid()) {
					TALLOC_FREE(ncacn_conn->remote_client_addr);

					rc = tsocket_address_unix_from_path(ncacn_conn,
									    AS_SYSTEM_MAGIC_PATH_TOKEN,
									    &ncacn_conn->remote_client_addr);
					if (rc < 0) {
						DBG_ERR("No memory\n");
						ncacn_terminate_connection(ncacn_conn, "No memory");
						return;
					}

					TALLOC_FREE(ncacn_conn->remote_client_name);
					ncacn_conn->remote_client_name
						= tsocket_address_unix_path(ncacn_conn->remote_client_addr,
									    ncacn_conn);
					if (ncacn_conn->remote_client_name == NULL) {
						DBG_ERR("No memory\n");
						ncacn_terminate_connection(ncacn_conn, "No memory");
						return;
					}
				}
			}

			FALL_THROUGH;
		case NCACN_NP:
			pipe_name = talloc_strdup(ncacn_conn, endpoint);
			if (pipe_name == NULL) {
				DBG_ERR("No memory\n");
				ncacn_terminate_connection(ncacn_conn, "No memory");
				return;
			}
			break;
		default:
			DBG_ERR("unknown dcerpc transport: %u!\n", transport);
			ncacn_terminate_connection(ncacn_conn,
					"Unknown DCE/RPC transport");
			return;
	}

	if (ncacn_conn->session_info == NULL) {
		status = make_session_info_anonymous(ncacn_conn,
						     &ncacn_conn->session_info);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed to create anonymous session info: "
				"%s\n", nt_errstr(status));
			ncacn_terminate_connection(ncacn_conn,
				nt_errstr(status));
			return;
		}
	}

	rc = make_server_pipes_struct(ncacn_conn,
				      ncacn_conn->msg_ctx,
				      pipe_name,
				      transport,
				      ncacn_conn->remote_client_addr,
				      ncacn_conn->local_server_addr,
				      &ncacn_conn->p,
				      &sys_errno);
	if (rc < 0) {
		DBG_ERR("Failed to create pipe struct: %s",
			strerror(sys_errno));
		ncacn_terminate_connection(ncacn_conn, strerror(sys_errno));
		return;
	}

	/*
	 * This fills in dcesrv_conn->endpoint with the endpoint
	 * associated with the socket.  From this point on we know
	 * which (group of) services we are handling, but not the
	 * specific interface.
	 */
	status = dcesrv_endpoint_connect(ncacn_conn->dce_ctx,
					 ncacn_conn,
					 ncacn_conn->endpoint,
					 ncacn_conn->session_info,
					 ncacn_conn->ev_ctx,
					 DCESRV_CALL_STATE_FLAG_MAY_ASYNC,
					 &dcesrv_conn);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to connect to endpoint: %s\n",
			nt_errstr(status));
		ncacn_terminate_connection(ncacn_conn, nt_errstr(status));
		return;
	}
	talloc_set_destructor(dcesrv_conn, dcesrv_connection_destructor);

	dcesrv_conn->transport.private_data = ncacn_conn;
	dcesrv_conn->transport.report_output_data =
		dcesrv_sock_report_output_data;
	dcesrv_conn->transport.terminate_connection =
		dcesrv_transport_terminate_connection;
	dcesrv_conn->send_queue = tevent_queue_create(dcesrv_conn,
						      "dcesrv send queue");
	if (dcesrv_conn->send_queue == NULL) {
		status = NT_STATUS_NO_MEMORY;
		DBG_ERR("Failed to create send queue: %s\n",
			nt_errstr(status));
		ncacn_terminate_connection(ncacn_conn, nt_errstr(status));
		return;
	}

	dcesrv_conn->stream = talloc_move(dcesrv_conn, &ncacn_conn->tstream);
	dcesrv_conn->local_address = ncacn_conn->local_server_addr;
	dcesrv_conn->remote_address = ncacn_conn->remote_client_addr;
	status = dcesrv_connection_loop_start(dcesrv_conn);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to start dcesrv_connection loop: %s\n",
				nt_errstr(status));
		ncacn_terminate_connection(ncacn_conn, nt_errstr(status));
	}
	DBG_DEBUG("dcerpc_ncacn_accept done\n");

	return;
}

NTSTATUS dcesrv_auth_gensec_prepare(TALLOC_CTX *mem_ctx,
				    struct dcesrv_call_state *call,
				    struct gensec_security **out)
{
	struct gensec_security *gensec = NULL;
	NTSTATUS status;

	if (out == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = auth_generic_prepare(mem_ctx,
				      call->conn->remote_address,
				      call->conn->local_address,
				      "DCE/RPC",
				      &gensec);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to prepare gensec: %s\n", nt_errstr(status));
		return status;
	}

	*out = gensec;

	return NT_STATUS_OK;
}

void dcesrv_log_successful_authz(struct dcesrv_call_state *call)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct auth4_context *auth4_context = NULL;
	struct dcesrv_auth *auth = call->auth_state;
	enum dcerpc_transport_t transport = dcerpc_binding_get_transport(
			call->conn->endpoint->ep_description);
	const char *auth_type = derpc_transport_string_by_transport(transport);
	const char *transport_protection = AUTHZ_TRANSPORT_PROTECTION_NONE;
	NTSTATUS status;

	if (frame == NULL) {
		DBG_ERR("No memory");
		return;
	}

	if (transport == NCACN_NP) {
		transport_protection = AUTHZ_TRANSPORT_PROTECTION_SMB;
	}

	become_root();
	status = make_auth4_context(frame, &auth4_context);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Unable to make auth context for authz log.\n");
		TALLOC_FREE(frame);
		return;
	}

	/*
	 * Log the authorization to this RPC interface.  This
	 * covered ncacn_np pass-through auth, and anonymous
	 * DCE/RPC (eg epmapper, netlogon etc)
	 */
	log_successful_authz_event(auth4_context->msg_ctx,
				   auth4_context->lp_ctx,
				   call->conn->remote_address,
				   call->conn->local_address,
				   "DCE/RPC",
				   auth_type,
				   transport_protection,
				   auth->session_info);

	auth->auth_audited = true;

	TALLOC_FREE(frame);
}

static NTSTATUS dcesrv_assoc_group_new(struct dcesrv_call_state *call,
				       uint32_t assoc_group_id)
{
	struct dcesrv_connection *conn = call->conn;
	struct dcesrv_context *dce_ctx = conn->dce_ctx;
	const struct dcesrv_endpoint *endpoint = conn->endpoint;
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(endpoint->ep_description);
	struct dcesrv_assoc_group *assoc_group = NULL;

	assoc_group = talloc_zero(conn, struct dcesrv_assoc_group);
	if (assoc_group == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	assoc_group->transport = transport;
	assoc_group->id = assoc_group_id;
	assoc_group->dce_ctx = dce_ctx;

	call->conn->assoc_group = assoc_group;

	return NT_STATUS_OK;
}

NTSTATUS dcesrv_assoc_group_find(struct dcesrv_call_state *call)
{
	uint32_t assoc_group_id = call->pkt.u.bind.assoc_group_id;

	/* If not requested by client create a new association group */
	if (assoc_group_id == 0) {
		assoc_group_id = 0x53F0;
	}

	return dcesrv_assoc_group_new(call, assoc_group_id);
}

void dcesrv_transport_terminate_connection(struct dcesrv_connection *dce_conn,
					   const char *reason)
{
       struct dcerpc_ncacn_conn *ncacn_conn = talloc_get_type_abort(
                       dce_conn->transport.private_data,
                       struct dcerpc_ncacn_conn);

       ncacn_terminate_connection(ncacn_conn, reason);
}

static void ncacn_terminate_connection(struct dcerpc_ncacn_conn *conn,
				       const char *reason)
{
       if (reason == NULL) {
               reason = "Unknown reason";
       }

       DBG_NOTICE("Terminating connection - '%s'\n", reason);

       talloc_free(conn);
}

NTSTATUS dcesrv_endpoint_by_ncacn_np_name(struct dcesrv_context *dce_ctx,
					  const char *pipe_name,
					  struct dcesrv_endpoint **out)
{
	struct dcesrv_endpoint *e = NULL;

	for (e = dce_ctx->endpoint_list; e; e = e->next) {
		enum dcerpc_transport_t transport =
			dcerpc_binding_get_transport(e->ep_description);
		const char *endpoint = NULL;

		if (transport != NCACN_NP) {
			continue;
		}

		endpoint = dcerpc_binding_get_string_option(e->ep_description,
							    "endpoint");
		if (endpoint == NULL) {
			continue;
		}

		if (strncmp(endpoint, "\\pipe\\", 6) == 0) {
			endpoint += 6;
		}

		if (strequal(endpoint, pipe_name)) {
			*out = e;
			return NT_STATUS_OK;
		}
	}

	return NT_STATUS_OBJECT_NAME_NOT_FOUND;
}

struct pipes_struct *dcesrv_get_pipes_struct(struct dcesrv_connection *conn)
{
	struct dcerpc_ncacn_conn *ncacn_conn = talloc_get_type_abort(
			conn->transport.private_data,
			struct dcerpc_ncacn_conn);

	return ncacn_conn->p;
}

/* vim: set ts=8 sw=8 noet cindent syntax=c.doxygen: */
