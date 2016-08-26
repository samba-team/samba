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
#include "librpc/gen_ndr/ndr_dcerpc.h"

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
			     struct auth_session_info **psession_info,
			     struct pipes_struct **_p,
			     int *perrno)
{
	struct auth_session_info *session_info = *psession_info;
	struct pipes_struct *p;
	int ret;

	ret = make_base_pipes_struct(mem_ctx, msg_ctx, pipe_name,
				     transport, RPC_LITTLE_ENDIAN,
				     remote_address, local_address, &p);
	if (ret) {
		*perrno = ret;
		return -1;
	}

	if ((session_info->unix_token == NULL) ||
	    (session_info->unix_info == NULL) ||
	    (session_info->security_token == NULL)) {
		DBG_ERR("Supplied session_info was incomplete!\n");
		TALLOC_FREE(p);
		*perrno = EINVAL;
		return -1;
	}

	/* Don't call create_local_token(), we already have the full details here */
	p->session_info = talloc_move(p, psession_info);

	*_p = p;
	return 0;
}

/* Start listening on the appropriate unix socket and setup all is needed to
 * dispatch requests to the pipes rpc implementation */

struct dcerpc_ncacn_listen_state {
	struct ndr_syntax_id syntax_id;

	int fd;
	union {
		char *name;
		uint16_t port;
	} ep;

	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;
	dcerpc_ncacn_termination_fn termination_fn;
	void *termination_data;
};

static void dcesrv_ncacn_np_listener(struct tevent_context *ev,
				     struct tevent_fd *fde,
				     uint16_t flags,
				     void *private_data);

NTSTATUS dcesrv_create_ncacn_np_socket(const char *pipe_name, int *out_fd)
{
	char *np_dir = NULL;
	int fd = -1;
	NTSTATUS status;

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

	fd = create_pipe_sock(np_dir, pipe_name, 0700);
	if (fd == -1) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to create ncacn_np socket! '%s/%s': %s\n",
			np_dir, pipe_name, strerror(errno));
		goto out;
	}

	DBG_DEBUG("Opened pipe socket fd %d for %s\n", fd, pipe_name);

	*out_fd = fd;

	status = NT_STATUS_OK;

out:
	talloc_free(np_dir);
	return status;
}

NTSTATUS dcesrv_setup_ncacn_np_socket(const char *pipe_name,
				      struct tevent_context *ev_ctx,
				      struct messaging_context *msg_ctx)
{
	struct dcerpc_ncacn_listen_state *state;
	struct tevent_fd *fde;
	int rc;
	NTSTATUS status;

	state = talloc_zero(ev_ctx, struct dcerpc_ncacn_listen_state);
	if (state == NULL) {
		DBG_ERR("Out of memory\n");
		return NT_STATUS_NO_MEMORY;
	}
	state->fd = -1;
	state->ep.name = talloc_strdup(state, pipe_name);
	if (state->ep.name == NULL) {
		DBG_ERR("Out of memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	status = dcesrv_create_ncacn_np_socket(pipe_name, &state->fd);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	rc = listen(state->fd, 5);
	if (rc < 0) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to listen on ncacn_np socket %s: %s\n",
			pipe_name, strerror(errno));
		goto out;
	}

	state->ev_ctx = ev_ctx;
	state->msg_ctx = msg_ctx;

	DBG_DEBUG("Opened pipe socket fd %d for %s\n",
		  state->fd, pipe_name);

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

	DBG_DEBUG("Accepted ncacn_np socket %s (fd: %d)\n",
		   addr.u.un.sun_path, sd);

	dcerpc_ncacn_accept(state->ev_ctx,
			    state->msg_ctx,
			    NCACN_NP,
			    state->ep.name,
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
					  const struct sockaddr_storage *ifss,
					  uint16_t *port)
{
	struct dcerpc_ncacn_listen_state *state;
	struct tevent_fd *fde;
	int rc;
	NTSTATUS status;

	state = talloc_zero(ev_ctx, struct dcerpc_ncacn_listen_state);
	if (state == NULL) {
		DBG_ERR("Out of memory\n");
		return NT_STATUS_NO_MEMORY;
	}

	state->fd = -1;
	state->ep.port = *port;

	status = dcesrv_create_ncacn_ip_tcp_socket(ifss, &state->ep.port,
						   &state->fd);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	state->ev_ctx = ev_ctx;
	state->msg_ctx = msg_ctx;

	/* ready to listen */
	set_socket_options(state->fd, "SO_KEEPALIVE");
	set_socket_options(state->fd, lp_socket_options());

	/* Set server socket to non-blocking for the accept. */
	set_blocking(state->fd, false);

	rc = listen(state->fd, SMBD_LISTEN_BACKLOG);
	if (rc == -1) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to listen on ncacn_ip_tcp socket: %s\n",
			strerror(errno));
		goto out;
	}

	DBG_DEBUG("Opened socket fd %d for port %u\n",
		  state->fd, state->ep.port);

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

	*port = state->ep.port;

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
			    NCACN_IP_TCP,
			    "IP",
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

NTSTATUS dcesrv_create_ncalrpc_socket(const char *name, int *out_fd)
{
	int fd = -1;
	NTSTATUS status;

	if (name == NULL) {
		name = "DEFAULT";
	}

	if (!directory_create_or_exist(lp_ncalrpc_dir(), 0755)) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to create ncalrpc directory '%s': %s\n",
			lp_ncalrpc_dir(), strerror(errno));
		goto out;
	}

	fd = create_pipe_sock(lp_ncalrpc_dir(), name, 0755);
	if (fd == -1) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to create ncalrpc socket '%s/%s': %s\n",
			lp_ncalrpc_dir(), name, strerror(errno));
		goto out;
	}

	DBG_DEBUG("Opened ncalrpc socket fd '%d' for '%s/%s'\n",
		  fd, lp_ncalrpc_dir(), name);

	*out_fd = fd;

	return NT_STATUS_OK;

out:
	return status;
}

NTSTATUS dcesrv_setup_ncalrpc_socket(struct tevent_context *ev_ctx,
				     struct messaging_context *msg_ctx,
				     const char *name,
				     dcerpc_ncacn_termination_fn term_fn,
				     void *termination_data)
{
	struct dcerpc_ncacn_listen_state *state;
	struct tevent_fd *fde;
	int rc;
	NTSTATUS status;

	state = talloc_zero(ev_ctx, struct dcerpc_ncacn_listen_state);
	if (state == NULL) {
		DBG_ERR("Out of memory\n");
		return NT_STATUS_NO_MEMORY;
	}

	state->fd = -1;
	state->termination_fn = term_fn;
	state->termination_data = termination_data;

	if (name == NULL) {
		name = "DEFAULT";
	}

	state->ep.name = talloc_strdup(state, name);
	if (state->ep.name == NULL) {
		DBG_ERR("Out of memory\n");
		talloc_free(state);
		return NT_STATUS_NO_MEMORY;
	}

	status = dcesrv_create_ncalrpc_socket(name, &state->fd);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to create ncalrpc socket: %s\n",
			nt_errstr(status));
		goto out;
	}

	rc = listen(state->fd, 5);
	if (rc < 0) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to listen on ncalrpc socket %s: %s\n",
			name, strerror(errno));
		goto out;
	}

	state->ev_ctx = ev_ctx;
	state->msg_ctx = msg_ctx;

	/* Set server socket to non-blocking for the accept. */
	set_blocking(state->fd, false);

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

	DBG_DEBUG("Accepted ncalrpc socket %s (fd: %d)\n",
		   addr.u.un.sun_path, sd);

	dcerpc_ncacn_accept(state->ev_ctx,
			    state->msg_ctx,
			    NCALRPC,
			    state->ep.name,
			    cli_addr, srv_addr, sd,
			    state->termination_fn,
			    state->termination_data);
}

static int dcerpc_ncacn_conn_destructor(struct dcerpc_ncacn_conn *ncacn_conn)
{
	if (ncacn_conn->termination_fn != NULL) {
		ncacn_conn->termination_fn(ncacn_conn->p,
					   ncacn_conn->termination_data);
	}

	return 0;
}

NTSTATUS dcerpc_ncacn_conn_init(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev_ctx,
				struct messaging_context *msg_ctx,
				enum dcerpc_transport_t transport,
				const char *name,
				dcerpc_ncacn_termination_fn term_fn,
				void *termination_data,
				struct dcerpc_ncacn_conn **out)
{
	struct dcerpc_ncacn_conn *ncacn_conn = NULL;

	ncacn_conn = talloc_zero(mem_ctx, struct dcerpc_ncacn_conn);
	if (ncacn_conn == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(ncacn_conn, dcerpc_ncacn_conn_destructor);

	ncacn_conn->transport = transport;
	ncacn_conn->ev_ctx = ev_ctx;
	ncacn_conn->msg_ctx = msg_ctx;
	ncacn_conn->sock = -1;
	ncacn_conn->termination_fn = term_fn;
	ncacn_conn->termination_data = termination_data;
	if (name != NULL) {
		ncacn_conn->name = talloc_strdup(ncacn_conn, name);
		if (ncacn_conn->name == NULL) {
			talloc_free(ncacn_conn);
			return NT_STATUS_NO_MEMORY;;
		}
	}

	*out = ncacn_conn;

	return NT_STATUS_OK;
}

static void dcerpc_ncacn_packet_done(struct tevent_req *subreq);
static void dcesrv_ncacn_np_accept_done(struct tevent_req *subreq);
static void dcesrv_ncacn_accept_step2(struct dcerpc_ncacn_conn *ncacn_conn);

void dcerpc_ncacn_accept(struct tevent_context *ev_ctx,
			 struct messaging_context *msg_ctx,
			 enum dcerpc_transport_t transport,
			 const char *name,
			 struct tsocket_address *cli_addr,
			 struct tsocket_address *srv_addr,
			 int s,
			 dcerpc_ncacn_termination_fn termination_fn,
			 void *termination_data)
{
	struct dcerpc_ncacn_conn *ncacn_conn;
	NTSTATUS status;
	int rc;

	DEBUG(10, ("dcerpc_ncacn_accept\n"));

	status = dcerpc_ncacn_conn_init(ev_ctx,
					ev_ctx,
					msg_ctx,
					transport,
					name,
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
			talloc_free(ncacn_conn);
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
			DEBUG(0, ("Out of memory obtaining local socket address as a string!\n"));
			talloc_free(ncacn_conn);
			close(s);
			return;
		}
	}

	rc = set_blocking(s, false);
	if (rc < 0) {
		DBG_WARNING("Failed to set dcerpc socket to non-blocking\n");
		talloc_free(ncacn_conn);
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
		talloc_free(ncacn_conn);
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
			DBG_ERR("Failed to start async accept procedure\n");
			talloc_free(ncacn_conn);
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
		talloc_free(ncacn_conn);
		return;
	}

	dcesrv_ncacn_accept_step2(ncacn_conn);
}

static void dcesrv_ncacn_accept_step2(struct dcerpc_ncacn_conn *ncacn_conn)
{
	struct tevent_req *subreq = NULL;
	char *pipe_name = NULL;
	uid_t uid;
	gid_t gid;
	int rc;
	int sys_errno;

	switch (ncacn_conn->transport) {
		case NCACN_IP_TCP:
			pipe_name = tsocket_address_string(ncacn_conn->remote_client_addr,
							   ncacn_conn);
			if (pipe_name == NULL) {
				talloc_free(ncacn_conn);
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
						DEBUG(0, ("Out of memory building magic ncalrpc_as_system path!\n"));
						talloc_free(ncacn_conn);
						return;
					}

					TALLOC_FREE(ncacn_conn->remote_client_name);
					ncacn_conn->remote_client_name
						= tsocket_address_unix_path(ncacn_conn->remote_client_addr,
									    ncacn_conn);
					if (ncacn_conn->remote_client_name == NULL) {
						DEBUG(0, ("Out of memory getting magic ncalrpc_as_system string!\n"));
						talloc_free(ncacn_conn);
						return;
					}
				}
			}

			FALL_THROUGH;
		case NCACN_NP:
			pipe_name = talloc_strdup(ncacn_conn,
						  ncacn_conn->name);
			if (pipe_name == NULL) {
				talloc_free(ncacn_conn);
				return;
			}
			break;
		default:
			DEBUG(0, ("unknown dcerpc transport: %u!\n",
				  ncacn_conn->transport));
			talloc_free(ncacn_conn);
			return;
	}

	if (ncacn_conn->session_info == NULL) {
		NTSTATUS status;

		status = make_session_info_anonymous(ncacn_conn,
						     &ncacn_conn->session_info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(2, ("Failed to create "
				  "make_session_info_anonymous - %s\n",
				  nt_errstr(status)));
			talloc_free(ncacn_conn);
			return;
		}
	}

	rc = make_server_pipes_struct(ncacn_conn,
				      ncacn_conn->msg_ctx,
				      pipe_name,
				      ncacn_conn->transport,
				      ncacn_conn->remote_client_addr,
				      ncacn_conn->local_server_addr,
				      &ncacn_conn->session_info,
				      &ncacn_conn->p,
				      &sys_errno);
	if (rc < 0) {
		DEBUG(2, ("Failed to create pipe struct - %s",
			  strerror(sys_errno)));
		talloc_free(ncacn_conn);
		return;
	}

	ncacn_conn->send_queue = tevent_queue_create(ncacn_conn,
							"dcerpc send queue");
	if (ncacn_conn->send_queue == NULL) {
		DEBUG(0, ("Out of memory building dcerpc send queue!\n"));
		talloc_free(ncacn_conn);
		return;
	}

	subreq = dcerpc_read_ncacn_packet_send(ncacn_conn,
					       ncacn_conn->ev_ctx,
					       ncacn_conn->tstream);
	if (subreq == NULL) {
		DEBUG(2, ("Failed to send ncacn packet\n"));
		talloc_free(ncacn_conn);
		return;
	}

	tevent_req_set_callback(subreq, dcerpc_ncacn_packet_process, ncacn_conn);

	DEBUG(10, ("dcerpc_ncacn_accept done\n"));

	return;
}

void dcerpc_ncacn_packet_process(struct tevent_req *subreq)
{
	struct dcerpc_ncacn_conn *ncacn_conn =
		tevent_req_callback_data(subreq, struct dcerpc_ncacn_conn);

	struct _output_data *out = &ncacn_conn->p->out_data;
	DATA_BLOB recv_buffer = data_blob_null;
	struct ncacn_packet *pkt;
	uint32_t to_send;
	size_t i;
	NTSTATUS status;
	bool ok;

	status = dcerpc_read_ncacn_packet_recv(subreq, ncacn_conn, &pkt, &recv_buffer);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* dcerpc_read_ncacn_packet_recv() returns a full PDU */
	ncacn_conn->p->in_data.pdu_needed_len = 0;
	ncacn_conn->p->in_data.pdu = recv_buffer;
	if (dcerpc_get_endian_flag(&recv_buffer) & DCERPC_DREP_LE) {
		ncacn_conn->p->endian = RPC_LITTLE_ENDIAN;
	} else {
		ncacn_conn->p->endian = RPC_BIG_ENDIAN;
	}
	DEBUG(10, ("PDU is in %s Endian format!\n",
		   ncacn_conn->p->endian ? "Big" : "Little"));
	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(ncacn_packet, pkt);
	}
	process_complete_pdu(ncacn_conn->p, pkt);

	/* reset pipe state and free PDU */
	ncacn_conn->p->in_data.pdu.length = 0;
	talloc_free(recv_buffer.data);
	talloc_free(pkt);

	/*
	 * This is needed because of the way DCERPC binds work in the RPC
	 * marshalling code
	 */
	to_send = out->frag.length - out->current_pdu_sent;
	if (to_send > 0) {

		DEBUG(10, ("Current_pdu_len = %u, "
			   "current_pdu_sent = %u "
			   "Returning %u bytes\n",
			   (unsigned int)out->frag.length,
			   (unsigned int)out->current_pdu_sent,
			   (unsigned int)to_send));

		ncacn_conn->iov = talloc_zero(ncacn_conn, struct iovec);
		if (ncacn_conn->iov == NULL) {
			status = NT_STATUS_NO_MEMORY;
			DEBUG(3, ("Out of memory!\n"));
			goto fail;
		}
		ncacn_conn->count = 1;

		ncacn_conn->iov[0].iov_base = out->frag.data
					    + out->current_pdu_sent;
		ncacn_conn->iov[0].iov_len = to_send;

		out->current_pdu_sent += to_send;
	}

	/*
	 * This condition is false for bind packets, or when we haven't yet got
	 * a full request, and need to wait for more data from the client
	 */
	while (out->data_sent_length < out->rdata.length) {
		ok = create_next_pdu(ncacn_conn->p);
		if (!ok) {
			DEBUG(3, ("Failed to create next PDU!\n"));
			status = NT_STATUS_UNEXPECTED_IO_ERROR;
			goto fail;
		}

		ncacn_conn->iov = talloc_realloc(ncacn_conn,
						 ncacn_conn->iov,
						 struct iovec,
						 ncacn_conn->count + 1);
		if (ncacn_conn->iov == NULL) {
			DEBUG(3, ("Out of memory!\n"));
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}

		ncacn_conn->iov[ncacn_conn->count].iov_base = out->frag.data;
		ncacn_conn->iov[ncacn_conn->count].iov_len = out->frag.length;

		DEBUG(10, ("PDU number: %d, PDU Length: %u\n",
			   (unsigned int) ncacn_conn->count,
			   (unsigned int) ncacn_conn->iov[ncacn_conn->count].iov_len));
		dump_data(11, (const uint8_t *) ncacn_conn->iov[ncacn_conn->count].iov_base,
			      ncacn_conn->iov[ncacn_conn->count].iov_len);
		ncacn_conn->count++;
	}

	/*
	 * We still don't have a complete request, go back and wait for more
	 * data.
	 */
	if (ncacn_conn->count == 0) {
		/* Wait for the next packet */
		subreq = dcerpc_read_ncacn_packet_send(ncacn_conn,
						       ncacn_conn->ev_ctx,
						       ncacn_conn->tstream);
		if (subreq == NULL) {
			DEBUG(2, ("Failed to start receiving packets\n"));
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
		tevent_req_set_callback(subreq, dcerpc_ncacn_packet_process, ncacn_conn);
		return;
	}

	switch (ncacn_conn->transport) {
	case NCACN_NP:
		/* If sending packets over named pipe proxy we need to send
		 * each fragment on its own to be a message
		 */
		DBG_DEBUG("Sending %u fragments in a total of %u bytes\n",
			  (unsigned int)ncacn_conn->count,
			  (unsigned int)ncacn_conn->p->out_data.data_sent_length);
		for (i = 0; i < ncacn_conn->count; i++) {
			DBG_DEBUG("Sending PDU number: %d, PDU Length: %u\n",
				  (unsigned int)i,
				  (unsigned int)ncacn_conn->iov[i].iov_len);
			dump_data(11, (const uint8_t *)ncacn_conn->iov[i].iov_base,
				  ncacn_conn->iov[i].iov_len);

			subreq = tstream_writev_queue_send(ncacn_conn,
					ncacn_conn->ev_ctx,
					ncacn_conn->tstream,
					ncacn_conn->send_queue,
					(ncacn_conn->iov + i),
					1);
			if (subreq == NULL) {
				DBG_ERR("Failed to send packet\n");
				status = NT_STATUS_NO_MEMORY;
				goto fail;
			}
			tevent_req_set_callback(subreq,
						dcerpc_ncacn_packet_done,
						ncacn_conn);
		}
		break;
	default:
		DBG_DEBUG("Sending a total of %u bytes\n",
			  (unsigned int)ncacn_conn->p->out_data.data_sent_length);

		subreq = tstream_writev_queue_send(ncacn_conn,
				ncacn_conn->ev_ctx,
				ncacn_conn->tstream,
				ncacn_conn->send_queue,
				ncacn_conn->iov,
				ncacn_conn->count);
		if (subreq == NULL) {
			DBG_ERR("Failed to send packet\n");
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}

		tevent_req_set_callback(subreq,
					dcerpc_ncacn_packet_done,
					ncacn_conn);
		break;
	}

	return;

fail:
	DEBUG(3, ("Terminating client(%s) connection! - '%s'\n",
		  ncacn_conn->remote_client_name, nt_errstr(status)));

	/* Terminate client connection */
	talloc_free(ncacn_conn);
	return;
}

static void dcerpc_ncacn_packet_done(struct tevent_req *subreq)
{
	struct dcerpc_ncacn_conn *ncacn_conn =
		tevent_req_callback_data(subreq, struct dcerpc_ncacn_conn);
	NTSTATUS status = NT_STATUS_OK;
	int sys_errno;
	int rc;

	rc = tstream_writev_queue_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (rc < 0) {
		DEBUG(2, ("Writev failed!\n"));
		status = map_nt_error_from_unix(sys_errno);
		goto fail;
	}

	if (ncacn_conn->transport == NCACN_NP &&
	    tevent_queue_length(ncacn_conn->send_queue) > 0) {
		/* More fragments to send before reading a new packet */
		return;
	}

	if (ncacn_conn->p->fault_state != 0) {
		DEBUG(2, ("Disconnect after fault\n"));
		sys_errno = EINVAL;
		goto fail;
	}

	/* clear out any data that may have been left around */
	ncacn_conn->count = 0;
	TALLOC_FREE(ncacn_conn->iov);
	data_blob_free(&ncacn_conn->p->in_data.data);
	data_blob_free(&ncacn_conn->p->out_data.frag);
	data_blob_free(&ncacn_conn->p->out_data.rdata);

	talloc_free_children(ncacn_conn->p->mem_ctx);

	/* Wait for the next packet */
	subreq = dcerpc_read_ncacn_packet_send(ncacn_conn,
					       ncacn_conn->ev_ctx,
					       ncacn_conn->tstream);
	if (subreq == NULL) {
		DEBUG(2, ("Failed to start receiving packets\n"));
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	tevent_req_set_callback(subreq, dcerpc_ncacn_packet_process, ncacn_conn);
	return;

fail:
	DEBUG(3, ("Terminating client(%s) connection! - '%s'\n",
		  ncacn_conn->remote_client_name, nt_errstr(status)));

	/* Terminate client connection */
	talloc_free(ncacn_conn);
	return;
}

/* vim: set ts=8 sw=8 noet cindent syntax=c.doxygen: */
