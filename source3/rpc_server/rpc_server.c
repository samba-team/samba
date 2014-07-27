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

#define SERVER_TCP_LOW_PORT  1024
#define SERVER_TCP_HIGH_PORT 1300

/* Creates a pipes_struct and initializes it with the information
 * sent from the client */
int make_server_pipes_struct(TALLOC_CTX *mem_ctx,
			     struct messaging_context *msg_ctx,
			     const char *pipe_name,
			     enum dcerpc_transport_t transport,
			     const struct tsocket_address *local_address,
			     const struct tsocket_address *remote_address,
			     struct auth_session_info *session_info,
			     struct pipes_struct **_p,
			     int *perrno)
{
	struct pipes_struct *p;
	int ret;

	ret = make_base_pipes_struct(mem_ctx, msg_ctx, pipe_name,
				     transport, RPC_LITTLE_ENDIAN,
				     remote_address, local_address, &p);
	if (ret) {
		*perrno = ret;
		return -1;
	}

	if (session_info->unix_token && session_info->unix_info && session_info->security_token) {
		/* Don't call create_local_token(), we already have the full details here */
		p->session_info = talloc_steal(p, session_info);

	} else {
		DEBUG(0, ("Supplied session_info in make_server_pipes_struct was incomplete!"));
		*perrno = EINVAL;
		return -1;
	}

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
	dcerpc_ncacn_disconnect_fn disconnect_fn;
};

static void named_pipe_listener(struct tevent_context *ev,
				struct tevent_fd *fde,
				uint16_t flags,
				void *private_data);

int create_named_pipe_socket(const char *pipe_name)
{
	char *np_dir = NULL;
	int fd = -1;

	/*
	 * As lp_ncalrpc_dir() should have 0755, but
	 * lp_ncalrpc_dir()/np should have 0700, we need to
	 * create lp_ncalrpc_dir() first.
	 */
	if (!directory_create_or_exist(lp_ncalrpc_dir(), 0755)) {
		DEBUG(0, ("Failed to create pipe directory %s - %s\n",
			  lp_ncalrpc_dir(), strerror(errno)));
		goto out;
	}

	np_dir = talloc_asprintf(talloc_tos(), "%s/np", lp_ncalrpc_dir());
	if (!np_dir) {
		DEBUG(0, ("Out of memory\n"));
		goto out;
	}

	if (!directory_create_or_exist_strict(np_dir, geteuid(), 0700)) {
		DEBUG(0, ("Failed to create pipe directory %s - %s\n",
			  np_dir, strerror(errno)));
		goto out;
	}

	fd = create_pipe_sock(np_dir, pipe_name, 0700);
	if (fd == -1) {
		DEBUG(0, ("Failed to create pipe socket! [%s/%s]\n",
			  np_dir, pipe_name));
		goto out;
	}

	DEBUG(10, ("Openened pipe socket fd %d for %s\n", fd, pipe_name));

out:
	talloc_free(np_dir);
	return fd;
}

bool setup_named_pipe_socket(const char *pipe_name,
			     struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx)
{
	struct dcerpc_ncacn_listen_state *state;
	struct tevent_fd *fde;
	int rc;

	state = talloc(ev_ctx, struct dcerpc_ncacn_listen_state);
	if (!state) {
		DEBUG(0, ("Out of memory\n"));
		return false;
	}
	state->ep.name = talloc_strdup(state, pipe_name);
	if (state->ep.name == NULL) {
		DEBUG(0, ("Out of memory\n"));
		goto out;
	}
	state->fd = create_named_pipe_socket(pipe_name);
	if (state->fd == -1) {
		goto out;
	}

	rc = listen(state->fd, 5);
	if (rc < 0) {
		DEBUG(0, ("Failed to listen on pipe socket %s: %s\n",
			  pipe_name, strerror(errno)));
		goto out;
	}

	state->ev_ctx = ev_ctx;
	state->msg_ctx = msg_ctx;

	DEBUG(10, ("Openened pipe socket fd %d for %s\n",
		   state->fd, pipe_name));

	fde = tevent_add_fd(ev_ctx,
			    state, state->fd, TEVENT_FD_READ,
			    named_pipe_listener, state);
	if (!fde) {
		DEBUG(0, ("Failed to add event handler!\n"));
		goto out;
	}

	tevent_fd_set_auto_close(fde);
	return true;

out:
	if (state->fd != -1) {
		close(state->fd);
	}
	TALLOC_FREE(state);
	return false;
}

static void named_pipe_listener(struct tevent_context *ev,
				struct tevent_fd *fde,
				uint16_t flags,
				void *private_data)
{
	struct dcerpc_ncacn_listen_state *state =
			talloc_get_type_abort(private_data,
					      struct dcerpc_ncacn_listen_state);
	struct sockaddr_un sunaddr;
	socklen_t len;
	int sd = -1;

	/* TODO: should we have a limit to the number of clients ? */

	len = sizeof(sunaddr);

	sd = accept(state->fd,
		    (struct sockaddr *)(void *)&sunaddr, &len);

	if (sd == -1) {
		if (errno != EINTR) {
			DEBUG(6, ("Failed to get a valid socket [%s]\n",
				  strerror(errno)));
		}
		return;
	}

	DEBUG(6, ("Accepted socket %d\n", sd));

	named_pipe_accept_function(state->ev_ctx,
				   state->msg_ctx,
				   state->ep.name,
				   sd, NULL, 0);
}


/* This is the core of the rpc server.
 * Accepts connections from clients and process requests using the appropriate
 * dispatcher table. */

static int named_pipe_destructor(struct named_pipe_client *npc)
{
	if (npc->term_fn) {
		npc->term_fn(npc->private_data);
	}
	return 0;
}

struct named_pipe_client *named_pipe_client_init(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev_ctx,
						 struct messaging_context *msg_ctx,
						 const char *pipe_name,
						 named_pipe_termination_fn *term_fn,
						 uint16_t file_type,
						 uint16_t device_state,
						 uint64_t allocation_size,
						 void *private_data)
{
	struct named_pipe_client *npc;

	npc = talloc_zero(mem_ctx, struct named_pipe_client);
	if (npc == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		return NULL;
	}
	talloc_set_destructor(npc, named_pipe_destructor);

	npc->pipe_name = talloc_strdup(npc, pipe_name);
	if (npc->pipe_name == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		talloc_free(npc);
		return NULL;
	}

	npc->ev = ev_ctx;
	npc->msg_ctx = msg_ctx;
	npc->term_fn = term_fn;
	npc->private_data = private_data;

	npc->file_type = file_type;
	npc->device_state = device_state;
	npc->allocation_size = allocation_size;

	return npc;
}

static void named_pipe_accept_done(struct tevent_req *subreq);

void named_pipe_accept_function(struct tevent_context *ev_ctx,
			        struct messaging_context *msg_ctx,
				const char *pipe_name, int fd,
				named_pipe_termination_fn *term_fn,
				void *private_data)
{
	struct named_pipe_client *npc;
	struct tstream_context *plain;
	struct tevent_req *subreq;
	int ret;

	npc = talloc_zero(ev_ctx, struct named_pipe_client);
	if (!npc) {
		DEBUG(0, ("Out of memory!\n"));
		close(fd);
		return;
	}

	npc->pipe_name = talloc_strdup(npc, pipe_name);
	if (npc->pipe_name == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		TALLOC_FREE(npc);
		close(fd);
		return;
	}
	npc->ev = ev_ctx;
	npc->msg_ctx = msg_ctx;
	npc->term_fn = term_fn;
	npc->private_data = private_data;

	talloc_set_destructor(npc, named_pipe_destructor);

	/* make sure socket is in NON blocking state */
	ret = set_blocking(fd, false);
	if (ret != 0) {
		DEBUG(2, ("Failed to make socket non-blocking\n"));
		TALLOC_FREE(npc);
		close(fd);
		return;
	}

	ret = tstream_bsd_existing_socket(npc, fd, &plain);
	if (ret != 0) {
		DEBUG(2, ("Failed to create tstream socket\n"));
		TALLOC_FREE(npc);
		close(fd);
		return;
	}

	npc->file_type = FILE_TYPE_MESSAGE_MODE_PIPE;
	npc->device_state = 0xff | 0x0400 | 0x0100;
	npc->allocation_size = 4096;

	subreq = tstream_npa_accept_existing_send(npc, npc->ev, plain,
						  npc->file_type,
						  npc->device_state,
						  npc->allocation_size);
	if (!subreq) {
		DEBUG(2, ("Failed to start async accept procedure\n"));
		TALLOC_FREE(npc);
		close(fd);
		return;
	}
	tevent_req_set_callback(subreq, named_pipe_accept_done, npc);
}

static void named_pipe_packet_done(struct tevent_req *subreq);

static void named_pipe_accept_done(struct tevent_req *subreq)
{
	struct auth_session_info_transport *session_info_transport;
	struct named_pipe_client *npc =
		tevent_req_callback_data(subreq, struct named_pipe_client);
	int error;
	int ret;

	ret = tstream_npa_accept_existing_recv(subreq, &error, npc,
						&npc->tstream,
						&npc->client,
						&npc->client_name,
						&npc->server,
						&npc->server_name,
						&session_info_transport);

	npc->session_info = talloc_move(npc, &session_info_transport->session_info);

	TALLOC_FREE(subreq);
	if (ret != 0) {
		DEBUG(2, ("Failed to accept named pipe connection! (%s)\n",
			  strerror(error)));
		TALLOC_FREE(npc);
		return;
	}

	ret = make_server_pipes_struct(npc,
				       npc->msg_ctx,
				       npc->pipe_name, NCACN_NP,
				       npc->server,
				       npc->client,
				       npc->session_info,
				       &npc->p, &error);
	if (ret != 0) {
		DEBUG(2, ("Failed to create pipes_struct! (%s)\n",
			  strerror(error)));
		goto fail;
	}

	npc->write_queue = tevent_queue_create(npc, "np_server_write_queue");
	if (!npc->write_queue) {
		DEBUG(2, ("Failed to set up write queue!\n"));
		goto fail;
	}

	/* And now start receiving and processing packets */
	subreq = dcerpc_read_ncacn_packet_send(npc, npc->ev, npc->tstream);
	if (!subreq) {
		DEBUG(2, ("Failed to start receving packets\n"));
		goto fail;
	}
	tevent_req_set_callback(subreq, named_pipe_packet_process, npc);
	return;

fail:
	DEBUG(2, ("Fatal error. Terminating client(%s) connection!\n",
		  npc->client_name));
	/* terminate client connection */
	talloc_free(npc);
	return;
}

void named_pipe_packet_process(struct tevent_req *subreq)
{
	struct named_pipe_client *npc =
		tevent_req_callback_data(subreq, struct named_pipe_client);
	struct _output_data *out = &npc->p->out_data;
	DATA_BLOB recv_buffer = data_blob_null;
	struct ncacn_packet *pkt;
	NTSTATUS status;
	uint32_t to_send;
	size_t i;
	bool ok;

	status = dcerpc_read_ncacn_packet_recv(subreq, npc, &pkt, &recv_buffer);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* dcerpc_read_ncacn_packet_recv() returns a full PDU */
	npc->p->in_data.pdu_needed_len = 0;
	npc->p->in_data.pdu = recv_buffer;
	if (dcerpc_get_endian_flag(&recv_buffer) & DCERPC_DREP_LE) {
		npc->p->endian = RPC_LITTLE_ENDIAN;
	} else {
		npc->p->endian = RPC_BIG_ENDIAN;
	}
	DEBUG(10, ("PDU is in %s Endian format!\n",
		   npc->p->endian ? "Big" : "Little"));
	process_complete_pdu(npc->p, pkt);

	/* reset pipe state and free PDU */
	npc->p->in_data.pdu.length = 0;
	talloc_free(recv_buffer.data);
	talloc_free(pkt);

	/* this is needed because of the way DCERPC Binds work in
	 * the RPC marshalling code */
	to_send = out->frag.length - out->current_pdu_sent;
	if (to_send > 0) {

		npc->iov = talloc_zero(npc, struct iovec);
		if (!npc->iov) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
		npc->count = 1;

		npc->iov[0].iov_base = out->frag.data
					+ out->current_pdu_sent;
		npc->iov[0].iov_len = to_send;

		out->current_pdu_sent += to_send;
	}

	/* this condition is false for bind packets, or when we haven't
	 * yet got a full request, and need to wait for more data from
	 * the client */
	while (out->data_sent_length < out->rdata.length) {

		ok = create_next_pdu(npc->p);
		if (!ok) {
			DEBUG(3, ("Failed to create next PDU!\n"));
			status = NT_STATUS_UNEXPECTED_IO_ERROR;
			goto fail;
		}

		npc->iov = talloc_realloc(npc, npc->iov,
					    struct iovec, npc->count + 1);
		if (!npc->iov) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}

		npc->iov[npc->count].iov_base = out->frag.data;
		npc->iov[npc->count].iov_len = out->frag.length;

		npc->count++;
	}

	/* we still don't have a complete request, go back and wait for more
	 * data */
	if (npc->count == 0) {
		/* Wait for the next packet */
		subreq = dcerpc_read_ncacn_packet_send(npc, npc->ev, npc->tstream);
		if (!subreq) {
			DEBUG(2, ("Failed to start receving packets\n"));
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
		tevent_req_set_callback(subreq, named_pipe_packet_process, npc);
		return;
	}

	DEBUG(10, ("Sending %u fragments in a total of %u bytes\n",
		   (unsigned int)npc->count,
		   (unsigned int)npc->p->out_data.data_sent_length));

	for (i = 0; i < npc->count; i++) {
		DEBUG(10, ("Sending PDU number: %d, PDU Length: %u\n",
			  (unsigned int)i,
			  (unsigned int)npc->iov[i].iov_len));
		dump_data(11, (const uint8_t *)npc->iov[i].iov_base,
				npc->iov[i].iov_len);

		subreq = tstream_writev_queue_send(npc,
						   npc->ev,
						   npc->tstream,
						   npc->write_queue,
						   (npc->iov + i),
						   1);
		if (!subreq) {
			DEBUG(2, ("Failed to send packet\n"));
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
		tevent_req_set_callback(subreq, named_pipe_packet_done, npc);
	}

	return;

fail:
	DEBUG(2, ("Fatal error(%s). "
		  "Terminating client(%s) connection!\n",
		  nt_errstr(status), npc->client_name));
	/* terminate client connection */
	talloc_free(npc);
	return;
}

static void named_pipe_packet_done(struct tevent_req *subreq)
{
	struct named_pipe_client *npc =
		tevent_req_callback_data(subreq, struct named_pipe_client);
	int sys_errno;
	int ret;

	ret = tstream_writev_queue_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		DEBUG(2, ("Writev failed!\n"));
		goto fail;
	}

	if (tevent_queue_length(npc->write_queue) > 0) {
		return;
	}

	/* clear out any data that may have been left around */
	npc->count = 0;
	TALLOC_FREE(npc->iov);
	data_blob_free(&npc->p->in_data.data);
	data_blob_free(&npc->p->out_data.frag);
	data_blob_free(&npc->p->out_data.rdata);

	talloc_free_children(npc->p->mem_ctx);

	/* Wait for the next packet */
	subreq = dcerpc_read_ncacn_packet_send(npc, npc->ev, npc->tstream);
	if (!subreq) {
		DEBUG(2, ("Failed to start receving packets\n"));
		sys_errno = ENOMEM;
		goto fail;
	}
	tevent_req_set_callback(subreq, named_pipe_packet_process, npc);
	return;

fail:
	DEBUG(2, ("Fatal error(%s). "
		  "Terminating client(%s) connection!\n",
		  strerror(sys_errno), npc->client_name));
	/* terminate client connection */
	talloc_free(npc);
	return;
}

/********************************************************************
 * Start listening on the tcp/ip socket
 ********************************************************************/

static void dcerpc_ncacn_tcpip_listener(struct tevent_context *ev,
					struct tevent_fd *fde,
					uint16_t flags,
					void *private_data);

int create_tcpip_socket(const struct sockaddr_storage *ifss, uint16_t *port)
{
	int fd = -1;

	if (*port == 0) {
		uint16_t i;

		for (i = SERVER_TCP_LOW_PORT; i <= SERVER_TCP_HIGH_PORT; i++) {
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
		DEBUG(0, ("Failed to create socket on port %u!\n", *port));
		return -1;
	}

	DEBUG(10, ("Opened tcpip socket fd %d for port %u\n", fd, *port));

	return fd;
}

uint16_t setup_dcerpc_ncacn_tcpip_socket(struct tevent_context *ev_ctx,
					 struct messaging_context *msg_ctx,
					 const struct sockaddr_storage *ifss,
					 uint16_t port)
{
	struct dcerpc_ncacn_listen_state *state;
	struct tevent_fd *fde;
	int rc;

	state = talloc(ev_ctx, struct dcerpc_ncacn_listen_state);
	if (state == NULL) {
		DEBUG(0, ("setup_dcerpc_ncacn_tcpip_socket: Out of memory\n"));
		return 0;
	}

	state->fd = -1;
	state->ep.port = port;
	state->disconnect_fn = NULL;

	state->fd = create_tcpip_socket(ifss, &state->ep.port);
	if (state->fd == -1) {
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
		DEBUG(0,("setup_tcpip_socket: listen - %s\n", strerror(errno)));
		goto out;
	}

	DEBUG(10, ("setup_tcpip_socket: openened socket fd %d for port %u\n",
		   state->fd, state->ep.port));

	fde = tevent_add_fd(state->ev_ctx,
			    state,
			    state->fd,
			    TEVENT_FD_READ,
			    dcerpc_ncacn_tcpip_listener,
			    state);
	if (fde == NULL) {
		DEBUG(0, ("setup_tcpip_socket: Failed to add event handler!\n"));
		goto out;
	}

	tevent_fd_set_auto_close(fde);

	return state->ep.port;
out:
	if (state->fd != -1) {
		close(state->fd);
	}
	TALLOC_FREE(state);

	return 0;
}

static void dcerpc_ncacn_tcpip_listener(struct tevent_context *ev,
					struct tevent_fd *fde,
					uint16_t flags,
					void *private_data)
{
	struct dcerpc_ncacn_listen_state *state =
			talloc_get_type_abort(private_data,
					      struct dcerpc_ncacn_listen_state);
	struct tsocket_address *cli_addr = NULL;
	struct tsocket_address *srv_addr = NULL;
	struct sockaddr_storage addr;
	socklen_t in_addrlen = sizeof(addr);
	int s = -1;
	int rc;

	s = accept(state->fd, (struct sockaddr *)(void *) &addr, &in_addrlen);
	if (s == -1) {
		if (errno != EINTR) {
			DEBUG(0,("tcpip_listener accept: %s\n",
				 strerror(errno)));
		}
		return;
	}

	rc = tsocket_address_bsd_from_sockaddr(state,
					       (struct sockaddr *)(void *) &addr,
					       in_addrlen,
					       &cli_addr);
	if (rc < 0) {
		close(s);
		return;
	}

	rc = getsockname(s, (struct sockaddr *)(void *) &addr, &in_addrlen);
	if (rc < 0) {
		close(s);
		return;
	}

	rc = tsocket_address_bsd_from_sockaddr(state,
					       (struct sockaddr *)(void *) &addr,
					       in_addrlen,
					       &srv_addr);
	if (rc < 0) {
		close(s);
		return;
	}

	DEBUG(6, ("tcpip_listener: Accepted socket %d\n", s));

	dcerpc_ncacn_accept(state->ev_ctx,
			    state->msg_ctx,
			    NCACN_IP_TCP,
			    NULL,
			    cli_addr,
			    srv_addr,
			    s,
			    NULL);
}

/********************************************************************
 * Start listening on the ncalrpc socket
 ********************************************************************/

static void dcerpc_ncalrpc_listener(struct tevent_context *ev,
				    struct tevent_fd *fde,
				    uint16_t flags,
				    void *private_data);

int create_dcerpc_ncalrpc_socket(const char *name)
{
	int fd = -1;

	if (name == NULL) {
		name = "DEFAULT";
	}

	if (!directory_create_or_exist(lp_ncalrpc_dir(), 0755)) {
		DEBUG(0, ("Failed to create ncalrpc directory %s - %s\n",
			  lp_ncalrpc_dir(), strerror(errno)));
		return -1;
	}

	fd = create_pipe_sock(lp_ncalrpc_dir(), name, 0755);
	if (fd == -1) {
		DEBUG(0, ("Failed to create ncalrpc socket! [%s/%s]\n",
			  lp_ncalrpc_dir(), name));
		return -1;
	}

	DEBUG(10, ("Openened ncalrpc socket fd %d for %s\n", fd, name));

	return fd;
}

bool setup_dcerpc_ncalrpc_socket(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx,
				 const char *name,
				 dcerpc_ncacn_disconnect_fn fn)
{
	struct dcerpc_ncacn_listen_state *state;
	struct tevent_fd *fde;
	int rc;

	state = talloc(ev_ctx, struct dcerpc_ncacn_listen_state);
	if (state == NULL) {
		DEBUG(0, ("Out of memory\n"));
		return false;
	}

	state->fd = -1;
	state->disconnect_fn = fn;

	if (name == NULL) {
		name = "DEFAULT";
	}

	state->ep.name = talloc_strdup(state, name);
	if (state->ep.name == NULL) {
		DEBUG(0, ("Out of memory\n"));
		talloc_free(state);
		return false;
	}

	state->fd = create_dcerpc_ncalrpc_socket(name);
	if (state->fd == -1) {
		goto out;
	}

	rc = listen(state->fd, 5);
	if (rc < 0) {
		DEBUG(0, ("Failed to listen on ncalrpc socket %s: %s\n",
			  name, strerror(errno)));
		goto out;
	}

	state->ev_ctx = ev_ctx;
	state->msg_ctx = msg_ctx;

	/* Set server socket to non-blocking for the accept. */
	set_blocking(state->fd, false);

	fde = tevent_add_fd(state->ev_ctx,
			    state,
			    state->fd,
			    TEVENT_FD_READ,
			    dcerpc_ncalrpc_listener,
			    state);
	if (fde == NULL) {
		DEBUG(0, ("Failed to add event handler for ncalrpc!\n"));
		goto out;
	}

	tevent_fd_set_auto_close(fde);

	return true;
out:
	if (state->fd != -1) {
		close(state->fd);
	}
	TALLOC_FREE(state);

	return 0;
}

static void dcerpc_ncalrpc_listener(struct tevent_context *ev,
					struct tevent_fd *fde,
					uint16_t flags,
					void *private_data)
{
	struct dcerpc_ncacn_listen_state *state =
			talloc_get_type_abort(private_data,
					      struct dcerpc_ncacn_listen_state);
	struct tsocket_address *cli_addr = NULL;
	struct sockaddr_un sunaddr;
	struct sockaddr *addr = (struct sockaddr *)(void *)&sunaddr;
	socklen_t len = sizeof(sunaddr);
	int sd = -1;
	int rc;

	ZERO_STRUCT(sunaddr);

	sd = accept(state->fd, addr, &len);
	if (sd == -1) {
		if (errno != EINTR) {
			DEBUG(0, ("ncalrpc accept() failed: %s\n", strerror(errno)));
		}
		return;
	}

	rc = tsocket_address_bsd_from_sockaddr(state,
					       addr, len,
					       &cli_addr);
	if (rc < 0) {
		close(sd);
		return;
	}

	DEBUG(10, ("Accepted ncalrpc socket %d\n", sd));

	dcerpc_ncacn_accept(state->ev_ctx,
			    state->msg_ctx,
			    NCALRPC,
			    state->ep.name,
			    cli_addr, NULL, sd,
			    state->disconnect_fn);
}

struct dcerpc_ncacn_conn {
	enum dcerpc_transport_t transport;

	int sock;

	struct pipes_struct *p;
	dcerpc_ncacn_disconnect_fn disconnect_fn;

	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;

	struct tstream_context *tstream;
	struct tevent_queue *send_queue;

	struct tsocket_address *client;
	char *client_name;
	struct tsocket_address *server;
	char *server_name;
	struct auth_session_info *session_info;

	struct iovec *iov;
	size_t count;
};

static void dcerpc_ncacn_packet_process(struct tevent_req *subreq);
static void dcerpc_ncacn_packet_done(struct tevent_req *subreq);

void dcerpc_ncacn_accept(struct tevent_context *ev_ctx,
			 struct messaging_context *msg_ctx,
			 enum dcerpc_transport_t transport,
			 const char *name,
			 struct tsocket_address *cli_addr,
			 struct tsocket_address *srv_addr,
			 int s,
			 dcerpc_ncacn_disconnect_fn fn) {
	struct dcerpc_ncacn_conn *ncacn_conn;
	struct tevent_req *subreq;
	char *pipe_name;
	NTSTATUS status;
	int sys_errno;
	uid_t uid;
	gid_t gid;
	int rc;

	DEBUG(10, ("dcerpc_ncacn_accept\n"));

	ncacn_conn = talloc_zero(ev_ctx, struct dcerpc_ncacn_conn);
	if (ncacn_conn == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		close(s);
		return;
	}

	ncacn_conn->transport = transport;
	ncacn_conn->ev_ctx = ev_ctx;
	ncacn_conn->msg_ctx = msg_ctx;
	ncacn_conn->sock = s;
	ncacn_conn->disconnect_fn = fn;

	ncacn_conn->client = talloc_move(ncacn_conn, &cli_addr);
	if (tsocket_address_is_inet(ncacn_conn->client, "ip")) {
		ncacn_conn->client_name =
			tsocket_address_inet_addr_string(ncacn_conn->client,
							 ncacn_conn);
	} else {
		ncacn_conn->client_name =
			tsocket_address_unix_path(ncacn_conn->client,
						  ncacn_conn);
	}
	if (ncacn_conn->client_name == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		talloc_free(ncacn_conn);
		close(s);
		return;
	}

	if (srv_addr != NULL) {
		ncacn_conn->server = talloc_move(ncacn_conn, &srv_addr);

		ncacn_conn->server_name =
			tsocket_address_inet_addr_string(ncacn_conn->server,
							 ncacn_conn);
		if (ncacn_conn->server_name == NULL) {
			DEBUG(0, ("Out of memory!\n"));
			talloc_free(ncacn_conn);
			close(s);
			return;
		}
	}

	switch (transport) {
		case NCACN_IP_TCP:
			pipe_name = tsocket_address_string(ncacn_conn->client,
							   ncacn_conn);
			if (pipe_name == NULL) {
				close(s);
				talloc_free(ncacn_conn);
				return;
			}

			break;
		case NCALRPC:
			rc = getpeereid(s, &uid, &gid);
			if (rc < 0) {
				DEBUG(2, ("Failed to get ncalrpc connecting "
					  "uid - %s!\n", strerror(errno)));
			} else {
				if (uid == sec_initial_uid()) {
					TALLOC_FREE(ncacn_conn->client);

					rc = tsocket_address_unix_from_path(ncacn_conn,
									    "/root/ncalrpc_as_system",
									    &ncacn_conn->client);
					if (rc < 0) {
						DEBUG(0, ("Out of memory!\n"));
						talloc_free(ncacn_conn);
						close(s);
						return;
					}

					TALLOC_FREE(ncacn_conn->client_name);
					ncacn_conn->client_name = tsocket_address_unix_path(ncacn_conn->client,
											    ncacn_conn);
					if (ncacn_conn->client == NULL) {
						DEBUG(0, ("Out of memory!\n"));
						talloc_free(ncacn_conn);
						close(s);
						return;
					}
				}
			}
			/* FALL TROUGH */
		case NCACN_NP:
			pipe_name = talloc_strdup(ncacn_conn,
						  name);
			if (pipe_name == NULL) {
				close(s);
				talloc_free(ncacn_conn);
				return;
			}
			break;
		default:
			DEBUG(0, ("unknown dcerpc transport: %u!\n",
				  transport));
			talloc_free(ncacn_conn);
			close(s);
			return;
	}

	rc = set_blocking(s, false);
	if (rc < 0) {
		DEBUG(2, ("Failed to set dcerpc socket to non-blocking\n"));
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
		DEBUG(2, ("Failed to create tstream socket for dcerpc\n"));
		talloc_free(ncacn_conn);
		close(s);
		return;
	}

	if (ncacn_conn->session_info == NULL) {
		/*
		 * TODO: use auth_anonymous_session_info() here?
		 */
		status = make_session_info_guest(ncacn_conn,
						 &ncacn_conn->session_info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(2, ("Failed to create "
				  "make_session_info_guest - %s\n",
				  nt_errstr(status)));
			talloc_free(ncacn_conn);
			return;
		}
	}

	rc = make_server_pipes_struct(ncacn_conn,
				      ncacn_conn->msg_ctx,
				      pipe_name,
				      ncacn_conn->transport,
				      ncacn_conn->server,
				      ncacn_conn->client,
				      ncacn_conn->session_info,
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
		DEBUG(0, ("Out of memory!\n"));
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

static void dcerpc_ncacn_packet_process(struct tevent_req *subreq)
{
	struct dcerpc_ncacn_conn *ncacn_conn =
		tevent_req_callback_data(subreq, struct dcerpc_ncacn_conn);

	struct _output_data *out = &ncacn_conn->p->out_data;
	DATA_BLOB recv_buffer = data_blob_null;
	struct ncacn_packet *pkt;
	uint32_t to_send;
	NTSTATUS status;
	bool ok;

	status = dcerpc_read_ncacn_packet_recv(subreq, ncacn_conn, &pkt, &recv_buffer);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		if (ncacn_conn->disconnect_fn != NULL) {
			ok = ncacn_conn->disconnect_fn(ncacn_conn->p);
			if (!ok) {
				DEBUG(3, ("Failed to call disconnect function\n"));
			}
		}
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
			DEBUG(2, ("Failed to start receving packets\n"));
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
		tevent_req_set_callback(subreq, dcerpc_ncacn_packet_process, ncacn_conn);
		return;
	}

	DEBUG(10, ("Sending a total of %u bytes\n",
		   (unsigned int)ncacn_conn->p->out_data.data_sent_length));

	subreq = tstream_writev_queue_send(ncacn_conn,
					   ncacn_conn->ev_ctx,
					   ncacn_conn->tstream,
					   ncacn_conn->send_queue,
					   ncacn_conn->iov,
					   ncacn_conn->count);
	if (subreq == NULL) {
		DEBUG(2, ("Failed to send packet\n"));
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	tevent_req_set_callback(subreq, dcerpc_ncacn_packet_done, ncacn_conn);
	return;

fail:
	DEBUG(3, ("Terminating client(%s) connection! - '%s'\n",
		  ncacn_conn->client_name, nt_errstr(status)));

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
		DEBUG(2, ("Failed to start receving packets\n"));
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	tevent_req_set_callback(subreq, dcerpc_ncacn_packet_process, ncacn_conn);
	return;

fail:
	DEBUG(3, ("Terminating client(%s) connection! - '%s'\n",
		  ncacn_conn->client_name, nt_errstr(status)));

	/* Terminate client connection */
	talloc_free(ncacn_conn);
	return;
}

/* vim: set ts=8 sw=8 noet cindent syntax=c.doxygen: */
