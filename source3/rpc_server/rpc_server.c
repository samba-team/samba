/*
   Unix SMB/Netbios implementation.
   Generic infrstructure for RPC Daemons
   Copyright (C) Simo Sorce 2010

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
#include "rpc_server/rpc_server.h"
#include "rpc_dce.h"
#include "librpc/gen_ndr/netlogon.h"
#include "registry/reg_parse_prs.h"
#include "lib/tsocket/tsocket.h"

/* Creates a pipes_struct and initializes it with the information
 * sent from the client */
static int make_server_pipes_struct(TALLOC_CTX *mem_ctx,
				    const char *pipe_name,
				    const struct ndr_syntax_id id,
				    const char *client_address,
				    struct netr_SamInfo3 *info3,
				    struct pipes_struct **_p,
				    int *perrno)
{
	struct pipes_struct *p;
	NTSTATUS status;
	bool ok;

	p = talloc_zero(mem_ctx, struct pipes_struct);
	if (!p) {
		*perrno = ENOMEM;
		return -1;
	}
	p->syntax = id;

	p->mem_ctx = talloc_named(p, 0, "pipe %s %p", pipe_name, p);
	if (!p->mem_ctx) {
		TALLOC_FREE(p);
		*perrno = ENOMEM;
		return -1;
	}

	ok = init_pipe_handles(p, &id);
	if (!ok) {
		DEBUG(1, ("Failed to init handles\n"));
		TALLOC_FREE(p);
		*perrno = EINVAL;
		return -1;
	}

	/*
	 * Initialize the incoming RPC data buffer with one PDU worth of
	 * memory. We cheat here and say we're marshalling, as we intend
	 * to add incoming data directly into the prs_struct and we want
	 * it to auto grow. We will change the type to UNMARSALLING before
	 * processing the stream.
	 */
	if (!prs_init(&p->in_data.data, 128, p->mem_ctx, MARSHALL)) {
		DEBUG(0, ("malloc fail for in_data struct.\n"));
		TALLOC_FREE(p);
		*perrno = ENOMEM;
		return -1;
	}

	/*
	 * Initialize the outgoing RPC data buffer with no memory.
	 */
	prs_init_empty(&p->out_data.rdata, p->mem_ctx, MARSHALL);

	p->endian = RPC_LITTLE_ENDIAN;

	status = make_server_info_info3(p,
					info3->base.account_name.string,
					info3->base.domain.string,
					&p->server_info, info3);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to init server info\n"));
		TALLOC_FREE(p);
		*perrno = EINVAL;
		return -1;
	}

	/*
	 * Some internal functions need a local token to determine access to
	 * resoutrces.
	 */
	status = create_local_token(p->server_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to init local auth token\n"));
		TALLOC_FREE(p);
		*perrno = EINVAL;
		return -1;
	}

	p->client_id = talloc_zero(p, struct client_address);
	if (!p->client_id) {
		TALLOC_FREE(p);
		*perrno = ENOMEM;
		return -1;
	}
	strlcpy(p->client_id->addr,
		client_address, sizeof(p->client_id->addr));

	talloc_set_destructor(p, close_internal_rpc_pipe_hnd);

	*_p = p;
	return 0;
}

/* Add some helper functions to wrap the common ncacn packet reading functions
 * until we can share more dcerpc code */
struct named_pipe_read_packet_state {
	struct ncacn_packet *pkt;
	DATA_BLOB buffer;
};

static void named_pipe_read_packet_done(struct tevent_req *subreq);

static struct tevent_req *named_pipe_read_packet_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct tstream_context *tstream)
{
	struct named_pipe_read_packet_state *state;
	struct tevent_req *req, *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct named_pipe_read_packet_state);
	if (!req) {
		return NULL;
	}
	ZERO_STRUCTP(state);

	subreq = dcerpc_read_ncacn_packet_send(state, ev, tstream);
	if (!subreq) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		tevent_req_post(req, ev);
		return req;
	}
	tevent_req_set_callback(subreq, named_pipe_read_packet_done, req);

	return req;
}

static void named_pipe_read_packet_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq, struct tevent_req);
	struct named_pipe_read_packet_state *state =
		tevent_req_data(req, struct named_pipe_read_packet_state);
	NTSTATUS status;

	status = dcerpc_read_ncacn_packet_recv(subreq, state,
						&state->pkt,
						&state->buffer);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("Failed to receive dceprc packet!\n"));
		tevent_req_nterror(req, status);
		return;
	}

	tevent_req_done(req);
}

static NTSTATUS named_pipe_read_packet_recv(struct tevent_req *req,
						TALLOC_CTX *mem_ctx,
						DATA_BLOB *buffer)
{
	struct named_pipe_read_packet_state *state =
		tevent_req_data(req, struct named_pipe_read_packet_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	buffer->data = talloc_move(mem_ctx, &state->buffer.data);
	buffer->length = state->buffer.length;

	tevent_req_received(req);
	return NT_STATUS_OK;
}



/* Start listening on the appropriate unix socket and setup all is needed to
 * dispatch requests to the pipes rpc implementation */

struct named_pipe_listen_state {
	int fd;
	char *name;
};

static void named_pipe_listener(struct tevent_context *ev,
				struct tevent_fd *fde,
				uint16_t flags,
				void *private_data);

bool setup_named_pipe_socket(const char *pipe_name,
			     struct tevent_context *ev_ctx)
{
	struct named_pipe_listen_state *state;
	struct tevent_fd *fde;
	char *np_dir;

	state = talloc(ev_ctx, struct named_pipe_listen_state);
	if (!state) {
		DEBUG(0, ("Out of memory\n"));
		return false;
	}
	state->name = talloc_strdup(state, pipe_name);
	if (!state->name) {
		DEBUG(0, ("Out of memory\n"));
		goto out;
	}
	state->fd = -1;

	np_dir = talloc_asprintf(state, "%s/np", lp_ncalrpc_dir());
	if (!np_dir) {
		DEBUG(0, ("Out of memory\n"));
		goto out;
	}

	if (!directory_create_or_exist(np_dir, geteuid(), 0700)) {
		DEBUG(0, ("Failed to create pipe directory %s - %s\n",
			  np_dir, strerror(errno)));
		goto out;
	}

	state->fd = create_pipe_sock(np_dir, pipe_name, 0700);
	if (state->fd == -1) {
		DEBUG(0, ("Failed to create pipe socket! [%s/%s]\n",
			  np_dir, pipe_name));
		goto out;
	}

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

static void named_pipe_accept_function(const char *pipe_name, int fd);

static void named_pipe_listener(struct tevent_context *ev,
				struct tevent_fd *fde,
				uint16_t flags,
				void *private_data)
{
	struct named_pipe_listen_state *state =
			talloc_get_type_abort(private_data,
					      struct named_pipe_listen_state);
	struct sockaddr_un sunaddr;
	socklen_t len;
	int sd = -1;

	/* TODO: should we have a limit to the number of clients ? */

	len = sizeof(sunaddr);

	while (sd == -1) {
		sd = accept(state->fd,
			    (struct sockaddr *)(void *)&sunaddr, &len);
		if (errno != EINTR) break;
	}

	if (sd == -1) {
		DEBUG(6, ("Failed to get a valid socket [%s]\n",
			  strerror(errno)));
		return;
	}

	DEBUG(6, ("Accepted socket %d\n", sd));

	named_pipe_accept_function(state->name, sd);
}

static void named_pipe_accept_function(const char *pipe_name, int fd)
{
	return;
}
