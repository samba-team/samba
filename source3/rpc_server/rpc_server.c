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
#include "libcli/named_pipe_auth/npa_tstream.h"

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


	data_blob_free(&p->in_data.data);
	data_blob_free(&p->in_data.pdu);

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


/* This is the core of the rpc server.
 * Accepts connections from clients and process requests using the appropriate
 * dispatcher table. */

struct named_pipe_client {
	const char *pipe_name;
	struct ndr_syntax_id pipe_id;

	struct tevent_context *ev;

	uint16_t file_type;
	uint16_t device_state;
	uint64_t allocation_size;

	struct tstream_context *tstream;

	struct tsocket_address *client;
	char *client_name;
	struct tsocket_address *server;
	char *server_name;
	struct netr_SamInfo3 *info3;
	DATA_BLOB session_key;
	DATA_BLOB delegated_creds;

	struct pipes_struct *p;

	struct tevent_queue *write_queue;

	struct iovec *iov;
	size_t count;
};

static void named_pipe_accept_done(struct tevent_req *subreq);

static void named_pipe_accept_function(const char *pipe_name, int fd)
{
	struct ndr_syntax_id syntax;
	struct named_pipe_client *npc;
	struct tstream_context *plain;
	struct tevent_req *subreq;
	bool ok;
	int ret;

	ok = is_known_pipename(pipe_name, &syntax);
	if (!ok) {
		DEBUG(1, ("Unknown pipe [%s]\n", pipe_name));
		close(fd);
		return;
	}

	npc = talloc_zero(NULL, struct named_pipe_client);
	if (!npc) {
		DEBUG(0, ("Out of memory!\n"));
		close(fd);
		return;
	}
	npc->pipe_name = pipe_name;
	npc->pipe_id = syntax;
	npc->ev = server_event_context();

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

static void named_pipe_packet_process(struct tevent_req *subreq);
static void named_pipe_packet_done(struct tevent_req *subreq);

static void named_pipe_accept_done(struct tevent_req *subreq)
{
	struct named_pipe_client *npc =
		tevent_req_callback_data(subreq, struct named_pipe_client);
	const char *cli_addr;
	int error;
	int ret;

	ret = tstream_npa_accept_existing_recv(subreq, &error, npc,
						&npc->tstream,
						&npc->client,
						&npc->client_name,
						&npc->server,
						&npc->server_name,
						&npc->info3,
						&npc->session_key,
						&npc->delegated_creds);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		DEBUG(2, ("Failed to accept named pipe connection! (%s)\n",
			  strerror(error)));
		TALLOC_FREE(npc);
		return;
	}

	if (tsocket_address_is_inet(npc->client, "ip")) {
		cli_addr = tsocket_address_inet_addr_string(npc->client,
							    subreq);
		if (cli_addr == NULL) {
			TALLOC_FREE(npc);
			return;
		}
	} else {
		cli_addr = "";
	}

	ret = make_server_pipes_struct(npc,
					npc->pipe_name, npc->pipe_id,
					cli_addr, npc->info3,
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

	/* And now start receaving and processing packets */
	subreq = named_pipe_read_packet_send(npc, npc->ev, npc->tstream);
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

static void named_pipe_packet_process(struct tevent_req *subreq)
{
	struct named_pipe_client *npc =
		tevent_req_callback_data(subreq, struct named_pipe_client);
	struct _output_data *out = &npc->p->out_data;
	DATA_BLOB recv_buffer = data_blob_null;
	NTSTATUS status;
	ssize_t data_left;
	ssize_t data_used;
	char *data;
	uint32_t to_send;
	bool ok;

	status = named_pipe_read_packet_recv(subreq, npc, &recv_buffer);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	data_left = recv_buffer.length;
	data = (char *)recv_buffer.data;

	while (data_left) {

		data_used = process_incoming_data(npc->p, data, data_left);
		if (data_used < 0) {
			DEBUG(3, ("Failed to process dceprc request!\n"));
			status = NT_STATUS_UNEXPECTED_IO_ERROR;
			goto fail;
		}

		data_left -= data_used;
		data += data_used;
	}

	/* Do not leak this buffer, npc is a long lived context */
	talloc_free(recv_buffer.data);

	/* this is needed because of the way DCERPC Binds work in
	 * the RPC marshalling code */
	to_send = out->frag.length - out->current_pdu_sent;
	if (to_send > 0) {

		DEBUG(10, ("Current_pdu_len = %u, "
			   "current_pdu_sent = %u "
			   "Returning %u bytes\n",
			   (unsigned int)out->frag.length,
			   (unsigned int)out->current_pdu_sent,
			   (unsigned int)to_send));

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

		DEBUG(10, ("PDU number: %d, PDU Length: %u\n",
			   (unsigned int)npc->count,
			   (unsigned int)npc->iov[npc->count].iov_len));
		dump_data(11, (const uint8_t *)npc->iov[npc->count].iov_base,
				npc->iov[npc->count].iov_len);
		npc->count++;
	}

	/* we still don't have a complete request, go back and wait for more
	 * data */
	if (npc->count == 0) {
		/* Wait for the next packet */
		subreq = named_pipe_read_packet_send(npc, npc->ev, npc->tstream);
		if (!subreq) {
			DEBUG(2, ("Failed to start receving packets\n"));
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
		tevent_req_set_callback(subreq, named_pipe_packet_process, npc);
		return;
	}

	DEBUG(10, ("Sending a total of %u bytes\n",
		   (unsigned int)npc->p->out_data.data_sent_length));

	subreq = tstream_writev_queue_send(npc, npc->ev,
					   npc->tstream,
					   npc->write_queue,
					   npc->iov, npc->count);
	if (!subreq) {
		DEBUG(2, ("Failed to send packet\n"));
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	tevent_req_set_callback(subreq, named_pipe_packet_done, npc);
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

	/* clear out any data that may have been left around */
	npc->count = 0;
	TALLOC_FREE(npc->iov);
	data_blob_free(&npc->p->in_data.data);
	data_blob_free(&npc->p->out_data.frag);
	data_blob_free(&npc->p->out_data.rdata);

	/* Wait for the next packet */
	subreq = named_pipe_read_packet_send(npc, npc->ev, npc->tstream);
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
