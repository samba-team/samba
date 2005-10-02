/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Volker Lendecke
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/
/*
  a composite API to fire connect calls to multiple targets, picking the first
  one.
*/

#include "includes.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"
#include "libcli/smb_composite/smb_composite.h"

struct connectmulti_state {
	struct smb_composite_connectmulti *io;
	struct composite_context *creq;
	struct smbcli_socket *result;
	int num_socks, socks_left;
	struct smbcli_socket **socks;
	struct composite_context **creqs;
};

static void connect_receive(struct composite_context *c)

{
	struct connectmulti_state *state =
		talloc_get_type(c->async.private_data,
				struct connectmulti_state);
	int i;

	for (i=0; i<state->num_socks; i++) {
		if (state->creqs[i] == c) {
			break;
		}
	}

	if (i == state->num_socks) {
		c->status = NT_STATUS_INTERNAL_ERROR;
		c->state = COMPOSITE_STATE_ERROR;
		if (state->creq->async.fn != NULL) {
			state->creq->async.fn(state->creq);
		}
		return;
	}

	state->creq->status = smbcli_sock_connect_recv(c);
	if (!NT_STATUS_IS_OK(state->creq->status)) {
		talloc_free(state->socks[i]);
		state->socks[i] = NULL;
		state->creqs[i] = NULL;
		state->socks_left -= 1;
		if (state->socks_left == 0) {
			state->creq->state = COMPOSITE_STATE_ERROR;
			if (state->creq->async.fn != NULL) {
				state->creq->async.fn(state->creq);
			}
		}
		return;
	}

	state->result = talloc_steal(state, state->socks[i]);
	talloc_free(state->socks);

	state->creq->state = COMPOSITE_STATE_DONE;
	if (state->creq->async.fn != NULL) {
		state->creq->async.fn(state->creq);
	}
}

struct composite_context *smb_composite_connectmulti_send(struct smb_composite_connectmulti *io,
							  TALLOC_CTX *mem_ctx,
							  struct event_context *event_ctx)
{
	struct composite_context *c;
	struct connectmulti_state *state;
	int num_socks = io->in.num_dests;
	const char **hostnames = io->in.hostnames;
	const char **addresses = io->in.addresses;
	int *ports = io->in.ports;
	int i;

	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) goto failed;

	state = talloc(c, struct connectmulti_state);
	if (state == NULL) goto failed;

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->event_ctx = talloc_reference(c, event_ctx);
	c->private_data = state;

	if (ports == NULL) {
		int j, nports;
		const char **smb_ports = lp_smb_ports();

		for (nports=0; smb_ports[nports]; nports++) /* noop */;

		num_socks *= nports;
		hostnames = talloc_array(state, const char *, num_socks);
		if (hostnames == NULL) goto failed;
		addresses = talloc_array(state, const char *, num_socks);
		if (addresses == NULL) goto failed;
		ports = talloc_array(state, int, num_socks);
		if (ports == NULL) goto failed;

		for (i=0; i<io->in.num_dests; i++) {
			for (j=0; j<nports; j++) {
				hostnames[i*nports+j] = io->in.hostnames[i];
				addresses[i*nports+j] = io->in.addresses[i];
				ports[i*nports+j] = atoi(smb_ports[j]);
			}
		}
	}

	state->io = io;
	state->creq = c;
	state->num_socks = num_socks;
	state->socks_left = num_socks;
	state->socks = talloc_array(state, struct smbcli_socket *, num_socks);
	state->creqs = talloc_array(state, struct composite_context *,
				    num_socks);
	if ((state->socks == NULL) || (state->creqs == NULL)) goto failed;

	for (i=0; i<num_socks; i++) {
		state->socks[i] = smbcli_sock_init(state->socks, event_ctx);
		if (state->socks[i] == NULL) goto failed;

		/* If the event_ctx we got given is NULL, the first socket
		 * creates one and all others need to refer to it. */
		event_ctx = state->socks[i]->event.ctx;

		state->creqs[i] = smbcli_sock_connect_send(state->socks[i],
							   addresses[i],
							   ports[i],
							   hostnames[i]);
		if (state->creqs[i] == NULL) goto failed;
		state->creqs[i]->async.fn = connect_receive;
		state->creqs[i]->async.private_data = state;
	}

	return c;

 failed:
	talloc_free(c);
	return NULL;
}

NTSTATUS smb_composite_connectmulti_recv(struct composite_context *c,
					 TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status)) {
		struct connectmulti_state *state =
			talloc_get_type(c->private_data,
					struct connectmulti_state);
		state->io->out.socket = talloc_steal(mem_ctx, state->result);
	}

	talloc_free(c);
	return status;
}

NTSTATUS smb_composite_connectmulti(struct smb_composite_connectmulti *io,
				    TALLOC_CTX *mem_ctx,
				    struct event_context *ev)
{
	struct composite_context *c =
		smb_composite_connectmulti_send(io, mem_ctx, ev);
	return smb_composite_connectmulti_recv(c, mem_ctx);
}
