/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Volker Lendecke 2005
   
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
  a composite API for loading a whole file into memory
*/

#include "includes.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"

enum fetchfile_stage {FETCHFILE_CONNECT,
		      FETCHFILE_READ};

struct fetchfile_state {
	enum fetchfile_stage stage;
	struct smb_composite_fetchfile *io;
	struct composite_context *req;
	struct smb_composite_connect *connect;
	struct smb_composite_loadfile *loadfile;
};

static void fetchfile_composite_handler(struct composite_context *req);

static NTSTATUS fetchfile_connect(struct composite_context *c,
				  struct smb_composite_fetchfile *io)
{
	NTSTATUS status;
	struct fetchfile_state *state;
	state = talloc_get_type(c->private, struct fetchfile_state);

	status = smb_composite_connect_recv(state->req, c);
	NT_STATUS_NOT_OK_RETURN(status);

	state->loadfile = talloc(state, struct smb_composite_loadfile);
	NT_STATUS_HAVE_NO_MEMORY(state->loadfile);

	state->loadfile->in.fname = io->in.filename;

	state->req = smb_composite_loadfile_send(state->connect->out.tree,
						 state->loadfile);
	NT_STATUS_HAVE_NO_MEMORY(state->req);

	state->req->async.private = c;
	state->req->async.fn = fetchfile_composite_handler;

	state->stage = FETCHFILE_READ;
	c->event_ctx = talloc_reference(c, state->req->event_ctx);

	return NT_STATUS_OK;
}

static NTSTATUS fetchfile_read(struct composite_context *c,
			       struct smb_composite_fetchfile *io)
{
	NTSTATUS status;
	struct fetchfile_state *state;
	state = talloc_get_type(c->private, struct fetchfile_state);

	status = smb_composite_loadfile_recv(state->req, NULL);
	NT_STATUS_NOT_OK_RETURN(status);

	io->out.data = state->loadfile->out.data;
	io->out.size = state->loadfile->out.size;

	c->state = SMBCLI_REQUEST_DONE;
	if (c->async.fn)
		c->async.fn(c);

	return NT_STATUS_OK;
}

static void fetchfile_state_handler(struct composite_context *c)
{
	struct fetchfile_state *state;
	NTSTATUS status;
	
	state = talloc_get_type(c->private, struct fetchfile_state);

	/* when this handler is called, the stage indicates what
	   call has just finished */
	switch (state->stage) {
	case FETCHFILE_CONNECT:
		status = fetchfile_connect(c, state->io);
		break;
	case FETCHFILE_READ:
		status = fetchfile_read(c, state->io);
		break;
	}

	if (!NT_STATUS_IS_OK(status)) {
		c->status = status;
		c->state = SMBCLI_REQUEST_ERROR;
		if (c->async.fn) {
			c->async.fn(c);
		}
	}
}

static void fetchfile_composite_handler(struct composite_context *req)
{
	struct composite_context *c = talloc_get_type(req->async.private, 
						     struct composite_context);
	return fetchfile_state_handler(c);
}

struct composite_context *smb_composite_fetchfile_send(struct smb_composite_fetchfile *io,
						      struct event_context *event_ctx)
{
	struct composite_context *c;
	struct fetchfile_state *state;

	c = talloc_zero(NULL, struct composite_context);
	if (c == NULL) goto failed;

	state = talloc(c, struct fetchfile_state);
	if (state == NULL) goto failed;

	state->connect = talloc(state, struct smb_composite_connect);
	if (state->connect == NULL) goto failed;

	state->io = io;

	state->connect->in.dest_host    = io->in.dest_host;
	state->connect->in.port         = io->in.port;
	state->connect->in.called_name  = io->in.called_name;
	state->connect->in.service      = io->in.service;
	state->connect->in.service_type = io->in.service_type;
	state->connect->in.credentials  = io->in.credentials;
	state->connect->in.workgroup    = io->in.workgroup;

	state->req = smb_composite_connect_send(state->connect, event_ctx);
	if (state->req == NULL) goto failed;

	state->req->async.private = c;
	state->req->async.fn = fetchfile_composite_handler;

	c->state = SMBCLI_REQUEST_SEND;
	state->stage = FETCHFILE_CONNECT;
	c->event_ctx = talloc_reference(c, state->req->event_ctx);
	c->private = state;

	return c;
 failed:
	talloc_free(c);
	return NULL;
}

NTSTATUS smb_composite_fetchfile_recv(struct composite_context *c,
				      TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;

	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status)) {
		struct fetchfile_state *state = talloc_get_type(c->private, struct fetchfile_state);
		talloc_steal(mem_ctx, state->io->out.data);
	}

	talloc_free(c);
	return status;
}

NTSTATUS smb_composite_fetchfile(struct smb_composite_fetchfile *io,
				 TALLOC_CTX *mem_ctx)
{
	struct composite_context *c = smb_composite_fetchfile_send(io, NULL);
	return smb_composite_fetchfile_recv(c, mem_ctx);
}
