/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Tridgell 2005
   
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
  a composite API for making a full SMB connection
*/

#include "includes.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"

/* the stages of this call */
enum connect_stage {CONNECT_SOCKET, 
		    CONNECT_SESSION_REQUEST, 
		    CONNECT_NEGPROT,
		    CONNECT_SESSION_SETUP,
		    CONNECT_TCON};

struct connect_state {
	struct smbcli_socket *sock;
	struct smbcli_transport *transport;
	struct smbcli_session *session;
};


static void request_handler(struct smbcli_request *);
static void composite_handler(struct smbcli_composite *);

/*
  setup a negprot send 
*/
static NTSTATUS connect_send_negprot(struct smbcli_composite *c, 
				     struct smb_composite_connect *io)
{
	struct connect_state *state = c->private;
	struct smbcli_request *req;

	req = smb_raw_negotiate_send(state->transport, lp_maxprotocol());
	NT_STATUS_HAVE_NO_MEMORY(req);

	req->async.fn = request_handler;
	req->async.private = c;
	c->stage = CONNECT_NEGPROT;
	c->req = req;
	
	return NT_STATUS_OK;
}


/*
  a tree connect request has competed
*/
static NTSTATUS connect_tcon(struct smbcli_composite *c, 
			     struct smb_composite_connect *io)
{
	struct smbcli_request *req = c->req;
	union smb_tcon *io_tcon = c->req_parms;
	NTSTATUS status;

	status = smb_tree_connect_recv(req, c, io_tcon);
	NT_STATUS_NOT_OK_RETURN(status);

	io->out.tree->tid = io_tcon->tconx.out.tid;
	if (io_tcon->tconx.out.dev_type) {
		io->out.tree->device = talloc_strdup(io->out.tree, 
						     io_tcon->tconx.out.dev_type);
	}
	if (io_tcon->tconx.out.fs_type) {
		io->out.tree->fs_type = talloc_strdup(io->out.tree, 
						      io_tcon->tconx.out.fs_type);
	}

	/* all done! */
	c->state = SMBCLI_REQUEST_DONE;
	if (c->async.fn) {
		c->async.fn(c);
	}

	return NT_STATUS_OK;
}


/*
  a session setup request has competed
*/
static NTSTATUS connect_session_setup(struct smbcli_composite *c, 
				      struct smb_composite_connect *io)
{
	struct connect_state *state = c->private;
	struct smbcli_request *req = c->req;
	union smb_sesssetup *io_setup = c->req_parms;
	union smb_tcon *io_tcon;
	NTSTATUS status;

	status = smb_raw_session_setup_recv(req, c, io_setup);
	NT_STATUS_NOT_OK_RETURN(status);
	
	state->session->vuid = io_setup->nt1.out.vuid;
	
	/* setup for a tconx */
	io->out.tree = smbcli_tree_init(state->session);
	NT_STATUS_HAVE_NO_MEMORY(io->out.tree);

	io_tcon = talloc(c, union smb_tcon);
	NT_STATUS_HAVE_NO_MEMORY(io_tcon);

	/* connect to a share using a tree connect */
	io_tcon->generic.level = RAW_TCON_TCONX;
	io_tcon->tconx.in.flags = 0;
	io_tcon->tconx.in.password = data_blob(NULL, 0);	
	
	io_tcon->tconx.in.path = talloc_asprintf(io_tcon, 
						 "\\\\%s\\%s", 
						 io->in.called_name, 
						 io->in.service);
	NT_STATUS_HAVE_NO_MEMORY(io_tcon->tconx.in.path);
	if (!io->in.service_type) {
		io_tcon->tconx.in.device = "?????";
	} else {
		io_tcon->tconx.in.device = io->in.service_type;
	}

	req = smb_tree_connect_send(io->out.tree, io_tcon);
	NT_STATUS_HAVE_NO_MEMORY(req);

	req->async.fn = request_handler;
	req->async.private = c;
	c->req_parms = io_tcon;
	c->req = req;
	c->stage = CONNECT_TCON;

	return NT_STATUS_OK;
}

/*
  form an encrypted lanman password from a plaintext password
  and the server supplied challenge
*/
static DATA_BLOB lanman_blob(const char *pass, DATA_BLOB challenge)
{
	DATA_BLOB blob = data_blob(NULL, 24);
	SMBencrypt(pass, challenge.data, blob.data);
	return blob;
}

/*
  form an encrypted NT password from a plaintext password
  and the server supplied challenge
*/
static DATA_BLOB nt_blob(const char *pass, DATA_BLOB challenge)
{
	DATA_BLOB blob = data_blob(NULL, 24);
	SMBNTencrypt(pass, challenge.data, blob.data);
	return blob;
}

/*
  a negprot request has competed
*/
static NTSTATUS connect_negprot(struct smbcli_composite *c, 
				struct smb_composite_connect *io)
{
	struct connect_state *state = c->private;
	struct smbcli_request *req = c->req;
	NTSTATUS status;
	union smb_sesssetup *io_setup;

	status = smb_raw_negotiate_recv(req);
	NT_STATUS_NOT_OK_RETURN(status);

	/* next step is a session setup */
	state->session = smbcli_session_init(state->transport);
	NT_STATUS_HAVE_NO_MEMORY(state->session);

	/* get rid of the extra reference to the transport */
	talloc_free(state->transport);

	io_setup = talloc(c, union smb_sesssetup);
	NT_STATUS_HAVE_NO_MEMORY(io_setup);

	/* prepare a session setup to establish a security context */
	io_setup->nt1.level = RAW_SESSSETUP_NT1;
	io_setup->nt1.in.bufsize = state->session->transport->options.max_xmit;
	io_setup->nt1.in.mpx_max = state->session->transport->options.max_mux;
	io_setup->nt1.in.vc_num = 1;
	io_setup->nt1.in.sesskey = state->transport->negotiate.sesskey;
	io_setup->nt1.in.capabilities = state->transport->negotiate.capabilities;
	io_setup->nt1.in.domain = io->in.domain;
	io_setup->nt1.in.user = io->in.user;
	io_setup->nt1.in.os = "Unix";
	io_setup->nt1.in.lanman = "Samba";

	if (!io->in.password) {
		io_setup->nt1.in.password1 = data_blob(NULL, 0);
		io_setup->nt1.in.password2 = data_blob(NULL, 0);
	} else if (state->session->transport->negotiate.sec_mode & 
		   NEGOTIATE_SECURITY_CHALLENGE_RESPONSE) {
		io_setup->nt1.in.password1 = lanman_blob(io->in.password, 
							 state->transport->negotiate.secblob);
		io_setup->nt1.in.password2 = nt_blob(io->in.password, 
						     state->transport->negotiate.secblob);
		smb_session_use_nt1_session_keys(state->session, io->in.password, &io_setup->nt1.in.password2);

	} else {
		io_setup->nt1.in.password1 = data_blob(io->in.password, 
						       strlen(io->in.password));
		io_setup->nt1.in.password2 = data_blob(NULL, 0);
	}

	req = smb_raw_session_setup_send(state->session, io_setup);
	NT_STATUS_HAVE_NO_MEMORY(req);

	req->async.fn = request_handler;
	req->async.private = c;
	c->req_parms = io_setup;
	c->req = req;
	c->stage = CONNECT_SESSION_SETUP;
	
	return NT_STATUS_OK;
}


/*
  a session request operation has competed
*/
static NTSTATUS connect_session_request(struct smbcli_composite *c, 
					struct smb_composite_connect *io)
{
	struct smbcli_request *req = c->req;
	NTSTATUS status;

	status = smbcli_transport_connect_recv(req);
	NT_STATUS_NOT_OK_RETURN(status);

	/* next step is a negprot */
	return connect_send_negprot(c, io);
}

/*
  a socket connection operation has competed
*/
static NTSTATUS connect_socket(struct smbcli_composite *c, 
			       struct smb_composite_connect *io)
{
	struct connect_state *state = c->private;
	NTSTATUS status;
	struct smbcli_request *req;
	struct nmb_name calling, called;

	status = smbcli_sock_connect_recv(c->req);
	NT_STATUS_NOT_OK_RETURN(status);

	/* the socket is up - we can initialise the smbcli transport layer */
	state->transport = smbcli_transport_init(state->sock);
	NT_STATUS_HAVE_NO_MEMORY(state->transport);

	/* we have a connected socket - next step is a session
	   request, if needed. Port 445 doesn't need it, so it goes
	   straight to the negprot */
	if (state->sock->port == 445) {
		return connect_send_negprot(c, io);
	}

	make_nmb_name(&calling, io->in.calling_name, 0x0);
	choose_called_name(&called, io->in.called_name, 0x20);

	req = smbcli_transport_connect_send(state->transport, &calling, &called);
	NT_STATUS_HAVE_NO_MEMORY(req);

	req->async.fn = request_handler;
	req->async.private = c;
	c->stage = CONNECT_SESSION_REQUEST;
	c->req = req;

	return NT_STATUS_OK;
}



/*
  handle and dispatch state transitions
*/
static void state_handler(struct smbcli_composite *c)
{
	struct smb_composite_connect *io = c->composite_parms;
	
	switch (c->stage) {
	case CONNECT_SOCKET:
		c->status = connect_socket(c, io);
		break;
	case CONNECT_SESSION_REQUEST:
		c->status = connect_session_request(c, io);
		break;
	case CONNECT_NEGPROT:
		c->status = connect_negprot(c, io);
		break;
	case CONNECT_SESSION_SETUP:
		c->status = connect_session_setup(c, io);
		break;
	case CONNECT_TCON:
		c->status = connect_tcon(c, io);
		break;
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = SMBCLI_REQUEST_ERROR;
		if (c->async.fn) {
			c->async.fn(c);
		}
	}
}


/*
  handler for completion of a smbcli_request sub-request
*/
static void request_handler(struct smbcli_request *req)
{
	struct smbcli_composite *c = req->async.private;
	return state_handler(c);
}

/*
  handler for completion of a smbcli_composite sub-request
*/
static void composite_handler(struct smbcli_composite *req)
{
	struct smbcli_composite *c = req->async.private;
	return state_handler(c);
}

/*
  a function to establish a smbcli_tree from scratch
*/
struct smbcli_composite *smb_composite_connect_send(struct smb_composite_connect *io)
{
	struct smbcli_composite *c, *req;
	struct connect_state *state;

	c = talloc_zero(NULL, struct smbcli_composite);
	if (c == NULL) goto failed;

	state = talloc(c, struct connect_state);
	if (state == NULL) goto failed;

	state->sock = smbcli_sock_init(state);
	if (state->sock == NULL) goto failed;

	c->state = SMBCLI_REQUEST_SEND;
	c->composite_parms = io;
	c->stage = CONNECT_SOCKET;
	c->event_ctx = state->sock->event.ctx;
	c->private = state;

	req = smbcli_sock_connect_send(state->sock, io->in.dest_host, io->in.port);
	if (req == NULL) goto failed;

	req->async.private = c;
	req->async.fn = composite_handler;
	c->req = req;

	return c;
failed:
	talloc_free(c);
	return NULL;
}

/*
  recv half of async composite connect code
*/
NTSTATUS smb_composite_connect_recv(struct smbcli_composite *c, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;

	status = smb_composite_wait(c);

	if (NT_STATUS_IS_OK(status)) {
		struct smb_composite_connect *io = c->composite_parms;
		talloc_steal(mem_ctx, io->out.tree);
	}

	talloc_free(c);
	return status;
}

/*
  sync version of smb_composite_connect 
*/
NTSTATUS smb_composite_connect(struct smb_composite_connect *io, TALLOC_CTX *mem_ctx)
{
	struct smbcli_composite *c = smb_composite_connect_send(io);
	return smb_composite_connect_recv(c, mem_ctx);
}
