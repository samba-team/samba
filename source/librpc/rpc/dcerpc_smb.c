/* 
   Unix SMB/CIFS implementation.

   dcerpc over SMB transport

   Copyright (C) Tim Potter 2003
   Copyright (C) Andrew Tridgell 2003
   
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

#include "includes.h"
#include "libcli/raw/libcliraw.h"

/* transport private information used by SMB pipe transport */
struct smb_private {
	uint16_t fnum;
	struct smbcli_tree *tree;
};


/*
  tell the dcerpc layer that the transport is dead
*/
static void pipe_dead(struct dcerpc_pipe *p, NTSTATUS status)
{
	p->transport.recv_data(p, NULL, status);
}


/* 
   this holds the state of an in-flight call
*/
struct smb_read_state {
	struct dcerpc_pipe *p;
	struct smbcli_request *req;
	size_t received;
	DATA_BLOB data;
	union smb_read *io;
};

/*
  called when a read request has completed
*/
static void smb_read_callback(struct smbcli_request *req)
{
	struct smb_private *smb;
	struct smb_read_state *state;
	union smb_read *io;
	uint16_t frag_length;
	NTSTATUS status;

	state = req->async.private;
	smb = state->p->transport.private;
	io = state->io;

	status = smb_raw_read_recv(state->req, io);
	if (NT_STATUS_IS_ERR(status)) {
		pipe_dead(state->p, status);
		talloc_free(state);
		return;
	}

	state->received += io->readx.out.nread;

	if (state->received < 16) {
		DEBUG(0,("dcerpc_smb: short packet (length %d) in read callback!\n",
			 state->received));
		pipe_dead(state->p, NT_STATUS_INFO_LENGTH_MISMATCH);
		talloc_free(state);
		return;
	}

	frag_length = dcerpc_get_frag_length(&state->data);

	if (frag_length <= state->received) {
		state->data.length = state->received;
		state->p->transport.recv_data(state->p, &state->data, NT_STATUS_OK);
		talloc_free(state);
		return;
	}

	/* initiate another read request, as we only got part of a fragment */
	state->data.data = talloc_realloc(state, state->data.data, frag_length);

	io->readx.in.mincnt = MIN(state->p->srv_max_xmit_frag, 
				  frag_length - state->received);
	io->readx.in.maxcnt = io->readx.in.mincnt;
	io->readx.out.data = state->data.data + state->received;

	state->req = smb_raw_read_send(smb->tree, io);
	if (state->req == NULL) {
		pipe_dead(state->p, NT_STATUS_NO_MEMORY);
		talloc_free(state);
		return;
	}

	state->req->async.fn = smb_read_callback;
	state->req->async.private = state;
}

/*
  trigger a read request from the server, possibly with some initial
  data in the read buffer
*/
static NTSTATUS send_read_request_continue(struct dcerpc_pipe *p, DATA_BLOB *blob)
{
	struct smb_private *smb = p->transport.private;
	union smb_read *io;
	struct smb_read_state *state;
	struct smbcli_request *req;

	state = talloc_p(smb, struct smb_read_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->p = p;
	if (blob == NULL) {
		state->received = 0;
		state->data = data_blob_talloc(state, NULL, 0x2000);
	} else {
		uint32_t frag_length = blob->length>=16?
			dcerpc_get_frag_length(blob):0x2000;
		state->received = blob->length;
		state->data = data_blob_talloc(state, NULL, frag_length);
		if (!state->data.data) {
			talloc_free(state);
			return NT_STATUS_NO_MEMORY;
		}
		memcpy(state->data.data, blob->data, blob->length);
	}

	state->io = talloc_p(state, union smb_read);

	io = state->io;
	io->generic.level = RAW_READ_READX;
	io->readx.in.fnum = smb->fnum;
	io->readx.in.mincnt = state->data.length - state->received;
	io->readx.in.maxcnt = io->readx.in.mincnt;
	io->readx.in.offset = 0;
	io->readx.in.remaining = 0;
	io->readx.out.data = state->data.data + state->received;
	req = smb_raw_read_send(smb->tree, io);
	if (req == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	req->async.fn = smb_read_callback;
	req->async.private = state;

	state->req = req;

	return NT_STATUS_OK;
}


/*
  trigger a read request from the server
*/
static NTSTATUS send_read_request(struct dcerpc_pipe *p)
{
	return send_read_request_continue(p, NULL);
}

/* 
   this holds the state of an in-flight trans call
*/
struct smb_trans_state {
	struct dcerpc_pipe *p;
	struct smbcli_request *req;
	struct smb_trans2 *trans;
};

/*
  called when a trans request has completed
*/
static void smb_trans_callback(struct smbcli_request *req)
{
	struct smb_trans_state *state = req->async.private;
	struct dcerpc_pipe *p = state->p;
	NTSTATUS status;

	status = smb_raw_trans_recv(req, state, state->trans);

	if (NT_STATUS_IS_ERR(status)) {
		pipe_dead(p, status);
		return;
	}

	if (!NT_STATUS_EQUAL(status, STATUS_BUFFER_OVERFLOW)) {
		p->transport.recv_data(p, &state->trans->out.data, NT_STATUS_OK);
		talloc_free(state);
		return;
	}

	/* there is more to receive - setup a readx */
	send_read_request_continue(p, &state->trans->out.data);
	talloc_free(state);
}

/*
  send a SMBtrans style request
*/
static NTSTATUS smb_send_trans_request(struct dcerpc_pipe *p, DATA_BLOB *blob)
{
        struct smb_private *smb = p->transport.private;
        struct smb_trans2 *trans;
        uint16 setup[2];
	struct smb_trans_state *state;

	state = talloc_p(smb, struct smb_trans_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->p = p;
	state->trans = talloc_p(state, struct smb_trans2);
	trans = state->trans;

        trans->in.data = *blob;
        trans->in.params = data_blob(NULL, 0);
        
        setup[0] = TRANSACT_DCERPCCMD;
        setup[1] = smb->fnum;

        trans->in.max_param = 0;
        trans->in.max_data = smb_raw_max_trans_data(smb->tree, 0);
        trans->in.max_setup = 0;
        trans->in.setup_count = 2;
        trans->in.flags = 0;
        trans->in.timeout = 0;
        trans->in.setup = setup;
        trans->in.trans_name = "\\PIPE\\";

        state->req = smb_raw_trans_send(smb->tree, trans);
	if (state->req == NULL) {
		talloc_free(state);
		return NT_STATUS_NO_MEMORY;
	}

	state->req->async.fn = smb_trans_callback;
	state->req->async.private = state;

        return NT_STATUS_OK;
}

/*
  called when a write request has completed
*/
static void smb_write_callback(struct smbcli_request *req)
{
	struct dcerpc_pipe *p = req->async.private;

	if (!NT_STATUS_IS_OK(req->status)) {
		DEBUG(0,("dcerpc_smb: write callback error\n"));
		pipe_dead(p, req->status);
	}

	smbcli_request_destroy(req);
}

/* 
   send a packet to the server
*/
static NTSTATUS smb_send_request(struct dcerpc_pipe *p, DATA_BLOB *blob, BOOL trigger_read)
{
	struct smb_private *smb = p->transport.private;
	union smb_write io;
	struct smbcli_request *req;

	if (trigger_read) {
		return smb_send_trans_request(p, blob);
	}

	io.generic.level = RAW_WRITE_WRITEX;
	io.writex.in.fnum = smb->fnum;
	io.writex.in.offset = 0;
	io.writex.in.wmode = PIPE_START_MESSAGE;
	io.writex.in.remaining = blob->length;
	io.writex.in.count = blob->length;
	io.writex.in.data = blob->data;

	req = smb_raw_write_send(smb->tree, &io);
	if (req == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	req->async.fn = smb_write_callback;
	req->async.private = p;

	if (trigger_read) {
		send_read_request(p);
	}

	return NT_STATUS_OK;
}

/* 
   return the event context for the pipe, so the caller can wait
   for events asynchronously
*/
static struct event_context *smb_event_context(struct dcerpc_pipe *p)
{
	struct smb_private *smb = p->transport.private;

	return smb->tree->session->transport->event.ctx;
}


/* 
   shutdown SMB pipe connection
*/
static NTSTATUS smb_shutdown_pipe(struct dcerpc_pipe *p)
{
	struct smb_private *smb = p->transport.private;
	union smb_close c;

	/* maybe we're still starting up */
	if (!smb) return NT_STATUS_OK;

	c.close.level = RAW_CLOSE_CLOSE;
	c.close.in.fnum = smb->fnum;
	c.close.in.write_time = 0;
	smb_raw_close(smb->tree, &c);

	talloc_free(smb);

	return NT_STATUS_OK;
}

/*
  return SMB server name
*/
static const char *smb_peer_name(struct dcerpc_pipe *p)
{
	struct smb_private *smb = p->transport.private;
	return smb->tree->session->transport->called.name;
}

/*
  fetch the user session key 
*/
static NTSTATUS smb_session_key(struct dcerpc_pipe *p, DATA_BLOB *session_key)
{
	struct smb_private *smb = p->transport.private;

	if (smb->tree->session->user_session_key.data) {
		*session_key = smb->tree->session->user_session_key;
		return NT_STATUS_OK;
	}
	return NT_STATUS_NO_USER_SESSION_KEY;
}

/* 
   open a rpc connection to a named pipe 
*/
NTSTATUS dcerpc_pipe_open_smb(struct dcerpc_pipe **p, 
			      struct smbcli_tree *tree,
			      const char *pipe_name)
{
	struct smb_private *smb;
        NTSTATUS status;
	union smb_open io;

	io.ntcreatex.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = 
		STD_RIGHT_READ_CONTROL_ACCESS | 
		SA_RIGHT_FILE_WRITE_ATTRIBUTES | 
		SA_RIGHT_FILE_WRITE_EA | 
		GENERIC_RIGHTS_FILE_READ |
		GENERIC_RIGHTS_FILE_WRITE;
	io.ntcreatex.in.file_attr = 0;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_IMPERSONATION;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = pipe_name;

	status = smb_raw_open(tree, tree, &io);

	if (!NT_STATUS_IS_OK(status)) {
                return status;
        }

        if (!(*p = dcerpc_pipe_init())) {
                return NT_STATUS_NO_MEMORY;
	}
 
	/*
	  fill in the transport methods
	*/
	(*p)->transport.transport = NCACN_NP;
	(*p)->transport.private = NULL;
	(*p)->transport.shutdown_pipe = smb_shutdown_pipe;
	(*p)->transport.peer_name = smb_peer_name;

	(*p)->transport.send_request = smb_send_request;
	(*p)->transport.send_read = send_read_request;
	(*p)->transport.event_context = smb_event_context;
	(*p)->transport.recv_data = NULL;
	
	/* Over-ride the default session key with the SMB session key */
	(*p)->security_state.session_key = smb_session_key;

	smb = talloc_p((*p), struct smb_private);
	if (!smb) {
		dcerpc_pipe_close(*p);
		return NT_STATUS_NO_MEMORY;
	}

	smb->fnum = io.ntcreatex.out.fnum;
	smb->tree = tree;

	(*p)->transport.private = smb;

        return NT_STATUS_OK;
}

/*
  return the SMB tree used for a dcerpc over SMB pipe
*/
struct smbcli_tree *dcerpc_smb_tree(struct dcerpc_pipe *p)
{
	struct smb_private *smb = p->transport.private;

	if (p->transport.transport != NCACN_NP) {
		return NULL;
	}

	return smb->tree;
}
