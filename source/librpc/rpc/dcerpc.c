/* 
   Unix SMB/CIFS implementation.
   raw dcerpc operations

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
#include "librpc/gen_ndr/ndr_epmapper.h"

/* initialise a dcerpc pipe. */
struct dcerpc_pipe *dcerpc_pipe_init(void)
{
	struct dcerpc_pipe *p;

	p = talloc_p(NULL, struct dcerpc_pipe);
	if (!p) {
		return NULL;
	}

	p->reference_count = 0;
	p->call_id = 1;
	p->security_state.auth_info = NULL;
	p->security_state.session_key = dcerpc_generic_session_key;
	p->security_state.generic_state = NULL;
	p->binding_string = NULL;
	p->flags = 0;
	p->srv_max_xmit_frag = 0;
	p->srv_max_recv_frag = 0;
	p->last_fault_code = 0;
	p->pending = NULL;

	return p;
}

/* 
   choose the next call id to use
*/
static uint32_t next_call_id(struct dcerpc_pipe *p)
{
	p->call_id++;
	if (p->call_id == 0) {
		p->call_id++;
	}
	return p->call_id;
}

/* close down a dcerpc over SMB pipe */
void dcerpc_pipe_close(struct dcerpc_pipe *p)
{
	if (!p) return;
	p->reference_count--;
	if (p->reference_count <= 0) {
		if (p->security_state.generic_state) {
			gensec_end(&p->security_state.generic_state);
		}
		p->transport.shutdown_pipe(p);
		talloc_free(p);
	}
}

/* we need to be able to get/set the fragment length without doing a full
   decode */
void dcerpc_set_frag_length(DATA_BLOB *blob, uint16_t v)
{
	if (CVAL(blob->data,DCERPC_DREP_OFFSET) & DCERPC_DREP_LE) {
		SSVAL(blob->data, DCERPC_FRAG_LEN_OFFSET, v);
	} else {
		RSSVAL(blob->data, DCERPC_FRAG_LEN_OFFSET, v);
	}
}

uint16_t dcerpc_get_frag_length(const DATA_BLOB *blob)
{
	if (CVAL(blob->data,DCERPC_DREP_OFFSET) & DCERPC_DREP_LE) {
		return SVAL(blob->data, DCERPC_FRAG_LEN_OFFSET);
	} else {
		return RSVAL(blob->data, DCERPC_FRAG_LEN_OFFSET);
	}
}

void dcerpc_set_auth_length(DATA_BLOB *blob, uint16_t v)
{
	if (CVAL(blob->data,DCERPC_DREP_OFFSET) & DCERPC_DREP_LE) {
		SSVAL(blob->data, DCERPC_AUTH_LEN_OFFSET, v);
	} else {
		RSSVAL(blob->data, DCERPC_AUTH_LEN_OFFSET, v);
	}
}


/*
  setup for a ndr pull, also setting up any flags from the binding string
*/
static struct ndr_pull *ndr_pull_init_flags(struct dcerpc_pipe *p, DATA_BLOB *blob, TALLOC_CTX *mem_ctx)
{
	struct ndr_pull *ndr = ndr_pull_init_blob(blob, mem_ctx);

	if (ndr == NULL) return ndr;

	if (p->flags & DCERPC_DEBUG_PAD_CHECK) {
		ndr->flags |= LIBNDR_FLAG_PAD_CHECK;
	}

	if (p->flags & DCERPC_NDR_REF_ALLOC) {
		ndr->flags |= LIBNDR_FLAG_REF_ALLOC;
	}

	return ndr;
}

/* 
   parse a data blob into a dcerpc_packet structure. This handles both
   input and output packets
*/
static NTSTATUS dcerpc_pull(struct dcerpc_pipe *p, DATA_BLOB *blob, TALLOC_CTX *mem_ctx, 
			    struct dcerpc_packet *pkt)
{
	struct ndr_pull *ndr;

	ndr = ndr_pull_init_flags(p, blob, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}

	if (! (CVAL(blob->data, DCERPC_DREP_OFFSET) & DCERPC_DREP_LE)) {
		ndr->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	return ndr_pull_dcerpc_packet(ndr, NDR_SCALARS|NDR_BUFFERS, pkt);
}

/*
  generate a CONNECT level verifier
*/
static NTSTATUS dcerpc_connect_verifier(TALLOC_CTX *mem_ctx, DATA_BLOB *blob)
{
	*blob = data_blob_talloc(mem_ctx, NULL, 16);
	if (blob->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	SIVAL(blob->data, 0, 1);
	memset(blob->data+4, 0, 12);
	return NT_STATUS_OK;
}

/*
  generate a CONNECT level verifier
*/
static NTSTATUS dcerpc_check_connect_verifier(DATA_BLOB *blob)
{
	if (blob->length != 16 ||
	    IVAL(blob->data, 0) != 1) {
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

/* 
   parse a possibly signed blob into a dcerpc request packet structure
*/
static NTSTATUS dcerpc_pull_request_sign(struct dcerpc_pipe *p, 
					 DATA_BLOB *blob, TALLOC_CTX *mem_ctx, 
					 struct dcerpc_packet *pkt)
{
	struct ndr_pull *ndr;
	NTSTATUS status;
	struct dcerpc_auth auth;
	DATA_BLOB auth_blob;

	/* non-signed packets are simpler */
	if (!p->security_state.auth_info || 
	    !p->security_state.generic_state) {
		return dcerpc_pull(p, blob, mem_ctx, pkt);
	}

	ndr = ndr_pull_init_flags(p, blob, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}

	if (! (CVAL(blob->data, DCERPC_DREP_OFFSET) & DCERPC_DREP_LE)) {
		ndr->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	/* pull the basic packet */
	status = ndr_pull_dcerpc_packet(ndr, NDR_SCALARS|NDR_BUFFERS, pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (pkt->ptype != DCERPC_PKT_RESPONSE) {
		return status;
	}

	if (pkt->auth_length == 0 &&
	    p->security_state.auth_info->auth_level == DCERPC_AUTH_LEVEL_CONNECT) {
		return NT_STATUS_OK;
	}

	auth_blob.length = 8 + pkt->auth_length;

	/* check for a valid length */
	if (pkt->u.response.stub_and_verifier.length < auth_blob.length) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}

	auth_blob.data = 
		pkt->u.response.stub_and_verifier.data + 
		pkt->u.response.stub_and_verifier.length - auth_blob.length;
	pkt->u.response.stub_and_verifier.length -= auth_blob.length;

	/* pull the auth structure */
	ndr = ndr_pull_init_flags(p, &auth_blob, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}

	if (! (CVAL(blob->data, DCERPC_DREP_OFFSET) & DCERPC_DREP_LE)) {
		ndr->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	status = ndr_pull_dcerpc_auth(ndr, NDR_SCALARS|NDR_BUFFERS, &auth);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	
	/* check signature or unseal the packet */
	switch (p->security_state.auth_info->auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		status = gensec_unseal_packet(p->security_state.generic_state, 
					      mem_ctx, 
					      blob->data + DCERPC_REQUEST_LENGTH,
					      pkt->u.response.stub_and_verifier.length, 
					      blob->data,
					      blob->length - auth.credentials.length,
					      &auth.credentials);
		memcpy(pkt->u.response.stub_and_verifier.data,
		       blob->data + DCERPC_REQUEST_LENGTH,
		       pkt->u.response.stub_and_verifier.length);
		break;
		
	case DCERPC_AUTH_LEVEL_INTEGRITY:
		status = gensec_check_packet(p->security_state.generic_state, 
					     mem_ctx, 
					     pkt->u.response.stub_and_verifier.data, 
					     pkt->u.response.stub_and_verifier.length, 
					     blob->data,
					     blob->length - auth.credentials.length,
					     &auth.credentials);
		break;

	case DCERPC_AUTH_LEVEL_CONNECT:
		status = dcerpc_check_connect_verifier(&auth.credentials);
		break;

	case DCERPC_AUTH_LEVEL_NONE:
		break;

	default:
		status = NT_STATUS_INVALID_LEVEL;
		break;
	}
	
	/* remove the indicated amount of paddiing */
	if (pkt->u.response.stub_and_verifier.length < auth.auth_pad_length) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}
	pkt->u.response.stub_and_verifier.length -= auth.auth_pad_length;

	return status;
}


/* 
   push a dcerpc request packet into a blob, possibly signing it.
*/
static NTSTATUS dcerpc_push_request_sign(struct dcerpc_pipe *p, 
					 DATA_BLOB *blob, TALLOC_CTX *mem_ctx, 
					 struct dcerpc_packet *pkt)
{
	NTSTATUS status;
	struct ndr_push *ndr;
	DATA_BLOB creds2;

	/* non-signed packets are simpler */
	if (!p->security_state.auth_info || 
	    !p->security_state.generic_state) {
		return dcerpc_push_auth(blob, mem_ctx, pkt, p->security_state.auth_info);
	}

	ndr = ndr_push_init_ctx(mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}

	if (p->flags & DCERPC_PUSH_BIGENDIAN) {
		ndr->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	status = ndr_push_dcerpc_packet(ndr, NDR_SCALARS|NDR_BUFFERS, pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* pad to 16 byte multiple in the payload portion of the
	   packet. This matches what w2k3 does */
	p->security_state.auth_info->auth_pad_length = 
		(16 - (pkt->u.request.stub_and_verifier.length & 15)) & 15;
	ndr_push_zero(ndr, p->security_state.auth_info->auth_pad_length);

	/* sign or seal the packet */
	switch (p->security_state.auth_info->auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
	case DCERPC_AUTH_LEVEL_INTEGRITY:
		p->security_state.auth_info->credentials
			= data_blob_talloc(mem_ctx, NULL, gensec_sig_size(p->security_state.generic_state));
		data_blob_clear(&p->security_state.auth_info->credentials);
		break;

	case DCERPC_AUTH_LEVEL_CONNECT:
		status = dcerpc_connect_verifier(mem_ctx, &p->security_state.auth_info->credentials);
		break;
		
	case DCERPC_AUTH_LEVEL_NONE:
		p->security_state.auth_info->credentials = data_blob(NULL, 0);
		break;
		
	default:
		status = NT_STATUS_INVALID_LEVEL;
		break;
	}
	
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}	

	/* add the auth verifier */
	status = ndr_push_dcerpc_auth(ndr, NDR_SCALARS|NDR_BUFFERS, p->security_state.auth_info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* extract the whole packet as a blob */
	*blob = ndr_push_blob(ndr);

	/* fill in the fragment length and auth_length, we can't fill
	   in these earlier as we don't know the signature length (it
	   could be variable length) */
	dcerpc_set_frag_length(blob, blob->length);
	dcerpc_set_auth_length(blob, p->security_state.auth_info->credentials.length);

	/* sign or seal the packet */
	switch (p->security_state.auth_info->auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		status = gensec_seal_packet(p->security_state.generic_state, 
					    mem_ctx, 
					    blob->data + DCERPC_REQUEST_LENGTH, 
					    pkt->u.request.stub_and_verifier.length+p->security_state.auth_info->auth_pad_length,
					    blob->data,
					    blob->length - 
					    p->security_state.auth_info->credentials.length,
					    &creds2);
		memcpy(blob->data + blob->length - creds2.length, creds2.data, creds2.length);
		break;

	case DCERPC_AUTH_LEVEL_INTEGRITY:
		status = gensec_sign_packet(p->security_state.generic_state, 
					    mem_ctx, 
					    blob->data + DCERPC_REQUEST_LENGTH, 
					    pkt->u.request.stub_and_verifier.length+p->security_state.auth_info->auth_pad_length,
					    blob->data,
					    blob->length - 
					    p->security_state.auth_info->credentials.length,
					    &creds2);
		memcpy(blob->data + blob->length - creds2.length, creds2.data, creds2.length);
		break;

	case DCERPC_AUTH_LEVEL_CONNECT:
		break;

	case DCERPC_AUTH_LEVEL_NONE:
		p->security_state.auth_info->credentials = data_blob(NULL, 0);
		break;

	default:
		status = NT_STATUS_INVALID_LEVEL;
		break;
	}

	data_blob_free(&p->security_state.auth_info->credentials);

	return NT_STATUS_OK;
}


/* 
   fill in the fixed values in a dcerpc header 
*/
static void init_dcerpc_hdr(struct dcerpc_pipe *p, struct dcerpc_packet *pkt)
{
	pkt->rpc_vers = 5;
	pkt->rpc_vers_minor = 0;
	if (p->flags & DCERPC_PUSH_BIGENDIAN) {
		pkt->drep[0] = 0;
	} else {
		pkt->drep[0] = DCERPC_DREP_LE;
	}
	pkt->drep[1] = 0;
	pkt->drep[2] = 0;
	pkt->drep[3] = 0;
}

/*
  hold the state of pending full requests
*/
struct full_request_state {
	DATA_BLOB *reply_blob;
	NTSTATUS status;
};

/*
  receive a reply to a full request
 */
static void full_request_recv(struct dcerpc_pipe *p, DATA_BLOB *blob, 
			      NTSTATUS status)
{
	struct full_request_state *state = p->full_request_private;

	if (!NT_STATUS_IS_OK(status)) {
		state->status = status;
		return;
	}
	state->reply_blob[0] = data_blob_talloc(state, blob->data, blob->length);
	state->reply_blob = NULL;
}

/*
  perform a single pdu synchronous request - used for the bind code
  this cannot be mixed with normal async requests
*/
static NTSTATUS full_request(struct dcerpc_pipe *p, 
			     TALLOC_CTX *mem_ctx,
			     DATA_BLOB *request_blob,
			     DATA_BLOB *reply_blob)
{
	struct full_request_state *state = talloc_p(mem_ctx, struct full_request_state);
	NTSTATUS status;

	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->reply_blob = reply_blob;
	state->status = NT_STATUS_OK;

	p->transport.recv_data = full_request_recv;
	p->full_request_private = state;

	status = p->transport.send_request(p, request_blob, True);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	while (NT_STATUS_IS_OK(state->status) && state->reply_blob) {
		struct event_context *ctx = p->transport.event_context(p);
		if (event_loop_once(ctx) != 0) {
			return NT_STATUS_CONNECTION_DISCONNECTED;
		}
	}

	return state->status;
}


/* 
   perform a bind using the given syntax 

   the auth_info structure is updated with the reply authentication info
   on success
*/
NTSTATUS dcerpc_bind(struct dcerpc_pipe *p, 
		     TALLOC_CTX *mem_ctx,
		     const struct dcerpc_syntax_id *syntax,
		     const struct dcerpc_syntax_id *transfer_syntax)
{
	struct dcerpc_packet pkt;
	NTSTATUS status;
	DATA_BLOB blob;

	p->syntax = *syntax;
	p->transfer_syntax = *transfer_syntax;

	init_dcerpc_hdr(p, &pkt);

	pkt.ptype = DCERPC_PKT_BIND;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.call_id = p->call_id;
	pkt.auth_length = 0;

	pkt.u.bind.max_xmit_frag = 5840;
	pkt.u.bind.max_recv_frag = 5840;
	pkt.u.bind.assoc_group_id = 0;
	pkt.u.bind.num_contexts = 1;
	pkt.u.bind.ctx_list = talloc(mem_ctx, sizeof(pkt.u.bind.ctx_list[0]));
	if (!pkt.u.bind.ctx_list) {
		return NT_STATUS_NO_MEMORY;
	}
	pkt.u.bind.ctx_list[0].context_id = 0;
	pkt.u.bind.ctx_list[0].num_transfer_syntaxes = 1;
	pkt.u.bind.ctx_list[0].abstract_syntax = p->syntax;
	pkt.u.bind.ctx_list[0].transfer_syntaxes = &p->transfer_syntax;
	pkt.u.bind.auth_info = data_blob(NULL, 0);

	/* construct the NDR form of the packet */
	status = dcerpc_push_auth(&blob, mem_ctx, &pkt, p->security_state.auth_info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* send it on its way */
	status = full_request(p, mem_ctx, &blob, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* unmarshall the NDR */
	status = dcerpc_pull(p, &blob, mem_ctx, &pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (pkt.ptype == DCERPC_PKT_BIND_NAK) {
		DEBUG(2,("dcerpc: bind_nak reason %d\n", pkt.u.bind_nak.reject_reason));
		return NT_STATUS_ACCESS_DENIED;
	}

	if ((pkt.ptype != DCERPC_PKT_BIND_ACK) ||
	    pkt.u.bind_ack.num_results == 0 ||
	    pkt.u.bind_ack.ctx_list[0].result != 0) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (pkt.ptype == DCERPC_PKT_BIND_ACK) {
		p->srv_max_xmit_frag = pkt.u.bind_ack.max_xmit_frag;
		p->srv_max_recv_frag = pkt.u.bind_ack.max_recv_frag;
	}

	/* the bind_ack might contain a reply set of credentials */
	if (p->security_state.auth_info && pkt.u.bind_ack.auth_info.length) {
		status = ndr_pull_struct_blob(&pkt.u.bind_ack.auth_info,
					      mem_ctx,
					      p->security_state.auth_info,
					      (ndr_pull_flags_fn_t)ndr_pull_dcerpc_auth);
	}

	return status;	
}

/* 
   perform a alter context using the given syntax 

   the auth_info structure is updated with the reply authentication info
   on success
*/
NTSTATUS dcerpc_alter(struct dcerpc_pipe *p, 
		     TALLOC_CTX *mem_ctx)
{
	struct dcerpc_packet pkt;
	NTSTATUS status;
	DATA_BLOB blob;

	init_dcerpc_hdr(p, &pkt);

	pkt.ptype = DCERPC_PKT_ALTER;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.call_id = p->call_id;
	pkt.auth_length = 0;

	pkt.u.alter.max_xmit_frag = 0x2000;
	pkt.u.alter.max_recv_frag = 0x2000;
	pkt.u.alter.assoc_group_id = 0;
	pkt.u.alter.num_contexts = 1;
	pkt.u.alter.ctx_list = talloc(mem_ctx, sizeof(pkt.u.alter.ctx_list[0]));
	if (!pkt.u.alter.ctx_list) {
		return NT_STATUS_NO_MEMORY;
	}
	pkt.u.alter.ctx_list[0].context_id = 0;
	pkt.u.alter.ctx_list[0].num_transfer_syntaxes = 1;
	pkt.u.alter.ctx_list[0].abstract_syntax = p->syntax;
	pkt.u.alter.ctx_list[0].transfer_syntaxes = &p->transfer_syntax;
	pkt.u.alter.auth_info = data_blob(NULL, 0);

	/* construct the NDR form of the packet */
	status = dcerpc_push_auth(&blob, mem_ctx, &pkt, p->security_state.auth_info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* send it on its way */
	status = full_request(p, mem_ctx, &blob, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* unmarshall the NDR */
	status = dcerpc_pull(p, &blob, mem_ctx, &pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if ((pkt.ptype != DCERPC_PKT_ALTER_ACK) ||
	    pkt.u.alter_ack.num_results == 0 ||
	    pkt.u.alter_ack.ctx_list[0].result != 0) {
		status = NT_STATUS_UNSUCCESSFUL;
	}

	/* the bind_ack might contain a reply set of credentials */
	if (p->security_state.auth_info && pkt.u.alter_ack.auth_info.length) {
		status = ndr_pull_struct_blob(&pkt.u.alter_ack.auth_info,
					      mem_ctx,
					      p->security_state.auth_info,
					      (ndr_pull_flags_fn_t)ndr_pull_dcerpc_auth);
	}

	return status;	
}

/* 
   perform a continued bind (and auth3)
*/
NTSTATUS dcerpc_auth3(struct dcerpc_pipe *p, 
		      TALLOC_CTX *mem_ctx)
{
	struct dcerpc_packet pkt;
	NTSTATUS status;
	DATA_BLOB blob;

	init_dcerpc_hdr(p, &pkt);

	pkt.ptype = DCERPC_PKT_AUTH3;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.call_id = next_call_id(p);
	pkt.auth_length = 0;
	pkt.u.auth._pad = 0;
	pkt.u.auth.auth_info = data_blob(NULL, 0);

	/* construct the NDR form of the packet */
	status = dcerpc_push_auth(&blob, mem_ctx, &pkt, p->security_state.auth_info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* send it on its way */
	status = p->transport.send_request(p, &blob, False);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return status;	
}


/* perform a dcerpc bind, using the uuid as the key */
NTSTATUS dcerpc_bind_byuuid(struct dcerpc_pipe *p, 
			    TALLOC_CTX *mem_ctx,
			    const char *uuid, uint_t version)
{
	struct dcerpc_syntax_id syntax;
	struct dcerpc_syntax_id transfer_syntax;
	NTSTATUS status;

	status = GUID_from_string(uuid, &syntax.uuid);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2,("Invalid uuid string in dcerpc_bind_byuuid\n"));
		return status;
	}
	syntax.if_version = version;

	status = GUID_from_string(NDR_GUID, &transfer_syntax.uuid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	transfer_syntax.if_version = NDR_GUID_VERSION;

	return dcerpc_bind(p, mem_ctx, &syntax, &transfer_syntax);
}

/*
  process a fragment received from the transport layer during a
  request
*/
static void dcerpc_request_recv_data(struct dcerpc_pipe *p, 
				     DATA_BLOB *data,
				     NTSTATUS status)
{
	struct dcerpc_packet pkt;
	struct rpc_request *req;
	uint_t length;
	
	if (!NT_STATUS_IS_OK(status)) {
		/* all pending requests get the error */
		while (p->pending) {
			req = p->pending;
			req->state = RPC_REQUEST_DONE;
			req->status = status;
			DLIST_REMOVE(p->pending, req);
			if (req->async.callback) {
				req->async.callback(req);
			}
		}
		return;
	}

	pkt.call_id = 0;

	status = dcerpc_pull_request_sign(p, data, (TALLOC_CTX *)data->data, &pkt);

	/* find the matching request. Notice we match before we check
	   the status.  this is ok as a pending call_id can never be
	   zero */
	for (req=p->pending;req;req=req->next) {
		if (pkt.call_id == req->call_id) break;
	}

	if (req == NULL) {
		DEBUG(2,("dcerpc_request: unmatched call_id %u in response packet\n", pkt.call_id));
		return;
	}

	if (!NT_STATUS_IS_OK(status)) {
		req->status = status;
		req->state = RPC_REQUEST_DONE;
		DLIST_REMOVE(p->pending, req);
		if (req->async.callback) {
			req->async.callback(req);
		}
		return;
	}

	if (pkt.ptype == DCERPC_PKT_FAULT) {
		DEBUG(5,("rpc fault: %s\n", dcerpc_errstr(p, pkt.u.fault.status)));
		req->fault_code = pkt.u.fault.status;
		req->status = NT_STATUS_NET_WRITE_FAULT;
		req->state = RPC_REQUEST_DONE;
		DLIST_REMOVE(p->pending, req);
		if (req->async.callback) {
			req->async.callback(req);
		}
		return;
	}

	if (pkt.ptype != DCERPC_PKT_RESPONSE) {
		DEBUG(2,("Unexpected packet type %d in dcerpc response\n",
			 (int)pkt.ptype)); 
		req->fault_code = DCERPC_FAULT_OTHER;
		req->status = NT_STATUS_NET_WRITE_FAULT;
		req->state = RPC_REQUEST_DONE;
		DLIST_REMOVE(p->pending, req);
		if (req->async.callback) {
			req->async.callback(req);
		}
		return;
	}

	length = pkt.u.response.stub_and_verifier.length;

	if (length > 0) {
		req->payload.data = talloc_realloc(req, 
						   req->payload.data, 
						   req->payload.length + length);
		if (!req->payload.data) {
			req->status = NT_STATUS_NO_MEMORY;
			req->state = RPC_REQUEST_DONE;
			DLIST_REMOVE(p->pending, req);
			if (req->async.callback) {
				req->async.callback(req);
			}
			return;
		}
		memcpy(req->payload.data+req->payload.length, 
		       pkt.u.response.stub_and_verifier.data, length);
		req->payload.length += length;
	}

	if (!(pkt.pfc_flags & DCERPC_PFC_FLAG_LAST)) {
		p->transport.send_read(p);
		return;
	}

	/* we've got the full payload */
	req->state = RPC_REQUEST_DONE;
	DLIST_REMOVE(p->pending, req);

	if (!(pkt.drep[0] & DCERPC_DREP_LE)) {
		req->flags |= DCERPC_PULL_BIGENDIAN;
	} else {
		req->flags &= ~DCERPC_PULL_BIGENDIAN;
	}

	if (req->async.callback) {
		req->async.callback(req);
	}
}


/*
  make sure requests are cleaned up 
 */
static int dcerpc_req_destructor(void *ptr)
{
	struct rpc_request *req = ptr;
	DLIST_REMOVE(req->p->pending, req);
	return 0;
}

/*
  perform the send size of a async dcerpc request
*/
struct rpc_request *dcerpc_request_send(struct dcerpc_pipe *p, 
					uint16_t opnum,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *stub_data)
{
	struct rpc_request *req;
	struct dcerpc_packet pkt;
	DATA_BLOB blob;
	uint32_t remaining, chunk_size;
	BOOL first_packet = True;

	p->transport.recv_data = dcerpc_request_recv_data;

	req = talloc_p(mem_ctx, struct rpc_request);
	if (req == NULL) {
		return NULL;
	}

	req->p = p;
	req->call_id = next_call_id(p);
	req->status = NT_STATUS_OK;
	req->state = RPC_REQUEST_PENDING;
	req->payload = data_blob(NULL, 0);
	req->flags = 0;
	req->fault_code = 0;
	req->async.callback = NULL;

	init_dcerpc_hdr(p, &pkt);

	remaining = stub_data->length;

	/* we can write a full max_recv_frag size, minus the dcerpc
	   request header size */
	chunk_size = p->srv_max_recv_frag - (DCERPC_MAX_SIGN_SIZE+DCERPC_REQUEST_LENGTH);

	pkt.ptype = DCERPC_PKT_REQUEST;
	pkt.call_id = req->call_id;
	pkt.auth_length = 0;
	pkt.u.request.alloc_hint = remaining;
	pkt.u.request.context_id = 0;
	pkt.u.request.opnum = opnum;

	DLIST_ADD(p->pending, req);

	/* we send a series of pdus without waiting for a reply */
	while (remaining > 0 || first_packet) {
		uint32_t chunk = MIN(chunk_size, remaining);
		BOOL last_frag = False;

		first_packet = False;
		pkt.pfc_flags = 0;

		if (remaining == stub_data->length) {
			pkt.pfc_flags |= DCERPC_PFC_FLAG_FIRST;
		}
		if (chunk == remaining) {
			pkt.pfc_flags |= DCERPC_PFC_FLAG_LAST;
			last_frag = True;
		}

		pkt.u.request.stub_and_verifier.data = stub_data->data + 
			(stub_data->length - remaining);
		pkt.u.request.stub_and_verifier.length = chunk;

		req->status = dcerpc_push_request_sign(p, &blob, mem_ctx, &pkt);
		if (!NT_STATUS_IS_OK(req->status)) {
			req->state = RPC_REQUEST_DONE;
			DLIST_REMOVE(p->pending, req);
			return req;
		}
		
		req->status = p->transport.send_request(p, &blob, last_frag);
		if (!NT_STATUS_IS_OK(req->status)) {
			req->state = RPC_REQUEST_DONE;
			DLIST_REMOVE(p->pending, req);
			return req;
		}		

		remaining -= chunk;
	}

	talloc_set_destructor(req, dcerpc_req_destructor);

	return req;
}

/*
  return the event context for a dcerpc pipe
  used by callers who wish to operate asynchronously
*/
struct event_context *dcerpc_event_context(struct dcerpc_pipe *p)
{
	return p->transport.event_context(p);
}



/*
  perform the receive side of a async dcerpc request
*/
NTSTATUS dcerpc_request_recv(struct rpc_request *req,
			     TALLOC_CTX *mem_ctx,
			     DATA_BLOB *stub_data)
{
	NTSTATUS status;

	while (req->state == RPC_REQUEST_PENDING) {
		struct event_context *ctx = dcerpc_event_context(req->p);
		if (event_loop_once(ctx) != 0) {
			return NT_STATUS_CONNECTION_DISCONNECTED;
		}
	}
	*stub_data = req->payload;
	status = req->status;
	if (stub_data->data) {
		stub_data->data = talloc_steal(mem_ctx, stub_data->data);
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
		req->p->last_fault_code = req->fault_code;
	}
	talloc_free(req);
	return status;
}

/*
  perform a full request/response pair on a dcerpc pipe
*/
NTSTATUS dcerpc_request(struct dcerpc_pipe *p, 
			uint16_t opnum,
			TALLOC_CTX *mem_ctx,
			DATA_BLOB *stub_data_in,
			DATA_BLOB *stub_data_out)
{
	struct rpc_request *req;

	req = dcerpc_request_send(p, opnum, mem_ctx, stub_data_in);
	if (req == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return dcerpc_request_recv(req, mem_ctx, stub_data_out);
}


/*
  this is a paranoid NDR validator. For every packet we push onto the wire
  we pull it back again, then push it again. Then we compare the raw NDR data
  for that to the NDR we initially generated. If they don't match then we know
  we must have a bug in either the pull or push side of our code
*/
static NTSTATUS dcerpc_ndr_validate_in(struct dcerpc_pipe *p, 
				       TALLOC_CTX *mem_ctx,
				       DATA_BLOB blob,
				       size_t struct_size,
				       NTSTATUS (*ndr_push)(struct ndr_push *, int, void *),
				       NTSTATUS (*ndr_pull)(struct ndr_pull *, int, void *))
{
	void *st;
	struct ndr_pull *pull;
	struct ndr_push *push;
	NTSTATUS status;
	DATA_BLOB blob2;

	st = talloc(mem_ctx, struct_size);
	if (!st) {
		return NT_STATUS_NO_MEMORY;
	}

	pull = ndr_pull_init_flags(p, &blob, mem_ctx);
	if (!pull) {
		return NT_STATUS_NO_MEMORY;
	}

	status = ndr_pull(pull, NDR_IN, st);
	if (!NT_STATUS_IS_OK(status)) {
		return ndr_pull_error(pull, NDR_ERR_VALIDATE, 
				      "failed input validation pull - %s",
				      nt_errstr(status));
	}

	push = ndr_push_init_ctx(mem_ctx);
	if (!push) {
		return NT_STATUS_NO_MEMORY;
	}	

	status = ndr_push(push, NDR_IN, st);
	if (!NT_STATUS_IS_OK(status)) {
		return ndr_push_error(push, NDR_ERR_VALIDATE, 
				      "failed input validation push - %s",
				      nt_errstr(status));
	}

	blob2 = ndr_push_blob(push);

	if (!data_blob_equal(&blob, &blob2)) {
		DEBUG(3,("original:\n"));
		dump_data(3, blob.data, blob.length);
		DEBUG(3,("secondary:\n"));
		dump_data(3, blob2.data, blob2.length);
		return ndr_push_error(push, NDR_ERR_VALIDATE, 
				      "failed input validation data - %s",
				      nt_errstr(status));
	}

	return NT_STATUS_OK;
}

/*
  this is a paranoid NDR input validator. For every packet we pull
  from the wire we push it back again then pull and push it
  again. Then we compare the raw NDR data for that to the NDR we
  initially generated. If they don't match then we know we must have a
  bug in either the pull or push side of our code
*/
static NTSTATUS dcerpc_ndr_validate_out(struct dcerpc_pipe *p,
					TALLOC_CTX *mem_ctx,
					void *struct_ptr,
					size_t struct_size,
					NTSTATUS (*ndr_push)(struct ndr_push *, int, void *),
					NTSTATUS (*ndr_pull)(struct ndr_pull *, int, void *))
{
	void *st;
	struct ndr_pull *pull;
	struct ndr_push *push;
	NTSTATUS status;
	DATA_BLOB blob, blob2;

	st = talloc(mem_ctx, struct_size);
	if (!st) {
		return NT_STATUS_NO_MEMORY;
	}
	memcpy(st, struct_ptr, struct_size);

	push = ndr_push_init_ctx(mem_ctx);
	if (!push) {
		return NT_STATUS_NO_MEMORY;
	}	

	status = ndr_push(push, NDR_OUT, struct_ptr);
	if (!NT_STATUS_IS_OK(status)) {
		return ndr_push_error(push, NDR_ERR_VALIDATE, 
				      "failed output validation push - %s",
				      nt_errstr(status));
	}

	blob = ndr_push_blob(push);

	pull = ndr_pull_init_flags(p, &blob, mem_ctx);
	if (!pull) {
		return NT_STATUS_NO_MEMORY;
	}

	pull->flags |= LIBNDR_FLAG_REF_ALLOC;
	status = ndr_pull(pull, NDR_OUT, st);
	if (!NT_STATUS_IS_OK(status)) {
		return ndr_pull_error(pull, NDR_ERR_VALIDATE, 
				      "failed output validation pull - %s",
				      nt_errstr(status));
	}

	push = ndr_push_init_ctx(mem_ctx);
	if (!push) {
		return NT_STATUS_NO_MEMORY;
	}	

	status = ndr_push(push, NDR_OUT, st);
	if (!NT_STATUS_IS_OK(status)) {
		return ndr_push_error(push, NDR_ERR_VALIDATE, 
				      "failed output validation push2 - %s",
				      nt_errstr(status));
	}

	blob2 = ndr_push_blob(push);

	if (!data_blob_equal(&blob, &blob2)) {
		DEBUG(3,("original:\n"));
		dump_data(3, blob.data, blob.length);
		DEBUG(3,("secondary:\n"));
		dump_data(3, blob2.data, blob2.length);
		return ndr_push_error(push, NDR_ERR_VALIDATE, 
				      "failed output validation data - %s",
				      nt_errstr(status));
	}

	return NT_STATUS_OK;
}


/*
  send a rpc request with a given set of ndr helper functions

  call dcerpc_ndr_request_recv() to receive the answer
*/
struct rpc_request *dcerpc_ndr_request_send(struct dcerpc_pipe *p,
					    uint32_t opnum,
					    TALLOC_CTX *mem_ctx,
					    NTSTATUS (*ndr_push)(struct ndr_push *, int, void *),
					    NTSTATUS (*ndr_pull)(struct ndr_pull *, int, void *),
					    void *struct_ptr,
					    size_t struct_size)
{
	struct ndr_push *push;
	NTSTATUS status;
	DATA_BLOB request;
	struct rpc_request *req;

	/* setup for a ndr_push_* call */
	push = ndr_push_init();
	if (!push) {
		return NULL;
	}

	if (p->flags & DCERPC_PUSH_BIGENDIAN) {
		push->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	/* push the structure into a blob */
	status = ndr_push(push, NDR_IN, struct_ptr);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2,("Unable to ndr_push structure in dcerpc_ndr_request_send - %s\n",
			 nt_errstr(status)));
		ndr_push_free(push);
		return NULL;
	}

	/* retrieve the blob */
	request = ndr_push_blob(push);

	if (p->flags & DCERPC_DEBUG_VALIDATE_IN) {
		status = dcerpc_ndr_validate_in(p, mem_ctx, request, struct_size, 
						ndr_push, ndr_pull);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(2,("Validation failed in dcerpc_ndr_request_send - %s\n",
				 nt_errstr(status)));
			ndr_push_free(push);
			return NULL;
		}
	}

	DEBUG(10,("rpc request data:\n"));
	dump_data(10, request.data, request.length);

	/* make the actual dcerpc request */
	req = dcerpc_request_send(p, opnum, mem_ctx, &request);

	if (req != NULL) {
		req->ndr.ndr_push = ndr_push;
		req->ndr.ndr_pull = ndr_pull;
		req->ndr.struct_ptr = struct_ptr;
		req->ndr.struct_size = struct_size;
		req->ndr.mem_ctx = mem_ctx;
	}

	ndr_push_free(push);
	
	return req;
}

/*
  receive the answer from a dcerpc_ndr_request_send()
*/
NTSTATUS dcerpc_ndr_request_recv(struct rpc_request *req)
{
	struct dcerpc_pipe *p = req->p;
	NTSTATUS status;
	DATA_BLOB response;
	struct ndr_pull *pull;
	struct rpc_request_ndr ndr = req->ndr;
	uint_t flags;

	/* make sure the recv code doesn't free the request, as we
	   need to grab the flags element before it is freed */
	talloc_increase_ref_count(req);

	status = dcerpc_request_recv(req, ndr.mem_ctx, &response);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	flags = req->flags;
	talloc_free(req);

	/* prepare for ndr_pull_* */
	pull = ndr_pull_init_flags(p, &response, ndr.mem_ctx);
	if (!pull) {
		return NT_STATUS_NO_MEMORY;
	}

	if (flags & DCERPC_PULL_BIGENDIAN) {
		pull->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	DEBUG(10,("rpc reply data:\n"));
	dump_data(10, pull->data, pull->data_size);

	/* pull the structure from the blob */
	status = ndr.ndr_pull(pull, NDR_OUT, ndr.struct_ptr);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (p->flags & DCERPC_DEBUG_VALIDATE_OUT) {
		status = dcerpc_ndr_validate_out(p, ndr.mem_ctx, ndr.struct_ptr, ndr.struct_size, 
						 ndr.ndr_push, ndr.ndr_pull);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (pull->offset != pull->data_size) {
		DEBUG(0,("Warning! ignoring %d unread bytes in rpc packet!\n", 
			 pull->data_size - pull->offset));
		/* we used return NT_STATUS_INFO_LENGTH_MISMATCH here,
		   but it turns out that early versions of NT
		   (specifically NT3.1) add junk onto the end of rpc
		   packets, so if we want to interoperate at all with
		   those versions then we need to ignore this error */
	}

	return NT_STATUS_OK;
}


/*
  a useful helper function for synchronous rpc requests 

  this can be used when you have ndr push/pull functions in the
  standard format
*/
NTSTATUS dcerpc_ndr_request(struct dcerpc_pipe *p,
			    uint32_t opnum,
			    TALLOC_CTX *mem_ctx,
			    NTSTATUS (*ndr_push)(struct ndr_push *, int, void *),
			    NTSTATUS (*ndr_pull)(struct ndr_pull *, int, void *),
			    void *struct_ptr,
			    size_t struct_size)
{
	struct rpc_request *req;

	req = dcerpc_ndr_request_send(p, opnum, mem_ctx, ndr_push, ndr_pull, struct_ptr, struct_size);
	if (req == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return dcerpc_ndr_request_recv(req);
}


/*
  a useful function for retrieving the server name we connected to
*/
const char *dcerpc_server_name(struct dcerpc_pipe *p)
{
	if (!p->transport.peer_name) {
		return "";
	}
	return p->transport.peer_name(p);
}

/*
  a useful function to get the auth_level 
*/

uint32 dcerpc_auth_level(struct dcerpc_pipe *p) 
{
	uint8_t auth_level;

	if (p->flags & DCERPC_SEAL) {
		auth_level = DCERPC_AUTH_LEVEL_PRIVACY;
	} else if (p->flags & DCERPC_SIGN) {
		auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
	} else if (p->flags & DCERPC_CONNECT) {
		auth_level = DCERPC_AUTH_LEVEL_CONNECT;
	} else {
		auth_level = DCERPC_AUTH_LEVEL_NONE;
	}
	return auth_level;
}
