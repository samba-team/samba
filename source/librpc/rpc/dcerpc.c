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

/* initialise a dcerpc pipe. This currently assumes a SMB named pipe
   transport */
struct dcerpc_pipe *dcerpc_pipe_init(void)
{
	struct dcerpc_pipe *p;

	TALLOC_CTX *mem_ctx = talloc_init("dcerpc_tree");
	if (mem_ctx == NULL)
		return NULL;

	p = talloc(mem_ctx, sizeof(*p));
	if (!p) {
		talloc_destroy(mem_ctx);
		return NULL;
	}

	p->reference_count = 0;
	p->mem_ctx = mem_ctx;
	p->call_id = 1;
	p->auth_info = NULL;
	p->ntlmssp_state = NULL;
	p->flags = 0;

	return p;
}

/* close down a dcerpc over SMB pipe */
void dcerpc_pipe_close(struct dcerpc_pipe *p)
{
	if (!p) return;
	p->reference_count--;
	if (p->reference_count <= 0) {
		if (p->ntlmssp_state) {
			ntlmssp_end(&p->ntlmssp_state);
		}
		p->transport.shutdown_pipe(p);
		talloc_destroy(p->mem_ctx);
	}
}


/* 
   parse a data blob into a dcerpc_packet structure. This handles both
   input and output packets
*/
static NTSTATUS dcerpc_pull(DATA_BLOB *blob, TALLOC_CTX *mem_ctx, 
			    struct dcerpc_packet *pkt)
{
	struct ndr_pull *ndr;

	ndr = ndr_pull_init_blob(blob, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}

	return ndr_pull_dcerpc_packet(ndr, NDR_SCALARS|NDR_BUFFERS, pkt);
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
	if (!p->auth_info || !p->ntlmssp_state) {
		return dcerpc_pull(blob, mem_ctx, pkt);
	}

	ndr = ndr_pull_init_blob(blob, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}

	/* pull the basic packet */
	status = ndr_pull_dcerpc_packet(ndr, NDR_SCALARS|NDR_BUFFERS, pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (pkt->ptype != DCERPC_PKT_RESPONSE) {
		return status;
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
	ndr = ndr_pull_init_blob(&auth_blob, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}

	status = ndr_pull_dcerpc_auth(ndr, NDR_SCALARS|NDR_BUFFERS, &auth);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}


	/* check signature or unseal the packet */
	switch (p->auth_info->auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		status = ntlmssp_unseal_packet(p->ntlmssp_state, 
					       pkt->u.response.stub_and_verifier.data, 
					       pkt->u.response.stub_and_verifier.length, 
					       &auth.credentials);
		break;

	case DCERPC_AUTH_LEVEL_INTEGRITY:
		status = ntlmssp_check_packet(p->ntlmssp_state, 
					      pkt->u.response.stub_and_verifier.data, 
					      pkt->u.response.stub_and_verifier.length, 
					      &auth.credentials);
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
   push a dcerpc_packet into a blob. This handles both input and
   output packets
*/
static NTSTATUS dcerpc_push(struct dcerpc_pipe *p, 
			    DATA_BLOB *blob, TALLOC_CTX *mem_ctx, 
			    struct dcerpc_packet *pkt)
{
	NTSTATUS status;
	struct ndr_push *ndr;

	ndr = ndr_push_init_ctx(mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}

	if (p->auth_info) {
		pkt->auth_length = p->auth_info->credentials.length;
	} else {
		pkt->auth_length = 0;
	}

	status = ndr_push_dcerpc_packet(ndr, NDR_SCALARS|NDR_BUFFERS, pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (p->auth_info) {
		status = ndr_push_dcerpc_auth(ndr, NDR_SCALARS|NDR_BUFFERS, 
					      p->auth_info);
	}

	*blob = ndr_push_blob(ndr);

	/* fill in the frag length */
	SSVAL(blob->data, 8, blob->length);

	return NT_STATUS_OK;
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

	/* non-signed packets are simpler */
	if (!p->auth_info || !p->ntlmssp_state) {
		return dcerpc_push(p, blob, mem_ctx, pkt);
	}

	ndr = ndr_push_init_ctx(mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}

	status = ndr_push_dcerpc_packet(ndr, NDR_SCALARS|NDR_BUFFERS, pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* pad to 8 byte multiple */
	p->auth_info->auth_pad_length = NDR_ALIGN(ndr, 8);
	ndr_push_zero(ndr, p->auth_info->auth_pad_length);

	/* sign or seal the packet */
	switch (p->auth_info->auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		status = ntlmssp_seal_packet(p->ntlmssp_state, 
					     ndr->data + DCERPC_REQUEST_LENGTH, 
					     ndr->offset - DCERPC_REQUEST_LENGTH,
					     &p->auth_info->credentials);
		break;

	case DCERPC_AUTH_LEVEL_INTEGRITY:
		status = ntlmssp_sign_packet(p->ntlmssp_state, 
					     ndr->data + DCERPC_REQUEST_LENGTH, 
					     ndr->offset - DCERPC_REQUEST_LENGTH,
					     &p->auth_info->credentials);
		break;

	case DCERPC_AUTH_LEVEL_NONE:
		p->auth_info->credentials = data_blob(NULL, 0);
		break;

	default:
		status = NT_STATUS_INVALID_LEVEL;
		break;
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}	

	/* add the auth verifier */
	status = ndr_push_dcerpc_auth(ndr, NDR_SCALARS|NDR_BUFFERS, p->auth_info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* extract the whole packet as a blob */
	*blob = ndr_push_blob(ndr);

	/* fill in the fragment length and auth_length, we can't fill
	   in these earlier as we don't know the signature length (it
	   could be variable length) */
	SSVAL(blob->data,  DCERPC_FRAG_LEN_OFFSET, blob->length);
	SSVAL(blob->data,  DCERPC_AUTH_LEN_OFFSET, p->auth_info->credentials.length);

	data_blob_free(&p->auth_info->credentials);

	return NT_STATUS_OK;
}


/* 
   fill in the fixed values in a dcerpc header 
*/
static void init_dcerpc_hdr(struct dcerpc_packet *pkt)
{
	pkt->rpc_vers = 5;
	pkt->rpc_vers_minor = 0;
	pkt->drep[0] = 0x10; /* Little endian */
	pkt->drep[1] = 0;
	pkt->drep[2] = 0;
	pkt->drep[3] = 0;
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
	struct dcerpc_syntax_id tsyntax;

	init_dcerpc_hdr(&pkt);

	pkt.ptype = DCERPC_PKT_BIND;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.call_id = p->call_id;
	pkt.auth_length = 0;

	pkt.u.bind.max_xmit_frag = 0x2000;
	pkt.u.bind.max_recv_frag = 0x2000;
	pkt.u.bind.assoc_group_id = 0;
	pkt.u.bind.num_contexts = 1;
	pkt.u.bind.ctx_list = talloc(mem_ctx, sizeof(pkt.u.bind.ctx_list[0]));
	if (!pkt.u.bind.ctx_list) {
		return NT_STATUS_NO_MEMORY;
	}
	pkt.u.bind.ctx_list[0].context_id = 0;
	pkt.u.bind.ctx_list[0].num_transfer_syntaxes = 1;
	pkt.u.bind.ctx_list[0].abstract_syntax = *syntax;
	tsyntax = *transfer_syntax;
	pkt.u.bind.ctx_list[0].transfer_syntaxes = &tsyntax;
	pkt.u.bind.auth_info = data_blob(NULL, 0);

	/* construct the NDR form of the packet */
	status = dcerpc_push(p, &blob, mem_ctx, &pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* send it on its way */
	status = p->transport.full_request(p, mem_ctx, &blob, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* unmarshall the NDR */
	status = dcerpc_pull(&blob, mem_ctx, &pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (pkt.ptype != DCERPC_PKT_BIND_ACK ||
	    pkt.u.bind_ack.num_results == 0 ||
	    pkt.u.bind_ack.ctx_list[0].result != 0) {
		status = NT_STATUS_UNSUCCESSFUL;
	}

	p->srv_max_xmit_frag = pkt.u.bind_ack.max_xmit_frag;
	p->srv_max_recv_frag = pkt.u.bind_ack.max_recv_frag;

	/* the bind_ack might contain a reply set of credentials */
	if (p->auth_info && pkt.u.bind_ack.auth_info.length) {
		status = ndr_pull_struct_blob(&pkt.u.bind_ack.auth_info,
					      mem_ctx,
					      p->auth_info,
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

	init_dcerpc_hdr(&pkt);

	pkt.ptype = DCERPC_PKT_AUTH3;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.call_id = p->call_id++;
	pkt.auth_length = 0;
	pkt.u.auth._pad = 0;
	pkt.u.auth.auth_info = data_blob(NULL, 0);

	/* construct the NDR form of the packet */
	status = dcerpc_push(p, &blob, mem_ctx, &pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* send it on its way */
	status = p->transport.initial_request(p, mem_ctx, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return status;	
}


/* perform a dcerpc bind, using the uuid as the key */
NTSTATUS dcerpc_bind_byuuid(struct dcerpc_pipe *p, 
			    TALLOC_CTX *mem_ctx,
			    const char *uuid, unsigned version)
{
	struct dcerpc_syntax_id syntax;
	struct dcerpc_syntax_id transfer_syntax;
	NTSTATUS status;

	status = GUID_from_string(uuid, &syntax.uuid);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2,("Invalid uuid string in dcerpc_bind_byuuid\n"));
		return status;
	}
	syntax.major_version = version;
	syntax.minor_version = 0;

	status = GUID_from_string(NDR_GUID, &transfer_syntax.uuid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	transfer_syntax.major_version = NDR_GUID_VERSION;
	transfer_syntax.minor_version = 0;

	return dcerpc_bind(p, mem_ctx, &syntax, &transfer_syntax);
}

/*
  perform a full request/response pair on a dcerpc pipe
*/
NTSTATUS dcerpc_request(struct dcerpc_pipe *p, 
			uint16 opnum,
			TALLOC_CTX *mem_ctx,
			DATA_BLOB *stub_data_in,
			DATA_BLOB *stub_data_out)
{
	
	struct dcerpc_packet pkt;
	NTSTATUS status;
	DATA_BLOB blob, payload;
	uint32 remaining, chunk_size;

	init_dcerpc_hdr(&pkt);

	remaining = stub_data_in->length;

	/* we can write a full max_recv_frag size, minus the dcerpc
	   request header size */
	chunk_size = p->srv_max_recv_frag - DCERPC_REQUEST_LENGTH;

	pkt.ptype = DCERPC_PKT_REQUEST;
	pkt.call_id = p->call_id++;
	pkt.auth_length = 0;
	pkt.u.request.alloc_hint = remaining;
	pkt.u.request.context_id = 0;
	pkt.u.request.opnum = opnum;

	/* we send a series of pdus without waiting for a reply until
	   the last pdu */
	while (remaining > chunk_size) {
		if (remaining == stub_data_in->length) {
			pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST;
		} else {
			pkt.pfc_flags = 0;
		}

		pkt.u.request.stub_and_verifier.data = stub_data_in->data + 
			(stub_data_in->length - remaining);
		pkt.u.request.stub_and_verifier.length = chunk_size;

		status = dcerpc_push_request_sign(p, &blob, mem_ctx, &pkt);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		
		status = p->transport.initial_request(p, mem_ctx, &blob);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}		

		remaining -= chunk_size;
	}

	/* now we send a pdu with LAST_FRAG sent and get the first
	   part of the reply */
	if (remaining == stub_data_in->length) {
		pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	} else {
		pkt.pfc_flags = DCERPC_PFC_FLAG_LAST;
	}
	pkt.u.request.stub_and_verifier.data = stub_data_in->data + 
		(stub_data_in->length - remaining);
	pkt.u.request.stub_and_verifier.length = remaining;

	status = dcerpc_push_request_sign(p, &blob, mem_ctx, &pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* send the pdu and get the initial response pdu */
	status = p->transport.full_request(p, mem_ctx, &blob, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = dcerpc_pull_request_sign(p, &blob, mem_ctx, &pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (pkt.ptype == DCERPC_PKT_FAULT) {
		return NT_STATUS_NET_WRITE_FAULT;
	}

	if (pkt.ptype != DCERPC_PKT_RESPONSE) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!(pkt.pfc_flags & DCERPC_PFC_FLAG_FIRST)) {
		/* something is badly wrong! */
		return NT_STATUS_UNSUCCESSFUL;
	}

	payload = pkt.u.response.stub_and_verifier;

	/* continue receiving fragments */
	while (!(pkt.pfc_flags & DCERPC_PFC_FLAG_LAST)) {
		uint32 length;

		status = p->transport.secondary_request(p, mem_ctx, &blob);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		status = dcerpc_pull_request_sign(p, &blob, mem_ctx, &pkt);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		if (pkt.pfc_flags & DCERPC_PFC_FLAG_FIRST) {
			/* start of another packet!? */
			return NT_STATUS_UNSUCCESSFUL;
		}

		if (pkt.ptype != DCERPC_PKT_RESPONSE) {
			return NT_STATUS_UNSUCCESSFUL;
		}

		length = pkt.u.response.stub_and_verifier.length;

		payload.data = talloc_realloc(mem_ctx, 
					      payload.data, 
					      payload.length + length);
		if (!payload.data) {
			return NT_STATUS_NO_MEMORY;
		}

		memcpy(payload.data + payload.length,
		       pkt.u.response.stub_and_verifier.data,
		       length);

		payload.length += length;
	}

	if (stub_data_out) {
		*stub_data_out = payload;
	}

	return status;
}


/*
  this is a paranoid NDR validator. For every packet we push onto the wire
  we pull it back again, then push it again. Then we compare the raw NDR data
  for that to the NDR we initially generated. If they don't match then we know
  we must have a bug in either the pull or push side of our code
*/
static NTSTATUS dcerpc_ndr_validate_in(TALLOC_CTX *mem_ctx,
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

	pull = ndr_pull_init_blob(&blob, mem_ctx);
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
static NTSTATUS dcerpc_ndr_validate_out(TALLOC_CTX *mem_ctx,
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

	pull = ndr_pull_init_blob(&blob, mem_ctx);
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
  a useful helper function for synchronous rpc requests 

  this can be used when you have ndr push/pull functions in the
  standard format
*/
NTSTATUS dcerpc_ndr_request(struct dcerpc_pipe *p,
			    uint32 opnum,
			    TALLOC_CTX *mem_ctx,
			    NTSTATUS (*ndr_push)(struct ndr_push *, int, void *),
			    NTSTATUS (*ndr_pull)(struct ndr_pull *, int, void *),
			    void *struct_ptr,
			    size_t struct_size)
{
	struct ndr_push *push;
	struct ndr_pull *pull;
	NTSTATUS status;
	DATA_BLOB request, response;

	/* setup for a ndr_push_* call */
	push = ndr_push_init();
	if (!push) {
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	/* push the structure into a blob */
	status = ndr_push(push, NDR_IN, struct_ptr);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	/* retrieve the blob */
	request = ndr_push_blob(push);

	if (p->flags & DCERPC_DEBUG_VALIDATE_IN) {
		status = dcerpc_ndr_validate_in(mem_ctx, request, struct_size, 
						ndr_push, ndr_pull);
		if (!NT_STATUS_IS_OK(status)) {
			goto failed;
		}
	}

	DEBUG(10,("rpc request data:\n"));
	dump_data(10, request.data, request.length);

	/* make the actual dcerpc request */
	status = dcerpc_request(p, opnum, mem_ctx, &request, &response);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	/* prepare for ndr_pull_* */
	pull = ndr_pull_init_blob(&response, mem_ctx);
	if (!pull) {
		goto failed;
	}

	DEBUG(10,("rpc reply data:\n"));
	dump_data(10, pull->data, pull->data_size);

	/* pull the structure from the blob */
	status = ndr_pull(pull, NDR_OUT, struct_ptr);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	/* possibly check the packet signature */
	

	if (p->flags & DCERPC_DEBUG_VALIDATE_OUT) {
		status = dcerpc_ndr_validate_out(mem_ctx, struct_ptr, struct_size, 
						 ndr_push, ndr_pull);
		if (!NT_STATUS_IS_OK(status)) {
			goto failed;
		}
	}

	if (pull->offset != pull->data_size) {
		DEBUG(0,("Warning! %d unread bytes\n", pull->data_size - pull->offset));
		status = NT_STATUS_INFO_LENGTH_MISMATCH;
		goto failed;
	}

failed:
	ndr_push_free(push);
	return status;
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
