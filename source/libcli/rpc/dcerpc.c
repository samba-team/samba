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
struct dcerpc_pipe *dcerpc_pipe_init(struct cli_tree *tree)
{
	struct dcerpc_pipe *p;

	TALLOC_CTX *mem_ctx = talloc_init("cli_dcerpc_tree");
	if (mem_ctx == NULL)
		return NULL;

	p = talloc(mem_ctx, sizeof(*p));
	if (!p) {
		talloc_destroy(mem_ctx);
		return NULL;
	}

	p->mem_ctx = mem_ctx;
	p->tree = tree;
	p->tree->reference_count++;
	p->call_id = 1;
	p->fnum = 0;

	return p;
}

/* close down a dcerpc over SMB pipe */
void dcerpc_pipe_close(struct dcerpc_pipe *p)
{
	if (!p) return;
	p->reference_count--;
	if (p->reference_count <= 0) {
		cli_tree_close(p->tree);
		talloc_destroy(p->mem_ctx);
	}
}

#define BLOB_CHECK_BOUNDS(blob, offset, len) do { \
	if ((offset) > blob->length || (blob->length - (offset) < (len))) { \
		return NT_STATUS_INVALID_PARAMETER; \
	} \
} while (0)

#define DCERPC_ALIGN(offset, n) do { \
	(offset) = ((offset) + ((n)-1)) & ~((n)-1); \
} while (0)

/*
  pull a wire format uuid into a string. This will consume 16 bytes
*/
static char *dcerpc_pull_uuid(char *data, TALLOC_CTX *mem_ctx)
{
	uint32 time_low;
	uint16 time_mid, time_hi_and_version;
	uint8 clock_seq_hi_and_reserved;
	uint8 clock_seq_low;
	uint8 node[6];
	int i;

	time_low                  = IVAL(data, 0);
	time_mid                  = SVAL(data, 4);
	time_hi_and_version       = SVAL(data, 6);
	clock_seq_hi_and_reserved = CVAL(data, 8);
	clock_seq_low             = CVAL(data, 9);
	for (i=0;i<6;i++) {
		node[i]           = CVAL(data, 10 + i);
	}

	return talloc_asprintf(mem_ctx, 
			       "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			       time_low, time_mid, time_hi_and_version, 
			       clock_seq_hi_and_reserved, clock_seq_low,
			       node[0], node[1], node[2], node[3], node[4], node[5]);
}

/*
  push a uuid_str into wire format. It will consume 16 bytes
*/
static NTSTATUS push_uuid_str(char *data, const char *uuid_str)
{
	uint32 time_low;
	uint32 time_mid, time_hi_and_version;
	uint32 clock_seq_hi_and_reserved;
	uint32 clock_seq_low;
	uint32 node[6];
	int i;

	if (11 != sscanf(uuid_str, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			 &time_low, &time_mid, &time_hi_and_version, 
			 &clock_seq_hi_and_reserved, &clock_seq_low,
			 &node[0], &node[1], &node[2], &node[3], &node[4], &node[5])) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	SIVAL(data, 0, time_low);
	SSVAL(data, 4, time_mid);
	SSVAL(data, 6, time_hi_and_version);
	SCVAL(data, 8, clock_seq_hi_and_reserved);
	SCVAL(data, 9, clock_seq_low);
	for (i=0;i<6;i++) {
		SCVAL(data, 10 + i, node[i]);
	}

	return NT_STATUS_OK;
}

/*
  pull a dcerpc syntax id from a blob
*/
static NTSTATUS dcerpc_pull_syntax_id(DATA_BLOB *blob, TALLOC_CTX *mem_ctx, 
				      uint32 *offset, 
				      struct dcerpc_syntax_id *syntax)
{
	syntax->uuid_str = dcerpc_pull_uuid(blob->data + (*offset), mem_ctx);
	if (!syntax->uuid_str) {
		return NT_STATUS_NO_MEMORY;
	}
	(*offset) += 16;
	syntax->if_version = IVAL(blob->data, *offset);
	(*offset) += 4;
	return NT_STATUS_OK;
}

/*
  push a syntax id onto the wire. It will consume 20 bytes
*/
static NTSTATUS push_syntax_id(char *data, const struct dcerpc_syntax_id *syntax)
{
	NTSTATUS status;

	status = push_uuid_str(data, syntax->uuid_str);
	SIVAL(data, 16, syntax->if_version);

	return status;
}

/*
  pull an auth verifier from a packet
*/
static NTSTATUS dcerpc_pull_auth_verifier(DATA_BLOB *blob, TALLOC_CTX *mem_ctx, 
					  uint32 *offset, 
					  struct dcerpc_hdr *hdr,
					  DATA_BLOB *auth)
{
	if (hdr->auth_length == 0) {
		return NT_STATUS_OK;
	}

	BLOB_CHECK_BOUNDS(blob, *offset, hdr->auth_length);
	*auth = data_blob_talloc(mem_ctx, blob->data + (*offset), hdr->auth_length);
	if (!auth->data) {
		return NT_STATUS_NO_MEMORY;
	}
	(*offset) += hdr->auth_length;
	return NT_STATUS_OK;
}

/* 
   parse a struct dcerpc_response
*/
static NTSTATUS dcerpc_pull_response(DATA_BLOB *blob, TALLOC_CTX *mem_ctx, 
				     uint32 *offset, 
				     struct dcerpc_hdr *hdr,
				     struct dcerpc_response *pkt)
{
	uint32 alloc_hint, stub_len;
	
	BLOB_CHECK_BOUNDS(blob, *offset, 8);

	alloc_hint        = IVAL(blob->data, (*offset) + 0);
	pkt->context_id   = SVAL(blob->data, (*offset) + 4);
	pkt->cancel_count = CVAL(blob->data, (*offset) + 6);

	(*offset) += 8;

	stub_len = blob->length - ((*offset) + hdr->auth_length);
	BLOB_CHECK_BOUNDS(blob, *offset, stub_len);
	pkt->stub_data = data_blob_talloc(mem_ctx, blob->data + (*offset), stub_len);
	if (stub_len != 0 && !pkt->stub_data.data) {
		return NT_STATUS_NO_MEMORY;
	}
	(*offset) += stub_len;

	return dcerpc_pull_auth_verifier(blob, mem_ctx, offset, hdr, &pkt->auth_verifier);	
}


/* 
   parse a struct bind_ack
*/
static NTSTATUS dcerpc_pull_bind_ack(DATA_BLOB *blob, TALLOC_CTX *mem_ctx, 
				     uint32 *offset, 
				     struct dcerpc_hdr *hdr,
				     struct dcerpc_bind_ack *pkt)
{
	uint16 len;
	int i;
	
	BLOB_CHECK_BOUNDS(blob, *offset, 10);
	pkt->max_xmit_frag  = SVAL(blob->data, (*offset) + 0);
	pkt->max_recv_frag  = SVAL(blob->data, (*offset) + 2);
	pkt->assoc_group_id = IVAL(blob->data, (*offset) + 4);
	len                 = SVAL(blob->data, (*offset) + 8);
	(*offset) += 10;

	if (len) {
		BLOB_CHECK_BOUNDS(blob, *offset, len);
		pkt->secondary_address = talloc_strndup(mem_ctx, blob->data + (*offset), len);
		if (!pkt->secondary_address) {
			return NT_STATUS_NO_MEMORY;
		}
		(*offset) += len;
	}

	DCERPC_ALIGN(*offset, 4);
	BLOB_CHECK_BOUNDS(blob, *offset, 4);
	pkt->num_results = CVAL(blob->data, *offset); 
	(*offset) += 4;

	if (pkt->num_results > 0) {
		pkt->ctx_list = talloc(mem_ctx, sizeof(pkt->ctx_list[0]) * pkt->num_results);
		if (!pkt->ctx_list) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	for (i=0;i<pkt->num_results;i++) {
		NTSTATUS status;

		BLOB_CHECK_BOUNDS(blob, *offset, 24);
		pkt->ctx_list[i].result = IVAL(blob->data, *offset);
		(*offset) += 4;
		status = dcerpc_pull_syntax_id(blob, mem_ctx, offset, &pkt->ctx_list[i].syntax);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return dcerpc_pull_auth_verifier(blob, mem_ctx, offset, hdr, &pkt->auth_verifier);
}


/* 
   parse a dcerpc header
*/
static NTSTATUS dcerpc_pull_hdr(DATA_BLOB *blob, uint32 *offset, struct dcerpc_hdr *hdr)
{
	BLOB_CHECK_BOUNDS(blob, *offset, 16);
	
	hdr->rpc_vers       = CVAL(blob->data, (*offset) + 0);
	hdr->rpc_vers_minor = CVAL(blob->data, (*offset) + 1);
	hdr->ptype          = CVAL(blob->data, (*offset) + 2);
	hdr->pfc_flags      = CVAL(blob->data, (*offset) + 3);
	memcpy(hdr->drep, blob->data + (*offset) + 4, 4);
	hdr->frag_length    = SVAL(blob->data, (*offset) + 8);
	hdr->auth_length    = SVAL(blob->data, (*offset) + 10);
	hdr->call_id        = IVAL(blob->data, (*offset) + 12);

	(*offset) += 16;

	return NT_STATUS_OK;
}

/* 
   parse a dcerpc header. It consumes 16 bytes
*/
static void dcerpc_push_hdr(char *data, struct dcerpc_hdr *hdr)
{
	SCVAL(data, 0, hdr->rpc_vers);
	SCVAL(data, 1, hdr->rpc_vers_minor);
	SCVAL(data, 2, hdr->ptype);
	SCVAL(data, 3, hdr->pfc_flags);
	memcpy(data + 4, hdr->drep, 4);
	SSVAL(data, 8, hdr->frag_length);
	SSVAL(data, 12, hdr->call_id);
}



/* 
   parse a data blob into a dcerpc_packet structure. This handles both
   input and output packets
*/
NTSTATUS dcerpc_pull(DATA_BLOB *blob, TALLOC_CTX *mem_ctx, struct dcerpc_packet *pkt)
{
	NTSTATUS status;
	uint32 offset = 0;

	status = dcerpc_pull_hdr(blob, &offset, &pkt->hdr);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	switch (pkt->hdr.ptype) {
	case DCERPC_PKT_BIND_ACK:
		status = dcerpc_pull_bind_ack(blob, mem_ctx, &offset, &pkt->hdr, &pkt->out.bind_ack);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}		
		break;

	case DCERPC_PKT_RESPONSE:
		status = dcerpc_pull_response(blob, mem_ctx, &offset, &pkt->hdr, &pkt->out.response);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}		
		break;

	default:
		return NT_STATUS_INVALID_LEVEL;
	}

	return status;
}


/* 
   push a dcerpc_bind into a blob
*/
static NTSTATUS dcerpc_push_bind(DATA_BLOB *blob, uint32 *offset,
				 struct dcerpc_hdr *hdr,
				 struct dcerpc_bind *pkt)
{
	int i, j;

	SSVAL(blob->data, (*offset) + 0, pkt->max_xmit_frag);
	SSVAL(blob->data, (*offset) + 2, pkt->max_recv_frag);
	SIVAL(blob->data, (*offset) + 4, pkt->assoc_group_id);
	SCVAL(blob->data, (*offset) + 8, pkt->num_contexts);
	(*offset) += 12;

	for (i=0;i<pkt->num_contexts;i++) {
		NTSTATUS status;

		SSVAL(blob->data, (*offset) + 0, pkt->ctx_list[i].context_id);
		SCVAL(blob->data, (*offset) + 2, pkt->ctx_list[i].num_transfer_syntaxes);
		status = push_syntax_id(blob->data + (*offset) + 4, &pkt->ctx_list[i].abstract_syntax);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		(*offset) += 24;
		for (j=0;j<pkt->ctx_list[i].num_transfer_syntaxes;j++) {
			status = push_syntax_id(blob->data + (*offset), 
						&pkt->ctx_list[i].transfer_syntaxes[j]);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			(*offset) += 20;
		}
	}

	return NT_STATUS_OK;
}

/* 
   push a dcerpc_request into a blob
*/
static NTSTATUS dcerpc_push_request(DATA_BLOB *blob, uint32 *offset,
				    struct dcerpc_hdr *hdr,
				    struct dcerpc_request *pkt)
{
	uint32 alloc_hint = 8 + pkt->stub_data.length + pkt->auth_verifier.length;

	SIVAL(blob->data, (*offset) + 0, alloc_hint);
	SSVAL(blob->data, (*offset) + 4, pkt->context_id);
	SSVAL(blob->data, (*offset) + 6, pkt->opnum);

	(*offset) += 8;

	memcpy(blob->data + (*offset), pkt->stub_data.data, pkt->stub_data.length);
	(*offset) += pkt->stub_data.length;

	memcpy(blob->data + (*offset), pkt->auth_verifier.data, pkt->auth_verifier.length);
	(*offset) += pkt->auth_verifier.length;

	return NT_STATUS_OK;
}


/*
  work out the wire size of a dcerpc packet 
*/
static uint32 dcerpc_wire_size(struct dcerpc_packet *pkt)
{
	int i;
	uint32 size = 0;

	size += 16; /* header */

	switch (pkt->hdr.ptype) {
	case DCERPC_PKT_REQUEST:
		size += 8;
		size += pkt->in.request.stub_data.length;
		size += pkt->in.request.auth_verifier.length;
		break;

	case DCERPC_PKT_RESPONSE:
		size += 8;
		size += pkt->out.response.stub_data.length;
		size += pkt->hdr.auth_length;
		break;

	case DCERPC_PKT_BIND:
		size += 12;
		for (i=0;i<pkt->in.bind.num_contexts;i++) {
			size += 24;
			size += pkt->in.bind.ctx_list[i].num_transfer_syntaxes * 20;
		}
		size += pkt->hdr.auth_length;
		break;

	case DCERPC_PKT_BIND_ACK:
		size += 10;
		if (pkt->out.bind_ack.secondary_address) {
			size += strlen(pkt->out.bind_ack.secondary_address) + 1;
		}
		size += 4;
		size += pkt->out.bind_ack.num_results * 24;
		size += pkt->hdr.auth_length;
		break;
	}

	return size;
}

/* 
   push a dcerpc_packet into a blob. This handles both input and
   output packets
*/
NTSTATUS dcerpc_push(DATA_BLOB *blob, TALLOC_CTX *mem_ctx, struct dcerpc_packet *pkt)
{
	uint32 offset = 0;
	uint32 wire_size;
	NTSTATUS status;

	/* work out how big the packet will be on the wire */
	wire_size = dcerpc_wire_size(pkt);

	(*blob) = data_blob_talloc(mem_ctx, NULL, wire_size);
	if (!blob->data) {
		return NT_STATUS_NO_MEMORY;
	}

	pkt->hdr.frag_length = wire_size;

	dcerpc_push_hdr(blob->data + offset, &pkt->hdr);
	offset += 16;

	switch (pkt->hdr.ptype) {
	case DCERPC_PKT_BIND:
		status = dcerpc_push_bind(blob, &offset, &pkt->hdr, &pkt->in.bind);
		break;

	case DCERPC_PKT_REQUEST:
		status = dcerpc_push_request(blob, &offset, &pkt->hdr, &pkt->in.request);
		break;
		
	default:
		status = NT_STATUS_INVALID_LEVEL;
	}

	return status;
}




/* 
   fill in the fixed values in a dcerpc header 
*/
static void init_dcerpc_hdr(struct dcerpc_hdr *hdr)
{
        hdr->rpc_vers = 5;
        hdr->rpc_vers_minor = 0;
        hdr->drep[0] = 0x10; /* Little endian */
        hdr->drep[1] = 0;
        hdr->drep[2] = 0;
        hdr->drep[3] = 0;
}


/* 
   perform a bind using the given syntax 
*/
NTSTATUS dcerpc_bind(struct dcerpc_pipe *p, 
		     const struct dcerpc_syntax_id *syntax,
		     const struct dcerpc_syntax_id *transfer_syntax)
{
	TALLOC_CTX *mem_ctx;
        struct dcerpc_packet pkt;
	NTSTATUS status;
	DATA_BLOB blob;
	DATA_BLOB blob_out;

	mem_ctx = talloc_init("cli_dcerpc_bind");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	init_dcerpc_hdr(&pkt.hdr);

	pkt.hdr.ptype = DCERPC_PKT_BIND;
	pkt.hdr.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.hdr.call_id = p->call_id++;
	pkt.hdr.auth_length = 0;

        pkt.in.bind.max_xmit_frag = 0x2000;
        pkt.in.bind.max_recv_frag = 0x2000;
        pkt.in.bind.assoc_group_id = 0;
        pkt.in.bind.num_contexts = 1;
	pkt.in.bind.ctx_list = talloc(mem_ctx, sizeof(pkt.in.bind.ctx_list[0]));
	if (!pkt.in.bind.ctx_list) {
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	pkt.in.bind.ctx_list[0].context_id = 0;
	pkt.in.bind.ctx_list[0].num_transfer_syntaxes = 1;
	pkt.in.bind.ctx_list[0].abstract_syntax = *syntax;
	pkt.in.bind.ctx_list[0].transfer_syntaxes = transfer_syntax;

	pkt.in.bind.auth_verifier = data_blob(NULL, 0);

	status = dcerpc_push(&blob, mem_ctx, &pkt);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_destroy(mem_ctx);
		return status;
	}

	status = dcerpc_raw_packet(p, mem_ctx, &blob, &blob_out);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_destroy(mem_ctx);
		return status;
	}

	status = dcerpc_pull(&blob_out, mem_ctx, &pkt);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_destroy(mem_ctx);
		return status;
	}

	if (pkt.hdr.ptype != DCERPC_PKT_BIND_ACK) {
		status = NT_STATUS_UNSUCCESSFUL;
	}

	p->srv_max_xmit_frag = pkt.out.bind_ack.max_xmit_frag;
	p->srv_max_recv_frag = pkt.out.bind_ack.max_recv_frag;

	talloc_destroy(mem_ctx);

	return status;	
}

static const struct {
	const char *name;
	struct dcerpc_syntax_id syntax;
	const struct dcerpc_syntax_id transfer_syntax;
} known_pipes[] = {
	{ "lsarpc"  , { "12345778-1234-abcd-ef00-0123456789ab", 0 }, DCERPC_TRANSFER_SYNTAX_V2 },
	{ "samr"    , { "12345778-1234-abcd-ef00-0123456789ac", 1 }, DCERPC_TRANSFER_SYNTAX_V2 },
	{ "netlogon", { "12345778-1234-abcd-ef00-01234567cffb", 1 }, DCERPC_TRANSFER_SYNTAX_V2 },
	{ "srvsvc"  , { "4b324fc8-1670-01d3-1278-5a47bf6ee188", 3 }, DCERPC_TRANSFER_SYNTAX_V2 },
	{ "wkssvc"  , { "6bffd098-a112-3610-9833-46c3f87e345a", 1 }, DCERPC_TRANSFER_SYNTAX_V2 },
	{ "winreg"  , { "338cd001-2244-31f1-aaaa-900038001003", 1 }, DCERPC_TRANSFER_SYNTAX_V2 },
	{ "spoolss" , { "12345678-1234-abcd-ef00-0123456789ab", 1 }, DCERPC_TRANSFER_SYNTAX_V2 },
	{ "netdfs"  , { "4fc742e0-4a10-11cf-8273-00aa004ae673", 3 }, DCERPC_TRANSFER_SYNTAX_V2 },
	{ "rpcecho" , { "60a15ec5-4de8-11d7-a637-005056a20182", 1 }, DCERPC_TRANSFER_SYNTAX_V2 },
	{ NULL         , }
};


/* Perform a bind using the given well-known pipe name */
NTSTATUS cli_dcerpc_bind_byname(struct dcerpc_pipe *p, const char *pipe_name)
{
	int i;

	for (i=0; known_pipes[i].name; i++) {
		if (strcasecmp(known_pipes[i].name, pipe_name) == 0)
			break;
	}
	
	if (known_pipes[i].name == NULL) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	return dcerpc_bind(p, &known_pipes[i].syntax, &known_pipes[i].transfer_syntax);
}

/*
  perform a full request/response pair on a dcerpc pipe
*/
NTSTATUS cli_dcerpc_request(struct dcerpc_pipe *p, 
			    uint16 opnum,
			    TALLOC_CTX *mem_ctx,
			    DATA_BLOB *stub_data_in,
			    DATA_BLOB *stub_data_out)
{
	
	struct dcerpc_packet pkt;
	NTSTATUS status;
	DATA_BLOB blob_in, blob_out, payload;

	init_dcerpc_hdr(&pkt.hdr);

	pkt.hdr.ptype = DCERPC_PKT_REQUEST;
	pkt.hdr.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.hdr.call_id = p->call_id++;
	pkt.hdr.auth_length = 0;

	pkt.in.request.context_id = 0;
	pkt.in.request.opnum = opnum;
	pkt.in.request.stub_data = *stub_data_in;
	pkt.in.request.auth_verifier = data_blob(NULL, 0);

	status = dcerpc_push(&blob_in, mem_ctx, &pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = dcerpc_raw_packet(p, mem_ctx, &blob_in, &blob_out);

	status = dcerpc_pull(&blob_out, mem_ctx, &pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (pkt.hdr.ptype != DCERPC_PKT_RESPONSE) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!(pkt.hdr.pfc_flags & DCERPC_PFC_FLAG_FIRST)) {
		/* something is badly wrong! */
		return NT_STATUS_UNSUCCESSFUL;
	}

	payload = pkt.out.response.stub_data;

	/* continue receiving fragments */
	while (!(pkt.hdr.pfc_flags & DCERPC_PFC_FLAG_LAST)) {
		uint32 length;

		status = dcerpc_raw_packet_secondary(p, mem_ctx, &blob_out);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		status = dcerpc_pull(&blob_out, mem_ctx, &pkt);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		if (pkt.hdr.pfc_flags & DCERPC_PFC_FLAG_FIRST) {
			/* start of another packet!? */
			return NT_STATUS_UNSUCCESSFUL;
		}

		if (pkt.hdr.ptype != DCERPC_PKT_RESPONSE) {
			return NT_STATUS_UNSUCCESSFUL;
		}

		length = pkt.out.response.stub_data.length;

		payload.data = talloc_realloc(mem_ctx, 
					      payload.data, 
					      payload.length + length);
		if (!payload.data) {
			return NT_STATUS_NO_MEMORY;
		}

		memcpy(payload.data + payload.length,
		       pkt.out.response.stub_data.data,
		       length);

		payload.length += length;
	}

	if (stub_data_out) {
		*stub_data_out = payload;
	}

	return status;
}


/*
  a useful helper function for synchronous rpc requests
*/
NTSTATUS dcerpc_ndr_request(struct dcerpc_pipe *p,
			    uint32 opnum,
			    TALLOC_CTX *mem_ctx,
			    NTSTATUS (*ndr_push)(struct ndr_push *, void *),
			    NTSTATUS (*ndr_pull)(struct ndr_pull *, void *),
			    void *struct_ptr)
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
	status = ndr_push(push, struct_ptr);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	/* retrieve the blob */
	request = ndr_push_blob(push);

	/* make the actual dcerpc request */
	status = cli_dcerpc_request(p, opnum, mem_ctx, &request, &response);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	/* prepare for ndr_pull_* */
	pull = ndr_pull_init_blob(&response, mem_ctx);
	if (!pull) {
		goto failed;
	}

	/* pull the structure from the blob */
	status = ndr_pull(pull, struct_ptr);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

failed:
	ndr_push_free(push);
	return status;
}
