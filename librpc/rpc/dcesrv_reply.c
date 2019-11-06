/*
   Unix SMB/CIFS implementation.

   server side dcerpc common code

   Copyright (C) Andrew Tridgell 2003-2010
   Copyright (C) Stefan (metze) Metzmacher 2004-2005

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
#include "librpc/rpc/dcesrv_core.h"
#include "librpc/rpc/dcesrv_core_proto.h"
#include "auth/gensec/gensec.h"
#include "lib/util/dlinklist.h"
#include "param/param.h"

/*
  move a call from an existing linked list to the specified list. This
  prevents bugs where we forget to remove the call from a previous
  list when moving it.
 */
static void dcesrv_call_set_list(struct dcesrv_call_state *call,
				 enum dcesrv_call_list list)
{
	switch (call->list) {
	case DCESRV_LIST_NONE:
		break;
	case DCESRV_LIST_CALL_LIST:
		DLIST_REMOVE(call->conn->call_list, call);
		break;
	case DCESRV_LIST_FRAGMENTED_CALL_LIST:
		DLIST_REMOVE(call->conn->incoming_fragmented_call_list, call);
		break;
	case DCESRV_LIST_PENDING_CALL_LIST:
		DLIST_REMOVE(call->conn->pending_call_list, call);
		break;
	}
	call->list = list;
	switch (list) {
	case DCESRV_LIST_NONE:
		break;
	case DCESRV_LIST_CALL_LIST:
		DLIST_ADD_END(call->conn->call_list, call);
		break;
	case DCESRV_LIST_FRAGMENTED_CALL_LIST:
		DLIST_ADD_END(call->conn->incoming_fragmented_call_list, call);
		break;
	case DCESRV_LIST_PENDING_CALL_LIST:
		DLIST_ADD_END(call->conn->pending_call_list, call);
		break;
	}
}


void dcesrv_init_hdr(struct ncacn_packet *pkt, bool bigendian)
{
	pkt->rpc_vers = 5;
	pkt->rpc_vers_minor = 0;
	if (bigendian) {
		pkt->drep[0] = 0;
	} else {
		pkt->drep[0] = DCERPC_DREP_LE;
	}
	pkt->drep[1] = 0;
	pkt->drep[2] = 0;
	pkt->drep[3] = 0;
}


/*
  return a dcerpc fault
*/
NTSTATUS dcesrv_fault_with_flags(struct dcesrv_call_state *call,
				 uint32_t fault_code,
				 uint8_t extra_flags)
{
	struct ncacn_packet pkt;
	struct data_blob_list_item *rep;
	NTSTATUS status;

	/* setup a fault */
	dcesrv_init_hdr(&pkt, lpcfg_rpc_big_endian(call->conn->dce_ctx->lp_ctx));
	pkt.auth_length = 0;
	pkt.call_id = call->pkt.call_id;
	pkt.ptype = DCERPC_PKT_FAULT;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST | extra_flags;
	pkt.u.fault.alloc_hint = 24;
	if (call->context != NULL) {
		pkt.u.fault.context_id = call->context->context_id;
	} else {
		pkt.u.fault.context_id = 0;
	}
	pkt.u.fault.cancel_count = 0;
	pkt.u.fault.flags = 0;
	pkt.u.fault.status = fault_code;
	pkt.u.fault.reserved = 0;
	pkt.u.fault.error_and_verifier = data_blob_null;

	rep = talloc_zero(call, struct data_blob_list_item);
	if (!rep) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dcerpc_ncacn_push_auth(&rep->blob, call, &pkt, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dcerpc_set_frag_length(&rep->blob, rep->blob.length);

	DLIST_ADD_END(call->replies, rep);
	dcesrv_call_set_list(call, DCESRV_LIST_CALL_LIST);

	if (call->conn->call_list && call->conn->call_list->replies) {
		if (call->conn->transport.report_output_data) {
			call->conn->transport.report_output_data(call->conn);
		}
	}

	return NT_STATUS_OK;
}

NTSTATUS dcesrv_fault(struct dcesrv_call_state *call, uint32_t fault_code)
{
	return dcesrv_fault_with_flags(call, fault_code, 0);
}

_PUBLIC_ NTSTATUS dcesrv_reply(struct dcesrv_call_state *call)
{
	struct ndr_push *push;
	NTSTATUS status;
	DATA_BLOB stub;
	uint32_t total_length, chunk_size;
	struct dcesrv_connection_context *context = call->context;
	struct dcesrv_auth *auth = call->auth_state;
	size_t sig_size = 0;

	/* call the reply function */
	status = context->iface->reply(call, call, call->r);
	if (!NT_STATUS_IS_OK(status)) {
		return dcesrv_fault(call, call->fault_code);
	}

	/* form the reply NDR */
	push = ndr_push_init_ctx(call);
	NT_STATUS_HAVE_NO_MEMORY(push);

	/* carry over the pointer count to the reply in case we are
	   using full pointer. See NDR specification for full
	   pointers */
	push->ptr_count = call->ndr_pull->ptr_count;

	if (lpcfg_rpc_big_endian(call->conn->dce_ctx->lp_ctx)) {
		push->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	status = context->iface->ndr_push(call, call, push, call->r);
	if (!NT_STATUS_IS_OK(status)) {
		return dcesrv_fault(call, call->fault_code);
	}

	stub = ndr_push_blob(push);

	dcesrv_save_ndr_fuzz_seed(stub,
				  call,
				  NDR_OUT);

	total_length = stub.length;

	/* we can write a full max_recv_frag size, minus the dcerpc
	   request header size */
	chunk_size = call->conn->max_xmit_frag;
	chunk_size -= DCERPC_REQUEST_LENGTH;
	if (auth->auth_finished && auth->gensec_security != NULL) {
		size_t max_payload = chunk_size;

		max_payload -= DCERPC_AUTH_TRAILER_LENGTH;
		max_payload -= (max_payload % DCERPC_AUTH_PAD_ALIGNMENT);

		sig_size = gensec_sig_size(auth->gensec_security,
					   max_payload);
		if (sig_size) {
			chunk_size -= DCERPC_AUTH_TRAILER_LENGTH;
			chunk_size -= sig_size;
		}
	}
	chunk_size -= (chunk_size % DCERPC_AUTH_PAD_ALIGNMENT);

	do {
		uint32_t length;
		struct data_blob_list_item *rep;
		struct ncacn_packet pkt;
		bool ok;

		rep = talloc_zero(call, struct data_blob_list_item);
		NT_STATUS_HAVE_NO_MEMORY(rep);

		length = MIN(chunk_size, stub.length);

		/* form the dcerpc response packet */
		dcesrv_init_hdr(&pkt,
				lpcfg_rpc_big_endian(call->conn->dce_ctx->lp_ctx));
		pkt.auth_length = 0;
		pkt.call_id = call->pkt.call_id;
		pkt.ptype = DCERPC_PKT_RESPONSE;
		pkt.pfc_flags = 0;
		if (stub.length == total_length) {
			pkt.pfc_flags |= DCERPC_PFC_FLAG_FIRST;
		}
		if (length == stub.length) {
			pkt.pfc_flags |= DCERPC_PFC_FLAG_LAST;
		}
		pkt.u.response.alloc_hint = stub.length;
		/*
		 * bug for bug, feature for feature...
		 *
		 * Windows truncates the context_id with & 0xFF,
		 * so we do.
		 */
		pkt.u.response.context_id = context->context_id & 0xFF;
		pkt.u.response.cancel_count = 0;
		pkt.u.response.stub_and_verifier.data = stub.data;
		pkt.u.response.stub_and_verifier.length = length;

		ok = dcesrv_auth_pkt_push(call, &rep->blob, sig_size,
					  DCERPC_RESPONSE_LENGTH,
					  &pkt.u.response.stub_and_verifier,
					  &pkt);
		if (!ok) {
			return dcesrv_fault(call, DCERPC_FAULT_OTHER);
		}

		dcerpc_set_frag_length(&rep->blob, rep->blob.length);

		DLIST_ADD_END(call->replies, rep);

		stub.data += length;
		stub.length -= length;
	} while (stub.length != 0);

	/* move the call from the pending to the finished calls list */
	dcesrv_call_set_list(call, DCESRV_LIST_CALL_LIST);

	if (call->conn->call_list && call->conn->call_list->replies) {
		if (call->conn->transport.report_output_data) {
			call->conn->transport.report_output_data(call->conn);
		}
	}

	return NT_STATUS_OK;
}
