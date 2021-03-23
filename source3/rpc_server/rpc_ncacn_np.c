/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998,
 *  Largely re-written : 2005
 *  Copyright (C) Jeremy Allison		1998 - 2005
 *  Copyright (C) Simo Sorce			2010
 *  Copyright (C) Andrew Bartlett		2011
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "rpc_client/cli_pipe.h"
#include "rpc_dce.h"
#include "../libcli/named_pipe_auth/npa_tstream.h"
#include "rpc_server/rpc_ncacn_np.h"
#include "librpc/gen_ndr/netlogon.h"
#include "librpc/gen_ndr/auth.h"
#include "../auth/auth_sam_reply.h"
#include "../auth/auth_util.h"
#include "auth.h"
#include "rpc_server/rpc_pipes.h"
#include "../lib/tsocket/tsocket.h"
#include "../lib/util/tevent_ntstatus.h"
#include "rpc_server/rpc_config.h"
#include "librpc/ndr/ndr_table.h"
#include "rpc_server/rpc_server.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

struct np_proxy_state {
	uint16_t file_type;
	uint16_t device_state;
	uint64_t allocation_size;
	struct tstream_context *npipe;
	struct tevent_queue *read_queue;
	struct tevent_queue *write_queue;
};

static struct np_proxy_state *make_external_rpc_pipe_p(TALLOC_CTX *mem_ctx,
				const char *pipe_name,
				const struct tsocket_address *remote_address,
				const struct tsocket_address *local_address,
				const struct auth_session_info *session_info);

static struct npa_state *npa_state_init(TALLOC_CTX *mem_ctx)
{
	struct npa_state *npa;

	npa = talloc_zero(mem_ctx, struct npa_state);
	if (npa == NULL) {
		return NULL;
	}

	npa->read_queue = tevent_queue_create(npa, "npa_cli_read");
	if (npa->read_queue == NULL) {
		DEBUG(0, ("tevent_queue_create failed\n"));
		goto fail;
	}

	npa->write_queue = tevent_queue_create(npa, "npa_cli_write");
	if (npa->write_queue == NULL) {
		DEBUG(0, ("tevent_queue_create failed\n"));
		goto fail;
	}

	return npa;
fail:
	talloc_free(npa);
	return NULL;
}

NTSTATUS make_internal_rpc_pipe_socketpair(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev_ctx,
	struct messaging_context *msg_ctx,
	struct dcesrv_context *dce_ctx,
	struct dcesrv_endpoint *endpoint,
	const struct tsocket_address *remote_address,
	const struct tsocket_address *local_address,
	const struct auth_session_info *session_info,
	struct npa_state **pnpa)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	struct dcerpc_ncacn_conn *ncacn_conn = NULL;
	struct dcesrv_connection *dcesrv_conn = NULL;
	struct npa_state *npa;
	NTSTATUS status;
	int error;
	int rc;
	enum dcerpc_transport_t transport = dcerpc_binding_get_transport(
			endpoint->ep_description);
	const char *pipe_name = dcerpc_binding_get_string_option(
			endpoint->ep_description, "endpoint");

	DEBUG(4, ("Create of internal pipe %s requested\n", pipe_name));

	npa = npa_state_init(tmp_ctx);
	if (npa == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	npa->file_type = FILE_TYPE_MESSAGE_MODE_PIPE;
	npa->device_state = 0xff | 0x0400 | 0x0100;
	npa->allocation_size = 4096;

	status = dcerpc_ncacn_conn_init(npa,
					ev_ctx,
					msg_ctx,
					dce_ctx,
					endpoint,
					NULL, /* termination fn */
					NULL, /* termination data */
					&ncacn_conn);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	npa->private_data = (void*)ncacn_conn;

	rc = tstream_npa_socketpair(npa->file_type,
				    npa,
				    &npa->stream,
				    ncacn_conn,
				    &ncacn_conn->tstream);
	if (rc == -1) {
		status = map_nt_error_from_unix(errno);
		goto out;
	}

	ncacn_conn->remote_client_addr = tsocket_address_copy(remote_address,
			ncacn_conn);
	if (ncacn_conn->remote_client_addr == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ncacn_conn->remote_client_name = tsocket_address_inet_addr_string(
			ncacn_conn->remote_client_addr, ncacn_conn);
	if (ncacn_conn->remote_client_name == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ncacn_conn->local_server_addr = tsocket_address_copy(local_address,
			ncacn_conn);
	if (ncacn_conn->local_server_addr == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ncacn_conn->local_server_name = tsocket_address_inet_addr_string(
		ncacn_conn->local_server_addr, ncacn_conn);
	if (ncacn_conn->local_server_name == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ncacn_conn->session_info = copy_session_info(ncacn_conn, session_info);
	if (ncacn_conn->session_info == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	rc = make_server_pipes_struct(ncacn_conn,
				      ncacn_conn->msg_ctx,
				      pipe_name,
				      transport,
				      ncacn_conn->remote_client_addr,
				      ncacn_conn->local_server_addr,
				      &ncacn_conn->p,
				      &error);
	if (rc == -1) {
		status = map_nt_error_from_unix(error);
		goto out;
	}

	/*
	 * This fills in dcesrv_conn->endpoint with the endpoint
	 * associated with the socket.  From this point on we know
	 * which (group of) services we are handling, but not the
	 * specific interface.
	 */
	status = dcesrv_endpoint_connect(ncacn_conn->dce_ctx,
					 ncacn_conn,
					 ncacn_conn->endpoint,
					 ncacn_conn->session_info,
					 ncacn_conn->ev_ctx,
					 DCESRV_CALL_STATE_FLAG_MAY_ASYNC,
					 &dcesrv_conn);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to connect to endpoint: %s\n",
			nt_errstr(status));
		goto out;
	}

	dcesrv_conn->transport.private_data = ncacn_conn;
	dcesrv_conn->transport.report_output_data =
		dcesrv_sock_report_output_data;
	dcesrv_conn->transport.terminate_connection =
		dcesrv_transport_terminate_connection;
	dcesrv_conn->send_queue = tevent_queue_create(dcesrv_conn,
						      "dcesrv send queue");
	if (dcesrv_conn->send_queue == NULL) {
		status = NT_STATUS_NO_MEMORY;
		DBG_ERR("Failed to create send queue: %s\n",
			nt_errstr(status));
		goto out;
	}

	dcesrv_conn->stream = talloc_move(dcesrv_conn, &ncacn_conn->tstream);
	dcesrv_conn->local_address = ncacn_conn->local_server_addr;
	dcesrv_conn->remote_address = ncacn_conn->remote_client_addr;

	status = dcesrv_connection_loop_start(dcesrv_conn);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to start dcesrv_connection loop: %s\n",
			nt_errstr(status));
		goto out;
	}

	*pnpa = talloc_move(mem_ctx, &npa);
	status = NT_STATUS_OK;
out:
	talloc_free(tmp_ctx);
	return status;
}

static NTSTATUS make_internal_ncacn_conn(TALLOC_CTX *mem_ctx,
				const struct ndr_interface_table *table,
				const struct tsocket_address *remote_address,
				const struct tsocket_address *local_address,
				const struct auth_session_info *session_info,
				struct messaging_context *msg_ctx,
				struct dcerpc_ncacn_conn **_out)
{
	struct dcerpc_ncacn_conn *ncacn_conn = NULL;
	const char *pipe_name = NULL;
	NTSTATUS status;
	int ret;

	pipe_name = dcerpc_default_transport_endpoint(mem_ctx,
						      NCACN_NP,
						      table);

	DBG_INFO("Create pipe requested %s\n", pipe_name);

	ncacn_conn = talloc_zero(mem_ctx, struct dcerpc_ncacn_conn);
	if (ncacn_conn == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ncacn_conn->msg_ctx = msg_ctx;

	if (remote_address != NULL) {
		ncacn_conn->remote_client_addr =
			tsocket_address_copy(remote_address, ncacn_conn);
		if (ncacn_conn->remote_client_addr == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
	}

	if (local_address != NULL) {
		ncacn_conn->local_server_addr =
			tsocket_address_copy(local_address, ncacn_conn);
		if (ncacn_conn->local_server_addr == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
	}

	ncacn_conn->session_info = copy_session_info(ncacn_conn, session_info);
	if (ncacn_conn->session_info == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	ret = make_base_pipes_struct(ncacn_conn,
				     msg_ctx,
				     pipe_name,
				     NCALRPC,
				     ncacn_conn->remote_client_addr,
				     ncacn_conn->local_server_addr,
				     &ncacn_conn->p);
	if (ret) {
		DBG_ERR("No memory for pipes_struct!\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	DEBUG(4,("Created internal pipe %s\n", pipe_name));

	*_out = ncacn_conn;

	return NT_STATUS_OK;

fail:
	talloc_free(ncacn_conn);
	return status;
}

static NTSTATUS find_ncalrpc_default_endpoint(struct dcesrv_context *dce_ctx,
					      struct dcesrv_endpoint **ep)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct dcerpc_binding *binding = NULL;
	const char *ep_description = NULL;
	NTSTATUS status;

	tmp_ctx = talloc_new(dce_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Some services use a rpcint binding handle in their initialization,
	 * before the server is fully initialized. Search the NCALRPC endpoint
	 * with and without endpoint
	 */
	status = dcerpc_parse_binding(tmp_ctx, "ncalrpc:", &binding);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	status = dcesrv_find_endpoint(dce_ctx, binding, ep);
	if (NT_STATUS_IS_OK(status)) {
		goto out;
	}

	if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC) {
		ep_description = "ncalrpc:[SMBD]";
	} else {
		ep_description = "ncalrpc:[DEFAULT]";
	}

	status = dcerpc_parse_binding(tmp_ctx, ep_description, &binding);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	status = dcesrv_find_endpoint(dce_ctx, binding, ep);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

out:
	talloc_free(tmp_ctx);
	return status;
}

static NTSTATUS make_internal_dcesrv_connection(TALLOC_CTX *mem_ctx,
				const struct ndr_interface_table *ndr_table,
				struct dcerpc_ncacn_conn *ncacn_conn,
				struct dcesrv_connection **_out)
{
	struct dcesrv_connection *conn = NULL;
	struct dcesrv_connection_context *context = NULL;
	struct dcesrv_endpoint *endpoint = NULL;
	NTSTATUS status;

	conn = talloc_zero(mem_ctx, struct dcesrv_connection);
	if (conn == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	conn->dce_ctx = global_dcesrv_context();
	conn->preferred_transfer = &ndr_transfer_syntax_ndr;
	conn->transport.private_data = ncacn_conn;

	status = find_ncalrpc_default_endpoint(conn->dce_ctx, &endpoint);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	conn->endpoint = endpoint;

	conn->default_auth_state = talloc_zero(conn, struct dcesrv_auth);
	if (conn->default_auth_state == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	conn->default_auth_state->session_info = ncacn_conn->session_info;
	conn->default_auth_state->auth_finished = true;

	context = talloc_zero(conn, struct dcesrv_connection_context);
	if (context == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	context->conn = conn;
	context->context_id = 0;
	context->transfer_syntax = *(conn->preferred_transfer);
	context->iface = find_interface_by_uuid(conn->endpoint,
					&ndr_table->syntax_id.uuid,
					ndr_table->syntax_id.if_version);
	if (context->iface == NULL) {
		status = NT_STATUS_RPC_INTERFACE_NOT_FOUND;
		goto fail;
	}

	DLIST_ADD(conn->contexts, context);

	*_out = conn;

	return NT_STATUS_OK;
fail:
	talloc_free(conn);
	return status;
}

static NTSTATUS rpcint_dispatch(struct dcesrv_call_state *call)
{
	NTSTATUS status;
	struct ndr_pull *pull = NULL;
	struct ndr_push *push = NULL;
	struct data_blob_list_item *rep = NULL;

	pull = ndr_pull_init_blob(&call->pkt.u.request.stub_and_verifier,
				  call);
	if (pull == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	pull->flags |= LIBNDR_FLAG_REF_ALLOC;

	call->ndr_pull = pull;

	/* unravel the NDR for the packet */
	status = call->context->iface->ndr_pull(call, call, pull, &call->r);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("DCE/RPC fault in call %s:%02X - %s\n",
			call->context->iface->name,
			call->pkt.u.request.opnum,
			dcerpc_errstr(call, call->fault_code));
		return status;
	}

	status = call->context->iface->local(call, call, call->r);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("DCE/RPC fault in call %s:%02X - %s\n",
			call->context->iface->name,
			call->pkt.u.request.opnum,
			dcerpc_errstr(call, call->fault_code));
		return status;
	}

	push = ndr_push_init_ctx(call);
	if (push == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	push->ptr_count = call->ndr_pull->ptr_count;

	status = call->context->iface->ndr_push(call, call, push, call->r);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("DCE/RPC fault in call %s:%02X - %s\n",
			call->context->iface->name,
			call->pkt.u.request.opnum,
			dcerpc_errstr(call, call->fault_code));
		return status;
	}

	rep = talloc_zero(call, struct data_blob_list_item);
	if (rep == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	rep->blob = ndr_push_blob(push);
	DLIST_ADD_END(call->replies, rep);

	return NT_STATUS_OK;
}

struct rpcint_bh_state {
	struct dcesrv_connection *conn;
};

static bool rpcint_bh_is_connected(struct dcerpc_binding_handle *h)
{
	struct rpcint_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct rpcint_bh_state);

	if (hs->conn == NULL) {
		return false;
	}

	return true;
}

static uint32_t rpcint_bh_set_timeout(struct dcerpc_binding_handle *h,
				      uint32_t timeout)
{
	/* TODO: implement timeouts */
	return UINT32_MAX;
}

struct rpcint_bh_raw_call_state {
	struct dcesrv_call_state *call;
};

static struct tevent_req *rpcint_bh_raw_call_send(TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct dcerpc_binding_handle *h,
						  const struct GUID *object,
						  uint32_t opnum,
						  uint32_t in_flags,
						  const uint8_t *in_data,
						  size_t in_length)
{
	struct rpcint_bh_state *hs =
		dcerpc_binding_handle_data(h,
		struct rpcint_bh_state);
	struct tevent_req *req;
	struct rpcint_bh_raw_call_state *state;
	struct dcesrv_context *dce_ctx = global_dcesrv_context();
	bool ok;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct rpcint_bh_raw_call_state);
	if (req == NULL) {
		return NULL;
	}

	ok = rpcint_bh_is_connected(h);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_CONNECTION_DISCONNECTED);
		return tevent_req_post(req, ev);
	}

	state->call = talloc_zero(state, struct dcesrv_call_state);
	if (tevent_req_nomem(state->call, req)) {
		return tevent_req_post(req, ev);
	}

	state->call->event_ctx = ev;
	state->call->conn = hs->conn;
	state->call->context = hs->conn->contexts;
	state->call->auth_state = hs->conn->default_auth_state;

	if (hs->conn->assoc_group == NULL) {
		ZERO_STRUCT(state->call->pkt);
		state->call->pkt.u.bind.assoc_group_id = 0;
		status = dce_ctx->callbacks.assoc_group.find(state->call);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
	}

	ZERO_STRUCT(state->call->pkt);
	state->call->pkt.u.request.opnum = opnum;
	state->call->pkt.u.request.context_id = 0;
	state->call->pkt.u.request.stub_and_verifier.data = discard_const_p(uint8_t, in_data);
	state->call->pkt.u.request.stub_and_verifier.length = in_length;

	/* TODO: allow async */
	status = rpcint_dispatch(state->call);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS rpcint_bh_raw_call_recv(struct tevent_req *req,
					TALLOC_CTX *mem_ctx,
					uint8_t **out_data,
					size_t *out_length,
					uint32_t *out_flags)
{
	struct rpcint_bh_raw_call_state *state =
		tevent_req_data(req,
		struct rpcint_bh_raw_call_state);
	struct data_blob_list_item *rep = NULL;
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	rep = state->call->replies;
	DLIST_REMOVE(state->call->replies, rep);

	*out_data = talloc_steal(mem_ctx, rep->blob.data);
	*out_length = rep->blob.length;
	*out_flags = 0;

	talloc_free(rep);

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct rpcint_bh_disconnect_state {
	uint8_t _dummy;
};

static struct tevent_req *rpcint_bh_disconnect_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct dcerpc_binding_handle *h)
{
	struct rpcint_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct rpcint_bh_state);
	struct tevent_req *req;
	struct rpcint_bh_disconnect_state *state;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct rpcint_bh_disconnect_state);
	if (req == NULL) {
		return NULL;
	}

	ok = rpcint_bh_is_connected(h);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_CONNECTION_DISCONNECTED);
		return tevent_req_post(req, ev);
	}

	/*
	 * TODO: do a real async disconnect ...
	 *
	 * For now the caller needs to free dcesrv_connection
	 */
	hs->conn = NULL;

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS rpcint_bh_disconnect_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

static bool rpcint_bh_ref_alloc(struct dcerpc_binding_handle *h)
{
	return true;
}

static void rpcint_bh_do_ndr_print(struct dcerpc_binding_handle *h,
				   int ndr_flags,
				   const void *_struct_ptr,
				   const struct ndr_interface_call *call)
{
	void *struct_ptr = discard_const(_struct_ptr);

	if (DEBUGLEVEL < 11) {
		return;
	}

	if (ndr_flags & NDR_IN) {
		ndr_print_function_debug(call->ndr_print,
					 call->name,
					 ndr_flags,
					 struct_ptr);
	}
	if (ndr_flags & NDR_OUT) {
		ndr_print_function_debug(call->ndr_print,
					 call->name,
					 ndr_flags,
					 struct_ptr);
	}
}

static const struct dcerpc_binding_handle_ops rpcint_bh_ops = {
	.name			= "rpcint",
	.is_connected		= rpcint_bh_is_connected,
	.set_timeout		= rpcint_bh_set_timeout,
	.raw_call_send		= rpcint_bh_raw_call_send,
	.raw_call_recv		= rpcint_bh_raw_call_recv,
	.disconnect_send	= rpcint_bh_disconnect_send,
	.disconnect_recv	= rpcint_bh_disconnect_recv,

	.ref_alloc		= rpcint_bh_ref_alloc,
	.do_ndr_print		= rpcint_bh_do_ndr_print,
};

static NTSTATUS rpcint_binding_handle_ex(TALLOC_CTX *mem_ctx,
			const struct ndr_syntax_id *abstract_syntax,
			const struct ndr_interface_table *ndr_table,
			const struct tsocket_address *remote_address,
			const struct tsocket_address *local_address,
			const struct auth_session_info *session_info,
			struct messaging_context *msg_ctx,
			struct dcerpc_binding_handle **binding_handle)
{
	struct dcerpc_binding_handle *h;
	struct rpcint_bh_state *hs;
	struct dcerpc_ncacn_conn *ncacn_conn = NULL;
	NTSTATUS status;

	h = dcerpc_binding_handle_create(mem_ctx,
					 &rpcint_bh_ops,
					 NULL,
					 ndr_table,
					 &hs,
					 struct rpcint_bh_state,
					 __location__);
	if (h == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = make_internal_ncacn_conn(hs,
					  ndr_table,
					  remote_address,
					  local_address,
					  session_info,
					  msg_ctx,
					  &ncacn_conn);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(h);
		return status;
	}

	status = make_internal_dcesrv_connection(ncacn_conn,
						 ndr_table,
						 ncacn_conn,
						 &hs->conn);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(h);
		return status;
	}

	*binding_handle = h;
	return NT_STATUS_OK;
}
/**
 * @brief Create a new DCERPC Binding Handle which uses a local dispatch function.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @param[in]  ndr_table Normally the ndr_table_<name>.
 *
 * @param[in]  remote_address The info about the connected client.
 *
 * @param[in]  serversupplied_info The server supplied authentication function.
 *
 * @param[in]  msg_ctx   The messaging context that can be used by the server
 *
 * @param[out] binding_handle  A pointer to store the connected
 *                             dcerpc_binding_handle
 *
 * @return              NT_STATUS_OK on success, a corresponding NT status if an
 *                      error occurred.
 *
 * @code
 *   struct dcerpc_binding_handle *winreg_binding;
 *   NTSTATUS status;
 *
 *   status = rpcint_binding_handle(tmp_ctx,
 *                                  &ndr_table_winreg,
 *                                  p->remote_address,
 *                                  p->session_info,
 *                                  p->msg_ctx
 *                                  &winreg_binding);
 * @endcode
 */
NTSTATUS rpcint_binding_handle(TALLOC_CTX *mem_ctx,
			       const struct ndr_interface_table *ndr_table,
			       const struct tsocket_address *remote_address,
			       const struct tsocket_address *local_address,
			       const struct auth_session_info *session_info,
			       struct messaging_context *msg_ctx,
			       struct dcerpc_binding_handle **binding_handle)
{
	return rpcint_binding_handle_ex(mem_ctx, NULL, ndr_table, remote_address,
					local_address, session_info,
					msg_ctx, binding_handle);
}

/**
 * @internal
 *
 * @brief Create a new RPC client context which uses a local transport.
 *
 * This creates a local transport. It is a shortcut to directly call the server
 * functions and avoid marshalling.
 * NOTE: this function should be used only by rpc_pipe_open_interface()
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @param[in]  ndr_table the ndr_table_<name> structure.
 *
 * @param[in]  serversupplied_info The server supplied authentication function.
 *
 * @param[in]  remote_address The client address information.
 *
 * @param[in]  msg_ctx  The messaging context to use.
 *
 * @param[out] presult  A pointer to store the connected rpc client pipe.
 *
 * @return              NT_STATUS_OK on success, a corresponding NT status if an
 *                      error occurred.
 */
NTSTATUS rpc_pipe_open_internal(TALLOC_CTX *mem_ctx,
				const struct ndr_interface_table *ndr_table,
				const struct auth_session_info *session_info,
				const struct tsocket_address *remote_address,
				const struct tsocket_address *local_address,
				struct messaging_context *msg_ctx,
				struct rpc_pipe_client **presult)
{
	struct rpc_pipe_client *result;
	NTSTATUS status;

	result = talloc_zero(mem_ctx, struct rpc_pipe_client);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result->abstract_syntax = ndr_table->syntax_id;
	result->transfer_syntax = ndr_transfer_syntax_ndr;

	if (remote_address == NULL) {
		struct tsocket_address *local;
		int rc;

		rc = tsocket_address_inet_from_strings(mem_ctx,
						       "ip",
						       "127.0.0.1",
						       0,
						       &local);
		if (rc < 0) {
			TALLOC_FREE(result);
			return NT_STATUS_NO_MEMORY;
		}

		remote_address = local;
	}

	result->max_xmit_frag = -1;

	status = rpcint_binding_handle(result,
				       ndr_table,
				       remote_address,
				       local_address,
				       session_info,
				       msg_ctx,
				       &result->binding_handle);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(result);
		return status;
	}

	*presult = result;
	return NT_STATUS_OK;
}

/****************************************************************************
 * External pipes functions
 ***************************************************************************/

NTSTATUS make_external_rpc_pipe(TALLOC_CTX *mem_ctx,
				const char *pipe_name,
				const struct tsocket_address *remote_client_address,
				const struct tsocket_address *local_server_address,
				const struct auth_session_info *session_info,
				struct npa_state **pnpa)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	struct auth_session_info_transport *session_info_t;
	struct tevent_context *ev_ctx;
	struct tevent_req *subreq;
	const char *socket_np_dir;
	const char *socket_dir;
	struct npa_state *npa;
	int sys_errno;
	NTSTATUS status;
	int rc = -1;
	bool ok;

	npa = npa_state_init(tmp_ctx);
	if (npa == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	socket_dir = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					  "external_rpc_pipe",
					  "socket_dir",
					  lp_ncalrpc_dir());
	if (socket_dir == NULL) {
		DEBUG(0, ("external_rpc_pipe: socket_dir not set\n"));
		status = NT_STATUS_PIPE_NOT_AVAILABLE;
		goto out;
	}

	socket_np_dir = talloc_asprintf(tmp_ctx, "%s/np", socket_dir);
	if (socket_np_dir == NULL) {
		DEBUG(0, ("talloc_asprintf failed\n"));
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	session_info_t = talloc_zero(tmp_ctx,
				     struct auth_session_info_transport);
	if (session_info_t == NULL) {
		DEBUG(0, ("talloc failed\n"));
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	session_info_t->session_info = copy_session_info(session_info_t,
							 session_info);
	if (session_info_t->session_info == NULL) {
		DEBUG(0, ("copy_session_info failed\n"));
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ev_ctx = samba_tevent_context_init(tmp_ctx);
	if (ev_ctx == NULL) {
		DEBUG(0, ("samba_tevent_context_init failed\n"));
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	become_root();
	subreq = tstream_npa_connect_send(tmp_ctx,
					  ev_ctx,
					  socket_np_dir,
					  pipe_name,
					  remote_client_address,
					  NULL, /* client_name */
					  local_server_address,
					  NULL, /* server_name */
					  session_info_t);
	if (subreq == NULL) {
		unbecome_root();
		DEBUG(0, ("tstream_npa_connect_send to %s for pipe %s and "
			  "user %s\\%s failed\n",
			  socket_np_dir, pipe_name, session_info_t->session_info->info->domain_name,
			  session_info_t->session_info->info->account_name));
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto out;
	}
	ok = tevent_req_poll(subreq, ev_ctx);
	unbecome_root();
	if (!ok) {
		DEBUG(0, ("tevent_req_poll to %s for pipe %s and user %s\\%s "
			  "failed for tstream_npa_connect: %s\n",
			  socket_np_dir,
			  pipe_name,
			  session_info_t->session_info->info->domain_name,
			  session_info_t->session_info->info->account_name,
			  strerror(errno)));
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto out;
	}

	rc = tstream_npa_connect_recv(subreq,
				      &sys_errno,
				      npa,
				      &npa->stream,
				      &npa->file_type,
				      &npa->device_state,
				      &npa->allocation_size);
	talloc_free(subreq);
	if (rc != 0) {
		int l = 1;

		if (errno == ENOENT) {
			l = 2;
		}

		DEBUG(l, ("tstream_npa_connect_recv  to %s for pipe %s and "
			  "user %s\\%s failed: %s\n",
			  socket_np_dir,
			  pipe_name,
			  session_info_t->session_info->info->domain_name,
			  session_info_t->session_info->info->account_name,
			  strerror(sys_errno)));
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto out;
	}

	*pnpa = talloc_steal(mem_ctx, npa);
	status = NT_STATUS_OK;
out:
	talloc_free(tmp_ctx);

	return status;
}

static struct np_proxy_state *make_external_rpc_pipe_p(TALLOC_CTX *mem_ctx,
				const char *pipe_name,
				const struct tsocket_address *remote_address,
				const struct tsocket_address *local_address,
				const struct auth_session_info *session_info)
{
	struct np_proxy_state *result;
	char *socket_np_dir;
	const char *socket_dir;
	struct tevent_context *ev;
	struct tevent_req *subreq;
	struct auth_session_info_transport *session_info_t;
	bool ok;
	int ret;
	int sys_errno;

	result = talloc(mem_ctx, struct np_proxy_state);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	result->read_queue = tevent_queue_create(result, "np_read");
	if (result->read_queue == NULL) {
		DEBUG(0, ("tevent_queue_create failed\n"));
		goto fail;
	}

	result->write_queue = tevent_queue_create(result, "np_write");
	if (result->write_queue == NULL) {
		DEBUG(0, ("tevent_queue_create failed\n"));
		goto fail;
	}

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		DEBUG(0, ("samba_tevent_context_init failed\n"));
		goto fail;
	}

	socket_dir = lp_parm_const_string(
		GLOBAL_SECTION_SNUM, "external_rpc_pipe", "socket_dir",
		lp_ncalrpc_dir());
	if (socket_dir == NULL) {
		DEBUG(0, ("external_rpc_pipe:socket_dir not set\n"));
		goto fail;
	}
	socket_np_dir = talloc_asprintf(talloc_tos(), "%s/np", socket_dir);
	if (socket_np_dir == NULL) {
		DEBUG(0, ("talloc_asprintf failed\n"));
		goto fail;
	}

	session_info_t = talloc_zero(talloc_tos(), struct auth_session_info_transport);
	if (session_info_t == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	session_info_t->session_info = copy_session_info(session_info_t,
							 session_info);
	if (session_info_t->session_info == NULL) {
		DEBUG(0, ("copy_session_info failed\n"));
		goto fail;
	}

	become_root();
	subreq = tstream_npa_connect_send(talloc_tos(), ev,
					  socket_np_dir,
					  pipe_name,
					  remote_address,
					  NULL, /* client_name */
					  local_address,
					  NULL, /* server_name */
					  session_info_t);
	if (subreq == NULL) {
		unbecome_root();
		DEBUG(0, ("tstream_npa_connect_send to %s for pipe %s and "
			  "user %s\\%s failed\n",
			  socket_np_dir, pipe_name, session_info_t->session_info->info->domain_name,
			  session_info_t->session_info->info->account_name));
		goto fail;
	}
	ok = tevent_req_poll(subreq, ev);
	unbecome_root();
	if (!ok) {
		DEBUG(0, ("tevent_req_poll to %s for pipe %s and user %s\\%s "
			  "failed for tstream_npa_connect: %s\n",
			  socket_np_dir, pipe_name, session_info_t->session_info->info->domain_name,
			  session_info_t->session_info->info->account_name,
			  strerror(errno)));
		goto fail;

	}
	ret = tstream_npa_connect_recv(subreq, &sys_errno,
				       result,
				       &result->npipe,
				       &result->file_type,
				       &result->device_state,
				       &result->allocation_size);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		int l = 1;
		if (errno == ENOENT) {
			l = 2;
		}
		DEBUG(l, ("tstream_npa_connect_recv  to %s for pipe %s and "
			  "user %s\\%s failed: %s\n",
			  socket_np_dir, pipe_name, session_info_t->session_info->info->domain_name,
			  session_info_t->session_info->info->account_name,
			  strerror(sys_errno)));
		goto fail;
	}

	return result;

 fail:
	TALLOC_FREE(result);
	return NULL;
}

static NTSTATUS rpc_pipe_open_external(TALLOC_CTX *mem_ctx,
				       const char *pipe_name,
				       const struct ndr_interface_table *table,
				       const struct auth_session_info *session_info,
				       const struct tsocket_address *remote_client_address,
				       const struct tsocket_address *local_server_address,
				       struct rpc_pipe_client **_result)
{
	struct rpc_pipe_client *result = NULL;
	struct np_proxy_state *proxy_state = NULL;
	struct pipe_auth_data *auth;
	struct tsocket_address *remote_client_addr;
	struct tsocket_address *local_server_addr;
	NTSTATUS status;
	int ret;

	if (local_server_address == NULL) {
		/* this is an internal connection, fake up ip addresses */
		ret = tsocket_address_inet_from_strings(talloc_tos(), "ip",
							NULL, 0, &local_server_addr);
		if (ret) {
			return NT_STATUS_NO_MEMORY;
		}
		local_server_address = local_server_addr;
	}

	if (remote_client_address == NULL) {
		/* this is an internal connection, fake up ip addresses */
		ret = tsocket_address_inet_from_strings(talloc_tos(), "ip",
							NULL, 0, &remote_client_addr);
		if (ret) {
			return NT_STATUS_NO_MEMORY;
		}
		remote_client_address = remote_client_addr;
	}

	proxy_state = make_external_rpc_pipe_p(mem_ctx, pipe_name,
					       remote_client_address,
					       local_server_address,
					       session_info);
	if (!proxy_state) {
		DEBUG(1, ("Unable to make proxy_state for connection to %s.\n", pipe_name));
		return NT_STATUS_UNSUCCESSFUL;
	}

	result = talloc_zero(mem_ctx, struct rpc_pipe_client);
	if (result == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	result->abstract_syntax = table->syntax_id;
	result->transfer_syntax = ndr_transfer_syntax_ndr;

	result->desthost = get_myname(result);
	result->srv_name_slash = talloc_asprintf_strupper_m(
		result, "\\\\%s", result->desthost);
	if ((result->desthost == NULL) || (result->srv_name_slash == NULL)) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	result->max_xmit_frag = RPC_MAX_PDU_FRAG_LEN;

	status = rpc_transport_tstream_init(result,
					    &proxy_state->npipe,
					    &result->transport);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	result->binding_handle = rpccli_bh_create(result, NULL, table);
	if (result->binding_handle == NULL) {
		status = NT_STATUS_NO_MEMORY;
		DEBUG(0, ("Failed to create binding handle.\n"));
		goto done;
	}

	result->auth = talloc_zero(result, struct pipe_auth_data);
	if (!result->auth) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	result->auth->auth_type = DCERPC_AUTH_TYPE_NONE;
	result->auth->auth_level = DCERPC_AUTH_LEVEL_NONE;
	result->auth->auth_context_id = 0;

	status = rpccli_anon_bind_data(result, &auth);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to initialize anonymous bind.\n"));
		goto done;
	}

	status = rpc_pipe_bind(result, auth);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to bind external pipe.\n"));
		goto done;
	}

done:
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(result);
	}
	TALLOC_FREE(proxy_state);
	*_result = result;
	return status;
}

/**
 * @brief Create a new RPC client context which uses a local dispatch function
 *	  or a remote transport, depending on rpc_server configuration for the
 *	  specific service.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @param[in]  abstract_syntax Normally the syntax_id of the autogenerated
 *                             ndr_table_<name>.
 *
 * @param[in]  serversupplied_info The server supplied authentication function.
 *
 * @param[in]  remote_address The client address information.
 *
 * @param[in]  msg_ctx  The messaging context to use.
 *
 * @param[out] presult  A pointer to store the connected rpc client pipe.
 *
 * @return              NT_STATUS_OK on success, a corresponding NT status if an
 *                      error occurred.
 *
 * @code
 *   struct rpc_pipe_client *winreg_pipe;
 *   NTSTATUS status;
 *
 *   status = rpc_pipe_open_interface(tmp_ctx,
 *                                    &ndr_table_winreg.syntax_id,
 *                                    p->session_info,
 *                                    remote_address,
 *                                    &winreg_pipe);
 * @endcode
 */

NTSTATUS rpc_pipe_open_interface(TALLOC_CTX *mem_ctx,
				 const struct ndr_interface_table *table,
				 const struct auth_session_info *session_info,
				 const struct tsocket_address *remote_address,
				 const struct tsocket_address *local_address,
				 struct messaging_context *msg_ctx,
				 struct rpc_pipe_client **cli_pipe)
{
	struct rpc_pipe_client *cli = NULL;
	enum rpc_service_mode_e pipe_mode;
	const char *pipe_name;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;

	if (cli_pipe != NULL) {
		if (rpccli_is_connected(*cli_pipe)) {
			return NT_STATUS_OK;
		} else {
			TALLOC_FREE(*cli_pipe);
		}
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	pipe_name = dcerpc_default_transport_endpoint(mem_ctx, NCACN_NP, table);
	if (pipe_name == NULL) {
		DEBUG(1, ("Unable to find pipe name to forward %s to.\n", table->name));
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	while (pipe_name[0] == '\\') {
		pipe_name++;
	}

	DEBUG(5, ("Connecting to %s pipe.\n", pipe_name));

	pipe_mode = rpc_service_mode(pipe_name);

	switch (pipe_mode) {
	case RPC_SERVICE_MODE_EMBEDDED:
		status = rpc_pipe_open_internal(tmp_ctx,
						table, session_info,
						remote_address, local_address,
						msg_ctx,
						&cli);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
		break;
	case RPC_SERVICE_MODE_EXTERNAL:
		/* It would be nice to just use rpc_pipe_open_ncalrpc() but
		 * for now we need to use the special proxy setup to connect
		 * to spoolssd. */

		status = rpc_pipe_open_external(tmp_ctx,
						pipe_name, table,
						session_info,
						remote_address, local_address,
						&cli);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
		break;
	case RPC_SERVICE_MODE_DISABLED:
		status = NT_STATUS_NOT_IMPLEMENTED;
		DEBUG(0, ("Service pipe %s is disabled in config file: %s",
			  pipe_name, nt_errstr(status)));
		goto done;
        }

	status = NT_STATUS_OK;
done:
	if (NT_STATUS_IS_OK(status) && cli_pipe != NULL) {
		*cli_pipe = talloc_move(mem_ctx, &cli);
	}
	TALLOC_FREE(tmp_ctx);
	return status;
}
