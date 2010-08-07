/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998,
 *  Largely re-written : 2005
 *  Copyright (C) Jeremy Allison		1998 - 2005
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
#include "rpc_server/srv_pipe_internal.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static int pipes_open;

static struct pipes_struct *InternalPipes;

/* TODO
 * the following prototypes are declared here to avoid
 * code being moved about too much for a patch to be
 * disrupted / less obvious.
 *
 * these functions, and associated functions that they
 * call, should be moved behind a .so module-loading
 * system _anyway_.  so that's the next step...
 */

static int close_internal_rpc_pipe_hnd(struct pipes_struct *p);

/****************************************************************************
 Internal Pipe iterator functions.
****************************************************************************/

struct pipes_struct *get_first_internal_pipe(void)
{
	return InternalPipes;
}

struct pipes_struct *get_next_internal_pipe(struct pipes_struct *p)
{
	return p->next;
}

static void free_pipe_rpc_context_internal( PIPE_RPC_FNS *list )
{
	PIPE_RPC_FNS *tmp = list;
	PIPE_RPC_FNS *tmp2;

	while (tmp) {
		tmp2 = tmp->next;
		SAFE_FREE(tmp);
		tmp = tmp2;
	}

	return;
}

bool check_open_pipes(void)
{
	struct pipes_struct *p;

	for (p = InternalPipes; p != NULL; p = p->next) {
		if (num_pipe_handles(p) != 0) {
			return true;
		}
	}
	return false;
}

/****************************************************************************
 Close an rpc pipe.
****************************************************************************/

static int close_internal_rpc_pipe_hnd(struct pipes_struct *p)
{
	if (!p) {
		DEBUG(0,("Invalid pipe in close_internal_rpc_pipe_hnd\n"));
		return False;
	}

	if (p->auth.auth_data_free_func) {
		(*p->auth.auth_data_free_func)(&p->auth);
	}

	free_pipe_rpc_context_internal( p->contexts );

	/* Free the handles database. */
	close_policy_by_pipe(p);

	DLIST_REMOVE(InternalPipes, p);

	ZERO_STRUCTP(p);

	return 0;
}

/****************************************************************************
 Make an internal namedpipes structure
****************************************************************************/

struct pipes_struct *make_internal_rpc_pipe_p(TALLOC_CTX *mem_ctx,
					      const struct ndr_syntax_id *syntax,
					      const char *client_address,
					      struct auth_serversupplied_info *server_info,
					      struct messaging_context *msg_ctx)
{
	struct pipes_struct *p;

	DEBUG(4,("Create pipe requested %s\n",
		 get_pipe_name_from_syntax(talloc_tos(), syntax)));

	p = TALLOC_ZERO_P(mem_ctx, struct pipes_struct);

	if (!p) {
		DEBUG(0,("ERROR! no memory for pipes_struct!\n"));
		return NULL;
	}

	p->mem_ctx = talloc_named(p, 0, "pipe %s %p",
				 get_pipe_name_from_syntax(talloc_tos(),
							   syntax), p);
	if (p->mem_ctx == NULL) {
		DEBUG(0,("open_rpc_pipe_p: talloc_init failed.\n"));
		TALLOC_FREE(p);
		return NULL;
	}

	if (!init_pipe_handles(p, syntax)) {
		DEBUG(0,("open_rpc_pipe_p: init_pipe_handles failed.\n"));
		TALLOC_FREE(p);
		return NULL;
	}

	p->server_info = copy_serverinfo(p, server_info);
	if (p->server_info == NULL) {
		DEBUG(0, ("open_rpc_pipe_p: copy_serverinfo failed\n"));
		close_policy_by_pipe(p);
		TALLOC_FREE(p);
		return NULL;
	}

	p->msg_ctx = msg_ctx;

	DLIST_ADD(InternalPipes, p);

	strlcpy(p->client_address, client_address, sizeof(p->client_address));

	p->endian = RPC_LITTLE_ENDIAN;

	p->syntax = *syntax;

	DEBUG(4,("Created internal pipe %s (pipes_open=%d)\n",
		 get_pipe_name_from_syntax(talloc_tos(), syntax), pipes_open));

	talloc_set_destructor(p, close_internal_rpc_pipe_hnd);

	return p;
}

/****************************************************************************
****************************************************************************/

static NTSTATUS internal_ndr_push(TALLOC_CTX *mem_ctx,
				  struct rpc_pipe_client *cli,
				  const struct ndr_interface_table *table,
				  uint32_t opnum,
				  void *r)
{
	const struct ndr_interface_call *call;
	struct ndr_push *push;
	enum ndr_err_code ndr_err;

	if (!ndr_syntax_id_equal(&table->syntax_id, &cli->abstract_syntax) ||
	    (opnum >= table->num_calls)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	call = &table->calls[opnum];

	if (DEBUGLEVEL >= 10) {
		ndr_print_function_debug(call->ndr_print,
					 call->name, NDR_IN, r);
	}

	push = ndr_push_init_ctx(mem_ctx);
	if (push == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ndr_err = call->ndr_push(push, NDR_IN, r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(push);
		return ndr_map_error2ntstatus(ndr_err);
	}

	cli->pipes_struct->in_data.data = ndr_push_blob(push);
	talloc_steal(cli->pipes_struct->mem_ctx,
		     cli->pipes_struct->in_data.data.data);
	TALLOC_FREE(push);

	return NT_STATUS_OK;
}

/****************************************************************************
****************************************************************************/

static NTSTATUS internal_ndr_pull(TALLOC_CTX *mem_ctx,
				  struct rpc_pipe_client *cli,
				  const struct ndr_interface_table *table,
				  uint32_t opnum,
				  void *r)
{
	const struct ndr_interface_call *call;
	struct ndr_pull *pull;
	enum ndr_err_code ndr_err;

	if (!ndr_syntax_id_equal(&table->syntax_id, &cli->abstract_syntax) ||
	    (opnum >= table->num_calls)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	call = &table->calls[opnum];

	pull = ndr_pull_init_blob(&cli->pipes_struct->out_data.rdata,
				  mem_ctx);
	if (pull == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* have the ndr parser alloc memory for us */
	pull->flags |= LIBNDR_FLAG_REF_ALLOC;
	ndr_err = call->ndr_pull(pull, NDR_OUT, r);
	TALLOC_FREE(pull);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	if (DEBUGLEVEL >= 10) {
		ndr_print_function_debug(call->ndr_print,
					 call->name, NDR_OUT, r);
	}

	return NT_STATUS_OK;
}

/****************************************************************************
****************************************************************************/

static NTSTATUS rpc_pipe_internal_dispatch(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx,
					   const struct ndr_interface_table *table,
					   uint32_t opnum, void *r)
{
	NTSTATUS status;
	int num_cmds = rpc_srv_get_pipe_num_cmds(&table->syntax_id);
	const struct api_struct *cmds = rpc_srv_get_pipe_cmds(&table->syntax_id);
	int i;

	if (cli->pipes_struct == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* set opnum */
	cli->pipes_struct->opnum = opnum;

	for (i = 0; i < num_cmds; i++) {
		if (cmds[i].opnum == opnum && cmds[i].fn != NULL) {
			break;
		}
	}

	if (i == num_cmds) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = internal_ndr_push(mem_ctx, cli, table, opnum, r);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!cmds[i].fn(cli->pipes_struct)) {
		data_blob_free(&cli->pipes_struct->in_data.data);
		data_blob_free(&cli->pipes_struct->out_data.rdata);
		talloc_free_children(cli->pipes_struct->mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	status = internal_ndr_pull(mem_ctx, cli, table, opnum, r);
	if (!NT_STATUS_IS_OK(status)) {
		data_blob_free(&cli->pipes_struct->in_data.data);
		data_blob_free(&cli->pipes_struct->out_data.rdata);
		talloc_free_children(cli->pipes_struct->mem_ctx);
		return status;
	}

	data_blob_free(&cli->pipes_struct->in_data.data);
	data_blob_free(&cli->pipes_struct->out_data.rdata);
	talloc_free_children(cli->pipes_struct->mem_ctx);

	return NT_STATUS_OK;
}

static NTSTATUS rpcint_dispatch(struct pipes_struct *p,
				TALLOC_CTX *mem_ctx,
				uint32_t opnum,
				const DATA_BLOB *in_data,
				DATA_BLOB *out_data)
{
	uint32_t num_cmds = rpc_srv_get_pipe_num_cmds(&p->syntax);
	const struct api_struct *cmds = rpc_srv_get_pipe_cmds(&p->syntax);
	uint32_t i;
	bool ok;

	/* set opnum */
	p->opnum = opnum;

	for (i = 0; i < num_cmds; i++) {
		if (cmds[i].opnum == opnum && cmds[i].fn != NULL) {
			break;
		}
	}

	if (i == num_cmds) {
		return NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE;
	}

	p->in_data.data = *in_data;
	p->out_data.rdata = data_blob_null;

	ok = cmds[i].fn(p);
	p->in_data.data = data_blob_null;
	if (!ok) {
		data_blob_free(&p->out_data.rdata);
		talloc_free_children(p->mem_ctx);
		return NT_STATUS_RPC_CALL_FAILED;
	}

	if (p->fault_state) {
		p->fault_state = false;
		data_blob_free(&p->out_data.rdata);
		talloc_free_children(p->mem_ctx);
		return NT_STATUS_RPC_CALL_FAILED;
	}

	if (p->bad_handle_fault_state) {
		p->bad_handle_fault_state = false;
		data_blob_free(&p->out_data.rdata);
		talloc_free_children(p->mem_ctx);
		return NT_STATUS_RPC_SS_CONTEXT_MISMATCH;
	}

	if (p->rng_fault_state) {
		p->rng_fault_state = false;
		data_blob_free(&p->out_data.rdata);
		talloc_free_children(p->mem_ctx);
		return NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE;
	}

	*out_data = p->out_data.rdata;
	talloc_steal(mem_ctx, out_data->data);
	p->out_data.rdata = data_blob_null;

	talloc_free_children(p->mem_ctx);
	return NT_STATUS_OK;
}

struct rpcint_bh_state {
	struct pipes_struct *p;
};

static bool rpcint_bh_is_connected(struct dcerpc_binding_handle *h)
{
	struct rpcint_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct rpcint_bh_state);

	if (!hs->p) {
		return false;
	}

	return true;
}

struct rpcint_bh_raw_call_state {
	DATA_BLOB in_data;
	DATA_BLOB out_data;
	uint32_t out_flags;
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
	bool ok;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct rpcint_bh_raw_call_state);
	if (req == NULL) {
		return NULL;
	}
	state->in_data.data = discard_const_p(uint8_t, in_data);
	state->in_data.length = in_length;

	ok = rpcint_bh_is_connected(h);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_INVALID_CONNECTION);
		return tevent_req_post(req, ev);
	}

	/* TODO: allow async */
	status = rpcint_dispatch(hs->p, state, opnum,
				 &state->in_data,
				 &state->out_data);
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
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out_data = talloc_move(mem_ctx, &state->out_data.data);
	*out_length = state->out_data.length;
	*out_flags = 0;
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
		tevent_req_nterror(req, NT_STATUS_INVALID_CONNECTION);
		return tevent_req_post(req, ev);
	}

	/*
	 * TODO: do a real async disconnect ...
	 *
	 * For now the caller needs to free pipes_struct
	 */
	hs->p = NULL;

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

	if (DEBUGLEVEL < 10) {
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
	.raw_call_send		= rpcint_bh_raw_call_send,
	.raw_call_recv		= rpcint_bh_raw_call_recv,
	.disconnect_send	= rpcint_bh_disconnect_send,
	.disconnect_recv	= rpcint_bh_disconnect_recv,

	.ref_alloc		= rpcint_bh_ref_alloc,
	.do_ndr_print		= rpcint_bh_do_ndr_print,
};

/* initialise a wbint binding handle */
static struct dcerpc_binding_handle *rpcint_binding_handle(struct pipes_struct *p)
{
	struct dcerpc_binding_handle *h;
	struct rpcint_bh_state *hs;

	h = dcerpc_binding_handle_create(p,
					 &rpcint_bh_ops,
					 NULL,
					 NULL, /* TODO */
					 &hs,
					 struct rpcint_bh_state,
					 __location__);
	if (h == NULL) {
		return NULL;
	}
	hs->p = p;

	return h;
}

/**
 * @brief Create a new RPC client context which uses a local dispatch function.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @param[in]  abstract_syntax Normally the syntax_id of the autogenerated
 *                             ndr_table_<name>.
 *
 * @param[in]  dispatch The corresponding autogenerated dispatch function
 *                      rpc_<name>_dispatch.
 *
 * @param[in]  serversupplied_info The server supplied authentication function.
 *
 * @param[out] presult  A pointer to store the connected rpc client pipe.
 *
 * @return              NT_STATUS_OK on success, a corresponding NT status if an
 *                      error occured.
 *
 * @code
 *   struct rpc_pipe_client *winreg_pipe;
 *   NTSTATUS status;
 *
 *   status = rpc_pipe_open_internal(tmp_ctx,
 *                                   &ndr_table_winreg.syntax_id,
 *                                   rpc_winreg_dispatch,
 *                                   p->server_info,
 *                                   &winreg_pipe);
 * @endcode
 */
NTSTATUS rpc_pipe_open_internal(TALLOC_CTX *mem_ctx,
				const struct ndr_syntax_id *abstract_syntax,
				struct auth_serversupplied_info *serversupplied_info,
				struct messaging_context *msg_ctx,
				struct rpc_pipe_client **presult)
{
	struct rpc_pipe_client *result;

	result = TALLOC_ZERO_P(mem_ctx, struct rpc_pipe_client);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result->abstract_syntax = *abstract_syntax;
	result->transfer_syntax = ndr_transfer_syntax;
	result->dispatch = rpc_pipe_internal_dispatch;

	result->pipes_struct = make_internal_rpc_pipe_p(
		result, abstract_syntax, "", serversupplied_info, msg_ctx);
	if (result->pipes_struct == NULL) {
		TALLOC_FREE(result);
		return NT_STATUS_NO_MEMORY;
	}

	result->max_xmit_frag = -1;
	result->max_recv_frag = -1;

	result->binding_handle = rpcint_binding_handle(result->pipes_struct);
	if (result->binding_handle == NULL) {
		TALLOC_FREE(result);
		return NT_STATUS_NO_MEMORY;
	}

	*presult = result;
	return NT_STATUS_OK;
}
