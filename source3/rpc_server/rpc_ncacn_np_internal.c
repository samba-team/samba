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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static int pipes_open;

static pipes_struct *InternalPipes;

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

pipes_struct *get_first_internal_pipe(void)
{
	return InternalPipes;
}

pipes_struct *get_next_internal_pipe(pipes_struct *p)
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
	pipes_struct *p;

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

	prs_mem_free(&p->out_data.frag);
	prs_mem_free(&p->out_data.rdata);
	prs_mem_free(&p->in_data.data);

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
					      struct auth_serversupplied_info *server_info)
{
	pipes_struct *p;

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

	if (!init_pipe_handle_list(p, syntax)) {
		DEBUG(0,("open_rpc_pipe_p: init_pipe_handles failed.\n"));
		TALLOC_FREE(p);
		return NULL;
	}

	/*
	 * Initialize the incoming RPC data buffer with one PDU worth of memory.
	 * We cheat here and say we're marshalling, as we intend to add incoming
	 * data directly into the prs_struct and we want it to auto grow. We will
	 * change the type to UNMARSALLING before processing the stream.
	 */

	if(!prs_init(&p->in_data.data, 128, p->mem_ctx, MARSHALL)) {
		DEBUG(0,("open_rpc_pipe_p: malloc fail for in_data struct.\n"));
		close_policy_by_pipe(p);
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

	DLIST_ADD(InternalPipes, p);

	strlcpy(p->client_address, client_address, sizeof(p->client_address));

	p->endian = RPC_LITTLE_ENDIAN;

	/*
	 * Initialize the outgoing RPC data buffer with no memory.
	 */
	prs_init_empty(&p->out_data.rdata, p->mem_ctx, MARSHALL);

	p->syntax = *syntax;

	DEBUG(4,("Created internal pipe %s (pipes_open=%d)\n",
		 get_pipe_name_from_syntax(talloc_tos(), syntax), pipes_open));

	talloc_set_destructor(p, close_internal_rpc_pipe_hnd);

	return p;
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
				NTSTATUS (*dispatch) (struct rpc_pipe_client *cli,
						      TALLOC_CTX *mem_ctx,
						      const struct ndr_interface_table *table,
						      uint32_t opnum, void *r),
				struct auth_serversupplied_info *serversupplied_info,
				struct rpc_pipe_client **presult)
{
	struct rpc_pipe_client *result;

	result = TALLOC_ZERO_P(mem_ctx, struct rpc_pipe_client);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result->abstract_syntax = *abstract_syntax;
	result->transfer_syntax = ndr_transfer_syntax;
	result->dispatch = dispatch;

	result->pipes_struct = make_internal_rpc_pipe_p(
		result, abstract_syntax, "", serversupplied_info);
	if (result->pipes_struct == NULL) {
		TALLOC_FREE(result);
		return NT_STATUS_NO_MEMORY;
	}

	result->max_xmit_frag = -1;
	result->max_recv_frag = -1;

	*presult = result;
	return NT_STATUS_OK;
}
