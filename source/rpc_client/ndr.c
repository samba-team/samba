/* 
   Unix SMB/CIFS implementation.

   libndr interface

   Copyright (C) Jelmer Vernooij 2006
   
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


NTSTATUS cli_do_rpc_ndr(struct rpc_pipe_client *cli,
			TALLOC_CTX *mem_ctx,
			const struct ndr_interface_table *table,
			uint32 opnum, void *r)
{
	prs_struct q_ps, r_ps;
	const struct ndr_interface_call *call;
	struct ndr_pull *pull;
	DATA_BLOB blob;
	struct ndr_push *push;
	NTSTATUS status;
	enum ndr_err_code ndr_err;

	SMB_ASSERT(ndr_syntax_id_equal(&table->syntax_id,
				       &cli->abstract_syntax));
	SMB_ASSERT(table->num_calls > opnum);

	call = &table->calls[opnum];

	push = ndr_push_init_ctx(mem_ctx);
	if (!push) {
		return NT_STATUS_NO_MEMORY;
	}

	ndr_err = call->ndr_push(push, NDR_IN, r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	blob = ndr_push_blob(push);

	if (!prs_init_data_blob(&q_ps, &blob, mem_ctx)) {
		return NT_STATUS_NO_MEMORY;
	}

	talloc_free(push);

	prs_init_empty( &r_ps, mem_ctx, UNMARSHALL );
	
	status = rpc_api_pipe_req(cli, opnum, &q_ps, &r_ps); 

	prs_mem_free( &q_ps );

	if (!NT_STATUS_IS_OK(status)) {
		prs_mem_free( &r_ps );
		return status;
	}

	if (!prs_data_blob(&r_ps, &blob, mem_ctx)) {
		prs_mem_free( &r_ps );
		return NT_STATUS_NO_MEMORY;
	}

	prs_mem_free( &r_ps );

	pull = ndr_pull_init_blob(&blob, mem_ctx);
	if (pull == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* have the ndr parser alloc memory for us */
	pull->flags |= LIBNDR_FLAG_REF_ALLOC;
	ndr_err = call->ndr_pull(pull, NDR_OUT, r);
	talloc_free(pull);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	return NT_STATUS_OK;
}
