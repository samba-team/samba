/* 
   Unix SMB/CIFS implementation.
   ACL get/set operations
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

/****************************************************************************
fetch file ACL (async send)
****************************************************************************/
struct cli_request *smb_raw_query_secdesc_send(struct cli_tree *tree, 
					       struct smb_query_secdesc *query)
{
	struct smb_nttrans nt;
	uint8_t params[8];

	nt.in.max_setup = 0;
	nt.in.max_param = 4;
	nt.in.max_data = 0x10000;
	nt.in.setup_count = 0;
	nt.in.function = NT_TRANSACT_QUERY_SECURITY_DESC;
	nt.in.setup = NULL;

	SSVAL(params, 0, query->in.fnum);
	SSVAL(params, 2, 0); /* padding */
	SIVAL(params, 4, query->in.secinfo_flags);

	nt.in.params.data = params;
	nt.in.params.length = 8;
	
	nt.in.data = data_blob(NULL, 0);

	return smb_raw_nttrans_send(tree, &nt);
}


/****************************************************************************
fetch file ACL (async recv)
****************************************************************************/
NTSTATUS smb_raw_query_secdesc_recv(struct cli_request *req, 
				    TALLOC_CTX *mem_ctx, 
				    struct smb_query_secdesc *query)
{
	NTSTATUS status;
	struct smb_nttrans nt;
	struct ndr_pull *ndr;

	status = smb_raw_nttrans_recv(req, mem_ctx, &nt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* check that the basics are valid */
	if (nt.out.params.length != 4 ||
	    IVAL(nt.out.params.data, 0) > nt.out.data.length) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	nt.out.data.length = IVAL(nt.out.params.data, 0);

	ndr = ndr_pull_init_blob(&nt.out.data, mem_ctx);
	if (!ndr) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	query->out.sd = talloc(mem_ctx, sizeof(query->out.sd));
	if (!query->out.sd) {
		return NT_STATUS_NO_MEMORY;
	}
	status = ndr_pull_security_descriptor(ndr, NDR_SCALARS|NDR_BUFFERS, query->out.sd);

	return NT_STATUS_OK;
}


/****************************************************************************
fetch file ACL (sync interface)
****************************************************************************/
NTSTATUS smb_raw_query_secdesc(struct cli_tree *tree, 
			       TALLOC_CTX *mem_ctx, 
			       struct smb_query_secdesc *query)
{
	struct cli_request *req = smb_raw_query_secdesc_send(tree, query);
	return smb_raw_query_secdesc_recv(req, mem_ctx, query);
}



/****************************************************************************
set file ACL (async send)
****************************************************************************/
struct cli_request *smb_raw_set_secdesc_send(struct cli_tree *tree, 
					     struct smb_set_secdesc *set)
{
	struct smb_nttrans nt;
	uint8_t params[8];
	struct ndr_push *ndr;
	struct cli_request *req;
	NTSTATUS status;

	nt.in.max_setup = 0;
	nt.in.max_param = 0;
	nt.in.max_data = 0;
	nt.in.setup_count = 0;
	nt.in.function = NT_TRANSACT_SET_SECURITY_DESC;
	nt.in.setup = NULL;

	SSVAL(params, 0, set->in.fnum);
	SSVAL(params, 2, 0); /* padding */
	SIVAL(params, 4, set->in.secinfo_flags);

	nt.in.params.data = params;
	nt.in.params.length = 8;

	ndr = ndr_push_init();
	if (!ndr) return NULL;

//	status = ndr_push_security_descriptor(ndr, set->in.sd);
	if (!NT_STATUS_IS_OK(status)) {
		ndr_push_free(ndr);
		return NULL;
	}
	
	nt.in.data = ndr_push_blob(ndr);

	req = smb_raw_nttrans_send(tree, &nt);

	ndr_push_free(ndr);
	return req;
}
