/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Jeremy Allison                    1999.
 *  Copyright (C) Simo Sorce                        2010
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
#include "librpc/gen_ndr/ndr_dcerpc.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_PARSE

NTSTATUS dcerpc_pull_dcerpc_bind(TALLOC_CTX *mem_ctx,
				 const DATA_BLOB *blob,
				 struct dcerpc_bind *r)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(blob, mem_ctx, r,
		(ndr_pull_flags_fn_t)ndr_pull_dcerpc_bind);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 Reads or writes an RPC_HDR_RESP structure.
********************************************************************/

bool smb_io_rpc_hdr_resp(const char *desc, RPC_HDR_RESP *rpc, prs_struct *ps, int depth)
{
	if (rpc == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr_resp");
	depth++;

	if(!prs_uint32("alloc_hint", ps, depth, &rpc->alloc_hint))
		return False;
	if(!prs_uint16("context_id", ps, depth, &rpc->context_id))
		return False;
	if(!prs_uint8 ("cancel_ct ", ps, depth, &rpc->cancel_count))
		return False;
	if(!prs_uint8 ("reserved  ", ps, depth, &rpc->reserved))
		return False;
	return True;
}

/*******************************************************************
 Inits an RPC_HDR_AUTH structure.
********************************************************************/

void init_rpc_hdr_auth(RPC_HDR_AUTH *rai,
				uint8 auth_type, uint8 auth_level,
				uint8 auth_pad_len,
				uint32 auth_context_id)
{
	rai->auth_type     = auth_type;
	rai->auth_level    = auth_level;
	rai->auth_pad_len  = auth_pad_len;
	rai->auth_reserved = 0;
	rai->auth_context_id = auth_context_id;
}

/*******************************************************************
 Reads or writes an RPC_HDR_AUTH structure.
 NB This writes UNALIGNED. Ensure you're correctly aligned before
 calling.
********************************************************************/

bool smb_io_rpc_hdr_auth(const char *desc, RPC_HDR_AUTH *rai, prs_struct *ps, int depth)
{
	if (rai == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr_auth");
	depth++;

	if(!prs_uint8 ("auth_type    ", ps, depth, &rai->auth_type))
		return False;
	if(!prs_uint8 ("auth_level   ", ps, depth, &rai->auth_level))
		return False;
	if(!prs_uint8 ("auth_pad_len ", ps, depth, &rai->auth_pad_len))
		return False;
	if(!prs_uint8 ("auth_reserved", ps, depth, &rai->auth_reserved))
		return False;
	if(!prs_uint32("auth_context_id", ps, depth, &rai->auth_context_id))
		return False;

	return True;
}
