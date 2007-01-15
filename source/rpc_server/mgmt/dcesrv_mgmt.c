/* 
   Unix SMB/CIFS implementation.

   endpoint server for the mgmt pipe

   Copyright (C) Jelmer Vernooij 2006
   
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
#include "rpc_server/dcerpc_server.h"
#include "librpc/gen_ndr/ndr_mgmt.h"
#include "rpc_server/common/common.h"

/* 
  mgmt_inq_if_ids 
*/
static WERROR mgmt_inq_if_ids(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct mgmt_inq_if_ids *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  mgmt_inq_stats 
*/
static WERROR mgmt_inq_stats(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct mgmt_inq_stats *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  mgmt_is_server_listening 
*/
static uint32_t mgmt_is_server_listening(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct mgmt_is_server_listening *r)
{
	*r->out.status = 1;
	return 0;
}


/* 
  mgmt_stop_server_listening 
*/
static WERROR mgmt_stop_server_listening(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct mgmt_stop_server_listening *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  mgmt_inq_princ_name 
*/
static WERROR mgmt_inq_princ_name(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct mgmt_inq_princ_name *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_mgmt_s.c"
