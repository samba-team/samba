/* 
   Unix SMB/CIFS implementation.

   endpoint server for the rot pipe

   Copyright (C) Jelmer Vernooij 2004
   
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
#include "librpc/gen_ndr/ndr_rot.h"
#include "rpc_server/common/common.h"


/* 
  rot_add 
*/
static WERROR rot_add(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct rot_add *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  rot_remove 
*/
static WERROR rot_remove(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct rot_remove *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  rot_is_listed 
*/
static WERROR rot_is_listed(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct rot_is_listed *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  rot_get_interface_pointer 
*/
static WERROR rot_get_interface_pointer(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct rot_get_interface_pointer *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  rot_set_modification_time 
*/
static WERROR rot_set_modification_time(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct rot_set_modification_time *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  rot_get_modification_time 
*/
static WERROR rot_get_modification_time(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct rot_get_modification_time *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  rot_enum 
*/
static WERROR rot_enum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct rot_enum *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_rot_s.c"
