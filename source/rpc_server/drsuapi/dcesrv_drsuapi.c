/* 
   Unix SMB/CIFS implementation.

   endpoint server for the drsuapi pipe

   Copyright (C) Stefan Metzmacher 2004
   
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
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"
#include "rpc_server/drsuapi/dcesrv_drsuapi.h"

/*
  destroy a general handle. 
*/
static void drsuapi_handle_destroy(struct dcesrv_connection *conn, struct dcesrv_handle *h)
{
	talloc_free(h->data);
}

/* 
  drsuapi_DsBind 
*/
static WERROR drsuapi_DsBind(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsBind *r)
{
	struct drsuapi_bind_state *b_state;
	struct dcesrv_handle *handle;
	struct drsuapi_DsBindInfoCtr *bind_info;
	struct GUID site_guid;

	r->out.bind_info = NULL;
	ZERO_STRUCTP(r->out.bind_handle);

	b_state = talloc_p(dce_call->conn, struct drsuapi_bind_state);
	WERR_TALLOC_CHECK(b_state);

	b_state->sam_ctx = samdb_connect(b_state);
	if (!b_state->sam_ctx) {
		talloc_free(b_state);
		return WERR_FOOBAR;
	}

	handle = dcesrv_handle_new(dce_call->conn, DRSUAPI_BIND_HANDLE);
	if (!handle) {
		talloc_free(b_state);
		return WERR_NOMEM;
	}

	handle->data = b_state;
	handle->destroy = drsuapi_handle_destroy;

	bind_info = talloc_p(mem_ctx, struct drsuapi_DsBindInfoCtr);
	WERR_TALLOC_CHECK(bind_info);

	ZERO_STRUCT(site_guid);

	bind_info->length				= 28;
	bind_info->info.info28.supported_extensions	= 0;
	bind_info->info.info28.site_guid		= site_guid;
	bind_info->info.info28.u1			= 0;
	bind_info->info.info28.repl_epoch		= 0;

	r->out.bind_info = bind_info;
	*r->out.bind_handle = handle->wire_handle;

	return WERR_OK;
}


/* 
  drsuapi_DsUnbind 
*/
static WERROR drsuapi_DsUnbind(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsUnbind *r)
{
	struct dcesrv_handle *h;

	*r->out.bind_handle = *r->in.bind_handle;

	DCESRV_PULL_HANDLE_WERR(h, r->in.bind_handle, DRSUAPI_BIND_HANDLE);

	/* this causes the callback drsuapi_handle_destroy() to be called by
	   the handle destroy code which destroys the state associated
	   with the handle */
	dcesrv_handle_destroy(dce_call->conn, h);

	ZERO_STRUCTP(r->out.bind_handle);

	return WERR_OK;
}


/* 
  drsuapi_DsReplicaSync 
*/
static WERROR drsuapi_DsReplicaSync(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsReplicaSync *r)
{
	/* TODO: implement this call correct!
	 *       for now we just say yes,
	 *       because we have no output parameter
	 */
	return WERR_OK;
}


/* 
  DRSUAPI_GET_NC_CHANGES 
*/
static WERROR DRSUAPI_GET_NC_CHANGES(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_GET_NC_CHANGES *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_UPDATE_REFS 
*/
static WERROR DRSUAPI_UPDATE_REFS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_UPDATE_REFS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_REPLICA_ADD 
*/
static WERROR DRSUAPI_REPLICA_ADD(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_REPLICA_ADD *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_REPLICA_DEL 
*/
static WERROR DRSUAPI_REPLICA_DEL(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_REPLICA_DEL *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_REPLICA_MODIFY 
*/
static WERROR DRSUAPI_REPLICA_MODIFY(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_REPLICA_MODIFY *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_VERIFY_NAMES 
*/
static WERROR DRSUAPI_VERIFY_NAMES(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_VERIFY_NAMES *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_GET_MEMBERSHIPS 
*/
static WERROR DRSUAPI_GET_MEMBERSHIPS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_GET_MEMBERSHIPS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_INTER_DOMAIN_MOVE 
*/
static WERROR DRSUAPI_INTER_DOMAIN_MOVE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_INTER_DOMAIN_MOVE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_GET_NT4_CHANGELOG 
*/
static WERROR DRSUAPI_GET_NT4_CHANGELOG(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_GET_NT4_CHANGELOG *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  drsuapi_DsCrackNames => drsuapip_cracknames.c
*/
static WERROR (*drsuapi_DsCrackNames)(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsCrackNames *r) = dcesrv_drsuapi_DsCrackNames;

/* 
  drsuapi_DsWriteAccountSpn 
*/
static WERROR drsuapi_DsWriteAccountSpn(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsWriteAccountSpn *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_REMOVE_DS_SERVER 
*/
static WERROR DRSUAPI_REMOVE_DS_SERVER(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_REMOVE_DS_SERVER *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_REMOVE_DS_DOMAIN 
*/
static WERROR DRSUAPI_REMOVE_DS_DOMAIN(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_REMOVE_DS_DOMAIN *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  drsuapi_DsGetDomainControllerInfo 
*/
static WERROR drsuapi_DsGetDomainControllerInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsGetDomainControllerInfo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_ADD_ENTRY 
*/
static WERROR DRSUAPI_ADD_ENTRY(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_ADD_ENTRY *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_EXECUTE_KCC 
*/
static WERROR DRSUAPI_EXECUTE_KCC(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_EXECUTE_KCC *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  drsuapi_DsReplicaGetInfo 
*/
static WERROR drsuapi_DsReplicaGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsReplicaGetInfo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_ADD_SID_HISTORY 
*/
static WERROR DRSUAPI_ADD_SID_HISTORY(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_ADD_SID_HISTORY *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_GET_MEMBERSHIPS2 
*/
static WERROR DRSUAPI_GET_MEMBERSHIPS2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_GET_MEMBERSHIPS2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_REPLICA_VERIFY_OBJECTS 
*/
static WERROR DRSUAPI_REPLICA_VERIFY_OBJECTS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_REPLICA_VERIFY_OBJECTS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_GET_OBJECT_EXISTENCE 
*/
static WERROR DRSUAPI_GET_OBJECT_EXISTENCE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_GET_OBJECT_EXISTENCE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_QUERY_SITES_BY_COST 
*/
static WERROR DRSUAPI_QUERY_SITES_BY_COST(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_QUERY_SITES_BY_COST *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_drsuapi_s.c"
