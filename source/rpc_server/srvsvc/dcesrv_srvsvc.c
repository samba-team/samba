/* 
   Unix SMB/CIFS implementation.

   endpoint server for the srvsvc pipe

   Copyright (C) Stefan (metze) Metzmacher 2004
   
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
#include "librpc/gen_ndr/ndr_srvsvc.h"
#include "rpc_server/common/common.h"

/* 
  srvsvc_NetCharDevEnum 
*/
static WERROR srvsvc_NetCharDevEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				      struct srvsvc_NetCharDevEnum *r)
{
	r->out.level = r->in.level;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;

	switch (r->in.level) {
	case 0:
		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetCharDevCtr0);
		WERR_TALLOC_CHECK(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = 0;
		r->out.ctr.ctr0->array = NULL;

		return WERR_NOT_SUPPORTED;

	case 1:
		r->out.ctr.ctr1 = talloc_p(mem_ctx, struct srvsvc_NetCharDevCtr1);
		WERR_TALLOC_CHECK(r->out.ctr.ctr1);

		r->out.ctr.ctr1->count = 0;
		r->out.ctr.ctr1->array = NULL;

		return WERR_NOT_SUPPORTED;

	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_OK;
}


/* 
  srvsvc_NetCharDevGetInfo 
*/
static WERROR srvsvc_NetCharDevGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetCharDevGetInfo *r)
{
	switch (r->in.level) {
	case 0:
		r->out.info.info0 = NULL;

		return WERR_NOT_SUPPORTED;

	case 1:
		r->out.info.info1 = NULL;

		return WERR_NOT_SUPPORTED;

	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_OK;
}


/* 
  srvsvc_NetCharDevControl 
*/
static WERROR srvsvc_NetCharDevControl(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetCharDevControl *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NetCharDevQEnum 
*/
static WERROR srvsvc_NetCharDevQEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct srvsvc_NetCharDevQEnum *r)
{
	r->out.level = r->in.level;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;

	switch (r->in.level) {
	case 0:
		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetCharDevQCtr0);
		WERR_TALLOC_CHECK(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = 0;
		r->out.ctr.ctr0->array = NULL;

		return WERR_NOT_SUPPORTED;

	case 1:
		r->out.ctr.ctr1 = talloc_p(mem_ctx, struct srvsvc_NetCharDevQCtr1);
		WERR_TALLOC_CHECK(r->out.ctr.ctr1);

		r->out.ctr.ctr1->count = 0;
		r->out.ctr.ctr1->array = NULL;

		return WERR_NOT_SUPPORTED;

	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_OK;
}


/* 
  srvsvc_NetCharDevQGetInfo 
*/
static WERROR srvsvc_NetCharDevQGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct srvsvc_NetCharDevQGetInfo *r)
{
	switch (r->in.level) {
	case 0:
		r->out.info.info0 = NULL;

		return WERR_NOT_SUPPORTED;

	case 1:
		r->out.info.info1 = NULL;

		return WERR_NOT_SUPPORTED;

	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_OK;
}


/* 
  srvsvc_NetCharDevQSetInfo 
*/
static WERROR srvsvc_NetCharDevQSetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetCharDevQSetInfo *r)
{
	switch (r->in.level) {
	case 0:	
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		return WERR_NOT_SUPPORTED;
	case 1:
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		return WERR_NOT_SUPPORTED;
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_OK;
}


/* 
  srvsvc_NetCharDevQPurge 
*/
static WERROR srvsvc_NetCharDevQPurge(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetCharDevQPurge *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NetCharDevQPurgeSelf 
*/
static WERROR srvsvc_NetCharDevQPurgeSelf(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					  struct srvsvc_NetCharDevQPurgeSelf *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);	
}


/* 
  srvsvc_NetConnEnum 
*/
static WERROR srvsvc_NetConnEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetConnEnum *r)
{
	r->out.level = r->in.level;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;

	switch (r->in.level) {
	case 0:
		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetConnCtr0);
		WERR_TALLOC_CHECK(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = 0;
		r->out.ctr.ctr0->array = NULL;

		return WERR_NOT_SUPPORTED;

	case 1:
		r->out.ctr.ctr1 = talloc_p(mem_ctx, struct srvsvc_NetConnCtr1);
		WERR_TALLOC_CHECK(r->out.ctr.ctr1);

		r->out.ctr.ctr1->count = 0;
		r->out.ctr.ctr1->array = NULL;

		return WERR_NOT_SUPPORTED;

	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_OK;
}


/* 
  srvsvc_NetFileEnum 
*/
static WERROR srvsvc_NetFileEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct srvsvc_NetFileEnum *r)
{
	r->out.level = r->in.level;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;

	switch (r->in.level) {
	case 2:
		r->out.ctr.ctr2 = talloc_p(mem_ctx, struct srvsvc_NetFileCtr2);
		WERR_TALLOC_CHECK(r->out.ctr.ctr2);

		r->out.ctr.ctr2->count = 0;
		r->out.ctr.ctr2->array = NULL;

		return WERR_NOT_SUPPORTED;

	case 3:
		r->out.ctr.ctr3 = talloc_p(mem_ctx, struct srvsvc_NetFileCtr3);
		WERR_TALLOC_CHECK(r->out.ctr.ctr3);

		r->out.ctr.ctr3->count = 0;
		r->out.ctr.ctr3->array = NULL;

		return WERR_NOT_SUPPORTED;

	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_OK;
}


/* 
  srvsvc_NetFileGetInfo 
*/
static WERROR srvsvc_NetFileGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				    struct srvsvc_NetFileGetInfo *r)
{
	switch (r->in.level) {
	case 2:
		r->out.info.info2 = NULL;
		return WERR_NOT_SUPPORTED;

	case 3:
		r->out.info.info3 = NULL;
		return WERR_NOT_SUPPORTED;

	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_OK;
}


/* 
  srvsvc_NetFileClose 
*/
static WERROR srvsvc_NetFileClose(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetFileClose *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NetSessEnum 
*/
static WERROR srvsvc_NetSessEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetSessEnum *r)
{
	r->out.level = r->in.level;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;

	switch (r->in.level) {
	case 0:
		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetSessCtr0);
		WERR_TALLOC_CHECK(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = 0;
		r->out.ctr.ctr0->array = NULL;

		return WERR_NOT_SUPPORTED;

	case 1:
		r->out.ctr.ctr1 = talloc_p(mem_ctx, struct srvsvc_NetSessCtr1);
		WERR_TALLOC_CHECK(r->out.ctr.ctr1);

		r->out.ctr.ctr1->count = 0;
		r->out.ctr.ctr1->array = NULL;

		return WERR_NOT_SUPPORTED;

	case 2:
		r->out.ctr.ctr2 = talloc_p(mem_ctx, struct srvsvc_NetSessCtr2);
		WERR_TALLOC_CHECK(r->out.ctr.ctr2);

		r->out.ctr.ctr2->count = 0;
		r->out.ctr.ctr2->array = NULL;

		return WERR_NOT_SUPPORTED;

	case 10:
		r->out.ctr.ctr10 = talloc_p(mem_ctx, struct srvsvc_NetSessCtr10);
		WERR_TALLOC_CHECK(r->out.ctr.ctr10);

		r->out.ctr.ctr2->count = 0;
		r->out.ctr.ctr2->array = NULL;

		return WERR_NOT_SUPPORTED;

	case 502:
		r->out.ctr.ctr502 = talloc_p(mem_ctx, struct srvsvc_NetSessCtr502);
		WERR_TALLOC_CHECK(r->out.ctr.ctr502);

		r->out.ctr.ctr2->count = 0;
		r->out.ctr.ctr2->array = NULL;

		return WERR_NOT_SUPPORTED;

	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_OK;
}


/* 
  srvsvc_NetSessDel 
*/
static WERROR srvsvc_NetSessDel(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetSessDel *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NetShareAdd 
*/
static WERROR srvsvc_NetShareAdd(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetShareAdd *r)
{
	switch (r->in.level) {
	case 0:	
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		return WERR_NOT_SUPPORTED;

	case 1:
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		return WERR_NOT_SUPPORTED;

	case 2:
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		return WERR_NOT_SUPPORTED;

	case 501:
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		return WERR_NOT_SUPPORTED;

	case 502:
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		return WERR_NOT_SUPPORTED;

	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_OK;
}


/* 
  srvsvc_NetShareEnumAll
*/
static WERROR srvsvc_NetShareEnumAll(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetShareEnumAll *r)
{
	struct dcesrv_context *dce_ctx = dce_call->conn->dce_ctx;
	r->out.level = r->in.level;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;

	switch (r->in.level) {
	case 0: {
		int i;

		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr0);
		WERR_TALLOC_CHECK(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		r->out.ctr.ctr0->array = NULL;

		if (r->out.ctr.ctr0->count == 0) break;

		r->out.ctr.ctr0->array = talloc_array_p(mem_ctx, struct srvsvc_NetShareInfo0, r->out.ctr.ctr0->count);
		WERR_TALLOC_CHECK(r->out.ctr.ctr0->array);

		for (i=0;i<r->out.ctr.ctr0->count;i++) {
			r->out.ctr.ctr0->array[i].name = dcesrv_common_get_share_name(mem_ctx, dce_ctx, i);
			WERR_TALLOC_CHECK(r->out.ctr.ctr0->array[i].name);
		}

		r->out.totalentries = r->out.ctr.ctr0->count;

		break;
		}
	case 1: {
		int i;
		r->out.ctr.ctr1 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr1);
		WERR_TALLOC_CHECK(r->out.ctr.ctr1);

		r->out.ctr.ctr1->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		r->out.ctr.ctr1->array = NULL;

		if (r->out.ctr.ctr1->count == 0) break;

		r->out.ctr.ctr1->array = talloc_array_p(mem_ctx, struct srvsvc_NetShareInfo1, r->out.ctr.ctr1->count);
		WERR_TALLOC_CHECK(r->out.ctr.ctr1->array);

		for (i=0;i<r->out.ctr.ctr1->count;i++) {
			r->out.ctr.ctr1->array[i].name = dcesrv_common_get_share_name(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr1->array[i].type = dcesrv_common_get_share_type(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr1->array[i].comment = dcesrv_common_get_share_comment(mem_ctx, dce_ctx, i);
		}

		r->out.totalentries = r->out.ctr.ctr1->count;

		break;
		}
	case 2: {
		int i;
		r->out.ctr.ctr2 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr2);
		WERR_TALLOC_CHECK(r->out.ctr.ctr2);

		r->out.ctr.ctr2->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		r->out.ctr.ctr2->array = NULL;

		if (r->out.ctr.ctr2->count == 0) break;

		r->out.ctr.ctr2->array = talloc_array_p(mem_ctx, struct srvsvc_NetShareInfo2, r->out.ctr.ctr2->count);
		WERR_TALLOC_CHECK(r->out.ctr.ctr2->array);

		for (i=0;i<r->out.ctr.ctr2->count;i++) {
			r->out.ctr.ctr2->array[i].name = dcesrv_common_get_share_name(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr2->array[i].type = dcesrv_common_get_share_type(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr2->array[i].comment = dcesrv_common_get_share_comment(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr2->array[i].permissions = dcesrv_common_get_share_permissions(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr2->array[i].max_users = dcesrv_common_get_share_max_users(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr2->array[i].current_users = dcesrv_common_get_share_current_users(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr2->array[i].path = dcesrv_common_get_share_path(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr2->array[i].password = dcesrv_common_get_share_password(mem_ctx, dce_ctx, i);
		}

		r->out.totalentries = r->out.ctr.ctr2->count;

		break;
		}
	case 501:{
		int i;
		r->out.ctr.ctr501 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr501);
		WERR_TALLOC_CHECK(r->out.ctr.ctr501);

		r->out.ctr.ctr501->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		r->out.ctr.ctr501->array = NULL;

		if (r->out.ctr.ctr501->count == 0) break;

		r->out.ctr.ctr501->array = talloc_array_p(mem_ctx, struct srvsvc_NetShareInfo501, r->out.ctr.ctr501->count);
		WERR_TALLOC_CHECK(r->out.ctr.ctr501->array);

		for (i=0;i<r->out.ctr.ctr501->count;i++) {
			r->out.ctr.ctr501->array[i].name = dcesrv_common_get_share_name(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr501->array[i].type = dcesrv_common_get_share_type(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr501->array[i].comment = dcesrv_common_get_share_comment(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr501->array[i].csc_policy = dcesrv_common_get_share_csc_policy(mem_ctx, dce_ctx, i);
		}

		r->out.totalentries = r->out.ctr.ctr501->count;

		break;
		}
	case 502:{
		int i;
		r->out.ctr.ctr502 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr502);
		WERR_TALLOC_CHECK(r->out.ctr.ctr502);

		r->out.ctr.ctr502->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		r->out.ctr.ctr502->array = NULL;

		if (r->out.ctr.ctr502->count == 0) break;

		r->out.ctr.ctr502->array = talloc_array_p(mem_ctx, struct srvsvc_NetShareInfo502, r->out.ctr.ctr502->count);
		WERR_TALLOC_CHECK(r->out.ctr.ctr502->array);

		for (i=0;i<r->out.ctr.ctr502->count;i++) {
			r->out.ctr.ctr502->array[i].name = dcesrv_common_get_share_name(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].type = dcesrv_common_get_share_type(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].comment = dcesrv_common_get_share_comment(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].permissions = dcesrv_common_get_share_permissions(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].max_users = dcesrv_common_get_share_max_users(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].current_users = dcesrv_common_get_share_current_users(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].path = dcesrv_common_get_share_path(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].password = dcesrv_common_get_share_password(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].unknown = dcesrv_common_get_share_unknown(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].sd = dcesrv_common_get_security_descriptor(mem_ctx, dce_ctx, i);
		}

		r->out.totalentries = r->out.ctr.ctr502->count;

		break;
		}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_OK;
}


/* 
  srvsvc_NetShareGetInfo 
*/
static WERROR srvsvc_NetShareGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetShareGetInfo *r)
{
	switch (r->in.level) {
	case 0:
		r->out.info.info0 = NULL;

		return WERR_NOT_SUPPORTED;

	case 1:
		r->out.info.info0 = NULL;

		return WERR_NOT_SUPPORTED;

	case 2:
		r->out.info.info0 = NULL;

		return WERR_NOT_SUPPORTED;

	case 501:
		r->out.info.info0 = NULL;

		return WERR_NOT_SUPPORTED;

	case 502:
		r->out.info.info0 = NULL;

		return WERR_NOT_SUPPORTED;

	default:
		return WERR_UNKNOWN_LEVEL;
		break;
	}

	return WERR_OK;
}


/* 
  srvsvc_NetShareSetInfo 
*/
static WERROR srvsvc_NetShareSetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetShareSetInfo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NetShareDel 
*/
static WERROR srvsvc_NetShareDel(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetShareDel *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NetShareDelSticky 
*/
static WERROR srvsvc_NetShareDelSticky(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetShareDelSticky *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NetShareCheck 
*/
static WERROR srvsvc_NetShareCheck(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetShareCheck *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NetSrvGetInfo 
*/
static WERROR srvsvc_NetSrvGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetSrvGetInfo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NetSrvSetInfo 
*/
static WERROR srvsvc_NetSrvSetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetSrvSetInfo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NetDiskEnum 
*/
static WERROR srvsvc_NetDiskEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetDiskEnum *r)
{
	r->out.count = 0;
	r->out.ctr0 = NULL;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;

	switch (r->in.level) {
	case 0: {
		r->out.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetDiskCtr0);
		WERR_TALLOC_CHECK(r->out.ctr0);

		r->out.ctr0->unknown = 0x1;
		r->out.ctr0->count = 0;
		r->out.ctr0->array = NULL;

		return WERR_NOT_SUPPORTED;
		break;
		}
	default:
		return WERR_UNKNOWN_LEVEL;
		break;
	}

	return WERR_OK;
}


/* 
  srvsvc_NETRSERVERSTATISTICSGET 
*/
static WERROR srvsvc_NETRSERVERSTATISTICSGET(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					     struct srvsvc_NETRSERVERSTATISTICSGET *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRSERVERTRANSPORTADD 
*/
static WERROR srvsvc_NETRSERVERTRANSPORTADD(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRSERVERTRANSPORTADD *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NetTransportEnum 
*/
static WERROR srvsvc_NetTransportEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetTransportEnum *r)
{
	r->out.level = r->in.level;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;

	switch (r->in.level) {
	case 0: {
		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetTransportCtr0);
		WERR_TALLOC_CHECK(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = 0;
		r->out.ctr.ctr0->array = NULL;

		return WERR_NOT_SUPPORTED;
		break;
		}
	case 1: {
		r->out.ctr.ctr1 = talloc_p(mem_ctx, struct srvsvc_NetTransportCtr1);
		WERR_TALLOC_CHECK(r->out.ctr.ctr1);

		r->out.ctr.ctr1->count = 0;
		r->out.ctr.ctr1->array = NULL;

		return WERR_NOT_SUPPORTED;
		break;
		}
	case 2: {
		r->out.ctr.ctr2 = talloc_p(mem_ctx, struct srvsvc_NetTransportCtr2);
		WERR_TALLOC_CHECK(r->out.ctr.ctr2);

		r->out.ctr.ctr2->count = 0;
		r->out.ctr.ctr2->array = NULL;

		return WERR_NOT_SUPPORTED;
		break;
		}
	case 3: {
		r->out.ctr.ctr3 = talloc_p(mem_ctx, struct srvsvc_NetTransportCtr3);
		WERR_TALLOC_CHECK(r->out.ctr.ctr3);

		r->out.ctr.ctr3->count = 0;
		r->out.ctr.ctr3->array = NULL;

		return WERR_NOT_SUPPORTED;
		break;
		}
	default:
		return WERR_UNKNOWN_LEVEL;
		break;
	}

	return WERR_OK;
}


/* 
  srvsvc_NETRSERVERTRANSPORTDEL 
*/
static WERROR srvsvc_NETRSERVERTRANSPORTDEL(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRSERVERTRANSPORTDEL *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NetRemoteTOD 
*/
static WERROR srvsvc_NetRemoteTOD(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetRemoteTOD *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRSERVERSETSERVICEBITS 
*/
static WERROR srvsvc_NETRSERVERSETSERVICEBITS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRSERVERSETSERVICEBITS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRPRPATHTYPE 
*/
static WERROR srvsvc_NETRPRPATHTYPE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRPRPATHTYPE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRPRPATHCANONICALIZE 
*/
static WERROR srvsvc_NETRPRPATHCANONICALIZE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRPRPATHCANONICALIZE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRPRPATHCOMPARE 
*/
static WERROR srvsvc_NETRPRPATHCOMPARE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRPRPATHCOMPARE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NET_NAME_VALIDATE 
*/
static WERROR srvsvc_NET_NAME_VALIDATE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NET_NAME_VALIDATE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRPRNAMECANONICALIZE 
*/
static WERROR srvsvc_NETRPRNAMECANONICALIZE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRPRNAMECANONICALIZE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRPRNAMECOMPARE 
*/
static WERROR srvsvc_NETRPRNAMECOMPARE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRPRNAMECOMPARE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NetShareEnum 
*/
static WERROR srvsvc_NetShareEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetShareEnum *r)
{
	struct dcesrv_context *dce_ctx = dce_call->conn->dce_ctx;
	r->out.level = r->in.level;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;

	switch (r->in.level) {
	case 0: {
		int i;

		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr0);
		WERR_TALLOC_CHECK(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		r->out.ctr.ctr0->array = NULL;

		if (r->out.ctr.ctr0->count == 0) break;

		r->out.ctr.ctr0->array = talloc_array_p(mem_ctx, 
							struct srvsvc_NetShareInfo0, 
							r->out.ctr.ctr0->count);
		WERR_TALLOC_CHECK(r->out.ctr.ctr0->array);

		for (i=0;i<r->out.ctr.ctr0->count;i++) {
			r->out.ctr.ctr0->array[i].name = dcesrv_common_get_share_name(mem_ctx, dce_ctx, i);
			WERR_TALLOC_CHECK(r->out.ctr.ctr0->array[i].name);
		}

		r->out.totalentries = r->out.ctr.ctr0->count;

		break;
		}
	case 1: {
		int i;
		r->out.ctr.ctr1 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr1);
		WERR_TALLOC_CHECK(r->out.ctr.ctr1);

		r->out.ctr.ctr1->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		r->out.ctr.ctr1->array = NULL;

		if (r->out.ctr.ctr1->count == 0) break;

		r->out.ctr.ctr1->array = talloc_array_p(mem_ctx, 
							struct srvsvc_NetShareInfo1, 
							r->out.ctr.ctr1->count);
		WERR_TALLOC_CHECK(r->out.ctr.ctr1->array);

		for (i=0;i<r->out.ctr.ctr1->count;i++) {
			r->out.ctr.ctr1->array[i].name = dcesrv_common_get_share_name(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr1->array[i].type = dcesrv_common_get_share_type(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr1->array[i].comment = dcesrv_common_get_share_comment(mem_ctx, dce_ctx, i);
		}

		r->out.totalentries = r->out.ctr.ctr1->count;

		break;
		}
	case 2: {
		int i;
		r->out.ctr.ctr2 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr2);
		WERR_TALLOC_CHECK(r->out.ctr.ctr2);

		r->out.ctr.ctr2->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		r->out.ctr.ctr2->array = NULL;

		if (r->out.ctr.ctr2->count == 0) break;

		r->out.ctr.ctr2->array = talloc_array_p(mem_ctx, 
							struct srvsvc_NetShareInfo2,
							r->out.ctr.ctr2->count);
		WERR_TALLOC_CHECK(r->out.ctr.ctr2->array);

		for (i=0;i<r->out.ctr.ctr2->count;i++) {
			r->out.ctr.ctr2->array[i].name = dcesrv_common_get_share_name(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr2->array[i].type = dcesrv_common_get_share_type(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr2->array[i].comment = dcesrv_common_get_share_comment(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr2->array[i].permissions = dcesrv_common_get_share_permissions(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr2->array[i].max_users = dcesrv_common_get_share_max_users(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr2->array[i].current_users = dcesrv_common_get_share_current_users(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr2->array[i].path = dcesrv_common_get_share_path(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr2->array[i].password = dcesrv_common_get_share_password(mem_ctx, dce_ctx, i);
		}

		r->out.totalentries = r->out.ctr.ctr2->count;

		break;
		}
	case 501:{
		int i;
		r->out.ctr.ctr501 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr501);
		WERR_TALLOC_CHECK(r->out.ctr.ctr501);

		r->out.ctr.ctr501->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		r->out.ctr.ctr501->array = NULL;

		if (r->out.ctr.ctr501->count == 0) break;

		r->out.ctr.ctr501->array = talloc_array_p(mem_ctx, 
							  struct srvsvc_NetShareInfo501,
							  r->out.ctr.ctr501->count);
		WERR_TALLOC_CHECK(r->out.ctr.ctr501->array);

		for (i=0;i<r->out.ctr.ctr501->count;i++) {
			r->out.ctr.ctr501->array[i].name = dcesrv_common_get_share_name(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr501->array[i].type = dcesrv_common_get_share_type(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr501->array[i].comment = dcesrv_common_get_share_comment(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr501->array[i].csc_policy = dcesrv_common_get_share_csc_policy(mem_ctx, dce_ctx, i);
		}

		r->out.totalentries = r->out.ctr.ctr501->count;

		break;
		}
	case 502:{
		int i;
		r->out.ctr.ctr502 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr502);
		WERR_TALLOC_CHECK(r->out.ctr.ctr502);

		r->out.ctr.ctr502->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		r->out.ctr.ctr502->array = NULL;

		if (r->out.ctr.ctr502->count == 0) break;

		r->out.ctr.ctr502->array = talloc_array_p(mem_ctx, 
							  struct srvsvc_NetShareInfo502,
							  r->out.ctr.ctr502->count);
		WERR_TALLOC_CHECK(r->out.ctr.ctr502->array);

		for (i=0;i<r->out.ctr.ctr502->count;i++) {
			r->out.ctr.ctr502->array[i].name = dcesrv_common_get_share_name(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].type = dcesrv_common_get_share_type(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].comment = dcesrv_common_get_share_comment(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].permissions = dcesrv_common_get_share_permissions(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].max_users = dcesrv_common_get_share_max_users(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].current_users = dcesrv_common_get_share_current_users(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].path = dcesrv_common_get_share_path(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].password = dcesrv_common_get_share_password(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].unknown = dcesrv_common_get_share_unknown(mem_ctx, dce_ctx, i);
			r->out.ctr.ctr502->array[i].sd = dcesrv_common_get_security_descriptor(mem_ctx, dce_ctx, i);
		}

		r->out.totalentries = r->out.ctr.ctr502->count;

		break;
		}
	default:
		return WERR_UNKNOWN_LEVEL;
		break;
	}

	return WERR_OK;
}


/* 
  srvsvc_NETRSHAREDELSTART 
*/
static WERROR srvsvc_NETRSHAREDELSTART(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRSHAREDELSTART *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRSHAREDELCOMMIT 
*/
static WERROR srvsvc_NETRSHAREDELCOMMIT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRSHAREDELCOMMIT *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NET_FILE_QUERY_SECDESC 
*/
static WERROR srvsvc_NET_FILE_QUERY_SECDESC(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NET_FILE_QUERY_SECDESC *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NET_FILE_SET_SECDESC 
*/
static WERROR srvsvc_NET_FILE_SET_SECDESC(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NET_FILE_SET_SECDESC *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRSERVERTRANSPORTADDEX 
*/
static WERROR srvsvc_NETRSERVERTRANSPORTADDEX(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRSERVERTRANSPORTADDEX *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRSERVERSETSERVICEBITSEX 
*/
static WERROR srvsvc_NETRSERVERSETSERVICEBITSEX(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRSERVERSETSERVICEBITSEX *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRDFSGETVERSION 
*/
static WERROR srvsvc_NETRDFSGETVERSION(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSGETVERSION *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRDFSCREATELOCALPARTITION 
*/
static WERROR srvsvc_NETRDFSCREATELOCALPARTITION(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSCREATELOCALPARTITION *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRDFSDELETELOCALPARTITION 
*/
static WERROR srvsvc_NETRDFSDELETELOCALPARTITION(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSDELETELOCALPARTITION *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRDFSSETLOCALVOLUMESTATE 
*/
static WERROR srvsvc_NETRDFSSETLOCALVOLUMESTATE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSSETLOCALVOLUMESTATE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRDFSSETSERVERINFO 
*/
static WERROR srvsvc_NETRDFSSETSERVERINFO(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSSETSERVERINFO *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRDFSCREATEEXITPOINT 
*/
static WERROR srvsvc_NETRDFSCREATEEXITPOINT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSCREATEEXITPOINT *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRDFSDELETEEXITPOINT 
*/
static WERROR srvsvc_NETRDFSDELETEEXITPOINT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSDELETEEXITPOINT *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRDFSMODIFYPREFIX 
*/
static WERROR srvsvc_NETRDFSMODIFYPREFIX(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSMODIFYPREFIX *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRDFSFIXLOCALVOLUME 
*/
static WERROR srvsvc_NETRDFSFIXLOCALVOLUME(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSFIXLOCALVOLUME *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRDFSMANAGERREPORTSITEINFO 
*/
static WERROR srvsvc_NETRDFSMANAGERREPORTSITEINFO(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSMANAGERREPORTSITEINFO *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  srvsvc_NETRSERVERTRANSPORTDELEX 
*/
static WERROR srvsvc_NETRSERVERTRANSPORTDELEX(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRSERVERTRANSPORTDELEX *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_srvsvc_s.c"
