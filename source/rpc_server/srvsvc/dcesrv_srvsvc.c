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
#include "rpc_server/common/common.h"

/* 
  srvsvc_NetCharDevEnum 
*/
static NTSTATUS srvsvc_NetCharDevEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetCharDevEnum *r)
{
	r->out.level = r->in.level;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;
	r->out.result = WERR_OK;

	switch (r->in.level) {
	case 0:
		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetCharDevCtr0);
		WERR_TALLOC_CHECK(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = 0;
		r->out.ctr.ctr0->array = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
	case 1:
		r->out.ctr.ctr1 = talloc_p(mem_ctx, struct srvsvc_NetCharDevCtr1);
		WERR_TALLOC_CHECK(r->out.ctr.ctr1);

		r->out.ctr.ctr1->count = 0;
		r->out.ctr.ctr1->array = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
	default:
		r->out.result = WERR_UNKNOWN_LEVEL;
		break;
	}

	return NT_STATUS_OK;
}


/* 
  srvsvc_NetCharDevGetInfo 
*/
static NTSTATUS srvsvc_NetCharDevGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetCharDevGetInfo *r)
{
	r->out.result = WERR_OK;

	switch (r->in.level) {
	case 0:
		r->out.info.info0 = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
	case 1:
		r->out.info.info1 = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
	default:
		r->out.result = WERR_UNKNOWN_LEVEL;
		break;
	}

	return NT_STATUS_OK;
}


/* 
  srvsvc_NetCharDevControl 
*/
static NTSTATUS srvsvc_NetCharDevControl(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetCharDevControl *r)
{
	r->out.result = WERR_NOT_SUPPORTED;
	return NT_STATUS_OK;
}


/* 
  srvsvc_NetCharDevQEnum 
*/
static NTSTATUS srvsvc_NetCharDevQEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetCharDevQEnum *r)
{
	r->out.level = r->in.level;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;
	r->out.result = WERR_OK;

	switch (r->in.level) {
	case 0:
		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetCharDevQCtr0);
		WERR_TALLOC_CHECK(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = 0;
		r->out.ctr.ctr0->array = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
	case 1:
		r->out.ctr.ctr1 = talloc_p(mem_ctx, struct srvsvc_NetCharDevQCtr1);
		WERR_TALLOC_CHECK(r->out.ctr.ctr1);

		r->out.ctr.ctr1->count = 0;
		r->out.ctr.ctr1->array = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
	default:
		r->out.result = WERR_UNKNOWN_LEVEL;
		break;
	}

	return NT_STATUS_OK;
}


/* 
  srvsvc_NetCharDevQGetInfo 
*/
static NTSTATUS srvsvc_NetCharDevQGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetCharDevQGetInfo *r)
{
	r->out.result = WERR_OK;

	switch (r->in.level) {
	case 0:
		r->out.info.info0 = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
	case 1:
		r->out.info.info1 = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
	default:
		r->out.result = WERR_UNKNOWN_LEVEL;
		break;
	}

	return NT_STATUS_OK;
}


/* 
  srvsvc_NetCharDevQSetInfo 
*/
static NTSTATUS srvsvc_NetCharDevQSetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetCharDevQSetInfo *r)
{
	r->out.result = WERR_OK;

	switch (r->in.level) {
	case 0:	
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		r->out.result = WERR_NOT_SUPPORTED;
		break;
	case 1:
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		r->out.result = WERR_NOT_SUPPORTED;
		break;
	default:
		r->out.result = WERR_UNKNOWN_LEVEL;
		break;
	}

	return NT_STATUS_OK;
}


/* 
  srvsvc_NetCharDevQPurge 
*/
static NTSTATUS srvsvc_NetCharDevQPurge(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetCharDevQPurge *r)
{
	r->out.result = WERR_NOT_SUPPORTED;
	return NT_STATUS_OK;
}


/* 
  srvsvc_NetCharDevQPurgeSelf 
*/
static NTSTATUS srvsvc_NetCharDevQPurgeSelf(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetCharDevQPurgeSelf *r)
{
	r->out.result = WERR_NOT_SUPPORTED;
	return NT_STATUS_OK;
}


/* 
  srvsvc_NetConnEnum 
*/
static NTSTATUS srvsvc_NetConnEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetConnEnum *r)
{
	r->out.level = r->in.level;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;
	r->out.result = WERR_OK;

	switch (r->in.level) {
	case 0: {
		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetConnCtr0);
		WERR_TALLOC_CHECK(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = 0;
		r->out.ctr.ctr0->array = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	case 1: {
		r->out.ctr.ctr1 = talloc_p(mem_ctx, struct srvsvc_NetConnCtr1);
		WERR_TALLOC_CHECK(r->out.ctr.ctr1);

		r->out.ctr.ctr1->count = 0;
		r->out.ctr.ctr1->array = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	default:
		r->out.result = WERR_UNKNOWN_LEVEL;
		break;
	}

	return NT_STATUS_OK;
}


/* 
  srvsvc_NetFileEnum 
*/
static NTSTATUS srvsvc_NetFileEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetFileEnum *r)
{
	r->out.level = r->in.level;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;
	r->out.result = WERR_OK;

	switch (r->in.level) {
	case 2: {
		r->out.ctr.ctr2 = talloc_p(mem_ctx, struct srvsvc_NetFileCtr2);
		WERR_TALLOC_CHECK(r->out.ctr.ctr2);

		r->out.ctr.ctr2->count = 0;
		r->out.ctr.ctr2->array = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	case 3: {
		r->out.ctr.ctr3 = talloc_p(mem_ctx, struct srvsvc_NetFileCtr3);
		WERR_TALLOC_CHECK(r->out.ctr.ctr3);

		r->out.ctr.ctr3->count = 0;
		r->out.ctr.ctr3->array = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	default:
		r->out.result = WERR_UNKNOWN_LEVEL;
		break;
	}

	return NT_STATUS_OK;
}


/* 
  srvsvc_NetFileGetInfo 
*/
static NTSTATUS srvsvc_NetFileGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetFileGetInfo *r)
{
	r->out.result = WERR_OK;

	switch (r->in.level) {
	case 2: {
		r->out.info.info2 = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	case 3: {
		r->out.info.info3 = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	default:
		r->out.result = WERR_UNKNOWN_LEVEL;
		break;
	}

	return NT_STATUS_OK;
}


/* 
  srvsvc_NetFileClose 
*/
static NTSTATUS srvsvc_NetFileClose(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetFileClose *r)
{
	r->out.result = WERR_NOT_SUPPORTED;
	return NT_STATUS_OK;
}


/* 
  srvsvc_NetSessEnum 
*/
static NTSTATUS srvsvc_NetSessEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetSessEnum *r)
{
	r->out.level = r->in.level;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;
	r->out.result = WERR_OK;

	switch (r->in.level) {
	case 0: {
		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetSessCtr0);
		WERR_TALLOC_CHECK(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = 0;
		r->out.ctr.ctr0->array = talloc(mem_ctx, r->out.ctr.ctr0->count*sizeof(struct srvsvc_NetSessInfo0));

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	case 1: {
		r->out.ctr.ctr1 = talloc_p(mem_ctx, struct srvsvc_NetSessCtr1);
		WERR_TALLOC_CHECK(r->out.ctr.ctr1);

		r->out.ctr.ctr1->count = 0;
		r->out.ctr.ctr1->array = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	case 2: {
		r->out.ctr.ctr2 = talloc_p(mem_ctx, struct srvsvc_NetSessCtr2);
		WERR_TALLOC_CHECK(r->out.ctr.ctr2);

		r->out.ctr.ctr2->count = 0;
		r->out.ctr.ctr2->array = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	case 10:{
		r->out.ctr.ctr10 = talloc_p(mem_ctx, struct srvsvc_NetSessCtr10);
		WERR_TALLOC_CHECK(r->out.ctr.ctr10);

		r->out.ctr.ctr2->count = 0;
		r->out.ctr.ctr2->array = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	case 502:{
		r->out.ctr.ctr502 = talloc_p(mem_ctx, struct srvsvc_NetSessCtr502);
		WERR_TALLOC_CHECK(r->out.ctr.ctr502);

		r->out.ctr.ctr2->count = 0;
		r->out.ctr.ctr2->array = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	default:
		r->out.result = WERR_UNKNOWN_LEVEL;
		break;
	}

	return NT_STATUS_OK;
}


/* 
  srvsvc_NetSessDel 
*/
static NTSTATUS srvsvc_NetSessDel(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetSessDel *r)
{
	r->out.result = WERR_NOT_SUPPORTED;
	return NT_STATUS_OK;
}


/* 
  srvsvc_NetShareAdd 
*/
static NTSTATUS srvsvc_NetShareAdd(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetShareAdd *r)
{
	r->out.result = WERR_OK;

	switch (r->in.level) {
	case 0:	
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		r->out.result = WERR_NOT_SUPPORTED;
		break;
	case 1:
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		r->out.result = WERR_NOT_SUPPORTED;
		break;
	case 2:
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		r->out.result = WERR_NOT_SUPPORTED;
		break;
	case 501:
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		r->out.result = WERR_NOT_SUPPORTED;
		break;
	case 502:
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		r->out.result = WERR_NOT_SUPPORTED;
		break;
	default:
		r->out.result = WERR_UNKNOWN_LEVEL;
		break;
	}

	return NT_STATUS_OK;
}


/* 
  srvsvc_NetShareEnumAll
*/
static NTSTATUS srvsvc_NetShareEnumAll(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetShareEnumAll *r)
{
	struct dcesrv_context *dce_ctx = dce_call->conn->dce_ctx;
	r->out.level = r->in.level;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;
	r->out.result = WERR_OK;

	switch (r->in.level) {
	case 0: {
		int i;

		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr0);
		WERR_TALLOC_CHECK(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		r->out.ctr.ctr0->array = NULL;

		if (r->out.ctr.ctr0->count == 0) break;

		r->out.ctr.ctr0->array = talloc(mem_ctx, r->out.ctr.ctr0->count*sizeof(struct srvsvc_NetShareInfo0));
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

		r->out.ctr.ctr1->array = talloc(mem_ctx, r->out.ctr.ctr1->count*sizeof(struct srvsvc_NetShareInfo1));
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

		r->out.ctr.ctr2->array = talloc(mem_ctx, r->out.ctr.ctr2->count*sizeof(struct srvsvc_NetShareInfo2));
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

		r->out.ctr.ctr501->array = talloc(mem_ctx, r->out.ctr.ctr501->count*sizeof(struct srvsvc_NetShareInfo501));
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

		r->out.ctr.ctr502->array = talloc(mem_ctx, r->out.ctr.ctr502->count*sizeof(struct srvsvc_NetShareInfo502));
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
		r->out.result = WERR_UNKNOWN_LEVEL;
		break;
	}

	return NT_STATUS_OK;
}


/* 
  srvsvc_NetShareGetInfo 
*/
static NTSTATUS srvsvc_NetShareGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetShareGetInfo *r)
{
	r->out.result = WERR_OK;

	switch (r->in.level) {
	case 0: {
		r->out.info.info0 = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	case 1: {
		r->out.info.info0 = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	case 2: {
		r->out.info.info0 = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	case 501:{
		r->out.info.info0 = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	case 502:{
		r->out.info.info0 = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	default:
		r->out.result = WERR_UNKNOWN_LEVEL;
		break;
	}

	return NT_STATUS_OK;
}


/* 
  srvsvc_NetShareSetInfo 
*/
static NTSTATUS srvsvc_NetShareSetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetShareSetInfo *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NetShareDel 
*/
static NTSTATUS srvsvc_NetShareDel(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetShareDel *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NetShareDelSticky 
*/
static NTSTATUS srvsvc_NetShareDelSticky(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetShareDelSticky *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NetShareCheck 
*/
static NTSTATUS srvsvc_NetShareCheck(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetShareCheck *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NetSrvGetInfo 
*/
static NTSTATUS srvsvc_NetSrvGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetSrvGetInfo *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NetSrvSetInfo 
*/
static NTSTATUS srvsvc_NetSrvSetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetSrvSetInfo *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NetDiskEnum 
*/
static NTSTATUS srvsvc_NetDiskEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetDiskEnum *r)
{
	r->out.count = 0;
	r->out.ctr0 = NULL;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;
	r->out.result = WERR_OK;

	switch (r->in.level) {
	case 0: {
		r->out.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetDiskCtr0);
		WERR_TALLOC_CHECK(r->out.ctr0);

		r->out.ctr0->unknown = 0x1;
		r->out.ctr0->count = 0;
		r->out.ctr0->array = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	default:
		r->out.result = WERR_UNKNOWN_LEVEL;
		break;
	}

	return NT_STATUS_OK;
}


/* 
  srvsvc_NETRSERVERSTATISTICSGET 
*/
static NTSTATUS srvsvc_NETRSERVERSTATISTICSGET(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRSERVERSTATISTICSGET *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRSERVERTRANSPORTADD 
*/
static NTSTATUS srvsvc_NETRSERVERTRANSPORTADD(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRSERVERTRANSPORTADD *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NetTransportEnum 
*/
static NTSTATUS srvsvc_NetTransportEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetTransportEnum *r)
{
	ZERO_STRUCT(r->out);
	r->out.result = WERR_NOT_SUPPORTED;
	return NT_STATUS_OK;
}


/* 
  srvsvc_NETRSERVERTRANSPORTDEL 
*/
static NTSTATUS srvsvc_NETRSERVERTRANSPORTDEL(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRSERVERTRANSPORTDEL *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NET_REMOTE_TOD 
*/
static NTSTATUS srvsvc_NET_REMOTE_TOD(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NET_REMOTE_TOD *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRSERVERSETSERVICEBITS 
*/
static NTSTATUS srvsvc_NETRSERVERSETSERVICEBITS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRSERVERSETSERVICEBITS *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRPRPATHTYPE 
*/
static NTSTATUS srvsvc_NETRPRPATHTYPE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRPRPATHTYPE *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRPRPATHCANONICALIZE 
*/
static NTSTATUS srvsvc_NETRPRPATHCANONICALIZE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRPRPATHCANONICALIZE *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRPRPATHCOMPARE 
*/
static NTSTATUS srvsvc_NETRPRPATHCOMPARE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRPRPATHCOMPARE *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NET_NAME_VALIDATE 
*/
static NTSTATUS srvsvc_NET_NAME_VALIDATE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NET_NAME_VALIDATE *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRPRNAMECANONICALIZE 
*/
static NTSTATUS srvsvc_NETRPRNAMECANONICALIZE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRPRNAMECANONICALIZE *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRPRNAMECOMPARE 
*/
static NTSTATUS srvsvc_NETRPRNAMECOMPARE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRPRNAMECOMPARE *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NetShareEnum 
*/
static NTSTATUS srvsvc_NetShareEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetShareEnum *r)
{
	struct dcesrv_context *dce_ctx = dce_call->conn->dce_ctx;
	r->out.level = r->in.level;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;
	r->out.result = WERR_OK;

	switch (r->in.level) {
	case 0: {
		int i;

		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr0);
		WERR_TALLOC_CHECK(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		r->out.ctr.ctr0->array = NULL;

		if (r->out.ctr.ctr0->count == 0) break;

		r->out.ctr.ctr0->array = talloc(mem_ctx, r->out.ctr.ctr0->count*sizeof(struct srvsvc_NetShareInfo0));
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

		r->out.ctr.ctr1->array = talloc(mem_ctx, r->out.ctr.ctr1->count*sizeof(struct srvsvc_NetShareInfo1));
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

		r->out.ctr.ctr2->array = talloc(mem_ctx, r->out.ctr.ctr2->count*sizeof(struct srvsvc_NetShareInfo2));
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

		r->out.ctr.ctr501->array = talloc(mem_ctx, r->out.ctr.ctr501->count*sizeof(struct srvsvc_NetShareInfo501));
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

		r->out.ctr.ctr502->array = talloc(mem_ctx, r->out.ctr.ctr502->count*sizeof(struct srvsvc_NetShareInfo502));
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
		r->out.result = WERR_UNKNOWN_LEVEL;
		break;
	}

	return NT_STATUS_OK;
}


/* 
  srvsvc_NETRSHAREDELSTART 
*/
static NTSTATUS srvsvc_NETRSHAREDELSTART(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRSHAREDELSTART *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRSHAREDELCOMMIT 
*/
static NTSTATUS srvsvc_NETRSHAREDELCOMMIT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRSHAREDELCOMMIT *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NET_FILE_QUERY_SECDESC 
*/
static NTSTATUS srvsvc_NET_FILE_QUERY_SECDESC(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NET_FILE_QUERY_SECDESC *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NET_FILE_SET_SECDESC 
*/
static NTSTATUS srvsvc_NET_FILE_SET_SECDESC(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NET_FILE_SET_SECDESC *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRSERVERTRANSPORTADDEX 
*/
static NTSTATUS srvsvc_NETRSERVERTRANSPORTADDEX(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRSERVERTRANSPORTADDEX *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRSERVERSETSERVICEBITSEX 
*/
static NTSTATUS srvsvc_NETRSERVERSETSERVICEBITSEX(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRSERVERSETSERVICEBITSEX *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRDFSGETVERSION 
*/
static NTSTATUS srvsvc_NETRDFSGETVERSION(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSGETVERSION *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRDFSCREATELOCALPARTITION 
*/
static NTSTATUS srvsvc_NETRDFSCREATELOCALPARTITION(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSCREATELOCALPARTITION *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRDFSDELETELOCALPARTITION 
*/
static NTSTATUS srvsvc_NETRDFSDELETELOCALPARTITION(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSDELETELOCALPARTITION *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRDFSSETLOCALVOLUMESTATE 
*/
static NTSTATUS srvsvc_NETRDFSSETLOCALVOLUMESTATE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSSETLOCALVOLUMESTATE *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRDFSSETSERVERINFO 
*/
static NTSTATUS srvsvc_NETRDFSSETSERVERINFO(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSSETSERVERINFO *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRDFSCREATEEXITPOINT 
*/
static NTSTATUS srvsvc_NETRDFSCREATEEXITPOINT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSCREATEEXITPOINT *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRDFSDELETEEXITPOINT 
*/
static NTSTATUS srvsvc_NETRDFSDELETEEXITPOINT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSDELETEEXITPOINT *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRDFSMODIFYPREFIX 
*/
static NTSTATUS srvsvc_NETRDFSMODIFYPREFIX(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSMODIFYPREFIX *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRDFSFIXLOCALVOLUME 
*/
static NTSTATUS srvsvc_NETRDFSFIXLOCALVOLUME(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSFIXLOCALVOLUME *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRDFSMANAGERREPORTSITEINFO 
*/
static NTSTATUS srvsvc_NETRDFSMANAGERREPORTSITEINFO(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRDFSMANAGERREPORTSITEINFO *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  srvsvc_NETRSERVERTRANSPORTDELEX 
*/
static NTSTATUS srvsvc_NETRSERVERTRANSPORTDELEX(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NETRSERVERTRANSPORTDELEX *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_srvsvc_s.c"
