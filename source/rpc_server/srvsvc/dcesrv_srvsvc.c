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
#include "system/time.h"

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
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = 0;
		r->out.ctr.ctr0->array = NULL;

		return WERR_NOT_SUPPORTED;

	case 1:
		r->out.ctr.ctr1 = talloc_p(mem_ctx, struct srvsvc_NetCharDevCtr1);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr.ctr1);

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
	ZERO_STRUCT(r->out);

	switch (r->in.level) {
	case 0:
	{
		return WERR_NOT_SUPPORTED;
	}
	case 1:
	{
		return WERR_NOT_SUPPORTED;
	}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
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
	{
		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetCharDevQCtr0);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = 0;
		r->out.ctr.ctr0->array = NULL;

		return WERR_NOT_SUPPORTED;
	}
	case 1:
	{
		r->out.ctr.ctr1 = talloc_p(mem_ctx, struct srvsvc_NetCharDevQCtr1);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr.ctr1);

		r->out.ctr.ctr1->count = 0;
		r->out.ctr.ctr1->array = NULL;

		return WERR_NOT_SUPPORTED;
	}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
}


/* 
  srvsvc_NetCharDevQGetInfo 
*/
static WERROR srvsvc_NetCharDevQGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct srvsvc_NetCharDevQGetInfo *r)
{
	ZERO_STRUCT(r->out);

	switch (r->in.level) {
	case 0:
	{
		return WERR_NOT_SUPPORTED;
	}
	case 1:
	{
		return WERR_NOT_SUPPORTED;
	}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
}


/* 
  srvsvc_NetCharDevQSetInfo 
*/
static WERROR srvsvc_NetCharDevQSetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetCharDevQSetInfo *r)
{
	switch (r->in.level) {
	case 0:
	{
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		return WERR_NOT_SUPPORTED;
	}
	case 1:
	{
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		return WERR_NOT_SUPPORTED;
	}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
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
	{
		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetConnCtr0);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = 0;
		r->out.ctr.ctr0->array = NULL;

		return WERR_NOT_SUPPORTED;
	}
	case 1:
	{
		r->out.ctr.ctr1 = talloc_p(mem_ctx, struct srvsvc_NetConnCtr1);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr.ctr1);

		r->out.ctr.ctr1->count = 0;
		r->out.ctr.ctr1->array = NULL;

		return WERR_NOT_SUPPORTED;
	}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
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
	{
		r->out.ctr.ctr2 = talloc_p(mem_ctx, struct srvsvc_NetFileCtr2);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr.ctr2);

		r->out.ctr.ctr2->count = 0;
		r->out.ctr.ctr2->array = NULL;

		return WERR_NOT_SUPPORTED;
	}
	case 3:
	{
		r->out.ctr.ctr3 = talloc_p(mem_ctx, struct srvsvc_NetFileCtr3);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr.ctr3);

		r->out.ctr.ctr3->count = 0;
		r->out.ctr.ctr3->array = NULL;

		return WERR_NOT_SUPPORTED;
	}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
}


/* 
  srvsvc_NetFileGetInfo 
*/
static WERROR srvsvc_NetFileGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				    struct srvsvc_NetFileGetInfo *r)
{
	ZERO_STRUCT(r->out);

	switch (r->in.level) {
	case 2:
	{
		return WERR_NOT_SUPPORTED;
	}
	case 3:
	{
		return WERR_NOT_SUPPORTED;
	}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
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
	{
		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetSessCtr0);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = 0;
		r->out.ctr.ctr0->array = NULL;

		return WERR_NOT_SUPPORTED;
	}
	case 1:
	{
		r->out.ctr.ctr1 = talloc_p(mem_ctx, struct srvsvc_NetSessCtr1);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr.ctr1);

		r->out.ctr.ctr1->count = 0;
		r->out.ctr.ctr1->array = NULL;

		return WERR_NOT_SUPPORTED;
	}
	case 2:
	{
		r->out.ctr.ctr2 = talloc_p(mem_ctx, struct srvsvc_NetSessCtr2);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr.ctr2);

		r->out.ctr.ctr2->count = 0;
		r->out.ctr.ctr2->array = NULL;

		return WERR_NOT_SUPPORTED;
	}
	case 10:
	{
		r->out.ctr.ctr10 = talloc_p(mem_ctx, struct srvsvc_NetSessCtr10);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr.ctr10);

		r->out.ctr.ctr2->count = 0;
		r->out.ctr.ctr2->array = NULL;

		return WERR_NOT_SUPPORTED;
	}
	case 502:
	{
		r->out.ctr.ctr502 = talloc_p(mem_ctx, struct srvsvc_NetSessCtr502);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr.ctr502);

		r->out.ctr.ctr2->count = 0;
		r->out.ctr.ctr2->array = NULL;

		return WERR_NOT_SUPPORTED;
	}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
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
	{
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		return WERR_NOT_SUPPORTED;
	}
	case 1:
	{
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		return WERR_NOT_SUPPORTED;
	}
	case 2:
	{
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		return WERR_NOT_SUPPORTED;
	}
	case 501:
	{	
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		return WERR_NOT_SUPPORTED;
	}
	case 502:
	{
		if (r->in.parm_error) {
			r->out.parm_error = r->in.parm_error;
		}
		return WERR_NOT_SUPPORTED;
	}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
}

static WERROR srvsvc_fiel_ShareInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				   int snum, uint32_t level, union srvsvc_NetShareInfo *info)
{
	struct dcesrv_context *dce_ctx = dce_call->conn->dce_ctx;

	switch (level) {
	case 0:
	{
		info->info0->name	= dcesrv_common_get_share_name(mem_ctx, dce_ctx, snum);
		W_ERROR_HAVE_NO_MEMORY(info->info0->name);

		return WERR_OK;
	}
	case 1:
	{
		info->info1->name	= dcesrv_common_get_share_name(mem_ctx, dce_ctx, snum);
		W_ERROR_HAVE_NO_MEMORY(info->info1->name);
		info->info1->type	= dcesrv_common_get_share_type(mem_ctx, dce_ctx, snum);
		info->info1->comment	= dcesrv_common_get_share_comment(mem_ctx, dce_ctx, snum);
		W_ERROR_HAVE_NO_MEMORY(info->info1->comment);

		return WERR_OK;
	}
	case 2:
	{
		info->info2->name		= dcesrv_common_get_share_name(mem_ctx, dce_ctx, snum);
		W_ERROR_HAVE_NO_MEMORY(info->info2->name);
		info->info2->type		= dcesrv_common_get_share_type(mem_ctx, dce_ctx, snum);
		info->info2->comment		= dcesrv_common_get_share_comment(mem_ctx, dce_ctx, snum);
		W_ERROR_HAVE_NO_MEMORY(info->info2->comment);
		info->info2->permissions 	= dcesrv_common_get_share_permissions(mem_ctx, dce_ctx, snum);
		info->info2->max_users 	= dcesrv_common_get_share_max_users(mem_ctx, dce_ctx, snum);
		info->info2->current_users	= dcesrv_common_get_share_current_users(mem_ctx, dce_ctx, snum);
		info->info2->path		= dcesrv_common_get_share_path(mem_ctx, dce_ctx, snum);
		W_ERROR_HAVE_NO_MEMORY(info->info2->path);
		info->info2->password		= dcesrv_common_get_share_password(mem_ctx, dce_ctx, snum);

		return WERR_OK;
	}
	case 501:
	{
		info->info501->name		= dcesrv_common_get_share_name(mem_ctx, dce_ctx, snum);
		W_ERROR_HAVE_NO_MEMORY(info->info501->name);
		info->info501->type		= dcesrv_common_get_share_type(mem_ctx, dce_ctx, snum);
		info->info501->comment		= dcesrv_common_get_share_comment(mem_ctx, dce_ctx, snum);
		W_ERROR_HAVE_NO_MEMORY(info->info501->comment);
		info->info501->csc_policy	= dcesrv_common_get_share_csc_policy(mem_ctx, dce_ctx, snum);

		return WERR_OK;
	}
	case 502:
	{
		info->info502->name		= dcesrv_common_get_share_name(mem_ctx, dce_ctx, snum);
		W_ERROR_HAVE_NO_MEMORY(info->info502->name);
		info->info502->type		= dcesrv_common_get_share_type(mem_ctx, dce_ctx, snum);
		info->info502->comment		= dcesrv_common_get_share_comment(mem_ctx, dce_ctx, snum);
		W_ERROR_HAVE_NO_MEMORY(info->info502->comment);
		info->info502->permissions	= dcesrv_common_get_share_permissions(mem_ctx, dce_ctx, snum);
		info->info502->max_users	= dcesrv_common_get_share_max_users(mem_ctx, dce_ctx, snum);
		info->info502->current_users	= dcesrv_common_get_share_current_users(mem_ctx, dce_ctx, snum);
		info->info502->path		= dcesrv_common_get_share_path(mem_ctx, dce_ctx, snum);
		W_ERROR_HAVE_NO_MEMORY(info->info502->path);
		info->info502->password		= dcesrv_common_get_share_password(mem_ctx, dce_ctx, snum);
		info->info502->unknown		= dcesrv_common_get_share_unknown(mem_ctx, dce_ctx, snum);
		info->info502->sd		= dcesrv_common_get_security_descriptor(mem_ctx, dce_ctx, snum);

		return WERR_OK;
	}
	case 1005:
	{
		info->info1005->dfs_flags	= dcesrv_common_get_share_dfs_flags(mem_ctx, dce_ctx, snum);

		return WERR_OK;
	}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
}

/* 
  srvsvc_NetShareEnumAll
*/
static WERROR srvsvc_NetShareEnumAll(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct srvsvc_NetShareEnumAll *r)
{
	struct dcesrv_context *dce_ctx = dce_call->conn->dce_ctx;

	r->out.level = r->in.level;
	ZERO_STRUCT(r->out.ctr);
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;

	/* TODO: - paging of results 
	 *       - access check
	 */

	switch (r->in.level) {
	case 0:
	{
		int i;
		struct srvsvc_NetShareCtr0 *ctr0;

		ctr0 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr0);
		W_ERROR_HAVE_NO_MEMORY(ctr0);

		ctr0->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		ctr0->array = NULL;

		if (ctr0->count == 0) {
			r->out.ctr.ctr0	= ctr0;
			return WERR_OK;
		}

		ctr0->array = talloc_array_p(mem_ctx, struct srvsvc_NetShareInfo0, ctr0->count);
		W_ERROR_HAVE_NO_MEMORY(ctr0->array);

		for (i=0; i < ctr0->count; i++) {
			WERROR status;
			union srvsvc_NetShareInfo info;

			info.info0 = &ctr0->array[i];
			status = srvsvc_fiel_ShareInfo(dce_call, mem_ctx, i, r->in.level, &info);
			if (!W_ERROR_IS_OK(status)) {
				return status;
			}
		}

		r->out.ctr.ctr0		= ctr0;
		r->out.totalentries	= r->out.ctr.ctr0->count;
		return WERR_OK;
	}
	case 1:
	{
		int i;
		struct srvsvc_NetShareCtr1 *ctr1;

		ctr1 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr1);
		W_ERROR_HAVE_NO_MEMORY(ctr1);

		ctr1->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		ctr1->array = NULL;

		if (ctr1->count == 0) {
			r->out.ctr.ctr1	= ctr1;
			return WERR_OK;
		}

		ctr1->array = talloc_array_p(mem_ctx, struct srvsvc_NetShareInfo1, ctr1->count);
		W_ERROR_HAVE_NO_MEMORY(ctr1->array);

		for (i=0; i < ctr1->count; i++) {
			WERROR status;
			union srvsvc_NetShareInfo info;

			info.info1 = &ctr1->array[i];
			status = srvsvc_fiel_ShareInfo(dce_call, mem_ctx, i, r->in.level, &info);
			if (!W_ERROR_IS_OK(status)) {
				return status;
			}
		}

		r->out.ctr.ctr1		= ctr1;
		r->out.totalentries	= r->out.ctr.ctr1->count;
		return WERR_OK;
	}
	case 2:
	{
		int i;
		struct srvsvc_NetShareCtr2 *ctr2;

		ctr2 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr2);
		W_ERROR_HAVE_NO_MEMORY(ctr2);

		ctr2->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		ctr2->array = NULL;

		if (ctr2->count == 0) {
			r->out.ctr.ctr2 = ctr2;
			return WERR_OK;
		}

		ctr2->array = talloc_array_p(mem_ctx, struct srvsvc_NetShareInfo2, ctr2->count);
		W_ERROR_HAVE_NO_MEMORY(ctr2->array);

		for (i=0; i < ctr2->count; i++) {
			WERROR status;
			union srvsvc_NetShareInfo info;

			info.info2 = &ctr2->array[i];
			status = srvsvc_fiel_ShareInfo(dce_call, mem_ctx, i, r->in.level, &info);
			if (!W_ERROR_IS_OK(status)) {
				return status;
			}
		}

		r->out.ctr.ctr2		= ctr2;
		r->out.totalentries	= r->out.ctr.ctr2->count;
		return WERR_OK;
	}
	case 501:
	{
		int i;
		struct srvsvc_NetShareCtr501 *ctr501;

		ctr501 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr501);
		W_ERROR_HAVE_NO_MEMORY(ctr501);

		ctr501->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		ctr501->array = NULL;

		if (ctr501->count == 0) {
			r->out.ctr.ctr501 = ctr501;
			return WERR_OK;
		}

		ctr501->array = talloc_array_p(mem_ctx, struct srvsvc_NetShareInfo501, ctr501->count);
		W_ERROR_HAVE_NO_MEMORY(ctr501->array);

		for (i=0; i < ctr501->count; i++) {
			WERROR status;
			union srvsvc_NetShareInfo info;

			info.info501 = &ctr501->array[i];
			status = srvsvc_fiel_ShareInfo(dce_call, mem_ctx, i, r->in.level, &info);
			if (!W_ERROR_IS_OK(status)) {
				return status;
			}
		}

		r->out.ctr.ctr501	= ctr501;
		r->out.totalentries	= r->out.ctr.ctr501->count;
		return WERR_OK;
	}
	case 502:
	{
		int i;
		struct srvsvc_NetShareCtr502 *ctr502;

		ctr502 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr502);
		W_ERROR_HAVE_NO_MEMORY(ctr502);

		ctr502->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		ctr502->array = NULL;

		if (ctr502->count == 0) {
			r->out.ctr.ctr502 = ctr502;
			return WERR_OK;
		}

		ctr502->array = talloc_array_p(mem_ctx, struct srvsvc_NetShareInfo502, ctr502->count);
		W_ERROR_HAVE_NO_MEMORY(ctr502->array);

		for (i=0; i < ctr502->count; i++) {
			WERROR status;
			union srvsvc_NetShareInfo info;

			info.info502 = &ctr502->array[i];
			status = srvsvc_fiel_ShareInfo(dce_call, mem_ctx, i, r->in.level, &info);
			if (!W_ERROR_IS_OK(status)) {
				return status;
			}
		}

		r->out.ctr.ctr502	= ctr502;
		r->out.totalentries	= r->out.ctr.ctr502->count;
		return WERR_OK;
	}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
}


/* 
  srvsvc_NetShareGetInfo 
*/
static WERROR srvsvc_NetShareGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct srvsvc_NetShareGetInfo *r)
{
	int snum;

	ZERO_STRUCT(r->out);

	/* TODO: - access check
	 */

	if (strcmp("", r->in.share_name) == 0) {
		return WERR_INVALID_PARAM;
	}

	snum = lp_servicenumber(r->in.share_name);
	if (snum < 0) {
		return WERR_NET_NAME_NOT_FOUND;
	}

	switch (r->in.level) {
	case 0:
	{
		WERROR status;
		union srvsvc_NetShareInfo info;

		info.info0 = talloc_p(mem_ctx, struct srvsvc_NetShareInfo0);
		W_ERROR_HAVE_NO_MEMORY(info.info0);

		status = srvsvc_fiel_ShareInfo(dce_call, mem_ctx, snum, r->in.level, &info);
		if (!W_ERROR_IS_OK(status)) {
			return status;
		}

		r->out.info.info0 = info.info0;
		return WERR_OK;
	}
	case 1:
	{
		WERROR status;
		union srvsvc_NetShareInfo info;

		info.info1 = talloc_p(mem_ctx, struct srvsvc_NetShareInfo1);
		W_ERROR_HAVE_NO_MEMORY(info.info1);

		status = srvsvc_fiel_ShareInfo(dce_call, mem_ctx, snum, r->in.level, &info);
		if (!W_ERROR_IS_OK(status)) {
			return status;
		}

		r->out.info.info1 = info.info1;
		return WERR_OK;
	}
	case 2:
	{
		WERROR status;
		union srvsvc_NetShareInfo info;

		info.info2 = talloc_p(mem_ctx, struct srvsvc_NetShareInfo2);
		W_ERROR_HAVE_NO_MEMORY(info.info2);

		status = srvsvc_fiel_ShareInfo(dce_call, mem_ctx, snum, r->in.level, &info);
		if (!W_ERROR_IS_OK(status)) {
			return status;
		}

		r->out.info.info2 = info.info2;
		return WERR_OK;
	}
	case 501:
	{
		WERROR status;
		union srvsvc_NetShareInfo info;

		info.info501 = talloc_p(mem_ctx, struct srvsvc_NetShareInfo501);
		W_ERROR_HAVE_NO_MEMORY(info.info501);

		status = srvsvc_fiel_ShareInfo(dce_call, mem_ctx, snum, r->in.level, &info);
		if (!W_ERROR_IS_OK(status)) {
			return status;
		}

		r->out.info.info501 = info.info501;
		return WERR_OK;
	}
	case 502:
	{
		WERROR status;
		union srvsvc_NetShareInfo info;

		info.info502 = talloc_p(mem_ctx, struct srvsvc_NetShareInfo502);
		W_ERROR_HAVE_NO_MEMORY(info.info502);

		status = srvsvc_fiel_ShareInfo(dce_call, mem_ctx, snum, r->in.level, &info);
		if (!W_ERROR_IS_OK(status)) {
			return status;
		}

		r->out.info.info502 = info.info502;
		return WERR_OK;
	}
	case 1005:
	{
		WERROR status;
		union srvsvc_NetShareInfo info;

		info.info1005 = talloc_p(mem_ctx, struct srvsvc_NetShareInfo1005);
		W_ERROR_HAVE_NO_MEMORY(info.info1005);

		status = srvsvc_fiel_ShareInfo(dce_call, mem_ctx, snum, r->in.level, &info);
		if (!W_ERROR_IS_OK(status)) {
			return status;
		}

		r->out.info.info1005 = info.info1005;
		return WERR_OK;
	}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
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
	ZERO_STRUCT(r->out);

	/* TODO: - access check
	 */

	if (strcmp("", r->in.device_name) == 0) {
		r->out.type = STYPE_IPC;
		return WERR_OK;
	}

	if (strcmp("C:\\", r->in.device_name) == 0) {
		r->out.type = STYPE_DISKTREE;
		return WERR_OK;
	}

	/* TODO: - lookup the share be devicename (path) */
	return WERR_DEVICE_NOT_SHARED;
}


/* 
  srvsvc_NetSrvGetInfo 
*/
static WERROR srvsvc_NetSrvGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct srvsvc_NetSrvGetInfo *r)
{
	struct dcesrv_context *dce_ctx = dce_call->conn->dce_ctx;

	ZERO_STRUCT(r->out);

	switch (r->in.level) {
	case 100:
	{
		struct srvsvc_NetSrvInfo100 *info100;

		info100 = talloc_p(mem_ctx, struct srvsvc_NetSrvInfo100);
		W_ERROR_HAVE_NO_MEMORY(info100);

		info100->platform_id	= dcesrv_common_get_platform_id(mem_ctx, dce_ctx);
		info100->server_name	= dcesrv_common_get_server_name(mem_ctx, dce_ctx, r->in.server_unc);
		W_ERROR_HAVE_NO_MEMORY(info100->server_name);

		r->out.info.info100 = info100;
		return WERR_OK;
	}
	case 101:
	{
		struct srvsvc_NetSrvInfo101 *info101;

		info101 = talloc_p(mem_ctx, struct srvsvc_NetSrvInfo101);
		W_ERROR_HAVE_NO_MEMORY(info101);

		info101->platform_id	= dcesrv_common_get_platform_id(mem_ctx, dce_ctx);
		info101->server_name	= dcesrv_common_get_server_name(mem_ctx, dce_ctx, r->in.server_unc);
		W_ERROR_HAVE_NO_MEMORY(info101->server_name);

		info101->version_major	= dcesrv_common_get_version_major(mem_ctx, dce_ctx);
		info101->version_minor	= dcesrv_common_get_version_minor(mem_ctx, dce_ctx);
		info101->server_type	= dcesrv_common_get_server_type(mem_ctx, dce_ctx);
		info101->comment	= talloc_strdup(mem_ctx, lp_serverstring());
		W_ERROR_HAVE_NO_MEMORY(info101->comment);

		r->out.info.info101 = info101;
		return WERR_OK;
	}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
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
	case 0:
	{
		r->out.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetDiskCtr0);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr0);

		r->out.ctr0->unknown = 0x1;
		r->out.ctr0->count = 0;
		r->out.ctr0->array = NULL;

		return WERR_NOT_SUPPORTED;
	}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
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
	case 0:
	{
		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct srvsvc_NetTransportCtr0);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = 0;
		r->out.ctr.ctr0->array = NULL;

		return WERR_NOT_SUPPORTED;
	}
	case 1:
	{
		r->out.ctr.ctr1 = talloc_p(mem_ctx, struct srvsvc_NetTransportCtr1);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr.ctr1);

		r->out.ctr.ctr1->count = 0;
		r->out.ctr.ctr1->array = NULL;

		return WERR_NOT_SUPPORTED;
	}
	case 2:
	{
		r->out.ctr.ctr2 = talloc_p(mem_ctx, struct srvsvc_NetTransportCtr2);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr.ctr2);

		r->out.ctr.ctr2->count = 0;
		r->out.ctr.ctr2->array = NULL;

		return WERR_NOT_SUPPORTED;
	}
	case 3:
	{
		r->out.ctr.ctr3 = talloc_p(mem_ctx, struct srvsvc_NetTransportCtr3);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr.ctr3);

		r->out.ctr.ctr3->count = 0;
		r->out.ctr.ctr3->array = NULL;

		return WERR_NOT_SUPPORTED;
	}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
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
	struct timeval tval;
	time_t t;
	struct tm tm;

	r->out.info = talloc_p(mem_ctx, struct srvsvc_NetRemoteTODInfo);
	W_ERROR_HAVE_NO_MEMORY(r->out.info);

	GetTimeOfDay(&tval);
	t = tval.tv_sec;

	gmtime_r(&t, &tm);

	r->out.info->elapsed	= t;
	/* TODO: fake the uptime: just return the milliseconds till 0:00:00 today */
	r->out.info->msecs	= (tm.tm_hour*60*60*1000)
				+ (tm.tm_min*60*1000)
				+ (tm.tm_sec*1000)
				+ (tval.tv_usec/1000);
	r->out.info->hours	= tm.tm_hour;
	r->out.info->mins	= tm.tm_min;
	r->out.info->secs	= tm.tm_sec;
	r->out.info->hunds	= tval.tv_usec/10000;
	r->out.info->timezone	= get_time_zone(t)/60;
	r->out.info->tinterval	= 310; /* just return the same as windows */
	r->out.info->day	= tm.tm_mday;
	r->out.info->month	= tm.tm_mon + 1;
	r->out.info->year	= tm.tm_year + 1900;
	r->out.info->weekday	= tm.tm_wday;

	return WERR_OK;
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
	ZERO_STRUCT(r->out.ctr);
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;

	/* TODO: - paging of results 
	 *       - access check
	 */

	switch (r->in.level) {
	case 0:
	{
		int i;
		uint32_t count;
		struct srvsvc_NetShareCtr0 *ctr0;

		ctr0 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr0);
		W_ERROR_HAVE_NO_MEMORY(ctr0);

		ctr0->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		ctr0->array = NULL;

		if (ctr0->count == 0) {
			r->out.ctr.ctr0	= ctr0;
			return WERR_OK;
		}

		ctr0->array = talloc_array_p(mem_ctx, struct srvsvc_NetShareInfo0, ctr0->count);
		W_ERROR_HAVE_NO_MEMORY(ctr0->array);

		count		= ctr0->count;
		ctr0->count	= 0;
		for (i=0; i < count; i++) {
			WERROR status;
			union srvsvc_NetShareInfo info;

			if (!lp_browseable(i)){
				continue;
			}

			info.info0 = &ctr0->array[ctr0->count++];
			status = srvsvc_fiel_ShareInfo(dce_call, mem_ctx, i, r->in.level, &info);
			if (!W_ERROR_IS_OK(status)) {
				return status;
			}
		}

		r->out.ctr.ctr0		= ctr0;
		r->out.totalentries	= r->out.ctr.ctr0->count;
		return WERR_OK;
	}
	case 1:
	{
		int i;
		uint32_t count;
		struct srvsvc_NetShareCtr1 *ctr1;

		ctr1 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr1);
		W_ERROR_HAVE_NO_MEMORY(ctr1);

		ctr1->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		ctr1->array = NULL;

		if (ctr1->count == 0) {
			r->out.ctr.ctr1	= ctr1;
			return WERR_OK;
		}

		ctr1->array = talloc_array_p(mem_ctx, struct srvsvc_NetShareInfo1, ctr1->count);
		W_ERROR_HAVE_NO_MEMORY(ctr1->array);

		count		= ctr1->count;
		ctr1->count	= 0;
		for (i=0; i < count; i++) {
			WERROR status;
			union srvsvc_NetShareInfo info;

			if (!lp_browseable(i)){
				continue;
			}

			info.info1 = &ctr1->array[ctr1->count++];
			status = srvsvc_fiel_ShareInfo(dce_call, mem_ctx, i, r->in.level, &info);
			if (!W_ERROR_IS_OK(status)) {
				return status;
			}
		}

		r->out.ctr.ctr1		= ctr1;
		r->out.totalentries	= r->out.ctr.ctr1->count;
		return WERR_OK;
	}
	case 2:
	{
		int i;
		uint32_t count;
		struct srvsvc_NetShareCtr2 *ctr2;

		ctr2 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr2);
		W_ERROR_HAVE_NO_MEMORY(ctr2);

		ctr2->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		ctr2->array = NULL;

		if (ctr2->count == 0) {
			r->out.ctr.ctr2 = ctr2;
			return WERR_OK;
		}

		ctr2->array = talloc_array_p(mem_ctx, struct srvsvc_NetShareInfo2, ctr2->count);
		W_ERROR_HAVE_NO_MEMORY(ctr2->array);

		count		= ctr2->count;
		ctr2->count	= 0;
		for (i=0; i < count; i++) {
			WERROR status;
			union srvsvc_NetShareInfo info;

			if (!lp_browseable(i)){
				continue;
			}

			info.info2 = &ctr2->array[ctr2->count++];
			status = srvsvc_fiel_ShareInfo(dce_call, mem_ctx, i, r->in.level, &info);
			if (!W_ERROR_IS_OK(status)) {
				return status;
			}
		}

		r->out.ctr.ctr2		= ctr2;
		r->out.totalentries	= r->out.ctr.ctr2->count;
		return WERR_OK;
	}
	case 501:
	{
		int i;
		uint32_t count;
		struct srvsvc_NetShareCtr501 *ctr501;

		ctr501 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr501);
		W_ERROR_HAVE_NO_MEMORY(ctr501);

		ctr501->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		ctr501->array = NULL;

		if (ctr501->count == 0) {
			r->out.ctr.ctr501 = ctr501;
			return WERR_OK;
		}

		ctr501->array = talloc_array_p(mem_ctx, struct srvsvc_NetShareInfo501, ctr501->count);
		W_ERROR_HAVE_NO_MEMORY(ctr501->array);

		count		= ctr501->count;
		ctr501->count	= 0;
		for (i=0; i < count; i++) {
			WERROR status;
			union srvsvc_NetShareInfo info;

			if (!lp_browseable(i)){
				continue;
			}

			info.info501 = &ctr501->array[ctr501->count++];
			status = srvsvc_fiel_ShareInfo(dce_call, mem_ctx, i, r->in.level, &info);
			if (!W_ERROR_IS_OK(status)) {
				return status;
			}
		}

		r->out.ctr.ctr501	= ctr501;
		r->out.totalentries	= r->out.ctr.ctr501->count;
		return WERR_OK;
	}
	case 502:
	{
		int i;
		uint32_t count;
		struct srvsvc_NetShareCtr502 *ctr502;

		ctr502 = talloc_p(mem_ctx, struct srvsvc_NetShareCtr502);
		W_ERROR_HAVE_NO_MEMORY(ctr502);

		ctr502->count = dcesrv_common_get_count_of_shares(mem_ctx, dce_ctx);
		ctr502->array = NULL;

		if (ctr502->count == 0) {
			r->out.ctr.ctr502 = ctr502;
			return WERR_OK;
		}

		ctr502->array = talloc_array_p(mem_ctx, struct srvsvc_NetShareInfo502, ctr502->count);
		W_ERROR_HAVE_NO_MEMORY(ctr502->array);

		count		= ctr502->count;
		ctr502->count	= 0;
		for (i=0; i < count; i++) {
			WERROR status;
			union srvsvc_NetShareInfo info;

			if (!lp_browseable(i)){
				continue;
			}

			info.info502 = &ctr502->array[ctr502->count++];
			status = srvsvc_fiel_ShareInfo(dce_call, mem_ctx, i, r->in.level, &info);
			if (!W_ERROR_IS_OK(status)) {
				return status;
			}
		}

		r->out.ctr.ctr502	= ctr502;
		r->out.totalentries	= r->out.ctr.ctr502->count;
		return WERR_OK;
	}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
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
