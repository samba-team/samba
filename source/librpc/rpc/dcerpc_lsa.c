/* 
   Unix SMB/CIFS implementation.
   raw dcerpc operations

   Copyright (C) Tim Potter 2004
   
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

NTSTATUS lsa_Close(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		   struct policy_handle *handle)
{
	struct lsa_Close r;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;

	if ((tmp_ctx = talloc_init("lsa_OpenPolicy")) == NULL)
		return NT_STATUS_NO_MEMORY;

	r.in.handle = r.out.handle = handle;

	status = dcerpc_lsa_Close(p, tmp_ctx, &r);

	talloc_destroy(tmp_ctx);

	return status;
}

NTSTATUS lsa_Delete(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		    struct policy_handle *handle)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS lsa_EnumPrivs(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS lsa_SetSecObj(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS lsa_ChangePassword(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS lsa_OpenPolicy(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			struct policy_handle *handle)
{
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy r;
	NTSTATUS status;
	uint16 system_name = '\\';
	TALLOC_CTX *tmp_ctx;

	if ((tmp_ctx = talloc_init("lsa_OpenPolicy")) == NULL)
		return NT_STATUS_NO_MEMORY;

	qos.len = 0;
	qos.impersonation_level = 2;
	qos.context_mode = 1;
	qos.effective_only = 0;

	attr.len = 0;
	attr.root_dir = NULL;
	attr.object_name = NULL;
	attr.attributes = 0;
	attr.sec_desc = NULL;
	attr.sec_qos = &qos;

	r.in.system_name = &system_name;
	r.in.attr = &attr;
	r.in.desired_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.handle = handle;	

	status = dcerpc_lsa_OpenPolicy(p, tmp_ctx, &r);

	talloc_destroy(tmp_ctx);

	return status;
}

NTSTATUS lsa_QueryInfoPolicy(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS lsa_SetInfoPolicy(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS lsa_ClearAuditLog(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS lsa_CreateAccount(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			   struct policy_handle *handle)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS lsa_EnumAccounts(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


NTSTATUS lsa_CreateTrustedDomain(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				 struct policy_handle *handle)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS lsa_EnumTrustDom(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS lsa_LookupNames(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			 struct policy_handle *handle, char **names,
			 uint32 num_names, struct dom_sid **sids,
			 uint32 **sid_types, uint32 *num_sids)
{
	struct lsa_LookupNames r;
	struct lsa_TransSidArray lsa_sids;
	struct lsa_Name *lsa_names;
	uint32 count = 0;
	NTSTATUS status;
	int i;
	TALLOC_CTX *tmp_ctx;

	if ((tmp_ctx = talloc_init("lsa_LookupNames")) == NULL)
		return NT_STATUS_NO_MEMORY;

	lsa_sids.count = 0;
	lsa_sids.sids = NULL;

	lsa_names = talloc(tmp_ctx, num_names * sizeof(lsa_names[0]));

	for (i = 0; i < num_names; i++)
		lsa_names[i].name = names[i];

	r.in.handle = handle;
	r.in.num_names = num_names;
	r.in.names = lsa_names;
	r.in.sids = &lsa_sids;
	r.in.level = 1;
	r.in.count = &count;
	r.out.count = &count;
	r.out.sids = &lsa_sids;

	status = dcerpc_lsa_LookupNames(p, tmp_ctx, &r);

	*num_sids = count;

	if ((*sids = talloc(mem_ctx, count * sizeof(struct dom_sid))) == NULL){
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	if ((*sid_types = talloc(mem_ctx, count * sizeof(uint32))) == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/* TODO: We should really return a list of sids that is the
	 * same length as the list of names, but with sid type unknown
	 * for the case where only some of the names could be
	 * resolved.  When no names are resolved the result code is
         * NT_STATUS_NONE_MAPPED. 
	 */

	for (i = 0; i < count; i++) {
		struct dom_sid *s;

		s = dom_sid_add_rid(tmp_ctx, r.out.domains->domains[i].sid,
				    lsa_sids.sids[i].rid);

		(*sids)[i].sid_rev_num = s->sid_rev_num;
		(*sids)[i].num_auths = s->num_auths;
		memcpy((*sids)[i].id_auth, s->id_auth, sizeof(s->id_auth));
		(*sids)[i].sub_auths = talloc_steal(
			tmp_ctx, mem_ctx, s->sub_auths);

		(*sid_types)[i] = lsa_sids.sids[i].sid_type;
	}

 done:
	talloc_destroy(tmp_ctx);

	return status;
}

NTSTATUS lsa_LookupSids(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			struct policy_handle *handle, struct dom_sid *sids,
			int num_sids, char ***names, uint32 **sid_types,
			uint32 *num_names)
{
	struct lsa_LookupSids r;
	struct lsa_TransNameArray lsa_names;
	struct lsa_SidArray lsa_sids;
	uint32 count = num_sids;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;
	uint32 i;

	if ((tmp_ctx = talloc_init("lsa_LookupNames")) == NULL)
		return NT_STATUS_NO_MEMORY;

	lsa_names.count = 0;
	lsa_names.names = NULL;

	lsa_sids.num_sids = num_sids;
	lsa_sids.sids = talloc(tmp_ctx, num_sids * sizeof(struct lsa_SidPtr));

	for (i = 0; i < num_sids; i++)
		lsa_sids.sids[i].sid = &sids[i];

	r.in.handle = handle;
	r.in.sids = &lsa_sids;
	r.in.names = r.out.names = &lsa_names;
	r.in.level = 1;
	r.in.count = r.out.count = &count;

	status = dcerpc_lsa_LookupSids(p, tmp_ctx, &r);

	*num_names = count;

	if ((*names = talloc(mem_ctx, count * sizeof(char *))) == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	if ((*sid_types = talloc(mem_ctx, count * sizeof(uint32))) == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/* TODO: Again, we need to consider the case where some of the
	 * sids could not be resolved.
	 */

	for (i = 0; i < count; i++) {
		(*names)[i] = talloc_steal(tmp_ctx, mem_ctx,
					   lsa_names.names[i].name.name);
		(*sid_types)[i] = lsa_names.names[i].sid_type;
	}

 done:
	talloc_destroy(tmp_ctx);

	return status;
}

NTSTATUS lsa_CreateSecret(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			  struct policy_handle *handle)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS lsa_OpenAccount(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS lsa_EnumPrivsAccount(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			      struct policy_handle *handle,
			      struct policy_handle *acct_handle)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* AddPrivs */

/* RemovePrivs */

/* GetQuotas */

/* SetQuotas */

/* GetSystemAccount */

/* SetSystemAccount */

/* OpenTrustDom */

/* QueryTrustDom */

/* SetInfoTrustDom */

NTSTATUS lsa_OpenSecret(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS lsa_SetSecret(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS lsa_QuerySecret(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* LookupPrivValue */

NTSTATUS lsa_LookupPrivName(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			    struct policy_handle *handle)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* PrivGetDispname */

/* DeleteObject */

/* EnumAcctWithRight */

NTSTATUS lsa_EnumAccountRights(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* AddAcctRights */

/* RemoveAcctRights */

/* QueryTrustDomInfo */

/* SetTrustDomInfo */

/* DeleteTrustDom */

/* StorePrivData */

/* RetrPrivData */

NTSTATUS lsa_OpenPolicy2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			 struct policy_handle *handle)
{
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy2 r;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;

	if ((tmp_ctx = talloc_init("lsa_OpenPolicy2")) == NULL)
		return NT_STATUS_NO_MEMORY;

	qos.len = 0;
	qos.impersonation_level = 2;
	qos.context_mode = 1;
	qos.effective_only = 0;

	attr.len = 0;
	attr.root_dir = NULL;
	attr.object_name = NULL;
	attr.attributes = 0;
	attr.sec_desc = NULL;
	attr.sec_qos = &qos;

	r.in.system_name = "\\";
	r.in.attr = &attr;
	r.in.desired_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.handle = handle;

	status = dcerpc_lsa_OpenPolicy2(p, tmp_ctx, &r);

	talloc_destroy(tmp_ctx);

	return status;
}
