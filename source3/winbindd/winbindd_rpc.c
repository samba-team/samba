/*
 * Unix SMB/CIFS implementation.
 *
 * Winbind rpc backend functions
 *
 * Copyright (c) 2000-2003 Tim Potter
 * Copyright (c) 2001      Andrew Tridgell
 * Copyright (c) 2005      Volker Lendecke
 * Copyright (c) 2008      Guenther Deschner (pidl conversion)
 * Copyright (c) 2010      Andreas Schneider <asn@samba.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "winbindd.h"
#include "winbindd_rpc.h"
#include "rpc_client/rpc_client.h"
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"
#include "rpc_client/cli_samr.h"
#include "rpc_client/cli_lsarpc.h"
#include "../libcli/security/security.h"
#include "lsa.h"

/* Query display info for a domain */
NTSTATUS rpc_query_user_list(TALLOC_CTX *mem_ctx,
			     struct rpc_pipe_client *samr_pipe,
			     struct policy_handle *samr_policy,
			     const struct dom_sid *domain_sid,
			     uint32_t **prids)
{
	struct dcerpc_binding_handle *b = samr_pipe->binding_handle;
	uint32_t *rids = NULL;
	uint32_t num_rids = 0;
	uint32_t i = 0;
	uint32_t resume_handle = 0;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *tmp_ctx;

	*prids = NULL;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	do {
		struct samr_SamArray *sam_array = NULL;
		uint32_t count = 0;
		uint32_t *tmp;

		status = dcerpc_samr_EnumDomainUsers(
			b, tmp_ctx, samr_policy, &resume_handle,
			ACB_NORMAL, &sam_array, 0xffff, &count, &result);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
		if (!NT_STATUS_IS_OK(result)) {
			if (!NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES)) {
				DBG_WARNING("EnumDomainUsers failed: %s\n",
					    nt_errstr(result));
				status = result;
				goto done;
			}
		}

		if (num_rids + count < num_rids) {
			status = NT_STATUS_INTEGER_OVERFLOW;
			goto done;
		}

		tmp = talloc_realloc(tmp_ctx, rids, uint32_t, num_rids+count);
		if (tmp == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
		rids = tmp;

		for (i=0; i<count; i++) {
			rids[num_rids++] = sam_array->entries[i].idx;
		}

		TALLOC_FREE(sam_array);
	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));

	*prids = talloc_steal(mem_ctx, rids);
	status = NT_STATUS_OK;

done:
	TALLOC_FREE(tmp_ctx);
	return status;
}

/* List all domain groups */
NTSTATUS rpc_enum_dom_groups(TALLOC_CTX *mem_ctx,
			     struct rpc_pipe_client *samr_pipe,
			     struct policy_handle *samr_policy,
			     uint32_t *pnum_info,
			     struct wb_acct_info **pinfo)
{
	struct wb_acct_info *info = NULL;
	uint32_t start = 0;
	uint32_t num_info = 0;
	NTSTATUS status, result;
	struct dcerpc_binding_handle *b = samr_pipe->binding_handle;

	*pnum_info = 0;

	do {
		struct samr_SamArray *sam_array = NULL;
		uint32_t count = 0;
		uint32_t g;

		/* start is updated by this call. */
		status = dcerpc_samr_EnumDomainGroups(b,
						      mem_ctx,
						      samr_policy,
						      &start,
						      &sam_array,
						      0xFFFF, /* buffer size? */
						      &count,
						      &result);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		if (!NT_STATUS_IS_OK(result)) {
			if (!NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES)) {
				DEBUG(2,("query_user_list: failed to enum domain groups: %s\n",
					 nt_errstr(result)));
				return result;
			}
		}

		info = talloc_realloc(mem_ctx,
					    info,
					    struct wb_acct_info,
					    num_info + count);
		if (info == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		for (g = 0; g < count; g++) {
			struct wb_acct_info *i = &info[num_info + g];

			i->acct_name = talloc_strdup(info,
				sam_array->entries[g].name.string);
			if (i->acct_name == NULL) {
				TALLOC_FREE(info);
				return NT_STATUS_NO_MEMORY;
			}
			i->acct_desc = NULL;
			i->rid = sam_array->entries[g].idx;
		}

		num_info += count;
	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));

	*pnum_info = num_info;
	*pinfo = info;

	return NT_STATUS_OK;
}

NTSTATUS rpc_enum_local_groups(TALLOC_CTX *mem_ctx,
			       struct rpc_pipe_client *samr_pipe,
			       struct policy_handle *samr_policy,
			       uint32_t *pnum_info,
			       struct wb_acct_info **pinfo)
{
	struct wb_acct_info *info = NULL;
	uint32_t num_info = 0;
	NTSTATUS status, result;
	struct dcerpc_binding_handle *b = samr_pipe->binding_handle;

	*pnum_info = 0;

	do {
		struct samr_SamArray *sam_array = NULL;
		uint32_t count = 0;
		uint32_t start = num_info;
		uint32_t g;

		status = dcerpc_samr_EnumDomainAliases(b,
						       mem_ctx,
						       samr_policy,
						       &start,
						       &sam_array,
						       0xFFFF, /* buffer size? */
						       &count,
						       &result);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		if (!NT_STATUS_IS_OK(result)) {
			if (!NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES)) {
				return result;
			}
		}

		info = talloc_realloc(mem_ctx,
					    info,
					    struct wb_acct_info,
					    num_info + count);
		if (info == NULL) {
			return  NT_STATUS_NO_MEMORY;
		}

		for (g = 0; g < count; g++) {
			struct wb_acct_info *i = &info[num_info + g];

			i->acct_name = talloc_strdup(info,
				sam_array->entries[g].name.string);
			if (i->acct_name == NULL) {
				TALLOC_FREE(info);
				return NT_STATUS_NO_MEMORY;
			}
			i->acct_desc = NULL;
			i->rid = sam_array->entries[g].idx;
		}

		num_info += count;
	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));

	*pnum_info = num_info;
	*pinfo = info;

	return NT_STATUS_OK;
}

/* Lookup groups a user is a member of. */
NTSTATUS rpc_lookup_usergroups(TALLOC_CTX *mem_ctx,
			       struct rpc_pipe_client *samr_pipe,
			       struct policy_handle *samr_policy,
			       const struct dom_sid *domain_sid,
			       const struct dom_sid *user_sid,
			       uint32_t *pnum_groups,
			       struct dom_sid **puser_grpsids)
{
	struct policy_handle user_policy;
	struct samr_RidWithAttributeArray *rid_array = NULL;
	struct dom_sid *user_grpsids = NULL;
	uint32_t num_groups = 0, i;
	uint32_t user_rid;
	NTSTATUS status, result;
	struct dcerpc_binding_handle *b = samr_pipe->binding_handle;

	if (!sid_peek_check_rid(domain_sid, user_sid, &user_rid)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Get user handle */
	status = dcerpc_samr_OpenUser(b,
				      mem_ctx,
				      samr_policy,
				      SEC_FLAG_MAXIMUM_ALLOWED,
				      user_rid,
				      &user_policy,
				      &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	/* Query user rids */
	status = dcerpc_samr_GetGroupsForUser(b,
					      mem_ctx,
					      &user_policy,
					      &rid_array,
					      &result);
	{
		NTSTATUS _result;
		dcerpc_samr_Close(b, mem_ctx, &user_policy, &_result);
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	num_groups = rid_array->count;

	user_grpsids = talloc_array(mem_ctx, struct dom_sid, num_groups);
	if (user_grpsids == NULL) {
		status = NT_STATUS_NO_MEMORY;
		return status;
	}

	for (i = 0; i < num_groups; i++) {
		sid_compose(&(user_grpsids[i]), domain_sid,
			    rid_array->rids[i].rid);
	}

	*pnum_groups = num_groups;

	*puser_grpsids = user_grpsids;

	return NT_STATUS_OK;
}

NTSTATUS rpc_lookup_useraliases(TALLOC_CTX *mem_ctx,
				struct rpc_pipe_client *samr_pipe,
				struct policy_handle *samr_policy,
				uint32_t num_sids,
				const struct dom_sid *sids,
				uint32_t *pnum_aliases,
				uint32_t **palias_rids)
{
#define MAX_SAM_ENTRIES_W2K 0x400 /* 1024 */
	uint32_t num_queries = 1;
	uint32_t num_aliases = 0;
	uint32_t total_sids = 0;
	uint32_t *alias_rids = NULL;
	uint32_t rangesize = MAX_SAM_ENTRIES_W2K;
	uint32_t i;
	struct samr_Ids alias_rids_query;
	NTSTATUS status, result;
	struct dcerpc_binding_handle *b = samr_pipe->binding_handle;

	do {
		/* prepare query */
		struct lsa_SidArray sid_array;
		uint32_t num_query_sids = 0;

		ZERO_STRUCT(sid_array);

		num_query_sids = MIN(num_sids - total_sids, rangesize);

		DEBUG(10,("rpc: lookup_useraliases: entering query %d for %d sids\n",
			num_queries, num_query_sids));

		if (num_query_sids) {
			sid_array.sids = talloc_zero_array(mem_ctx, struct lsa_SidPtr, num_query_sids);
			if (sid_array.sids == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
		} else {
			sid_array.sids = NULL;
		}

		for (i = 0; i < num_query_sids; i++) {
			sid_array.sids[i].sid = dom_sid_dup(mem_ctx, &sids[total_sids++]);
			if (sid_array.sids[i].sid == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
		}
		sid_array.num_sids = num_query_sids;

		/* do request */
		status = dcerpc_samr_GetAliasMembership(b,
							mem_ctx,
							samr_policy,
							&sid_array,
							&alias_rids_query,
							&result);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		if (!NT_STATUS_IS_OK(result)) {
			return result;
		}

		/* process output */
		for (i = 0; i < alias_rids_query.count; i++) {
			size_t na = num_aliases;

			if (!add_rid_to_array_unique(mem_ctx,
						     alias_rids_query.ids[i],
						     &alias_rids,
						     &na)) {
					return NT_STATUS_NO_MEMORY;
				}
				num_aliases = na;
		}

		num_queries++;

	} while (total_sids < num_sids);

	DEBUG(10,("rpc: rpc_lookup_useraliases: got %d aliases in %d queries "
		  "(rangesize: %d)\n", num_aliases, num_queries, rangesize));

	*pnum_aliases = num_aliases;
	*palias_rids = alias_rids;

	return NT_STATUS_OK;
#undef MAX_SAM_ENTRIES_W2K
}

/* Lookup group membership given a rid.   */
NTSTATUS rpc_lookup_groupmem(TALLOC_CTX *mem_ctx,
			     struct rpc_pipe_client *samr_pipe,
			     struct policy_handle *samr_policy,
			     const char *domain_name,
			     const struct dom_sid *domain_sid,
			     const struct dom_sid *group_sid,
			     enum lsa_SidType type,
			     uint32_t *pnum_names,
			     struct dom_sid **psid_mem,
			     char ***pnames,
			     uint32_t **pname_types)
{
	struct policy_handle group_policy;
	uint32_t group_rid;
	uint32_t *rid_mem = NULL;

	uint32_t num_names = 0;
	uint32_t total_names = 0;
	struct dom_sid *sid_mem = NULL;
	char **names = NULL;
	uint32_t *name_types = NULL;

	struct lsa_Strings tmp_names;
	struct samr_Ids tmp_types;

	uint32_t j, r;
	NTSTATUS status, result;
	struct dcerpc_binding_handle *b = samr_pipe->binding_handle;

	if (!sid_peek_check_rid(domain_sid, group_sid, &group_rid)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	switch(type) {
	case SID_NAME_DOM_GRP:
	{
		struct samr_RidAttrArray *rids = NULL;

		status = dcerpc_samr_OpenGroup(b,
					       mem_ctx,
					       samr_policy,
					       SEC_FLAG_MAXIMUM_ALLOWED,
					       group_rid,
					       &group_policy,
					       &result);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		if (!NT_STATUS_IS_OK(result)) {
			return result;
		}

		/*
		 * Step #1: Get a list of user rids that are the members of the group.
		 */
		status = dcerpc_samr_QueryGroupMember(b,
						      mem_ctx,
						      &group_policy,
						      &rids,
						      &result);
		{
			NTSTATUS _result;
			dcerpc_samr_Close(b, mem_ctx, &group_policy, &_result);
		}

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		if (!NT_STATUS_IS_OK(result)) {
			return result;
		}


		if (rids == NULL || rids->count == 0) {
			pnum_names = 0;
			pnames = NULL;
			pname_types = NULL;
			psid_mem = NULL;

			return NT_STATUS_OK;
		}

		num_names = rids->count;
		rid_mem = rids->rids;

		break;
	}
	default:
		return NT_STATUS_UNSUCCESSFUL;
	}

	/*
	 * Step #2: Convert list of rids into list of usernames.
	 */
	if (num_names > 0) {
		names = talloc_zero_array(mem_ctx, char *, num_names);
		name_types = talloc_zero_array(mem_ctx, uint32_t, num_names);
		sid_mem = talloc_zero_array(mem_ctx, struct dom_sid, num_names);
		if (names == NULL || name_types == NULL || sid_mem == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	for (j = 0; j < num_names; j++) {
		sid_compose(&sid_mem[j], domain_sid, rid_mem[j]);
	}

	status = dcerpc_samr_LookupRids(b,
					mem_ctx,
					samr_policy,
					num_names,
					rid_mem,
					&tmp_names,
					&tmp_types,
					&result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!NT_STATUS_IS_OK(result)) {
		if (!NT_STATUS_EQUAL(result, STATUS_SOME_UNMAPPED)) {
			return result;
		}
	}

	/* Copy result into array.  The talloc system will take
	   care of freeing the temporary arrays later on. */
	if (tmp_names.count != num_names) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}
	if (tmp_types.count != num_names) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	for (r = 0; r < tmp_names.count; r++) {
		if (tmp_types.ids[r] == SID_NAME_UNKNOWN) {
			continue;
		}
		if (total_names >= num_names) {
			break;
		}
		names[total_names] = fill_domain_username_talloc(names,
								 domain_name,
								 tmp_names.names[r].string,
								 true);
		if (names[total_names] == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		name_types[total_names] = tmp_types.ids[r];
		total_names++;
	}

	*pnum_names = total_names;
	*pnames = names;
	*pname_types = name_types;
	*psid_mem = sid_mem;

	return NT_STATUS_OK;
}

/* Lookup alias membership using a rid taken from alias_sid. */
NTSTATUS rpc_lookup_aliasmem(TALLOC_CTX *mem_ctx,
			     struct rpc_pipe_client *samr_pipe,
			     struct policy_handle *samr_policy,
			     const struct dom_sid *domain_sid,
			     const struct dom_sid *alias_sid,
			     enum lsa_SidType type,
			     uint32_t *pnum_sids,
			     struct dom_sid **psids)
{
	uint32_t alias_rid;
	struct dom_sid *sid_mem = NULL;
	struct lsa_SidArray sid_array;
	uint32_t i;
	NTSTATUS status, result;
	struct dcerpc_binding_handle *b = samr_pipe->binding_handle;

	if (!sid_peek_check_rid(domain_sid, alias_sid, &alias_rid)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	switch (type) {
	case SID_NAME_ALIAS: {
		struct policy_handle alias_policy;

		status = dcerpc_samr_OpenAlias(b,
					       mem_ctx,
					       samr_policy,
					       SEC_FLAG_MAXIMUM_ALLOWED,
					       alias_rid,
					       &alias_policy,
					       &result);
		if (any_nt_status_not_ok(status, result, &status)) {
			return status;
		}

		status = dcerpc_samr_GetMembersInAlias(b,
						       mem_ctx,
						       &alias_policy,
						       &sid_array,
						       &result);
		{
			NTSTATUS _result;
			dcerpc_samr_Close(b, mem_ctx, &alias_policy, &_result);
		}
		if (any_nt_status_not_ok(status, result, &status)) {
			return status;
		}

		sid_mem = talloc_zero_array(mem_ctx,
					    struct dom_sid,
					    sid_array.num_sids);
		if (sid_mem == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		/*
		 * We cannot just simply assign '*psids = sid_array.sids;'
		 * we need to copy every sid since these are incompatible types:
		 * 'struct dom_sid *' vs 'struct lsa_SidPtr *'
		 */
		for (i = 0; i < sid_array.num_sids; i++) {
			sid_copy(&sid_mem[i], sid_array.sids[i].sid);
		}

		*pnum_sids = sid_array.num_sids;
		*psids = sid_mem;

		return NT_STATUS_OK;
	}
	default:
		return NT_STATUS_UNSUCCESSFUL;
	}
}

/* Get a list of trusted domains */
NTSTATUS rpc_trusted_domains(TALLOC_CTX *mem_ctx,
			     struct rpc_pipe_client *lsa_pipe,
			     struct policy_handle *lsa_policy,
			     uint32_t *pnum_trusts,
			     struct netr_DomainTrust **ptrusts)
{
	struct netr_DomainTrust *array = NULL;
	uint32_t enum_ctx = 0;
	uint32_t count = 0;
	NTSTATUS status, result;
	struct dcerpc_binding_handle *b = lsa_pipe->binding_handle;

	do {
		struct lsa_DomainList dom_list;
		struct lsa_DomainListEx dom_list_ex;
		bool has_ex = false;
		uint32_t i;

		/*
		 * We don't run into deadlocks here, cause winbind_off() is
		 * called in the main function.
		 */
		status = dcerpc_lsa_EnumTrustedDomainsEx(b,
							 mem_ctx,
							 lsa_policy,
							 &enum_ctx,
							 &dom_list_ex,
							 (uint32_t) -1,
							 &result);
		if (NT_STATUS_IS_OK(status) && !NT_STATUS_IS_ERR(result) &&
		    dom_list_ex.count > 0) {
			count += dom_list_ex.count;
			has_ex = true;
		} else {
			status = dcerpc_lsa_EnumTrustDom(b,
							 mem_ctx,
							 lsa_policy,
							 &enum_ctx,
							 &dom_list,
							 (uint32_t) -1,
							 &result);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			if (!NT_STATUS_IS_OK(result)) {
				if (!NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES)) {
					return result;
				}
			}

			count += dom_list.count;
		}

		array = talloc_realloc(mem_ctx,
				       array,
				       struct netr_DomainTrust,
				       count);
		if (array == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		for (i = 0; i < count; i++) {
			struct netr_DomainTrust *trust = &array[i];
			struct dom_sid *sid;

			ZERO_STRUCTP(trust);

			sid = talloc(array, struct dom_sid);
			if (sid == NULL) {
				return NT_STATUS_NO_MEMORY;
			}

			if (dom_list_ex.domains[i].sid == NULL) {
				DBG_ERR("Trusted domain %s has no SID, "
					"skipping!\n",
					trust->dns_name);
				continue;
			}

			if (has_ex) {
				trust->netbios_name = talloc_move(array,
								  &dom_list_ex.domains[i].netbios_name.string);
				trust->dns_name = talloc_move(array,
							      &dom_list_ex.domains[i].domain_name.string);
				sid_copy(sid, dom_list_ex.domains[i].sid);
			} else {
				trust->netbios_name = talloc_move(array,
								  &dom_list.domains[i].name.string);
				trust->dns_name = NULL;

				sid_copy(sid, dom_list.domains[i].sid);
			}

			trust->sid = sid;
		}
	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));

	*pnum_trusts = count;
	*ptrusts = array;

	return NT_STATUS_OK;
}

static NTSTATUS rpc_try_lookup_sids3(TALLOC_CTX *mem_ctx,
				     struct winbindd_domain *domain,
				     struct rpc_pipe_client *cli,
				     struct lsa_SidArray *sids,
				     struct lsa_RefDomainList **pdomains,
				     struct lsa_TransNameArray **pnames)
{
	struct lsa_TransNameArray2 lsa_names2;
	struct lsa_TransNameArray *names = *pnames;
	uint32_t i, count = 0;
	NTSTATUS status, result;

	ZERO_STRUCT(lsa_names2);
	status = dcerpc_lsa_LookupSids3(cli->binding_handle,
					mem_ctx,
					sids,
					pdomains,
					&lsa_names2,
					LSA_LOOKUP_NAMES_ALL,
					&count,
					LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES,
					LSA_CLIENT_REVISION_2,
					&result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (NT_STATUS_LOOKUP_ERR(result)) {
		return result;
	}
	if (sids->num_sids != lsa_names2.count) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	names->count = lsa_names2.count;
	names->names = talloc_array(names, struct lsa_TranslatedName,
				    names->count);
	if (names->names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0; i<names->count; i++) {
		names->names[i].sid_type = lsa_names2.names[i].sid_type;
		names->names[i].name.string = talloc_move(
			names->names, &lsa_names2.names[i].name.string);
		names->names[i].sid_index = lsa_names2.names[i].sid_index;

		if (names->names[i].sid_index == UINT32_MAX) {
			continue;
		}
		if ((*pdomains) == NULL) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		if (names->names[i].sid_index >= (*pdomains)->count) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
	}
	return NT_STATUS_OK;
}

NTSTATUS rpc_lookup_sids(TALLOC_CTX *mem_ctx,
			 struct winbindd_domain *domain,
			 struct lsa_SidArray *sids,
			 struct lsa_RefDomainList **pdomains,
			 struct lsa_TransNameArray **pnames)
{
	struct lsa_TransNameArray *names = *pnames;
	struct rpc_pipe_client *cli = NULL;
	struct dcerpc_binding_handle *b = NULL;
	struct policy_handle lsa_policy;
	uint32_t count;
	uint32_t i;
	NTSTATUS status, result;

	status = cm_connect_lsat(domain, mem_ctx, &cli, &lsa_policy);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	b = cli->binding_handle;

	if (dcerpc_binding_handle_get_transport(b) == NCACN_IP_TCP) {
		return rpc_try_lookup_sids3(mem_ctx, domain, cli, sids,
					    pdomains, pnames);
	}

	status = dcerpc_lsa_LookupSids(b, mem_ctx,
				       &lsa_policy, sids, pdomains,
				       names, LSA_LOOKUP_NAMES_ALL,
				       &count, &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (NT_STATUS_LOOKUP_ERR(result)) {
		return result;
	}

	if (sids->num_sids != names->count) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	for (i=0; i < names->count; i++) {
		if (names->names[i].sid_index == UINT32_MAX) {
			continue;
		}
		if ((*pdomains) == NULL) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		if (names->names[i].sid_index >= (*pdomains)->count) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
	}

	return NT_STATUS_OK;
}
