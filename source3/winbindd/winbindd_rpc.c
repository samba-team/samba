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

#include "librpc/gen_ndr/cli_samr.h"
#include "librpc/gen_ndr/srv_samr.h"
#include "librpc/gen_ndr/cli_lsa.h"
#include "librpc/gen_ndr/srv_lsa.h"
#include "rpc_client/cli_samr.h"
#include "rpc_client/cli_lsarpc.h"

/* Query display info for a domain */
NTSTATUS rpc_query_user_list(TALLOC_CTX *mem_ctx,
			     struct rpc_pipe_client *samr_pipe,
			     struct policy_handle *samr_policy,
			     const struct dom_sid *domain_sid,
			     uint32_t *pnum_info,
			     struct wbint_userinfo **pinfo)
{
	struct wbint_userinfo *info = NULL;
	uint32_t num_info = 0;
	uint32_t loop_count = 0;
	uint32_t start_idx = 0;
	uint32_t i = 0;
	NTSTATUS status;

	*pnum_info = 0;

	do {
		uint32_t j;
		uint32_t num_dom_users;
		uint32_t max_entries, max_size;
		uint32_t total_size, returned_size;
		union samr_DispInfo disp_info;

		get_query_dispinfo_params(loop_count,
					  &max_entries,
					  &max_size);

		status = rpccli_samr_QueryDisplayInfo(samr_pipe,
						      mem_ctx,
						      samr_policy,
						      1, /* level */
						      start_idx,
						      max_entries,
						      max_size,
						      &total_size,
						      &returned_size,
						      &disp_info);
		if (!NT_STATUS_IS_OK(status)) {
			if (!NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				return status;
			}
		}

		/* increment required start query values */
		start_idx += disp_info.info1.count;
		loop_count++;
		num_dom_users = disp_info.info1.count;

		num_info += num_dom_users;

		info = TALLOC_REALLOC_ARRAY(mem_ctx,
					    info,
					    struct wbint_userinfo,
					    num_info);
		if (info == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		for (j = 0; j < num_dom_users; i++, j++) {
			uint32_t rid = disp_info.info1.entries[j].rid;
			struct samr_DispEntryGeneral *src;
			struct wbint_userinfo *dst;

			src = &(disp_info.info1.entries[j]);
			dst = &(info[i]);

			dst->acct_name = talloc_strdup(info,
						       src->account_name.string);
			if (dst->acct_name == NULL) {
				return NT_STATUS_NO_MEMORY;
			}

			dst->full_name = talloc_strdup(info, src->full_name.string);
			if (dst->full_name == NULL) {
				return NT_STATUS_NO_MEMORY;
			}

			dst->homedir = NULL;
			dst->shell = NULL;

			sid_compose(&dst->user_sid, domain_sid, rid);

			/* For the moment we set the primary group for
			   every user to be the Domain Users group.
			   There are serious problems with determining
			   the actual primary group for large domains.
			   This should really be made into a 'winbind
			   force group' smb.conf parameter or
			   something like that. */
			sid_compose(&dst->group_sid, domain_sid,
				    DOMAIN_RID_USERS);
		}
	} while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES));

	*pnum_info = num_info;
	*pinfo = info;

	return NT_STATUS_OK;
}

/* List all domain groups */
NTSTATUS rpc_enum_dom_groups(TALLOC_CTX *mem_ctx,
			     struct rpc_pipe_client *samr_pipe,
			     struct policy_handle *samr_policy,
			     uint32_t *pnum_info,
			     struct acct_info **pinfo)
{
	struct acct_info *info = NULL;
	uint32_t start = 0;
	uint32_t num_info = 0;
	NTSTATUS status;

	*pnum_info = 0;

	do {
		struct samr_SamArray *sam_array = NULL;
		uint32_t count = 0;
		uint32_t g;

		/* start is updated by this call. */
		status = rpccli_samr_EnumDomainGroups(samr_pipe,
						      mem_ctx,
						      samr_policy,
						      &start,
						      &sam_array,
						      0xFFFF, /* buffer size? */
						      &count);
		if (!NT_STATUS_IS_OK(status)) {
			if (!NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				DEBUG(2,("query_user_list: failed to enum domain groups: %s\n",
					 nt_errstr(status)));
				return status;
			}
		}

		info = TALLOC_REALLOC_ARRAY(mem_ctx,
					    info,
					    struct acct_info,
					    num_info + count);
		if (info == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		for (g = 0; g < count; g++) {
			fstrcpy(info[num_info + g].acct_name,
				sam_array->entries[g].name.string);

			info[num_info + g].rid = sam_array->entries[g].idx;
		}

		num_info += count;
	} while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES));

	*pnum_info = num_info;
	*pinfo = info;

	return NT_STATUS_OK;
}

NTSTATUS rpc_enum_local_groups(TALLOC_CTX *mem_ctx,
			       struct rpc_pipe_client *samr_pipe,
			       struct policy_handle *samr_policy,
			       uint32_t *pnum_info,
			       struct acct_info **pinfo)
{
	struct acct_info *info = NULL;
	uint32_t num_info = 0;
	NTSTATUS status;

	*pnum_info = 0;

	do {
		struct samr_SamArray *sam_array = NULL;
		uint32_t count = 0;
		uint32_t start = num_info;
		uint32_t g;

		status = rpccli_samr_EnumDomainAliases(samr_pipe,
						       mem_ctx,
						       samr_policy,
						       &start,
						       &sam_array,
						       0xFFFF, /* buffer size? */
						       &count);
		if (!NT_STATUS_IS_OK(status)) {
			if (!NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				return status;
			}
		}

		info = TALLOC_REALLOC_ARRAY(mem_ctx,
					    info,
					    struct acct_info,
					    num_info + count);
		if (info == NULL) {
			return  NT_STATUS_NO_MEMORY;
		}

		for (g = 0; g < count; g++) {
			fstrcpy(info[num_info + g].acct_name,
				sam_array->entries[g].name.string);
			info[num_info + g].rid = sam_array->entries[g].idx;
		}

		num_info += count;
	} while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES));

	*pnum_info = num_info;
	*pinfo = info;

	return NT_STATUS_OK;
}

/* convert a single name to a sid in a domain */
NTSTATUS rpc_name_to_sid(TALLOC_CTX *mem_ctx,
			 struct rpc_pipe_client *lsa_pipe,
			 struct policy_handle *lsa_policy,
			 const char *domain_name,
			 const char *name,
			 uint32_t flags,
			 struct dom_sid *sid,
			 enum lsa_SidType *type)
{
	enum lsa_SidType *types = NULL;
	struct dom_sid *sids = NULL;
	char *full_name = NULL;
	char *mapped_name = NULL;
	NTSTATUS status;

	if (name == NULL || name[0] == '\0') {
		full_name = talloc_asprintf(mem_ctx, "%s", domain_name);
	} else if (domain_name == NULL || domain_name[0] == '\0') {
		full_name = talloc_asprintf(mem_ctx, "%s", name);
	} else {
		full_name = talloc_asprintf(mem_ctx, "%s\\%s", domain_name, name);
	}

	if (full_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = normalize_name_unmap(mem_ctx, full_name, &mapped_name);
	/* Reset the full_name pointer if we mapped anything */
	if (NT_STATUS_IS_OK(status) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_FILE_RENAMED)) {
		full_name = mapped_name;
	}

	DEBUG(3,("name_to_sid: %s for domain %s\n",
		 full_name ? full_name : "", domain_name ));

	/*
	 * We don't run into deadlocks here, cause winbind_off() is
	 * called in the main function.
	 */
	status = rpccli_lsa_lookup_names(lsa_pipe,
					 mem_ctx,
					 lsa_policy,
					 1, /* num_names */
					 (const char **) &full_name,
					 NULL, /* domains */
					 1, /* level */
					 &sids,
					 &types);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2,("name_to_sid: failed to lookup name: %s\n",
			nt_errstr(status)));
		return status;
	}

	sid_copy(sid, &sids[0]);
	*type = types[0];

	return NT_STATUS_OK;
}

/* Convert a domain SID to a user or group name */
NTSTATUS rpc_sid_to_name(TALLOC_CTX *mem_ctx,
			 struct rpc_pipe_client *lsa_pipe,
			 struct policy_handle *lsa_policy,
			 struct winbindd_domain *domain,
			 const struct dom_sid *sid,
			 char **pdomain_name,
			 char **pname,
			 enum lsa_SidType *ptype)
{
	char *mapped_name = NULL;
	char **domains = NULL;
	char **names = NULL;
	enum lsa_SidType *types = NULL;
	NTSTATUS map_status;
	NTSTATUS status;

	status = rpccli_lsa_lookup_sids(lsa_pipe,
					mem_ctx,
					lsa_policy,
					1, /* num_sids */
					sid,
					&domains,
					&names,
					&types);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2,("sid_to_name: failed to lookup sids: %s\n",
			nt_errstr(status)));
		return status;
	}

	*ptype = (enum lsa_SidType) types[0];

	map_status = normalize_name_map(mem_ctx,
					domain,
					*pname,
					&mapped_name);
	if (NT_STATUS_IS_OK(map_status) ||
	    NT_STATUS_EQUAL(map_status, NT_STATUS_FILE_RENAMED)) {
		*pname = talloc_strdup(mem_ctx, mapped_name);
		DEBUG(5,("returning mapped name -- %s\n", *pname));
	} else {
		*pname = talloc_strdup(mem_ctx, names[0]);
	}
	if (*pname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*pdomain_name = talloc_strdup(mem_ctx, domains[0]);
	if (*pdomain_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

/* Convert a bunch of rids to user or group names */
NTSTATUS rpc_rids_to_names(TALLOC_CTX *mem_ctx,
			   struct rpc_pipe_client *lsa_pipe,
			   struct policy_handle *lsa_policy,
			   struct winbindd_domain *domain,
			   const struct dom_sid *sid,
			   uint32_t *rids,
			   size_t num_rids,
			   char **pdomain_name,
			   char ***pnames,
			   enum lsa_SidType **ptypes)
{
	enum lsa_SidType *types = NULL;
	char *domain_name = NULL;
	char **domains = NULL;
	char **names = NULL;
	struct dom_sid *sids;
	size_t i;
	NTSTATUS status;

	if (num_rids > 0) {
		sids = TALLOC_ARRAY(mem_ctx, struct dom_sid, num_rids);
		if (sids == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		sids = NULL;
	}

	for (i = 0; i < num_rids; i++) {
		if (!sid_compose(&sids[i], sid, rids[i])) {
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	status = rpccli_lsa_lookup_sids(lsa_pipe,
					mem_ctx,
					lsa_policy,
					num_rids,
					sids,
					&domains,
					&names,
					&types);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		DEBUG(2,("rids_to_names: failed to lookup sids: %s\n",
			nt_errstr(status)));
		return status;
	}

	for (i = 0; i < num_rids; i++) {
		char *mapped_name = NULL;
		NTSTATUS map_status;

		if (types[i] != SID_NAME_UNKNOWN) {
			map_status = normalize_name_map(mem_ctx,
							domain,
							names[i],
							&mapped_name);
			if (NT_STATUS_IS_OK(map_status) ||
			    NT_STATUS_EQUAL(map_status, NT_STATUS_FILE_RENAMED)) {
				TALLOC_FREE(names[i]);
				names[i] = talloc_strdup(names, mapped_name);
				if (names[i] == NULL) {
					return NT_STATUS_NO_MEMORY;
				}
			}

			domain_name = domains[i];
		}
	}

	*pdomain_name = domain_name;
	*ptypes = types;
	*pnames = names;

	return NT_STATUS_OK;
}

/* Lookup user information from a rid or username. */
NTSTATUS rpc_query_user(TALLOC_CTX *mem_ctx,
			struct rpc_pipe_client *samr_pipe,
			struct policy_handle *samr_policy,
			const struct dom_sid *domain_sid,
			const struct dom_sid *user_sid,
			struct wbint_userinfo *user_info)
{
	struct policy_handle user_policy;
	union samr_UserInfo *info = NULL;
	uint32_t user_rid;
	NTSTATUS status;

	if (!sid_peek_check_rid(domain_sid, user_sid, &user_rid)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Get user handle */
	status = rpccli_samr_OpenUser(samr_pipe,
				      mem_ctx,
				      samr_policy,
				      SEC_FLAG_MAXIMUM_ALLOWED,
				      user_rid,
				      &user_policy);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Get user info */
	status = rpccli_samr_QueryUserInfo(samr_pipe,
					   mem_ctx,
					   &user_policy,
					   0x15,
					   &info);

	rpccli_samr_Close(samr_pipe, mem_ctx, &user_policy);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	sid_compose(&user_info->user_sid, domain_sid, user_rid);
	sid_compose(&user_info->group_sid, domain_sid,
		    info->info21.primary_gid);

	user_info->acct_name = talloc_strdup(user_info,
					info->info21.account_name.string);
	if (user_info->acct_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	user_info->full_name = talloc_strdup(user_info,
					info->info21.full_name.string);
	if (user_info->acct_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	user_info->homedir = NULL;
	user_info->shell = NULL;
	user_info->primary_gid = (gid_t)-1;

	return NT_STATUS_OK;
}
