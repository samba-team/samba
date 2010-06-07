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
#include "../librpc/gen_ndr/cli_samr.h"
#include "rpc_client/cli_samr.h"
#include "../librpc/gen_ndr/srv_samr.h"
#include "../librpc/gen_ndr/cli_lsa.h"
#include "rpc_client/cli_lsarpc.h"
#include "../librpc/gen_ndr/srv_lsa.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

static NTSTATUS open_internal_samr_pipe(TALLOC_CTX *mem_ctx,
					struct rpc_pipe_client **samr_pipe)
{
	static struct rpc_pipe_client *cli = NULL;
	struct auth_serversupplied_info *server_info = NULL;
	NTSTATUS status;

	if (cli != NULL) {
		goto done;
	}

	if (server_info == NULL) {
		status = make_server_info_system(mem_ctx, &server_info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("open_samr_pipe: Could not create auth_serversupplied_info: %s\n",
				  nt_errstr(status)));
			return status;
		}
	}

	/* create a samr connection */
	status = rpc_pipe_open_internal(talloc_autofree_context(),
					&ndr_table_samr.syntax_id,
					rpc_samr_dispatch,
					server_info,
					&cli);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("open_samr_pipe: Could not connect to samr_pipe: %s\n",
			  nt_errstr(status)));
		return status;
	}

done:
	if (samr_pipe) {
		*samr_pipe = cli;
	}

	return NT_STATUS_OK;
}

static NTSTATUS open_internal_samr_conn(TALLOC_CTX *mem_ctx,
				        struct winbindd_domain *domain,
				        struct rpc_pipe_client **samr_pipe,
				        struct policy_handle *samr_domain_hnd)
{
	NTSTATUS status;
	struct policy_handle samr_connect_hnd;

	status = open_internal_samr_pipe(mem_ctx, samr_pipe);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = rpccli_samr_Connect2((*samr_pipe),
				      mem_ctx,
				      (*samr_pipe)->desthost,
				      SEC_FLAG_MAXIMUM_ALLOWED,
				      &samr_connect_hnd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = rpccli_samr_OpenDomain((*samr_pipe),
					mem_ctx,
					&samr_connect_hnd,
					SEC_FLAG_MAXIMUM_ALLOWED,
					&domain->sid,
					samr_domain_hnd);

	return status;
}

static NTSTATUS open_internal_lsa_pipe(TALLOC_CTX *mem_ctx,
				       struct rpc_pipe_client **lsa_pipe)
{
	static struct rpc_pipe_client *cli = NULL;
	struct auth_serversupplied_info *server_info = NULL;
	NTSTATUS status;

	if (cli != NULL) {
		goto done;
	}

	if (server_info == NULL) {
		status = make_server_info_system(mem_ctx, &server_info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("open_samr_pipe: Could not create auth_serversupplied_info: %s\n",
				  nt_errstr(status)));
			return status;
		}
	}

	/* create a samr connection */
	status = rpc_pipe_open_internal(talloc_autofree_context(),
					&ndr_table_lsarpc.syntax_id,
					rpc_lsarpc_dispatch,
					server_info,
					&cli);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("open_samr_pipe: Could not connect to samr_pipe: %s\n",
			  nt_errstr(status)));
		return status;
	}

done:
	if (lsa_pipe) {
		*lsa_pipe = cli;
	}

	return NT_STATUS_OK;
}

static NTSTATUS open_internal_lsa_conn(TALLOC_CTX *mem_ctx,
				       struct rpc_pipe_client **lsa_pipe,
				       struct policy_handle *lsa_hnd)
{
	NTSTATUS status;

	status = open_internal_lsa_pipe(mem_ctx, lsa_pipe);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = rpccli_lsa_open_policy((*lsa_pipe),
					mem_ctx,
					true,
					SEC_FLAG_MAXIMUM_ALLOWED,
					lsa_hnd);

	return status;
}

/*********************************************************************
 SAM specific functions.
*********************************************************************/

/* List all domain groups */
static NTSTATUS sam_enum_dom_groups(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    uint32_t *pnum_info,
				    struct acct_info **pinfo)
{
	struct rpc_pipe_client *samr_pipe;
	struct policy_handle dom_pol;
	struct acct_info *info = NULL;
	TALLOC_CTX *tmp_ctx;
	uint32_t start = 0;
	uint32_t num_info = 0;
	NTSTATUS status;

	DEBUG(3,("samr: query_user_list\n"));

	if (pnum_info) {
		*pnum_info = 0;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = open_internal_samr_conn(tmp_ctx, domain, &samr_pipe, &dom_pol);
	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}

	do {
		struct samr_SamArray *sam_array = NULL;
		uint32_t count = 0;
		uint32_t g;

		/* start is updated by this call. */
		status = rpccli_samr_EnumDomainGroups(samr_pipe,
						      tmp_ctx,
						      &dom_pol,
						      &start,
						      &sam_array,
						      0xFFFF, /* buffer size? */
						      &count);
		if (!NT_STATUS_IS_OK(status)) {
			if (!NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				DEBUG(2,("query_user_list: failed to enum domain groups: %s\n",
					 nt_errstr(status)));
				goto error;
			}
		}

		info = TALLOC_REALLOC_ARRAY(tmp_ctx,
					    info,
					    struct acct_info,
					    num_info + count);
		if (info == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto error;
		}

		for (g = 0; g < count; g++) {
			fstrcpy(info[num_info + g].acct_name,
				sam_array->entries[g].name.string);

			info[num_info + g].rid = sam_array->entries[g].idx;
		}

		num_info += count;
	} while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES));

	if (pnum_info) {
		*pnum_info = num_info;
	}

	if (pinfo) {
		*pinfo = talloc_move(mem_ctx, &info);
	}

error:
	TALLOC_FREE(tmp_ctx);
	return status;
}

/* Query display info for a domain */
static NTSTATUS sam_query_user_list(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    uint32_t *pnum_info,
				    struct wbint_userinfo **pinfo)
{
	struct rpc_pipe_client *samr_pipe = NULL;
	struct wbint_userinfo *info = NULL;
	struct policy_handle dom_pol;
	uint32_t num_info = 0;
	uint32_t loop_count = 0;
	uint32_t start_idx = 0;
	uint32_t i = 0;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;

	DEBUG(3,("samr: query_user_list\n"));

	if (pnum_info) {
		*pnum_info = 0;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = open_internal_samr_conn(tmp_ctx, domain, &samr_pipe, &dom_pol);
	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}

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
						      tmp_ctx,
						      &dom_pol,
						      1, /* level */
						      start_idx,
						      max_entries,
						      max_size,
						      &total_size,
						      &returned_size,
						      &disp_info);
		if (!NT_STATUS_IS_OK(status)) {
			if (!NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				goto error;
			}
		}

		/* increment required start query values */
		start_idx += disp_info.info1.count;
		loop_count++;
		num_dom_users = disp_info.info1.count;

		num_info += num_dom_users;

		info = TALLOC_REALLOC_ARRAY(tmp_ctx,
					    info,
					    struct wbint_userinfo,
					    num_info);
		if (info == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto error;
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
				status = NT_STATUS_NO_MEMORY;
				goto error;
			}

			dst->full_name = talloc_strdup(info, src->full_name.string);
			if (dst->full_name == NULL) {
				status = NT_STATUS_NO_MEMORY;
				goto error;
			}

			dst->homedir = NULL;
			dst->shell = NULL;

			sid_compose(&dst->user_sid, &domain->sid, rid);

			/* For the moment we set the primary group for
			   every user to be the Domain Users group.
			   There are serious problems with determining
			   the actual primary group for large domains.
			   This should really be made into a 'winbind
			   force group' smb.conf parameter or
			   something like that. */
			sid_compose(&dst->group_sid, &domain->sid,
				    DOMAIN_RID_USERS);
		}
	} while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES));

	if (pnum_info) {
		*pnum_info = num_info;
	}

	if (pinfo) {
		*pinfo = talloc_move(mem_ctx, &info);
	}

error:
	TALLOC_FREE(tmp_ctx);
	return status;
}

/* Lookup user information from a rid or username. */
static NTSTATUS sam_query_user(struct winbindd_domain *domain,
			       TALLOC_CTX *mem_ctx,
			       const struct dom_sid *user_sid,
			       struct wbint_userinfo *user_info)
{
	struct rpc_pipe_client *samr_pipe;
	struct policy_handle dom_pol, user_pol;
	union samr_UserInfo *info = NULL;
	TALLOC_CTX *tmp_ctx;
	uint32_t user_rid;
	NTSTATUS status;

	DEBUG(3,("samr: query_user\n"));

	if (!sid_peek_check_rid(&domain->sid, user_sid, &user_rid)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (user_info) {
		user_info->homedir = NULL;
		user_info->shell = NULL;
		user_info->primary_gid = (gid_t) -1;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = open_internal_samr_conn(tmp_ctx, domain, &samr_pipe, &dom_pol);
	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}

	/* Get user handle */
	status = rpccli_samr_OpenUser(samr_pipe,
				      tmp_ctx,
				      &dom_pol,
				      SEC_FLAG_MAXIMUM_ALLOWED,
				      user_rid,
				      &user_pol);
	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}

	/* Get user info */
	status = rpccli_samr_QueryUserInfo(samr_pipe,
					   tmp_ctx,
					   &user_pol,
					   0x15,
					   &info);

	rpccli_samr_Close(samr_pipe, tmp_ctx, &user_pol);

	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}

	sid_compose(&user_info->user_sid, &domain->sid, user_rid);
	sid_compose(&user_info->group_sid, &domain->sid,
		    info->info21.primary_gid);

	if (user_info) {
		user_info->acct_name = talloc_strdup(mem_ctx,
						     info->info21.account_name.string);
		if (user_info->acct_name == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto error;
		}

		user_info->full_name = talloc_strdup(mem_ctx,
						     info->info21.full_name.string);
		if (user_info->acct_name == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto error;
		}

		user_info->homedir = NULL;
		user_info->shell = NULL;
		user_info->primary_gid = (gid_t)-1;
	}

	status = NT_STATUS_OK;
error:
	TALLOC_FREE(tmp_ctx);
	return status;
}

/* get a list of trusted domains - builtin domain */
static NTSTATUS sam_trusted_domains(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    struct netr_DomainTrustList *trusts)
{
	/* TODO FIXME */
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* Lookup group membership given a rid.   */
static NTSTATUS sam_lookup_groupmem(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    const struct dom_sid *group_sid,
				    enum lsa_SidType type,
				    uint32_t *num_names,
				    struct dom_sid **sid_mem,
				    char ***names,
				    uint32_t **name_types)
{
	/* TODO FIXME */
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*********************************************************************
 BUILTIN specific functions.
*********************************************************************/

/* List all domain groups */
static NTSTATUS builtin_enum_dom_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_entries,
				struct acct_info **info)
{
	/* BUILTIN doesn't have domain groups */
	*num_entries = 0;
	*info = NULL;
	return NT_STATUS_OK;
}

/* Query display info for a domain */
static NTSTATUS builtin_query_user_list(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_entries,
				struct wbint_userinfo **info)
{
	/* We don't have users */
	*num_entries = 0;
	*info = NULL;
	return NT_STATUS_OK;
}

/* Lookup user information from a rid or username. */
static NTSTATUS builtin_query_user(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				const struct dom_sid *user_sid,
				struct wbint_userinfo *user_info)
{
	return NT_STATUS_NO_SUCH_USER;
}

/* get a list of trusted domains - builtin domain */
static NTSTATUS builtin_trusted_domains(struct winbindd_domain *domain,
					TALLOC_CTX *mem_ctx,
					struct netr_DomainTrustList *trusts)
{
	ZERO_STRUCTP(trusts);
	return NT_STATUS_OK;
}

/*********************************************************************
 COMMON functions.
*********************************************************************/

/* List all local groups (aliases) */
static NTSTATUS common_enum_local_groups(struct winbindd_domain *domain,
					 TALLOC_CTX *mem_ctx,
					 uint32_t *num_entries,
					 struct acct_info **info)
{
	/* TODO FIXME */
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* convert a single name to a sid in a domain */
static NTSTATUS common_name_to_sid(struct winbindd_domain *domain,
				   TALLOC_CTX *mem_ctx,
				   const char *domain_name,
				   const char *name,
				   uint32_t flags,
				   struct dom_sid *sid,
				   enum lsa_SidType *type)
{
	/* TODO FIXME */
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* convert a domain SID to a user or group name */
static NTSTATUS common_sid_to_name(struct winbindd_domain *domain,
				   TALLOC_CTX *mem_ctx,
				   const struct dom_sid *sid,
				   char **domain_name,
				   char **name,
				   enum lsa_SidType *type)
{
	/* TODO FIXME */
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS common_rids_to_names(struct winbindd_domain *domain,
				     TALLOC_CTX *mem_ctx,
				     const struct dom_sid *sid,
				     uint32 *rids,
				     size_t num_rids,
				     char **domain_name,
				     char ***names,
				     enum lsa_SidType **types)
{
	/* TODO FIXME */
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS common_lockout_policy(struct winbindd_domain *domain,
				      TALLOC_CTX *mem_ctx,
				      struct samr_DomInfo12 *policy)
{
	/* TODO FIXME */
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS common_password_policy(struct winbindd_domain *domain,
				       TALLOC_CTX *mem_ctx,
				       struct samr_DomInfo1 *policy)
{
	/* TODO FIXME */
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* Lookup groups a user is a member of.  I wish Unix had a call like this! */
static NTSTATUS common_lookup_usergroups(struct winbindd_domain *domain,
					 TALLOC_CTX *mem_ctx,
					 const struct dom_sid *user_sid,
					 uint32_t *num_groups,
					 struct dom_sid **user_gids)
{
	/* TODO FIXME */
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS common_lookup_useraliases(struct winbindd_domain *domain,
					  TALLOC_CTX *mem_ctx,
					  uint32_t num_sids,
					  const struct dom_sid *sids,
					  uint32_t *p_num_aliases,
					  uint32_t **rids)
{
	/* TODO FIXME */
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* find the sequence number for a domain */
static NTSTATUS common_sequence_number(struct winbindd_domain *domain,
				       uint32_t *seq)
{
	/* TODO FIXME */
	return NT_STATUS_NOT_IMPLEMENTED;
}

#if 0
/* the rpc backend methods are exposed via this structure */
struct winbindd_methods builtin_passdb_methods = {
	.consistent            = false,

	.query_user_list       = builtin_query_user_list,
	.enum_dom_groups       = builtin_enum_dom_groups,
	.enum_local_groups     = common_enum_local_groups,
	.name_to_sid           = common_name_to_sid,
	.sid_to_name           = common_sid_to_name,
	.rids_to_names         = common_rids_to_names,
	.query_user            = builtin_query_user,
	.lookup_usergroups     = common_lookup_usergroups,
	.lookup_useraliases    = common_lookup_useraliases,
	.lookup_groupmem       = sam_lookup_groupmem,
	.sequence_number       = common_sequence_number,
	.lockout_policy        = common_lockout_policy,
	.password_policy       = common_password_policy,
	.trusted_domains       = builtin_trusted_domains
};

/* the rpc backend methods are exposed via this structure */
struct winbindd_methods sam_passdb_methods = {
	.consistent            = false,

	.query_user_list       = sam_query_user_list,
	.enum_dom_groups       = sam_enum_dom_groups,
	.enum_local_groups     = common_enum_local_groups,
	.name_to_sid           = common_name_to_sid,
	.sid_to_name           = common_sid_to_name,
	.rids_to_names         = common_rids_to_names,
	.query_user            = sam_query_user,
	.lookup_usergroups     = common_lookup_usergroups,
	.lookup_useraliases    = common_lookup_useraliases,
	.lookup_groupmem       = sam_lookup_groupmem,
	.sequence_number       = common_sequence_number,
	.lockout_policy        = common_lockout_policy,
	.password_policy       = common_password_policy,
	.trusted_domains       = sam_trusted_domains
};
#endif
