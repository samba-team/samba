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
