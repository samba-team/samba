/*
   Unix SMB/CIFS implementation.

   Convert a server info struct into the form for PAC and NETLOGON replies

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2011
   Copyright (C) Stefan Metzmacher <metze@samba.org>  2005

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "librpc/gen_ndr/auth.h"
#include "libcli/security/security.h"
#include "auth/auth_sam_reply.h"

/* Returns true if this SID belongs in SamBaseInfo, otherwise false. */
static bool is_base_sid(const struct auth_SidAttr *sid,
			const struct dom_sid *domain_sid)
{
	if (sid->attrs & SE_GROUP_RESOURCE) {
		/*
		 * Resource groups don't belong in the base
		 * RIDs, they're handled elsewhere.
		 */
		return false;
	}

	/*
	 * This SID belongs in the base structure only if it's in the account's
	 * domain.
	 */
	return dom_sid_in_domain(domain_sid, &sid->sid);
}

/* Stores a SID in a previously allocated array. */
static NTSTATUS store_extra_sid(struct netr_SidAttr *sids,
				uint32_t *sidcount,
				const uint32_t allocated_sids,
				const struct auth_SidAttr *sid)
{
	/* Check we aren't about to overflow our allocation. */
	if (*sidcount >= allocated_sids) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	sids[*sidcount].sid = dom_sid_dup(sids, &sid->sid);
	if (sids[*sidcount].sid == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	sids[*sidcount].attributes = sid->attrs;
	*sidcount += 1;

	return NT_STATUS_OK;
}

/*
 * Stores a resource SID in a previously allocated array, either Extra SIDs or
 * Resource SIDs. Any SID within the domain of the first SID so added is stored
 * there, while remaining SIDs are stored in Extra SIDs.
 */
static NTSTATUS store_resource_sid(struct netr_SidAttr *sids,
				   uint32_t *sidcount,
				   const uint32_t allocated_sids,
				   const struct auth_SidAttr *sid,
				   struct PAC_DOMAIN_GROUP_MEMBERSHIP *resource_groups,
				   const uint32_t allocated_resource_groups)
{
	NTSTATUS status;

	struct dom_sid *resource_domain = NULL;
	uint32_t rid;

	if (resource_groups == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Split the SID into domain and RID.  */
	status = dom_sid_split_rid(resource_groups, &sid->sid, &resource_domain, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (resource_groups->domain_sid == NULL) {
		/*
		 * There is no domain SID set. Set it to the domain of this SID.
		 */
		resource_groups->domain_sid = resource_domain;
	} else {
		/*
		 * A domain SID has already been set. Check whether this SID's
		 * domain matches.
		 *
		 * Assuming that resource SIDs have been obtained with
		 * dsdb_expand_nested_groups(), they should all be within the
		 * same domain (ours), so unless something has gone horribly
		 * wrong, we should always find that they match.
		 */
		bool match = dom_sid_equal(resource_groups->domain_sid, resource_domain);
		talloc_free(resource_domain);
		if (!match) {
			/*
			 * It doesn't match, so we can't store this SID here. It
			 * will have to go in Extra SIDs.
			 */
			return store_extra_sid(sids, sidcount, allocated_sids, sid);
		}
	}

	/* Store the SID in Resource SIDs. */

	/* Check we aren't about to overflow our allocation. */
	if (resource_groups->groups.count >= allocated_resource_groups) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	resource_groups->groups.rids[resource_groups->groups.count].rid = rid;
	resource_groups->groups.rids[resource_groups->groups.count].attributes = sid->attrs;
	resource_groups->groups.count++;

	return NT_STATUS_OK;
}

/*
 * Stores a SID in a previously allocated array, or excludes it if we are not
 * storing resource groups. It will be placed in either Extra SIDs or Resource
 * SIDs, depending on which is appropriate.
 */
static NTSTATUS store_sid(struct netr_SidAttr *sids,
			  uint32_t *sidcount,
			  const uint32_t allocated_sids,
			  const struct auth_SidAttr *sid,
			  struct PAC_DOMAIN_GROUP_MEMBERSHIP *resource_groups,
			  const uint32_t allocated_resource_groups,
			  const enum auth_group_inclusion group_inclusion)
{
	/* See if it's a resource SID. */
	if (sid->attrs & SE_GROUP_RESOURCE) {
		/*
		 * If this is the SID of a resource group, determine whether it
		 * should be included or filtered out.
		 */
		switch (group_inclusion) {
		case AUTH_INCLUDE_RESOURCE_GROUPS:
			/* Include this SID in Extra SIDs. */
			break;
		case AUTH_INCLUDE_RESOURCE_GROUPS_COMPRESSED:
			/*
			 * Try to include this SID in Resource Groups. If this
			 * can't be arranged, we shall fall back to Extra
			 * SIDs.
			 */
			return store_resource_sid(sids,
						  sidcount,
						  allocated_sids,
						  sid,
						  resource_groups,
						  allocated_resource_groups);
		case AUTH_EXCLUDE_RESOURCE_GROUPS:
			/* Ignore this SID. */
			return NT_STATUS_OK;
		default:
			/* This means we have a bug. */
			DBG_ERR("invalid group inclusion parameter: %u\n", group_inclusion);
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	/* Just store the SID in Extra SIDs. */
	return store_extra_sid(sids,
			       sidcount,
			       allocated_sids,
			       sid);
}

static NTSTATUS auth_convert_user_info_dc_sambaseinfo(TALLOC_CTX *mem_ctx,
				const struct auth_user_info_dc *user_info_dc,
				struct netr_SamBaseInfo *sam)
{
	NTSTATUS status;
	const struct auth_user_info *info;

	ZERO_STRUCTP(sam);

	if (user_info_dc->num_sids > PRIMARY_USER_SID_INDEX) {
		status = dom_sid_split_rid(sam, &user_info_dc->sids[PRIMARY_USER_SID_INDEX].sid,
					   &sam->domain_sid, &sam->rid);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (user_info_dc->num_sids > PRIMARY_GROUP_SID_INDEX) {
		status = dom_sid_split_rid(NULL, &user_info_dc->sids[PRIMARY_GROUP_SID_INDEX].sid,
					   NULL, &sam->primary_gid);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else {
		/* if we have to encode something like SYSTEM (with no
		 * second SID in the token) then this is the only
		 * choice */
		sam->primary_gid = sam->rid;
	}

	info = user_info_dc->info;

	sam->logon_time = info->last_logon;
	sam->logoff_time =  info->last_logoff;
	sam->kickoff_time = info->acct_expiry;
	sam->last_password_change = info->last_password_change;
	sam->allow_password_change = info->allow_password_change;
	sam->force_password_change = info->force_password_change;

#define _COPY_STRING_TALLOC(src_name, dst_name) do { \
	if (info->src_name != NULL) {\
		sam->dst_name.string = talloc_strdup(mem_ctx, info->src_name); \
		if (sam->dst_name.string == NULL) { \
			return NT_STATUS_NO_MEMORY; \
		} \
	} \
} while(0)
	_COPY_STRING_TALLOC(account_name, account_name);
	_COPY_STRING_TALLOC(full_name, full_name);
	_COPY_STRING_TALLOC(logon_script, logon_script);
	_COPY_STRING_TALLOC(profile_path, profile_path);
	_COPY_STRING_TALLOC(home_directory, home_directory);
	_COPY_STRING_TALLOC(home_drive, home_drive);
	_COPY_STRING_TALLOC(logon_server, logon_server);
	_COPY_STRING_TALLOC(domain_name, logon_domain);
#undef _COPY_STRING_TALLOC

	sam->logon_count = info->logon_count;
	sam->bad_password_count = info->bad_password_count;
	sam->groups.count = 0;
	sam->groups.rids = NULL;

	if (user_info_dc->num_sids > REMAINING_SIDS_INDEX) {
		size_t i;
		sam->groups.rids = talloc_array(mem_ctx, struct samr_RidWithAttribute,
						user_info_dc->num_sids);

		if (sam->groups.rids == NULL)
			return NT_STATUS_NO_MEMORY;

		for (i=REMAINING_SIDS_INDEX; i<user_info_dc->num_sids; i++) {
			struct auth_SidAttr *group_sid = &user_info_dc->sids[i];

			bool belongs_in_base = is_base_sid(group_sid, sam->domain_sid);
			if (!belongs_in_base) {
				/* We handle this elsewhere */
				continue;
			}
			sam->groups.rids[sam->groups.count].rid =
				group_sid->sid.sub_auths[group_sid->sid.num_auths-1];

			sam->groups.rids[sam->groups.count].attributes = group_sid->attrs;
			sam->groups.count += 1;
		}

		if (sam->groups.count == 0) {
			TALLOC_FREE(sam->groups.rids);
		}
	}

	sam->user_flags = info->user_flags; /* w2k3 uses NETLOGON_EXTRA_SIDS | NETLOGON_NTLMV2_ENABLED */
	sam->acct_flags = user_info_dc->info->acct_flags;
	sam->sub_auth_status = 0;
	sam->last_successful_logon = 0;
	sam->last_failed_logon = 0;
	sam->failed_logon_count = 0;
	sam->reserved = 0;

	ZERO_STRUCT(sam->key);
	if (user_info_dc->user_session_key.length == sizeof(sam->key.key)) {
		memcpy(sam->key.key, user_info_dc->user_session_key.data, sizeof(sam->key.key));
	}

	ZERO_STRUCT(sam->LMSessKey);
	if (user_info_dc->lm_session_key.length == sizeof(sam->LMSessKey.key)) {
		memcpy(sam->LMSessKey.key, user_info_dc->lm_session_key.data,
		       sizeof(sam->LMSessKey.key));
	}

	return NT_STATUS_OK;
}

/* Note that the validity of the _sam6 and resource_groups structures is only as
 * long as the user_info_dc it was generated from */
NTSTATUS auth_convert_user_info_dc_saminfo6(TALLOC_CTX *mem_ctx,
					    const struct auth_user_info_dc *user_info_dc,
					    enum auth_group_inclusion group_inclusion,
					    struct netr_SamInfo6 **_sam6,
					    struct PAC_DOMAIN_GROUP_MEMBERSHIP **_resource_groups)
{
	NTSTATUS status;
	struct netr_SamInfo6 *sam6 = NULL;
	struct PAC_DOMAIN_GROUP_MEMBERSHIP *resource_groups = NULL;
	size_t i;

	const uint32_t allocated_sids = user_info_dc->num_sids;
	uint32_t allocated_resource_groups = 0;

	sam6 = talloc_zero(mem_ctx, struct netr_SamInfo6);
	if (sam6 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (_resource_groups == NULL) {
		if (group_inclusion == AUTH_INCLUDE_RESOURCE_GROUPS_COMPRESSED) {
			DBG_ERR("_resource_groups parameter not provided to receive resource groups!\n");
			TALLOC_FREE(sam6);
			return NT_STATUS_INVALID_PARAMETER;
		}
	} else if (group_inclusion == AUTH_INCLUDE_RESOURCE_GROUPS_COMPRESSED) {
		*_resource_groups = NULL;

		/* Allocate resource groups structure. */
		resource_groups = talloc_zero(mem_ctx, struct PAC_DOMAIN_GROUP_MEMBERSHIP);
		if (resource_groups == NULL) {
			TALLOC_FREE(sam6);
			return NT_STATUS_NO_MEMORY;
		}

		/*
		 * Allocate enough space to store user_info_dc->num_sids
		 * RIDs in the worst case.
		 */
		allocated_resource_groups = user_info_dc->num_sids;
		resource_groups->groups.rids = talloc_zero_array(resource_groups,
								 struct samr_RidWithAttribute,
								 allocated_resource_groups);
		if (resource_groups->groups.rids == NULL) {
			TALLOC_FREE(sam6);
			TALLOC_FREE(resource_groups);
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		/* No resource groups will be provided. */
		*_resource_groups = NULL;
	}

	status = auth_convert_user_info_dc_sambaseinfo(sam6,
						       user_info_dc,
						       &sam6->base);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(sam6);
		TALLOC_FREE(resource_groups);
		return status;
	}

	/*
	 * Allocate enough space to store user_info_dc->num_sids SIDs in the
	 * worst case.
	 */
	sam6->sids = talloc_zero_array(sam6, struct netr_SidAttr,
				       allocated_sids);
	if (sam6->sids == NULL) {
		TALLOC_FREE(sam6);
		TALLOC_FREE(resource_groups);
		return NT_STATUS_NO_MEMORY;
	}

	/* We don't put the user and group SIDs in there */
	for (i=REMAINING_SIDS_INDEX; i<user_info_dc->num_sids; i++) {
		struct auth_SidAttr *group_sid = &user_info_dc->sids[i];
		bool belongs_in_base = is_base_sid(group_sid, sam6->base.domain_sid);
		if (belongs_in_base) {
			/* We already handled this in the base. */
			continue;
		}

		status = store_sid(sam6->sids,
				   &sam6->sidcount,
				   allocated_sids,
				   group_sid,
				   resource_groups,
				   allocated_resource_groups,
				   group_inclusion);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(sam6);
			TALLOC_FREE(resource_groups);
			return status;
		}
	}
	if (sam6->sidcount) {
		sam6->base.user_flags |= NETLOGON_EXTRA_SIDS;
	} else {
		sam6->base.user_flags &= ~NETLOGON_EXTRA_SIDS;
		TALLOC_FREE(sam6->sids);
	}

	if (user_info_dc->info->dns_domain_name != NULL) {
		sam6->dns_domainname.string = talloc_strdup(sam6,
					user_info_dc->info->dns_domain_name);
		if (sam6->dns_domainname.string == NULL) {
			TALLOC_FREE(sam6);
			TALLOC_FREE(resource_groups);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (user_info_dc->info->user_principal_name != NULL) {
		sam6->principal_name.string = talloc_strdup(sam6,
					user_info_dc->info->user_principal_name);
		if (sam6->principal_name.string == NULL) {
			TALLOC_FREE(sam6);
			TALLOC_FREE(resource_groups);
			return NT_STATUS_NO_MEMORY;
		}
	}

	*_sam6 = sam6;
	if (resource_groups != NULL) {
		if (resource_groups->groups.count > 0) {
			*_resource_groups = resource_groups;
		} else {
			TALLOC_FREE(resource_groups);
		}
	}
	return NT_STATUS_OK;
}

/* Note that the validity of the _sam2 structure is only as long as
 * the user_info_dc it was generated from */
NTSTATUS auth_convert_user_info_dc_saminfo2(TALLOC_CTX *mem_ctx,
					   const struct auth_user_info_dc *user_info_dc,
					   enum auth_group_inclusion group_inclusion,
					   struct netr_SamInfo2 **_sam2)
{
	NTSTATUS status;
	struct netr_SamInfo6 *sam6 = NULL;
	struct netr_SamInfo2 *sam2 = NULL;

	sam2 = talloc_zero(mem_ctx, struct netr_SamInfo2);
	if (sam2 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = auth_convert_user_info_dc_saminfo6(sam2, user_info_dc,
						    group_inclusion, &sam6,
						    NULL);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(sam2);
		return status;
	}
	sam2->base	= sam6->base;
	/*
	 * We have nowhere to put sam6->sids, so we follow Windows here and drop
	 * it. Any resource groups it happened to contain are lost.
	 */
	sam2->base.user_flags &= ~NETLOGON_EXTRA_SIDS;
	TALLOC_FREE(sam6->sids);

	*_sam2 = sam2;
	return NT_STATUS_OK;
}

/* Note that the validity of the _sam3 structure is only as long as
 * the user_info_dc it was generated from */
NTSTATUS auth_convert_user_info_dc_saminfo3(TALLOC_CTX *mem_ctx,
					   const struct auth_user_info_dc *user_info_dc,
					   enum auth_group_inclusion group_inclusion,
					   struct netr_SamInfo3 **_sam3,
					   struct PAC_DOMAIN_GROUP_MEMBERSHIP **_resource_groups)
{
	NTSTATUS status;
	struct netr_SamInfo6 *sam6 = NULL;
	struct netr_SamInfo3 *sam3 = NULL;

	sam3 = talloc_zero(mem_ctx, struct netr_SamInfo3);
	if (sam3 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = auth_convert_user_info_dc_saminfo6(sam3, user_info_dc,
						    group_inclusion, &sam6,
						    _resource_groups);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(sam3);
		return status;
	}
	sam3->base	= sam6->base;
	sam3->sidcount	= sam6->sidcount;
	sam3->sids	= sam6->sids;

	*_sam3 = sam3;
	return NT_STATUS_OK;
}

/**
 * Make a user_info struct from the info3 or similar returned by a domain logon.
 *
 * The netr_SamInfo3 is also a key structure in the source3 auth subsystem
 */

NTSTATUS make_user_info_SamBaseInfo(TALLOC_CTX *mem_ctx,
				    const char *account_name,
				    const struct netr_SamBaseInfo *base,
				    bool authenticated,
				    struct auth_user_info **_user_info)
{
	struct auth_user_info *info;

	info = talloc_zero(mem_ctx, struct auth_user_info);
	if (info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (base->account_name.string) {
		info->account_name = talloc_strdup(info, base->account_name.string);
	} else {
		info->account_name = talloc_strdup(info, account_name);
	}
	if (info->account_name == NULL) {
		talloc_free(info);
		return NT_STATUS_NO_MEMORY;
	}

	if (base->logon_domain.string) {
		info->domain_name = talloc_strdup(info, base->logon_domain.string);
		if (info->domain_name == NULL) {
			talloc_free(info);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (base->full_name.string) {
		info->full_name = talloc_strdup(info, base->full_name.string);
		if (info->full_name == NULL) {
			talloc_free(info);
			return NT_STATUS_NO_MEMORY;
		}
	}
	if (base->logon_script.string) {
		info->logon_script = talloc_strdup(info, base->logon_script.string);
		if (info->logon_script == NULL) {
			talloc_free(info);
			return NT_STATUS_NO_MEMORY;
		}
	}
	if (base->profile_path.string) {
		info->profile_path = talloc_strdup(info, base->profile_path.string);
		if (info->profile_path == NULL) {
			talloc_free(info);
			return NT_STATUS_NO_MEMORY;
		}
	}
	if (base->home_directory.string) {
		info->home_directory = talloc_strdup(info, base->home_directory.string);
		if (info->home_directory == NULL) {
			talloc_free(info);
			return NT_STATUS_NO_MEMORY;
		}
	}
	if (base->home_drive.string) {
		info->home_drive = talloc_strdup(info, base->home_drive.string);
		if (info->home_drive == NULL) {
			talloc_free(info);
			return NT_STATUS_NO_MEMORY;
		}
	}
	if (base->logon_server.string) {
		info->logon_server = talloc_strdup(info, base->logon_server.string);
		if (info->logon_server == NULL) {
			talloc_free(info);
			return NT_STATUS_NO_MEMORY;
		}
	}
	info->last_logon = base->logon_time;
	info->last_logoff = base->logoff_time;
	info->acct_expiry = base->kickoff_time;
	info->last_password_change = base->last_password_change;
	info->allow_password_change = base->allow_password_change;
	info->force_password_change = base->force_password_change;
	info->logon_count = base->logon_count;
	info->bad_password_count = base->bad_password_count;
	info->acct_flags = base->acct_flags;

	info->user_flags = base->user_flags;
	if (!authenticated) {
		/*
		 * We only consider the user authenticated if NETLOGON_GUEST is
		 * not set, and authenticated is set
		 */
		info->user_flags |= NETLOGON_GUEST;
	}

	*_user_info = info;
	return NT_STATUS_OK;
}

struct auth_user_info *auth_user_info_copy(TALLOC_CTX *mem_ctx,
					   const struct auth_user_info *src)
{
	struct auth_user_info *dst = NULL;

	dst = talloc_zero(mem_ctx, struct auth_user_info);
	if (dst == NULL) {
		return NULL;
	}

	*dst = *src;
#define _COPY_STRING(_mem, _str) do { \
	if ((_str) != NULL) { \
		(_str) = talloc_strdup((_mem), (_str)); \
		if ((_str) == NULL) { \
			TALLOC_FREE(dst); \
			return NULL; \
		} \
	} \
} while(0)
	_COPY_STRING(dst, dst->account_name);
	_COPY_STRING(dst, dst->user_principal_name);
	_COPY_STRING(dst, dst->domain_name);
	_COPY_STRING(dst, dst->dns_domain_name);
	_COPY_STRING(dst, dst->full_name);
	_COPY_STRING(dst, dst->logon_script);
	_COPY_STRING(dst, dst->profile_path);
	_COPY_STRING(dst, dst->home_directory);
	_COPY_STRING(dst, dst->home_drive);
	_COPY_STRING(dst, dst->logon_server);
#undef _COPY_STRING

	return dst;
}

/**
 * Make a user_info_dc struct from the info3 returned by a domain logon
 */
NTSTATUS make_user_info_dc_netlogon_validation(TALLOC_CTX *mem_ctx,
					      const char *account_name,
					      uint16_t validation_level,
					      const union netr_Validation *validation,
					       bool authenticated,
					      struct auth_user_info_dc **_user_info_dc)
{
	NTSTATUS status;
	struct auth_user_info_dc *user_info_dc = NULL;
	const struct netr_SamBaseInfo *base = NULL;
	uint32_t sidcount = 0;
	const struct netr_SidAttr *sids = NULL;
	const char *dns_domainname = NULL;
	const char *principal = NULL;
	uint32_t i;

	switch (validation_level) {
	case 2:
		if (!validation || !validation->sam2) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		base = &validation->sam2->base;
		break;
	case 3:
		if (!validation || !validation->sam3) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		base = &validation->sam3->base;
		sidcount = validation->sam3->sidcount;
		sids = validation->sam3->sids;
		break;
	case 6:
		if (!validation || !validation->sam6) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		base = &validation->sam6->base;
		sidcount = validation->sam6->sidcount;
		sids = validation->sam6->sids;
		dns_domainname = validation->sam6->dns_domainname.string;
		principal = validation->sam6->principal_name.string;
		break;
	default:
		return NT_STATUS_INVALID_LEVEL;
	}

	/*
	   Here is where we should check the list of
	   trusted domains, and verify that the SID
	   matches.
	*/
	if (!base->domain_sid) {
		DEBUG(0, ("Cannot operate on a Netlogon Validation without a domain SID\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* The IDL layer would be a better place to check this, but to
	 * guard the integer addition below, we double-check */
	if (base->groups.count > UINT16_MAX) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/*
	 * The IDL layer would be a better place to check this, but to
	 * guard the integer addition below, we double-check
	 */
	if (sidcount > UINT16_MAX) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	user_info_dc = talloc_zero(mem_ctx, struct auth_user_info_dc);
	if (user_info_dc == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	user_info_dc->num_sids = PRIMARY_SIDS_COUNT;

	user_info_dc->sids = talloc_array(user_info_dc, struct auth_SidAttr,  user_info_dc->num_sids + base->groups.count);
	if (user_info_dc->sids == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	user_info_dc->sids[PRIMARY_USER_SID_INDEX].sid = *base->domain_sid;
	if (!sid_append_rid(&user_info_dc->sids[PRIMARY_USER_SID_INDEX].sid, base->rid)) {
		talloc_free(user_info_dc);
		return NT_STATUS_INVALID_PARAMETER;
	}
	user_info_dc->sids[PRIMARY_USER_SID_INDEX].attrs = SE_GROUP_DEFAULT_FLAGS;

	user_info_dc->sids[PRIMARY_GROUP_SID_INDEX].sid = *base->domain_sid;
	if (!sid_append_rid(&user_info_dc->sids[PRIMARY_GROUP_SID_INDEX].sid, base->primary_gid)) {
		talloc_free(user_info_dc);
		return NT_STATUS_INVALID_PARAMETER;
	}
	/*
	 * This attribute value might be wrong if the primary group is a
	 * resource group. But a resource group is not meant to be in a primary
	 * group in the first place, and besides, these attributes will never
	 * make their way into a PAC.
	 */
	user_info_dc->sids[PRIMARY_GROUP_SID_INDEX].attrs = SE_GROUP_DEFAULT_FLAGS;

	for (i = 0; i < base->groups.count; i++) {
		user_info_dc->sids[user_info_dc->num_sids].sid = *base->domain_sid;
		if (!sid_append_rid(&user_info_dc->sids[user_info_dc->num_sids].sid, base->groups.rids[i].rid)) {
			talloc_free(user_info_dc);
			return NT_STATUS_INVALID_PARAMETER;
		}
		user_info_dc->sids[user_info_dc->num_sids].attrs = base->groups.rids[i].attributes;
		user_info_dc->num_sids++;
	}

	if (sidcount > 0) {
		struct auth_SidAttr *dgrps = user_info_dc->sids;
		size_t dgrps_count;

		dgrps_count = user_info_dc->num_sids + sidcount;
		dgrps = talloc_realloc(user_info_dc, dgrps, struct auth_SidAttr,
				       dgrps_count);
		if (dgrps == NULL) {
			talloc_free(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}

		for (i = 0; i < sidcount; i++) {
			if (sids[i].sid) {
				dgrps[user_info_dc->num_sids].sid = *sids[i].sid;
				dgrps[user_info_dc->num_sids].attrs = sids[i].attributes;
				user_info_dc->num_sids++;
			}
		}

		user_info_dc->sids = dgrps;

		/* Where are the 'global' sids?... */
	}

	status = make_user_info_SamBaseInfo(user_info_dc, account_name, base, authenticated, &user_info_dc->info);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(user_info_dc);
		return status;
	}

	if (dns_domainname != NULL) {
		user_info_dc->info->dns_domain_name = talloc_strdup(user_info_dc->info,
								    dns_domainname);
		if (user_info_dc->info->dns_domain_name == NULL) {
			talloc_free(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (principal != NULL) {
		user_info_dc->info->user_principal_name = talloc_strdup(user_info_dc->info,
									principal);
		if (user_info_dc->info->user_principal_name == NULL) {
			talloc_free(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* ensure we are never given NULL session keys */

	if (all_zero(base->key.key, sizeof(base->key.key))) {
		user_info_dc->user_session_key = data_blob(NULL, 0);
	} else {
		user_info_dc->user_session_key = data_blob_talloc(user_info_dc, base->key.key, sizeof(base->key.key));
		if (user_info_dc->user_session_key.data == NULL) {
			talloc_free(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (all_zero(base->LMSessKey.key, sizeof(base->LMSessKey.key))) {
		user_info_dc->lm_session_key = data_blob(NULL, 0);
	} else {
		user_info_dc->lm_session_key = data_blob_talloc(user_info_dc, base->LMSessKey.key, sizeof(base->LMSessKey.key));
		if (user_info_dc->lm_session_key.data == NULL) {
			talloc_free(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}
	}

	*_user_info_dc = user_info_dc;
	return NT_STATUS_OK;
}

/**
 * Make a user_info_dc struct from the PAC_LOGON_INFO supplied in the krb5
 * logon. For group_inclusion, pass AUTH_INCLUDE_RESOURCE_GROUPS if SIDs from
 * the resource groups are to be included in the resulting structure, and pass
 * AUTH_EXCLUDE_RESOURCE_GROUPS otherwise.
 */
NTSTATUS make_user_info_dc_pac(TALLOC_CTX *mem_ctx,
			      const struct PAC_LOGON_INFO *pac_logon_info,
			      const struct PAC_UPN_DNS_INFO *pac_upn_dns_info,
			      const enum auth_group_inclusion group_inclusion,
			      struct auth_user_info_dc **_user_info_dc)
{
	uint32_t i;
	NTSTATUS nt_status;
	union netr_Validation validation;
	struct auth_user_info_dc *user_info_dc;
	const struct PAC_DOMAIN_GROUP_MEMBERSHIP *rg = NULL;
	size_t sidcount;

	validation.sam3 = discard_const_p(struct netr_SamInfo3, &pac_logon_info->info3);

	nt_status = make_user_info_dc_netlogon_validation(mem_ctx, "", 3, &validation,
							  true, /* This user was authenticated */
							  &user_info_dc);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	if (pac_logon_info->info3.base.user_flags & NETLOGON_RESOURCE_GROUPS) {
		switch (group_inclusion) {
		case AUTH_INCLUDE_RESOURCE_GROUPS:
			/* Take resource groups from the PAC. */
			rg = &pac_logon_info->resource_groups;
			break;
		case AUTH_EXCLUDE_RESOURCE_GROUPS:
			/*
			 * The PAC is from a TGT, or we don't want to process
			 * its resource groups.
			 */
			break;
		default:
			DBG_ERR("invalid group inclusion parameter: %u\n", group_inclusion);
			talloc_free(user_info_dc);
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	if (rg != NULL && rg->groups.count > 0) {
		/* The IDL layer would be a better place to check this, but to
		 * guard the integer addition below, we double-check */
		if (rg->groups.count > 65535) {
			talloc_free(user_info_dc);
			return NT_STATUS_INVALID_PARAMETER;
		}

		/*
		  Here is where we should check the list of
		  trusted domains, and verify that the SID
		  matches.
		*/
		if (rg->domain_sid == NULL) {
			talloc_free(user_info_dc);
			DEBUG(0, ("Cannot operate on a PAC without a resource domain SID\n"));
			return NT_STATUS_INVALID_PARAMETER;
		}

		sidcount = user_info_dc->num_sids + rg->groups.count;
		user_info_dc->sids
			= talloc_realloc(user_info_dc, user_info_dc->sids, struct auth_SidAttr, sidcount);
		if (user_info_dc->sids == NULL) {
			TALLOC_FREE(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}

		for (i = 0; i < rg->groups.count; i++) {
			bool ok;

			user_info_dc->sids[user_info_dc->num_sids].sid = *rg->domain_sid;
			ok = sid_append_rid(&user_info_dc->sids[user_info_dc->num_sids].sid,
					    rg->groups.rids[i].rid);
			if (!ok) {
				talloc_free(user_info_dc);
				return NT_STATUS_INVALID_PARAMETER;
			}
			user_info_dc->sids[user_info_dc->num_sids].attrs = rg->groups.rids[i].attributes;
			user_info_dc->num_sids++;
		}
	}

	if (pac_upn_dns_info != NULL) {
		if (pac_upn_dns_info->upn_name != NULL) {
			user_info_dc->info->user_principal_name =
				talloc_strdup(user_info_dc->info,
					      pac_upn_dns_info->upn_name);
			if (user_info_dc->info->user_principal_name == NULL) {
				talloc_free(user_info_dc);
				return NT_STATUS_NO_MEMORY;
			}
		}

		user_info_dc->info->dns_domain_name =
			talloc_strdup(user_info_dc->info,
				      pac_upn_dns_info->dns_domain_name);
		if (user_info_dc->info->dns_domain_name == NULL) {
			talloc_free(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}

		if (pac_upn_dns_info->flags & PAC_UPN_DNS_FLAG_CONSTRUCTED) {
			user_info_dc->info->user_principal_constructed = true;
		}
	}

	*_user_info_dc = user_info_dc;
	return NT_STATUS_OK;
}
