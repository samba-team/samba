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

static NTSTATUS auth_convert_user_info_dc_sambaseinfo(TALLOC_CTX *mem_ctx,
				const struct auth_user_info_dc *user_info_dc,
				struct netr_SamBaseInfo *sam)
{
	NTSTATUS status;
	const struct auth_user_info *info;

	ZERO_STRUCTP(sam);

	if (user_info_dc->num_sids > PRIMARY_USER_SID_INDEX) {
		status = dom_sid_split_rid(sam, &user_info_dc->sids[PRIMARY_USER_SID_INDEX],
					   &sam->domain_sid, &sam->rid);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (user_info_dc->num_sids > PRIMARY_GROUP_SID_INDEX) {
		status = dom_sid_split_rid(NULL, &user_info_dc->sids[PRIMARY_GROUP_SID_INDEX],
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

	if (user_info_dc->num_sids > PRIMARY_GROUP_SID_INDEX) {
		size_t i;
		sam->groups.rids = talloc_array(mem_ctx, struct samr_RidWithAttribute,
						user_info_dc->num_sids);

		if (sam->groups.rids == NULL)
			return NT_STATUS_NO_MEMORY;

		for (i=PRIMARY_GROUP_SID_INDEX; i<user_info_dc->num_sids; i++) {
			struct dom_sid *group_sid = &user_info_dc->sids[i];
			if (!dom_sid_in_domain(sam->domain_sid, group_sid)) {
				/* We handle this elsewhere */
				continue;
			}
			sam->groups.rids[sam->groups.count].rid =
				group_sid->sub_auths[group_sid->num_auths-1];

			sam->groups.rids[sam->groups.count].attributes =
				SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;
			sam->groups.count += 1;
		}
	}

	sam->user_flags = 0; /* w2k3 uses NETLOGON_EXTRA_SIDS | NETLOGON_NTLMV2_ENABLED */
	if (!user_info_dc->info->authenticated) {
		sam->user_flags |= NETLOGON_GUEST;
	}
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

/* Note that the validity of the _sam6 structure is only as long as
 * the user_info_dc it was generated from */
NTSTATUS auth_convert_user_info_dc_saminfo6(TALLOC_CTX *mem_ctx,
					    const struct auth_user_info_dc *user_info_dc,
					    struct netr_SamInfo6 **_sam6)
{
	NTSTATUS status;
	struct netr_SamInfo6 *sam6 = NULL;
	size_t i;

	sam6 = talloc_zero(mem_ctx, struct netr_SamInfo6);
	if (sam6 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = auth_convert_user_info_dc_sambaseinfo(sam6,
						       user_info_dc,
						       &sam6->base);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(sam6);
		return status;
	}

	sam6->sids = talloc_array(sam6, struct netr_SidAttr,
				  user_info_dc->num_sids);
	if (sam6->sids == NULL) {
		TALLOC_FREE(sam6);
		return NT_STATUS_NO_MEMORY;
	}

	/* We don't put the user and group SIDs in there */
	for (i=2; i<user_info_dc->num_sids; i++) {
		if (dom_sid_in_domain(sam6->base.domain_sid, &user_info_dc->sids[i])) {
			continue;
		}
		sam6->sids[sam6->sidcount].sid = dom_sid_dup(sam6->sids, &user_info_dc->sids[i]);
		if (sam6->sids[sam6->sidcount].sid == NULL) {
			TALLOC_FREE(sam6);
			return NT_STATUS_NO_MEMORY;
		}
		sam6->sids[sam6->sidcount].attributes =
			SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;
		sam6->sidcount += 1;
	}
	if (sam6->sidcount) {
		sam6->base.user_flags |= NETLOGON_EXTRA_SIDS;
	} else {
		sam6->sids = NULL;
	}

	if (user_info_dc->info->dns_domain_name != NULL) {
		sam6->dns_domainname.string = talloc_strdup(sam6,
					user_info_dc->info->dns_domain_name);
		if (sam6->dns_domainname.string == NULL) {
			TALLOC_FREE(sam6);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (user_info_dc->info->user_principal_name != NULL) {
		sam6->principal_name.string = talloc_strdup(sam6,
					user_info_dc->info->user_principal_name);
		if (sam6->principal_name.string == NULL) {
			TALLOC_FREE(sam6);
			return NT_STATUS_NO_MEMORY;
		}
	}

	*_sam6 = sam6;
	return NT_STATUS_OK;
}

/* Note that the validity of the _sam2 structure is only as long as
 * the user_info_dc it was generated from */
NTSTATUS auth_convert_user_info_dc_saminfo2(TALLOC_CTX *mem_ctx,
					   const struct auth_user_info_dc *user_info_dc,
					   struct netr_SamInfo2 **_sam2)
{
	NTSTATUS status;
	struct netr_SamInfo6 *sam6 = NULL;
	struct netr_SamInfo2 *sam2 = NULL;

	sam2 = talloc_zero(mem_ctx, struct netr_SamInfo2);
	if (sam2 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = auth_convert_user_info_dc_saminfo6(sam2, user_info_dc, &sam6);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(sam2);
		return status;
	}
	sam2->base	= sam6->base;

	*_sam2 = sam2;
	return NT_STATUS_OK;
}

/* Note that the validity of the _sam3 structure is only as long as
 * the user_info_dc it was generated from */
NTSTATUS auth_convert_user_info_dc_saminfo3(TALLOC_CTX *mem_ctx,
					   const struct auth_user_info_dc *user_info_dc,
					   struct netr_SamInfo3 **_sam3)
{
	NTSTATUS status;
	struct netr_SamInfo6 *sam6 = NULL;
	struct netr_SamInfo3 *sam3 = NULL;

	sam3 = talloc_zero(mem_ctx, struct netr_SamInfo3);
	if (sam3 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = auth_convert_user_info_dc_saminfo6(sam3, user_info_dc, &sam6);
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
	NT_STATUS_HAVE_NO_MEMORY(info);

	if (base->account_name.string) {
		info->account_name = talloc_strdup(info, base->account_name.string);
	} else {
		info->account_name = talloc_strdup(info, account_name);
	}
	NT_STATUS_HAVE_NO_MEMORY(info->account_name);

	if (base->logon_domain.string) {
		info->domain_name = talloc_strdup(info, base->logon_domain.string);
		NT_STATUS_HAVE_NO_MEMORY(info->domain_name);
	}

	if (base->full_name.string) {
		info->full_name = talloc_strdup(info, base->full_name.string);
		NT_STATUS_HAVE_NO_MEMORY(info->full_name);
	}
	if (base->logon_script.string) {
		info->logon_script = talloc_strdup(info, base->logon_script.string);
		NT_STATUS_HAVE_NO_MEMORY(info->logon_script);
	}
	if (base->profile_path.string) {
		info->profile_path = talloc_strdup(info, base->profile_path.string);
		NT_STATUS_HAVE_NO_MEMORY(info->profile_path);
	}
	if (base->home_directory.string) {
		info->home_directory = talloc_strdup(info, base->home_directory.string);
		NT_STATUS_HAVE_NO_MEMORY(info->home_directory);
	}
	if (base->home_drive.string) {
		info->home_drive = talloc_strdup(info, base->home_drive.string);
		NT_STATUS_HAVE_NO_MEMORY(info->home_drive);
	}
	if (base->logon_server.string) {
		info->logon_server = talloc_strdup(info, base->logon_server.string);
		NT_STATUS_HAVE_NO_MEMORY(info->logon_server);
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

	/* Only set authenticated if both NETLOGON_GUEST is not set, and authenticated is set */
	info->authenticated = (authenticated && (!(base->user_flags & NETLOGON_GUEST)));

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

	user_info_dc = talloc(mem_ctx, struct auth_user_info_dc);
	NT_STATUS_HAVE_NO_MEMORY(user_info_dc);

	/*
	   Here is where we should check the list of
	   trusted domains, and verify that the SID
	   matches.
	*/
	if (!base->domain_sid) {
		DEBUG(0, ("Cannot operate on a Netlogon Validation without a domain SID"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* The IDL layer would be a better place to check this, but to
	 * guard the integer addition below, we double-check */
	if (base->groups.count > 65535) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	user_info_dc->num_sids = 2;

	user_info_dc->sids = talloc_array(user_info_dc, struct dom_sid,  user_info_dc->num_sids + base->groups.count);
	NT_STATUS_HAVE_NO_MEMORY(user_info_dc->sids);

	user_info_dc->sids[PRIMARY_USER_SID_INDEX] = *base->domain_sid;
	if (!sid_append_rid(&user_info_dc->sids[PRIMARY_USER_SID_INDEX], base->rid)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	user_info_dc->sids[PRIMARY_GROUP_SID_INDEX] = *base->domain_sid;
	if (!sid_append_rid(&user_info_dc->sids[PRIMARY_GROUP_SID_INDEX], base->primary_gid)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	for (i = 0; i < base->groups.count; i++) {
		/* Skip primary group, already added above */
		if (base->groups.rids[i].rid == base->primary_gid) {
			continue;
		}
		user_info_dc->sids[user_info_dc->num_sids] = *base->domain_sid;
		if (!sid_append_rid(&user_info_dc->sids[user_info_dc->num_sids], base->groups.rids[i].rid)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		user_info_dc->num_sids++;
	}

	/* Copy 'other' sids.  We need to do sid filtering here to
	   prevent possible elevation of privileges.  See:

           http://www.microsoft.com/windows2000/techinfo/administration/security/sidfilter.asp
         */

	/*
	 * The IDL layer would be a better place to check this, but to
	 * guard the integer addition below, we double-check
	 */
	if (sidcount > UINT16_MAX) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (sidcount > 0) {
		struct dom_sid *dgrps = user_info_dc->sids;
		size_t dgrps_count;

		dgrps_count = user_info_dc->num_sids + sidcount;
		dgrps = talloc_realloc(user_info_dc, dgrps, struct dom_sid,
				       dgrps_count);
		if (dgrps == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		for (i = 0; i < sidcount; i++) {
			if (sids[i].sid) {
				dgrps[user_info_dc->num_sids] = *sids[i].sid;
				user_info_dc->num_sids++;
			}
		}

		user_info_dc->sids = dgrps;

		/* Where are the 'global' sids?... */
	}

	status = make_user_info_SamBaseInfo(user_info_dc, account_name, base, authenticated, &user_info_dc->info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (dns_domainname != NULL) {
		user_info_dc->info->dns_domain_name = talloc_strdup(user_info_dc->info,
								    dns_domainname);
		if (user_info_dc->info->dns_domain_name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (principal != NULL) {
		user_info_dc->info->user_principal_name = talloc_strdup(user_info_dc->info,
									principal);
		if (user_info_dc->info->user_principal_name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* ensure we are never given NULL session keys */

	if (all_zero(base->key.key, sizeof(base->key.key))) {
		user_info_dc->user_session_key = data_blob(NULL, 0);
	} else {
		user_info_dc->user_session_key = data_blob_talloc(user_info_dc, base->key.key, sizeof(base->key.key));
		NT_STATUS_HAVE_NO_MEMORY(user_info_dc->user_session_key.data);
	}

	if (all_zero(base->LMSessKey.key, sizeof(base->LMSessKey.key))) {
		user_info_dc->lm_session_key = data_blob(NULL, 0);
	} else {
		user_info_dc->lm_session_key = data_blob_talloc(user_info_dc, base->LMSessKey.key, sizeof(base->LMSessKey.key));
		NT_STATUS_HAVE_NO_MEMORY(user_info_dc->lm_session_key.data);
	}

	*_user_info_dc = user_info_dc;
	return NT_STATUS_OK;
}

/**
 * Make a user_info_dc struct from the PAC_LOGON_INFO supplied in the krb5 logon
 */
NTSTATUS make_user_info_dc_pac(TALLOC_CTX *mem_ctx,
			      const struct PAC_LOGON_INFO *pac_logon_info,
			      const struct PAC_UPN_DNS_INFO *pac_upn_dns_info,
			      struct auth_user_info_dc **_user_info_dc)
{
	uint32_t i;
	NTSTATUS nt_status;
	union netr_Validation validation;
	struct auth_user_info_dc *user_info_dc;
	const struct PAC_DOMAIN_GROUP_MEMBERSHIP *rg = NULL;
	size_t sidcount;

	rg = &pac_logon_info->resource_groups;

	validation.sam3 = discard_const_p(struct netr_SamInfo3, &pac_logon_info->info3);

	nt_status = make_user_info_dc_netlogon_validation(mem_ctx, "", 3, &validation,
							  true, /* This user was authenticated */
							  &user_info_dc);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	if (pac_logon_info->info3.base.user_flags & NETLOGON_RESOURCE_GROUPS) {
		rg = &pac_logon_info->resource_groups;
	}

	if (rg == NULL) {
		*_user_info_dc = user_info_dc;
		return NT_STATUS_OK;
	}

	if (rg->groups.count > 0) {
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
			DEBUG(0, ("Cannot operate on a PAC without a resource domain SID"));
			return NT_STATUS_INVALID_PARAMETER;
		}

		sidcount = user_info_dc->num_sids + rg->groups.count;
		user_info_dc->sids
			= talloc_realloc(user_info_dc, user_info_dc->sids, struct dom_sid, sidcount);
		if (user_info_dc->sids == NULL) {
			TALLOC_FREE(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}

		for (i = 0; i < rg->groups.count; i++) {
			bool ok;

			user_info_dc->sids[user_info_dc->num_sids] = *rg->domain_sid;
			ok = sid_append_rid(&user_info_dc->sids[user_info_dc->num_sids],
					    rg->groups.rids[i].rid);
			if (!ok) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			user_info_dc->num_sids++;
		}
	}

	if (pac_upn_dns_info != NULL) {
		user_info_dc->info->user_principal_name =
			talloc_strdup(user_info_dc->info,
				      pac_upn_dns_info->upn_name);
		if (user_info_dc->info->user_principal_name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		user_info_dc->info->dns_domain_name =
			talloc_strdup(user_info_dc->info,
				      pac_upn_dns_info->dns_domain_name);
		if (user_info_dc->info->dns_domain_name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		if (pac_upn_dns_info->flags & PAC_UPN_DNS_FLAG_CONSTRUCTED) {
			user_info_dc->info->user_principal_constructed = true;
		}
	}

	*_user_info_dc = user_info_dc;
	return NT_STATUS_OK;
}
