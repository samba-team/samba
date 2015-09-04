/*
   Unix SMB/CIFS implementation.
   Authentication utility functions
   Copyright (C) Volker Lendecke 2010

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
#include "auth.h"
#include "../lib/crypto/arcfour.h"
#include "../librpc/gen_ndr/netlogon.h"
#include "../libcli/security/security.h"
#include "rpc_client/util_netlogon.h"
#include "nsswitch/libwbclient/wbclient.h"
#include "lib/winbind_util.h"
#include "passdb.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

/***************************************************************************
 Make a server_info struct. Free with TALLOC_FREE().
***************************************************************************/

struct auth_serversupplied_info *make_server_info(TALLOC_CTX *mem_ctx)
{
	struct auth_serversupplied_info *result;

	result = talloc_zero(mem_ctx, struct auth_serversupplied_info);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	/* Initialise the uid and gid values to something non-zero
	   which may save us from giving away root access if there
	   is a bug in allocating these fields. */

	result->utok.uid = -1;
	result->utok.gid = -1;

	return result;
}

/****************************************************************************
 inits a netr_SamInfo2 structure from an auth_serversupplied_info. sam2 must
 already be initialized and is used as the talloc parent for its members.
*****************************************************************************/

NTSTATUS serverinfo_to_SamInfo2(struct auth_serversupplied_info *server_info,
				struct netr_SamInfo2 *sam2)
{
	struct netr_SamInfo3 *info3;

	info3 = copy_netr_SamInfo3(sam2, server_info->info3);
	if (!info3) {
		return NT_STATUS_NO_MEMORY;
	}

	if (server_info->session_key.length) {
		memcpy(info3->base.key.key,
		       server_info->session_key.data,
		       MIN(sizeof(info3->base.key.key),
			   server_info->session_key.length));
	}
	if (server_info->lm_session_key.length) {
		memcpy(info3->base.LMSessKey.key,
		       server_info->lm_session_key.data,
		       MIN(sizeof(info3->base.LMSessKey.key),
			   server_info->lm_session_key.length));
	}

	sam2->base = info3->base;

	return NT_STATUS_OK;
}

/****************************************************************************
 inits a netr_SamInfo3 structure from an auth_serversupplied_info. sam3 must
 already be initialized and is used as the talloc parent for its members.
*****************************************************************************/

NTSTATUS serverinfo_to_SamInfo3(const struct auth_serversupplied_info *server_info,
				struct netr_SamInfo3 *sam3)
{
	struct netr_SamInfo3 *info3;

	info3 = copy_netr_SamInfo3(sam3, server_info->info3);
	if (!info3) {
		return NT_STATUS_NO_MEMORY;
	}

	if (server_info->session_key.length) {
		memcpy(info3->base.key.key,
		       server_info->session_key.data,
		       MIN(sizeof(info3->base.key.key),
			   server_info->session_key.length));
	}
	if (server_info->lm_session_key.length) {
		memcpy(info3->base.LMSessKey.key,
		       server_info->lm_session_key.data,
		       MIN(sizeof(info3->base.LMSessKey.key),
			   server_info->lm_session_key.length));
	}

	sam3->base = info3->base;

	sam3->sidcount		= 0;
	sam3->sids		= NULL;

	return NT_STATUS_OK;
}

/****************************************************************************
 inits a netr_SamInfo6 structure from an auth_serversupplied_info. sam6 must
 already be initialized and is used as the talloc parent for its members.
*****************************************************************************/

NTSTATUS serverinfo_to_SamInfo6(struct auth_serversupplied_info *server_info,
				struct netr_SamInfo6 *sam6)
{
	struct pdb_domain_info *dominfo;
	struct netr_SamInfo3 *info3;

	if ((pdb_capabilities() & PDB_CAP_ADS) == 0) {
		DEBUG(10,("Not adding validation info level 6 "
			   "without ADS passdb backend\n"));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	dominfo = pdb_get_domain_info(sam6);
	if (dominfo == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	info3 = copy_netr_SamInfo3(sam6, server_info->info3);
	if (!info3) {
		return NT_STATUS_NO_MEMORY;
	}

	if (server_info->session_key.length) {
		memcpy(info3->base.key.key,
		       server_info->session_key.data,
		       MIN(sizeof(info3->base.key.key),
			   server_info->session_key.length));
	}
	if (server_info->lm_session_key.length) {
		memcpy(info3->base.LMSessKey.key,
		       server_info->lm_session_key.data,
		       MIN(sizeof(info3->base.LMSessKey.key),
			   server_info->lm_session_key.length));
	}

	sam6->base = info3->base;

	sam6->sidcount		= 0;
	sam6->sids		= NULL;

	sam6->dns_domainname.string = talloc_strdup(sam6, dominfo->dns_domain);
	if (sam6->dns_domainname.string == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	sam6->principle.string	= talloc_asprintf(sam6, "%s@%s",
						  sam6->base.account_name.string,
						  sam6->dns_domainname.string);
	if (sam6->principle.string == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

static NTSTATUS append_netr_SidAttr(TALLOC_CTX *mem_ctx,
				    struct netr_SidAttr **sids,
				    uint32_t *count,
				    const struct dom_sid2 *asid,
				    uint32_t attributes)
{
	uint32_t t = *count;

	*sids = talloc_realloc(mem_ctx, *sids, struct netr_SidAttr, t + 1);
	if (*sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	(*sids)[t].sid = dom_sid_dup(*sids, asid);
	if ((*sids)[t].sid == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	(*sids)[t].attributes = attributes;
	*count = t + 1;

	return NT_STATUS_OK;
}

/* Fills the samr_RidWithAttributeArray with the provided sids.
 * If it happens that we have additional groups that do not belong
 * to the domain, add their sids as extra sids */
static NTSTATUS group_sids_to_info3(struct netr_SamInfo3 *info3,
				    const struct dom_sid *sids,
				    size_t num_sids)
{
	uint32_t attributes = SE_GROUP_MANDATORY |
				SE_GROUP_ENABLED_BY_DEFAULT |
				SE_GROUP_ENABLED;
	struct samr_RidWithAttributeArray *groups;
	struct dom_sid *domain_sid;
	unsigned int i;
	NTSTATUS status;
	uint32_t rid;
	bool ok;

	domain_sid = info3->base.domain_sid;
	groups = &info3->base.groups;

	groups->rids = talloc_array(info3,
				    struct samr_RidWithAttribute, num_sids);
	if (!groups->rids) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < num_sids; i++) {
		ok = sid_peek_check_rid(domain_sid, &sids[i], &rid);
		if (ok) {
			/* store domain group rid */
			groups->rids[groups->count].rid = rid;
			groups->rids[groups->count].attributes = attributes;
			groups->count++;
			continue;
		}

		/* if this wasn't a domain sid, add it as extra sid */
		status = append_netr_SidAttr(info3, &info3->sids,
					     &info3->sidcount,
					     &sids[i], attributes);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}

/*
 * Merge resource SIDs, if any, into the passed in info3 structure.
 */

static NTSTATUS merge_resource_sids(const struct PAC_LOGON_INFO *logon_info,
				struct netr_SamInfo3 *info3)
{
	uint32_t i = 0;

	if (!(logon_info->info3.base.user_flags & NETLOGON_RESOURCE_GROUPS)) {
		return NT_STATUS_OK;
	}

	/*
	 * If there are any resource groups (SID Compression) add
	 * them to the extra sids portion of the info3 in the PAC.
	 *
	 * This makes the info3 look like it would if we got the info
	 * from the DC rather than the PAC.
	 */

	/*
	 * Construct a SID for each RID in the list and then append it
	 * to the info3.
	 */
	for (i = 0; i < logon_info->res_groups.count; i++) {
		NTSTATUS status;
		struct dom_sid new_sid;
		uint32_t attributes = logon_info->res_groups.rids[i].attributes;

		sid_compose(&new_sid,
			logon_info->res_group_dom_sid,
			logon_info->res_groups.rids[i].rid);

		DEBUG(10, ("Adding SID %s to extra SIDS\n",
			sid_string_dbg(&new_sid)));

		status = append_netr_SidAttr(info3, &info3->sids,
					&info3->sidcount,
					&new_sid,
					attributes);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("failed to append SID %s to extra SIDS: %s\n",
				sid_string_dbg(&new_sid),
				nt_errstr(status)));
			return status;
		}
	}

	return NT_STATUS_OK;
}

/*
 * Create a copy of an info3 struct from the struct PAC_LOGON_INFO,
 * then merge resource SIDs, if any, into it. If successful return
 * the created info3 struct.
 */

NTSTATUS create_info3_from_pac_logon_info(TALLOC_CTX *mem_ctx,
					const struct PAC_LOGON_INFO *logon_info,
					struct netr_SamInfo3 **pp_info3)
{
	NTSTATUS status;
	struct netr_SamInfo3 *info3 = copy_netr_SamInfo3(mem_ctx,
					&logon_info->info3);
	if (info3 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	status = merge_resource_sids(logon_info, info3);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(info3);
		return status;
	}
	*pp_info3 = info3;
	return NT_STATUS_OK;
}

/*
 * Check if this is a "Unix Users" domain user, or a
 * "Unix Groups" domain group, we need to handle it
 * in a special way if that's the case.
 */

static NTSTATUS SamInfo3_handle_sids(const char *username,
			const struct dom_sid *user_sid,
			const struct dom_sid *group_sid,
			struct netr_SamInfo3 *info3,
			struct dom_sid *domain_sid,
			struct extra_auth_info *extra)
{
	if (sid_check_is_in_unix_users(user_sid)) {
		/* in info3 you can only set rids for the user and the
		 * primary group, and the domain sid must be that of
		 * the sam domain.
		 *
		 * Store a completely bogus value here.
		 * The real SID is stored in the extra sids.
		 * Other code will know to look there if (-1) is found
		 */
		info3->base.rid = (uint32_t)(-1);
		sid_copy(&extra->user_sid, user_sid);

		DEBUG(10, ("Unix User found. Rid marked as "
			"special and sid (%s) saved as extra sid\n",
			sid_string_dbg(user_sid)));
	} else {
		sid_copy(domain_sid, user_sid);
		sid_split_rid(domain_sid, &info3->base.rid);
	}

	if (is_null_sid(domain_sid)) {
		sid_copy(domain_sid, get_global_sam_sid());
	}

	/* check if this is a "Unix Groups" domain group,
	 * if so we need special handling */
	if (sid_check_is_in_unix_groups(group_sid)) {
		/* in info3 you can only set rids for the user and the
		 * primary group, and the domain sid must be that of
		 * the sam domain.
		 *
		 * Store a completely bogus value here.
		 * The real SID is stored in the extra sids.
		 * Other code will know to look there if (-1) is found
		 */
		info3->base.primary_gid = (uint32_t)(-1);
		sid_copy(&extra->pgid_sid, group_sid);

		DEBUG(10, ("Unix Group found. Rid marked as "
			"special and sid (%s) saved as extra sid\n",
			sid_string_dbg(group_sid)));
	} else {
		bool ok = sid_peek_check_rid(domain_sid, group_sid,
					&info3->base.primary_gid);
		if (!ok) {
			DEBUG(1, ("The primary group domain sid(%s) does not "
				"match the domain sid(%s) for %s(%s)\n",
				sid_string_dbg(group_sid),
				sid_string_dbg(domain_sid),
				username,
				sid_string_dbg(user_sid)));
			return NT_STATUS_INVALID_SID;
		}
	}
	return NT_STATUS_OK;
}

#define RET_NOMEM(ptr) do { \
	if (!ptr) { \
		TALLOC_FREE(info3); \
		return NT_STATUS_NO_MEMORY; \
	} } while(0)

NTSTATUS samu_to_SamInfo3(TALLOC_CTX *mem_ctx,
			  struct samu *samu,
			  const char *login_server,
			  struct netr_SamInfo3 **_info3,
			  struct extra_auth_info *extra)
{
	struct netr_SamInfo3 *info3;
	const struct dom_sid *user_sid;
	const struct dom_sid *group_sid;
	struct dom_sid domain_sid;
	struct dom_sid *group_sids;
	uint32_t num_group_sids = 0;
	const char *tmp;
	gid_t *gids;
	NTSTATUS status;

	user_sid = pdb_get_user_sid(samu);
	group_sid = pdb_get_group_sid(samu);

	if (!user_sid || !group_sid) {
		DEBUG(1, ("Sam account is missing sids!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	info3 = talloc_zero(mem_ctx, struct netr_SamInfo3);
	if (!info3) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCT(domain_sid);

	status = SamInfo3_handle_sids(pdb_get_username(samu),
				user_sid,
				group_sid,
				info3,
				&domain_sid,
				extra);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(info3);
		return status;
	}

	unix_to_nt_time(&info3->base.logon_time, pdb_get_logon_time(samu));
	unix_to_nt_time(&info3->base.logoff_time, get_time_t_max());
	unix_to_nt_time(&info3->base.kickoff_time, get_time_t_max());
	unix_to_nt_time(&info3->base.last_password_change,
			pdb_get_pass_last_set_time(samu));
	unix_to_nt_time(&info3->base.allow_password_change,
			pdb_get_pass_can_change_time(samu));
	unix_to_nt_time(&info3->base.force_password_change,
			pdb_get_pass_must_change_time(samu));

	tmp = pdb_get_username(samu);
	if (tmp) {
		info3->base.account_name.string	= talloc_strdup(info3, tmp);
		RET_NOMEM(info3->base.account_name.string);
	}
	tmp = pdb_get_fullname(samu);
	if (tmp) {
		info3->base.full_name.string = talloc_strdup(info3, tmp);
		RET_NOMEM(info3->base.full_name.string);
	}
	tmp = pdb_get_logon_script(samu);
	if (tmp) {
		info3->base.logon_script.string = talloc_strdup(info3, tmp);
		RET_NOMEM(info3->base.logon_script.string);
	}
	tmp = pdb_get_profile_path(samu);
	if (tmp) {
		info3->base.profile_path.string	= talloc_strdup(info3, tmp);
		RET_NOMEM(info3->base.profile_path.string);
	}
	tmp = pdb_get_homedir(samu);
	if (tmp) {
		info3->base.home_directory.string = talloc_strdup(info3, tmp);
		RET_NOMEM(info3->base.home_directory.string);
	}
	tmp = pdb_get_dir_drive(samu);
	if (tmp) {
		info3->base.home_drive.string = talloc_strdup(info3, tmp);
		RET_NOMEM(info3->base.home_drive.string);
	}

	info3->base.logon_count	= pdb_get_logon_count(samu);
	info3->base.bad_password_count = pdb_get_bad_password_count(samu);

	info3->base.logon_domain.string = talloc_strdup(info3,
						  pdb_get_domain(samu));
	RET_NOMEM(info3->base.logon_domain.string);

	info3->base.domain_sid = dom_sid_dup(info3, &domain_sid);
	RET_NOMEM(info3->base.domain_sid);

	status = pdb_enum_group_memberships(mem_ctx, samu,
					    &group_sids, &gids,
					    &num_group_sids);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to get groups from sam account.\n"));
		TALLOC_FREE(info3);
		return status;
	}

	if (num_group_sids) {
		status = group_sids_to_info3(info3, group_sids, num_group_sids);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(info3);
			return status;
		}
	}

	/* We don't need sids and gids after the conversion */
	TALLOC_FREE(group_sids);
	TALLOC_FREE(gids);
	num_group_sids = 0;

	/* FIXME: should we add other flags ? */
	info3->base.user_flags = NETLOGON_EXTRA_SIDS;

	if (login_server) {
		info3->base.logon_server.string = talloc_strdup(info3, login_server);
		RET_NOMEM(info3->base.logon_server.string);
	}

	info3->base.acct_flags = pdb_get_acct_ctrl(samu);

	*_info3 = info3;
	return NT_STATUS_OK;
}

NTSTATUS passwd_to_SamInfo3(TALLOC_CTX *mem_ctx,
			    const char *unix_username,
			    const struct passwd *pwd,
			    struct netr_SamInfo3 **pinfo3,
			    struct extra_auth_info *extra)
{
	struct netr_SamInfo3 *info3;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;
	const char *domain_name = NULL;
	const char *user_name = NULL;
	struct dom_sid domain_sid;
	struct dom_sid user_sid;
	struct dom_sid group_sid;
	enum lsa_SidType type;
	uint32_t num_sids = 0;
	struct dom_sid *user_sids = NULL;
	bool is_null;
	bool ok;

	tmp_ctx = talloc_stackframe();

	ok = lookup_name_smbconf(tmp_ctx,
				 unix_username,
				 LOOKUP_NAME_ALL,
				 &domain_name,
				 &user_name,
				 &user_sid,
				 &type);
	if (!ok) {
		status = NT_STATUS_NO_SUCH_USER;
		goto done;
	}

	if (type != SID_NAME_USER) {
		status = NT_STATUS_NO_SUCH_USER;
		goto done;
	}

	ok = winbind_lookup_usersids(tmp_ctx,
				     &user_sid,
				     &num_sids,
				     &user_sids);
	/* Check if winbind is running */
	if (ok) {
		/*
		 * Winbind is running and the first element of the user_sids
		 * is the primary group.
		 */
		if (num_sids > 0) {
			group_sid = user_sids[0];
		}
	} else {
		/*
		 * Winbind is not running, try to create the group_sid from the
		 * passwd group id.
		 */

		/*
		 * This can lead to a primary group of S-1-22-2-XX which
		 * will be rejected by other Samba code.
		 */
		gid_to_sid(&group_sid, pwd->pw_gid);

		ZERO_STRUCT(domain_sid);

		/*
		 * If we are a unix group, set the group_sid to the
		 * 'Domain Users' RID of 513 which will always resolve to a
		 * name.
		 */
		if (sid_check_is_in_unix_groups(&group_sid)) {
			sid_compose(&group_sid,
				    get_global_sam_sid(),
				    DOMAIN_RID_USERS);
		}
	}

	/* Make sure we have a valid group sid */
	is_null = is_null_sid(&group_sid);
	if (is_null) {
		status = NT_STATUS_NO_SUCH_USER;
		goto done;
	}

	/* Construct a netr_SamInfo3 from the information we have */
	info3 = talloc_zero(tmp_ctx, struct netr_SamInfo3);
	if (!info3) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	info3->base.account_name.string = talloc_strdup(info3, unix_username);
	if (info3->base.account_name.string == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	ZERO_STRUCT(domain_sid);

	status = SamInfo3_handle_sids(unix_username,
				&user_sid,
				&group_sid,
				info3,
				&domain_sid,
				extra);

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	info3->base.domain_sid = dom_sid_dup(info3, &domain_sid);
	if (info3->base.domain_sid == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	ok = sid_peek_check_rid(&domain_sid, &group_sid,
				&info3->base.primary_gid);
	if (!ok) {
		DEBUG(1, ("The primary group domain sid(%s) does not "
			  "match the domain sid(%s) for %s(%s)\n",
			  sid_string_dbg(&group_sid),
			  sid_string_dbg(&domain_sid),
			  unix_username,
			  sid_string_dbg(&user_sid)));
		status = NT_STATUS_INVALID_SID;
		goto done;
	}

	info3->base.acct_flags = ACB_NORMAL;

	if (num_sids) {
		status = group_sids_to_info3(info3, user_sids, num_sids);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
	}

	*pinfo3 = talloc_steal(mem_ctx, info3);

	status = NT_STATUS_OK;
done:
	talloc_free(tmp_ctx);

	return status;
}

#undef RET_NOMEM

#define RET_NOMEM(ptr) do { \
	if (!ptr) { \
		TALLOC_FREE(info3); \
		return NULL; \
	} } while(0)

struct netr_SamInfo3 *copy_netr_SamInfo3(TALLOC_CTX *mem_ctx,
					 const struct netr_SamInfo3 *orig)
{
	struct netr_SamInfo3 *info3;
	unsigned int i;
	NTSTATUS status;

	info3 = talloc_zero(mem_ctx, struct netr_SamInfo3);
	if (!info3) return NULL;

	status = copy_netr_SamBaseInfo(info3, &orig->base, &info3->base);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(info3);
		return NULL;
	}

	if (orig->sidcount) {
		info3->sidcount = orig->sidcount;
		info3->sids = talloc_array(info3, struct netr_SidAttr,
					   orig->sidcount);
		RET_NOMEM(info3->sids);
		for (i = 0; i < orig->sidcount; i++) {
			info3->sids[i].sid = dom_sid_dup(info3->sids,
							    orig->sids[i].sid);
			RET_NOMEM(info3->sids[i].sid);
			info3->sids[i].attributes =
				orig->sids[i].attributes;
		}
	}

	return info3;
}

