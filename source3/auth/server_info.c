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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

static int server_info_dtor(struct auth_serversupplied_info *server_info)
{
	TALLOC_FREE(server_info->sam_account);
	ZERO_STRUCTP(server_info);
	return 0;
}

/***************************************************************************
 Make a server_info struct. Free with TALLOC_FREE().
***************************************************************************/

struct auth_serversupplied_info *make_server_info(TALLOC_CTX *mem_ctx)
{
	struct auth_serversupplied_info *result;

	result = TALLOC_ZERO_P(mem_ctx, struct auth_serversupplied_info);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	talloc_set_destructor(result, server_info_dtor);

	/* Initialise the uid and gid values to something non-zero
	   which may save us from giving away root access if there
	   is a bug in allocating these fields. */

	result->utok.uid = -1;
	result->utok.gid = -1;
	return result;
}

/*******************************************************************
 gets a domain user's groups from their already-calculated NT_USER_TOKEN
 ********************************************************************/

static NTSTATUS nt_token_to_group_list(TALLOC_CTX *mem_ctx,
				       const DOM_SID *domain_sid,
				       size_t num_sids,
				       const DOM_SID *sids,
				       int *numgroups,
				       struct samr_RidWithAttribute **pgids)
{
	int i;

	*numgroups=0;
	*pgids = NULL;

	for (i=0; i<num_sids; i++) {
		struct samr_RidWithAttribute gid;
		if (!sid_peek_check_rid(domain_sid, &sids[i], &gid.rid)) {
			continue;
		}
		gid.attributes = (SE_GROUP_MANDATORY|SE_GROUP_ENABLED_BY_DEFAULT|
			    SE_GROUP_ENABLED);
		ADD_TO_ARRAY(mem_ctx, struct samr_RidWithAttribute,
			     gid, pgids, numgroups);
		if (*pgids == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 inits a netr_SamBaseInfo structure from an auth_serversupplied_info.
*****************************************************************************/

static NTSTATUS serverinfo_to_SamInfo_base(TALLOC_CTX *mem_ctx,
					   struct auth_serversupplied_info *server_info,
					   uint8_t *pipe_session_key,
					   size_t pipe_session_key_len,
					   struct netr_SamBaseInfo *base)
{
	struct samu *sampw;
	struct samr_RidWithAttribute *gids = NULL;
	const DOM_SID *user_sid = NULL;
	const DOM_SID *group_sid = NULL;
	DOM_SID domain_sid;
	uint32 user_rid, group_rid;
	NTSTATUS status;

	int num_gids = 0;
	const char *my_name;

	struct netr_UserSessionKey user_session_key;
	struct netr_LMSessionKey lm_session_key;

	NTTIME last_logon, last_logoff, acct_expiry, last_password_change;
	NTTIME allow_password_change, force_password_change;
	struct samr_RidWithAttributeArray groups;
	int i;
	struct dom_sid2 *sid = NULL;

	ZERO_STRUCT(user_session_key);
	ZERO_STRUCT(lm_session_key);

	sampw = server_info->sam_account;

	user_sid = pdb_get_user_sid(sampw);
	group_sid = pdb_get_group_sid(sampw);

	if (pipe_session_key && pipe_session_key_len != 16) {
		DEBUG(0,("serverinfo_to_SamInfo3: invalid "
			 "pipe_session_key_len[%zu] != 16\n",
			 pipe_session_key_len));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if ((user_sid == NULL) || (group_sid == NULL)) {
		DEBUG(1, ("_netr_LogonSamLogon: User without group or user SID\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	sid_copy(&domain_sid, user_sid);
	sid_split_rid(&domain_sid, &user_rid);

	sid = sid_dup_talloc(mem_ctx, &domain_sid);
	if (!sid) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!sid_peek_check_rid(&domain_sid, group_sid, &group_rid)) {
		DEBUG(1, ("_netr_LogonSamLogon: user %s\\%s has user sid "
			  "%s\n but group sid %s.\n"
			  "The conflicting domain portions are not "
			  "supported for NETLOGON calls\n",
			  pdb_get_domain(sampw),
			  pdb_get_username(sampw),
			  sid_string_dbg(user_sid),
			  sid_string_dbg(group_sid)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if(server_info->login_server) {
		my_name = server_info->login_server;
	} else {
		my_name = global_myname();
	}

	status = nt_token_to_group_list(mem_ctx, &domain_sid,
					server_info->num_sids,
					server_info->sids,
					&num_gids, &gids);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (server_info->user_session_key.length) {
		memcpy(user_session_key.key,
		       server_info->user_session_key.data,
		       MIN(sizeof(user_session_key.key),
			   server_info->user_session_key.length));
		if (pipe_session_key) {
			arcfour_crypt(user_session_key.key, pipe_session_key, 16);
		}
	}
	if (server_info->lm_session_key.length) {
		memcpy(lm_session_key.key,
		       server_info->lm_session_key.data,
		       MIN(sizeof(lm_session_key.key),
			   server_info->lm_session_key.length));
		if (pipe_session_key) {
			arcfour_crypt(lm_session_key.key, pipe_session_key, 8);
		}
	}

	groups.count = num_gids;
	groups.rids = TALLOC_ARRAY(mem_ctx, struct samr_RidWithAttribute, groups.count);
	if (!groups.rids) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i < groups.count; i++) {
		groups.rids[i].rid = gids[i].rid;
		groups.rids[i].attributes = gids[i].attributes;
	}

	unix_to_nt_time(&last_logon, pdb_get_logon_time(sampw));
	unix_to_nt_time(&last_logoff, get_time_t_max());
	unix_to_nt_time(&acct_expiry, get_time_t_max());
	unix_to_nt_time(&last_password_change, pdb_get_pass_last_set_time(sampw));
	unix_to_nt_time(&allow_password_change, pdb_get_pass_can_change_time(sampw));
	unix_to_nt_time(&force_password_change, pdb_get_pass_must_change_time(sampw));

	base->last_logon		= last_logon;
	base->last_logoff		= last_logoff;
	base->acct_expiry		= acct_expiry;
	base->last_password_change	= last_password_change;
	base->allow_password_change	= allow_password_change;
	base->force_password_change	= force_password_change;
	base->account_name.string	= talloc_strdup(mem_ctx, pdb_get_username(sampw));
	base->full_name.string		= talloc_strdup(mem_ctx, pdb_get_fullname(sampw));
	base->logon_script.string	= talloc_strdup(mem_ctx, pdb_get_logon_script(sampw));
	base->profile_path.string	= talloc_strdup(mem_ctx, pdb_get_profile_path(sampw));
	base->home_directory.string	= talloc_strdup(mem_ctx, pdb_get_homedir(sampw));
	base->home_drive.string		= talloc_strdup(mem_ctx, pdb_get_dir_drive(sampw));
	base->logon_count		= 0; /* ?? */
	base->bad_password_count	= 0; /* ?? */
	base->rid			= user_rid;
	base->primary_gid		= group_rid;
	base->groups			= groups;
	base->user_flags		= NETLOGON_EXTRA_SIDS;
	base->key			= user_session_key;
	base->logon_server.string	= talloc_strdup(mem_ctx, my_name);
	base->domain.string		= talloc_strdup(mem_ctx, pdb_get_domain(sampw));
	base->domain_sid		= sid;
	base->LMSessKey			= lm_session_key;
	base->acct_flags		= pdb_get_acct_ctrl(sampw);

	ZERO_STRUCT(user_session_key);
	ZERO_STRUCT(lm_session_key);

	return NT_STATUS_OK;
}

/****************************************************************************
 inits a netr_SamInfo2 structure from an auth_serversupplied_info. sam2 must
 already be initialized and is used as the talloc parent for its members.
*****************************************************************************/

NTSTATUS serverinfo_to_SamInfo2(struct auth_serversupplied_info *server_info,
				uint8_t *pipe_session_key,
				size_t pipe_session_key_len,
				struct netr_SamInfo2 *sam2)
{
	NTSTATUS status;

	status = serverinfo_to_SamInfo_base(sam2,
					    server_info,
					    pipe_session_key,
					    pipe_session_key_len,
					    &sam2->base);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 inits a netr_SamInfo3 structure from an auth_serversupplied_info. sam3 must
 already be initialized and is used as the talloc parent for its members.
*****************************************************************************/

NTSTATUS serverinfo_to_SamInfo3(struct auth_serversupplied_info *server_info,
				uint8_t *pipe_session_key,
				size_t pipe_session_key_len,
				struct netr_SamInfo3 *sam3)
{
	NTSTATUS status;

	status = serverinfo_to_SamInfo_base(sam3,
					    server_info,
					    pipe_session_key,
					    pipe_session_key_len,
					    &sam3->base);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	sam3->sidcount		= 0;
	sam3->sids		= NULL;

	return NT_STATUS_OK;
}

/****************************************************************************
 inits a netr_SamInfo6 structure from an auth_serversupplied_info. sam6 must
 already be initialized and is used as the talloc parent for its members.
*****************************************************************************/

NTSTATUS serverinfo_to_SamInfo6(struct auth_serversupplied_info *server_info,
				uint8_t *pipe_session_key,
				size_t pipe_session_key_len,
				struct netr_SamInfo6 *sam6)
{
	NTSTATUS status;
	struct pdb_domain_info *dominfo;

	if ((pdb_capabilities() & PDB_CAP_ADS) == 0) {
		DEBUG(10,("Not adding validation info level 6 "
			   "without ADS passdb backend\n"));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	dominfo = pdb_get_domain_info(sam6);
	if (dominfo == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = serverinfo_to_SamInfo_base(sam6,
					    server_info,
					    pipe_session_key,
					    pipe_session_key_len,
					    &sam6->base);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	sam6->sidcount		= 0;
	sam6->sids		= NULL;

	sam6->forest.string	= talloc_strdup(sam6, dominfo->dns_forest);
	if (sam6->forest.string == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	sam6->principle.string	= talloc_asprintf(sam6, "%s@%s",
						  pdb_get_username(server_info->sam_account),
						  dominfo->dns_domain);
	if (sam6->principle.string == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}
