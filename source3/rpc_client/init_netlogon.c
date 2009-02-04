/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Guenther Deschner                  2008.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

/*******************************************************************
 inits a structure.
********************************************************************/

void init_netr_SamBaseInfo(struct netr_SamBaseInfo *r,
			   NTTIME last_logon,
			   NTTIME last_logoff,
			   NTTIME acct_expiry,
			   NTTIME last_password_change,
			   NTTIME allow_password_change,
			   NTTIME force_password_change,
			   const char *account_name,
			   const char *full_name,
			   const char *logon_script,
			   const char *profile_path,
			   const char *home_directory,
			   const char *home_drive,
			   uint16_t logon_count,
			   uint16_t bad_password_count,
			   uint32_t rid,
			   uint32_t primary_gid,
			   struct samr_RidWithAttributeArray groups,
			   uint32_t user_flags,
			   struct netr_UserSessionKey key,
			   const char *logon_server,
			   const char *domain,
			   struct dom_sid2 *domain_sid,
			   struct netr_LMSessionKey LMSessKey,
			   uint32_t acct_flags)
{
	r->last_logon = last_logon;
	r->last_logoff = last_logoff;
	r->acct_expiry = acct_expiry;
	r->last_password_change = last_password_change;
	r->allow_password_change = allow_password_change;
	r->force_password_change = force_password_change;
	init_lsa_String(&r->account_name, account_name);
	init_lsa_String(&r->full_name, full_name);
	init_lsa_String(&r->logon_script, logon_script);
	init_lsa_String(&r->profile_path, profile_path);
	init_lsa_String(&r->home_directory, home_directory);
	init_lsa_String(&r->home_drive, home_drive);
	r->logon_count = logon_count;
	r->bad_password_count = bad_password_count;
	r->rid = rid;
	r->primary_gid = primary_gid;
	r->groups = groups;
	r->user_flags = user_flags;
	r->key = key;
	init_lsa_StringLarge(&r->logon_server, logon_server);
	init_lsa_StringLarge(&r->domain, domain);
	r->domain_sid = domain_sid;
	r->LMSessKey = LMSessKey;
	r->acct_flags = acct_flags;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_netr_SamInfo3(struct netr_SamInfo3 *r,
			NTTIME last_logon,
			NTTIME last_logoff,
			NTTIME acct_expiry,
			NTTIME last_password_change,
			NTTIME allow_password_change,
			NTTIME force_password_change,
			const char *account_name,
			const char *full_name,
			const char *logon_script,
			const char *profile_path,
			const char *home_directory,
			const char *home_drive,
			uint16_t logon_count,
			uint16_t bad_password_count,
			uint32_t rid,
			uint32_t primary_gid,
			struct samr_RidWithAttributeArray groups,
			uint32_t user_flags,
			struct netr_UserSessionKey key,
			const char *logon_server,
			const char *domain,
			struct dom_sid2 *domain_sid,
			struct netr_LMSessionKey LMSessKey,
			uint32_t acct_flags,
			uint32_t sidcount,
			struct netr_SidAttr *sids)
{
	init_netr_SamBaseInfo(&r->base,
			      last_logon,
			      last_logoff,
			      acct_expiry,
			      last_password_change,
			      allow_password_change,
			      force_password_change,
			      account_name,
			      full_name,
			      logon_script,
			      profile_path,
			      home_directory,
			      home_drive,
			      logon_count,
			      bad_password_count,
			      rid,
			      primary_gid,
			      groups,
			      user_flags,
			      key,
			      logon_server,
			      domain,
			      domain_sid,
			      LMSessKey,
			      acct_flags);
	r->sidcount = sidcount;
	r->sids = sids;
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
 inits a netr_SamInfo3 structure from an auth_serversupplied_info. sam3 must
 already be initialized and is used as the talloc parent for its members.
*****************************************************************************/

NTSTATUS serverinfo_to_SamInfo3(struct auth_serversupplied_info *server_info,
				uint8_t *pipe_session_key,
				size_t pipe_session_key_len,
				struct netr_SamInfo3 *sam3)
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

	sid = sid_dup_talloc(sam3, &domain_sid);
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

	status = nt_token_to_group_list(sam3, &domain_sid,
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
			SamOEMhash(user_session_key.key, pipe_session_key, 16);
		}
	}
	if (server_info->lm_session_key.length) {
		memcpy(lm_session_key.key,
		       server_info->lm_session_key.data,
		       MIN(sizeof(lm_session_key.key),
			   server_info->lm_session_key.length));
		if (pipe_session_key) {
			SamOEMhash(lm_session_key.key, pipe_session_key, 8);
		}
	}

	groups.count = num_gids;
	groups.rids = TALLOC_ARRAY(sam3, struct samr_RidWithAttribute, groups.count);
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

	init_netr_SamInfo3(sam3,
			   last_logon,
			   last_logoff,
			   acct_expiry,
			   last_password_change,
			   allow_password_change,
			   force_password_change,
			   talloc_strdup(sam3, pdb_get_username(sampw)),
			   talloc_strdup(sam3, pdb_get_fullname(sampw)),
			   talloc_strdup(sam3, pdb_get_logon_script(sampw)),
			   talloc_strdup(sam3, pdb_get_profile_path(sampw)),
			   talloc_strdup(sam3, pdb_get_homedir(sampw)),
			   talloc_strdup(sam3, pdb_get_dir_drive(sampw)),
			   0, /* logon_count */
			   0, /* bad_password_count */
			   user_rid,
			   group_rid,
			   groups,
			   NETLOGON_EXTRA_SIDS,
			   user_session_key,
			   my_name,
			   talloc_strdup(sam3, pdb_get_domain(sampw)),
			   sid,
			   lm_session_key,
			   pdb_get_acct_ctrl(sampw),
			   0, /* sidcount */
			   NULL); /* struct netr_SidAttr *sids */
	ZERO_STRUCT(user_session_key);
	ZERO_STRUCT(lm_session_key);

	return NT_STATUS_OK;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_netr_IdentityInfo(struct netr_IdentityInfo *r,
			    const char *domain_name,
			    uint32_t parameter_control,
			    uint32_t logon_id_low,
			    uint32_t logon_id_high,
			    const char *account_name,
			    const char *workstation)
{
	init_lsa_String(&r->domain_name, domain_name);
	r->parameter_control = parameter_control;
	r->logon_id_low = logon_id_low;
	r->logon_id_high = logon_id_high;
	init_lsa_String(&r->account_name, account_name);
	init_lsa_String(&r->workstation, workstation);
}

/*******************************************************************
 inits a structure.
 This is a network logon packet. The log_id parameters
 are what an NT server would generate for LUID once the
 user is logged on. I don't think we care about them.

 Note that this has no access to the NT and LM hashed passwords,
 so it forwards the challenge, and the NT and LM responses (24
 bytes each) over the secure channel to the Domain controller
 for it to say yea or nay. This is the preferred method of
 checking for a logon as it doesn't export the password
 hashes to anyone who has compromised the secure channel. JRA.

********************************************************************/

void init_netr_NetworkInfo(struct netr_NetworkInfo *r,
			   const char *domain_name,
			   uint32_t parameter_control,
			   uint32_t logon_id_low,
			   uint32_t logon_id_high,
			   const char *account_name,
			   const char *workstation,
			   uint8_t challenge[8],
			   struct netr_ChallengeResponse nt,
			   struct netr_ChallengeResponse lm)
{
	init_netr_IdentityInfo(&r->identity_info,
			       domain_name,
			       parameter_control,
			       logon_id_low,
			       logon_id_high,
			       account_name,
			       workstation);
	memcpy(r->challenge, challenge, 8);
	r->nt = nt;
	r->lm = lm;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_netr_PasswordInfo(struct netr_PasswordInfo *r,
			    const char *domain_name,
			    uint32_t parameter_control,
			    uint32_t logon_id_low,
			    uint32_t logon_id_high,
			    const char *account_name,
			    const char *workstation,
			    struct samr_Password lmpassword,
			    struct samr_Password ntpassword)
{
	init_netr_IdentityInfo(&r->identity_info,
			       domain_name,
			       parameter_control,
			       logon_id_low,
			       logon_id_high,
			       account_name,
			       workstation);
	r->lmpassword = lmpassword;
	r->ntpassword = ntpassword;
}

/*************************************************************************
 inits a netr_CryptPassword structure
 *************************************************************************/

void init_netr_CryptPassword(const char *pwd,
			     unsigned char session_key[16],
			     struct netr_CryptPassword *pwd_buf)
{
	struct samr_CryptPassword password_buf;

	encode_pw_buffer(password_buf.data, pwd, STR_UNICODE);

	SamOEMhash(password_buf.data, session_key, 516);
	memcpy(pwd_buf->data, password_buf.data, 512);
	pwd_buf->length = IVAL(password_buf.data, 512);
}
