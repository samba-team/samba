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
