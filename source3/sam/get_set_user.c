/* 
   Unix SMB/CIFS implementation.
   SAM_USER_HANDLE access routines
   Copyright (C) Andrew Bartlett			2002
   Copyright (C) Stefan (metze) Metzmacher	2002
   Copyright (C) Jelmer Vernooij 			2002
      
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SAM

NTSTATUS sam_get_user_domain_sid (const SAM_USER_HANDLE *sampass, DOM_SID **sid)
{
	NTSTATUS status;
	SAM_DOMAIN_HANDLE *domain;
	if (!sampass || !sid) return NT_STATUS_UNSUCCESSFUL;

	if (!NT_STATUS_IS_OK(status = sam_get_user_domain(sampass, &domain))){
		DEBUG(0, ("sam_get_user_domain_sid: Can't get domain for user\n"));
		return status;
	}

	return sam_get_domain_sid(domain, sid);
}

NTSTATUS sam_get_user_domain_name (const SAM_USER_HANDLE *sampass, char **domain_name)
{
	NTSTATUS status;
	SAM_DOMAIN_HANDLE *domain;
	if (!sampass || !domain_name) return NT_STATUS_UNSUCCESSFUL;

	if (!NT_STATUS_IS_OK(status = sam_get_user_domain(sampass, &domain))){
		DEBUG(0, ("sam_get_user_domain_name: Can't get domain for user\n"));
		return status;
	}

	return sam_get_domain_name(domain, domain_name);
}

NTSTATUS sam_get_user_acct_ctrl (const SAM_USER_HANDLE *sampass, uint16 *acct_ctrl)
{
	if(!sampass || !acct_ctrl)return NT_STATUS_UNSUCCESSFUL;

	*acct_ctrl = sampass->private.acct_ctrl;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_logon_time (const SAM_USER_HANDLE *sampass, NTTIME *logon_time)
{
	if(!sampass || !logon_time)return NT_STATUS_UNSUCCESSFUL;

	*logon_time = sampass->private.logon_time;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_logoff_time (const SAM_USER_HANDLE *sampass, NTTIME *logoff_time)
{
	if(!sampass || !logoff_time)return NT_STATUS_UNSUCCESSFUL;

	*logoff_time = sampass->private.logoff_time;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_kickoff_time (const SAM_USER_HANDLE *sampass, NTTIME *kickoff_time)
{
	if (!sampass || !kickoff_time)return NT_STATUS_UNSUCCESSFUL;

	*kickoff_time = sampass->private.kickoff_time;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_pass_last_set_time (const SAM_USER_HANDLE *sampass, NTTIME *pass_last_set_time)
{
	if (!sampass || !pass_last_set_time)return NT_STATUS_UNSUCCESSFUL;

	*pass_last_set_time = sampass->private.pass_last_set_time;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_pass_can_change_time (const SAM_USER_HANDLE *sampass, NTTIME *pass_can_change_time)
{
	if (!sampass || !pass_can_change_time)return NT_STATUS_UNSUCCESSFUL;

	*pass_can_change_time = sampass->private.pass_can_change_time;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_pass_must_change_time (const SAM_USER_HANDLE *sampass, NTTIME *pass_must_change_time)
{
	if (!sampass || !pass_must_change_time)return NT_STATUS_UNSUCCESSFUL;

	*pass_must_change_time = sampass->private.pass_must_change_time;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_logon_divs (const SAM_USER_HANDLE *sampass, uint16 *logon_divs)
{
	if (!sampass || !logon_divs)return NT_STATUS_UNSUCCESSFUL;

	*logon_divs = sampass->private.logon_divs;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_hours_len (const SAM_USER_HANDLE *sampass, uint32 *hours_len)
{
	if (!sampass || !hours_len)return NT_STATUS_UNSUCCESSFUL;

	*hours_len = sampass->private.hours_len;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_hours (const SAM_USER_HANDLE *sampass, uint8 **hours)
{
	if (!sampass || !hours)return NT_STATUS_UNSUCCESSFUL;

	*hours = sampass->private.hours;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_nt_pwd (const SAM_USER_HANDLE *sampass, DATA_BLOB *nt_pwd)
{
	if (!sampass)return NT_STATUS_UNSUCCESSFUL;

	SMB_ASSERT((!sampass->private.nt_pw.data) 
		   || sampass->private.nt_pw.length == NT_HASH_LEN);

	*nt_pwd = sampass->private.nt_pw;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_lm_pwd (const SAM_USER_HANDLE *sampass, DATA_BLOB *lm_pwd)
{ 
	if (!sampass)return NT_STATUS_UNSUCCESSFUL;

	SMB_ASSERT((!sampass->private.lm_pw.data) 
		   || sampass->private.lm_pw.length == LM_HASH_LEN);

	*lm_pwd = sampass->private.lm_pw;

	return NT_STATUS_OK;
}

/* Return the plaintext password if known.  Most of the time
   it isn't, so don't assume anything magic about this function.
   
   Used to pass the plaintext to sam backends that might 
   want to store more than just the NTLM hashes.
*/

NTSTATUS sam_get_user_plaintext_pwd (const SAM_USER_HANDLE *sampass, DATA_BLOB **plain_pwd)
{
	if (!sampass || !plain_pwd)return NT_STATUS_UNSUCCESSFUL;

	*plain_pwd = &(sampass->private.plaintext_pw);

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_sid(const SAM_USER_HANDLE *sampass, DOM_SID **sid)
{
	if (!sampass)return NT_STATUS_UNSUCCESSFUL;

	*sid = &(sampass->private.user_sid);

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_pgroup(const SAM_USER_HANDLE *sampass, DOM_SID **sid)
{
	if (!sampass)return NT_STATUS_UNSUCCESSFUL;

	*sid = &(sampass->private.group_sid);

	return NT_STATUS_OK;
}

/**
 * Get flags showing what is initalised in the SAM_USER_HANDLE
 * @param sampass the SAM_USER_HANDLE in question
 * @return the flags indicating the members initialised in the struct.
 **/
 
NTSTATUS sam_get_user_init_flag (const SAM_USER_HANDLE *sampass, uint32 *initflag)
{
	if (!sampass)return NT_STATUS_UNSUCCESSFUL;

	*initflag = sampass->private.init_flag;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_name (const SAM_USER_HANDLE *sampass, char **username)
{
	if (!sampass)return NT_STATUS_UNSUCCESSFUL;

	*username = sampass->private.username;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_domain (const SAM_USER_HANDLE *sampass, SAM_DOMAIN_HANDLE **domain)
{
	if (!sampass)return NT_STATUS_UNSUCCESSFUL;

	*domain = sampass->private.domain;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_fullname (const SAM_USER_HANDLE *sampass, char **fullname)
{
	if (!sampass)return NT_STATUS_UNSUCCESSFUL;

	*fullname = sampass->private.full_name;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_homedir (const SAM_USER_HANDLE *sampass, char **homedir)
{
	if (!sampass)return NT_STATUS_UNSUCCESSFUL;

	*homedir = sampass->private.home_dir;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_unix_home_dir (const SAM_USER_HANDLE *sampass, char **uhomedir)
{
	if (!sampass)return NT_STATUS_UNSUCCESSFUL;

	*uhomedir = sampass->private.unix_home_dir;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_dir_drive (const SAM_USER_HANDLE *sampass, char **dirdrive)
{
	if (!sampass)return NT_STATUS_UNSUCCESSFUL;

	*dirdrive = sampass->private.dir_drive;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_logon_script (const SAM_USER_HANDLE *sampass, char **logon_script)
{
	if (!sampass)return NT_STATUS_UNSUCCESSFUL;

	*logon_script = sampass->private.logon_script;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_profile_path (const SAM_USER_HANDLE *sampass, char **profile_path)
{
	if (!sampass)return NT_STATUS_UNSUCCESSFUL;

	*profile_path = sampass->private.profile_path;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_description (const SAM_USER_HANDLE *sampass, char **description)
{
	if (!sampass)return NT_STATUS_UNSUCCESSFUL;

	*description = sampass->private.acct_desc;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_workstations (const SAM_USER_HANDLE *sampass, char **workstations)
{
	if (!sampass)return NT_STATUS_UNSUCCESSFUL;

	*workstations = sampass->private.workstations;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_unknown_str (const SAM_USER_HANDLE *sampass, char **unknown_str)
{
	if (!sampass)return NT_STATUS_UNSUCCESSFUL;

	*unknown_str = sampass->private.unknown_str;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_munged_dial (const SAM_USER_HANDLE *sampass, char **munged_dial)
{
	if (!sampass)return NT_STATUS_UNSUCCESSFUL;

	*munged_dial = sampass->private.munged_dial;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_unknown_1 (const SAM_USER_HANDLE *sampass, uint32 *unknown1)
{
	if (!sampass || !unknown1)return NT_STATUS_UNSUCCESSFUL;

	*unknown1 = sampass->private.unknown_1;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_unknown_2 (const SAM_USER_HANDLE *sampass, uint32 *unknown2)
{
	if (!sampass || !unknown2)return NT_STATUS_UNSUCCESSFUL;

	*unknown2 = sampass->private.unknown_2;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_user_unknown_3 (const SAM_USER_HANDLE *sampass, uint32 *unknown3)
{
	if (!sampass || !unknown3)return NT_STATUS_UNSUCCESSFUL;

	*unknown3 = sampass->private.unknown_3;

	return NT_STATUS_OK;
}

/*********************************************************************
 Collection of set...() functions for SAM_USER_HANDLE_INFO.
 ********************************************************************/

NTSTATUS sam_set_user_acct_ctrl (SAM_USER_HANDLE *sampass, uint16 flags)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;
		
	sampass->private.acct_ctrl = flags;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_user_logon_time (SAM_USER_HANDLE *sampass, NTTIME mytime, BOOL store)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.logon_time = mytime;

	if (store)
		sam_set_user_init_flag(sampass, FLAG_SAM_LOGONTIME); 

	return NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS sam_set_user_logoff_time (SAM_USER_HANDLE *sampass, NTTIME mytime, BOOL store)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.logoff_time = mytime;

	if (store)
		sam_set_user_init_flag(sampass, FLAG_SAM_LOGOFFTIME); 

	return NT_STATUS_OK;
}

NTSTATUS sam_set_user_kickoff_time (SAM_USER_HANDLE *sampass, NTTIME mytime, BOOL store)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.kickoff_time = mytime;

	if (store)
		sam_set_user_init_flag(sampass, FLAG_SAM_KICKOFFTIME); 

	return NT_STATUS_OK;
}

NTSTATUS sam_set_user_pass_can_change_time (SAM_USER_HANDLE *sampass, NTTIME mytime, BOOL store)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.pass_can_change_time = mytime;

	if (store)
		sam_set_user_init_flag(sampass, FLAG_SAM_CANCHANGETIME); 

	return NT_STATUS_OK;
}

NTSTATUS sam_set_user_pass_must_change_time (SAM_USER_HANDLE *sampass, NTTIME mytime, BOOL store)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.pass_must_change_time = mytime;

	if (store)
		sam_set_user_init_flag(sampass, FLAG_SAM_MUSTCHANGETIME); 

	return NT_STATUS_OK;
}

NTSTATUS sam_set_user_pass_last_set_time (SAM_USER_HANDLE *sampass, NTTIME mytime)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.pass_last_set_time = mytime;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_user_hours_len (SAM_USER_HANDLE *sampass, uint32 len)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.hours_len = len;
	return NT_STATUS_OK;
}

NTSTATUS sam_set_user_logon_divs (SAM_USER_HANDLE *sampass, uint16 hours)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.logon_divs = hours;
	return NT_STATUS_OK;
}

/**
 * Set flags showing what is initalised in the SAM_USER_HANDLE
 * @param sampass the SAM_USER_HANDLE in question
 * @param flag The *new* flag to be set.  Old flags preserved
 *             this flag is only added.  
 **/
 
NTSTATUS sam_set_user_init_flag (SAM_USER_HANDLE *sampass, uint32 flag)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.init_flag |= flag;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_user_sid (SAM_USER_HANDLE *sampass, DOM_SID *u_sid)
{
	if (!sampass || !u_sid)
		return NT_STATUS_UNSUCCESSFUL;
	
	sid_copy(&sampass->private.user_sid, u_sid);

	DEBUG(10, ("sam_set_user_sid: setting user sid %s\n", 
		    sid_string_static(&sampass->private.user_sid)));
	
	return NT_STATUS_OK;
}

NTSTATUS sam_set_user_sid_from_string (SAM_USER_HANDLE *sampass, fstring u_sid)
{
	DOM_SID new_sid;
	if (!sampass || !u_sid)
		return NT_STATUS_UNSUCCESSFUL;

	DEBUG(10, ("sam_set_user_sid_from_string: setting user sid %s\n",
		   u_sid));

	if (!string_to_sid(&new_sid, u_sid)) { 
		DEBUG(1, ("sam_set_user_sid_from_string: %s isn't a valid SID!\n", u_sid));
		return NT_STATUS_UNSUCCESSFUL;
	}
	 
	if (!NT_STATUS_IS_OK(sam_set_user_sid(sampass, &new_sid))) {
		DEBUG(1, ("sam_set_user_sid_from_string: could not set sid %s on SAM_USER_HANDLE!\n", u_sid));
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_set_user_pgroup_sid (SAM_USER_HANDLE *sampass, DOM_SID *g_sid)
{
	if (!sampass || !g_sid)
		return NT_STATUS_UNSUCCESSFUL;

	sid_copy(&sampass->private.group_sid, g_sid);

	DEBUG(10, ("sam_set_group_sid: setting group sid %s\n", 
		    sid_string_static(&sampass->private.group_sid)));

	return NT_STATUS_OK;
}

NTSTATUS sam_set_user_pgroup_string (SAM_USER_HANDLE *sampass, fstring g_sid)
{
	DOM_SID new_sid;
	if (!sampass || !g_sid)
		return NT_STATUS_UNSUCCESSFUL;

	DEBUG(10, ("sam_set_group_sid_from_string: setting group sid %s\n",
		   g_sid));

	if (!string_to_sid(&new_sid, g_sid)) { 
		DEBUG(1, ("sam_set_group_sid_from_string: %s isn't a valid SID!\n", g_sid));
		return NT_STATUS_UNSUCCESSFUL;
	}
	 
	if (!NT_STATUS_IS_OK(sam_set_user_pgroup_sid(sampass, &new_sid))) {
		DEBUG(1, ("sam_set_group_sid_from_string: could not set sid %s on SAM_USER_HANDLE!\n", g_sid));
		return NT_STATUS_UNSUCCESSFUL;
	}
	return NT_STATUS_OK;
}

/*********************************************************************
 Set the domain name.
 ********************************************************************/

NTSTATUS sam_set_user_domain(SAM_USER_HANDLE *sampass, SAM_DOMAIN_HANDLE *domain)
{	
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.domain = domain;

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the user's NT name.
 ********************************************************************/

NTSTATUS sam_set_user_username(SAM_USER_HANDLE *sampass, const char *nt_username)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	DEBUG(10, ("sam_set_user_username: setting nt username %s, was %s\n", nt_username, sampass->private.username));

	sampass->private.username = talloc_strdup(sampass->mem_ctx, nt_username);

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the user's full name.
 ********************************************************************/

NTSTATUS sam_set_user_fullname(SAM_USER_HANDLE *sampass, const char *full_name)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	DEBUG(10, ("sam_set_user_fullname: setting full name %s, was %s\n", full_name, sampass->private.full_name));

	sampass->private.full_name = talloc_strdup(sampass->mem_ctx, full_name);

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the user's logon script.
 ********************************************************************/

NTSTATUS sam_set_user_logon_script(SAM_USER_HANDLE *sampass, const char *logon_script, BOOL store)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	DEBUG(10, ("sam_set_logon_script: from %s to %s\n", logon_script, sampass->private.logon_script));

	sampass->private.logon_script = talloc_strdup(sampass->mem_ctx, logon_script);
	
	sam_set_user_init_flag(sampass, FLAG_SAM_LOGONSCRIPT);

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the user's profile path.
 ********************************************************************/

NTSTATUS sam_set_user_profile_path (SAM_USER_HANDLE *sampass, const char *profile_path, BOOL store)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	DEBUG(10, ("sam_set_profile_path: setting profile path %s, was %s\n", profile_path, sampass->private.profile_path));
 
	sampass->private.profile_path = talloc_strdup(sampass->mem_ctx, profile_path);
		
	if (store) {
		DEBUG(10, ("sam_set_profile_path: setting profile path sam flag!\n"));
		sam_set_user_init_flag(sampass, FLAG_SAM_PROFILE);
	}

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the user's directory drive.
 ********************************************************************/

NTSTATUS sam_set_user_dir_drive (SAM_USER_HANDLE *sampass, const char *dir_drive, BOOL store)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	DEBUG(10, ("sam_set_dir_drive: setting dir drive %s, was %s\n", dir_drive,
			sampass->private.dir_drive));
 
	sampass->private.dir_drive = talloc_strdup(sampass->mem_ctx, dir_drive);
		
	if (store) {
		DEBUG(10, ("sam_set_dir_drive: setting dir drive sam flag!\n"));
		sam_set_user_init_flag(sampass, FLAG_SAM_DRIVE);
	}

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the user's home directory.
 ********************************************************************/

NTSTATUS sam_set_user_homedir (SAM_USER_HANDLE *sampass, const char *home_dir, BOOL store)
{
	if (!sampass) return NT_STATUS_UNSUCCESSFUL;

	DEBUG(10, ("sam_set_homedir: setting home dir %s, was %s\n", home_dir,
		sampass->private.home_dir));
 
	sampass->private.home_dir = talloc_strdup(sampass->mem_ctx, home_dir);
		
	if (store) {
		DEBUG(10, ("sam_set_homedir: setting home dir sam flag!\n"));
		sam_set_user_init_flag(sampass, FLAG_SAM_SMBHOME);
	}

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the user's unix home directory.
 ********************************************************************/

NTSTATUS sam_set_user_unix_homedir (SAM_USER_HANDLE *sampass, const char *unix_home_dir)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	DEBUG(10, ("sam_set_unix_homedir: setting home dir %s, was %s\n", unix_home_dir,
		sampass->private.unix_home_dir));
 
	sampass->private.unix_home_dir = talloc_strdup(sampass->mem_ctx, unix_home_dir);
		
	return NT_STATUS_OK;
}

/*********************************************************************
 Set the user's account description.
 ********************************************************************/

NTSTATUS sam_set_user_acct_desc (SAM_USER_HANDLE *sampass, const char *acct_desc)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.acct_desc = talloc_strdup(sampass->mem_ctx, acct_desc);

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the user's workstation allowed list.
 ********************************************************************/

NTSTATUS sam_set_user_workstations (SAM_USER_HANDLE *sampass, const char *workstations)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	DEBUG(10, ("sam_set_workstations: setting workstations %s, was %s\n", workstations,
			sampass->private.workstations));
 
	sampass->private.workstations = talloc_strdup(sampass->mem_ctx, workstations);

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the user's 'unknown_str', whatever the heck this actually is...
 ********************************************************************/

NTSTATUS sam_set_user_unknown_str (SAM_USER_HANDLE *sampass, const char *unknown_str)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.unknown_str = talloc_strdup(sampass->mem_ctx, unknown_str);
		
	return NT_STATUS_OK;
}

/*********************************************************************
 Set the user's dial string.
 ********************************************************************/

NTSTATUS sam_set_user_munged_dial (SAM_USER_HANDLE *sampass, const char *munged_dial)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.munged_dial = talloc_strdup(sampass->mem_ctx, munged_dial);
	return NT_STATUS_OK;
}

/*********************************************************************
 Set the user's NT hash.
 ********************************************************************/

NTSTATUS sam_set_user_nt_pwd (SAM_USER_HANDLE *sampass, DATA_BLOB data)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.nt_pw = data;

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the user's LM hash.
 ********************************************************************/

NTSTATUS sam_set_user_lm_pwd (SAM_USER_HANDLE *sampass, DATA_BLOB data)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.lm_pw = data;

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the user's plaintext password only (base procedure, see helper
 below)
 ********************************************************************/

NTSTATUS sam_set_user_plaintext_pw_only (SAM_USER_HANDLE *sampass, DATA_BLOB data)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.plaintext_pw = data;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_user_unknown_1 (SAM_USER_HANDLE *sampass, uint32 unkn)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.unknown_1 = unkn;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_user_unknown_2 (SAM_USER_HANDLE *sampass, uint32 unkn)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.unknown_2 = unkn;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_user_unknown_3 (SAM_USER_HANDLE *sampass, uint32 unkn)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	sampass->private.unknown_3 = unkn;
	return NT_STATUS_OK;
}

NTSTATUS sam_set_user_hours (SAM_USER_HANDLE *sampass, const uint8 *hours)
{
	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;

	if (!hours) {
		memset ((char *)sampass->private.hours, 0, MAX_HOURS_LEN);
		return NT_STATUS_OK;
	}
	
	memcpy (sampass->private.hours, hours, MAX_HOURS_LEN);

	return NT_STATUS_OK;
}

/* Helpful interfaces to the above */

/*********************************************************************
 Sets the last changed times and must change times for a normal
 password change.
 ********************************************************************/

NTSTATUS sam_set_user_pass_changed_now (SAM_USER_HANDLE *sampass)
{
	uint32 expire;
	NTTIME temptime;

	if (!sampass)
		return NT_STATUS_UNSUCCESSFUL;
	
	unix_to_nt_time(&temptime, time(NULL));
	if (!NT_STATUS_IS_OK(sam_set_user_pass_last_set_time (sampass, temptime)))
		return NT_STATUS_UNSUCCESSFUL;

	if (!account_policy_get(AP_MAX_PASSWORD_AGE, &expire) 
	    || (expire==(uint32)-1)) {

		get_nttime_max(&temptime);
		if (!NT_STATUS_IS_OK(sam_set_user_pass_must_change_time (sampass, temptime, False)))
			return NT_STATUS_UNSUCCESSFUL;

	} else {
		/* FIXME: Add expire to temptime */
		
		if (!NT_STATUS_IS_OK(sam_get_user_pass_last_set_time(sampass,&temptime)) || !NT_STATUS_IS_OK(sam_set_user_pass_must_change_time (sampass, temptime,True)))
			return NT_STATUS_UNSUCCESSFUL;
	}
	
	return NT_STATUS_OK;
}

/*********************************************************************
 Set the user's PLAINTEXT password.  Used as an interface to the above.
 Also sets the last change time to NOW.
 ********************************************************************/

NTSTATUS sam_set_plaintext_passwd (SAM_USER_HANDLE *sampass, const char *plaintext)
{
	DATA_BLOB data;
	uchar new_lanman_p16[16];
	uchar new_nt_p16[16];

	if (!sampass || !plaintext)
		return NT_STATUS_UNSUCCESSFUL;
	
	nt_lm_owf_gen (plaintext, new_nt_p16, new_lanman_p16);

	data = data_blob(new_nt_p16, 16);
	if (!NT_STATUS_IS_OK(sam_set_user_nt_pwd (sampass, data)))
		return NT_STATUS_UNSUCCESSFUL;

	data = data_blob(new_lanman_p16, 16);

	if (!NT_STATUS_IS_OK(sam_set_user_lm_pwd (sampass, data)))
		return NT_STATUS_UNSUCCESSFUL;
	
	if (!NT_STATUS_IS_OK(sam_set_user_pass_changed_now (sampass)))
		return NT_STATUS_UNSUCCESSFUL;

	return NT_STATUS_OK;
}

