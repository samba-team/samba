/* 
   Unix SMB/CIFS implementation.
   SAM_ACCOUNT_HANDLE access routines
   Copyright (C) Andrew Bartlett			2002
   Copyright (C) Stefan (metze) Metzmacher		2002
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

NTSTATUS sam_get_account_domain_sid(const SAM_ACCOUNT_HANDLE *sampass, const DOM_SID **sid)
{
	NTSTATUS status;
	SAM_DOMAIN_HANDLE *domain;
	SAM_ASSERT(!sampass || !sid);

	if (!NT_STATUS_IS_OK(status = sam_get_account_domain(sampass, &domain))){
		DEBUG(0, ("sam_get_account_domain_sid: Can't get domain for account\n"));
		return status;
	}

	return sam_get_domain_sid(domain, sid);
}

NTSTATUS sam_get_account_domain_name(const SAM_ACCOUNT_HANDLE *sampass, const char **domain_name)
{
	NTSTATUS status;
	SAM_DOMAIN_HANDLE *domain;
	SAM_ASSERT(sampass && domain_name);

	if (!NT_STATUS_IS_OK(status = sam_get_account_domain(sampass, &domain))){
		DEBUG(0, ("sam_get_account_domain_name: Can't get domain for account\n"));
		return status;
	}

	return sam_get_domain_name(domain, domain_name);
}

NTSTATUS sam_get_account_acct_ctrl(const SAM_ACCOUNT_HANDLE *sampass, uint16 *acct_ctrl)
{
	SAM_ASSERT(sampass && acct_ctrl);

	*acct_ctrl = sampass->private.acct_ctrl;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_logon_time(const SAM_ACCOUNT_HANDLE *sampass, NTTIME *logon_time)
{
	SAM_ASSERT(sampass && logon_time) ;

	*logon_time = sampass->private.logon_time;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_logoff_time(const SAM_ACCOUNT_HANDLE *sampass, NTTIME *logoff_time)
{
	SAM_ASSERT(sampass && logoff_time) ;

	*logoff_time = sampass->private.logoff_time;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_kickoff_time(const SAM_ACCOUNT_HANDLE *sampass, NTTIME *kickoff_time)
{
	SAM_ASSERT(sampass && kickoff_time);

	*kickoff_time = sampass->private.kickoff_time;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_pass_last_set_time(const SAM_ACCOUNT_HANDLE *sampass, NTTIME *pass_last_set_time)
{
	SAM_ASSERT(sampass && pass_last_set_time);

	*pass_last_set_time = sampass->private.pass_last_set_time;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_pass_can_change_time(const SAM_ACCOUNT_HANDLE *sampass, NTTIME *pass_can_change_time)
{
	SAM_ASSERT(sampass && pass_can_change_time);

	*pass_can_change_time = sampass->private.pass_can_change_time;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_pass_must_change_time(const SAM_ACCOUNT_HANDLE *sampass, NTTIME *pass_must_change_time)
{
	SAM_ASSERT(sampass && pass_must_change_time);

	*pass_must_change_time = sampass->private.pass_must_change_time;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_logon_divs(const SAM_ACCOUNT_HANDLE *sampass, uint16 *logon_divs)
{
	SAM_ASSERT(sampass && logon_divs);

	*logon_divs = sampass->private.logon_divs;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_hours_len(const SAM_ACCOUNT_HANDLE *sampass, uint32 *hours_len)
{
	SAM_ASSERT(sampass && hours_len);

	*hours_len = sampass->private.hours_len;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_hours(const SAM_ACCOUNT_HANDLE *sampass, const uint8 **hours)
{
	SAM_ASSERT(sampass && hours);

	*hours = sampass->private.hours;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_nt_pwd(const SAM_ACCOUNT_HANDLE *sampass, DATA_BLOB *nt_pwd)
{
	SAM_ASSERT(sampass);

	SMB_ASSERT((!sampass->private.nt_pw.data) 
		   || sampass->private.nt_pw.length == NT_HASH_LEN);

	*nt_pwd = sampass->private.nt_pw;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_lm_pwd(const SAM_ACCOUNT_HANDLE *sampass, DATA_BLOB *lm_pwd)
{ 
	SAM_ASSERT(sampass);

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

NTSTATUS sam_get_account_plaintext_pwd(const SAM_ACCOUNT_HANDLE *sampass, char **plain_pwd)
{
	SAM_ASSERT(sampass && plain_pwd);

	*plain_pwd = sampass->private.plaintext_pw;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_sid(const SAM_ACCOUNT_HANDLE *sampass, const DOM_SID **sid)
{
	SAM_ASSERT(sampass);

	*sid = &(sampass->private.account_sid);

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_pgroup(const SAM_ACCOUNT_HANDLE *sampass, const DOM_SID **sid)
{
	SAM_ASSERT(sampass);

	*sid = &(sampass->private.group_sid);

	return NT_STATUS_OK;
}

/**
 * Get flags showing what is initalised in the SAM_ACCOUNT_HANDLE
 * @param sampass the SAM_ACCOUNT_HANDLE in question
 * @return the flags indicating the members initialised in the struct.
 **/
 
NTSTATUS sam_get_account_init_flag(const SAM_ACCOUNT_HANDLE *sampass, uint32 *initflag)
{
	SAM_ASSERT(sampass);

	*initflag = sampass->private.init_flag;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_name(const SAM_ACCOUNT_HANDLE *sampass, char **account_name)
{
	SAM_ASSERT(sampass);

	*account_name = sampass->private.account_name;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_domain(const SAM_ACCOUNT_HANDLE *sampass, SAM_DOMAIN_HANDLE **domain)
{
	SAM_ASSERT(sampass);

	*domain = sampass->private.domain;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_fullname(const SAM_ACCOUNT_HANDLE *sampass, char **fullname)
{
	SAM_ASSERT(sampass);

	*fullname = sampass->private.full_name;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_homedir(const SAM_ACCOUNT_HANDLE *sampass, char **homedir)
{
	SAM_ASSERT(sampass);

	*homedir = sampass->private.home_dir;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_unix_home_dir(const SAM_ACCOUNT_HANDLE *sampass, char **uhomedir)
{
	SAM_ASSERT(sampass);

	*uhomedir = sampass->private.unix_home_dir;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_dir_drive(const SAM_ACCOUNT_HANDLE *sampass, char **dirdrive)
{
	SAM_ASSERT(sampass);

	*dirdrive = sampass->private.dir_drive;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_logon_script(const SAM_ACCOUNT_HANDLE *sampass, char **logon_script)
{
	SAM_ASSERT(sampass);

	*logon_script = sampass->private.logon_script;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_profile_path(const SAM_ACCOUNT_HANDLE *sampass, char **profile_path)
{
	SAM_ASSERT(sampass);

	*profile_path = sampass->private.profile_path;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_description(const SAM_ACCOUNT_HANDLE *sampass, char **description)
{
	SAM_ASSERT(sampass);

	*description = sampass->private.acct_desc;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_workstations(const SAM_ACCOUNT_HANDLE *sampass, char **workstations)
{
	SAM_ASSERT(sampass);

	*workstations = sampass->private.workstations;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_unknown_str(const SAM_ACCOUNT_HANDLE *sampass, char **unknown_str)
{
	SAM_ASSERT(sampass);

	*unknown_str = sampass->private.unknown_str;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_munged_dial(const SAM_ACCOUNT_HANDLE *sampass, char **munged_dial)
{
	SAM_ASSERT(sampass);

	*munged_dial = sampass->private.munged_dial;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_unknown_1(const SAM_ACCOUNT_HANDLE *sampass, uint32 *unknown1)
{
	SAM_ASSERT(sampass && unknown1);

	*unknown1 = sampass->private.unknown_1;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_unknown_2(const SAM_ACCOUNT_HANDLE *sampass, uint32 *unknown2)
{
	SAM_ASSERT(sampass && unknown2);

	*unknown2 = sampass->private.unknown_2;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_unknown_3(const SAM_ACCOUNT_HANDLE *sampass, uint32 *unknown3)
{
	SAM_ASSERT(sampass && unknown3);

	*unknown3 = sampass->private.unknown_3;

	return NT_STATUS_OK;
}

/*********************************************************************
 Collection of set...() functions for SAM_ACCOUNT_HANDLE_INFO.
 ********************************************************************/

NTSTATUS sam_set_account_acct_ctrl(SAM_ACCOUNT_HANDLE *sampass, uint16 acct_ctrl)
{
	SAM_ASSERT(sampass);
		
	sampass->private.acct_ctrl = acct_ctrl;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_account_logon_time(SAM_ACCOUNT_HANDLE *sampass, NTTIME mytime, BOOL store)
{
	SAM_ASSERT(sampass);

	sampass->private.logon_time = mytime;


	return NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS sam_set_account_logoff_time(SAM_ACCOUNT_HANDLE *sampass, NTTIME mytime, BOOL store)
{
	SAM_ASSERT(sampass);

	sampass->private.logoff_time = mytime;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_account_kickoff_time(SAM_ACCOUNT_HANDLE *sampass, NTTIME mytime, BOOL store)
{
	SAM_ASSERT(sampass);

	sampass->private.kickoff_time = mytime;


	return NT_STATUS_OK;
}

NTSTATUS sam_set_account_pass_can_change_time(SAM_ACCOUNT_HANDLE *sampass, NTTIME mytime, BOOL store)
{
	SAM_ASSERT(sampass);

	sampass->private.pass_can_change_time = mytime;


	return NT_STATUS_OK;
}

NTSTATUS sam_set_account_pass_must_change_time(SAM_ACCOUNT_HANDLE *sampass, NTTIME mytime, BOOL store)
{
	SAM_ASSERT(sampass);

	sampass->private.pass_must_change_time = mytime;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_account_pass_last_set_time(SAM_ACCOUNT_HANDLE *sampass, NTTIME mytime)
{
	SAM_ASSERT(sampass);

	sampass->private.pass_last_set_time = mytime;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_account_hours_len(SAM_ACCOUNT_HANDLE *sampass, uint32 len)
{
	SAM_ASSERT(sampass);

	sampass->private.hours_len = len;
	return NT_STATUS_OK;
}

NTSTATUS sam_set_account_logon_divs(SAM_ACCOUNT_HANDLE *sampass, uint16 hours)
{
	SAM_ASSERT(sampass);

	sampass->private.logon_divs = hours;
	return NT_STATUS_OK;
}

/**
 * Set flags showing what is initalised in the SAM_ACCOUNT_HANDLE
 * @param sampass the SAM_ACCOUNT_HANDLE in question
 * @param flag The *new* flag to be set.  Old flags preserved
 *             this flag is only added.  
 **/
 
NTSTATUS sam_set_account_init_flag(SAM_ACCOUNT_HANDLE *sampass, uint32 flag)
{
	SAM_ASSERT(sampass);

	sampass->private.init_flag |= flag;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_account_sid(SAM_ACCOUNT_HANDLE *sampass, const DOM_SID *u_sid)
{
	SAM_ASSERT(sampass && u_sid);
	
	sid_copy(&sampass->private.account_sid, u_sid);

	DEBUG(10, ("sam_set_account_sid: setting account sid %s\n", 
		    sid_string_static(&sampass->private.account_sid)));
	
	return NT_STATUS_OK;
}

NTSTATUS sam_set_account_sid_from_string(SAM_ACCOUNT_HANDLE *sampass, const char *u_sid)
{
	DOM_SID new_sid;
	SAM_ASSERT(sampass && u_sid);

	DEBUG(10, ("sam_set_account_sid_from_string: setting account sid %s\n",
		   u_sid));

	if (!string_to_sid(&new_sid, u_sid)) { 
		DEBUG(1, ("sam_set_account_sid_from_string: %s isn't a valid SID!\n", u_sid));
		return NT_STATUS_UNSUCCESSFUL;
	}
	 
	if (!NT_STATUS_IS_OK(sam_set_account_sid(sampass, &new_sid))) {
		DEBUG(1, ("sam_set_account_sid_from_string: could not set sid %s on SAM_ACCOUNT_HANDLE!\n", u_sid));
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_set_account_pgroup_sid(SAM_ACCOUNT_HANDLE *sampass, const DOM_SID *g_sid)
{
	SAM_ASSERT(sampass && g_sid);

	sid_copy(&sampass->private.group_sid, g_sid);

	DEBUG(10, ("sam_set_group_sid: setting group sid %s\n", 
		    sid_string_static(&sampass->private.group_sid)));

	return NT_STATUS_OK;
}

NTSTATUS sam_set_account_pgroup_string(SAM_ACCOUNT_HANDLE *sampass, const char *g_sid)
{
	DOM_SID new_sid;
	SAM_ASSERT(sampass && g_sid);

	DEBUG(10, ("sam_set_group_sid_from_string: setting group sid %s\n",
		   g_sid));

	if (!string_to_sid(&new_sid, g_sid)) { 
		DEBUG(1, ("sam_set_group_sid_from_string: %s isn't a valid SID!\n", g_sid));
		return NT_STATUS_UNSUCCESSFUL;
	}
	 
	if (!NT_STATUS_IS_OK(sam_set_account_pgroup_sid(sampass, &new_sid))) {
		DEBUG(1, ("sam_set_group_sid_from_string: could not set sid %s on SAM_ACCOUNT_HANDLE!\n", g_sid));
		return NT_STATUS_UNSUCCESSFUL;
	}
	return NT_STATUS_OK;
}

/*********************************************************************
 Set the domain name.
 ********************************************************************/

NTSTATUS sam_set_account_domain(SAM_ACCOUNT_HANDLE *sampass, SAM_DOMAIN_HANDLE *domain)
{	
	SAM_ASSERT(sampass);

	sampass->private.domain = domain;

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the account's NT name.
 ********************************************************************/

NTSTATUS sam_set_account_name(SAM_ACCOUNT_HANDLE *sampass, const char *account_name)
{
	SAM_ASSERT(sampass);

	DEBUG(10, ("sam_set_account_name: setting nt account_name %s, was %s\n", account_name, sampass->private.account_name));

	sampass->private.account_name = talloc_strdup(sampass->mem_ctx, account_name);

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the account's full name.
 ********************************************************************/

NTSTATUS sam_set_account_fullname(SAM_ACCOUNT_HANDLE *sampass, const char *full_name)
{
	SAM_ASSERT(sampass);

	DEBUG(10, ("sam_set_account_fullname: setting full name %s, was %s\n", full_name, sampass->private.full_name));

	sampass->private.full_name = talloc_strdup(sampass->mem_ctx, full_name);

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the account's logon script.
 ********************************************************************/

NTSTATUS sam_set_account_logon_script(SAM_ACCOUNT_HANDLE *sampass, const char *logon_script, BOOL store)
{
	SAM_ASSERT(sampass);

	DEBUG(10, ("sam_set_logon_script: from %s to %s\n", logon_script, sampass->private.logon_script));

	sampass->private.logon_script = talloc_strdup(sampass->mem_ctx, logon_script);
	

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the account's profile path.
 ********************************************************************/

NTSTATUS sam_set_account_profile_path(SAM_ACCOUNT_HANDLE *sampass, const char *profile_path, BOOL store)
{
	SAM_ASSERT(sampass);

	DEBUG(10, ("sam_set_profile_path: setting profile path %s, was %s\n", profile_path, sampass->private.profile_path));
 
	sampass->private.profile_path = talloc_strdup(sampass->mem_ctx, profile_path);
		
	return NT_STATUS_OK;
}

/*********************************************************************
 Set the account's directory drive.
 ********************************************************************/

NTSTATUS sam_set_account_dir_drive(SAM_ACCOUNT_HANDLE *sampass, const char *dir_drive, BOOL store)
{
	SAM_ASSERT(sampass);

	DEBUG(10, ("sam_set_dir_drive: setting dir drive %s, was %s\n", dir_drive,
			sampass->private.dir_drive));
 
	sampass->private.dir_drive = talloc_strdup(sampass->mem_ctx, dir_drive);
		
	return NT_STATUS_OK;
}

/*********************************************************************
 Set the account's home directory.
 ********************************************************************/

NTSTATUS sam_set_account_homedir(SAM_ACCOUNT_HANDLE *sampass, const char *home_dir, BOOL store)
{
	SAM_ASSERT(sampass);

	DEBUG(10, ("sam_set_homedir: setting home dir %s, was %s\n", home_dir,
		sampass->private.home_dir));
 
	sampass->private.home_dir = talloc_strdup(sampass->mem_ctx, home_dir);
		
	return NT_STATUS_OK;
}

/*********************************************************************
 Set the account's unix home directory.
 ********************************************************************/

NTSTATUS sam_set_account_unix_homedir(SAM_ACCOUNT_HANDLE *sampass, const char *unix_home_dir)
{
	SAM_ASSERT(sampass);

	DEBUG(10, ("sam_set_unix_homedir: setting home dir %s, was %s\n", unix_home_dir,
		sampass->private.unix_home_dir));
 
	sampass->private.unix_home_dir = talloc_strdup(sampass->mem_ctx, unix_home_dir);
		
	return NT_STATUS_OK;
}

/*********************************************************************
 Set the account's account description.
 ********************************************************************/

NTSTATUS sam_set_account_acct_desc(SAM_ACCOUNT_HANDLE *sampass, const char *acct_desc)
{
	SAM_ASSERT(sampass);

	sampass->private.acct_desc = talloc_strdup(sampass->mem_ctx, acct_desc);

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the account's workstation allowed list.
 ********************************************************************/

NTSTATUS sam_set_account_workstations(SAM_ACCOUNT_HANDLE *sampass, const char *workstations)
{
	SAM_ASSERT(sampass);

	DEBUG(10, ("sam_set_workstations: setting workstations %s, was %s\n", workstations,
			sampass->private.workstations));
 
	sampass->private.workstations = talloc_strdup(sampass->mem_ctx, workstations);

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the account's 'unknown_str', whatever the heck this actually is...
 ********************************************************************/

NTSTATUS sam_set_account_unknown_str(SAM_ACCOUNT_HANDLE *sampass, const char *unknown_str)
{
	SAM_ASSERT(sampass);

	sampass->private.unknown_str = talloc_strdup(sampass->mem_ctx, unknown_str);
		
	return NT_STATUS_OK;
}

/*********************************************************************
 Set the account's dial string.
 ********************************************************************/

NTSTATUS sam_set_account_munged_dial(SAM_ACCOUNT_HANDLE *sampass, const char *munged_dial)
{
	SAM_ASSERT(sampass);

	sampass->private.munged_dial = talloc_strdup(sampass->mem_ctx, munged_dial);
	
	return NT_STATUS_OK;
}

/*********************************************************************
 Set the account's NT hash.
 ********************************************************************/

NTSTATUS sam_set_account_nt_pwd(SAM_ACCOUNT_HANDLE *sampass, const DATA_BLOB data)
{
	SAM_ASSERT(sampass);

	sampass->private.nt_pw = data;

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the account's LM hash.
 ********************************************************************/

NTSTATUS sam_set_account_lm_pwd(SAM_ACCOUNT_HANDLE *sampass, const DATA_BLOB data)
{
	SAM_ASSERT(sampass);

	sampass->private.lm_pw = data;

	return NT_STATUS_OK;
}

/*********************************************************************
 Set the account's plaintext password only (base procedure, see helper
 below)
 ********************************************************************/

NTSTATUS sam_set_account_plaintext_pwd(SAM_ACCOUNT_HANDLE *sampass, const char *plain_pwd)
{
	SAM_ASSERT(sampass);

	sampass->private.plaintext_pw = talloc_strdup(sampass->mem_ctx, plain_pwd);

	return NT_STATUS_OK;
}

NTSTATUS sam_set_account_unknown_1(SAM_ACCOUNT_HANDLE *sampass, uint32 unkn)
{
	SAM_ASSERT(sampass);

	sampass->private.unknown_1 = unkn;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_account_unknown_2(SAM_ACCOUNT_HANDLE *sampass, uint32 unkn)
{
	SAM_ASSERT(sampass);

	sampass->private.unknown_2 = unkn;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_account_unknown_3(SAM_ACCOUNT_HANDLE *sampass, uint32 unkn)
{
	SAM_ASSERT(sampass);

	sampass->private.unknown_3 = unkn;
	return NT_STATUS_OK;
}

NTSTATUS sam_set_account_hours(SAM_ACCOUNT_HANDLE *sampass, const uint8 *hours)
{
	SAM_ASSERT(sampass);

	if (!hours) {
		memset ((char *)sampass->private.hours, 0, MAX_HOURS_LEN);
		return NT_STATUS_OK;
	}
	
	memcpy(sampass->private.hours, hours, MAX_HOURS_LEN);

	return NT_STATUS_OK;
}

/* Helpful interfaces to the above */

/*********************************************************************
 Sets the last changed times and must change times for a normal
 password change.
 ********************************************************************/

NTSTATUS sam_set_account_pass_changed_now(SAM_ACCOUNT_HANDLE *sampass)
{
	uint32 expire;
	NTTIME temptime;

	SAM_ASSERT(sampass);
	
	unix_to_nt_time(&temptime, time(NULL));
	if (!NT_STATUS_IS_OK(sam_set_account_pass_last_set_time(sampass, temptime)))
		return NT_STATUS_UNSUCCESSFUL;

	if (!account_policy_get(AP_MAX_PASSWORD_AGE, &expire) 
	    || (expire==(uint32)-1)) {

		get_nttime_max(&temptime);
		if (!NT_STATUS_IS_OK(sam_set_account_pass_must_change_time(sampass, temptime, False)))
			return NT_STATUS_UNSUCCESSFUL;

	} else {
		/* FIXME: Add expire to temptime */
		
		if (!NT_STATUS_IS_OK(sam_get_account_pass_last_set_time(sampass,&temptime)) || !NT_STATUS_IS_OK(sam_set_account_pass_must_change_time(sampass, temptime,True)))
			return NT_STATUS_UNSUCCESSFUL;
	}
	
	return NT_STATUS_OK;
}

/*********************************************************************
 Set the account's PLAINTEXT password.  Used as an interface to the above.
 Also sets the last change time to NOW.
 ********************************************************************/

NTSTATUS sam_set_account_passwd(SAM_ACCOUNT_HANDLE *sampass, const char *plaintext)
{
	DATA_BLOB data;
	uchar new_lanman_p16[16];
	uchar new_nt_p16[16];

	SAM_ASSERT(sampass && plaintext);
	
	nt_lm_owf_gen(plaintext, new_nt_p16, new_lanman_p16);

	data = data_blob(new_nt_p16, 16);
	if (!NT_STATUS_IS_OK(sam_set_account_nt_pwd(sampass, data)))
		return NT_STATUS_UNSUCCESSFUL;

	data = data_blob(new_lanman_p16, 16);

	if (!NT_STATUS_IS_OK(sam_set_account_lm_pwd(sampass, data)))
		return NT_STATUS_UNSUCCESSFUL;

	if (!NT_STATUS_IS_OK(sam_set_account_plaintext_pwd(sampass, plaintext)))
		return NT_STATUS_UNSUCCESSFUL;
	
	if (!NT_STATUS_IS_OK(sam_set_account_pass_changed_now(sampass)))
		return NT_STATUS_UNSUCCESSFUL;

	return NT_STATUS_OK;
}

