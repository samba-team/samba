/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   SAM_ACCOUNT access routines
   Copyright (C) Jeremy Allison 		1996-2001
   Copyright (C) Luke Kenneth Casson Leighton 	1996-1998
   Copyright (C) Gerald (Jerry) Carter		2000-2001
   Copyright (C) Andrew Bartlett		2001-2002
      
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

/*********************************************************************
 Collection of get...() functions for SAM_ACCOUNT_INFO.
 ********************************************************************/

uint16 pdb_get_acct_ctrl (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.acct_ctrl);
	else
		return (ACB_DISABLED);
}

time_t pdb_get_logon_time (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.logon_time);
	else
		return (0);
}

time_t pdb_get_logoff_time (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.logoff_time);
	else
		return (-1);
}

time_t pdb_get_kickoff_time (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.kickoff_time);
	else
		return (-1);
}

time_t pdb_get_pass_last_set_time (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.pass_last_set_time);
	else
		return (-1);
}

time_t pdb_get_pass_can_change_time (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.pass_can_change_time);
	else
		return (-1);
}

time_t pdb_get_pass_must_change_time (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.pass_must_change_time);
	else
		return (-1);
}

uint16 pdb_get_logon_divs (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.logon_divs);
	else
		return (-1);
}

uint32 pdb_get_hours_len (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.hours_len);
	else
		return (-1);
}

const uint8* pdb_get_hours (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.hours);
	else
		return (NULL);
}

const uint8* pdb_get_nt_passwd (const SAM_ACCOUNT *sampass)
{
	if (sampass) {
		SMB_ASSERT((!sampass->private.nt_pw.data) 
			   || sampass->private.nt_pw.length == NT_HASH_LEN);
		return ((uint8*)sampass->private.nt_pw.data);
	}
	else
		return (NULL);
}

const uint8* pdb_get_lanman_passwd (const SAM_ACCOUNT *sampass)
{
	if (sampass) {
		SMB_ASSERT((!sampass->private.lm_pw.data) 
			   || sampass->private.lm_pw.length == LM_HASH_LEN);
		return ((uint8*)sampass->private.lm_pw.data);
	}
	else
		return (NULL);
}

uint32 pdb_get_user_rid (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.user_rid);
	else
		return (-1);
}

uint32 pdb_get_group_rid (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.group_rid);
	else
		return (-1);
}

/**
 * Get flags showing what is initalised in the SAM_ACCOUNT
 * @param sampass the SAM_ACCOUNT in question
 * @return the flags indicating the members initialised in the struct.
 **/
 
uint32 pdb_get_init_flag (SAM_ACCOUNT *sampass)
{
        if (sampass)
		return sampass->private.init_flag;
	else 
                return FLAG_SAM_UNINIT;
}

uid_t pdb_get_uid (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.uid);
	else
		return (-1);
}

gid_t pdb_get_gid (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.gid);
	else
		return (-1);
}

const char* pdb_get_username (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.username);
	else
		return (NULL);
}

const char* pdb_get_domain (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.domain);
	else
		return (NULL);
}

const char* pdb_get_nt_username (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.nt_username);
	else
		return (NULL);
}

const char* pdb_get_fullname (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.full_name);
	else
		return (NULL);
}

const char* pdb_get_homedir (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.home_dir);
	else
		return (NULL);
}

const char* pdb_get_dirdrive (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.dir_drive);
	else
		return (NULL);
}

const char* pdb_get_logon_script (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.logon_script);
	else
		return (NULL);
}

const char* pdb_get_profile_path (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.profile_path);
	else
		return (NULL);
}

const char* pdb_get_acct_desc (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.acct_desc);
	else
		return (NULL);
}

const char* pdb_get_workstations (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.workstations);
	else
		return (NULL);
}

const char* pdb_get_unknown_str (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.unknown_str);
	else
		return (NULL);
}

const char* pdb_get_munged_dial (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.munged_dial);
	else
		return (NULL);
}

uint32 pdb_get_unknown3 (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.unknown_3);
	else
		return (-1);
}

uint32 pdb_get_unknown5 (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.unknown_5);
	else
		return (-1);
}

uint32 pdb_get_unknown6 (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.unknown_6);
	else
		return (-1);
}

/*********************************************************************
 Collection of set...() functions for SAM_ACCOUNT_INFO.
 ********************************************************************/

BOOL pdb_set_acct_ctrl (SAM_ACCOUNT *sampass, uint16 flags)
{
	if (!sampass)
		return False;
		
	if (sampass) {
		sampass->private.acct_ctrl = flags;
		return True;
	}
	
	return False;
}

BOOL pdb_set_logon_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->private.logon_time = mytime;
	return True;
}

BOOL pdb_set_logoff_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->private.logoff_time = mytime;
	return True;
}

BOOL pdb_set_kickoff_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->private.kickoff_time = mytime;
	return True;
}

BOOL pdb_set_pass_can_change_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->private.pass_can_change_time = mytime;
	return True;
}

BOOL pdb_set_pass_must_change_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->private.pass_must_change_time = mytime;
	return True;
}

BOOL pdb_set_pass_last_set_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->private.pass_last_set_time = mytime;
	return True;
}

BOOL pdb_set_hours_len (SAM_ACCOUNT *sampass, uint32 len)
{
	if (!sampass)
		return False;

	sampass->private.hours_len = len;
	return True;
}

BOOL pdb_set_logon_divs (SAM_ACCOUNT *sampass, uint16 hours)
{
	if (!sampass)
		return False;

	sampass->private.logon_divs = hours;
	return True;
}

/**
 * Set flags showing what is initalised in the SAM_ACCOUNT
 * @param sampass the SAM_ACCOUNT in question
 * @param flag The *new* flag to be set.  Old flags preserved
 *             this flag is only added.  
 **/
 
BOOL pdb_set_init_flag (SAM_ACCOUNT *sampass, uint32 flag)
{
        if (!sampass)
                return False;

        sampass->private.init_flag |= flag;

        return True;
}

BOOL pdb_set_uid (SAM_ACCOUNT *sampass, const uid_t uid)
{
	if (!sampass)
		return False;
	
	DEBUG(10, ("pdb_set_uid: setting uid %d, was %d\n", 
		   (int)uid, (int)sampass->private.uid));
 
	sampass->private.uid = uid;
	pdb_set_init_flag(sampass, FLAG_SAM_UID); 

	return True;

}

BOOL pdb_set_gid (SAM_ACCOUNT *sampass, const gid_t gid)
{
	if (!sampass)
		return False;
		
	DEBUG(10, ("pdb_set_gid: setting gid %d, was %d\n", 
		   (int)gid, (int)sampass->private.gid));
 
	sampass->private.gid = gid; 
	pdb_set_init_flag(sampass, FLAG_SAM_GID); 

	return True;

}

BOOL pdb_set_user_rid (SAM_ACCOUNT *sampass, uint32 rid)
{
	if (!sampass)
		return False;

	DEBUG(10, ("pdb_set_rid: setting user rid %d, was %d\n", 
		   rid, sampass->private.user_rid));
 
	sampass->private.user_rid = rid;
	return True;
}

BOOL pdb_set_group_rid (SAM_ACCOUNT *sampass, uint32 grid)
{
	if (!sampass)
		return False;

	DEBUG(10, ("pdb_set_group_rid: setting group rid %d, was %d\n", 
		   grid, sampass->private.group_rid));
 
	sampass->private.group_rid = grid;
	return True;
}

/*********************************************************************
 Set the user's UNIX name.
 ********************************************************************/

BOOL pdb_set_username(SAM_ACCOUNT *sampass, const char *username)
{	
	if (!sampass)
		return False;
	
	*sampass->private.username = '\0';
	DEBUG(10, ("pdb_set_username: setting username %s, was %s\n", 
		   username, sampass->private.username));
 
	if (!username)
		return False;
	StrnCpy (sampass->private.username, username, sizeof(pstring) - 1);

	return True;
}

/*********************************************************************
 Set the domain name.
 ********************************************************************/

BOOL pdb_set_domain(SAM_ACCOUNT *sampass, const char *domain)
{	
	if (!sampass)
		return False;
	*sampass->private.domain = '\0';
	if (!domain)
		return False;

	StrnCpy (sampass->private.domain, domain, sizeof(pstring) - 1);

	return True;
}

/*********************************************************************
 Set the user's NT name.
 ********************************************************************/

BOOL pdb_set_nt_username(SAM_ACCOUNT *sampass, const char *nt_username)
{
	if (!sampass)
		return False;
	*sampass->private.nt_username = '\0';
	if (!nt_username)
		return False;

	StrnCpy (sampass->private.nt_username, nt_username, sizeof(pstring) - 1);

	return True;
}

/*********************************************************************
 Set the user's full name.
 ********************************************************************/

BOOL pdb_set_fullname(SAM_ACCOUNT *sampass, const char *fullname)
{
	if (!sampass)
		return False;

	DEBUG(10, ("pdb_set_fullname: setting full name %s, was %s\n", 
		   fullname, sampass->private.full_name));
 
	*sampass->private.full_name = '\0';
	if (!fullname)
		return False;

	StrnCpy (sampass->private.full_name, fullname, sizeof(pstring) - 1);

	return True;
}

/*********************************************************************
 Set the user's logon script.
 ********************************************************************/

BOOL pdb_set_logon_script(SAM_ACCOUNT *sampass, const char *logon_script, BOOL store)
{
	if (!sampass)
		return False;

	DEBUG(10, ("pdb_set_logon_script: setting logon script (store:%d) %s, was %s\n", 
		   store, logon_script, sampass->private.logon_script));
 
	*sampass->private.logon_script = '\0';
	if (!logon_script)
		return False;

	StrnCpy (sampass->private.logon_script, logon_script, sizeof(pstring) - 1);

	if (store)
		pdb_set_init_flag(sampass, FLAG_SAM_LOGONSCRIPT); 

	return True;
}

/*********************************************************************
 Set the user's profile path.
 ********************************************************************/

BOOL pdb_set_profile_path (SAM_ACCOUNT *sampass, const char *profile_path, BOOL store)
{
	if (!sampass)
		return False;

	DEBUG(10, ("pdb_set_profile_path: setting profile path (store:%d) %s, was %s\n", 
		   store, profile_path, sampass->private.profile_path));
 
	*sampass->private.profile_path = '\0';
	if (!profile_path)
		return False;
	
	StrnCpy (sampass->private.profile_path, profile_path, sizeof(pstring) - 1);

	if (store)
		pdb_set_init_flag(sampass, FLAG_SAM_PROFILE);
	
	return True;
}

/*********************************************************************
 Set the user's directory drive.
 ********************************************************************/

BOOL pdb_set_dir_drive (SAM_ACCOUNT *sampass, const char *dir_drive, BOOL store)
{
	if (!sampass)
		return False;
	*sampass->private.dir_drive = '\0';
	if (!dir_drive)
		return False;

	StrnCpy (sampass->private.dir_drive, dir_drive, sizeof(pstring) - 1);

	if (store)
		pdb_set_init_flag(sampass, FLAG_SAM_DRIVE);

	return True;
}

/*********************************************************************
 Set the user's home directory.
 ********************************************************************/

BOOL pdb_set_homedir (SAM_ACCOUNT *sampass, const char *homedir, BOOL store)
{
	if (!sampass)
		return False;
	*sampass->private.home_dir = '\0';
	if (!homedir)
		return False;
	
	StrnCpy (sampass->private.home_dir, homedir, sizeof(pstring) - 1);

	if (store)
		pdb_set_init_flag(sampass, FLAG_SAM_SMBHOME);

	return True;
}

/*********************************************************************
 Set the user's account description.
 ********************************************************************/

BOOL pdb_set_acct_desc (SAM_ACCOUNT *sampass, const char *acct_desc)
{
	if (!sampass)
		return False;
	*sampass->private.acct_desc = '\0';
	if (!acct_desc)
		return False;
	
	StrnCpy (sampass->private.acct_desc, acct_desc, sizeof(pstring) - 1);

	return True;
}

/*********************************************************************
 Set the user's workstation allowed list.
 ********************************************************************/

BOOL pdb_set_workstations (SAM_ACCOUNT *sampass, const char *workstations)
{
	if (!sampass)
		return False;
	*sampass->private.workstations = '\0';
	if (!workstations)
		return False;

	StrnCpy (sampass->private.workstations, workstations, sizeof(pstring) - 1);

	return True;
}

/*********************************************************************
 Set the user's 'unknown_str', whatever the heck this actually is...
 ********************************************************************/

BOOL pdb_set_unknown_str (SAM_ACCOUNT *sampass, const char *unknown_str)
{
	if (!sampass)
		return False;
	*sampass->private.unknown_str = '\0';
	if (!unknown_str)
		return False;

	StrnCpy (sampass->private.unknown_str, unknown_str, sizeof(pstring) - 1);

	return True;
}

/*********************************************************************
 Set the user's dial string.
 ********************************************************************/

BOOL pdb_set_munged_dial (SAM_ACCOUNT *sampass, const char *munged_dial)
{
	if (!sampass)
		return False;
	*sampass->private.munged_dial = '\0';
	if (!munged_dial)
		return False;

	StrnCpy (sampass->private.munged_dial, munged_dial, sizeof(pstring) - 1);

	return True;
}

/*********************************************************************
 Set the user's NT hash.
 ********************************************************************/

BOOL pdb_set_nt_passwd (SAM_ACCOUNT *sampass, const uint8 *pwd)
{
	if (!sampass)
		return False;

	data_blob_clear_free(&sampass->private.nt_pw);
	
	sampass->private.nt_pw = data_blob(pwd, NT_HASH_LEN);

	return True;
}

/*********************************************************************
 Set the user's LM hash.
 ********************************************************************/

BOOL pdb_set_lanman_passwd (SAM_ACCOUNT *sampass, const uint8 *pwd)
{
	if (!sampass)
		return False;

	data_blob_clear_free(&sampass->private.lm_pw);
	
	sampass->private.lm_pw = data_blob(pwd, LM_HASH_LEN);

	return True;
}

BOOL pdb_set_unknown_3 (SAM_ACCOUNT *sampass, uint32 unkn)
{
	if (!sampass)
		return False;

	sampass->private.unknown_3 = unkn;
	return True;
}

BOOL pdb_set_unknown_5 (SAM_ACCOUNT *sampass, uint32 unkn)
{
	if (!sampass)
		return False;

	sampass->private.unknown_5 = unkn;
	return True;
}

BOOL pdb_set_unknown_6 (SAM_ACCOUNT *sampass, uint32 unkn)
{
	if (!sampass)
		return False;

	sampass->private.unknown_6 = unkn;
	return True;
}

BOOL pdb_set_hours (SAM_ACCOUNT *sampass, const uint8 *hours)
{
	if (!sampass)
		return False;

	if (!hours) {
		memset ((char *)sampass->private.hours, 0, MAX_HOURS_LEN);
		return True;
	}
	
	memcpy (sampass->private.hours, hours, MAX_HOURS_LEN);

	return True;
}


/* Helpful interfaces to the above */

/*********************************************************************
 Sets the last changed times and must change times for a normal
 password change.
 ********************************************************************/

BOOL pdb_set_pass_changed_now (SAM_ACCOUNT *sampass)
{
	uint32 expire;

	if (!sampass)
		return False;
	
	if (!pdb_set_pass_last_set_time (sampass, time(NULL)))
		return False;

	account_policy_get(AP_MAX_PASSWORD_AGE, &expire);

	if (expire==(uint32)-1) {
		if (!pdb_set_pass_must_change_time (sampass, 0))
			return False;
	} else {
		if (!pdb_set_pass_must_change_time (sampass, 
					    pdb_get_pass_last_set_time(sampass)
					    + expire))
			return False;
	}
	
	return True;
}

/*********************************************************************
 Set the user's PLAINTEXT password.  Used as an interface to the above.
 Also sets the last change time to NOW.
 ********************************************************************/

BOOL pdb_set_plaintext_passwd (SAM_ACCOUNT *sampass, const char *plaintext)
{
	uchar new_lanman_p16[16];
	uchar new_nt_p16[16];

	if (!sampass || !plaintext)
		return False;
	
	nt_lm_owf_gen (plaintext, new_nt_p16, new_lanman_p16);

	if (!pdb_set_nt_passwd (sampass, new_nt_p16)) 
		return False;

	if (!pdb_set_lanman_passwd (sampass, new_lanman_p16)) 
		return False;
	
	if (!pdb_set_pass_changed_now (sampass))
		return False;

	return True;
}

