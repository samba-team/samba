/* 
   Unix SMB/CIFS implementation.
   SAM_ACCOUNT access routines
   Copyright (C) Jeremy Allison 		1996-2001
   Copyright (C) Luke Kenneth Casson Leighton 	1996-1998
   Copyright (C) Gerald (Jerry) Carter		2000-2001
   Copyright (C) Andrew Bartlett		2001-2002
   Copyright (C) Stefan (metze) Metzmacher	2002
      
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
#define DBGC_CLASS DBGC_PASSDB

/**
 * @todo Redefine this to NULL, but this changes the API because
 *       much of samba assumes that the pdb_get...() funtions 
 *       return pstrings.  (ie not null-pointers).
 *       See also pdb_fill_default_sam().
 */

#define PDB_NOT_QUITE_NULL ""

/*********************************************************************
 Collection of get...() functions for SAM_ACCOUNT.
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

time_t pdb_get_bad_password_time (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.bad_password_time);
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

/* Return the plaintext password if known.  Most of the time
   it isn't, so don't assume anything magic about this function.
   
   Used to pass the plaintext to passdb backends that might 
   want to store more than just the NTLM hashes.
*/
const char* pdb_get_plaintext_passwd (const SAM_ACCOUNT *sampass)
{
	if (sampass) {
		return (sampass->private.plaintext_pw);
	}
	else
		return (NULL);
}
const DOM_SID *pdb_get_user_sid(const SAM_ACCOUNT *sampass)
{
	if (sampass) 
		return &sampass->private.user_sid;
	else
		return (NULL);
}

const DOM_SID *pdb_get_group_sid(const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return &sampass->private.group_sid;
	else	
		return (NULL);
}	

/**
 * Get flags showing what is initalised in the SAM_ACCOUNT
 * @param sampass the SAM_ACCOUNT in question
 * @return the flags indicating the members initialised in the struct.
 **/
 
enum pdb_value_state pdb_get_init_flags (const SAM_ACCOUNT *sampass, enum pdb_elements element)
{
	enum pdb_value_state ret = PDB_DEFAULT;
	
        if (!sampass || !sampass->private.change_flags || !sampass->private.set_flags)
        	return ret;
        	
        if (bitmap_query(sampass->private.set_flags, element)) {
		DEBUG(11, ("element %d: SET\n", element)); 
        	ret = PDB_SET;
	}
		
        if (bitmap_query(sampass->private.change_flags, element)) {
		DEBUG(11, ("element %d: CHANGED\n", element)); 
        	ret = PDB_CHANGED;
	}

	if (ret == PDB_DEFAULT) {
		DEBUG(11, ("element %d: DEFAULT\n", element)); 
	}

        return ret;
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

const char* pdb_get_unix_homedir (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.unix_home_dir);
	else
		return (NULL);
}

const char* pdb_get_dir_drive (const SAM_ACCOUNT *sampass)
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

uint32 pdb_get_fields_present (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.fields_present);
	else
		return (-1);
}

uint16 pdb_get_bad_password_count(const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.bad_password_count);
	else
		return 0;
}

uint16 pdb_get_logon_count(const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.logon_count);
	else
		return 0;
}

uint32 pdb_get_unknown_6 (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.unknown_6);
	else
		return (-1);
}

void *pdb_get_backend_private_data (const SAM_ACCOUNT *sampass, const struct pdb_methods *my_methods)
{
	if (sampass && my_methods == sampass->private.backend_private_methods)
		return sampass->private.backend_private_data;
	else
		return NULL;
}

/*********************************************************************
 Collection of set...() functions for SAM_ACCOUNT.
 ********************************************************************/

BOOL pdb_set_acct_ctrl (SAM_ACCOUNT *sampass, uint16 acct_ctrl, enum pdb_value_state flag)
{
	if (!sampass)
		return False;
		
	sampass->private.acct_ctrl = acct_ctrl;

	return pdb_set_init_flags(sampass, PDB_ACCTCTRL, flag);
}

BOOL pdb_set_logon_time (SAM_ACCOUNT *sampass, time_t mytime, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	sampass->private.logon_time = mytime;

	return pdb_set_init_flags(sampass, PDB_LOGONTIME, flag);
}

BOOL pdb_set_logoff_time (SAM_ACCOUNT *sampass, time_t mytime, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	sampass->private.logoff_time = mytime;

	return pdb_set_init_flags(sampass, PDB_LOGOFFTIME, flag);
}

BOOL pdb_set_kickoff_time (SAM_ACCOUNT *sampass, time_t mytime, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	sampass->private.kickoff_time = mytime;

	return pdb_set_init_flags(sampass, PDB_KICKOFFTIME, flag);
}

BOOL pdb_set_bad_password_time (SAM_ACCOUNT *sampass, time_t mytime, 
				enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	sampass->private.bad_password_time = mytime;

	return pdb_set_init_flags(sampass, PDB_BAD_PASSWORD_TIME, flag);
}

BOOL pdb_set_pass_can_change_time (SAM_ACCOUNT *sampass, time_t mytime, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	sampass->private.pass_can_change_time = mytime;

	return pdb_set_init_flags(sampass, PDB_CANCHANGETIME, flag);
}

BOOL pdb_set_pass_must_change_time (SAM_ACCOUNT *sampass, time_t mytime, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	sampass->private.pass_must_change_time = mytime;

	return pdb_set_init_flags(sampass, PDB_MUSTCHANGETIME, flag);
}

BOOL pdb_set_pass_last_set_time (SAM_ACCOUNT *sampass, time_t mytime, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	sampass->private.pass_last_set_time = mytime;

	return pdb_set_init_flags(sampass, PDB_PASSLASTSET, flag);
}

BOOL pdb_set_hours_len (SAM_ACCOUNT *sampass, uint32 len, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	sampass->private.hours_len = len;

	return pdb_set_init_flags(sampass, PDB_HOURSLEN, flag);
}

BOOL pdb_set_logon_divs (SAM_ACCOUNT *sampass, uint16 hours, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	sampass->private.logon_divs = hours;

	return pdb_set_init_flags(sampass, PDB_LOGONDIVS, flag);
}

/**
 * Set flags showing what is initalised in the SAM_ACCOUNT
 * @param sampass the SAM_ACCOUNT in question
 * @param flag The *new* flag to be set.  Old flags preserved
 *             this flag is only added.  
 **/
 
BOOL pdb_set_init_flags (SAM_ACCOUNT *sampass, enum pdb_elements element, enum pdb_value_state value_flag)
{
        if (!sampass || !sampass->mem_ctx)
                return False;

        if (!sampass->private.set_flags) {
        	if ((sampass->private.set_flags = 
        		bitmap_talloc(sampass->mem_ctx, 
        				PDB_COUNT))==NULL) {
        		DEBUG(0,("bitmap_talloc failed\n"));
        		return False;
        	}
        }
        if (!sampass->private.change_flags) {
        	if ((sampass->private.change_flags = 
        		bitmap_talloc(sampass->mem_ctx, 
        				PDB_COUNT))==NULL) {
        		DEBUG(0,("bitmap_talloc failed\n"));
        		return False;
        	}
        }
        
        switch(value_flag) {
        	case PDB_CHANGED:
        		if (!bitmap_set(sampass->private.change_flags, element)) {
				DEBUG(0,("Can't set flag: %d in change_flags.\n",element));
				return False;
			}
        		if (!bitmap_set(sampass->private.set_flags, element)) {
				DEBUG(0,("Can't set flag: %d in set_flags.\n",element));
				return False;
			}
			DEBUG(11, ("element %d -> now CHANGED\n", element)); 
        		break;
        	case PDB_SET:
        		if (!bitmap_clear(sampass->private.change_flags, element)) {
				DEBUG(0,("Can't set flag: %d in change_flags.\n",element));
				return False;
			}
        		if (!bitmap_set(sampass->private.set_flags, element)) {
				DEBUG(0,("Can't set flag: %d in set_flags.\n",element));
				return False;
			}
			DEBUG(10, ("element %d -> now SET\n", element)); 
        		break;
        	case PDB_DEFAULT:
        	default:
        		if (!bitmap_clear(sampass->private.change_flags, element)) {
				DEBUG(0,("Can't set flag: %d in change_flags.\n",element));
				return False;
			}
        		if (!bitmap_clear(sampass->private.set_flags, element)) {
				DEBUG(0,("Can't set flag: %d in set_flags.\n",element));
				return False;
			}
			DEBUG(11, ("element %d -> now DEFAULT\n", element)); 
        		break;
	}

        return True;
}

BOOL pdb_set_user_sid (SAM_ACCOUNT *sampass, const DOM_SID *u_sid, enum pdb_value_state flag)
{
	if (!sampass || !u_sid)
		return False;
	
	sid_copy(&sampass->private.user_sid, u_sid);

	DEBUG(10, ("pdb_set_user_sid: setting user sid %s\n", 
		    sid_string_static(&sampass->private.user_sid)));

	return pdb_set_init_flags(sampass, PDB_USERSID, flag);
}

BOOL pdb_set_user_sid_from_string (SAM_ACCOUNT *sampass, fstring u_sid, enum pdb_value_state flag)
{
	DOM_SID new_sid;
	
	if (!sampass || !u_sid)
		return False;

	DEBUG(10, ("pdb_set_user_sid_from_string: setting user sid %s\n",
		   u_sid));

	if (!string_to_sid(&new_sid, u_sid)) { 
		DEBUG(1, ("pdb_set_user_sid_from_string: %s isn't a valid SID!\n", u_sid));
		return False;
	}
	 
	if (!pdb_set_user_sid(sampass, &new_sid, flag)) {
		DEBUG(1, ("pdb_set_user_sid_from_string: could not set sid %s on SAM_ACCOUNT!\n", u_sid));
		return False;
	}

	return True;
}

BOOL pdb_set_group_sid (SAM_ACCOUNT *sampass, const DOM_SID *g_sid, enum pdb_value_state flag)
{
	if (!sampass || !g_sid)
		return False;

	sid_copy(&sampass->private.group_sid, g_sid);

	DEBUG(10, ("pdb_set_group_sid: setting group sid %s\n", 
		    sid_string_static(&sampass->private.group_sid)));

	return pdb_set_init_flags(sampass, PDB_GROUPSID, flag);
}

BOOL pdb_set_group_sid_from_string (SAM_ACCOUNT *sampass, fstring g_sid, enum pdb_value_state flag)
{
	DOM_SID new_sid;
	if (!sampass || !g_sid)
		return False;

	DEBUG(10, ("pdb_set_group_sid_from_string: setting group sid %s\n",
		   g_sid));

	if (!string_to_sid(&new_sid, g_sid)) { 
		DEBUG(1, ("pdb_set_group_sid_from_string: %s isn't a valid SID!\n", g_sid));
		return False;
	}
	 
	if (!pdb_set_group_sid(sampass, &new_sid, flag)) {
		DEBUG(1, ("pdb_set_group_sid_from_string: could not set sid %s on SAM_ACCOUNT!\n", g_sid));
		return False;
	}
	return True;
}

/*********************************************************************
 Set the user's UNIX name.
 ********************************************************************/

BOOL pdb_set_username(SAM_ACCOUNT *sampass, const char *username, enum pdb_value_state flag)
{
	if (!sampass)
		return False;
 
	if (username) { 
		DEBUG(10, ("pdb_set_username: setting username %s, was %s\n", username,
			(sampass->private.username)?(sampass->private.username):"NULL"));

		sampass->private.username = talloc_strdup(sampass->mem_ctx, username);

		if (!sampass->private.username) {
			DEBUG(0, ("pdb_set_username: talloc_strdup() failed!\n"));
			return False;
		}

	} else {
		sampass->private.username = PDB_NOT_QUITE_NULL;
	}
	
	return pdb_set_init_flags(sampass, PDB_USERNAME, flag);
}

/*********************************************************************
 Set the domain name.
 ********************************************************************/

BOOL pdb_set_domain(SAM_ACCOUNT *sampass, const char *domain, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	if (domain) { 
		DEBUG(10, ("pdb_set_domain: setting domain %s, was %s\n", domain,
			(sampass->private.domain)?(sampass->private.domain):"NULL"));

		sampass->private.domain = talloc_strdup(sampass->mem_ctx, domain);

		if (!sampass->private.domain) {
			DEBUG(0, ("pdb_set_domain: talloc_strdup() failed!\n"));
			return False;
		}

	} else {
		sampass->private.domain = PDB_NOT_QUITE_NULL;
	}

	return pdb_set_init_flags(sampass, PDB_DOMAIN, flag);
}

/*********************************************************************
 Set the user's NT name.
 ********************************************************************/

BOOL pdb_set_nt_username(SAM_ACCOUNT *sampass, const char *nt_username, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	if (nt_username) { 
		DEBUG(10, ("pdb_set_nt_username: setting nt username %s, was %s\n", nt_username,
			(sampass->private.nt_username)?(sampass->private.nt_username):"NULL"));
 
		sampass->private.nt_username = talloc_strdup(sampass->mem_ctx, nt_username);
		
		if (!sampass->private.nt_username) {
			DEBUG(0, ("pdb_set_nt_username: talloc_strdup() failed!\n"));
			return False;
		}

	} else {
		sampass->private.nt_username = PDB_NOT_QUITE_NULL;
	}

	return pdb_set_init_flags(sampass, PDB_NTUSERNAME, flag);
}

/*********************************************************************
 Set the user's full name.
 ********************************************************************/

BOOL pdb_set_fullname(SAM_ACCOUNT *sampass, const char *full_name, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	if (full_name) { 
		DEBUG(10, ("pdb_set_full_name: setting full name %s, was %s\n", full_name,
			(sampass->private.full_name)?(sampass->private.full_name):"NULL"));
	
		sampass->private.full_name = talloc_strdup(sampass->mem_ctx, full_name);

		if (!sampass->private.full_name) {
			DEBUG(0, ("pdb_set_fullname: talloc_strdup() failed!\n"));
			return False;
		}

	} else {
		sampass->private.full_name = PDB_NOT_QUITE_NULL;
	}

	return pdb_set_init_flags(sampass, PDB_FULLNAME, flag);
}

/*********************************************************************
 Set the user's logon script.
 ********************************************************************/

BOOL pdb_set_logon_script(SAM_ACCOUNT *sampass, const char *logon_script, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	if (logon_script) { 
		DEBUG(10, ("pdb_set_logon_script: setting logon script %s, was %s\n", logon_script,
			(sampass->private.logon_script)?(sampass->private.logon_script):"NULL"));
 
		sampass->private.logon_script = talloc_strdup(sampass->mem_ctx, logon_script);

		if (!sampass->private.logon_script) {
			DEBUG(0, ("pdb_set_logon_script: talloc_strdup() failed!\n"));
			return False;
		}

	} else {
		sampass->private.logon_script = PDB_NOT_QUITE_NULL;
	}
	
	return pdb_set_init_flags(sampass, PDB_LOGONSCRIPT, flag);
}

/*********************************************************************
 Set the user's profile path.
 ********************************************************************/

BOOL pdb_set_profile_path (SAM_ACCOUNT *sampass, const char *profile_path, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	if (profile_path) { 
		DEBUG(10, ("pdb_set_profile_path: setting profile path %s, was %s\n", profile_path,
			(sampass->private.profile_path)?(sampass->private.profile_path):"NULL"));
 
		sampass->private.profile_path = talloc_strdup(sampass->mem_ctx, profile_path);
		
		if (!sampass->private.profile_path) {
			DEBUG(0, ("pdb_set_profile_path: talloc_strdup() failed!\n"));
			return False;
		}

	} else {
		sampass->private.profile_path = PDB_NOT_QUITE_NULL;
	}

	return pdb_set_init_flags(sampass, PDB_PROFILE, flag);
}

/*********************************************************************
 Set the user's directory drive.
 ********************************************************************/

BOOL pdb_set_dir_drive (SAM_ACCOUNT *sampass, const char *dir_drive, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	if (dir_drive) { 
		DEBUG(10, ("pdb_set_dir_drive: setting dir drive %s, was %s\n", dir_drive,
			(sampass->private.dir_drive)?(sampass->private.dir_drive):"NULL"));
 
		sampass->private.dir_drive = talloc_strdup(sampass->mem_ctx, dir_drive);
		
		if (!sampass->private.dir_drive) {
			DEBUG(0, ("pdb_set_dir_drive: talloc_strdup() failed!\n"));
			return False;
		}

	} else {
		sampass->private.dir_drive = PDB_NOT_QUITE_NULL;
	}
	
	return pdb_set_init_flags(sampass, PDB_DRIVE, flag);
}

/*********************************************************************
 Set the user's home directory.
 ********************************************************************/

BOOL pdb_set_homedir (SAM_ACCOUNT *sampass, const char *home_dir, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	if (home_dir) { 
		DEBUG(10, ("pdb_set_homedir: setting home dir %s, was %s\n", home_dir,
			(sampass->private.home_dir)?(sampass->private.home_dir):"NULL"));
 
		sampass->private.home_dir = talloc_strdup(sampass->mem_ctx, home_dir);
		
		if (!sampass->private.home_dir) {
			DEBUG(0, ("pdb_set_home_dir: talloc_strdup() failed!\n"));
			return False;
		}

	} else {
		sampass->private.home_dir = PDB_NOT_QUITE_NULL;
	}

	return pdb_set_init_flags(sampass, PDB_SMBHOME, flag);
}

/*********************************************************************
 Set the user's unix home directory.
 ********************************************************************/

BOOL pdb_set_unix_homedir (SAM_ACCOUNT *sampass, const char *unix_home_dir, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	if (unix_home_dir) { 
		DEBUG(10, ("pdb_set_unix_homedir: setting home dir %s, was %s\n", unix_home_dir,
			(sampass->private.unix_home_dir)?(sampass->private.unix_home_dir):"NULL"));
 
		sampass->private.unix_home_dir = talloc_strdup(sampass->mem_ctx, 
							  unix_home_dir);
		
		if (!sampass->private.unix_home_dir) {
			DEBUG(0, ("pdb_set_unix_home_dir: talloc_strdup() failed!\n"));
			return False;
		}

	} else {
		sampass->private.unix_home_dir = PDB_NOT_QUITE_NULL;
	}

	return pdb_set_init_flags(sampass, PDB_UNIXHOMEDIR, flag);
}

/*********************************************************************
 Set the user's account description.
 ********************************************************************/

BOOL pdb_set_acct_desc (SAM_ACCOUNT *sampass, const char *acct_desc, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	if (acct_desc) { 
		sampass->private.acct_desc = talloc_strdup(sampass->mem_ctx, acct_desc);

		if (!sampass->private.acct_desc) {
			DEBUG(0, ("pdb_set_acct_desc: talloc_strdup() failed!\n"));
			return False;
		}

	} else {
		sampass->private.acct_desc = PDB_NOT_QUITE_NULL;
	}

	return pdb_set_init_flags(sampass, PDB_ACCTDESC, flag);
}

/*********************************************************************
 Set the user's workstation allowed list.
 ********************************************************************/

BOOL pdb_set_workstations (SAM_ACCOUNT *sampass, const char *workstations, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	if (workstations) { 
		DEBUG(10, ("pdb_set_workstations: setting workstations %s, was %s\n", workstations,
			(sampass->private.workstations)?(sampass->private.workstations):"NULL"));
 
		sampass->private.workstations = talloc_strdup(sampass->mem_ctx, workstations);

		if (!sampass->private.workstations) {
			DEBUG(0, ("pdb_set_workstations: talloc_strdup() failed!\n"));
			return False;
		}

	} else {
		sampass->private.workstations = PDB_NOT_QUITE_NULL;
	}

	return pdb_set_init_flags(sampass, PDB_WORKSTATIONS, flag);
}

/*********************************************************************
 Set the user's 'unknown_str', whatever the heck this actually is...
 ********************************************************************/

BOOL pdb_set_unknown_str (SAM_ACCOUNT *sampass, const char *unknown_str, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	if (unknown_str) { 
		sampass->private.unknown_str = talloc_strdup(sampass->mem_ctx, unknown_str);
		
		if (!sampass->private.unknown_str) {
			DEBUG(0, ("pdb_set_unknown_str: talloc_strdup() failed!\n"));
			return False;
		}

	} else {
		sampass->private.unknown_str = PDB_NOT_QUITE_NULL;
	}

	return pdb_set_init_flags(sampass, PDB_UNKNOWNSTR, flag);
}

/*********************************************************************
 Set the user's dial string.
 ********************************************************************/

BOOL pdb_set_munged_dial (SAM_ACCOUNT *sampass, const char *munged_dial, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	if (munged_dial) { 
		sampass->private.munged_dial = talloc_strdup(sampass->mem_ctx, munged_dial);
		
		if (!sampass->private.munged_dial) {
			DEBUG(0, ("pdb_set_munged_dial: talloc_strdup() failed!\n"));
			return False;
		}

	} else {
		sampass->private.munged_dial = PDB_NOT_QUITE_NULL;
	}

	return pdb_set_init_flags(sampass, PDB_MUNGEDDIAL, flag);
}

/*********************************************************************
 Set the user's NT hash.
 ********************************************************************/

BOOL pdb_set_nt_passwd (SAM_ACCOUNT *sampass, const uint8 pwd[NT_HASH_LEN], enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	data_blob_clear_free(&sampass->private.nt_pw);
	
       if (pwd) {
               sampass->private.nt_pw = data_blob(pwd, NT_HASH_LEN);
       } else {
               sampass->private.nt_pw = data_blob(NULL, 0);
       }

	return pdb_set_init_flags(sampass, PDB_NTPASSWD, flag);
}

/*********************************************************************
 Set the user's LM hash.
 ********************************************************************/

BOOL pdb_set_lanman_passwd (SAM_ACCOUNT *sampass, const uint8 pwd[LM_HASH_LEN], enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	data_blob_clear_free(&sampass->private.lm_pw);
	
       if (pwd) {
               sampass->private.lm_pw = data_blob(pwd, LM_HASH_LEN);
       } else {
               sampass->private.lm_pw = data_blob(NULL, 0);
       }

	return pdb_set_init_flags(sampass, PDB_LMPASSWD, flag);
}

/*********************************************************************
 Set the user's plaintext password only (base procedure, see helper
 below)
 ********************************************************************/

BOOL pdb_set_plaintext_pw_only (SAM_ACCOUNT *sampass, const char *password, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	if (password) { 
		if (sampass->private.plaintext_pw!=NULL) 
			memset(sampass->private.plaintext_pw,'\0',strlen(sampass->private.plaintext_pw)+1);

		sampass->private.plaintext_pw = talloc_strdup(sampass->mem_ctx, password);
		
		if (!sampass->private.plaintext_pw) {
			DEBUG(0, ("pdb_set_unknown_str: talloc_strdup() failed!\n"));
			return False;
		}

	} else {
		sampass->private.plaintext_pw = NULL;
	}

	return pdb_set_init_flags(sampass, PDB_PLAINTEXT_PW, flag);
}

BOOL pdb_set_fields_present (SAM_ACCOUNT *sampass, uint32 fields_present, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	sampass->private.fields_present = fields_present;
	
	return pdb_set_init_flags(sampass, PDB_FIELDS_PRESENT, flag);
}

BOOL pdb_set_bad_password_count(SAM_ACCOUNT *sampass, uint16 bad_password_count, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	sampass->private.bad_password_count = bad_password_count;

	return pdb_set_init_flags(sampass, PDB_BAD_PASSWORD_COUNT, flag);
}

BOOL pdb_set_logon_count(SAM_ACCOUNT *sampass, uint16 logon_count, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	sampass->private.logon_count = logon_count;

	return pdb_set_init_flags(sampass, PDB_LOGON_COUNT, flag);
}

BOOL pdb_set_unknown_6 (SAM_ACCOUNT *sampass, uint32 unkn, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	sampass->private.unknown_6 = unkn;

	return pdb_set_init_flags(sampass, PDB_UNKNOWN6, flag);
}

BOOL pdb_set_hours (SAM_ACCOUNT *sampass, const uint8 *hours, enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	if (!hours) {
		memset ((char *)sampass->private.hours, 0, MAX_HOURS_LEN);
		return True;
	}
	
	memcpy (sampass->private.hours, hours, MAX_HOURS_LEN);

	return pdb_set_init_flags(sampass, PDB_HOURS, flag);
}

BOOL pdb_set_backend_private_data (SAM_ACCOUNT *sampass, void *private_data, 
				   void (*free_fn)(void **), 
				   const struct pdb_methods *my_methods, 
				   enum pdb_value_state flag)
{
	if (!sampass)
		return False;

	if (sampass->private.backend_private_data && sampass->private.backend_private_data_free_fn) {
		sampass->private.backend_private_data_free_fn(&sampass->private.backend_private_data);
	}

	sampass->private.backend_private_data = private_data;
	sampass->private.backend_private_data_free_fn = free_fn;
	sampass->private.backend_private_methods = my_methods;

	return pdb_set_init_flags(sampass, PDB_BACKEND_PRIVATE_DATA, flag);
}


/* Helpful interfaces to the above */

/*********************************************************************
 Sets the last changed times and must change times for a normal
 password change.
 ********************************************************************/

BOOL pdb_set_pass_changed_now (SAM_ACCOUNT *sampass)
{
	uint32 expire;
	uint32 min_age;

	if (!sampass)
		return False;
	
	if (!pdb_set_pass_last_set_time (sampass, time(NULL), PDB_CHANGED))
		return False;

	if (!account_policy_get(AP_MAX_PASSWORD_AGE, &expire) 
	    || (expire==(uint32)-1) || (expire == 0)) {
		if (!pdb_set_pass_must_change_time (sampass, get_time_t_max(), PDB_CHANGED))
			return False;
	} else {
		if (!pdb_set_pass_must_change_time (sampass, 
						    pdb_get_pass_last_set_time(sampass)
						    + expire, PDB_CHANGED))
			return False;
	}
	
	if (!account_policy_get(AP_MIN_PASSWORD_AGE, &min_age) 
	    || (min_age==(uint32)-1)) {
		if (!pdb_set_pass_can_change_time (sampass, 0, PDB_CHANGED))
			return False;
	} else {
		if (!pdb_set_pass_can_change_time (sampass, 
						    pdb_get_pass_last_set_time(sampass)
						    + min_age, PDB_CHANGED))
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
	
	/* Calculate the MD4 hash (NT compatible) of the password */
	E_md4hash(plaintext, new_nt_p16);

	if (!pdb_set_nt_passwd (sampass, new_nt_p16, PDB_CHANGED)) 
		return False;

	if (!E_deshash(plaintext, new_lanman_p16)) {
		/* E_deshash returns false for 'long' passwords (> 14
		   DOS chars).  This allows us to match Win2k, which
		   does not store a LM hash for these passwords (which
		   would reduce the effective password length to 14 */

		if (!pdb_set_lanman_passwd (sampass, NULL, PDB_CHANGED)) 
			return False;
	} else {
		if (!pdb_set_lanman_passwd (sampass, new_lanman_p16, PDB_CHANGED)) 
			return False;
	}

	if (!pdb_set_plaintext_pw_only (sampass, plaintext, PDB_CHANGED)) 
		return False;

	if (!pdb_set_pass_changed_now (sampass))
		return False;

	return True;
}

/* check for any PDB_SET/CHANGED field and fill the appropriate mask bit */
uint32 pdb_build_fields_present (SAM_ACCOUNT *sampass)
{
	/* value set to all for testing */
	return 0x00ffffff;
}
