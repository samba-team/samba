/*
 * Unix SMB/Netbios implementation. Version 1.9. SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1998 Modified by Jeremy Allison 1995.
 * Copyright (C) Elrond 2000
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"
#include "sids.h"

#ifdef USE_SMBPASS_DB

extern int DEBUGLEVEL;

/***************************************************************
 Start to enumerate the smbpasswd list. Returns a void pointer
 to ensure no modification outside this module.
****************************************************************/

static void *startsamfilepwent(BOOL update)
{
	return startsmbpwent(update);
}

/***************************************************************
 End enumeration of the smbpasswd list.
****************************************************************/

static void endsamfilepwent(void *vp)
{
	endsmbpwent(vp);
}

/*************************************************************************
 Return the current position in the smbpasswd list as an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/

static SMB_BIG_UINT getsamfilepwpos(void *vp)
{
	return getsmbpwpos(vp);
}

/*************************************************************************
 Set the current position in the smbpasswd list from an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/

static BOOL setsamfilepwpos(void *vp, SMB_BIG_UINT tok)
{
	return setsmbpwpos(vp, tok);
}

static BOOL string_empty (const char *str)
{
  return str == NULL || *str == '\0';
}

  
/*************************************************************************
 Routine to return the next entry in the smbpasswd list.
 this function is a nice, messy combination of reading:
 - the smbpasswd file
 - the unix password database
 - smb.conf options (not done at present).
 *************************************************************************/

static struct sam_passwd *getsamfile21pwent(void *vp)
{
	struct sam_passwd *user;
	user_struct bogus_user_struct;
#if 0
	user_struct *vuser;
#endif

	static pstring full_name;
	static pstring home_dir;
	static pstring home_drive;
	static pstring logon_script;
	static pstring profile_path;
	static pstring acct_desc;
	static pstring workstations;

	DEBUG(5,("getsamfile21pwent\n"));

        ZERO_STRUCT(bogus_user_struct);

	user = pwdb_smb_to_sam(pwdb_smb_map_names(getsmbfilepwent(vp)));
	if (user == NULL)
	{
		return NULL;
	}

	/*
	 * get all the other gubbins we need.  substitute unix name for %U
	 */

#if 0
	vuser = get_valid_user_struct(get_sec_ctx());
#endif

	/* HACK to make %U work in substitutions below */
	fstrcpy(bogus_user_struct.requested_name, user->nt_name);
	fstrcpy(bogus_user_struct.unix_name     , user->unix_name);
	DEBUG(7, ("getsamfile21pwent: nt_name=%s, unix_name=%s\n",
		  user->nt_name, user->unix_name));
 
  	pstrcpy(full_name    , "");
 	pstrcpy(logon_script , lp_logon_script (&bogus_user_struct));
 	pstrcpy(profile_path , lp_logon_path (&bogus_user_struct));
 	pstrcpy(home_drive   , lp_logon_drive (&bogus_user_struct));
 	pstrcpy(home_dir     , lp_logon_home (&bogus_user_struct));
  	pstrcpy(acct_desc    , "");
  	pstrcpy(workstations , "");

#if 0
	vuid_free_user_struct(vuser);
#endif

	/* 
	   only overwrite values with defaults IIF specific backend
	   didn't filled the values
	*/ 

	if (string_empty (user->full_name))
		user->full_name    = full_name;
	if (string_empty (user->home_dir))
		user->home_dir     = home_dir;
	if (string_empty (user->dir_drive))
		user->dir_drive    = home_drive;
	if (string_empty (user->logon_script))
		user->logon_script = logon_script;
	if (string_empty (user->profile_path))
		user->profile_path = profile_path;
	if (string_empty (user->acct_desc))
		user->acct_desc    = acct_desc;
	if (string_empty (user->workstations))
		user->workstations = workstations;

	user->unknown_str = NULL; /* don't know, yet! */
	user->munged_dial = NULL; /* "munged" dial-back telephone number */

	user->unknown_3 = 0xffffff; /* don't know */
	user->logon_divs = 168; /* hours per week */
	user->hours_len = 21; /* 21 times 8 bits = 168 */
	memset(user->hours, 0xff, user->hours_len); /* available at all hours */
	user->unknown_5 = 0x00020000; /* don't know */
	user->unknown_6 = 0x000004ec; /* don't know */

	return user;
}

/************************************************************************
search sam db by uid.
*************************************************************************/
static struct sam_passwd *getsamfilepwuid(uid_t uid)
{
	struct sam_passwd *pwd = NULL;
	void *fp = NULL;

	DEBUG(10, ("search by uid: %x\n", (int)uid));

	/* Open the smb password file - not for update. */
	fp = startsam21pwent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open sam password database.\n"));
		return NULL;
	}

	while ((pwd = getsamfile21pwent(fp)) != NULL && pwd->unix_uid != uid)
	{
	}

	if (pwd != NULL)
	{
		DEBUG(10, ("found by unix_uid: %x\n", (int)uid));
	}

	endsam21pwent(fp);

	return pwd;
}

/************************************************************************
search sam db by rid.
*************************************************************************/
static struct sam_passwd *getsamfilepwrid(uint32 user_rid)
{
	DOM_NAME_MAP gmep;
	DOM_SID sid;
	sid_copy(&sid, &global_sam_sid);
	sid_append_rid(&sid, user_rid);

	if (!lookupsmbpwsid(&sid, &gmep))
	{
		return NULL;
	}

	return getsamfilepwuid((uid_t)gmep.unix_id);
}

/************************************************************************
search sam db by nt name.
*************************************************************************/
static struct sam_passwd *getsamfilepwntnam(const char *nt_name)
{
	DOM_NAME_MAP gmep;

	if (!lookupsmbpwntnam(nt_name, &gmep))
	{
		return NULL;
	}

	return getsamfilepwuid((uid_t)gmep.unix_id);
}

/*
 * Stub functions - implemented in terms of others.
 */

static BOOL mod_samfile21pwd_entry(struct sam_passwd* pwd, BOOL override)
{
 	return mod_smbpwd_entry(pwdb_sam_to_smb(pwd), override);
}

static BOOL add_samfile21pwd_entry(struct sam_passwd *newpwd)
{
 	return add_smbpwd_entry(pwdb_sam_to_smb(newpwd));
}

static struct sam_disp_info *getsamfiledispntnam(const char *ntname)
{
	return pwdb_sam_to_dispinfo(getsam21pwntnam(ntname));
}

static struct sam_disp_info *getsamfiledisprid(uint32 rid)
{
	return pwdb_sam_to_dispinfo(getsam21pwrid(rid));
}

static struct sam_disp_info *getsamfiledispent(void *vp)
{
	return pwdb_sam_to_dispinfo(getsam21pwent(vp));
}

static struct sam_passdb_ops sam_file_ops =
{
	startsamfilepwent,
	endsamfilepwent,
	getsamfilepwpos,
	setsamfilepwpos,
	getsamfilepwntnam,
	getsamfilepwuid,
	getsamfilepwrid, 
	getsamfile21pwent,
	add_samfile21pwd_entry,
	mod_samfile21pwd_entry,
	getsamfiledispntnam,
	getsamfiledisprid,
	getsamfiledispent
};

struct sam_passdb_ops *file_initialise_sam_password_db(void)
{    
  return &sam_file_ops;
}

#else
 /* Do *NOT* make this function static. It breaks the compile on gcc. JRA */
 void sampass_dummy_function(void) { } /* stop some compilers complaining */
#endif /* USE_SMBPASS_DB */
