/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
   Copyright (C) Jeremy Allison 1996-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
      
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
#include "nterr.h"
#include "sids.h"

extern int DEBUGLEVEL;

/*
 * NOTE. All these functions are abstracted into a structure
 * that points to the correct function for the selected database. JRA.
 *
 * NOTE.  for the get/mod/add functions, there are two sets of functions.
 * one supports struct sam_passwd, the other supports struct smb_passwd.
 * for speed optimisation it is best to support both these sets.
 * 
 * it is, however, optional to support one set but not the other: there
 * is conversion-capability built in to passdb.c, and run-time error
 * detection for when neither are supported.
 * 
 * password database writers are recommended to implement the sam_passwd
 * functions in a first pass, as struct sam_passwd contains more
 * information, needed by the NT Domain support.
 * 
 * an API writer is expected to create either one set (struct smb_passwd) or
 * the other (struct sam_passwd) OR both, and optionally also to write display
 * info routines * (struct sam_disp_info).  functions which the API writer
 * chooses NOT to write must be wrapped in conversion functions (pwdb_x_to_y)
 * such that API users can call any function and still get valid results.
 *
 * the password API does NOT fill in the gaps if you set an API function
 * to NULL: it will deliberately attempt to call the NULL function.
 *
 */

static struct sam_passdb_ops *pwdb_ops;

/***************************************************************
 Initialise the password db operations.
***************************************************************/

BOOL initialise_sam_password_db(void)
{
  if (pwdb_ops)
  {
    return True;
  }

#ifdef WITH_NISPLUS
  pwdb_ops =  nisplus_initialise_sam_password_db();
#elif defined(WITH_LDAP)
  pwdb_ops = ldap_initialise_sam_password_db();
#elif defined(HAVE_MYSQL_H) && defined(WITH_MYSQLSAM)
  pwdb_ops = mysql_initialise_sam_password_db();
#elif defined(USE_SMBPASS_DB)
  pwdb_ops = file_initialise_sam_password_db();
#endif 

  return (pwdb_ops != NULL);
}

/*
 * Functions that return/manipulate a struct sam_passwd.
 */

/***************************************************************
 Start to enumerate the smb or sam passwd list. Returns a void pointer
 to ensure no modification outside this module.

 Note that currently it is being assumed that a pointer returned
 from this function may be used to enumerate struct sam_passwd
 entries as well as struct smb_passwd entries. This may need
 to change. JRA.

****************************************************************/

void *startsam21pwent(BOOL update)
{
  return pwdb_ops->startsam21pwent(update);
}

/***************************************************************
 End enumeration of the sam passwd list.

 Note that currently it is being assumed that a pointer returned
 from this function may be used to enumerate struct sam_passwd
 entries as well as struct smb_passwd entries. This may need
 to change. JRA.

****************************************************************/

void endsam21pwent(void *vp)
{
  pwdb_ops->endsam21pwent(vp);
}

/*************************************************************************
 Routine to return the next entry in the smb passwd list.
 *************************************************************************/

struct sam_passwd *getsam21pwent(void *vp)
{
	return pwdb_sam_map_names(pwdb_ops->getsam21pwent(vp));
}

/************************************************************************
 Routine to search the smb passwd file for an entry matching the username.
 and then modify its password entry. We can't use the startsampwent()/
 getsampwent()/endsampwent() interfaces here as we depend on looking
 in the actual file to decide how much room we have to write data.
 override = False, normal
 override = True, override XXXXXXXX'd out password or NO PASS
************************************************************************/

BOOL mod_sam21pwd_entry(struct sam_passwd* pwd, BOOL override)
{
	struct sam_passwd *mapped;

	DEBUG(10,("mod_sam21pwd_entry: unix user %s rid %d\n", 
		pwd->unix_name, pwd->user_rid));

	mapped = pwdb_sam_map_names(pwd);
	if (mapped != NULL)
	{
		return pwdb_ops->mod_sam21pwd_entry(mapped, override);
	}
	return False;
}

/************************************************************************
 Utility function to search sam passwd by name.  use this if your database
 does not have search facilities.
*************************************************************************/

struct sam_passwd *iterate_getsam21pwntnam(const char *ntname)
{
	fstring nt_name;
	struct sam_passwd *pwd = NULL;
	void *fp = NULL;

	DEBUG(10, ("search by name: %s\n", ntname));

	fstrcpy(nt_name, ntname);

	/* Open the smb password database - not for update. */
	fp = startsmbpwent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open sam password database.\n"));
		return NULL;
	}

	while ((pwd = getsam21pwent(fp)) != NULL && !strequal(pwd->nt_name, nt_name))
	{
		DEBUG(10, ("iterate: %s 0x%x\n", pwd->nt_name, pwd->user_rid));
	}

	if (pwd != NULL)
	{
		DEBUG(10, ("found by name: %s\n", nt_name));
	}

	endsmbpwent(fp);
	return pwd;
}

/************************************************************************
 Utility function to search sam passwd by rid.  use this if your database
 does not have search facilities.

 search capability by both rid and uid are needed as the rid <-> uid
 mapping may be non-monotonic.  

*************************************************************************/

struct sam_passwd *iterate_getsam21pwrid(uint32 rid)
{
	struct sam_passwd *pwd = NULL;
	void *fp = NULL;

	DEBUG(10, ("search by rid: %x\n", rid));

	/* Open the smb password file - not for update. */
	fp = startsmbpwent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open sam password database.\n"));
		return NULL;
	}

	while ((pwd = getsam21pwent(fp)) != NULL && pwd->user_rid != rid)
	{
		DEBUG(10, ("iterate: %s 0x%x\n", pwd->nt_name, pwd->user_rid));
	}

	if (pwd != NULL)
	{
		DEBUG(10, ("found by user_rid: %x\n", rid));
	}

	endsmbpwent(fp);
	return pwd;
}

/************************************************************************
 Utility function to search sam passwd by uid.  use this if your database
 does not have search facilities.

 search capability by both rid and uid are needed as the rid <-> uid
 mapping may be non-monotonic.  

*************************************************************************/

struct sam_passwd *iterate_getsam21pwuid(uid_t uid)
{
	struct sam_passwd *pwd = NULL;
	void *fp = NULL;

	DEBUG(10, ("search by uid: %x\n", (int)uid));

	/* Open the smb password file - not for update. */
	fp = startsmbpwent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open sam password database.\n"));
		return NULL;
	}

	while ((pwd = getsam21pwent(fp)) != NULL && pwd->unix_uid != uid)
	{
	}

	if (pwd != NULL)
	{
		DEBUG(10, ("found by unix_uid: %x\n", (int)uid));
	}

	endsmbpwent(fp);
	return pwd;
}

/*************************************************************************
 Routine to return a display info structure, by rid
 *************************************************************************/
struct sam_disp_info *getsamdisprid(uint32 rid)
{
	return pwdb_ops->getsamdisprid(rid);
}

/************************************************************************
 Routine to search sam passwd by name.
*************************************************************************/

struct sam_passwd *getsam21pwntnam(const char *name)
{
	return pwdb_sam_map_names(pwdb_ops->getsam21pwntnam(name));
}

/************************************************************************
 Routine to search sam passwd by rid.  
*************************************************************************/

struct sam_passwd *getsam21pwrid(uint32 rid)
{
	return pwdb_sam_map_names(pwdb_ops->getsam21pwrid(rid));
}


/**********************************************************
 **********************************************************

 utility routines which are likely to be useful to all password
 databases

 **********************************************************
 **********************************************************/

/*************************************************************
 initialises a struct sam_disp_info.
 **************************************************************/

static void pwdb_init_dispinfo(struct sam_disp_info *user)
{
	if (user == NULL) return;
	bzero(user, sizeof(*user));
	user->user_rid = 0xffffffff;
}

/*************************************************************
 initialises a struct sam_passwd.
 **************************************************************/
void pwdb_init_sam(struct sam_passwd *user)
{
	if (user == NULL) return;
	bzero(user, sizeof(*user));

	init_nt_time(&user->logon_time);
	init_nt_time(&user->logoff_time);
	init_nt_time(&user->kickoff_time);
	init_nt_time(&user->pass_last_set_time);
	init_nt_time(&user->pass_can_change_time);
	init_nt_time(&user->pass_must_change_time);

	user->unix_uid = (uid_t)-1;
	user->unix_gid = (gid_t)-1;
	user->user_rid  = 0xffffffff;
	user->group_rid = 0xffffffff;
}

/*************************************************************************
 Routine to return the next entry in the sam passwd list.
 *************************************************************************/

struct sam_disp_info *pwdb_sam_to_dispinfo(struct sam_passwd *user)
{
	static struct sam_disp_info disp_info;

	if (user == NULL) return NULL;

	pwdb_init_dispinfo(&disp_info);

	disp_info.nt_name   = user->nt_name;
	disp_info.full_name = user->full_name;
	disp_info.user_rid  = user->user_rid;

	return &disp_info;
}

static void select_name(fstring *string, char **name, const UNISTR2 *from)
{
	if (from->buffer != 0)
	{
		unistr2_to_ascii(*string, from, sizeof(*string));
		*name = *string;
	}
}

/*************************************************************
 copies a sam passwd.
 **************************************************************/
void copy_id23_to_sam_passwd(struct sam_passwd *to, const SAM_USER_INFO_23 *from)
{
	static fstring nt_name;
	static fstring full_name;
	static fstring home_dir;
	static fstring dir_drive;
	static fstring logon_script;
	static fstring profile_path;
	static fstring acct_desc;
	static fstring workstations;
	static fstring unknown_str;
	static fstring munged_dial;

	if (from == NULL || to == NULL) return;

	to->logon_time = from->logon_time;
	to->logoff_time = from->logoff_time;
	to->kickoff_time = from->kickoff_time;
	to->pass_last_set_time = from->pass_last_set_time;
	to->pass_can_change_time = from->pass_can_change_time;
	to->pass_must_change_time = from->pass_must_change_time;

	select_name(&nt_name     , &to->nt_name     , &from->uni_user_name   );
	select_name(&full_name   , &to->full_name   , &from->uni_full_name   );
	select_name(&home_dir    , &to->home_dir    , &from->uni_home_dir    );
	select_name(&dir_drive   , &to->dir_drive   , &from->uni_dir_drive   );
	select_name(&logon_script, &to->logon_script, &from->uni_logon_script);
	select_name(&profile_path, &to->profile_path, &from->uni_profile_path);
	select_name(&acct_desc   , &to->acct_desc   , &from->uni_acct_desc   );
	select_name(&workstations, &to->workstations, &from->uni_workstations);
	select_name(&unknown_str , &to->unknown_str , &from->uni_unknown_str );
	select_name(&munged_dial , &to->munged_dial , &from->uni_munged_dial );

	to->unix_uid = (uid_t)-1;
	to->unix_gid = (gid_t)-1;
	to->user_rid = from->user_rid;
	to->group_rid = from->group_rid;

	to->smb_passwd = NULL;
	to->smb_nt_passwd = NULL;

	to->acct_ctrl = from->acb_info;
	to->unknown_3 = from->unknown_3;

	to->logon_divs = from->logon_divs;
	to->hours_len = from->logon_hrs.len;
	memcpy(to->hours, from->logon_hrs.hours, MAX_HOURS_LEN);

	to->unknown_5 = from->unknown_5;
#if 0
	to->unknown_6 = from->unknown_6;
#endif
}


/*************************************************************
 copies a sam passwd.
 **************************************************************/
void copy_sam_passwd(struct sam_passwd *to, const struct sam_passwd *from)
{
	static fstring nt_name;
	static fstring unix_name;
	static fstring full_name;
	static fstring home_dir;
	static fstring dir_drive;
	static fstring logon_script;
	static fstring profile_path;
	static fstring acct_desc;
	static fstring workstations;
	static fstring unknown_str;
	static fstring munged_dial;

	if (from == NULL || to == NULL) return;

	memcpy(to, from, sizeof(*from));

	if (from->nt_name != NULL)
	{
		fstrcpy(nt_name  , from->nt_name);
		to->nt_name = nt_name;
	}
	else if (to->nt_name != NULL)
	{
		fstrcpy(nt_name  , to->nt_name);
		to->nt_name = nt_name;
	}

	if (from->unix_name != NULL)
	{
		fstrcpy(unix_name, from->unix_name);
		to->unix_name = unix_name;
	}
	else if (to->unix_name != NULL)
	{
		fstrcpy(unix_name, to->unix_name);
		to->unix_name = unix_name;
	}

	if (from->full_name != NULL)
	{
		fstrcpy(full_name, from->full_name);
		to->full_name = full_name;
	}
	else if (to->full_name != NULL)
	{
		fstrcpy(full_name, to->full_name);
		to->full_name = full_name;
	}

	if (from->home_dir != NULL)
	{
		fstrcpy(home_dir  , from->home_dir);
		to->home_dir = home_dir;
	}
	else if (to->home_dir != NULL)
	{
		fstrcpy(home_dir  , to->home_dir);
		to->home_dir = home_dir;
	}

	if (from->dir_drive != NULL)
	{
		fstrcpy(dir_drive  , from->dir_drive);
		to->dir_drive = dir_drive;
	}
	else if (to->dir_drive != NULL)
	{
		fstrcpy(dir_drive  , to->dir_drive);
		to->dir_drive = dir_drive;
	}

	if (from->logon_script != NULL)
	{
		fstrcpy(logon_script  , from->logon_script);
		to->logon_script = logon_script;
	}
	else if (to->logon_script != NULL)
	{
		fstrcpy(logon_script  , to->logon_script);
		to->logon_script = logon_script;
	}

	if (from->profile_path != NULL)
	{
		fstrcpy(profile_path  , from->profile_path);
		to->profile_path = profile_path;
	}
	else if (to->profile_path != NULL)
	{
		fstrcpy(profile_path  , to->profile_path);
		to->profile_path = profile_path;
	}

	if (from->acct_desc != NULL)
	{
		fstrcpy(acct_desc  , from->acct_desc);
		to->acct_desc = acct_desc;
	}
	else if (to->acct_desc != NULL)
	{
		fstrcpy(acct_desc  , to->acct_desc);
		to->acct_desc = acct_desc;
	}

	if (from->workstations != NULL)
	{
		fstrcpy(workstations  , from->workstations);
		to->workstations = workstations;
	}
	else if (to->workstations != NULL)
	{
		fstrcpy(workstations  , to->workstations);
		to->workstations = workstations;
	}

	if (from->unknown_str != NULL)
	{
		fstrcpy(unknown_str  , from->unknown_str);
		to->unknown_str = unknown_str;
	}
	else if (to->unknown_str != NULL)
	{
		fstrcpy(unknown_str  , to->unknown_str);
		to->unknown_str = unknown_str;
	}

	if (from->munged_dial != NULL)
	{
		fstrcpy(munged_dial  , from->munged_dial);
		to->munged_dial = munged_dial;
	}
	else if (to->munged_dial != NULL)
	{
		fstrcpy(munged_dial  , to->munged_dial);
		to->munged_dial = munged_dial;
	}
}


/*************************************************************
 converts a sam_passwd structure to a smb_passwd structure.
 **************************************************************/
struct smb_passwd *pwdb_sam_to_smb(struct sam_passwd *user)
{
	static struct smb_passwd pw_buf;
	static fstring nt_name;
	static fstring unix_name;

	if (user == NULL) return NULL;

	pwdb_init_smb(&pw_buf);

	if (user->nt_name != NULL)
	{
		fstrcpy(nt_name  , user->nt_name);
		pw_buf.nt_name = nt_name;
	}
	if (user->unix_name != NULL)
	{
		fstrcpy(unix_name, user->unix_name);
		pw_buf.unix_name = unix_name;
	}
	pw_buf.unix_uid           = user->unix_uid;
	pw_buf.user_rid           = user->user_rid;
	pw_buf.smb_passwd         = user->smb_passwd;
	pw_buf.smb_nt_passwd      = user->smb_nt_passwd;
	pw_buf.acct_ctrl          = user->acct_ctrl;
	pw_buf.pass_last_set_time = nt_time_to_unix(&user->pass_last_set_time);

	return &pw_buf;
}


/*************************************************************
 converts a smb_passwd structure to a sam_passwd structure.
 **************************************************************/
struct sam_passwd *pwdb_smb_to_sam(struct smb_passwd *user)
{
	static struct sam_passwd pw_buf;
	struct passwd *pass=NULL;
	static fstring nt_name;
	static fstring unix_name;
	static pstring unix_gecos;

	static pstring home_dir;
	static pstring home_drive;
	static pstring logon_script;
	static pstring profile_path;
	static pstring acct_desc;
	static pstring workstations;

	if (user == NULL) return NULL;

	pwdb_init_sam(&pw_buf);

	if (user->nt_name != NULL)
	{
		fstrcpy(nt_name  , user->nt_name);
		pw_buf.nt_name = nt_name;
	}
	if (user->unix_name != NULL)
	{
		fstrcpy(unix_name, user->unix_name);
		pw_buf.unix_name = unix_name;
	}
	pw_buf.unix_uid           = user->unix_uid;
	pw_buf.user_rid           = user->user_rid;
	pw_buf.smb_passwd         = user->smb_passwd;
	pw_buf.smb_nt_passwd      = user->smb_nt_passwd;
	pw_buf.acct_ctrl          = user->acct_ctrl;
		
	pass = hashed_getpwnam(unix_name);
	if (pass != NULL)
	{
		pstrcpy(unix_gecos, pass->pw_gecos);
		pw_buf.full_name=unix_gecos;
	}

        if ( user->pass_last_set_time != (time_t)-1 )
        {
		unix_to_nt_time(&pw_buf.pass_last_set_time, user->pass_last_set_time);
		unix_to_nt_time(&pw_buf.pass_can_change_time, user->pass_last_set_time);
	}

	DEBUG(5,("getsamfile21pwent\n"));

	if (pw_buf.home_dir == NULL)
		pw_buf.home_dir     = home_dir;
	if (pw_buf.dir_drive == NULL)
		pw_buf.dir_drive    = home_drive;
	if (pw_buf.logon_script == NULL)
		pw_buf.logon_script = logon_script;
	if (pw_buf.profile_path == NULL)
		pw_buf.profile_path = profile_path;
	if (pw_buf.acct_desc == NULL)
		pw_buf.acct_desc    = acct_desc;
	if (pw_buf.workstations == NULL)
		pw_buf.workstations = workstations;

	return &pw_buf;
}

static BOOL trust_account_warning_done = False;

/*************************************************************
 fills in missing details.  one set of details _must_ exist.
 **************************************************************/
struct sam_passwd *pwdb_sam_map_names(struct sam_passwd *sam)
{
	DOM_NAME_MAP gmep;
	BOOL found = False;
	DOM_SID sid;
	static fstring unix_name;
	static fstring nt_name;

	/*
	 * name details
	 */

	if (sam == NULL)
	{
		DEBUG(10,("pwdb_sam_map_names: NULL\n"));
		return NULL;
	}

	DEBUG(10,("pwdb_sam_map_names: unix %s nt %s unix %d nt%d\n",
	           sam->unix_name != NULL ? sam->unix_name : "NULL",
	           sam->nt_name   != NULL ? sam->nt_name   : "NULL",
	           sam->unix_uid, sam->user_rid));

	if (!found && sam->unix_name != NULL)
	{
		found = lookupsmbpwnam(sam->unix_name, &gmep);
	}
	if (!found && sam->unix_uid  != (uid_t)-1)
	{
		found = lookupsmbpwuid(sam->unix_uid , &gmep);
	}
	if (!found && sam->user_rid != 0xffffffff)
	{
		sid_copy(&sid, &global_sam_sid);
		sid_append_rid(&sid, sam->user_rid);
		found = lookupsmbpwsid  (&sid        , &gmep);
	}
	if (!found && sam->nt_name  != NULL)
	{
		found = lookupsmbpwntnam(sam->nt_name, &gmep);
	}

	if (!found)
	{
		return NULL;
	}

	if (!sid_front_equal(&global_sam_sid, &gmep.sid))
	{
		return NULL;
	}

	fstrcpy(unix_name, gmep.unix_name);
	fstrcpy(nt_name  , gmep.nt_name  );
	if (sam->unix_name == NULL      ) sam->unix_name = unix_name;
	if (sam->nt_name   == NULL      ) sam->nt_name   = nt_name  ;
	if (sam->unix_uid  == (uid_t)-1 ) sam->unix_uid  = (uid_t)gmep.unix_id;
	if (sam->user_rid  == 0xffffffff) sid_split_rid(&gmep.sid, &sam->user_rid);

	DEBUG(10,("pwdb_sam_map_name: found unix user %s nt %s uid %d rid 0x%x\n",
	           sam->unix_name, sam->nt_name, sam->unix_uid, sam->user_rid));

	/*
	 * group details
	 */

	found = False;

	if (sam->unix_gid != (gid_t)-1 && sam->group_rid != 0xffffffff)
	{
		return sam;
	}

	if (sam->unix_gid == (gid_t)-1 && sam->group_rid == 0xffffffff)
	{
		struct passwd *pass = hashed_getpwnam(unix_name);
		if (pass != NULL)
		{
			sam->unix_gid = pass->pw_gid;
		}
		else
		{
			DEBUG(0,("pwdb_sam_map_names: no unix password entry for %s\n",
			          unix_name));
		}
	}

	if (!found && sam->unix_gid  != (gid_t)-1)
	{
		found = lookupsmbgrpgid(sam->unix_gid , &gmep);
	}
	if (!found && sam->group_rid != 0xffffffff)
	{
		sid_copy(&sid, &global_sam_sid);
		sid_append_rid(&sid, sam->group_rid);
		found = lookupsmbgrpsid(&sid        , &gmep);
	}

	if (!found)
	{
		if (IS_BITS_SET_SOME(sam->acct_ctrl, ACB_WSTRUST|ACB_DOMTRUST|ACB_SVRTRUST))
		{
			if (!trust_account_warning_done)
			{
				trust_account_warning_done = True;
				DEBUG(0, ("\
pwdb_sam_map_names: your unix password database appears to have difficulties\n\
resolving trust account %s, probably because it ends in a '$'.\n\
you will get this warning only once (for all trust accounts)\n", unix_name));
			}
			/*
			 * oh, dear.
			 */
			if (sam->unix_gid != (gid_t)-1)
			{
				sam->unix_gid = (gid_t)-1;
			}
			sam->group_rid = DOMAIN_GROUP_RID_USERS;

			return sam;
		}
		else
		{
			DEBUG(0, ("pwdb_sam_map_names: could not find Primary Group for %s\n",
				   unix_name));
			return NULL;
		}
	}

	if (!sid_front_equal(&global_sam_sid, &gmep.sid))
	{
		fstring sid_str;
		sid_to_string(sid_str, &gmep.sid);
		DEBUG(0,("UNIX User %s Primary Group is in the wrong domain! %s\n",
		          sam->unix_name, sid_str));
		return NULL;
	}

	if (sam->unix_gid  == (gid_t)-1 ) sam->unix_gid  = (gid_t)gmep.unix_id;
	if (sam->group_rid == 0xffffffff) sid_split_rid(&gmep.sid, &sam->group_rid);

	DEBUG(10,("pwdb_sam_map_name: found gid %d and group rid 0x%x for unix user %s\n",
	           sam->unix_gid, sam->group_rid, sam->unix_name));

	return sam;
}
