/*
 * Unix SMB/Netbios implementation. Version 1.9. SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1998 Modified by Jeremy Allison 1995.
 * Copyright (C) Benny Holmgren 1998 <bigfoot@astrakan.hgs.se> 
 * Copyright (C) Luke Kenneth Casson Leighton 1996-1998.
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

#ifdef WITH_NISPLUS

#include "includes.h"
#include <rpcsvc/nis.h>

extern int      DEBUGLEVEL;

static int gotalarm;

/***************************************************************

 the fields for the NIS+ table, generated from mknissmbpwtbl.sh, are:

    	name=S,nogw=r 
    	uid=S,nogw=r 
		user_rid=S,nogw=r
		smb_grpid=,nw+r
		group_rid=,nw+r
		acb=,nw+r
		          
    	lmpwd=C,nw=,g=r,o=rm 
    	ntpwd=C,nw=,g=r,o=rm 
		                     
		logon_t=,nw+r 
		logoff_t=,nw+r 
		kick_t=,nw+r 
		pwdlset_t=,nw+r 
		pwdlchg_t=,nw+r 
		pwdmchg_t=,nw+r 
		                
		full_name=,nw+r 
		home_dir=,nw+r 
		dir_drive=,nw+r 
		logon_script=,nw+r 
		profile_path=,nw+r 
		acct_desc=,nw+r 
		workstations=,nw+r 
		                   
		hours=,nw+r 

****************************************************************/

#define NPF_NAME          0
#define NPF_UID           1
#define NPF_USER_RID      2
#define NPF_SMB_GRPID     3
#define NPF_GROUP_RID     4
#define NPF_ACB           5
#define NPF_LMPWD         6
#define NPF_NTPWD         7
#define NPF_LOGON_T       8
#define NPF_LOGOFF_T      9
#define NPF_KICK_T        10
#define NPF_PWDLSET_T     11
#define NPF_PWDLCHG_T     12
#define NPF_PWDMCHG_T     13
#define NPF_FULL_NAME     14
#define NPF_HOME_DIR      15
#define NPF_DIR_DRIVE     16
#define NPF_LOGON_SCRIPT  17
#define NPF_PROFILE_PATH  18
#define NPF_ACCT_DESC     19
#define NPF_WORKSTATIONS  20
#define NPF_HOURS         21

/***************************************************************
 Signal function to tell us we timed out.
****************************************************************/
static void gotalarm_sig(void)
{
  gotalarm = 1;
}

/***************************************************************
 make_nisname_from_user_rid
 ****************************************************************/
static char *make_nisname_from_user_rid(uint32 rid, char *pfile)
{
	static pstring nisname;

	safe_strcpy(nisname, "[user_rid=", sizeof(nisname)-1);
	slprintf(nisname, sizeof(nisname)-1, "%s%d", nisname, rid);
	safe_strcat(nisname, "],", sizeof(nisname)-strlen(nisname)-1);
	safe_strcat(nisname, pfile, sizeof(nisname)-strlen(nisname)-1);

	return nisname;
}

/***************************************************************
 make_nisname_from_uid
 ****************************************************************/
static char *make_nisname_from_uid(int uid, char *pfile)
{
	static pstring nisname;

	safe_strcpy(nisname, "[uid=", sizeof(nisname)-1);
	slprintf(nisname, sizeof(nisname)-1, "%s%d", nisname, uid);
	safe_strcat(nisname, "],", sizeof(nisname)-strlen(nisname)-1);
	safe_strcat(nisname, pfile, sizeof(nisname)-strlen(nisname)-1);

	return nisname;
}

/***************************************************************
 make_nisname_from_name
 ****************************************************************/
static char *make_nisname_from_name(char *user_name, char *pfile)
{
	static pstring nisname;

	safe_strcpy(nisname, "[name=", sizeof(nisname)-1);
	safe_strcat(nisname, user_name, sizeof(nisname) - strlen(nisname) - 1);
	safe_strcat(nisname, "],", sizeof(nisname)-strlen(nisname)-1);
	safe_strcat(nisname, pfile, sizeof(nisname)-strlen(nisname)-1);

	return nisname;
}

/*************************************************************************
 gets a NIS+ attribute
 *************************************************************************/
static void get_single_attribute(nis_object *new_obj, int col,
				char *val, int len)
{
	int entry_len;

	if (new_obj == NULL || val == NULL) return;
	
	entry_len = ENTRY_LEN(new_obj, col);
	if (len > entry_len)
	{
		DEBUG(10,("get_single_attribute: entry length truncated\n"));
		len = entry_len;
	}

	safe_strcpy(val, len, ENTRY_VAL(new_obj, col));
}

/***************************************************************
 calls nis_list, returns results.
 ****************************************************************/
static nis_result *nisp_get_nis_list(char *nis_name)
{
	nis_result *result;
	result = nis_list(nis_name, FOLLOW_PATH|EXPAND_NAME|HARD_LOOKUP,NULL,NULL);

	alarm(0);
	CatchSignal(SIGALRM, SIGNAL_CAST SIG_DFL);

	if (gotalarm)
	{
		DEBUG(0,("nisp_get_nis_list: NIS+ lookup time out\n"));
		nis_freeresult(result);
		return NULL;
	}
	return result;
}



struct nisp_enum_info
{
	nis_result *result;
	int enum_entry;
};

/***************************************************************
 Start to enumerate the nisplus passwd list. Returns a void pointer
 to ensure no modification outside this module.

 do not call this function directly.  use passdb.c instead.

 ****************************************************************/
static void *startnisppwent(BOOL update)
{
	static struct nisp_enum_info res;
	res.result = nisp_get_nis_list(lp_smb_passwd_file());
	res.enum_entry = 0;
	return res.result != NULL ? &res : NULL;
}

/***************************************************************
 End enumeration of the nisplus passwd list.
****************************************************************/
static void endnisppwent(void *vp)
{
}

/*************************************************************************
 Routine to return the next entry in the nisplus passwd list.
 this function is a nice, messy combination of reading:
 - the nisplus passwd file
 - the unix password database
 - nisp.conf options (not done at present).

 do not call this function directly.  use passdb.c instead.

 *************************************************************************/
static struct sam_passwd *getnisp21pwent(void *vp)
{
	return NULL;
}

/*************************************************************************
 Return the current position in the nisplus passwd list as an SMB_BIG_UINT.
 This must be treated as an opaque token.

 do not call this function directly.  use passdb.c instead.

*************************************************************************/
static SMB_BIG_UINT getnisppwpos(void *vp)
{
	return (SMB_BIG_UINT)0;
}

/*************************************************************************
 Set the current position in the nisplus passwd list from SMB_BIG_UINT.
 This must be treated as an opaque token.

 do not call this function directly.  use passdb.c instead.

*************************************************************************/
static BOOL setnisppwpos(void *vp, SMB_BIG_UINT tok)
{
	return False;
}

/*************************************************************************
 sets a NIS+ attribute
 *************************************************************************/
static void set_single_attribute(nis_object *new_obj, int col,
				char *val, int len, int flags)
{
	if (new_obj == NULL) return;

	ENTRY_VAL(new_obj, col) = val;
	ENTRY_LEN(new_obj, col) = len;

	if (flags != 0)
	{
		new_obj->EN_data.en_cols.en_cols_val[col].ec_flags = flags;
	}
}

/************************************************************************
 Routine to add an entry to the nisplus passwd file.

 do not call this function directly.  use passdb.c instead.

*************************************************************************/
static BOOL add_nisp21pwd_entry(struct sam_passwd *newpwd)
{
	char           *pfile;
	char           *nisname;
	nis_result	*nis_user;
	nis_result *result = NULL,
	*tblresult = NULL, 
	*addresult = NULL;
	nis_object new_obj, *obj;

    fstring uid;
	fstring user_rid;
	fstring smb_grpid;
	fstring group_rid;
	fstring acb;
		          
	fstring smb_passwd;
	fstring smb_nt_passwd;

	fstring logon_t;
	fstring logoff_t;
	fstring kickoff_t;
	fstring pwdlset_t;
	fstring pwdlchg_t;
	fstring pwdmchg_t;

	ZERO_STRUCT(logon_t  );
	ZERO_STRUCT(logoff_t );
	ZERO_STRUCT(kickoff_t);
	ZERO_STRUCT(pwdlset_t);
	ZERO_STRUCT(pwdlchg_t);
	ZERO_STRUCT(pwdmchg_t);

	pfile = lp_smb_passwd_file();

	nisname = make_nisname_from_name(newpwd->smb_name, pfile);
	result = nisp_get_nis_list(nisname);
	if (result->status != NIS_SUCCESS && result->status != NIS_NOTFOUND)
	{
		DEBUG(3, ( "add_nisppwd_entry: nis_list failure: %s: %s\n",
		            nisname,  nis_sperrno(result->status)));
		nis_freeresult(nis_user);
		nis_freeresult(result);
		return False;
	}   

	if (result->status == NIS_SUCCESS && NIS_RES_NUMOBJ(result) > 0)
	{
		DEBUG(3, ("add_nisppwd_entry: User already exists in NIS+ password db: %s\n",
		            pfile));
		nis_freeresult(result);
		nis_freeresult(nis_user);
		return False;
	}

#if 0
	/* User not found. */
	if (!add_user)
	{
		DEBUG(3, ("add_nisppwd_entry: User not found in NIS+ password db: %s\n",
		            pfile));
		nis_freeresult(result);
		nis_freeresult(nis_user);
		return False;
	}

#endif

	tblresult = nis_lookup(pfile, FOLLOW_PATH | EXPAND_NAME | HARD_LOOKUP );
	if (tblresult->status != NIS_SUCCESS)
	{
		nis_freeresult(result);
		nis_freeresult(nis_user);
		nis_freeresult(tblresult);
		DEBUG(3, ( "add_nisppwd_entry: nis_lookup failure: %s\n",
		            nis_sperrno(tblresult->status)));
		return False;
	}

	new_obj.zo_name   = NIS_RES_OBJECT(tblresult)->zo_name;
	new_obj.zo_domain = NIS_RES_OBJECT(tblresult)->zo_domain;
	new_obj.zo_owner  = NIS_RES_OBJECT(tblresult)->zo_owner;
	new_obj.zo_group  = NIS_RES_OBJECT(tblresult)->zo_group;
	new_obj.zo_access = NIS_RES_OBJECT(tblresult)->zo_access;
	new_obj.zo_ttl    = NIS_RES_OBJECT(tblresult)->zo_ttl;

	new_obj.zo_data.zo_type = ENTRY_OBJ;

	new_obj.zo_data.objdata_u.en_data.en_type = NIS_RES_OBJECT(tblresult)->zo_data.objdata_u.ta_data.ta_type;
	new_obj.zo_data.objdata_u.en_data.en_cols.en_cols_len = NIS_RES_OBJECT(tblresult)->zo_data.objdata_u.ta_data.ta_maxcol;
	new_obj.zo_data.objdata_u.en_data.en_cols.en_cols_val = calloc(new_obj.zo_data.objdata_u.en_data.en_cols.en_cols_len, sizeof(entry_col));

	pwdb_sethexpwd(smb_passwd   , newpwd->smb_passwd   , newpwd->acct_ctrl);
	pwdb_sethexpwd(smb_nt_passwd, newpwd->smb_nt_passwd, newpwd->acct_ctrl);

	pwdb_set_logon_time      (logon_t  , sizeof(logon_t  ), newpwd->logon_time           );
	pwdb_set_logoff_time     (logoff_t , sizeof(logoff_t ), newpwd->logoff_time          );
	pwdb_set_kickoff_time    (kickoff_t, sizeof(kickoff_t), newpwd->kickoff_time         );
	pwdb_set_last_set_time   (pwdlset_t, sizeof(pwdlset_t), newpwd->pass_last_set_time   ); 
	pwdb_set_can_change_time (pwdlchg_t, sizeof(pwdlchg_t), newpwd->pass_can_change_time ); 
	pwdb_set_must_change_time(pwdmchg_t, sizeof(pwdmchg_t), newpwd->pass_must_change_time); 

	slprintf(uid, sizeof(uid), "%u", newpwd->unix_uid);
	slprintf(user_rid, sizeof(user_rid), "0x%x", newpwd->user_rid);
	slprintf(smb_grpid, sizeof(smb_grpid), "%u", newpwd->smb_grpid);
	slprintf(group_rid, sizeof(group_rid), "0x%x", newpwd->group_rid);

	safe_strcpy(acb, pwdb_encode_acct_ctrl(newpwd->acct_ctrl, NEW_PW_FORMAT_SPACE_PADDED_LEN), sizeof(acb)); 

	set_single_attribute(&new_obj, NPF_NAME          , newpwd->smb_name     , strlen(newpwd->smb_name)     , 0);
	set_single_attribute(&new_obj, NPF_UID           , uid                  , strlen(uid)                  , 0);
	set_single_attribute(&new_obj, NPF_USER_RID      , user_rid             , strlen(user_rid)             , 0);
	set_single_attribute(&new_obj, NPF_SMB_GRPID     , smb_grpid            , strlen(smb_grpid)            , 0);
	set_single_attribute(&new_obj, NPF_GROUP_RID     , group_rid            , strlen(group_rid)            , 0);
	set_single_attribute(&new_obj, NPF_ACB           , acb                  , strlen(acb)                  , 0);
	set_single_attribute(&new_obj, NPF_LMPWD         , smb_passwd           , strlen(smb_passwd)           , EN_CRYPT);
	set_single_attribute(&new_obj, NPF_NTPWD         , smb_nt_passwd        , strlen(smb_nt_passwd)        , EN_CRYPT);
	set_single_attribute(&new_obj, NPF_LOGON_T       , logon_t              , strlen(logon_t)              , 0);
	set_single_attribute(&new_obj, NPF_LOGOFF_T      , logoff_t             , strlen(logoff_t)             , 0);
	set_single_attribute(&new_obj, NPF_KICK_T        , kickoff_t            , strlen(kickoff_t)            , 0);
	set_single_attribute(&new_obj, NPF_PWDLSET_T     , pwdlset_t            , strlen(pwdlset_t)            , 0);
	set_single_attribute(&new_obj, NPF_PWDLCHG_T     , pwdlchg_t            , strlen(pwdlchg_t)            , 0);
	set_single_attribute(&new_obj, NPF_PWDMCHG_T     , pwdmchg_t            , strlen(pwdmchg_t)            , 0);
	set_single_attribute(&new_obj, NPF_FULL_NAME     , newpwd->full_name    , strlen(newpwd->full_name)    , 0);
	set_single_attribute(&new_obj, NPF_HOME_DIR      , newpwd->home_dir     , strlen(newpwd->home_dir)     , 0);
	set_single_attribute(&new_obj, NPF_DIR_DRIVE     , newpwd->dir_drive    , strlen(newpwd->dir_drive)    , 0);
	set_single_attribute(&new_obj, NPF_LOGON_SCRIPT  , newpwd->logon_script , strlen(newpwd->logon_script) , 0);
	set_single_attribute(&new_obj, NPF_PROFILE_PATH  , newpwd->profile_path , strlen(newpwd->profile_path) , 0);
	set_single_attribute(&new_obj, NPF_ACCT_DESC     , newpwd->acct_desc    , strlen(newpwd->acct_desc)    , 0);
	set_single_attribute(&new_obj, NPF_WORKSTATIONS  , newpwd->workstations , strlen(newpwd->workstations) , 0);
	set_single_attribute(&new_obj, NPF_HOURS         , newpwd->hours        , newpwd->hours_len            , 0);

	obj = &new_obj;

	addresult = nis_add_entry(pfile, obj, ADD_OVERWRITE | FOLLOW_PATH | EXPAND_NAME | HARD_LOOKUP);

	nis_freeresult(nis_user);
	if (tblresult)
	{
		nis_freeresult(tblresult);
	}

	if (addresult->status != NIS_SUCCESS)
	{
		DEBUG(3, ( "add_nisppwd_entry: NIS+ table update failed: %s\n",
		            nisname, nis_sperrno(addresult->status)));
		nis_freeresult(addresult);
		nis_freeresult(result);
		return False;
	}

	nis_freeresult(addresult);
	nis_freeresult(result);

	return True;
}

/************************************************************************
 Routine to search the nisplus passwd file for an entry matching the username.
 and then modify its password entry. We can't use the startnisppwent()/
 getnisppwent()/endnisppwent() interfaces here as we depend on looking
 in the actual file to decide how much room we have to write data.
 override = False, normal
 override = True, override XXXXXXXX'd out password or NO PASS

 do not call this function directly.  use passdb.c instead.

************************************************************************/
static BOOL mod_nisp21pwd_entry(struct sam_passwd* pwd, BOOL override)
{
	return False;
}
 
/************************************************************************
 makes a struct sam_passwd from a NIS+ result.
 ************************************************************************/
static BOOL make_sam_from_nisp(struct sam_passwd *pw_buf, nis_result *result)
{
	int uidval;
	static pstring  user_name;
	static unsigned char smbpwd[16];
	static unsigned char smbntpwd[16];
	nis_object *obj;
	uchar *p;

	if (pw_buf == NULL || result == NULL) return False;

	pwdb_init_sam(pw_buf);

	if (result->status != NIS_SUCCESS)
	{
		DEBUG(0, ("make_smb_from_nisp: NIS+ lookup failure: %s\n",
		           nis_sperrno(result->status)));
		return False;
	}

	/* User not found. */
	if (NIS_RES_NUMOBJ(result) <= 0)
	{
		DEBUG(10, ("make_smb_from_nisp: user not found in NIS+\n"));
		return False;
	}

	if (NIS_RES_NUMOBJ(result) > 1)
	{
		DEBUG(10, ("make_smb_from_nisp: WARNING: Multiple entries for user in NIS+ table!\n"));
	}

	/* Grab the first hit. */
	obj = &NIS_RES_OBJECT(result)[0];

	/* Check the lanman password column. */
	p = (uchar *)ENTRY_VAL(obj, NPF_LMPWD);
	if (strlen((char *)p) != 32 || !pwdb_gethexpwd((char *)p, (char *)smbpwd))
	{
		DEBUG(0, ("make_smb_from_nisp: malformed LM pwd entry.\n"));
		return False;
	}

	/* Check the NT password column. */
	p = (uchar *)ENTRY_VAL(obj, NPF_NTPWD);
	if (strlen((char *)p) != 32 || !pwdb_gethexpwd((char *)p, (char *)smbntpwd))
	{
		DEBUG(0, ("make_smb_from_nisp: malformed NT pwd entry\n"));
		return False;
	}

	strncpy(user_name, ENTRY_VAL(obj, NPF_NAME), sizeof(user_name));
	uidval = atoi(ENTRY_VAL(obj, NPF_UID));

	pw_buf->smb_name      = user_name;
	pw_buf->unix_uid    = uidval;		
	pw_buf->smb_passwd    = smbpwd;
	pw_buf->smb_nt_passwd = smbntpwd;

	return True;
}

/*************************************************************************
 Routine to search the nisplus passwd file for an entry matching the username
 *************************************************************************/
static struct sam_passwd *getnisp21pwnam(char *name)
{
	/* Static buffers we will return. */
	static struct sam_passwd pw_buf;
	nis_result *result;
	pstring nisname;
	BOOL ret;

	if (!*lp_smb_passwd_file())
	{
		DEBUG(0, ("No SMB password file set\n"));
		return NULL;
	}

	DEBUG(10, ("getnisppwnam: search by name: %s\n", name));
	DEBUG(10, ("getnisppwnam: using NIS+ table %s\n", lp_smb_passwd_file()));

	slprintf(nisname, sizeof(nisname)-1, "[name=%s],%s", name, lp_smb_passwd_file());

	/* Search the table. */
	gotalarm = 0;
	CatchSignal(SIGALRM, SIGNAL_CAST gotalarm_sig);
	alarm(5);

	result = nis_list(nisname, FOLLOW_PATH | EXPAND_NAME | HARD_LOOKUP, NULL, NULL);

	alarm(0);
	CatchSignal(SIGALRM, SIGNAL_CAST SIG_DFL);

	if (gotalarm)
	{
		DEBUG(0,("getnisppwnam: NIS+ lookup time out\n"));
		nis_freeresult(result);
		return NULL;
	}

	ret = make_sam_from_nisp(&pw_buf, result);
	nis_freeresult(result);

	return ret ? &pw_buf : NULL;
}

/*************************************************************************
 Routine to search the nisplus passwd file for an entry matching the username
 *************************************************************************/
static struct sam_passwd *getnisp21pwrid(uint32 rid)
{
	/* Static buffers we will return. */
	static struct sam_passwd pw_buf;
	nis_result *result;
	char *nisname;
	BOOL ret;

	if (!*lp_smb_passwd_file())
	{
		DEBUG(0, ("No SMB password file set\n"));
		return NULL;
	}

	DEBUG(10, ("getnisp21pwrid: search by rid: %x\n", rid));
	DEBUG(10, ("getnisp21pwrid: using NIS+ table %s\n", lp_smb_passwd_file()));

	nisname = make_nisname_from_user_rid(rid, lp_smb_passwd_file());

	/* Search the table. */
	gotalarm = 0;
	CatchSignal(SIGALRM, SIGNAL_CAST gotalarm_sig);
	alarm(5);

	result = nis_list(nisname, FOLLOW_PATH | EXPAND_NAME | HARD_LOOKUP, NULL, NULL);

	alarm(0);
	CatchSignal(SIGALRM, SIGNAL_CAST SIG_DFL);

	if (gotalarm)
	{
		DEBUG(0,("getnisp21pwrid: NIS+ lookup time out\n"));
		nis_freeresult(result);
		return NULL;
	}

	ret = make_sam_from_nisp(&pw_buf, result);
	nis_freeresult(result);

	return ret ? &pw_buf : NULL;
}

/*
 * Derived functions for NIS+.
 */

static struct smb_passwd *getnisppwent(void *vp)
{
	return pwdb_sam_to_smb(getnisp21pwent(vp));
}

static BOOL add_nisppwd_entry(struct smb_passwd *newpwd)
{
 	return add_nisp21pwd_entry(pwdb_smb_to_sam(newpwd));
}

static BOOL mod_nisppwd_entry(struct smb_passwd* pwd, BOOL override)
{
 	return mod_nisp21pwd_entry(pwdb_smb_to_sam(pwd), override);
}

static struct smb_passwd *getnisppwnam(char *name)
{
	return pwdb_sam_to_smb(getnisp21pwnam(name));
}

static struct sam_passwd *getnisp21pwuid(uid_t unix_uid)
{
	return getnisp21pwrid(pwdb_uid_to_user_rid(unix_uid));
}

static struct smb_passwd *getnisppwrid(uid_t user_rid)
{
	return pwdb_sam_to_smb(getnisp21pwuid(pwdb_user_rid_to_uid(user_rid)));
}

static struct smb_passwd *getnisppwuid(uid_t unix_uid)
{
	return pwdb_sam_to_smb(getnisp21pwuid(unix_uid));
}

static struct sam_disp_info *getnispdispnam(char *name)
{
	return pwdb_sam_to_dispinfo(getnisp21pwnam(name));
}

static struct sam_disp_info *getnispdisprid(uint32 rid)
{
	return pwdb_sam_to_dispinfo(getnisp21pwrid(rid));
}

static struct sam_disp_info *getnispdispent(void *vp)
{
	return pwdb_sam_to_dispinfo(getnisp21pwent(vp));
}

static struct passdb_ops nispasswd_ops = {
  startnisppwent,
  endnisppwent,
  getnisppwpos,
  setnisppwpos,
  getnisppwnam,
  getnisppwuid,
  getnisppwrid,
  getnisppwent,
  add_nisppwd_entry,
  mod_nisppwd_entry,
  getnisp21pwent,
  getnisp21pwnam,
  getnisp21pwuid,
  getnisp21pwrid, 
  add_nisp21pwd_entry,
  mod_nisp21pwd_entry,
  getnispdispnam,
  getnispdisprid,
  getnispdispent
};

struct passdb_ops *nisplus_initialise_password_db(void)
{
  return &nispasswd_ops;
}
 
#else
 void nisplus_dummy_function(void);
 void nisplus_dummy_function(void) { } /* stop some compilers complaining */
#endif /* WITH_NISPLUS */

/* useful code i can't bring myself to delete */
#if 0
static void useful_code(void) {
	/* checks user in unix password database.  don't want to do that, here. */
	nisname = make_nisname_from_name(newpwd->smb_name, "passwd.org_dir");

	nis_user = nis_list(nisname, FOLLOW_PATH | EXPAND_NAME | HARD_LOOKUP, NULL, NULL);

	if (nis_user->status != NIS_SUCCESS || NIS_RES_NUMOBJ(nis_user) <= 0)
	{
		DEBUG(3, ("add_nisppwd_entry: Unable to get NIS+ passwd entry for user: %s.\n",
		        nis_sperrno(nis_user->status)));
		return False;
	}

	user_obj = NIS_RES_OBJECT(nis_user);
	make_nisname_from_name(ENTRY_VAL(user_obj,0), pfile);
}
#endif
