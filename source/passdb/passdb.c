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

static struct passdb_ops *pwdb_ops;

/***************************************************************
 Initialise the password db operations.
***************************************************************/

BOOL initialise_password_db(void)
{
  if (pwdb_ops)
  {
    return True;
  }

#ifdef WITH_NISPLUS
  pwdb_ops =  nisplus_initialise_password_db();
#elif defined(WITH_LDAP)
  pwdb_ops = ldap_initialise_password_db();
#else 
  pwdb_ops = file_initialise_password_db();
#endif 

  return (pwdb_ops != NULL);
}

/*
 * Functions that return/manipulate a struct smb_passwd.
 */

/************************************************************************
 Utility function to search smb passwd by rid.  
*************************************************************************/

struct smb_passwd *iterate_getsmbpwrid(uint32 user_rid)
{
	return iterate_getsmbpwuid(pwdb_user_rid_to_uid(user_rid));
}

/************************************************************************
 Utility function to search smb passwd by uid.  use this if your database
 does not have search facilities.
*************************************************************************/

struct smb_passwd *iterate_getsmbpwuid(uid_t smb_userid)
{
	struct smb_passwd *pwd = NULL;
	void *fp = NULL;

	DEBUG(10, ("search by smb_userid: %x\n", (int)smb_userid));

	/* Open the smb password database - not for update. */
	fp = startsmbpwent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open smb password database.\n"));
		return NULL;
	}

	while ((pwd = getsmbpwent(fp)) != NULL && pwd->smb_userid != smb_userid)
      ;

	if (pwd != NULL)
	{
		DEBUG(10, ("found by smb_userid: %x\n", (int)smb_userid));
	}

	endsmbpwent(fp);
	return pwd;
}

/************************************************************************
 Utility function to search smb passwd by name.  use this if your database
 does not have search facilities.
*************************************************************************/

struct smb_passwd *iterate_getsmbpwnam(char *name)
{
	struct smb_passwd *pwd = NULL;
	void *fp = NULL;

	DEBUG(10, ("search by name: %s\n", name));

	/* Open the sam password file - not for update. */
	fp = startsmbpwent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open smb password database.\n"));
		return NULL;
	}

	while ((pwd = getsmbpwent(fp)) != NULL && !strequal(pwd->smb_name, name))
      ;

	if (pwd != NULL)
	{
		DEBUG(10, ("found by name: %s\n", name));
	}

	endsmbpwent(fp);
	return pwd;
}

/***************************************************************
 Start to enumerate the smb or sam passwd list. Returns a void pointer
 to ensure no modification outside this module.

 Note that currently it is being assumed that a pointer returned
 from this function may be used to enumerate struct sam_passwd
 entries as well as struct smb_passwd entries. This may need
 to change. JRA.

****************************************************************/

void *startsmbpwent(BOOL update)
{
  return pwdb_ops->startsmbpwent(update);
}

/***************************************************************
 End enumeration of the smb or sam passwd list.

 Note that currently it is being assumed that a pointer returned
 from this function may be used to enumerate struct sam_passwd
 entries as well as struct smb_passwd entries. This may need
 to change. JRA.

****************************************************************/

void endsmbpwent(void *vp)
{
  pwdb_ops->endsmbpwent(vp);
}

/*************************************************************************
 Routine to return the next entry in the smb passwd list.
 *************************************************************************/

struct smb_passwd *getsmbpwent(void *vp)
{
	return pwdb_ops->getsmbpwent(vp);
}

/************************************************************************
 Routine to add an entry to the smb passwd file.
*************************************************************************/

BOOL add_smbpwd_entry(struct smb_passwd *newpwd)
{
 	return pwdb_ops->add_smbpwd_entry(newpwd);
}

/************************************************************************
 Routine to search the smb passwd file for an entry matching the username.
 and then modify its password entry. We can't use the startsampwent()/
 getsampwent()/endsampwent() interfaces here as we depend on looking
 in the actual file to decide how much room we have to write data.
 override = False, normal
 override = True, override XXXXXXXX'd out password or NO PASS
************************************************************************/

BOOL mod_smbpwd_entry(struct smb_passwd* pwd, BOOL override)
{
 	return pwdb_ops->mod_smbpwd_entry(pwd, override);
}

/************************************************************************
 Routine to search smb passwd by name.
*************************************************************************/

struct smb_passwd *getsmbpwnam(char *name)
{
	return pwdb_ops->getsmbpwnam(name);
}

/************************************************************************
 Routine to search smb passwd by user rid.
*************************************************************************/

struct smb_passwd *getsmbpwrid(uint32 user_rid)
{
	return pwdb_ops->getsmbpwrid(user_rid);
}

/************************************************************************
 Routine to search smb passwd by uid.
*************************************************************************/

struct smb_passwd *getsmbpwuid(uid_t smb_userid)
{
	return pwdb_ops->getsmbpwuid(smb_userid);
}

/*
 * Functions that manupulate a struct sam_passwd.
 */

/************************************************************************
 Utility function to search sam passwd by name.  use this if your database
 does not have search facilities.
*************************************************************************/

struct sam_passwd *iterate_getsam21pwnam(char *name)
{
	struct sam_passwd *pwd = NULL;
	void *fp = NULL;

	DEBUG(10, ("search by name: %s\n", name));

	/* Open the smb password database - not for update. */
	fp = startsmbpwent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open sam password database.\n"));
		return NULL;
	}

	while ((pwd = getsam21pwent(fp)) != NULL && !strequal(pwd->smb_name, name))
	{
		DEBUG(10, ("iterate: %s 0x%x\n", pwd->smb_name, pwd->user_rid));
	}

	if (pwd != NULL)
	{
		DEBUG(10, ("found by name: %s\n", name));
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
		DEBUG(10, ("iterate: %s 0x%x\n", pwd->smb_name, pwd->user_rid));
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

	while ((pwd = getsam21pwent(fp)) != NULL && pwd->smb_userid != uid)
      ;

	if (pwd != NULL)
	{
		DEBUG(10, ("found by smb_userid: %x\n", (int)uid));
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

/*************************************************************************
 Routine to return the next entry in the sam passwd list.
 *************************************************************************/

struct sam_passwd *getsam21pwent(void *vp)
{
	return pwdb_ops->getsam21pwent(vp);
}


/************************************************************************
 Routine to search sam passwd by name.
*************************************************************************/

struct sam_passwd *getsam21pwnam(char *name)
{
	return pwdb_ops->getsam21pwnam(name);
}

/************************************************************************
 Routine to search sam passwd by rid.  
*************************************************************************/

struct sam_passwd *getsam21pwrid(uint32 rid)
{
	return pwdb_ops->getsam21pwrid(rid);
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
}

/*************************************************************
 initialises a struct smb_passwd.
 **************************************************************/

void pwdb_init_smb(struct smb_passwd *user)
{
	if (user == NULL) return;
	bzero(user, sizeof(*user));
	user->pass_last_set_time    = (time_t)-1;
}

/*************************************************************
 initialises a struct sam_passwd.
 **************************************************************/
void pwdb_init_sam(struct sam_passwd *user)
{
	if (user == NULL) return;
	bzero(user, sizeof(*user));
	user->logon_time            = (time_t)-1;
	user->logoff_time           = (time_t)-1;
	user->kickoff_time          = (time_t)-1;
	user->pass_last_set_time    = (time_t)-1;
	user->pass_can_change_time  = (time_t)-1;
	user->pass_must_change_time = (time_t)-1;
}

/*************************************************************************
 Routine to return the next entry in the sam passwd list.
 *************************************************************************/

struct sam_disp_info *pwdb_sam_to_dispinfo(struct sam_passwd *user)
{
	static struct sam_disp_info disp_info;

	if (user == NULL) return NULL;

	pwdb_init_dispinfo(&disp_info);

	disp_info.smb_name  = user->smb_name;
	disp_info.full_name = user->full_name;
	disp_info.user_rid  = user->user_rid;

	return &disp_info;
}

/*************************************************************
 converts a sam_passwd structure to a smb_passwd structure.
 **************************************************************/

struct smb_passwd *pwdb_sam_to_smb(struct sam_passwd *user)
{
	static struct smb_passwd pw_buf;

	if (user == NULL) return NULL;

	pwdb_init_smb(&pw_buf);

	pw_buf.smb_userid         = user->smb_userid;
	pw_buf.smb_name           = user->smb_name;
	pw_buf.smb_passwd         = user->smb_passwd;
	pw_buf.smb_nt_passwd      = user->smb_nt_passwd;
	pw_buf.acct_ctrl          = user->acct_ctrl;
	pw_buf.pass_last_set_time = user->pass_last_set_time;

	return &pw_buf;
}


/*************************************************************
 converts a smb_passwd structure to a sam_passwd structure.
 **************************************************************/

struct sam_passwd *pwdb_smb_to_sam(struct smb_passwd *user)
{
	static struct sam_passwd pw_buf;

	if (user == NULL) return NULL;

	pwdb_init_sam(&pw_buf);

	pw_buf.smb_userid         = user->smb_userid;
	pw_buf.smb_name           = user->smb_name;
	pw_buf.smb_passwd         = user->smb_passwd;
	pw_buf.smb_nt_passwd      = user->smb_nt_passwd;
	pw_buf.acct_ctrl          = user->acct_ctrl;
	pw_buf.pass_last_set_time = user->pass_last_set_time;

	return &pw_buf;
}

/**********************************************************
 Encode the account control bits into a string.
 length = length of string to encode into (including terminating
 null). length *MUST BE MORE THAN 2* !
 **********************************************************/

char *pwdb_encode_acct_ctrl(uint16 acct_ctrl, size_t length)
{
  static fstring acct_str;
  size_t i = 0;

  acct_str[i++] = '[';

  if (acct_ctrl & ACB_PWNOTREQ ) acct_str[i++] = 'N';
  if (acct_ctrl & ACB_DISABLED ) acct_str[i++] = 'D';
  if (acct_ctrl & ACB_HOMDIRREQ) acct_str[i++] = 'H';
  if (acct_ctrl & ACB_TEMPDUP  ) acct_str[i++] = 'T'; 
  if (acct_ctrl & ACB_NORMAL   ) acct_str[i++] = 'U';
  if (acct_ctrl & ACB_MNS      ) acct_str[i++] = 'M';
  if (acct_ctrl & ACB_WSTRUST  ) acct_str[i++] = 'W';
  if (acct_ctrl & ACB_SVRTRUST ) acct_str[i++] = 'S';
  if (acct_ctrl & ACB_AUTOLOCK ) acct_str[i++] = 'L';
  if (acct_ctrl & ACB_PWNOEXP  ) acct_str[i++] = 'X';
  if (acct_ctrl & ACB_DOMTRUST ) acct_str[i++] = 'I';

  for ( ; i < length - 2 ; i++ ) { acct_str[i] = ' '; }

  i = length - 2;
  acct_str[i++] = ']';
  acct_str[i++] = '\0';

  return acct_str;
}     

/**********************************************************
 Decode the account control bits from a string.

 this function breaks coding standards minimum line width of 80 chars.
 reason: vertical line-up code clarity - all case statements fit into
 15 lines, which is more important.
 **********************************************************/

uint16 pwdb_decode_acct_ctrl(const char *p)
{
	uint16 acct_ctrl = 0;
	BOOL finished = False;

	/*
	 * Check if the account type bits have been encoded after the
	 * NT password (in the form [NDHTUWSLXI]).
	 */

	if (*p != '[') return 0;

	for (p++; *p && !finished; p++)
	{
		switch (*p)
		{
			case 'N': { acct_ctrl |= ACB_PWNOTREQ ; break; /* 'N'o password. */ }
			case 'D': { acct_ctrl |= ACB_DISABLED ; break; /* 'D'isabled. */ }
			case 'H': { acct_ctrl |= ACB_HOMDIRREQ; break; /* 'H'omedir required. */ }
			case 'T': { acct_ctrl |= ACB_TEMPDUP  ; break; /* 'T'emp account. */ } 
			case 'U': { acct_ctrl |= ACB_NORMAL   ; break; /* 'U'ser account (normal). */ } 
			case 'M': { acct_ctrl |= ACB_MNS      ; break; /* 'M'NS logon user account. What is this ? */ } 
			case 'W': { acct_ctrl |= ACB_WSTRUST  ; break; /* 'W'orkstation account. */ } 
			case 'S': { acct_ctrl |= ACB_SVRTRUST ; break; /* 'S'erver account. */ } 
			case 'L': { acct_ctrl |= ACB_AUTOLOCK ; break; /* 'L'ocked account. */ } 
			case 'X': { acct_ctrl |= ACB_PWNOEXP  ; break; /* No 'X'piry on password */ } 
			case 'I': { acct_ctrl |= ACB_DOMTRUST ; break; /* 'I'nterdomain trust account. */ }
            case ' ': { break; }
			case ':':
			case '\n':
			case '\0': 
			case ']':
			default:  { finished = True; }
		}
	}

	return acct_ctrl;
}

/*******************************************************************
 gets password-database-format time from a string.
 ********************************************************************/

static time_t get_time_from_string(const char *p)
{
	int i;

	for (i = 0; i < 8; i++)
	{
		if (p[i] == '\0' || !isxdigit((int)(p[i]&0xFF)))
		{
			break;
		}
	}
	if (i == 8)
	{
		/*
		 * p points at 8 characters of hex digits - 
		 * read into a time_t as the seconds since
		 * 1970 that the password was last changed.
		 */
		return (time_t)strtol(p, NULL, 16);
	}
	return (time_t)-1;
}

/*******************************************************************
 gets password last set time
 ********************************************************************/

time_t pwdb_get_last_set_time(const char *p)
{
	if (*p && StrnCaseCmp(p, "LCT-", 4))
	{
		return get_time_from_string(p + 4);
	}
	return (time_t)-1;
}


/*******************************************************************
 sets password-database-format time in a string.
 ********************************************************************/
static void set_time_in_string(char *p, int max_len, char *type, time_t t)
{
	slprintf(p, max_len, ":%s-%08X:", type, (uint32)t);
}

/*******************************************************************
 sets logon time
 ********************************************************************/
void pwdb_set_logon_time(char *p, int max_len, time_t t)
{
	set_time_in_string(p, max_len, "LNT", t);
}

/*******************************************************************
 sets logoff time
 ********************************************************************/
void pwdb_set_logoff_time(char *p, int max_len, time_t t)
{
	set_time_in_string(p, max_len, "LOT", t);
}

/*******************************************************************
 sets kickoff time
 ********************************************************************/
void pwdb_set_kickoff_time(char *p, int max_len, time_t t)
{
	set_time_in_string(p, max_len, "KOT", t);
}

/*******************************************************************
 sets password can change time
 ********************************************************************/
void pwdb_set_can_change_time(char *p, int max_len, time_t t)
{
	set_time_in_string(p, max_len, "CCT", t);
}

/*******************************************************************
 sets password last set time
 ********************************************************************/
void pwdb_set_must_change_time(char *p, int max_len, time_t t)
{
	set_time_in_string(p, max_len, "MCT", t);
}

/*******************************************************************
 sets password last set time
 ********************************************************************/
void pwdb_set_last_set_time(char *p, int max_len, time_t t)
{
	set_time_in_string(p, max_len, "LCT", t);
}


/*************************************************************
 Routine to set 32 hex password characters from a 16 byte array.
**************************************************************/
void pwdb_sethexpwd(char *p, char *pwd, uint16 acct_ctrl)
{
	if (pwd != NULL)
	{
		int i;
		for (i = 0; i < 16; i++)
		{
			slprintf(&p[i*2], 33, "%02X", pwd[i]);
		}
	}
	else
	{
		if (IS_BITS_SET_ALL(acct_ctrl, ACB_PWNOTREQ))
		{
			safe_strcpy(p, "NO PASSWORDXXXXXXXXXXXXXXXXXXXXX", 33);
		}
		else
		{
			safe_strcpy(p, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 33);
		}
	}
}

/*************************************************************
 Routine to get the 32 hex characters and turn them
 into a 16 byte array.
**************************************************************/
BOOL pwdb_gethexpwd(char *p, char *pwd)
{
	return strhex_to_str(pwd, 32, p) == 16;
}

/*******************************************************************
 converts UNIX uid to an NT User RID. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
uid_t pwdb_user_rid_to_uid(uint32 user_rid)
{
	uid_t uid = (uid_t)(((user_rid & (~RID_TYPE_USER))- 1000)/RID_MULTIPLIER);
	return uid;
}

/*******************************************************************
 converts UNIX uid to an NT User RID. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
uint32 pwdb_uid_to_user_rid(uid_t uid)
{
	uint32 user_rid = (((((uint32)uid)*RID_MULTIPLIER) + 1000) | RID_TYPE_USER);
	return user_rid;
}

/*******************************************************************
 converts NT Group RID to a UNIX uid. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
uint32 pwdb_gid_to_group_rid(gid_t gid)
{
	uint32 grp_rid = (((((uint32)gid)*RID_MULTIPLIER) + 1000) | RID_TYPE_GROUP);
	return grp_rid;
}

/*******************************************************************
 converts NT Group RID to a UNIX uid. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
gid_t pwdb_group_rid_to_gid(uint32 group_rid)
{
	gid_t gid = (gid_t)(((group_rid & (~RID_TYPE_GROUP))- 1000)/RID_MULTIPLIER);
	return gid;
}

/*******************************************************************
 converts UNIX gid to an NT Alias RID. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
uint32 pwdb_gid_to_alias_rid(gid_t gid)
{
	uint32 alias_rid = (((((uint32)gid)*RID_MULTIPLIER) + 1000) | RID_TYPE_ALIAS);
	return alias_rid;
}

/*******************************************************************
 converts NT Alias RID to a UNIX uid. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
gid_t pwdb_alias_rid_to_gid(uint32 alias_rid)
{
	gid_t gid = (gid_t)(((alias_rid & (~RID_TYPE_ALIAS))- 1000)/RID_MULTIPLIER);
	return gid;
}

/*******************************************************************
 Decides if a RID is a well known RID.
 ********************************************************************/
static BOOL pwdb_rid_is_well_known(uint32 rid)
{
	return (rid < 1000);
}

/*******************************************************************
 determines a rid's type.  NOTE: THIS IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static uint32 pwdb_rid_type(uint32 rid)
{
	/* lkcl i understand that NT attaches an enumeration to a RID
	 * such that it can be identified as either a user, group etc
	 * type: SID_ENUM_TYPE.
	 */
	if (pwdb_rid_is_well_known(rid))
	{
		/*
		 * The only well known user RIDs are DOMAIN_USER_RID_ADMIN
		 * and DOMAIN_USER_RID_GUEST.
		 */
		if (rid == DOMAIN_USER_RID_ADMIN || rid == DOMAIN_USER_RID_GUEST)
		{
			return RID_TYPE_USER;
		}
		if (DOMAIN_GROUP_RID_ADMINS <= rid && rid <= DOMAIN_GROUP_RID_GUESTS)
		{
			return RID_TYPE_GROUP;
		}
		if (BUILTIN_ALIAS_RID_ADMINS <= rid && rid <= BUILTIN_ALIAS_RID_REPLICATOR)
		{
			return RID_TYPE_ALIAS;
		}
	}
	return (rid & RID_TYPE_MASK);
}

/*******************************************************************
 checks whether rid is a user rid.  NOTE: THIS IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
BOOL pwdb_rid_is_user(uint32 rid)
{
	return pwdb_rid_type(rid) == RID_TYPE_USER;
}

