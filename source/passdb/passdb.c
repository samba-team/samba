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

static struct smb_passdb_ops *pwdb_ops;

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
#elif defined(WITH_NT5LDAP)
  pwdb_ops = nt5ldap_initialise_password_db();
#elif defined(WITH_LDAP)
  pwdb_ops = ldap_initialise_password_db();
#elif defined(HAVE_MYSQL_H) && defined(WITH_MYSQLSAM)
  pwdb_ops = mysql_initialise_password_db();
#elif defined(USE_SMBPASS_DB)
  pwdb_ops = file_initialise_password_db();
#endif 

	return pwdb_ops != NULL;
}

/*
 * Functions that return/manipulate a struct smb_passwd.
 */

/************************************************************************
 Utility function to search smb passwd by uid.  use this if your database
 does not have search facilities.
*************************************************************************/

struct smb_passwd *iterate_getsmbpwuid(uid_t unix_uid)
{
	struct smb_passwd *pwd = NULL;
	void *fp = NULL;

	DEBUG(10, ("search by unix_uid: %x\n", (int)unix_uid));

	/* Open the smb password database - not for update. */
	fp = startsmbpwent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open smb password database.\n"));
		return NULL;
	}

	while ((pwd = getsmbpwent(fp)) != NULL && pwd->unix_uid != unix_uid)
	{
	}

	if (pwd != NULL)
	{
		DEBUG(10, ("found by unix_uid: %x\n", (int)unix_uid));
	}

	endsmbpwent(fp);
	return pwd;
}

/************************************************************************
 Utility function to search smb passwd by name.  use this if your database
 does not have search facilities.
*************************************************************************/

struct smb_passwd *iterate_getsmbpwnam(const char *name)
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

	while ((pwd = getsmbpwent(fp)) != NULL && !strequal(pwd->unix_name, name))
	{
		DEBUG(10, ("iterate: %s 0x%x\n", pwd->unix_name, pwd->unix_uid));
	}

	if (pwd != NULL)
	{
		DEBUG(10, ("found by name: %s\n", name));
	}

	endsmbpwent(fp);
	return pwd;
}

/***************************************************************
 obtain sequence number for sam database
****************************************************************/

uint32 getsamseqnum(void)
{
  return pwdb_ops->getsamseqnum();
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

SMB_BIG_UINT getsmbpwpos(void *vp)
{
  return pwdb_ops->getsmbpwpos(vp);
}

BOOL setsmbpwpos(void *vp, SMB_BIG_UINT tok)
{
  return pwdb_ops->setsmbpwpos(vp, tok);
}

/*************************************************************************
 Routine to return the next entry in the smb passwd list.
 *************************************************************************/

struct smb_passwd *getsmbpwent(void *vp)
{
	return pwdb_smb_map_names(pwdb_ops->getsmbpwent(vp));
}

/************************************************************************
 Routine to add an entry to the smb passwd file.
*************************************************************************/

BOOL add_smbpwd_entry(struct smb_passwd *newpwd)
{
 	struct smb_passwd *mapped = pwdb_smb_map_names(newpwd);
	if (mapped)
	{
		return pwdb_ops->add_smbpwd_entry(mapped);
	}
	return False;
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
 	struct smb_passwd *mapped = pwdb_smb_map_names(pwd);
	if (mapped)
	{
		return pwdb_ops->mod_smbpwd_entry(mapped, override);
	}
	return False;
}

/************************************************************************
 Routine to del an entry from the smb passwd file.
*************************************************************************/

BOOL del_smbpwd_entry(uint32 rid)
{
        return pwdb_ops->del_smbpwd_entry(rid);
}

/************************************************************************
 Routine to search smb passwd by name.
*************************************************************************/

struct smb_passwd *getsmbpwnam(const char *name)
{
	return pwdb_smb_map_names(pwdb_ops->getsmbpwnam(name));
}

/************************************************************************
 Routine to search smb passwd by uid.
*************************************************************************/

struct smb_passwd *getsmbpwuid(uid_t unix_uid)
{
	return pwdb_smb_map_names(pwdb_ops->getsmbpwuid(unix_uid));
}

/*************************************************************
 initialises a struct smb_passwd.
 **************************************************************/
void pwdb_init_smb(struct smb_passwd *user)
{
	if (user == NULL) return;
	ZERO_STRUCTP(user);
	user->pass_last_set_time    = (time_t)-1;
	user->unix_uid = (uid_t)-1;
	user->user_rid = 0xffffffff;
}

/*************************************************************
 fills in missing details.  one set of details _must_ exist.
 **************************************************************/
struct smb_passwd *pwdb_smb_map_names(struct smb_passwd *smb)
{
	DOM_NAME_MAP gmep;
	BOOL found = False;
	DOM_SID sid;
	static fstring unix_name;
	static fstring nt_name;

	if (smb == NULL)
	{
		DEBUG(10,("pwdb_smb_map_names: NULL\n"));
		return NULL;
	}

	DEBUG(10,("pwdb_smb_map_names: unix %s nt %s unix %d nt%d\n",
	           smb->unix_name != NULL ? smb->unix_name : "NULL",
	           smb->nt_name   != NULL ? smb->nt_name   : "NULL",
	           smb->unix_uid, smb->user_rid));

	if (smb->unix_name == NULL && smb->nt_name == NULL &&
	    smb->unix_uid == (uid_t)-1 && smb->user_rid == 0xffffffff)
	{
		return NULL;
	}
	if (smb->unix_name != NULL && smb->nt_name != NULL &&
	    smb->unix_uid != (uid_t)-1 && smb->user_rid != 0xffffffff)
	{
		return smb;
	}

	if (!found && smb->unix_name != NULL)
	{
		found = lookupsmbpwnam(smb->unix_name, &gmep);
	}
	if (!found && smb->unix_uid  != (uid_t)-1)
	{
		found = lookupsmbpwuid(smb->unix_uid , &gmep);
	}

	if (!found)
	{
		sid_copy(&sid, &global_sam_sid);
		sid_append_rid(&sid, smb->user_rid);
	}

	if (!found && smb->user_rid != 0xffffffff)
	{
		found = lookupsmbpwsid  (&sid        , &gmep);
	}
	if (!found && smb->nt_name  != NULL)
	{
		found = lookupsmbpwntnam(smb->nt_name, &gmep);
	}

	if (!found)
	{
		return NULL;
	}

	if (!sid_front_equal(&global_sam_sid, &gmep.sid))
	{
		fstring sid_str;
		sid_to_string(sid_str, &gmep.sid);
		DEBUG(0,("UNIX User %s Primary Group is in the wrong domain! %s\n",
		          smb->unix_name, sid_str));
		return NULL;
	}

	fstrcpy(unix_name, gmep.unix_name);
	fstrcpy(nt_name  , gmep.nt_name  );
	if (smb->unix_name == NULL      ) smb->unix_name = unix_name;
	if (smb->nt_name   == NULL      ) smb->nt_name   = nt_name  ;
	if (smb->unix_uid  == (uid_t)-1 ) smb->unix_uid  = (uid_t)gmep.unix_id;
	if (smb->user_rid  == 0xffffffff) sid_split_rid(&gmep.sid, &smb->user_rid);

	return smb;
}
