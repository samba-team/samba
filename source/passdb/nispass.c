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

#ifdef USE_NISPLUS_DB

#include "includes.h"
#include <rpcsvc/nis.h>

extern int      DEBUGLEVEL;

static int gotalarm;

/***************************************************************
 Signal function to tell us we timed out.
****************************************************************/

static void gotalarm_sig(void)
{
  gotalarm = 1;
}

/***************************************************************
 Start to enumerate the nisplus passwd list. Returns a void pointer
 to ensure no modification outside this module.

 do not call this function directly.  use passdb.c instead.

 ****************************************************************/
void *startnisppwent(BOOL update)
{
	return NULL;
}

/***************************************************************
 End enumeration of the nisplus passwd list.
****************************************************************/
void endnisppwent(void *vp)
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
struct sam_passwd *getnisp21pwent(void *vp)
{
	return NULL;
}

/*************************************************************************
 Routine to return the next entry in the nisplus passwd list.

 do not call this function directly.  use passdb.c instead.

 *************************************************************************/
struct smb_passwd *getnisppwent(void *vp)
{
	DEBUG(5,("getnisppwent: end of file reached.\n"));
	return NULL;
}

/*************************************************************************
 Return the current position in the nisplus passwd list as an unsigned long.
 This must be treated as an opaque token.

 do not call this function directly.  use passdb.c instead.

*************************************************************************/
unsigned long getnisppwpos(void *vp)
{
	return 0;
}

/*************************************************************************
 Set the current position in the nisplus passwd list from unsigned long.
 This must be treated as an opaque token.

 do not call this function directly.  use passdb.c instead.

*************************************************************************/
BOOL setnisppwpos(void *vp, unsigned long tok)
{
	return False;
}

/************************************************************************
 Routine to add an entry to the nisplus passwd file.

 do not call this function directly.  use passdb.c instead.

*************************************************************************/
BOOL add_nisp21pwd_entry(struct sam_passwd *newpwd)
{
}

/************************************************************************
 Routine to add an entry to the nisplus passwd file.

 do not call this function directly.  use passdb.c instead.

*************************************************************************/
BOOL add_nisppwd_entry(struct smb_passwd *newpwd)
{
	/* Static buffers we will return. */
	static pstring  user_name;

	BOOL            add_user = True;
	char           *pfile;
	pstring nisname;
	nis_result	*nis_user;
	nis_result *result = NULL,
	*tblresult = NULL, 
	*addresult = NULL;
	nis_object newobj, *obj, *user_obj;
	char lmpwd[33], ntpwd[33];

	pfile = lp_smb_passwd_file();

	safe_strcpy(user_name, newpwd->smb_name, sizeof(user_name));

	safe_strcpy(nisname, "[name=", sizeof(nisname));
	safe_strcat(nisname, user_name, sizeof(nisname) - strlen(nisname) -1);
	safe_strcat(nisname, "],passwd.org_dir", sizeof(nisname)-strlen(nisname)-1);

	safe_strcpy(nisname, "[uid=", sizeof(nisname));
	slprintf(nisname, sizeof(nisname), "%s%d", nisname, newpwd->smb_userid);
	safe_strcat(nisname, "],passwd.org_dir", sizeof(nisname)-strlen(nisname)-1);

	nis_user = nis_list(nisname, FOLLOW_PATH | EXPAND_NAME | HARD_LOOKUP, NULL, NULL);

	if (nis_user->status != NIS_SUCCESS || NIS_RES_NUMOBJ(nis_user) <= 0)
	{
		DEBUG(3, ("add_nisppwd_entry: Unable to get NIS+ passwd entry for user: %s.\n",
		        nis_sperrno(nis_user->status)));
		return False;
	}

	/*
	* Calculate the SMB (lanman) hash functions of both old and new passwords.
	*/

	user_obj = NIS_RES_OBJECT(nis_user);

	safe_strcpy(nisname, "[name=", sizeof(nisname));
	safe_strcat(nisname, ENTRY_VAL(user_obj,0),sizeof(nisname)-strlen(nisname)-1);
	safe_strcat(nisname, "],", sizeof(nisname)-strlen(nisname)-1);
	safe_strcat(nisname, pfile, sizeof(nisname)-strlen(nisname)-1);

	result = nis_list(nisname, FOLLOW_PATH|EXPAND_NAME|HARD_LOOKUP,NULL,NULL);
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

	/* User not found. */

	if (!add_user)
	{
		DEBUG(3, ("add_nisppwd_entry: User not found in NIS+ password db: %s\n",
		            pfile));
		nis_freeresult(result);
		nis_freeresult(nis_user);
		return False;
	}

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

	newobj.zo_name   = NIS_RES_OBJECT(tblresult)->zo_name;
	newobj.zo_domain = NIS_RES_OBJECT(tblresult)->zo_domain;
	newobj.zo_owner  = NIS_RES_OBJECT(nis_user)->zo_owner;
	newobj.zo_group  = NIS_RES_OBJECT(tblresult)->zo_group;
	newobj.zo_access = NIS_RES_OBJECT(tblresult)->zo_access;
	newobj.zo_ttl    = NIS_RES_OBJECT(tblresult)->zo_ttl;

	newobj.zo_data.zo_type = ENTRY_OBJ;

	newobj.zo_data.objdata_u.en_data.en_type = NIS_RES_OBJECT(tblresult)->zo_data.objdata_u.ta_data.ta_type;
	newobj.zo_data.objdata_u.en_data.en_cols.en_cols_len = NIS_RES_OBJECT(tblresult)->zo_data.objdata_u.ta_data.ta_maxcol;
	newobj.zo_data.objdata_u.en_data.en_cols.en_cols_val = calloc(newobj.zo_data.objdata_u.en_data.en_cols.en_cols_len, sizeof(entry_col));

	ENTRY_VAL(&newobj, 0) = ENTRY_VAL(user_obj, 0);
	ENTRY_LEN(&newobj, 0) = ENTRY_LEN(user_obj, 0);

	ENTRY_VAL(&newobj, 1) = ENTRY_VAL(user_obj, 2);
	ENTRY_LEN(&newobj, 1) = ENTRY_LEN(user_obj, 2);

	ENTRY_VAL(&newobj, 2) = lmpwd;
	ENTRY_LEN(&newobj, 2) = strlen(lmpwd);
	newobj.EN_data.en_cols.en_cols_val[2].ec_flags = EN_CRYPT;

	ENTRY_VAL(&newobj, 3) = ntpwd;
	ENTRY_LEN(&newobj, 3) = strlen(ntpwd);
	newobj.EN_data.en_cols.en_cols_val[3].ec_flags = EN_CRYPT;

	ENTRY_VAL(&newobj, 4) = ENTRY_VAL(user_obj, 4);
	ENTRY_LEN(&newobj, 4) = ENTRY_LEN(user_obj, 4);

	ENTRY_VAL(&newobj, 5) = ENTRY_VAL(user_obj, 5);
	ENTRY_LEN(&newobj, 5) = ENTRY_LEN(user_obj, 5);

	ENTRY_VAL(&newobj, 6) = ENTRY_VAL(user_obj, 6);
	ENTRY_LEN(&newobj, 6) = ENTRY_LEN(user_obj, 6);

	obj = &newobj;

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
BOOL mod_nisp21pwd_entry(struct sam_passwd* pwd, BOOL override)
{
	return False;
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
BOOL mod_nisppwd_entry(struct smb_passwd* pwd, BOOL override)
{
	return False;
}
 
/************************************************************************
 makes a struct smb_passwd from a NIS+ result.
 ************************************************************************/
static BOOL make_smb_from_nisp(struct smb_passwd *pw_buf, nis_result *result)
{
	int uidval;
	static pstring  user_name;
	static unsigned char smbpwd[16];
	static unsigned char smbntpwd[16];
	nis_object *obj;
	uchar *p;

	if (pw_buf == NULL || result == NULL) return False;

	bzero(pw_buf, sizeof(*pw_buf));

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
	p = (uchar *)ENTRY_VAL(obj, 2);
	if (strlen((char *)p) != 32 || !pdb_gethexpwd((char *)p, (char *)smbpwd))
	{
		DEBUG(0, ("make_smb_from_nisp: malformed LM pwd entry.\n"));
		return False;
	}

	/* Check the NT password column. */
	p = (uchar *)ENTRY_VAL(obj, 3);
	if (strlen((char *)p) != 32 || !pdb_gethexpwd((char *)p, (char *)smbntpwd))
	{
		DEBUG(0, ("make_smb_from_nisp: malformed NT pwd entry\n"));
		return False;
	}

	strncpy(user_name, ENTRY_VAL(obj, 0), sizeof(user_name));
	uidval = atoi(ENTRY_VAL(obj, 1));

	pw_buf->smb_name      = user_name;
	pw_buf->smb_userid    = uidval;		
	pw_buf->smb_passwd    = smbpwd;
	pw_buf->smb_nt_passwd = smbntpwd;

	return True;
}

/*************************************************************************
 Routine to search the nisplus passwd file for an entry matching the username
 *************************************************************************/
struct smb_passwd *getnisppwnam(char *name)
{
	/* Static buffers we will return. */
	static struct smb_passwd pw_buf;
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

	slprintf(nisname, sizeof(nisname), "[name=%s],%s", name, lp_smb_passwd_file());

	/* Search the table. */
	gotalarm = 0;
	signal(SIGALRM, SIGNAL_CAST gotalarm_sig);
	alarm(5);

	result = nis_list(nisname, FOLLOW_PATH | EXPAND_NAME | HARD_LOOKUP, NULL, NULL);

	alarm(0);
	signal(SIGALRM, SIGNAL_CAST SIG_DFL);

	if (gotalarm)
	{
		DEBUG(0,("getnisppwnam: NIS+ lookup time out\n"));
		nis_freeresult(result);
		return NULL;
	}

	ret = make_smb_from_nisp(&pw_buf, result);
	nis_freeresult(result);

	return ret ? &pw_buf : NULL;
}

/*************************************************************************
 Routine to search the nisplus passwd file for an entry matching the username
 *************************************************************************/
struct smb_passwd *getnisppwuid(int smb_userid)
{
	/* Static buffers we will return. */
	static struct smb_passwd pw_buf;
	nis_result *result;
	pstring nisname;
	BOOL ret;

	if (!*lp_smb_passwd_file())
	{
		DEBUG(0, ("No SMB password file set\n"));
		return NULL;
	}

	DEBUG(10, ("getnisppwuid: search by uid: %d\n", smb_userid));
	DEBUG(10, ("getnisppwuid: using NIS+ table %s\n", lp_smb_passwd_file()));

	slprintf(nisname, sizeof(nisname), "[uid=%d],%s", smb_userid, lp_smb_passwd_file());

	/* Search the table. */
	gotalarm = 0;
	signal(SIGALRM, SIGNAL_CAST gotalarm_sig);
	alarm(5);

	result = nis_list(nisname, FOLLOW_PATH | EXPAND_NAME | HARD_LOOKUP, NULL, NULL);

	alarm(0);
	signal(SIGALRM, SIGNAL_CAST SIG_DFL);

	if (gotalarm)
	{
		DEBUG(0,("getnisppwuid: NIS+ lookup time out\n"));
		nis_freeresult(result);
		return NULL;
	}

	ret = make_smb_from_nisp(&pw_buf, result);
	nis_freeresult(result);

	return ret ? &pw_buf : NULL;
}

#else
static void dummy_function(void) { } /* stop some compilers complaining */
#endif /* USE_NISPLUS_DB */
