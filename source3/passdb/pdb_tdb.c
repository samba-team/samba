/*
 * Unix SMB/Netbios implementation. Version 1.9. SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1998
 * Copyright (C) Simo Sorce 2000
 * Copyright (C) Gerald Carter 2000
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

#ifdef WITH_TDBPWD

#define TDB_FORMAT_STRING	"ddddddfffPPfPPPPffddBBwdwdBdd"
#define USERPREFIX		"USER_"
#define UIDPREFIX		"UID_"
#define RIDPREFIX		"RID_"

extern int 		DEBUGLEVEL;
extern pstring 		samlogon_user;
extern BOOL 		sam_logon_in_ssb;


struct tdb_enum_info
{
	TDB_CONTEXT 	*passwd_tdb;
	TDB_DATA 	key;
};

static struct tdb_enum_info 	global_tdb_ent;
static SAM_ACCOUNT 		global_sam_pass;

/**********************************************************************
 Intialize a SAM_ACCOUNT struct from a BYTE buffer of size len
 *********************************************************************/
static BOOL init_sam_from_buffer (SAM_ACCOUNT *sampass, BYTE *buf, 
				  uint32 buflen)
{
	static fstring	username,
			domain,
			nt_username,
			dir_drive,
			unknown_str,
			munged_dial;
	static pstring	full_name,
			home_dir,
			logon_script,
			profile_path,
			acct_desc,
			workstations;
	static BYTE	*lm_pw_ptr,
			*nt_pw_ptr,
			lm_pw[16],
			nt_pw[16];
	uint32		len = 0;
	uint32		lmpwlen, ntpwlen, hourslen;

	/* using static memory for strings */
	/* you set it now or you will delete any fields retrieved by tdb_unpack */
	pdb_set_mem_ownership(sampass, False);

									
	/* unpack the buffer into variables */
	len = tdb_unpack (buf, buflen, TDB_FORMAT_STRING,
		&sampass->logon_time,
		&sampass->logoff_time,
		&sampass->kickoff_time,
		&sampass->pass_last_set_time,
		&sampass->pass_can_change_time,
		&sampass->pass_must_change_time,
		username,
		domain,
		nt_username,
		full_name,
		home_dir,
		dir_drive,
		logon_script,
		profile_path,
		acct_desc,
		workstations,
		unknown_str,
		munged_dial,
		&sampass->user_rid,
		&sampass->group_rid,
		&lmpwlen, &lm_pw_ptr,
		&ntpwlen, &nt_pw_ptr,
		&sampass->acct_ctrl,
		&sampass->unknown_3,
		&sampass->logon_divs,
		&sampass->hours_len,
		&hourslen, &sampass->hours,
		&sampass->unknown_5,
		&sampass->unknown_6);
		
	if (len == -1) 
		return False;

	/*
	 * We have to copy the password hashes into static memory
	 * and free the memory allocated by tdb_unpack.  This is because
	 * the sampass->own_memory flag is for all pointer members.
	 * The remaining members are using static memory and so
	 * the password hashes must as well.     --jerry
	 */
	if (lm_pw_ptr)
	{
		memcpy(lm_pw, lm_pw_ptr, 16);
		free (lm_pw_ptr);
	}
	if (nt_pw_ptr)
	{
		memcpy(nt_pw, nt_pw_ptr, 16);
		free (nt_pw_ptr);
	}
	
	pdb_set_username     (sampass, username);
	pdb_set_domain       (sampass, domain);
	pdb_set_nt_username  (sampass, nt_username);
	pdb_set_fullname     (sampass, full_name);
	pdb_set_homedir      (sampass, home_dir);
	pdb_set_dir_drive    (sampass, dir_drive);
	pdb_set_logon_script (sampass, logon_script);
	pdb_set_profile_path (sampass, profile_path);
	pdb_set_acct_desc    (sampass, acct_desc);
	pdb_set_workstations (sampass, workstations);
	pdb_set_munged_dial  (sampass, munged_dial);
	pdb_set_lanman_passwd(sampass, lm_pw);
	pdb_set_nt_passwd    (sampass, nt_pw);
	
	return True;
}

/**********************************************************************
 Intialize a BYTE buffer from a SAM_ACCOUNT struct
 *********************************************************************/
static uint32 init_buffer_from_sam (BYTE **buf, SAM_ACCOUNT *sampass)
{
	size_t		len, buflen;

	fstring		username,
			domain,
			nt_username,
			dir_drive,
			unknown_str,
			munged_dial;
	pstring		full_name,
			home_dir,
			logon_script,
			profile_path,
			acct_desc,
			workstations;
	BYTE		lm_pw[16],
			nt_pw[16];
	char		null_pw[] = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

	/* do we have a valid SAM_ACCOUNT pointer? */
	if (sampass == NULL)
		return -1;
		
	*buf = NULL;
	buflen = 0;

	fstrcpy(username, sampass->username);
	fstrcpy(domain,   sampass->domain);
	fstrcpy(nt_username, sampass->nt_username);
	fstrcpy(dir_drive, sampass->dir_drive);
	fstrcpy(unknown_str, sampass->unknown_str);
	fstrcpy(munged_dial, sampass->munged_dial);
	
	pstrcpy(full_name, sampass->full_name);
	pstrcpy(home_dir, sampass->home_dir);
	pstrcpy(logon_script, sampass->logon_script);
	pstrcpy(profile_path, sampass->profile_path);
	pstrcpy(acct_desc, sampass->acct_desc);
	pstrcpy(workstations, sampass->workstations);
	
	if (sampass->lm_pw)
		memcpy(lm_pw, sampass->lm_pw, 16);
	else
		pdb_gethexpwd (null_pw, lm_pw);
		
	if (sampass->nt_pw)
		memcpy(nt_pw, sampass->nt_pw, 16);
	else
		pdb_gethexpwd (null_pw, nt_pw);
		
			
	/* one time to get the size needed */
	len = tdb_pack(NULL, 0,  TDB_FORMAT_STRING,
		sampass->logon_time,
		sampass->logoff_time,
		sampass->kickoff_time,
		sampass->pass_last_set_time,
		sampass->pass_can_change_time,
		sampass->pass_must_change_time,
		username,
		domain,
		nt_username,
		full_name,
		home_dir,
		dir_drive,
		logon_script,
		profile_path,
		acct_desc,
		workstations,
		unknown_str,
		munged_dial,
		sampass->user_rid,
		sampass->group_rid,
		16, lm_pw,
		16, nt_pw,
		sampass->acct_ctrl,
		sampass->unknown_3,
		sampass->logon_divs,
		sampass->hours_len,
		MAX_HOURS_LEN, sampass->hours,
		sampass->unknown_5,
		sampass->unknown_6);


	/* malloc the space needed */
	if ( (*buf=(BYTE*)malloc(len)) == NULL)
	{
		DEBUG(0,("init_buffer_from_sam: Unable to malloc() memory for buffer!\n"));
		return (-1);
	}
	
	/* now for the real call to tdb_pack() */
	/* one time to get the size needed */
	buflen = tdb_pack(*buf, len,  TDB_FORMAT_STRING,
		sampass->logon_time,
		sampass->logoff_time,
		sampass->kickoff_time,
		sampass->pass_last_set_time,
		sampass->pass_can_change_time,
		sampass->pass_must_change_time,
		username,
		domain,
		nt_username,
		full_name,
		home_dir,
		dir_drive,
		logon_script,
		profile_path,
		acct_desc,
		workstations,
		unknown_str,
		munged_dial,
		sampass->user_rid,
		sampass->group_rid,
		16, lm_pw,
		16, nt_pw,
		sampass->acct_ctrl,
		sampass->unknown_3,
		sampass->logon_divs,
		sampass->hours_len,
		MAX_HOURS_LEN, sampass->hours,
		sampass->unknown_5,
		sampass->unknown_6);
	
	
	/* check to make sure we got it correct */
	if (buflen != len)
	{
		/* error */
		free (*buf);
		return (-1);
	}

	return (buflen);
}

/***************************************************************
 Open the TDB account SAM fo renumeration.
****************************************************************/
BOOL pdb_setsampwent(BOOL update)
{
	pstring		tdbfile;
	
	pstrcpy (tdbfile, lp_private_dir());
	pstrcat (tdbfile, "/passdb.tdb");
	
	/* Open tdb passwd */
	if (!(global_tdb_ent.passwd_tdb = tdb_open(tdbfile, 0, 0, update ? O_RDWR : O_RDONLY, 0600)))
	{
		DEBUG(0, ("Unable to open TDB passwd, trying create new!\n"));
		if (!(global_tdb_ent.passwd_tdb = tdb_open(tdbfile, 0, 0, O_RDWR | O_CREAT | O_EXCL, 0600)))
		{
			DEBUG(0, ("Unable to create TDB passwd (passdb.tdb) !!!"));
			return False;
		}
	}
	
	global_tdb_ent.key = tdb_firstkey(global_tdb_ent.passwd_tdb);

	return True;
}

/***************************************************************
 End enumeration of the TDB passwd list.
****************************************************************/
void pdb_endsampwent(void)
{
	if (global_tdb_ent.passwd_tdb)
	{
		tdb_close(global_tdb_ent.passwd_tdb);
		global_tdb_ent.passwd_tdb = NULL;
	}
	
	DEBUG(7, ("endtdbpwent: closed password file.\n"));
}


/*****************************************************************
 Get one SAM_ACCOUNT from the TDB (next in line)
*****************************************************************/
SAM_ACCOUNT* pdb_getsampwent(void)
{
	TDB_DATA 			data;
	struct passwd			*pw;

	/* do we have an valid interation pointer? */
	if(global_tdb_ent.passwd_tdb == NULL) 
	{
		DEBUG(0,("pdb_get_sampwent: Bad TDB Context pointer.\n"));
		return NULL;
	}

	data = tdb_fetch (global_tdb_ent.passwd_tdb, global_tdb_ent.key);
	if (!data.dptr)
	{
		DEBUG(5,("pdb_getsampwent: database entry not found.\n"));
		return NULL;
	}
  
  	/* unpack the buffer */
	pdb_clear_sam (&global_sam_pass);
	if (!init_sam_from_buffer (&global_sam_pass, data.dptr, data.dsize))
	{
		DEBUG(0,("pdb_getsampwent: Bad SAM_ACCOUNT entry returned from TDB!\n"));
		return NULL;
	}
	
	/* validate the account and fill in UNIX uid and gid.  sys_getpwnam()
	   is used instaed of Get_Pwnam() as we do not need to try case
	   permutations */
	if ((pw=sys_getpwnam(pdb_get_username(&global_sam_pass))) == NULL)
	{
		DEBUG(0,("pdb_getsampwent: getpwnam(%s) return NULL.  User does not exist!\n", 
		          pdb_get_username(&global_sam_pass)));
		return NULL;
	}
	
	pdb_set_uid (&global_sam_pass, pw->pw_uid);
	pdb_set_gid (&global_sam_pass, pw->pw_gid);

	/* increment to next in line */
	global_tdb_ent.key = tdb_nextkey (global_tdb_ent.passwd_tdb, global_tdb_ent.key);

	return (&global_sam_pass);
}

/******************************************************************
 Lookup a name in the SAM TDB
******************************************************************/
SAM_ACCOUNT* pdb_getsampwnam (char *sname)
{
	TDB_CONTEXT 		*pwd_tdb;
	TDB_DATA 		data, key;
	fstring 		keystr;
	struct passwd		*pw;
	pstring			tdbfile;
	fstring			name;
	
	fstrcpy (name, sname);
	strlower (name);
	pstrcpy (tdbfile, lp_private_dir());
	pstrcat (tdbfile, "/passdb.tdb");
	
	/* set search key */
	slprintf(keystr, sizeof(keystr), "%s%s", USERPREFIX, name);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;

	/* open the accounts TDB */
	if (!(pwd_tdb = tdb_open(tdbfile, 0, 0, O_RDONLY, 0600)))
	{
		DEBUG(0, ("pdb_getsampwnam: Unable to open TDB passwd!\n"));
		return False;
	}

	/* get the record */
	data = tdb_fetch (pwd_tdb, key);
	if (!data.dptr)
	{
		DEBUG(5,("pdb_getsampwnam (TDB): error fetching database.\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		tdb_close (pwd_tdb);
		return NULL;
	}
  
  	/* unpack the buffer */
	pdb_clear_sam (&global_sam_pass);
	if (!init_sam_from_buffer (&global_sam_pass, data.dptr, data.dsize))
	{
		DEBUG(0,("pdb_getsampwent: Bad SAM_ACCOUNT entry returned from TDB!\n"));
		return NULL;
	}
	
	/* validate the account and fill in UNIX uid and gid.  sys_getpwnam()
	   is used instaed of Get_Pwnam() as we do not need to try case
	   permutations */
	if ((pw=sys_getpwnam(pdb_get_username(&global_sam_pass))) == NULL)
	{
		DEBUG(0,("pdb_getsampwent: getpwnam(%s) return NULL.  User does not exist!\n", 
		          pdb_get_username(&global_sam_pass)));
		return NULL;
	}
	
	pdb_set_uid (&global_sam_pass, pw->pw_uid);
	pdb_set_gid (&global_sam_pass, pw->pw_gid);
	
	/* cleanup */
	tdb_close (pwd_tdb);

	return (&global_sam_pass);
}

/***************************************************************************
 Search by uid
 
 I now know what the 'T' stands for in TDB :-(  This is an unacceptable
 solution.  We need multiple indexes and transactional support.  I'm
 including this implementation only as an example.
 **************************************************************************/
SAM_ACCOUNT* pdb_getsampwuid (uid_t uid)
{
	SAM_ACCOUNT		*pw = NULL;
	TDB_CONTEXT 		*pwd_tdb;
	TDB_DATA 		data, key;
	fstring 		keystr;
	pstring			tdbfile;
	fstring			name;
	
	pstrcpy (tdbfile, lp_private_dir());
	pstrcat (tdbfile, "/uiddb.tdb");
	
	/* set search key */
	slprintf(keystr, sizeof(keystr), "%s%.5u", UIDPREFIX, uid);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;

	/* open the accounts TDB */
	if (!(pwd_tdb = tdb_open(tdbfile, 0, 0, O_RDONLY, 0600)))
	{
		DEBUG(0, ("pdb_getsampwuid: Unable to open TDB uid database!\n"));
		return False;
	}

	/* get the record */
	data = tdb_fetch (pwd_tdb, key);
	if (!data.dptr)
	{
		DEBUG(5,("pdb_getsampwuid (TDB): error fetching database.\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		tdb_close (pwd_tdb);
		return NULL;
	}

	fstrcpy (name, data.dptr);

	tdb_close (pwd_tdb);
	
	pw = pdb_getsampwnam (name);
			
	return pw;
}

/***************************************************************************
 Search by rid
 **************************************************************************/
SAM_ACCOUNT* pdb_getsampwrid (uint32 rid)
{
	SAM_ACCOUNT		*pw = NULL;
	TDB_CONTEXT 		*pwd_tdb;
	TDB_DATA 		data, key;
	fstring 		keystr;
	pstring			tdbfile;
	fstring			name;
	
	pstrcpy (tdbfile, lp_private_dir());
	pstrcat (tdbfile, "/riddb.tdb");
	
	/* set search key */
	slprintf(keystr, sizeof(keystr), "%s%.8x", RIDPREFIX, rid);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;

	/* open the accounts TDB */
	if (!(pwd_tdb = tdb_open(tdbfile, 0, 0, O_RDONLY, 0600)))
	{
		DEBUG(0, ("pdb_getsampwrid: Unable to open TDB rid database!\n"));
		return False;
	}

	/* get the record */
	data = tdb_fetch (pwd_tdb, key);
	if (!data.dptr)
	{
		DEBUG(5,("pdb_getsampwrid (TDB): error fetching database.\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		tdb_close (pwd_tdb);
		return NULL;
	}

	fstrcpy (name, data.dptr);
	
	tdb_close (pwd_tdb);
	
	pw = pdb_getsampwnam (name);
			
	return pw;

}


/***************************************************************************
 Delete a SAM_ACCOUNT
****************************************************************************/
BOOL pdb_delete_sam_account(char *sname)
{
	struct passwd  *pwd = NULL;
	TDB_CONTEXT 	*pwd_tdb;
	TDB_DATA 	key, data;
	fstring 	keystr;
	pstring		tdbfile;
	uid_t		uid;
	uint32		rid;
	fstring		name;
	
	fstrcpy (name, sname);
	strlower (name);
	
	pstrcpy (tdbfile, lp_private_dir());
	pstrcat (tdbfile, "/passdb.tdb");

	/* open the TDB */
	if (!(pwd_tdb = tdb_open(tdbfile, 0, 0, O_RDWR, 0600)))
	{
		DEBUG(0, ("Unable to open TDB passwd!"));
		return False;
	}
  
  	/* set the search key */
	slprintf(keystr, sizeof(keystr), "%s%s", USERPREFIX, name);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;
	
	/* get the record */
	data = tdb_fetch (pwd_tdb, key);
	if (!data.dptr)
	{
		DEBUG(5,("pdb_getsampwnam (TDB): error fetching database.\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		tdb_close (pwd_tdb);
		return False;
	}
  
  	/* unpack the buffer */
	pdb_clear_sam (&global_sam_pass);
	if (!init_sam_from_buffer (&global_sam_pass, data.dptr, data.dsize))
	{
		DEBUG(0,("pdb_getsampwent: Bad SAM_ACCOUNT entry returned from TDB!\n"));
		return False;
	}

	pwd = sys_getpwnam(global_sam_pass.username);
	uid = pwd->pw_uid;
	rid = pdb_uid_to_user_rid (uid);

	/* it's outaa here!  8^) */
	if (tdb_delete(pwd_tdb, key) != TDB_SUCCESS)
	{
		DEBUG(5, ("Error deleting entry from tdb passwd database!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		tdb_close(pwd_tdb); 
		return False;
	}	
	tdb_close(pwd_tdb);
	
	pstrcpy (tdbfile, lp_private_dir());
	pstrcat (tdbfile, "/uiddb.tdb");

	/* open the UID TDB */
	if (!(pwd_tdb = tdb_open(tdbfile, 0, 0, O_RDWR, 0600)))
	{
		DEBUG(0, ("Unable to open TDB uid file!"));
		return False;
	}	

  	/* set the search key */
	slprintf(keystr, sizeof(keystr), "%s%.5u", UIDPREFIX, uid);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;

	/* it's outaa here!  8^) */
	if (tdb_delete(pwd_tdb, key) != TDB_SUCCESS)
	{
		DEBUG(5, ("Error deleting entry from tdb uid database!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		tdb_close(pwd_tdb); 
		return False;
	}
	
	tdb_close(pwd_tdb);
	
	pstrcpy (tdbfile, lp_private_dir());
	pstrcat (tdbfile, "/riddb.tdb");	
	
	/* open the RID TDB */
	if (!(pwd_tdb = tdb_open(tdbfile, 0, 0, O_RDWR, 0600)))
	{
		DEBUG(0, ("Unable to open TDB rid file!"));
		return False;
	}	

  	/* set the search key */
	slprintf(keystr, sizeof(keystr), "%s%.8x", UIDPREFIX, rid);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;

	/* it's outaa here!  8^) */
	if (tdb_delete(pwd_tdb, key) != TDB_SUCCESS)
	{
		DEBUG(5, ("Error deleting entry from tdb rid database!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		tdb_close(pwd_tdb); 
		return False;
	}
	
	tdb_close(pwd_tdb);
	
	return True;
}

/***************************************************************************
 Update the TDB SAM
****************************************************************************/
static BOOL tdb_update_sam(SAM_ACCOUNT* newpwd, BOOL override, int flag)
{
	TDB_CONTEXT 	*pwd_tdb;
	TDB_DATA 	key, data;
	BYTE		*buf = NULL;
	fstring 	keystr;
	pstring		tdbfile;
	fstring		name;
	int		newtdb = FALSE;
	
	pstrcpy (tdbfile, lp_private_dir());
	pstrcat (tdbfile, "/passdb.tdb");
	
	if ( (!newpwd->uid) || (!newpwd->gid) )
		DEBUG (0,("tdb_update_sam: Storing a SAM_ACCOUNT for [%s] with uid %d and gid %d!\n",
			newpwd->username, newpwd->uid, newpwd->gid));
		
	/* if we don't have a RID, then generate one */
	if (!newpwd->user_rid)
		pdb_set_user_rid (newpwd, pdb_uid_to_user_rid (newpwd->uid));
	if (!newpwd->group_rid)
		pdb_set_group_rid (newpwd, pdb_gid_to_group_rid (newpwd->gid));
    
	/* copy the SAM_ACCOUNT struct into a BYTE buffer for storage */
	if ((data.dsize=init_buffer_from_sam (&buf, newpwd)) == -1)
	{
		DEBUG(0,("tdb_update_sam: ERROR - Unable to copy SAM_ACCOUNT info BYTE buffer!\n"));
		return False;
	}
	data.dptr = buf;

	fstrcpy (name, pdb_get_username(newpwd));
	strlower (name);
	
  	/* setup the USER index key */
	slprintf(keystr, sizeof(keystr), "%s%s", USERPREFIX, name);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;

	/* invalidate the existing TDB iterator if it is open */
	if (global_tdb_ent.passwd_tdb)
	{
		tdb_close(global_tdb_ent.passwd_tdb);
		global_tdb_ent.passwd_tdb = NULL;
	}
 
 	/* open the account TDB passwd*/
  	if (!(pwd_tdb = tdb_open(tdbfile, 0, 0, O_RDWR, 0600)))
	{
     		DEBUG(0, ("tdb_update_sam: Unable to open TDB passwd!\n"));
		if (flag == TDB_INSERT)
		{
			DEBUG(0, ("Unable to open TDB passwd, trying create new!\n"));
			if (!(pwd_tdb = tdb_open(tdbfile, 0, 0, O_RDWR | O_CREAT | O_EXCL, 0600)))
			{
				DEBUG(0, ("Unable to create TDB passwd (passdb.tdb) !!!\n"));
				return False;
			}
			newtdb = TRUE;
		}
	}

	/* add the account */
	if (tdb_store(pwd_tdb, key, data, flag) != TDB_SUCCESS)
	{
		DEBUG(0, ("Unable to modify TDB passwd!"));
		DEBUGADD(0, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		tdb_close (pwd_tdb);
		return False;
	}

	/* cleanup */
	tdb_close (pwd_tdb);
	
	/* setup UID/RID data */
	data.dsize = sizeof(fstring);
	data.dptr = name;

	pstrcpy (tdbfile, lp_private_dir());
	pstrcat (tdbfile, "/uiddb.tdb");

	/* setup the UID index key */
	slprintf(keystr, sizeof(keystr), "%s%.5u", UIDPREFIX, pdb_get_uid(newpwd));
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;
	
	/* open the account TDB uid file*/
  	if (!(pwd_tdb = tdb_open(tdbfile, 0, 0, O_RDWR, 0600)))
	{
     		DEBUG(0, ("tdb_update_sam: Unable to open TDB uid database!\n"));
		if (newtdb == FALSE)
			DEBUG(0, ("WARNING: uid database missing and passdb exist, check references integrity!\n"));
		if (flag == TDB_INSERT)
		{
			DEBUG(0, ("Unable to open TDB uid file, trying create new!\n"));
			if (!(pwd_tdb = tdb_open(tdbfile, 0, 0, O_RDWR | O_CREAT | O_EXCL, 0600)))
			{
				DEBUG(0, ("Unable to create TDB uid (uiddb.tdb) !!!\n"));
				/* return False; */
			}
		}
	}
		
	/* add the reference */
	if (tdb_store(pwd_tdb, key, data, flag) != TDB_SUCCESS)
	{
		DEBUG(0, ("Unable to modify TDB uid database!"));
		DEBUGADD(0, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		/* tdb_close (pwd_tdb);
		return False; */
	}
	
	/* cleanup */
	tdb_close (pwd_tdb);

	pstrcpy (tdbfile, lp_private_dir());
	pstrcat (tdbfile, "/riddb.tdb");

	/* setup the RID index key */
	slprintf(keystr, sizeof(keystr), "%s%.8x", UIDPREFIX, pdb_get_user_rid(newpwd));
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;
	
	/* open the account TDB rid file*/
  	if (!(pwd_tdb = tdb_open(tdbfile, 0, 0, O_RDWR, 0600)))
	{
     		DEBUG(0, ("tdb_update_sam: Unable to open TDB rid database!\n"));
		if (newtdb == FALSE)
			DEBUG(0, ("WARNING: rid database missing and passdb exist, check references integrity!\n"));
		if (flag == TDB_INSERT)
		{
			DEBUG(0, ("Unable to open TDB rid file, trying create new!\n"));
			if (!(pwd_tdb = tdb_open(tdbfile, 0, 0, O_RDWR | O_CREAT | O_EXCL, 0600)))
			{
				DEBUG(0, ("Unable to create TDB rid (riddb.tdb) !!!\n"));
				/* return False; */
			}
		}
	}
		
	/* add the reference */
	if (tdb_store(pwd_tdb, key, data, flag) != TDB_SUCCESS)
	{
		DEBUG(0, ("Unable to modify TDB rid database!"));
		DEBUGADD(0, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		/* tdb_close (pwd_tdb);
		return False; */
	}
	
	/* cleanup */
	tdb_close (pwd_tdb);
	
	return (True);
}

/***************************************************************************
 Modifies an existing SAM_ACCOUNT
****************************************************************************/
BOOL pdb_update_sam_account (SAM_ACCOUNT *newpwd, BOOL override)
{
	return (tdb_update_sam(newpwd, override, TDB_MODIFY));
}

/***************************************************************************
 Adds an existing SAM_ACCOUNT
****************************************************************************/
BOOL pdb_add_sam_account (SAM_ACCOUNT *newpwd)
{
	return (tdb_update_sam(newpwd, True, TDB_INSERT));
}


#else
	/* Do *NOT* make this function static. It breaks the compile on gcc. JRA */
	void samtdb_dummy_function(void) { } /* stop some compilers complaining */
#endif /* WITH_TDBPWD */
