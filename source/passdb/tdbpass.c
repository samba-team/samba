/*
 * Unix SMB/Netbios implementation. Version 1.9. SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1998
 * Copyright (C) Simo Sorce 2000
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

#define lp_tdb_passwd_file lp_smb_passwd_file
#define tdb_writelock(ptr)
#define tdb_writeunlock(ptr)

extern int DEBUGLEVEL;
extern pstring samlogon_user;
extern BOOL sam_logon_in_ssb;

struct tdb_sam_entry
{
	time_t logon_time;            /* logon time */
	time_t logoff_time;           /* logoff time */
	time_t kickoff_time;          /* kickoff time */
	time_t pass_last_set_time;    /* password last set time */
	time_t pass_can_change_time;  /* password can change time */
	time_t pass_must_change_time; /* password must change time */

	uid_t smb_userid;       /* this is actually the unix uid_t */
	gid_t smb_grpid;        /* this is actually the unix gid_t */
	uint32 user_rid;      /* Primary User ID */
	uint32 group_rid;     /* Primary Group ID */

	char smb_passwd[33]; /* Null if no password */
	char smb_nt_passwd[33]; /* Null if no password */

	uint16 acct_ctrl; /* account info (ACB_xxxx bit-mask) */
	uint32 unknown_3; /* 0x00ff ffff */

	uint16 logon_divs; /* 168 - number of hours in a week */
	uint32 hours_len; /* normally 21 bytes */
	uint8 hours[MAX_HOURS_LEN];

	uint32 unknown_5; /* 0x0002 0000 */
	uint32 unknown_6; /* 0x0000 04ec */
	
	/* relative pointers to dynamically allocated strings[] */
	int smb_name_offset;     /* username string */
	int full_name_offset;    /* user's full name string */
	int home_dir_offset;     /* home directory string */
	int dir_drive_offset;    /* home directory drive string */
	int logon_script_offset; /* logon script string */
	int profile_path_offset; /* profile path string */
	int acct_desc_offset;  /* user description string */
	int workstations_offset; /* login from workstations string */
	int unknown_str_offset; /* don't know what this is, yet. */
	int munged_dial_offset; /* munged path name and dial-back tel number */

	/* how to correctly declare this ?*/
	char strings[1]; 
};

struct tdb_enum_info
{
	TDB_CONTEXT *passwd_tdb;
	TDB_DATA key;
};

static struct tdb_enum_info tdb_ent;

/***************************************************************
 Start to enumerate the TDB passwd list. Returns a void pointer
 to ensure no modification outside this module.
****************************************************************/

static void *startsamtdbpwent(BOOL update)
{
  /* Open tdb passwd */
  if (!(tdb_ent.passwd_tdb = tdb_open_log(lp_tdb_passwd_file(), 0, 0, update ? O_RDWR : O_RDONLY, 0600)))
  {
     DEBUG(0, ("Unable to open TDB passwd, trying create new!\n"));
     if (!(tdb_ent.passwd_tdb = tdb_open_log(lp_tdb_passwd_file(), 0, 0, O_RDWR | O_CREAT | O_EXCL, 0600)))
     {
         DEBUG(0, ("Unable to creat TDB passwd (smbpasswd.tdb) !!!"));
	 return NULL;
     }
     return &tdb_ent;
  }
  tdb_ent.key = tdb_firstkey(tdb_ent.passwd_tdb);
  return &tdb_ent;
}

/***************************************************************
 End enumeration of the TDB passwd list.
****************************************************************/

static void endsamtdbpwent(void *vp)
{
  struct tdb_enum_info *p_ent = (struct tdb_enum_info *)vp;

  tdb_close(p_ent->passwd_tdb);
  DEBUG(7, ("endtdbpwent: closed password file.\n"));
}

static struct sam_passwd *getsamtdb21pwent(void *vp)
{
  static struct sam_passwd sam_entry;
  static struct tdb_sam_entry *tdb_entry;
  struct tdb_enum_info *p_ent = (struct tdb_enum_info *)vp;
  TDB_DATA data;

  if(p_ent == NULL) {
    DEBUG(0,("gettdbpwent: Bad TDB Context pointer.\n"));
    return NULL;
  }

  data = tdb_fetch (p_ent->passwd_tdb, p_ent->key);
  if (!data.dptr)
  {
    DEBUG(5,("gettdbpwent: database entry not found.\n"));
    return NULL;
  }
  
  tdb_entry = (struct tdb_sam_entry *)(data.dptr);

  sam_entry.logon_time = tdb_entry->logon_time;
  sam_entry.logoff_time = tdb_entry->logoff_time;
  sam_entry.kickoff_time = tdb_entry->kickoff_time;
  sam_entry.pass_last_set_time = tdb_entry->pass_last_set_time;
  sam_entry.pass_can_change_time = tdb_entry->pass_can_change_time;
  sam_entry.pass_must_change_time = tdb_entry->pass_must_change_time;
  sam_entry.smb_name = tdb_entry->strings + tdb_entry->smb_name_offset;
  sam_entry.full_name = tdb_entry->strings + tdb_entry->full_name_offset;
  sam_entry.home_dir = tdb_entry->strings + tdb_entry->home_dir_offset;
  sam_entry.dir_drive = tdb_entry->strings + tdb_entry->dir_drive_offset;
  sam_entry.logon_script = tdb_entry->strings + tdb_entry->logon_script_offset;
  sam_entry.profile_path = tdb_entry->strings + tdb_entry->profile_path_offset;
  sam_entry.acct_desc = tdb_entry->strings + tdb_entry->acct_desc_offset;
  sam_entry.workstations = tdb_entry->strings + tdb_entry->workstations_offset;
  sam_entry.unknown_str = tdb_entry->strings + tdb_entry->unknown_str_offset;
  sam_entry.munged_dial = tdb_entry->strings + tdb_entry->munged_dial_offset;
  sam_entry.smb_userid = tdb_entry->smb_userid;
  sam_entry.smb_grpid = tdb_entry->smb_grpid;
  sam_entry.user_rid = tdb_entry->user_rid;
  sam_entry.group_rid = tdb_entry->group_rid;
  sam_entry.smb_passwd = tdb_entry->smb_passwd;
  sam_entry.smb_nt_passwd = tdb_entry->smb_nt_passwd;
  sam_entry.acct_ctrl = tdb_entry->acct_ctrl;
  sam_entry.unknown_3 = tdb_entry->unknown_3;
  sam_entry.logon_divs = tdb_entry->logon_divs;
  sam_entry.hours_len = tdb_entry->hours_len;
  memcpy (sam_entry.hours, tdb_entry->hours, MAX_HOURS_LEN);
  sam_entry.unknown_5 = tdb_entry->unknown_5;
  sam_entry.unknown_6 = tdb_entry->unknown_6;

  p_ent->key = tdb_nextkey (p_ent->passwd_tdb, p_ent->key);

  return &sam_entry;
}

static BOOL del_samtdbpwd_entry(const char *name)
{
  TDB_CONTEXT *pwd_tdb;
  TDB_DATA key;
  fstring keystr;

  if (!(pwd_tdb = tdb_open_log(lp_tdb_passwd_file(), 0, 0, O_RDWR, 0600)))
  {
     DEBUG(0, ("Unable to open TDB passwd!"));
     return False;
  }
  
  slprintf(keystr, sizeof(keystr)-1, "USER_%s", name);
  dos_to_unix(keystr, True);               /* Convert key to unix-codepage */
  key.dptr = keystr;
  key.dsize = strlen (keystr) + 1;
  if (tdb_delete(pwd_tdb, key) != TDB_SUCCESS)
  {
  	DEBUG(5, ("Error deleting entry from tdb database!\n"));
	DEBUGADD(5, (" Error: %s\n", tdb_error(pwd_tdb)));
	tdb_close(pwd_tdb); 
	return False;
  }
  tdb_close(pwd_tdb);
  return True;
}

static BOOL mod_samtdb21pwd_entry(struct sam_passwd* newpwd, BOOL override)
{
  TDB_CONTEXT *pwd_tdb;
  TDB_DATA key;
  TDB_DATA data;
  struct tdb_sam_entry *tdb_entry;
  fstring keystr;
  
  int smb_name_len = (newpwd->smb_name) ? (strlen (newpwd->smb_name) + 1) : 0;
  int full_name_len = (newpwd->full_name) ? (strlen (newpwd->full_name) + 1) : 0;
  int home_dir_len = (newpwd->home_dir) ? (strlen (newpwd->home_dir) + 1) : 0;
  int dir_drive_len = (newpwd->dir_drive) ? (strlen (newpwd->dir_drive) + 1) : 0;
  int logon_script_len = (newpwd->logon_script) ? (strlen (newpwd->logon_script) + 1) : 0;
  int profile_path_len = (newpwd->profile_path) ? (strlen (newpwd->profile_path) + 1) : 0;
  int acct_desc_len = (newpwd->acct_desc) ? (strlen (newpwd->acct_desc) + 1) : 0;
  int workstations_len = (newpwd->workstations) ? (strlen (newpwd->workstations) + 1) : 0;
  int unknown_str_len = (newpwd->unknown_str) ? (strlen (newpwd->unknown_str) + 1) : 0;
  int munged_dial_len = (newpwd->munged_dial) ? (strlen (newpwd->munged_dial) + 1) : 0;
  
  if (!(pwd_tdb = tdb_open_log(lp_tdb_passwd_file(), 0, 0, O_RDWR, 0600)))
  {
     DEBUG(0, ("Unable to open TDB passwd!"));
     return False;
  }

  data.dsize = sizeof (struct tdb_sam_entry) +
  				smb_name_len +
				full_name_len +
				home_dir_len +
				dir_drive_len +
				logon_script_len +
				profile_path_len +
				acct_desc_len +
				workstations_len +
				unknown_str_len +
				munged_dial_len;

  tdb_entry = malloc (data.dsize);
  data.dptr = tdb_entry;
  memset (data.dptr, 0, data.dsize);

  tdb_entry->logon_time = newpwd->logon_time;
  tdb_entry->logoff_time = newpwd->logoff_time;
  tdb_entry->kickoff_time = newpwd->kickoff_time;
  tdb_entry->pass_last_set_time = newpwd->pass_last_set_time;
  tdb_entry->pass_can_change_time = newpwd->pass_can_change_time;
  tdb_entry->pass_must_change_time = newpwd->pass_must_change_time;
  tdb_entry->smb_userid = newpwd->smb_userid;
  tdb_entry->smb_grpid = newpwd->smb_grpid;
  tdb_entry->user_rid = newpwd->user_rid;
  tdb_entry->group_rid = newpwd->group_rid;
  memcpy (tdb_entry->smb_passwd, newpwd->smb_passwd, strlen (newpwd->smb_passwd) + 1);
  memcpy (tdb_entry->smb_nt_passwd, newpwd->smb_nt_passwd, strlen (newpwd->smb_nt_passwd) + 1);
  tdb_entry->acct_ctrl = newpwd->acct_ctrl;
  tdb_entry->unknown_3 = newpwd->unknown_3;
  tdb_entry->logon_divs = newpwd->logon_divs;
  tdb_entry->hours_len = newpwd->hours_len;
  memcpy (tdb_entry->hours, newpwd->hours, MAX_HOURS_LEN);
  tdb_entry->unknown_5 = newpwd->unknown_5;
  tdb_entry->unknown_6 = newpwd->unknown_6;
  tdb_entry->smb_name_offset = 0;
  tdb_entry->full_name_offset = smb_name_len;
  tdb_entry->home_dir_offset = tdb_entry->full_name_offset + full_name_len;
  tdb_entry->dir_drive_offset = tdb_entry->home_dir_offset + home_dir_len;
  tdb_entry->logon_script_offset = tdb_entry->dir_drive_offset + dir_drive_len;
  tdb_entry->profile_path_offset = tdb_entry->logon_script_offset + logon_script_len;
  tdb_entry->acct_desc_offset = tdb_entry->profile_path_offset + profile_path_len;
  tdb_entry->workstations_offset = tdb_entry->acct_desc_offset + acct_desc_len;
  tdb_entry->unknown_str_offset = tdb_entry->workstations_offset  + workstations_len;
  tdb_entry->munged_dial_offset = tdb_entry->unknown_str_offset + unknown_str_len;
  if (newpwd->smb_name)
    memcpy (tdb_entry->strings + tdb_entry->smb_name_offset, newpwd->smb_name, smb_name_len);
  if (newpwd->full_name)
    memcpy (tdb_entry->strings + tdb_entry->full_name_offset, newpwd->full_name, full_name_len);
  if (newpwd->home_dir)
    memcpy (tdb_entry->strings + tdb_entry->home_dir_offset, newpwd->home_dir, home_dir_len);
  if (newpwd->dir_drive)
    memcpy (tdb_entry->strings + tdb_entry->dir_drive_offset, newpwd->dir_drive, dir_drive_len);
  if (newpwd->logon_script)
    memcpy (tdb_entry->strings + tdb_entry->logon_script_offset, newpwd->logon_script, logon_script_len);
  if (newpwd->profile_path)
    memcpy (tdb_entry->strings + tdb_entry->profile_path_offset, newpwd->profile_path, profile_path_len);
  if (newpwd->acct_desc)
    memcpy (tdb_entry->strings + tdb_entry->acct_desc_offset, newpwd->acct_desc, acct_desc_len);
  if (newpwd->workstations)
    memcpy (tdb_entry->strings + tdb_entry->workstations_offset, newpwd->workstations, workstations_len);
  if (newpwd->unknown_str)
    memcpy (tdb_entry->strings + tdb_entry->unknown_str_offset, newpwd->unknown_str, unknown_str_len);
  if (newpwd->munged_dial)
    memcpy (tdb_entry->strings + tdb_entry->munged_dial_offset, newpwd->munged_dial, munged_dial_len);
 
  slprintf(keystr, sizeof(keystr)-1, "USER_%s", newpwd->smb_name);
  dos_to_unix(keystr, True);             /* Convert key to unix-codepage */
  key.dptr = keystr;
  key.dsize = strlen (keystr) + 1;
  
  tdb_writelock (pwd_tdb);
  if (tdb_store (pwd_tdb, key, data, TDB_MODIFY) != TDB_SUCCESS)
  {
      DEBUG(0, ("Unable to modify TDB passwd!"));
      DEBUGADD(0, (" Error: %s\n", tdb_error (pwd_tdb)));
      tdb_writeunlock (pwd_tdb);
      tdb_close (pwd_tdb);
      return False;
  }
  
  tdb_writeunlock (pwd_tdb);
  tdb_close (pwd_tdb);
  return True;
}

static BOOL add_samtdb21pwd_entry(struct sam_passwd *newpwd)
{
  TDB_CONTEXT *pwd_tdb;
  TDB_DATA key;
  TDB_DATA data;
  struct tdb_sam_entry *tdb_entry;
  fstring keystr;
  
  int smb_name_len = (newpwd->smb_name) ? (strlen (newpwd->smb_name) + 1) : 1;
  int full_name_len = (newpwd->full_name) ? (strlen (newpwd->full_name) + 1) : 1;
  int home_dir_len = (newpwd->home_dir) ? (strlen (newpwd->home_dir) + 1) : 1;
  int dir_drive_len = (newpwd->dir_drive) ? (strlen (newpwd->dir_drive) + 1) : 1;
  int logon_script_len = (newpwd->logon_script) ? (strlen (newpwd->logon_script) + 1) : 1;
  int profile_path_len = (newpwd->profile_path) ? (strlen (newpwd->profile_path) + 1) : 1;
  int acct_desc_len = (newpwd->acct_desc) ? (strlen (newpwd->acct_desc) + 1) : 1;
  int workstations_len = (newpwd->workstations) ? (strlen (newpwd->workstations) + 1) : 1;
  int unknown_str_len = (newpwd->unknown_str) ? (strlen (newpwd->unknown_str) + 1) : 1;
  int munged_dial_len = (newpwd->munged_dial) ? (strlen (newpwd->munged_dial) + 1) : 1;
  
  if (!(pwd_tdb = tdb_open_log(lp_tdb_passwd_file(), 0, 0, O_RDWR, 0600)))
  {
     DEBUG(0, ("Unable to open TDB passwd!"));
     return False;
  }

  data.dsize = sizeof (struct tdb_sam_entry) +
  				smb_name_len +
				full_name_len +
				home_dir_len +
				dir_drive_len +
				logon_script_len +
				profile_path_len +
				acct_desc_len +
				workstations_len +
				unknown_str_len +
				munged_dial_len;

  tdb_entry = malloc (data.dsize);
  data.dptr = tdb_entry;
  memset (data.dptr, 0, data.dsize);

  tdb_entry->logon_time = newpwd->logon_time;
  tdb_entry->logoff_time = newpwd->logoff_time;
  tdb_entry->kickoff_time = newpwd->kickoff_time;
  tdb_entry->pass_last_set_time = newpwd->pass_last_set_time;
  tdb_entry->pass_can_change_time = newpwd->pass_can_change_time;
  tdb_entry->pass_must_change_time = newpwd->pass_must_change_time;
  tdb_entry->smb_userid = newpwd->smb_userid;
  tdb_entry->smb_grpid = newpwd->smb_grpid;
  tdb_entry->user_rid = newpwd->user_rid;
  tdb_entry->group_rid = newpwd->group_rid;
  memcpy (tdb_entry->smb_passwd, newpwd->smb_passwd, strlen (newpwd->smb_passwd) + 1);
  memcpy (tdb_entry->smb_nt_passwd, newpwd->smb_nt_passwd, strlen (newpwd->smb_nt_passwd) + 1);
  tdb_entry->acct_ctrl = newpwd->acct_ctrl;
  tdb_entry->unknown_3 = newpwd->unknown_3;
  tdb_entry->logon_divs = newpwd->logon_divs;
  tdb_entry->hours_len = newpwd->hours_len;
  memcpy (tdb_entry->hours, newpwd->hours, MAX_HOURS_LEN);
  tdb_entry->unknown_5 = newpwd->unknown_5;
  tdb_entry->unknown_6 = newpwd->unknown_6;
  tdb_entry->smb_name_offset = 0;
  tdb_entry->full_name_offset = smb_name_len;
  tdb_entry->home_dir_offset = tdb_entry->full_name_offset + full_name_len;
  tdb_entry->dir_drive_offset = tdb_entry->home_dir_offset + home_dir_len;
  tdb_entry->logon_script_offset = tdb_entry->dir_drive_offset + dir_drive_len;
  tdb_entry->profile_path_offset = tdb_entry->logon_script_offset + logon_script_len;
  tdb_entry->acct_desc_offset = tdb_entry->profile_path_offset + profile_path_len;
  tdb_entry->workstations_offset = tdb_entry->acct_desc_offset + acct_desc_len;
  tdb_entry->unknown_str_offset = tdb_entry->workstations_offset  + workstations_len;
  tdb_entry->munged_dial_offset = tdb_entry->unknown_str_offset + unknown_str_len;
  if (newpwd->smb_name)
    memcpy (tdb_entry->strings + tdb_entry->smb_name_offset, newpwd->smb_name, smb_name_len);
  if (newpwd->full_name)
    memcpy (tdb_entry->strings + tdb_entry->full_name_offset, newpwd->full_name, full_name_len);
  if (newpwd->home_dir)
    memcpy (tdb_entry->strings + tdb_entry->home_dir_offset, newpwd->home_dir, home_dir_len);
  if (newpwd->dir_drive)
    memcpy (tdb_entry->strings + tdb_entry->dir_drive_offset, newpwd->dir_drive, dir_drive_len);
  if (newpwd->logon_script)
    memcpy (tdb_entry->strings + tdb_entry->logon_script_offset, newpwd->logon_script, logon_script_len);
  if (newpwd->profile_path)
    memcpy (tdb_entry->strings + tdb_entry->profile_path_offset, newpwd->profile_path, profile_path_len);
  if (newpwd->acct_desc)
    memcpy (tdb_entry->strings + tdb_entry->acct_desc_offset, newpwd->acct_desc, acct_desc_len);
  if (newpwd->workstations)
    memcpy (tdb_entry->strings + tdb_entry->workstations_offset, newpwd->workstations, workstations_len);
  if (newpwd->unknown_str)
    memcpy (tdb_entry->strings + tdb_entry->unknown_str_offset, newpwd->unknown_str, unknown_str_len);
  if (newpwd->munged_dial)
    memcpy (tdb_entry->strings + tdb_entry->munged_dial_offset, newpwd->munged_dial, munged_dial_len);
  
  slprintf(keystr, sizeof(keystr)-1, "USER_%s", newpwd->smb_name);
  dos_to_unix(keystr, True);             /* Convert key to unix-codepage */
  key.dptr = keystr;
  key.dsize = strlen (keystr) + 1;
  
  tdb_writelock (pwd_tdb);
  if (tdb_store (pwd_tdb, key, data, TDB_INSERT) != TDB_SUCCESS)
  {
      DEBUG(0, ("Unable to modify TDB passwd!"));
      DEBUGADD(0, (" Error: %s\n", tdb_error (pwd_tdb)));
      tdb_writeunlock (pwd_tdb);
      tdb_close (pwd_tdb);
      return False;
  }

  tdb_writeunlock (pwd_tdb);
  tdb_close (pwd_tdb);
  return True;
}

static struct sam_passwd *iterate_getsamtdb21pwrid(uint32 user_rid)
{
	struct sam_passwd *pwd = NULL;
	void *fp = NULL;

	DEBUG(10, ("search by smb_userid: %x\n", (int)user_rid));

	/* Open the smb password database - not for update. */
	fp = startsamtdbpwent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open smb password database.\n"));
		return NULL;
	}

	while ((pwd = getsamtdb21pwent(fp)) != NULL && pwd->user_rid != user_rid);

	if (pwd != NULL)
	{
		DEBUG(10, ("found by user_rid: %x\n", (int)user_rid));
	}

	endsamtdbpwent(fp);
	return pwd;
}

static struct sam_passwd *getsamtdb21pwnam(char *name)
{
  static struct sam_passwd sam_entry;
  static struct tdb_sam_entry *tdb_entry;
  TDB_CONTEXT *pwd_tdb;
  TDB_DATA data;
  TDB_DATA key;
  fstring keystr;

  if (!(pwd_tdb = tdb_open_log(lp_tdb_passwd_file(), 0, 0, O_RDONLY, 0600)))
  {
     DEBUG(0, ("Unable to open TDB passwd!"));
     return False;
  }

  slprintf(keystr, sizeof(keystr)-1, "USER_%s", name);
  dos_to_unix(keystr, True);             /* Convert key to unix-codepage */
  key.dptr = keystr;
  key.dsize = strlen (keystr) + 1;

  data = tdb_fetch (pwd_tdb, key);
  if (!data.dptr)
  {
    DEBUG(5,("getsamtdbpwent: error fetching database.\n"));
    DEBUGADD(5, (" Error: %s\n", tdb_error(pwd_tdb)));
    tdb_close (pwd_tdb);
    return NULL;
  }
  
  tdb_entry = (struct tdb_sam_entry *)(data.dptr);

  sam_entry.logon_time = tdb_entry->logon_time;
  sam_entry.logoff_time = tdb_entry->logoff_time;
  sam_entry.kickoff_time = tdb_entry->kickoff_time;
  sam_entry.pass_last_set_time = tdb_entry->pass_last_set_time;
  sam_entry.pass_can_change_time = tdb_entry->pass_can_change_time;
  sam_entry.pass_must_change_time = tdb_entry->pass_must_change_time;
  sam_entry.smb_name = tdb_entry->strings + tdb_entry->smb_name_offset;
  sam_entry.full_name = tdb_entry->strings + tdb_entry->full_name_offset;
  sam_entry.home_dir = tdb_entry->strings + tdb_entry->home_dir_offset;
  sam_entry.dir_drive = tdb_entry->strings + tdb_entry->dir_drive_offset;
  sam_entry.logon_script = tdb_entry->strings + tdb_entry->logon_script_offset;
  sam_entry.profile_path = tdb_entry->strings + tdb_entry->profile_path_offset;
  sam_entry.acct_desc = tdb_entry->strings + tdb_entry->acct_desc_offset;
  sam_entry.workstations = tdb_entry->strings + tdb_entry->workstations_offset;
  sam_entry.unknown_str = tdb_entry->strings + tdb_entry->unknown_str_offset;
  sam_entry.munged_dial = tdb_entry->strings + tdb_entry->munged_dial_offset;
  sam_entry.smb_userid = tdb_entry->smb_userid;
  sam_entry.smb_grpid = tdb_entry->smb_grpid;
  sam_entry.user_rid = tdb_entry->user_rid;
  sam_entry.group_rid = tdb_entry->group_rid;
  sam_entry.smb_passwd = tdb_entry->smb_passwd;
  sam_entry.smb_nt_passwd = tdb_entry->smb_nt_passwd;
  sam_entry.acct_ctrl = tdb_entry->acct_ctrl;
  sam_entry.unknown_3 = tdb_entry->unknown_3;
  sam_entry.logon_divs = tdb_entry->logon_divs;
  sam_entry.hours_len = tdb_entry->hours_len;
  memcpy (sam_entry.hours, tdb_entry->hours, MAX_HOURS_LEN);
  sam_entry.unknown_5 = tdb_entry->unknown_5;
  sam_entry.unknown_6 = tdb_entry->unknown_6;

  tdb_close (pwd_tdb);
  return &sam_entry;
}

static SMB_BIG_UINT getsamtdbpwpos(void *vp)
{
	return (SMB_BIG_UINT)0;
}

static BOOL setsamtdbpwpos(void *vp, SMB_BIG_UINT tok)
{
	return False;
}

static struct smb_passwd *getsamtdbpwent(void *vp)
{
	return pdb_sam_to_smb(getsamtdb21pwent(vp));
}

static BOOL add_samtdbpwd_entry(struct smb_passwd *newpwd)
{
	return add_samtdb21pwd_entry(pdb_smb_to_sam(newpwd));
}

static BOOL mod_samtdbpwd_entry(struct smb_passwd* pwd, BOOL override)
{
	return mod_samtdb21pwd_entry(pdb_smb_to_sam(pwd), override);
}

static struct sam_disp_info *getsamtdbdispnam(char *name)
{
	return pdb_sam_to_dispinfo(getsam21pwnam(name));
}

static struct sam_disp_info *getsamtdbdisprid(uint32 rid)
{
	return pdb_sam_to_dispinfo(getsam21pwrid(rid));
}

static struct sam_disp_info *getsamtdbdispent(void *vp)
{
	return pdb_sam_to_dispinfo(getsam21pwent(vp));
}

static struct smb_passwd *iterate_getsamtdbpwrid(uint32 user_rid)
{
	return pdb_sam_to_smb(iterate_getsamtdb21pwrid(user_rid));
}

static struct smb_passwd *getsamtdbpwnam(char *name)
{
	return pdb_sam_to_smb(getsamtdb21pwnam(name));
}

static struct passdb_ops tdb_ops = {
	startsamtdbpwent,
	endsamtdbpwent,
	getsamtdbpwpos,
	setsamtdbpwpos,
	getsamtdbpwnam,
	iterate_getsmbpwuid,          /* In passdb.c */
	iterate_getsamtdbpwrid,
	getsamtdbpwent,
	add_samtdbpwd_entry,
	mod_samtdbpwd_entry,
	del_samtdbpwd_entry,
	getsamtdb21pwent,
	getsamtdb21pwnam,

	/* TODO change get username from uid and then use
	   getsamtdb21pwnam */
	iterate_getsam21pwuid,

	iterate_getsamtdb21pwrid, 
	add_samtdb21pwd_entry,
	mod_samtdb21pwd_entry,
	getsamtdbdispnam,
	getsamtdbdisprid,
	getsamtdbdispent
};

struct passdb_ops *tdb_initialize_password_db(void)
{    
  return &tdb_ops;
}

#else
	/* Do *NOT* make this function static. It breaks the compile on gcc. JRA */
	void samtdb_dummy_function(void) { } /* stop some compilers complaining */
#endif /* WITH_TDBPWD */
