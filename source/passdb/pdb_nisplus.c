/*
 * Unix SMB/Netbios implementation. Version 1.9. SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1998 Modified by Jeremy Allison 1995.
 * Copyright (C) Benny Holmgren 1998 <bigfoot@astrakan.hgs.se> 
 * Copyright (C) Luke Kenneth Casson Leighton 1996-1998.
 * Copyright (C) Toomas Soome <tsoome@ut.ee> 2001
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

#ifdef WITH_NISPLUS_SAM

#ifdef BROKEN_NISPLUS_INCLUDE_FILES

/*
 * The following lines are needed due to buggy include files
 * in Solaris 2.6 which define GROUP in both /usr/include/sys/acl.h and
 * also in /usr/include/rpcsvc/nis.h. The definitions conflict. JRA.
 * Also GROUP_OBJ is defined as 0x4 in /usr/include/sys/acl.h and as
 * an enum in /usr/include/rpcsvc/nis.h.
 */

#if defined(GROUP)
#undef GROUP
#endif

#if defined(GROUP_OBJ)
#undef GROUP_OBJ
#endif

#endif

#include <rpcsvc/nis.h>

extern int      DEBUGLEVEL;
extern pstring	samlogon_user;
extern BOOL	sam_logon_in_ssb;

struct nisp_enum_info
{
	nis_result *result;
	int enum_entry;
};

static struct nisp_enum_info global_nisp_ent;
static SIG_ATOMIC_T gotalarm;

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
#define NPF_PWDCCHG_T     12
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

       slprintf(nisname, sizeof(nisname)-1, "[user_rid=%d],%s", rid, pfile);

	return nisname;
}

/***************************************************************
 make_nisname_from_name
 ****************************************************************/
static char *make_nisname_from_name(char *user_name, char *pfile)
{
	static pstring nisname;

       slprintf(nisname, sizeof(nisname)-1, "[name=%s],%s", user_name, pfile);

	return nisname;
}

/***************************************************************
 smb_passwd_table

 * if only plain table in is in pfile, org_dir will be concated.
 * so, at first we will clear path prefix from pfile, and
 * then we will use pfiletmp as playground to put together full
 * nisname string.
 * such approach will make it possible to specify samba private dir
 * AND still use NIS+ table. as all domain related data is normally
 * stored in org_dir.DOMAIN, this should be ok to do.
 ****************************************************************/
static char *smb_passwd_table(){
	char *sp, *p = lp_smb_passwd_file();
#if 1
	static pstring pfiletmp; 
#endif

	/* if lp_smb_passwd_file() returns anything wierd, pass it on */
	if (!p || !*p) return p;
	sp = strrchr( p, '/' );
	if (sp) p=sp+1;

#if 1
	/* append org_dir ONLY if plain table name is used.
	   why we do append it is because NIS_PATH env may not be set,
	   should we check if it's set?
	   do not append if lp_smb_passwd_file() returns an empty string
	*/
	if (!strchr(p, '.')){
	  slprintf(pfiletmp, sizeof(pfiletmp)-1, "%s.org_dir", p);
	  return pfiletmp;
	}
#endif
	return p;
	
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
		len = entry_len;
	}

	safe_strcpy(val, ENTRY_VAL(new_obj, col), len-1);
}

/************************************************************************
 makes a struct sam_passwd from a NIS+ object.
 ************************************************************************/
static BOOL make_sam_from_nisp_object(SAM_ACCOUNT *pw_buf, nis_object *obj)
{
  char *ptr;
  pstring full_name;    /* this must be translated to dos code page */
  pstring acct_desc;    /* this must be translated to dos code page */
  pstring home_dir;     /* set default value from smb.conf for user */
  pstring home_drive;   /* set default value from smb.conf for user */
  pstring logon_script; /* set default value from smb.conf for user */
  pstring profile_path; /* set default value from smb.conf for user */
  pstring hours;
  int hours_len;
  unsigned char smbpwd[16];
  unsigned char smbntpwd[16];
  

  /*
   * time values. note: this code assumes 32bit time_t!
   */

  pdb_set_logon_time(pw_buf, (time_t)0);
  ptr = ENTRY_VAL(obj, NPF_LOGON_T);
  if(ptr && *ptr && (StrnCaseCmp(ptr, "LNT-", 4)==0)) {
    int i;
    ptr += 4;
    for(i = 0; i < 8; i++) {
      if(ptr[i] == '\0' || !isxdigit(ptr[i]))
	break;
    }
    if(i == 8) {
      pdb_set_logon_time(pw_buf, (time_t)strtol(ptr, NULL, 16));
    }
  }

  pdb_set_logoff_time(pw_buf, get_time_t_max());
  ptr = ENTRY_VAL(obj, NPF_LOGOFF_T);
  if(ptr && *ptr && (StrnCaseCmp(ptr, "LOT-", 4)==0)) {
    int i;
    ptr += 4;
    for(i = 0; i < 8; i++) {
      if(ptr[i] == '\0' || !isxdigit(ptr[i]))
	break;
    }
    if(i == 8) {
      pdb_set_logoff_time(pw_buf, (time_t)strtol(ptr, NULL, 16));
    }
  }

  pdb_set_kickoff_time(pw_buf, get_time_t_max());
  ptr = ENTRY_VAL(obj, NPF_KICK_T);
  if(ptr && *ptr && (StrnCaseCmp(ptr, "KOT-", 4)==0)) {
    int i;
    ptr += 4;
    for(i = 0; i < 8; i++) {
      if(ptr[i] == '\0' || !isxdigit(ptr[i]))
	break;
    }
    if(i == 8) {
      pdb_set_kickoff_time(pw_buf, (time_t)strtol(ptr, NULL, 16));
    }
  }

  pdb_set_pass_last_set_time(pw_buf, (time_t)0);
  ptr = ENTRY_VAL(obj, NPF_PWDLSET_T);
  if(ptr && *ptr && (StrnCaseCmp(ptr, "LCT-", 4)==0)) {
    int i;
    ptr += 4;
    for(i = 0; i < 8; i++) {
      if(ptr[i] == '\0' || !isxdigit(ptr[i]))
	break;
    }
    if(i == 8) {
      pdb_set_pass_last_set_time(pw_buf, (time_t)strtol(ptr, NULL, 16));
    }
  }
  
  pdb_set_pass_can_change_time(pw_buf, (time_t)0);
  ptr = ENTRY_VAL(obj, NPF_PWDCCHG_T);
  if(ptr && *ptr && (StrnCaseCmp(ptr, "CCT-", 4)==0)) {
    int i;
    ptr += 4;
    for(i = 0; i < 8; i++) {
      if(ptr[i] == '\0' || !isxdigit(ptr[i]))
	break;
    }
    if(i == 8) {
      pdb_set_pass_can_change_time(pw_buf, (time_t)strtol(ptr, NULL, 16));
    }
  }
  
  pdb_set_pass_must_change_time(pw_buf, get_time_t_max()); /* Password never expires. */
  ptr = ENTRY_VAL(obj, NPF_PWDMCHG_T);
  if(ptr && *ptr && (StrnCaseCmp(ptr, "MCT-", 4)==0)) {
    int i;
    ptr += 4;
    for(i = 0; i < 8; i++) {
      if(ptr[i] == '\0' || !isxdigit(ptr[i]))
	break;
    }
    if(i == 8) {
      pdb_set_pass_must_change_time(pw_buf, (time_t)strtol(ptr, NULL, 16));
    }
  }

  /* string values */
  pdb_set_username(pw_buf, ENTRY_VAL(obj, NPF_NAME));
  pdb_set_domain(pw_buf, lp_workgroup());
  /* pdb_set_nt_username() -- cant set it here... */

  get_single_attribute(obj, NPF_FULL_NAME, full_name, sizeof(pstring));
  unix_to_dos(full_name);
  pdb_set_fullname(pw_buf, full_name);

  pdb_set_acct_ctrl(pw_buf, pdb_decode_acct_ctrl(ENTRY_VAL(obj,
							   NPF_ACB)));

  get_single_attribute(obj, NPF_ACCT_DESC, acct_desc, sizeof(pstring));
  unix_to_dos(acct_desc);
  pdb_set_acct_desc(pw_buf, acct_desc);

  pdb_set_workstations(pw_buf, ENTRY_VAL(obj, NPF_WORKSTATIONS));
  pdb_set_munged_dial(pw_buf, NULL);

/* Might want to consult sys_getpwnam for the following two.
  for now, use same default as pdb_fill-default_sam */

  ptr = ENTRY_VAL(obj, NPF_UID);
  pdb_set_uid(pw_buf, ptr ? atoi(ptr) : -1);

  ptr = ENTRY_VAL(obj, NPF_SMB_GRPID);
  pdb_set_gid(pw_buf, ptr ? atoi(ptr) : -1);


  ptr = ENTRY_VAL(obj, NPF_USER_RID); 
  pdb_set_user_rid(pw_buf, ptr ? atoi(ptr) : 
	pdb_uid_to_user_rid(pdb_get_uid(pw_buf)));

  ptr = ENTRY_VAL(obj, NPF_GROUP_RID);
  pdb_set_group_rid(pw_buf, ptr ? atoi(ptr) :
	pdb_gid_to_group_rid(pdb_get_gid(pw_buf)));


  /* values, must exist for user */
  if( !(pdb_get_acct_ctrl(pw_buf) & ACB_WSTRUST) ) {
    /* FIXME!!  This doesn't belong here. 
       Should be set in net_sam_logon() 
       --jerry */
    pstrcpy(samlogon_user, pdb_get_username(pw_buf));
    
    get_single_attribute(obj, NPF_HOME_DIR, home_dir, sizeof(pstring));
    if( !(home_dir && *home_dir) ) {
      pstrcpy(home_dir, lp_logon_home());
      pdb_set_homedir(pw_buf, home_dir, False);
    }
    else
      pdb_set_homedir(pw_buf, home_dir, True);

    get_single_attribute(obj, NPF_DIR_DRIVE, home_drive, sizeof(pstring));
    if( !(home_drive && *home_drive) ) {
      pstrcpy(home_drive, lp_logon_drive());
      pdb_set_dir_drive(pw_buf, home_drive, False);
    }
    else
      pdb_set_dir_drive(pw_buf, home_drive, True);

    get_single_attribute(obj, NPF_LOGON_SCRIPT, logon_script,
			 sizeof(pstring));
    if( !(logon_script && *logon_script) ) {
      pstrcpy(logon_script, lp_logon_script());
      pdb_set_logon_script(pw_buf, logon_script, False);
    }
    else
      pdb_set_logon_script(pw_buf, logon_script, True);

    get_single_attribute(obj, NPF_PROFILE_PATH, profile_path, sizeof(pstring));
    if( !(profile_path && *profile_path) ) {
      pstrcpy(profile_path, lp_logon_path());
      pdb_set_profile_path(pw_buf, profile_path, False);
    }
    else
      pdb_set_profile_path(pw_buf, profile_path, True);

  } 
  else 
  {
    /* lkclXXXX this is OBSERVED behaviour by NT PDCs, enforced here. */
    pdb_set_group_rid (pw_buf, DOMAIN_GROUP_RID_USERS); 
  }

  /* Check the lanman password column. */
  ptr = ENTRY_VAL(obj, NPF_LMPWD);
  if (!pdb_set_lanman_passwd(pw_buf, NULL))
	return False;

  if (!strncasecmp(ptr, "NO PASSWORD", 11)) {
    pdb_set_acct_ctrl(pw_buf, pdb_get_acct_ctrl(pw_buf) | ACB_PWNOTREQ);
  } else {
    if (strlen(ptr) != 32 || !pdb_gethexpwd(ptr, smbpwd)) {
      DEBUG(0, ("malformed LM pwd entry: %s.\n",
		pdb_get_username(pw_buf)));
      return False;
    } 
    if (!pdb_set_lanman_passwd(pw_buf, smbpwd))
		return False;
  }
  
  /* Check the NT password column. */
  ptr = ENTRY_VAL(obj, NPF_NTPWD);
  if (!pdb_set_nt_passwd(pw_buf, NULL))
	return False;
  
  if (!(pdb_get_acct_ctrl(pw_buf) & ACB_PWNOTREQ) &&
      strncasecmp(ptr, "NO PASSWORD", 11)) {
    if (strlen(ptr) != 32 || !pdb_gethexpwd(ptr, smbntpwd)) {
      DEBUG(0, ("malformed NT pwd entry:\
 uid = %d.\n",
		pdb_get_uid(pw_buf)));
      return False;
    }
    if (!pdb_set_nt_passwd(pw_buf, smbntpwd))
		return False;
  }
  
  pdb_set_unknown_3(pw_buf, 0xffffff); /* don't know */
  pdb_set_logon_divs(pw_buf, 168);     /* hours per week */
		      
		      if( (hours_len = ENTRY_LEN(obj, NPF_HOURS)) == 21 ) {
    memcpy(hours, ENTRY_VAL(obj, NPF_HOURS), hours_len);
  } else {
    hours_len = 21; /* 21 times 8 bits = 168 */
    /* available at all hours */
    memset(hours, 0xff, hours_len);
  }
  pdb_set_hours_len(pw_buf, hours_len);
  pdb_set_hours(pw_buf, (uchar *)hours);

  pdb_set_unknown_5(pw_buf, 0x00020000); /* don't know */
  pdb_set_unknown_6(pw_buf, 0x000004ec); /* don't know */

  return True;
}

/************************************************************************
 makes a struct sam_passwd from a NIS+ result.
 ************************************************************************/
static BOOL make_sam_from_nisresult(SAM_ACCOUNT *pw_buf, nis_result *result)
{
	if (pw_buf == NULL || result == NULL) return False;

	if (result->status != NIS_SUCCESS && result->status != NIS_NOTFOUND)
	{
		DEBUG(0, ("NIS+ lookup failure: %s\n",
		           nis_sperrno(result->status)));
		return False;
	}

	/* User not found. */
	if (NIS_RES_NUMOBJ(result) <= 0)
	{
		DEBUG(10, ("user not found in NIS+\n"));
		return False;
	}

	if (NIS_RES_NUMOBJ(result) > 1)
	{
		DEBUG(10, ("WARNING: Multiple entries for user in NIS+ table!\n"));
	}

	/* Grab the first hit. */
	return make_sam_from_nisp_object(pw_buf, &NIS_RES_OBJECT(result)[0]);
}

/*************************************************************************
 sets a NIS+ attribute
 *************************************************************************/
static void set_single_attribute(nis_object *new_obj, int col,
				char *val, int len, int flags)
{
	if (new_obj == NULL) return;

	ENTRY_VAL(new_obj, col) = val;
	ENTRY_LEN(new_obj, col) = len+1;

	if (flags != 0)
	{
		new_obj->EN_data.en_cols.en_cols_val[col].ec_flags = flags;
	}
}

/***************************************************************
 copy or modify nis object. this object is used to add or update
 nisplus table entry.
 ****************************************************************/
static BOOL init_nisp_from_sam(nis_object *obj, SAM_ACCOUNT *sampass,
			       nis_object *old)
{
  /*
   * Fill nis_object for entry add or update.
   * if we are updateing, we have to find out differences and set
   * EN_MODIFIED flag. also set need_to_modify to trigger
   * nis_modify_entry() call in pdb_update_sam_account().
   *
   * TODO:
   *   get data from SAM
   *   if (modify) get data from nis_object, compare and store if
   *               different + set EN_MODIFIED and need_to_modify
   *   else
   *               store
   */
  BOOL need_to_modify = False;
  char *name;                      /* from SAM */
  /* these must be static or allocate and free entry columns! */
  static fstring uid;                     /* from SAM */
  static fstring user_rid;                /* from SAM */
  static fstring gid;                     /* from SAM */
  static fstring group_rid;               /* from SAM */
  char *acb;                       /* from SAM */
  static fstring smb_passwd;              /* from SAM */
  static fstring smb_nt_passwd;           /* from SAM */
  static fstring logon_t;                 /* from SAM */
  static fstring logoff_t;                /* from SAM */
  static fstring kickoff_t;               /* from SAM */
  static fstring pwdlset_t;               /* from SAM */
  static fstring pwdlchg_t;               /* from SAM */
  static fstring pwdmchg_t;               /* from SAM */
  static fstring full_name;               /* from SAM */
  static fstring acct_desc;               /* from SAM */
  static char empty[1];                   /* just an empty string */


  name = pdb_get_username(sampass);
  slprintf(uid, sizeof(uid)-1, "%u", pdb_get_uid(sampass));
  slprintf(user_rid, sizeof(user_rid)-1, "%u",
	   pdb_get_user_rid(sampass)? pdb_get_user_rid(sampass):
	   pdb_uid_to_user_rid(pdb_get_uid(sampass))); 
  slprintf(gid, sizeof(gid)-1, "%u", pdb_get_gid(sampass));
  slprintf(group_rid, sizeof(group_rid)-1, "%u",
	   pdb_get_group_rid(sampass)? pdb_get_group_rid(sampass):
	   pdb_gid_to_group_rid(pdb_get_gid(sampass)));
  acb = pdb_encode_acct_ctrl(pdb_get_acct_ctrl(sampass),
			     NEW_PW_FORMAT_SPACE_PADDED_LEN);
  pdb_sethexpwd (smb_passwd, pdb_get_lanman_passwd(sampass),
		 pdb_get_acct_ctrl(sampass));
  pdb_sethexpwd (smb_nt_passwd, pdb_get_nt_passwd(sampass),
		 pdb_get_acct_ctrl(sampass));
  slprintf(logon_t, 13, "LNT-%08X",
	   (uint32)pdb_get_logon_time(sampass));
  slprintf(logoff_t, 13, "LOT-%08X",
	   (uint32)pdb_get_logoff_time(sampass));
  slprintf(kickoff_t, 13, "KOT-%08X",
	   (uint32)pdb_get_kickoff_time(sampass));
  slprintf(pwdlset_t, 13, "LCT-%08X",
	   (uint32)pdb_get_pass_last_set_time(sampass));
  slprintf(pwdlchg_t, 13, "CCT-%08X",
	   (uint32)pdb_get_pass_can_change_time(sampass));
  slprintf(pwdmchg_t, 13, "MCT-%08X",
	   (uint32)pdb_get_pass_must_change_time(sampass));
  safe_strcpy(full_name, pdb_get_fullname(sampass), sizeof(full_name)-1);
  dos_to_unix(full_name);
  safe_strcpy(acct_desc, pdb_get_acct_desc(sampass), sizeof(acct_desc)-1);
  dos_to_unix(acct_desc);
  
  if( old ) {
    /* name */
    if(strcmp(ENTRY_VAL(old, NPF_NAME), name))
      {
	need_to_modify = True;
	set_single_attribute(obj, NPF_NAME, name, strlen(name),
			     EN_MODIFIED);
      }


    /* uid */
    if(pdb_get_uid(sampass) != -1) {
      if(!ENTRY_VAL(old, NPF_UID) || strcmp(ENTRY_VAL(old, NPF_UID), uid)) 
	{
	  need_to_modify = True;
	  set_single_attribute(obj, NPF_UID, uid,
			       strlen(uid), EN_MODIFIED);
	}
    }
      
    /* user_rid */
    if (pdb_get_user_rid(sampass)) {
      if(!ENTRY_VAL(old, NPF_USER_RID) ||
	 strcmp(ENTRY_VAL(old, NPF_USER_RID), user_rid) ) {
	need_to_modify = True;
	set_single_attribute(obj, NPF_USER_RID, user_rid,
			     strlen(user_rid), EN_MODIFIED);
      }
    }
    
    /* smb_grpid */
    if (pdb_get_gid(sampass) != -1) {
      if(!ENTRY_VAL(old, NPF_SMB_GRPID) ||
	 strcmp(ENTRY_VAL(old, NPF_SMB_GRPID), gid) ) {
	need_to_modify = True;
	set_single_attribute(obj, NPF_SMB_GRPID, gid,
			     strlen(gid), EN_MODIFIED);
      }
    }

    /* group_rid */
    if (pdb_get_group_rid(sampass)) {
      if(!ENTRY_VAL(old, NPF_GROUP_RID) ||
	 strcmp(ENTRY_VAL(old, NPF_GROUP_RID), group_rid) ) {
	need_to_modify = True;
	set_single_attribute(obj, NPF_GROUP_RID, group_rid,
			     strlen(group_rid), EN_MODIFIED);
      }
    }

    /* acb */
    if (!ENTRY_VAL(old, NPF_ACB) || 
	strcmp(ENTRY_VAL(old, NPF_ACB), acb)) {
      need_to_modify = True;
      set_single_attribute(obj, NPF_ACB, acb, strlen(acb), EN_MODIFIED);
    }
    
    /* lmpwd */
    if(!ENTRY_VAL(old, NPF_LMPWD) || 
       strcmp(ENTRY_VAL(old, NPF_LMPWD), smb_passwd) ) {
      need_to_modify = True;
      set_single_attribute(obj, NPF_LMPWD, smb_passwd,
			   strlen(smb_passwd), EN_CRYPT|EN_MODIFIED);
    }

    /* ntpwd */
    if(!ENTRY_VAL(old, NPF_NTPWD) ||
       strcmp(ENTRY_VAL(old, NPF_NTPWD), smb_nt_passwd) ) {
      need_to_modify = True;
      set_single_attribute(obj, NPF_NTPWD, smb_nt_passwd,
			   strlen(smb_nt_passwd), EN_CRYPT|EN_MODIFIED);
    }

    /* logon_t */
    if( pdb_get_logon_time(sampass) && 
	(!ENTRY_VAL(old, NPF_LOGON_T) ||
	 strcmp(ENTRY_VAL(old, NPF_LOGON_T), logon_t ))) {
      need_to_modify = True;
      set_single_attribute(obj, NPF_LOGON_T, logon_t,
			   strlen(logon_t), EN_MODIFIED);
    }

    /* logoff_t */
    if( pdb_get_logoff_time(sampass) && 
	(!ENTRY_VAL(old, NPF_LOGOFF_T) ||
	 strcmp(ENTRY_VAL(old, NPF_LOGOFF_T), logoff_t))) {
      need_to_modify = True;
      set_single_attribute(obj, NPF_LOGOFF_T, logoff_t,
			   strlen(logoff_t), EN_MODIFIED);
    }

    /* kick_t */
    if( pdb_get_kickoff_time(sampass) &&
	(!ENTRY_VAL(old, NPF_KICK_T) ||
	 strcmp(ENTRY_VAL(old, NPF_KICK_T), kickoff_t))) {
      need_to_modify = True;
      set_single_attribute(obj, NPF_KICK_T, kickoff_t,
			   strlen(kickoff_t), EN_MODIFIED);
    }
    
    /* pwdlset_t */
    if( pdb_get_pass_last_set_time(sampass) &&
	(!ENTRY_VAL(old, NPF_PWDLSET_T) ||
	 strcmp(ENTRY_VAL(old, NPF_PWDLSET_T), pwdlset_t))) {
      need_to_modify = True;
      set_single_attribute(obj, NPF_PWDLSET_T, pwdlset_t,
			   strlen(pwdlset_t), EN_MODIFIED);
    }

    /* pwdlchg_t */
    if( pdb_get_pass_can_change_time(sampass) &&
	(!ENTRY_VAL(old, NPF_PWDCCHG_T) ||
	 strcmp(ENTRY_VAL(old, NPF_PWDCCHG_T), pwdlchg_t))) {
      need_to_modify = True;
      set_single_attribute(obj, NPF_PWDCCHG_T, pwdlchg_t,
			   strlen(pwdlchg_t), EN_MODIFIED);
    }

    /* pwdmchg_t */
    if( pdb_get_pass_must_change_time(sampass) &&
	(!ENTRY_VAL(old, NPF_PWDMCHG_T) ||
	 strcmp(ENTRY_VAL(old, NPF_PWDMCHG_T), pwdmchg_t))) {
      need_to_modify = True;
      set_single_attribute(obj, NPF_PWDMCHG_T, pwdmchg_t,
			   strlen(pwdmchg_t), EN_MODIFIED);
    }
    
    /* full_name */
    /* must support set, unset and change */
    if ( (pdb_get_fullname(sampass) &&
	  !ENTRY_VAL(old, NPF_FULL_NAME)) ||
	 (ENTRY_VAL(old, NPF_FULL_NAME) &&
	  !pdb_get_fullname(sampass))  ||
	 (ENTRY_VAL(old, NPF_FULL_NAME) &&
	  pdb_get_fullname(sampass) && 
	  strcmp( ENTRY_VAL(old, NPF_FULL_NAME), full_name ))) {
      need_to_modify = True;
      set_single_attribute(obj, NPF_FULL_NAME, full_name,
			   strlen(full_name), EN_MODIFIED);
    }
    
    /* home_dir */
    /* must support set, unset and change */
    if( (pdb_get_homedir(sampass) && 
	 !ENTRY_VAL(old, NPF_HOME_DIR)) ||
	(ENTRY_VAL(old, NPF_HOME_DIR) && 
	 !pdb_get_homedir(sampass)) ||
	(ENTRY_VAL(old, NPF_HOME_DIR) && 
	 pdb_get_homedir(sampass) &&
	 strcmp( ENTRY_VAL(old, NPF_HOME_DIR),
		 pdb_get_homedir(sampass)))) {
      need_to_modify = True;
      set_single_attribute(obj, NPF_HOME_DIR, pdb_get_homedir(sampass),
			   strlen(pdb_get_homedir(sampass)), EN_MODIFIED);
    }
    
    /* dir_drive */
    /* must support set, unset and change */
    if( (pdb_get_dirdrive(sampass) && 
	 !ENTRY_VAL(old, NPF_DIR_DRIVE)) ||
	(ENTRY_VAL(old, NPF_DIR_DRIVE) && 
	 !pdb_get_dirdrive(sampass)) ||
	(ENTRY_VAL(old, NPF_DIR_DRIVE) && 
	 pdb_get_dirdrive(sampass) &&
	 strcmp( ENTRY_VAL(old, NPF_DIR_DRIVE),
		 pdb_get_dirdrive(sampass)))) {
      need_to_modify = True;
      set_single_attribute(obj, NPF_DIR_DRIVE, pdb_get_dirdrive(sampass),
			   strlen(pdb_get_dirdrive(sampass)), EN_MODIFIED);
    }
    
    /* logon_script */
    /* must support set, unset and change */
    if( (pdb_get_logon_script(sampass) && 
	 !ENTRY_VAL(old, NPF_LOGON_SCRIPT) ||
	 (ENTRY_VAL(old, NPF_LOGON_SCRIPT) &&
	  !pdb_get_logon_script(sampass)) ||
	 ( ENTRY_VAL(old, NPF_LOGON_SCRIPT) &&
	   pdb_get_logon_script(sampass) &&
	   strcmp( ENTRY_VAL(old, NPF_LOGON_SCRIPT),
		   pdb_get_logon_script(sampass))))) {
      need_to_modify = True;
      set_single_attribute(obj, NPF_LOGON_SCRIPT,
			   pdb_get_logon_script(sampass),
			   strlen(pdb_get_logon_script(sampass)),
			   EN_MODIFIED);
    }
    
    /* profile_path */
    /* must support set, unset and change */
    if( (pdb_get_profile_path(sampass) && 
	 !ENTRY_VAL(old, NPF_PROFILE_PATH)) || 
	(ENTRY_VAL(old, NPF_PROFILE_PATH) &&
	 !pdb_get_profile_path(sampass)) ||
	(ENTRY_VAL(old, NPF_PROFILE_PATH) &&
	 pdb_get_profile_path(sampass) &&
	 strcmp( ENTRY_VAL(old, NPF_PROFILE_PATH),
		 pdb_get_profile_path(sampass) ) )) {
      need_to_modify = True;
      set_single_attribute(obj, NPF_PROFILE_PATH,
			   pdb_get_profile_path(sampass),
			   strlen(pdb_get_profile_path(sampass)),
			   EN_MODIFIED);
    }
    
    /* acct_desc */
    /* must support set, unset and change */
    if( (pdb_get_acct_desc(sampass) &&
	 !ENTRY_VAL(old, NPF_ACCT_DESC)) || 
	(ENTRY_VAL(old, NPF_ACCT_DESC) && 
	 !pdb_get_acct_desc(sampass)) ||
	(ENTRY_VAL(old, NPF_ACCT_DESC) && 
	 pdb_get_acct_desc(sampass) &&
	 strcmp( ENTRY_VAL(old, NPF_ACCT_DESC), acct_desc ) )) {
      need_to_modify = True;
      set_single_attribute(obj, NPF_ACCT_DESC, acct_desc,
			   strlen(acct_desc), EN_MODIFIED);
    }

    /* workstations */
    /* must support set, unset and change */
    if ( (pdb_get_workstations(sampass) &&
	  !ENTRY_VAL(old, NPF_WORKSTATIONS) ) ||
	 (ENTRY_VAL(old, NPF_WORKSTATIONS) &&
	  !pdb_get_workstations(sampass)) ||
	 (ENTRY_VAL(old, NPF_WORKSTATIONS) &&
	  pdb_get_workstations(sampass)) &&
	 strcmp( ENTRY_VAL(old, NPF_WORKSTATIONS), 
		 pdb_get_workstations(sampass))) {
      need_to_modify = True;
      set_single_attribute(obj, NPF_WORKSTATIONS,
			   pdb_get_workstations(sampass),
			   strlen(pdb_get_workstations(sampass)),
			   EN_MODIFIED);
    }
    
    /* hours */
    if ((pdb_get_hours_len(sampass) != ENTRY_LEN(old, NPF_HOURS)) ||
	memcmp(pdb_get_hours(sampass), ENTRY_VAL(old, NPF_HOURS),
	       ENTRY_LEN(old, NPF_HOURS))) {
      need_to_modify = True;
      /* set_single_attribute will add 1 for len ... */
      set_single_attribute(obj, NPF_HOURS, (char *)pdb_get_hours(sampass), 
			   pdb_get_hours_len(sampass)-1, EN_MODIFIED);
    }  
  } else {
    char *homedir, *dirdrive, *logon_script, *profile_path, *workstations;

    *empty = '\0'; /* empty string */

    set_single_attribute(obj, NPF_NAME, name, strlen(name), 0);
    set_single_attribute(obj, NPF_UID, uid, strlen(uid), 0);
    set_single_attribute(obj, NPF_USER_RID, user_rid,
			 strlen(user_rid), 0);
    set_single_attribute(obj, NPF_SMB_GRPID, gid, strlen(gid), 0);
    set_single_attribute(obj, NPF_GROUP_RID, group_rid,
			 strlen(group_rid), 0);
    set_single_attribute(obj, NPF_ACB, acb, strlen(acb), 0);
    set_single_attribute(obj, NPF_LMPWD, smb_passwd,
			 strlen(smb_passwd), EN_CRYPT);
    set_single_attribute(obj, NPF_NTPWD, smb_nt_passwd,
			 strlen(smb_nt_passwd), EN_CRYPT);
    set_single_attribute(obj, NPF_LOGON_T, logon_t,
			 strlen(logon_t), 0);
    set_single_attribute(obj, NPF_LOGOFF_T, logoff_t,
			 strlen(logoff_t), 0);
    set_single_attribute(obj, NPF_KICK_T, kickoff_t,
			 strlen(kickoff_t),0);
    set_single_attribute(obj, NPF_PWDLSET_T, pwdlset_t, 
			 strlen(pwdlset_t), 0);
    set_single_attribute(obj, NPF_PWDCCHG_T, pwdlchg_t,
			 strlen(pwdlchg_t), 0);
    set_single_attribute(obj, NPF_PWDMCHG_T, pwdmchg_t,
			 strlen(pwdmchg_t), 0);
    set_single_attribute(obj, NPF_FULL_NAME     , 
			 full_name, strlen(full_name), 0);

    if(!(homedir = pdb_get_homedir(sampass)))
      homedir = empty;

    set_single_attribute(obj, NPF_HOME_DIR,
			 homedir, strlen(homedir), 0);
    
    if(!(dirdrive = pdb_get_dirdrive(sampass)))
       dirdrive = empty;
       
    set_single_attribute(obj, NPF_DIR_DRIVE,
			 dirdrive, strlen(dirdrive), 0);
    
    if(!(logon_script = pdb_get_logon_script(sampass)))
       logon_script = empty;
    
    set_single_attribute(obj, NPF_LOGON_SCRIPT,
			 logon_script, strlen(logon_script), 0);
    
    if(!(profile_path = pdb_get_profile_path(sampass)))
      profile_path = empty;

    set_single_attribute(obj, NPF_PROFILE_PATH,
			 profile_path, strlen(profile_path), 0);
    
    set_single_attribute(obj, NPF_ACCT_DESC,
			 acct_desc, strlen(acct_desc), 0);
    
    if(!(workstations = pdb_get_workstations(sampass)))
      workstations = empty;
    
    set_single_attribute(obj, NPF_WORKSTATIONS,	
			 workstations, strlen(workstations), 0);
    
    /* set_single_attribute will add 1 for len ... */
    set_single_attribute(obj, NPF_HOURS,
			 (char *)pdb_get_hours(sampass),
			 pdb_get_hours_len(sampass)-1, 0);
  }
  
  return need_to_modify;
}

/***************************************************************
 calls nis_list, returns results.
 ****************************************************************/
static nis_result *nisp_get_nis_list(char *nis_name, unsigned int flags)
{
	nis_result *result;
	int i;

	if( ! flags)
	  flags = FOLLOW_LINKS|FOLLOW_PATH|EXPAND_NAME|HARD_LOOKUP;

	for(i = 0; i<2;i++ ) {
	  alarm(60);		/* hopefully ok for long searches */
	  result = nis_list(nis_name, flags,NULL,NULL);

	  alarm(0);
	  CatchSignal(SIGALRM, SIGNAL_CAST SIG_DFL);

	  if (gotalarm)
	  {
		DEBUG(0,("NIS+ lookup time out\n"));
		nis_freeresult(result);
		return NULL;
	  }
	  if( !(flags & MASTER_ONLY) && NIS_RES_NUMOBJ(result) <= 0 ) {
	    /* nis replicas are not in sync perhaps?
             * this can happen, if account was just added.
             */
	    DEBUG(10,("will try master only\n"));
            nis_freeresult(result);
            flags |= MASTER_ONLY;
          } else
            break;
	}
	return result;
}

/***************************************************************
 Start to enumerate the nisplus passwd list.
 ****************************************************************/
BOOL pdb_setsampwent(BOOL update)
{
	char *pfile = smb_passwd_table();

	pdb_endsampwent();	/* just in case */
	global_nisp_ent.result = nisp_get_nis_list( pfile, 0 );
	global_nisp_ent.enum_entry = 0;
	return global_nisp_ent.result != NULL ? True : False;
}

/***************************************************************
 End enumeration of the nisplus passwd list.
****************************************************************/
void pdb_endsampwent(void)
{
  if( global_nisp_ent.result )
    nis_freeresult(global_nisp_ent.result);
  global_nisp_ent.result = NULL;
  global_nisp_ent.enum_entry = 0;
}

/*************************************************************************
 Routine to return the next entry in the nisplus passwd list.
 *************************************************************************/
BOOL pdb_getsampwent(SAM_ACCOUNT *user)
{
  int enum_entry = (int)(global_nisp_ent.enum_entry);
  nis_result *result = global_nisp_ent.result;
  
  if (user==NULL) {
	DEBUG(0,("SAM_ACCOUNT is NULL.\n"));
	return False;
  }

  if (result == NULL ||
      enum_entry < 0 || enum_entry >= (NIS_RES_NUMOBJ(result) - 1))
  {
	return False;
  } 

  if(!make_sam_from_nisp_object(user, &NIS_RES_OBJECT(result)[enum_entry]) )
  {
    DEBUG(0,("Bad SAM_ACCOUNT entry returned from NIS+!\n"));
	return False;
  }
  (int)(global_nisp_ent.enum_entry)++;
  return True;
}

/*************************************************************************
 Routine to search the nisplus passwd file for an entry matching the username
 *************************************************************************/
BOOL pdb_getsampwnam(SAM_ACCOUNT * user, const char *sname)
{
	/* Static buffers we will return. */
	nis_result *result = NULL;
	pstring nisname;
	BOOL ret;
	char *pfile = smb_passwd_table();
        int i;

	if (!*pfile)
	{
		DEBUG(0, ("No SMB password file set\n"));
		return False;
	}

	slprintf(nisname, sizeof(nisname)-1, "[name=%s],%s", sname, pfile);
	DEBUG(10, ("search by nisname: %s\n", nisname));

	/* Search the table. */

	if(!(result = nisp_get_nis_list(nisname, 0)))
	{
		return False;
  	}

	ret = make_sam_from_nisresult(user, result);
	nis_freeresult(result);

	return ret;
}

/*************************************************************************
 Routine to search the nisplus passwd file for an entry matching the username
 *************************************************************************/
BOOL pdb_getsampwrid(SAM_ACCOUNT * user, uint32 rid)
{
	nis_result *result;
	char *nisname;
	BOOL ret;
	char *pfile = smb_passwd_table();

	if (!*pfile)
	{
		DEBUG(0, ("no SMB password file set\n"));
		return False;
	}

	nisname = make_nisname_from_user_rid(rid, pfile);

	DEBUG(10, ("search by rid: %s\n", nisname));

	/* Search the table. */

	if(!(result = nisp_get_nis_list(nisname, 0)))
	{
		return False;
	}

	ret = make_sam_from_nisresult(user, result);
	nis_freeresult(result);

	return ret;
}

/*************************************************************************
 Routine to remove entry from the nisplus smbpasswd table
 *************************************************************************/
BOOL pdb_delete_sam_account(const char *sname)
{
  char *pfile = smb_passwd_table();
  pstring nisname;
  nis_result *result, *delresult;
  nis_object *obj;
  int i;
  
  if (!*pfile)
    {
      DEBUG(0, ("no SMB password file set\n"));
      return False;
    }
  
  slprintf(nisname, sizeof(nisname)-1, "[name=%s],%s", sname, pfile);
  
  /* Search the table. */
  
  if( !(result = nisp_get_nis_list(nisname,
				   MASTER_ONLY|FOLLOW_LINKS|FOLLOW_PATH|\
				   EXPAND_NAME|HARD_LOOKUP))) {
    return False;
  }
  
  if(result->status != NIS_SUCCESS || NIS_RES_NUMOBJ(result) <= 0) {
    /* User not found. */
    DEBUG(0,("user not found in NIS+\n"));
    nis_freeresult(result);
    return False;
  }

  obj = NIS_RES_OBJECT(result);
  slprintf(nisname, sizeof(nisname)-1, "[name=%s],%s.%s", sname, obj->zo_name,
	   obj->zo_domain);

  DEBUG(10, ("removing name: %s\n", nisname));
  delresult = nis_remove_entry(nisname, obj, 
    MASTER_ONLY|REM_MULTIPLE|ALL_RESULTS|FOLLOW_PATH|EXPAND_NAME|HARD_LOOKUP);
  
  nis_freeresult(result);

  if(delresult->status != NIS_SUCCESS) {
    DEBUG(0, ("NIS+ table update failed: %s %s\n",
          nisname, nis_sperrno(delresult->status)));
    nis_freeresult(delresult);
    return False;
  }
  nis_freeresult(delresult);
  return True;
}

/************************************************************************
 Routine to add an entry to the nisplus passwd file.
*************************************************************************/
BOOL pdb_add_sam_account(SAM_ACCOUNT * newpwd)
{
  int local_user = 0;
  char           *pfile = smb_passwd_table();
  pstring	  pfiletmp;
  char           *nisname;
  nis_result     *result = NULL, *tblresult = NULL;
  nis_object new_obj, *obj;
  entry_col *ecol;
  int ta_maxcol;
 
  /*
   * 1. find user domain.
   *   a. try nis search in passwd.org_dir - if found use domain from result.
   *   b. try getpwnam. this may be needed if user is defined
   *      in /etc/passwd file (or elsewere) and not in passwd.org_dir.
   *      if found, use host default domain.
   *   c. exit with False - no such user.
   *
   * 2. add user
   *   a. find smbpasswd table
   *      search pfile in user domain if not found, try host default
   *      domain. 
   *   b. smbpasswd domain is found, fill data and add entry.
   *
   */


  /*
   * Check if user is already there.
   */
  safe_strcpy(pfiletmp, pfile, sizeof(pfiletmp)-1);

  if(pdb_get_username(newpwd) != NULL) {
    nisname = make_nisname_from_name(pdb_get_username(newpwd),
				     pfiletmp);
  } else {
    return False;
  }

  if(!(result = nisp_get_nis_list(nisname, MASTER_ONLY|FOLLOW_LINKS|\
				  FOLLOW_PATH|EXPAND_NAME|HARD_LOOKUP))) {
    return False;
  }
  if (result->status != NIS_SUCCESS && 
      result->status != NIS_NOTFOUND) {
    DEBUG(3, ( "nis_list failure: %s: %s\n",
	       nisname,  nis_sperrno(result->status)));
    nis_freeresult(result);
    return False;
  }   

  if (result->status == NIS_SUCCESS && NIS_RES_NUMOBJ(result) > 0)
    {
      DEBUG(3, ("User already exists in NIS+ password db: %s\n",
		pfile));
      nis_freeresult(result);
      return False;
    }

  nis_freeresult(result); /* no such user, free results */

  /*
   * check for user in unix password database. we need this to get
   * domain, where smbpasswd entry should be stored.
   */

#if 1	/* passwd and smbpasswd users should be in the same domain */
  nisname = make_nisname_from_name(pdb_get_username(newpwd),
				     "passwd.org_dir");
  
  result = nisp_get_nis_list(nisname,
			     MASTER_ONLY|FOLLOW_LINKS|FOLLOW_PATH|\
			     EXPAND_NAME|HARD_LOOKUP);
  
  if (result->status != NIS_SUCCESS || NIS_RES_NUMOBJ(result) <= 0)
    {
      DEBUG(3, ("nis_list failure: %s: %s\n", 
		nisname,  nis_sperrno(result->status)));
      nis_freeresult(result);

      if (!sys_getpwnam(pdb_get_username(newpwd))) {
	/* no such user in system! */
	return False;
      }
	/* 
	 * user is defined, but not in passwd.org_dir.
	 */
      local_user = 1;
    } else {
      safe_strcpy(pfiletmp, pfile, sizeof(pfiletmp)-1);
      safe_strcat(pfiletmp, ".", sizeof(pfiletmp)-strlen(pfiletmp)-1);
      safe_strcat(pfiletmp, NIS_RES_OBJECT(result)->zo_domain,
		  sizeof(pfiletmp)-strlen(pfiletmp)-1);
      nis_freeresult(result); /* not needed any more */

      tblresult = nis_lookup(pfiletmp,
				    MASTER_ONLY|FOLLOW_LINKS|\
				    FOLLOW_PATH|EXPAND_NAME|HARD_LOOKUP); 
    }

  if (local_user || tblresult->status != NIS_SUCCESS)
    {
      /*
       * no user domain or
       * smbpasswd table not found in user domain, fallback to
       * default domain.
       */
      if (!local_user) /* free previous failed search result */
	nis_freeresult(tblresult);
#endif
      tblresult = nis_lookup(pfile, MASTER_ONLY|FOLLOW_LINKS|\
			     FOLLOW_PATH|EXPAND_NAME|HARD_LOOKUP);
      if (tblresult->status != NIS_SUCCESS)
	{
	    /* still nothing. bail out */
	  nis_freeresult(tblresult);
	  DEBUG(3, ( "nis_lookup failure: %s\n",
		     nis_sperrno(tblresult->status)));
	  return False;
	}
      obj = NIS_RES_OBJECT(tblresult);
      /* we need full name for nis_add_entry() */
      slprintf(pfiletmp, sizeof(pfiletmp)-1, "%s.%s", obj->zo_name,
		obj->zo_domain);
#if 1 /* matching } from previous #if */
    }
#endif

  memset((char *)&new_obj, 0, sizeof (new_obj));
  /* fill entry headers */
  /* we do not free these. */
  new_obj.zo_name   = obj->zo_name;
  new_obj.zo_owner  = obj->zo_owner;
  new_obj.zo_group  = obj->zo_group;
  new_obj.zo_domain = obj->zo_domain;
  /* uints */
  new_obj.zo_access = obj->zo_access;
  new_obj.zo_ttl    = obj->zo_ttl;

  new_obj.zo_data.zo_type = ENTRY_OBJ;
  new_obj.EN_data.en_type = obj->TA_data.ta_type;

  ta_maxcol = obj->TA_data.ta_maxcol;
  
  if(!(ecol = (entry_col*)malloc(ta_maxcol*sizeof(entry_col)))) {
    DEBUG(0, ("memory allocation failure\n"));
    nis_freeresult(tblresult);
    return False;
  }
  
  memset((char *)ecol, 0, ta_maxcol*sizeof (entry_col));
  new_obj.EN_data.en_cols.en_cols_val = ecol;
  new_obj.EN_data.en_cols.en_cols_len = ta_maxcol;
  
  init_nisp_from_sam(&new_obj, newpwd, NULL);
  
  DEBUG(10, ( "add NIS+ entry: %s\n", nisname));
  result = nis_add_entry(pfiletmp, &new_obj, 0);

  free(ecol); /* free allocated entry space */
  
  if (result->status != NIS_SUCCESS)
    {
      DEBUG(3, ( "NIS+ table update failed: %s\n",
		 nisname, nis_sperrno(result->status)));
      nis_freeresult(tblresult);
      nis_freeresult(result);
      return False;
    }
  
  nis_freeresult(tblresult);
  nis_freeresult(result);
  
  return True;
}

/************************************************************************
 Routine to modify the nisplus passwd entry.
************************************************************************/
BOOL pdb_update_sam_account(SAM_ACCOUNT * newpwd, BOOL override)
{
  nis_result *result, *addresult;
  nis_object *obj;
  nis_object new_obj;
  entry_col *ecol;
  int ta_maxcol;
  char *pfile = smb_passwd_table();
  pstring nisname;
  int i;

  if (!*pfile)
    {
      DEBUG(0, ("no SMB password file set\n"));
      return False;
    }
  
  slprintf(nisname, sizeof(nisname)-1, "[name=%s],%s",
	   pdb_get_username(newpwd), pfile);
  
  DEBUG(10, ("search by name: %s\n", nisname));
  
  /* Search the table. */
  
  if( !(result = nisp_get_nis_list(nisname, MASTER_ONLY|FOLLOW_LINKS|\
				   FOLLOW_PATH|EXPAND_NAME|HARD_LOOKUP))) {
    return False;
  }
  
  if(result->status != NIS_SUCCESS || NIS_RES_NUMOBJ(result) <= 0) {
    /* User not found. */
    DEBUG(0,("user not found in NIS+\n"));
    nis_freeresult(result);
    return False;
  }

  obj = NIS_RES_OBJECT(result);
  DEBUG(6,("entry found in %s\n", obj->zo_domain));

  /* we must create new stub object with EN_MODIFIED flag.
     this is because obj from result is going to be freed and
     we do not want to break it or cause memory leaks or corruption.
  */
  
  memmove((char *)&new_obj, obj, sizeof (new_obj));
  ta_maxcol = obj->TA_data.ta_maxcol;
  
  if(!(ecol = (entry_col*)malloc(ta_maxcol*sizeof(entry_col)))) {
    DEBUG(0, ("memory allocation failure\n"));
    nis_freeresult(result);
    return False;
  }

  memmove((char *)ecol, obj->EN_data.en_cols.en_cols_val,
	  ta_maxcol*sizeof (entry_col));
  new_obj.EN_data.en_cols.en_cols_val = ecol;
  new_obj.EN_data.en_cols.en_cols_len = ta_maxcol;

  if ( init_nisp_from_sam(&new_obj, newpwd, obj) == True ) {
    slprintf(nisname, sizeof(nisname)-1, "[name=%s],%s.%s",
	   pdb_get_username(newpwd), obj->zo_name, obj->zo_domain);

    DEBUG(10, ("NIS+ table update: %s\n", nisname));
    addresult =
      nis_modify_entry(nisname, &new_obj, 
		  MOD_SAMEOBJ | FOLLOW_PATH | EXPAND_NAME | HARD_LOOKUP);
  
    if(addresult->status != NIS_SUCCESS) {
      DEBUG(0, ("NIS+ table update failed: %s %s\n",
		nisname, nis_sperrno(addresult->status)));
      nis_freeresult(addresult);
      nis_freeresult(result);
      free(ecol);
      return False;
    }
    
    DEBUG(6,("password changed\n"));
    nis_freeresult(addresult);
  } else {
    DEBUG(6,("nothing to change!\n"));
  }

  free(ecol);
  nis_freeresult(result);
  
  return True;
}
 
#else
 void nisplus_dummy_function(void);
 void nisplus_dummy_function(void) { } /* stop some compilers complaining */
#endif /* WITH_NISPLUSSAM */

