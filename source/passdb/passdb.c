/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
   Copyright (C) Jeremy Allison 		1996-1998
   Copyright (C) Luke Kenneth Casson Leighton 	1996-1998
   Copyright (C) Gerald (Jerry) Carter		2000
      
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

#include <dlfcn.h>
#include "includes.h"

extern int DEBUGLEVEL;

/*
 * This is set on startup - it defines the SID for this
 * machine, and therefore the SAM database for which it is
 * responsible.
 */

extern DOM_SID global_sam_sid;
extern pstring global_myname;
extern fstring global_myworkgroup;

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
 * a full example set of derivative functions are listed below.  an API
 * writer is expected to cut/paste these into their module, replace
 * either one set (struct smb_passwd) or the other (struct sam_passwd)
 * OR both, and optionally also to write display info routines
 * (struct sam_disp_info).  lkcl
 *
 */

struct passdb_ops *pdb_ops;

static void* pdb_handle = NULL;

/***************************************************************
 Initialize the password db operations.
***************************************************************/
BOOL initialize_password_db(BOOL reload)
{

	char*	modulename = lp_passdb_module_path();
	
	return True;
	
	/* load another module? */
	if (reload && pdb_handle)
	{
		dlclose (pdb_handle);
		pdb_handle = NULL;
	}
	
	/* do we have a module defined or use the default? */
	if (strlen (modulename) != 0)
	{
		if ((pdb_handle=dlopen (modulename, RTLD_LAZY)) == NULL)
		{
			DEBUG(0,("initialize_password_db: ERROR - Unable to open passdb module \"%s\"!\n%s\n",
				modulename, dlerror()));
		}
		else
			DEBUG(1,("initialize_password_db: passdb module \"%s\" loaded successfully\n", modulename));
	}	
	
	/* either no module name defined or the one that was failed 
	   to open.  Let's try the default */
	if (pdb_handle == NULL)
	{
		if ((pdb_handle=dlopen ("libpdbfile.so", RTLD_LAZY)) == NULL)
		{
			DEBUG(0,("initialize_password_db: ERROR - Unable to open \"libpdbfile.so\" passdb module!  No user authentication possible!\n%s\n",
				dlerror()));
			return False;
		}
		else
			DEBUG(1,("initialize_password_db: passdb module \"libpdbfile.so\" loaded successfully\n"));
	}
					

	return (pdb_handle != NULL);
}

/*************************************************************
 initialises a struct sam_disp_info.
 **************************************************************/
static void pdb_init_dispinfo(struct sam_disp_info *user)
{
	if (user == NULL) 
		return;
	ZERO_STRUCTP(user);
}

/*************************************************************
 initialises a struct sam_passwd.
 ************************************************************/
void pdb_init_sam(SAM_ACCOUNT *user)
{
	if (user == NULL) 
		return;
	
	ZERO_STRUCTP(user);
	
	user->logon_time            = (time_t)-1;
	user->logoff_time           = (time_t)-1;
	user->kickoff_time          = (time_t)-1;
	user->pass_last_set_time    = (time_t)-1;
	user->pass_can_change_time  = (time_t)-1;
	user->pass_must_change_time = (time_t)-1;

	user->unknown_3 = 0x00ffffff; 	/* don't know */
	user->logon_divs = 168; 	/* hours per week */
	user->hours_len = 21; 		/* 21 times 8 bits = 168 */
	memset(user->hours, 0xff, user->hours_len); /* available at all hours */
	user->unknown_5 = 0x00020000; 	/* don't know */
	user->unknown_5 = 0x000004ec; 	/* don't know */
	
}

/************************************************************
 free all pointer members and then reinit the SAM_ACCOUNT
 ***********************************************************/
void pdb_clear_sam(SAM_ACCOUNT *user)
{
	if (user == NULL) 
		return;
		
	/* clear all pointer members */
	if (user->username)
		free(user->username);
	if (user->full_name)
		free(user->full_name);
	if (user->home_dir)
		free(user->home_dir);
	if (user->dir_drive)
		free(user->dir_drive);
	if (user->logon_script)
		free(user->logon_script);
	if (user->profile_path)
		free(user->profile_path);
	if (user->acct_desc)
		free(user->acct_desc);
	if (user->workstations)
		free(user->workstations);
	if (user->unknown_str)
		free(user->unknown_str);
	if (user->munged_dial)
		free(user->munged_dial);
		
	if (user->lm_pw)
		free(user->lm_pw);
	if (user->nt_pw)
		free(user->nt_pw);
	
	
	/* now initialize */
	pdb_init_sam(user);
	
}


/*************************************************************************
 Routine to return the next entry in the sam passwd list.
 *************************************************************************/
struct sam_disp_info *pdb_sam_to_dispinfo(SAM_ACCOUNT *user)
{
	static struct sam_disp_info disp_info;

	if (user == NULL) 
		return NULL;

	pdb_init_dispinfo(&disp_info);

	disp_info.smb_name  = user->username;
	disp_info.full_name = user->full_name;
	disp_info.user_rid  = user->user_rid;

	return &disp_info;
}


/**********************************************************
 Encode the account control bits into a string.
 length = length of string to encode into (including terminating
 null). length *MUST BE MORE THAN 2* !
 **********************************************************/
char *pdb_encode_acct_ctrl(uint16 acct_ctrl, size_t length)
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

uint16 pdb_decode_acct_ctrl(const char *p)
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

/*************************************************************
 Routine to set 32 hex password characters from a 16 byte array.
**************************************************************/
void pdb_sethexpwd(char *p, unsigned char *pwd, uint16 acct_ctrl)
{
	if (pwd != NULL) {
		int i;
		for (i = 0; i < 16; i++)
			slprintf(&p[i*2], 3, "%02X", pwd[i]);
	} else {
		if (acct_ctrl & ACB_PWNOTREQ)
			safe_strcpy(p, "NO PASSWORDXXXXXXXXXXXXXXXXXXXXX", 33);
		else
			safe_strcpy(p, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 33);
	}
}

/*************************************************************
 Routine to get the 32 hex characters and turn them
 into a 16 byte array.
**************************************************************/
BOOL pdb_gethexpwd(char *p, unsigned char *pwd)
{
	int i;
	unsigned char   lonybble, hinybble;
	char           *hexchars = "0123456789ABCDEF";
	char           *p1, *p2;

	for (i = 0; i < 32; i += 2)
	{
		hinybble = toupper(p[i]);
		lonybble = toupper(p[i + 1]);

		p1 = strchr(hexchars, hinybble);
		p2 = strchr(hexchars, lonybble);

		if (!p1 || !p2)
		{
			return (False);
		}

		hinybble = PTR_DIFF(p1, hexchars);
		lonybble = PTR_DIFF(p2, hexchars);

		pwd[i / 2] = (hinybble << 4) | lonybble;
	}
	return (True);
}

/*******************************************************************
 Group and User RID username mapping function
 ********************************************************************/
BOOL pdb_name_to_rid(char *user_name, uint32 *u_rid, uint32 *g_rid)
{
	struct passwd *pw = Get_Pwnam(user_name, False);

	if (u_rid == NULL || g_rid == NULL || user_name == NULL)
	{
		return False;
	}

	if (!pw)
	{
		DEBUG(1,("Username %s is invalid on this system\n", user_name));
		return False;
	}

	if (user_in_list(user_name, lp_domain_guest_users()))
	{
		*u_rid = DOMAIN_USER_RID_GUEST;
	}
	else if (user_in_list(user_name, lp_domain_admin_users()))
	{
		*u_rid = DOMAIN_USER_RID_ADMIN;
	}
	else
	{
		/* turn the unix UID into a Domain RID.  this is what the posix
		   sub-system does (adds 1000 to the uid) */
		*u_rid = pdb_uid_to_user_rid(pw->pw_uid);
	}

	/* absolutely no idea what to do about the unix GID to Domain RID mapping */
	*g_rid = pdb_gid_to_group_rid(pw->pw_gid);

	return True;
}

/*******************************************************************
 Converts NT user RID to a UNIX uid.
 ********************************************************************/
uid_t pdb_user_rid_to_uid(uint32 user_rid)
{
	return (uid_t)(((user_rid & (~USER_RID_TYPE))- 1000)/RID_MULTIPLIER);
}

/*******************************************************************
 Converts NT user RID to a UNIX gid.
 ********************************************************************/

gid_t pdb_user_rid_to_gid(uint32 user_rid)
{
	return (uid_t)(((user_rid & (~GROUP_RID_TYPE))- 1000)/RID_MULTIPLIER);
}

/*******************************************************************
 converts UNIX uid to an NT User RID.
 ********************************************************************/

uint32 pdb_uid_to_user_rid(uid_t uid)
{
	return (((((uint32)uid)*RID_MULTIPLIER) + 1000) | USER_RID_TYPE);
}

/*******************************************************************
 converts NT Group RID to a UNIX uid.
 ********************************************************************/

uint32 pdb_gid_to_group_rid(gid_t gid)
{
  return (((((uint32)gid)*RID_MULTIPLIER) + 1000) | GROUP_RID_TYPE);
}

/*******************************************************************
 Decides if a RID is a well known RID.
 ********************************************************************/

static BOOL pdb_rid_is_well_known(uint32 rid)
{
  return (rid < 1000);
}

/*******************************************************************
 Decides if a RID is a user or group RID.
 ********************************************************************/
BOOL pdb_rid_is_user(uint32 rid)
{
  /* lkcl i understand that NT attaches an enumeration to a RID
   * such that it can be identified as either a user, group etc
   * type.  there are 5 such categories, and they are documented.
   */
   if(pdb_rid_is_well_known(rid)) {
      /*
       * The only well known user RIDs are DOMAIN_USER_RID_ADMIN
       * and DOMAIN_USER_RID_GUEST.
       */
     if(rid == DOMAIN_USER_RID_ADMIN || rid == DOMAIN_USER_RID_GUEST)
       return True;
   } else if((rid & RID_TYPE_MASK) == USER_RID_TYPE) {
     return True;
   }
   return False;
}

/*******************************************************************
 Convert a rid into a name. Used in the lookup SID rpc.
 ********************************************************************/
BOOL local_lookup_rid(uint32 rid, char *name, enum SID_NAME_USE *psid_name_use)
{

	BOOL is_user = pdb_rid_is_user(rid);

	DEBUG(5,("local_lookup_rid: looking up %s RID %u.\n", is_user ? "user" :
			"group", (unsigned int)rid));

	if(is_user) {
		if(rid == DOMAIN_USER_RID_ADMIN) {
			pstring admin_users;
			char *p = admin_users;
			pstrcpy( admin_users, lp_domain_admin_users());
			if(!next_token(&p, name, NULL, sizeof(fstring)))
				fstrcpy(name, "Administrator");
		} else if (rid == DOMAIN_USER_RID_GUEST) {
			pstring guest_users;
			char *p = guest_users;
			pstrcpy( guest_users, lp_domain_guest_users());
			if(!next_token(&p, name, NULL, sizeof(fstring)))
				fstrcpy(name, "Guest");
		} else {
			uid_t uid = pdb_user_rid_to_uid(rid);
			struct passwd *pass = sys_getpwuid(uid);

			*psid_name_use = SID_NAME_USER;

			DEBUG(5,("local_lookup_rid: looking up uid %u %s\n", (unsigned int)uid,
				pass ? "succeeded" : "failed" ));

			if(!pass) {
				slprintf(name, sizeof(fstring)-1, "unix_user.%u", (unsigned int)uid);
				return True;
			}

			fstrcpy(name, pass->pw_name);

			DEBUG(5,("local_lookup_rid: found user %s for rid %u\n", name,
				(unsigned int)rid ));
		}

	} else {
		gid_t gid = pdb_user_rid_to_gid(rid);
		struct group *gr = getgrgid(gid);

		*psid_name_use = SID_NAME_ALIAS;

		DEBUG(5,("local_local_rid: looking up gid %u %s\n", (unsigned int)gid,
			gr ? "succeeded" : "failed" ));

		if(!gr) {
			slprintf(name, sizeof(fstring)-1, "unix_group.%u", (unsigned int)gid);
			return True;
		}

		fstrcpy( name, gr->gr_name);

		DEBUG(5,("local_lookup_rid: found group %s for rid %u\n", name,
			(unsigned int)rid ));
	}

	return True;
}

/*******************************************************************
 Convert a name into a SID. Used in the lookup name rpc.
 ********************************************************************/

BOOL local_lookup_name(char *domain, char *user, DOM_SID *psid, enum SID_NAME_USE *psid_name_use)
{
	extern DOM_SID global_sid_World_Domain;
	struct passwd *pass = NULL;
	DOM_SID local_sid;

	sid_copy(&local_sid, &global_sam_sid);

	if(!strequal(global_myname, domain) && !strequal(global_myworkgroup, domain))
		return False;

	/*
	 * Special case for MACHINE\Everyone. Map to the world_sid.
	 */

	if(strequal(user, "Everyone")) {
		sid_copy( psid, &global_sid_World_Domain);
		sid_append_rid(psid, 0);
		*psid_name_use = SID_NAME_ALIAS;
		return True;
	}

	(void)map_username(user);

	if(!(pass = Get_Pwnam(user, False))) {
		/*
		 * Maybe it was a group ?
		 */
		struct group *grp = getgrnam(user);

		if(!grp)
			return False;

		sid_append_rid( &local_sid, pdb_gid_to_group_rid(grp->gr_gid));
		*psid_name_use = SID_NAME_ALIAS;
	} else {

		sid_append_rid( &local_sid, pdb_uid_to_user_rid(pass->pw_uid));
		*psid_name_use = SID_NAME_USER;
	}

	sid_copy( psid, &local_sid);

	return True;
}

/****************************************************************************
 Convert a uid to SID - locally.
****************************************************************************/
DOM_SID *local_uid_to_sid(DOM_SID *psid, uid_t uid)
{
	extern DOM_SID global_sam_sid;

	sid_copy(psid, &global_sam_sid);
	sid_append_rid(psid, pdb_uid_to_user_rid(uid));

	return psid;
}


/****************************************************************************
 Convert a SID to uid - locally.
****************************************************************************/
BOOL local_sid_to_uid(uid_t *puid, DOM_SID *psid, enum SID_NAME_USE *name_type)
{
	extern DOM_SID global_sam_sid;

	DOM_SID dom_sid;
	uint32 rid;

	*name_type = SID_NAME_UNKNOWN;

	sid_copy(&dom_sid, psid);
	sid_split_rid(&dom_sid, &rid);

	/*
	 * We can only convert to a uid if this is our local
	 * Domain SID (ie. we are the controling authority).
	 */
	if (!sid_equal(&global_sam_sid, &dom_sid))
		return False;

	*puid = pdb_user_rid_to_uid(rid);

	/*
	 * Ensure this uid really does exist.
	 */
	if(!sys_getpwuid(*puid))
		return False;

	return True;
}

/****************************************************************************
 Convert a gid to SID - locally.
****************************************************************************/
DOM_SID *local_gid_to_sid(DOM_SID *psid, gid_t gid)
{
    extern DOM_SID global_sam_sid;

	sid_copy(psid, &global_sam_sid);
	sid_append_rid(psid, pdb_gid_to_group_rid(gid));

	return psid;
}

/****************************************************************************
 Convert a SID to gid - locally.
****************************************************************************/
BOOL local_sid_to_gid(gid_t *pgid, DOM_SID *psid, enum SID_NAME_USE *name_type)
{
    extern DOM_SID global_sam_sid;
	DOM_SID dom_sid;
	uint32 rid;

	*name_type = SID_NAME_UNKNOWN;

	sid_copy(&dom_sid, psid);
	sid_split_rid(&dom_sid, &rid);

	/*
	 * We can only convert to a gid if this is our local
	 * Domain SID (ie. we are the controling authority).
	 */

	if (!sid_equal(&global_sam_sid, &dom_sid))
		return False;

	*pgid = pdb_user_rid_to_gid(rid);

	/*
	 * Ensure this gid really does exist.
	 */

	if(!getgrgid(*pgid))
		return False;

	return True;
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
void copy_id23_to_sam_passwd(struct sam_passwd *to, SAM_USER_INFO_23 *from)
{
	static fstring smb_name;
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

	to->logon_time = nt_time_to_unix(&from->logon_time);
	to->logoff_time = nt_time_to_unix(&from->logoff_time);
	to->kickoff_time = nt_time_to_unix(&from->kickoff_time);
	to->pass_last_set_time = nt_time_to_unix(&from->pass_last_set_time);
	to->pass_can_change_time = nt_time_to_unix(&from->pass_can_change_time);
	to->pass_must_change_time = nt_time_to_unix(&from->pass_must_change_time);

	select_name(&smb_name    , &to->username    , &from->uni_user_name   );
	select_name(&full_name   , &to->full_name   , &from->uni_full_name   );
	select_name(&home_dir    , &to->home_dir    , &from->uni_home_dir    );
	select_name(&dir_drive   , &to->dir_drive   , &from->uni_dir_drive   );
	select_name(&logon_script, &to->logon_script, &from->uni_logon_script);
	select_name(&profile_path, &to->profile_path, &from->uni_profile_path);
	select_name(&acct_desc   , &to->acct_desc   , &from->uni_acct_desc   );
	select_name(&workstations, &to->workstations, &from->uni_workstations);
	select_name(&unknown_str , &to->unknown_str , &from->uni_unknown_str );
	select_name(&munged_dial , &to->munged_dial , &from->uni_munged_dial );

	to->uid = (uid_t)-1;
	to->gid = (gid_t)-1;
	to->user_rid = from->user_rid;
	to->group_rid = from->group_rid;

	to->lm_pw = NULL;
	to->nt_pw = NULL;

	to->acct_ctrl = from->acb_info;
	to->unknown_3 = from->unknown_3;

	to->logon_divs = from->logon_divs;
	to->hours_len = from->logon_hrs.len;
	memcpy(to->hours, from->logon_hrs.hours, MAX_HOURS_LEN);

	to->unknown_5 = from->unknown_5;
	to->unknown_6 = from->unknown_6;
}

/*************************************************************
 copies a sam passwd.
 **************************************************************/
void copy_id21_to_sam_passwd(struct sam_passwd *to, SAM_USER_INFO_21 *from)
{
	static fstring smb_name;
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

	to->logon_time = nt_time_to_unix(&from->logon_time);
	to->logoff_time = nt_time_to_unix(&from->logoff_time);
	to->kickoff_time = nt_time_to_unix(&from->kickoff_time);
	to->pass_last_set_time = nt_time_to_unix(&from->pass_last_set_time);
	to->pass_can_change_time = nt_time_to_unix(&from->pass_can_change_time);
	to->pass_must_change_time = nt_time_to_unix(&from->pass_must_change_time);

	select_name(&smb_name    , &to->username    , &from->uni_user_name   );
	select_name(&full_name   , &to->full_name   , &from->uni_full_name   );
	select_name(&home_dir    , &to->home_dir    , &from->uni_home_dir    );
	select_name(&dir_drive   , &to->dir_drive   , &from->uni_dir_drive   );
	select_name(&logon_script, &to->logon_script, &from->uni_logon_script);
	select_name(&profile_path, &to->profile_path, &from->uni_profile_path);
	select_name(&acct_desc   , &to->acct_desc   , &from->uni_acct_desc   );
	select_name(&workstations, &to->workstations, &from->uni_workstations);
	select_name(&unknown_str , &to->unknown_str , &from->uni_unknown_str );
	select_name(&munged_dial , &to->munged_dial , &from->uni_munged_dial );

	to->uid = (uid_t)-1;
	to->gid = (gid_t)-1;
	to->user_rid = from->user_rid;
	to->group_rid = from->group_rid;

	to->lm_pw = NULL;
	to->nt_pw = NULL;

	to->acct_ctrl = from->acb_info;
	to->unknown_3 = from->unknown_3;

	to->logon_divs = from->logon_divs;
	to->hours_len = from->logon_hrs.len;
	memcpy(to->hours, from->logon_hrs.hours, MAX_HOURS_LEN);

	to->unknown_5 = from->unknown_5;
	to->unknown_6 = from->unknown_6;
}


/*************************************************************
 copies a sam passwd.
 
 FIXME!  Do we need to use dynamically allocated strings
 here instead of static strings?     
 
 Why are password hashes not also copied?     --jerry
 **************************************************************/
void copy_sam_passwd(struct sam_passwd *to, const struct sam_passwd *from)
{
	static fstring smb_name="";
	static fstring full_name="";
	static fstring home_dir="";
	static fstring dir_drive="";
	static fstring logon_script="";
	static fstring profile_path="";
	static fstring acct_desc="";
	static fstring workstations="";
	static fstring unknown_str="";
	static fstring munged_dial="";

	if (from == NULL || to == NULL) return;

	memcpy(to, from, sizeof(*from));

	if (from->username != NULL) {
		fstrcpy(smb_name  , from->username);
		to->username = smb_name;
	}
	
	if (from->full_name != NULL) {
		fstrcpy(full_name, from->full_name);
		to->full_name = full_name;
	}

	if (from->home_dir != NULL) {
		fstrcpy(home_dir  , from->home_dir);
		to->home_dir = home_dir;
	}

	if (from->dir_drive != NULL) {
		fstrcpy(dir_drive  , from->dir_drive);
		to->dir_drive = dir_drive;
	}

	if (from->logon_script != NULL) {
		fstrcpy(logon_script  , from->logon_script);
		to->logon_script = logon_script;
	}

	if (from->profile_path != NULL) {
		fstrcpy(profile_path  , from->profile_path);
		to->profile_path = profile_path;
	}

	if (from->acct_desc != NULL) {
		fstrcpy(acct_desc  , from->acct_desc);
		to->acct_desc = acct_desc;
	}

	if (from->workstations != NULL) {
		fstrcpy(workstations  , from->workstations);
		to->workstations = workstations;
	}

	if (from->unknown_str != NULL) {
		fstrcpy(unknown_str  , from->unknown_str);
		to->unknown_str = unknown_str;
	}

	if (from->munged_dial != NULL) {
		fstrcpy(munged_dial  , from->munged_dial);
		to->munged_dial = munged_dial;
	}
}

/*************************************************************
 change a password entry in the local smbpasswd file

 FIXME!!  The function needs to be abstracted into the
 passdb interface or something.  It is currently being called
 by _api_samr_create_user() in rpc_server/srv_samr.c
 
 --jerry
 *************************************************************/

BOOL local_password_change(char *user_name, int local_flags,
			   char *new_passwd, 
			   char *err_str, size_t err_str_len,
			   char *msg_str, size_t msg_str_len)
{
	struct passwd  *pwd = NULL;
	SAM_ACCOUNT 	*sam_pass;
	SAM_ACCOUNT	new_sam_acct;
	uchar           new_p16[16];
	uchar           new_nt_p16[16];

	*err_str = '\0';
	*msg_str = '\0';

	if (local_flags & LOCAL_ADD_USER) {
	
		/*
		 * Check for a local account - if we're adding only.
		 */
	
		if(!(pwd = sys_getpwnam(user_name))) {
			slprintf(err_str, err_str_len - 1, "User %s does not \
exist in system password file (usually /etc/passwd). Cannot add \
account without a valid local system user.\n", user_name);
			return False;
		}
	}

	/* Calculate the MD4 hash (NT compatible) of the new password. */
	nt_lm_owf_gen(new_passwd, new_nt_p16, new_p16);

	/* Get the smb passwd entry for this user */
	sam_pass = pdb_getsampwnam(user_name);
	if (sam_pass == NULL) 
	{
		if(!(local_flags & LOCAL_ADD_USER)) 
		{
			slprintf(err_str, err_str_len-1,"Failed to find entry for user %s.\n", user_name);
			return False;
		}

		/* create the SAM_ACCOUNT struct and call pdb_add_sam_account */
		pdb_init_sam 	      (&new_sam_acct);
		pdb_set_username      (&new_sam_acct, user_name);
		pdb_set_uid	      (&new_sam_acct, pwd->pw_uid);
		pdb_set_pass_last_set_time(&new_sam_acct, time(NULL));

		/* set account flags */
		pdb_set_acct_ctrl(&new_sam_acct,((local_flags & LOCAL_TRUST_ACCOUNT) ? ACB_WSTRUST : ACB_NORMAL) );
		if (local_flags & LOCAL_DISABLE_USER)
		{
			pdb_set_acct_ctrl (&new_sam_acct, pdb_get_acct_ctrl(&new_sam_acct)|ACB_DISABLED);
		}
		if (local_flags & LOCAL_SET_NO_PASSWORD)
		{
			pdb_set_acct_ctrl (&new_sam_acct, pdb_get_acct_ctrl(&new_sam_acct)|ACB_PWNOTREQ);
		}
		else
		{
			/* set the passwords here.  if we get to here it means
			   we have a valid, active account */
			pdb_set_lanman_passwd (&new_sam_acct, new_p16);
			pdb_set_nt_passwd     (&new_sam_acct, new_nt_p16);
		}
		
			
		if (pdb_add_sam_account(&new_sam_acct)) 
		{
			slprintf(msg_str, msg_str_len-1, "Added user %s.\n", user_name);
			pdb_clear_sam (&new_sam_acct);
			return True;
		} 
		else 
		{
			slprintf(err_str, err_str_len-1, "Failed to add entry for user %s.\n", user_name);
			return False;
		}
	} 
	else 
	{
		/* the entry already existed */
		local_flags &= ~LOCAL_ADD_USER;
	}

	/*
	 * We are root - just write the new password
	 * and the valid last change time.
	 */

	if(local_flags & LOCAL_DISABLE_USER) 
	{
		pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)|ACB_DISABLED);
	}
	else if (local_flags & LOCAL_ENABLE_USER) 
	{
		if(pdb_get_lanman_passwd(sam_pass) == NULL) 
		{
			pdb_set_lanman_passwd (sam_pass, new_p16);
			pdb_set_nt_passwd     (sam_pass, new_nt_p16);
		}
		pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)&(~ACB_DISABLED));
	} else if (local_flags & LOCAL_SET_NO_PASSWORD) 
	{
		pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)|ACB_PWNOTREQ);
		
		/* This is needed to preserve ACB_PWNOTREQ in mod_smbfilepwd_entry */
		pdb_set_lanman_passwd (sam_pass, NULL);
		pdb_set_nt_passwd     (sam_pass, NULL);
	} 
	else 
	{
		/*
		 * If we're dealing with setting a completely empty user account
		 * ie. One with a password of 'XXXX', but not set disabled (like
		 * an account created from scratch) then if the old password was
		 * 'XX's then getsmbpwent will have set the ACB_DISABLED flag.
		 * We remove that as we're giving this user their first password
		 * and the decision hasn't really been made to disable them (ie.
		 * don't create them disabled). JRA.
		 */
		if ((pdb_get_lanman_passwd(sam_pass)==NULL) && (pdb_get_acct_ctrl(sam_pass)&ACB_DISABLED))
			pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)&(~ACB_DISABLED));
		pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)&(~ACB_PWNOTREQ));
		pdb_set_lanman_passwd (sam_pass, new_p16);
		pdb_set_nt_passwd     (sam_pass, new_nt_p16);
	}
	
	if(local_flags & LOCAL_DELETE_USER) 
	{
		if (!pdb_delete_sam_account(user_name)) 
		{
			slprintf(err_str,err_str_len-1, "Failed to delete entry for user %s.\n", user_name);
			return False;
		}
		slprintf(msg_str, msg_str_len-1, "Deleted user %s.\n", user_name);
	} 
	else 
	{
		if(!pdb_update_sam_account(sam_pass, True)) 
		{
			slprintf(err_str, err_str_len-1, "Failed to modify entry for user %s.\n", user_name);
			return False;
		}
		if(local_flags & LOCAL_DISABLE_USER)
			slprintf(msg_str, msg_str_len-1, "Disabled user %s.\n", user_name);
		else if (local_flags & LOCAL_ENABLE_USER)
			slprintf(msg_str, msg_str_len-1, "Enabled user %s.\n", user_name);
		else if (local_flags & LOCAL_SET_NO_PASSWORD)
			slprintf(msg_str, msg_str_len-1, "User %s password set to none.\n", user_name);
	}

	return True;
}


/*********************************************************************
 collection of get...() functions for SAM_ACCOUNT_INFO
 ********************************************************************/
uint16 pdb_get_acct_ctrl (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->acct_ctrl);
	else
		return (ACB_DISABLED);
}

time_t pdb_get_logon_time (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->logon_time);
	else
		return (-1);
}

time_t pdb_get_logoff_time (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->logoff_time);
	else
		return (-1);
}

time_t pdb_get_kickoff_time (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->kickoff_time);
	else
		return (-1);
}

time_t pdb_get_pass_last_set_time (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->pass_last_set_time);
	else
		return (-1);
}

time_t pdb_get_pass_can_change_time (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->pass_can_change_time);
	else
		return (-1);
}

time_t pdb_get_pass_must_change_time (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->pass_must_change_time);
	else
		return (-1);
}

uint16 pdb_get_logon_divs (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->logon_divs);
	else
		return (-1);
}

uint32 pdb_get_hours_len (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->hours_len);
	else
		return (-1);
}

uint8* pdb_get_hours (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->hours);
	else
		return (NULL);
}

BYTE* pdb_get_nt_passwd (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->nt_pw);
	else
		return (NULL);
}

BYTE* pdb_get_lanman_passwd (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->lm_pw);
	else
		return (NULL);
}


uint32 pdb_get_user_rid (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->user_rid);
	else
		return (-1);
}

uint32 pdb_get_group_rid (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->group_rid);
	else
		return (-1);
}

uid_t pdb_get_uid (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->uid);
	else
		return ((uid_t)-1);
}

gid_t pdb_get_gid (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->gid);
	else
		return ((gid_t)-1);
}

char* pdb_get_username (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->username);
	else
		return (NULL);
}

char* pdb_get_domain (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->domain);
	else
		return (NULL);
}

char* pdb_get_nt_username (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->nt_username);
	else
		return (NULL);
}

char* pdb_get_fullname (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->full_name);
	else
		return (NULL);
}

char* pdb_get_homedir (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->home_dir);
	else
		return (NULL);
}

char* pdb_get_dirdrive (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->dir_drive);
	else
		return (NULL);
}

char* pdb_get_logon_script (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->logon_script);
	else
		return (NULL);
}

char* pdb_get_profile_path (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->profile_path);
	else
		return (NULL);
}

char* pdb_get_acct_desc (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->acct_desc);
	else
		return (NULL);
}

char* pdb_get_workstations (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->workstations);
	else
		return (NULL);
}

char* pdb_get_munged_dial (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->munged_dial);
	else
		return (NULL);
}

uint32 pdb_get_unknown3 (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->unknown_3);
	else
		return (-1);
}

uint32 pdb_get_unknown5 (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->unknown_5);
	else
		return (-1);
}

uint32 pdb_get_unknown6 (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->unknown_6);
	else
		return (-1);
}

/*********************************************************************
 collection of set...() functions for SAM_ACCOUNT_INFO
 ********************************************************************/
BOOL pdb_set_acct_ctrl (SAM_ACCOUNT *sampass, uint16 flags)
{
	if (sampass)
	{
		sampass->acct_ctrl = flags;
		return True;
	}
	
	return False;
}

BOOL pdb_set_logon_time (SAM_ACCOUNT *sampass, time_t time)
{
	if (sampass)
	{
		sampass->logon_time = time;
		return True;
	}
	
	return False;
}

BOOL pdb_set_logoff_time (SAM_ACCOUNT *sampass, time_t time)
{
	if (sampass)
	{
		sampass->logoff_time = time;
		return True;
	}
	
	return False;
}

BOOL pdb_set_kickoff_time (SAM_ACCOUNT *sampass, time_t time)
{
	if (sampass)
	{
		sampass->kickoff_time = time;
		return True;
	}
	
	return False;
}

BOOL pdb_set_pass_can_change_time (SAM_ACCOUNT *sampass, time_t time)
{
	if (sampass)
	{
		sampass->pass_can_change_time = time;
		return True;
	}
	
	return False;
}

BOOL pdb_set_pass_must_change_time (SAM_ACCOUNT *sampass, time_t time)
{
	if (sampass)
	{
		sampass->pass_must_change_time = time;
		return True;
	}
	
	return False;
}

BOOL pdb_set_pass_last_set_time (SAM_ACCOUNT *sampass, time_t time)
{
	if (sampass)
	{
		sampass->pass_last_set_time = time;
		return True;
	}
	
	return False;
}

BOOL pdb_set_hours_len (SAM_ACCOUNT *sampass, uint32 len)
{
	if (sampass)
	{
		sampass->hours_len = len;
		return True;
	}
	
	return False;
}

BOOL pdb_set_logons_divs (SAM_ACCOUNT *sampass, uint16 hours)
{
	if (sampass)
	{
		sampass->logon_divs = hours;
		return True;
	}
	
	return False;
}

BOOL pdb_set_uid (SAM_ACCOUNT *sampass, uid_t uid)
{
	if (sampass)
	{
		sampass->uid = uid;
		return True;
	}
	
	return False;
}

BOOL pdb_set_gid (SAM_ACCOUNT *sampass, gid_t gid)
{
	if (sampass)
	{
		sampass->gid = gid;
		return True;
	}
	
	return False;
}

BOOL pdb_set_user_rid (SAM_ACCOUNT *sampass, uint32 rid)
{
	if (sampass)
	{
		sampass->user_rid = rid;
		return True;
	}
	
	return False;
}

BOOL pdb_set_group_rid (SAM_ACCOUNT *sampass, uint32 grid)
{
	if (sampass)
	{
		sampass->group_rid = grid;
		return True;
	}
	
	return False;
}

BOOL pdb_set_username (SAM_ACCOUNT *sampass, char *username)
{
	if (sampass)
	{
		sampass->username = strdup(username);
		return True;
	}
	
	return False;
}

BOOL pdb_set_domain (SAM_ACCOUNT *sampass, char *domain)
{
	if (sampass)
	{
		sampass->domain = strdup(domain);
		return True;
	}
	
	return False;
}

BOOL pdb_set_nt_username (SAM_ACCOUNT *sampass, char *nt_username)
{
	if (sampass)
	{
		sampass->nt_username = strdup(nt_username);
		return True;
	}
	
	return False;
}

BOOL pdb_set_fullname (SAM_ACCOUNT *sampass, char *fullname)
{
	if (sampass)
	{
		sampass->full_name = strdup(fullname);
		return True;
	}
	
	return False;
}

BOOL pdb_set_logon_script (SAM_ACCOUNT *sampass, char *logon_script)
{
	if (sampass)
	{
		sampass->logon_script = strdup(logon_script);
		return True;
	}
	
	return False;
}

BOOL pdb_set_profile_path (SAM_ACCOUNT *sampass, char *profile_path)
{
	if (sampass)
	{
		sampass->profile_path = strdup(profile_path);
		return True;
	}
	
	return False;
}

BOOL pdb_set_dir_drive (SAM_ACCOUNT *sampass, char *dir_drive)
{
	if (sampass)
	{
		sampass->dir_drive = strdup(dir_drive);
		return True;
	}
	
	return False;
}

BOOL pdb_set_homedir (SAM_ACCOUNT *sampass, char *homedir)
{
	if (sampass)
	{
		sampass->home_dir = strdup(homedir);
		return True;
	}
	
	return False;
}


BOOL pdb_set_nt_passwd (SAM_ACCOUNT *sampass, BYTE *pwd)
{

	if (pwd == NULL)
		return False;
		
	/* allocate space for the password and make a copy of it */
	if (sampass)
	{
		if ((sampass->nt_pw=(BYTE*)malloc(sizeof(BYTE)*16)) == NULL)
		{
			DEBUG(0,("pdb_set_nt_passwd: ERROR - out of memory for nt_pw!\n"));
			return False;
		}
		if (memcpy(sampass->nt_pw, pwd, 16))
			return True;
	}	

	return False;
}

BOOL pdb_set_lanman_passwd (SAM_ACCOUNT *sampass, BYTE *pwd)
{
	if (pwd == NULL)
		return False;
	
	/* allocate space for the password and make a copy of it */
	if (sampass)
	{
		if ((sampass->lm_pw=(BYTE*)malloc(sizeof(BYTE)*16)) == NULL)
		{
			DEBUG(0,("pdb_set_lanman_passwd: ERROR - out of memory for lm_pw!\n"));
			return False;
		}
		if (memcpy(sampass->lm_pw, pwd, 16))
			return True;
	}	

	return False;
}





