/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
   Copyright (C) Jeremy Allison 		1996-2001
   Copyright (C) Luke Kenneth Casson Leighton 	1996-1998
   Copyright (C) Gerald (Jerry) Carter		2000-2001
      
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

/*
 * This is set on startup - it defines the SID for this
 * machine, and therefore the SAM database for which it is
 * responsible.
 */

extern DOM_SID global_sam_sid;

struct passdb_ops *pdb_ops;

#if 0	/* JERRY */
static void* pdb_handle = NULL;
#endif

/***************************************************************
 Initialize the password db operations.
***************************************************************/

BOOL initialize_password_db(BOOL reload)
{	
	/* 
	 * This function is unfinished right now, so just 
	 * ignore the details and always return True.  It 
	 * is here only as a placeholder          --jerry 
	 */
	return True;
	
}

/*************************************************************
 Initialises a struct sam_disp_info.
 **************************************************************/

static void pdb_init_dispinfo(struct sam_disp_info *user)
{
	if (user == NULL) 
		return;
	ZERO_STRUCTP(user);
}


/************************************************************
 Fill the SAM_ACCOUNT with default values.
 ***********************************************************/

static BOOL pdb_fill_default_sam(SAM_ACCOUNT *user)
{
	if (user == NULL) {
		DEBUG(0,("pdb_fill_default_sam: SAM_ACCOUNT was NULL\n"));
		return False;
	}
	
	ZERO_STRUCTP(user);
	
	user->init_flag		        = FLAG_SAM_UNINIT;
	user->uid = user->gid		= -1;
	user->logon_time            = (time_t)0;
	user->pass_last_set_time    = (time_t)0;
	user->pass_can_change_time  = (time_t)0;
	user->logoff_time           = 
	user->kickoff_time          = 
	user->pass_must_change_time = get_time_t_max(); /* Password never expires. */

	user->unknown_3 = 0x00ffffff; 	/* don't know */
	user->logon_divs = 168; 	/* hours per week */
	user->hours_len = 21; 		/* 21 times 8 bits = 168 */
	memset(user->hours, 0xff, user->hours_len); /* available at all hours */
	user->unknown_5 = 0x00000000; /* don't know */
	user->unknown_6 = 0x000004ec; /* don't know */
	return True;
}	


/*************************************************************
 Alloc memory and initialises a struct sam_passwd.
 ************************************************************/

BOOL pdb_init_sam(SAM_ACCOUNT **user)
{
	if (*user != NULL) {
		DEBUG(0,("pdb_init_sam: SAM_ACCOUNT was non NULL\n"));
#if 0
		smb_panic("NULL pointer passed to pdb_init_sam\n");
#endif
		return False;
	}
	
	*user=(SAM_ACCOUNT *)malloc(sizeof(SAM_ACCOUNT));
	
	if (*user==NULL) {
		DEBUG(0,("pdb_init_sam: error while allocating memory\n"));
		return False;
	}

	pdb_fill_default_sam(*user);

	return True;
}


/*************************************************************
 Initialises a struct sam_passwd with sane values.
 ************************************************************/

BOOL pdb_init_sam_pw(SAM_ACCOUNT **new_sam_acct, struct passwd *pwd)
{
	if (!pwd) {
		new_sam_acct = NULL;
		return False;
	}

	if (!pdb_init_sam(new_sam_acct)) {
		new_sam_acct = NULL;
		return False;
	}


	pdb_set_username(*new_sam_acct, pwd->pw_name);
	pdb_set_fullname(*new_sam_acct, pwd->pw_gecos);
	pdb_set_uid(*new_sam_acct, pwd->pw_uid);
	pdb_set_gid(*new_sam_acct, pwd->pw_gid);
	pdb_set_profile_path(*new_sam_acct, lp_logon_path(), False);
	pdb_set_homedir(*new_sam_acct, lp_logon_home(), False);
	pdb_set_dir_drive(*new_sam_acct, lp_logon_drive(), False);
	pdb_set_logon_script(*new_sam_acct, lp_logon_script(), False);
	return True;
}


/************************************************************
 Free the NT/LM hashes only.
 ***********************************************************/

static BOOL pdb_free_sam_contents(SAM_ACCOUNT *user)
{
	if (user == NULL) {
		DEBUG(0,("pdb_free_sam_contents: SAM_ACCOUNT was NULL\n"));
#if 0
		smb_panic("NULL pointer passed to pdb_free_sam\n");
#endif
		return False;
	}

	/* As we start mallocing more strings this is where  
	   we should free them. */

	SAFE_FREE(user->nt_pw);
	SAFE_FREE(user->lm_pw);
	
	return True;	
}


/************************************************************
 Reset the SAM_ACCOUNT and free the NT/LM hashes.
  - note: they are not zero'ed out however.
 ***********************************************************/

BOOL pdb_reset_sam(SAM_ACCOUNT *user)
{
	if (user == NULL) {
		DEBUG(0,("pdb_reset_sam: SAM_ACCOUNT was NULL\n"));
		return False;
	}
	
	if (!pdb_free_sam_contents(user)) {
		return False;
	}

	if (!pdb_fill_default_sam(user)) {
		return False;
	}

	return True;
}


/************************************************************
 Free the SAM_ACCOUNT and the NT/LM hashes.
 ***********************************************************/

BOOL pdb_free_sam(SAM_ACCOUNT *user)
{
	if (user == NULL) {
		DEBUG(0,("pdb_free_sam: SAM_ACCOUNT was NULL\n"));
#if 0
		smb_panic("NULL pointer passed to pdb_free_sam\n");
#endif
		return False;
	}

	if (!pdb_free_sam_contents(user)) {
		return False;
	}

	SAFE_FREE(user);
	
	return True;	
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

	for ( ; i < length - 2 ; i++ )
		acct_str[i] = ' ';

	i = length - 2;
	acct_str[i++] = ']';
	acct_str[i++] = '\0';

	return acct_str;
}     

/**********************************************************
 Decode the account control bits from a string.
 **********************************************************/

uint16 pdb_decode_acct_ctrl(const char *p)
{
	uint16 acct_ctrl = 0;
	BOOL finished = False;

	/*
	 * Check if the account type bits have been encoded after the
	 * NT password (in the form [NDHTUWSLXI]).
	 */

	if (*p != '[')
		return 0;

	for (p++; *p && !finished; p++) {
		switch (*p) {
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
	const char           *hexchars = "0123456789ABCDEF";
	char           *p1, *p2;
	
	if (!p)
		return (False);
	
	for (i = 0; i < 32; i += 2) {
		hinybble = toupper(p[i]);
		lonybble = toupper(p[i + 1]);

		p1 = strchr(hexchars, hinybble);
		p2 = strchr(hexchars, lonybble);

		if (!p1 || !p2)
			return (False);

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
		return False;

	if (!pw) {
		DEBUG(1,("Username %s is invalid on this system\n", user_name));
		return False;
	}

	/* turn the unix UID into a Domain RID.  this is what the posix
	   sub-system does (adds 1000 to the uid) */
	*u_rid = pdb_uid_to_user_rid(pw->pw_uid);

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

	*psid_name_use = SID_NAME_UNKNOWN;

	DEBUG(5,("local_lookup_rid: looking up %s RID %u.\n", is_user ? "user" :
			"group", (unsigned int)rid));

	if(is_user) {
		if(rid == DOMAIN_USER_RID_ADMIN) {
			const char *p = lp_admin_users(-1);
			*psid_name_use = SID_NAME_USER;
			if(!next_token(&p, name, NULL, sizeof(fstring)))
				fstrcpy(name, "Administrator");
		} else if (rid == DOMAIN_USER_RID_GUEST) {
			const char *p = lp_guestaccount(-1);
			*psid_name_use = SID_NAME_USER;
			if(!next_token(&p, name, NULL, sizeof(fstring)))
				fstrcpy(name, "Guest");
		} else {
			uid_t uid;
			struct passwd *pass;
			
			/*
			 * Don't try to convert the rid to a name if 
			 * running in appliance mode
			 */
			if (lp_hide_local_users())
				return False;
			
			uid = pdb_user_rid_to_uid(rid);
			pass = sys_getpwuid(uid);

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
		gid_t gid;
		struct group *gr; 

		/* 
		 * Don't try to convert the rid to a name if running
		 * in appliance mode
		 */
		
		if (lp_hide_local_users()) 
			return False;
		
		gid = pdb_user_rid_to_gid(rid);
		gr = getgrgid(gid);

		*psid_name_use = SID_NAME_ALIAS;

		DEBUG(5,("local_local_rid: looking up gid %u %s\n", (unsigned int)gid,
			gr ? "succeeded" : "failed" ));

		if(!gr) {
			switch (rid) {
			case DOMAIN_GROUP_RID_ADMINS:
				fstrcpy(name, "Domain Admins");
				return True;
			case DOMAIN_GROUP_RID_USERS:
				fstrcpy(name, "Domain Users");
				return True;
			case DOMAIN_GROUP_RID_GUESTS:
				fstrcpy(name, "Domain Guests");
				return True;
			case BUILTIN_ALIAS_RID_USERS:
				fstrcpy(name, "Users");
				return True;
			}
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

BOOL local_lookup_name(const char *c_domain, const char *c_user, DOM_SID *psid, enum SID_NAME_USE *psid_name_use)
{
	extern DOM_SID global_sid_World_Domain;
	struct passwd *pass = NULL;
	DOM_SID local_sid;
	fstring user;
	fstring domain;

	*psid_name_use = SID_NAME_UNKNOWN;

	/*
	 * domain and user may be quoted const strings, and map_username and
	 * friends can modify them. Make a modifiable copy. JRA.
	 */

	fstrcpy(domain, c_domain);
	fstrcpy(user, c_user);

	sid_copy(&local_sid, &global_sam_sid);

	/*
	 * Special case for MACHINE\Everyone. Map to the world_sid.
	 */

	if(strequal(user, "Everyone")) {
		sid_copy( psid, &global_sid_World_Domain);
		sid_append_rid(psid, 0);
		*psid_name_use = SID_NAME_ALIAS;
		return True;
	}

	/* 
	 * Don't lookup local unix users if running in appliance mode
	 */
	if (lp_hide_local_users()) 
		return False;

	(void)map_username(user);

	if((pass = Get_Pwnam(user, False))) {
		sid_append_rid( &local_sid, pdb_uid_to_user_rid(pass->pw_uid));
		*psid_name_use = SID_NAME_USER;
	} else {
		/*
		 * Maybe it was a group ?
		 */
		struct group *grp = getgrnam(user);

		if(!grp)
			return False;

		sid_append_rid( &local_sid, pdb_gid_to_group_rid(grp->gr_gid));
		*psid_name_use = SID_NAME_ALIAS;
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
	fstring str;
	struct passwd *pass;

	*name_type = SID_NAME_UNKNOWN;

	sid_copy(&dom_sid, psid);
	sid_split_rid(&dom_sid, &rid);

	if (!pdb_rid_is_user(rid))
		return False;

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
	if(!(pass = sys_getpwuid(*puid)))
		return False;

	DEBUG(10,("local_sid_to_uid: SID %s -> uid (%u) (%s).\n", sid_to_string( str, psid),
		(unsigned int)*puid, pass->pw_name ));

	*name_type = SID_NAME_USER;
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
	fstring str;
	struct group *grp;

	*name_type = SID_NAME_UNKNOWN;

	sid_copy(&dom_sid, psid);
	sid_split_rid(&dom_sid, &rid);

	/*
	 * We can only convert to a gid if this is our local
	 * Domain SID (ie. we are the controling authority).
	 */

	if (!sid_equal(&global_sam_sid, &dom_sid))
		return False;

	if (pdb_rid_is_user(rid))
		return False;

	*pgid = pdb_user_rid_to_gid(rid);

	/*
	 * Ensure this gid really does exist.
	 */

	if(!(grp = getgrgid(*pgid)))
		return False;

	*name_type = SID_NAME_ALIAS;

	DEBUG(10,("local_sid_to_gid: SID %s -> gid (%u) (%s).\n", sid_to_string( str, psid),
		(unsigned int)*pgid, grp->gr_name ));

	return True;
}

static void select_name(pstring string, const UNISTR2 *from)
{
	if (from->buffer != 0)
		unistr2_to_dos(string, from, sizeof(pstring));
}

/*************************************************************
 Copies a SAM_USER_INFO_23 to a SAM_ACCOUNT
 **************************************************************/

void copy_id23_to_sam_passwd(SAM_ACCOUNT *to, SAM_USER_INFO_23 *from)
{

	if (from == NULL || to == NULL) 
		return;

	to->logon_time = nt_time_to_unix(&from->logon_time);
	to->logoff_time = nt_time_to_unix(&from->logoff_time);
	to->kickoff_time = nt_time_to_unix(&from->kickoff_time);
	to->pass_last_set_time = nt_time_to_unix(&from->pass_last_set_time);
	to->pass_can_change_time = nt_time_to_unix(&from->pass_can_change_time);
	to->pass_must_change_time = nt_time_to_unix(&from->pass_must_change_time);

	select_name(to->username    , &from->uni_user_name   );
	select_name(to->full_name   , &from->uni_full_name   );
	select_name(to->home_dir    , &from->uni_home_dir    );
	select_name(to->dir_drive   , &from->uni_dir_drive   );
	select_name(to->logon_script, &from->uni_logon_script);
	select_name(to->profile_path, &from->uni_profile_path);
	select_name(to->acct_desc   , &from->uni_acct_desc   );
	select_name(to->workstations, &from->uni_workstations);
	select_name(to->unknown_str , &from->uni_unknown_str );
	select_name(to->munged_dial , &from->uni_munged_dial );

	to->user_rid = from->user_rid;
	to->group_rid = from->group_rid;

	to->acct_ctrl = from->acb_info;
	to->unknown_3 = from->unknown_3;

	to->logon_divs = from->logon_divs;
	to->hours_len = from->logon_hrs.len;
	memcpy(to->hours, from->logon_hrs.hours, MAX_HOURS_LEN);

	to->unknown_5 = from->unknown_5;
	to->unknown_6 = from->unknown_6;
}

/*************************************************************
 Copies a sam passwd.
 **************************************************************/

void copy_id21_to_sam_passwd(SAM_ACCOUNT *to, SAM_USER_INFO_21 *from)
{
	if (from == NULL || to == NULL) 
		return;

	to->logon_time = nt_time_to_unix(&from->logon_time);
	to->logoff_time = nt_time_to_unix(&from->logoff_time);
	to->kickoff_time = nt_time_to_unix(&from->kickoff_time);
	to->pass_last_set_time = nt_time_to_unix(&from->pass_last_set_time);
	to->pass_can_change_time = nt_time_to_unix(&from->pass_can_change_time);
	to->pass_must_change_time = nt_time_to_unix(&from->pass_must_change_time);

	select_name(to->username    , &from->uni_user_name   );
	select_name(to->full_name   , &from->uni_full_name   );
	select_name(to->home_dir    , &from->uni_home_dir    );
	select_name(to->dir_drive   , &from->uni_dir_drive   );
	select_name(to->logon_script, &from->uni_logon_script);
	select_name(to->profile_path, &from->uni_profile_path);
	select_name(to->acct_desc   , &from->uni_acct_desc   );
	select_name(to->workstations, &from->uni_workstations);
	select_name(to->unknown_str , &from->uni_unknown_str );
	select_name(to->munged_dial , &from->uni_munged_dial );

	to->user_rid = from->user_rid;
	to->group_rid = from->group_rid;
	
	/* FIXME!!  Do we need to copy the passwords here as well?
	   I don't know.  Need to figure this out   --jerry */

	to->acct_ctrl = from->acb_info;
	to->unknown_3 = from->unknown_3;

	to->logon_divs = from->logon_divs;
	to->hours_len = from->logon_hrs.len;
	memcpy(to->hours, from->logon_hrs.hours, MAX_HOURS_LEN);

	to->unknown_5 = from->unknown_5;
	to->unknown_6 = from->unknown_6;
}

#if 0	/* JERRY */
/*************************************************************
 Copies a SAM_ACCOUNT.
 FIXME!!!!  This is broken as SAM_ACCOUNT contains two 
 pointers.   --jerry
 **************************************************************/

void copy_sam_passwd(SAM_ACCOUNT *to, const SAM_ACCOUNT *from)
{
	if (!from || !to)
		return;

	memcpy(to, from, sizeof(SAM_ACCOUNT));
	
	
} 
#endif 

/*************************************************************
 Change a password entry in the local smbpasswd file.

 FIXME!!  The function needs to be abstracted into the
 passdb interface or something.  It is currently being called
 by _api_samr_create_user() in rpc_server/srv_samr.c
 
 --jerry

 FIXME ! The new password is in UNIX character set. Must be
 changed to DOS codepage before hashing.
 *************************************************************/

BOOL local_password_change(const char *user_name, int local_flags,
			   const char *new_passwd, 
			   char *err_str, size_t err_str_len,
			   char *msg_str, size_t msg_str_len)
{
	struct passwd  *pwd = NULL;
	SAM_ACCOUNT 	*sam_pass=NULL;

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

	/* Get the smb passwd entry for this user */
	pdb_init_sam(&sam_pass);
	if(local_flags & LOCAL_DELETE_USER) {
		if (!pdb_delete_sam_account(user_name)) {
			slprintf(err_str,err_str_len-1, "Failed to delete entry for user %s.\n", user_name);
			pdb_free_sam(sam_pass);
			return False;
		}
		slprintf(msg_str, msg_str_len-1, "Deleted user %s.\n", user_name);
		pdb_free_sam(sam_pass);
		return True;
	}
	if(!pdb_getsampwnam(sam_pass, user_name)) {
		pdb_free_sam(sam_pass);
		
		if(!(local_flags & LOCAL_ADD_USER)) {
			slprintf(err_str, err_str_len-1,"Failed to find entry for user %s.\n", user_name);
			return False;
		}

		sam_pass = NULL;
		if (!pdb_init_sam_pw(&sam_pass, sys_getpwnam(user_name))) {
			return False;
		}

		/* Set account flags. Note that the default is non-expiring accounts */
		pdb_set_acct_ctrl(sam_pass,(local_flags & LOCAL_TRUST_ACCOUNT) ? ACB_WSTRUST : ACB_NORMAL|ACB_PWNOEXP);

		if (local_flags & LOCAL_DISABLE_USER)
			pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)|ACB_DISABLED);

		if (local_flags & LOCAL_SET_NO_PASSWORD) {
			pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)|ACB_PWNOTREQ);
		} else {
			/* set the passwords here.  if we get to here it means
			   we have a valid, active account */
			if (!pdb_set_plaintext_passwd (sam_pass, new_passwd)) {
				pdb_free_sam(sam_pass);
				return False;
			}
		}

		/* Remember to set the "last changed time". */
		pdb_set_pass_last_set_time(sam_pass, time(NULL));

		if (pdb_add_sam_account(sam_pass)) {
			slprintf(msg_str, msg_str_len-1, "Added user %s.\n", user_name);
			pdb_free_sam(sam_pass);
			return True;
		} else {
			slprintf(err_str, err_str_len-1, "Failed to add entry for user %s.\n", user_name);
			pdb_free_sam(sam_pass);
			return False;
		}
	} else {
		/* the entry already existed */
		local_flags &= ~LOCAL_ADD_USER;
		slprintf(msg_str, msg_str_len-1, "Password changed for user %s.\n", user_name );
	}

	/*
	 * We are root - just write the new password
	 * and the valid last change time.
	 */

	if(local_flags & LOCAL_DISABLE_USER) {
		pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)|ACB_DISABLED);
	} else if (local_flags & LOCAL_ENABLE_USER) {
		if(pdb_get_lanman_passwd(sam_pass) == NULL) {
			if (!pdb_set_plaintext_passwd (sam_pass, new_passwd)) {
				pdb_free_sam(sam_pass);
				return False;
			}
		}
		pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)&(~ACB_DISABLED));
	} else if (local_flags & LOCAL_SET_NO_PASSWORD) {
		pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)|ACB_PWNOTREQ);
		/* This is needed to preserve ACB_PWNOTREQ in mod_smbfilepwd_entry */
		if (!pdb_set_lanman_passwd (sam_pass, NULL)) {
			pdb_free_sam(sam_pass);
			return False;
		}
		if (!pdb_set_nt_passwd(sam_pass, NULL)) {
			pdb_free_sam(sam_pass);
			return False;
		}
	} else {
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
		if (!pdb_set_plaintext_passwd (sam_pass, new_passwd)) {
			pdb_free_sam(sam_pass);
			return False;	
		}
	}
	
	if(!pdb_update_sam_account(sam_pass, True)) {
		slprintf(err_str, err_str_len-1, "Failed to modify entry for user %s.\n", user_name);
		pdb_free_sam(sam_pass);
		return False;
	}
	if(local_flags & LOCAL_DISABLE_USER)
		slprintf(msg_str, msg_str_len-1, "Disabled user %s.\n", user_name);
	else if (local_flags & LOCAL_ENABLE_USER)
		slprintf(msg_str, msg_str_len-1, "Enabled user %s.\n", user_name);
	else if (local_flags & LOCAL_SET_NO_PASSWORD)
		slprintf(msg_str, msg_str_len-1, "User %s password set to none.\n", user_name);

	pdb_free_sam(sam_pass);
	return True;
}

/*********************************************************************
 Collection of get...() functions for SAM_ACCOUNT_INFO.
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
		return (0);
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

uint8* pdb_get_nt_passwd (SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->nt_pw);
	else
		return (NULL);
}

uint8* pdb_get_lanman_passwd (SAM_ACCOUNT *sampass)
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
 Collection of set...() functions for SAM_ACCOUNT_INFO.
 ********************************************************************/

BOOL pdb_set_acct_ctrl (SAM_ACCOUNT *sampass, uint16 flags)
{
	if (!sampass)
		return False;
		
	if (sampass) {
		sampass->acct_ctrl = flags;
		return True;
	}
	
	return False;
}

BOOL pdb_set_logon_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->logon_time = mytime;
	return True;
}

BOOL pdb_set_logoff_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->logoff_time = mytime;
	return True;
}

BOOL pdb_set_kickoff_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->kickoff_time = mytime;
	return True;
}

BOOL pdb_set_pass_can_change_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->pass_can_change_time = mytime;
	return True;
}

BOOL pdb_set_pass_must_change_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->pass_must_change_time = mytime;
	return True;
}

BOOL pdb_set_pass_last_set_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->pass_last_set_time = mytime;
	return True;
}

BOOL pdb_set_hours_len (SAM_ACCOUNT *sampass, uint32 len)
{
	if (!sampass)
		return False;

	sampass->hours_len = len;
	return True;
}

BOOL pdb_set_logon_divs (SAM_ACCOUNT *sampass, uint16 hours)
{
	if (!sampass)
		return False;

	sampass->logon_divs = hours;
	return True;
}

BOOL pdb_set_init_flag (SAM_ACCOUNT *sampass, uint32 flag)
{
	if (!sampass)
		return False;
	
	sampass->init_flag |= flag;

	return True;
}

BOOL pdb_set_uid (SAM_ACCOUNT *sampass, uid_t uid)
{
	if (!sampass)
		return False;

	sampass->uid = uid;
	sampass->init_flag |= FLAG_SAM_UID; 

	return True;
}

BOOL pdb_set_gid (SAM_ACCOUNT *sampass, gid_t gid)
{
	if (!sampass)
		return False;

	sampass->gid = gid;	
	sampass->init_flag |= FLAG_SAM_GID; 

	return True;
}

BOOL pdb_set_user_rid (SAM_ACCOUNT *sampass, uint32 rid)
{
	if (!sampass)
		return False;

	sampass->user_rid = rid;
	return True;
}

BOOL pdb_set_group_rid (SAM_ACCOUNT *sampass, uint32 grid)
{
	if (!sampass)
		return False;

	sampass->group_rid = grid;
	return True;
}

/*********************************************************************
 Set the user's UNIX name.
 ********************************************************************/

BOOL pdb_set_username(SAM_ACCOUNT *sampass, char *username)
{	
	if (!sampass)
		return False;
	*sampass->username = '\0';
	if (!username)
		return False;

	StrnCpy (sampass->username, username, sizeof(sampass->username)-1);

	return True;
}

/*********************************************************************
 Set the domain name.
 ********************************************************************/

BOOL pdb_set_domain(SAM_ACCOUNT *sampass, char *domain)
{	
	if (!sampass)
		return False;
	*sampass->domain = '\0';
	if (!domain)
		return False;

	StrnCpy (sampass->domain, domain, sizeof(sampass->domain)-1);

	return True;
}

/*********************************************************************
 Set the user's NT name.
 ********************************************************************/

BOOL pdb_set_nt_username(SAM_ACCOUNT *sampass, char *nt_username)
{
	if (!sampass)
		return False;
	*sampass->nt_username = '\0';
	if (!nt_username)
		return False;

	StrnCpy (sampass->nt_username, nt_username, sizeof(sampass->nt_username) -1);

	return True;
}

/*********************************************************************
 Set the user's full name.
 ********************************************************************/

BOOL pdb_set_fullname(SAM_ACCOUNT *sampass, char *fullname)
{
	if (!sampass)
		return False;
	*sampass->full_name = '\0';
	if (!fullname)
		return False;

	StrnCpy (sampass->full_name, fullname, sizeof(sampass->full_name)-1);

	return True;
}

/*********************************************************************
 Set the user's logon script.
 ********************************************************************/

BOOL pdb_set_logon_script(SAM_ACCOUNT *sampass, char *logon_script, BOOL store)
{
	if (!sampass)
		return False;
	*sampass->logon_script = '\0';
	if (!logon_script)
		return False;

	StrnCpy (sampass->logon_script, logon_script, sizeof(sampass->logon_script)-1);

	if (store)
		pdb_set_init_flag(sampass, FLAG_SAM_LOGONSCRIPT);

	return True;
}

/*********************************************************************
 Set the user's profile path.
 ********************************************************************/

BOOL pdb_set_profile_path (SAM_ACCOUNT *sampass, char *profile_path, BOOL store)
{
	if (!sampass)
		return False;
	*sampass->profile_path = '\0';
	if (!profile_path)
		return False;
	
	StrnCpy (sampass->profile_path, profile_path, sizeof(sampass->profile_path)-1);

	if (store)
		pdb_set_init_flag(sampass, FLAG_SAM_PROFILE);
	
	return True;
}

/*********************************************************************
 Set the user's directory drive.
 ********************************************************************/

BOOL pdb_set_dir_drive (SAM_ACCOUNT *sampass, char *dir_drive, BOOL store)
{
	if (!sampass)
		return False;
	*sampass->dir_drive = '\0';
	if (!dir_drive)
		return False;

	StrnCpy (sampass->dir_drive, dir_drive, sizeof(sampass->dir_drive)-1);
	
	if (store)
		pdb_set_init_flag(sampass, FLAG_SAM_DRIVE);

	return True;
}

/*********************************************************************
 Set the user's home directory.
 ********************************************************************/

BOOL pdb_set_homedir (SAM_ACCOUNT *sampass, char *homedir, BOOL store)
{
	if (!sampass)
		return False;
	*sampass->home_dir = '\0';
	if (!homedir)
		return False;
	
	StrnCpy (sampass->home_dir, homedir, sizeof(sampass->home_dir)-1);

	if (store)
		pdb_set_init_flag(sampass, FLAG_SAM_SMBHOME);

	return True;
}

/*********************************************************************
 Set the user's account description.
 ********************************************************************/

BOOL pdb_set_acct_desc (SAM_ACCOUNT *sampass, char *acct_desc)
{
	if (!sampass)
		return False;
	*sampass->acct_desc = '\0';
	if (!acct_desc)
		return False;
	
	StrnCpy (sampass->acct_desc, acct_desc, sizeof(sampass->acct_desc)-1);

	return True;
}

/*********************************************************************
 Set the user's workstation allowed list.
 ********************************************************************/

BOOL pdb_set_workstations (SAM_ACCOUNT *sampass, char *workstations)
{
	if (!sampass)
		return False;
	*sampass->workstations = '\0';
	if (!workstations)
		return False;

	StrnCpy (sampass->workstations, workstations, sizeof(sampass->workstations)-1);

	return True;
}

/*********************************************************************
 Set the user's dial string.
 ********************************************************************/

BOOL pdb_set_munged_dial (SAM_ACCOUNT *sampass, char *munged_dial)
{
	if (!sampass)
		return False;
	*sampass->munged_dial = '\0';
	if (!munged_dial)
		return False;

	StrnCpy (sampass->munged_dial, munged_dial, sizeof(sampass->munged_dial)-1);

	return True;
}

/*********************************************************************
 Set the user's NT hash.
 ********************************************************************/

BOOL pdb_set_nt_passwd (SAM_ACCOUNT *sampass, uint8 *pwd)
{
	if (!sampass)
		return False;
	
	/* Remember to set the "last changed time". */
	pdb_set_pass_last_set_time(sampass, time(NULL));

	if (!pwd) {
		/* Allow setting to NULL */
		SAFE_FREE(sampass->nt_pw);
		return True;
	}

	if (sampass->nt_pw!=NULL)
		DEBUG(4,("pdb_set_nt_passwd: NT hash non NULL overwritting ?\n"));
	else
		sampass->nt_pw=(unsigned char *)malloc(sizeof(unsigned char)*16);
	
	if (sampass->nt_pw==NULL)
		return False;

	memcpy (sampass->nt_pw, pwd, 16);

	return True;
}

/*********************************************************************
 Set the user's LM hash.
 ********************************************************************/

BOOL pdb_set_lanman_passwd (SAM_ACCOUNT *sampass, uint8 *pwd)
{
	if (!sampass)
		return False;

	/* Remember to set the "last changed time". */
	pdb_set_pass_last_set_time(sampass, time(NULL));

	if (!pwd) {
		/* Allow setting to NULL */
		SAFE_FREE(sampass->lm_pw);
		return True;
	}
	
	if (sampass->lm_pw!=NULL)
		DEBUG(4,("pdb_set_lanman_passwd: LM hash non NULL overwritting ?\n"));
	else
		sampass->lm_pw=(unsigned char *)malloc(sizeof(unsigned char)*16);
	
	if (sampass->lm_pw==NULL)
		return False;

	memcpy (sampass->lm_pw, pwd, 16);

	return True;
}

/*********************************************************************
 Set the user's PLAINTEXT password.  Used as an interface to the above.
 NB. The plaintext is in UNIX character set. Must be converted to DOS
 codepage.
 ********************************************************************/

BOOL pdb_set_plaintext_passwd (SAM_ACCOUNT *sampass, const char *plaintext)
{
	uchar new_lanman_p16[16];
	uchar new_nt_p16[16];
	fstring dos_plaintext;

	if (!sampass || !plaintext)
		return False;
	
	fstrcpy(dos_plaintext, unix_to_dos_static(plaintext));

	nt_lm_owf_gen (dos_plaintext, new_nt_p16, new_lanman_p16);

	if (!pdb_set_nt_passwd (sampass, new_nt_p16)) 
		return False;

	if (!pdb_set_lanman_passwd (sampass, new_lanman_p16)) 
		return False;

	return True;
}

BOOL pdb_set_unknown_3 (SAM_ACCOUNT *sampass, uint32 unkn)
{
	if (!sampass)
		return False;

	sampass->unknown_3 = unkn;
	return True;
}

BOOL pdb_set_unknown_5 (SAM_ACCOUNT *sampass, uint32 unkn)
{
	if (!sampass)
		return False;

	sampass->unknown_5 = unkn;
	return True;
}

BOOL pdb_set_unknown_6 (SAM_ACCOUNT *sampass, uint32 unkn)
{
	if (!sampass)
		return False;

	sampass->unknown_6 = unkn;
	return True;
}

BOOL pdb_set_hours (SAM_ACCOUNT *sampass, uint8 *hours)
{
	if (!sampass)
		return False;

	if (!hours) {
		memset ((char *)sampass->hours, 0, MAX_HOURS_LEN);
		return True;
	}
	
	memcpy (sampass->hours, hours, MAX_HOURS_LEN);

	return True;
}

/***************************************************************************
 Search by uid.  Wrapper around pdb_getsampwnam()
 **************************************************************************/

BOOL pdb_getsampwuid (SAM_ACCOUNT* user, uid_t uid)
{
	struct passwd	*pw;
	fstring		name;

	if (user==NULL) {
		DEBUG(0,("pdb_getsampwuid: SAM_ACCOUNT is NULL.\n"));
		return False;
	}

	/*
	 * Never trust the uid in the passdb.  Lookup the username first
	 * and then lokup the user by name in the sam.
	 */
	 
	if ((pw=sys_getpwuid(uid)) == NULL)  {
		DEBUG(0,("pdb_getsampwuid: getpwuid(%u) return NULL. User does not exist in Unix accounts!\n",
					(unsigned int)uid));
		return False;
	}
	
	fstrcpy (name, pw->pw_name);

	return pdb_getsampwnam (user, name);

}

