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

        /* Don't change these timestamp settings without a good reason.
           They are important for NT member server compatibility. */

	user->private.init_flag		    = FLAG_SAM_UNINIT;
	user->private.uid = user->private.gid	    = -1;

	user->private.logon_time            = (time_t)0;
	user->private.pass_last_set_time    = (time_t)0;
	user->private.pass_can_change_time  = (time_t)0;
	user->private.logoff_time           = 
	user->private.kickoff_time          = 
	user->private.pass_must_change_time = get_time_t_max();
	user->private.unknown_3 = 0x00ffffff; 	/* don't know */
	user->private.logon_divs = 168; 	/* hours per week */
	user->private.hours_len = 21; 		/* 21 times 8 bits = 168 */
	memset(user->private.hours, 0xff, user->private.hours_len); /* available at all hours */
	user->private.unknown_5 = 0x00000000; /* don't know */
	user->private.unknown_6 = 0x000004ec; /* don't know */
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

BOOL pdb_init_sam_pw(SAM_ACCOUNT **new_sam_acct, const struct passwd *pwd)
{
	pstring str;
	GROUP_MAP map;
	uint32 rid;

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
	
	pdb_set_user_rid(*new_sam_acct, pdb_uid_to_user_rid(pwd->pw_uid));

	/* call the mapping code here */
	if(get_group_map_from_gid(pwd->pw_gid, &map, MAPPING_WITHOUT_PRIV)) {
		sid_peek_rid(&map.sid, &rid);
	} 
	else {
		rid=pdb_gid_to_group_rid(pwd->pw_gid);
	}
		
	pdb_set_group_rid(*new_sam_acct, rid);

	pstrcpy(str, lp_logon_path());
	standard_sub_advanced(-1, pwd->pw_name, "", pwd->pw_gid, pwd->pw_name, str);
	pdb_set_profile_path(*new_sam_acct, str, False);
	
	pstrcpy(str, lp_logon_home());
	standard_sub_advanced(-1, pwd->pw_name, "", pwd->pw_gid, pwd->pw_name, str);
	pdb_set_homedir(*new_sam_acct, str, False);
	
	pstrcpy(str, lp_logon_drive());
	standard_sub_advanced(-1, pwd->pw_name, "", pwd->pw_gid, pwd->pw_name, str);
	pdb_set_dir_drive(*new_sam_acct, str, False);

	pstrcpy(str, lp_logon_script());
	standard_sub_advanced(-1, pwd->pw_name, "", pwd->pw_gid, pwd->pw_name, str);
	pdb_set_logon_script(*new_sam_acct, str, False);
	
	return True;
}


/**
 * Free the contets of the SAM_ACCOUNT, but not the structure.
 *
 * Also wipes the LM and NT hashes from memory.
 *
 * @param user SAM_ACCOUNT to free members of.
 **/

static BOOL pdb_free_sam_contents(SAM_ACCOUNT *user)
{
	if (user == NULL) {
		DEBUG(0,("pdb_free_sam_contents: SAM_ACCOUNT was NULL\n"));
#if 0
		smb_panic("NULL pointer passed to pdb_free_sam_contents\n");
#endif
		return False;
	}

	/* As we start mallocing more strings this is where  
	   we should free them. */

	data_blob_clear_free(&(user->private.lm_pw));
	data_blob_clear_free(&(user->private.nt_pw));

	return True;	
}


/************************************************************
 Reset the SAM_ACCOUNT and free the NT/LM hashes.
 ***********************************************************/

BOOL pdb_reset_sam(SAM_ACCOUNT *user)
{
	if (user == NULL) {
		DEBUG(0,("pdb_reset_sam: SAM_ACCOUNT was NULL\n"));
#if 0
		smb_panic("NULL pointer passed to pdb_free_sam\n");
#endif
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
 Free the SAM_ACCOUNT and the member pointers.
 ***********************************************************/

BOOL pdb_free_sam(SAM_ACCOUNT **user)
{
	if (*user == NULL) {
		DEBUG(0,("pdb_free_sam: SAM_ACCOUNT was NULL\n"));
#if 0
		smb_panic("NULL pointer passed to pdb_free_sam\n");
#endif
		return False;
	}

	if (!pdb_free_sam_contents(*user)) {
		return False;
	}

	SAFE_FREE(*user);
	
	return True;	
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

void pdb_sethexpwd(char *p, const unsigned char *pwd, uint16 acct_ctrl)
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

BOOL pdb_gethexpwd(const char *p, unsigned char *pwd)
{
	int i;
	unsigned char   lonybble, hinybble;
	char           *hexchars = "0123456789ABCDEF";
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

BOOL pdb_name_to_rid(const char *user_name, uint32 *u_rid, uint32 *g_rid)
{
	GROUP_MAP map;
	struct passwd *pw = Get_Pwnam(user_name);

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
	/* map it ! */
	if (get_group_map_from_gid(pw->pw_gid, &map, MAPPING_WITHOUT_PRIV)) {
		sid_peek_rid(&map.sid, g_rid);
	} else 
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
 Converts NT group RID to a UNIX gid.
 ********************************************************************/

gid_t pdb_group_rid_to_gid(uint32 group_rid)
{
	return (gid_t)(((group_rid & (~GROUP_RID_TYPE))- 1000)/RID_MULTIPLIER);
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
 
 warning: you must not call that function only
 you must do a call to the group mapping first.
 there is not anymore a direct link between the gid and the rid.
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

BOOL local_lookup_sid(DOM_SID *sid, char *name, enum SID_NAME_USE *psid_name_use)
{
	uint32 rid;
	BOOL is_user;

	sid_peek_rid(sid, &rid);
	is_user = pdb_rid_is_user(rid);
	*psid_name_use = SID_NAME_UNKNOWN;

	DEBUG(5,("local_lookup_sid: looking up %s RID %u.\n", is_user ? "user" :
			"group", (unsigned int)rid));

	if(is_user) {
		if(rid == DOMAIN_USER_RID_ADMIN) {
			pstring admin_users;
			char *p = admin_users;
			*psid_name_use = SID_NAME_USER;
			if(!next_token(&p, name, NULL, sizeof(fstring)))
				fstrcpy(name, "Administrator");
		} else if (rid == DOMAIN_USER_RID_GUEST) {
			pstring guest_users;
			char *p = guest_users;
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

			DEBUG(5,("local_lookup_sid: looking up uid %u %s\n", (unsigned int)uid,
				pass ? "succeeded" : "failed" ));

			if(!pass) {
				slprintf(name, sizeof(fstring)-1, "unix_user.%u", (unsigned int)uid);
				return True;
			}

			fstrcpy(name, pass->pw_name);

			DEBUG(5,("local_lookup_sid: found user %s for rid %u\n", name,
				(unsigned int)rid ));
		}

	} else {
		gid_t gid;
		struct group *gr; 
		GROUP_MAP map;
		
		/* 
		 * Don't try to convert the rid to a name if running
		 * in appliance mode
		 */
		
		if (lp_hide_local_users()) 
			return False;

		/* check if it's a mapped group */
		if (get_group_map_from_sid(*sid, &map, MAPPING_WITHOUT_PRIV)) {
			if (map.gid!=-1) {
				DEBUG(5,("local_lookup_sid: mapped group %s to gid %u\n", map.nt_name, (unsigned int)map.gid));
				fstrcpy(name, map.nt_name);
				*psid_name_use = map.sid_name_use;
				return True;
			}
		}
		
		gid = pdb_group_rid_to_gid(rid);
		gr = getgrgid(gid);

		*psid_name_use = SID_NAME_ALIAS;

		DEBUG(5,("local_lookup_sid: looking up gid %u %s\n", (unsigned int)gid,
			gr ? "succeeded" : "failed" ));

		if(!gr) {
			slprintf(name, sizeof(fstring)-1, "unix_group.%u", (unsigned int)gid);
			return False;
		}

		fstrcpy( name, gr->gr_name);

		DEBUG(5,("local_lookup_sid: found group %s for rid %u\n", name,
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

	if((pass = Get_Pwnam(user))) {
		sid_append_rid( &local_sid, pdb_uid_to_user_rid(pass->pw_uid));
		*psid_name_use = SID_NAME_USER;
	} else {
		/*
		 * Maybe it was a group ?
		 */
		struct group *grp;
		GROUP_MAP map;
		
		/* check if it's a mapped group */
		if (get_group_map_from_ntname(user, &map, MAPPING_WITHOUT_PRIV)) {
			if (map.gid!=-1) {
				/* yes it's a mapped group to a valid unix group */
				sid_copy(&local_sid, &map.sid);
				*psid_name_use = map.sid_name_use;
			}
			else
				/* it's a correct name but not mapped so it points to nothing*/
				return False;
		} else {
			/* it's not a mapped group */
			grp = getgrnam(user);
			if(!grp)
				return False;

			/* 
			 *check if it's mapped, if it is reply it doesn't exist
			 *
			 * that's to prevent this case:
			 *
			 * unix group ug is mapped to nt group ng
			 * someone does a lookup on ug
			 * we must not reply as it doesn't "exist" anymore
			 * for NT. For NT only ng exists.
			 * JFM, 30/11/2001
			 */
			
			if(get_group_map_from_gid(grp->gr_gid, &map, MAPPING_WITHOUT_PRIV)){
				return False;
			}

			sid_append_rid( &local_sid, pdb_gid_to_group_rid(grp->gr_gid));
			*psid_name_use = SID_NAME_ALIAS;
		}
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
	GROUP_MAP map;

	sid_copy(psid, &global_sam_sid);
	
	if (get_group_map_from_gid(gid, &map, MAPPING_WITHOUT_PRIV)) {
		sid_copy(psid, &map.sid);
	}
	else {
		sid_append_rid(psid, pdb_gid_to_group_rid(gid));
	}

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
	GROUP_MAP map;

	*name_type = SID_NAME_UNKNOWN;

	sid_copy(&dom_sid, psid);
	sid_split_rid(&dom_sid, &rid);

	/*
	 * We can only convert to a gid if this is our local
	 * Domain SID (ie. we are the controling authority).
	 *
	 * Or in the Builtin SID too. JFM, 11/30/2001
	 */

	if (!sid_equal(&global_sam_sid, &dom_sid))
		return False;

	if (pdb_rid_is_user(rid))
		return False;

	if (get_group_map_from_sid(*psid, &map, MAPPING_WITHOUT_PRIV)) {
		
		/* the SID is in the mapping table but not mapped */
		if (map.gid==-1)
			return False;

		sid_peek_rid(&map.sid, &rid);
		*pgid = rid;
		*name_type = map.sid_name_use;
	} else {
		*pgid = pdb_group_rid_to_gid(rid);
		*name_type = SID_NAME_ALIAS;
	}

	/*
	 * Ensure this gid really does exist.
	 */

	if(!(grp = getgrgid(*pgid)))
		return False;

	DEBUG(10,("local_sid_to_gid: SID %s -> gid (%u) (%s).\n", sid_to_string( str, psid),
		(unsigned int)*pgid, grp->gr_name ));

	return True;
}

/** 
 * Quick hack to do an easy ucs2 -> mulitbyte conversion 
 * @return static buffer containing the converted string
 **/

static char *pdb_convert(const UNISTR2 *from)
{
	static pstring convert_buffer;
	*convert_buffer = 0;
	if (!from) {
		return convert_buffer;
	}

	unistr2_to_ascii(convert_buffer, from, sizeof(pstring));
	return convert_buffer;
}

/*************************************************************
 Copies a SAM_USER_INFO_23 to a SAM_ACCOUNT
 **************************************************************/

void copy_id23_to_sam_passwd(SAM_ACCOUNT *to, SAM_USER_INFO_23 *from)
{

	if (from == NULL || to == NULL) 
		return;

	pdb_set_logon_time(to,nt_time_to_unix(&from->logon_time));
	pdb_set_logoff_time(to,nt_time_to_unix(&from->logoff_time));
	pdb_set_kickoff_time(to, nt_time_to_unix(&from->kickoff_time));
	pdb_set_pass_last_set_time(to, nt_time_to_unix(&from->pass_last_set_time));
	pdb_set_pass_can_change_time(to, nt_time_to_unix(&from->pass_can_change_time));
	pdb_set_pass_must_change_time(to, nt_time_to_unix(&from->pass_must_change_time));

	pdb_set_username(to      , pdb_convert(&from->uni_user_name   ));
	pdb_set_fullname(to      , pdb_convert(&from->uni_full_name   ));
	pdb_set_homedir(to       , pdb_convert(&from->uni_home_dir    ), True);
	pdb_set_dir_drive(to     , pdb_convert(&from->uni_dir_drive   ), True);
	pdb_set_logon_script(to  , pdb_convert(&from->uni_logon_script), True);
	pdb_set_profile_path(to  , pdb_convert(&from->uni_profile_path), True);
	pdb_set_acct_desc(to     , pdb_convert(&from->uni_acct_desc   ));
	pdb_set_workstations(to  , pdb_convert(&from->uni_workstations));
	pdb_set_unknown_str(to   , pdb_convert(&from->uni_unknown_str ));
	pdb_set_munged_dial(to   , pdb_convert(&from->uni_munged_dial ));

	if (from->user_rid)
		pdb_set_user_rid(to, from->user_rid);
	if (from->group_rid)
		pdb_set_group_rid(to, from->group_rid);

	pdb_set_acct_ctrl(to, from->acb_info);
	pdb_set_unknown_3(to, from->unknown_3);

	pdb_set_logon_divs(to, from->logon_divs);
	pdb_set_hours_len(to, from->logon_hrs.len);
	pdb_set_hours(to, from->logon_hrs.hours);

	pdb_set_unknown_5(to, from->unknown_5);
	pdb_set_unknown_6(to, from->unknown_6);
}


/*************************************************************
 Copies a sam passwd.
 **************************************************************/

void copy_id21_to_sam_passwd(SAM_ACCOUNT *to, SAM_USER_INFO_21 *from)
{
	if (from == NULL || to == NULL) 
		return;

	pdb_set_logon_time(to,nt_time_to_unix(&from->logon_time));
	pdb_set_logoff_time(to,nt_time_to_unix(&from->logoff_time));
	pdb_set_kickoff_time(to, nt_time_to_unix(&from->kickoff_time));
	pdb_set_pass_last_set_time(to, nt_time_to_unix(&from->pass_last_set_time));
	pdb_set_pass_can_change_time(to, nt_time_to_unix(&from->pass_can_change_time));
	pdb_set_pass_must_change_time(to, nt_time_to_unix(&from->pass_must_change_time));

	pdb_set_username(to      , pdb_convert(&from->uni_user_name   ));
	pdb_set_fullname(to      , pdb_convert(&from->uni_full_name   ));
	pdb_set_homedir(to       , pdb_convert(&from->uni_home_dir    ), True);
	pdb_set_dir_drive(to     , pdb_convert(&from->uni_dir_drive   ), True);
	pdb_set_logon_script(to  , pdb_convert(&from->uni_logon_script), True);
	pdb_set_profile_path(to  , pdb_convert(&from->uni_profile_path), True);
	pdb_set_acct_desc(to     , pdb_convert(&from->uni_acct_desc   ));
	pdb_set_workstations(to  , pdb_convert(&from->uni_workstations));
	pdb_set_unknown_str(to   , pdb_convert(&from->uni_unknown_str ));
	pdb_set_munged_dial(to   , pdb_convert(&from->uni_munged_dial ));

	if (from->user_rid)
		pdb_set_user_rid(to, from->user_rid);
	if (from->group_rid)
		pdb_set_group_rid(to, from->group_rid);

	/* FIXME!!  Do we need to copy the passwords here as well?
	   I don't know.  Need to figure this out   --jerry */

	/* Passwords dealt with in caller --abartlet */

	pdb_set_acct_ctrl(to, from->acb_info);
	pdb_set_unknown_3(to, from->unknown_3);

	pdb_set_logon_divs(to, from->logon_divs);
	pdb_set_hours_len(to, from->logon_hrs.len);
	pdb_set_hours(to, from->logon_hrs.hours);

	pdb_set_unknown_5(to, from->unknown_5);
	pdb_set_unknown_6(to, from->unknown_6);
}


/*************************************************************
 Change a password entry in the local smbpasswd file.

 FIXME!!  The function needs to be abstracted into the
 passdb interface or something.  It is currently being called
 by _api_samr_create_user() in rpc_server/srv_samr.c,
 in SWAT and by smbpasswd/pdbedit.
 
 --jerry
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

	/* Get the smb passwd entry for this user */
	pdb_init_sam(&sam_pass);
	if(!pdb_getsampwnam(sam_pass, user_name)) {
		pdb_free_sam(&sam_pass);
		
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
		} else {
			slprintf(err_str, err_str_len-1,"Failed to find entry for user %s.\n", user_name);
			return False;
		}

		if (!pdb_init_sam_pw(&sam_pass, pwd)) {
			slprintf(err_str, err_str_len-1, "Failed initialise SAM_ACCOUNT for user %s.\n", user_name);
			return False;
		}

	
		if (local_flags & LOCAL_TRUST_ACCOUNT) {
	        	if (!pdb_set_acct_ctrl(sam_pass, ACB_WSTRUST)) {
	                	slprintf(err_str, err_str_len - 1, "Failed to set 'trusted workstation account' flags for user %s.\n", user_name);
	                	pdb_free_sam(&sam_pass);
	                	return False;
	        	}
		} else if (local_flags & LOCAL_INTERDOM_ACCOUNT) {
	        	if (!pdb_set_acct_ctrl(sam_pass, ACB_DOMTRUST)) {
	                	slprintf(err_str, err_str_len - 1, "Failed to set 'domain trust account' flags for user %s.\n", user_name);
	                	pdb_free_sam(&sam_pass);
	                	return False;
	        	}
		} else {
	        	if (!pdb_set_acct_ctrl(sam_pass, ACB_NORMAL)) {
	                	slprintf(err_str, err_str_len - 1, "Failed to set 'normal account' flags for user %s.\n", user_name);
	               	 	pdb_free_sam(&sam_pass);
	               	 	return False;
	        	}
		}

	} else {
		/* the entry already existed */
		local_flags &= ~LOCAL_ADD_USER;
	}

	/*
	 * We are root - just write the new password
	 * and the valid last change time.
	 */

	if (local_flags & LOCAL_DISABLE_USER) {
		if (!pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)|ACB_DISABLED)) {
			slprintf(err_str, err_str_len-1, "Failed to set 'disabled' flag for user %s.\n", user_name);
			pdb_free_sam(&sam_pass);
			return False;
		}
	} else if (local_flags & LOCAL_ENABLE_USER) {
		if (!pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)&(~ACB_DISABLED))) {
			slprintf(err_str, err_str_len-1, "Failed to unset 'disabled' flag for user %s.\n", user_name);
			pdb_free_sam(&sam_pass);
			return False;
		}
	}
	
	if (local_flags & LOCAL_SET_NO_PASSWORD) {
		if (!pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)|ACB_PWNOTREQ)) {
			slprintf(err_str, err_str_len-1, "Failed to set 'no password required' flag for user %s.\n", user_name);
			pdb_free_sam(&sam_pass);
			return False;
		}
	} else if (local_flags & LOCAL_SET_PASSWORD) {
		/*
		 * If we're dealing with setting a completely empty user account
		 * ie. One with a password of 'XXXX', but not set disabled (like
		 * an account created from scratch) then if the old password was
		 * 'XX's then getsmbpwent will have set the ACB_DISABLED flag.
		 * We remove that as we're giving this user their first password
		 * and the decision hasn't really been made to disable them (ie.
		 * don't create them disabled). JRA.
		 */
		if ((pdb_get_lanman_passwd(sam_pass)==NULL) && (pdb_get_acct_ctrl(sam_pass)&ACB_DISABLED)) {
			if (!pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)&(~ACB_DISABLED))) {
				slprintf(err_str, err_str_len-1, "Failed to unset 'disabled' flag for user %s.\n", user_name);
				pdb_free_sam(&sam_pass);
				return False;
			}
		}
		if (!pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)&(~ACB_PWNOTREQ))) {
			slprintf(err_str, err_str_len-1, "Failed to unset 'no password required' flag for user %s.\n", user_name);
			pdb_free_sam(&sam_pass);
			return False;
		}
		
		if (!pdb_set_plaintext_passwd (sam_pass, new_passwd)) {
			slprintf(err_str, err_str_len-1, "Failed to set password for user %s.\n", user_name);
			pdb_free_sam(&sam_pass);
			return False;
		}
	}	

	if (local_flags & LOCAL_ADD_USER) {
		if (pdb_add_sam_account(sam_pass)) {
			slprintf(msg_str, msg_str_len-1, "Added user %s.\n", user_name);
			pdb_free_sam(&sam_pass);
			return True;
		} else {
			slprintf(err_str, err_str_len-1, "Failed to add entry for user %s.\n", user_name);
			pdb_free_sam(&sam_pass);
			return False;
		}
	} else if (local_flags & LOCAL_DELETE_USER) {
		if (!pdb_delete_sam_account(user_name)) {
			slprintf(err_str,err_str_len-1, "Failed to delete entry for user %s.\n", user_name);
			pdb_free_sam(&sam_pass);
			return False;
		}
		slprintf(msg_str, msg_str_len-1, "Deleted user %s.\n", user_name);
	} else {
		if(!pdb_update_sam_account(sam_pass, True)) {
			slprintf(err_str, err_str_len-1, "Failed to modify entry for user %s.\n", user_name);
			pdb_free_sam(&sam_pass);
			return False;
		}
		if(local_flags & LOCAL_DISABLE_USER)
			slprintf(msg_str, msg_str_len-1, "Disabled user %s.\n", user_name);
		else if (local_flags & LOCAL_ENABLE_USER)
			slprintf(msg_str, msg_str_len-1, "Enabled user %s.\n", user_name);
		else if (local_flags & LOCAL_SET_NO_PASSWORD)
			slprintf(msg_str, msg_str_len-1, "User %s password set to none.\n", user_name);
	}

	pdb_free_sam(&sam_pass);
	return True;
}

/*********************************************************************
 Collection of get...() functions for SAM_ACCOUNT_INFO.
 ********************************************************************/

uint16 pdb_get_acct_ctrl (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.acct_ctrl);
	else
		return (ACB_DISABLED);
}

time_t pdb_get_logon_time (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.logon_time);
	else
		return (0);
}

time_t pdb_get_logoff_time (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.logoff_time);
	else
		return (-1);
}

time_t pdb_get_kickoff_time (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.kickoff_time);
	else
		return (-1);
}

time_t pdb_get_pass_last_set_time (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.pass_last_set_time);
	else
		return (-1);
}

time_t pdb_get_pass_can_change_time (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.pass_can_change_time);
	else
		return (-1);
}

time_t pdb_get_pass_must_change_time (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.pass_must_change_time);
	else
		return (-1);
}

uint16 pdb_get_logon_divs (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.logon_divs);
	else
		return (-1);
}

uint32 pdb_get_hours_len (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.hours_len);
	else
		return (-1);
}

const uint8* pdb_get_hours (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.hours);
	else
		return (NULL);
}

const uint8* pdb_get_nt_passwd (const SAM_ACCOUNT *sampass)
{
	if (sampass) {
		SMB_ASSERT((!sampass->private.nt_pw.data) 
			   || sampass->private.nt_pw.length == NT_HASH_LEN);
		return ((uint8*)sampass->private.nt_pw.data);
	}
	else
		return (NULL);
}

const uint8* pdb_get_lanman_passwd (const SAM_ACCOUNT *sampass)
{
	if (sampass) {
		SMB_ASSERT((!sampass->private.lm_pw.data) 
			   || sampass->private.lm_pw.length == LM_HASH_LEN);
		return ((uint8*)sampass->private.lm_pw.data);
	}
	else
		return (NULL);
}

uint32 pdb_get_user_rid (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.user_rid);
	else
		return (-1);
}

uint32 pdb_get_group_rid (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.group_rid);
	else
		return (-1);
}

/**
 * Get flags showing what is initalised in the SAM_ACCOUNT
 * @param sampass the SAM_ACCOUNT in question
 * @return the flags indicating the members initialised in the struct.
 **/
 
uint32 pdb_get_init_flag (SAM_ACCOUNT *sampass)
{
        if (sampass)
		return sampass->private.init_flag;
	else 
                return FLAG_SAM_UNINIT;
}

uid_t pdb_get_uid (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.uid);
	else
		return (-1);
}

gid_t pdb_get_gid (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.gid);
	else
		return (-1);
}

const char* pdb_get_username (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.username);
	else
		return (NULL);
}

const char* pdb_get_domain (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.domain);
	else
		return (NULL);
}

const char* pdb_get_nt_username (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.nt_username);
	else
		return (NULL);
}

const char* pdb_get_fullname (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.full_name);
	else
		return (NULL);
}

const char* pdb_get_homedir (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.home_dir);
	else
		return (NULL);
}

const char* pdb_get_dirdrive (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.dir_drive);
	else
		return (NULL);
}

const char* pdb_get_logon_script (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.logon_script);
	else
		return (NULL);
}

const char* pdb_get_profile_path (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.profile_path);
	else
		return (NULL);
}

const char* pdb_get_acct_desc (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.acct_desc);
	else
		return (NULL);
}

const char* pdb_get_workstations (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.workstations);
	else
		return (NULL);
}

const char* pdb_get_unknown_str (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.unknown_str);
	else
		return (NULL);
}

const char* pdb_get_munged_dial (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.munged_dial);
	else
		return (NULL);
}

uint32 pdb_get_unknown3 (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.unknown_3);
	else
		return (-1);
}

uint32 pdb_get_unknown5 (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.unknown_5);
	else
		return (-1);
}

uint32 pdb_get_unknown6 (const SAM_ACCOUNT *sampass)
{
	if (sampass)
		return (sampass->private.unknown_6);
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
		sampass->private.acct_ctrl = flags;
		return True;
	}
	
	return False;
}

BOOL pdb_set_logon_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->private.logon_time = mytime;
	return True;
}

BOOL pdb_set_logoff_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->private.logoff_time = mytime;
	return True;
}

BOOL pdb_set_kickoff_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->private.kickoff_time = mytime;
	return True;
}

BOOL pdb_set_pass_can_change_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->private.pass_can_change_time = mytime;
	return True;
}

BOOL pdb_set_pass_must_change_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->private.pass_must_change_time = mytime;
	return True;
}

BOOL pdb_set_pass_last_set_time (SAM_ACCOUNT *sampass, time_t mytime)
{
	if (!sampass)
		return False;

	sampass->private.pass_last_set_time = mytime;
	return True;
}

BOOL pdb_set_hours_len (SAM_ACCOUNT *sampass, uint32 len)
{
	if (!sampass)
		return False;

	sampass->private.hours_len = len;
	return True;
}

BOOL pdb_set_logon_divs (SAM_ACCOUNT *sampass, uint16 hours)
{
	if (!sampass)
		return False;

	sampass->private.logon_divs = hours;
	return True;
}

/**
 * Set flags showing what is initalised in the SAM_ACCOUNT
 * @param sampass the SAM_ACCOUNT in question
 * @param flag The *new* flag to be set.  Old flags preserved
 *             this flag is only added.  
 **/
 
BOOL pdb_set_init_flag (SAM_ACCOUNT *sampass, uint32 flag)
{
        if (!sampass)
                return False;

        sampass->private.init_flag |= flag;

        return True;
}

BOOL pdb_set_uid (SAM_ACCOUNT *sampass, const uid_t uid)
{
	if (!sampass)
		return False;
	
	DEBUG(10, ("pdb_set_uid: setting uid %d, was %d\n", 
		   (int)uid, (int)sampass->private.uid));
 
	sampass->private.uid = uid;
	pdb_set_init_flag(sampass, FLAG_SAM_UID); 

	return True;

}

BOOL pdb_set_gid (SAM_ACCOUNT *sampass, const gid_t gid)
{
	if (!sampass)
		return False;
		
	DEBUG(10, ("pdb_set_gid: setting gid %d, was %d\n", 
		   (int)gid, (int)sampass->private.gid));
 
	sampass->private.gid = gid; 
	pdb_set_init_flag(sampass, FLAG_SAM_GID); 

	return True;

}

BOOL pdb_set_user_rid (SAM_ACCOUNT *sampass, uint32 rid)
{
	if (!sampass)
		return False;

	DEBUG(10, ("pdb_set_rid: setting user rid %d, was %d\n", 
		   rid, sampass->private.user_rid));
 
	sampass->private.user_rid = rid;
	return True;
}

BOOL pdb_set_group_rid (SAM_ACCOUNT *sampass, uint32 grid)
{
	if (!sampass)
		return False;

	DEBUG(10, ("pdb_set_group_rid: setting group rid %d, was %d\n", 
		   grid, sampass->private.group_rid));
 
	sampass->private.group_rid = grid;
	return True;
}

/*********************************************************************
 Set the user's UNIX name.
 ********************************************************************/

BOOL pdb_set_username(SAM_ACCOUNT *sampass, const char *username)
{	
	if (!sampass)
		return False;
	
	*sampass->private.username = '\0';
	DEBUG(10, ("pdb_set_username: setting username %s, was %s\n", 
		   username, sampass->private.username));
 
	if (!username)
		return False;
	StrnCpy (sampass->private.username, username, strlen(username));

	return True;
}

/*********************************************************************
 Set the domain name.
 ********************************************************************/

BOOL pdb_set_domain(SAM_ACCOUNT *sampass, const char *domain)
{	
	if (!sampass)
		return False;
	*sampass->private.domain = '\0';
	if (!domain)
		return False;

	StrnCpy (sampass->private.domain, domain, strlen(domain));

	return True;
}

/*********************************************************************
 Set the user's NT name.
 ********************************************************************/

BOOL pdb_set_nt_username(SAM_ACCOUNT *sampass, const char *nt_username)
{
	if (!sampass)
		return False;
	*sampass->private.nt_username = '\0';
	if (!nt_username)
		return False;

	StrnCpy (sampass->private.nt_username, nt_username, strlen(nt_username));

	return True;
}

/*********************************************************************
 Set the user's full name.
 ********************************************************************/

BOOL pdb_set_fullname(SAM_ACCOUNT *sampass, const char *fullname)
{
	if (!sampass)
		return False;

	DEBUG(10, ("pdb_set_fullname: setting full name %s, was %s\n", 
		   fullname, sampass->private.full_name));
 
	*sampass->private.full_name = '\0';
	if (!fullname)
		return False;

	StrnCpy (sampass->private.full_name, fullname, strlen(fullname));

	return True;
}

/*********************************************************************
 Set the user's logon script.
 ********************************************************************/

BOOL pdb_set_logon_script(SAM_ACCOUNT *sampass, const char *logon_script, BOOL store)
{
	if (!sampass)
		return False;

	DEBUG(10, ("pdb_set_logon_script: setting logon script (store:%d) %s, was %s\n", 
		   store, logon_script, sampass->private.logon_script));
 
	*sampass->private.logon_script = '\0';
	if (!logon_script)
		return False;

	StrnCpy (sampass->private.logon_script, logon_script, strlen(logon_script));

	if (store)
		pdb_set_init_flag(sampass, FLAG_SAM_LOGONSCRIPT); 

	return True;
}

/*********************************************************************
 Set the user's profile path.
 ********************************************************************/

BOOL pdb_set_profile_path (SAM_ACCOUNT *sampass, const char *profile_path, BOOL store)
{
	if (!sampass)
		return False;

	DEBUG(10, ("pdb_set_profile_path: setting profile path (store:%d) %s, was %s\n", 
		   store, profile_path, sampass->private.profile_path));
 
	*sampass->private.profile_path = '\0';
	if (!profile_path)
		return False;
	
	StrnCpy (sampass->private.profile_path, profile_path, strlen(profile_path));

	if (store)
		pdb_set_init_flag(sampass, FLAG_SAM_PROFILE);
	
	return True;
}

/*********************************************************************
 Set the user's directory drive.
 ********************************************************************/

BOOL pdb_set_dir_drive (SAM_ACCOUNT *sampass, const char *dir_drive, BOOL store)
{
	if (!sampass)
		return False;
	*sampass->private.dir_drive = '\0';
	if (!dir_drive)
		return False;

	StrnCpy (sampass->private.dir_drive, dir_drive, strlen(dir_drive));

	if (store)
		pdb_set_init_flag(sampass, FLAG_SAM_DRIVE);

	return True;
}

/*********************************************************************
 Set the user's home directory.
 ********************************************************************/

BOOL pdb_set_homedir (SAM_ACCOUNT *sampass, const char *homedir, BOOL store)
{
	if (!sampass)
		return False;
	*sampass->private.home_dir = '\0';
	if (!homedir)
		return False;
	
	StrnCpy (sampass->private.home_dir, homedir, strlen(homedir));

	if (store)
		pdb_set_init_flag(sampass, FLAG_SAM_SMBHOME);

	return True;
}

/*********************************************************************
 Set the user's account description.
 ********************************************************************/

BOOL pdb_set_acct_desc (SAM_ACCOUNT *sampass, const char *acct_desc)
{
	if (!sampass)
		return False;
	*sampass->private.acct_desc = '\0';
	if (!acct_desc)
		return False;
	
	StrnCpy (sampass->private.acct_desc, acct_desc, strlen(acct_desc));

	return True;
}

/*********************************************************************
 Set the user's workstation allowed list.
 ********************************************************************/

BOOL pdb_set_workstations (SAM_ACCOUNT *sampass, const char *workstations)
{
	if (!sampass)
		return False;
	*sampass->private.workstations = '\0';
	if (!workstations)
		return False;

	StrnCpy (sampass->private.workstations, workstations, strlen(workstations));

	return True;
}

/*********************************************************************
 Set the user's 'unknown_str', whatever the heck this actually is...
 ********************************************************************/

BOOL pdb_set_unknown_str (SAM_ACCOUNT *sampass, const char *unknown_str)
{
	if (!sampass)
		return False;
	*sampass->private.unknown_str = '\0';
	if (!unknown_str)
		return False;

	StrnCpy (sampass->private.unknown_str, unknown_str, strlen(unknown_str));

	return True;
}

/*********************************************************************
 Set the user's dial string.
 ********************************************************************/

BOOL pdb_set_munged_dial (SAM_ACCOUNT *sampass, const char *munged_dial)
{
	if (!sampass)
		return False;
	*sampass->private.munged_dial = '\0';
	if (!munged_dial)
		return False;

	StrnCpy (sampass->private.munged_dial, munged_dial, strlen(munged_dial));

	return True;
}

/*********************************************************************
 Set the user's NT hash.
 ********************************************************************/

BOOL pdb_set_nt_passwd (SAM_ACCOUNT *sampass, const uint8 *pwd)
{
	if (!sampass)
		return False;

	data_blob_clear_free(&(sampass->private.nt_pw));
	
	sampass->private.nt_pw = data_blob(pwd, NT_HASH_LEN);

	return True;
}

/*********************************************************************
 Set the user's LM hash.
 ********************************************************************/

BOOL pdb_set_lanman_passwd (SAM_ACCOUNT *sampass, const uint8 *pwd)
{
	if (!sampass)
		return False;

	data_blob_clear_free(&(sampass->private.lm_pw));
	
	sampass->private.lm_pw = data_blob(pwd, LM_HASH_LEN);

	return True;
}

BOOL pdb_set_unknown_3 (SAM_ACCOUNT *sampass, uint32 unkn)
{
	if (!sampass)
		return False;

	sampass->private.unknown_3 = unkn;
	return True;
}

BOOL pdb_set_unknown_5 (SAM_ACCOUNT *sampass, uint32 unkn)
{
	if (!sampass)
		return False;

	sampass->private.unknown_5 = unkn;
	return True;
}

BOOL pdb_set_unknown_6 (SAM_ACCOUNT *sampass, uint32 unkn)
{
	if (!sampass)
		return False;

	sampass->private.unknown_6 = unkn;
	return True;
}

BOOL pdb_set_hours (SAM_ACCOUNT *sampass, const uint8 *hours)
{
	if (!sampass)
		return False;

	if (!hours) {
		memset ((char *)sampass->private.hours, 0, MAX_HOURS_LEN);
		return True;
	}
	
	memcpy (sampass->private.hours, hours, MAX_HOURS_LEN);

	return True;
}


/* Helpful interfaces to the above */

/*********************************************************************
 Sets the last changed times and must change times for a normal
 password change.
 ********************************************************************/

BOOL pdb_set_pass_changed_now (SAM_ACCOUNT *sampass)
{
	uint32 expire;

	if (!sampass)
		return False;
	
	if (!pdb_set_pass_last_set_time (sampass, time(NULL)))
		return False;

	account_policy_get(AP_MAX_PASSWORD_AGE, &expire);

	if (expire==(uint32)-1) {
		if (!pdb_set_pass_must_change_time (sampass, 0))
			return False;
	} else {
		if (!pdb_set_pass_must_change_time (sampass, 
					    pdb_get_pass_last_set_time(sampass)
					    + expire))
			return False;
	}
	
	return True;
}

/*********************************************************************
 Set the user's PLAINTEXT password.  Used as an interface to the above.
 Also sets the last change time to NOW.
 ********************************************************************/

BOOL pdb_set_plaintext_passwd (SAM_ACCOUNT *sampass, const char *plaintext)
{
	uchar new_lanman_p16[16];
	uchar new_nt_p16[16];

	if (!sampass || !plaintext)
		return False;
	
	nt_lm_owf_gen (plaintext, new_nt_p16, new_lanman_p16);

	if (!pdb_set_nt_passwd (sampass, new_nt_p16)) 
		return False;

	if (!pdb_set_lanman_passwd (sampass, new_lanman_p16)) 
		return False;
	
	if (!pdb_set_pass_changed_now (sampass))
		return False;

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
		DEBUG(0,("pdb_getsampwuid: getpwuid(%d) return NULL. User does not exist in Unix accounts!\n", uid));
		return False;
	}
	
	fstrcpy (name, pw->pw_name);

	return pdb_getsampwnam (user, name);

}

