/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Jeremy Allison 		1996-2001
   Copyright (C) Luke Kenneth Casson Leighton 	1996-1998
   Copyright (C) Gerald (Jerry) Carter		2000-2001
   Copyright (C) Andrew Bartlett		2001-2002
   Copyright (C) Simo Sorce			2003
      
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_PASSDB

/******************************************************************
 get the default domain/netbios name to be used when 
 testing authentication.  For example, if you connect
 to a Windows member server using a bogus domain name, the
 Windows box will map the BOGUS\user to DOMAIN\user.  A 
 standalone box will map to WKS\user.
******************************************************************/

const char *get_default_sam_name(void)
{
	/* standalone servers can only use the local netbios name */
	if ( lp_server_role() == ROLE_STANDALONE )
		return global_myname();

	/* Windows domain members default to the DOMAIN
	   name when not specified */
	return lp_workgroup();
}

/************************************************************
 Fill the SAM_ACCOUNT with default values.
 ***********************************************************/

void pdb_fill_default_sam(SAM_ACCOUNT *user)
{
	ZERO_STRUCT(user->private); /* Don't touch the talloc context */

	/* no initial methods */
	user->methods = NULL;

        /* Don't change these timestamp settings without a good reason.
           They are important for NT member server compatibility. */

	user->private.logon_time            = (time_t)0;
	user->private.pass_last_set_time    = (time_t)0;
	user->private.pass_can_change_time  = (time_t)0;
	user->private.logoff_time           = 
	user->private.kickoff_time          = 
	user->private.pass_must_change_time = get_time_t_max();
	user->private.fields_present        = 0x00ffffff;
	user->private.logon_divs = 168; 	/* hours per week */
	user->private.hours_len = 21; 		/* 21 times 8 bits = 168 */
	memset(user->private.hours, 0xff, user->private.hours_len); /* available at all hours */
	user->private.bad_password_count = 0;
	user->private.logon_count = 0;
	user->private.unknown_6 = 0x000004ec; /* don't know */

	/* Some parts of samba strlen their pdb_get...() returns, 
	   so this keeps the interface unchanged for now. */
	   
	user->private.username = "";
	user->private.domain = "";
	user->private.nt_username = "";
	user->private.full_name = "";
	user->private.home_dir = "";
	user->private.logon_script = "";
	user->private.profile_path = "";
	user->private.acct_desc = "";
	user->private.workstations = "";
	user->private.unknown_str = "";
	user->private.munged_dial = "";

	user->private.plaintext_pw = NULL;

	/* 
	   Unless we know otherwise have a Account Control Bit
	   value of 'normal user'.  This helps User Manager, which
	   asks for a filtered list of users.
	*/

	user->private.acct_ctrl = ACB_NORMAL;
}	

static void destroy_pdb_talloc(SAM_ACCOUNT **user) 
{
	if (*user) {
		data_blob_clear_free(&((*user)->private.lm_pw));
		data_blob_clear_free(&((*user)->private.nt_pw));

		if((*user)->private.plaintext_pw!=NULL)
			memset((*user)->private.plaintext_pw,'\0',strlen((*user)->private.plaintext_pw));
		talloc_destroy((*user)->mem_ctx);
		*user = NULL;
	}
}


/**********************************************************************
 Allocates memory and initialises a struct sam_passwd on supplied mem_ctx.
***********************************************************************/

NTSTATUS pdb_init_sam_talloc(TALLOC_CTX *mem_ctx, SAM_ACCOUNT **user)
{
	if (*user != NULL) {
		DEBUG(0,("pdb_init_sam_talloc: SAM_ACCOUNT was non NULL\n"));
#if 0
		smb_panic("non-NULL pointer passed to pdb_init_sam\n");
#endif
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!mem_ctx) {
		DEBUG(0,("pdb_init_sam_talloc: mem_ctx was NULL!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	*user=(SAM_ACCOUNT *)talloc(mem_ctx, sizeof(SAM_ACCOUNT));

	if (*user==NULL) {
		DEBUG(0,("pdb_init_sam_talloc: error while allocating memory\n"));
		return NT_STATUS_NO_MEMORY;
	}

	(*user)->mem_ctx = mem_ctx;

	(*user)->free_fn = NULL;

	pdb_fill_default_sam(*user);
	
	return NT_STATUS_OK;
}


/*************************************************************
 Allocates memory and initialises a struct sam_passwd.
 ************************************************************/

NTSTATUS pdb_init_sam(SAM_ACCOUNT **user)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS nt_status;
	
	mem_ctx = talloc_init("passdb internal SAM_ACCOUNT allocation");

	if (!mem_ctx) {
		DEBUG(0,("pdb_init_sam: error while doing talloc_init()\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (!NT_STATUS_IS_OK(nt_status = pdb_init_sam_talloc(mem_ctx, user))) {
		talloc_destroy(mem_ctx);
		return nt_status;
	}
	
	(*user)->free_fn = destroy_pdb_talloc;

	return NT_STATUS_OK;
}

/**************************************************************************
 * This function will take care of all the steps needed to correctly
 * allocate and set the user SID, please do use this function to create new
 * users, messing with SIDs is not good.
 *
 * account_data must be provided initialized, pwd may be null.
 * 									SSS
 ***************************************************************************/

static NTSTATUS pdb_set_sam_sids(SAM_ACCOUNT *account_data, const struct passwd *pwd)
{
	const char *guest_account = lp_guestaccount();
	GROUP_MAP map;
	BOOL ret;
	
	if (!account_data || !pwd) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* this is a hack this thing should not be set
	   this way --SSS */
	if (!(guest_account && *guest_account)) {
		DEBUG(1, ("NULL guest account!?!?\n"));
		return NT_STATUS_UNSUCCESSFUL;
	} else {
		/* Ensure this *must* be set right */
		if (strcmp(pwd->pw_name, guest_account) == 0) {
			if (!pdb_set_user_sid_from_rid(account_data, DOMAIN_USER_RID_GUEST, PDB_DEFAULT)) {
				return NT_STATUS_UNSUCCESSFUL;
			}
			if (!pdb_set_group_sid_from_rid(account_data, DOMAIN_GROUP_RID_GUESTS, PDB_DEFAULT)) {
				return NT_STATUS_UNSUCCESSFUL;
			}
			return NT_STATUS_OK;
		}
	}

	if (!pdb_set_user_sid_from_rid(account_data, fallback_pdb_uid_to_user_rid(pwd->pw_uid), PDB_SET)) {
		DEBUG(0,("Can't set User SID from RID!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	/* call the mapping code here */
	become_root();
	ret = pdb_getgrgid(&map, pwd->pw_gid);
	unbecome_root();
	
	if( ret ) {
		if (!pdb_set_group_sid(account_data, &map.sid, PDB_SET)){
			DEBUG(0,("Can't set Group SID!\n"));
			return NT_STATUS_INVALID_PARAMETER;
		}
	} 
	else {
		if (!pdb_set_group_sid_from_rid(account_data, pdb_gid_to_group_rid(pwd->pw_gid), PDB_SET)) {
			DEBUG(0,("Can't set Group SID\n"));
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	return NT_STATUS_OK;
}

/*************************************************************
 Initialises a struct sam_passwd with sane values.
 ************************************************************/

NTSTATUS pdb_fill_sam_pw(SAM_ACCOUNT *sam_account, const struct passwd *pwd)
{
	NTSTATUS ret;

	if (!pwd) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	pdb_fill_default_sam(sam_account);

	pdb_set_username(sam_account, pwd->pw_name, PDB_SET);
	pdb_set_fullname(sam_account, pwd->pw_gecos, PDB_SET);

	pdb_set_unix_homedir(sam_account, pwd->pw_dir, PDB_SET);

	pdb_set_domain (sam_account, get_global_sam_name(), PDB_DEFAULT);
	
	/* When we get a proper uid -> SID and SID -> uid allocation
	   mechinism, we should call it here.  
	   
	   We can't just set this to 0 or allow it only to be filled
	   in when added to the backend, because the user's SID 
	   may already be in security descriptors etc.
	   
	   -- abartlet 11-May-02
	*/

	ret = pdb_set_sam_sids(sam_account, pwd);
	if (!NT_STATUS_IS_OK(ret)) return ret;

	/* check if this is a user account or a machine account */
	if (pwd->pw_name[strlen(pwd->pw_name)-1] != '$')
	{
		pdb_set_profile_path(sam_account, 
				     talloc_sub_specified((sam_account)->mem_ctx, 
							    lp_logon_path(), 
							    pwd->pw_name, global_myname(), 
							    pwd->pw_uid, pwd->pw_gid), 
				     PDB_DEFAULT);
		
		pdb_set_homedir(sam_account, 
				talloc_sub_specified((sam_account)->mem_ctx, 
						       lp_logon_home(),
						       pwd->pw_name, global_myname(), 
						       pwd->pw_uid, pwd->pw_gid),
				PDB_DEFAULT);
		
		pdb_set_dir_drive(sam_account, 
				  talloc_sub_specified((sam_account)->mem_ctx, 
							 lp_logon_drive(),
							 pwd->pw_name, global_myname(), 
							 pwd->pw_uid, pwd->pw_gid),
				  PDB_DEFAULT);
		
		pdb_set_logon_script(sam_account, 
				     talloc_sub_specified((sam_account)->mem_ctx, 
							    lp_logon_script(),
							    pwd->pw_name, global_myname(), 
							    pwd->pw_uid, pwd->pw_gid), 
				     PDB_DEFAULT);
		if (!pdb_set_acct_ctrl(sam_account, ACB_NORMAL, PDB_DEFAULT)) {
			DEBUG(1, ("Failed to set 'normal account' flags for user %s.\n", pwd->pw_name));
			return NT_STATUS_UNSUCCESSFUL;
		}
	} else {
		if (!pdb_set_acct_ctrl(sam_account, ACB_WSTRUST, PDB_DEFAULT)) {
			DEBUG(1, ("Failed to set 'trusted workstation account' flags for user %s.\n", pwd->pw_name));
			return NT_STATUS_UNSUCCESSFUL;
		}
	}
	return NT_STATUS_OK;
}


/*************************************************************
 Initialises a struct sam_passwd with sane values.
 ************************************************************/

NTSTATUS pdb_init_sam_pw(SAM_ACCOUNT **new_sam_acct, const struct passwd *pwd)
{
	NTSTATUS nt_status;

	if (!pwd) {
		new_sam_acct = NULL;
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!NT_STATUS_IS_OK(nt_status = pdb_init_sam(new_sam_acct))) {
		new_sam_acct = NULL;
		return nt_status;
	}

	if (!NT_STATUS_IS_OK(nt_status = pdb_fill_sam_pw(*new_sam_acct, pwd))) {
		pdb_free_sam(new_sam_acct);
		new_sam_acct = NULL;
		return nt_status;
	}

	return NT_STATUS_OK;
}


/*************************************************************
 Initialises a SAM_ACCOUNT ready to add a new account, based
 on the UNIX user.  Pass in a RID if you have one
 ************************************************************/

NTSTATUS pdb_init_sam_new(SAM_ACCOUNT **new_sam_acct, const char *username,
                          uint32 rid)
{
	NTSTATUS 	nt_status = NT_STATUS_NO_MEMORY;
	struct passwd 	*pwd;
	BOOL		ret;
	
	pwd = Get_Pwnam(username);

	if (!pwd) 
		return NT_STATUS_NO_SUCH_USER;
	
	if (!NT_STATUS_IS_OK(nt_status = pdb_init_sam_pw(new_sam_acct, pwd))) {
		*new_sam_acct = NULL;
		return nt_status;
	}
	
	/* see if we need to generate a new rid using the 2.2 algorithm */
	if ( rid == 0 && lp_enable_rid_algorithm() ) {
		DEBUG(10,("pdb_init_sam_new: no RID specified.  Generating one via old algorithm\n"));
		rid = fallback_pdb_uid_to_user_rid(pwd->pw_uid);
	}
	
	/* set the new SID */
	
	ret = pdb_set_user_sid_from_rid( *new_sam_acct, rid, PDB_SET );
	 
	return (ret ? NT_STATUS_OK : NT_STATUS_NO_SUCH_USER);
}


/**
 * Free the contets of the SAM_ACCOUNT, but not the structure.
 *
 * Also wipes the LM and NT hashes and plaintext password from 
 * memory.
 *
 * @param user SAM_ACCOUNT to free members of.
 **/

static void pdb_free_sam_contents(SAM_ACCOUNT *user)
{

	/* Kill off sensitive data.  Free()ed by the
	   talloc mechinism */

	data_blob_clear_free(&(user->private.lm_pw));
	data_blob_clear_free(&(user->private.nt_pw));
	if (user->private.plaintext_pw!=NULL)
		memset(user->private.plaintext_pw,'\0',strlen(user->private.plaintext_pw));

	if (user->private.backend_private_data && user->private.backend_private_data_free_fn) {
		user->private.backend_private_data_free_fn(&user->private.backend_private_data);
	}
}


/************************************************************
 Reset the SAM_ACCOUNT and free the NT/LM hashes.
 ***********************************************************/

NTSTATUS pdb_reset_sam(SAM_ACCOUNT *user)
{
	if (user == NULL) {
		DEBUG(0,("pdb_reset_sam: SAM_ACCOUNT was NULL\n"));
#if 0
		smb_panic("NULL pointer passed to pdb_free_sam\n");
#endif
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	pdb_free_sam_contents(user);

	pdb_fill_default_sam(user);

	return NT_STATUS_OK;
}


/************************************************************
 Free the SAM_ACCOUNT and the member pointers.
 ***********************************************************/

NTSTATUS pdb_free_sam(SAM_ACCOUNT **user)
{
	if (*user == NULL) {
		DEBUG(0,("pdb_free_sam: SAM_ACCOUNT was NULL\n"));
#if 0
		smb_panic("NULL pointer passed to pdb_free_sam\n");
#endif
		return NT_STATUS_UNSUCCESSFUL;
	}

	pdb_free_sam_contents(*user);
	
	if ((*user)->free_fn) {
		(*user)->free_fn(user);
	}

	return NT_STATUS_OK;	
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

	SMB_ASSERT(length <= sizeof(acct_str));

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
	const char      *hexchars = "0123456789ABCDEF";
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

int algorithmic_rid_base(void)
{
	static int rid_offset = 0;

	if (rid_offset != 0)
		return rid_offset;

	rid_offset = lp_algorithmic_rid_base();

	if (rid_offset < BASE_RID) {  
		/* Try to prevent admin foot-shooting, we can't put algorithmic
		   rids below 1000, that's the 'well known RIDs' on NT */
		DEBUG(0, ("'algorithmic rid base' must be equal to or above %ld\n", BASE_RID));
		rid_offset = BASE_RID;
	}
	if (rid_offset & 1) {
		DEBUG(0, ("algorithmic rid base must be even\n"));
		rid_offset += 1;
	}
	return rid_offset;
}

/*******************************************************************
 Converts NT user RID to a UNIX uid.
 ********************************************************************/

uid_t fallback_pdb_user_rid_to_uid(uint32 user_rid)
{
	int rid_offset = algorithmic_rid_base();
	return (uid_t)(((user_rid & (~USER_RID_TYPE)) - rid_offset)/RID_MULTIPLIER);
}

/*******************************************************************
 converts UNIX uid to an NT User RID.
 ********************************************************************/

uint32 fallback_pdb_uid_to_user_rid(uid_t uid)
{
	int rid_offset = algorithmic_rid_base();
	return (((((uint32)uid)*RID_MULTIPLIER) + rid_offset) | USER_RID_TYPE);
}

/*******************************************************************
 Converts NT group RID to a UNIX gid.
 ********************************************************************/

gid_t pdb_group_rid_to_gid(uint32 group_rid)
{
	int rid_offset = algorithmic_rid_base();
	return (gid_t)(((group_rid & (~GROUP_RID_TYPE))- rid_offset)/RID_MULTIPLIER);
}

/*******************************************************************
 converts NT Group RID to a UNIX uid.
 
 warning: you must not call that function only
 you must do a call to the group mapping first.
 there is not anymore a direct link between the gid and the rid.
 ********************************************************************/

uint32 pdb_gid_to_group_rid(gid_t gid)
{
	int rid_offset = algorithmic_rid_base();
	return (((((uint32)gid)*RID_MULTIPLIER) + rid_offset) | GROUP_RID_TYPE);
}

/*******************************************************************
 Decides if a RID is a well known RID.
 ********************************************************************/

static BOOL pdb_rid_is_well_known(uint32 rid)
{
	/* Not using rid_offset here, because this is the actual
	   NT fixed value (1000) */

	return (rid < BASE_RID);
}

/*******************************************************************
 Decides if a RID is a user or group RID.
 ********************************************************************/

BOOL fallback_pdb_rid_is_user(uint32 rid)
{
  /* lkcl i understand that NT attaches an enumeration to a RID
   * such that it can be identified as either a user, group etc
   * type.  there are 5 such categories, and they are documented.
   */
	/* However, they are not in the RID, just somthing you can query
	   seperatly.  Sorry luke :-) */

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

BOOL local_lookup_sid(const DOM_SID *sid, char *name, enum SID_NAME_USE *psid_name_use)
{
	uint32 rid;
	SAM_ACCOUNT *sam_account = NULL;
	GROUP_MAP map;
	BOOL ret;

	if (!sid_peek_check_rid(get_global_sam_sid(), sid, &rid)){
		DEBUG(0,("local_lookup_sid: sid_peek_check_rid return False! SID: %s\n",
			sid_string_static(&map.sid)));
		return False;
	}	
	*psid_name_use = SID_NAME_UNKNOWN;
	
	DEBUG(5,("local_lookup_sid: looking up RID %u.\n", (unsigned int)rid));
	
	if (rid == DOMAIN_USER_RID_ADMIN) {
		const char **admin_list = lp_admin_users(-1);
		*psid_name_use = SID_NAME_USER;
		if (admin_list) {
			const char *p = *admin_list;
			if(!next_token(&p, name, NULL, sizeof(fstring)))
				fstrcpy(name, "Administrator");
		} else {
			fstrcpy(name, "Administrator");
		}
		return True;
	}

	if (!NT_STATUS_IS_OK(pdb_init_sam(&sam_account))) {
		return False;
	}
	
	/* see if the passdb can help us with the name of the user */

	/* BEING ROOT BLLOCK */
	become_root();
	if (pdb_getsampwsid(sam_account, sid)) {
		unbecome_root();			/* -----> EXIT BECOME_ROOT() */
		fstrcpy(name, pdb_get_username(sam_account));
		*psid_name_use = SID_NAME_USER;

		pdb_free_sam(&sam_account);
			
		return True;
	}
	pdb_free_sam(&sam_account);
	
	ret = pdb_getgrsid(&map, *sid);
	unbecome_root();
	/* END BECOME_ROOT BLOCK */
	
	if ( ret ) {
		if (map.gid!=(gid_t)-1) {
			DEBUG(5,("local_lookup_sid: mapped group %s to gid %u\n", map.nt_name, (unsigned int)map.gid));
		} else {
			DEBUG(5,("local_lookup_sid: mapped group %s to no unix gid.  Returning name.\n", map.nt_name));
		}

		fstrcpy(name, map.nt_name);
		*psid_name_use = map.sid_name_use;
		return True;
	}

	if (fallback_pdb_rid_is_user(rid)) {
		uid_t uid;
		struct passwd *pw = NULL;

		DEBUG(5, ("assuming RID %u is a user\n", (unsigned)rid));

       		uid = fallback_pdb_user_rid_to_uid(rid);
		pw = sys_getpwuid( uid );
		
		DEBUG(5,("local_lookup_sid: looking up uid %u %s\n", (unsigned int)uid,
			 pw ? "succeeded" : "failed" ));
			 
		if ( !pw )
			fstr_sprintf(name, "unix_user.%u", (unsigned int)uid);	
		else 
			fstrcpy( name, pw->pw_name );
			
		DEBUG(5,("local_lookup_sid: found user %s for rid %u\n", name,
			 (unsigned int)rid ));
			 
		*psid_name_use = SID_NAME_USER;
		
		return ( pw != NULL );
	} else {
		gid_t gid;
		struct group *gr; 
			
		DEBUG(5, ("assuming RID %u is a group\n", (unsigned)rid));

		gid = pdb_group_rid_to_gid(rid);
		gr = getgrgid(gid);
			
		*psid_name_use = SID_NAME_ALIAS;
			
		DEBUG(5,("local_lookup_sid: looking up gid %u %s\n", (unsigned int)gid,
			 gr ? "succeeded" : "failed" ));
			
		if( !gr )
			fstr_sprintf(name, "unix_group.%u", (unsigned int)gid);
		else
			fstrcpy( name, gr->gr_name);
			
		DEBUG(5,("local_lookup_sid: found group %s for rid %u\n", name,
			 (unsigned int)rid ));
		
		/* assume fallback groups aer domain global groups */
		
		*psid_name_use = SID_NAME_DOM_GRP;
		
		return ( gr != NULL );
	}
}

/*******************************************************************
 Convert a name into a SID. Used in the lookup name rpc.
 ********************************************************************/

BOOL local_lookup_name(const char *c_user, DOM_SID *psid, enum SID_NAME_USE *psid_name_use)
{
	extern DOM_SID global_sid_World_Domain;
	DOM_SID local_sid;
	fstring user;
	SAM_ACCOUNT *sam_account = NULL;
	struct group *grp;
	GROUP_MAP map;
		
	*psid_name_use = SID_NAME_UNKNOWN;

	/*
	 * user may be quoted a const string, and map_username and
	 * friends can modify it. Make a modifiable copy. JRA.
	 */

	fstrcpy(user, c_user);

	sid_copy(&local_sid, get_global_sam_sid());

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

	if (!NT_STATUS_IS_OK(pdb_init_sam(&sam_account))) {
		return False;
	}
	
	/* BEGIN ROOT BLOCK */
	
	become_root();
	if (pdb_getsampwnam(sam_account, user)) {
		unbecome_root();
		sid_copy(psid, pdb_get_user_sid(sam_account));
		*psid_name_use = SID_NAME_USER;
		
		pdb_free_sam(&sam_account);
		return True;
	}

	pdb_free_sam(&sam_account);

	/*
	 * Maybe it was a group ?
	 */

	/* check if it's a mapped group */
	if (pdb_getgrnam(&map, user)) {
		/* yes it's a mapped group */
		sid_copy(&local_sid, &map.sid);
		*psid_name_use = map.sid_name_use;
	} else {
		/* it's not a mapped group */
		grp = getgrnam(user);
		if(!grp) {
			unbecome_root();		/* ---> exit form block */	
			return False;
		}
		
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
		
		if (pdb_getgrgid(&map, grp->gr_gid)){
			unbecome_root();		/* ---> exit form block */
			return False;
		}
		
		sid_append_rid( &local_sid, pdb_gid_to_group_rid(grp->gr_gid));
		*psid_name_use = SID_NAME_ALIAS;
	}
	unbecome_root();
	/* END ROOT BLOCK */

	sid_copy( psid, &local_sid);

	return True;
}

/*************************************************************
 Change a password entry in the local smbpasswd file.
 *************************************************************/

BOOL local_password_change(const char *user_name, int local_flags,
			   const char *new_passwd, 
			   char *err_str, size_t err_str_len,
			   char *msg_str, size_t msg_str_len)
{
	SAM_ACCOUNT 	*sam_pass=NULL;
	uint16 other_acb;

	*err_str = '\0';
	*msg_str = '\0';

	/* Get the smb passwd entry for this user */
	pdb_init_sam(&sam_pass);

	become_root();
	if(!pdb_getsampwnam(sam_pass, user_name)) {
		unbecome_root();
		pdb_free_sam(&sam_pass);
		
		if ((local_flags & LOCAL_ADD_USER) || (local_flags & LOCAL_DELETE_USER)) {
			/* Might not exist in /etc/passwd.  Use rid algorithm here */
			if (!NT_STATUS_IS_OK(pdb_init_sam_new(&sam_pass, user_name, 0))) {
				slprintf(err_str, err_str_len-1, "Failed to initialise SAM_ACCOUNT for user %s.\n", user_name);
				return False;
			}
		} else {
			slprintf(err_str, err_str_len-1,"Failed to find entry for user %s.\n", user_name);
			return False;
		}
	} else {
		unbecome_root();
		/* the entry already existed */
		local_flags &= ~LOCAL_ADD_USER;
	}

	/* the 'other' acb bits not being changed here */
	other_acb =  (pdb_get_acct_ctrl(sam_pass) & (!(ACB_WSTRUST|ACB_DOMTRUST|ACB_SVRTRUST|ACB_NORMAL)));
	if (local_flags & LOCAL_TRUST_ACCOUNT) {
		if (!pdb_set_acct_ctrl(sam_pass, ACB_WSTRUST | other_acb, PDB_CHANGED) ) {
			slprintf(err_str, err_str_len - 1, "Failed to set 'trusted workstation account' flags for user %s.\n", user_name);
			pdb_free_sam(&sam_pass);
			return False;
		}
	} else if (local_flags & LOCAL_INTERDOM_ACCOUNT) {
		if (!pdb_set_acct_ctrl(sam_pass, ACB_DOMTRUST | other_acb, PDB_CHANGED)) {
			slprintf(err_str, err_str_len - 1, "Failed to set 'domain trust account' flags for user %s.\n", user_name);
			pdb_free_sam(&sam_pass);
			return False;
		}
	} else {
		if (!pdb_set_acct_ctrl(sam_pass, ACB_NORMAL | other_acb, PDB_CHANGED)) {
			slprintf(err_str, err_str_len - 1, "Failed to set 'normal account' flags for user %s.\n", user_name);
			pdb_free_sam(&sam_pass);
			return False;
		}
	}

	/*
	 * We are root - just write the new password
	 * and the valid last change time.
	 */

	if (local_flags & LOCAL_DISABLE_USER) {
		if (!pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)|ACB_DISABLED, PDB_CHANGED)) {
			slprintf(err_str, err_str_len-1, "Failed to set 'disabled' flag for user %s.\n", user_name);
			pdb_free_sam(&sam_pass);
			return False;
		}
	} else if (local_flags & LOCAL_ENABLE_USER) {
		if (!pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)&(~ACB_DISABLED), PDB_CHANGED)) {
			slprintf(err_str, err_str_len-1, "Failed to unset 'disabled' flag for user %s.\n", user_name);
			pdb_free_sam(&sam_pass);
			return False;
		}
	}
	
	if (local_flags & LOCAL_SET_NO_PASSWORD) {
		if (!pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)|ACB_PWNOTREQ, PDB_CHANGED)) {
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
			if (!pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)&(~ACB_DISABLED), PDB_CHANGED)) {
				slprintf(err_str, err_str_len-1, "Failed to unset 'disabled' flag for user %s.\n", user_name);
				pdb_free_sam(&sam_pass);
				return False;
			}
		}
		if (!pdb_set_acct_ctrl (sam_pass, pdb_get_acct_ctrl(sam_pass)&(~ACB_PWNOTREQ), PDB_CHANGED)) {
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
		if (!pdb_delete_sam_account(sam_pass)) {
			slprintf(err_str,err_str_len-1, "Failed to delete entry for user %s.\n", user_name);
			pdb_free_sam(&sam_pass);
			return False;
		}
		slprintf(msg_str, msg_str_len-1, "Deleted user %s.\n", user_name);
	} else {
		if(!pdb_update_sam_account(sam_pass)) {
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

/****************************************************************************
 Convert a uid to SID - algorithmic.
****************************************************************************/

DOM_SID *algorithmic_uid_to_sid(DOM_SID *psid, uid_t uid)
{
	if ( !lp_enable_rid_algorithm() )
		return NULL;

	DEBUG(8,("algorithmic_uid_to_sid: falling back to RID algorithm\n"));
	sid_copy( psid, get_global_sam_sid() );
	sid_append_rid( psid, fallback_pdb_uid_to_user_rid(uid) );
	DEBUG(10,("algorithmic_uid_to_sid:  uid (%d) -> SID %s.\n",
		(unsigned int)uid, sid_string_static(psid) ));

	return psid;
}

/****************************************************************************
 Convert a uid to SID - locally.
****************************************************************************/

DOM_SID *local_uid_to_sid(DOM_SID *psid, uid_t uid)
{
	SAM_ACCOUNT *sampw = NULL;
	struct passwd *unix_pw;
	BOOL ret;
	
	unix_pw = sys_getpwuid( uid );

	if ( !unix_pw ) {
		DEBUG(4,("local_uid_to_sid: host has no idea of uid %lu\n", (unsigned long)uid));
		return algorithmic_uid_to_sid( psid, uid);
	}
	
	if ( !NT_STATUS_IS_OK(pdb_init_sam(&sampw)) ) {
		DEBUG(0,("local_uid_to_sid: failed to allocate SAM_ACCOUNT object\n"));
		return NULL;
	}
	
	become_root();
	ret = pdb_getsampwnam( sampw, unix_pw->pw_name );
	unbecome_root();
	
	if ( ret )
		sid_copy( psid, pdb_get_user_sid(sampw) );
	else {
		DEBUG(4,("local_uid_to_sid: User %s [uid == %lu] has no samba account\n",
			unix_pw->pw_name, (unsigned long)uid));

		return algorithmic_uid_to_sid( psid, uid);
	}

	DEBUG(10,("local_uid_to_sid:  uid (%d) -> SID %s (%s).\n", 
		(unsigned int)uid, sid_string_static(psid), unix_pw->pw_name));
	
	return psid;
}

/****************************************************************************
 Convert a SID to uid - locally.
****************************************************************************/

BOOL local_sid_to_uid(uid_t *puid, const DOM_SID *psid, enum SID_NAME_USE *name_type)
{
	SAM_ACCOUNT *sampw = NULL;	
	struct passwd *unix_pw;
	const char *user_name;

	*name_type = SID_NAME_UNKNOWN;

	/*
	 * We can only convert to a uid if this is our local
	 * Domain SID (ie. we are the controling authority).
	 */
	if (!sid_check_is_in_our_domain(psid) ) {
		DEBUG(5,("local_sid_to_uid: this SID (%s) is not from our domain\n", sid_string_static(psid)));
		return False;
	}

	/* lookup the user account */
	
	if ( !NT_STATUS_IS_OK(pdb_init_sam(&sampw)) ) {
		DEBUG(0,("local_sid_to_uid: Failed to allocate memory for SAM_ACCOUNT object\n"));
		return False;
	}
		
	become_root();
	if ( !pdb_getsampwsid(sampw, psid) ) {
		unbecome_root();
		DEBUG(8,("local_sid_to_uid: Could not find SID %s in passdb\n",
			sid_string_static(psid)));
		return False;
	}
	unbecome_root();
	
	user_name = pdb_get_username(sampw);

	unix_pw = sys_getpwnam( user_name );

	if ( !unix_pw ) {
		DEBUG(0,("local_sid_to_uid: %s found in passdb but getpwnam() return NULL!\n",
			user_name));
		pdb_free_sam( &sampw );
		return False;
	}
		
	*puid = unix_pw->pw_uid;
	
	DEBUG(10,("local_sid_to_uid: SID %s -> uid (%u) (%s).\n", sid_string_static(psid),
		(unsigned int)*puid, user_name ));

	*name_type = SID_NAME_USER;
	
	return True;
}

/****************************************************************************
 Convert a gid to SID - locally.
****************************************************************************/

DOM_SID *local_gid_to_sid(DOM_SID *psid, gid_t gid)
{
	GROUP_MAP group;
	BOOL ret;
	
	/* we don't need to disable winbindd since the gid is stored in 
	   the GROUP_MAP object */
	   
	/* done as root since ldap backend requires root to open a connection */

	become_root();
	ret = pdb_getgrgid( &group, gid );
	unbecome_root();
	
	if ( !ret ) {

		/* fallback to rid mapping if enabled */

		if ( lp_enable_rid_algorithm() ) {
			sid_copy(psid, get_global_sam_sid());
			sid_append_rid(psid, pdb_gid_to_group_rid(gid));

			DEBUG(10,("local_gid_to_sid: Fall back to algorithmic mapping: %u -> %s\n", 
				(unsigned int)gid, sid_string_static(psid)));
				
			return psid;
		}
		else
			return NULL;
	}
	
	sid_copy( psid, &group.sid );
	
	DEBUG(10,("local_gid_to_sid:  gid (%d) -> SID %s.\n", 
		(unsigned int)gid, sid_string_static(psid)));	
	
	return psid;
}

/****************************************************************************
 Convert a SID to gid - locally.
****************************************************************************/

BOOL local_sid_to_gid(gid_t *pgid, const DOM_SID *psid, enum SID_NAME_USE *name_type)
{
	uint32 rid;
	GROUP_MAP group;
	BOOL ret;

	*name_type = SID_NAME_UNKNOWN;

	/* This call can enumerate group mappings for foreign sids as well.
	   So don't check for a match against our domain SID */

	/* we don't need to disable winbindd since the gid is stored in 
	   the GROUP_MAP object */
	   
	become_root();
	ret = pdb_getgrsid(&group, *psid);
	unbecome_root();
	
	if ( !ret ) {

		/* fallback to rid mapping if enabled */

		if ( lp_enable_rid_algorithm() ) {

			if (!sid_check_is_in_our_domain(psid) ) {
				DEBUG(5,("local_sid_to_gid: RID algorithm only supported for our domain (%s is not)\n", sid_string_static(psid)));
				return False;
			}

			if (!sid_peek_rid(psid, &rid)) {
				DEBUG(10,("local_sid_to_uid: invalid SID!\n"));
					return False;
			}

			DEBUG(10,("local_sid_to_gid: Fall back to algorithmic mapping\n"));

			if (fallback_pdb_rid_is_user(rid)) {
				DEBUG(3, ("local_sid_to_gid: SID %s is *NOT* a group\n", sid_string_static(psid)));
				return False;
			} else {
				*pgid = pdb_group_rid_to_gid(rid);
				DEBUG(10,("local_sid_to_gid: mapping: %s -> %u\n", sid_string_static(psid), (unsigned int)(*pgid)));
				return True;
			}
		}
		
		return False;
	}

	*pgid = group.gid;

	DEBUG(10,("local_sid_to_gid: SID %s -> gid (%u)\n", sid_string_static(psid),
		(unsigned int)*pgid));

	return True;
}

/**********************************************************************
 Marshall/unmarshall SAM_ACCOUNT structs.
 *********************************************************************/

#define TDB_FORMAT_STRING_V0       "ddddddBBBBBBBBBBBBddBBwdwdBwwd"
#define TDB_FORMAT_STRING_V1       "dddddddBBBBBBBBBBBBddBBwdwdBwwd"

/**********************************************************************
 Intialize a SAM_ACCOUNT struct from a BYTE buffer of size len
 *********************************************************************/

BOOL init_sam_from_buffer(SAM_ACCOUNT *sampass, uint8 *buf, uint32 buflen)
{
	return(init_sam_from_buffer_v1(sampass, buf, buflen));
}

/**********************************************************************
 Intialize a BYTE buffer from a SAM_ACCOUNT struct
 *********************************************************************/

uint32 init_buffer_from_sam (uint8 **buf, const SAM_ACCOUNT *sampass, BOOL size_only)
{
	return(init_buffer_from_sam_v1(buf, sampass, size_only));
}


BOOL init_sam_from_buffer_v0(SAM_ACCOUNT *sampass, uint8 *buf, uint32 buflen)
{

	/* times are stored as 32bit integer
	   take care on system with 64bit wide time_t
	   --SSS */
	uint32	logon_time,
		logoff_time,
		kickoff_time,
		pass_last_set_time,
		pass_can_change_time,
		pass_must_change_time;
	char *username;
	char *domain;
	char *nt_username;
	char *dir_drive;
	char *unknown_str;
	char *munged_dial;
	char *fullname;
	char *homedir;
	char *logon_script;
	char *profile_path;
	char *acct_desc;
	char *workstations;
	uint32	username_len, domain_len, nt_username_len,
		dir_drive_len, unknown_str_len, munged_dial_len,
		fullname_len, homedir_len, logon_script_len,
		profile_path_len, acct_desc_len, workstations_len;
		
	uint32	user_rid, group_rid, remove_me, hours_len, unknown_6;
	uint16	acct_ctrl, logon_divs;
	uint16	bad_password_count, logon_count;
	uint8	*hours;
	static uint8	*lm_pw_ptr, *nt_pw_ptr;
	uint32		len = 0;
	uint32		lm_pw_len, nt_pw_len, hourslen;
	BOOL ret = True;
	
	if(sampass == NULL || buf == NULL) {
		DEBUG(0, ("init_sam_from_buffer: NULL parameters found!\n"));
		return False;
	}
									
	/* unpack the buffer into variables */
	len = tdb_unpack ((char *)buf, buflen, TDB_FORMAT_STRING_V0,
		&logon_time,
		&logoff_time,
		&kickoff_time,
		&pass_last_set_time,
		&pass_can_change_time,
		&pass_must_change_time,
		&username_len, &username,
		&domain_len, &domain,
		&nt_username_len, &nt_username,
		&fullname_len, &fullname,
		&homedir_len, &homedir,
		&dir_drive_len, &dir_drive,
		&logon_script_len, &logon_script,
		&profile_path_len, &profile_path,
		&acct_desc_len, &acct_desc,
		&workstations_len, &workstations,
		&unknown_str_len, &unknown_str,
		&munged_dial_len, &munged_dial,
		&user_rid,
		&group_rid,
		&lm_pw_len, &lm_pw_ptr,
		&nt_pw_len, &nt_pw_ptr,
		&acct_ctrl,
		&remove_me, /* remove on the next TDB_FORMAT upgarde */
		&logon_divs,
		&hours_len,
		&hourslen, &hours,
		&bad_password_count,
		&logon_count,
		&unknown_6);
		
	if (len == (uint32) -1)  {
		ret = False;
		goto done;
	}

	pdb_set_logon_time(sampass, logon_time, PDB_SET);
	pdb_set_logoff_time(sampass, logoff_time, PDB_SET);
	pdb_set_kickoff_time(sampass, kickoff_time, PDB_SET);
	pdb_set_pass_can_change_time(sampass, pass_can_change_time, PDB_SET);
	pdb_set_pass_must_change_time(sampass, pass_must_change_time, PDB_SET);
	pdb_set_pass_last_set_time(sampass, pass_last_set_time, PDB_SET);

	pdb_set_username(sampass, username, PDB_SET); 
	pdb_set_domain(sampass, domain, PDB_SET);
	pdb_set_nt_username(sampass, nt_username, PDB_SET);
	pdb_set_fullname(sampass, fullname, PDB_SET);

	if (homedir) {
		pdb_set_homedir(sampass, homedir, PDB_SET);
	}
	else {
		pdb_set_homedir(sampass, 
			talloc_sub_basic(sampass->mem_ctx, username, lp_logon_home()),
			PDB_DEFAULT);
	}

	if (dir_drive) 	
		pdb_set_dir_drive(sampass, dir_drive, PDB_SET);
	else {
		pdb_set_dir_drive(sampass, 
			talloc_sub_basic(sampass->mem_ctx,  username, lp_logon_drive()),
			PDB_DEFAULT);
	}

	if (logon_script) 
		pdb_set_logon_script(sampass, logon_script, PDB_SET);
	else {
		pdb_set_logon_script(sampass, 
			talloc_sub_basic(sampass->mem_ctx, username, lp_logon_script()),
			PDB_DEFAULT);
	}
	
	if (profile_path) {	
		pdb_set_profile_path(sampass, profile_path, PDB_SET);
	} else {
		pdb_set_profile_path(sampass, 
			talloc_sub_basic(sampass->mem_ctx, username, lp_logon_path()),
			PDB_DEFAULT);
	}

	pdb_set_acct_desc(sampass, acct_desc, PDB_SET);
	pdb_set_workstations(sampass, workstations, PDB_SET);
	pdb_set_munged_dial(sampass, munged_dial, PDB_SET);

	if (lm_pw_ptr && lm_pw_len == LM_HASH_LEN) {
		if (!pdb_set_lanman_passwd(sampass, lm_pw_ptr, PDB_SET)) {
			ret = False;
			goto done;
		}
	}

	if (nt_pw_ptr && nt_pw_len == NT_HASH_LEN) {
		if (!pdb_set_nt_passwd(sampass, nt_pw_ptr, PDB_SET)) {
			ret = False;
			goto done;
		}
	}

	pdb_set_user_sid_from_rid(sampass, user_rid, PDB_SET);
	pdb_set_group_sid_from_rid(sampass, group_rid, PDB_SET);
	pdb_set_hours_len(sampass, hours_len, PDB_SET);
	pdb_set_bad_password_count(sampass, bad_password_count, PDB_SET);
	pdb_set_logon_count(sampass, logon_count, PDB_SET);
	pdb_set_unknown_6(sampass, unknown_6, PDB_SET);
	pdb_set_acct_ctrl(sampass, acct_ctrl, PDB_SET);
	pdb_set_logon_divs(sampass, logon_divs, PDB_SET);
	pdb_set_hours(sampass, hours, PDB_SET);

done:

	SAFE_FREE(username);
	SAFE_FREE(domain);
	SAFE_FREE(nt_username);
	SAFE_FREE(fullname);
	SAFE_FREE(homedir);
	SAFE_FREE(dir_drive);
	SAFE_FREE(logon_script);
	SAFE_FREE(profile_path);
	SAFE_FREE(acct_desc);
	SAFE_FREE(workstations);
	SAFE_FREE(munged_dial);
	SAFE_FREE(unknown_str);
	SAFE_FREE(hours);

	return ret;
}


uint32 init_buffer_from_sam_v0 (uint8 **buf, const SAM_ACCOUNT *sampass, BOOL size_only)
{
	size_t len, buflen;

	/* times are stored as 32bit integer
	   take care on system with 64bit wide time_t
	   --SSS */
	uint32	logon_time,
		logoff_time,
		kickoff_time,
		pass_last_set_time,
		pass_can_change_time,
		pass_must_change_time;

	uint32  user_rid, group_rid;

	const char *username;
	const char *domain;
	const char *nt_username;
	const char *dir_drive;
	const char *unknown_str;
	const char *munged_dial;
	const char *fullname;
	const char *homedir;
	const char *logon_script;
	const char *profile_path;
	const char *acct_desc;
	const char *workstations;
	uint32	username_len, domain_len, nt_username_len,
		dir_drive_len, unknown_str_len, munged_dial_len,
		fullname_len, homedir_len, logon_script_len,
		profile_path_len, acct_desc_len, workstations_len;

	const uint8 *lm_pw;
	const uint8 *nt_pw;
	uint32	lm_pw_len = 16;
	uint32	nt_pw_len = 16;

	/* do we have a valid SAM_ACCOUNT pointer? */
	if (sampass == NULL) {
		DEBUG(0, ("init_buffer_from_sam: SAM_ACCOUNT is NULL!\n"));
		return -1;
	}
	
	*buf = NULL;
	buflen = 0;

	logon_time = (uint32)pdb_get_logon_time(sampass);
	logoff_time = (uint32)pdb_get_logoff_time(sampass);
	kickoff_time = (uint32)pdb_get_kickoff_time(sampass);
	pass_can_change_time = (uint32)pdb_get_pass_can_change_time(sampass);
	pass_must_change_time = (uint32)pdb_get_pass_must_change_time(sampass);
	pass_last_set_time = (uint32)pdb_get_pass_last_set_time(sampass);

	user_rid = pdb_get_user_rid(sampass);
	group_rid = pdb_get_group_rid(sampass);

	username = pdb_get_username(sampass);
	if (username)
		username_len = strlen(username) +1;
	else
		username_len = 0;

	domain = pdb_get_domain(sampass);
	if (domain)
		domain_len = strlen(domain) +1;
	else
		domain_len = 0;

	nt_username = pdb_get_nt_username(sampass);
	if (nt_username)
		nt_username_len = strlen(nt_username) +1;
	else
		nt_username_len = 0;

	fullname = pdb_get_fullname(sampass);
	if (fullname)
		fullname_len = strlen(fullname) +1;
	else
		fullname_len = 0;

	/*
	 * Only updates fields which have been set (not defaults from smb.conf)
	 */

	if (!IS_SAM_DEFAULT(sampass, PDB_DRIVE)) 
		dir_drive = pdb_get_dir_drive(sampass);
	else
		dir_drive = NULL;
	if (dir_drive)
		dir_drive_len = strlen(dir_drive) +1;
	else
		dir_drive_len = 0;

	if (!IS_SAM_DEFAULT(sampass, PDB_SMBHOME))
		homedir = pdb_get_homedir(sampass);
	else
		homedir = NULL;
	if (homedir)
		homedir_len = strlen(homedir) +1;
	else
		homedir_len = 0;

	if (!IS_SAM_DEFAULT(sampass, PDB_LOGONSCRIPT))
		logon_script = pdb_get_logon_script(sampass);
	else
		logon_script = NULL;
	if (logon_script)
		logon_script_len = strlen(logon_script) +1;
	else
		logon_script_len = 0;

	if (!IS_SAM_DEFAULT(sampass, PDB_PROFILE))
		profile_path = pdb_get_profile_path(sampass);
	else
		profile_path = NULL;
	if (profile_path)
		profile_path_len = strlen(profile_path) +1;
	else
		profile_path_len = 0;
	
	lm_pw = pdb_get_lanman_passwd(sampass);
	if (!lm_pw)
		lm_pw_len = 0;
	
	nt_pw = pdb_get_nt_passwd(sampass);
	if (!nt_pw)
		nt_pw_len = 0;
		
	acct_desc = pdb_get_acct_desc(sampass);
	if (acct_desc)
		acct_desc_len = strlen(acct_desc) +1;
	else
		acct_desc_len = 0;

	workstations = pdb_get_workstations(sampass);
	if (workstations)
		workstations_len = strlen(workstations) +1;
	else
		workstations_len = 0;

	unknown_str = NULL;
	unknown_str_len = 0;

	munged_dial = pdb_get_munged_dial(sampass);
	if (munged_dial)
		munged_dial_len = strlen(munged_dial) +1;
	else
		munged_dial_len = 0;	
		
	/* one time to get the size needed */
	len = tdb_pack(NULL, 0,  TDB_FORMAT_STRING_V0,
		logon_time,
		logoff_time,
		kickoff_time,
		pass_last_set_time,
		pass_can_change_time,
		pass_must_change_time,
		username_len, username,
		domain_len, domain,
		nt_username_len, nt_username,
		fullname_len, fullname,
		homedir_len, homedir,
		dir_drive_len, dir_drive,
		logon_script_len, logon_script,
		profile_path_len, profile_path,
		acct_desc_len, acct_desc,
		workstations_len, workstations,
		unknown_str_len, unknown_str,
		munged_dial_len, munged_dial,
		user_rid,
		group_rid,
		lm_pw_len, lm_pw,
		nt_pw_len, nt_pw,
		pdb_get_acct_ctrl(sampass),
		0, /* was: fileds_present, to be removed on format change */
		pdb_get_logon_divs(sampass),
		pdb_get_hours_len(sampass),
		MAX_HOURS_LEN, pdb_get_hours(sampass),
		pdb_get_bad_password_count(sampass),
		pdb_get_logon_count(sampass),
		pdb_get_unknown_6(sampass));


	if (size_only)
		return buflen;

	/* malloc the space needed */
	if ( (*buf=(uint8*)malloc(len)) == NULL) {
		DEBUG(0,("init_buffer_from_sam: Unable to malloc() memory for buffer!\n"));
		return (-1);
	}
	
	/* now for the real call to tdb_pack() */
	buflen = tdb_pack((char *)*buf, len,  TDB_FORMAT_STRING_V0,
		logon_time,
		logoff_time,
		kickoff_time,
		pass_last_set_time,
		pass_can_change_time,
		pass_must_change_time,
		username_len, username,
		domain_len, domain,
		nt_username_len, nt_username,
		fullname_len, fullname,
		homedir_len, homedir,
		dir_drive_len, dir_drive,
		logon_script_len, logon_script,
		profile_path_len, profile_path,
		acct_desc_len, acct_desc,
		workstations_len, workstations,
		unknown_str_len, unknown_str,
		munged_dial_len, munged_dial,
		user_rid,
		group_rid,
		lm_pw_len, lm_pw,
		nt_pw_len, nt_pw,
		pdb_get_acct_ctrl(sampass),
		0, /* was: fileds_present, to be removed on format change */
		pdb_get_logon_divs(sampass),
		pdb_get_hours_len(sampass),
		MAX_HOURS_LEN, pdb_get_hours(sampass),
		pdb_get_bad_password_count(sampass),
		pdb_get_logon_count(sampass),
		pdb_get_unknown_6(sampass));
	
	
	/* check to make sure we got it correct */
	if (buflen != len) {
		DEBUG(0, ("init_buffer_from_sam: somthing odd is going on here: bufflen (%lu) != len (%lu) in tdb_pack operations!\n", 
			  (unsigned long)buflen, (unsigned long)len));  
		/* error */
		SAFE_FREE (*buf);
		return (-1);
	}

	return (buflen);
}


BOOL init_sam_from_buffer_v1(SAM_ACCOUNT *sampass, uint8 *buf, uint32 buflen)
{

	/* times are stored as 32bit integer
	   take care on system with 64bit wide time_t
	   --SSS */
	uint32	logon_time,
		logoff_time,
		kickoff_time,
		bad_password_time,
		pass_last_set_time,
		pass_can_change_time,
		pass_must_change_time;
	char *username;
	char *domain;
	char *nt_username;
	char *dir_drive;
	char *unknown_str;
	char *munged_dial;
	char *fullname;
	char *homedir;
	char *logon_script;
	char *profile_path;
	char *acct_desc;
	char *workstations;
	uint32	username_len, domain_len, nt_username_len,
		dir_drive_len, unknown_str_len, munged_dial_len,
		fullname_len, homedir_len, logon_script_len,
		profile_path_len, acct_desc_len, workstations_len;
		
	uint32	user_rid, group_rid, remove_me, hours_len, unknown_6;
	uint16	acct_ctrl, logon_divs;
	uint16	bad_password_count, logon_count;
	uint8	*hours;
	static uint8	*lm_pw_ptr, *nt_pw_ptr;
	uint32		len = 0;
	uint32		lm_pw_len, nt_pw_len, hourslen;
	BOOL ret = True;
	
	if(sampass == NULL || buf == NULL) {
		DEBUG(0, ("init_sam_from_buffer: NULL parameters found!\n"));
		return False;
	}
									
	/* unpack the buffer into variables */
	len = tdb_unpack ((char *)buf, buflen, TDB_FORMAT_STRING_V1,
		&logon_time,
		&logoff_time,
		&kickoff_time,
		&bad_password_time,
		&pass_last_set_time,
		&pass_can_change_time,
		&pass_must_change_time,
		&username_len, &username,
		&domain_len, &domain,
		&nt_username_len, &nt_username,
		&fullname_len, &fullname,
		&homedir_len, &homedir,
		&dir_drive_len, &dir_drive,
		&logon_script_len, &logon_script,
		&profile_path_len, &profile_path,
		&acct_desc_len, &acct_desc,
		&workstations_len, &workstations,
		&unknown_str_len, &unknown_str,
		&munged_dial_len, &munged_dial,
		&user_rid,
		&group_rid,
		&lm_pw_len, &lm_pw_ptr,
		&nt_pw_len, &nt_pw_ptr,
		&acct_ctrl,
		&remove_me,
		&logon_divs,
		&hours_len,
		&hourslen, &hours,
		&bad_password_count,
		&logon_count,
		&unknown_6);
		
	if (len == (uint32) -1)  {
		ret = False;
		goto done;
	}

	pdb_set_logon_time(sampass, logon_time, PDB_SET);
	pdb_set_logoff_time(sampass, logoff_time, PDB_SET);
	pdb_set_kickoff_time(sampass, kickoff_time, PDB_SET);
	pdb_set_bad_password_time(sampass, bad_password_time, PDB_SET);
	pdb_set_pass_can_change_time(sampass, pass_can_change_time, PDB_SET);
	pdb_set_pass_must_change_time(sampass, pass_must_change_time, PDB_SET);
	pdb_set_pass_last_set_time(sampass, pass_last_set_time, PDB_SET);

	pdb_set_username(sampass, username, PDB_SET); 
	pdb_set_domain(sampass, domain, PDB_SET);
	pdb_set_nt_username(sampass, nt_username, PDB_SET);
	pdb_set_fullname(sampass, fullname, PDB_SET);

	if (homedir) {
		pdb_set_homedir(sampass, homedir, PDB_SET);
	}
	else {
		pdb_set_homedir(sampass, 
			talloc_sub_basic(sampass->mem_ctx, username, lp_logon_home()),
			PDB_DEFAULT);
	}

	if (dir_drive) 	
		pdb_set_dir_drive(sampass, dir_drive, PDB_SET);
	else {
		pdb_set_dir_drive(sampass, 
			talloc_sub_basic(sampass->mem_ctx,  username, lp_logon_drive()),
			PDB_DEFAULT);
	}

	if (logon_script) 
		pdb_set_logon_script(sampass, logon_script, PDB_SET);
	else {
		pdb_set_logon_script(sampass, 
			talloc_sub_basic(sampass->mem_ctx, username, lp_logon_script()),
			PDB_DEFAULT);
	}
	
	if (profile_path) {	
		pdb_set_profile_path(sampass, profile_path, PDB_SET);
	} else {
		pdb_set_profile_path(sampass, 
			talloc_sub_basic(sampass->mem_ctx, username, lp_logon_path()),
			PDB_DEFAULT);
	}

	pdb_set_acct_desc(sampass, acct_desc, PDB_SET);
	pdb_set_workstations(sampass, workstations, PDB_SET);
	pdb_set_munged_dial(sampass, munged_dial, PDB_SET);

	if (lm_pw_ptr && lm_pw_len == LM_HASH_LEN) {
		if (!pdb_set_lanman_passwd(sampass, lm_pw_ptr, PDB_SET)) {
			ret = False;
			goto done;
		}
	}

	if (nt_pw_ptr && nt_pw_len == NT_HASH_LEN) {
		if (!pdb_set_nt_passwd(sampass, nt_pw_ptr, PDB_SET)) {
			ret = False;
			goto done;
		}
	}

	pdb_set_user_sid_from_rid(sampass, user_rid, PDB_SET);
	pdb_set_group_sid_from_rid(sampass, group_rid, PDB_SET);
	pdb_set_hours_len(sampass, hours_len, PDB_SET);
	pdb_set_bad_password_count(sampass, bad_password_count, PDB_SET);
	pdb_set_logon_count(sampass, logon_count, PDB_SET);
	pdb_set_unknown_6(sampass, unknown_6, PDB_SET);
	pdb_set_acct_ctrl(sampass, acct_ctrl, PDB_SET);
	pdb_set_logon_divs(sampass, logon_divs, PDB_SET);
	pdb_set_hours(sampass, hours, PDB_SET);

done:

	SAFE_FREE(username);
	SAFE_FREE(domain);
	SAFE_FREE(nt_username);
	SAFE_FREE(fullname);
	SAFE_FREE(homedir);
	SAFE_FREE(dir_drive);
	SAFE_FREE(logon_script);
	SAFE_FREE(profile_path);
	SAFE_FREE(acct_desc);
	SAFE_FREE(workstations);
	SAFE_FREE(munged_dial);
	SAFE_FREE(unknown_str);
	SAFE_FREE(hours);

	return ret;
}


uint32 init_buffer_from_sam_v1 (uint8 **buf, const SAM_ACCOUNT *sampass, BOOL size_only)
{
	size_t len, buflen;

	/* times are stored as 32bit integer
	   take care on system with 64bit wide time_t
	   --SSS */
	uint32	logon_time,
		logoff_time,
		kickoff_time,
		bad_password_time,
		pass_last_set_time,
		pass_can_change_time,
		pass_must_change_time;

	uint32  user_rid, group_rid;

	const char *username;
	const char *domain;
	const char *nt_username;
	const char *dir_drive;
	const char *unknown_str;
	const char *munged_dial;
	const char *fullname;
	const char *homedir;
	const char *logon_script;
	const char *profile_path;
	const char *acct_desc;
	const char *workstations;
	uint32	username_len, domain_len, nt_username_len,
		dir_drive_len, unknown_str_len, munged_dial_len,
		fullname_len, homedir_len, logon_script_len,
		profile_path_len, acct_desc_len, workstations_len;

	const uint8 *lm_pw;
	const uint8 *nt_pw;
	uint32	lm_pw_len = 16;
	uint32	nt_pw_len = 16;

	/* do we have a valid SAM_ACCOUNT pointer? */
	if (sampass == NULL) {
		DEBUG(0, ("init_buffer_from_sam: SAM_ACCOUNT is NULL!\n"));
		return -1;
	}
	
	*buf = NULL;
	buflen = 0;

	logon_time = (uint32)pdb_get_logon_time(sampass);
	logoff_time = (uint32)pdb_get_logoff_time(sampass);
	kickoff_time = (uint32)pdb_get_kickoff_time(sampass);
	bad_password_time = (uint32)pdb_get_bad_password_time(sampass);
	pass_can_change_time = (uint32)pdb_get_pass_can_change_time(sampass);
	pass_must_change_time = (uint32)pdb_get_pass_must_change_time(sampass);
	pass_last_set_time = (uint32)pdb_get_pass_last_set_time(sampass);

	user_rid = pdb_get_user_rid(sampass);
	group_rid = pdb_get_group_rid(sampass);

	username = pdb_get_username(sampass);
	if (username)
		username_len = strlen(username) +1;
	else
		username_len = 0;

	domain = pdb_get_domain(sampass);
	if (domain)
		domain_len = strlen(domain) +1;
	else
		domain_len = 0;

	nt_username = pdb_get_nt_username(sampass);
	if (nt_username)
		nt_username_len = strlen(nt_username) +1;
	else
		nt_username_len = 0;

	fullname = pdb_get_fullname(sampass);
	if (fullname)
		fullname_len = strlen(fullname) +1;
	else
		fullname_len = 0;

	/*
	 * Only updates fields which have been set (not defaults from smb.conf)
	 */

	if (!IS_SAM_DEFAULT(sampass, PDB_DRIVE)) 
		dir_drive = pdb_get_dir_drive(sampass);
	else
		dir_drive = NULL;
	if (dir_drive)
		dir_drive_len = strlen(dir_drive) +1;
	else
		dir_drive_len = 0;

	if (!IS_SAM_DEFAULT(sampass, PDB_SMBHOME))
		homedir = pdb_get_homedir(sampass);
	else
		homedir = NULL;
	if (homedir)
		homedir_len = strlen(homedir) +1;
	else
		homedir_len = 0;

	if (!IS_SAM_DEFAULT(sampass, PDB_LOGONSCRIPT))
		logon_script = pdb_get_logon_script(sampass);
	else
		logon_script = NULL;
	if (logon_script)
		logon_script_len = strlen(logon_script) +1;
	else
		logon_script_len = 0;

	if (!IS_SAM_DEFAULT(sampass, PDB_PROFILE))
		profile_path = pdb_get_profile_path(sampass);
	else
		profile_path = NULL;
	if (profile_path)
		profile_path_len = strlen(profile_path) +1;
	else
		profile_path_len = 0;
	
	lm_pw = pdb_get_lanman_passwd(sampass);
	if (!lm_pw)
		lm_pw_len = 0;
	
	nt_pw = pdb_get_nt_passwd(sampass);
	if (!nt_pw)
		nt_pw_len = 0;
		
	acct_desc = pdb_get_acct_desc(sampass);
	if (acct_desc)
		acct_desc_len = strlen(acct_desc) +1;
	else
		acct_desc_len = 0;

	workstations = pdb_get_workstations(sampass);
	if (workstations)
		workstations_len = strlen(workstations) +1;
	else
		workstations_len = 0;

	unknown_str = NULL;
	unknown_str_len = 0;

	munged_dial = pdb_get_munged_dial(sampass);
	if (munged_dial)
		munged_dial_len = strlen(munged_dial) +1;
	else
		munged_dial_len = 0;	
		
	/* one time to get the size needed */
	len = tdb_pack(NULL, 0,  TDB_FORMAT_STRING_V1,
		logon_time,
		logoff_time,
		kickoff_time,
		bad_password_time,
		pass_last_set_time,
		pass_can_change_time,
		pass_must_change_time,
		username_len, username,
		domain_len, domain,
		nt_username_len, nt_username,
		fullname_len, fullname,
		homedir_len, homedir,
		dir_drive_len, dir_drive,
		logon_script_len, logon_script,
		profile_path_len, profile_path,
		acct_desc_len, acct_desc,
		workstations_len, workstations,
		unknown_str_len, unknown_str,
		munged_dial_len, munged_dial,
		user_rid,
		group_rid,
		lm_pw_len, lm_pw,
		nt_pw_len, nt_pw,
		pdb_get_acct_ctrl(sampass),
		0,
		pdb_get_logon_divs(sampass),
		pdb_get_hours_len(sampass),
		MAX_HOURS_LEN, pdb_get_hours(sampass),
		pdb_get_bad_password_count(sampass),
		pdb_get_logon_count(sampass),
		pdb_get_unknown_6(sampass));


	if (size_only)
		return buflen;

	/* malloc the space needed */
	if ( (*buf=(uint8*)malloc(len)) == NULL) {
		DEBUG(0,("init_buffer_from_sam: Unable to malloc() memory for buffer!\n"));
		return (-1);
	}
	
	/* now for the real call to tdb_pack() */
	buflen = tdb_pack((char *)*buf, len,  TDB_FORMAT_STRING_V1,
		logon_time,
		logoff_time,
		kickoff_time,
		bad_password_time,
		pass_last_set_time,
		pass_can_change_time,
		pass_must_change_time,
		username_len, username,
		domain_len, domain,
		nt_username_len, nt_username,
		fullname_len, fullname,
		homedir_len, homedir,
		dir_drive_len, dir_drive,
		logon_script_len, logon_script,
		profile_path_len, profile_path,
		acct_desc_len, acct_desc,
		workstations_len, workstations,
		unknown_str_len, unknown_str,
		munged_dial_len, munged_dial,
		user_rid,
		group_rid,
		lm_pw_len, lm_pw,
		nt_pw_len, nt_pw,
		pdb_get_acct_ctrl(sampass),
		0,
		pdb_get_logon_divs(sampass),
		pdb_get_hours_len(sampass),
		MAX_HOURS_LEN, pdb_get_hours(sampass),
		pdb_get_bad_password_count(sampass),
		pdb_get_logon_count(sampass),
		pdb_get_unknown_6(sampass));
	
	
	/* check to make sure we got it correct */
	if (buflen != len) {
		DEBUG(0, ("init_buffer_from_sam: somthing odd is going on here: bufflen (%lu) != len (%lu) in tdb_pack operations!\n", 
			  (unsigned long)buflen, (unsigned long)len));  
		/* error */
		SAFE_FREE (*buf);
		return (-1);
	}

	return (buflen);
}


/**********************************************************************
**********************************************************************/

static BOOL get_free_ugid_range(uint32 *low, uint32 *high)
{
	uid_t u_low, u_high;
	gid_t g_low, g_high;

	if (!lp_idmap_uid(&u_low, &u_high) || !lp_idmap_gid(&g_low, &g_high)) {
		return False;
	}
	
	*low  = (u_low < g_low)   ? u_low  : g_low;
	*high = (u_high < g_high) ? u_high : g_high;
	
	return True;
}

/******************************************************************
 Get the the non-algorithmic RID range if idmap range are defined
******************************************************************/

BOOL get_free_rid_range(uint32 *low, uint32 *high)
{
	uint32 id_low, id_high;

	if (!lp_enable_rid_algorithm()) {
		*low = BASE_RID;
		*high = (uint32)-1;
	}

	if (!get_free_ugid_range(&id_low, &id_high)) {
		return False;
	}

	*low = fallback_pdb_uid_to_user_rid(id_low);
	if (fallback_pdb_user_rid_to_uid((uint32)-1) < id_high) {
		*high = (uint32)-1;
	} else {
		*high = fallback_pdb_uid_to_user_rid(id_high);
	}

	return True;
}

/*********************************************************************
 Update the bad password count checking the AP_RESET_COUNT_TIME 
*********************************************************************/

BOOL pdb_update_bad_password_count(SAM_ACCOUNT *sampass, BOOL *updated)
{
	time_t LastBadPassword;
	uint16 BadPasswordCount;
	uint32 resettime; 

	if (!sampass) return False;
	
	BadPasswordCount = pdb_get_bad_password_count(sampass);
	if (!BadPasswordCount) {
		DEBUG(9, ("No bad password attempts.\n"));
		return True;
	}

	if (!account_policy_get(AP_RESET_COUNT_TIME, &resettime)) {
		DEBUG(0, ("pdb_update_bad_password_count: account_policy_get failed.\n"));
		return False;
	}

	/* First, check if there is a reset time to compare */
	if ((resettime == (uint32) -1) || (resettime == 0)) {
		DEBUG(9, ("No reset time, can't reset bad pw count\n"));
		return True;
	}

	LastBadPassword = pdb_get_bad_password_time(sampass);
	DEBUG(7, ("LastBadPassword=%d, resettime=%d, current time=%d.\n", 
		   (uint32) LastBadPassword, resettime, (uint32)time(NULL)));
	if (time(NULL) > (LastBadPassword + (time_t)resettime*60)){
		pdb_set_bad_password_count(sampass, 0, PDB_CHANGED);
		pdb_set_bad_password_time(sampass, 0, PDB_CHANGED);
		if (updated) *updated = True;
	}

	return True;
}

/*********************************************************************
 Update the ACB_AUTOLOCK flag checking the AP_LOCK_ACCOUNT_DURATION 
*********************************************************************/

BOOL pdb_update_autolock_flag(SAM_ACCOUNT *sampass, BOOL *updated)
{
	uint32 duration;
	time_t LastBadPassword;

	if (!sampass) return False;
 
	if (!(pdb_get_acct_ctrl(sampass) & ACB_AUTOLOCK)) {
		DEBUG(9, ("Account not autolocked, no check needed\n"));
		return True;
	}

	if (!account_policy_get(AP_LOCK_ACCOUNT_DURATION, &duration)) {
		DEBUG(0, ("pdb_update_autolock_flag: account_policy_get failed.\n"));
		return False;
	}

	/* First, check if there is a duration to compare */
	if ((duration == (uint32) -1)  || (duration == 0)) {
		DEBUG(9, ("No reset duration, can't reset autolock\n"));
		return True;
	}
		      
	LastBadPassword = pdb_get_bad_password_time(sampass);
	DEBUG(7, ("LastBadPassword=%d, duration=%d, current time =%d.\n",
		  (uint32)LastBadPassword, duration*60, (uint32)time(NULL)));
	if ((time(NULL) > (LastBadPassword + (time_t) duration * 60))) {
		pdb_set_acct_ctrl(sampass,
				  pdb_get_acct_ctrl(sampass) & ~ACB_AUTOLOCK,
				  PDB_CHANGED);
		pdb_set_bad_password_count(sampass, 0, PDB_CHANGED);
		pdb_set_bad_password_time(sampass, 0, PDB_CHANGED);
		if (updated) *updated = True;
	}
	
	return True;
}

/*********************************************************************
 Increment the bad_password_count 
*********************************************************************/

BOOL pdb_increment_bad_password_count(SAM_ACCOUNT *sampass)
{
	uint32 account_policy_lockout;
	BOOL autolock_updated = False, badpw_updated = False;

	if (!sampass)
		return False;

	/* Retrieve the account lockout policy */
	if (!account_policy_get(AP_BAD_ATTEMPT_LOCKOUT,
				&account_policy_lockout)) {
		DEBUG(0, ("pdb_increment_bad_password_count: account_policy_get failed.\n"));
		return False;
	}

	/* If there is no policy, we don't need to continue checking */
	if (!account_policy_lockout) {
		DEBUG(9, ("No lockout policy, don't track bad passwords\n"));
		return True;
	}

	/* Check if the autolock needs to be cleared */
	if (!pdb_update_autolock_flag(sampass, &autolock_updated))
		return False;

	/* Check if the badpw count needs to be reset */
	if (!pdb_update_bad_password_count(sampass, &badpw_updated))
		return False;

	/*
	  Ok, now we can assume that any resetting that needs to be 
	  done has been done, and just get on with incrementing
	  and autolocking if necessary
	*/

	pdb_set_bad_password_count(sampass, 
				   pdb_get_bad_password_count(sampass)+1,
				   PDB_CHANGED);
	pdb_set_bad_password_time(sampass, time(NULL), PDB_CHANGED);


	if (pdb_get_bad_password_count(sampass) < account_policy_lockout) 
		return True;

	if (!pdb_set_acct_ctrl(sampass,
			       pdb_get_acct_ctrl(sampass) | ACB_AUTOLOCK,
			       PDB_CHANGED)) {
		DEBUG(1, ("pdb_increment_bad_password_count:failed to set 'autolock' flag. \n")); 
		return False;
	}

	return True;
}
