/*
   Unix SMB/CIFS implementation.
   Authentication utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Andrew Bartlett 2001
   Copyright (C) Jeremy Allison 2000-2001
   Copyright (C) Rafal Szczesniak 2002

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
#define DBGC_CLASS DBGC_AUTH

extern DOM_SID global_sid_World;
extern DOM_SID global_sid_Network;
extern DOM_SID global_sid_Builtin_Guests;
extern DOM_SID global_sid_Authenticated_Users;


/****************************************************************************
 Create a UNIX user on demand.
****************************************************************************/

static int smb_create_user(const char *domain, const char *unix_username, const char *homedir)
{
	pstring add_script;
	int ret;

	pstrcpy(add_script, lp_adduser_script());
	if (! *add_script)
		return -1;
	all_string_sub(add_script, "%u", unix_username, sizeof(pstring));
	if (domain)
		all_string_sub(add_script, "%D", domain, sizeof(pstring));
	if (homedir)
		all_string_sub(add_script, "%H", homedir, sizeof(pstring));
	ret = smbrun(add_script,NULL);
	DEBUG(3,("smb_create_user: Running the command `%s' gave %d\n",add_script,ret));
	return ret;
}

/****************************************************************************
 Add and Delete UNIX users on demand, based on NTSTATUS codes.
 We don't care about RID's here so ignore.
****************************************************************************/

void auth_add_user_script(const char *domain, const char *username)
{
	uint32 rid;
	/*
	 * User validated ok against Domain controller.
	 * If the admin wants us to try and create a UNIX
	 * user on the fly, do so.
	 */
	
	if ( *lp_adduser_script() )
		smb_create_user(domain, username, NULL);
	else {
		DEBUG(10,("auth_add_user_script: no 'add user script'.  Asking winbindd\n"));
		
		/* should never get here is we a re a domain member running winbindd
		   However, a host set for 'security = server' might run winbindd for 
		   account allocation */
		   
		if ( !winbind_create_user(username, NULL) ) {
			DEBUG(5,("auth_add_user_script: winbindd_create_user() failed\n"));
			rid = 0;
		}
	}
}

/****************************************************************************
 Create a SAM_ACCOUNT - either by looking in the pdb, or by faking it up from
 unix info.
****************************************************************************/

NTSTATUS auth_get_sam_account(const char *user, SAM_ACCOUNT **account) 
{
	BOOL pdb_ret;
	NTSTATUS nt_status;
	if (!NT_STATUS_IS_OK(nt_status = pdb_init_sam(account))) {
		return nt_status;
	}
	
	become_root();
	pdb_ret = pdb_getsampwnam(*account, user);
	unbecome_root();

	if (!pdb_ret) {
		
		struct passwd *pass = Get_Pwnam(user);
		if (!pass) 
			return NT_STATUS_NO_SUCH_USER;

		if (!NT_STATUS_IS_OK(nt_status = pdb_fill_sam_pw(*account, pass))) {
			return nt_status;
		}
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Create an auth_usersupplied_data structure
****************************************************************************/

static NTSTATUS make_user_info(auth_usersupplied_info **user_info, 
                               const char *smb_name, 
                               const char *internal_username,
                               const char *client_domain, 
                               const char *domain,
                               const char *wksta_name, 
                               DATA_BLOB *lm_pwd, DATA_BLOB *nt_pwd,
                               DATA_BLOB *lm_interactive_pwd, DATA_BLOB *nt_interactive_pwd,
                               DATA_BLOB *plaintext, 
                               BOOL encrypted)
{

	DEBUG(5,("attempting to make a user_info for %s (%s)\n", internal_username, smb_name));

	*user_info = malloc(sizeof(**user_info));
	if (!user_info) {
		DEBUG(0,("malloc failed for user_info (size %lu)\n", (unsigned long)sizeof(*user_info)));
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(*user_info);

	DEBUG(5,("making strings for %s's user_info struct\n", internal_username));

	(*user_info)->smb_name.str = strdup(smb_name);
	if ((*user_info)->smb_name.str) { 
		(*user_info)->smb_name.len = strlen(smb_name);
	} else {
		free_user_info(user_info);
		return NT_STATUS_NO_MEMORY;
	}
	
	(*user_info)->internal_username.str = strdup(internal_username);
	if ((*user_info)->internal_username.str) { 
		(*user_info)->internal_username.len = strlen(internal_username);
	} else {
		free_user_info(user_info);
		return NT_STATUS_NO_MEMORY;
	}

	(*user_info)->domain.str = strdup(domain);
	if ((*user_info)->domain.str) { 
		(*user_info)->domain.len = strlen(domain);
	} else {
		free_user_info(user_info);
		return NT_STATUS_NO_MEMORY;
	}

	(*user_info)->client_domain.str = strdup(client_domain);
	if ((*user_info)->client_domain.str) { 
		(*user_info)->client_domain.len = strlen(client_domain);
	} else {
		free_user_info(user_info);
		return NT_STATUS_NO_MEMORY;
	}

	(*user_info)->wksta_name.str = strdup(wksta_name);
	if ((*user_info)->wksta_name.str) { 
		(*user_info)->wksta_name.len = strlen(wksta_name);
	} else {
		free_user_info(user_info);
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(5,("making blobs for %s's user_info struct\n", internal_username));

	if (lm_pwd)
		(*user_info)->lm_resp = data_blob(lm_pwd->data, lm_pwd->length);
	if (nt_pwd)
		(*user_info)->nt_resp = data_blob(nt_pwd->data, nt_pwd->length);
	if (lm_interactive_pwd)
		(*user_info)->lm_interactive_pwd = data_blob(lm_interactive_pwd->data, lm_interactive_pwd->length);
	if (nt_interactive_pwd)
		(*user_info)->nt_interactive_pwd = data_blob(nt_interactive_pwd->data, nt_interactive_pwd->length);

	if (plaintext)
		(*user_info)->plaintext_password = data_blob(plaintext->data, plaintext->length);

	(*user_info)->encrypted = encrypted;

	DEBUG(10,("made an %sencrypted user_info for %s (%s)\n", encrypted ? "":"un" , internal_username, smb_name));

	return NT_STATUS_OK;
}

/****************************************************************************
 Create an auth_usersupplied_data structure after appropriate mapping.
****************************************************************************/

NTSTATUS make_user_info_map(auth_usersupplied_info **user_info, 
			    const char *smb_name, 
			    const char *client_domain, 
			    const char *wksta_name, 
 			    DATA_BLOB *lm_pwd, DATA_BLOB *nt_pwd,
 			    DATA_BLOB *lm_interactive_pwd, DATA_BLOB *nt_interactive_pwd,
			    DATA_BLOB *plaintext, 
			    BOOL encrypted)
{
	const char *domain;
	fstring internal_username;
	fstrcpy(internal_username, smb_name);
	map_username(internal_username); 
	
	DEBUG(5, ("make_user_info_map: Mapping user [%s]\\[%s] from workstation [%s]\n",
	      client_domain, smb_name, wksta_name));
	
	/* don't allow "" as a domain, fixes a Win9X bug 
	   where it doens't supply a domain for logon script
	   'net use' commands.                                 */

	if ( *client_domain )
		domain = client_domain;
	else
		domain = lp_workgroup();

	/* do what win2k does.  Always map unknown domains to our own
	   and let the "passdb backend" handle unknown users. */

	if ( !is_trusted_domain(domain) && !strequal(domain, get_global_sam_name()) ) 
		domain = get_default_sam_name();
	
	/* we know that it is a trusted domain (and we are allowing them) or it is our domain */
	
	return make_user_info(user_info, smb_name, internal_username, 
			      client_domain, domain, wksta_name, 
			      lm_pwd, nt_pwd,
			      lm_interactive_pwd, nt_interactive_pwd,
			      plaintext, encrypted);
}

/****************************************************************************
 Create an auth_usersupplied_data, making the DATA_BLOBs here. 
 Decrypt and encrypt the passwords.
****************************************************************************/

BOOL make_user_info_netlogon_network(auth_usersupplied_info **user_info, 
				     const char *smb_name, 
				     const char *client_domain, 
				     const char *wksta_name, 
				     const uchar *lm_network_pwd, int lm_pwd_len,
				     const uchar *nt_network_pwd, int nt_pwd_len)
{
	BOOL ret;
	NTSTATUS nt_status;
	DATA_BLOB lm_blob = data_blob(lm_network_pwd, lm_pwd_len);
	DATA_BLOB nt_blob = data_blob(nt_network_pwd, nt_pwd_len);

	nt_status = make_user_info_map(user_info,
				       smb_name, client_domain, 
				       wksta_name, 
				       lm_pwd_len ? &lm_blob : NULL, 
				       nt_pwd_len ? &nt_blob : NULL,
				       NULL, NULL, NULL,
				       True);
	
	ret = NT_STATUS_IS_OK(nt_status) ? True : False;
		
	data_blob_free(&lm_blob);
	data_blob_free(&nt_blob);
	return ret;
}

/****************************************************************************
 Create an auth_usersupplied_data, making the DATA_BLOBs here. 
 Decrypt and encrypt the passwords.
****************************************************************************/

BOOL make_user_info_netlogon_interactive(auth_usersupplied_info **user_info, 
					 const char *smb_name, 
					 const char *client_domain, 
					 const char *wksta_name, 
					 const uchar chal[8], 
					 const uchar lm_interactive_pwd[16], 
					 const uchar nt_interactive_pwd[16], 
					 const uchar *dc_sess_key)
{
	char lm_pwd[16];
	char nt_pwd[16];
	unsigned char local_lm_response[24];
	unsigned char local_nt_response[24];
	unsigned char key[16];
	
	ZERO_STRUCT(key);
	memcpy(key, dc_sess_key, 8);
	
	if (lm_interactive_pwd) memcpy(lm_pwd, lm_interactive_pwd, sizeof(lm_pwd));
	if (nt_interactive_pwd) memcpy(nt_pwd, nt_interactive_pwd, sizeof(nt_pwd));
	
#ifdef DEBUG_PASSWORD
	DEBUG(100,("key:"));
	dump_data(100, (char *)key, sizeof(key));
	
	DEBUG(100,("lm owf password:"));
	dump_data(100, lm_pwd, sizeof(lm_pwd));
	
	DEBUG(100,("nt owf password:"));
	dump_data(100, nt_pwd, sizeof(nt_pwd));
#endif
	
	if (lm_interactive_pwd)
		SamOEMhash((uchar *)lm_pwd, key, sizeof(lm_pwd));
	
	if (nt_interactive_pwd)
		SamOEMhash((uchar *)nt_pwd, key, sizeof(nt_pwd));
	
#ifdef DEBUG_PASSWORD
	DEBUG(100,("decrypt of lm owf password:"));
	dump_data(100, lm_pwd, sizeof(lm_pwd));
	
	DEBUG(100,("decrypt of nt owf password:"));
	dump_data(100, nt_pwd, sizeof(nt_pwd));
#endif
	
	if (lm_interactive_pwd)
		SMBOWFencrypt((const unsigned char *)lm_pwd, chal, local_lm_response);

	if (nt_interactive_pwd)
		SMBOWFencrypt((const unsigned char *)nt_pwd, chal, local_nt_response);
	
	/* Password info paranoia */
	ZERO_STRUCT(key);

	{
		BOOL ret;
		NTSTATUS nt_status;
		DATA_BLOB local_lm_blob;
		DATA_BLOB local_nt_blob;

		DATA_BLOB lm_interactive_blob;
		DATA_BLOB nt_interactive_blob;
		
		if (lm_interactive_pwd) {
			local_lm_blob = data_blob(local_lm_response, sizeof(local_lm_response));
			lm_interactive_blob = data_blob(lm_pwd, sizeof(lm_pwd));
			ZERO_STRUCT(lm_pwd);
		}
		
		if (nt_interactive_pwd) {
			local_nt_blob = data_blob(local_nt_response, sizeof(local_nt_response));
			nt_interactive_blob = data_blob(nt_pwd, sizeof(nt_pwd));
			ZERO_STRUCT(nt_pwd);
		}

		nt_status = make_user_info_map(user_info, 
		                               smb_name, client_domain, 
		                               wksta_name, 
		                               lm_interactive_pwd ? &local_lm_blob : NULL,
		                               nt_interactive_pwd ? &local_nt_blob : NULL,
		                               lm_interactive_pwd ? &lm_interactive_blob : NULL,
		                               nt_interactive_pwd ? &nt_interactive_blob : NULL,
		                               NULL,
		                               True);

		ret = NT_STATUS_IS_OK(nt_status) ? True : False;
		data_blob_free(&local_lm_blob);
		data_blob_free(&local_nt_blob);
		data_blob_free(&lm_interactive_blob);
		data_blob_free(&nt_interactive_blob);
		return ret;
	}
}


/****************************************************************************
 Create an auth_usersupplied_data structure
****************************************************************************/

BOOL make_user_info_for_reply(auth_usersupplied_info **user_info, 
			      const char *smb_name, 
			      const char *client_domain,
			      const uint8 chal[8],
			      DATA_BLOB plaintext_password)
{

	DATA_BLOB local_lm_blob;
	DATA_BLOB local_nt_blob;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
			
	/*
	 * Not encrypted - do so.
	 */
	
	DEBUG(5,("make_user_info_for_reply: User passwords not in encrypted format.\n"));
	
	if (plaintext_password.data) {
		unsigned char local_lm_response[24];
		
#ifdef DEBUG_PASSWORD
		DEBUG(10,("Unencrypted password (len %d):\n",plaintext_password.length));
		dump_data(100, plaintext_password.data, plaintext_password.length);
#endif

		SMBencrypt( (const char *)plaintext_password.data, (const uchar*)chal, local_lm_response);
		local_lm_blob = data_blob(local_lm_response, 24);
		
		/* We can't do an NT hash here, as the password needs to be
		   case insensitive */
		local_nt_blob = data_blob(NULL, 0); 
		
	} else {
		local_lm_blob = data_blob(NULL, 0); 
		local_nt_blob = data_blob(NULL, 0); 
	}
	
	ret = make_user_info_map(user_info, smb_name,
	                         client_domain, 
	                         get_remote_machine_name(),
	                         local_lm_blob.data ? &local_lm_blob : NULL,
	                         local_nt_blob.data ? &local_nt_blob : NULL,
				 NULL, NULL,
	                         plaintext_password.data ? &plaintext_password : NULL, 
	                         False);
	
	data_blob_free(&local_lm_blob);
	return NT_STATUS_IS_OK(ret) ? True : False;
}

/****************************************************************************
 Create an auth_usersupplied_data structure
****************************************************************************/

NTSTATUS make_user_info_for_reply_enc(auth_usersupplied_info **user_info, 
                                      const char *smb_name,
                                      const char *client_domain, 
                                      DATA_BLOB lm_resp, DATA_BLOB nt_resp)
{
	return make_user_info_map(user_info, smb_name, 
				  client_domain, 
				  get_remote_machine_name(), 
				  lm_resp.data ? &lm_resp : NULL, 
				  nt_resp.data ? &nt_resp : NULL, 
				  NULL, NULL, NULL,
				  True);
}

/****************************************************************************
 Create a guest user_info blob, for anonymous authenticaion.
****************************************************************************/

BOOL make_user_info_guest(auth_usersupplied_info **user_info) 
{
	NTSTATUS nt_status;

	nt_status = make_user_info(user_info, 
				   "","", 
				   "","", 
				   "", 
				   NULL, NULL, 
				   NULL, NULL, 
				   NULL,
				   True);
			      
	return NT_STATUS_IS_OK(nt_status) ? True : False;
}

/****************************************************************************
 prints a NT_USER_TOKEN to debug output.
****************************************************************************/

void debug_nt_user_token(int dbg_class, int dbg_lev, NT_USER_TOKEN *token)
{
	fstring sid_str;
	size_t     i;
	
	if (!token) {
		DEBUGC(dbg_class, dbg_lev, ("NT user token: (NULL)\n"));
		return;
	}
	
	DEBUGC(dbg_class, dbg_lev, ("NT user token of user %s\n",
				    sid_to_string(sid_str, &token->user_sids[0]) ));
	DEBUGADDC(dbg_class, dbg_lev, ("contains %lu SIDs\n", (unsigned long)token->num_sids));
	for (i = 0; i < token->num_sids; i++)
		DEBUGADDC(dbg_class, dbg_lev, ("SID[%3lu]: %s\n", (unsigned long)i, 
					       sid_to_string(sid_str, &token->user_sids[i])));
}

/****************************************************************************
 prints a UNIX 'token' to debug output.
****************************************************************************/

void debug_unix_user_token(int dbg_class, int dbg_lev, uid_t uid, gid_t gid, int n_groups, gid_t *groups)
{
	int     i;
	DEBUGC(dbg_class, dbg_lev, ("UNIX token of user %ld\n", (long int)uid));

	DEBUGADDC(dbg_class, dbg_lev, ("Primary group is %ld and contains %i supplementary groups\n", (long int)gid, n_groups));
	for (i = 0; i < n_groups; i++)
		DEBUGADDC(dbg_class, dbg_lev, ("Group[%3i]: %ld\n", i, 
			(long int)groups[i]));
}

/****************************************************************************
 Create the SID list for this user.
****************************************************************************/

static NTSTATUS create_nt_user_token(const DOM_SID *user_sid, const DOM_SID *group_sid, 
				     int n_groupSIDs, DOM_SID *groupSIDs, 
				     BOOL is_guest, NT_USER_TOKEN **token)
{
	NTSTATUS       nt_status = NT_STATUS_OK;
	NT_USER_TOKEN *ptoken;
	int i;
	int sid_ndx;
	
	if ((ptoken = malloc( sizeof(NT_USER_TOKEN) ) ) == NULL) {
		DEBUG(0, ("create_nt_token: Out of memory allocating token\n"));
		nt_status = NT_STATUS_NO_MEMORY;
		return nt_status;
	}

	ZERO_STRUCTP(ptoken);

	ptoken->num_sids = n_groupSIDs + 5;

	if ((ptoken->user_sids = (DOM_SID *)malloc( sizeof(DOM_SID) * ptoken->num_sids )) == NULL) {
		DEBUG(0, ("create_nt_token: Out of memory allocating SIDs\n"));
		nt_status = NT_STATUS_NO_MEMORY;
		return nt_status;
	}
	
	memset((char*)ptoken->user_sids,0,sizeof(DOM_SID) * ptoken->num_sids);
	
	/*
	 * Note - user SID *MUST* be first in token !
	 * se_access_check depends on this.
	 *
	 * Primary group SID is second in token. Convention.
	 */

	sid_copy(&ptoken->user_sids[PRIMARY_USER_SID_INDEX], user_sid);
	if (group_sid)
		sid_copy(&ptoken->user_sids[PRIMARY_GROUP_SID_INDEX], group_sid);

	/*
	 * Finally add the "standard" SIDs.
	 * The only difference between guest and "anonymous" (which we
	 * don't really support) is the addition of Authenticated_Users.
	 */

	sid_copy(&ptoken->user_sids[2], &global_sid_World);
	sid_copy(&ptoken->user_sids[3], &global_sid_Network);

	if (is_guest)
		sid_copy(&ptoken->user_sids[4], &global_sid_Builtin_Guests);
	else
		sid_copy(&ptoken->user_sids[4], &global_sid_Authenticated_Users);
	
	sid_ndx = 5; /* next available spot */

	for (i = 0; i < n_groupSIDs; i++) {
		size_t check_sid_idx;
		for (check_sid_idx = 1; check_sid_idx < ptoken->num_sids; check_sid_idx++) {
			if (sid_equal(&ptoken->user_sids[check_sid_idx], 
				      &groupSIDs[i])) {
				break;
			}
		}
		
		if (check_sid_idx >= ptoken->num_sids) /* Not found already */ {
			sid_copy(&ptoken->user_sids[sid_ndx++], &groupSIDs[i]);
		} else {
			ptoken->num_sids--;
		}
	}
	
	debug_nt_user_token(DBGC_AUTH, 10, ptoken);
	
	*token = ptoken;

	return nt_status;
}

/****************************************************************************
 Create the SID list for this user.
****************************************************************************/

NT_USER_TOKEN *create_nt_token(uid_t uid, gid_t gid, int ngroups, gid_t *groups, BOOL is_guest)
{
	DOM_SID user_sid;
	DOM_SID group_sid;
	DOM_SID *group_sids;
	NT_USER_TOKEN *token;
	int i;

	if (!NT_STATUS_IS_OK(uid_to_sid(&user_sid, uid))) {
		return NULL;
	}
	if (!NT_STATUS_IS_OK(gid_to_sid(&group_sid, gid))) {
		return NULL;
	}

	group_sids = malloc(sizeof(DOM_SID) * ngroups);
	if (!group_sids) {
		DEBUG(0, ("create_nt_token: malloc() failed for DOM_SID list!\n"));
		return NULL;
	}

	for (i = 0; i < ngroups; i++) {
		if (!NT_STATUS_IS_OK(gid_to_sid(&(group_sids)[i], (groups)[i]))) {
			DEBUG(1, ("create_nt_token: failed to convert gid %ld to a sid!\n", (long int)groups[i]));
			SAFE_FREE(group_sids);
			return NULL;
		}
	}

	if (!NT_STATUS_IS_OK(create_nt_user_token(&user_sid, &group_sid, 
						  ngroups, group_sids, is_guest, &token))) {
		SAFE_FREE(group_sids);
		return NULL;
	}

	SAFE_FREE(group_sids);

	return token;
}

/******************************************************************************
 * this function returns the groups (SIDs) of the local SAM the user is in.
 * If this samba server is a DC of the domain the user belongs to, it returns 
 * both domain groups and local / builtin groups. If the user is in a trusted
 * domain, or samba is a member server of a domain, then this function returns
 * local and builtin groups the user is a member of.
 *
 * currently this is a hack, as there is no sam implementation that is capable
 * of groups.
 *
 * NOTE!! This function will fail if you pass in a winbind user without 
 * the domain   --jerry
 ******************************************************************************/

static NTSTATUS get_user_groups(const char *username, uid_t uid, gid_t gid,
                                int *n_groups, DOM_SID **groups, gid_t **unix_groups)
{
	int		n_unix_groups;
	int		i;

	*n_groups = 0;
	*groups   = NULL;
	
	/* Try winbind first */

	if ( strchr(username, *lp_winbind_separator()) ) {
		n_unix_groups = winbind_getgroups( username, unix_groups );

		DEBUG(10,("get_user_groups: winbind_getgroups(%s): result = %s\n", username, 
			  n_unix_groups == -1 ? "FAIL" : "SUCCESS"));
			  
		if ( n_unix_groups == -1 )
			return NT_STATUS_NO_SUCH_USER; /* what should this return value be? */	
	}
	else {
		/* fallback to getgrouplist() */
		
		n_unix_groups = groups_max();
		
		if ((*unix_groups = malloc( sizeof(gid_t) * n_unix_groups ) ) == NULL) {
			DEBUG(0, ("get_user_groups: Out of memory allocating unix group list\n"));
			return NT_STATUS_NO_MEMORY;
		}
	
		if (sys_getgrouplist(username, gid, *unix_groups, &n_unix_groups) == -1) {
		
			gid_t *groups_tmp;
			
			groups_tmp = Realloc(*unix_groups, sizeof(gid_t) * n_unix_groups);
			
			if (!groups_tmp) {
				SAFE_FREE(*unix_groups);
				return NT_STATUS_NO_MEMORY;
			}
			*unix_groups = groups_tmp;

			if (sys_getgrouplist(username, gid, *unix_groups, &n_unix_groups) == -1) {
				DEBUG(0, ("get_user_groups: failed to get the unix group list\n"));
				SAFE_FREE(*unix_groups);
				return NT_STATUS_NO_SUCH_USER; /* what should this return value be? */
			}
		}
	}

	debug_unix_user_token(DBGC_CLASS, 5, uid, gid, n_unix_groups, *unix_groups);
	
	/* now setup the space for storing the SIDS */
	
	if (n_unix_groups > 0) {
	
		*groups   = malloc(sizeof(DOM_SID) * n_unix_groups);
		
		if (!*groups) {
			DEBUG(0, ("get_user_group: malloc() failed for DOM_SID list!\n"));
			SAFE_FREE(*unix_groups);
			return NT_STATUS_NO_MEMORY;
		}
	}

	*n_groups = n_unix_groups;

	for (i = 0; i < *n_groups; i++) {
		if (!NT_STATUS_IS_OK(gid_to_sid(&(*groups)[i], (*unix_groups)[i]))) {
			DEBUG(1, ("get_user_groups: failed to convert gid %ld to a sid!\n", 
				(long int)(*unix_groups)[i+1]));
			SAFE_FREE(*groups);
			SAFE_FREE(*unix_groups);
			return NT_STATUS_NO_SUCH_USER;
		}
	}
		     
	return NT_STATUS_OK;
}

/***************************************************************************
 Make a user_info struct
***************************************************************************/

static NTSTATUS make_server_info(auth_serversupplied_info **server_info)
{
	*server_info = malloc(sizeof(**server_info));
	if (!*server_info) {
		DEBUG(0,("make_server_info: malloc failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}
	ZERO_STRUCTP(*server_info);

	/* Initialise the uid and gid values to something non-zero
	   which may save us from giving away root access if there
	   is a bug in allocating these fields. */

	(*server_info)->uid = -1;
	(*server_info)->gid = -1;

	return NT_STATUS_OK;
}

/***************************************************************************
Fill a server_info struct from a SAM_ACCOUNT with their groups
***************************************************************************/

static NTSTATUS add_user_groups(auth_serversupplied_info **server_info, 
				const char * unix_username,
				SAM_ACCOUNT *sampass,
				uid_t uid, gid_t gid)
{
	NTSTATUS nt_status;
	const DOM_SID *user_sid = pdb_get_user_sid(sampass);
	const DOM_SID *group_sid = pdb_get_group_sid(sampass);
	int       n_groupSIDs = 0;
	DOM_SID  *groupSIDs   = NULL;
	gid_t    *unix_groups = NULL;
	NT_USER_TOKEN *token;
	BOOL is_guest;
	uint32 rid;

	nt_status = get_user_groups(unix_username, uid, gid, 
		&n_groupSIDs, &groupSIDs, &unix_groups);
		
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(4,("get_user_groups_from_local_sam failed\n"));
		free_server_info(server_info);
		return nt_status;
	}
	
	is_guest = (sid_peek_rid(user_sid, &rid) && rid == DOMAIN_USER_RID_GUEST);

	if (!NT_STATUS_IS_OK(nt_status = create_nt_user_token(user_sid, group_sid,
							      n_groupSIDs, groupSIDs, is_guest, 
							      &token)))
	{
		DEBUG(4,("create_nt_user_token failed\n"));
		SAFE_FREE(groupSIDs);
		SAFE_FREE(unix_groups);
		free_server_info(server_info);
		return nt_status;
	}
	
	SAFE_FREE(groupSIDs);

	(*server_info)->n_groups = n_groupSIDs;
	(*server_info)->groups = unix_groups;
	(*server_info)->ptok = token;

	return nt_status;
}

/***************************************************************************
 Make (and fill) a user_info struct from a SAM_ACCOUNT
***************************************************************************/

NTSTATUS make_server_info_sam(auth_serversupplied_info **server_info, 
			      SAM_ACCOUNT *sampass)
{
	NTSTATUS nt_status;
	struct passwd *pwd;

	if (!NT_STATUS_IS_OK(nt_status = make_server_info(server_info)))
		return nt_status;

	(*server_info)->sam_account    = sampass;

	if ( !(pwd = getpwnam_alloc(pdb_get_username(sampass))) )  {
		DEBUG(1, ("User %s in passdb, but getpwnam() fails!\n",
			  pdb_get_username(sampass)));
		free_server_info(server_info);
		return NT_STATUS_NO_SUCH_USER;
	}
	(*server_info)->unix_name = smb_xstrdup(pwd->pw_name);
	(*server_info)->gid = pwd->pw_gid;
	(*server_info)->uid = pwd->pw_uid;
	
	passwd_free(&pwd);

	if (!NT_STATUS_IS_OK(nt_status = add_user_groups(server_info, pdb_get_username(sampass), 
							 sampass,
							 (*server_info)->uid, 
							 (*server_info)->gid))) 
	{
		free_server_info(server_info);
		return nt_status;
	}

	(*server_info)->sam_fill_level = SAM_FILL_ALL;
	DEBUG(5,("make_server_info_sam: made server info for user %s -> %s\n",
		 pdb_get_username(sampass),
		 (*server_info)->unix_name));

	return nt_status;
}

/***************************************************************************
 Make (and fill) a user_info struct from a 'struct passwd' by conversion 
 to a SAM_ACCOUNT
***************************************************************************/

NTSTATUS make_server_info_pw(auth_serversupplied_info **server_info, 
                             char *unix_username,
			     struct passwd *pwd)
{
	NTSTATUS nt_status;
	SAM_ACCOUNT *sampass = NULL;
	if (!NT_STATUS_IS_OK(nt_status = pdb_init_sam_pw(&sampass, pwd))) {		
		return nt_status;
	}
	if (!NT_STATUS_IS_OK(nt_status = make_server_info(server_info))) {
		return nt_status;
	}

	(*server_info)->sam_account    = sampass;

	if (!NT_STATUS_IS_OK(nt_status = add_user_groups(server_info, unix_username,
		sampass, pwd->pw_uid, pwd->pw_gid))) 
	{
		return nt_status;
	}

	(*server_info)->unix_name = smb_xstrdup(unix_username);

	(*server_info)->sam_fill_level = SAM_FILL_ALL;
	(*server_info)->uid = pwd->pw_uid;
	(*server_info)->gid = pwd->pw_gid;
	return nt_status;
}

/***************************************************************************
 Make (and fill) a user_info struct for a guest login.
***************************************************************************/

NTSTATUS make_server_info_guest(auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status;
	SAM_ACCOUNT *sampass = NULL;
	DOM_SID guest_sid;

	if (!NT_STATUS_IS_OK(nt_status = pdb_init_sam(&sampass))) {
		return nt_status;
	}

	sid_copy(&guest_sid, get_global_sam_sid());
	sid_append_rid(&guest_sid, DOMAIN_USER_RID_GUEST);

	become_root();
	if (!pdb_getsampwsid(sampass, &guest_sid)) {
		unbecome_root();
		return NT_STATUS_NO_SUCH_USER;
	}
	unbecome_root();

	nt_status = make_server_info_sam(server_info, sampass);

	if (NT_STATUS_IS_OK(nt_status)) {
		static const char zeros[16];
		(*server_info)->guest = True;
		
		/* annoying, but the Guest really does have a session key, 
		   and it is all zeros! */
		(*server_info)->user_session_key = data_blob(zeros, sizeof(zeros));
		(*server_info)->lm_session_key = data_blob(zeros, sizeof(zeros));
	}

	return nt_status;
}

/***************************************************************************
 Purely internal function for make_server_info_info3
 Fill the sam account from getpwnam
***************************************************************************/
static NTSTATUS fill_sam_account(TALLOC_CTX *mem_ctx, 
				 const char *domain,
				 const char *username,
				 char **found_username,
				 uid_t *uid, gid_t *gid,
				 SAM_ACCOUNT **sam_account)
{
	fstring dom_user;
	fstring real_username;
	struct passwd *passwd;

	fstr_sprintf(dom_user, "%s%s%s", domain, lp_winbind_separator(), 
		username);

	/* get the passwd struct but don't create the user if he/she 
	   does not exist.  We were explicitly called from a following
	   a winbindd authentication request so we should assume that 
	   nss_winbindd is working */

	if ( !(passwd = smb_getpwnam( dom_user, real_username, True )) )
		return NT_STATUS_NO_SUCH_USER;

	*uid = passwd->pw_uid;
	*gid = passwd->pw_gid;

	/* This is pointless -- there is no suport for differing 
	   unix and windows names.  Make sure to always store the 
	   one we actually looked up and succeeded. Have I mentioned
	   why I hate the 'winbind use default domain' parameter?   
	                                 --jerry              */
	   
	*found_username = talloc_strdup( mem_ctx, real_username );
	
	DEBUG(5,("fill_sam_account: located username was [%s]\n",
		*found_username));

	return pdb_init_sam_pw(sam_account, passwd);
}

/****************************************************************************
 Wrapper to allow the getpwnam() call to strip the domain name and 
 try again in case a local UNIX user is already there.  Also run through 
 the username if we fallback to the username only.
 ****************************************************************************/
 
struct passwd *smb_getpwnam( char *domuser, fstring save_username, BOOL create )
{
	struct passwd *pw = NULL;
	char *p;
	fstring mapped_username;
	fstring strip_username;
	
	/* we only save a copy of the username it has been mangled 
	   by winbindd use default domain */
	   
	save_username[0] = '\0';
	
	/* save a local copy of the username and run it through the 
	   username map */
	   
	fstrcpy( mapped_username, domuser );
	map_username( mapped_username );	
	
	p = strchr_m( mapped_username, *lp_winbind_separator() );
	
	/* code for a DOMAIN\user string */
	
	if ( p ) {
		pw = Get_Pwnam( domuser );
		if ( pw ) {	
			/* make sure we get the case of the username correct */
			/* work around 'winbind use default domain = yes' */

			if ( !strchr_m( pw->pw_name, *lp_winbind_separator() ) ) {
				char *domain;
				
				domain = mapped_username;
				*p = '\0';
				fstr_sprintf(save_username, "%s%c%s", domain, *lp_winbind_separator(), pw->pw_name);
			}
			else
				fstrcpy( save_username, pw->pw_name );

			/* whew -- done! */		
			return pw;
		}

		/* setup for lookup of just the username */
		/* remember that p and mapped_username are overlapping memory */

		p++;
		fstrcpy( strip_username, p );
		fstrcpy( mapped_username, strip_username );
	}
	
	/* just lookup a plain username */
	
	pw = Get_Pwnam(mapped_username);
		
	/* Create local user if requested. */
	
	if ( !pw && create ) {
		/* Don't add a machine account. */
		if (mapped_username[strlen(mapped_username)-1] == '$')
			return NULL;

		auth_add_user_script(NULL, mapped_username);
		pw = Get_Pwnam(mapped_username);
	}
	
	/* one last check for a valid passwd struct */
	
	if ( pw )
		fstrcpy( save_username, pw->pw_name );

	return pw;
}

/***************************************************************************
 Make a server_info struct from the info3 returned by a domain logon 
***************************************************************************/

NTSTATUS make_server_info_info3(TALLOC_CTX *mem_ctx, 
				const char *internal_username,
				const char *sent_nt_username,
				const char *domain,
				auth_serversupplied_info **server_info, 
				NET_USER_INFO_3 *info3) 
{
	static const char zeros[16];

	NTSTATUS nt_status = NT_STATUS_OK;
	char *found_username;
	const char *nt_domain;
	const char *nt_username;

	SAM_ACCOUNT *sam_account = NULL;
	DOM_SID user_sid;
	DOM_SID group_sid;

	uid_t uid;
	gid_t gid;

	int n_lgroupSIDs;
	DOM_SID *lgroupSIDs   = NULL;

	gid_t *unix_groups = NULL;
	NT_USER_TOKEN *token;

	DOM_SID *all_group_SIDs;
	size_t i;

	/* 
	   Here is where we should check the list of
	   trusted domains, and verify that the SID 
	   matches.
	*/

	sid_copy(&user_sid, &info3->dom_sid.sid);
	if (!sid_append_rid(&user_sid, info3->user_rid)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	sid_copy(&group_sid, &info3->dom_sid.sid);
	if (!sid_append_rid(&group_sid, info3->group_rid)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!(nt_username = unistr2_tdup(mem_ctx, &(info3->uni_user_name)))) {
		/* If the server didn't give us one, just use the one we sent them */
		nt_username = sent_nt_username;
	}

	if (!(nt_domain = unistr2_tdup(mem_ctx, &(info3->uni_logon_dom)))) {
		/* If the server didn't give us one, just use the one we sent them */
		nt_domain = domain;
	}
	
	/* try to fill the SAM account..  If getpwnam() fails, then try the 
	   add user script (2.2.x behavior) */
	   
	nt_status = fill_sam_account(mem_ctx, nt_domain, internal_username,
		&found_username, &uid, &gid, &sam_account);

	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_SUCH_USER)) {
		DEBUG(3,("User %s does not exist, trying to add it\n", 
			internal_username));
		auth_add_user_script(nt_domain, internal_username);
		nt_status = fill_sam_account(mem_ctx, nt_domain, 
			internal_username, &found_username,
			&uid, &gid, &sam_account);
	}
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("make_server_info_info3: pdb_init_sam failed!\n"));
		return nt_status;
	}
		
	if (!pdb_set_nt_username(sam_account, nt_username, PDB_CHANGED)) {
		pdb_free_sam(&sam_account);
		return NT_STATUS_NO_MEMORY;
	}

	if (!pdb_set_username(sam_account, nt_username, PDB_CHANGED)) {
		pdb_free_sam(&sam_account);
		return NT_STATUS_NO_MEMORY;
	}

	if (!pdb_set_domain(sam_account, nt_domain, PDB_CHANGED)) {
		pdb_free_sam(&sam_account);
		return NT_STATUS_NO_MEMORY;
	}

	if (!pdb_set_user_sid(sam_account, &user_sid, PDB_CHANGED)) {
		pdb_free_sam(&sam_account);
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!pdb_set_group_sid(sam_account, &group_sid, PDB_CHANGED)) {
		pdb_free_sam(&sam_account);
		return NT_STATUS_UNSUCCESSFUL;
	}
		
	if (!pdb_set_fullname(sam_account, unistr2_static(&(info3->uni_full_name)), 
			      PDB_CHANGED)) {
		pdb_free_sam(&sam_account);
		return NT_STATUS_NO_MEMORY;
	}

	if (!pdb_set_logon_script(sam_account, unistr2_static(&(info3->uni_logon_script)), PDB_CHANGED)) {
		pdb_free_sam(&sam_account);
		return NT_STATUS_NO_MEMORY;
	}

	if (!pdb_set_profile_path(sam_account, unistr2_static(&(info3->uni_profile_path)), PDB_CHANGED)) {
		pdb_free_sam(&sam_account);
		return NT_STATUS_NO_MEMORY;
	}

	if (!pdb_set_homedir(sam_account, unistr2_static(&(info3->uni_home_dir)), PDB_CHANGED)) {
		pdb_free_sam(&sam_account);
		return NT_STATUS_NO_MEMORY;
	}

	if (!pdb_set_dir_drive(sam_account, unistr2_static(&(info3->uni_dir_drive)), PDB_CHANGED)) {
		pdb_free_sam(&sam_account);
		return NT_STATUS_NO_MEMORY;
	}

	if (!NT_STATUS_IS_OK(nt_status = make_server_info(server_info))) {
		DEBUG(4, ("make_server_info failed!\n"));
		pdb_free_sam(&sam_account);
		return nt_status;
	}

	/* save this here to _net_sam_logon() doesn't fail (it assumes a 
	   valid SAM_ACCOUNT) */
		   
	(*server_info)->sam_account = sam_account;

	(*server_info)->unix_name = smb_xstrdup(found_username);

	/* Fill in the unix info we found on the way */

	(*server_info)->sam_fill_level = SAM_FILL_ALL;
	(*server_info)->uid = uid;
	(*server_info)->gid = gid;

	/* Store the user group information in the server_info 
	   returned to the caller. */
	
	nt_status = get_user_groups((*server_info)->unix_name,
		uid, gid, &n_lgroupSIDs, &lgroupSIDs, &unix_groups);
		
	if ( !NT_STATUS_IS_OK(nt_status) ) {
		DEBUG(4,("get_user_groups failed\n"));
		return nt_status;
	}

	(*server_info)->groups = unix_groups;
	(*server_info)->n_groups = n_lgroupSIDs;
	
	/* Create a 'combined' list of all SIDs we might want in the SD */
	
	all_group_SIDs = malloc(sizeof(DOM_SID) * (info3->num_groups2 +info3->num_other_sids));
	
	if (!all_group_SIDs) {
		DEBUG(0, ("malloc() failed for DOM_SID list!\n"));
		SAFE_FREE(lgroupSIDs);
		free_server_info(server_info);
		return NT_STATUS_NO_MEMORY;
	}

#if 0 	/* JERRY -- no such thing as local groups in current code */
	/* Copy the 'local' sids */
	memcpy(all_group_SIDs, lgroupSIDs, sizeof(DOM_SID) * n_lgroupSIDs);
	SAFE_FREE(lgroupSIDs);
#endif

	/* and create (by appending rids) the 'domain' sids */
	
	for (i = 0; i < info3->num_groups2; i++) {
	
		sid_copy(&all_group_SIDs[i], &(info3->dom_sid.sid));
		
		if (!sid_append_rid(&all_group_SIDs[i], info3->gids[i].g_rid)) {
		
			nt_status = NT_STATUS_INVALID_PARAMETER;
			
			DEBUG(3,("could not append additional group rid 0x%x\n",
				info3->gids[i].g_rid));			
				
			SAFE_FREE(lgroupSIDs);
			free_server_info(server_info);
			
			return nt_status;
			
		}
	}

	/* Copy 'other' sids.  We need to do sid filtering here to
 	   prevent possible elevation of privileges.  See:

           http://www.microsoft.com/windows2000/techinfo/administration/security/sidfilter.asp
         */

	for (i = 0; i < info3->num_other_sids; i++) {
		sid_copy(&all_group_SIDs[info3->num_groups2 + i],
			 &info3->other_sids[i].sid);
	}
	
	/* Where are the 'global' sids... */

	/* can the user be guest? if yes, where is it stored? */
	
	nt_status = create_nt_user_token(&user_sid, &group_sid,
		info3->num_groups2 + info3->num_other_sids,
		all_group_SIDs, False, &token);
		
	if ( !NT_STATUS_IS_OK(nt_status) ) {
		DEBUG(4,("create_nt_user_token failed\n"));
		SAFE_FREE(all_group_SIDs);
		free_server_info(server_info);
		return nt_status;
	}

	(*server_info)->ptok = token; 

	SAFE_FREE(all_group_SIDs);

	/* ensure we are never given NULL session keys */
	
	if (memcmp(info3->user_sess_key, zeros, sizeof(zeros)) == 0) {
		(*server_info)->user_session_key = data_blob(NULL, 0);
	} else {
		(*server_info)->user_session_key = data_blob(info3->user_sess_key, sizeof(info3->user_sess_key));
	}

	if (memcmp(info3->padding, zeros, sizeof(zeros)) == 0) {
		(*server_info)->lm_session_key = data_blob(NULL, 0);
	} else {
		(*server_info)->lm_session_key = data_blob(info3->padding, 16);
	}
	return NT_STATUS_OK;
}

/***************************************************************************
 Free a user_info struct
***************************************************************************/

void free_user_info(auth_usersupplied_info **user_info)
{
	DEBUG(5,("attempting to free (and zero) a user_info structure\n"));
	if (*user_info != NULL) {
		if ((*user_info)->smb_name.str) {
			DEBUG(10,("structure was created for %s\n", (*user_info)->smb_name.str));
		}
		SAFE_FREE((*user_info)->smb_name.str);
		SAFE_FREE((*user_info)->internal_username.str);
		SAFE_FREE((*user_info)->client_domain.str);
		SAFE_FREE((*user_info)->domain.str);
		SAFE_FREE((*user_info)->wksta_name.str);
		data_blob_free(&(*user_info)->lm_resp);
		data_blob_free(&(*user_info)->nt_resp);
		data_blob_clear_free(&(*user_info)->lm_interactive_pwd);
		data_blob_clear_free(&(*user_info)->nt_interactive_pwd);
		data_blob_clear_free(&(*user_info)->plaintext_password);
		ZERO_STRUCT(**user_info);
	}
	SAFE_FREE(*user_info);
}

/***************************************************************************
 Clear out a server_info struct that has been allocated
***************************************************************************/

void free_server_info(auth_serversupplied_info **server_info)
{
	DEBUG(5,("attempting to free (and zero) a server_info structure\n"));
	if (*server_info != NULL) {
		pdb_free_sam(&(*server_info)->sam_account);

		/* call pam_end here, unless we know we are keeping it */
		delete_nt_token( &(*server_info)->ptok );
		SAFE_FREE((*server_info)->groups);
		SAFE_FREE((*server_info)->unix_name);
		data_blob_free(&(*server_info)->lm_session_key);
		data_blob_free(&(*server_info)->user_session_key);
		ZERO_STRUCT(**server_info);
	}
	SAFE_FREE(*server_info);
}

/***************************************************************************
 Make an auth_methods struct
***************************************************************************/

BOOL make_auth_methods(struct auth_context *auth_context, auth_methods **auth_method) 
{
	if (!auth_context) {
		smb_panic("no auth_context supplied to make_auth_methods()!\n");
	}

	if (!auth_method) {
		smb_panic("make_auth_methods: pointer to auth_method pointer is NULL!\n");
	}

	*auth_method = talloc(auth_context->mem_ctx, sizeof(**auth_method));
	if (!*auth_method) {
		DEBUG(0,("make_auth_method: malloc failed!\n"));
		return False;
	}
	ZERO_STRUCTP(*auth_method);
	
	return True;
}

/****************************************************************************
 Delete a SID token.
****************************************************************************/

void delete_nt_token(NT_USER_TOKEN **pptoken)
{
    if (*pptoken) {
	    NT_USER_TOKEN *ptoken = *pptoken;
	    SAFE_FREE( ptoken->user_sids );
	    ZERO_STRUCTP(ptoken);
    }
    SAFE_FREE(*pptoken);
}

/****************************************************************************
 Duplicate a SID token.
****************************************************************************/

NT_USER_TOKEN *dup_nt_token(NT_USER_TOKEN *ptoken)
{
	NT_USER_TOKEN *token;

	if (!ptoken)
		return NULL;

    if ((token = (NT_USER_TOKEN *)malloc( sizeof(NT_USER_TOKEN) ) ) == NULL)
        return NULL;

    ZERO_STRUCTP(token);

    if ((token->user_sids = (DOM_SID *)memdup( ptoken->user_sids, sizeof(DOM_SID) * ptoken->num_sids )) == NULL) {
        SAFE_FREE(token);
        return NULL;
    }

    token->num_sids = ptoken->num_sids;

	return token;
}

/**
 * Verify whether or not given domain is trusted.
 *
 * @param domain_name name of the domain to be verified
 * @return true if domain is one of the trusted once or
 *         false if otherwise
 **/

BOOL is_trusted_domain(const char* dom_name)
{
	DOM_SID trustdom_sid;
	char *pass = NULL;
	time_t lct;
	BOOL ret;

	/* no trusted domains for a standalone server */

	if ( lp_server_role() == ROLE_STANDALONE )
		return False;

	/* if we are a DC, then check for a direct trust relationships */

	if (lp_server_role() == ROLE_DOMAIN_BDC || lp_server_role() == ROLE_DOMAIN_PDC) {
		become_root();
		ret = secrets_fetch_trusted_domain_password(dom_name, &pass, &trustdom_sid, &lct);
		unbecome_root();
		SAFE_FREE(pass);
		if (ret)
			return True;
	}
	else {
		/* if winbindd is not up and we are a domain member) then we need to update the
		   trustdom_cache ourselves */

		if ( !winbind_ping() )
			update_trustdom_cache();
	}

	/* now the trustdom cache should be available a DC could still
	 * have a transitive trust so fall back to the cache of trusted
	 * domains (like a domain member would use  */

	if ( trustdom_cache_fetch(dom_name, &trustdom_sid) ) {
		return True;
	}

	return False;
}

