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
	
	DEBUG(5, ("make_user_info_map: Mapping user [%s]\\[%s] from workstation [%s]\n",
	      client_domain, smb_name, wksta_name));
	
	/* don't allow "" as a domain, fixes a Win9X bug 
	   where it doens't supply a domain for logon script
	   'net use' commands.                                 */

	if ( *client_domain )
		domain = client_domain;
	else
		domain = lp_workgroup();

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
	                         sub_get_remote_machine(),
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
				  sub_get_remote_machine(), 
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

struct nt_user_token *create_nt_token(uid_t uid, gid_t gid, int ngroups, gid_t *groups, BOOL is_guest)
{
	DOM_SID user_sid;
	DOM_SID group_sid;
	DOM_SID *group_sids;
	NT_USER_TOKEN *token;
	int i;

	if (!uid_to_sid(&user_sid, uid)) {
		return NULL;
	}
	if (!gid_to_sid(&group_sid, gid)) {
		return NULL;
	}

	group_sids = malloc(sizeof(DOM_SID) * ngroups);
	if (!group_sids) {
		DEBUG(0, ("create_nt_token: malloc() failed for DOM_SID list!\n"));
		return NULL;
	}

	for (i = 0; i < ngroups; i++) {
		if (!gid_to_sid(&(group_sids)[i], (groups)[i])) {
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

/***************************************************************************
 Make a user_info struct
***************************************************************************/

static NTSTATUS make_server_info(auth_serversupplied_info **server_info, SAM_ACCOUNT *sampass)
{
	*server_info = malloc(sizeof(**server_info));
	if (!*server_info) {
		DEBUG(0,("make_server_info: malloc failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}
	ZERO_STRUCTP(*server_info);

	return NT_STATUS_OK;
}

/***************************************************************************
 Make (and fill) a user_info struct from a SAM_ACCOUNT
***************************************************************************/

NTSTATUS make_server_info_sam(auth_serversupplied_info **server_info, 
			      SAM_ACCOUNT *sampass)
{
	NTSTATUS nt_status = NT_STATUS_OK;
	const DOM_SID *user_sid = pdb_get_user_sid(sampass);
	const DOM_SID *group_sid = pdb_get_group_sid(sampass);
	NT_USER_TOKEN *token;
	BOOL is_guest;
	uint32 rid;

	if (!NT_STATUS_IS_OK(nt_status = make_server_info(server_info, sampass))) {
		return nt_status;
	}
	
	is_guest = (sid_peek_rid(user_sid, &rid) && rid == DOMAIN_USER_RID_GUEST);

	if (!NT_STATUS_IS_OK(nt_status = create_nt_user_token(user_sid, group_sid,
							      0, NULL, is_guest, 
							      &token)))
	{
		DEBUG(4,("create_nt_user_token failed\n"));
		free_server_info(server_info);
		return nt_status;
	}

	(*server_info)->ptok = token;
	
	return nt_status;
}

/***************************************************************************
 Make (and fill) a user_info struct from a 'struct passwd' by conversion 
 to a SAM_ACCOUNT
***************************************************************************/

NTSTATUS make_server_info_pw(auth_serversupplied_info **server_info, const struct passwd *pwd)
{
	NTSTATUS nt_status;
	SAM_ACCOUNT *sampass = NULL;
	if (!NT_STATUS_IS_OK(nt_status = pdb_init_sam_pw(&sampass, pwd))) {		
		return nt_status;
	}
	return make_server_info_sam(server_info, sampass);
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

		/* call pam_end here, unless we know we are keeping it */
		delete_nt_token( &(*server_info)->ptok );
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

struct nt_user_token *dup_nt_token(NT_USER_TOKEN *ptoken)
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
 * Squash an NT_STATUS in line with security requirements.
 * In an attempt to avoid giving the whole game away when users
 * are authenticating, NT replaces both NT_STATUS_NO_SUCH_USER and 
 * NT_STATUS_WRONG_PASSWORD with NT_STATUS_LOGON_FAILURE in certain situations 
 * (session setups in particular).
 *
 * @param nt_status NTSTATUS input for squashing.
 * @return the 'squashed' nt_status
 **/

NTSTATUS nt_status_squash(NTSTATUS nt_status)
{
	if NT_STATUS_IS_OK(nt_status) {
		return nt_status;		
	} else if NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_SUCH_USER) {
		/* Match WinXP and don't give the game away */
		return NT_STATUS_LOGON_FAILURE;
		
	} else if NT_STATUS_EQUAL(nt_status, NT_STATUS_WRONG_PASSWORD) {
		/* Match WinXP and don't give the game away */
		return NT_STATUS_LOGON_FAILURE;
	} else {
		return nt_status;
	}  
}



