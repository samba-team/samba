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
			      const uint8_t chal[8],
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
	TALLOC_CTX *mem_ctx;

	size_t     i;
	
	if (!token) {
		DEBUGC(dbg_class, dbg_lev, ("NT user token: (NULL)\n"));
		return;
	}
	
	mem_ctx = talloc_init("debug_nt_user_token()");
	if (!mem_ctx) {
		return;
	}

	DEBUGC(dbg_class, dbg_lev, ("NT user token of user %s\n",
				    dom_sid_string(mem_ctx, token->user_sids[0]) ));
	DEBUGADDC(dbg_class, dbg_lev, ("contains %lu SIDs\n", (unsigned long)token->num_sids));
	for (i = 0; i < token->num_sids; i++)
		DEBUGADDC(dbg_class, dbg_lev, ("SID[%3lu]: %s\n", (unsigned long)i, 
					       dom_sid_string(mem_ctx, token->user_sids[i])));

	talloc_destroy(mem_ctx);
}

/****************************************************************************
 Create the SID list for this user.
****************************************************************************/

NTSTATUS create_nt_user_token(TALLOC_CTX *mem_ctx, 
			      struct dom_sid *user_sid, struct dom_sid *group_sid, 
			      int n_groupSIDs, struct dom_sid **groupSIDs, 
			      BOOL is_guest, struct nt_user_token **token)
{
	NTSTATUS       nt_status = NT_STATUS_OK;
	struct nt_user_token *ptoken;
	int i;
	int sid_ndx;
	
	if (!(ptoken = talloc_p(mem_ctx, struct nt_user_token))) {
		DEBUG(0, ("create_nt_token: Out of memory allocating token\n"));
		nt_status = NT_STATUS_NO_MEMORY;
		return nt_status;
	}

	ptoken->num_sids = 0;

	if (!(ptoken->user_sids = talloc_array_p(mem_ctx, struct dom_sid*, n_groupSIDs + 5))) {
		DEBUG(0, ("create_nt_token: Out of memory allocating SIDs\n"));
		nt_status = NT_STATUS_NO_MEMORY;
		return nt_status;
	}
	
	/*
	 * Note - user SID *MUST* be first in token !
	 * se_access_check depends on this.
	 *
	 * Primary group SID is second in token. Convention.
	 */

	ptoken->user_sids[PRIMARY_USER_SID_INDEX] = user_sid;
	ptoken->num_sids++;
	ptoken->user_sids[PRIMARY_GROUP_SID_INDEX] = group_sid;
	ptoken->num_sids++;

	/*
	 * Finally add the "standard" SIDs.
	 * The only difference between guest and "anonymous" (which we
	 * don't really support) is the addition of Authenticated_Users.
	 */
	ptoken->user_sids[2] = dom_sid_parse_talloc(mem_ctx, SID_WORLD);
	ptoken->user_sids[3] = dom_sid_parse_talloc(mem_ctx, SID_NETWORK);

	if (is_guest) {
		ptoken->user_sids[4] = dom_sid_parse_talloc(mem_ctx, SID_BUILTIN_GUESTS);
		ptoken->num_sids++;
	} else {
		ptoken->user_sids[4] = dom_sid_parse_talloc(mem_ctx, SID_AUTHENTICATED_USERS);
		ptoken->num_sids++;
	}

	sid_ndx = 5; /* next available spot */

	for (i = 0; i < n_groupSIDs; i++) {
		size_t check_sid_idx;
		for (check_sid_idx = 1; check_sid_idx < ptoken->num_sids; check_sid_idx++) {
			if (sid_equal(ptoken->user_sids[check_sid_idx], 
				      groupSIDs[i])) {
				break;
			}
		}
		
		if (check_sid_idx >= ptoken->num_sids) /* Not found already */ {
			ptoken->user_sids[sid_ndx++] = groupSIDs[i];
			ptoken->num_sids++;
		}
	}
	
	debug_nt_user_token(DBGC_AUTH, 10, ptoken);
	
	*token = ptoken;

	return nt_status;
}

/***************************************************************************
 Make a user_info struct
***************************************************************************/

NTSTATUS make_server_info(auth_serversupplied_info **server_info, const char *username)
{
	TALLOC_CTX *mem_ctx = talloc_init("auth subsystem: server_info for %s", username);
	*server_info = talloc_p(mem_ctx, auth_serversupplied_info);
	if (!*server_info) {
		DEBUG(0,("make_server_info: malloc failed!\n"));
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	(*server_info)->mem_ctx = mem_ctx;
	
	return NT_STATUS_OK;
}

/***************************************************************************
 Make (and fill) a user_info struct for a guest login.
***************************************************************************/
NTSTATUS make_server_info_guest(auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status;
	static const char zeros[16];
	struct dom_sid *sid_Anonymous;
	struct dom_sid *sid_Builtin_Guests;

	nt_status = make_server_info(server_info, "");

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}
	
	(*server_info)->guest = True;

	sid_Anonymous = dom_sid_parse_talloc((*server_info)->mem_ctx, SID_ANONYMOUS);
	sid_Builtin_Guests = dom_sid_parse_talloc((*server_info)->mem_ctx, SID_BUILTIN_GUESTS);
	
	if (!NT_STATUS_IS_OK(nt_status = create_nt_user_token((*server_info)->mem_ctx, 
							      sid_Anonymous, sid_Builtin_Guests,
							      0, NULL, 
							      True, &(*server_info)->ptok))) {
		DEBUG(1,("check_sam_security: create_nt_user_token failed with '%s'\n", nt_errstr(nt_status)));
		free_server_info(server_info);
		return nt_status;
	}
	
	/* annoying, but the Guest really does have a session key, 
	   and it is all zeros! */
	(*server_info)->user_session_key = data_blob(zeros, sizeof(zeros));
	(*server_info)->lm_session_key = data_blob(zeros, sizeof(zeros));

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
	DEBUG(5,("attempting to free a server_info structure\n"));
	if (!*server_info) {
		talloc_destroy((*server_info)->mem_ctx);
	}
	*server_info = NULL;
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



