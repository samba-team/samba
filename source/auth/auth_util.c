/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Authentication utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Andrew Bartlett 2001
   Copyright (C) Jeremy Allison 2000-2001

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

extern fstring remote_machine;
extern pstring global_myname;

/****************************************************************************
 Create a UNIX user on demand.
****************************************************************************/

static int smb_create_user(const char *unix_user, const char *homedir)
{
	pstring add_script;
	int ret;

	pstrcpy(add_script, lp_adduser_script());
	if (! *add_script)
		return -1;
	all_string_sub(add_script, "%u", unix_user, sizeof(pstring));
	if (homedir)
		all_string_sub(add_script, "%H", homedir, sizeof(pstring));
	ret = smbrun(add_script,NULL);
	DEBUG(3,("smb_create_user: Running the command `%s' gave %d\n",add_script,ret));
	return ret;
}

/****************************************************************************
 Delete a UNIX user on demand.
****************************************************************************/

static int smb_delete_user(char *unix_user)
{
	pstring del_script;
	int ret;

	pstrcpy(del_script, lp_deluser_script());
	if (! *del_script)
		return -1;
	all_string_sub(del_script, "%u", unix_user, sizeof(pstring));
	ret = smbrun(del_script,NULL);
	DEBUG(3,("smb_delete_user: Running the command `%s' gave %d\n",del_script,ret));
	return ret;
}

/****************************************************************************
 Add and Delete UNIX users on demand, based on NTSTATUS codes.
****************************************************************************/

void smb_user_control(const auth_usersupplied_info *user_info, auth_serversupplied_info *server_info, NTSTATUS nt_status) 
{
	struct passwd *pwd=NULL;

	if (NT_STATUS_IS_OK(nt_status)) {

		if (!(server_info->sam_fill_level & SAM_FILL_UNIX)) {
			
			/*
			 * User validated ok against Domain controller.
			 * If the admin wants us to try and create a UNIX
			 * user on the fly, do so.
			 */
			
			if(lp_adduser_script() && !(pwd = Get_Pwnam(user_info->internal_username.str))) {
				smb_create_user(user_info->internal_username.str, NULL);
			}
		} else {			
			if(lp_adduser_script()) {
				SMB_STRUCT_STAT st;
				const char *home_dir = pdb_get_homedir(server_info->sam_account);
				/*
				 * Also call smb_create_user if the users
				 * home directory doesn't exist. Used with
				 * winbindd to allow the script to create
				 * the home directory for a user mapped
				 * with winbindd.
				 */

				if (home_dir && 
				    (sys_stat(home_dir, &st) == -1) && (errno == ENOENT)) {
						smb_create_user(user_info->internal_username.str, home_dir);
				}
			}
		}
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_SUCH_USER)) {
		/*
		 * User failed to validate ok against Domain controller.
		 * If the failure was "user doesn't exist" and admin 
		 * wants us to try and delete that UNIX user on the fly,
		 * do so.
		 */
		if (lp_deluser_script()) {
			smb_delete_user(user_info->internal_username.str);
		}
	}
}

/****************************************************************************
 Create an auth_usersupplied_data structure
****************************************************************************/

static BOOL make_user_info(auth_usersupplied_info **user_info, 
			   const char *smb_name, 
			   const char *internal_username,
			   const char *client_domain, 
			   const char *domain,
			   const char *wksta_name, 
			   DATA_BLOB lm_pwd, DATA_BLOB nt_pwd,
			   DATA_BLOB plaintext, 
			   uint32 ntlmssp_flags, BOOL encrypted)
{

	DEBUG(5,("attempting to make a user_info for %s (%s)\n", internal_username, smb_name));

	*user_info = malloc(sizeof(**user_info));
	if (!user_info) {
		DEBUG(0,("malloc failed for user_info (size %d)\n", sizeof(*user_info)));
		return False;
	}

	ZERO_STRUCTP(*user_info);

	DEBUG(5,("makeing strings for %s's user_info struct\n", internal_username));

	(*user_info)->smb_name.str = strdup(smb_name);
	if ((*user_info)->smb_name.str) { 
		(*user_info)->smb_name.len = strlen(smb_name);
	} else {
		free_user_info(user_info);
		return False;
	}
	
	(*user_info)->internal_username.str = strdup(internal_username);
	if ((*user_info)->internal_username.str) { 
		(*user_info)->internal_username.len = strlen(internal_username);
	} else {
		free_user_info(user_info);
		return False;
	}

	(*user_info)->domain.str = strdup(domain);
	if ((*user_info)->domain.str) { 
		(*user_info)->domain.len = strlen(domain);
	} else {
		free_user_info(user_info);
		return False;
	}

	(*user_info)->client_domain.str = strdup(client_domain);
	if ((*user_info)->client_domain.str) { 
		(*user_info)->client_domain.len = strlen(client_domain);
	} else {
		free_user_info(user_info);
		return False;
	}

	(*user_info)->wksta_name.str = strdup(wksta_name);
	if ((*user_info)->wksta_name.str) { 
		(*user_info)->wksta_name.len = strlen(wksta_name);
	} else {
		free_user_info(user_info);
		return False;
	}

	DEBUG(5,("makeing blobs for %s's user_info struct\n", internal_username));

	(*user_info)->lm_resp = data_blob(lm_pwd.data, lm_pwd.length);
	(*user_info)->nt_resp = data_blob(nt_pwd.data, nt_pwd.length);
	(*user_info)->plaintext_password = data_blob(plaintext.data, plaintext.length);

	(*user_info)->encrypted = encrypted;
	(*user_info)->ntlmssp_flags = ntlmssp_flags;

	DEBUG(10,("made an %sencrypted user_info for %s (%s)\n", encrypted ? "":"un" , internal_username, smb_name));

	return True;
}

/****************************************************************************
 Create an auth_usersupplied_data structure after appropriate mapping.
****************************************************************************/

BOOL make_user_info_map(auth_usersupplied_info **user_info, 
			const char *smb_name, 
			const char *client_domain, 
			const char *wksta_name, 
			DATA_BLOB lm_pwd, DATA_BLOB nt_pwd,
			DATA_BLOB plaintext, 
			uint32 ntlmssp_flags, BOOL encrypted)
{
	const char *domain;
	fstring internal_username;
	fstrcpy(internal_username, smb_name);
	map_username(internal_username); 
	
	if (lp_allow_trusted_domains()) {
		domain = client_domain;
	} else {
		domain = lp_workgroup();
	}
	
	return make_user_info(user_info, 
			      smb_name, internal_username,
			      client_domain, domain,
			      wksta_name, 
			      lm_pwd, nt_pwd,
			      plaintext, 
			      ntlmssp_flags, encrypted);
	
}

/****************************************************************************
 Create an auth_usersupplied_data, making the DATA_BLOBs here. 
 Decrypt and encrypt the passwords.
****************************************************************************/

BOOL make_user_info_netlogon_network(auth_usersupplied_info **user_info, 
				     char *smb_name, 
				     char *client_domain, 
				     char *wksta_name, 
				     uchar *lm_network_pwd, int lm_pwd_len,
				     uchar *nt_network_pwd, int nt_pwd_len)
{
	BOOL ret;
	DATA_BLOB lm_blob = data_blob(lm_network_pwd, lm_pwd_len);
	DATA_BLOB nt_blob = data_blob(nt_network_pwd, nt_pwd_len);
	DATA_BLOB plaintext_blob = data_blob(NULL, 0);
	uint32 ntlmssp_flags = 0;

	if (lm_pwd_len)
		ntlmssp_flags |= NTLMSSP_NEGOTIATE_OEM;
	if (nt_pwd_len == 24) {
		ntlmssp_flags |= NTLMSSP_NEGOTIATE_NTLM; 
	} else if (nt_pwd_len != 0) {
		ntlmssp_flags |= NTLMSSP_NEGOTIATE_NTLM2; 
	}

	ret = make_user_info_map(user_info, 
				 smb_name, client_domain, 
				 wksta_name, 
				 lm_blob, nt_blob,
				 plaintext_blob, 
				 ntlmssp_flags, True);
		
	data_blob_free(&lm_blob);
	data_blob_free(&nt_blob);
	return ret;
}

/****************************************************************************
 Create an auth_usersupplied_data, making the DATA_BLOBs here. 
 Decrypt and encrypt the passwords.
****************************************************************************/

BOOL make_user_info_netlogon_interactive(auth_usersupplied_info **user_info, 
					 char *smb_name, 
					 char *client_domain, 
					 char *wksta_name, 
					 char chal[8], 
					 uchar lm_interactive_pwd[16], 
					 uchar nt_interactive_pwd[16], 
					 uchar *dc_sess_key)
{
	char lm_pwd[16];
	char nt_pwd[16];
	unsigned char local_lm_response[24];
	unsigned char local_nt_response[24];
	unsigned char key[16];
	uint32 ntlmssp_flags = 0;
	
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
	
	SamOEMhash((uchar *)lm_pwd, key, sizeof(lm_pwd));
	SamOEMhash((uchar *)nt_pwd, key, sizeof(nt_pwd));
	
#ifdef DEBUG_PASSWORD
	DEBUG(100,("decrypt of lm owf password:"));
	dump_data(100, lm_pwd, sizeof(lm_pwd));
	
	DEBUG(100,("decrypt of nt owf password:"));
	dump_data(100, nt_pwd, sizeof(nt_pwd));
#endif
	
	SMBOWFencrypt((const unsigned char *)lm_pwd, chal, local_lm_response);
	SMBOWFencrypt((const unsigned char *)nt_pwd, chal, local_nt_response);
	
	/* Password info parinoia */
	ZERO_STRUCT(lm_pwd);
	ZERO_STRUCT(nt_pwd);
	ZERO_STRUCT(key);

	{
		BOOL ret;
		DATA_BLOB local_lm_blob = data_blob(local_lm_response, sizeof(local_lm_response));
		DATA_BLOB local_nt_blob = data_blob(local_nt_response, sizeof(local_nt_response));
		DATA_BLOB plaintext_blob = data_blob(NULL, 0);

		if (lm_interactive_pwd)
			ntlmssp_flags |= NTLMSSP_NEGOTIATE_OEM;
		if (nt_interactive_pwd)
			ntlmssp_flags |= NTLMSSP_NEGOTIATE_NTLM; 

		ret = make_user_info_map(user_info, 
					 smb_name, client_domain, 
					 wksta_name, 
					 local_lm_blob,
					 local_nt_blob,
					 plaintext_blob, 
					 ntlmssp_flags, True);
		
		data_blob_free(&local_lm_blob);
		data_blob_free(&local_nt_blob);
		return ret;
	}
}

/****************************************************************************
 Create an auth_usersupplied_data structure
****************************************************************************/

BOOL make_user_info_winbind(auth_usersupplied_info **user_info, 
                            const char *username,
                            const char *domain, 
                            const char *password,
			    char chal[8] /* Give winbind back the challange we used */
	)
{
	unsigned char local_lm_response[24];
	unsigned char local_nt_response[24];
	DATA_BLOB local_lm_blob;
	DATA_BLOB local_nt_blob;
	DATA_BLOB plaintext_blob;
	uint32 ntlmssp_flags = 0;

	/*
	 * Not encrypted - do so.
	 */
	
	DEBUG(5,("pass_check_smb: User passwords not in encrypted format.\n"));
	
	generate_random_buffer(chal, 8, False);

	if (*password) {
		SMBencrypt( (const uchar *)password, chal, local_lm_response);
		
		/* This encrypts the lm_pwd field, which actually contains
		   the password rather than the nt_pwd field because that
		   contains nothing */
		
		/* WATCH OUT. This doesn't work if the incoming password is
		   incorrectly cased.  We might want to add a check here
		   and only do an LM in that case */
		
		SMBNTencrypt((const uchar *)password, chal, local_nt_response);

		local_lm_blob = data_blob(local_lm_response, sizeof(local_lm_response));
		local_nt_blob = data_blob(local_nt_response, sizeof(local_nt_response));
		plaintext_blob = data_blob(password, strlen(password)+1);
		if ((!local_lm_blob.data) || (!local_nt_blob.data)|| (!plaintext_blob.data)) {
			data_blob_free(&local_lm_blob);
			data_blob_free(&local_nt_blob);
			data_blob_clear_free(&plaintext_blob);
			return False;
		}
		ntlmssp_flags = NTLMSSP_NEGOTIATE_OEM | NTLMSSP_NEGOTIATE_NTLM;
	} else {
		local_lm_blob = data_blob(NULL, 0);
		local_nt_blob = data_blob(NULL, 0);
		plaintext_blob = data_blob(NULL, 0);
	}

	{
		BOOL ret;

		ret = make_user_info(user_info, 
				     username, username,
				     domain, domain, 
				     global_myname, 
				     local_nt_blob,
				     local_lm_blob,
				     plaintext_blob, 
				     ntlmssp_flags, False);
		
		data_blob_free(&local_lm_blob);
		data_blob_free(&local_nt_blob);
		data_blob_clear_free(&plaintext_blob);
		return ret;
	}
}

/****************************************************************************
 Create an auth_usersupplied_data, making the DATA_BLOBs here. 
 Decrypt and encrypt the passwords.
****************************************************************************/

BOOL make_user_info_winbind_crap(auth_usersupplied_info **user_info, 
				 char *smb_name, 
				 char *client_domain, 
				 uchar *lm_network_pwd, int lm_pwd_len,
				 uchar *nt_network_pwd, int nt_pwd_len)
{
	BOOL ret;
	DATA_BLOB lm_blob = data_blob(lm_network_pwd, lm_pwd_len);
	DATA_BLOB nt_blob = data_blob(nt_network_pwd, nt_pwd_len);
	DATA_BLOB plaintext_blob = data_blob(NULL, 0);
	uint32 ntlmssp_flags = 0;

	if (lm_pwd_len)
		ntlmssp_flags |= NTLMSSP_NEGOTIATE_OEM;
	if (nt_pwd_len)
		ntlmssp_flags |= NTLMSSP_NEGOTIATE_NTLM; 
	
	ret = make_user_info(user_info, 
			     smb_name, smb_name, 
			     client_domain, client_domain, 
			     global_myname, 
			     nt_blob, lm_blob,
			     plaintext_blob, 
			     ntlmssp_flags, True);

	data_blob_free(&lm_blob);
	data_blob_free(&nt_blob);
	return ret;
}

/****************************************************************************
 Create an auth_usersupplied_data structure
****************************************************************************/

BOOL make_user_info_for_reply(auth_usersupplied_info **user_info, 
			      char *smb_name, 
			      char *client_domain,
			      char chal[8],
			      DATA_BLOB plaintext_password)
{

	DATA_BLOB local_lm_blob;
	DATA_BLOB local_nt_blob;
	BOOL ret = False;
	uint32 ntlmssp_flags = 0;
			
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

		SMBencrypt( (const uchar *)plaintext_password.data, chal, local_lm_response);
		local_lm_blob = data_blob(local_lm_response, 24);
		
		/* We can't do an NT hash here, as the password needs to be
		   case insensitive */
		local_nt_blob = data_blob(NULL, 0); 
		
		ntlmssp_flags = NTLMSSP_NEGOTIATE_OEM;
	} else {
		local_lm_blob = data_blob(NULL, 0); 
		local_nt_blob = data_blob(NULL, 0); 
	}
	
	ret = make_user_info_map(user_info, smb_name,
				 client_domain, 
				 remote_machine,
				 local_lm_blob,
				 local_nt_blob,
				 plaintext_password, 
				 ntlmssp_flags, False);
	
	data_blob_free(&local_lm_blob);
	return ret;
}

/****************************************************************************
 Create an auth_usersupplied_data structure
****************************************************************************/

BOOL make_user_info_for_reply_enc(auth_usersupplied_info **user_info, 
			      char *smb_name,
			      char *client_domain, 
			      DATA_BLOB lm_resp, DATA_BLOB nt_resp,
			      DATA_BLOB plaintext_password)
{
	uint32 ntlmssp_flags = 0;

	DATA_BLOB no_plaintext_blob = data_blob(NULL, 0); 
	
	if (lm_resp.length == 24) {
		ntlmssp_flags |= NTLMSSP_NEGOTIATE_OEM;
	}
	if (nt_resp.length == 0) {
	} else if (nt_resp.length == 24) {
		ntlmssp_flags |= NTLMSSP_NEGOTIATE_NTLM;
	} else {
		ntlmssp_flags |= NTLMSSP_NEGOTIATE_NTLM2;
	}

	return make_user_info_map(user_info, smb_name, 
				 client_domain, 
				 remote_machine, 
				 lm_resp, 
				 nt_resp, 
				 no_plaintext_blob, 
				 ntlmssp_flags, True);
}

/****************************************************************************
 Create a guest user_info blob, for anonymous authenticaion.
****************************************************************************/

BOOL make_user_info_guest(auth_usersupplied_info **user_info) 
{
	DATA_BLOB lm_blob = data_blob(NULL, 0);
	DATA_BLOB nt_blob = data_blob(NULL, 0);
	DATA_BLOB plaintext_blob = data_blob(NULL, 0);
	uint32 ntlmssp_flags = 0;

	return make_user_info(user_info, 
			      "","", 
			      "","", 
			      "", 
			      nt_blob, lm_blob,
			      plaintext_blob, 
			      ntlmssp_flags, True);
}

/***************************************************************************
 Make a user_info struct
***************************************************************************/

BOOL make_server_info(auth_serversupplied_info **server_info) 
{
	*server_info = malloc(sizeof(**server_info));
	if (!*server_info) {
		DEBUG(0,("make_server_info: malloc failed!\n"));
		return False;
	}
	ZERO_STRUCTP(*server_info);
	return True;
}

/***************************************************************************
 Make (and fill) a user_info struct from a SAM_ACCOUNT
***************************************************************************/

BOOL make_server_info_sam(auth_serversupplied_info **server_info, SAM_ACCOUNT *sampass) 
{
	if (!make_server_info(server_info)) {
		return False;
	}

	(*server_info)->sam_fill_level = SAM_FILL_ALL;
	(*server_info)->sam_account = sampass;

	DEBUG(5,("make_server_info_sam: made server info for user %s\n",
		 pdb_get_username((*server_info)->sam_account)));
	return True;
}

/***************************************************************************
 Make (and fill) a user_info struct from a 'struct passwd' by conversion 
 to a SAM_ACCOUNT
***************************************************************************/

BOOL make_server_info_pw(auth_serversupplied_info **server_info, const struct passwd *pwd)
{
	SAM_ACCOUNT *sampass = NULL;
	if (!pdb_init_sam_pw(&sampass, pwd)) {		
		return False;
	}
	return make_server_info_sam(server_info, sampass);
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
		data_blob_free(&(*user_info)->lm_resp);
		data_blob_free(&(*user_info)->nt_resp);
		SAFE_FREE((*user_info)->interactive_password);
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
	if (*server_info != NULL) {
		pdb_free_sam(&(*server_info)->sam_account);
		
		/* call pam_end here, unless we know we are keeping it */
		delete_nt_token( &(*server_info)->ptok );
		ZERO_STRUCT(**server_info);
	}
	SAFE_FREE(*server_info);
}

/***************************************************************************
 Make a server_info struct for a guest user 
***************************************************************************/

BOOL make_server_info_guest(auth_serversupplied_info **server_info) 
{
	struct passwd *pass = sys_getpwnam(lp_guestaccount());
	
	if (pass) {
		if (!make_server_info_pw(server_info, pass)) {
			return False;
		}
		(*server_info)->guest = True;
		return True;
	}
	DEBUG(0,("make_server_info_guest: sys_getpwnam() failed on guest account!\n")); 
	return False;
}

/***************************************************************************
 Make an auth_methods struct
***************************************************************************/

BOOL make_auth_methods(auth_methods **auth_method) 
{
	*auth_method = malloc(sizeof(**auth_method));
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
