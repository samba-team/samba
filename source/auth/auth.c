/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Andrew Bartlett              2001
   
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

/**
 * Check user is in correct domain (if required)
 *
 * @param user Only used to fill in the debug message
 * 
 * @param domain The domain to be verified
 *
 * @return True if the user can connect with that domain, 
 *         False otherwise.
**/

static BOOL check_domain_match(const char *user, const char *domain) 
{
	/*
	 * If we aren't serving to trusted domains, we must make sure that
	 * the validation request comes from an account in the same domain
	 * as the Samba server
	 */

	if (!lp_allow_trusted_domains() &&
	    !(strequal("", domain) || 
	      strequal(lp_workgroup(), domain) || 
	      is_netbios_alias_or_name(domain))) {
		DEBUG(1, ("check_domain_match: Attempt to connect as user %s from domain %s denied.\n", user, domain));
		return False;
	} else {
		return True;
	}
}

/**
 * Check a user's Plaintext, LM or NTLM password.
 *
 * Check a user's password, as given in the user_info struct and return various
 * interesting details in the server_info struct.
 *
 * This function does NOT need to be in a become_root()/unbecome_root() pair
 * as it makes the calls itself when needed.
 *
 * The return value takes precedence over the contents of the server_info 
 * struct.  When the return is other than NT_STATUS_OK the contents 
 * of that structure is undefined.
 *
 * @param user_info Contains the user supplied components, including the passwords.
 *                  Must be created with make_user_info() or one of its wrappers.
 *
 * @param auth_info Supplies the challanges and some other data. 
 *                  Must be created with make_auth_info(), and the challanges should be 
 *                  filled in, either at creation or by calling the challange geneation 
 *                  function auth_get_challange().  
 *
 * @param server_info If successful, contains information about the authenticaion, 
 *                    including a SAM_ACCOUNT struct describing the user.
 *
 * @return An NTSTATUS with NT_STATUS_OK or an appropriate error.
 *
 **/

NTSTATUS check_password(const auth_usersupplied_info *user_info, 
			const auth_authsupplied_info *auth_info,
			auth_serversupplied_info **server_info)
{
	
	NTSTATUS nt_status = NT_STATUS_LOGON_FAILURE;
	const char *pdb_username;
	auth_methods *auth_method;
	TALLOC_CTX *mem_ctx;

	if (!user_info || !auth_info || !server_info) {
		return NT_STATUS_LOGON_FAILURE;
	}

	DEBUG(3, ("check_password:  Checking password for unmapped user [%s]\\[%s]@[%s] with the new password interface\n", 
		  user_info->client_domain.str, user_info->smb_name.str, user_info->wksta_name.str));

	DEBUG(3, ("check_password:  mapped user is: [%s]\\[%s]@[%s]\n", 
		  user_info->domain.str, user_info->internal_username.str, user_info->wksta_name.str));
	if (auth_info->challenge_set_by) {
		DEBUG(10, ("auth_info challenge created by %s\n", auth_info->challenge_set_by));
	}
	DEBUG(10, ("challenge is: \n"));
	dump_data(5, (auth_info)->challenge.data, (auth_info)->challenge.length);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("user_info has passwords of length %d and %d\n", 
		    user_info->lm_resp.length, user_info->nt_resp.length));
	DEBUG(100, ("lm:\n"));
	dump_data(100, user_info->lm_resp.data, user_info->lm_resp.length);
	DEBUG(100, ("nt:\n"));
	dump_data(100, user_info->nt_resp.data, user_info->nt_resp.length);
#endif

	/* This needs to be sorted:  If it doesn't match, what should we do? */
  	if (!check_domain_match(user_info->smb_name.str, user_info->domain.str)) {
		return NT_STATUS_LOGON_FAILURE;
	}

	for (auth_method = auth_info->auth_method_list;auth_method; auth_method = auth_method->next)
	{
		mem_ctx = talloc_init_named("%s authentication for user %s\\%s", auth_method->name, 
					    user_info->domain.str, user_info->smb_name.str);

		nt_status = auth_method->auth(auth_method->private_data, mem_ctx, user_info, auth_info, server_info);
		if (NT_STATUS_IS_OK(nt_status)) {
			DEBUG(3, ("check_password: %s authentication for user [%s] suceeded\n", 
				  auth_method->name, user_info->smb_name.str));
		} else {
			DEBUG(5, ("check_password: %s authentication for user [%s] FAILED with error %s\n", 
				  auth_method->name, user_info->smb_name.str, get_nt_error_msg(nt_status)));
		}

		talloc_destroy(mem_ctx);

		if (NT_STATUS_IS_OK(nt_status)) {
			break;
		}
	}

	/* This is one of the few places the *relies* (rather than just sets defaults
	   on the value of lp_security().  This needs to change.  A new paramater 
	   perhaps? */
	if (lp_security() >= SEC_SERVER) {
		smb_user_control(user_info, *server_info, nt_status);
	}

	if (NT_STATUS_IS_OK(nt_status)) {
		pdb_username = pdb_get_username((*server_info)->sam_account);
		if (!(*server_info)->guest) {
			/* We might not be root if we are an RPC call */
			become_root();
			nt_status = smb_pam_accountcheck(pdb_username);
			unbecome_root();
			
			if (NT_STATUS_IS_OK(nt_status)) {
				DEBUG(5, ("check_password:  PAM Account for user [%s] suceeded\n", 
					  pdb_username));
			} else {
				DEBUG(3, ("check_password:  PAM Account for user [%s] FAILED with error %s\n", 
					  pdb_username, get_nt_error_msg(nt_status)));
			} 
		}
		
		if (NT_STATUS_IS_OK(nt_status)) {
			DEBUG((*server_info)->guest ? 5 : 2, 
			      ("check_password:  %sauthenticaion for user [%s] -> [%s] -> [%s] suceeded\n", 
			       (*server_info)->guest ? "guest " : "", 
			       user_info->smb_name.str, 
			       user_info->internal_username.str, 
			       pdb_username));
		}
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(2, ("check_password:  Authenticaion for user [%s] -> [%s] FAILED with error %s\n", 
			  user_info->smb_name.str, user_info->internal_username.str, 
			  get_nt_error_msg(nt_status)));
		ZERO_STRUCTP(server_info);
	}
	return nt_status;

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



/****************************************************************************
 COMPATABILITY INTERFACES:
 ***************************************************************************/

/****************************************************************************
check if a username/password is OK assuming the password is a 24 byte
SMB hash
return True if the password is correct, False otherwise
****************************************************************************/

static NTSTATUS pass_check_smb(char *smb_name,
			       char *domain, 
			       DATA_BLOB lm_pwd,
			       DATA_BLOB nt_pwd,
			       DATA_BLOB plaintext_password,
			       BOOL encrypted)

{
	NTSTATUS nt_status;
	auth_usersupplied_info *user_info = NULL;
	extern auth_authsupplied_info *negprot_global_auth_info;
	auth_serversupplied_info *server_info = NULL;
	if (encrypted) {		
		make_user_info_for_reply_enc(&user_info, smb_name, 
					     domain,
					     lm_pwd, 
					     nt_pwd, 
					     plaintext_password);
		nt_status = check_password(user_info, negprot_global_auth_info, &server_info);
	} else {
		auth_authsupplied_info *plaintext_auth_info = NULL;
		DATA_BLOB chal;
		if (!make_auth_info_subsystem(&plaintext_auth_info)) {
			return NT_STATUS_NO_MEMORY;
		}

		chal = auth_get_challenge(plaintext_auth_info);

		if (!make_user_info_for_reply(&user_info, 
					      smb_name, domain, chal.data,
					      plaintext_password)) {
			return NT_STATUS_NO_MEMORY;
		}
		
		nt_status = check_password(user_info, plaintext_auth_info, &server_info); 
		
		data_blob_free(&chal);
		free_auth_info(&plaintext_auth_info);
	}		
	free_user_info(&user_info);
	free_server_info(&server_info);
	return nt_status;
}

/****************************************************************************
check if a username/password pair is OK either via the system password
database or the encrypted SMB password database
return True if the password is correct, False otherwise
****************************************************************************/
BOOL password_ok(char *smb_name, DATA_BLOB password_blob)
{

	DATA_BLOB null_password = data_blob(NULL, 0);
	extern BOOL global_encrypted_passwords_negotiated;
	BOOL encrypted = (global_encrypted_passwords_negotiated && password_blob.length == 24);
	
	if (encrypted) {
		/* 
		 * The password could be either NTLM or plain LM.  Try NTLM first, 
		 * but fall-through as required.
		 * NTLMv2 makes no sense here.
		 */
		if (NT_STATUS_IS_OK(pass_check_smb(smb_name, lp_workgroup(), null_password, password_blob, null_password, encrypted))) {
			return True;
		}
		
		if (NT_STATUS_IS_OK(pass_check_smb(smb_name, lp_workgroup(), password_blob, null_password, null_password, encrypted))) {
			return True;
		}
	} else {
		if (NT_STATUS_IS_OK(pass_check_smb(smb_name, lp_workgroup(), null_password, null_password, password_blob, encrypted))) {
			return True;
		}
	}

	return False;
}


