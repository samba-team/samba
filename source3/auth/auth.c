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

/****************************************************************************
 Check user is in correct domain if required
****************************************************************************/

static BOOL check_domain_match(char *user, char *domain) 
{
  /*
   * If we aren't serving to trusted domains, we must make sure that
   * the validation request comes from an account in the same domain
   * as the Samba server
   */

  if (!lp_allow_trusted_domains() &&
      !strequal(lp_workgroup(), domain) ) {
      DEBUG(1, ("check_domain_match: Attempt to connect as user %s from domain %s denied.\n", user, domain));
      return False;
  } else {
      return True;
  }
}

/****************************************************************************
 Check a users password, as given in the user-info struct and return various
 interesting details in the server_info struct.

 This functions does NOT need to be in a become_root()/unbecome_root() pair
 as it makes the calls itself when needed.

 The return value takes precedence over the contents of the server_info 
 struct.  When the return is other than NT_STATUS_NOPROBLEMO the contents 
 of that structure is undefined.

****************************************************************************/

NTSTATUS check_password(const auth_usersupplied_info *user_info, 
			auth_serversupplied_info **server_info)
{
	
	NTSTATUS nt_status = NT_STATUS_LOGON_FAILURE;
	BOOL done_pam = False;
	const char *pdb_username;

	DEBUG(3, ("check_password:  Checking password for unmapped user [%s]\\[%s]@[%s] with the new password interface\n", 
		  user_info->client_domain.str, user_info->smb_name.str, user_info->wksta_name.str));

	DEBUG(3, ("check_password:  mapped user is: [%s]\\[%s]@[%s]\n", 
		  user_info->domain.str, user_info->internal_username.str, user_info->wksta_name.str));

	if (!NT_STATUS_IS_OK(nt_status)) {
		nt_status = check_guest_security(user_info, server_info);
		if (NT_STATUS_IS_OK(nt_status)) {
			DEBUG(5, ("check_password:  checking guest-account for user [%s] suceeded\n", user_info->smb_name.str));
		} else {
			DEBUG(10, ("check_password:  checking gusst-account for user [%s] FAILED with error %s\n", user_info->smb_name.str, get_nt_error_msg(nt_status)));
			
		}		
	}

	/* This needs to be sorted:  If it doesn't match, what should we do? */
  	if (!check_domain_match(user_info->smb_name.str, user_info->domain.str)) {
		return NT_STATUS_LOGON_FAILURE;
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		nt_status = check_rhosts_security(user_info, server_info);
		if (NT_STATUS_IS_OK(nt_status)) {
			DEBUG(3, ("check_password:  Password (rhosts) for user [%s] suceeded\n", user_info->smb_name.str));
		} else {
			DEBUG(10, ("check_password:  Password (rhosts) for user [%s] FAILED with error %s\n", user_info->smb_name.str, get_nt_error_msg(nt_status)));
			
		}		
	}
	
	if ((lp_security() == SEC_DOMAIN) && !NT_STATUS_IS_OK(nt_status)) {
		nt_status = check_domain_security(user_info, server_info);
		if (NT_STATUS_IS_OK(nt_status)) {
			DEBUG(7, ("check_password:  Password (domain) for user [%s] suceeded\n", user_info->smb_name.str));
		} else {
			DEBUG(5, ("check_password:  Password (domain) for user [%s] FAILED with error %s\n", user_info->smb_name.str, get_nt_error_msg(nt_status)));
			
		}		
	}
	
	if ((lp_security() == SEC_SERVER) && !NT_STATUS_IS_OK(nt_status)) {
		nt_status = check_server_security(user_info, server_info);
		if (NT_STATUS_IS_OK(nt_status)) {
			DEBUG(7, ("check_password:  Password (server) for user [%s] suceeded\n", user_info->smb_name.str));
		} else {
			DEBUG(5, ("check_password:  Password (server) for user [%s] FAILED with error %s\n", user_info->smb_name.str, get_nt_error_msg(nt_status)));
			
		}		
	}

	if (lp_security() >= SEC_SERVER) {
		smb_user_control(user_info, *server_info, nt_status);
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		if (user_info->encrypted || lp_plaintext_to_smbpasswd()) { 
			nt_status = check_smbpasswd_security(user_info, server_info);
		} else {
			nt_status = check_unix_security(user_info, server_info);
			done_pam = True;
		}
		
		if (NT_STATUS_IS_OK(nt_status)) {
			DEBUG(7, ("check_password:  Password (unix/smbpasswd) for user [%s] suceeded\n", user_info->smb_name.str));
		} else {
			DEBUG(5, ("check_password:  Password (unix/smbpasswd) for user [%s] FAILED with error %s\n", user_info->smb_name.str, get_nt_error_msg(nt_status)));
			
		}		
	}

	if (NT_STATUS_IS_OK(nt_status)) {
		pdb_username = pdb_get_username((*server_info)->sam_account);
		if (!done_pam && !(*server_info)->guest) {
			/* We might not be root if we are an RPC call */
			become_root();
			nt_status = smb_pam_accountcheck(pdb_username);
			unbecome_root();
			
			if (NT_STATUS_IS_OK(nt_status)) {
				DEBUG(5, ("check_password:  PAM Account for user [%s] suceeded\n", pdb_username));
			} else {
				DEBUG(3, ("check_password:  PAM Account for user [%s] FAILED with error %s\n", pdb_username, get_nt_error_msg(nt_status)));
			} 
		}
	}

	if (NT_STATUS_IS_OK(nt_status)) {
		DEBUG(3, ("check_password:  %sauthenticaion for user [%s] -> [%s] -> [%s] suceeded\n", 
			  (*server_info)->guest ? "guest " : "", 
			  user_info->smb_name.str, 
			  user_info->internal_username.str, 
			  pdb_username));
	} else {
		DEBUG(3, ("check_password:  Authenticaion for user [%s] -> [%s] FAILED with error %s\n", user_info->smb_name.str, user_info->internal_username.str, get_nt_error_msg(nt_status)));
		ZERO_STRUCTP(server_info);
	}		

	return nt_status;

}

/****************************************************************************
 Squash an NT_STATUS return in line with requirements for unauthenticated 
 connections.  (session setups in particular)
****************************************************************************/

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
	auth_serversupplied_info *server_info = NULL;

	make_user_info_for_reply(&user_info, smb_name, 
				 domain, 
				 lm_pwd, 
				 nt_pwd, 
				 plaintext_password, 
				 encrypted);
	
	nt_status = check_password(user_info, &server_info);
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

	if (global_encrypted_passwords_negotiated) {
		/* 
		 * The password could be either NTLM or plain LM.  Try NTLM first, 
		 * but fall-through as required.
		 * NTLMv2 makes no sense here.
		 */
		if (NT_STATUS_IS_OK(pass_check_smb(smb_name, lp_workgroup(), null_password, password_blob, null_password, global_encrypted_passwords_negotiated))) {
			return True;
		}
		
		if (NT_STATUS_IS_OK(pass_check_smb(smb_name, lp_workgroup(), password_blob, null_password, null_password, global_encrypted_passwords_negotiated))) {
			return True;
		}
	} else {
		if (NT_STATUS_IS_OK(pass_check_smb(smb_name, lp_workgroup(), null_password, null_password, password_blob, global_encrypted_passwords_negotiated))) {
			return True;
		}
	}

	return False;
}


