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

extern int DEBUGLEVEL;

extern pstring global_myname;


/****************************************************************************
update the encrypted smbpasswd file from the plaintext username and password

this ugly hack needs to die, but not quite yet...
*****************************************************************************/
static BOOL update_smbpassword_file(char *user, char *password)
{
	SAM_ACCOUNT 	*sampass = NULL;
	BOOL 		ret;
	
	pdb_init_sam(&sampass);
	
	become_root();
	ret = pdb_getsampwnam(sampass, user);
	unbecome_root();

	if(ret == False) {
		DEBUG(0,("update_smbpassword_file: pdb_getsampwnam failed to locate %s\n", user));
		pdb_free_sam(sampass);
		return False;
	}

	/*
	 * Remove the account disabled flag - we are updating the
	 * users password from a login.
	 */
	pdb_set_acct_ctrl(sampass, pdb_get_acct_ctrl(sampass) & ~ACB_DISABLED);

	/* Here, the flag is one, because we want to ignore the
           XXXXXXX'd out password */
	ret = change_oem_password( sampass, password, True);
	if (ret == False) {
		DEBUG(3,("change_oem_password returned False\n"));
	}

	pdb_free_sam(sampass);
	return ret;
}

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


uint32 check_password(const auth_usersupplied_info *user_info, auth_serversupplied_info *server_info)
{
	
	uint32 nt_status = NT_STATUS_LOGON_FAILURE;

	DEBUG(3, ("check_password:  Checking password for user %s with the new password interface\n", user_info->smb_username.str));
        if (check_hosts_equiv(user_info->smb_username.str)) {
		nt_status = NT_STATUS_NOPROBLEMO;
	}
		
  	if (!check_domain_match(user_info->smb_username.str, user_info->domain.str)) {
		return NT_STATUS_LOGON_FAILURE;
	}

	if ((lp_security() == SEC_DOMAIN) && (nt_status != NT_STATUS_NOPROBLEMO)) {
		nt_status = check_domain_security(user_info, server_info);
	}
	
	if ((lp_security() == SEC_SERVER) && (nt_status != NT_STATUS_NOPROBLEMO)) {
		nt_status = check_server_security(user_info, server_info);
	}

	if (lp_security() >= SEC_SERVER) {
		smb_user_control(user_info->smb_username.str, nt_status);
	}

	if ((nt_status != NT_STATUS_NOPROBLEMO) 
	    && (user_info->plaintext_password.len > 0) 
	    && (!lp_plaintext_to_smbpasswd())) {
		return (pass_check(user_info->smb_username.str, 
				  user_info->plaintext_password.str, 
				  user_info->plaintext_password.len, 
				  lp_update_encrypted() ? 
				  update_smbpassword_file : NULL) 
			? NT_STATUS_NOPROBLEMO : NT_STATUS_LOGON_FAILURE);
	}

	if (nt_status != NT_STATUS_NOPROBLEMO) {
		nt_status = check_smbpasswd_security(user_info, server_info);
	}
	
	if (nt_status == NT_STATUS_NOPROBLEMO) {
		/* We might not be root if we are an RPC call */
		become_root();
		nt_status = smb_pam_accountcheck(user_info->smb_username.str);
		unbecome_root();
	}

	if (nt_status == NT_STATUS_NOPROBLEMO) {
		DEBUG(5, ("check_password:  Password for user %s suceeded\n", user_info->smb_username.str));
	} else {
		DEBUG(3, ("check_password:  Password for user %s FAILED with error %s\n", user_info->smb_username.str, get_nt_error_msg(nt_status)));

	}		
	return nt_status;

}

/****************************************************************************
 COMPATABILITY INTERFACES:
 ***************************************************************************/

/****************************************************************************
check if a username/password is OK assuming the password is a 24 byte
SMB hash
return True if the password is correct, False otherwise
****************************************************************************/

uint32 pass_check_smb_with_chal(char *user, char *domain, uchar chal[8], 
                    uchar *lm_pwd, int lm_pwd_len,
		    uchar *nt_pwd, int nt_pwd_len)
{

	auth_usersupplied_info user_info;
	auth_serversupplied_info server_info;
	AUTH_STR ourdomain, theirdomain, smb_username, wksta_name;
		
	ZERO_STRUCT(user_info);
	ZERO_STRUCT(ourdomain);
	ZERO_STRUCT(theirdomain);
	ZERO_STRUCT(smb_username);
	ZERO_STRUCT(wksta_name);
	
	ourdomain.str = lp_workgroup();
	ourdomain.len = strlen(ourdomain.str);

	theirdomain.str = domain;
	theirdomain.len = strlen(theirdomain.str);

	user_info.requested_domain = theirdomain;
	user_info.domain = ourdomain;
	
	smb_username.str = user;
	smb_username.len = strlen(smb_username.str);

	user_info.requested_username = smb_username;  /* For the time-being */
	user_info.smb_username = smb_username;

	user_info.wksta_name.str = client_name();
	user_info.wksta_name.len = strlen(client_name());

	user_info.wksta_name = wksta_name;

	memcpy(user_info.chal, chal, 8);

	if (lm_pwd_len >= 24 || (lp_encrypted_passwords() && (lm_pwd_len == 0) && lp_null_passwords())) {
		/* if 24 bytes long assume it is an encrypted password */
	  
		user_info.lm_resp.buffer = (uint8 *)lm_pwd;
		user_info.lm_resp.len = lm_pwd_len;
		user_info.nt_resp.buffer = (uint8 *)nt_pwd;
		user_info.nt_resp.len = nt_pwd_len;

	} else {
		unsigned char local_lm_response[24];
		unsigned char local_nt_response[24];
		
		/*
		 * Not encrypted - do so.
		 */
		
		DEBUG(5,("pass_check_smb: User passwords not in encrypted format.\n"));

		if (lm_pwd_len > 0) {
			SMBencrypt( (uchar *)lm_pwd, user_info.chal, local_lm_response);
			user_info.lm_resp.buffer = (uint8 *)local_lm_response;
			user_info.lm_resp.len = 24;

			/* This encrypts the lm_pwd feild, which actualy contains the password
			   rather than the nt_pwd field becouse that contains nothing */
			SMBNTencrypt((uchar *)lm_pwd, user_info.chal, local_nt_response);
			user_info.nt_resp.buffer = (uint8 *)local_nt_response;
			user_info.nt_resp.len = 24;
		}
		
		user_info.plaintext_password.str = lm_pwd;
		user_info.plaintext_password.len = lm_pwd_len;

	}

	return check_password(&user_info, &server_info);
}

uint32 pass_check_smb(char *user, char *domain,
                    uchar *lm_pwd, int lm_pwd_len,
		    uchar *nt_pwd, int nt_pwd_len)
{
	uchar chal[8];

	if (!last_challenge(chal)) {
		generate_random_buffer( chal, 8, False);
	}

	return pass_check_smb_with_chal(user, domain, chal, 
					lm_pwd, lm_pwd_len,
					nt_pwd, nt_pwd_len);

}

/****************************************************************************
check if a username/password pair is OK either via the system password
database or the encrypted SMB password database
return True if the password is correct, False otherwise
****************************************************************************/
BOOL password_ok(char *user, char *password, int pwlen)
{

	/* 
	 *  This hack must die!  But until I rewrite the rest of samba
	 *  it must stay - abartlet 2001-08-03
	 */

	if ((pwlen == 0) && !lp_null_passwords()) {
                DEBUG(4,("Null passwords not allowed.\n"));
                return False;
        }
	
	if (pass_check_smb(user, lp_workgroup(), NULL, 0, password, pwlen) == NT_STATUS_NOPROBLEMO) {
		return True;
	}

	if (pass_check_smb(user, lp_workgroup(), password, pwlen, NULL, 0) == NT_STATUS_NOPROBLEMO) {
		return True;
	}

	return False;
}

