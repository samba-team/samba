/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Jeremy Allison                    1998.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"

extern int DEBUGLEVEL;
extern pstring global_myname;
extern pstring global_myworkgroup;

/***********************************************************************
 Do the same as security=server, but using NT Domain calls and a session
 key from the workstation trust account password.
************************************************************************/
static uint32 domain_client_validate( char *user, char *domain, 
				char *acct_name, uint16 acct_type,
				char *challenge,
				char *smb_apasswd, int smb_apasslen, 
				char *smb_ntpasswd, int smb_ntpasslen,
				uchar user_sess_key[16],
				char lm_pw8[8])
{
	unsigned char trust_passwd[16];
	NET_ID_INFO_CTR ctr;
	NET_USER_INFO_3 info3;
	uint32 smb_uid_low;
	uint32 status;
	fstring trust_acct;
	fstring srv_name;
	BOOL cleartext = smb_apasslen != 0 && smb_apasslen != 24 &&
	                 smb_ntpasslen == 0;

#ifdef DEBUG_PASSWORD
	DEBUG(100,("domain_client_validate: %s %s\n", user, domain));
	dump_data(100, smb_apasswd, smb_apasslen);
	dump_data(100, smb_ntpasswd, smb_ntpasslen);
#endif

	fstrcpy(trust_acct, acct_name);
	fstrcat(trust_acct, "$");

	/* 
	* Check that the requested domain is not our own machine name.
	* If it is, we should never check the PDC here, we use our own local
	* password file.
	*/

	if (!get_any_dc_name(domain, srv_name))
	{
		DEBUG(3,("domain_client_validate: could not find domain %s\n",
				domain));
		return False;
	}

	become_root(False);
	if (!trust_get_passwd( trust_passwd, domain, acct_name))
	{
		unbecome_root(False);
		return False;
	}
	unbecome_root(False);

	/*
	 * At this point, smb_apasswd points to the lanman response to
	 * the challenge in local_challenge, and smb_ntpasswd points to
	 * the NT response to the challenge in local_challenge. Ship
	 * these over the secure channel to a domain controller and
	 * see if they were valid.
	 */

	/*
	* Ok - we have an anonymous connection to the IPC$ share.
	* Now start the NT Domain stuff :-).
	*/

	status = cli_nt_setup_creds(srv_name, domain, global_myname, trust_acct,
	                      trust_passwd, acct_type);
	if (status != 0x0)
	{
		DEBUG(0,("domain_client_validate: credentials failed (%s)\n",
		          srv_name));
		return status;
	}

	/* We really don't care what LUID we give the user. */
	generate_random_buffer( (unsigned char *)&smb_uid_low, 4, False);

	if (challenge == NULL && !cleartext)
	{
		status = cli_nt_login_interactive(srv_name,
			global_myname, 
	                domain, user,
	                smb_uid_low, 
			smb_apasswd, smb_ntpasswd, 
			&ctr, &info3);
	}
	else if (challenge == NULL)
	{
		status = cli_nt_login_general(srv_name,
			global_myname, 
	                domain, user,
	                smb_uid_low, 
			smb_apasswd, 
			&ctr, &info3);
	}
	else
	{
		status = cli_nt_login_network(srv_name,
			global_myname, 
	                domain, user,
	               smb_uid_low, (char *)challenge,
			((smb_apasslen != 0) ? smb_apasswd : NULL),
			((smb_ntpasslen != 0) ? smb_ntpasswd : NULL),
			&ctr, &info3);

		if (lm_pw8 != NULL)
		{
			memcpy(lm_pw8, info3.padding, 8);
		}
	}

	if (status == (NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT|0xc0000000))
	{
		DEBUG(10,("domain_client_validate: wks trust valid:%s\n",
		           user));
		return status;
	}

	if (status == (NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT|0xc0000000))
	{
		DEBUG(10,("domain_client_validate: srv trust valid:%s\n",
		           user));
		return status;
	}

	if (status == (NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT|0xc0000000))
	{
		DEBUG(10,("domain_client_validate: interdom trust valid:%s\n",
		           user));
		return status;
	}

	if (status != 0x0)
	{
		DEBUG(0,("domain_client_validate: unable to validate password for user %s in domain \
		%s to Domain controller %s.\n", user, domain, srv_name));
		return status;
	}

	/* grab the user session key - really important, this */
	if (user_sess_key != NULL)
	{
		memcpy(user_sess_key, info3.user_sess_key,
		       sizeof(info3.user_sess_key));
		dump_data_pw("user session key\n", user_sess_key, 16);
	}

	/*
	 * Here, if we really want it, we have lots of info about the user in info3.
	 * LKCLXXXX - really important to check things like "is this user acct
	 * locked out / disabled" etc!!!!
	 */

	DEBUG(10,("domain_client_validate: user %s\%s OK\n", domain, user));
	DEBUG(3,("domain_client_validate: check lockout / pwd expired!\n"));

	return 0x0;
}

/****************************************************************************
 Check for a valid username and password in security=domain mode.
****************************************************************************/
uint32 check_domain_security(char *orig_user, char *domain, 
				uchar *challenge,
				char *smb_apasswd, int smb_apasslen,
				char *smb_ntpasswd, int smb_ntpasslen,
				uchar user_sess_key[16],
				char lm_pw8[8])
{
	fstring acct_name;
	uint16 acct_type = 0;

	if (lp_security() == SEC_SHARE || lp_security() == SEC_SERVER)
	{
		return False;
	}

	if (domain == NULL || strequal(domain, ""))
	{
		domain = global_myworkgroup;
	}

	if (lp_security() == SEC_USER ||
	    (lp_security() == SEC_DOMAIN &&
	     strequal(domain, global_myworkgroup)))
	{
		fstrcpy(acct_name, global_myname);
		acct_type = SEC_CHAN_WKSTA;
	}
	else
	{
		fstrcpy(acct_name, global_myworkgroup);
		acct_type = SEC_CHAN_DOMAIN;
	}

	DEBUG(10,("check_domain_security: %s(%d)\n", acct_name, acct_type));

	return domain_client_validate(orig_user, domain, 
	                        acct_name, acct_type,
	                        challenge,
	                        smb_apasswd, smb_apasslen,
	                        smb_ntpasswd, smb_ntpasslen,
	                        user_sess_key, lm_pw8);
}
