/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Jeremy Allison               1998-2000.
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

#include "includes.h"
#include "rpc_client.h"
#include "nterr.h"

extern int DEBUGLEVEL;
extern pstring global_myname;
extern pstring global_myworkgroup;

/*********************************************************
 Change the domain password on the PDC.
**********************************************************/

BOOL modify_trust_password(const char *domain, const char *srv_name,
			   const uchar orig_trust_passwd_hash[16],
			   const uchar new_trust_passwd_hash[16],
			   uint16 sec_chan)
{
	fstring trust_acct;
	uint16 validation_level;

	fstrcpy(trust_acct, global_myname);
	fstrcat(trust_acct, "$");

	if (cli_nt_setup_creds(srv_name, domain, global_myname, trust_acct,
			       orig_trust_passwd_hash, sec_chan,
			       &validation_level) != 0x0)
	{
		return False;
	}

	if (!cli_nt_srv_pwset(srv_name, global_myname, trust_acct,
			      new_trust_passwd_hash, sec_chan))
	{
		return False;
	}

	return True;
}

/***********************************************************************
 Do the same as security=server, but using NT Domain calls and a session
 key from the workstation trust account password.
************************************************************************/
uint32 domain_client_validate(const char *server,
			      const char *user, const char *domain,
			      const char *acct_name, uint16 acct_type,
			      const char *challenge,
			      const char *smb_apasswd,
			      int smb_apasslen,
			      const char *smb_ntpasswd,
			      int smb_ntpasslen, NET_USER_INFO_3 * info3)
{
	unsigned char trust_passwd[16];
	NET_ID_INFO_CTR ctr;
	uint32 smb_uid_low;
	uint32 status;
	fstring trust_acct;
	fstring srv_name;
	fstring sec_name;
	uint16 validation_level;
	BOOL cleartext = smb_apasslen != 0 && smb_apasslen != 24 &&
		smb_ntpasslen == 0;

	DEBUG(100, ("domain_client_validate: %s %s\n", user, domain));
	dump_data_pw("lmpw:", smb_apasswd, smb_apasslen);
	dump_data_pw("ntpw:", smb_ntpasswd, smb_ntpasslen);

	fstrcpy(trust_acct, acct_name);
	fstrcat(trust_acct, "$");

	if (server != NULL)
	{
		fstrcpy(srv_name, server);
	}
	else if (!get_any_dc_name(domain, srv_name))
	{
		DEBUG(3,
		      ("domain_client_validate: could not find domain %s, using local SAM\n",
		       domain));
		fstrcpy(srv_name, "\\\\.");
	}

	if (acct_type == SEC_CHAN_DOMAIN)
	{
		fstrcpy(sec_name, "G$$");
		fstrcat(sec_name, domain);
	}
	else
	{
		fstrcpy(sec_name, "$MACHINE.ACC");
	}

	if (!msrpc_lsa_query_trust_passwd("\\\\.", sec_name,
					  trust_passwd, NULL))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

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

	status = cli_nt_setup_creds(srv_name, domain, global_myname,
				    trust_acct, trust_passwd, acct_type,
				    &validation_level);
	if (status != 0x0)
	{
		DEBUG(0, ("domain_client_validate: credentials failed (%s)\n",
			  srv_name));
		return status;
	}

	/* We really don't care what LUID we give the user. */
	generate_random_buffer((unsigned char *)&smb_uid_low, 4, False);

	if (challenge == NULL && !cleartext)
	{
		status = cli_nt_login_interactive(srv_name,
						  global_myname,
						  domain, user,
						  smb_uid_low,
						  smb_apasswd, smb_ntpasswd,
						  &ctr, validation_level,
						  info3);
	}
	else if (challenge == NULL)
	{
		status = cli_nt_login_general(srv_name,
					      global_myname,
					      domain, user,
					      smb_uid_low,
					      smb_apasswd, &ctr,
					      validation_level, info3);
	}
	else
	{
		status = cli_nt_login_network(srv_name,
					      global_myname,
					      domain, user,
					      smb_uid_low,
					      (const char *)challenge,
					      (const uchar *)smb_apasswd,
					      smb_apasslen,
					      (const uchar *)smb_ntpasswd,
					      smb_ntpasslen, &ctr,
					      validation_level, info3);
	}

	if (status ==
	    (NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT | 0xc0000000))
	{
		DEBUG(10, ("domain_client_validate: wks trust valid:%s\n",
			   user));
		return status;
	}

	if (status == (NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT | 0xc0000000))
	{
		DEBUG(10, ("domain_client_validate: srv trust valid:%s\n",
			   user));
		return status;
	}

	if (status ==
	    (NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT | 0xc0000000))
	{
		DEBUG(10,
		      ("domain_client_validate: interdom trust valid:%s\n",
		       user));
		return status;
	}

	if (status != 0x0)
	{
		DEBUG(0, ("domain_client_validate: unable to validate \
			password for user %s in domain %s to \
			Domain controller %s.\n", user, domain, srv_name));
		return status;
	}

	/*
	 * Here, if we really want it, we have lots of info about the user in info3.
	 * LKCLXXXX - really important to check things like "is this user acct
	 * locked out / disabled" etc!!!!
	 */

	DEBUG(10, ("domain_client_validate: user %s\\%s OK\n", domain, user));
	DEBUG(3, ("domain_client_validate: check lockout / pwd expired!\n"));

	return 0x0;
}

/****************************************************************************
 Check for a valid username and password in security=domain mode.
****************************************************************************/
uint32 check_domain_security(const char *orig_user, const char *domain,
			     const uchar * challenge,
			     const char *smb_apasswd, int smb_apasslen,
			     const char *smb_ntpasswd, int smb_ntpasslen,
			     NET_USER_INFO_3 * info3)
{
	fstring acct_name;
	uint16 acct_type = 0;

	if (lp_security() == SEC_SHARE || lp_security() == SEC_SERVER)
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	if (domain == NULL || strequal(domain, ""))
	{
		domain = global_myworkgroup;
	}

	if (strequal(domain, global_myworkgroup) ||
	    strequal(domain, global_myname))
	{
		/*
		 * local
		 */
		fstrcpy(acct_name, global_myname);
		acct_type = SEC_CHAN_WKSTA;
	}
	else
	{
		/*
		 * hm, must be a trusted domain name.
		 */
		fstrcpy(acct_name, global_myworkgroup);
		acct_type = SEC_CHAN_DOMAIN;
	}

	DEBUG(10, ("check_domain_security: %s(%d)\n", acct_name, acct_type));

	return domain_client_validate(NULL, orig_user, domain,
				      acct_name, acct_type,
				      challenge,
				      smb_apasswd, smb_apasslen,
				      smb_ntpasswd, smb_ntpasslen, info3);
}
