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
static BOOL domain_client_validate( char *user, char *domain, 
				char *acct_name, uint16 acct_type,
				char *challenge,
				char *smb_apasswd, int smb_apasslen, 
				char *smb_ntpasswd, int smb_ntpasslen,
				uchar user_sess_key[16])
{
	unsigned char local_challenge[8];
	unsigned char local_lm_response[24];
	unsigned char local_nt_reponse[24];
	unsigned char trust_passwd[16];
	NET_ID_INFO_CTR ctr;
	NET_USER_INFO_3 info3;
	uint32 smb_uid_low;
	fstring trust_acct;
	fstring srv_name;

	fstrcpy(trust_acct, acct_name);
	fstrcat(trust_acct, "$");

	/* 
	* Check that the requested domain is not our own machine name.
	* If it is, we should never check the PDC here, we use our own local
	* password file.
	*/

	if(strequal( domain, global_myname))
	{
		DEBUG(5,("domain_client_validate: domain is for this machine.\n"));
		return False;
	}

	if (!get_any_dc_name(domain, srv_name))
	{
		DEBUG(3,("domain_client_validate: could not find domain %s\n",
				domain));
		return False;
	}

	/*
	 * Next, check that the passwords given were encrypted.
	 */

	if(((smb_apasslen  != 24) && (smb_apasslen  != 0)) || 
	   ((smb_ntpasslen <= 24) && (smb_ntpasslen != 0)))
	{
		/*
		 * Not encrypted - do so.
		 */

		DEBUG(3,("domain_client_validate: User passwords not in encrypted format.\n"));
		generate_random_buffer( local_challenge, 8, False);
		SMBencrypt( (uchar *)smb_apasswd, local_challenge, local_lm_response);
		SMBNTencrypt((uchar *)smb_ntpasswd, local_challenge, local_nt_reponse);
		smb_apasslen = 24;
		smb_ntpasslen = 24;
		smb_apasswd = (char *)local_lm_response;
		smb_ntpasswd = (char *)local_nt_reponse;
		challenge = local_challenge;
	}

	/*
	 * Get the workstation trust account password.
	 */
	if (strequal(&srv_name[2], acct_name))
	{
		/* loop-back to ourselves */
		memset(trust_passwd, 0, sizeof(trust_passwd));
	}
	else if (!trust_get_passwd( trust_passwd, domain, acct_name))
	{
		return False;
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

	if(cli_nt_setup_creds(srv_name, global_myname, trust_acct,
	                      trust_passwd, acct_type) != 0x0)
	{
		DEBUG(0,("domain_client_validate: unable to setup the PDC credentials to machine \
		%s.\n", srv_name));
		return False;
	}

	/* We really don't care what LUID we give the user. */
	generate_random_buffer( (unsigned char *)&smb_uid_low, 4, False);

	if (!cli_nt_login_network(srv_name, global_myname, 
	                domain, user,
	               smb_uid_low, (char *)challenge,
			((smb_apasslen != 0) ? smb_apasswd : NULL),
			((smb_ntpasslen != 0) ? smb_ntpasswd : NULL),
			&ctr, &info3))
	{
		DEBUG(0,("domain_client_validate: unable to validate password for user %s in domain \
		%s to Domain controller %s.\n", user, domain, srv_name));
		return False;
	}

	/* grab the user session key - really important, this */
	memcpy(user_sess_key, info3.user_sess_key, sizeof(info3.user_sess_key));

	/*
	 * Here, if we really want it, we have lots of info about the user in info3.
	 * LKCLXXXX - really important to check things like "is this user acct
	 * locked out / disabled" etc!!!!
	 */

	return True;
}

/****************************************************************************
 Check for a valid username and password in security=domain mode.
****************************************************************************/
BOOL check_domain_security(char *orig_user, char *domain, 
				uchar *challenge,
				char *smb_apasswd, int smb_apasslen,
				char *smb_ntpasswd, int smb_ntpasslen,
				uchar user_sess_key[16])
{
	fstring acct_name;
	uint16 acct_type = 0;

	if (lp_security() == SEC_SHARE || lp_security() == SEC_SERVER)
	{
		return False;
	}
	
	if (lp_security() == SEC_DOMAIN && strequal(domain, global_myworkgroup))
	{
		fstrcpy(acct_name, global_myname);
		acct_type = SEC_CHAN_WKSTA;
	}
	else
	{
		fstrcpy(acct_name, global_myworkgroup);
		acct_type = SEC_CHAN_DOMAIN;
	}

	return domain_client_validate(orig_user, domain, 
	                        acct_name, acct_type,
	                        challenge,
	                        smb_apasswd, smb_apasslen,
	                        smb_ntpasswd, smb_ntpasslen,
	                        user_sess_key);
}
