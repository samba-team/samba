/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Jeremy Allison  1999.
   
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

extern fstring global_myworkgroup;
extern pstring global_myname;

/****************************************************************************
Initialize domain session credentials.
****************************************************************************/

NTSTATUS cli_nt_setup_creds(struct cli_state *cli, unsigned char mach_pwd[16])
{
	NTSTATUS result;
	DOM_CHAL clnt_chal;
	DOM_CHAL srv_chal;

	UTIME zerotime;

	/******************* Request Challenge ********************/

	generate_random_buffer( clnt_chal.data, 8, False);
	
	/* Send a client challenge; receive a server challenge */
	if (!cli_net_req_chal(cli, &clnt_chal, &srv_chal)) {
		DEBUG(0,("cli_nt_setup_creds: request challenge failed\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/**************** Long-term Session key **************/

	/* calculate the session key */
	cred_session_key(&clnt_chal, &srv_chal, (uchar *)mach_pwd, cli->sess_key);
	memset((char *)cli->sess_key+8, '\0', 8);

	/******************* Authenticate 2 ********************/

	/* Calculate auth-2 credentials */
	zerotime.time = 0;
	cred_create(cli->sess_key, &clnt_chal, zerotime, &(cli->clnt_cred.challenge));

	/*  
	 * Send client auth-2 challenge.
	 * Receive an auth-2 challenge response and check it.
	 */

	result = cli_net_auth2(cli, (lp_server_role() == ROLE_DOMAIN_MEMBER) ?
			SEC_CHAN_WKSTA : SEC_CHAN_BDC, 0x000001ff, &srv_chal);
  
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0,("cli_nt_setup_creds: auth2 challenge failed\n"));
		return result;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Set machine password.
 ****************************************************************************/

BOOL cli_nt_srv_pwset(struct cli_state *cli, unsigned char *new_hashof_mach_pwd)
{
	unsigned char processed_new_pwd[16];

	DEBUG(5,("cli_nt_srv_pwset: %d\n", __LINE__));

#ifdef DEBUG_PASSWORD
	dump_data(6, (char *)new_hashof_mach_pwd, 16);
#endif

	/* Process the new password. */
	cred_hash3( processed_new_pwd, new_hashof_mach_pwd, cli->sess_key, 1);

	/* Send client srv_pwset challenge */
	return cli_net_srv_pwset(cli, processed_new_pwd);
}

/****************************************************************************
NT login - interactive.
*NEVER* use this code. This method of doing a logon (sending the cleartext
password equivalents, protected by the session key) is inherently insecure
given the current design of the NT Domain system. JRA.
 ****************************************************************************/

NTSTATUS cli_nt_login_interactive(struct cli_state *cli, char *unix_domain, char *unix_username, 
				uint32 smb_userid_low, char *unix_password,
				NET_ID_INFO_CTR *ctr, NET_USER_INFO_3 *user_info3)
{
	fstring dos_password, dos_username, dos_domain;
	uchar lm_owf_user_pwd[16];
	uchar nt_owf_user_pwd[16];
	NTSTATUS ret;

	DEBUG(5,("cli_nt_login_interactive: %d\n", __LINE__));

	fstrcpy(dos_password, unix_password);
	unix_to_dos(dos_password);
	fstrcpy(dos_username, unix_username);
	unix_to_dos(dos_username);
	fstrcpy(dos_domain, unix_domain);
	unix_to_dos(dos_domain);

	nt_lm_owf_gen(dos_password, nt_owf_user_pwd, lm_owf_user_pwd);

#ifdef DEBUG_PASSWORD

	DEBUG(100,("nt owf of user password: "));
	dump_data(100, (char *)lm_owf_user_pwd, 16);

	DEBUG(100,("nt owf of user password: "));
	dump_data(100, (char *)nt_owf_user_pwd, 16);

#endif

	DEBUG(5,("cli_nt_login_interactive: %d\n", __LINE__));

	/* indicate an "interactive" login */
	ctr->switch_value = INTERACTIVE_LOGON_TYPE;

	/* Create the structure needed for SAM logon. */
	init_id_info1(&ctr->auth.id1, dos_domain, 0, 
		smb_userid_low, 0,
		dos_username, cli->clnt_name_slash,
		(char *)cli->sess_key, lm_owf_user_pwd, nt_owf_user_pwd);

	/* Ensure we overwrite all the plaintext password equivalents. */
	memset(lm_owf_user_pwd, '\0', sizeof(lm_owf_user_pwd));
	memset(nt_owf_user_pwd, '\0', sizeof(nt_owf_user_pwd));

	/* Send client sam-logon request - update credentials on success. */
	ret = cli_net_sam_logon(cli, ctr, user_info3);

	memset(ctr->auth.id1.lm_owf.data, '\0', sizeof(lm_owf_user_pwd));
	memset(ctr->auth.id1.nt_owf.data, '\0', sizeof(nt_owf_user_pwd));

	return ret;
}

/****************************************************************************
NT login - network.
*ALWAYS* use this call to validate a user as it does not expose plaintext
password equivalents over the network. JRA.
****************************************************************************/

NTSTATUS cli_nt_login_network(struct cli_state *cli, char *unix_domain, char *unix_username, 
				uint32 smb_userid_low, const char lm_chal[8], 
				const char *lm_chal_resp, const char *nt_chal_resp,
				NET_ID_INFO_CTR *ctr, NET_USER_INFO_3 *user_info3)
{
	fstring dos_wksta_name, dos_username, dos_domain;
	DEBUG(5,("cli_nt_login_network: %d\n", __LINE__));
	/* indicate a "network" login */
	ctr->switch_value = NET_LOGON_TYPE;

	fstrcpy(dos_wksta_name, cli->clnt_name_slash);
	unix_to_dos(dos_wksta_name);

	fstrcpy(dos_username, unix_username);
	unix_to_dos(dos_username);

	fstrcpy(dos_domain, unix_domain);
	unix_to_dos(dos_domain);

	/* Create the structure needed for SAM logon. */
	init_id_info2(&ctr->auth.id2, dos_domain, 0, smb_userid_low, 0,
		dos_username, dos_wksta_name,
		(const uchar *)lm_chal, (const uchar *)lm_chal_resp, lm_chal_resp ? 24 : 0,
		(const uchar *)nt_chal_resp, nt_chal_resp ? 24 : 0 );

	/* Send client sam-logon request - update credentials on success. */
	return cli_net_sam_logon(cli, ctr, user_info3);
}

/****************************************************************************
NT Logoff.
****************************************************************************/

BOOL cli_nt_logoff(struct cli_state *cli, NET_ID_INFO_CTR *ctr)
{
	DEBUG(5,("cli_nt_logoff: %d\n", __LINE__));

	/* Send client sam-logoff request - update credentials on success. */
	return cli_net_sam_logoff(cli, ctr);
}
