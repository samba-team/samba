/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Authenticate to a remote server
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Andrew Bartlett 2001

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
 Return the client state structure.
****************************************************************************/

struct cli_state *server_client(void)
{
	static struct cli_state pw_cli;
	return &pw_cli;
}

/****************************************************************************
 Support for server level security.
****************************************************************************/

struct cli_state *server_cryptkey(void)
{
	struct cli_state *cli;
	fstring desthost;
	struct in_addr dest_ip;
	char *p, *pserver;
	BOOL connected_ok = False;

	cli = server_client();

	if (!cli_initialise(cli))
		return NULL;

        pserver = strdup(lp_passwordserver());
	p = pserver;

        while(next_token( &p, desthost, LIST_SEP, sizeof(desthost))) {
		standard_sub_basic(desthost);
		strupper(desthost);

		if(!resolve_name( desthost, &dest_ip, 0x20)) {
			DEBUG(1,("server_cryptkey: Can't resolve address for %s\n",desthost));
			continue;
		}

		if (ismyip(dest_ip)) {
			DEBUG(1,("Password server loop - disabling password server %s\n",desthost));
			continue;
		}

		if (cli_connect(cli, desthost, &dest_ip)) {
			DEBUG(3,("connected to password server %s\n",desthost));
			connected_ok = True;
			break;
		}
	}

	free(pserver);

	if (!connected_ok) {
		DEBUG(0,("password server not available\n"));
		cli_shutdown(cli);
		return NULL;
	}

	if (!attempt_netbios_session_request(cli, global_myname, desthost, &dest_ip))
		return NULL;

	DEBUG(3,("got session\n"));

	if (!cli_negprot(cli)) {
		DEBUG(1,("%s rejected the negprot\n",desthost));
		cli_shutdown(cli);
		return NULL;
	}

	if (cli->protocol < PROTOCOL_LANMAN2 ||
	    !(cli->sec_mode & 1)) {
		DEBUG(1,("%s isn't in user level security mode\n",desthost));
		cli_shutdown(cli);
		return NULL;
	}

	DEBUG(3,("password server OK\n"));

	return cli;
}


/****************************************************************************
 Validate a password with the password server.
****************************************************************************/

static uint32 server_validate(const auth_usersupplied_info *user_info, auth_serversupplied_info *server_info)
{
	struct cli_state *cli;
	static unsigned char badpass[24];
	static fstring baduser; 
	static BOOL tested_password_server = False;
	static BOOL bad_password_server = False;
	uint32 nt_status = NT_STATUS_LOGON_FAILURE;

	cli = server_client();

	if (!cli->initialised) {
		DEBUG(1,("password server %s is not connected\n", cli->desthost));
		return(NT_STATUS_LOGON_FAILURE);
	}  

	if(badpass[0] == 0)
		memset(badpass, 0x1f, sizeof(badpass));

	if((user_info->nt_resp.len == sizeof(badpass)) && 
	   !memcmp(badpass, user_info->nt_resp.buffer, sizeof(badpass))) {
		/* 
		 * Very unlikely, our random bad password is the same as the users
		 * password.
		 */
		memset(badpass, badpass[0]+1, sizeof(badpass));
	}

	if(baduser[0] == 0) {
		fstrcpy(baduser, INVALID_USER_PREFIX);
		fstrcat(baduser, global_myname);
	}

	/*
	 * Attempt a session setup with a totally incorrect password.
	 * If this succeeds with the guest bit *NOT* set then the password
	 * server is broken and is not correctly setting the guest bit. We
	 * need to detect this as some versions of NT4.x are broken. JRA.
	 */

	/* I sure as hell hope that there arn't servers out there that take 
	 * NTLMv2 and have this bug, as we don't test for that... 
	 *  - abartlet@samba.org
	 */

	if(!tested_password_server) {
		if (cli_session_setup(cli, baduser, (char *)badpass, sizeof(badpass), 
					(char *)badpass, sizeof(badpass), user_info->domain.str)) {

			/*
			 * We connected to the password server so we
			 * can say we've tested it.
			 */
			tested_password_server = True;

			if ((SVAL(cli->inbuf,smb_vwv2) & 1) == 0) {
				DEBUG(0,("server_validate: password server %s allows users as non-guest \
with a bad password.\n", cli->desthost));
				DEBUG(0,("server_validate: This is broken (and insecure) behaviour. Please do not \
use this machine as the password server.\n"));
				cli_ulogoff(cli);

				/*
				 * Password server has the bug.
				 */
				bad_password_server = True;
				return NT_STATUS_LOGON_FAILURE;
			}
			cli_ulogoff(cli);
		}
	} else {

		/*
		 * We have already tested the password server.
		 * Fail immediately if it has the bug.
		 */

		if(bad_password_server) {
			DEBUG(0,("server_validate: [1] password server %s allows users as non-guest \
with a bad password.\n", cli->desthost));
			DEBUG(0,("server_validate: [1] This is broken (and insecure) behaviour. Please do not \
use this machine as the password server.\n"));
			return NT_STATUS_LOGON_FAILURE;
		}
	}

	/*
	 * Now we know the password server will correctly set the guest bit, or is
	 * not guest enabled, we can try with the real password.
	 */

	if (!cli_session_setup(cli, user_info->smb_username.str, 
			       user_info->lm_resp.buffer, 
			       user_info->lm_resp.len, 
			       user_info->nt_resp.buffer, 
			       user_info->nt_resp.len, 
			       user_info->domain.str)) {
		DEBUG(1,("password server %s rejected the password\n", cli->desthost));
		/* Make this cli_nt_error() when the conversion is in */
		nt_status = NT_STATUS_LOGON_FAILURE;
	} else {
		nt_status = NT_STATUS_NOPROBLEMO;
	}

	/* if logged in as guest then reject */
	if ((SVAL(cli->inbuf,smb_vwv2) & 1) != 0) {
		DEBUG(1,("password server %s gave us guest only\n", cli->desthost));
		nt_status = NT_STATUS_LOGON_FAILURE;
	}

	cli_ulogoff(cli);

	return(nt_status);
}

/****************************************************************************
 Check for a valid username and password in security=server mode.
****************************************************************************/

uint32 check_server_security(const auth_usersupplied_info *user_info, auth_serversupplied_info *server_info)
{
	
	if(lp_security() != SEC_SERVER)
		return NT_STATUS_LOGON_FAILURE;
	
	return server_validate(user_info, server_info);

}


