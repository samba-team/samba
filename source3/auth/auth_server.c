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

extern pstring global_myname;
extern userdom_struct current_user_info;

/****************************************************************************
 Support for server level security.
****************************************************************************/

static struct cli_state *server_cryptkey(TALLOC_CTX *mem_ctx)
{
	struct cli_state *cli = NULL;
	fstring desthost;
	struct in_addr dest_ip;
	char *p, *pserver;
	BOOL connected_ok = False;

	if (!(cli = cli_initialise(cli)))
		return NULL;

	/* security = server just can't function with spnego */
	cli->use_spnego = False;

        pserver = talloc_strdup(mem_ctx, lp_passwordserver());
	p = pserver;

        while(next_token( &p, desthost, LIST_SEP, sizeof(desthost))) {
		standard_sub_basic(current_user_info.smb_name, desthost);
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

	if (!connected_ok) {
		DEBUG(0,("password server not available\n"));
		cli_shutdown(cli);
		return NULL;
	}

	if (!attempt_netbios_session_request(cli, global_myname, desthost, &dest_ip))
		return NULL;
	
	if (strequal(desthost,myhostname())) {
		exit_server("Password server loop!");
	}
	
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
 Clean up our allocated cli.
****************************************************************************/

static void free_server_private_data(void **private_data_pointer) 
{
	struct cli_state **cli = (struct cli_state **)private_data_pointer;
	if (*cli && (*cli)->initialised) {
		cli_shutdown(*cli);
	}
}

/****************************************************************************
 Send a 'keepalive' packet down the cli pipe.
****************************************************************************/

static void send_server_keepalive(void **private_data_pointer) 
{
	struct cli_state **cli = (struct cli_state **)private_data_pointer;
	
	/* also send a keepalive to the password server if its still
	   connected */
	if (cli && *cli && (*cli)->initialised) {
		if (!send_keepalive((*cli)->fd)) {
			DEBUG( 2, ( "password server keepalive failed.\n"));
			cli_shutdown(*cli);
		}
	}
}

/****************************************************************************
 Get the challenge out of a password server.
****************************************************************************/

static DATA_BLOB auth_get_challenge_server(const struct auth_context *auth_context,
					   void **my_private_data, 
					   TALLOC_CTX *mem_ctx)
{
	struct cli_state *cli = server_cryptkey(mem_ctx);
	
	if (cli) {
		DEBUG(3,("using password server validation\n"));

		if ((cli->sec_mode & 2) == 0) {
			/* We can't work with unencrypted password servers
			   unless 'encrypt passwords = no' */
			DEBUG(5,("make_auth_info_server: Server is unencrypted, no challenge available..\n"));
			
			/* However, it is still a perfectly fine connection
			   to pass that unencrypted password over */
			*my_private_data = (void *)cli;
			return data_blob(NULL, 0);
			
		} else if (cli->secblob.length < 8) {
			/* We can't do much if we don't get a full challenge */
			DEBUG(2,("make_auth_info_server: Didn't receive a full challenge from server\n"));
			cli_shutdown(cli);
			return data_blob(NULL, 0);
		}

		*my_private_data = (void *)cli;

		/* The return must be allocated on the caller's mem_ctx, as our own will be
		   destoyed just after the call. */
		return data_blob_talloc(auth_context->mem_ctx, cli->secblob.data,8);
	} else {
		return data_blob(NULL, 0);
	}
}


/****************************************************************************
 Check for a valid username and password in security=server mode.
  - Validate a password with the password server.
****************************************************************************/

static NTSTATUS check_smbserver_security(const struct auth_context *auth_context,
					 void *my_private_data, 
					 TALLOC_CTX *mem_ctx,
					 const auth_usersupplied_info *user_info, 
					 auth_serversupplied_info **server_info)
{
	struct cli_state *cli;
	static unsigned char badpass[24];
	static fstring baduser; 
	static BOOL tested_password_server = False;
	static BOOL bad_password_server = False;
	NTSTATUS nt_status = NT_STATUS_LOGON_FAILURE;
	BOOL locally_made_cli = False;

	/* 
	 * Check that the requested domain is not our own machine name.
	 * If it is, we should never check the PDC here, we use our own local
	 * password file.
	 */

	if(is_netbios_alias_or_name(user_info->domain.str)) {
		DEBUG(3,("check_smbserver_security: Requested domain was for this machine.\n"));
		return NT_STATUS_LOGON_FAILURE;
	}

	cli = my_private_data;
	
	if (cli) {
	} else {
		cli = server_cryptkey(mem_ctx);
		locally_made_cli = True;
	}

	if (!cli || !cli->initialised) {
		DEBUG(1,("password server is not connected (cli not initilised)\n"));
		return NT_STATUS_LOGON_FAILURE;
	}  
	
	if ((cli->sec_mode & 2) == 0) {
		if (user_info->encrypted) {
			DEBUG(1,("password server %s is plaintext, but we are encrypted. This just can't work :-(\n", cli->desthost));
			return NT_STATUS_LOGON_FAILURE;		
		}
	} else {
		if (memcmp(cli->secblob.data, auth_context->challenge.data, 8) != 0) {
			DEBUG(1,("the challenge that the password server (%s) supplied us is not the one we gave our client. This just can't work :-(\n", cli->desthost));
			return NT_STATUS_LOGON_FAILURE;		
		}
	}

	if(badpass[0] == 0)
		memset(badpass, 0x1f, sizeof(badpass));

	if((user_info->nt_resp.length == sizeof(badpass)) && 
	   !memcmp(badpass, user_info->nt_resp.data, sizeof(badpass))) {
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

	if ((!tested_password_server) && (lp_paranoid_server_security())) {
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

	if (!user_info->encrypted) {
		/* Plaintext available */
		if (!cli_session_setup(cli, user_info->smb_name.str, 
				       (char *)user_info->plaintext_password.data, 
				       user_info->plaintext_password.length, 
				       NULL, 0,
				       user_info->domain.str)) {
			DEBUG(1,("password server %s rejected the password\n", cli->desthost));
			/* Make this cli_nt_error() when the conversion is in */
			nt_status = cli_nt_error(cli);
		} else {
			nt_status = NT_STATUS_OK;
		}
	} else {
		if (!cli_session_setup(cli, user_info->smb_name.str, 
				       (char *)user_info->lm_resp.data, 
				       user_info->lm_resp.length, 
				       (char *)user_info->nt_resp.data, 
				       user_info->nt_resp.length, 
				       user_info->domain.str)) {
			DEBUG(1,("password server %s rejected the password\n", cli->desthost));
			/* Make this cli_nt_error() when the conversion is in */
			nt_status = cli_nt_error(cli);
		} else {
			nt_status = NT_STATUS_OK;
		}
	}

	/* if logged in as guest then reject */
	if ((SVAL(cli->inbuf,smb_vwv2) & 1) != 0) {
		DEBUG(1,("password server %s gave us guest only\n", cli->desthost));
		nt_status = NT_STATUS_LOGON_FAILURE;
	}

	cli_ulogoff(cli);

	if NT_STATUS_IS_OK(nt_status) {
		struct passwd *pass = Get_Pwnam(user_info->internal_username.str);
		if (pass) {
			if (!make_server_info_pw(server_info, pass)) { 
				nt_status = NT_STATUS_NO_MEMORY;
			}
		} else {
			nt_status = NT_STATUS_NO_SUCH_USER;
		}
	}

	if (locally_made_cli) {
		cli_shutdown(cli);
	}

	return(nt_status);
}

BOOL auth_init_smbserver(struct auth_context *auth_context, auth_methods **auth_method) 
{
	if (!make_auth_methods(auth_context, auth_method)) {
		return False;
	}
	(*auth_method)->auth = check_smbserver_security;
	(*auth_method)->get_chal = auth_get_challenge_server;
	(*auth_method)->send_keepalive = send_server_keepalive;
	(*auth_method)->free_private_data = free_server_private_data;
	return True;
}
