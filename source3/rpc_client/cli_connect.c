/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client generic functions
   Copyright (C) Andrew Tridgell 1994-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   
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

#define NO_SYSLOG

#include "includes.h"
#include "trans2.h"

struct user_credentials *usr_creds = NULL;

extern int DEBUGLEVEL;
extern pstring scope;
extern pstring global_myname;

struct cli_connection
{
	struct cli_state *cli;
	uint16 fnum;
};


/****************************************************************************
terminate client connection
****************************************************************************/
void cli_connection_free(struct cli_connection *con)
{
	cli_nt_session_close(con->cli, con->fnum);
	cli_shutdown(con->cli);
	free(con->cli);
	free(con);
}

/****************************************************************************
terminate client state
****************************************************************************/
void cli_connection_unlink(struct cli_connection *con)
{
	if (con != NULL)
	{
		cli_connection_free(con);
	}
	return;
}

/****************************************************************************
init client state
****************************************************************************/
BOOL cli_connection_init_list(char* servers, const char* pipe_name,
				struct cli_connection **con)
{
	BOOL res = True;

	/*
	 * allocate
	 */

	(*con) = (struct cli_connection*)malloc(sizeof(**con));

	if ((*con) == NULL)
	{
		return False;
	}

	(*con)->cli = cli_initialise(NULL);
	(*con)->fnum = 0xffff;

	if ((*con)->cli == NULL)
	{
		return False;
	}

	/*
	 * initialise
	 */

	(*con)->cli->capabilities |= CAP_NT_SMBS | CAP_STATUS32;
	cli_init_creds((*con)->cli, usr_creds);

	(*con)->cli->use_ntlmv2 = lp_client_ntlmv2();

	if (!cli_connect_serverlist((*con)->cli, servers))
	{
		DEBUG(0,("cli_state_init: connection failed\n"));
		cli_connection_free((*con));
		return False;
	}

	(*con)->cli->ntlmssp_cli_flgs = 0x0;

	res = res ? cli_nt_session_open((*con)->cli, pipe_name,
	                               &(*con)->fnum) : False;

	return res;
}

/****************************************************************************
init client state
****************************************************************************/
BOOL cli_connection_init(const char* server_name, const char* pipe_name,
				struct cli_connection **con)
{
	struct nmb_name calling;
	struct nmb_name called;
	struct in_addr *dest_ip = NULL;
	fstring dest_host;
	struct in_addr ip;

	BOOL res = True;

	/*
	 * allocate
	 */

	(*con) = (struct cli_connection*)malloc(sizeof(**con));

	if ((*con) == NULL)
	{
		return False;
	}

	(*con)->cli = cli_initialise(NULL);
	(*con)->fnum = 0xffff;

	if ((*con)->cli == NULL)
	{
		return False;
	}

	/*
	 * initialise
	 */

	(*con)->cli->capabilities |= CAP_NT_SMBS | CAP_STATUS32;
	cli_init_creds((*con)->cli, usr_creds);

	(*con)->cli->use_ntlmv2 = lp_client_ntlmv2();

	if (resolve_srv_name(server_name, dest_host, &ip))
	{
		dest_ip = &ip;
	}
	else
	{
		return False;
	}

	make_nmb_name(&called , dns_to_netbios_name(dest_host    ), 32, scope);
	make_nmb_name(&calling, dns_to_netbios_name(global_myname),  0, scope);

	/*
	 * connect
	 */

	if (!cli_establish_connection((*con)->cli, 
	                          dest_host, dest_ip,
	                          &calling, &called,
	                          "IPC$", "IPC",
	                          False, True))
	{
		DEBUG(0,("cli_state_init: connection failed\n"));
		cli_connection_free((*con));
		return False;
	}

	(*con)->cli->ntlmssp_cli_flgs = 0x0;

	res = res ? cli_nt_session_open((*con)->cli, pipe_name,
	                               &(*con)->fnum) : False;

	return res;
}

/****************************************************************************
obtain client state
****************************************************************************/
BOOL cli_connection_get(const POLICY_HND *pol, struct cli_connection **con)
{
	return get_policy_con(pol, con);
}

/****************************************************************************
link a child policy handle to a parent one
****************************************************************************/
BOOL cli_pol_link(POLICY_HND *to, const POLICY_HND *from)
{
	struct cli_connection *con = NULL;

	if (!cli_connection_get(from, &con))
	{
		return False;
	}

	return register_policy_hnd(to) && set_policy_con(to, con, NULL);
}

/****************************************************************************
get a user session key associated with a connection associated with a
policy handle.
****************************************************************************/
BOOL cli_get_usr_sesskey(const POLICY_HND *pol, uchar sess_key[16])
{
	struct cli_connection *con = NULL;

	if (!cli_connection_get(pol, &con))
	{
		return False;
	}

	memcpy(sess_key, con->cli->sess_key, sizeof(con->cli->sess_key));

	return True;
}

/****************************************************************************
 send a request on an rpc pipe.
 ****************************************************************************/
BOOL rpc_hnd_pipe_req(const POLICY_HND *hnd, uint8 op_num,
                      prs_struct *data, prs_struct *rdata)
{
	struct cli_connection *con = NULL;

	if (!cli_connection_get(hnd, &con))
	{
		return False;
	}

	return rpc_con_pipe_req(con, op_num, data, rdata);
}

/****************************************************************************
 send a request on an rpc pipe.
 ****************************************************************************/
BOOL rpc_con_pipe_req(struct cli_connection *con, uint8 op_num,
                      prs_struct *data, prs_struct *rdata)
{
	return rpc_api_pipe_req(con->cli, con->fnum, op_num, data, rdata);
}
