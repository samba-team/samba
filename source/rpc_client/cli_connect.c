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

/****************************************************************************
terminate client state
****************************************************************************/
void cli_state_free(struct cli_state *cli, uint16 fnum)
{
	cli_nt_session_close(cli, fnum);
	cli_shutdown(cli);
	free(cli);
}

/****************************************************************************
init client state
****************************************************************************/
BOOL cli_state_init(const char* server_name, const char* pipe_name,
				struct cli_state **cli,
				uint16 *fnum)
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

	*cli = cli_initialise(NULL);

	if ((*cli) == NULL)
	{
		return False;
	}

	/*
	 * initialise
	 */

	(*cli)->capabilities |= CAP_NT_SMBS | CAP_STATUS32;
	cli_init_creds(*cli, usr_creds);

	(*cli)->use_ntlmv2 = lp_client_ntlmv2();

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

	if (!cli_establish_connection((*cli), 
	                          dest_host, dest_ip,
	                          &calling, &called,
	                          "IPC$", "IPC",
	                          False, True))
	{
		DEBUG(0,("cli_state_init: connection failed\n"));
		cli_shutdown((*cli));
		free(*cli);
		return False;
	}

	(*cli)->ntlmssp_cli_flgs = 0x0;

	res = res ? cli_nt_session_open(*cli, pipe_name, fnum) : False;

	return res;
}

/****************************************************************************
obtain client state
****************************************************************************/
BOOL cli_state_get(const POLICY_HND *pol,
				struct cli_state **cli,
				uint16 *fnum)
{
	return get_policy_cli_state(pol, cli, fnum);
}

/****************************************************************************
link a child policy handle to a parent one
****************************************************************************/
BOOL cli_pol_link(POLICY_HND *to, const POLICY_HND *from)
{
	struct cli_state *cli = NULL;
	uint16 fnum = 0xffff;

	if (!cli_state_get(from, &cli, &fnum))
	{
		return False;
	}

	return register_policy_hnd(to) &&
		set_policy_cli_state(to, cli, fnum, NULL);
}

BOOL cli_get_usr_sesskey(const POLICY_HND *pol, uchar sess_key[16])
{
	struct cli_state *cli = NULL;
	uint16 fnum = 0xffff;

	if (!cli_state_get(pol, &cli, &fnum))
	{
		return False;
	}

	memcpy(sess_key, cli->sess_key, sizeof(cli->sess_key));

	return True;
}
