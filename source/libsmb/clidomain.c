/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client generic functions
   Copyright (C) Andrew Tridgell 1994-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   
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
#include "nterr.h"
#include "trans2.h"

extern int DEBUGLEVEL;


/****************************************************************************
 connect to one of multiple servers: don't care which
****************************************************************************/
BOOL cli_connect_servers_auth(struct cli_state *cli,
				char *p,
				const struct ntuser_creds *usr)
{
	fstring remote_host;
	BOOL connected_ok = False;

	/*
	* Treat each name in the 'password server =' line as a potential
	* PDC/BDC. Contact each in turn and try and authenticate.
	*/

	DEBUG(10,("cli_connect_servers_auth: %s\n", p));

	while(p && next_token(&p,remote_host,LIST_SEP,sizeof(remote_host)))
	{
		fstring desthost;
		struct in_addr dest_ip;
		strupper(remote_host);

		if (!resolve_srv_name( remote_host, desthost, &dest_ip))
		{
			DEBUG(1,("Can't resolve address for %s\n", remote_host));
			continue;
		}   

		if (!cli_connect_auth(cli, desthost, &dest_ip, usr) &&
		    !cli_connect_auth(cli, "*SMBSERVER", &dest_ip, usr))
		{
			continue;
		}

		if (cli->protocol < PROTOCOL_LANMAN2 ||
		    !IS_BITS_SET_ALL(cli->sec_mode, 1))
		{
			DEBUG(1,("machine %s not in user level security mode\n",
				  remote_host));
			cli_shutdown(cli);
			continue;
		}

		/*
		 * We have an anonymous connection to IPC$.
		 */

		connected_ok = True;
		break;
	}

	if (!connected_ok)
	{
		DEBUG(0,("Domain password server not available.\n"));
	}

	return connected_ok;
}

/****************************************************************************
 connect to one of multiple servers: don't care which
****************************************************************************/
BOOL cli_connect_serverlist(struct cli_state *cli, char *p)
{
	fstring remote_host;
	fstring desthost;
	struct in_addr dest_ip;
	BOOL connected_ok = False;

	/*
	* Treat each name in the 'password server =' line as a potential
	* PDC/BDC. Contact each in turn and try and authenticate.
	*/

	while(p && next_token(&p,remote_host,LIST_SEP,sizeof(remote_host)))
	{
		ZERO_STRUCTP(cli);

		if (!cli_initialise(cli))
		{
			DEBUG(0,("cli_connect_serverlist: unable to initialise client connection.\n"));
			return False;
		}

		standard_sub_basic(remote_host);
		strupper(remote_host);

		if (!resolve_srv_name( remote_host, desthost, &dest_ip))
		{
			DEBUG(1,("cli_connect_serverlist: Can't resolve address for %s\n", remote_host));
			continue;
		}   

		if ((lp_security() != SEC_USER) && (ismyip(dest_ip)))
		{
			DEBUG(1,("cli_connect_serverlist: Password server loop - not using password server %s\n", remote_host));
			continue;
		}

		if (!cli_connect_auth(cli, remote_host , &dest_ip, NULL) &&
		    !cli_connect_auth(cli, "*SMBSERVER", &dest_ip, NULL))
		{
			continue;
		}


		if (cli->protocol < PROTOCOL_LANMAN2 ||
		    !IS_BITS_SET_ALL(cli->sec_mode, 1))
		{
			DEBUG(1,("cli_connect_serverlist: machine %s isn't in user level security mode\n",
				  remote_host));
			cli_shutdown(cli);
			continue;
		}

		/*
		 * We have an anonymous connection to IPC$.
		 */

		connected_ok = True;
		break;
	}

	if (!connected_ok)
	{
		DEBUG(0,("cli_connect_serverlist: Domain password server not available.\n"));
	}

	return connected_ok;
}

/****************************************************************************
 for a domain name, find any domain controller (PDC, BDC, don't care) name.
****************************************************************************/
BOOL get_any_dc_name(const char *domain, char *srv_name)
{
	extern pstring global_myname;
	struct cli_state cli;
	char *servers;

	DEBUG(10,("get_any_dc_name: domain %s\n", domain));

	if (strequal(domain, global_myname)
	    || strequal(domain, "Builtin"))
	{
		DEBUG(10,("get_any_dc_name: our own server!\n"));
		fstrcpy(srv_name, "\\\\.");
		return True;
	}

	servers = get_trusted_serverlist(domain);

	if (servers == NULL)
	{
		/* no domain found, not even our own domain. */
		return False;
	}

	if (servers[0] == 0)
	{
		/* empty list: return our own name */
		fstrcpy(srv_name, "\\\\.");
		return True;
	}

	if (!cli_connect_servers_auth(&cli, servers, NULL))
	{
		return False;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, cli.desthost);
	strupper(srv_name);

	cli_shutdown(&cli);

	return True;
}

