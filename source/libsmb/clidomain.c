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

