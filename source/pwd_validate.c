/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
   Copyright (C) Andrew Tridgell 1992-1997
   
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
extern int Protocol;


/****************************************************************************
initiates a connection to a user-level server.
****************************************************************************/
BOOL server_connect_init(struct cli_state *clnt, char my_netbios_name[16],
				struct in_addr dest_ip, char *desthost)
{
	DEBUG(5,("password server connection requested: %s [%s]\n",
		desthost, inet_ntoa(dest_ip)));

	if (clnt == NULL || !clnt->initialised)
	{
		DEBUG(1,("password server client state not initialised\n", desthost));
		return(False);
	}  

	if (!cli_connect(clnt, desthost, &dest_ip))
	{
		DEBUG(3,("connected to password server %s\n", desthost));
		return False;
	}

	if (!cli_session_request(clnt, desthost, 0x20, my_netbios_name, 0x0))
	{
		DEBUG(1,("%s rejected the session\n", desthost));
		return False;
	}

	DEBUG(3,("got session\n"));

	if (!cli_negprot(clnt))
	{
		DEBUG(1,("%s rejected the negprot\n", desthost));
		return False;
	}

	if (clnt->protocol < PROTOCOL_LANMAN2 || !(clnt->sec_mode & 1))
	{
		DEBUG(1,("%s isn't in user level security mode\n", desthost));
		return False;
	}

	DEBUG(3,("password server OK\n"));

	return True;
}

/****************************************************************************
support for server level security 
****************************************************************************/
BOOL server_cryptkey(struct cli_state *clnt, char my_netbios_name[16])
{
	fstring desthost;
	struct in_addr dest_ip;
	char *p;
	BOOL connection_found = False;

	if (clnt == NULL || !cli_initialise(clnt))
	{
		DEBUG(1,("server_cryptkey: failed to initialise client state\n"));
		return False;
	}
	    
	for (p = strtok(lp_passwordserver(),LIST_SEP); p && !connection_found; p = strtok(NULL,LIST_SEP))
	{
		fstrcpy(desthost,p);
		standard_sub_basic(desthost);
		strupper(desthost);

		dest_ip = *interpret_addr2(desthost);

		if (zero_ip(dest_ip))
		{
			DEBUG(1,("Can't resolve address for %s\n",p));
			continue;
		}

		if (ismyip(dest_ip))
		{
			DEBUG(1,("Password server loop - disabling password server %s\n", p));
			continue;
		}

		connection_found = server_connect_init(clnt, my_netbios_name, dest_ip, desthost);
	}

	if (!p && !connection_found)
	{
		DEBUG(1,("password server not available\n"));
		cli_shutdown(clnt);
		return False;
	}

	DEBUG(3,("password server OK\n"));

	return True;
}

/****************************************************************************
validate a password
****************************************************************************/
BOOL server_validate2(struct cli_state *clnt, char *user, char *domain, 
		     char *pass, int passlen,
		     char *ntpass, int ntpasslen)
{
	BOOL pwd_ok = False;

	DEBUG(4,("server_validate2: user:[%s] domain:[%s]\n", user, domain));

	if (clnt == NULL)
	{
		DEBUG(1,("server_validate2: NULL client_state. cannot validate\n"));
		return(False);
	}  

	if (pass == NULL && ntpass == NULL)
	{
		DEBUG(1,("server_validate2: both lm and nt passwords are NULL.  cannot validate\n"));
		return(False);
	}  
	
	if (!clnt->initialised)
	{
		DEBUG(1,("server %s is not connected\n", clnt->full_dest_host_name));
		return(False);
	}  

	if (!cli_session_setup(clnt, user, pass, passlen, ntpass, ntpasslen, domain)) {
		DEBUG(1,("server %s rejected the password\n", clnt->full_dest_host_name));
		return False;
	}

	if (!(BIT_SET(SVAL(clnt->inbuf,smb_vwv2), SESSION_LOGGED_ON_AS_USER)))
	{
		DEBUG(1,("server %s gave us guest access only\n", clnt->full_dest_host_name));
	}

	pwd_ok = False;

	if (!pwd_ok)
	{
		pwd_ok = pass != NULL && cli_send_tconX(clnt, "IPC$", "IPC", pass, passlen);
	}

	if (!pwd_ok)
	{
		DEBUG(1,("server %s refused IPC$ connect with LM password\n", clnt->full_dest_host_name));
	}

	if (!pwd_ok)
	{
		pwd_ok = ntpass != NULL && cli_send_tconX(clnt, "IPC$", "IPC", ntpass, ntpasslen);
	}

	if (!pwd_ok)
	{
		DEBUG(1,("server %s refused IPC$ connect with NT password\n", clnt->full_dest_host_name));
	}

	if (!pwd_ok)
	{
		DEBUG(3,("server %s rejected the password\n", clnt->full_dest_host_name));
	}
	else
	{
		DEBUG(3,("server %s accepted the password\n", clnt->full_dest_host_name));
	}

	cli_tdis(clnt);

	return pwd_ok;
}


/****************************************************************************
validate a password with the password server.  here's some good code to go
into an SMB pam, by the way...
****************************************************************************/
BOOL server_validate(struct cli_state *clnt, char *user, char *domain, 
		     char *pass, int passlen,
		     char *ntpass, int ntpasslen)
{
	if (clnt == NULL)
	{
		DEBUG(1,("server_validate: NULL client_state. cannot validate\n"));
		return(False);
	}  

	if (!clnt->initialised) {
		DEBUG(1,("password server %s is not connected\n", clnt->full_dest_host_name));
		return(False);
	}  

	if (!cli_session_setup(clnt, user, pass, passlen, ntpass, ntpasslen, domain)) {
		DEBUG(1,("password server %s rejected the password\n", clnt->full_dest_host_name));
		return False;
	}

	/* if logged in as guest then reject */
	if ((SVAL(clnt->inbuf,smb_vwv2) & 1) != 0) {
		DEBUG(1,("password server %s gave us guest only\n", clnt->full_dest_host_name));
		return(False);
	}


	if (!cli_send_tconX(clnt, "IPC$", "IPC", "", 1))
    {
		DEBUG(1,("password server %s refused IPC$ connect\n", clnt->full_dest_host_name));
		return False;
	}


	if (!cli_send_tconX(clnt, "IPC$", "IPC", "", 1)) {
		DEBUG(1,("password server %s refused IPC$ connect\n", clnt->full_dest_host_name));
		return False;
	}


	if (!cli_NetWkstaUserLogon(clnt, user, clnt->called_netbios_name))
	{
		DEBUG(1,("password server %s failed NetWkstaUserLogon\n", clnt->full_dest_host_name));
		cli_tdis(clnt);
		return False;
	}

	if (clnt->privileges == 0)
	{
		DEBUG(1,("password server %s gave guest privilages\n", clnt->full_dest_host_name));
		cli_tdis(clnt);
		return False;
	}

	if (!strequal(clnt->eff_name, user)) {
		DEBUG(1,("password server %s gave different username %s\n", 
			 clnt->full_dest_host_name,
			 clnt->eff_name));
		cli_tdis(clnt);
		return False;
	}

	DEBUG(3,("password server %s accepted the password\n", clnt->full_dest_host_name));

	cli_tdis(clnt);

	return(True);
}


