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
#include "rpc_client_proto.h"

extern int DEBUGLEVEL;
extern struct in_addr ipzero;

/****************************************************************************
 * make a connection to a server.
 ****************************************************************************/
static BOOL cli_connect_auth(struct cli_state *cli,
				const char* desthost,
				struct in_addr *dest_ip,
				const struct ntuser_creds *usr)
{
	extern pstring global_myname;
	struct nmb_name calling, called;

	ZERO_STRUCTP(cli);
	if (!cli_initialise(cli))
	{
		DEBUG(0,("unable to initialise client connection.\n"));
		return False;
	}

	make_nmb_name(&calling, global_myname, 0x0 );
	make_nmb_name(&called , desthost     , 0x20);

	cli_init_creds(cli, usr);

	if (!cli_establish_connection(cli, desthost, dest_ip,
				      &calling, &called,
				      "IPC$", "IPC", 
				      False, True))
	{
		cli_shutdown(cli);
		return False;
	}

	return True;
}

BOOL get_dc_name(const char *domain, char *server, int type)
{
	struct in_addr ip;
	extern pstring global_myname;

	if (!resolve_name(domain, &ip, type)) return False;

	return lookup_pdc_name(global_myname, domain, &ip, server);
}

/****************************************************************************
 obtains a list of PDCs / BDCs to contact, given the domain name.
 return result is char*, comma-separated: PDC, BDC1, BDC2 ...
****************************************************************************/
char *get_trusted_serverlist(const char *domain)
{
	pstring tmp;
	static pstring srv_list;
	char *trusted_list = lp_trusted_domains();

	if (domain == NULL ||
	    strequal(domain, "") || strequal(lp_workgroup(), domain))
	{
		pstrcpy(srv_list, lp_passwordserver());

		if (lp_wildcard_dc())
		{
			if (!get_dc_name(lp_workgroup(), srv_list, 0x1c))
				return NULL;
		}

		DEBUG(10, ("local domain server list: %s\n", srv_list));
		return srv_list;
	}

	if (!next_token(&trusted_list, tmp, NULL, sizeof(tmp)))
	{
		return NULL;
	}

	do
	{
		fstring trust_dom;
		split_at_first_component(tmp, trust_dom, '=', srv_list);

		if (strequal(domain, trust_dom))
		{
			DEBUG(10, ("trusted: %s\n", srv_list));
			if (strequal(srv_list, "*") &&
			    !get_dc_name(domain, srv_list, 0x1c))
			{
				return NULL;
			}
			return srv_list;
		}

	}
	while (next_token(NULL, tmp, NULL, sizeof(tmp)));

	return NULL;
}

/****************************************************************************
 connect to one of multiple servers: don't care which
****************************************************************************/
BOOL cli_connect_servers_auth(struct cli_state *cli,
				char *server,
				const struct ntuser_creds *usr)
{
	char *p = server;
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

/***********************************************************************
 Connect to a remote machine for domain security authentication
 given a name or IP address.
************************************************************************/

extern pstring global_myname;

static BOOL attempt_connect_dc(char *domain, struct in_addr dest_ip)
{
	fstring remote_machine;
	struct cli_state cli;
	uint16 fnum;
	
	/* Don't check ipzero addresses */

	if (ip_equal(ipzero, dest_ip)) return False;

	/* Look up remote name */

	if (!lookup_pdc_name(global_myname, domain, &dest_ip, 
			     remote_machine)) {
		DEBUG(0,("unable to lookup pdc name for %s in domain %s\n",
			 inet_ntoa(dest_ip), domain));
		return False;
	}

	/* Don't attempt connect if the password server parameter does
	   not list this controller */

	if (!lp_wildcard_dc() && 
	    !in_list(remote_machine, lp_passwordserver(), False)) {
		DEBUG(3, ("domain controller %s not in password server list\n",
			  remote_machine));
		return False;
	}

	/* Attempt connect */

	ZERO_STRUCT(cli);

	if(cli_initialise(&cli) == False) {
		DEBUG(0,("connect_to_domain_password_server: unable to initialize client connection.\n"));
		return False;
	}

	standard_sub_basic(remote_machine);
	strupper(remote_machine);
	
	if (ismyip(dest_ip)) {
		DEBUG(1,("connect_to_domain_password_server: Password server loop - not using password server %s\n",
			 remote_machine));
		cli_shutdown(&cli);
		return False;
	}
	
	if (!cli_connect(&cli, remote_machine, &dest_ip)) {
		DEBUG(0,("connect_to_domain_password_server: unable to connect to SMB server on \
machine %s. Error was : %s.\n", remote_machine, cli_errstr(&cli) ));
		cli_shutdown(&cli);
		return False;
	}
	
	if (!attempt_netbios_session_request(&cli, global_myname, 
					     remote_machine, &dest_ip)) {
		DEBUG(0,("connect_to_password_server: machine %s rejected the NetBIOS \
session request. Error was : %s.\n", remote_machine, cli_errstr(&cli) ));
		return False;
	}
	
	cli.protocol = PROTOCOL_NT1;
	
	if (!cli_negprot(&cli)) {
		DEBUG(0,("connect_to_domain_password_server: machine %s rejected the negotiate protocol. \
Error was : %s.\n", remote_machine, cli_errstr(&cli) ));
		cli_shutdown(&cli);
		return False;
	}
	
	if (cli.protocol != PROTOCOL_NT1) {
		DEBUG(0,("connect_to_domain_password_server: machine %s didn't negotiate NT protocol.\n",
			 remote_machine));
		cli_shutdown(&cli);
		return False;
	}
	
	/*
	 * Do an anonymous session setup.
	 */
	
	if (!cli_session_setup(&cli, "", "", 0, "", 0, "")) {
		DEBUG(0,("connect_to_domain_password_server: machine %s rejected the session setup. \
Error was : %s.\n", remote_machine, cli_errstr(&cli) ));
		cli_shutdown(&cli);
		return False;
	}
	
	if (!(cli.sec_mode & 1)) {
		DEBUG(1,("connect_to_domain_password_server: machine %s isn't in user level security mode\n",
			 remote_machine));
		cli_shutdown(&cli);
		return False;
	}
	
	if (!cli_send_tconX(&cli, "IPC$", "IPC", "", 1)) {
		DEBUG(0,("connect_to_domain_password_server: machine %s rejected the tconX on the IPC$ share. \
Error was : %s.\n", remote_machine, cli_errstr(&cli) ));
		cli_shutdown(&cli);
		return False;
	}
	
	/*
	 * We now have an anonymous connection to IPC$ on the domain password
	 * server.
	 */
	
	/*
	 * Even if the connect succeeds we need to setup the netlogon pipe
	 * here. We do this as we may just have changed the domain account
	 * password on the PDC and yet we may be talking to a BDC that 
	 * doesn't have this replicated yet. In this case a successful 
	 * connect to a DC needs to take the netlogon connect into account 
	 * also. This patch from "Bjart Kvarme" <bjart.kvarme@usit.uio.no>.  
	 */

	if(cli_nt_session_open(&cli, PIPE_NETLOGON, &fnum) == False) {
		DEBUG(0,("connect_to_domain_password_server: unable to open the domain client session to \
machine %s. Error was : %s.\n", remote_machine, cli_errstr(&cli)));
		cli_nt_session_close(&cli, fnum);
		cli_ulogoff(&cli);
		cli_shutdown(&cli);
		return False;
	}
	
	/* cli_nt_setup_creds() not called */
	
	return True;
}

/****************************************************************************
 for a domain name, find any domain controller (PDC, BDC, don't care) name.
****************************************************************************/
BOOL get_any_dc_name(char *domain, fstring srv_name)
{
	struct in_addr *ip_list = NULL, *dc_ip = NULL;
	BOOL connected_ok = False;
	int i, count = 0;

	DEBUG(3, ("looking up dc name for domain %s\n", domain));

	/* Get list of possible domain controllers */

	if (!get_dc_list(domain, &ip_list, &count)) {
		DEBUG(3, ("could not get dc list for workgroup %s\n",
			  domain));
                return False;
	}

	/* Find a DC on the local network */

	for (i = 0; i < count; i++) {

		if (!is_local_net(ip_list[i])) continue;

		/* Try to contact DC */

		if ((connected_ok = 
		     attempt_connect_dc(domain, ip_list[i]))) {
			dc_ip = &ip_list[i];
			break;
		}
		    
		ip_list[i] = ipzero;   /* Tried and failed */
	}

	/* Try a random DC elsewhere on the network */

	if (!connected_ok) {

		i = sys_random() % count;

		if (!(connected_ok = attempt_connect_dc(domain, ip_list[i]))) {
			ip_list[i] = ipzero;
		} else {
			dc_ip = &ip_list[i];
		}
	}

	/* Last resort - go through the IP list and try addresses we
	   haven't looked at yet.  Note that from a WINS server the
	   first IP address is the PDC. */

	if (!connected_ok) {
		for(i = 0; i < count; i++) {
			if ((connected_ok = 
			     attempt_connect_dc(domain, ip_list[i]))) {
				dc_ip = &ip_list[i];
				break;
			}
		}
	}

	/* Return DC name to caller */

	if (connected_ok) {
		lookup_pdc_name(global_myname, domain, dc_ip, srv_name);
		DEBUG(3, ("found dc %s\n", srv_name));
	}

	safe_free((char *)ip_list);

	return connected_ok;
}
