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

		if (!resolve_srv_name(remote_host, desthost, lp_workgroup(),
				      &dest_ip))
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

		if (!resolve_srv_name(remote_host, desthost, lp_workgroup(),
				      &dest_ip))
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

BOOL attempt_connect_dc(char *domain, struct in_addr dest_ip)
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

	/* This is the wrong place for this check I think.  The correct
	   place should be in the code that decides to use this server
	   for authentication rather than attempting to connect to it to
	   determine whether it is OK. */

#if 0

	/* Don't attempt connect if the password server parameter does
	   not list this controller */

	if (!lp_wildcard_dc() && 
	    !in_list(remote_machine, lp_passwordserver(), False)) {
		DEBUG(3, ("domain controller %s not in password server list\n",
			  remote_machine));
		return False;
	}
#endif

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

/***********************************************************************
 We have been asked to dynamcially determine the IP addresses of
 the PDC and BDC's for this DOMAIN, and query them in turn.
************************************************************************/

static BOOL find_connect_pdc(char *domain, struct in_addr *dc_ip)
{
	struct in_addr *ip_list = NULL;
	BOOL connected_ok = False;
	int count, i;
	BOOL use_pdc_only = False;

	/* Get list of possible domain controllers */

	if (!get_dc_list(use_pdc_only, domain, &ip_list, &count)) {
		DEBUG(3, ("could not get dc list for workgroup %s\n",
			  domain));
                return False;
	}

	/* Find a DC on the local network */

	for (i = 0; i < count; i++) {

		if (!is_local_net(ip_list[i])) 
			continue;

		/* Try to contact DC */

		if ((connected_ok = 
		     attempt_connect_dc(domain, ip_list[i]))) {
			*dc_ip = ip_list[i];
			goto done;
		}
		    
		ip_list[i] = ipzero;   /* Tried and failed */
	}

	/* Try a random DC elsewhere on the network.  Zero out the address
	   if it didn't work to avoid contacting it again. */

	if (!connected_ok) {

		i = sys_random() % count;

		if ((connected_ok = attempt_connect_dc(domain, ip_list[i]))) {
			*dc_ip = ip_list[i];
		} else {
			ip_list[i] = ipzero;
		}
	}

	/* Last resort - go through the IP list and try addresses we
	   haven't looked at yet.  Note that from a WINS server the
	   first IP address is the PDC. */

	if (!connected_ok) {
		for(i = 0; i < count; i++) {
			if ((connected_ok = 
			     attempt_connect_dc(domain, ip_list[i]))) {
				*dc_ip = ip_list[i];
				goto done;
			}
		}
	}

 done:
	safe_free((char *)ip_list);

	return connected_ok;
}

/****************************************************************************
 for a domain name, find any domain controller (PDC, BDC, don't care) name.
****************************************************************************/
BOOL get_any_dc_name(char *domain, fstring srv_name)
{
	BOOL connected_ok = False, triedagain = False;
	struct in_addr dest_ip;
	pstring remote_machine;
	char *p;

	DEBUG(3, ("looking up dc name for domain %s\n", domain));

	p = lp_passwordserver();

	if (!*p) 
		p = "*";

	/* If we're querying a trusted domain don't look at the password
	   server list. */

	if (!strequal(domain, lp_workgroup())) {
		connected_ok = find_connect_pdc(domain, &dest_ip);
		goto done;
	}

	/* Iterate over password server list */

 tryagain:

	while(!connected_ok && next_token(&p, remote_machine, LIST_SEP, 
					  sizeof(remote_machine))) {

		if (strequal(remote_machine, "*")) {

			/* Connect to a random DC on the network */

			connected_ok = find_connect_pdc(domain, &dest_ip);

		} else {
			fstring the_domain;

			/* Connect to specific DC */

			if (!resolve_name(remote_machine, &dest_ip, 0x20)) {
				DEBUG(1, ("get_any_dc_name(): Can't resolve "
					  "address for %s\n", remote_machine));
				continue;
			}

			/* Check that this DC is actually a member of the
			   domain we are interested in */

			if (name_status_find("*", 0x1c, dest_ip, the_domain)) {
                                if (!strequal(the_domain, domain)) {
                                        DEBUG(1, ("get_any_dc_name(): dc %s not a member of domain %s (%s)\n",
                                                  remote_machine, domain, the_domain));
                                        connected_ok = False;
                                        continue;
                                }
			} else {
                                DEBUG(1, ("get_any_dc_name(): %s not a dc\n",
                                          remote_machine));
                                connected_ok = False;
                                continue;
                        }

			connected_ok = attempt_connect_dc(domain, dest_ip);
		}
	}

	/* All our specified password servers are broken so try again with
	   ones that may not have been specified. */

	if (!connected_ok && !triedagain) {
		p = "*";
		triedagain = True;
		goto tryagain;
	}

 done:

	/* Return server name to caller */

 	if (connected_ok) {
 		lookup_pdc_name(global_myname, domain, &dest_ip, srv_name);
 		DEBUG(3, ("found dc %s for domain %s\n", srv_name, domain));
 	} else {
 		DEBUG(3, ("no domain controllers found for domain %s\n",
 			  domain));
  	}

	return connected_ok;
}
