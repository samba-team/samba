/* 
   Unix SMB/Netbios implementation.
   Version 3.0.
   Authenticate against a remote domain
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

BOOL global_machine_password_needs_changing = False;

extern struct in_addr ipzero;

extern pstring global_myname;

/***********************************************************************
 Connect to a remote machine for domain security authentication
 given a name or IP address.
 ***********************************************************************/

static BOOL connect_to_domain_password_server(struct cli_state *pcli, 
					      char *server, unsigned char *trust_passwd)
{
	struct in_addr dest_ip;
	fstring remote_machine;
        NTSTATUS result;

	if(cli_initialise(pcli) == NULL) {
		DEBUG(0,("connect_to_domain_password_server: unable to initialize client connection.\n"));
		return False;
	}

	if (is_ipaddress(server)) {
		struct in_addr to_ip;
	  
		/* we shouldn't have 255.255.255.255 forthe IP address of 
		   a password server anyways */
		if ((to_ip.s_addr=inet_addr(server)) == 0xFFFFFFFF) {
			DEBUG (0,("connect_to_domain_password_server: inet_addr(%s) returned 0xFFFFFFFF!\n", server));
			return False;
		}

		if (!name_status_find("*", 0x20, 0x20, to_ip, remote_machine)) {
			DEBUG(0, ("connect_to_domain_password_server: Can't "
				  "resolve name for IP %s\n", server));
			return False;
		}
	} else {
		fstrcpy(remote_machine, server);
	}

	standard_sub_basic(remote_machine);
	strupper(remote_machine);

	if(!resolve_name( remote_machine, &dest_ip, 0x20)) {
		DEBUG(1,("connect_to_domain_password_server: Can't resolve address for %s\n", remote_machine));
		cli_shutdown(pcli);
		return False;
	}
  
	if (ismyip(dest_ip)) {
		DEBUG(1,("connect_to_domain_password_server: Password server loop - not using password server %s\n",
			 remote_machine));
		cli_shutdown(pcli);
		return False;
	}
  
	if (!cli_connect(pcli, remote_machine, &dest_ip)) {
		DEBUG(0,("connect_to_domain_password_server: unable to connect to SMB server on \
machine %s. Error was : %s.\n", remote_machine, cli_errstr(pcli) ));
		cli_shutdown(pcli);
		return False;
	}
  
	if (!attempt_netbios_session_request(pcli, global_myname, remote_machine, &dest_ip)) {
		DEBUG(0,("connect_to_password_server: machine %s rejected the NetBIOS \
session request. Error was : %s.\n", remote_machine, cli_errstr(pcli) ));
		return False;
	}
  
	pcli->protocol = PROTOCOL_NT1;

	if (!cli_negprot(pcli)) {
		DEBUG(0,("connect_to_domain_password_server: machine %s rejected the negotiate protocol. \
Error was : %s.\n", remote_machine, cli_errstr(pcli) ));
		cli_shutdown(pcli);
		return False;
	}

	if (pcli->protocol != PROTOCOL_NT1) {
		DEBUG(0,("connect_to_domain_password_server: machine %s didn't negotiate NT protocol.\n",
			 remote_machine));
		cli_shutdown(pcli);
		return False;
	}

	/*
	 * Do an anonymous session setup.
	 */

	if (!cli_session_setup(pcli, "", "", 0, "", 0, "")) {
		DEBUG(0,("connect_to_domain_password_server: machine %s rejected the session setup. \
Error was : %s.\n", remote_machine, cli_errstr(pcli) ));
		cli_shutdown(pcli);
		return False;
	}

	if (!(pcli->sec_mode & 1)) {
		DEBUG(1,("connect_to_domain_password_server: machine %s isn't in user level security mode\n",
			 remote_machine));
		cli_shutdown(pcli);
		return False;
	}

	if (!cli_send_tconX(pcli, "IPC$", "IPC", "", 1)) {
		DEBUG(0,("connect_to_domain_password_server: machine %s rejected the tconX on the IPC$ share. \
Error was : %s.\n", remote_machine, cli_errstr(pcli) ));
		cli_shutdown(pcli);
		return False;
	}

	/*
	 * We now have an anonymous connection to IPC$ on the domain password server.
	 */

	/*
	 * Even if the connect succeeds we need to setup the netlogon
	 * pipe here. We do this as we may just have changed the domain
	 * account password on the PDC and yet we may be talking to
	 * a BDC that doesn't have this replicated yet. In this case
	 * a successful connect to a DC needs to take the netlogon connect
	 * into account also. This patch from "Bjart Kvarme" <bjart.kvarme@usit.uio.no>.
	 */

	if(cli_nt_session_open(pcli, PIPE_NETLOGON) == False) {
		DEBUG(0,("connect_to_domain_password_server: unable to open the domain client session to \
machine %s. Error was : %s.\n", remote_machine, cli_errstr(pcli)));
		cli_nt_session_close(pcli);
		cli_ulogoff(pcli);
		cli_shutdown(pcli);
		return False;
	}

	result = cli_nt_setup_creds(pcli, trust_passwd);

        if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0,("connect_to_domain_password_server: unable to setup the PDC credentials to machine \
%s. Error was : %s.\n", remote_machine, get_nt_error_msg(result)));
		cli_nt_session_close(pcli);
		cli_ulogoff(pcli);
		cli_shutdown(pcli);
		return(False);
	}

	return True;
}

/***********************************************************************
 Utility function to attempt a connection to an IP address of a DC.
************************************************************************/

static BOOL attempt_connect_to_dc(struct cli_state *pcli, struct in_addr *ip, 
				  unsigned char *trust_passwd)
{
	fstring dc_name;

	/*
	 * Ignore addresses we have already tried.
	 */

	if (ip_equal(ipzero, *ip))
		return False;

	if (!lookup_pdc_name(global_myname, lp_workgroup(), ip, dc_name))
		return False;

	return connect_to_domain_password_server(pcli, dc_name, trust_passwd);
}

/***********************************************************************
 We have been asked to dynamcially determine the IP addresses of
 the PDC and BDC's for this DOMAIN, and query them in turn.
************************************************************************/
static BOOL find_connect_pdc(struct cli_state *pcli, 
			     unsigned char *trust_passwd, 
			     time_t last_change_time)
{
	struct in_addr *ip_list = NULL;
	int count = 0;
	int i;
	BOOL connected_ok = False;
	time_t time_now = time(NULL);
	BOOL use_pdc_only = False;

	/*
	 * If the time the machine password has changed
	 * was less than an hour ago then we need to contact
	 * the PDC only, as we cannot be sure domain replication
	 * has yet taken place. Bug found by Gerald (way to go
	 * Gerald !). JRA.
	 */

	if (time_now - last_change_time < 3600)
		use_pdc_only = True;

	if (!get_dc_list(use_pdc_only, lp_workgroup(), &ip_list, &count))
		return False;

	/*
	 * Firstly try and contact a PDC/BDC who has the same
	 * network address as any of our interfaces.
	 */
	for(i = 0; i < count; i++) {
		if(!is_local_net(ip_list[i]))
			continue;

		if((connected_ok = attempt_connect_to_dc(pcli, &ip_list[i], trust_passwd))) 
			break;
		
		ip_list[i] = ipzero; /* Tried and failed. */
	}

	/*
	 * Secondly try and contact a random PDC/BDC.
	 */
	if(!connected_ok) {
		i = (sys_random() % count);

		if (!(connected_ok = attempt_connect_to_dc(pcli, &ip_list[i], trust_passwd)))
			ip_list[i] = ipzero; /* Tried and failed. */
	}

	/*
	 * Finally go through the IP list in turn, ignoring any addresses
	 * we have already tried.
	 */
	if(!connected_ok) {
		/*
		 * Try and connect to any of the other IP addresses in the PDC/BDC list.
		 * Note that from a WINS server the #1 IP address is the PDC.
		 */
		for(i = 0; i < count; i++) {
			if((connected_ok = attempt_connect_to_dc(pcli, &ip_list[i], trust_passwd)))
				break;
		}
	}

	SAFE_FREE(ip_list);


	return connected_ok;
}

/***********************************************************************
 Do the same as security=server, but using NT Domain calls and a session
 key from the machine password.  If the server parameter is specified
 use it, otherwise figure out a server from the 'password server' param.
************************************************************************/

static NTSTATUS domain_client_validate(const auth_usersupplied_info *user_info, 
				       uchar chal[8],
				       auth_serversupplied_info **server_info, 
				       char *server, unsigned char *trust_passwd,
				       time_t last_change_time)
{
	fstring remote_machine;
	NET_ID_INFO_CTR ctr;
	NET_USER_INFO_3 info3;
	struct cli_state cli;
	uint32 smb_uid_low;
	BOOL connected_ok = False;
	NTSTATUS status;
	struct passwd *pass;

	/* 
	 * Check that the requested domain is not our own machine name.
	 * If it is, we should never check the PDC here, we use our own local
	 * password file.
	 */

	if(strequal(user_info->domain.str, global_myname)) {
		DEBUG(3,("domain_client_validate: Requested domain was for this machine.\n"));
		return NT_STATUS_LOGON_FAILURE;
	}

	/*
	 * At this point, smb_apasswd points to the lanman response to
	 * the challenge in local_challenge, and smb_ntpasswd points to
	 * the NT response to the challenge in local_challenge. Ship
	 * these over the secure channel to a domain controller and
	 * see if they were valid.
	 */

	ZERO_STRUCT(cli);

	while (!connected_ok &&
	       next_token(&server,remote_machine,LIST_SEP,sizeof(remote_machine))) {
		if(strequal(remote_machine, "*")) {
			connected_ok = find_connect_pdc(&cli, trust_passwd, last_change_time);
		} else {
			connected_ok = connect_to_domain_password_server(&cli, remote_machine, trust_passwd);
		}
	}

	if (!connected_ok) {
		DEBUG(0,("domain_client_validate: Domain password server not available.\n"));
		cli_shutdown(&cli);
		return NT_STATUS_LOGON_FAILURE;
	}

	/* We really don't care what LUID we give the user. */
	generate_random_buffer( (unsigned char *)&smb_uid_low, 4, False);

	ZERO_STRUCT(info3);

        /*
         * If this call succeeds, we now have lots of info about the user
         * in the info3 structure.  
         */

	status = cli_nt_login_network(&cli, user_info, chal, smb_uid_low, 
				      &ctr, &info3);
        
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("domain_client_validate: unable to validate password "
                         "for user %s in domain %s to Domain controller %s. "
                         "Error was %s.\n", user_info->smb_name.str,
                         user_info->domain.str, cli.srv_name_slash, 
                         get_nt_error_msg(status)));
	} else {
                char *dom_user;

                /* Check DOMAIN\username first to catch winbind users, then
                   just the username for local users. */

                asprintf(&dom_user, "%s%s%s", user_info->domain.str,
                         lp_winbind_separator(),
                         user_info->internal_username.str);

                if (!(pass = Get_Pwnam(dom_user)))
                        pass = Get_Pwnam(user_info->internal_username.str);

                free(dom_user);

		if (pass) {
			make_server_info_pw(server_info, pass);
			if (!server_info) {
				status = NT_STATUS_NO_MEMORY;
			}
		} else {
			status = NT_STATUS_NO_SUCH_USER;
		}
	}

	/* Store the user group information in the server_info returned to the caller. */
	
	if (NT_STATUS_IS_OK(status) && (info3.num_groups2 != 0)) {
		DOM_SID domain_sid;
		int i;
		NT_USER_TOKEN *ptok;
		auth_serversupplied_info *pserver_info = *server_info;

		if ((pserver_info->ptok = malloc( sizeof(NT_USER_TOKEN) ) ) == NULL) {
			DEBUG(0, ("domain_client_validate: out of memory allocating rid group membership\n"));
			status = NT_STATUS_NO_MEMORY;
			free_server_info(server_info);
			goto done;
		}

		ptok = pserver_info->ptok;
		ptok->num_sids = (size_t)info3.num_groups2;

		if ((ptok->user_sids = (DOM_SID *)malloc( sizeof(DOM_SID) * ptok->num_sids )) == NULL) {
			DEBUG(0, ("domain_client_validate: Out of memory allocating group SIDS\n"));
			status = NT_STATUS_NO_MEMORY;
			free_server_info(server_info);
			goto done;
		}
 
		if (!secrets_fetch_domain_sid(lp_workgroup(), &domain_sid)) {
			DEBUG(0, ("domain_client_validate: unable to fetch domain sid.\n"));
			status = NT_STATUS_NO_MEMORY;
			free_server_info(server_info);
			goto done;
		}
 
		for (i = 0; i < ptok->num_sids; i++) {
			sid_copy(&ptok->user_sids[i], &domain_sid);
			sid_append_rid(&ptok->user_sids[i], info3.gids[i].g_rid);
		}
	}

#if 0
	/* 
	 * We don't actually need to do this - plus it fails currently with
	 * NT_STATUS_INVALID_INFO_CLASS - we need to know *exactly* what to
	 * send here. JRA.
	 */

	if (NT_STATUS_IS_OK(status)) {
		if(cli_nt_logoff(&cli, &ctr) == False) {
			DEBUG(0,("domain_client_validate: unable to log off user %s in domain \
%s to Domain controller %s. Error was %s.\n", user, domain, remote_machine, cli_errstr(&cli)));        
			status = NT_STATUS_LOGON_FAILURE;
		}
	}
#endif /* 0 */

  done:

	/* Note - once the cli stream is shutdown the mem_ctx used
	   to allocate the other_sids and gids structures has been deleted - so
	   these pointers are no longer valid..... */

	cli_nt_session_close(&cli);
	cli_ulogoff(&cli);
	cli_shutdown(&cli);
	return status;
}

/****************************************************************************
 Check for a valid username and password in security=domain mode.
****************************************************************************/

static NTSTATUS check_ntdomain_security(void *my_private_data,
					const auth_usersupplied_info *user_info, 
					const auth_authsupplied_info *auth_info,
					auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status = NT_STATUS_LOGON_FAILURE;
	char *p, *pserver;
	unsigned char trust_passwd[16];
	time_t last_change_time;

	become_root();

	/*
	 * Get the machine account password for our primary domain
	 */

	if (!secrets_fetch_trust_account_password(lp_workgroup(), trust_passwd, &last_change_time))
	{
		DEBUG(0, ("check_domain_security: could not fetch trust account password for domain %s\n", lp_workgroup()));
		unbecome_root();
		return NT_STATUS_LOGON_FAILURE;
	}

	unbecome_root();

	/* Test if machine password is expired and need to be changed */
	if (time(NULL) > last_change_time + lp_machine_password_timeout())
	{
		global_machine_password_needs_changing = True;
	}

	/*
	 * Treat each name in the 'password server =' line as a potential
	 * PDC/BDC. Contact each in turn and try and authenticate.
	 */

	pserver = lp_passwordserver();
	if (! *pserver) pserver = "*";
	p = pserver;

	nt_status = domain_client_validate(user_info, (uchar *)auth_info->challange.data,server_info, 
					   p, trust_passwd, last_change_time);

	return nt_status;
}

BOOL auth_init_ntdomain(auth_methods **auth_method) 
{
	if (!make_auth_methods(auth_method)) {
		return False;
	}

	(*auth_method)->auth = check_ntdomain_security;
	return True;
}
