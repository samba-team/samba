/* 
   Unix SMB/CIFS implementation.
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

BOOL global_machine_password_needs_changing = False;


/*
  resolve the name of a DC in ways appropriate for an ADS domain mode
  an ADS domain may not have Netbios enabled at all, so this is 
  quite different from the RPC case
  Note that we ignore the 'server' parameter here. That has the effect of using
  the 'ADS server' smb.conf parameter, which is what we really want anyway
 */
static NTSTATUS ads_resolve_dc(fstring remote_machine, 
			       struct in_addr *dest_ip)
{
	ADS_STRUCT *ads;
	ads = ads_init_simple();
	if (!ads) {
		return NT_STATUS_NO_LOGON_SERVERS;		
	}

	DEBUG(4,("ads_resolve_dc: realm=%s\n", ads->config.realm));

	ads->auth.flags |= ADS_AUTH_NO_BIND;

#ifdef HAVE_ADS
	/* a full ads_connect() is actually overkill, as we don't srictly need
	   to do the SASL auth in order to get the info we need, but libads
	   doesn't offer a better way right now */
	ads_connect(ads);
#endif

	fstrcpy(remote_machine, ads->config.ldap_server_name);
	strupper(remote_machine);
	*dest_ip = ads->ldap_ip;
	ads_destroy(&ads);
	
	if (!*remote_machine || is_zero_ip(*dest_ip)) {
		return NT_STATUS_NO_LOGON_SERVERS;		
	}

	DEBUG(4,("ads_resolve_dc: using server='%s' IP=%s\n",
		 remote_machine, inet_ntoa(*dest_ip)));
	
	return NT_STATUS_OK;
}

/*
  resolve the name of a DC in ways appropriate for RPC domain mode
  this relies on the server supporting netbios and port 137 not being
  firewalled
 */
static NTSTATUS rpc_resolve_dc(const char *server, 
			       fstring remote_machine, 
			       struct in_addr *dest_ip)
{
	if (is_ipaddress(server)) {
		struct in_addr to_ip = interpret_addr2(server);

		/* we need to know the machines netbios name - this is a lousy
		   way to find it, but until we have a RPC call that does this
		   it will have to do */
		if (!name_status_find("*", 0x20, 0x20, to_ip, remote_machine)) {
			DEBUG(2, ("rpc_resolve_dc: Can't resolve name for IP %s\n", server));
			return NT_STATUS_NO_LOGON_SERVERS;
		}

		*dest_ip = to_ip;
		return NT_STATUS_OK;
	} 

	fstrcpy(remote_machine, server);
	strupper(remote_machine);
	if (!resolve_name(remote_machine, dest_ip, 0x20)) {
		DEBUG(1,("rpc_resolve_dc: Can't resolve address for %s\n", 
			 remote_machine));
		return NT_STATUS_NO_LOGON_SERVERS;
	}

	DEBUG(4,("rpc_resolve_dc: using server='%s' IP=%s\n",
		 remote_machine, inet_ntoa(*dest_ip)));

	return NT_STATUS_OK;
}

/**
 * Connect to a remote server for domain security authenticaion.
 *
 * @param cli the cli to return containing the active connection
 * @param server either a machine name or text IP address to
 *               connect to.
 * @param trust_passwd the trust password to establish the
 *                       credentials with.
 *
 **/

static NTSTATUS connect_to_domain_password_server(struct smbcli_state **cli, 
						  const char *server, 
						  const char *setup_creds_as,
						  uint16_t sec_chan,
						  const uint8_t *trust_passwd,
						  BOOL *retry)
{
	struct in_addr dest_ip;
	fstring remote_machine;
        NTSTATUS result;
	uint32_t neg_flags = 0x000001ff;

	*retry = False;

	if (lp_security() == SEC_ADS)
		result = ads_resolve_dc(remote_machine, &dest_ip);
	else
		result = rpc_resolve_dc(server, remote_machine, &dest_ip);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(2,("connect_to_domain_password_server: unable to resolve DC: %s\n", 
			 nt_errstr(result)));
		return result;
	}

	if (ismyip(dest_ip)) {
		DEBUG(1,("connect_to_domain_password_server: Password server loop - not using password server %s\n",
			 remote_machine));
		return NT_STATUS_NO_LOGON_SERVERS;
	}
  
	/* TODO: Send a SAMLOGON request to determine whether this is a valid
	   logonserver.  We can avoid a 30-second timeout if the DC is down
	   if the SAMLOGON request fails as it is only over UDP. */

	/* we use a mutex to prevent two connections at once - when a 
	   Win2k PDC get two connections where one hasn't completed a 
	   session setup yet it will send a TCP reset to the first 
	   connection (tridge) */

	/*
	 * With NT4.x DC's *all* authentication must be serialized to avoid
	 * ACCESS_DENIED errors if 2 auths are done from the same machine. JRA.
	 */

	*retry = True;

	if (!grab_server_mutex(server))
		return NT_STATUS_NO_LOGON_SERVERS;
	
	/* Attempt connection */
	result = smbcli_full_connection(NULL, cli, lp_netbios_name(), remote_machine,
				     &dest_ip, 0, "IPC$", "IPC", "", "", "",0, retry);

	if (!NT_STATUS_IS_OK(result)) {
		release_server_mutex();
		return result;
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

	if(smbcli_nt_session_open(*cli, PI_NETLOGON) == False) {
		DEBUG(0,("connect_to_domain_password_server: unable to open the domain client session to \
machine %s. Error was : %s.\n", remote_machine, smbcli_errstr(*cli)));
		smbcli_nt_session_close(*cli);
		smbcli_ulogoff(*cli);
		smbcli_shutdown(*cli);
		release_server_mutex();
		return NT_STATUS_NO_LOGON_SERVERS;
	}

	snprintf((*cli)->mach_acct, sizeof((*cli)->mach_acct) - 1, "%s$", setup_creds_as);

	if (!(*cli)->mach_acct) {
		release_server_mutex();
		return NT_STATUS_NO_MEMORY;
	}

	result = smbcli_nt_setup_creds(*cli, sec_chan, trust_passwd, &neg_flags, 2);

        if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0,("connect_to_domain_password_server: unable to setup the NETLOGON credentials to machine \
%s. Error was : %s.\n", remote_machine, nt_errstr(result)));
		smbcli_nt_session_close(*cli);
		smbcli_ulogoff(*cli);
		smbcli_shutdown(*cli);
		release_server_mutex();
		return result;
	}

	/* We exit here with the mutex *locked*. JRA */

	return NT_STATUS_OK;
}

/***********************************************************************
 Utility function to attempt a connection to an IP address of a DC.
************************************************************************/

static NTSTATUS attempt_connect_to_dc(struct smbcli_state **cli, 
				      const char *domain, 
				      struct in_addr *ip, 
				      const char *setup_creds_as, 
				      uint16_t sec_chan,
				      const uint8_t *trust_passwd)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	BOOL retry = True;
	fstring dc_name;
	int i;

	/*
	 * Ignore addresses we have already tried.
	 */

	if (is_zero_ip(*ip))
		return NT_STATUS_NO_LOGON_SERVERS;

	if (!lookup_dc_name(lp_netbios_name(), domain, ip, dc_name))
		return NT_STATUS_NO_LOGON_SERVERS;

	for (i = 0; (!NT_STATUS_IS_OK(ret)) && retry && (i < 3); i++)
		ret = connect_to_domain_password_server(cli, dc_name, setup_creds_as,
				sec_chan, trust_passwd, &retry);
	return ret;
}

/***********************************************************************
 We have been asked to dynamically determine the IP addresses of
 the PDC and BDC's for DOMAIN, and query them in turn.
************************************************************************/
static NTSTATUS find_connect_dc(struct smbcli_state **cli, 
				 const char *domain,
				 const char *setup_creds_as,
				 uint16_t sec_chan,
				 uint8_t *trust_passwd, 
				 time_t last_change_time)
{
	struct in_addr dc_ip;
	fstring srv_name;

	if ( !rpc_find_dc(lp_workgroup(), srv_name, &dc_ip) ) {
		DEBUG(0,("find_connect_dc: Failed to find an DCs for %s\n", lp_workgroup()));
		return NT_STATUS_NO_LOGON_SERVERS;
	}
	
	return attempt_connect_to_dc( cli, domain, &dc_ip, setup_creds_as, 
			sec_chan, trust_passwd );
}

/***********************************************************************
 Do the same as security=server, but using NT Domain calls and a session
 key from the machine password.  If the server parameter is specified
 use it, otherwise figure out a server from the 'password server' param.
************************************************************************/

static NTSTATUS domain_client_validate(TALLOC_CTX *mem_ctx,
				       const auth_usersupplied_info *user_info, 
				       const char *domain,
				       uint8_t chal[8],
				       auth_serversupplied_info **server_info, 
				       const char *server, const char *setup_creds_as,
				       uint16_t sec_chan,
				       uint8_t trust_passwd[16],
				       time_t last_change_time)
{
	fstring remote_machine;
	NET_USER_INFO_3 info3;
	struct smbcli_state *cli = NULL;
	NTSTATUS nt_status = NT_STATUS_NO_LOGON_SERVERS;

	/*
	 * At this point, smb_apasswd points to the lanman response to
	 * the challenge in local_challenge, and smb_ntpasswd points to
	 * the NT response to the challenge in local_challenge. Ship
	 * these over the secure channel to a domain controller and
	 * see if they were valid.
	 */

	while (!NT_STATUS_IS_OK(nt_status) &&
	       next_token(&server,remote_machine,LIST_SEP,sizeof(remote_machine))) {
		if(lp_security() != SEC_ADS && strequal(remote_machine, "*")) {
			nt_status = find_connect_dc(&cli, domain, setup_creds_as, sec_chan, trust_passwd, last_change_time);
		} else {
			int i;
			BOOL retry = True;
			for (i = 0; !NT_STATUS_IS_OK(nt_status) && retry && (i < 3); i++)
				nt_status = connect_to_domain_password_server(&cli, remote_machine, setup_creds_as,
						sec_chan, trust_passwd, &retry);
		}
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0,("domain_client_validate: Domain password server not available.\n"));
		return nt_status;
	}

	ZERO_STRUCT(info3);

        /*
         * If this call succeeds, we now have lots of info about the user
         * in the info3 structure.  
         */

	nt_status = smbcli_netlogon_sam_network_logon(cli, mem_ctx,
						   user_info->smb_name.str, user_info->domain.str, 
						   user_info->wksta_name.str, chal, 
						   user_info->lm_resp, user_info->nt_resp, 
						   &info3);
        
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0,("domain_client_validate: unable to validate password "
                         "for user %s in domain %s to Domain controller %s. "
                         "Error was %s.\n", user_info->smb_name.str,
                         user_info->domain.str, cli->srv_name_slash, 
                         nt_errstr(nt_status)));
	} else {
		nt_status = make_server_info_info3(mem_ctx, user_info->internal_username.str, 
						   user_info->smb_name.str, domain, server_info, &info3);
#if 0 
		/* The stuff doesn't work right yet */
		SMB_ASSERT(sizeof((*server_info)->session_key) == sizeof(info3.user_sess_key)); 
		memcpy((*server_info)->session_key, info3.user_sess_key, sizeof((*server_info)->session_key)/* 16 */);
		SamOEMhash((*server_info)->session_key, trust_passwd, sizeof((*server_info)->session_key));
#endif		

		uni_group_cache_store_netlogon(mem_ctx, &info3);
	}

#if 0
	/* 
	 * We don't actually need to do this - plus it fails currently with
	 * NT_STATUS_INVALID_INFO_CLASS - we need to know *exactly* what to
	 * send here. JRA.
	 */

	if (NT_STATUS_IS_OK(status)) {
		if(smbcli_nt_logoff(&cli, &ctr) == False) {
			DEBUG(0,("domain_client_validate: unable to log off user %s in domain \
%s to Domain controller %s. Error was %s.\n", user, domain, remote_machine, smbcli_errstr(&cli)));        
			nt_status = NT_STATUS_LOGON_FAILURE;
		}
	}
#endif /* 0 */

	/* Note - once the cli stream is shutdown the mem_ctx used
	   to allocate the other_sids and gids structures has been deleted - so
	   these pointers are no longer valid..... */

	smbcli_nt_session_close(cli);
	smbcli_ulogoff(cli);
	smbcli_shutdown(cli);
	release_server_mutex();
	return nt_status;
}

/****************************************************************************
 Check for a valid username and password in security=domain mode.
****************************************************************************/

static NTSTATUS check_ntdomain_security(const struct auth_context *auth_context,
					void *my_private_data, 
					TALLOC_CTX *mem_ctx,
					const auth_usersupplied_info *user_info, 
					auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status = NT_STATUS_LOGON_FAILURE;
	char *password_server;
	uint8_t trust_passwd[16];
	time_t last_change_time;
	const char *domain = lp_workgroup();

	if (!user_info || !server_info || !auth_context) {
		DEBUG(1,("check_ntdomain_security: Critical variables not present.  Failing.\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* 
	 * Check that the requested domain is not our own machine name.
	 * If it is, we should never check the PDC here, we use our own local
	 * password file.
	 */

	if(is_myname(user_info->domain.str)) {
		DEBUG(3,("check_ntdomain_security: Requested domain was for this machine.\n"));
		return NT_STATUS_LOGON_FAILURE;
	}

	/*
	 * Get the machine account password for our primary domain
	 * No need to become_root() as secrets_init() is done at startup.
	 */

	if (!secrets_fetch_trust_account_password(domain, trust_passwd, &last_change_time))
	{
		DEBUG(0, ("check_ntdomain_security: could not fetch trust account password for domain '%s'\n", domain));
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	/* Test if machine password has expired and needs to be changed */
	if (lp_machine_password_timeout()) {
		if (last_change_time > 0 && 
		    time(NULL) > (last_change_time + 
				  lp_machine_password_timeout())) {
			global_machine_password_needs_changing = True;
		}
	}

	/*
	 * Treat each name in the 'password server =' line as a potential
	 * PDC/BDC. Contact each in turn and try and authenticate.
	 */

	password_server = lp_passwordserver();

	nt_status = domain_client_validate(mem_ctx, user_info, domain,
					   (uint8_t *)auth_context->challenge.data, 
					   server_info, 
					   password_server, lp_netbios_name(), SEC_CHAN_WKSTA, trust_passwd, last_change_time);
	return nt_status;
}

/* module initialisation */
NTSTATUS auth_init_ntdomain(struct auth_context *auth_context, const char* param, auth_methods **auth_method) 
{
	if (!make_auth_methods(auth_context, auth_method)) {
		return NT_STATUS_NO_MEMORY;
	}

	(*auth_method)->name = "ntdomain";
	(*auth_method)->auth = check_ntdomain_security;
	return NT_STATUS_OK;
}


/****************************************************************************
 Check for a valid username and password in a trusted domain
****************************************************************************/

static NTSTATUS check_trustdomain_security(const struct auth_context *auth_context,
					   void *my_private_data, 
					   TALLOC_CTX *mem_ctx,
					   const auth_usersupplied_info *user_info, 
					   auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status = NT_STATUS_LOGON_FAILURE;
	uint8_t trust_md4_password[16];
	char *trust_password;
	time_t last_change_time;
	DOM_SID sid;

	if (!user_info || !server_info || !auth_context) {
		DEBUG(1,("check_trustdomain_security: Critical variables not present.  Failing.\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* 
	 * Check that the requested domain is not our own machine name.
	 * If it is, we should never check the PDC here, we use our own local
	 * password file.
	 */

	if(is_myname(user_info->domain.str)) {
		DEBUG(3,("check_trustdomain_security: Requested domain was for this machine.\n"));
		return NT_STATUS_LOGON_FAILURE;
	}

	/* 
	 * Check that the requested domain is not our own domain,
	 * If it is, we should use our own local password file.
	 */

	if(strequal(lp_workgroup(), (user_info->domain.str))) {
		DEBUG(3,("check_trustdomain_security: Requested domain was for this domain.\n"));
		return NT_STATUS_LOGON_FAILURE;
	}

	/*
	 * Get the trusted account password for the trusted domain
	 * No need to become_root() as secrets_init() is done at startup.
	 */

	if (!secrets_fetch_trusted_domain_password(user_info->domain.str, &trust_password, &sid, &last_change_time))
	{
		DEBUG(0, ("check_trustdomain_security: could not fetch trust account password for domain %s\n", user_info->domain.str));
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("Trust password for domain %s is %s\n", user_info->domain.str, trust_password));
#endif
	E_md4hash(trust_password, trust_md4_password);
	SAFE_FREE(trust_password);

#if 0
	/* Test if machine password is expired and need to be changed */
	if (time(NULL) > last_change_time + lp_machine_password_timeout())
	{
		global_machine_password_needs_changing = True;
	}
#endif

	nt_status = domain_client_validate(mem_ctx, user_info, user_info->domain.str,
					   (uint8_t *)auth_context->challenge.data, 
					   server_info, "*" /* Do a lookup */, 
					   lp_workgroup(), SEC_CHAN_DOMAIN, trust_md4_password, last_change_time);
	
	return nt_status;
}

/* module initialisation */
NTSTATUS auth_init_trustdomain(struct auth_context *auth_context, const char* param, auth_methods **auth_method) 
{
	if (!make_auth_methods(auth_context, auth_method)) {
		return NT_STATUS_NO_MEMORY;
	}

	(*auth_method)->name = "trustdomain";
	(*auth_method)->auth = check_trustdomain_security;
	return NT_STATUS_OK;
}
