/* 
   Unix SMB/CIFS implementation.
   Authenticate against a remote domain
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Andrew Bartlett 2001

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "auth.h"
#include "../libcli/auth/libcli_auth.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "rpc_client/cli_pipe.h"
#include "rpc_client/cli_netlogon.h"
#include "secrets.h"
#include "passdb.h"
#include "libsmb/libsmb.h"
#include "libcli/auth/netlogon_creds_cli.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

static struct named_mutex *mutex;

/**
 * Connect to a remote server for (inter)domain security authenticaion.
 *
 * @param cli the cli to return containing the active connection
 * @param server either a machine name or text IP address to
 *               connect to.
 * @param setup_creds_as domain account to setup credentials as
 * @param sec_chan a switch value to distinguish between domain
 *                 member and interdomain authentication
 * @param trust_passwd the trust password to establish the
 *                     credentials with.
 *
 **/

static NTSTATUS connect_to_domain_password_server(struct cli_state **cli_ret,
						const char *domain,
						const char *dc_name,
						const struct sockaddr_storage *dc_ss,
						struct rpc_pipe_client **pipe_ret,
						struct netlogon_creds_cli_context **creds_ret)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_context *msg_ctx = server_messaging_context();
	NTSTATUS result;
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *netlogon_pipe = NULL;
	struct netlogon_creds_cli_context *netlogon_creds = NULL;
	struct netlogon_creds_CredentialState *creds = NULL;
	uint32_t netlogon_flags = 0;
	enum netr_SchannelType sec_chan_type = 0;
	const char *_account_name = NULL;
	const char *account_name = NULL;
	struct samr_Password current_nt_hash;
	struct samr_Password *previous_nt_hash = NULL;
	bool ok;

	*cli_ret = NULL;

	*pipe_ret = NULL;
	*creds_ret = NULL;

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

	mutex = grab_named_mutex(NULL, dc_name, 10);
	if (mutex == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_LOGON_SERVERS;
	}

	/* Attempt connection */
	result = cli_full_connection(&cli, lp_netbios_name(), dc_name, dc_ss, 0,
		"IPC$", "IPC", "", "", "", 0, SMB_SIGNING_DEFAULT);

	if (!NT_STATUS_IS_OK(result)) {
		/* map to something more useful */
		if (NT_STATUS_EQUAL(result, NT_STATUS_UNSUCCESSFUL)) {
			result = NT_STATUS_NO_LOGON_SERVERS;
		}

		TALLOC_FREE(mutex);
		TALLOC_FREE(frame);
		return result;
	}

	/*
	 * We now have an anonymous connection to IPC$ on the domain password server.
	 */

	ok = get_trust_pw_hash(domain,
			       current_nt_hash.hash,
			       &_account_name,
			       &sec_chan_type);
	if (!ok) {
		cli_shutdown(cli);
		TALLOC_FREE(mutex);
		TALLOC_FREE(frame);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	account_name = talloc_asprintf(talloc_tos(), "%s$", _account_name);
	if (account_name == NULL) {
		cli_shutdown(cli);
		TALLOC_FREE(mutex);
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	result = rpccli_create_netlogon_creds(dc_name,
					      domain,
					      account_name,
					      sec_chan_type,
					      msg_ctx,
					      talloc_tos(),
					      &netlogon_creds);
	if (!NT_STATUS_IS_OK(result)) {
		cli_shutdown(cli);
		TALLOC_FREE(mutex);
		TALLOC_FREE(frame);
		SAFE_FREE(previous_nt_hash);
		return result;
	}

	result = rpccli_setup_netlogon_creds(cli,
					     netlogon_creds,
					     false, /* force_reauth */
					     current_nt_hash,
					     previous_nt_hash);
	SAFE_FREE(previous_nt_hash);
	if (!NT_STATUS_IS_OK(result)) {
		cli_shutdown(cli);
		TALLOC_FREE(mutex);
		TALLOC_FREE(frame);
		return result;
	}

	result = netlogon_creds_cli_get(netlogon_creds,
					talloc_tos(),
					&creds);
	if (!NT_STATUS_IS_OK(result)) {
		cli_shutdown(cli);
		TALLOC_FREE(mutex);
		TALLOC_FREE(frame);
		return result;
	}
	netlogon_flags = creds->negotiate_flags;
	TALLOC_FREE(creds);

	if (netlogon_flags & NETLOGON_NEG_AUTHENTICATED_RPC) {
		result = cli_rpc_pipe_open_schannel_with_key(
			cli, &ndr_table_netlogon, NCACN_NP,
			domain, netlogon_creds, &netlogon_pipe);
	} else {
		result = cli_rpc_pipe_open_noauth(cli,
					&ndr_table_netlogon,
					&netlogon_pipe);
	}

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0,("connect_to_domain_password_server: "
			 "unable to open the domain client session to "
			 "machine %s. Flags[0x%08X] Error was : %s.\n",
			 dc_name, (unsigned)netlogon_flags,
			 nt_errstr(result)));
		cli_shutdown(cli);
		TALLOC_FREE(mutex);
		TALLOC_FREE(frame);
		return result;
	}

	if(!netlogon_pipe) {
		DEBUG(0, ("connect_to_domain_password_server: unable to open "
			  "the domain client session to machine %s. Error "
			  "was : %s.\n", dc_name, nt_errstr(result)));
		cli_shutdown(cli);
		TALLOC_FREE(mutex);
		TALLOC_FREE(frame);
		return NT_STATUS_NO_LOGON_SERVERS;
	}

	/* We exit here with the mutex *locked*. JRA */

	*cli_ret = cli;
	*pipe_ret = netlogon_pipe;
	*creds_ret = netlogon_creds;

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

/***********************************************************************
 Do the same as security=server, but using NT Domain calls and a session
 key from the machine password.  If the server parameter is specified
 use it, otherwise figure out a server from the 'password server' param.
************************************************************************/

static NTSTATUS domain_client_validate(TALLOC_CTX *mem_ctx,
					const struct auth_usersupplied_info *user_info,
					const char *domain,
					uchar chal[8],
					struct auth_serversupplied_info **server_info,
					const char *dc_name,
					const struct sockaddr_storage *dc_ss)

{
	struct netr_SamInfo3 *info3 = NULL;
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *netlogon_pipe = NULL;
	struct netlogon_creds_cli_context *netlogon_creds = NULL;
	NTSTATUS nt_status = NT_STATUS_NO_LOGON_SERVERS;
	int i;
	uint8_t authoritative = 0;
	uint32_t flags = 0;

	/*
	 * At this point, smb_apasswd points to the lanman response to
	 * the challenge in local_challenge, and smb_ntpasswd points to
	 * the NT response to the challenge in local_challenge. Ship
	 * these over the secure channel to a domain controller and
	 * see if they were valid.
	 */

	/* rety loop for robustness */

	for (i = 0; !NT_STATUS_IS_OK(nt_status) && (i < 3); i++) {
		nt_status = connect_to_domain_password_server(&cli,
							domain,
							dc_name,
							dc_ss,
							&netlogon_pipe,
							&netlogon_creds);
	}

	if ( !NT_STATUS_IS_OK(nt_status) ) {
		DEBUG(0,("domain_client_validate: Domain password server not available.\n"));
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_ACCESS_DENIED)) {
			return NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE;
		}
		return nt_status;
	}

	/* store a successful connection */

	saf_store(domain, dc_name);

        /*
         * If this call succeeds, we now have lots of info about the user
         * in the info3 structure.  
         */

	nt_status = rpccli_netlogon_network_logon(netlogon_creds,
						  netlogon_pipe->binding_handle,
						  mem_ctx,
						  user_info->logon_parameters,         /* flags such as 'allow workstation logon' */
						  user_info->client.account_name,      /* user name logging on. */
						  user_info->client.domain_name,       /* domain name */
						  user_info->workstation_name,         /* workstation name */
						  chal,                                /* 8 byte challenge. */
						  user_info->password.response.lanman, /* lanman 24 byte response */
						  user_info->password.response.nt,     /* nt 24 byte response */
						  &authoritative,
						  &flags,
						  &info3);                             /* info3 out */

	/* Let go as soon as possible so we avoid any potential deadlocks
	   with winbind lookup up users or groups. */

	TALLOC_FREE(mutex);

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0,("domain_client_validate: unable to validate password "
                         "for user %s in domain %s to Domain controller %s. "
                         "Error was %s.\n", user_info->client.account_name,
                         user_info->client.domain_name, dc_name,
                         nt_errstr(nt_status)));

		/* map to something more useful */
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_UNSUCCESSFUL)) {
			nt_status = NT_STATUS_NO_LOGON_SERVERS;
		}
	} else {
		nt_status = make_server_info_info3(mem_ctx,
						   user_info->client.account_name,
						   domain,
						   server_info,
						   info3);

		if (NT_STATUS_IS_OK(nt_status)) {
			(*server_info)->nss_token |= user_info->was_mapped;
			netsamlogon_cache_store(user_info->client.account_name, info3);
			TALLOC_FREE(info3);
		}
	}

	/* Note - once the cli stream is shutdown the mem_ctx used
	   to allocate the other_sids and gids structures has been deleted - so
	   these pointers are no longer valid..... */

	cli_shutdown(cli);
	return nt_status;
}

/****************************************************************************
 Check for a valid username and password in security=domain mode.
****************************************************************************/

static NTSTATUS check_ntdomain_security(const struct auth_context *auth_context,
					void *my_private_data, 
					TALLOC_CTX *mem_ctx,
					const struct auth_usersupplied_info *user_info,
					struct auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status = NT_STATUS_LOGON_FAILURE;
	const char *domain = lp_workgroup();
	fstring dc_name;
	struct sockaddr_storage dc_ss;

	if ( lp_server_role() != ROLE_DOMAIN_MEMBER ) {
		DEBUG(0,("check_ntdomain_security: Configuration error!  Cannot use "
			"ntdomain auth method when not a member of a domain.\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!user_info || !server_info || !auth_context) {
		DEBUG(1,("check_ntdomain_security: Critical variables not present.  Failing.\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(10, ("Check auth for: [%s]\n", user_info->mapped.account_name));

	/* 
	 * Check that the requested domain is not our own machine name.
	 * If it is, we should never check the PDC here, we use our own local
	 * password file.
	 */

	if(strequal(get_global_sam_name(), user_info->mapped.domain_name)) {
		DEBUG(3,("check_ntdomain_security: Requested domain was for this machine.\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	/* we need our DC to send the net_sam_logon() request to */

	if ( !get_dc_name(domain, NULL, dc_name, &dc_ss) ) {
		DEBUG(5,("check_ntdomain_security: unable to locate a DC for domain %s\n",
			user_info->mapped.domain_name));
		return NT_STATUS_NO_LOGON_SERVERS;
	}

	nt_status = domain_client_validate(mem_ctx,
					user_info,
					domain,
					(uchar *)auth_context->challenge.data,
					server_info,
					dc_name,
					&dc_ss);

	return nt_status;
}

/* module initialisation */
static NTSTATUS auth_init_ntdomain(struct auth_context *auth_context, const char* param, auth_methods **auth_method) 
{
	struct auth_methods *result;

	result = talloc_zero(auth_context, struct auth_methods);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	result->name = "ntdomain";
	result->auth = check_ntdomain_security;

        *auth_method = result;
	return NT_STATUS_OK;
}


/****************************************************************************
 Check for a valid username and password in a trusted domain
****************************************************************************/

static NTSTATUS check_trustdomain_security(const struct auth_context *auth_context,
					   void *my_private_data, 
					   TALLOC_CTX *mem_ctx,
					   const struct auth_usersupplied_info *user_info,
					   struct auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status = NT_STATUS_LOGON_FAILURE;
	fstring dc_name;
	struct sockaddr_storage dc_ss;

	if (!user_info || !server_info || !auth_context) {
		DEBUG(1,("check_trustdomain_security: Critical variables not present.  Failing.\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(10, ("Check auth for: [%s]\n", user_info->mapped.account_name));

	/* 
	 * Check that the requested domain is not our own machine name or domain name.
	 */

	if( strequal(get_global_sam_name(), user_info->mapped.domain_name)) {
		DEBUG(3,("check_trustdomain_security: Requested domain [%s] was for this machine.\n",
			user_info->mapped.domain_name));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	/* No point is bothering if this is not a trusted domain.
	   This return makes "map to guest = bad user" work again.
	   The logic is that if we know nothing about the domain, that
	   user is not known to us and does not exist */

	if ( !is_trusted_domain( user_info->mapped.domain_name ) )
		return NT_STATUS_NOT_IMPLEMENTED;

	/* use get_dc_name() for consistency even through we know that it will be 
	   a netbios name */

	if ( !get_dc_name(user_info->mapped.domain_name, NULL, dc_name, &dc_ss) ) {
		DEBUG(5,("check_trustdomain_security: unable to locate a DC for domain %s\n",
			user_info->mapped.domain_name));
		return NT_STATUS_NO_LOGON_SERVERS;
	}

	nt_status = domain_client_validate(mem_ctx,
					   user_info,
					   user_info->mapped.domain_name,
					   (uchar *)auth_context->challenge.data,
					   server_info,
					   dc_name,
					   &dc_ss);

	return nt_status;
}

/* module initialisation */
static NTSTATUS auth_init_trustdomain(struct auth_context *auth_context, const char* param, auth_methods **auth_method) 
{
	struct auth_methods *result;

	result = talloc_zero(auth_context, struct auth_methods);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	result->name = "trustdomain";
	result->auth = check_trustdomain_security;

        *auth_method = result;
	return NT_STATUS_OK;
}

NTSTATUS auth_domain_init(void) 
{
	smb_register_auth(AUTH_INTERFACE_VERSION, "trustdomain", auth_init_trustdomain);
	smb_register_auth(AUTH_INTERFACE_VERSION, "ntdomain", auth_init_ntdomain);
	return NT_STATUS_OK;
}
