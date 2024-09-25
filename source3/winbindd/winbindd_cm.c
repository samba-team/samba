/*
   Unix SMB/CIFS implementation.

   Winbind daemon connection manager

   Copyright (C) Tim Potter                2001
   Copyright (C) Andrew Bartlett           2002
   Copyright (C) Gerald (Jerry) Carter     2003-2005.
   Copyright (C) Volker Lendecke           2004-2005
   Copyright (C) Jeremy Allison		   2006

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
   We need to manage connections to domain controllers without having to
   mess up the main winbindd code with other issues.  The aim of the
   connection manager is to:

       - make connections to domain controllers and cache them
       - re-establish connections when networks or servers go down
       - centralise the policy on connection timeouts, domain controller
	 selection etc
       - manage re-entrancy for when winbindd becomes able to handle
	 multiple outstanding rpc requests

   Why not have connection management as part of the rpc layer like tng?
   Good question.  This code may morph into libsmb/rpc_cache.c or something
   like that but at the moment it's simply staying as part of winbind.	I
   think the TNG architecture of forcing every user of the rpc layer to use
   the connection caching system is a bad idea.	 It should be an optional
   method of using the routines.

   The TNG design is quite good but I disagree with some aspects of the
   implementation. -tpot

 */

/*
   TODO:

     - I'm pretty annoyed by all the make_nmb_name() stuff.  It should be
       moved down into another function.

     - Take care when destroying cli_structs as they can be shared between
       various sam handles.

 */

#include "includes.h"
#include "winbindd.h"
#include "libsmb/namequery.h"
#include "../libcli/auth/libcli_auth.h"
#include "../librpc/gen_ndr/ndr_netlogon_c.h"
#include "rpc_client/cli_pipe.h"
#include "rpc_client/cli_netlogon.h"
#include "../librpc/gen_ndr/ndr_samr_c.h"
#include "../librpc/gen_ndr/ndr_lsa_c.h"
#include "rpc_client/cli_lsarpc.h"
#include "../librpc/gen_ndr/ndr_dssetup_c.h"
#include "libads/sitename_cache.h"
#include "libsmb/libsmb.h"
#include "libsmb/clidgram.h"
#include "ads.h"
#include "secrets.h"
#include "../libcli/security/security.h"
#include "passdb.h"
#include "messages.h"
#include "auth/gensec/gensec.h"
#include "../libcli/smb/smbXcli_base.h"
#include "libcli/auth/netlogon_creds_cli.h"
#include "auth.h"
#include "rpc_server/rpc_ncacn_np.h"
#include "auth/credentials/credentials.h"
#include "lib/param/param.h"
#include "lib/gencache.h"
#include "lib/util/string_wrappers.h"
#include "lib/global_contexts.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

struct dc_name_ip {
	fstring name;
	struct sockaddr_storage ss;
};

extern struct winbindd_methods reconnect_methods;

static NTSTATUS init_dc_connection_network(struct winbindd_domain *domain, bool need_rw_dc);
static void set_dc_type_and_flags( struct winbindd_domain *domain );
static bool set_dc_type_and_flags_trustinfo( struct winbindd_domain *domain );
static bool get_dcs(TALLOC_CTX *mem_ctx, struct winbindd_domain *domain,
		    struct dc_name_ip **dcs, int *num_dcs,
		    uint32_t request_flags);

void winbind_msg_domain_offline(struct messaging_context *msg_ctx,
				void *private_data,
				uint32_t msg_type,
				struct server_id server_id,
				DATA_BLOB *data)
{
	const char *domain_name = (const char *)data->data;
	struct winbindd_domain *domain;

	domain = find_domain_from_name_noinit(domain_name);
	if (domain == NULL) {
		DBG_DEBUG("Domain %s not found!\n", domain_name);
		return;
	}

	DBG_DEBUG("Domain %s was %s, change to offline now.\n",
		  domain_name,
		  domain->online ? "online" : "offline");

	domain->online = false;
}

void winbind_msg_domain_online(struct messaging_context *msg_ctx,
				void *private_data,
				uint32_t msg_type,
				struct server_id server_id,
				DATA_BLOB *data)
{
	const char *domain_name = (const char *)data->data;
	struct winbindd_domain *domain;

	domain = find_domain_from_name_noinit(domain_name);
	if (domain == NULL) {
		return;
	}

	SMB_ASSERT(wb_child_domain() == NULL);

	DBG_DEBUG("Domain %s was %s, marking as online now!\n",
		  domain_name,
		  domain->online ? "online" : "offline");

	domain->online = true;
}

/****************************************************************
 Set domain offline and also add handler to put us back online
 if we detect a DC.
****************************************************************/

void set_domain_offline(struct winbindd_domain *domain)
{
	pid_t parent_pid = getppid();

	DEBUG(10,("set_domain_offline: called for domain %s\n",
		domain->name ));

	if (domain->internal) {
		DEBUG(3,("set_domain_offline: domain %s is internal - logic error.\n",
			domain->name ));
		return;
	}

	domain->online = False;

	/* Offline domains are always initialized. They're
	   re-initialized when they go back online. */

	domain->initialized = True;

	/* Send a message to the parent that the domain is offline. */
	if (parent_pid > 1 && !domain->internal) {
		messaging_send_buf(global_messaging_context(),
				   pid_to_procid(parent_pid),
				   MSG_WINBIND_DOMAIN_OFFLINE,
				   (uint8_t *)domain->name,
				   strlen(domain->name) + 1);
	}

	/* Send an offline message to the idmap child when our
	   primary domain goes offline */
	if ( domain->primary ) {
		pid_t idmap_pid = idmap_child_pid();

		if (idmap_pid != 0) {
			messaging_send_buf(global_messaging_context(),
					   pid_to_procid(idmap_pid),
					   MSG_WINBIND_OFFLINE,
					   (const uint8_t *)domain->name,
					   strlen(domain->name)+1);
		}
	}

	return;
}

/****************************************************************
 Set domain online - if allowed.
****************************************************************/

static void set_domain_online(struct winbindd_domain *domain)
{
	pid_t parent_pid = getppid();

	DEBUG(10,("set_domain_online: called for domain %s\n",
		domain->name ));

	if (domain->internal) {
		DEBUG(3,("set_domain_online: domain %s is internal - logic error.\n",
			domain->name ));
		return;
	}

	if (get_global_winbindd_state_offline()) {
		DEBUG(10,("set_domain_online: domain %s remaining globally offline\n",
			domain->name ));
		return;
	}

	winbindd_set_locator_kdc_envs(domain);

	/* If we are waiting to get a krb5 ticket, trigger immediately. */
	ccache_regain_all_now();

	/* Ok, we're out of any startup mode now... */
	domain->startup = False;

	if (domain->online == False) {
		/* We were offline - now we're online. We default to
		   using the MS-RPC backend if we started offline,
		   and if we're going online for the first time we
		   should really re-initialize the backends and the
		   checks to see if we're talking to an AD or NT domain.
		*/

		domain->initialized = False;

		/* 'reconnect_methods' is the MS-RPC backend. */
		if (domain->backend == &reconnect_methods) {
			domain->backend = NULL;
		}
	}

	domain->online = True;

	/* Send a message to the parent that the domain is online. */
	if (parent_pid > 1 && !domain->internal) {
		messaging_send_buf(global_messaging_context(),
				   pid_to_procid(parent_pid),
				   MSG_WINBIND_DOMAIN_ONLINE,
				   (uint8_t *)domain->name,
				   strlen(domain->name) + 1);
	}

	/* Send an online message to the idmap child when our
	   primary domain comes online */

	if ( domain->primary ) {
		pid_t idmap_pid = idmap_child_pid();

		if (idmap_pid != 0) {
			messaging_send_buf(global_messaging_context(),
					   pid_to_procid(idmap_pid),
					   MSG_WINBIND_ONLINE,
					   (const uint8_t *)domain->name,
					   strlen(domain->name)+1);
		}
	}

	return;
}

/****************************************************************
 Requested to set a domain online.
****************************************************************/

void set_domain_online_request(struct winbindd_domain *domain)
{
	NTSTATUS status;

	SMB_ASSERT(wb_child_domain() || idmap_child());

	DEBUG(10,("set_domain_online_request: called for domain %s\n",
		domain->name ));

	if (get_global_winbindd_state_offline()) {
		DEBUG(10,("set_domain_online_request: domain %s remaining globally offline\n",
			domain->name ));
		return;
	}

	if (domain->internal) {
		DEBUG(10, ("set_domain_online_request: Internal domains are "
			   "always online\n"));
		return;
	}

	/*
	 * This call takes care of setting the online flag to true if we
	 * connected, or tell the parent to ping us back if false. Bypasses
	 * online check so always does network calls.
	 */
	status = init_dc_connection_network(domain, true);
	DBG_DEBUG("init_dc_connection_network(), returned %s, called for "
		  "domain %s (online = %s)\n",
		  nt_errstr(status),
		  domain->name,
		  domain->online ? "true" : "false");
}

/****************************************************************
 Add -ve connection cache entries for domain and realm.
****************************************************************/

static void winbind_add_failed_connection_entry(
	const struct winbindd_domain *domain,
	const char *server,
	NTSTATUS result)
{
	add_failed_connection_entry(domain->name, server, result);
	/* If this was the saf name for the last thing we talked to,
	   remove it. */
	saf_delete(domain->name);
	if (domain->alt_name != NULL) {
		add_failed_connection_entry(domain->alt_name, server, result);
		saf_delete(domain->alt_name);
	}
	winbindd_unset_locator_kdc_env(domain);
}

/* Choose between anonymous or authenticated connections.  We need to use
   an authenticated connection if DCs have the RestrictAnonymous registry
   entry set > 0, or the "Additional restrictions for anonymous
   connections" set in the win2k Local Security Policy.

   Caller to free() result in domain, username, password
*/

static void cm_get_ipc_userpass(char **username, char **domain, char **password)
{
	*username = (char *)secrets_fetch(SECRETS_AUTH_USER, NULL);
	*domain = (char *)secrets_fetch(SECRETS_AUTH_DOMAIN, NULL);
	*password = (char *)secrets_fetch(SECRETS_AUTH_PASSWORD, NULL);

	if (*username && **username) {

		if (!*domain || !**domain)
			*domain = smb_xstrdup(lp_workgroup());

		if (!*password || !**password)
			*password = smb_xstrdup("");

		DEBUG(3, ("cm_get_ipc_userpass: Retrieved auth-user from secrets.tdb [%s\\%s]\n",
			  *domain, *username));

	} else {
		DEBUG(3, ("cm_get_ipc_userpass: No auth-user defined\n"));
		*username = smb_xstrdup("");
		*domain = smb_xstrdup("");
		*password = smb_xstrdup("");
	}
}

static NTSTATUS cm_get_ipc_credentials(TALLOC_CTX *mem_ctx,
				       struct cli_credentials **_creds)
{

	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_INTERNAL_ERROR;
	struct loadparm_context *lp_ctx;
	char *username = NULL;
	char *netbios_domain = NULL;
	char *password = NULL;
	struct cli_credentials *creds = NULL;
	bool ok;

	cm_get_ipc_userpass(&username, &netbios_domain, &password);

	lp_ctx = loadparm_init_s3(frame, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		DEBUG(1, ("loadparm_init_s3 failed\n"));
		status = NT_STATUS_INTERNAL_ERROR;
		goto fail;
	}

	creds = cli_credentials_init(mem_ctx);
	if (creds == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	ok = cli_credentials_set_conf(creds, lp_ctx);
	if (!ok) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto fail;
	}

	cli_credentials_set_kerberos_state(creds,
					   CRED_USE_KERBEROS_DISABLED,
					   CRED_SPECIFIED);

	ok = cli_credentials_set_domain(creds, netbios_domain, CRED_SPECIFIED);
	if (!ok) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	ok = cli_credentials_set_username(creds, username, CRED_SPECIFIED);
	if (!ok) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	ok = cli_credentials_set_password(creds, password, CRED_SPECIFIED);
	if (!ok) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	*_creds = creds;
	creds = NULL;
	status = NT_STATUS_OK;
 fail:
	TALLOC_FREE(creds);
	SAFE_FREE(username);
	SAFE_FREE(netbios_domain);
	SAFE_FREE(password);
	TALLOC_FREE(frame);
	return status;
}

static bool cm_is_ipc_credentials(struct cli_credentials *creds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *ipc_account = NULL;
	char *ipc_domain = NULL;
	char *ipc_password = NULL;
	const char *creds_account = NULL;
	const char *creds_domain = NULL;
	const char *creds_password = NULL;
	bool ret = false;

	cm_get_ipc_userpass(&ipc_account, &ipc_domain, &ipc_password);

	creds_account = cli_credentials_get_username(creds);
	creds_domain = cli_credentials_get_domain(creds);
	creds_password = cli_credentials_get_password(creds);

	if (!strequal(ipc_domain, creds_domain)) {
		goto done;
	}

	if (!strequal(ipc_account, creds_account)) {
		goto done;
	}

	if (!strcsequal(ipc_password, creds_password)) {
		goto done;
	}

	ret = true;
 done:
	SAFE_FREE(ipc_account);
	SAFE_FREE(ipc_domain);
	SAFE_FREE(ipc_password);
	TALLOC_FREE(frame);
	return ret;
}

static bool get_dc_name_via_netlogon(struct winbindd_domain *domain,
				     fstring dcname,
				     struct sockaddr_storage *dc_ss,
				     uint32_t request_flags)
{
	struct winbindd_domain *our_domain = NULL;
	struct rpc_pipe_client *netlogon_pipe = NULL;
	NTSTATUS result;
	WERROR werr;
	TALLOC_CTX *mem_ctx;
	unsigned int orig_timeout;
	const char *tmp = NULL;
	const char *p;
	struct dcerpc_binding_handle *b;

	/* Hmmmm. We can only open one connection to the NETLOGON pipe at the
	 * moment.... */

	if (IS_DC) {
		return False;
	}

	if (domain->primary) {
		return False;
	}

	our_domain = find_our_domain();

	if ((mem_ctx = talloc_init("get_dc_name_via_netlogon")) == NULL) {
		return False;
	}

	result = cm_connect_netlogon(our_domain, &netlogon_pipe);
	if (!NT_STATUS_IS_OK(result)) {
		talloc_destroy(mem_ctx);
		return False;
	}

	b = netlogon_pipe->binding_handle;

	/* This call can take a long time - allow the server to time out.
	   35 seconds should do it. */

	orig_timeout = rpccli_set_timeout(netlogon_pipe, 35000);

	if (our_domain->active_directory) {
		struct netr_DsRGetDCNameInfo *domain_info = NULL;

		/*
		 * TODO request flags are not respected in the server
		 * (and in some cases, like REQUIRE_PDC, causes an error)
		 */
		result = dcerpc_netr_DsRGetDCName(b,
						  mem_ctx,
						  our_domain->dcname,
						  domain->name,
						  NULL,
						  NULL,
						  request_flags|DS_RETURN_DNS_NAME,
						  &domain_info,
						  &werr);
		if (NT_STATUS_IS_OK(result) && W_ERROR_IS_OK(werr)) {
			tmp = talloc_strdup(
				mem_ctx, domain_info->dc_unc);
			if (tmp == NULL) {
				DBG_ERR("talloc_strdup failed for dc_unc[%s]\n",
					domain_info->dc_unc);
				talloc_destroy(mem_ctx);
				return false;
			}
			if (domain->alt_name == NULL) {
				domain->alt_name = talloc_strdup(domain,
								 domain_info->domain_name);
				if (domain->alt_name == NULL) {
					DBG_ERR("talloc_strdup failed for "
						"domain_info->domain_name[%s]\n",
						domain_info->domain_name);
					talloc_destroy(mem_ctx);
					return false;
				}
			}
			if (domain->forest_name == NULL) {
				domain->forest_name = talloc_strdup(domain,
								    domain_info->forest_name);
				if (domain->forest_name == NULL) {
					DBG_ERR("talloc_strdup failed for "
						"domain_info->forest_name[%s]\n",
						domain_info->forest_name);
					talloc_destroy(mem_ctx);
					return false;
				}
			}
		}
	} else {
		result = dcerpc_netr_GetAnyDCName(b, mem_ctx,
						  our_domain->dcname,
						  domain->name,
						  &tmp,
						  &werr);
	}

	/* And restore our original timeout. */
	rpccli_set_timeout(netlogon_pipe, orig_timeout);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(10,("dcerpc_netr_GetAnyDCName failed: %s\n",
			nt_errstr(result)));
		talloc_destroy(mem_ctx);
		return false;
	}

	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(10,("dcerpc_netr_GetAnyDCName failed: %s\n",
			   win_errstr(werr)));
		talloc_destroy(mem_ctx);
		return false;
	}

	/* dcerpc_netr_GetAnyDCName gives us a name with \\ */
	p = strip_hostname(tmp);

	fstrcpy(dcname, p);

	talloc_destroy(mem_ctx);

	DEBUG(10,("dcerpc_netr_GetAnyDCName returned %s\n", dcname));

	if (!resolve_name(dcname, dc_ss, 0x20, true)) {
		return False;
	}

	return True;
}

/**
 * Helper function to assemble trust password and account name
 */
NTSTATUS winbindd_get_trust_credentials(struct winbindd_domain *domain,
					TALLOC_CTX *mem_ctx,
					bool netlogon,
					bool allow_ipc_fallback,
					struct cli_credentials **_creds)
{
	const struct winbindd_domain *creds_domain = NULL;
	struct cli_credentials *creds;
	NTSTATUS status;
	bool force_machine_account = false;

	/* If we are a DC and this is not our own domain */

	if (!domain->active_directory) {
		if (!netlogon) {
			/*
			 * For non active directory domains
			 * we can only use NTLMSSP for SMB.
			 *
			 * But the trust account is not allowed
			 * to use SMB with NTLMSSP.
			 */
			force_machine_account = true;
		}
	}

	if (IS_DC && !force_machine_account) {
		creds_domain = domain;
	} else {
		creds_domain = find_our_domain();
		if (creds_domain == NULL) {
			return NT_STATUS_INVALID_SERVER_STATE;
		}
	}

	status = pdb_get_trust_credentials(creds_domain->name,
					   creds_domain->alt_name,
					   mem_ctx,
					   &creds);
	if (!NT_STATUS_IS_OK(status)) {
		goto ipc_fallback;
	}

	if (creds_domain != domain) {
		/*
		 * We can only use schannel against a direct trust
		 */
		cli_credentials_set_secure_channel_type(creds,
							SEC_CHAN_NULL);
	}

	*_creds = creds;
	return NT_STATUS_OK;

 ipc_fallback:
	if (netlogon) {
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	if (!allow_ipc_fallback) {
		return status;
	}

	status = cm_get_ipc_credentials(mem_ctx, &creds);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*_creds = creds;
	return NT_STATUS_OK;
}

/************************************************************************
 Given a fd with a just-connected TCP connection to a DC, open a connection
 to the pipe.
************************************************************************/

static NTSTATUS cm_prepare_connection(struct winbindd_domain *domain,
				      const int sockfd,
				      const char *controller,
				      struct cli_state **cli,
				      bool *retry)
{
	bool try_ipc_auth = false;
	const char *machine_principal = NULL;
	const char *machine_realm = NULL;
	const char *machine_account = NULL;
	const char *machine_domain = NULL;
	int flags = 0;
	struct cli_credentials *creds = NULL;

	struct named_mutex *mutex;

	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	NTSTATUS tmp_status;
	NTSTATUS tcon_status = NT_STATUS_NETWORK_NAME_DELETED;

	enum smb_signing_setting smb_sign_client_connections = lp_client_ipc_signing();

	if (IS_DC) {
		if (domain->secure_channel_type == SEC_CHAN_NULL) {
			/*
			 * Make sure we don't even try to
			 * connect to a foreign domain
			 * without a direct outbound trust.
			 */
			close(sockfd);
			return NT_STATUS_NO_TRUST_LSA_SECRET;
		}

		/*
		 * As AD DC we only use netlogon and lsa
		 * using schannel over an anonymous transport
		 * (ncacn_ip_tcp or ncacn_np).
		 *
		 * Currently we always establish the SMB connection,
		 * even if we don't use it, because we later use ncacn_ip_tcp.
		 *
		 * As we won't use the SMB connection there's no
		 * need to try kerberos. And NT4 domains expect
		 * an anonymous IPC$ connection anyway.
		 */
		smb_sign_client_connections = SMB_SIGNING_OFF;
	}

	if (smb_sign_client_connections == SMB_SIGNING_DEFAULT) {
		/*
		 * If we are connecting to our own AD domain, require
		 * smb signing to disrupt MITM attacks
		 */
		if (domain->primary && lp_security() == SEC_ADS) {
			smb_sign_client_connections = SMB_SIGNING_REQUIRED;
		/*
		 * If we are in or are an AD domain and connecting to another
		 * AD domain in our forest
		 * then require smb signing to disrupt MITM attacks
		 */
		} else if ((lp_security() == SEC_ADS)
			   && domain->active_directory
			   && (domain->domain_trust_attribs
			       & LSA_TRUST_ATTRIBUTE_WITHIN_FOREST)) {
			smb_sign_client_connections = SMB_SIGNING_REQUIRED;
		}
	}

	DEBUG(10,("cm_prepare_connection: connecting to DC %s for domain %s\n",
		controller, domain->name ));

	*retry = True;

	mutex = grab_named_mutex(talloc_tos(), controller,
				 WINBIND_SERVER_MUTEX_WAIT_TIME);
	if (mutex == NULL) {
		close(sockfd);
		DEBUG(0,("cm_prepare_connection: mutex grab failed for %s\n",
			 controller));
		result = NT_STATUS_POSSIBLE_DEADLOCK;
		goto done;
	}

	/*
	 * cm_prepare_connection() is responsible that sockfd does not leak.
	 * Once cli_state_create() returns with success, the
	 * smbXcli_conn_destructor() makes sure that close(sockfd) is finally
	 * called. Till that, close(sockfd) must be called on every unsuccessful
	 * return.
	 */
	*cli = cli_state_create(NULL, sockfd, controller,
				smb_sign_client_connections, flags);
	if (*cli == NULL) {
		close(sockfd);
		DEBUG(1, ("Could not cli_initialize\n"));
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	cli_set_timeout(*cli, 10000); /* 10 seconds */

	set_socket_options(sockfd, lp_socket_options());

	result = smbXcli_negprot((*cli)->conn,
				 (*cli)->timeout,
				 lp_client_ipc_min_protocol(),
				 lp_client_ipc_max_protocol(),
				 NULL,
				 NULL,
				 NULL);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(1, ("cli_negprot failed: %s\n", nt_errstr(result)));
		goto done;
	}

	if (smbXcli_conn_protocol((*cli)->conn) >= PROTOCOL_NT1 &&
	    smb1cli_conn_capabilities((*cli)->conn) & CAP_EXTENDED_SECURITY) {
		try_ipc_auth = true;
	} else if (smbXcli_conn_protocol((*cli)->conn) >= PROTOCOL_SMB2_02) {
		try_ipc_auth = true;
	} else if (smb_sign_client_connections == SMB_SIGNING_REQUIRED) {
		/*
		 * If we are forcing on SMB signing, then we must
		 * require authentication unless this is a one-way
		 * trust, and we have no stored user/password
		 */
		try_ipc_auth = true;
	}

	if (IS_DC) {
		/*
		 * As AD DC we only use netlogon and lsa
		 * using schannel over an anonymous transport
		 * (ncacn_ip_tcp or ncacn_np).
		 *
		 * Currently we always establish the SMB connection,
		 * even if we don't use it, because we later use ncacn_ip_tcp.
		 *
		 * As we won't use the SMB connection there's no
		 * need to try kerberos. And NT4 domains expect
		 * an anonymous IPC$ connection anyway.
		 */
		try_ipc_auth = false;
	}

	if (try_ipc_auth) {
		result = winbindd_get_trust_credentials(domain,
							talloc_tos(),
							false, /* netlogon */
							true, /* ipc_fallback */
							&creds);
		if (!NT_STATUS_IS_OK(result)) {
			DBG_WARNING("winbindd_get_trust_credentials(%s) "
				    "failed: %s\n",
				    domain->name,
				    nt_errstr(result));
			goto done;
		}
	} else {
		/*
		 * Without SPNEGO or NTLMSSP (perhaps via SMB2) we
		 * would try and authentication with our machine
		 * account password and fail.  This is very rare in
		 * the modern world however
		 */
		creds = cli_credentials_init_anon(talloc_tos());
		if (creds == NULL) {
			result = NT_STATUS_NO_MEMORY;
			DEBUG(1, ("cli_credentials_init_anon(%s) failed: %s\n",
				  domain->name, nt_errstr(result)));
			goto done;
		}
	}

	machine_principal = cli_credentials_get_principal(creds,
							talloc_tos());
	machine_realm = cli_credentials_get_realm(creds);
	machine_account = cli_credentials_get_username(creds);
	machine_domain = cli_credentials_get_domain(creds);

	DEBUG(5, ("connecting to %s (%s, %s) with account [%s\\%s] principal "
		  "[%s] and realm [%s]\n",
		  controller, domain->name, domain->alt_name,
		  machine_domain, machine_account,
		  machine_principal, machine_realm));

	if (cli_credentials_is_anonymous(creds)) {
		goto anon_fallback;
	}

	winbindd_set_locator_kdc_envs(domain);

	result = cli_session_setup_creds(*cli, creds);
	if (NT_STATUS_IS_OK(result)) {
		goto session_setup_done;
	}

	DEBUG(1, ("authenticated session setup to %s using %s failed with %s\n",
		  controller,
		  cli_credentials_get_unparsed_name(creds, talloc_tos()),
		  nt_errstr(result)));

	/*
	 * If we are not going to validate the connection
	 * with SMB signing, then allow us to fall back to
	 * anonymous
	 */
	if (NT_STATUS_EQUAL(result, NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT)
	    || NT_STATUS_EQUAL(result, NT_STATUS_TRUSTED_DOMAIN_FAILURE)
	    || NT_STATUS_EQUAL(result, NT_STATUS_INVALID_ACCOUNT_NAME)
	    || NT_STATUS_EQUAL(result, NT_STATUS_INVALID_COMPUTER_NAME)
	    || NT_STATUS_EQUAL(result, NT_STATUS_NO_SUCH_DOMAIN)
	    || NT_STATUS_EQUAL(result, NT_STATUS_NO_LOGON_SERVERS)
	    || NT_STATUS_EQUAL(result, NT_STATUS_LOGON_FAILURE))
	{
		if (!cm_is_ipc_credentials(creds)) {
			goto ipc_fallback;
		}

		if (smb_sign_client_connections == SMB_SIGNING_REQUIRED) {
			goto done;
		}

		goto anon_fallback;
	}

	goto done;

 ipc_fallback:
	TALLOC_FREE(creds);
	tmp_status = cm_get_ipc_credentials(talloc_tos(), &creds);
	if (!NT_STATUS_IS_OK(tmp_status)) {
		result = tmp_status;
		goto done;
	}

	if (cli_credentials_is_anonymous(creds)) {
		goto anon_fallback;
	}

	machine_account = cli_credentials_get_username(creds);
	machine_domain = cli_credentials_get_domain(creds);

	DEBUG(5, ("connecting to %s from %s using NTLMSSP with username "
		  "[%s]\\[%s]\n",  controller, lp_netbios_name(),
		  machine_domain, machine_account));

	result = cli_session_setup_creds(*cli, creds);
	if (NT_STATUS_IS_OK(result)) {
		goto session_setup_done;
	}

	DEBUG(1, ("authenticated session setup to %s using %s failed with %s\n",
		  controller,
		  cli_credentials_get_unparsed_name(creds, talloc_tos()),
		  nt_errstr(result)));

	/*
	 * If we are not going to validate the connection
	 * with SMB signing, then allow us to fall back to
	 * anonymous
	 */
	if (NT_STATUS_EQUAL(result, NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT)
	    || NT_STATUS_EQUAL(result, NT_STATUS_TRUSTED_DOMAIN_FAILURE)
	    || NT_STATUS_EQUAL(result, NT_STATUS_INVALID_ACCOUNT_NAME)
	    || NT_STATUS_EQUAL(result, NT_STATUS_INVALID_COMPUTER_NAME)
	    || NT_STATUS_EQUAL(result, NT_STATUS_NO_SUCH_DOMAIN)
	    || NT_STATUS_EQUAL(result, NT_STATUS_NO_LOGON_SERVERS)
	    || NT_STATUS_EQUAL(result, NT_STATUS_LOGON_FAILURE))
	{
		goto anon_fallback;
	}

	goto done;

 anon_fallback:
	TALLOC_FREE(creds);

	if (smb_sign_client_connections == SMB_SIGNING_REQUIRED) {
		goto done;
	}

	/* Fall back to anonymous connection, this might fail later */
	DEBUG(5,("cm_prepare_connection: falling back to anonymous "
		"connection for DC %s\n",
		controller ));

	result = cli_session_setup_anon(*cli);
	if (NT_STATUS_IS_OK(result)) {
		DEBUG(5, ("Connected anonymously\n"));
		goto session_setup_done;
	}

	DEBUG(1, ("anonymous session setup to %s failed with %s\n",
		  controller, nt_errstr(result)));

	/* We can't session setup */
	goto done;

 session_setup_done:
	TALLOC_FREE(creds);

	/*
	 * This should be a short term hack until
	 * dynamic re-authentication is implemented.
	 *
	 * See Bug 9175 - winbindd doesn't recover from
	 * NT_STATUS_NETWORK_SESSION_EXPIRED
	 */
	if (smbXcli_conn_protocol((*cli)->conn) >= PROTOCOL_SMB2_02) {
		smbXcli_session_set_disconnect_expired((*cli)->smb2.session);
	}

	result = cli_tree_connect(*cli, "IPC$", "IPC", NULL);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(1,("failed tcon_X with %s\n", nt_errstr(result)));
		goto done;
	}
	tcon_status = result;

	/* cache the server name for later connections */

	saf_store(domain->name, controller);
	if (domain->alt_name) {
		saf_store(domain->alt_name, controller);
	}

	winbindd_set_locator_kdc_envs(domain);

	TALLOC_FREE(mutex);
	*retry = False;

	result = NT_STATUS_OK;

 done:
	TALLOC_FREE(mutex);
	TALLOC_FREE(creds);

	if (NT_STATUS_IS_OK(result)) {
		result = tcon_status;
	}

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(1, ("Failed to prepare SMB connection to %s: %s\n",
			  controller, nt_errstr(result)));
		winbind_add_failed_connection_entry(domain, controller, result);
		if ((*cli) != NULL) {
			cli_shutdown(*cli);
			*cli = NULL;
		}
	}

	return result;
}

/*******************************************************************
 Add a dcname and sockaddr_storage pair to the end of a dc_name_ip
 array.

 Keeps the list unique by not adding duplicate entries.

 @param[in] mem_ctx talloc memory context to allocate from
 @param[in] domain_name domain of the DC
 @param[in] dcname name of the DC to add to the list
 @param[in] pss Internet address and port pair to add to the list
 @param[in,out] dcs array of dc_name_ip structures to add to
 @param[in,out] num_dcs number of dcs returned in the dcs array
 @return true if the list was added to, false otherwise
*******************************************************************/

static bool add_one_dc_unique(TALLOC_CTX *mem_ctx, const char *domain_name,
			      const char *dcname, struct sockaddr_storage *pss,
			      struct dc_name_ip **dcs, int *num)
{
	int i = 0;

	if (!NT_STATUS_IS_OK(check_negative_conn_cache(domain_name, dcname))) {
		DEBUG(10, ("DC %s was in the negative conn cache\n", dcname));
		return False;
	}

	/* Make sure there's no duplicates in the list */
	for (i=0; i<*num; i++)
		if (sockaddr_equal(
			    (struct sockaddr *)(void *)&(*dcs)[i].ss,
			    (struct sockaddr *)(void *)pss))
			return False;

	*dcs = talloc_realloc(mem_ctx, *dcs, struct dc_name_ip, (*num)+1);

	if (*dcs == NULL)
		return False;

	fstrcpy((*dcs)[*num].name, dcname);
	(*dcs)[*num].ss = *pss;
	*num += 1;
	return True;
}

static bool add_sockaddr_to_array(TALLOC_CTX *mem_ctx,
				  struct sockaddr_storage *pss, uint16_t port,
				  struct sockaddr_storage **addrs, int *num)
{
	*addrs = talloc_realloc(mem_ctx, *addrs, struct sockaddr_storage, (*num)+1);

	if (*addrs == NULL) {
		*num = 0;
		return False;
	}

	(*addrs)[*num] = *pss;
	set_sockaddr_port((struct sockaddr *)&(*addrs)[*num], port);

	*num += 1;
	return True;
}

#ifdef HAVE_ADS
static bool dcip_check_name_ads(const struct winbindd_domain *domain,
				struct samba_sockaddr *sa,
				uint32_t request_flags,
				TALLOC_CTX *mem_ctx,
				char **namep)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	char *name = NULL;
	ADS_STRUCT *ads = NULL;
	ADS_STATUS ads_status;
	char addr[INET6_ADDRSTRLEN];

	print_sockaddr(addr, sizeof(addr), &sa->u.ss);
	D_DEBUG("Trying to figure out the DC name for domain '%s' at IP '%s'.\n",
		domain->name,
		addr);

	ads = ads_init(tmp_ctx,
		       domain->alt_name,
		       domain->name,
		       addr,
		       ADS_SASL_PLAIN);
	if (ads == NULL) {
		ads_status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
		goto out;
	}
	ads->config.flags |= request_flags;
	ads->server.no_fallback = true;

	ads_status = ads_connect_cldap_only(ads);
	if (!ADS_ERR_OK(ads_status)) {
		goto out;
	}

	/* We got a cldap packet. */
	name = talloc_strdup(tmp_ctx, ads->config.ldap_server_name);
	if (name == NULL) {
		ads_status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
		goto out;
	}
	namecache_store(name, 0x20, 1, sa);

	DBG_DEBUG("CLDAP flags = 0x%"PRIx32"\n", ads->config.flags);

	if (domain->primary && (ads->config.flags & NBT_SERVER_KDC)) {
		if (ads_closest_dc(ads)) {
			char *sitename = sitename_fetch(tmp_ctx,
							ads->config.realm);

			/* We're going to use this KDC for this realm/domain.
			   If we are using sites, then force the krb5 libs
			   to use this KDC. */

			create_local_private_krb5_conf_for_domain(domain->alt_name,
							domain->name,
							sitename,
							&sa->u.ss);

			TALLOC_FREE(sitename);
		} else {
			/* use an off site KDC */
			create_local_private_krb5_conf_for_domain(domain->alt_name,
							domain->name,
							NULL,
							&sa->u.ss);
		}
		winbindd_set_locator_kdc_envs(domain);

		/* Ensure we contact this DC also. */
		saf_store(domain->name, name);
		saf_store(domain->alt_name, name);
	}

	D_DEBUG("DC name for domain '%s' at IP '%s' is '%s'\n",
		domain->name,
		addr,
		name);
	*namep = talloc_move(mem_ctx, &name);

out:
	TALLOC_FREE(tmp_ctx);

	return ADS_ERR_OK(ads_status) ? true : false;
}
#endif

/*******************************************************************
 convert an ip to a name
 For an AD Domain, it checks the requirements of the request flags.
*******************************************************************/

static bool dcip_check_name(TALLOC_CTX *mem_ctx,
			    const struct winbindd_domain *domain,
			    struct sockaddr_storage *pss,
			    char **name, uint32_t request_flags)
{
	struct samba_sockaddr sa = {0};
	uint32_t nt_version = NETLOGON_NT_VERSION_1;
	NTSTATUS status;
	const char *dc_name;
	fstring nbtname;
#ifdef HAVE_ADS
	bool is_ad_domain = false;
#endif
	bool ok = sockaddr_storage_to_samba_sockaddr(&sa, pss);
	if (!ok) {
		return false;
	}

#ifdef HAVE_ADS
	/* For active directory servers, try to get the ldap server name.
	   None of these failures should be considered critical for now */

	if ((lp_security() == SEC_ADS) && (domain->alt_name != NULL)) {
		is_ad_domain = true;
	} else if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC) {
		is_ad_domain = domain->active_directory;
	}

	if (is_ad_domain) {
		return dcip_check_name_ads(domain,
					   &sa,
					   request_flags,
					   mem_ctx,
					   name);
	}
#endif

	{
		size_t len = strlen(lp_netbios_name());
		char my_acct_name[len+2];

		snprintf(my_acct_name,
			 sizeof(my_acct_name),
			 "%s$",
			 lp_netbios_name());

		status = nbt_getdc(global_messaging_context(), 10, &sa.u.ss,
				   domain->name, &domain->sid,
				   my_acct_name, ACB_WSTRUST,
				   nt_version, mem_ctx, &nt_version,
				   &dc_name, NULL);
	}
	if (NT_STATUS_IS_OK(status)) {
		*name = talloc_strdup(mem_ctx, dc_name);
		if (*name == NULL) {
			return false;
		}
		namecache_store(*name, 0x20, 1, &sa);
		return True;
	}

	/* try node status request */

	if (name_status_find(domain->name, 0x1c, 0x20, &sa.u.ss, nbtname) ) {
		namecache_store(nbtname, 0x20, 1, &sa);

		if (name != NULL) {
			*name = talloc_strdup(mem_ctx, nbtname);
			if (*name == NULL) {
				return false;
			}
		}

		return true;
	}
	return False;
}

/*******************************************************************
 Retrieve a list of IP addresses for domain controllers.

 The array is sorted in the preferred connection order.

 @param[in] mem_ctx talloc memory context to allocate from
 @param[in] domain domain to retrieve DCs for
 @param[out] dcs array of dcs that will be returned
 @param[out] num_dcs number of dcs returned in the dcs array
 @return always true
*******************************************************************/

static bool get_dcs(TALLOC_CTX *mem_ctx, struct winbindd_domain *domain,
		    struct dc_name_ip **dcs, int *num_dcs,
		    uint32_t request_flags)
{
	fstring dcname;
	struct  sockaddr_storage ss;
	struct  samba_sockaddr *sa_list = NULL;
	size_t     salist_size = 0;
	size_t     i;
	bool    is_our_domain;
	enum security_types sec = (enum security_types)lp_security();

	is_our_domain = strequal(domain->name, lp_workgroup());

	/* If not our domain, get the preferred DC, by asking our primary DC */
	if ( !is_our_domain
		&& get_dc_name_via_netlogon(domain, dcname, &ss, request_flags)
		&& add_one_dc_unique(mem_ctx, domain->name, dcname, &ss, dcs,
		       num_dcs) )
	{
		char addr[INET6_ADDRSTRLEN];
		print_sockaddr(addr, sizeof(addr), &ss);
		DEBUG(10, ("Retrieved DC %s at %s via netlogon\n",
			   dcname, addr));
		return True;
	}

	if ((sec == SEC_ADS) && (domain->alt_name != NULL)) {
		char *sitename = NULL;

		/* We need to make sure we know the local site before
		   doing any DNS queries, as this will restrict the
		   get_sorted_dc_list() call below to only fetching
		   DNS records for the correct site. */

		/* Find any DC to get the site record.
		   We deliberately don't care about the
		   return here. */

		get_dc_name(domain->name, domain->alt_name, dcname, &ss);

		sitename = sitename_fetch(mem_ctx, domain->alt_name);
		if (sitename) {

			/* Do the site-specific AD dns lookup first. */
			(void)get_sorted_dc_list(mem_ctx,
					domain->alt_name,
					sitename,
					&sa_list,
					&salist_size,
					true);

			/* Add ips to the DC array.  We don't look up the name
			   of the DC in this function, but we fill in the char*
			   of the ip now to make the failed connection cache
			   work */
			for ( i=0; i<salist_size; i++ ) {
				char addr[INET6_ADDRSTRLEN];
				print_sockaddr(addr, sizeof(addr),
						&sa_list[i].u.ss);
				add_one_dc_unique(mem_ctx,
						domain->name,
						addr,
						&sa_list[i].u.ss,
						dcs,
						num_dcs);
			}

			TALLOC_FREE(sa_list);
			TALLOC_FREE(sitename);
			salist_size = 0;
		}

		/* Now we add DCs from the main AD DNS lookup. */
		(void)get_sorted_dc_list(mem_ctx,
				domain->alt_name,
				NULL,
				&sa_list,
				&salist_size,
				true);

		for ( i=0; i<salist_size; i++ ) {
			char addr[INET6_ADDRSTRLEN];
			print_sockaddr(addr, sizeof(addr),
					&sa_list[i].u.ss);
			add_one_dc_unique(mem_ctx,
					domain->name,
					addr,
					&sa_list[i].u.ss,
					dcs,
					num_dcs);
		}

		TALLOC_FREE(sa_list);
		salist_size = 0;
        }

	/* Try standard netbios queries if no ADS and fall back to DNS queries
	 * if alt_name is available */
	if (*num_dcs == 0) {
		(void)get_sorted_dc_list(mem_ctx,
					domain->name,
					NULL,
					&sa_list,
					&salist_size,
					false);
		if (salist_size == 0) {
			if (domain->alt_name != NULL) {
				(void)get_sorted_dc_list(mem_ctx,
						domain->alt_name,
						NULL,
						&sa_list,
						&salist_size,
						true);
			}
		}

		for ( i=0; i<salist_size; i++ ) {
			char addr[INET6_ADDRSTRLEN];
			print_sockaddr(addr, sizeof(addr),
					&sa_list[i].u.ss);
			add_one_dc_unique(mem_ctx,
					domain->name,
					addr,
					&sa_list[i].u.ss,
					dcs,
					num_dcs);
		}

		TALLOC_FREE(sa_list);
		salist_size = 0;
	}

	return True;
}

static bool connect_preferred_dc(TALLOC_CTX *mem_ctx,
				 struct winbindd_domain *domain,
				 uint32_t request_flags,
				 int *fd)
{
	char *saf_servername = NULL;
	NTSTATUS status;
	bool ok;

	/*
	 * We have to check the server affinity cache here since later we select
	 * a DC based on response time and not preference.
	 */
	if (domain->force_dc) {
		saf_servername = domain->dcname;
	} else {
		saf_servername = saf_fetch(mem_ctx, domain->name);
	}

	/*
	 * Check the negative connection cache before talking to it. It going
	 * down may have triggered the reconnection.
	 */
	if (saf_servername != NULL) {
		status = check_negative_conn_cache(domain->name,
						   saf_servername);
		if (!NT_STATUS_IS_OK(status)) {
			saf_servername = NULL;
		}
	}

	if (saf_servername != NULL) {
		DBG_DEBUG("saf_servername is '%s' for domain %s\n",
			  saf_servername, domain->name);

		/* convert an ip address to a name */
		if (is_ipaddress(saf_servername)) {
			ok = interpret_string_addr(&domain->dcaddr,
						   saf_servername,
						   AI_NUMERICHOST);
			if (!ok) {
				return false;
			}
		} else {
			ok = resolve_name(saf_servername,
					  &domain->dcaddr,
					  0x20,
					  true);
			if (!ok) {
				goto fail;
			}
		}

		TALLOC_FREE(domain->dcname);
		ok = dcip_check_name(domain,
				     domain,
				     &domain->dcaddr,
				     &domain->dcname,
				     request_flags);
		if (!ok) {
			goto fail;
		}
	}

	if (domain->dcname == NULL) {
		return false;
	}

	status = check_negative_conn_cache(domain->name, domain->dcname);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	status = smbsock_connect(&domain->dcaddr, 0,
				 domain->dcname, -1, NULL, -1,
				 fd, NULL, 10);
	if (!NT_STATUS_IS_OK(status)) {
		winbind_add_failed_connection_entry(domain,
						    domain->dcname,
						    NT_STATUS_UNSUCCESSFUL);
		return false;
	}
	return true;

fail:
	winbind_add_failed_connection_entry(domain,
					    saf_servername,
					    NT_STATUS_UNSUCCESSFUL);
	return false;

}

/*******************************************************************
 Find and make a connection to a DC in the given domain.

 @param[in] mem_ctx talloc memory context to allocate from
 @param[in] domain domain to find a dc in
 @param[out] fd fd of the open socket connected to the newly found dc
 @return true when a DC connection is made, false otherwise
*******************************************************************/

static bool find_dc(TALLOC_CTX *mem_ctx,
		    struct winbindd_domain *domain,
		    uint32_t request_flags,
		    int *fd)
{
	struct dc_name_ip *dcs = NULL;
	int num_dcs = 0;

	const char **dcnames = NULL;
	size_t num_dcnames = 0;

	struct sockaddr_storage *addrs = NULL;
	int num_addrs = 0;

	int i;
	size_t fd_index;

	NTSTATUS status;
	bool ok;

	*fd = -1;

	D_NOTICE("First try to connect to the closest DC (using server "
		 "affinity cache). If this fails, try to lookup the DC using "
		 "DNS afterwards.\n");
	ok = connect_preferred_dc(mem_ctx, domain, request_flags, fd);
	if (ok) {
		return true;
	}

	if (domain->force_dc) {
		return false;
	}

 again:
	D_DEBUG("Retrieving a list of IP addresses for DCs.\n");
	if (!get_dcs(mem_ctx, domain, &dcs, &num_dcs, request_flags) || (num_dcs == 0))
		return False;

	D_DEBUG("Retrieved IP addresses for %d DCs.\n", num_dcs);
	for (i=0; i<num_dcs; i++) {

		if (!add_string_to_array(mem_ctx, dcs[i].name,
				    &dcnames, &num_dcnames)) {
			return False;
		}
		if (!add_sockaddr_to_array(mem_ctx, &dcs[i].ss, TCP_SMB_PORT,
				      &addrs, &num_addrs)) {
			return False;
		}
	}

	if ((num_dcnames == 0) || (num_dcnames != num_addrs))
		return False;

	if ((addrs == NULL) || (dcnames == NULL))
		return False;

	D_DEBUG("Trying to establish a connection to one of the %d DCs "
		"(timeout of 10 sec for each DC).\n",
		num_dcs);
	status = smbsock_any_connect(addrs, dcnames, NULL, NULL, NULL,
				     num_addrs, 0, 10, fd, &fd_index, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		for (i=0; i<num_dcs; i++) {
			char ab[INET6_ADDRSTRLEN];
			print_sockaddr(ab, sizeof(ab), &dcs[i].ss);
			DBG_DEBUG("smbsock_any_connect failed for "
				"domain %s address %s. Error was %s\n",
				   domain->name, ab, nt_errstr(status));
			winbind_add_failed_connection_entry(domain,
				dcs[i].name, NT_STATUS_UNSUCCESSFUL);
		}
		return False;
	}
	D_NOTICE("Successfully connected to DC '%s'.\n", dcs[fd_index].name);

	domain->dcaddr = addrs[fd_index];

	if (*dcnames[fd_index] != '\0' && !is_ipaddress(dcnames[fd_index])) {
		/* Ok, we've got a name for the DC */
		TALLOC_FREE(domain->dcname);
		domain->dcname = talloc_strdup(domain, dcnames[fd_index]);
		if (domain->dcname == NULL) {
			return false;
		}
		return true;
	}

	/* Try to figure out the name */
	TALLOC_FREE(domain->dcname);
	ok = dcip_check_name(domain,
			     domain,
			     &domain->dcaddr,
			     &domain->dcname,
			     request_flags);
	if (ok) {
		return true;
	}

	/* We can not continue without the DC's name */
	winbind_add_failed_connection_entry(domain, dcs[fd_index].name,
				    NT_STATUS_UNSUCCESSFUL);

	/* Throw away all arrays as we're doing this again. */
	TALLOC_FREE(dcs);
	num_dcs = 0;

	TALLOC_FREE(dcnames);
	num_dcnames = 0;

	TALLOC_FREE(addrs);
	num_addrs = 0;

	if (*fd != -1) {
		close(*fd);
		*fd = -1;
	}

	/*
	 * This should not be an infinite loop, since get_dcs() will not return
	 * the DC added to the negative connection cache in the above
	 * winbind_add_failed_connection_entry() call.
	 */
	goto again;
}

static char *current_dc_key(TALLOC_CTX *mem_ctx, const char *domain_name)
{
	return talloc_asprintf_strupper_m(mem_ctx, "CURRENT_DCNAME/%s",
					  domain_name);
}

static void store_current_dc_in_gencache(const char *domain_name,
					 const char *dc_name,
					 struct cli_state *cli)
{
	char addr[INET6_ADDRSTRLEN];
	char *key = NULL;
	char *value = NULL;

	if (!cli_state_is_connected(cli)) {
		return;
	}

	print_sockaddr(addr, sizeof(addr),
		       smbXcli_conn_remote_sockaddr(cli->conn));

	key = current_dc_key(talloc_tos(), domain_name);
	if (key == NULL) {
		goto done;
	}

	value = talloc_asprintf(talloc_tos(), "%s %s", addr, dc_name);
	if (value == NULL) {
		goto done;
	}

	gencache_set(key, value, 0x7fffffff);
done:
	TALLOC_FREE(value);
	TALLOC_FREE(key);
}

bool fetch_current_dc_from_gencache(TALLOC_CTX *mem_ctx,
				    const char *domain_name,
				    char **p_dc_name, char **p_dc_ip)
{
	char *key, *p;
	char *value = NULL;
	bool ret = false;
	char *dc_name = NULL;
	char *dc_ip = NULL;

	key = current_dc_key(talloc_tos(), domain_name);
	if (key == NULL) {
		goto done;
	}
	if (!gencache_get(key, mem_ctx, &value, NULL)) {
		goto done;
	}
	p = strchr(value, ' ');
	if (p == NULL) {
		goto done;
	}
	dc_ip = talloc_strndup(mem_ctx, value, p - value);
	if (dc_ip == NULL) {
		goto done;
	}
	dc_name = talloc_strdup(mem_ctx, p+1);
	if (dc_name == NULL) {
		goto done;
	}

	if (p_dc_ip != NULL) {
		*p_dc_ip = dc_ip;
		dc_ip = NULL;
	}
	if (p_dc_name != NULL) {
		*p_dc_name = dc_name;
		dc_name = NULL;
	}
	ret = true;
done:
	TALLOC_FREE(dc_name);
	TALLOC_FREE(dc_ip);
	TALLOC_FREE(key);
	TALLOC_FREE(value);
	return ret;
}

NTSTATUS wb_open_internal_pipe(TALLOC_CTX *mem_ctx,
			       const struct ndr_interface_table *table,
			       struct rpc_pipe_client **ret_pipe)
{
	struct rpc_pipe_client *cli = NULL;
	const struct auth_session_info *session_info = NULL;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;


	session_info = get_session_info_system();
	SMB_ASSERT(session_info != NULL);

	status = rpc_pipe_open_local_np(
		mem_ctx, table, NULL, NULL, NULL, NULL, session_info, &cli);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (ret_pipe) {
		*ret_pipe = cli;
	}

	return NT_STATUS_OK;
}

static NTSTATUS cm_open_connection(struct winbindd_domain *domain,
				   struct winbindd_cm_conn *new_conn,
				   bool need_rw_dc)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS result = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	int retries;
	uint32_t request_flags = need_rw_dc ? DS_WRITABLE_REQUIRED : 0;
	int fd = -1;
	bool retry = false;
	bool seal_pipes = true;

	if ((mem_ctx = talloc_init("cm_open_connection")) == NULL) {
		set_domain_offline(domain);
		return NT_STATUS_NO_MEMORY;
	}

	D_NOTICE("Creating connection to domain controller. This is a start of "
		 "a new connection or a DC failover. The failover only happens "
		 "if the domain has more than one DC. We will try to connect 3 "
		 "times at most.\n");
	for (retries = 0; retries < 3; retries++) {
		bool found_dc;

		D_DEBUG("Attempt %d/3: DC '%s' of domain '%s'.\n",
			retries,
			domain->dcname ? domain->dcname : "",
			domain->name);

		found_dc = find_dc(mem_ctx, domain, request_flags, &fd);
		if (!found_dc) {
			/* This is the one place where we will
			   set the global winbindd offline state
			   to true, if a "WINBINDD_OFFLINE" entry
			   is found in the winbindd cache. */
			set_global_winbindd_state_offline();
			result = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
			break;
		}

		new_conn->cli = NULL;

		result = cm_prepare_connection(domain, fd, domain->dcname,
			&new_conn->cli, &retry);
		if (NT_STATUS_IS_OK(result)) {
			break;
		}
		if (!retry) {
			break;
		}
	}

	if (!NT_STATUS_IS_OK(result)) {
		/* Ensure we setup the retry handler. */
		set_domain_offline(domain);
		goto out;
	}

	winbindd_set_locator_kdc_envs(domain);

	if (domain->online == False) {
		/* We're changing state from offline to online. */
		set_global_winbindd_state_online();
	}
	set_domain_online(domain);

	/*
	 * Much as I hate global state, this seems to be the point
	 * where we can be certain that we have a proper connection to
	 * a DC. wbinfo --dc-info needs that information, store it in
	 * gencache with a looong timeout. This will need revisiting
	 * once we start to connect to multiple DCs, wbcDcInfo is
	 * already prepared for that.
	 */
	store_current_dc_in_gencache(domain->name, domain->dcname,
				     new_conn->cli);

	seal_pipes = lp_winbind_sealed_pipes();
	seal_pipes = lp_parm_bool(-1, "winbind sealed pipes",
				  domain->name,
				  seal_pipes);

	if (seal_pipes) {
		new_conn->auth_level = DCERPC_AUTH_LEVEL_PRIVACY;
	} else {
		new_conn->auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
	}

out:
	talloc_destroy(mem_ctx);
	return result;
}

/* Close down all open pipes on a connection. */

void invalidate_cm_connection(struct winbindd_domain *domain)
{
	NTSTATUS result;
	struct winbindd_cm_conn *conn = &domain->conn;

	domain->sequence_number = DOM_SEQUENCE_NONE;
	domain->last_seq_check = 0;
	domain->last_status = NT_STATUS_SERVER_DISABLED;

	/* We're closing down a possibly dead
	   connection. Don't have impossibly long (10s) timeouts. */

	if (conn->cli) {
		cli_set_timeout(conn->cli, 1000); /* 1 second. */
	}

	if (conn->samr_pipe != NULL) {
		if (is_valid_policy_hnd(&conn->sam_connect_handle)) {
			dcerpc_samr_Close(conn->samr_pipe->binding_handle,
					  talloc_tos(),
					  &conn->sam_connect_handle,
					  &result);
		}
		TALLOC_FREE(conn->samr_pipe);
		/* Ok, it must be dead. Drop timeout to 0.5 sec. */
		if (conn->cli) {
			cli_set_timeout(conn->cli, 500);
		}
	}

	if (conn->lsa_pipe != NULL) {
		if (is_valid_policy_hnd(&conn->lsa_policy)) {
			dcerpc_lsa_Close(conn->lsa_pipe->binding_handle,
					 talloc_tos(),
					 &conn->lsa_policy,
					 &result);
		}
		TALLOC_FREE(conn->lsa_pipe);
		/* Ok, it must be dead. Drop timeout to 0.5 sec. */
		if (conn->cli) {
			cli_set_timeout(conn->cli, 500);
		}
	}

	if (conn->lsa_pipe_tcp != NULL) {
		if (is_valid_policy_hnd(&conn->lsa_policy)) {
			dcerpc_lsa_Close(conn->lsa_pipe_tcp->binding_handle,
					 talloc_tos(),
					 &conn->lsa_policy,
					 &result);
		}
		TALLOC_FREE(conn->lsa_pipe_tcp);
		/* Ok, it must be dead. Drop timeout to 0.5 sec. */
		if (conn->cli) {
			cli_set_timeout(conn->cli, 500);
		}
	}

	if (conn->netlogon_pipe != NULL) {
		TALLOC_FREE(conn->netlogon_pipe);
		/* Ok, it must be dead. Drop timeout to 0.5 sec. */
		if (conn->cli) {
			cli_set_timeout(conn->cli, 500);
		}
	}

	conn->auth_level = DCERPC_AUTH_LEVEL_PRIVACY;
	TALLOC_FREE(conn->netlogon_creds_ctx);

	if (conn->cli) {
		cli_shutdown(conn->cli);
	}

	conn->cli = NULL;
}

void close_conns_after_fork(void)
{
	struct winbindd_domain *domain;
	struct winbindd_cli_state *cli_state;

	for (domain = domain_list(); domain; domain = domain->next) {
		/*
		 * first close the low level SMB TCP connection
		 * so that we don't generate any SMBclose
		 * requests in invalidate_cm_connection()
		 */
		if (cli_state_is_connected(domain->conn.cli)) {
			smbXcli_conn_disconnect(domain->conn.cli->conn, NT_STATUS_OK);
		}

		invalidate_cm_connection(domain);
	}

	for (cli_state = winbindd_client_list();
	     cli_state != NULL;
	     cli_state = cli_state->next) {
		if (cli_state->sock >= 0) {
			close(cli_state->sock);
			cli_state->sock = -1;
		}
	}
}

static bool connection_ok(struct winbindd_domain *domain)
{
	bool ok;

	ok = cli_state_is_connected(domain->conn.cli);
	if (!ok) {
		DEBUG(3, ("connection_ok: Connection to %s for domain %s is not connected\n",
			  domain->dcname, domain->name));
		return False;
	}

	if (!domain->online) {
		DEBUG(3, ("connection_ok: Domain %s is offline\n", domain->name));
		return False;
	}

	return True;
}

/* Initialize a new connection up to the RPC BIND.
   Bypass online status check so always does network calls. */

static NTSTATUS init_dc_connection_network(struct winbindd_domain *domain, bool need_rw_dc)
{
	NTSTATUS result;
	bool skip_connection = domain->internal;
	if (need_rw_dc && domain->rodc) {
		skip_connection = false;
	}

	/* Internal connections never use the network. */
	if (dom_sid_equal(&domain->sid, &global_sid_Builtin)) {
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	/* Still ask the internal LSA and SAMR server about the local domain */
	if (skip_connection || connection_ok(domain)) {
		if (!domain->initialized) {
			set_dc_type_and_flags(domain);
		}
		return NT_STATUS_OK;
	}

	invalidate_cm_connection(domain);

	if (!domain->primary && !domain->initialized) {
		/*
		 * Before we connect to a trust, work out if it is an
		 * AD domain by asking our own domain.
		 */
		set_dc_type_and_flags_trustinfo(domain);
	}

	result = cm_open_connection(domain, &domain->conn, need_rw_dc);

	if (NT_STATUS_IS_OK(result) && !domain->initialized) {
		set_dc_type_and_flags(domain);
	}

	return result;
}

NTSTATUS init_dc_connection(struct winbindd_domain *domain, bool need_rw_dc)
{
	if (dom_sid_equal(&domain->sid, &global_sid_Builtin)) {
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	SMB_ASSERT(wb_child_domain() || idmap_child());

	return init_dc_connection_network(domain, need_rw_dc);
}

static NTSTATUS init_dc_connection_rpc(struct winbindd_domain *domain, bool need_rw_dc)
{
	NTSTATUS status;

	status = init_dc_connection(domain, need_rw_dc);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!domain->internal && domain->conn.cli == NULL) {
		/* happens for trusted domains without inbound trust */
		return NT_STATUS_TRUSTED_DOMAIN_FAILURE;
	}

	return NT_STATUS_OK;
}

/******************************************************************************
 Set the trust flags (direction and forest location) for a domain
******************************************************************************/

static bool set_dc_type_and_flags_trustinfo( struct winbindd_domain *domain )
{
	struct winbindd_domain *our_domain;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	WERROR werr;
	struct netr_DomainTrustList trusts;
	int i;
	uint32_t flags = (NETR_TRUST_FLAG_IN_FOREST |
			NETR_TRUST_FLAG_OUTBOUND |
			NETR_TRUST_FLAG_INBOUND);
	struct rpc_pipe_client *cli;
	TALLOC_CTX *mem_ctx = NULL;
	struct dcerpc_binding_handle *b;

	if (IS_DC) {
		/*
		 * On a DC we loaded all trusts
		 * from configuration and never learn
		 * new domains.
		 */
		return true;
	}

	DEBUG(5, ("set_dc_type_and_flags_trustinfo: domain %s\n", domain->name ));

	/* Our primary domain doesn't need to worry about trust flags.
	   Force it to go through the network setup */
	if ( domain->primary ) {
		return False;
	}

	mem_ctx = talloc_stackframe();
	our_domain = find_our_domain();
	if (our_domain->internal) {
		result = init_dc_connection(our_domain, false);
		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(3,("set_dc_type_and_flags_trustinfo: "
				 "Not able to make a connection to our domain: %s\n",
				  nt_errstr(result)));
			TALLOC_FREE(mem_ctx);
			return false;
		}
	}

	/* This won't work unless our domain is AD */
	if ( !our_domain->active_directory ) {
		TALLOC_FREE(mem_ctx);
		return False;
	}

	if (our_domain->internal) {
		result = wb_open_internal_pipe(mem_ctx, &ndr_table_netlogon, &cli);
	} else if (!connection_ok(our_domain)) {
		DEBUG(3,("set_dc_type_and_flags_trustinfo: "
			 "No connection to our domain!\n"));
		TALLOC_FREE(mem_ctx);
		return False;
	} else {
		result = cm_connect_netlogon(our_domain, &cli);
	}

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(5, ("set_dc_type_and_flags_trustinfo: Could not open "
			  "a connection to %s for PIPE_NETLOGON (%s)\n",
			  domain->name, nt_errstr(result)));
		TALLOC_FREE(mem_ctx);
		return False;
	}
	b = cli->binding_handle;

	/* Use DsEnumerateDomainTrusts to get us the trust direction and type. */
	result = dcerpc_netr_DsrEnumerateDomainTrusts(b, mem_ctx,
						      cli->desthost,
						      flags,
						      &trusts,
						      &werr);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0,("set_dc_type_and_flags_trustinfo: "
			"failed to query trusted domain list: %s\n",
			nt_errstr(result)));
		TALLOC_FREE(mem_ctx);
		return false;
	}
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0,("set_dc_type_and_flags_trustinfo: "
			"failed to query trusted domain list: %s\n",
			win_errstr(werr)));
		TALLOC_FREE(mem_ctx);
		return false;
	}

	/* Now find the domain name and get the flags */

	for ( i=0; i<trusts.count; i++ ) {
		if ( strequal( domain->name, trusts.array[i].netbios_name) ) {
			domain->domain_flags          = trusts.array[i].trust_flags;
			domain->domain_type           = trusts.array[i].trust_type;
			domain->domain_trust_attribs  = trusts.array[i].trust_attributes;

			if ( domain->domain_type == LSA_TRUST_TYPE_UPLEVEL )
				domain->active_directory = True;

			DEBUG(5,("set_dc_type_and_flags_trustinfo: domain %s is %s"
				 "running active directory.\n", domain->name,
				 domain->active_directory ? "" : "NOT "));

			domain->can_do_ncacn_ip_tcp = domain->active_directory;

			domain->initialized = True;

			break;
		}
	}

	TALLOC_FREE(mem_ctx);

	return domain->initialized;
}

/******************************************************************************
 We can 'sense' certain things about the DC by it's replies to certain
 questions.

 This tells us if this particular remote server is Active Directory, and if it
 is native mode.
******************************************************************************/

static void set_dc_type_and_flags_connect( struct winbindd_domain *domain )
{
	NTSTATUS status, result;
	NTSTATUS close_status = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX              *mem_ctx = NULL;
	struct rpc_pipe_client  *cli = NULL;
	struct policy_handle pol = { .handle_type = 0 };
	union lsa_PolicyInformation *lsa_info = NULL;
	union lsa_revision_info out_revision_info = {
		.info1 = {
			.revision = 0,
		},
	};
	uint32_t out_version = 0;

	if (!domain->internal && !connection_ok(domain)) {
		return;
	}

	mem_ctx = talloc_init("set_dc_type_and_flags on domain %s\n",
			      domain->name);
	if (!mem_ctx) {
		DEBUG(1, ("set_dc_type_and_flags_connect: talloc_init() failed\n"));
		return;
	}

	DEBUG(5, ("set_dc_type_and_flags_connect: domain %s\n", domain->name ));

	if (domain->internal) {
		status = wb_open_internal_pipe(mem_ctx,
					       &ndr_table_lsarpc,
					       &cli);
	} else {
		status = cli_rpc_pipe_open_noauth(domain->conn.cli,
						  &ndr_table_lsarpc, &cli);
	}
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("set_dc_type_and_flags_connect: Could not bind to "
			  "PI_LSARPC on domain %s: (%s)\n",
			  domain->name, nt_errstr(status)));
		TALLOC_FREE(cli);
		TALLOC_FREE(mem_ctx);
		return;
	}

	status = dcerpc_lsa_open_policy_fallback(cli->binding_handle,
						 mem_ctx,
						 cli->srv_name_slash,
						 true,
						 SEC_FLAG_MAXIMUM_ALLOWED,
						 &out_version,
						 &out_revision_info,
						 &pol,
						 &result);

	if (NT_STATUS_IS_OK(status) && NT_STATUS_IS_OK(result)) {
		/* This particular query is exactly what Win2k clients use
		   to determine that the DC is active directory */
		status = dcerpc_lsa_QueryInfoPolicy2(cli->binding_handle, mem_ctx,
						     &pol,
						     LSA_POLICY_INFO_DNS,
						     &lsa_info,
						     &result);
	}

	/*
	 * If the status and result will not be OK we will fallback to
	 * OpenPolicy.
	 */
	if (NT_STATUS_IS_OK(status) && NT_STATUS_IS_OK(result)) {
		domain->active_directory = True;

		if (lsa_info->dns.name.string) {
			if (!strequal(domain->name, lsa_info->dns.name.string))
			{
				DEBUG(1, ("set_dc_type_and_flags_connect: DC "
					  "for domain %s claimed it was a DC "
					  "for domain %s, refusing to "
					  "initialize\n",
					  domain->name,
					  lsa_info->dns.name.string));
				TALLOC_FREE(cli);
				TALLOC_FREE(mem_ctx);
				return;
			}
			talloc_free(domain->name);
			domain->name = talloc_strdup(domain,
						     lsa_info->dns.name.string);
			if (domain->name == NULL) {
				goto done;
			}
		}

		if (lsa_info->dns.dns_domain.string) {
			if (domain->alt_name != NULL &&
			    !strequal(domain->alt_name,
				      lsa_info->dns.dns_domain.string))
			{
				DEBUG(1, ("set_dc_type_and_flags_connect: DC "
					  "for domain %s (%s) claimed it was "
					  "a DC for domain %s, refusing to "
					  "initialize\n",
					  domain->alt_name, domain->name,
					  lsa_info->dns.dns_domain.string));
				TALLOC_FREE(cli);
				TALLOC_FREE(mem_ctx);
				return;
			}
			talloc_free(domain->alt_name);
			domain->alt_name =
				talloc_strdup(domain,
					      lsa_info->dns.dns_domain.string);
			if (domain->alt_name == NULL) {
				goto done;
			}
		}

		/* See if we can set some domain trust flags about
		   ourself */

		if (lsa_info->dns.dns_forest.string) {
			talloc_free(domain->forest_name);
			domain->forest_name =
				talloc_strdup(domain,
					      lsa_info->dns.dns_forest.string);
			if (domain->forest_name == NULL) {
				goto done;
			}

			if (strequal(domain->forest_name, domain->alt_name)) {
				domain->domain_flags |= NETR_TRUST_FLAG_TREEROOT;
			}
		}

		if (lsa_info->dns.sid) {
			if (!is_null_sid(&domain->sid) &&
			    !dom_sid_equal(&domain->sid,
					   lsa_info->dns.sid))
			{
				struct dom_sid_buf buf1, buf2;
				DEBUG(1, ("set_dc_type_and_flags_connect: DC "
					  "for domain %s (%s) claimed it was "
					  "a DC for domain %s, refusing to "
					  "initialize\n",
					  dom_sid_str_buf(&domain->sid, &buf1),
					  domain->name,
					  dom_sid_str_buf(lsa_info->dns.sid,
							  &buf2)));
				TALLOC_FREE(cli);
				TALLOC_FREE(mem_ctx);
				return;
			}
			sid_copy(&domain->sid, lsa_info->dns.sid);
		}
	} else {
		domain->active_directory = False;

		status = rpccli_lsa_open_policy(cli, mem_ctx, True,
						SEC_FLAG_MAXIMUM_ALLOWED,
						&pol);

		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		status = dcerpc_lsa_QueryInfoPolicy(cli->binding_handle, mem_ctx,
						    &pol,
						    LSA_POLICY_INFO_ACCOUNT_DOMAIN,
						    &lsa_info,
						    &result);
		if (NT_STATUS_IS_OK(status) && NT_STATUS_IS_OK(result)) {

			if (lsa_info->account_domain.name.string) {
				if (!strequal(domain->name,
					lsa_info->account_domain.name.string))
				{
					DEBUG(1,
					      ("set_dc_type_and_flags_connect: "
					       "DC for domain %s claimed it was"
					       " a DC for domain %s, refusing "
					       "to initialize\n", domain->name,
					       lsa_info->
						account_domain.name.string));
					TALLOC_FREE(cli);
					TALLOC_FREE(mem_ctx);
					return;
				}
				talloc_free(domain->name);
				domain->name =
					talloc_strdup(domain,
						      lsa_info->account_domain.name.string);
			}

			if (lsa_info->account_domain.sid) {
				if (!is_null_sid(&domain->sid) &&
				    !dom_sid_equal(&domain->sid,
						lsa_info->account_domain.sid))
				{
					struct dom_sid_buf buf1, buf2;
					DEBUG(1,
					      ("set_dc_type_and_flags_connect: "
					       "DC for domain %s (%s) claimed "
					       "it was a DC for domain %s, "
					       "refusing to initialize\n",
					       dom_sid_str_buf(
						       &domain->sid, &buf1),
					       domain->name,
					       dom_sid_str_buf(
						lsa_info->account_domain.sid,
						&buf2)));
					TALLOC_FREE(cli);
					TALLOC_FREE(mem_ctx);
					return;
				}
				sid_copy(&domain->sid, lsa_info->account_domain.sid);
			}
		}
	}
done:
	if (is_valid_policy_hnd(&pol)) {
		dcerpc_lsa_Close(cli->binding_handle,
				 mem_ctx,
				 &pol,
				 &close_status);
	}

	DEBUG(5,("set_dc_type_and_flags_connect: domain %s is %srunning active directory.\n",
		  domain->name, domain->active_directory ? "" : "NOT "));

	domain->can_do_ncacn_ip_tcp = domain->active_directory;

	TALLOC_FREE(cli);

	TALLOC_FREE(mem_ctx);

	domain->initialized = True;
}

/**********************************************************************
 Set the domain_flags (trust attributes, domain operating modes, etc...
***********************************************************************/

static void set_dc_type_and_flags( struct winbindd_domain *domain )
{
	if (IS_DC) {
		/*
		 * On a DC we loaded all trusts
		 * from configuration and never learn
		 * new domains.
		 */
		return;
	}

	/* we always have to contact our primary domain */
	if (domain->primary || domain->internal) {
		/*
		 * primary and internal domains are
		 * are already completely
		 * setup via init_domain_list()
		 * calling add_trusted_domain()
		 *
		 * There's no need to ask the
		 * server again, if it hosts an AD
		 * domain...
		 */
		domain->initialized = true;
		return;
	}

	/* Use our DC to get the information if possible */

	if ( !set_dc_type_and_flags_trustinfo( domain ) ) {
		/* Otherwise, fallback to contacting the
		   domain directly */
		set_dc_type_and_flags_connect( domain );
	}

	return;
}



/**********************************************************************
***********************************************************************/

static NTSTATUS cm_get_schannel_creds(struct winbindd_domain *domain,
				   struct netlogon_creds_cli_context **ppdc)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	struct rpc_pipe_client *netlogon_pipe;

	*ppdc = NULL;

	if ((!IS_DC) && (!domain->primary)) {
		return NT_STATUS_TRUSTED_DOMAIN_FAILURE;
	}

	if (domain->conn.netlogon_creds_ctx != NULL) {
		*ppdc = domain->conn.netlogon_creds_ctx;
		return NT_STATUS_OK;
	}

	result = cm_connect_netlogon_secure(domain, &netlogon_pipe, ppdc);
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	return NT_STATUS_OK;
}

NTSTATUS cm_connect_sam(struct winbindd_domain *domain, TALLOC_CTX *mem_ctx,
			bool need_rw_dc,
			struct rpc_pipe_client **cli, struct policy_handle *sam_handle)
{
	struct winbindd_cm_conn *conn;
	NTSTATUS status, result;
	struct netlogon_creds_cli_context *p_creds;
	struct cli_credentials *creds = NULL;
	bool retry = false; /* allow one retry attempt for expired session */
	const char *remote_name = NULL;
	const struct sockaddr_storage *remote_sockaddr = NULL;
	bool sealed_pipes = true;
	bool strong_key = true;

	if (sid_check_is_our_sam(&domain->sid)) {
		if (domain->rodc == false || need_rw_dc == false) {
			return open_internal_samr_conn(mem_ctx, domain, cli, sam_handle);
		}
	}

	if (IS_AD_DC) {
		/*
		 * In theory we should not use SAMR within
		 * winbindd at all, but that's a larger task to
		 * remove this and avoid breaking existing
		 * setups.
		 *
		 * At least as AD DC we have the restriction
		 * to avoid SAMR against trusted domains,
		 * as there're no existing setups.
		 */
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

retry:
	status = init_dc_connection_rpc(domain, need_rw_dc);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	conn = &domain->conn;

	if (rpccli_is_connected(conn->samr_pipe)) {
		goto done;
	}

	TALLOC_FREE(conn->samr_pipe);

	/*
	 * No SAMR pipe yet. Attempt to get an NTLMSSP SPNEGO authenticated
	 * sign and sealed pipe using the machine account password by
	 * preference. If we can't - try schannel, if that fails, try
	 * anonymous.
	 */

	result = winbindd_get_trust_credentials(domain,
						talloc_tos(),
						false, /* netlogon */
						true, /* ipc_fallback */
						&creds);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(10, ("cm_connect_sam: No user available for "
			   "domain %s, trying schannel\n", domain->name));
		goto schannel;
	}

	if (cli_credentials_is_anonymous(creds)) {
		goto anonymous;
	}

	remote_name = smbXcli_conn_remote_name(conn->cli->conn);
	remote_sockaddr = smbXcli_conn_remote_sockaddr(conn->cli->conn);

	/*
	 * We have an authenticated connection. Use a SPNEGO
	 * authenticated SAMR pipe with sign & seal.
	 */
	status = cli_rpc_pipe_open_with_creds(conn->cli,
					      &ndr_table_samr,
					      NCACN_NP,
					      DCERPC_AUTH_TYPE_SPNEGO,
					      conn->auth_level,
					      remote_name,
					      remote_sockaddr,
					      creds,
					      &conn->samr_pipe);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_SESSION_EXPIRED)
	    && !retry) {
		invalidate_cm_connection(domain);
		retry = true;
		goto retry;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("cm_connect_sam: failed to connect to SAMR "
			  "pipe for domain %s using NTLMSSP "
			  "authenticated pipe: user %s. Error was "
			  "%s\n", domain->name,
			  cli_credentials_get_unparsed_name(creds, talloc_tos()),
			  nt_errstr(status)));
		goto schannel;
	}

	DEBUG(10,("cm_connect_sam: connected to SAMR pipe for "
		  "domain %s using NTLMSSP authenticated "
		  "pipe: user %s\n", domain->name,
		  cli_credentials_get_unparsed_name(creds, talloc_tos())));

	status = dcerpc_samr_Connect2(conn->samr_pipe->binding_handle, mem_ctx,
				      conn->samr_pipe->desthost,
				      SEC_FLAG_MAXIMUM_ALLOWED,
				      &conn->sam_connect_handle,
				      &result);

	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_DEVICE_ERROR) && !retry) {
		invalidate_cm_connection(domain);
		TALLOC_FREE(conn->samr_pipe);
		retry = true;
		goto retry;
	}

	if (NT_STATUS_IS_OK(status) && NT_STATUS_IS_OK(result)) {
		goto open_domain;
	}
	if (NT_STATUS_IS_OK(status)) {
		status = result;
	}

	DEBUG(10,("cm_connect_sam: ntlmssp-sealed dcerpc_samr_Connect2 "
		  "failed for domain %s, error was %s. Trying schannel\n",
		  domain->name, nt_errstr(status) ));
	TALLOC_FREE(conn->samr_pipe);

 schannel:

	/* Fall back to schannel if it's a W2K pre-SP1 box. */

	status = cm_get_schannel_creds(domain, &p_creds);
	if (!NT_STATUS_IS_OK(status)) {
		/* If this call fails - conn->cli can now be NULL ! */
		DEBUG(10, ("cm_connect_sam: Could not get schannel auth info "
			   "for domain %s (error %s), trying anon\n",
			domain->name,
			nt_errstr(status) ));
		goto anonymous;
	}
	TALLOC_FREE(creds);
	status = cli_rpc_pipe_open_schannel_with_creds(
		conn->cli, &ndr_table_samr, NCACN_NP, p_creds,
		remote_name,
		remote_sockaddr,
		&conn->samr_pipe);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_SESSION_EXPIRED)
	    && !retry) {
		invalidate_cm_connection(domain);
		retry = true;
		goto retry;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("cm_connect_sam: failed to connect to SAMR pipe for "
			  "domain %s using schannel. Error was %s\n",
			  domain->name, nt_errstr(status) ));
		goto anonymous;
	}
	DEBUG(10,("cm_connect_sam: connected to SAMR pipe for domain %s using "
		  "schannel.\n", domain->name ));

	status = dcerpc_samr_Connect2(conn->samr_pipe->binding_handle, mem_ctx,
				      conn->samr_pipe->desthost,
				      SEC_FLAG_MAXIMUM_ALLOWED,
				      &conn->sam_connect_handle,
				      &result);

	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_DEVICE_ERROR) && !retry) {
		invalidate_cm_connection(domain);
		TALLOC_FREE(conn->samr_pipe);
		retry = true;
		goto retry;
	}

	if (NT_STATUS_IS_OK(status) && NT_STATUS_IS_OK(result)) {
		goto open_domain;
	}
	if (NT_STATUS_IS_OK(status)) {
		status = result;
	}
	DEBUG(10,("cm_connect_sam: schannel-sealed dcerpc_samr_Connect2 failed "
		  "for domain %s, error was %s. Trying anonymous\n",
		  domain->name, nt_errstr(status) ));
	TALLOC_FREE(conn->samr_pipe);

 anonymous:

	sealed_pipes = lp_winbind_sealed_pipes();
	sealed_pipes = lp_parm_bool(-1, "winbind sealed pipes",
				    domain->name,
				    sealed_pipes);
	strong_key = lp_require_strong_key();
	strong_key = lp_parm_bool(-1, "require strong key",
				  domain->name,
				  strong_key);

	/* Finally fall back to anonymous. */
	if (sealed_pipes || strong_key) {
		status = NT_STATUS_DOWNGRADE_DETECTED;
		DEBUG(1, ("Unwilling to make SAMR connection to domain %s "
			  "without connection level security, "
			  "must set 'winbind sealed pipes:%s = false' and "
			  "'require strong key:%s = false' to proceed: %s\n",
			  domain->name, domain->name, domain->name,
			  nt_errstr(status)));
		goto done;
	}
	status = cli_rpc_pipe_open_noauth(conn->cli, &ndr_table_samr,
					  &conn->samr_pipe);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_SESSION_EXPIRED)
	    && !retry) {
		invalidate_cm_connection(domain);
		retry = true;
		goto retry;
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = dcerpc_samr_Connect2(conn->samr_pipe->binding_handle, mem_ctx,
				      conn->samr_pipe->desthost,
				      SEC_FLAG_MAXIMUM_ALLOWED,
				      &conn->sam_connect_handle,
				      &result);

	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_DEVICE_ERROR) && !retry) {
		invalidate_cm_connection(domain);
		TALLOC_FREE(conn->samr_pipe);
		retry = true;
		goto retry;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("cm_connect_sam: rpccli_samr_Connect2 failed "
			  "for domain %s Error was %s\n",
			  domain->name, nt_errstr(status) ));
		goto done;
	}
	if (!NT_STATUS_IS_OK(result)) {
		status = result;
		DEBUG(10,("cm_connect_sam: dcerpc_samr_Connect2 failed "
			  "for domain %s Error was %s\n",
			  domain->name, nt_errstr(result)));
		goto done;
	}

 open_domain:
	status = dcerpc_samr_OpenDomain(conn->samr_pipe->binding_handle,
					mem_ctx,
					&conn->sam_connect_handle,
					SEC_FLAG_MAXIMUM_ALLOWED,
					&domain->sid,
					&conn->sam_domain_handle,
					&result);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = result;
 done:

	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		/*
		 * if we got access denied, we might just have no access rights
		 * to talk to the remote samr server server (e.g. when we are a
		 * PDC and we are connecting a w2k8 pdc via an interdomain
		 * trust). In that case do not invalidate the whole connection
		 * stack
		 */
		TALLOC_FREE(conn->samr_pipe);
		ZERO_STRUCT(conn->sam_domain_handle);
		return status;
	} else if (!NT_STATUS_IS_OK(status)) {
		invalidate_cm_connection(domain);
		return status;
	}

	*cli = conn->samr_pipe;
	*sam_handle = conn->sam_domain_handle;
	return status;
}

/**********************************************************************
 open an schanneld ncacn_ip_tcp connection to LSA
***********************************************************************/

static NTSTATUS cm_connect_lsa_tcp(struct winbindd_domain *domain,
				   TALLOC_CTX *mem_ctx,
				   struct rpc_pipe_client **cli)
{
	struct winbindd_cm_conn *conn;
	struct netlogon_creds_cli_context *p_creds = NULL;
	NTSTATUS status;
	const char *remote_name = NULL;
	const struct sockaddr_storage *remote_sockaddr = NULL;

	DEBUG(10,("cm_connect_lsa_tcp\n"));

	status = init_dc_connection_rpc(domain, false);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	conn = &domain->conn;

	/*
	 * rpccli_is_connected handles more error cases
	 */
	if (rpccli_is_connected(conn->lsa_pipe_tcp)) {
		goto done;
	}

	TALLOC_FREE(conn->lsa_pipe_tcp);

	status = cm_get_schannel_creds(domain, &p_creds);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	remote_name = smbXcli_conn_remote_name(conn->cli->conn);
	remote_sockaddr = smbXcli_conn_remote_sockaddr(conn->cli->conn);

	status = cli_rpc_pipe_open_schannel_with_creds(
			conn->cli,
			&ndr_table_lsarpc,
			NCACN_IP_TCP,
			p_creds,
			remote_name,
			remote_sockaddr,
			&conn->lsa_pipe_tcp);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("cli_rpc_pipe_open_schannel_with_key failed: %s\n",
			nt_errstr(status)));
		goto done;
	}

 done:
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(conn->lsa_pipe_tcp);
		return status;
	}

	*cli = conn->lsa_pipe_tcp;

	return status;
}

NTSTATUS cm_connect_lsa(struct winbindd_domain *domain, TALLOC_CTX *mem_ctx,
			struct rpc_pipe_client **cli, struct policy_handle *lsa_policy)
{
	struct winbindd_cm_conn *conn;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	struct netlogon_creds_cli_context *p_creds;
	struct cli_credentials *creds = NULL;
	bool retry = false; /* allow one retry attempt for expired session */
	const char *remote_name = NULL;
	const struct sockaddr_storage *remote_sockaddr = NULL;
	bool sealed_pipes = true;
	bool strong_key = true;
	bool require_schannel = false;

retry:
	result = init_dc_connection_rpc(domain, false);
	if (!NT_STATUS_IS_OK(result))
		return result;

	conn = &domain->conn;

	if (rpccli_is_connected(conn->lsa_pipe)) {
		goto done;
	}

	TALLOC_FREE(conn->lsa_pipe);

	if (IS_DC ||
	    domain->secure_channel_type != SEC_CHAN_NULL)
	{
		/*
		 * Make sure we only use schannel as DC
		 * or with a direct trust
		 */
		require_schannel = true;
		goto schannel;
	}

	result = winbindd_get_trust_credentials(domain,
						talloc_tos(),
						false, /* netlogon */
						true, /* ipc_fallback */
						&creds);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(10, ("cm_connect_lsa: No user available for "
			   "domain %s, trying schannel\n", domain->name));
		goto schannel;
	}

	if (cli_credentials_is_anonymous(creds)) {
		goto anonymous;
	}

	remote_name = smbXcli_conn_remote_name(conn->cli->conn);
	remote_sockaddr = smbXcli_conn_remote_sockaddr(conn->cli->conn);

	/*
	 * We have an authenticated connection. Use a SPNEGO
	 * authenticated LSA pipe with sign & seal.
	 */
	result = cli_rpc_pipe_open_with_creds
		(conn->cli, &ndr_table_lsarpc, NCACN_NP,
		 DCERPC_AUTH_TYPE_SPNEGO,
		 conn->auth_level,
		 remote_name,
		 remote_sockaddr,
		 creds,
		 &conn->lsa_pipe);

	if (NT_STATUS_EQUAL(result, NT_STATUS_NETWORK_SESSION_EXPIRED)
	    && !retry) {
		invalidate_cm_connection(domain);
		retry = true;
		goto retry;
	}

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(10,("cm_connect_lsa: failed to connect to LSA pipe for "
			  "domain %s using NTLMSSP authenticated pipe: user "
			  "%s. Error was %s. Trying schannel.\n",
			  domain->name,
			  cli_credentials_get_unparsed_name(creds, talloc_tos()),
			  nt_errstr(result)));
		goto schannel;
	}

	DEBUG(10,("cm_connect_lsa: connected to LSA pipe for domain %s using "
		  "NTLMSSP authenticated pipe: user %s\n",
		  domain->name, cli_credentials_get_unparsed_name(creds, talloc_tos())));

	result = rpccli_lsa_open_policy(conn->lsa_pipe, mem_ctx, True,
					SEC_FLAG_MAXIMUM_ALLOWED,
					&conn->lsa_policy);
	if (NT_STATUS_EQUAL(result, NT_STATUS_IO_DEVICE_ERROR) && !retry) {
		invalidate_cm_connection(domain);
		TALLOC_FREE(conn->lsa_pipe);
		retry = true;
		goto retry;
	}

	if (NT_STATUS_IS_OK(result)) {
		goto done;
	}

	DEBUG(10,("cm_connect_lsa: rpccli_lsa_open_policy failed, trying "
		  "schannel\n"));

	TALLOC_FREE(conn->lsa_pipe);

 schannel:

	/* Fall back to schannel if it's a W2K pre-SP1 box. */

	result = cm_get_schannel_creds(domain, &p_creds);
	if (!NT_STATUS_IS_OK(result)) {
		/* If this call fails - conn->cli can now be NULL ! */
		DEBUG(10, ("cm_connect_lsa: Could not get schannel auth info "
			   "for domain %s (error %s), trying anon\n",
			domain->name,
			nt_errstr(result) ));
		goto anonymous;
	}

	TALLOC_FREE(creds);
	result = cli_rpc_pipe_open_schannel_with_creds(
		conn->cli, &ndr_table_lsarpc, NCACN_NP, p_creds,
		remote_name,
		remote_sockaddr,
		&conn->lsa_pipe);

	if (NT_STATUS_EQUAL(result, NT_STATUS_NETWORK_SESSION_EXPIRED)
	    && !retry) {
		invalidate_cm_connection(domain);
		retry = true;
		goto retry;
	}

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(10,("cm_connect_lsa: failed to connect to LSA pipe for "
			  "domain %s using schannel. Error was %s\n",
			  domain->name, nt_errstr(result) ));
		goto anonymous;
	}
	DEBUG(10,("cm_connect_lsa: connected to LSA pipe for domain %s using "
		  "schannel.\n", domain->name ));

	result = rpccli_lsa_open_policy(conn->lsa_pipe, mem_ctx, True,
					SEC_FLAG_MAXIMUM_ALLOWED,
					&conn->lsa_policy);

	if (NT_STATUS_EQUAL(result, NT_STATUS_IO_DEVICE_ERROR) && !retry) {
		invalidate_cm_connection(domain);
		TALLOC_FREE(conn->lsa_pipe);
		retry = true;
		goto retry;
	}

	if (NT_STATUS_IS_OK(result)) {
		goto done;
	}

	if (require_schannel) {
		/*
		 * Make sure we only use schannel as DC
		 * or with a direct trust
		 */
		goto done;
	}

	DEBUG(10,("cm_connect_lsa: rpccli_lsa_open_policy failed, trying "
		  "anonymous\n"));

	TALLOC_FREE(conn->lsa_pipe);

 anonymous:

	if (require_schannel) {
		/*
		 * Make sure we only use schannel as DC
		 * or with a direct trust
		 */
		goto done;
	}

	sealed_pipes = lp_winbind_sealed_pipes();
	sealed_pipes = lp_parm_bool(-1, "winbind sealed pipes",
				    domain->name,
				    sealed_pipes);
	strong_key = lp_require_strong_key();
	strong_key = lp_parm_bool(-1, "require strong key",
				  domain->name,
				  strong_key);

	/* Finally fall back to anonymous. */
	if (sealed_pipes || strong_key) {
		result = NT_STATUS_DOWNGRADE_DETECTED;
		DEBUG(1, ("Unwilling to make LSA connection to domain %s "
			  "without connection level security, "
			  "must set 'winbind sealed pipes:%s = false' and "
			  "'require strong key:%s = false' to proceed: %s\n",
			  domain->name, domain->name, domain->name,
			  nt_errstr(result)));
		goto done;
	}

	result = cli_rpc_pipe_open_noauth(conn->cli,
					  &ndr_table_lsarpc,
					  &conn->lsa_pipe);

	if (NT_STATUS_EQUAL(result, NT_STATUS_NETWORK_SESSION_EXPIRED)
	    && !retry) {
		invalidate_cm_connection(domain);
		retry = true;
		goto retry;
	}

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	result = rpccli_lsa_open_policy(conn->lsa_pipe, mem_ctx, True,
					SEC_FLAG_MAXIMUM_ALLOWED,
					&conn->lsa_policy);

	if (NT_STATUS_EQUAL(result, NT_STATUS_IO_DEVICE_ERROR) && !retry) {
		invalidate_cm_connection(domain);
		TALLOC_FREE(conn->lsa_pipe);
		retry = true;
		goto retry;
	}

 done:
	if (!NT_STATUS_IS_OK(result)) {
		invalidate_cm_connection(domain);
		return result;
	}

	*cli = conn->lsa_pipe;
	*lsa_policy = conn->lsa_policy;
	return result;
}

/****************************************************************************
Open a LSA connection to a DC, suitable for LSA lookup calls.
****************************************************************************/

NTSTATUS cm_connect_lsat(struct winbindd_domain *domain,
			 TALLOC_CTX *mem_ctx,
			 struct rpc_pipe_client **cli,
			 struct policy_handle *lsa_policy)
{
	NTSTATUS status;

	if (domain->can_do_ncacn_ip_tcp) {
		status = cm_connect_lsa_tcp(domain, mem_ctx, cli);
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_RPC_SEC_PKG_ERROR) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_ACCESS_DENIED)) {
			invalidate_cm_connection(domain);
			status = cm_connect_lsa_tcp(domain, mem_ctx, cli);
		}
		if (NT_STATUS_IS_OK(status)) {
			return status;
		}

		/*
		 * we tried twice to connect via ncan_ip_tcp and schannel and
		 * failed - maybe it is a trusted domain we can't connect to ?
		 * do not try tcp next time - gd
		 *
		 * This also prevents NETLOGON over TCP
		 */
		domain->can_do_ncacn_ip_tcp = false;
	}

	status = cm_connect_lsa(domain, mem_ctx, cli, lsa_policy);

	return status;
}

/****************************************************************************
 Open the netlogon pipe to this DC.
****************************************************************************/

static NTSTATUS cm_connect_netlogon_transport(struct winbindd_domain *domain,
					      enum dcerpc_transport_t transport,
					      struct rpc_pipe_client **cli)
{
	struct messaging_context *msg_ctx = global_messaging_context();
	struct winbindd_cm_conn *conn;
	NTSTATUS result;
	enum netr_SchannelType sec_chan_type;
	struct cli_credentials *creds = NULL;
	const char *remote_name = NULL;
	const struct sockaddr_storage *remote_sockaddr = NULL;

	*cli = NULL;

	if (IS_DC) {
		if (domain->secure_channel_type == SEC_CHAN_NULL) {
			/*
			 * Make sure we don't even try to
			 * connect to a foreign domain
			 * without a direct outbound trust.
			 */
			return NT_STATUS_NO_TRUST_LSA_SECRET;
		}
	}

	result = init_dc_connection_rpc(domain, domain->rodc);
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	conn = &domain->conn;

	if (rpccli_is_connected(conn->netlogon_pipe)) {
		*cli = conn->netlogon_pipe;
		return NT_STATUS_OK;
	}

	TALLOC_FREE(conn->netlogon_pipe);
	TALLOC_FREE(conn->netlogon_creds_ctx);

	remote_name = smbXcli_conn_remote_name(conn->cli->conn);
	remote_sockaddr = smbXcli_conn_remote_sockaddr(conn->cli->conn);

	result = winbindd_get_trust_credentials(domain,
						talloc_tos(),
						true, /* netlogon */
						false, /* ipc_fallback */
						&creds);
	if (!NT_STATUS_IS_OK(result)) {
		DBG_DEBUG("No user available for domain %s when trying "
			  "schannel\n", domain->name);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	if (cli_credentials_is_anonymous(creds)) {
		DBG_WARNING("get_trust_credential only gave anonymous for %s, "
			    "unable to make get NETLOGON credentials\n",
			    domain->name);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	sec_chan_type = cli_credentials_get_secure_channel_type(creds);
	if (sec_chan_type == SEC_CHAN_NULL) {
		if (transport == NCACN_IP_TCP) {
			DBG_NOTICE("get_secure_channel_type gave SEC_CHAN_NULL "
				   "for %s, deny NCACN_IP_TCP and let the "
				   "caller fallback to NCACN_NP.\n",
				   domain->name);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}

		DBG_NOTICE("get_secure_channel_type gave SEC_CHAN_NULL for %s, "
			   "fallback to noauth on NCACN_NP.\n",
			   domain->name);

		result = cli_rpc_pipe_open_noauth_transport(
			conn->cli,
			transport,
			&ndr_table_netlogon,
			remote_name,
			remote_sockaddr,
			&conn->netlogon_pipe);
		if (!NT_STATUS_IS_OK(result)) {
			invalidate_cm_connection(domain);
			return result;
		}

		*cli = conn->netlogon_pipe;
		return NT_STATUS_OK;
	}

	result = rpccli_create_netlogon_creds_ctx(creds,
						  domain->dcname,
						  msg_ctx,
						  domain,
						  &conn->netlogon_creds_ctx);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(1, ("rpccli_create_netlogon_creds failed for %s, "
			  "unable to create NETLOGON credentials: %s\n",
			  domain->name, nt_errstr(result)));
		return result;
	}

	result = rpccli_connect_netlogon(conn->cli,
					 transport,
					 remote_name,
					 remote_sockaddr,
					 conn->netlogon_creds_ctx,
					 conn->netlogon_force_reauth, creds,
					 &conn->netlogon_pipe);
	conn->netlogon_force_reauth = false;
	if (!NT_STATUS_IS_OK(result)) {
		DBG_DEBUG("rpccli_connect_netlogon failed: %s\n",
			  nt_errstr(result));
		return result;
	}

	*cli = conn->netlogon_pipe;
	return NT_STATUS_OK;
}

/****************************************************************************
Open a NETLOGON connection to a DC, suitable for SamLogon calls.
****************************************************************************/

NTSTATUS cm_connect_netlogon(struct winbindd_domain *domain,
			     struct rpc_pipe_client **cli)
{
	NTSTATUS status;

	status = init_dc_connection_rpc(domain, domain->rodc);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (domain->active_directory && domain->can_do_ncacn_ip_tcp) {
		status = cm_connect_netlogon_transport(domain, NCACN_IP_TCP, cli);
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_RPC_SEC_PKG_ERROR) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_ACCESS_DENIED)) {
			invalidate_cm_connection(domain);
			status = cm_connect_netlogon_transport(domain, NCACN_IP_TCP, cli);
		}
		if (NT_STATUS_IS_OK(status)) {
			return status;
		}

		/*
		 * we tried twice to connect via ncan_ip_tcp and schannel and
		 * failed - maybe it is a trusted domain we can't connect to ?
		 * do not try tcp next time - gd
		 *
		 * This also prevents LSA over TCP
		 */
		domain->can_do_ncacn_ip_tcp = false;
	}

	status = cm_connect_netlogon_transport(domain, NCACN_NP, cli);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_SESSION_EXPIRED)) {
		/*
		 * SMB2 session expired, needs reauthentication. Drop
		 * connection and retry.
		 */
		invalidate_cm_connection(domain);
		status = cm_connect_netlogon_transport(domain, NCACN_NP, cli);
	}

	return status;
}

NTSTATUS cm_connect_netlogon_secure(struct winbindd_domain *domain,
				    struct rpc_pipe_client **cli,
				    struct netlogon_creds_cli_context **ppdc)
{
	NTSTATUS status;

	if (domain->secure_channel_type == SEC_CHAN_NULL) {
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	status = cm_connect_netlogon(domain, cli);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (domain->conn.netlogon_creds_ctx == NULL) {
		return NT_STATUS_TRUSTED_DOMAIN_FAILURE;
	}

	*ppdc = domain->conn.netlogon_creds_ctx;
	return NT_STATUS_OK;
}

void winbind_msg_ip_dropped(struct messaging_context *msg_ctx,
			    void *private_data,
			    uint32_t msg_type,
			    struct server_id server_id,
			    DATA_BLOB *data)
{
	struct winbindd_domain *domain;
	char *freeit = NULL;
	char *addr;

	if ((data == NULL)
	    || (data->data == NULL)
	    || (data->length == 0)
	    || (data->data[data->length-1] != '\0')) {
		DEBUG(1, ("invalid msg_ip_dropped message: not a valid "
			  "string\n"));
		return;
	}

	addr = (char *)data->data;
	DEBUG(10, ("IP %s dropped\n", addr));

	if (!is_ipaddress(addr)) {
		char *slash;
		/*
		 * Some code sends us ip addresses with the /netmask
		 * suffix
		 */
		slash = strchr(addr, '/');
		if (slash == NULL) {
			DEBUG(1, ("invalid msg_ip_dropped message: %s\n",
				  addr));
			return;
		}
		freeit = talloc_strndup(talloc_tos(), addr, slash-addr);
		if (freeit == NULL) {
			DEBUG(1, ("talloc failed\n"));
			return;
		}
		addr = freeit;
		DEBUG(10, ("Stripped /netmask to IP %s\n", addr));
	}

	for (domain = domain_list(); domain != NULL; domain = domain->next) {
		char sockaddr[INET6_ADDRSTRLEN];

		if (!cli_state_is_connected(domain->conn.cli)) {
			continue;
		}

		print_sockaddr(sockaddr, sizeof(sockaddr),
			       smbXcli_conn_local_sockaddr(domain->conn.cli->conn));

		if (strequal(sockaddr, addr)) {
			smbXcli_conn_disconnect(domain->conn.cli->conn, NT_STATUS_OK);
		}
	}
	TALLOC_FREE(freeit);
}

void winbind_msg_disconnect_dc(struct messaging_context *msg_ctx,
			       void *private_data,
			       uint32_t msg_type,
			       struct server_id server_id,
			       DATA_BLOB *data)
{
	struct winbindd_domain *domain;

	for (domain = domain_list(); domain; domain = domain->next) {
		if (domain->internal) {
			continue;
		}
		invalidate_cm_connection(domain);
	}
}
