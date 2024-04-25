/*
   Unix SMB/Netbios implementation.
   Version 3.0
   handle GENSEC authentication, server side

   Copyright (C) Andrew Tridgell      2001
   Copyright (C) Andrew Bartlett 2001-2003,2011
   Copyright (C) Simo Sorce 2010.

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
#include <tevent.h>
#include "../lib/util/tevent_ntstatus.h"
#include "auth.h"
#include "../lib/tsocket/tsocket.h"
#include "auth/gensec/gensec.h"
#include "lib/param/param.h"
#ifdef HAVE_KRB5
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "auth/kerberos/pac_utils.h"
#include "nsswitch/libwbclient/wbclient.h"
#endif
#include "librpc/crypto/gse.h"
#include "auth/credentials/credentials.h"
#include "lib/param/loadparm.h"
#include "librpc/gen_ndr/dcerpc.h"
#include "source3/lib/substitute.h"

static NTSTATUS generate_pac_session_info(
	TALLOC_CTX *mem_ctx,
	const char *princ_name,
	const char *rhost,
	DATA_BLOB *pac_blob,
	struct auth_session_info **psession_info)
{
	NTSTATUS status;
	struct wbcAuthUserParams params = {0};
	struct wbcAuthUserInfo *info = NULL;
	struct wbcAuthErrorInfo *err = NULL;
	struct auth_serversupplied_info *server_info = NULL;
	char *original_user_name = NULL;
	char *p = NULL;
	wbcErr wbc_err;

	/*
	 * Let winbind decode the PAC.
	 * This will also store the user
	 * data in the netsamlogon cache.
	 *
	 * This used to be a cache prime
	 * optimization, but now we delegate
	 * all logic to winbindd, as we require
	 * winbindd as domain member anyway.
	 */
	params.level = WBC_AUTH_USER_LEVEL_PAC;
	params.password.pac.data = pac_blob->data;
	params.password.pac.length = pac_blob->length;

	/* we are contacting the privileged pipe */
	become_root();
	wbc_err = wbcAuthenticateUserEx(&params, &info, &err);
	unbecome_root();

	/*
	 * As this is merely a cache prime
	 * WBC_ERR_WINBIND_NOT_AVAILABLE
	 * is not a fatal error, treat it
	 * as success.
	 */

	switch (wbc_err) {
	case WBC_ERR_SUCCESS:
		break;
	case WBC_ERR_WINBIND_NOT_AVAILABLE:
		status = NT_STATUS_NO_LOGON_SERVERS;
		DBG_ERR("winbindd not running - "
			"but required as domain member: %s\n",
			nt_errstr(status));
		return status;
	case WBC_ERR_AUTH_ERROR:
		wbcFreeMemory(err);
		return NT_STATUS(err->nt_status);
	case WBC_ERR_NO_MEMORY:
		return NT_STATUS_NO_MEMORY;
	default:
		return NT_STATUS_LOGON_FAILURE;
	}

	status = make_server_info_wbcAuthUserInfo(mem_ctx,
						  info->account_name,
						  info->domain_name,
						  info,
						  &server_info);
	wbcFreeMemory(info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("make_server_info_wbcAuthUserInfo failed: %s\n",
			   nt_errstr(status)));
		return status;
	}

	/* We skip doing this step if the caller asked us not to */
	if (!(server_info->guest)) {
		const char *unix_username = server_info->unix_name;

		/* We might not be root if we are an RPC call */
		become_root();
		status = smb_pam_accountcheck(unix_username, rhost);
		unbecome_root();

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("check_ntlm_password:  PAM Account for user [%s] "
					  "FAILED with error %s\n",
					  unix_username, nt_errstr(status)));
			return status;
		}

		DEBUG(5, ("check_ntlm_password:  PAM Account for user [%s] "
			  "succeeded\n", unix_username));
	}

	DEBUG(3, ("Kerberos ticket principal name is [%s]\n", princ_name));

	p = strchr_m(princ_name, '@');
	if (!p) {
		DEBUG(3, ("[%s] Doesn't look like a valid principal\n",
				  princ_name));
		return NT_STATUS_LOGON_FAILURE;
	}

	original_user_name = talloc_strndup(mem_ctx,
					    princ_name,
					    p - princ_name);
	if (original_user_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = create_local_token(
		mem_ctx, server_info, NULL, original_user_name, psession_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("create_local_token failed: %s\n",
				   nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS generate_krb5_session_info(
	TALLOC_CTX *mem_ctx,
	const char *princ_name,
	const char *rhost,
	DATA_BLOB *pac_blob,
	struct auth_session_info **psession_info)
{
	bool is_mapped = false;
	bool is_guest = false;
	char *ntuser = NULL;
	char *ntdomain = NULL;
	char *username = NULL;
	struct passwd *pw = NULL;
	NTSTATUS status;

	if (pac_blob != NULL) {
		struct PAC_LOGON_NAME *logon_name = NULL;
		struct PAC_LOGON_INFO *logon_info = NULL;
		struct PAC_DATA *pac_data = NULL;
		enum ndr_err_code ndr_err;
		size_t i;

		pac_data = talloc_zero(mem_ctx, struct PAC_DATA);
		if (pac_data == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		ndr_err = ndr_pull_struct_blob(pac_blob,
					       pac_data,
					       pac_data,
					       (ndr_pull_flags_fn_t)
						       ndr_pull_PAC_DATA);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			status = ndr_map_error2ntstatus(ndr_err);
			DBG_ERR("Can't parse the PAC: %s\n", nt_errstr(status));
			return status;
		}

		if (pac_data->num_buffers < 4) {
			DBG_ERR("We expect at least 4 PAC buffers.\n");
			return NT_STATUS_INVALID_PARAMETER;
		}

		for (i = 0; i < pac_data->num_buffers; i++) {
			struct PAC_BUFFER *data_buf = &pac_data->buffers[i];

			switch (data_buf->type) {
			case PAC_TYPE_LOGON_NAME:
				logon_name = &data_buf->info->logon_name;
				break;
			case PAC_TYPE_LOGON_INFO:
				if (!data_buf->info) {
					break;
				}
				logon_info = data_buf->info->logon_info.info;
				break;
			default:
				break;
			}
		}

		if (logon_name == NULL) {
			TALLOC_FREE(pac_data);
			DBG_ERR("PAC without logon_name\n");
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (logon_info != NULL) {
			/*
			* In standalone mode we don't expect a MS-PAC!
			* we only support MIT realms
			*/
			TALLOC_FREE(pac_data);
			status = NT_STATUS_BAD_TOKEN_TYPE;
			DBG_WARNING("Unexpected PAC for [%s] in standalone mode - %s\n",
				princ_name, nt_errstr(status));
			return status;
		}

		TALLOC_FREE(pac_data);
	}

	status = get_user_from_kerberos_info(mem_ctx,
					     rhost,
					     princ_name,
					     &is_mapped,
					     &is_guest,
					     &ntuser,
					     &ntdomain,
					     &username,
					     &pw);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("Failed to map kerberos principal to system user "
			  "(%s)\n", nt_errstr(status));
		return NT_STATUS_ACCESS_DENIED;
	}

	status = make_session_info_krb5(mem_ctx,
					ntuser,
					ntdomain,
					username,
					pw,
					is_guest,
					is_mapped,
					psession_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to map kerberos pac to server info (%s)\n",
			  nt_errstr(status)));
		status = nt_status_squash(status);
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS auth3_generate_session_info_pac(
	struct auth4_context *auth_ctx,
	TALLOC_CTX *mem_ctx,
	struct smb_krb5_context *smb_krb5_context,
	DATA_BLOB *pac_blob,
	const char *princ_name,
	const struct tsocket_address *remote_address,
	uint32_t session_info_flags,
	struct auth_session_info **psession_info)
{
	enum server_role server_role = lp_server_role();
	struct auth_session_info *session_info = NULL;
	const char *rhost;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = NULL;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (tsocket_address_is_inet(remote_address, "ip")) {
		rhost = tsocket_address_inet_addr_string(remote_address,
							 tmp_ctx);
		if (rhost == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
	} else {
		rhost = "127.0.0.1";
	}

	switch (server_role) {
	case ROLE_DOMAIN_MEMBER:
	case ROLE_DOMAIN_BDC:
	case ROLE_DOMAIN_PDC:
	case ROLE_ACTIVE_DIRECTORY_DC:
	case ROLE_IPA_DC:
		/* This requires a complete MS-PAC including logon_info */
		status = generate_pac_session_info(
			tmp_ctx, princ_name, rhost, pac_blob, &session_info);
		break;
	case ROLE_STANDALONE:
		/* This requires no PAC or a minimal PAC */
		status = generate_krb5_session_info(
			tmp_ctx, princ_name, rhost, pac_blob, &session_info);
		break;
	default:
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	/* setup the string used by %U */
	set_current_user_info(session_info->unix_info->sanitized_username,
			      session_info->unix_info->unix_name,
			      session_info->info->domain_name);

	/* reload services so that the new %U is taken into account */
	lp_load_with_shares(get_dyn_CONFIGFILE());

	DEBUG(5, (__location__ "OK: user: %s domain: %s client: %s\n",
		  session_info->info->account_name,
		  session_info->info->domain_name,
		  rhost));

	*psession_info = talloc_move(mem_ctx, &session_info);

	status = NT_STATUS_OK;
done:
	TALLOC_FREE(tmp_ctx);
	return status;
}

static struct auth4_context *make_auth4_context_s3(TALLOC_CTX *mem_ctx, struct auth_context *auth_context)
{
	struct auth4_context *auth4_context = talloc_zero(mem_ctx, struct auth4_context);
	if (auth4_context == NULL) {
		DEBUG(10, ("failed to allocate auth4_context failed\n"));
		return NULL;
	}
	auth4_context->generate_session_info_pac = auth3_generate_session_info_pac;
	auth4_context->generate_session_info = auth3_generate_session_info;
	auth4_context->get_ntlm_challenge = auth3_get_challenge;
	auth4_context->set_ntlm_challenge = auth3_set_challenge;
	auth4_context->check_ntlm_password_send = auth3_check_password_send;
	auth4_context->check_ntlm_password_recv = auth3_check_password_recv;
	auth4_context->private_data = talloc_steal(auth4_context, auth_context);
	return auth4_context;
}

NTSTATUS make_auth4_context(TALLOC_CTX *mem_ctx, struct auth4_context **auth4_context_out)
{
	struct auth_context *auth_context;
	NTSTATUS nt_status;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	nt_status = make_auth3_context_for_ntlm(tmp_ctx, &auth_context);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	if (auth_context->make_auth4_context) {
		nt_status = auth_context->make_auth4_context(auth_context, mem_ctx, auth4_context_out);
		TALLOC_FREE(tmp_ctx);
		return nt_status;

	} else {
		struct auth4_context *auth4_context = make_auth4_context_s3(tmp_ctx, auth_context);
		if (auth4_context == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
		*auth4_context_out = talloc_steal(mem_ctx, auth4_context);
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_OK;
	}
}

NTSTATUS auth_generic_prepare(TALLOC_CTX *mem_ctx,
			      const struct tsocket_address *remote_address,
			      const struct tsocket_address *local_address,
			      const char *service_description,
			      struct gensec_security **gensec_security_out)
{
	struct gensec_security *gensec_security;
	struct auth_context *auth_context = NULL;
	NTSTATUS nt_status;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	nt_status = make_auth3_context_for_ntlm(tmp_ctx, &auth_context);
	if (!NT_STATUS_IS_OK(nt_status)) {
		goto done;
	}

	if (auth_context->prepare_gensec) {
		nt_status = auth_context->prepare_gensec(auth_context, tmp_ctx,
							 &gensec_security);
		if (!NT_STATUS_IS_OK(nt_status)) {
			goto done;
		}
	} else {
		const struct gensec_security_ops **backends = NULL;
		struct gensec_settings *gensec_settings;
		struct loadparm_context *lp_ctx;
		size_t idx = 0;
		struct cli_credentials *server_credentials;
		const char *dns_name;
		const char *dns_domain;
		bool ok;
		struct auth4_context *auth4_context = make_auth4_context_s3(tmp_ctx, auth_context);
		if (auth4_context == NULL) {
			goto nomem;
		}

		lp_ctx = loadparm_init_s3(tmp_ctx, loadparm_s3_helpers());
		if (lp_ctx == NULL) {
			DEBUG(10, ("loadparm_init_s3 failed\n"));
			nt_status = NT_STATUS_INVALID_SERVER_STATE;
			goto done;
		}

		gensec_settings = lpcfg_gensec_settings(tmp_ctx, lp_ctx);
		if (lp_ctx == NULL) {
			DEBUG(10, ("lpcfg_gensec_settings failed\n"));
			goto nomem;
		}

		/*
		 * This should be a 'netbios domain -> DNS domain'
		 * mapping, and can currently validly return NULL on
		 * poorly configured systems.
		 *
		 * This is used for the NTLMSSP server
		 *
		 */
		dns_name = get_mydnsfullname();
		if (dns_name == NULL) {
			dns_name = "";
		}

		dns_domain = get_mydnsdomname(tmp_ctx);
		if (dns_domain == NULL) {
			dns_domain = "";
		}

		gensec_settings->server_dns_name = strlower_talloc(gensec_settings, dns_name);
		if (gensec_settings->server_dns_name == NULL) {
			goto nomem;
		}

		gensec_settings->server_dns_domain = strlower_talloc(gensec_settings, dns_domain);
		if (gensec_settings->server_dns_domain == NULL) {
			goto nomem;
		}

		backends = talloc_zero_array(gensec_settings,
					     const struct gensec_security_ops *, 6);
		if (backends == NULL) {
			goto nomem;
		}
		gensec_settings->backends = backends;

		gensec_init();

		/* These need to be in priority order, krb5 before NTLMSSP */
#if defined(HAVE_KRB5)
		backends[idx++] = gensec_gse_security_by_oid(
			GENSEC_OID_KERBEROS5);
#endif

		backends[idx++] = gensec_security_by_oid(NULL, GENSEC_OID_NTLMSSP);

		backends[idx++] = gensec_security_by_oid(NULL, GENSEC_OID_SPNEGO);

		backends[idx++] = gensec_security_by_auth_type(NULL, DCERPC_AUTH_TYPE_SCHANNEL);

		backends[idx++] = gensec_security_by_auth_type(NULL, DCERPC_AUTH_TYPE_NCALRPC_AS_SYSTEM);

		/*
		 * This is anonymous for now, because we just use it
		 * to set the kerberos state at the moment
		 */
		server_credentials = cli_credentials_init_anon(tmp_ctx);
		if (!server_credentials) {
			DEBUG(0, ("auth_generic_prepare: Failed to init server credentials\n"));
			goto nomem;
		}

		ok = cli_credentials_set_conf(server_credentials, lp_ctx);
		if (!ok) {
			DBG_ERR("Failed to set server credentials defaults "
				"from smb.conf.\n");
			goto nomem;
		}

		if (lp_security() == SEC_ADS || USE_KERBEROS_KEYTAB) {
			cli_credentials_set_kerberos_state(server_credentials,
							   CRED_USE_KERBEROS_DESIRED,
							   CRED_SPECIFIED);
		} else {
			cli_credentials_set_kerberos_state(server_credentials,
							   CRED_USE_KERBEROS_DISABLED,
							   CRED_SPECIFIED);
		}

		nt_status = gensec_server_start(tmp_ctx, gensec_settings,
						auth4_context, &gensec_security);

		if (!NT_STATUS_IS_OK(nt_status)) {
			goto done;
		}

		nt_status = gensec_set_credentials(
			gensec_security, server_credentials);
		if (!NT_STATUS_IS_OK(nt_status)) {
			goto done;
		}
	}

	nt_status = gensec_set_remote_address(gensec_security,
					      remote_address);
	if (!NT_STATUS_IS_OK(nt_status)) {
		goto done;
	}

	nt_status = gensec_set_local_address(gensec_security,
					     local_address);
	if (!NT_STATUS_IS_OK(nt_status)) {
		goto done;
	}

	nt_status = gensec_set_target_service_description(gensec_security,
							  service_description);
	if (!NT_STATUS_IS_OK(nt_status)) {
		goto done;
	}

	*gensec_security_out = talloc_move(mem_ctx, &gensec_security);
	nt_status = NT_STATUS_OK;
	goto done;
nomem:
	nt_status = NT_STATUS_NO_MEMORY;
done:
	TALLOC_FREE(tmp_ctx);
	return nt_status;
}

/*
 * Check a username and password, and return the final session_info.
 * We also log the authorization of the session here, just as
 * gensec_session_info() does.
 */
NTSTATUS auth_check_password_session_info(struct auth4_context *auth_context,
					  TALLOC_CTX *mem_ctx,
					  struct auth_usersupplied_info *user_info,
					  struct auth_session_info **session_info)
{
	NTSTATUS nt_status;
	void *server_info;
	uint8_t authoritative = 1;
	struct tevent_context *ev = NULL;
	struct tevent_req *subreq = NULL;
	bool ok;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	subreq = auth_context->check_ntlm_password_send(ev, ev,
							auth_context,
							user_info);
	if (subreq == NULL) {
		TALLOC_FREE(ev);
		return NT_STATUS_NO_MEMORY;
	}
	ok = tevent_req_poll_ntstatus(subreq, ev, &nt_status);
	if (!ok) {
		TALLOC_FREE(ev);
		return nt_status;
	}
	nt_status = auth_context->check_ntlm_password_recv(subreq,
							   talloc_tos(),
							   &authoritative,
							   &server_info,
							   NULL, NULL);
	TALLOC_FREE(ev);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	nt_status = auth_context->generate_session_info(auth_context,
							mem_ctx,
							server_info,
							user_info->client.account_name,
							AUTH_SESSION_INFO_UNIX_TOKEN |
							AUTH_SESSION_INFO_DEFAULT_GROUPS |
							AUTH_SESSION_INFO_NTLM,
							session_info);
	TALLOC_FREE(server_info);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	/*
	 * This is rather redundant (the authentication has just been
	 * logged, with much the same details), but because we want to
	 * log all authorizations consistently (be they NLTM, NTLMSSP
	 * or krb5) we log this info again as an authorization.
	 */
	log_successful_authz_event(auth_context->msg_ctx,
				   auth_context->lp_ctx,
				   user_info->remote_host,
				   user_info->local_host,
				   user_info->service_description,
				   user_info->auth_description,
				   AUTHZ_TRANSPORT_PROTECTION_SMB,
				   *session_info,
				   NULL /* client_audit_info */,
				   NULL /* server_audit_info */);

	return nt_status;
}
