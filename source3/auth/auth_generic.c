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
#include "auth/kerberos/pac_utils.h"
#include "nsswitch/libwbclient/wbclient.h"
#endif
#include "librpc/crypto/gse.h"
#include "auth/credentials/credentials.h"
#include "lib/param/loadparm.h"
#include "librpc/gen_ndr/dcerpc.h"

static NTSTATUS auth3_generate_session_info_pac(struct auth4_context *auth_ctx,
						TALLOC_CTX *mem_ctx,
						struct smb_krb5_context *smb_krb5_context,
						DATA_BLOB *pac_blob,
						const char *princ_name,
						const struct tsocket_address *remote_address,
						uint32_t session_info_flags,
						struct auth_session_info **session_info)
{
	TALLOC_CTX *tmp_ctx;
	struct PAC_LOGON_INFO *logon_info = NULL;
	struct netr_SamInfo3 *info3_copy = NULL;
	bool is_mapped;
	bool is_guest;
	char *ntuser;
	char *ntdomain;
	char *username;
	char *rhost;
	struct passwd *pw;
	NTSTATUS status;
	int rc;

	tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	if (pac_blob) {
#ifdef HAVE_KRB5
		struct wbcAuthUserParams params = { 0 };
		struct wbcAuthUserInfo *info = NULL;
		struct wbcAuthErrorInfo *err = NULL;
		wbcErr wbc_err;

		/*
		 * Let winbind decode the PAC.
		 * This will also store the user
		 * data in the netsamlogon cache.
		 *
		 * We need to do this *before* we
		 * call get_user_from_kerberos_info()
		 * as that does a user lookup that
		 * expects info in the netsamlogon cache.
		 *
		 * See BUG: https://bugzilla.samba.org/show_bug.cgi?id=11259
		 */
		params.level = WBC_AUTH_USER_LEVEL_PAC;
		params.password.pac.data = pac_blob->data;
		params.password.pac.length = pac_blob->length;

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
			case WBC_ERR_WINBIND_NOT_AVAILABLE:
			case WBC_ERR_SUCCESS:
				break;
			case WBC_ERR_AUTH_ERROR:
				status = NT_STATUS(err->nt_status);
				wbcFreeMemory(err);
				goto done;
			default:
				status = NT_STATUS_LOGON_FAILURE;
				goto done;
		}

		status = kerberos_pac_logon_info(tmp_ctx, *pac_blob, NULL, NULL,
						 NULL, NULL, 0, &logon_info);
#else
		status = NT_STATUS_ACCESS_DENIED;
#endif
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
	}

	rc = get_remote_hostname(remote_address,
				 &rhost,
				 tmp_ctx);
	if (rc < 0) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	if (strequal(rhost, "UNKNOWN")) {
		rhost = tsocket_address_inet_addr_string(remote_address,
							 tmp_ctx);
		if (rhost == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
	}

	status = get_user_from_kerberos_info(tmp_ctx, rhost,
					     princ_name, logon_info,
					     &is_mapped, &is_guest,
					     &ntuser, &ntdomain,
					     &username, &pw);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("Failed to map kerberos principal to system user "
			  "(%s)\n", nt_errstr(status));
		status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	/* Get the info3 from the PAC data if we have it */
	if (logon_info) {
		status = create_info3_from_pac_logon_info(tmp_ctx,
					logon_info,
					&info3_copy);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
	}

	status = make_session_info_krb5(mem_ctx,
					ntuser, ntdomain, username, pw,
					info3_copy, is_guest, is_mapped, NULL /* No session key for now, caller will sort it out */,
					session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to map kerberos pac to server info (%s)\n",
			  nt_errstr(status)));
		status = nt_status_squash(status);
		goto done;
	}

	/* setup the string used by %U */
	set_current_user_info((*session_info)->unix_info->sanitized_username,
			      (*session_info)->unix_info->unix_name,
			      (*session_info)->info->domain_name);

	/* reload services so that the new %U is taken into account */
	lp_load_with_shares(get_dyn_CONFIGFILE());

	DEBUG(5, (__location__ "OK: user: %s domain: %s client: %s\n",
		  ntuser, ntdomain, rhost));

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
	struct auth_context *auth_context;
	NTSTATUS nt_status;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	nt_status = make_auth3_context_for_ntlm(tmp_ctx, &auth_context);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	if (auth_context->prepare_gensec) {
		nt_status = auth_context->prepare_gensec(auth_context, tmp_ctx,
							 &gensec_security);
		if (!NT_STATUS_IS_OK(nt_status)) {
			TALLOC_FREE(tmp_ctx);
			return nt_status;
		}
	} else {
		const struct gensec_security_ops **backends = NULL;
		struct gensec_settings *gensec_settings;
		struct loadparm_context *lp_ctx;
		size_t idx = 0;
		struct cli_credentials *server_credentials;
		const char *dns_name;
		const char *dns_domain;
		struct auth4_context *auth4_context = make_auth4_context_s3(tmp_ctx, auth_context);
		if (auth4_context == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		lp_ctx = loadparm_init_s3(tmp_ctx, loadparm_s3_helpers());
		if (lp_ctx == NULL) {
			DEBUG(10, ("loadparm_init_s3 failed\n"));
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_INVALID_SERVER_STATE;
		}

		gensec_settings = lpcfg_gensec_settings(tmp_ctx, lp_ctx);
		if (lp_ctx == NULL) {
			DEBUG(10, ("lpcfg_gensec_settings failed\n"));
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
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
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		gensec_settings->server_dns_domain = strlower_talloc(gensec_settings, dns_domain);
		if (gensec_settings->server_dns_domain == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		backends = talloc_zero_array(gensec_settings,
					     const struct gensec_security_ops *, 6);
		if (backends == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
		gensec_settings->backends = backends;

		gensec_init();

		/* These need to be in priority order, krb5 before NTLMSSP */
#if defined(HAVE_KRB5)
		backends[idx++] = &gensec_gse_krb5_security_ops;
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
			return NT_STATUS_NO_MEMORY;
		}

		cli_credentials_set_conf(server_credentials, lp_ctx);

		if (lp_security() == SEC_ADS || USE_KERBEROS_KEYTAB) {
			cli_credentials_set_kerberos_state(server_credentials, CRED_AUTO_USE_KERBEROS);
		} else {
			cli_credentials_set_kerberos_state(server_credentials, CRED_DONT_USE_KERBEROS);
		}

		nt_status = gensec_server_start(tmp_ctx, gensec_settings,
						auth4_context, &gensec_security);

		if (!NT_STATUS_IS_OK(nt_status)) {
			TALLOC_FREE(tmp_ctx);
			return nt_status;
		}

		gensec_set_credentials(gensec_security, server_credentials);

		talloc_unlink(tmp_ctx, lp_ctx);
		talloc_unlink(tmp_ctx, server_credentials);
		talloc_unlink(tmp_ctx, gensec_settings);
		talloc_unlink(tmp_ctx, auth4_context);
	}

	nt_status = gensec_set_remote_address(gensec_security,
					      remote_address);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	nt_status = gensec_set_local_address(gensec_security,
					     local_address);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	nt_status = gensec_set_target_service_description(gensec_security,
							  service_description);

	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	*gensec_security_out = talloc_steal(mem_ctx, gensec_security);
	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
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
				   *session_info);

	return nt_status;
}
