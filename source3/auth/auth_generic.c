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
#include "auth.h"
#include "../lib/tsocket/tsocket.h"
#include "auth/gensec/gensec.h"
#include "lib/param/param.h"
#ifdef HAVE_KRB5
#include "libcli/auth/krb5_wrap.h"
#endif
#include "librpc/crypto/gse.h"
#include "auth/credentials/credentials.h"

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
	struct PAC_DATA *pac_data = NULL;
	struct PAC_LOGON_INFO *logon_info = NULL;
	unsigned int i;
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
		status = kerberos_decode_pac(tmp_ctx,
				     *pac_blob,
				     NULL, NULL, NULL, NULL, 0, &pac_data);
#else
		status = NT_STATUS_ACCESS_DENIED;
#endif
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		/* get logon name and logon info */
		for (i = 0; i < pac_data->num_buffers; i++) {
			struct PAC_BUFFER *data_buf = &pac_data->buffers[i];

			switch (data_buf->type) {
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
		if (!logon_info) {
			DEBUG(1, ("Invalid PAC data, missing logon info!\n"));
			status = NT_STATUS_NOT_FOUND;
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
		DEBUG(1, ("Failed to map kerberos principal to system user "
			  "(%s)\n", nt_errstr(status)));
		status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	/* save the PAC data if we have it */
	if (logon_info) {
		netsamlogon_cache_store(ntuser, &logon_info->info3);
	}

	/* setup the string used by %U */
	sub_set_smb_name(username);

	/* reload services so that the new %U is taken into account */
	lp_load(get_dyn_CONFIGFILE(), false, false, true, true);

	status = make_session_info_krb5(mem_ctx,
					ntuser, ntdomain, username, pw,
					logon_info, is_guest, is_mapped, NULL /* No session key for now, caller will sort it out */,
					session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to map kerberos pac to server info (%s)\n",
			  nt_errstr(status)));
		status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	DEBUG(5, (__location__ "OK: user: %s domain: %s client: %s\n",
		  ntuser, ntdomain, rhost));

	status = NT_STATUS_OK;

done:
	TALLOC_FREE(tmp_ctx);
	return status;
}

NTSTATUS auth_generic_prepare(TALLOC_CTX *mem_ctx,
			      const struct tsocket_address *remote_address,
			      struct gensec_security **gensec_security_out)
{
	struct gensec_security *gensec_security;
	struct auth_context *auth_context;
	NTSTATUS nt_status;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	nt_status = make_auth_context_subsystem(tmp_ctx, &auth_context);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	if (auth_context->prepare_gensec) {
		nt_status = auth_context->prepare_gensec(tmp_ctx,
							 &gensec_security);
		if (!NT_STATUS_IS_OK(nt_status)) {
			TALLOC_FREE(tmp_ctx);
			return nt_status;
		}
	} else {
		struct gensec_settings *gensec_settings;
		struct loadparm_context *lp_ctx;
		size_t idx = 0;
		struct cli_credentials *server_credentials;
		const char *dns_name;
		const char *dns_domain;
		struct auth4_context *auth4_context = talloc_zero(tmp_ctx, struct auth4_context);
		if (auth4_context == NULL) {
			DEBUG(10, ("failed to allocate auth4_context failed\n"));
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
		auth4_context->generate_session_info_pac = auth3_generate_session_info_pac;
		auth4_context->generate_session_info = auth3_generate_session_info;
		auth4_context->get_challenge = auth3_get_challenge;
		auth4_context->set_challenge = auth3_set_challenge;
		auth4_context->challenge_may_be_modified = auth3_may_set_challenge;
		auth4_context->check_password = auth3_check_password;
		auth4_context->private_data = talloc_steal(auth4_context, auth_context);

		lp_ctx = loadparm_init_s3(tmp_ctx, loadparm_s3_context());
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

		gensec_settings->backends = talloc_zero_array(gensec_settings,
						struct gensec_security_ops *, 4);
		if (gensec_settings->backends == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		gensec_init();

		gensec_settings->backends[idx++] = gensec_security_by_oid(NULL, GENSEC_OID_NTLMSSP);

#if defined(HAVE_KRB5) && defined(HAVE_GSS_WRAP_IOV)
		gensec_settings->backends[idx++] = &gensec_gse_krb5_security_ops;
#endif

		gensec_settings->backends[idx++] = gensec_security_by_oid(NULL,
							GENSEC_OID_SPNEGO);

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

	*gensec_security_out = talloc_steal(mem_ctx, gensec_security);
	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
}
