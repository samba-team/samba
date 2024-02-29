/*
   Unix SMB/CIFS implementation.
   ads sasl code
   Copyright (C) Andrew Tridgell 2001

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
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "auth_generic.h"
#include "ads.h"
#include "smb_krb5.h"
#include "system/gssapi.h"
#include "lib/param/param.h"
#include "krb5_env.h"
#include "lib/util/asn1.h"

#ifdef HAVE_LDAP

static ADS_STATUS ads_sasl_gensec_wrap(struct ads_saslwrap *wrap,
				       uint8_t *buf, uint32_t len)
{
	struct gensec_security *gensec_security =
		talloc_get_type_abort(wrap->wrap_private_data,
		struct gensec_security);
	NTSTATUS nt_status;
	DATA_BLOB unwrapped, wrapped;
	TALLOC_CTX *frame = talloc_stackframe();

	unwrapped = data_blob_const(buf, len);

	nt_status = gensec_wrap(gensec_security, frame, &unwrapped, &wrapped);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(frame);
		return ADS_ERROR_NT(nt_status);
	}

	if ((wrap->out.size - 4) < wrapped.length) {
		TALLOC_FREE(frame);
		return ADS_ERROR_NT(NT_STATUS_INTERNAL_ERROR);
	}

	/* copy the wrapped blob to the right location */
	memcpy(wrap->out.buf + 4, wrapped.data, wrapped.length);

	/* set how many bytes must be written to the underlying socket */
	wrap->out.left = 4 + wrapped.length;

	TALLOC_FREE(frame);

	return ADS_SUCCESS;
}

static ADS_STATUS ads_sasl_gensec_unwrap(struct ads_saslwrap *wrap)
{
	struct gensec_security *gensec_security =
		talloc_get_type_abort(wrap->wrap_private_data,
		struct gensec_security);
	NTSTATUS nt_status;
	DATA_BLOB unwrapped, wrapped;
	TALLOC_CTX *frame = talloc_stackframe();

	wrapped = data_blob_const(wrap->in.buf + 4, wrap->in.ofs - 4);

	nt_status = gensec_unwrap(gensec_security, frame, &wrapped, &unwrapped);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(frame);
		return ADS_ERROR_NT(nt_status);
	}

	if (wrapped.length < unwrapped.length) {
		TALLOC_FREE(frame);
		return ADS_ERROR_NT(NT_STATUS_INTERNAL_ERROR);
	}

	/* copy the wrapped blob to the right location */
	memcpy(wrap->in.buf + 4, unwrapped.data, unwrapped.length);

	/* set how many bytes must be written to the underlying socket */
	wrap->in.left	= unwrapped.length;
	wrap->in.ofs	= 4;

	TALLOC_FREE(frame);

	return ADS_SUCCESS;
}

static void ads_sasl_gensec_disconnect(struct ads_saslwrap *wrap)
{
	struct gensec_security *gensec_security =
		talloc_get_type_abort(wrap->wrap_private_data,
		struct gensec_security);

	TALLOC_FREE(gensec_security);

	wrap->wrap_ops = NULL;
	wrap->wrap_private_data = NULL;
}

static const struct ads_saslwrap_ops ads_sasl_gensec_ops = {
	.name		= "gensec",
	.wrap		= ads_sasl_gensec_wrap,
	.unwrap		= ads_sasl_gensec_unwrap,
	.disconnect	= ads_sasl_gensec_disconnect
};

NTSTATUS ads_legacy_creds(ADS_STRUCT *ads,
			  TALLOC_CTX *mem_ctx,
			  struct cli_credentials **_creds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct cli_credentials *creds = NULL;
	struct loadparm_context *lp_ctx = NULL;
	const char *account_name = NULL;
	fstring acct_name;
	enum credentials_use_kerberos krb5_state;
	uint32_t gensec_features;
	bool ok;

	if (ads->auth.flags & (ADS_AUTH_NO_BIND|ADS_AUTH_ANON_BIND)) {
		SMB_ASSERT(!(ads->auth.flags & ADS_AUTH_USER_CREDS));

		creds = cli_credentials_init_anon(mem_ctx);
		if (creds == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
		talloc_steal(frame, creds);
		goto done;
	}

	if (ads->auth.user_name == NULL) {
		/*
		 * Must use the userPrincipalName value here or sAMAccountName
		 * and not servicePrincipalName; found by Guenther Deschner
		 */
		ads->auth.user_name = talloc_asprintf(ads,
						      "%s$",
						      lp_netbios_name());
		if (ads->auth.user_name == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (ads->auth.realm == NULL) {
		if (ads->server.realm != NULL) {
			ads->auth.realm = talloc_strdup(ads, ads->server.realm);
			if (ads->auth.realm == NULL) {
				TALLOC_FREE(frame);
				return NT_STATUS_NO_MEMORY;
			}
		} else {
			ads->auth.realm = talloc_strdup(ads, lp_realm());
			if (ads->auth.realm == NULL) {
				TALLOC_FREE(frame);
				return NT_STATUS_NO_MEMORY;
			}
		}
	}

	lp_ctx = loadparm_init_s3(frame, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		DBG_ERR("loadparm_init_s3 failed\n");
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_SERVER_STATE;
	}

	creds = cli_credentials_init(mem_ctx);
	if (creds == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_steal(frame, creds);

	ok = cli_credentials_guess(creds, lp_ctx);
	if (!ok) {
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_ERROR;
	}

	/*
	 * This logic was taken from ads_kinit_password()
	 */
	if (ads->auth.flags & ADS_AUTH_USER_CREDS) {
		account_name = ads->auth.user_name;
	} else if (IS_DC) {
		/* this will end up getting a ticket for DOMAIN@RUSTED.REA.LM */
		account_name = lp_workgroup();
	} else if (lp_security() == SEC_DOMAIN ) {
		fstr_sprintf( acct_name, "%s$", lp_netbios_name() );
		account_name = acct_name;
	} else {
		/* This looks like host/lp_netbios_name()@REA.LM */
		account_name = ads->auth.user_name;
	}

	ok = cli_credentials_set_username(creds,
					  account_name,
					  CRED_SPECIFIED);
	if (!ok) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	ok = cli_credentials_set_domain(creds,
					ads->auth.realm,
					CRED_SPECIFIED);
	if (!ok) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	ok = cli_credentials_set_password(creds,
					  ads->auth.password,
					  CRED_SPECIFIED);
	if (!ok) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

#define __ADS_AUTH_BOTH (ADS_AUTH_ALLOW_NTLMSSP|ADS_AUTH_DISABLE_KERBEROS)
	if ((ads->auth.flags & __ADS_AUTH_BOTH) == __ADS_AUTH_BOTH) {
		krb5_state = CRED_USE_KERBEROS_DISABLED;
	} else if (ads->auth.flags & ADS_AUTH_ALLOW_NTLMSSP) {
		krb5_state = CRED_USE_KERBEROS_DESIRED;
	} else if (ads->auth.flags & ADS_AUTH_DISABLE_KERBEROS) {
		TALLOC_FREE(frame);
		return NT_STATUS_INCOMPATIBLE_DRIVER_BLOCKED;
	} else {
		krb5_state = CRED_USE_KERBEROS_REQUIRED;
	}
	cli_credentials_set_kerberos_state(creds, krb5_state, CRED_SPECIFIED);

	gensec_features = cli_credentials_get_gensec_features(creds);
	if (ads->auth.flags & ADS_AUTH_SASL_LDAPS) {
		gensec_features &= ~(GENSEC_FEATURE_SIGN|GENSEC_FEATURE_SEAL);
	} else if (ads->auth.flags & ADS_AUTH_SASL_STARTTLS) {
		gensec_features &= ~(GENSEC_FEATURE_SIGN|GENSEC_FEATURE_SEAL);
	} else if (ads->auth.flags & ADS_AUTH_SASL_SEAL) {
		gensec_features |= GENSEC_FEATURE_SIGN;
		gensec_features |= GENSEC_FEATURE_SEAL;
	} else if (ads->auth.flags & ADS_AUTH_SASL_SIGN) {
		gensec_features |= GENSEC_FEATURE_SIGN;
	}
	cli_credentials_set_gensec_features(creds, gensec_features, CRED_SPECIFIED);

#ifdef HAVE_KRB5
	if (krb5_state != CRED_USE_KERBEROS_DISABLED &&
	    ads->auth.password != NULL &&
	    ads->auth.password[0] != '\0')
	{
		ADS_STATUS ads_status;
		const char *error_string = NULL;
		int rc;

		ads->auth.flags |= ADS_AUTH_GENERATE_KRB5_CONFIG;
		ads_status = ads_connect_cldap_only(ads);
		ads->auth.flags &= ~ADS_AUTH_NO_BIND;
		if (!ADS_ERR_OK(ads_status)) {
			TALLOC_FREE(frame);
			return ads_ntstatus(ads_status);
		}

		rc = ads_kinit_password(ads);
		if (rc == 0) {
			rc = cli_credentials_set_ccache(creds,
							lp_ctx,
							ads->auth.ccache_name,
							CRED_SPECIFIED,
							&error_string);
			if (rc != 0) {
				ads_status = ADS_ERROR_KRB5(rc);
				TALLOC_FREE(frame);
				return ads_ntstatus(ads_status);
			}
		} else if (krb5_state == CRED_USE_KERBEROS_REQUIRED) {
			/*
			 * Only fail if kerberos is required,
			 * otherwise we ignore the kinit failure
			 * and assume NTLMSSP will make it
			 */
			ads_status = ADS_ERROR_KRB5(rc);
			TALLOC_FREE(frame);
			return ads_ntstatus(ads_status);
		}
	}
#endif /* HAVE_KRB5 */

done:
	*_creds = talloc_move(mem_ctx, &creds);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

/*
   perform a LDAP/SASL/SPNEGO/{NTLMSSP,KRB5} bind (just how many layers can
   we fit on one socket??)
*/
static ADS_STATUS ads_sasl_spnego_gensec_bind(ADS_STRUCT *ads,
				struct cli_credentials *creds,
				const char *target_service,
				const char *target_hostname)
{
	DATA_BLOB blob_in = data_blob_null;
	DATA_BLOB blob_out = data_blob_null;
	int rc;
	NTSTATUS nt_status;
	ADS_STATUS status;
	struct auth_generic_state *auth_generic_state;
	const char *sasl = "GSS-SPNEGO";
	const char *sasl_list[] = { sasl, NULL };
	NTTIME end_nt_time;
	struct ads_saslwrap *wrap = &ads->ldap_wrap_data;
	const DATA_BLOB *tls_cb = NULL;

	nt_status = auth_generic_client_prepare(NULL, &auth_generic_state);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return ADS_ERROR_NT(nt_status);
	}

	if (!NT_STATUS_IS_OK(nt_status = auth_generic_set_creds(auth_generic_state, creds))) {
		return ADS_ERROR_NT(nt_status);
	}

	if (target_service != NULL) {
		nt_status = gensec_set_target_service(
					auth_generic_state->gensec_security,
					target_service);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return ADS_ERROR_NT(nt_status);
		}
	}

	if (target_hostname != NULL) {
		nt_status = gensec_set_target_hostname(
					auth_generic_state->gensec_security,
					target_hostname);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return ADS_ERROR_NT(nt_status);
		}
	}

	tls_cb = ads_tls_channel_bindings(&ads->ldap_tls_data);
	if (tls_cb != NULL) {
		uint32_t initiator_addrtype = 0;
		const DATA_BLOB *initiator_address = NULL;
		uint32_t acceptor_addrtype = 0;
		const DATA_BLOB *acceptor_address = NULL;
		const DATA_BLOB *application_data = tls_cb;

		nt_status = gensec_set_channel_bindings(auth_generic_state->gensec_security,
							initiator_addrtype,
							initiator_address,
							acceptor_addrtype,
							acceptor_address,
							application_data);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DBG_WARNING("Failed to set GENSEC channel bindings: %s\n",
				    nt_errstr(nt_status));
			return ADS_ERROR_NT(nt_status);
		}
	}

	switch (wrap->wrap_type) {
	case ADS_SASLWRAP_TYPE_SEAL:
		gensec_want_feature(auth_generic_state->gensec_security, GENSEC_FEATURE_SIGN);
		gensec_want_feature(auth_generic_state->gensec_security, GENSEC_FEATURE_SEAL);
		break;
	case ADS_SASLWRAP_TYPE_SIGN:
		if (ads->auth.flags & ADS_AUTH_SASL_FORCE) {
			gensec_want_feature(auth_generic_state->gensec_security, GENSEC_FEATURE_SIGN);
		} else {
			/*
			 * windows servers are broken with sign only,
			 * so we let the NTLMSSP backend to seal here,
			 * via GENSEC_FEATURE_LDAP_STYLE.
			 */
			gensec_want_feature(auth_generic_state->gensec_security, GENSEC_FEATURE_SIGN);
			gensec_want_feature(auth_generic_state->gensec_security, GENSEC_FEATURE_LDAP_STYLE);
		}
		break;
	case ADS_SASLWRAP_TYPE_PLAIN:
		break;
	}

	nt_status = auth_generic_client_start_by_sasl(auth_generic_state,
						      sasl_list);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return ADS_ERROR_NT(nt_status);
	}

	rc = LDAP_SASL_BIND_IN_PROGRESS;
	blob_in = data_blob_null;
	blob_out = data_blob_null;

	while (true) {
		struct berval cred, *scred = NULL;

		nt_status = gensec_update(auth_generic_state->gensec_security,
					  talloc_tos(), blob_in, &blob_out);
		data_blob_free(&blob_in);
		if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)
		    && !NT_STATUS_IS_OK(nt_status))
		{
			TALLOC_FREE(auth_generic_state);
			data_blob_free(&blob_out);
			return ADS_ERROR_NT(nt_status);
		}

		if (NT_STATUS_IS_OK(nt_status) && rc == 0 && blob_out.length == 0) {
			break;
		}

		cred.bv_val = (char *)blob_out.data;
		cred.bv_len = blob_out.length;
		scred = NULL;
		rc = ldap_sasl_bind_s(ads->ldap.ld, NULL, sasl, &cred, NULL, NULL, &scred);
		data_blob_free(&blob_out);
		if ((rc != LDAP_SASL_BIND_IN_PROGRESS) && (rc != 0)) {
			if (scred) {
				ber_bvfree(scred);
			}

			TALLOC_FREE(auth_generic_state);
			return ADS_ERROR(rc);
		}
		if (scred) {
			blob_in = data_blob_talloc(talloc_tos(),
						   scred->bv_val,
						   scred->bv_len);
			if (blob_in.length != scred->bv_len) {
				ber_bvfree(scred);
				TALLOC_FREE(auth_generic_state);
				return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
			}
			ber_bvfree(scred);
		} else {
			blob_in = data_blob_null;
		}
		if (NT_STATUS_IS_OK(nt_status) && rc == 0 && blob_in.length == 0) {
			break;
		}
	}

	data_blob_free(&blob_in);
	data_blob_free(&blob_out);

	if (wrap->wrap_type >= ADS_SASLWRAP_TYPE_SEAL) {
		bool ok;

		ok = gensec_have_feature(auth_generic_state->gensec_security,
					 GENSEC_FEATURE_SEAL);
		if (!ok) {
			DEBUG(0,("The gensec feature sealing request, but unavailable\n"));
			TALLOC_FREE(auth_generic_state);
			return ADS_ERROR_NT(NT_STATUS_INVALID_NETWORK_RESPONSE);
		}

		ok = gensec_have_feature(auth_generic_state->gensec_security,
					 GENSEC_FEATURE_SIGN);
		if (!ok) {
			DEBUG(0,("The gensec feature signing request, but unavailable\n"));
			TALLOC_FREE(auth_generic_state);
			return ADS_ERROR_NT(NT_STATUS_INVALID_NETWORK_RESPONSE);
		}

	} else if (wrap->wrap_type >= ADS_SASLWRAP_TYPE_SIGN) {
		bool ok;

		ok = gensec_have_feature(auth_generic_state->gensec_security,
					 GENSEC_FEATURE_SIGN);
		if (!ok) {
			DEBUG(0,("The gensec feature signing request, but unavailable\n"));
			TALLOC_FREE(auth_generic_state);
			return ADS_ERROR_NT(NT_STATUS_INVALID_NETWORK_RESPONSE);
		}
	}

	ads->auth.tgs_expire = LONG_MAX;
	end_nt_time = gensec_expire_time(auth_generic_state->gensec_security);
	if (end_nt_time != GENSEC_EXPIRE_TIME_INFINITY) {
		struct timeval tv;
		nttime_to_timeval(&tv, end_nt_time);
		ads->auth.tgs_expire = tv.tv_sec;
	}

	if (wrap->wrap_type > ADS_SASLWRAP_TYPE_PLAIN) {
		size_t max_wrapped =
			gensec_max_wrapped_size(auth_generic_state->gensec_security);
		wrap->out.max_unwrapped =
			gensec_max_input_size(auth_generic_state->gensec_security);

		wrap->out.sig_size = max_wrapped - wrap->out.max_unwrapped;
		/*
		 * Note that we have to truncate this to 0x2C
		 * (taken from a capture with LDAP unbind), as the
		 * signature size is not constant for Kerberos with
		 * arcfour-hmac-md5.
		 */
		wrap->in.min_wrapped = MIN(wrap->out.sig_size, 0x2C);
		wrap->in.max_wrapped = ADS_SASL_WRAPPING_IN_MAX_WRAPPED;
		status = ads_setup_sasl_wrapping(wrap, ads->ldap.ld,
						 &ads_sasl_gensec_ops,
						 auth_generic_state->gensec_security);
		if (!ADS_ERR_OK(status)) {
			DEBUG(0, ("ads_setup_sasl_wrapping() failed: %s\n",
				ads_errstr(status)));
			TALLOC_FREE(auth_generic_state);
			return status;
		}
		/* Only keep the gensec_security element around long-term */
		talloc_steal(NULL, auth_generic_state->gensec_security);
	}
	TALLOC_FREE(auth_generic_state);

	return ADS_ERROR(rc);
}

#ifdef HAVE_KRB5
struct ads_service_principal {
	char *service;
	char *hostname;
	char *string;
};

static void ads_free_service_principal(struct ads_service_principal *p)
{
	SAFE_FREE(p->service);
	SAFE_FREE(p->hostname);
	SAFE_FREE(p->string);
	ZERO_STRUCTP(p);
}

static ADS_STATUS ads_guess_target(ADS_STRUCT *ads,
				   char **service,
				   char **hostname,
				   char **principal)
{
	ADS_STATUS status = ADS_ERROR(LDAP_NO_MEMORY);
	char *princ = NULL;
	TALLOC_CTX *frame;
	char *server = NULL;
	char *realm = NULL;
	int rc;

	frame = talloc_stackframe();
	if (frame == NULL) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	if (ads->server.realm && ads->server.ldap_server) {
		server = strlower_talloc(frame, ads->server.ldap_server);
		if (server == NULL) {
			goto out;
		}

		realm = strupper_talloc(frame, ads->server.realm);
		if (realm == NULL) {
			goto out;
		}

		/*
		 * If we got a name which is bigger than a NetBIOS name,
		 * but isn't a FQDN, create one.
		 */
		if (strlen(server) > 15 && strstr(server, ".") == NULL) {
			char *dnsdomain;

			dnsdomain = strlower_talloc(frame, ads->server.realm);
			if (dnsdomain == NULL) {
				goto out;
			}

			server = talloc_asprintf(frame,
						 "%s.%s",
						 server, dnsdomain);
			if (server == NULL) {
				goto out;
			}
		}
	} else if (ads->config.realm && ads->config.ldap_server_name) {
		server = strlower_talloc(frame, ads->config.ldap_server_name);
		if (server == NULL) {
			goto out;
		}

		realm = strupper_talloc(frame, ads->config.realm);
		if (realm == NULL) {
			goto out;
		}

		/*
		 * If we got a name which is bigger than a NetBIOS name,
		 * but isn't a FQDN, create one.
		 */
		if (strlen(server) > 15 && strstr(server, ".") == NULL) {
			char *dnsdomain;

			dnsdomain = strlower_talloc(frame, ads->server.realm);
			if (dnsdomain == NULL) {
				goto out;
			}

			server = talloc_asprintf(frame,
						 "%s.%s",
						 server, dnsdomain);
			if (server == NULL) {
				goto out;
			}
		}
	}

	if (server == NULL || realm == NULL) {
		goto out;
	}

	*service = SMB_STRDUP("ldap");
	if (*service == NULL) {
		status = ADS_ERROR(LDAP_PARAM_ERROR);
		goto out;
	}
	*hostname = SMB_STRDUP(server);
	if (*hostname == NULL) {
		SAFE_FREE(*service);
		status = ADS_ERROR(LDAP_PARAM_ERROR);
		goto out;
	}
	rc = asprintf(&princ, "ldap/%s@%s", server, realm);
	if (rc == -1 || princ == NULL) {
		SAFE_FREE(*service);
		SAFE_FREE(*hostname);
		status = ADS_ERROR(LDAP_PARAM_ERROR);
		goto out;
	}

	*principal = princ;

	status = ADS_SUCCESS;
out:
	TALLOC_FREE(frame);
	return status;
}

static ADS_STATUS ads_generate_service_principal(ADS_STRUCT *ads,
						 struct ads_service_principal *p)
{
	ADS_STATUS status;

	ZERO_STRUCTP(p);

	status = ads_guess_target(ads,
				  &p->service,
				  &p->hostname,
				  &p->string);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	return ADS_SUCCESS;
}

#endif /* HAVE_KRB5 */

/*
   this performs a SASL/SPNEGO bind
*/
static ADS_STATUS ads_sasl_spnego_bind(ADS_STRUCT *ads,
				       struct cli_credentials *creds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct ads_service_principal p = {0};
	ADS_STATUS status;
	const char *debug_username = NULL;

	status = ads_generate_service_principal(ads, &p);
	if (!ADS_ERR_OK(status)) {
		goto done;
	}

	debug_username = cli_credentials_get_unparsed_name(creds, frame);
	if (debug_username == NULL) {
		status = ADS_ERROR_SYSTEM(errno);
		goto done;
	}

	status = ads_sasl_spnego_gensec_bind(ads,
					     creds,
					     p.service,
					     p.hostname);
	if (!ADS_ERR_OK(status)) {
		DBG_WARNING("ads_sasl_spnego_gensec_bind() failed "
			    "for %s/%s with user[%s]: %s\n",
			    p.service, p.hostname,
			    debug_username,
			    ads_errstr(status));
		goto done;
	}

done:
	ads_free_service_principal(&p);
	TALLOC_FREE(frame);
	return status;
}

ADS_STATUS ads_sasl_bind(ADS_STRUCT *ads, struct cli_credentials *creds)
{
	ADS_STATUS status;
	struct ads_saslwrap *wrap = &ads->ldap_wrap_data;
	bool tls = false;

	if (ads->auth.flags & ADS_AUTH_SASL_LDAPS) {
		tls = true;
		wrap->wrap_type = ADS_SASLWRAP_TYPE_PLAIN;
	} else if (ads->auth.flags & ADS_AUTH_SASL_STARTTLS) {
		tls = true;
		wrap->wrap_type = ADS_SASLWRAP_TYPE_PLAIN;
	} else if (ads->auth.flags & ADS_AUTH_SASL_SEAL) {
		wrap->wrap_type = ADS_SASLWRAP_TYPE_SEAL;
	} else if (ads->auth.flags & ADS_AUTH_SASL_SIGN) {
		wrap->wrap_type = ADS_SASLWRAP_TYPE_SIGN;
	} else {
		wrap->wrap_type = ADS_SASLWRAP_TYPE_PLAIN;
	}

	if (tls) {
		const DATA_BLOB *tls_cb = NULL;

		tls_cb = ads_tls_channel_bindings(&ads->ldap_tls_data);
		if (tls_cb == NULL) {
			DBG_ERR("No TLS channel bindings available\n");
			return ADS_ERROR_NT(NT_STATUS_INTERNAL_ERROR);
		}
	}

retry:
	status = ads_sasl_spnego_bind(ads, creds);
	if (status.error_type == ENUM_ADS_ERROR_LDAP &&
	    status.err.rc == LDAP_STRONG_AUTH_REQUIRED &&
	    !tls &&
	    wrap->wrap_type == ADS_SASLWRAP_TYPE_PLAIN)
	{
		DEBUG(3,("SASL bin got LDAP_STRONG_AUTH_REQUIRED "
			 "retrying with signing enabled\n"));
		wrap->wrap_type = ADS_SASLWRAP_TYPE_SIGN;
		goto retry;
	}
	return status;
}

#endif /* HAVE_LDAP */

