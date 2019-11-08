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
#include "../libcli/auth/spnego.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "auth_generic.h"
#include "ads.h"
#include "smb_krb5.h"
#include "system/gssapi.h"
#include "lib/param/loadparm.h"
#include "krb5_env.h"

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

/* 
   perform a LDAP/SASL/SPNEGO/{NTLMSSP,KRB5} bind (just how many layers can
   we fit on one socket??)
*/
static ADS_STATUS ads_sasl_spnego_gensec_bind(ADS_STRUCT *ads,
				const char *sasl,
				enum credentials_use_kerberos krb5_state,
				const char *target_service,
				const char *target_hostname,
				const DATA_BLOB server_blob)
{
	DATA_BLOB blob_in = data_blob_null;
	DATA_BLOB blob_out = data_blob_null;
	int rc;
	NTSTATUS nt_status;
	ADS_STATUS status;
	struct auth_generic_state *auth_generic_state;
	bool use_spnego_principal = lp_client_use_spnego_principal();
	const char *sasl_list[] = { sasl, NULL };
	NTTIME end_nt_time;
	struct ads_saslwrap *wrap = &ads->ldap_wrap_data;

	nt_status = auth_generic_client_prepare(NULL, &auth_generic_state);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return ADS_ERROR_NT(nt_status);
	}

	if (!NT_STATUS_IS_OK(nt_status = auth_generic_set_username(auth_generic_state, ads->auth.user_name))) {
		return ADS_ERROR_NT(nt_status);
	}
	if (!NT_STATUS_IS_OK(nt_status = auth_generic_set_domain(auth_generic_state, ads->auth.realm))) {
		return ADS_ERROR_NT(nt_status);
	}
	if (!NT_STATUS_IS_OK(nt_status = auth_generic_set_password(auth_generic_state, ads->auth.password))) {
		return ADS_ERROR_NT(nt_status);
	}

	if (server_blob.length == 0) {
		use_spnego_principal = false;
	}

	if (krb5_state == CRED_DONT_USE_KERBEROS) {
		use_spnego_principal = false;
	}

	cli_credentials_set_kerberos_state(auth_generic_state->credentials,
					   krb5_state);

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

	if (target_service != NULL && target_hostname != NULL) {
		use_spnego_principal = false;
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
	if (use_spnego_principal) {
		blob_in = data_blob_dup_talloc(talloc_tos(), server_blob);
		if (blob_in.length == 0) {
			TALLOC_FREE(auth_generic_state);
			return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
		}
	} else {
		blob_in = data_blob_null;
	}
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
static ADS_STATUS ads_sasl_spnego_bind(ADS_STRUCT *ads)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct ads_service_principal p = {0};
	struct berval *scred=NULL;
	int rc, i;
	ADS_STATUS status;
	DATA_BLOB blob = data_blob_null;
	char *given_principal = NULL;
	char *OIDs[ASN1_MAX_OIDS];
#ifdef HAVE_KRB5
	bool got_kerberos_mechanism = False;
#endif
	const char *mech = NULL;

	rc = ldap_sasl_bind_s(ads->ldap.ld, NULL, "GSS-SPNEGO", NULL, NULL, NULL, &scred);

	if (rc != LDAP_SASL_BIND_IN_PROGRESS) {
		status = ADS_ERROR(rc);
		goto done;
	}

	blob = data_blob(scred->bv_val, scred->bv_len);

	ber_bvfree(scred);

#if 0
	file_save("sasl_spnego.dat", blob.data, blob.length);
#endif

	/* the server sent us the first part of the SPNEGO exchange in the negprot 
	   reply */
	if (!spnego_parse_negTokenInit(talloc_tos(), blob, OIDs, &given_principal, NULL) ||
			OIDs[0] == NULL) {
		status = ADS_ERROR(LDAP_OPERATIONS_ERROR);
		goto done;
	}
	TALLOC_FREE(given_principal);

	/* make sure the server understands kerberos */
	for (i=0;OIDs[i];i++) {
		DEBUG(3,("ads_sasl_spnego_bind: got OID=%s\n", OIDs[i]));
#ifdef HAVE_KRB5
		if (strcmp(OIDs[i], OID_KERBEROS5_OLD) == 0 ||
		    strcmp(OIDs[i], OID_KERBEROS5) == 0) {
			got_kerberos_mechanism = True;
		}
#endif
		talloc_free(OIDs[i]);
	}

	status = ads_generate_service_principal(ads, &p);
	if (!ADS_ERR_OK(status)) {
		goto done;
	}

#ifdef HAVE_KRB5
	if (!(ads->auth.flags & ADS_AUTH_DISABLE_KERBEROS) &&
	    got_kerberos_mechanism) 
	{
		mech = "KRB5";

		if (ads->auth.password == NULL ||
		    ads->auth.password[0] == '\0')
		{

			status = ads_sasl_spnego_gensec_bind(ads, "GSS-SPNEGO",
							     CRED_MUST_USE_KERBEROS,
							     p.service, p.hostname,
							     blob);
			if (ADS_ERR_OK(status)) {
				ads_free_service_principal(&p);
				goto done;
			}

			DEBUG(10,("ads_sasl_spnego_gensec_bind(KRB5) failed with: %s, "
				  "calling kinit\n", ads_errstr(status)));
		}

		status = ADS_ERROR_KRB5(ads_kinit_password(ads)); 

		if (ADS_ERR_OK(status)) {
			status = ads_sasl_spnego_gensec_bind(ads, "GSS-SPNEGO",
							CRED_MUST_USE_KERBEROS,
							p.service, p.hostname,
							blob);
			if (!ADS_ERR_OK(status)) {
				DEBUG(0,("kinit succeeded but "
					"ads_sasl_spnego_gensec_bind(KRB5) failed "
					"for %s/%s with user[%s] realm[%s]: %s\n",
					p.service, p.hostname,
					ads->auth.user_name,
					ads->auth.realm,
					ads_errstr(status)));
			}
		}

		/* only fallback to NTLMSSP if allowed */
		if (ADS_ERR_OK(status) || 
		    !(ads->auth.flags & ADS_AUTH_ALLOW_NTLMSSP)) {
			goto done;
		}

		DEBUG(1,("ads_sasl_spnego_gensec_bind(KRB5) failed "
			 "for %s/%s with user[%s] realm[%s]: %s, "
			 "fallback to NTLMSSP\n",
			 p.service, p.hostname,
			 ads->auth.user_name,
			 ads->auth.realm,
			 ads_errstr(status)));
	}
#endif

	/* lets do NTLMSSP ... this has the big advantage that we don't need
	   to sync clocks, and we don't rely on special versions of the krb5 
	   library for HMAC_MD4 encryption */
	mech = "NTLMSSP";
	status = ads_sasl_spnego_gensec_bind(ads, "GSS-SPNEGO",
					     CRED_DONT_USE_KERBEROS,
					     p.service, p.hostname,
					     data_blob_null);
done:
	if (!ADS_ERR_OK(status)) {
		DEBUG(1,("ads_sasl_spnego_gensec_bind(%s) failed "
			 "for %s/%s with user[%s] realm=[%s]: %s\n", mech,
			  p.service, p.hostname,
			  ads->auth.user_name,
			  ads->auth.realm,
			  ads_errstr(status)));
	}
	ads_free_service_principal(&p);
	TALLOC_FREE(frame);
	if (blob.data != NULL) {
		data_blob_free(&blob);
	}
	return status;
}

/* mapping between SASL mechanisms and functions */
static struct {
	const char *name;
	ADS_STATUS (*fn)(ADS_STRUCT *);
} sasl_mechanisms[] = {
	{"GSS-SPNEGO", ads_sasl_spnego_bind},
	{NULL, NULL}
};

ADS_STATUS ads_sasl_bind(ADS_STRUCT *ads)
{
	const char *attrs[] = {"supportedSASLMechanisms", NULL};
	char **values;
	ADS_STATUS status;
	int i, j;
	LDAPMessage *res;
	struct ads_saslwrap *wrap = &ads->ldap_wrap_data;

	/* get a list of supported SASL mechanisms */
	status = ads_do_search(ads, "", LDAP_SCOPE_BASE, "(objectclass=*)", attrs, &res);
	if (!ADS_ERR_OK(status)) return status;

	values = ldap_get_values(ads->ldap.ld, res, "supportedSASLMechanisms");

	if (ads->auth.flags & ADS_AUTH_SASL_SEAL) {
		wrap->wrap_type = ADS_SASLWRAP_TYPE_SEAL;
	} else if (ads->auth.flags & ADS_AUTH_SASL_SIGN) {
		wrap->wrap_type = ADS_SASLWRAP_TYPE_SIGN;
	} else {
		wrap->wrap_type = ADS_SASLWRAP_TYPE_PLAIN;
	}

	/* try our supported mechanisms in order */
	for (i=0;sasl_mechanisms[i].name;i++) {
		/* see if the server supports it */
		for (j=0;values && values[j];j++) {
			if (strcmp(values[j], sasl_mechanisms[i].name) == 0) {
				DEBUG(4,("Found SASL mechanism %s\n", values[j]));
retry:
				status = sasl_mechanisms[i].fn(ads);
				if (status.error_type == ENUM_ADS_ERROR_LDAP &&
				    status.err.rc == LDAP_STRONG_AUTH_REQUIRED &&
				    wrap->wrap_type == ADS_SASLWRAP_TYPE_PLAIN)
				{
					DEBUG(3,("SASL bin got LDAP_STRONG_AUTH_REQUIRED "
						 "retrying with signing enabled\n"));
					wrap->wrap_type = ADS_SASLWRAP_TYPE_SIGN;
					goto retry;
				}
				ldap_value_free(values);
				ldap_msgfree(res);
				return status;
			}
		}
	}

	ldap_value_free(values);
	ldap_msgfree(res);
	return ADS_ERROR(LDAP_AUTH_METHOD_NOT_SUPPORTED);
}

#endif /* HAVE_LDAP */

