/* 
   Unix SMB/CIFS implementation.

   Kerberos backend for GENSEC
   
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2004-2005

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
#include "lib/util/tevent_ntstatus.h"
#include "lib/events/events.h"
#include "system/kerberos.h"
#include "system/gssapi.h"
#include "auth/kerberos/kerberos.h"
#include "librpc/gen_ndr/krb5pac.h"
#include "auth/auth.h"
#include <ldb.h>
#include "auth/auth_sam.h"
#include "librpc/gen_ndr/dcerpc.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_krb5.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "auth/gensec/gensec_proto.h"
#include "auth/gensec/gensec_toplevel_proto.h"
#include "param/param.h"
#include "auth/session_proto.h"
#include "gensec_gssapi.h"
#include "lib/util/util_net.h"
#include "auth/kerberos/pac_utils.h"
#include "auth/kerberos/gssapi_helper.h"

#ifndef gss_mech_spnego
gss_OID_desc spnego_mech_oid_desc =
		{ 6, discard_const_p(void, "\x2b\x06\x01\x05\x05\x02") };
#define gss_mech_spnego (&spnego_mech_oid_desc)
#endif

_PUBLIC_ NTSTATUS gensec_gssapi_init(TALLOC_CTX *);

static size_t gensec_gssapi_max_input_size(struct gensec_security *gensec_security);
static size_t gensec_gssapi_max_wrapped_size(struct gensec_security *gensec_security);
static size_t gensec_gssapi_sig_size(struct gensec_security *gensec_security, size_t data_size);

static int gensec_gssapi_destructor(struct gensec_gssapi_state *gensec_gssapi_state)
{
	OM_uint32 min_stat;

	if (gensec_gssapi_state->delegated_cred_handle != GSS_C_NO_CREDENTIAL) {
		gss_release_cred(&min_stat,
				 &gensec_gssapi_state->delegated_cred_handle);
	}

	if (gensec_gssapi_state->gssapi_context != GSS_C_NO_CONTEXT) {
		gss_delete_sec_context(&min_stat,
				       &gensec_gssapi_state->gssapi_context,
				       GSS_C_NO_BUFFER);
	}

	if (gensec_gssapi_state->server_name != GSS_C_NO_NAME) {
		gss_release_name(&min_stat,
				 &gensec_gssapi_state->server_name);
	}
	if (gensec_gssapi_state->client_name != GSS_C_NO_NAME) {
		gss_release_name(&min_stat,
				 &gensec_gssapi_state->client_name);
	}

	return 0;
}

static NTSTATUS gensec_gssapi_setup_server_principal(TALLOC_CTX *mem_ctx,
						     const char *target_principal,
						     const char *service,
						     const char *hostname,
						     const char *realm,
						     const gss_OID mech,
						     char **pserver_principal,
						     gss_name_t *pserver_name)
{
	char *server_principal = NULL;
	gss_buffer_desc name_token;
	gss_OID name_type;
	OM_uint32 maj_stat, min_stat = 0;

	if (target_principal != NULL) {
		server_principal = talloc_strdup(mem_ctx, target_principal);
		name_type = GSS_C_NULL_OID;
	} else {
		server_principal = talloc_asprintf(mem_ctx,
						   "%s/%s@%s",
						   service, hostname, realm);
		name_type = GSS_C_NT_USER_NAME;
	}
	if (server_principal == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	name_token.value = (uint8_t *)server_principal;
	name_token.length = strlen(server_principal);

	maj_stat = gss_import_name(&min_stat,
				   &name_token,
				   name_type,
				   pserver_name);
	if (maj_stat) {
		DBG_WARNING("GSS Import name of %s failed: %s\n",
			    server_principal,
			    gssapi_error_string(mem_ctx,
						maj_stat,
						min_stat,
						mech));
		TALLOC_FREE(server_principal);
		return NT_STATUS_INVALID_PARAMETER;
	}

	*pserver_principal = server_principal;

	return NT_STATUS_OK;
}

static NTSTATUS gensec_gssapi_start(struct gensec_security *gensec_security)
{
	struct gensec_gssapi_state *gensec_gssapi_state;
	krb5_error_code ret;
#ifdef SAMBA4_USES_HEIMDAL
	const char *realm;
#endif

	gensec_gssapi_state = talloc_zero(gensec_security, struct gensec_gssapi_state);
	if (!gensec_gssapi_state) {
		return NT_STATUS_NO_MEMORY;
	}

	gensec_security->private_data = gensec_gssapi_state;

	gensec_gssapi_state->gssapi_context = GSS_C_NO_CONTEXT;

	/* TODO: Fill in channel bindings */
	gensec_gssapi_state->input_chan_bindings = GSS_C_NO_CHANNEL_BINDINGS;

	gensec_gssapi_state->server_name = GSS_C_NO_NAME;
	gensec_gssapi_state->client_name = GSS_C_NO_NAME;
	
	gensec_gssapi_state->gss_want_flags = 0;
	gensec_gssapi_state->expire_time = GENSEC_EXPIRE_TIME_INFINITY;

	if (gensec_setting_bool(gensec_security->settings, "gensec_gssapi", "delegation_by_kdc_policy", true)) {
		gensec_gssapi_state->gss_want_flags |= GSS_C_DELEG_POLICY_FLAG;
	}
	if (gensec_setting_bool(gensec_security->settings, "gensec_gssapi", "mutual", true)) {
		gensec_gssapi_state->gss_want_flags |= GSS_C_MUTUAL_FLAG;
	}
	if (gensec_setting_bool(gensec_security->settings, "gensec_gssapi", "delegation", false)) {
		gensec_gssapi_state->gss_want_flags |= GSS_C_DELEG_FLAG;
	}
	if (gensec_setting_bool(gensec_security->settings, "gensec_gssapi", "replay", true)) {
		gensec_gssapi_state->gss_want_flags |= GSS_C_REPLAY_FLAG;
	}
	if (gensec_setting_bool(gensec_security->settings, "gensec_gssapi", "sequence", true)) {
		gensec_gssapi_state->gss_want_flags |= GSS_C_SEQUENCE_FLAG;
	}

	if (gensec_security->want_features & GENSEC_FEATURE_SESSION_KEY) {
		gensec_gssapi_state->gss_want_flags |= GSS_C_INTEG_FLAG;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SIGN) {
		gensec_gssapi_state->gss_want_flags |= GSS_C_INTEG_FLAG;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SEAL) {
		gensec_gssapi_state->gss_want_flags |= GSS_C_INTEG_FLAG;
		gensec_gssapi_state->gss_want_flags |= GSS_C_CONF_FLAG;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_DCE_STYLE) {
		gensec_gssapi_state->gss_want_flags |= GSS_C_DCE_STYLE;
	}

	gensec_gssapi_state->gss_got_flags = 0;

	switch (gensec_security->ops->auth_type) {
	case DCERPC_AUTH_TYPE_SPNEGO:
		gensec_gssapi_state->gss_oid = gss_mech_spnego;
		break;
	case DCERPC_AUTH_TYPE_KRB5:
	default:
		gensec_gssapi_state->gss_oid =
			discard_const_p(void, gss_mech_krb5);
		break;
	}

	ret = smb_krb5_init_context(gensec_gssapi_state,
				    gensec_security->settings->lp_ctx,
				    &gensec_gssapi_state->smb_krb5_context);
	if (ret) {
		DEBUG(1,("gensec_gssapi_start: smb_krb5_init_context failed (%s)\n",
			 error_message(ret)));
		talloc_free(gensec_gssapi_state);
		return NT_STATUS_INTERNAL_ERROR;
	}

	gensec_gssapi_state->client_cred = NULL;
	gensec_gssapi_state->server_cred = NULL;

	gensec_gssapi_state->delegated_cred_handle = GSS_C_NO_CREDENTIAL;

	gensec_gssapi_state->sasl = false;
	gensec_gssapi_state->sasl_state = STAGE_GSS_NEG;
	gensec_gssapi_state->sasl_protection = 0;

	gensec_gssapi_state->max_wrap_buf_size
		= gensec_setting_int(gensec_security->settings, "gensec_gssapi", "max wrap buf size", 65536);
	gensec_gssapi_state->gss_exchange_count = 0;
	gensec_gssapi_state->sig_size = 0;

	talloc_set_destructor(gensec_gssapi_state, gensec_gssapi_destructor);

#ifdef SAMBA4_USES_HEIMDAL
	realm = lpcfg_realm(gensec_security->settings->lp_ctx);
	if (realm != NULL) {
		ret = gsskrb5_set_default_realm(realm);
		if (ret) {
			DEBUG(1,("gensec_gssapi_start: gsskrb5_set_default_realm failed\n"));
			talloc_free(gensec_gssapi_state);
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	/* don't do DNS lookups of any kind, it might/will fail for a netbios name */
	ret = gsskrb5_set_dns_canonicalize(false);
	if (ret) {
		DEBUG(1,("gensec_gssapi_start: gsskrb5_set_dns_canonicalize failed\n"));
		talloc_free(gensec_gssapi_state);
		return NT_STATUS_INTERNAL_ERROR;
	}
#endif
	return NT_STATUS_OK;
}

static NTSTATUS gensec_gssapi_server_start(struct gensec_security *gensec_security)
{
	NTSTATUS nt_status;
	int ret;
	struct gensec_gssapi_state *gensec_gssapi_state;
	struct cli_credentials *machine_account;
	struct gssapi_creds_container *gcc;

	nt_status = gensec_gssapi_start(gensec_security);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	gensec_gssapi_state = talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);

	machine_account = gensec_get_credentials(gensec_security);
	
	if (!machine_account) {
		DEBUG(3, ("No machine account credentials specified\n"));
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	} else {
		ret = cli_credentials_get_server_gss_creds(machine_account, 
							   gensec_security->settings->lp_ctx, &gcc);
		if (ret) {
			DEBUG(1, ("Acquiring acceptor credentials failed: %s\n",
				  error_message(ret)));
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
	}

	gensec_gssapi_state->server_cred = gcc;
	return NT_STATUS_OK;

}

static NTSTATUS gensec_gssapi_sasl_server_start(struct gensec_security *gensec_security)
{
	NTSTATUS nt_status;
	struct gensec_gssapi_state *gensec_gssapi_state;
	nt_status = gensec_gssapi_server_start(gensec_security);

	if (NT_STATUS_IS_OK(nt_status)) {
		gensec_gssapi_state = talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);
		gensec_gssapi_state->sasl = true;
	}
	return nt_status;
}

static NTSTATUS gensec_gssapi_client_creds(struct gensec_security *gensec_security,
					   struct tevent_context *ev)
{
	struct gensec_gssapi_state *gensec_gssapi_state;
	struct gssapi_creds_container *gcc;
	struct cli_credentials *creds = gensec_get_credentials(gensec_security);
	const char *error_string;
	int ret;

	gensec_gssapi_state = talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);

	/* Only run this the first time the update() call is made */
	if (gensec_gssapi_state->client_cred) {
		return NT_STATUS_OK;
	}

	ret = cli_credentials_get_client_gss_creds(creds,
						   ev,
						   gensec_security->settings->lp_ctx, &gcc, &error_string);
	switch (ret) {
	case 0:
		break;
	case EINVAL:
		DEBUG(3, ("Cannot obtain client GSS credentials we need to contact %s : %s\n", gensec_gssapi_state->target_principal, error_string));
		return NT_STATUS_INVALID_PARAMETER;
	case KRB5KDC_ERR_PREAUTH_FAILED:
	case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
	case KRB5KRB_AP_ERR_BAD_INTEGRITY:
		DEBUG(1, ("Wrong username or password: %s\n", error_string));
		return NT_STATUS_LOGON_FAILURE;
	case KRB5KDC_ERR_CLIENT_REVOKED:
		DEBUG(1, ("Account locked out: %s\n", error_string));
		return NT_STATUS_ACCOUNT_LOCKED_OUT;
	case KRB5_REALM_UNKNOWN:
	case KRB5_KDC_UNREACH:
		DEBUG(3, ("Cannot reach a KDC we require to contact %s : %s\n", gensec_gssapi_state->target_principal, error_string));
		return NT_STATUS_NO_LOGON_SERVERS;
	case KRB5_CC_NOTFOUND:
	case KRB5_CC_END:
		DEBUG(2, ("Error obtaining ticket we require to contact %s: (possibly due to clock skew between us and the KDC) %s\n", gensec_gssapi_state->target_principal, error_string));
		return NT_STATUS_TIME_DIFFERENCE_AT_DC;
	default:
		DEBUG(1, ("Aquiring initiator credentials failed: %s\n", error_string));
		return NT_STATUS_UNSUCCESSFUL;
	}

	gensec_gssapi_state->client_cred = gcc;
	if (!talloc_reference(gensec_gssapi_state, gcc)) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

static NTSTATUS gensec_gssapi_client_start(struct gensec_security *gensec_security)
{
	struct gensec_gssapi_state *gensec_gssapi_state;
	struct cli_credentials *creds = gensec_get_credentials(gensec_security);
	NTSTATUS nt_status;
	const char *target_principal = NULL;
	const char *hostname = gensec_get_target_hostname(gensec_security);
	const char *service = gensec_get_target_service(gensec_security);
	const char *realm = cli_credentials_get_realm(creds);

	target_principal = gensec_get_target_principal(gensec_security);
	if (target_principal != NULL) {
		goto do_start;
	}

	if (!hostname) {
		DEBUG(3, ("No hostname for target computer passed in, cannot use kerberos for this connection\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (is_ipaddress(hostname)) {
		DEBUG(2, ("Cannot do GSSAPI to an IP address\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (strcmp(hostname, "localhost") == 0) {
		DEBUG(2, ("GSSAPI to 'localhost' does not make sense\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (realm == NULL) {
		char *cred_name = cli_credentials_get_unparsed_name(creds,
								gensec_security);
		DEBUG(3, ("cli_credentials(%s) without realm, "
			  "cannot use kerberos for this connection %s/%s\n",
			  cred_name, service, hostname));
		TALLOC_FREE(cred_name);
		return NT_STATUS_INVALID_PARAMETER;
	}

do_start:

	nt_status = gensec_gssapi_start(gensec_security);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	gensec_gssapi_state = talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);

	if (cli_credentials_get_impersonate_principal(creds)) {
		gensec_gssapi_state->gss_want_flags &= ~(GSS_C_DELEG_FLAG|GSS_C_DELEG_POLICY_FLAG);
	}

	return NT_STATUS_OK;
}

static NTSTATUS gensec_gssapi_sasl_client_start(struct gensec_security *gensec_security)
{
	NTSTATUS nt_status;
	struct gensec_gssapi_state *gensec_gssapi_state;
	nt_status = gensec_gssapi_client_start(gensec_security);

	if (NT_STATUS_IS_OK(nt_status)) {
		gensec_gssapi_state = talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);
		gensec_gssapi_state->sasl = true;
	}
	return nt_status;
}

static NTSTATUS gensec_gssapi_update_internal(struct gensec_security *gensec_security,
					      TALLOC_CTX *out_mem_ctx,
					      struct tevent_context *ev,
					      const DATA_BLOB in, DATA_BLOB *out)
{
	struct gensec_gssapi_state *gensec_gssapi_state
		= talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);
	NTSTATUS nt_status;
	OM_uint32 maj_stat, min_stat;
	OM_uint32 min_stat2;
	gss_buffer_desc input_token = { 0, NULL };
	gss_buffer_desc output_token = { 0, NULL };
	struct cli_credentials *cli_creds = gensec_get_credentials(gensec_security);
	const char *target_principal = gensec_get_target_principal(gensec_security);
	const char *hostname = gensec_get_target_hostname(gensec_security);
	const char *service = gensec_get_target_service(gensec_security);
	gss_OID gss_oid_p = NULL;
	OM_uint32 time_req = 0;
	OM_uint32 time_rec = 0;
	struct timeval tv;

	time_req = gensec_setting_int(gensec_security->settings,
				      "gensec_gssapi", "requested_life_time",
				      time_req);

	input_token.length = in.length;
	input_token.value = in.data;

	switch (gensec_gssapi_state->sasl_state) {
	case STAGE_GSS_NEG:
	{
		switch (gensec_security->gensec_role) {
		case GENSEC_CLIENT:
		{
			const char *client_realm = NULL;
#ifdef SAMBA4_USES_HEIMDAL
			struct gsskrb5_send_to_kdc send_to_kdc;
			krb5_error_code ret;
#else
			bool fallback = false;
#endif

			nt_status = gensec_gssapi_client_creds(gensec_security, ev);
			if (!NT_STATUS_IS_OK(nt_status)) {
				return nt_status;
			}

#ifdef SAMBA4_USES_HEIMDAL
			send_to_kdc.func = smb_krb5_send_and_recv_func;
			send_to_kdc.ptr = ev;

			min_stat = gsskrb5_set_send_to_kdc(&send_to_kdc);
			if (min_stat) {
				DEBUG(1,("gensec_gssapi_update: gsskrb5_set_send_to_kdc failed\n"));
				return NT_STATUS_INTERNAL_ERROR;
			}
#endif

			/*
			 * With credentials for
			 * administrator@FOREST1.EXAMPLE.COM this patch changes
			 * the target_principal for the ldap service of host
			 * dc2.forest2.example.com from
			 *
			 *   ldap/dc2.forest2.example.com@FOREST1.EXAMPLE.COM
			 *
			 * to
			 *
			 *   ldap/dc2.forest2.example.com@FOREST2.EXAMPLE.COM
			 *
			 * Typically
			 * ldap/dc2.forest2.example.com@FOREST1.EXAMPLE.COM
			 * should be used in order to allow the KDC of
			 * FOREST1.EXAMPLE.COM to generate a referral ticket
			 * for krbtgt/FOREST2.EXAMPLE.COM@FOREST1.EXAMPLE.COM.
			 *
			 * The problem is that KDCs only return such referral
			 * tickets if there's a forest trust between
			 * FOREST1.EXAMPLE.COM and FOREST2.EXAMPLE.COM. If
			 * there's only an external domain trust between
			 * FOREST1.EXAMPLE.COM and FOREST2.EXAMPLE.COM the KDC
			 * of FOREST1.EXAMPLE.COM will respond with
			 * S_PRINCIPAL_UNKNOWN when being asked for
			 * ldap/dc2.forest2.example.com@FOREST1.EXAMPLE.COM.
			 *
			 * In the case of an external trust the client can
			 * still ask explicitly for
			 * krbtgt/FOREST2.EXAMPLE.COM@FOREST1.EXAMPLE.COM and
			 * the KDC of FOREST1.EXAMPLE.COM will generate it.
			 *
			 * From there the client can use the
			 * krbtgt/FOREST2.EXAMPLE.COM@FOREST1.EXAMPLE.COM
			 * ticket and ask a KDC of FOREST2.EXAMPLE.COM for a
			 * service ticket for
			 * ldap/dc2.forest2.example.com@FOREST2.EXAMPLE.COM.
			 *
			 * With Heimdal we'll get the fallback on
			 * S_PRINCIPAL_UNKNOWN behavior when we pass
			 * ldap/dc2.forest2.example.com@FOREST2.EXAMPLE.COM as
			 * target principal. As _krb5_get_cred_kdc_any() first
			 * calls get_cred_kdc_referral() (which always starts
			 * with the client realm) and falls back to
			 * get_cred_kdc_capath() (which starts with the given
			 * realm).
			 *
			 * MIT krb5 only tries the given realm of the target
			 * principal, if we want to autodetect support for
			 * transitive forest trusts, would have to do the
			 * fallback ourself.
			 */
			client_realm = cli_credentials_get_realm(cli_creds);
#ifndef SAMBA4_USES_HEIMDAL
			if (gensec_gssapi_state->server_name == NULL) {
				nt_status = gensec_gssapi_setup_server_principal(gensec_gssapi_state,
										 target_principal,
										 service,
										 hostname,
										 client_realm,
										 gensec_gssapi_state->gss_oid,
										 &gensec_gssapi_state->target_principal,
										 &gensec_gssapi_state->server_name);
				if (!NT_STATUS_IS_OK(nt_status)) {
					return nt_status;
				}

				maj_stat = gss_init_sec_context(&min_stat,
								gensec_gssapi_state->client_cred->creds,
								&gensec_gssapi_state->gssapi_context,
								gensec_gssapi_state->server_name,
								gensec_gssapi_state->gss_oid,
								gensec_gssapi_state->gss_want_flags,
								time_req,
								gensec_gssapi_state->input_chan_bindings,
								&input_token,
								&gss_oid_p,
								&output_token,
								&gensec_gssapi_state->gss_got_flags, /* ret flags */
								&time_rec);
				if (maj_stat != GSS_S_FAILURE) {
					goto init_sec_context_done;
				}
				if (min_stat != (OM_uint32)KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN) {
					goto init_sec_context_done;
				}
				if (target_principal != NULL) {
					goto init_sec_context_done;
				}

				fallback = true;
				TALLOC_FREE(gensec_gssapi_state->target_principal);
				gss_release_name(&min_stat2, &gensec_gssapi_state->server_name);
			}
#endif /* !SAMBA4_USES_HEIMDAL */
			if (gensec_gssapi_state->server_name == NULL) {
				const char *server_realm = NULL;

				server_realm = smb_krb5_get_realm_from_hostname(gensec_gssapi_state,
										hostname,
										client_realm);
				if (server_realm == NULL) {
					return NT_STATUS_NO_MEMORY;
				}

#ifndef SAMBA4_USES_HEIMDAL
				if (fallback &&
				    strequal(client_realm, server_realm)) {
					goto init_sec_context_done;
				}
#endif /* !SAMBA4_USES_HEIMDAL */

				nt_status = gensec_gssapi_setup_server_principal(gensec_gssapi_state,
										 target_principal,
										 service,
										 hostname,
										 server_realm,
										 gensec_gssapi_state->gss_oid,
										 &gensec_gssapi_state->target_principal,
										 &gensec_gssapi_state->server_name);
				if (!NT_STATUS_IS_OK(nt_status)) {
					return nt_status;
				}
			}

			maj_stat = gss_init_sec_context(&min_stat, 
							gensec_gssapi_state->client_cred->creds,
							&gensec_gssapi_state->gssapi_context, 
							gensec_gssapi_state->server_name, 
							gensec_gssapi_state->gss_oid,
							gensec_gssapi_state->gss_want_flags, 
							time_req,
							gensec_gssapi_state->input_chan_bindings,
							&input_token, 
							&gss_oid_p,
							&output_token, 
							&gensec_gssapi_state->gss_got_flags, /* ret flags */
							&time_rec);
			goto init_sec_context_done;
			/* JUMP! */
init_sec_context_done:
			if (gss_oid_p) {
				gensec_gssapi_state->gss_oid = gss_oid_p;
			}

#ifdef SAMBA4_USES_HEIMDAL
			send_to_kdc.func = smb_krb5_send_and_recv_func;
			send_to_kdc.ptr = NULL;

			ret = gsskrb5_set_send_to_kdc(&send_to_kdc);
			if (ret) {
				DEBUG(1,("gensec_gssapi_update: gsskrb5_set_send_to_kdc failed\n"));
				return NT_STATUS_INTERNAL_ERROR;
			}
#endif
			break;
		}
		case GENSEC_SERVER:
		{
			maj_stat = gss_accept_sec_context(&min_stat, 
							  &gensec_gssapi_state->gssapi_context, 
							  gensec_gssapi_state->server_cred->creds,
							  &input_token, 
							  gensec_gssapi_state->input_chan_bindings,
							  &gensec_gssapi_state->client_name, 
							  &gss_oid_p,
							  &output_token, 
							  &gensec_gssapi_state->gss_got_flags, 
							  &time_rec,
							  &gensec_gssapi_state->delegated_cred_handle);
			if (gss_oid_p) {
				gensec_gssapi_state->gss_oid = gss_oid_p;
			}
			break;
		}
		default:
			return NT_STATUS_INVALID_PARAMETER;
			
		}

		gensec_gssapi_state->gss_exchange_count++;

		if (maj_stat == GSS_S_COMPLETE) {
			*out = data_blob_talloc(out_mem_ctx, output_token.value, output_token.length);
			gss_release_buffer(&min_stat2, &output_token);
			
			if (gensec_gssapi_state->gss_got_flags & GSS_C_DELEG_FLAG &&
			    gensec_gssapi_state->delegated_cred_handle != GSS_C_NO_CREDENTIAL) {
				DEBUG(5, ("gensec_gssapi: credentials were delegated\n"));
			} else {
				DEBUG(5, ("gensec_gssapi: NO credentials were delegated\n"));
			}

			tv = timeval_current_ofs(time_rec, 0);
			gensec_gssapi_state->expire_time = timeval_to_nttime(&tv);

			/* We may have been invoked as SASL, so there
			 * is more work to do */
			if (gensec_gssapi_state->sasl) {
				gensec_gssapi_state->sasl_state = STAGE_SASL_SSF_NEG;
				return NT_STATUS_MORE_PROCESSING_REQUIRED;
			} else {
				gensec_gssapi_state->sasl_state = STAGE_DONE;

				if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)) {
					DEBUG(5, ("GSSAPI Connection will be cryptographically sealed\n"));
				} else if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
					DEBUG(5, ("GSSAPI Connection will be cryptographically signed\n"));
				} else {
					DEBUG(5, ("GSSAPI Connection will have no cryptographic protection\n"));
				}

				return NT_STATUS_OK;
			}
		} else if (maj_stat == GSS_S_CONTINUE_NEEDED) {
			*out = data_blob_talloc(out_mem_ctx, output_token.value, output_token.length);
			gss_release_buffer(&min_stat2, &output_token);
			
			return NT_STATUS_MORE_PROCESSING_REQUIRED;
		} else if (maj_stat == GSS_S_CONTEXT_EXPIRED) {
			gss_cred_id_t creds = NULL;
			gss_name_t name;
			gss_buffer_desc buffer;
			OM_uint32 lifetime = 0;
			gss_cred_usage_t usage;
			const char *role = NULL;

			switch (gensec_security->gensec_role) {
			case GENSEC_CLIENT:
				creds = gensec_gssapi_state->client_cred->creds;
				role = "client";
				break;
			case GENSEC_SERVER:
				creds = gensec_gssapi_state->server_cred->creds;
				role = "server";
				break;
			}

			DBG_ERR("GSS %s Update(krb5)(%d) failed, credentials "
				"expired during GSSAPI handshake!\n",
				role,
				gensec_gssapi_state->gss_exchange_count);

			maj_stat = gss_inquire_cred(&min_stat, 
						    creds,
						    &name, &lifetime, &usage, NULL);

			if (maj_stat == GSS_S_COMPLETE) {
				const char *usage_string = NULL;
				switch (usage) {
				case GSS_C_BOTH:
					usage_string = "GSS_C_BOTH";
					break;
				case GSS_C_ACCEPT:
					usage_string = "GSS_C_ACCEPT";
					break;
				case GSS_C_INITIATE:
					usage_string = "GSS_C_INITIATE";
					break;
				}
				maj_stat = gss_display_name(&min_stat, name, &buffer, NULL);
				if (maj_stat) {
					buffer.value = NULL;
					buffer.length = 0;
				}
				if (lifetime > 0) {
					DEBUG(0, ("GSSAPI gss_inquire_cred indicates expiry of %*.*s in %u sec for %s\n", 
						  (int)buffer.length, (int)buffer.length, (char *)buffer.value, 
						  lifetime, usage_string));
				} else {
					DEBUG(0, ("GSSAPI gss_inquire_cred indicates %*.*s has already expired for %s\n", 
						  (int)buffer.length, (int)buffer.length, (char *)buffer.value, 
						  usage_string));
				}
				gss_release_buffer(&min_stat, &buffer);
				gss_release_name(&min_stat, &name);
			} else if (maj_stat != GSS_S_COMPLETE) {
				DEBUG(0, ("inquiry of credential lifefime via GSSAPI gss_inquire_cred failed: %s\n",
					  gssapi_error_string(out_mem_ctx, maj_stat, min_stat, gensec_gssapi_state->gss_oid)));
			}
			return NT_STATUS_INVALID_PARAMETER;
		} else if (smb_gss_oid_equal(gensec_gssapi_state->gss_oid,
					     gss_mech_krb5)) {
			switch (min_stat) {
			case KRB5KRB_AP_ERR_TKT_NYV:
				DEBUG(1, ("Error with ticket to contact %s: possible clock skew between us and the KDC or target server: %s\n",
					  gensec_gssapi_state->target_principal,
					  gssapi_error_string(out_mem_ctx, maj_stat, min_stat, gensec_gssapi_state->gss_oid)));
				return NT_STATUS_TIME_DIFFERENCE_AT_DC; /* Make SPNEGO ignore us, we can't go any further here */
			case KRB5KRB_AP_ERR_TKT_EXPIRED:
				DEBUG(1, ("Error with ticket to contact %s: ticket is expired, possible clock skew between us and the KDC or target server: %s\n",
					  gensec_gssapi_state->target_principal,
					  gssapi_error_string(out_mem_ctx, maj_stat, min_stat, gensec_gssapi_state->gss_oid)));
				return NT_STATUS_INVALID_PARAMETER; /* Make SPNEGO ignore us, we can't go any further here */
			case KRB5_KDC_UNREACH:
				DEBUG(3, ("Cannot reach a KDC we require in order to obtain a ticket to %s: %s\n",
					  gensec_gssapi_state->target_principal,
					  gssapi_error_string(out_mem_ctx, maj_stat, min_stat, gensec_gssapi_state->gss_oid)));
				return NT_STATUS_NO_LOGON_SERVERS; /* Make SPNEGO ignore us, we can't go any further here */
			case KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN:
				DEBUG(3, ("Server %s is not registered with our KDC: %s\n",
					  gensec_gssapi_state->target_principal,
					  gssapi_error_string(out_mem_ctx, maj_stat, min_stat, gensec_gssapi_state->gss_oid)));
				return NT_STATUS_INVALID_PARAMETER; /* Make SPNEGO ignore us, we can't go any further here */
			case KRB5KRB_AP_ERR_MSG_TYPE:
				/* garbage input, possibly from the auto-mech detection */
				return NT_STATUS_INVALID_PARAMETER;
			default:
				DEBUG(1, ("GSS %s Update(krb5)(%d) Update failed: %s\n",
					  gensec_security->gensec_role == GENSEC_CLIENT ? "client" : "server",
					  gensec_gssapi_state->gss_exchange_count,
					  gssapi_error_string(out_mem_ctx, maj_stat, min_stat, gensec_gssapi_state->gss_oid)));
				return NT_STATUS_LOGON_FAILURE;
			}
		} else {
			DEBUG(1, ("GSS %s Update(%d) failed: %s\n",
				  gensec_security->gensec_role == GENSEC_CLIENT ? "client" : "server",
				  gensec_gssapi_state->gss_exchange_count,
				  gssapi_error_string(out_mem_ctx, maj_stat, min_stat, gensec_gssapi_state->gss_oid)));
			return NT_STATUS_LOGON_FAILURE;
		}
		break;
	}

	/* These last two stages are only done if we were invoked as SASL */
	case STAGE_SASL_SSF_NEG:
	{
		switch (gensec_security->gensec_role) {
		case GENSEC_CLIENT:
		{
			uint8_t maxlength_proposed[4]; 
			uint8_t maxlength_accepted[4]; 
			uint8_t security_supported;
			int conf_state;
			gss_qop_t qop_state;
			input_token.length = in.length;
			input_token.value = in.data;

			/* As a client, we have just send a
			 * zero-length blob to the server (after the
			 * normal GSSAPI exchange), and it has replied
			 * with it's SASL negotiation */
			
			maj_stat = gss_unwrap(&min_stat, 
					      gensec_gssapi_state->gssapi_context, 
					      &input_token,
					      &output_token, 
					      &conf_state,
					      &qop_state);
			if (GSS_ERROR(maj_stat)) {
				DEBUG(1, ("gensec_gssapi_update: GSS UnWrap of SASL protection negotiation failed: %s\n", 
					  gssapi_error_string(out_mem_ctx, maj_stat, min_stat, gensec_gssapi_state->gss_oid)));
				return NT_STATUS_ACCESS_DENIED;
			}
			
			if (output_token.length < 4) {
				return NT_STATUS_INVALID_PARAMETER;
			}

			memcpy(maxlength_proposed, output_token.value, 4);
			gss_release_buffer(&min_stat, &output_token);

			/* first byte is the proposed security */
			security_supported = maxlength_proposed[0];
			maxlength_proposed[0] = '\0';
			
			/* Rest is the proposed max wrap length */
			gensec_gssapi_state->max_wrap_buf_size = MIN(RIVAL(maxlength_proposed, 0), 
								     gensec_gssapi_state->max_wrap_buf_size);
			gensec_gssapi_state->sasl_protection = 0;
			if (security_supported & NEG_SEAL) {
				if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)) {
					gensec_gssapi_state->sasl_protection |= NEG_SEAL;
				}
			}
			if (security_supported & NEG_SIGN) {
				if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
					gensec_gssapi_state->sasl_protection |= NEG_SIGN;
				}
			}
			if (security_supported & NEG_NONE) {
				gensec_gssapi_state->sasl_protection |= NEG_NONE;
			}
			if (gensec_gssapi_state->sasl_protection == 0) {
				DEBUG(1, ("Remote server does not support unprotected connections\n"));
				return NT_STATUS_ACCESS_DENIED;
			}

			/* Send back the negotiated max length */

			RSIVAL(maxlength_accepted, 0, gensec_gssapi_state->max_wrap_buf_size);

			maxlength_accepted[0] = gensec_gssapi_state->sasl_protection;
			
			input_token.value = maxlength_accepted;
			input_token.length = sizeof(maxlength_accepted);

			maj_stat = gss_wrap(&min_stat, 
					    gensec_gssapi_state->gssapi_context, 
					    false,
					    GSS_C_QOP_DEFAULT,
					    &input_token,
					    &conf_state,
					    &output_token);
			if (GSS_ERROR(maj_stat)) {
				DEBUG(1, ("GSS Update(SSF_NEG): GSS Wrap failed: %s\n", 
					  gssapi_error_string(out_mem_ctx, maj_stat, min_stat, gensec_gssapi_state->gss_oid)));
				return NT_STATUS_ACCESS_DENIED;
			}
			
			*out = data_blob_talloc(out_mem_ctx, output_token.value, output_token.length);
			gss_release_buffer(&min_stat, &output_token);

			/* quirk:  This changes the value that gensec_have_feature returns, to be that after SASL negotiation */
			gensec_gssapi_state->sasl_state = STAGE_DONE;

			if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)) {
				DEBUG(3, ("SASL/GSSAPI Connection to server will be cryptographically sealed\n"));
			} else if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
				DEBUG(3, ("SASL/GSSAPI Connection to server will be cryptographically signed\n"));
			} else {
				DEBUG(3, ("SASL/GSSAPI Connection to server will have no cryptographically protection\n"));
			}

			return NT_STATUS_OK;
		}
		case GENSEC_SERVER:
		{
			uint8_t maxlength_proposed[4]; 
			uint8_t security_supported = 0x0;
			int conf_state;

			/* As a server, we have just been sent a zero-length blob (note this, but it isn't fatal) */
			if (in.length != 0) {
				DEBUG(1, ("SASL/GSSAPI: client sent non-zero length starting SASL negotiation!\n"));
			}
			
			/* Give the client some idea what we will support */
			  
			RSIVAL(maxlength_proposed, 0, gensec_gssapi_state->max_wrap_buf_size);
			/* first byte is the proposed security */
			maxlength_proposed[0] = '\0';
			
			gensec_gssapi_state->sasl_protection = 0;
			if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)) {
				security_supported |= NEG_SEAL;
			} 
			if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
				security_supported |= NEG_SIGN;
			}
			if (security_supported == 0) {
				/* If we don't support anything, this must be 0 */
				RSIVAL(maxlength_proposed, 0, 0x0);
			}

			/* TODO:  We may not wish to support this */
			security_supported |= NEG_NONE;
			maxlength_proposed[0] = security_supported;
			
			input_token.value = maxlength_proposed;
			input_token.length = sizeof(maxlength_proposed);

			maj_stat = gss_wrap(&min_stat, 
					    gensec_gssapi_state->gssapi_context, 
					    false,
					    GSS_C_QOP_DEFAULT,
					    &input_token,
					    &conf_state,
					    &output_token);
			if (GSS_ERROR(maj_stat)) {
				DEBUG(1, ("GSS Update(SSF_NEG): GSS Wrap failed: %s\n", 
					  gssapi_error_string(out_mem_ctx, maj_stat, min_stat, gensec_gssapi_state->gss_oid)));
				return NT_STATUS_ACCESS_DENIED;
			}
			
			*out = data_blob_talloc(out_mem_ctx, output_token.value, output_token.length);
			gss_release_buffer(&min_stat, &output_token);

			gensec_gssapi_state->sasl_state = STAGE_SASL_SSF_ACCEPT;
			return NT_STATUS_MORE_PROCESSING_REQUIRED;
		}
		default:
  			return NT_STATUS_INVALID_PARAMETER;
			
		}
	}
	/* This is s server-only stage */
	case STAGE_SASL_SSF_ACCEPT:
	{
		uint8_t maxlength_accepted[4]; 
		uint8_t security_accepted;
		int conf_state;
		gss_qop_t qop_state;
		input_token.length = in.length;
		input_token.value = in.data;
			
		maj_stat = gss_unwrap(&min_stat, 
				      gensec_gssapi_state->gssapi_context, 
				      &input_token,
				      &output_token, 
				      &conf_state,
				      &qop_state);
		if (GSS_ERROR(maj_stat)) {
			DEBUG(1, ("gensec_gssapi_update: GSS UnWrap of SASL protection negotiation failed: %s\n", 
				  gssapi_error_string(out_mem_ctx, maj_stat, min_stat, gensec_gssapi_state->gss_oid)));
			return NT_STATUS_ACCESS_DENIED;
		}
			
		if (output_token.length < 4) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		memcpy(maxlength_accepted, output_token.value, 4);
		gss_release_buffer(&min_stat, &output_token);
		
		/* first byte is the proposed security */
		security_accepted = maxlength_accepted[0];
		maxlength_accepted[0] = '\0';

		/* Rest is the proposed max wrap length */
		gensec_gssapi_state->max_wrap_buf_size = MIN(RIVAL(maxlength_accepted, 0), 
							     gensec_gssapi_state->max_wrap_buf_size);

		gensec_gssapi_state->sasl_protection = 0;
		if (security_accepted & NEG_SEAL) {
			if (!gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)) {
				DEBUG(1, ("Remote client wanted seal, but gensec refused\n"));
				return NT_STATUS_ACCESS_DENIED;
			}
			gensec_gssapi_state->sasl_protection |= NEG_SEAL;
		}
		if (security_accepted & NEG_SIGN) {
			if (!gensec_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
				DEBUG(1, ("Remote client wanted sign, but gensec refused\n"));
				return NT_STATUS_ACCESS_DENIED;
			}
			gensec_gssapi_state->sasl_protection |= NEG_SIGN;
		}
		if (security_accepted & NEG_NONE) {
			gensec_gssapi_state->sasl_protection |= NEG_NONE;
		}

		/* quirk:  This changes the value that gensec_have_feature returns, to be that after SASL negotiation */
		gensec_gssapi_state->sasl_state = STAGE_DONE;
		if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)) {
			DEBUG(5, ("SASL/GSSAPI Connection from client will be cryptographically sealed\n"));
		} else if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
			DEBUG(5, ("SASL/GSSAPI Connection from client will be cryptographically signed\n"));
		} else {
			DEBUG(5, ("SASL/GSSAPI Connection from client will have no cryptographic protection\n"));
		}

		*out = data_blob(NULL, 0);
		return NT_STATUS_OK;	
	}
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}
}

struct gensec_gssapi_update_state {
	NTSTATUS status;
	DATA_BLOB out;
};

static struct tevent_req *gensec_gssapi_update_send(TALLOC_CTX *mem_ctx,
						    struct tevent_context *ev,
						    struct gensec_security *gensec_security,
						    const DATA_BLOB in)
{
	struct tevent_req *req = NULL;
	struct gensec_gssapi_update_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct gensec_gssapi_update_state);
	if (req == NULL) {
		return NULL;
	}

	status = gensec_gssapi_update_internal(gensec_security,
					       state, ev, in,
					       &state->out);
	state->status = status;
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS gensec_gssapi_update_recv(struct tevent_req *req,
					  TALLOC_CTX *out_mem_ctx,
					  DATA_BLOB *out)
{
	struct gensec_gssapi_update_state *state =
		tevent_req_data(req,
		struct gensec_gssapi_update_state);
	NTSTATUS status;

	*out = data_blob_null;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out = state->out;
	talloc_steal(out_mem_ctx, state->out.data);
	status = state->status;
	tevent_req_received(req);
	return status;
}

static NTSTATUS gensec_gssapi_wrap(struct gensec_security *gensec_security, 
				   TALLOC_CTX *mem_ctx, 
				   const DATA_BLOB *in, 
				   DATA_BLOB *out)
{
	struct gensec_gssapi_state *gensec_gssapi_state
		= talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_token, output_token;
	int conf_state;
	input_token.length = in->length;
	input_token.value = in->data;

	maj_stat = gss_wrap(&min_stat, 
			    gensec_gssapi_state->gssapi_context, 
			    gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL),
			    GSS_C_QOP_DEFAULT,
			    &input_token,
			    &conf_state,
			    &output_token);
	if (GSS_ERROR(maj_stat)) {
		DEBUG(1, ("gensec_gssapi_wrap: GSS Wrap failed: %s\n", 
			  gssapi_error_string(mem_ctx, maj_stat, min_stat, gensec_gssapi_state->gss_oid)));
		return NT_STATUS_ACCESS_DENIED;
	}

	*out = data_blob_talloc(mem_ctx, output_token.value, output_token.length);
	gss_release_buffer(&min_stat, &output_token);

	if (gensec_gssapi_state->sasl) {
		size_t max_wrapped_size = gensec_gssapi_max_wrapped_size(gensec_security);
		if (max_wrapped_size < out->length) {
			DEBUG(1, ("gensec_gssapi_wrap: when wrapped, INPUT data (%u) is grew to be larger than SASL negotiated maximum output size (%u > %u)\n",
				  (unsigned)in->length, 
				  (unsigned)out->length, 
				  (unsigned int)max_wrapped_size));
			return NT_STATUS_INVALID_PARAMETER;
		}
	}
	
	if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)
	    && !conf_state) {
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

static NTSTATUS gensec_gssapi_unwrap(struct gensec_security *gensec_security, 
				     TALLOC_CTX *mem_ctx, 
				     const DATA_BLOB *in, 
				     DATA_BLOB *out)
{
	struct gensec_gssapi_state *gensec_gssapi_state
		= talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_token, output_token;
	int conf_state;
	gss_qop_t qop_state;
	input_token.length = in->length;
	input_token.value = in->data;
	
	if (gensec_gssapi_state->sasl) {
		size_t max_wrapped_size = gensec_gssapi_max_wrapped_size(gensec_security);
		if (max_wrapped_size < in->length) {
			DEBUG(1, ("gensec_gssapi_unwrap: WRAPPED data is larger than SASL negotiated maximum size\n"));
			return NT_STATUS_INVALID_PARAMETER;
		}
	}
	
	/*
	 * FIXME: input_message_buffer is marked const, but gss_unwrap() may
	 * modify it (see calls to rrc_rotate() in _gssapi_unwrap_cfx()).
	 */
	maj_stat = gss_unwrap(&min_stat, 
			      gensec_gssapi_state->gssapi_context, 
			      &input_token,
			      &output_token, 
			      &conf_state,
			      &qop_state);
	if (GSS_ERROR(maj_stat)) {
		DEBUG(1, ("gensec_gssapi_unwrap: GSS UnWrap failed: %s\n", 
			  gssapi_error_string(mem_ctx, maj_stat, min_stat, gensec_gssapi_state->gss_oid)));
		return NT_STATUS_ACCESS_DENIED;
	}

	*out = data_blob_talloc(mem_ctx, output_token.value, output_token.length);
	gss_release_buffer(&min_stat, &output_token);
	
	if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)
	    && !conf_state) {
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

/* Find out the maximum input size negotiated on this connection */

static size_t gensec_gssapi_max_input_size(struct gensec_security *gensec_security) 
{
	struct gensec_gssapi_state *gensec_gssapi_state
		= talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);
	OM_uint32 maj_stat, min_stat;
	OM_uint32 max_input_size;

	maj_stat = gss_wrap_size_limit(&min_stat, 
				       gensec_gssapi_state->gssapi_context,
				       gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL),
				       GSS_C_QOP_DEFAULT,
				       gensec_gssapi_state->max_wrap_buf_size,
				       &max_input_size);
	if (GSS_ERROR(maj_stat)) {
		TALLOC_CTX *mem_ctx = talloc_new(NULL); 
		DEBUG(1, ("gensec_gssapi_max_input_size: determining signature size with gss_wrap_size_limit failed: %s\n",
			  gssapi_error_string(mem_ctx, maj_stat, min_stat, gensec_gssapi_state->gss_oid)));
		talloc_free(mem_ctx);
		return 0;
	}

	return max_input_size;
}

/* Find out the maximum output size negotiated on this connection */
static size_t gensec_gssapi_max_wrapped_size(struct gensec_security *gensec_security) 
{
	struct gensec_gssapi_state *gensec_gssapi_state = talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);;
	return gensec_gssapi_state->max_wrap_buf_size;
}

static NTSTATUS gensec_gssapi_seal_packet(struct gensec_security *gensec_security, 
					  TALLOC_CTX *mem_ctx, 
					  uint8_t *data, size_t length, 
					  const uint8_t *whole_pdu, size_t pdu_length, 
					  DATA_BLOB *sig)
{
	struct gensec_gssapi_state *gensec_gssapi_state
		= talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);
	bool hdr_signing = false;
	size_t sig_size = 0;
	NTSTATUS status;

	if (gensec_security->want_features & GENSEC_FEATURE_SIGN_PKT_HEADER) {
		hdr_signing = true;
	}

	sig_size = gensec_gssapi_sig_size(gensec_security, length);

	status = gssapi_seal_packet(gensec_gssapi_state->gssapi_context,
				    gensec_gssapi_state->gss_oid,
				    hdr_signing, sig_size,
				    data, length,
				    whole_pdu, pdu_length,
				    mem_ctx, sig);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("gssapi_seal_packet(hdr_signing=%u,sig_size=%zu,"
			  "data=%zu,pdu=%zu) failed: %s\n",
			  hdr_signing, sig_size, length, pdu_length,
			  nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS gensec_gssapi_unseal_packet(struct gensec_security *gensec_security, 
					    uint8_t *data, size_t length, 
					    const uint8_t *whole_pdu, size_t pdu_length,
					    const DATA_BLOB *sig)
{
	struct gensec_gssapi_state *gensec_gssapi_state
		= talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);
	bool hdr_signing = false;
	NTSTATUS status;

	if (gensec_security->want_features & GENSEC_FEATURE_SIGN_PKT_HEADER) {
		hdr_signing = true;
	}

	status = gssapi_unseal_packet(gensec_gssapi_state->gssapi_context,
				      gensec_gssapi_state->gss_oid,
				      hdr_signing,
				      data, length,
				      whole_pdu, pdu_length,
				      sig);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("gssapi_unseal_packet(hdr_signing=%u,sig_size=%zu,"
			  "data=%zu,pdu=%zu) failed: %s\n",
			  hdr_signing, sig->length, length, pdu_length,
			  nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS gensec_gssapi_sign_packet(struct gensec_security *gensec_security, 
					  TALLOC_CTX *mem_ctx, 
					  const uint8_t *data, size_t length, 
					  const uint8_t *whole_pdu, size_t pdu_length, 
					  DATA_BLOB *sig)
{
	struct gensec_gssapi_state *gensec_gssapi_state
		= talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);
	bool hdr_signing = false;
	NTSTATUS status;

	if (gensec_security->want_features & GENSEC_FEATURE_SIGN_PKT_HEADER) {
		hdr_signing = true;
	}

	status = gssapi_sign_packet(gensec_gssapi_state->gssapi_context,
				    gensec_gssapi_state->gss_oid,
				    hdr_signing,
				    data, length,
				    whole_pdu, pdu_length,
				    mem_ctx, sig);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("gssapi_sign_packet(hdr_signing=%u,"
			  "data=%zu,pdu=%zu) failed: %s\n",
			  hdr_signing, length, pdu_length,
			  nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS gensec_gssapi_check_packet(struct gensec_security *gensec_security, 
					   const uint8_t *data, size_t length, 
					   const uint8_t *whole_pdu, size_t pdu_length, 
					   const DATA_BLOB *sig)
{
	struct gensec_gssapi_state *gensec_gssapi_state
		= talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);
	bool hdr_signing = false;
	NTSTATUS status;

	if (gensec_security->want_features & GENSEC_FEATURE_SIGN_PKT_HEADER) {
		hdr_signing = true;
	}

	status = gssapi_check_packet(gensec_gssapi_state->gssapi_context,
				     gensec_gssapi_state->gss_oid,
				     hdr_signing,
				     data, length,
				     whole_pdu, pdu_length,
				     sig);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("gssapi_check_packet(hdr_signing=%u,sig_size=%zu,"
			  "data=%zu,pdu=%zu) failed: %s\n",
			  hdr_signing, sig->length, length, pdu_length,
			  nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

/* Try to figure out what features we actually got on the connection */
static bool gensec_gssapi_have_feature(struct gensec_security *gensec_security, 
				       uint32_t feature) 
{
	struct gensec_gssapi_state *gensec_gssapi_state
		= talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);
	if (feature & GENSEC_FEATURE_SIGN) {
		/* If we are going GSSAPI SASL, then we honour the second negotiation */
		if (gensec_gssapi_state->sasl 
		    && gensec_gssapi_state->sasl_state == STAGE_DONE) {
			return ((gensec_gssapi_state->sasl_protection & NEG_SIGN) 
				&& (gensec_gssapi_state->gss_got_flags & GSS_C_INTEG_FLAG));
		}
		return gensec_gssapi_state->gss_got_flags & GSS_C_INTEG_FLAG;
	}
	if (feature & GENSEC_FEATURE_SEAL) {
		/* If we are going GSSAPI SASL, then we honour the second negotiation */
		if (gensec_gssapi_state->sasl 
		    && gensec_gssapi_state->sasl_state == STAGE_DONE) {
			return ((gensec_gssapi_state->sasl_protection & NEG_SEAL) 
				 && (gensec_gssapi_state->gss_got_flags & GSS_C_CONF_FLAG));
		}
		return gensec_gssapi_state->gss_got_flags & GSS_C_CONF_FLAG;
	}
	if (feature & GENSEC_FEATURE_SESSION_KEY) {
		/* Only for GSSAPI/Krb5 */
		if (smb_gss_oid_equal(gensec_gssapi_state->gss_oid,
				      gss_mech_krb5)) {
			return true;
		}
	}
	if (feature & GENSEC_FEATURE_DCE_STYLE) {
		return gensec_gssapi_state->gss_got_flags & GSS_C_DCE_STYLE;
	}
	if (feature & GENSEC_FEATURE_NEW_SPNEGO) {
		NTSTATUS status;
		uint32_t keytype;

		if (!(gensec_gssapi_state->gss_got_flags & GSS_C_INTEG_FLAG)) {
			return false;
		}

		if (gensec_setting_bool(gensec_security->settings, "gensec_gssapi", "force_new_spnego", false)) {
			return true;
		}
		if (gensec_setting_bool(gensec_security->settings, "gensec_gssapi", "disable_new_spnego", false)) {
			return false;
		}

		status = gssapi_get_session_key(gensec_gssapi_state,
						gensec_gssapi_state->gssapi_context, NULL, &keytype);
		/* 
		 * We should do a proper sig on the mechListMic unless
		 * we know we have to be backwards compatible with
		 * earlier windows versions.  
		 * 
		 * Negotiating a non-krb5
		 * mech for example should be regarded as having
		 * NEW_SPNEGO
		 */
		if (NT_STATUS_IS_OK(status)) {
			switch (keytype) {
			case ENCTYPE_DES_CBC_CRC:
			case ENCTYPE_DES_CBC_MD5:
			case ENCTYPE_ARCFOUR_HMAC:
			case ENCTYPE_DES3_CBC_SHA1:
				return false;
			}
		}
		return true;
	}
	/* We can always do async (rather than strict request/reply) packets.  */
	if (feature & GENSEC_FEATURE_ASYNC_REPLIES) {
		return true;
	}
	if (feature & GENSEC_FEATURE_SIGN_PKT_HEADER) {
		return true;
	}
	return false;
}

static NTTIME gensec_gssapi_expire_time(struct gensec_security *gensec_security)
{
	struct gensec_gssapi_state *gensec_gssapi_state =
		talloc_get_type_abort(gensec_security->private_data,
		struct gensec_gssapi_state);

	return gensec_gssapi_state->expire_time;
}

/*
 * Extract the 'sesssion key' needed by SMB signing and ncacn_np 
 * (for encrypting some passwords).
 * 
 * This breaks all the abstractions, but what do you expect...
 */
static NTSTATUS gensec_gssapi_session_key(struct gensec_security *gensec_security, 
					  TALLOC_CTX *mem_ctx,
					  DATA_BLOB *session_key) 
{
	struct gensec_gssapi_state *gensec_gssapi_state
		= talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);
	return gssapi_get_session_key(mem_ctx, gensec_gssapi_state->gssapi_context, session_key, NULL);
}

/* Get some basic (and authorization) information about the user on
 * this session.  This uses either the PAC (if present) or a local
 * database lookup */
static NTSTATUS gensec_gssapi_session_info(struct gensec_security *gensec_security,
					   TALLOC_CTX *mem_ctx,
					   struct auth_session_info **_session_info) 
{
	NTSTATUS nt_status;
	TALLOC_CTX *tmp_ctx;
	struct gensec_gssapi_state *gensec_gssapi_state
		= talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);
	struct auth_session_info *session_info = NULL;
	OM_uint32 maj_stat, min_stat;
	DATA_BLOB pac_blob, *pac_blob_ptr = NULL;

	gss_buffer_desc name_token;
	char *principal_string;
	
	tmp_ctx = talloc_named(mem_ctx, 0, "gensec_gssapi_session_info context");
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	maj_stat = gss_display_name (&min_stat,
				     gensec_gssapi_state->client_name,
				     &name_token,
				     NULL);
	if (GSS_ERROR(maj_stat)) {
		DEBUG(1, ("GSS display_name failed: %s\n",
			  gssapi_error_string(tmp_ctx, maj_stat, min_stat, gensec_gssapi_state->gss_oid)));
		talloc_free(tmp_ctx);
		return NT_STATUS_FOOBAR;
	}

	principal_string = talloc_strndup(tmp_ctx,
					  (const char *)name_token.value,
					  name_token.length);

	gss_release_buffer(&min_stat, &name_token);

	if (!principal_string) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = gssapi_obtain_pac_blob(tmp_ctx,  gensec_gssapi_state->gssapi_context,
					   gensec_gssapi_state->client_name,
					   &pac_blob);
	
	/* IF we have the PAC - otherwise we need to get this
	 * data from elsewere - local ldb, or (TODO) lookup of some
	 * kind... 
	 */
	if (NT_STATUS_IS_OK(nt_status)) {
		pac_blob_ptr = &pac_blob;
	}
	nt_status = gensec_generate_session_info_pac(tmp_ctx,
						     gensec_security,
						     gensec_gssapi_state->smb_krb5_context,
						     pac_blob_ptr, principal_string,
						     gensec_get_remote_address(gensec_security),
						     &session_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	nt_status = gensec_gssapi_session_key(gensec_security, session_info, &session_info->session_key);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	if (gensec_gssapi_state->gss_got_flags & GSS_C_DELEG_FLAG &&
	    gensec_gssapi_state->delegated_cred_handle != GSS_C_NO_CREDENTIAL) {
		krb5_error_code ret;
		const char *error_string;

		DEBUG(10, ("gensec_gssapi: delegated credentials supplied by client\n"));

		/*
		 * Create anonymous credentials for now.
		 *
		 * We will update them with the provided client gss creds.
		 */
		session_info->credentials = cli_credentials_init_anon(session_info);
		if (session_info->credentials == NULL) {
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		ret = cli_credentials_set_client_gss_creds(session_info->credentials, 
							   gensec_security->settings->lp_ctx,
							   gensec_gssapi_state->delegated_cred_handle,
							   CRED_SPECIFIED, &error_string);
		if (ret) {
			talloc_free(tmp_ctx);
			DEBUG(2,("Failed to get gss creds: %s\n", error_string));
			return NT_STATUS_NO_MEMORY;
		}
		
		/* This credential handle isn't useful for password authentication, so ensure nobody tries to do that */
		cli_credentials_set_kerberos_state(session_info->credentials, CRED_MUST_USE_KERBEROS);

		/* It has been taken from this place... */
		gensec_gssapi_state->delegated_cred_handle = GSS_C_NO_CREDENTIAL;
	} else {
		DEBUG(10, ("gensec_gssapi: NO delegated credentials supplied by client\n"));
	}

	*_session_info = talloc_steal(mem_ctx, session_info);
	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}

static size_t gensec_gssapi_sig_size(struct gensec_security *gensec_security, size_t data_size)
{
	struct gensec_gssapi_state *gensec_gssapi_state
		= talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);
	size_t sig_size;

	if (gensec_gssapi_state->sig_size > 0) {
		return gensec_gssapi_state->sig_size;
	}

	sig_size = gssapi_get_sig_size(gensec_gssapi_state->gssapi_context,
				       gensec_gssapi_state->gss_oid,
				       gensec_gssapi_state->gss_got_flags,
				       data_size);

	gensec_gssapi_state->sig_size = sig_size;
	return gensec_gssapi_state->sig_size;
}

static const char *gensec_gssapi_final_auth_type(struct gensec_security *gensec_security)
{
	struct gensec_gssapi_state *gensec_gssapi_state
		= talloc_get_type(gensec_security->private_data, struct gensec_gssapi_state);
	/* Only return the string for GSSAPI/Krb5 */
	if (smb_gss_oid_equal(gensec_gssapi_state->gss_oid,
			      gss_mech_krb5)) {
		return GENSEC_FINAL_AUTH_TYPE_KRB5;
	} else {
		return "gensec_gssapi: UNKNOWN MECH";
	}
}

static const char *gensec_gssapi_krb5_oids[] = { 
	GENSEC_OID_KERBEROS5_OLD,
	GENSEC_OID_KERBEROS5,
	NULL 
};

static const char *gensec_gssapi_spnego_oids[] = { 
	GENSEC_OID_SPNEGO,
	NULL 
};

/* As a server, this could in theory accept any GSSAPI mech */
static const struct gensec_security_ops gensec_gssapi_spnego_security_ops = {
	.name		= "gssapi_spnego",
	.sasl_name	= "GSS-SPNEGO",
	.auth_type	= DCERPC_AUTH_TYPE_SPNEGO,
	.oid            = gensec_gssapi_spnego_oids,
	.client_start   = gensec_gssapi_client_start,
	.server_start   = gensec_gssapi_server_start,
	.magic  	= gensec_magic_check_krb5_oid,
	.update_send	= gensec_gssapi_update_send,
	.update_recv	= gensec_gssapi_update_recv,
	.session_key	= gensec_gssapi_session_key,
	.session_info	= gensec_gssapi_session_info,
	.sign_packet	= gensec_gssapi_sign_packet,
	.check_packet	= gensec_gssapi_check_packet,
	.seal_packet	= gensec_gssapi_seal_packet,
	.unseal_packet	= gensec_gssapi_unseal_packet,
	.max_input_size	  = gensec_gssapi_max_input_size,
	.max_wrapped_size = gensec_gssapi_max_wrapped_size,
	.wrap           = gensec_gssapi_wrap,
	.unwrap         = gensec_gssapi_unwrap,
	.have_feature   = gensec_gssapi_have_feature,
	.expire_time    = gensec_gssapi_expire_time,
	.final_auth_type = gensec_gssapi_final_auth_type,
	.enabled        = false,
	.kerberos       = true,
	.priority       = GENSEC_GSSAPI
};

/* As a server, this could in theory accept any GSSAPI mech */
static const struct gensec_security_ops gensec_gssapi_krb5_security_ops = {
	.name		= "gssapi_krb5",
	.auth_type	= DCERPC_AUTH_TYPE_KRB5,
	.oid            = gensec_gssapi_krb5_oids,
	.client_start   = gensec_gssapi_client_start,
	.server_start   = gensec_gssapi_server_start,
	.magic  	= gensec_magic_check_krb5_oid,
	.update_send	= gensec_gssapi_update_send,
	.update_recv	= gensec_gssapi_update_recv,
	.session_key	= gensec_gssapi_session_key,
	.session_info	= gensec_gssapi_session_info,
	.sig_size	= gensec_gssapi_sig_size,
	.sign_packet	= gensec_gssapi_sign_packet,
	.check_packet	= gensec_gssapi_check_packet,
	.seal_packet	= gensec_gssapi_seal_packet,
	.unseal_packet	= gensec_gssapi_unseal_packet,
	.max_input_size	  = gensec_gssapi_max_input_size,
	.max_wrapped_size = gensec_gssapi_max_wrapped_size,
	.wrap           = gensec_gssapi_wrap,
	.unwrap         = gensec_gssapi_unwrap,
	.have_feature   = gensec_gssapi_have_feature,
	.expire_time    = gensec_gssapi_expire_time,
	.final_auth_type = gensec_gssapi_final_auth_type,
	.enabled        = true,
	.kerberos       = true,
	.priority       = GENSEC_GSSAPI
};

/* As a server, this could in theory accept any GSSAPI mech */
static const struct gensec_security_ops gensec_gssapi_sasl_krb5_security_ops = {
	.name		  = "gssapi_krb5_sasl",
	.sasl_name        = "GSSAPI",
	.client_start     = gensec_gssapi_sasl_client_start,
	.server_start     = gensec_gssapi_sasl_server_start,
	.update_send      = gensec_gssapi_update_send,
	.update_recv      = gensec_gssapi_update_recv,
	.session_key	  = gensec_gssapi_session_key,
	.session_info	  = gensec_gssapi_session_info,
	.max_input_size	  = gensec_gssapi_max_input_size,
	.max_wrapped_size = gensec_gssapi_max_wrapped_size,
	.wrap             = gensec_gssapi_wrap,
	.unwrap           = gensec_gssapi_unwrap,
	.have_feature     = gensec_gssapi_have_feature,
	.expire_time      = gensec_gssapi_expire_time,
	.final_auth_type = gensec_gssapi_final_auth_type,
	.enabled          = true,
	.kerberos         = true,
	.priority         = GENSEC_GSSAPI
};

_PUBLIC_ NTSTATUS gensec_gssapi_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;

	ret = gensec_register(ctx, &gensec_gssapi_spnego_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_gssapi_spnego_security_ops.name));
		return ret;
	}

	ret = gensec_register(ctx, &gensec_gssapi_krb5_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_gssapi_krb5_security_ops.name));
		return ret;
	}

	ret = gensec_register(ctx, &gensec_gssapi_sasl_krb5_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_gssapi_sasl_krb5_security_ops.name));
		return ret;
	}

	return ret;
}
