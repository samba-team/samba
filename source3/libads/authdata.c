/*
   Unix SMB/CIFS implementation.
   kerberos authorization data (PAC) utility library
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Luke Howard 2002-2003
   Copyright (C) Stefan Metzmacher 2004-2005
   Copyright (C) Guenther Deschner 2005,2007,2008

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
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "smb_krb5.h"
#include "libads/kerberos_proto.h"
#include "auth/common_auth.h"
#include "lib/param/param.h"
#include "librpc/crypto/gse.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "../libcli/auth/spnego.h"
#include "lib/util/asn1.h"

#ifdef HAVE_KRB5

#include "auth/kerberos/pac_utils.h"

struct smb_krb5_context;

/*
  generate a krb5 GSS-API wrapper packet given a ticket
*/
static DATA_BLOB spnego_gen_krb5_wrap(
	TALLOC_CTX *ctx, const DATA_BLOB ticket, const uint8_t tok_id[2])
{
	ASN1_DATA *data;
	DATA_BLOB ret = data_blob_null;

	data = asn1_init(talloc_tos(), ASN1_MAX_TREE_DEPTH);
	if (data == NULL) {
		return data_blob_null;
	}

	if (!asn1_push_tag(data, ASN1_APPLICATION(0))) goto err;
	if (!asn1_write_OID(data, OID_KERBEROS5)) goto err;

	if (!asn1_write(data, tok_id, 2)) goto err;
	if (!asn1_write(data, ticket.data, ticket.length)) goto err;
	if (!asn1_pop_tag(data)) goto err;

	if (!asn1_extract_blob(data, ctx, &ret)) {
		goto err;
	}

	asn1_free(data);
	data = NULL;

  err:

	if (data != NULL) {
		if (asn1_has_error(data)) {
			DEBUG(1, ("Failed to build krb5 wrapper at offset %d\n",
				  (int)asn1_current_ofs(data)));
		}

		asn1_free(data);
	}

	return ret;
}

static NTSTATUS kerberos_return_pac_internal(TALLOC_CTX *mem_ctx,
					     time_t time_offset,
					     const char *ccache_name,
					     const char *impersonate_princ_s,
					     const char *local_service,
					     struct PAC_DATA_CTR **_pac_data_ctr)
{
	TALLOC_CTX *frame = talloc_stackframe();
	krb5_error_code ret;
	NTSTATUS status = NT_STATUS_INVALID_PARAMETER;
	DATA_BLOB tkt = {};
	DATA_BLOB tkt_wrapped = {};
	DATA_BLOB ap_rep = {};
	DATA_BLOB sesskey1 = {};
	struct auth_session_info *session_info = NULL;
	struct gensec_security *gensec_server_context = NULL;
	size_t idx = 0;
	const struct gensec_security_ops **backends = NULL;
	struct gensec_settings *gensec_settings = NULL;
	struct auth4_context *auth_context = NULL;
	struct loadparm_context *lp_ctx = NULL;
	struct PAC_DATA_CTR *pac_data_ctr = NULL;

	if (ccache_name == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_PARAMETER;
	}

	ret = ads_krb5_cli_get_ticket(frame,
				      local_service,
				      time_offset,
				      &tkt,
				      &sesskey1,
				      0,
				      ccache_name,
				      NULL,
				      impersonate_princ_s);
	if (ret) {
		DEBUG(1,("failed to get ticket for %s: %s\n",
			local_service, error_message(ret)));
		if (impersonate_princ_s) {
			DEBUGADD(1,("tried S4U2SELF impersonation as: %s\n",
				impersonate_princ_s));
		}
		TALLOC_FREE(frame);
		return krb5_to_nt_status(ret);
	}

	/* wrap that up in a nice GSS-API wrapping */
	tkt_wrapped = spnego_gen_krb5_wrap(frame, tkt, TOK_ID_KRB_AP_REQ);
	if (tkt_wrapped.data == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	auth_context = auth4_context_for_PAC_DATA_CTR(frame);
	if (auth_context == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	lp_ctx = loadparm_init_s3(frame, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_SERVER_STATE;
	}

	gensec_settings = lpcfg_gensec_settings(frame, lp_ctx);
	if (gensec_settings == NULL) {
		DEBUG(10, ("lpcfg_gensec_settings failed\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	backends = talloc_zero_array(gensec_settings,
				     const struct gensec_security_ops *,
				     2);
	if (backends == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	gensec_settings->backends = backends;

	gensec_init();

	backends[idx++] = gensec_gse_security_by_oid(GENSEC_OID_KERBEROS5);

	status = gensec_server_start(frame,
				     gensec_settings,
				     auth_context,
				     &gensec_server_context);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("Failed to start server-side GENSEC: %s\n",
			    nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	/* Session info is not complete, do not pass to auth log */
	gensec_want_feature(gensec_server_context, GENSEC_FEATURE_NO_AUTHZ_LOG);

	status = gensec_start_mech_by_oid(gensec_server_context,
					  GENSEC_OID_KERBEROS5);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("Failed to start server-side GENSEC krb5: %s\n",
			    nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	/* Do a client-server update dance */
	status = gensec_update(gensec_server_context,
			       frame,
			       tkt_wrapped,
			       &ap_rep);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("gensec_update() failed: %s\n",
			    nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	/*
	 * Now return the PAC information to the callers.  We ignore
	 * the session_info and instead pick out the PAC via the
	 * private_data on the auth_context
	 */
	status = gensec_session_info(gensec_server_context,
				     frame,
				     &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("Unable to obtain PAC via gensec_session_info: %s\n",
			    nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	pac_data_ctr = auth4_context_get_PAC_DATA_CTR(auth_context, mem_ctx);
	if (pac_data_ctr == NULL) {
		DEBUG(1,("no PAC\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_NO_IMPERSONATION_TOKEN;
	}

	*_pac_data_ctr = talloc_move(mem_ctx, &pac_data_ctr);

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

/*
 * Given the username/password, do a kinit, store the ticket in
 * cache_name if specified, and return the PAC_LOGON_INFO (the
 * structure containing the important user information such as
 * groups).
 */
NTSTATUS kerberos_return_pac(TALLOC_CTX *mem_ctx,
			     const char *name,
			     const char *pass,
			     time_t time_offset,
			     time_t *expire_time,
			     time_t *renew_till_time,
			     const char *cache_name,
			     bool request_pac,
			     bool add_netbios_addr,
			     time_t renewable_time,
			     const char *impersonate_princ_s,
			     const char *local_service,
			     char **_canon_principal,
			     char **_canon_realm,
			     struct PAC_DATA_CTR **_pac_data_ctr)
{
	krb5_error_code ret;
	NTSTATUS status = NT_STATUS_INVALID_PARAMETER;
	const char *auth_princ = NULL;
	const char *cc = NULL;
	struct PAC_DATA_CTR *pac_data_ctr = NULL;
	char *canon_principal = NULL;
	char *canon_realm = NULL;
	krb5_context ctx = NULL;
	krb5_ccache ccid = NULL;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	if (!name || !pass) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (_canon_principal != NULL) {
		*_canon_principal = NULL;
	}

	if (_canon_realm != NULL) {
		*_canon_realm = NULL;
	}

	if (cache_name) {
		cc = cache_name;
	} else {
		char *ccname = NULL;

		ret = smb_krb5_init_context_common(&ctx);
		if (ret != 0) {
			status = krb5_to_nt_status(ret);
			goto out;
		}

		ret = smb_krb5_cc_new_unique_memory(ctx,
						    tmp_ctx,
						    &ccname,
						    &ccid);
		if (ret != 0) {
			status = krb5_to_nt_status(ret);
			goto out;
		}
		cc = ccname;
	}

	if (!strchr_m(name, '@')) {
		auth_princ = talloc_asprintf(mem_ctx, "%s@%s", name,
			lp_realm());
	} else {
		auth_princ = name;
	}
	NT_STATUS_HAVE_NO_MEMORY(auth_princ);

	ret = kerberos_kinit_password_ext(auth_princ,
					  pass,
					  time_offset,
					  expire_time,
					  renew_till_time,
					  cc,
					  request_pac,
					  add_netbios_addr,
					  renewable_time,
					  tmp_ctx,
					  &canon_principal,
					  &canon_realm,
					  &status);
	if (ret) {
		DEBUG(1,("kinit failed for '%s' with: %s (%d)\n",
			auth_princ, error_message(ret), ret));
		/* status already set */
		goto out;
	}

	DEBUG(10,("got TGT for %s in %s\n", auth_princ, cc));
	if (expire_time) {
		DEBUGADD(10,("\tvalid until: %s (%d)\n",
			http_timestring(talloc_tos(), *expire_time),
			(int)*expire_time));
	}
	if (renew_till_time) {
		DEBUGADD(10,("\trenewable till: %s (%d)\n",
			http_timestring(talloc_tos(), *renew_till_time),
			(int)*renew_till_time));
	}

	/* we cannot continue with krb5 when UF_DONT_REQUIRE_PREAUTH is set,
	 * in that case fallback to NTLM - gd */

	if (expire_time && renew_till_time &&
	    (*expire_time == 0) && (*renew_till_time == 0)) {
		status = NT_STATUS_INVALID_LOGON_TYPE;
		goto out;
	}

	status = kerberos_return_pac_internal(mem_ctx,
					      time_offset,
					      cc,
					      impersonate_princ_s,
					      local_service,
					      &pac_data_ctr);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	*_pac_data_ctr = talloc_move(mem_ctx, &pac_data_ctr);
	if (_canon_principal != NULL) {
		*_canon_principal = talloc_move(mem_ctx, &canon_principal);
	}
	if (_canon_realm != NULL) {
		*_canon_realm = talloc_move(mem_ctx, &canon_realm);
	}

out:
	if (ccid != NULL) {
		krb5_cc_destroy(ctx, ccid);
		ccid = NULL;
	}
	if (ctx != NULL) {
		krb5_free_context(ctx);
		ctx = NULL;
	}
	talloc_free(tmp_ctx);

	return status;
}

NTSTATUS kerberos_s4u2self_pac(TALLOC_CTX *mem_ctx,
			       struct cli_credentials *machine_creds,
			       const char *impersonate_princ_s,
			       const char *local_service,
			       struct PAC_DATA_CTR **_pac_data_ctr)
{
	TALLOC_CTX *frame = talloc_stackframe();
	krb5_context ctx = NULL;
	char *machine_ccname = NULL;
	krb5_ccache machine_cc_id = NULL;
	char *s4u2self_ccname = NULL;
	krb5_ccache s4u2self_cc_id = NULL;
	struct PAC_DATA_CTR *pac_data_ctr = NULL;
	krb5_error_code ret;
	NTSTATUS status;
	bool ok;

	if (impersonate_princ_s == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	status = kerberos_prepare_cli_credentials_ccache(machine_creds,
							 NULL, /* explicit_kdc */
							 impersonate_princ_s);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	ok = cli_credentials_get_ccache_name_obtained(machine_creds,
						      frame,
						      &machine_ccname,
						      NULL); /* obtained */
	if (!ok) {
		/*
		 * This should work after
		 * kerberos_prepare_cli_credentials_ccache()
		 */
		status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}

	ret = smb_krb5_init_context_common(&ctx);
	if (ret != 0) {
		status = krb5_to_nt_status(ret);
		goto out;
	}

	/*
	 * We create a temporary copy of the creds.
	 * The most important one is the TGT of
	 * the machine account.
	 *
	 * As we don't want to add the s4u2self
	 * creds to the ccache of the machine_creds.
	 */

	ret = krb5_cc_resolve(ctx,
			      machine_ccname,
			      &machine_cc_id);
	if (ret != 0) {
		status = krb5_to_nt_status(ret);
		goto out;
	}

	ret = smb_krb5_cc_new_unique_memory(ctx,
					    frame,
					    &s4u2self_ccname,
					    &s4u2self_cc_id);
	if (ret != 0) {
		status = krb5_to_nt_status(ret);
		goto out;
	}

	ret = smb_krb5_cc_copy_creds(ctx,
				     machine_cc_id,
				     s4u2self_cc_id);
	if (ret != 0) {
		status = krb5_to_nt_status(ret);
		goto out;
	}

	status = kerberos_return_pac_internal(mem_ctx,
					      0, /* time_offset */
					      s4u2self_ccname,
					      impersonate_princ_s,
					      local_service,
					      &pac_data_ctr);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}
	/* cleanup via frame on error */
	talloc_reparent(mem_ctx, frame, pac_data_ctr);

	/*
	 * TODO: In future we can can copy
	 * all creds (cross-forest TGTs) belonging
	 * to the machine creds back into
	 * machine_ccname.
	 *
	 * But currently cli_credentials is
	 * typically only temporary and will
	 * be fully reconstructed from secrets.tdb
	 * each time. So for now it wouldn't gain much here.
	 */

	*_pac_data_ctr = talloc_move(mem_ctx, &pac_data_ctr);

out:
	if (s4u2self_cc_id != NULL) {
		krb5_cc_destroy(ctx, s4u2self_cc_id);
		s4u2self_cc_id = NULL;
	}
	if (machine_cc_id != NULL) {
		krb5_cc_close(ctx, machine_cc_id);
		machine_cc_id = NULL;
	}
	if (ctx != NULL) {
		krb5_free_context(ctx);
		ctx = NULL;
	}
	TALLOC_FREE(frame);

	return status;
}

#endif
