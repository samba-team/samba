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
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h" /* TODO: remove this */
#include "../libcli/auth/spnego.h"

#ifdef HAVE_KRB5

#include "auth/kerberos/pac_utils.h"

struct smb_krb5_context;

/****************************************************************
Callback to get the PAC_LOGON_INFO from the blob
****************************************************************/
static NTSTATUS kerberos_fetch_pac(struct auth4_context *auth_ctx,
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
	struct PAC_DATA_CTR *pac_data_ctr = NULL;
	NTSTATUS status = NT_STATUS_INTERNAL_ERROR;

	tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	if (pac_blob != NULL) {
		status = kerberos_decode_pac(tmp_ctx,
					     *pac_blob,
					     NULL,
					     NULL,
					     NULL,
					     NULL,
					     0,
					     &pac_data);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		pac_data_ctr = talloc(mem_ctx, struct PAC_DATA_CTR);
		if (pac_data_ctr == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}

		talloc_set_name_const(pac_data_ctr, "struct PAC_DATA_CTR");

		pac_data_ctr->pac_data = talloc_steal(pac_data_ctr, pac_data);
		pac_data_ctr->pac_blob = data_blob_talloc(pac_data_ctr,
							  pac_blob->data,
							  pac_blob->length);

		auth_ctx->private_data = talloc_steal(auth_ctx, pac_data_ctr);
	}

	*session_info = talloc_zero(mem_ctx, struct auth_session_info);
	if (!*session_info) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	status = NT_STATUS_OK;

done:
	TALLOC_FREE(tmp_ctx);

	return status;
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
			     struct PAC_DATA_CTR **_pac_data_ctr)
{
	krb5_error_code ret;
	NTSTATUS status = NT_STATUS_INVALID_PARAMETER;
	DATA_BLOB tkt, tkt_wrapped, ap_rep, sesskey1;
	const char *auth_princ = NULL;
	const char *cc = "MEMORY:kerberos_return_pac";
	struct auth_session_info *session_info;
	struct gensec_security *gensec_server_context;
	const struct gensec_security_ops **backends;
	struct gensec_settings *gensec_settings;
	size_t idx = 0;
	struct auth4_context *auth_context;
	struct loadparm_context *lp_ctx;
	struct PAC_DATA_CTR *pac_data_ctr = NULL;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	ZERO_STRUCT(tkt);
	ZERO_STRUCT(ap_rep);
	ZERO_STRUCT(sesskey1);

	if (!name || !pass) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (cache_name) {
		cc = cache_name;
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
		return NT_STATUS_INVALID_LOGON_TYPE;
	}

	ret = cli_krb5_get_ticket(mem_ctx,
				  local_service,
				  time_offset,
				  &tkt,
				  &sesskey1,
				  0,
				  cc,
				  NULL,
				  impersonate_princ_s);
	if (ret) {
		DEBUG(1,("failed to get ticket for %s: %s\n",
			local_service, error_message(ret)));
		if (impersonate_princ_s) {
			DEBUGADD(1,("tried S4U2SELF impersonation as: %s\n",
				impersonate_princ_s));
		}
		status = krb5_to_nt_status(ret);
		goto out;
	}

	/* wrap that up in a nice GSS-API wrapping */
	tkt_wrapped = spnego_gen_krb5_wrap(tmp_ctx, tkt, TOK_ID_KRB_AP_REQ);
	if (tkt_wrapped.data == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	auth_context = talloc_zero(tmp_ctx, struct auth4_context);
	if (auth_context == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	auth_context->generate_session_info_pac = kerberos_fetch_pac;

	lp_ctx = loadparm_init_s3(tmp_ctx, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		status = NT_STATUS_INVALID_SERVER_STATE;
		DEBUG(10, ("loadparm_init_s3 failed\n"));
		goto out;
	}

	gensec_settings = lpcfg_gensec_settings(tmp_ctx, lp_ctx);
	if (lp_ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		DEBUG(10, ("lpcfg_gensec_settings failed\n"));
		goto out;
	}

	backends = talloc_zero_array(gensec_settings,
				     const struct gensec_security_ops *, 2);
	if (backends == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	gensec_settings->backends = backends;

	gensec_init();

	backends[idx++] = &gensec_gse_krb5_security_ops;

	status = gensec_server_start(tmp_ctx, gensec_settings,
					auth_context, &gensec_server_context);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, (__location__ "Failed to start server-side GENSEC to validate a Kerberos ticket: %s\n", nt_errstr(status)));
		goto out;
	}

	talloc_unlink(tmp_ctx, lp_ctx);
	talloc_unlink(tmp_ctx, gensec_settings);
	talloc_unlink(tmp_ctx, auth_context);

	status = gensec_start_mech_by_oid(gensec_server_context, GENSEC_OID_KERBEROS5);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, (__location__ "Failed to start server-side GENSEC krb5 to validate a Kerberos ticket: %s\n", nt_errstr(status)));
		goto out;
	}

	/* Do a client-server update dance */
	status = gensec_update(gensec_server_context, tmp_ctx, tkt_wrapped, &ap_rep);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("gensec_update() failed: %s\n", nt_errstr(status)));
		goto out;
	}

	/* Now return the PAC information to the callers.  We ingore
	 * the session_info and instead pick out the PAC via the
	 * private_data on the auth_context */
	status = gensec_session_info(gensec_server_context, tmp_ctx, &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Unable to obtain PAC via gensec_session_info\n"));
		goto out;
	}

	pac_data_ctr = talloc_get_type_abort(gensec_server_context->auth_context->private_data,
					     struct PAC_DATA_CTR);
	if (pac_data_ctr == NULL) {
		DEBUG(1,("no PAC\n"));
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	*_pac_data_ctr = talloc_move(mem_ctx, &pac_data_ctr);

out:
	talloc_free(tmp_ctx);
	if (cc != cache_name) {
		ads_kdestroy(cc);
	}

	data_blob_free(&tkt);
	data_blob_free(&ap_rep);
	data_blob_free(&sesskey1);

	return status;
}

#endif
