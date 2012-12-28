/*
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Stefan Metzmacher 2007
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2012
   Copyright (C) Christof Schmit <christof.schmitt@us.ibm.com> 2012

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
#include "torture/smbtorture.h"
#include "torture/winbind/proto.h"
#include "auth/auth.h"
#include "auth/auth_sam_reply.h"
#include "auth/gensec/gensec.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "auth/credentials/credentials.h"
#include "param/param.h"
#include "lib/cmdline/popt_common.h"
#include "auth/kerberos/pac_utils.h"
#include "wbclient.h"

struct pac_data {
	DATA_BLOB pac_blob;
};

/* A helper function which avoids touching the local databases to
 * generate the session info, as we just want to verify the PAC
 * details, not the full local token */
static NTSTATUS test_generate_session_info_pac(struct auth4_context *auth_ctx,
					       TALLOC_CTX *mem_ctx,
					       struct smb_krb5_context *smb_krb5_context,
					       DATA_BLOB *pac_blob,
					       const char *principal_name,
					       const struct tsocket_address *remote_address,
					       uint32_t session_info_flags,
					       struct auth_session_info **session_info)
{
	NTSTATUS nt_status;
	struct auth_user_info_dc *user_info_dc;
	TALLOC_CTX *tmp_ctx;
	struct pac_data *pac_data;

	tmp_ctx = talloc_named(mem_ctx, 0, "gensec_gssapi_session_info context");
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	auth_ctx->private_data = pac_data = talloc_zero(auth_ctx, struct pac_data); 

	pac_data->pac_blob = *pac_blob;

	talloc_steal(pac_data, pac_data->pac_blob.data);
	nt_status = kerberos_pac_blob_to_user_info_dc(tmp_ctx,
						      *pac_blob,
						      smb_krb5_context->krb5_context,
						      &user_info_dc,
						      NULL, NULL);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	if (user_info_dc->info->authenticated) {
		session_info_flags |= AUTH_SESSION_INFO_AUTHENTICATED;
	}

	session_info_flags |= AUTH_SESSION_INFO_SIMPLE_PRIVILEGES;
	nt_status = auth_generate_session_info(mem_ctx,
					       NULL,
					       NULL,
					       user_info_dc, session_info_flags,
					       session_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	talloc_free(tmp_ctx);
	return nt_status;
}

static bool torture_decode_compare_pac(struct torture_context *tctx,
				       DATA_BLOB pac)
{
	struct wbcAuthUserParams params;
	struct wbcAuthUserInfo *info;
	struct wbcAuthErrorInfo *error;
	struct PAC_LOGON_INFO *logon_info;
	struct netr_SamInfo3 *info3;
	struct netr_SamBaseInfo *base;
	wbcErr wbc_err;
	NTSTATUS status;
	int result, sid_idx, i;
	char sid_str[50];

	/* Let winbind decode the PAC */
	memset(&params, 0, sizeof(params));
	params.level = WBC_AUTH_USER_LEVEL_PAC;
	params.password.pac.data = pac.data;
	params.password.pac.length = pac.length;

	wbc_err = wbcAuthenticateUserEx(&params, &info, &error);
	torture_assert(tctx, WBC_ERROR_IS_OK(wbc_err), wbcErrorString(wbc_err));

	/* Decode the PAC internally */
	status = kerberos_pac_logon_info(tctx, pac, NULL, NULL, NULL, NULL, 0,
					 &logon_info);
	torture_assert(tctx, NT_STATUS_IS_OK(status), "pac_logon_info");
	info3 = &logon_info->info3;
	base = &info3->base;

	/* Compare the decoded data from winbind and from internal call */
	torture_assert(tctx, info->user_flags == base->user_flags, "user_flags");
	torture_assert_str_equal(tctx, info->account_name, base->account_name.string, "account_name");
	torture_assert_str_equal(tctx, info->full_name, base->full_name.string, "full_name");
	torture_assert_str_equal(tctx, info->domain_name, base->logon_domain.string, "domain_name");
	torture_assert(tctx, info->acct_flags == base->acct_flags, "acct_flags");
	torture_assert(tctx, info->logon_count == base->logon_count, "logon_count");
	torture_assert(tctx, info->bad_password_count == base->bad_password_count, "bad_password_count");
	torture_assert(tctx, info->logon_time == nt_time_to_unix(base->logon_time), "logon_time");
	torture_assert(tctx, info->logoff_time == nt_time_to_unix(base->logoff_time), "logoff_time");
	torture_assert(tctx, info->kickoff_time == nt_time_to_unix(base->kickoff_time), "kickoff_time");
	torture_assert(tctx, info->pass_last_set_time == nt_time_to_unix(base->last_password_change), "last_password_change");
	torture_assert(tctx, info->pass_can_change_time == nt_time_to_unix(base->allow_password_change), "allow_password_change");
	torture_assert(tctx, info->pass_must_change_time == nt_time_to_unix(base->force_password_change), "force_password_change");
	torture_assert(tctx, info->num_sids == 2 + base->groups.count + info3->sidcount, "num_sids");

	sid_idx = 0;
	wbcSidToStringBuf(&info->sids[sid_idx].sid, sid_str, sizeof(sid_str));
	torture_assert(tctx,
		       dom_sid_equal(dom_sid_parse_talloc(tctx, sid_str),
				     dom_sid_add_rid(tctx, base->domain_sid, base->rid)),
		       sid_str);

	sid_idx++;
	wbcSidToStringBuf(&info->sids[sid_idx].sid, sid_str, sizeof(sid_str));
	torture_assert(tctx,
		       dom_sid_equal(dom_sid_parse_talloc(tctx, sid_str),
				     dom_sid_add_rid(tctx, base->domain_sid, base->primary_gid)),
		       sid_str);

	for(i = 0; i < base->groups.count; i++ ) {
		sid_idx++;
		wbcSidToStringBuf(&info->sids[sid_idx].sid,
				  sid_str, sizeof(sid_str));
		torture_assert(tctx,
			       dom_sid_equal(dom_sid_parse_talloc(tctx, sid_str),
					     dom_sid_add_rid(tctx, base->domain_sid,
							     base->groups.rids[i].rid)),
			       sid_str);
	}

	for(i = 0; i < info3->sidcount; i++) {
		sid_idx++;
		wbcSidToStringBuf(&info->sids[sid_idx].sid,
				  sid_str, sizeof(sid_str));
		torture_assert(tctx,
			       dom_sid_equal(dom_sid_parse_talloc(tctx, sid_str),
					     info3->sids[i].sid),
			       sid_str);
	}

	return true;
}

static bool torture_winbind_pac(struct torture_context *tctx)
{
	NTSTATUS status;

	struct gensec_security *gensec_client_context;
	struct gensec_security *gensec_server_context;

	DATA_BLOB client_to_server, server_to_client;	

	struct auth4_context *auth_context;
	struct auth_session_info *session_info;
	struct pac_data *pac_data;

	TALLOC_CTX *tmp_ctx = talloc_new(tctx);
	torture_assert(tctx, tmp_ctx != NULL, "talloc_new() failed");

	auth_context = talloc_zero(tmp_ctx, struct auth4_context);
	torture_assert(tctx, auth_context != NULL, "talloc_new() failed");

	auth_context->generate_session_info_pac = test_generate_session_info_pac;

	status = gensec_client_start(tctx, &gensec_client_context,
				     lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok(tctx, status, "gensec_client_start (client) failed");

	status = gensec_set_target_hostname(gensec_client_context, cli_credentials_get_workstation(cmdline_credentials));
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_target_hostname (client) failed");

	status = gensec_set_credentials(gensec_client_context, cmdline_credentials);
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_credentials (client) failed");

	status = gensec_start_mech_by_sasl_name(gensec_client_context, "GSSAPI");
	torture_assert_ntstatus_ok(tctx, status, "gensec_start_mech_by_sasl_name (client) failed");

	status = gensec_server_start(tctx,
				     lpcfg_gensec_settings(tctx, tctx->lp_ctx),
				     auth_context, &gensec_server_context);
	torture_assert_ntstatus_ok(tctx, status, "gensec_server_start (server) failed");

	status = gensec_set_credentials(gensec_server_context, cmdline_credentials);
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_credentials (server) failed");

	status = gensec_start_mech_by_sasl_name(gensec_server_context, "GSSAPI");
	torture_assert_ntstatus_ok(tctx, status, "gensec_start_mech_by_sasl_name (server) failed");

	server_to_client = data_blob(NULL, 0);
	
	do {
		/* Do a client-server update dance */
		status = gensec_update(gensec_client_context, tmp_ctx, tctx->ev, server_to_client, &client_to_server);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {;
			torture_assert_ntstatus_ok(tctx, status, "gensec_update (client) failed");
		}

		status = gensec_update(gensec_server_context, tmp_ctx, tctx->ev, client_to_server, &server_to_client);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {;
			torture_assert_ntstatus_ok(tctx, status, "gensec_update (server) failed");
		}

		if (NT_STATUS_IS_OK(status)) {
			break;
		}
	} while (1);

	/* Extract the PAC using Samba's code */

	status = gensec_session_info(gensec_server_context, gensec_server_context, &session_info);
	torture_assert_ntstatus_ok(tctx, status, "gensec_session_info failed");

	pac_data = talloc_get_type(auth_context->private_data, struct pac_data);

	torture_assert(tctx, pac_data != NULL, "gensec_update failed to fill in pac_data in auth_context");
	torture_assert(tctx, pac_data->pac_blob.data != NULL, "pac_blob not present");
	torture_decode_compare_pac(tctx, pac_data->pac_blob);

	return true;
}

NTSTATUS torture_winbind_init(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "winbind");

	torture_suite_add_suite(suite, torture_winbind_struct_init());
	torture_suite_add_suite(suite, torture_wbclient());
	torture_suite_add_simple_test(suite,
				      "pac", torture_winbind_pac);

	suite->description = talloc_strdup(suite, "WINBIND tests");

	torture_register_suite(suite);

	return NT_STATUS_OK;
}
