/*
   Unix SMB/CIFS implementation.

   Validate the krb5 pac generation routines

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2015

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
#include "system/kerberos.h"
#include "torture/smbtorture.h"
#include "torture/krb5/proto.h"
#include "auth/credentials/credentials.h"
#include "lib/cmdline/cmdline.h"
#include "source4/auth/kerberos/kerberos.h"
#include "lib/util/util_net.h"
#include "auth/auth.h"
#include "auth/gensec/gensec.h"
#include "param/param.h"

#undef strcasecmp

#define TEST_CANONICALIZE     0x0000001
#define TEST_ENTERPRISE       0x0000002
#define TEST_UPPER_USERNAME   0x0000004
#define TEST_UPN              0x0000008
#define TEST_REMOVEDOLLAR     0x0000010
#define TEST_AS_REQ_SPN       0x0000020
#define TEST_ALL              0x000003F

struct test_data {
	const char *test_name;
	const char *realm;
	const char *real_realm;
	const char *real_domain;
	const char *username;
	const char *real_username;
	bool canonicalize;
	bool enterprise;
	bool upper_username;
	bool upn;
	bool other_upn_suffix;
	bool removedollar;
	bool as_req_spn;
	bool spn_is_upn;
	const char *krb5_service;
	const char *krb5_hostname;
};

struct torture_krb5_context {
	struct smb_krb5_context *smb_krb5_context;
	struct torture_context *tctx;
	struct addrinfo *server;
};

struct pac_data {
	const char *principal_name;
};

/*
 * A helper function which avoids touching the local databases to
 * generate the session info, as we just want to verify the principal
 * name that we found in the ticket not the full local token
 */
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

	if (pac_blob == NULL) {
		DBG_ERR("pac_blob missing\n");
		return NT_STATUS_NO_IMPERSONATION_TOKEN;
	}

	tmp_ctx = talloc_named(mem_ctx, 0, "gensec_gssapi_session_info context");
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	auth_ctx->private_data = pac_data = talloc_zero(auth_ctx, struct pac_data);

	pac_data->principal_name = talloc_strdup(pac_data, principal_name);
	if (!pac_data->principal_name) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = kerberos_pac_blob_to_user_info_dc(tmp_ctx,
						      *pac_blob,
						      smb_krb5_context->krb5_context,
						      &user_info_dc, NULL, NULL);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	if (!(user_info_dc->info->user_flags & NETLOGON_GUEST)) {
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
	return NT_STATUS_OK;
}

/* Check to see if we can pass the PAC across to the NETLOGON server for validation */

/* Also happens to be a really good one-step verification of our Kerberos stack */

static bool test_accept_ticket(struct torture_context *tctx,
			       struct cli_credentials *credentials,
			       const char *principal,
			       DATA_BLOB client_to_server)
{
	NTSTATUS status;
	struct gensec_security *gensec_server_context;
	DATA_BLOB server_to_client;
	struct auth4_context *auth_context;
	struct auth_session_info *session_info;
	struct pac_data *pac_data;
	TALLOC_CTX *tmp_ctx = talloc_new(tctx);

	torture_assert(tctx, tmp_ctx != NULL, "talloc_new() failed");

	auth_context = talloc_zero(tmp_ctx, struct auth4_context);
	torture_assert(tctx, auth_context != NULL, "talloc_new() failed");

	auth_context->generate_session_info_pac = test_generate_session_info_pac;

	status = gensec_server_start(tctx,
				     lpcfg_gensec_settings(tctx, tctx->lp_ctx),
				     auth_context, &gensec_server_context);
	torture_assert_ntstatus_ok(tctx, status, "gensec_server_start (server) failed");

	status = gensec_set_credentials(gensec_server_context, credentials);
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_credentials (server) failed");

	status = gensec_start_mech_by_name(gensec_server_context, "krb5");
	torture_assert_ntstatus_ok(tctx, status, "gensec_start_mech_by_name (server) failed");

	server_to_client = data_blob(NULL, 0);

	/* Do a client-server update dance */
	status = gensec_update(gensec_server_context, tmp_ctx, client_to_server, &server_to_client);
	torture_assert_ntstatus_ok(tctx, status, "gensec_update (server) failed");

	/* Extract the PAC using Samba's code */

	status = gensec_session_info(gensec_server_context, gensec_server_context, &session_info);
	torture_assert_ntstatus_ok(tctx, status, "gensec_session_info failed");

	pac_data = talloc_get_type(auth_context->private_data, struct pac_data);

	torture_assert(tctx, pac_data != NULL, "gensec_update failed to fill in pac_data in auth_context");
	torture_assert(tctx, pac_data->principal_name != NULL, "principal_name not present");
	torture_assert_str_equal(tctx, pac_data->principal_name, principal, "wrong principal name");
	return true;
}

static int test_context_destructor(struct torture_krb5_context *test_context)
{
	freeaddrinfo(test_context->server);
	return 0;
}


static bool torture_krb5_init_context_canon(struct torture_context *tctx,
					     struct torture_krb5_context **torture_krb5_context)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	krb5_error_code k5ret;
	bool ok;

	struct torture_krb5_context *test_context = talloc_zero(tctx, struct torture_krb5_context);
	torture_assert(tctx, test_context != NULL, "Failed to allocate");

	test_context->tctx = tctx;

	k5ret = smb_krb5_init_context(test_context, tctx->lp_ctx, &test_context->smb_krb5_context);
	torture_assert_int_equal(tctx, k5ret, 0, "smb_krb5_init_context failed");

	ok = interpret_string_addr_internal(&test_context->server, host, AI_NUMERICHOST);
	torture_assert(tctx, ok, "Failed to parse target server");

	talloc_set_destructor(test_context, test_context_destructor);

	set_sockaddr_port(test_context->server->ai_addr, 88);

	*torture_krb5_context = test_context;
	return true;
}


static bool torture_krb5_as_req_canon(struct torture_context *tctx, const void *tcase_data)
{
	krb5_error_code k5ret;
	krb5_get_init_creds_opt *krb_options = NULL;
	struct test_data *test_data = talloc_get_type_abort(tcase_data, struct test_data);
	krb5_principal principal = NULL;
	krb5_principal canonical_principal = NULL;
	krb5_principal expected_principal = NULL;
	const char *principal_string = NULL;
	int principal_flags;
	const char *canonical_principal_string = NULL;
	const char *expected_principal_string = NULL;
	char *canonical_unparse_principal_string = NULL;
	char *expected_unparse_principal_string = NULL;
	int expected_principal_flags;
	char *got_principal_string = NULL;
	char *assertion_message = NULL;
	const char *password = cli_credentials_get_password(
			samba_cmdline_get_creds());
	krb5_context k5_context = NULL;
	struct torture_krb5_context *test_context = NULL;
	bool ok;
	krb5_creds my_creds;
	krb5_creds *server_creds = NULL;
	krb5_ccache ccache = NULL;
	krb5_auth_context auth_context = NULL;
	char *cc_name = NULL;
	krb5_data in_data, enc_ticket;

	bool require_canon = \
		lpcfg_kdc_require_canonicalization(tctx->lp_ctx);

	bool implicit_dollar_requires_canonicalize =
		!lpcfg_kdc_name_match_implicit_dollar_without_canonicalization(
			tctx->lp_ctx);
	bool krb5_acceptor_report_canonical_client_name =
		lpcfg_krb5_acceptor_report_canonical_client_name(tctx->lp_ctx);

	const char *spn = NULL;
	const char *spn_real_realm = NULL;
	const char *upn = torture_setting_string(tctx, "krb5-upn", "");
	test_data->krb5_service = torture_setting_string(tctx, "krb5-service", "host");
	test_data->krb5_hostname = torture_setting_string(tctx, "krb5-hostname", "");

	/*
	 * If we have not passed a UPN on the command line,
	 * then skip the UPN tests.
	 */
	if (test_data->upn && upn[0] == '\0') {
		torture_skip(tctx, "This test needs a UPN specified as --option=torture:krb5-upn=user@example.com to run");
	}

	/*
	 * If we have not passed a SPN on the command line,
	 * then skip the SPN tests.
	 */
	if (test_data->as_req_spn && test_data->krb5_hostname[0] == '\0') {
		torture_skip(tctx, "This test needs a hostname specified as --option=torture:krb5-hostname=hostname.example.com and optionally --option=torture:krb5-service=service (defaults to host) to run");
	}

	if (test_data->removedollar &&
	    !torture_setting_bool(tctx, "run_removedollar_test", false))
	{
		torture_skip(tctx, "--option=torture:run_removedollar_test=true not specified");
	}

	test_data->realm = test_data->real_realm;

	if (test_data->upn) {
		char *p;
		test_data->username = talloc_strdup(test_data, upn);
		p = strchr(test_data->username, '@');
		if (p) {
			*p = '\0';
			p++;
		}
		/*
		 * Test the UPN behaviour carefully.  We can
		 * test in two different modes, depending on
		 * what UPN has been set up for us.
		 *
		 * If the UPN is in our realm, then we do all the tests with this name also.
		 *
		 * If the UPN is not in our realm, then we
		 * expect the tests that replace the realm to
		 * fail (as it won't match)
		 */
		if (strcasecmp(p, test_data->real_realm) != 0) {
			test_data->other_upn_suffix = true;
		} else {
			test_data->other_upn_suffix = false;
		}

		/*
		 * This lets us test the combination of the UPN prefix
		 * with a valid domain, without adding even more
		 * combinations
		 */
		test_data->realm = p;
	}

	ok = torture_krb5_init_context_canon(tctx, &test_context);
	torture_assert(tctx, ok, "torture_krb5_init_context failed");
	k5_context = test_context->smb_krb5_context->krb5_context;

	test_data->realm = strupper_talloc(test_data, test_data->realm);
	if (test_data->upper_username) {
		test_data->username = strupper_talloc(test_data, test_data->username);
	} else {
		test_data->username = talloc_strdup(test_data, test_data->username);
	}

	if (test_data->removedollar) {
		char *p;

		p = strchr_m(test_data->username, '$');
		torture_assert(tctx, p != NULL, talloc_asprintf(tctx,
			       "username[%s] contains no '$'\n",
			       test_data->username));
		*p = '\0';
	}

	spn = talloc_asprintf(test_data, "%s/%s@%s",
			      test_data->krb5_service,
			      test_data->krb5_hostname,
			      test_data->realm);

	spn_real_realm = talloc_asprintf(test_data, "%s/%s@%s",
					 test_data->krb5_service,
					 test_data->krb5_hostname,
					 test_data->real_realm);

	if (!test_data->canonicalize && test_data->enterprise) {
		torture_skip(tctx,
			     "This test combination "
			     "is skipped intentionally");
	}

	if (test_data->as_req_spn) {
		if (test_data->enterprise) {
			torture_skip(tctx,
				     "This test combination "
				     "is skipped intentionally");
		}
		principal_string = spn;
	} else {
		principal_string = talloc_asprintf(test_data,
						   "%s@%s",
						   test_data->username,
						   test_data->realm);

	}

	test_data->spn_is_upn
		= (strcasecmp(upn, spn) == 0);

	if (test_data->as_req_spn && !test_data->spn_is_upn) {
		canonical_principal_string = spn;
	} else {
		canonical_principal_string = talloc_asprintf(
			test_data,
			"%s@%s",
			test_data->real_username,
			test_data->real_realm);
	}

	/*
	 * If we are set to canonicalize, we get back the fixed UPPER
	 * case realm, and the real username (ie matching LDAP
	 * samAccountName)
	 *
	 * Otherwise, if we are set to enterprise, we
	 * get back the whole principal as-sent
	 *
	 * Finally, if we are not set to canonicalize, we get back the
	 * fixed UPPER case realm, but the as-sent username
	 */
	if (test_data->as_req_spn && !test_data->spn_is_upn) {
		expected_principal_string = spn;
	} else if (test_data->canonicalize) {
		expected_principal_string = talloc_asprintf(test_data,
							    "%s@%s",
							    test_data->real_username,
							    test_data->real_realm);
	} else if (test_data->as_req_spn && test_data->spn_is_upn) {
		expected_principal_string = spn_real_realm;
	} else {
		expected_principal_string = talloc_asprintf(test_data,
							    "%s@%s",
							    test_data->username,
							    test_data->real_realm);
	}

	if (test_data->enterprise) {
		principal_flags = KRB5_PRINCIPAL_PARSE_ENTERPRISE;
	} else {
		if (test_data->upn && test_data->other_upn_suffix) {
			torture_skip(tctx, "UPN test for UPN with other UPN suffix only runs with enterprise principals");
		}
		principal_flags = 0;
	}

	if (test_data->canonicalize) {
		expected_principal_flags = 0;
	} else {
		expected_principal_flags = principal_flags;
	}

	torture_assert_int_equal(tctx,
				 krb5_parse_name_flags(k5_context,
						       principal_string,
						       principal_flags,
						       &principal),
					 0, "krb5_parse_name_flags failed");
	torture_assert_int_equal(tctx,
				 krb5_parse_name_flags(k5_context,
						       canonical_principal_string,
						       expected_principal_flags,
						       &canonical_principal),
				 0, "krb5_parse_name_flags failed");
	torture_assert_int_equal(tctx,
				 krb5_parse_name_flags(k5_context,
						       expected_principal_string,
						       expected_principal_flags,
						       &expected_principal),
				 0, "krb5_parse_name_flags failed");

	if (test_data->as_req_spn) {
		if (test_data->upn) {
			smb_krb5_principal_set_type(k5_context,
						    principal,
						    KRB5_NT_PRINCIPAL);
			smb_krb5_principal_set_type(k5_context,
						    canonical_principal,
						    KRB5_NT_PRINCIPAL);
			smb_krb5_principal_set_type(k5_context,
						    expected_principal,
						    KRB5_NT_PRINCIPAL);
		} else {
			smb_krb5_principal_set_type(k5_context,
						    principal,
						    KRB5_NT_SRV_HST);
			smb_krb5_principal_set_type(k5_context,
						    canonical_principal,
						    KRB5_NT_SRV_HST);
			smb_krb5_principal_set_type(k5_context,
						    expected_principal,
						    KRB5_NT_SRV_HST);
		}
	}

	torture_assert_int_equal(tctx,
				 krb5_unparse_name(k5_context,
						   canonical_principal,
						   &canonical_unparse_principal_string),
				 0, "krb5_unparse_name failed");
	torture_assert_int_equal(tctx,
				 krb5_unparse_name(k5_context,
						   expected_principal,
						   &expected_unparse_principal_string),
				 0, "krb5_unparse_name failed");
	/*
	 * Prepare a AS-REQ and run the TEST_AS_REQ tests
	 *
	 */

	/*
	 * Set the canonicalize flag if this test requires it
	 */
	torture_assert_int_equal(tctx,
				 krb5_get_init_creds_opt_alloc(k5_context, &krb_options),
				 0, "krb5_get_init_creds_opt_alloc failed");

	krb5_get_init_creds_opt_set_canonicalize(krb_options,
						 test_data->canonicalize);

	k5ret = krb5_get_init_creds_password(k5_context, &my_creds, principal,
					     password, NULL, NULL, 0,
					     NULL, krb_options);

	if (test_data->as_req_spn
		   && !test_data->spn_is_upn) {
		torture_assert_int_equal(tctx, k5ret,
					 KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN,
					 "Got wrong error_code from "
					 "krb5_get_init_creds_password");
		/* We can't proceed with more checks */
		return true;
	} else if (implicit_dollar_requires_canonicalize &&
		   test_data->removedollar && !test_data->canonicalize)
	{
		/*
		 * We are trying to match "foo" to "foo$", but we the
		 * server is configured to not make that match without
		 * canonicalization.
		 */
		torture_assert_int_equal(tctx, k5ret,
					 KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN,
					 "Got wrong error_code from "
					 "krb5_get_init_creds_password "
					 "(with no implicit dollar config)");
		return true;
	} else if (require_canon && !test_data->canonicalize) {
		/*
		 * The server is requiring canonicalization, and we are not
		 * using it. This should always fail.
		 */
		torture_assert_int_equal(tctx,
					 k5ret,
					 KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN,
					 "Principal should not match with "
					 "'require canonicalization = yes' "
					 "when canonicalization is not used.");
		return true;
	} else {
		assertion_message = talloc_asprintf(tctx,
						    "krb5_get_init_creds_password for %s failed: %s",
						    principal_string,
						    smb_get_krb5_error_message(k5_context, k5ret, tctx));
		torture_assert_int_equal(tctx, k5ret, 0, assertion_message);
	}

	/*
	 * Assert that the reply was with the correct type of
	 * principal, depending on the flags we set
	 */
	if (!test_data->canonicalize && test_data->as_req_spn) {
		torture_assert_int_equal(tctx,
					 smb_krb5_principal_get_type(
						 k5_context, my_creds.client),
					 KRB5_NT_SRV_HST,
					 "smb_krb5_init_context gave incorrect "
					 "client->name.name_type");
	} else {
		torture_assert_int_equal(tctx,
					 smb_krb5_principal_get_type(
						 k5_context, my_creds.client),
					 KRB5_NT_PRINCIPAL,
					 "smb_krb5_init_context gave incorrect "
					 "client->name.name_type");
	}

	torture_assert_int_equal(tctx,
				 krb5_unparse_name(k5_context,
						   my_creds.client, &got_principal_string), 0,
				 "krb5_unparse_name failed");

	assertion_message = talloc_asprintf(tctx,
					    "krb5_get_init_creds_password returned a different principal %s to what was expected %s",
					    got_principal_string, expected_principal_string);
	krb5_free_unparsed_name(k5_context, got_principal_string);

	torture_assert(tctx, krb5_principal_compare(k5_context,
						    my_creds.client, expected_principal),
		       assertion_message);

	torture_assert_int_equal(
		tctx,
		smb_krb5_principal_get_type(k5_context, my_creds.server),
		KRB5_NT_SRV_INST,
		"smb_krb5_init_context gave incorrect server->name.name_type");

	torture_assert_int_equal(tctx,
				 krb5_princ_size(k5_context, my_creds.server),
				 2,
				 "smb_krb5_init_context gave incorrect number "
				 "of components in my_creds.server->name");

	{
		char *princ_component = NULL;

		torture_assert_int_equal(
			tctx,
			smb_krb5_principal_get_comp_string(test_data,
							   k5_context,
							   my_creds.server,
							   0,
							   &princ_component),
			0,
			"smb_krb5_principal_get_comp_string failed");
		torture_assert_str_equal(
			tctx,
			princ_component,
			"krbtgt",
			"smb_krb5_init_context gave incorrect "
			"my_creds.server->name.name_string[0]");

		if (test_data->canonicalize) {
			torture_assert_int_equal(
				tctx,
				smb_krb5_principal_get_comp_string(
					test_data,
					k5_context,
					my_creds.server,
					1,
					&princ_component),
				0,
				"smb_krb5_principal_get_comp_string failed");
			torture_assert_str_equal(
				tctx,
				princ_component,
				test_data->real_realm,
				"smb_krb5_init_context gave incorrect "
				"my_creds.server->name.name_string[1]");
		} else {
			torture_assert_int_equal(
				tctx,
				smb_krb5_principal_get_comp_string(
					test_data,
					k5_context,
					my_creds.server,
					1,
					&princ_component),
				0,
				"smb_krb5_principal_get_comp_string failed");
			torture_assert_str_equal(
				tctx,
				princ_component,
				test_data->realm,
				"smb_krb5_init_context gave incorrect "
				"my_creds.server->name.name_string[1]");
		}
	}

	torture_assert_str_equal(
		tctx,
		smb_krb5_principal_get_realm(test_data,
					     k5_context,
					     my_creds.server),
		test_data->real_realm,
		"smb_krb5_init_context gave incorrect my_creds.server->realm");

	/* Store the result of the 'kinit' above into a memory ccache */
	cc_name = talloc_asprintf(tctx, "MEMORY:%s", test_data->test_name);
	torture_assert_int_equal(tctx, krb5_cc_resolve(k5_context, cc_name,
						       &ccache),
				 0, "krb5_cc_resolve failed");

	torture_assert_int_equal(tctx, krb5_cc_initialize(k5_context,
							  ccache, my_creds.client),
				 0, "krb5_cc_initialize failed");

	torture_assert_int_equal(tctx, krb5_cc_store_cred(k5_context,
							  ccache, &my_creds),
				 0, "krb5_cc_store_cred failed");

	/*
	 * Prepare a TGS-REQ and run the TEST_TGS_REQ_KRBTGT_CANON tests
	 *
	 * This tests krb5_get_creds behaviour, which allows us to set
	 * the KRB5_GC_CANONICALIZE option against the krbtgt/ principal
	 */

	/* Confirm if we can get a ticket to our own name */
	k5ret = krb5_get_credentials(k5_context,
				     KRB5_GC_NO_STORE | KRB5_GC_CANONICALIZE,
				     ccache,
				     &my_creds,
				     &server_creds);

	/*
	 * In these situations, the code above does not store a
	 * principal in the credentials cache matching what
	 * krb5_get_creds() needs, so the test fails.
	 *
	 */
	assertion_message = talloc_asprintf(
		tctx,
		"krb5_get_creds for %s failed: %s",
		principal_string,
		smb_get_krb5_error_message(k5_context, k5ret, tctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);
	torture_assert_int_equal(tctx,
				 krb5_cc_store_cred(k5_context,
						    ccache,
						    server_creds),
				 0,
				 "krb5_cc_store_cred failed");

	krb5_free_creds(k5_context, server_creds);

	/*
	 * Confirm getting a ticket to pass to the server, running
	 * either the TEST_TGS_REQ or TEST_SELF_TRUST_TGS_REQ stage.
	 *
	 * This triggers the client to attempt to get a
	 * cross-realm ticket between the alternate names of
	 * the server, and we need to confirm that behaviour.
	 *
	 */

	torture_assert_int_equal(tctx, krb5_auth_con_init(k5_context, &auth_context),
				 0, "krb5_auth_con_init failed");

	in_data = (krb5_data){};

	{
		krb5_creds *credsp = NULL;
		krb5_creds creds = {};

		torture_assert_int_equal(tctx,
					 krb5_copy_principal(k5_context,
							     principal,
							     &creds.server),
					 0,
					 "krb5_copy_principal failed");
		torture_assert_int_equal(tctx,
					 krb5_cc_get_principal(k5_context,
							       ccache,
							       &creds.client),
					 0,
					 "krb5_cc_get_principal failed");


		/*
		 * Only machine accounts (strictly, accounts with a
		 * servicePrincipalName) can expect this test to succeed
		 */
		if (torture_setting_bool(tctx, "expect_machine_account", false)
		    && (test_data->enterprise
			|| test_data->spn_is_upn
			|| !test_data->upn)) {
			torture_assert_int_equal(
				tctx,
				krb5_get_credentials(
					k5_context, 0, ccache, &creds, &credsp),
				0,
				"krb5_get_credentials failed");
		} else {
			torture_assert_int_equal(
				tctx,
				krb5_get_credentials(
					k5_context, 0, ccache, &creds, &credsp),
				KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN,
				"krb5_get_credentials failed");
		return true;
		}

		k5ret = krb5_mk_req_extended(k5_context,
					     &auth_context,
					     AP_OPTS_USE_SUBKEY,
					     &in_data,
					     credsp,
					     &enc_ticket);
		krb5_free_creds(k5_context, credsp);
		krb5_free_cred_contents(k5_context, &creds);
	}

	assertion_message = talloc_asprintf(tctx,
					    "krb5_mk_req_extended for %s failed: %s",
					    principal_string,
					    smb_get_krb5_error_message(k5_context, k5ret, tctx));

	/*
	 * Only machine accounts (strictly, accounts with a
	 * servicePrincipalName) can expect this test to succeed
	 */
	if (torture_setting_bool(tctx, "expect_machine_account", false)
	    && (test_data->enterprise ||
		(test_data->as_req_spn
		 || test_data->spn_is_upn)
		|| !test_data->upn)) {
		DATA_BLOB client_to_server;
		torture_assert_int_equal(tctx, k5ret, 0, assertion_message);
		client_to_server = data_blob_const(enc_ticket.data, enc_ticket.length);

		if (krb5_acceptor_report_canonical_client_name) {
			torture_assert(tctx,
				       test_accept_ticket(tctx,
							  samba_cmdline_get_creds(),
							  canonical_unparse_principal_string,
							  client_to_server),
				       "test_accept_ticket failed - failed to accept the ticket we just created");
		} else {
			torture_assert(tctx,
				       test_accept_ticket(tctx,
							  samba_cmdline_get_creds(),
							  expected_unparse_principal_string,
							  client_to_server),
				       "test_accept_ticket failed - failed to accept the ticket we just created");
		}
		krb5_free_data_contents(k5_context, &enc_ticket);
	} else {
		torture_assert_int_equal(tctx, k5ret, KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN,
					 assertion_message);
	}

	krb5_free_principal(k5_context, principal);
	krb5_get_init_creds_opt_free(k5_context, krb_options);

	krb5_free_cred_contents(k5_context, &my_creds);

	return true;
}

struct torture_suite *torture_krb5_canon_mit(TALLOC_CTX *mem_ctx)
{
	unsigned int i;
	struct torture_suite *suite = torture_suite_create(mem_ctx, "canon");
	suite->description = talloc_strdup(suite, "Kerberos Canonicalisation tests");

	for (i = 0; i < TEST_ALL; i++) {
		char *name = talloc_asprintf(suite, "%s.%s.%s.%s",
					     (i & TEST_CANONICALIZE) ? "canon" : "no-canon",
					     (i & TEST_ENTERPRISE) ? "enterprise" : "no-enterprise",
					     (i & TEST_UPPER_USERNAME) ? "uc-user" : "lc-user",
					     (i & TEST_UPN) ? "upn" :
					     ((i & TEST_AS_REQ_SPN) ? "spn" :
					      ((i & TEST_REMOVEDOLLAR) ? "removedollar" : "samaccountname")));
		struct torture_suite *sub_suite = torture_suite_create(mem_ctx, name);

		struct test_data *test_data = talloc_zero(suite, struct test_data);
		if (i & TEST_UPN) {
			if (i & TEST_AS_REQ_SPN) {
				continue;
			}
		}
		if ((i & TEST_UPN) || (i & TEST_AS_REQ_SPN)) {
			if (i & TEST_REMOVEDOLLAR) {
				continue;
			}
		}

		test_data->test_name = name;
		test_data->real_realm
			= strupper_talloc(test_data,
				cli_credentials_get_realm(
					samba_cmdline_get_creds()));
		test_data->real_domain = cli_credentials_get_domain(
						samba_cmdline_get_creds());
		test_data->username = cli_credentials_get_username(
						samba_cmdline_get_creds());
		test_data->real_username = cli_credentials_get_username(
						samba_cmdline_get_creds());
		test_data->canonicalize = (i & TEST_CANONICALIZE) != 0;
		test_data->enterprise = (i & TEST_ENTERPRISE) != 0;
		test_data->upper_username = (i & TEST_UPPER_USERNAME) != 0;
		test_data->upn = (i & TEST_UPN) != 0;
		test_data->removedollar = (i & TEST_REMOVEDOLLAR) != 0;
		test_data->as_req_spn = (i & TEST_AS_REQ_SPN) != 0;
		torture_suite_add_simple_tcase_const(sub_suite, name, torture_krb5_as_req_canon,
						     test_data);
		torture_suite_add_suite(suite, sub_suite);

	}
	return suite;
}
