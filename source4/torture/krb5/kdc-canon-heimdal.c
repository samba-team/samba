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
#include "source4/auth/kerberos/kerberos_util.h"
#include "lib/util/util_net.h"
#include "auth/auth.h"
#include "auth/auth_sam_reply.h"
#include "auth/gensec/gensec.h"
#include "param/param.h"

#undef strcasecmp

#define TEST_CANONICALIZE     0x0000001
#define TEST_ENTERPRISE       0x0000002
#define TEST_UPPER_USERNAME   0x0000004
#define TEST_WIN2K            0x0000008
#define TEST_UPN              0x0000010
#define TEST_S4U2SELF         0x0000020
#define TEST_REMOVEDOLLAR     0x0000040
#define TEST_AS_REQ_SPN       0x0000080
#define TEST_ALL              0x00000FF

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
	bool win2k;
	bool upn;
	bool other_upn_suffix;
	bool s4u2self;
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
	struct test_data *test_data;
	int packet_count;
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

/*
 * This function is set in torture_krb5_init_context_canon as krb5
 * send_and_recv function.  This allows us to override what server the
 * test is aimed at, and to inspect the packets just before they are
 * sent to the network, and before they are processed on the recv
 * side.
 *
 */
static krb5_error_code test_krb5_send_to_realm_canon_override(struct smb_krb5_context *smb_krb5_context,
							      void *data, /* struct torture_krb5_context */
							      krb5_const_realm realm,
							      time_t timeout,
							      const krb5_data *send_buf,
							      krb5_data *recv_buf)
{
	krb5_error_code k5ret;

	struct torture_krb5_context *test_context
		= talloc_get_type_abort(data, struct torture_krb5_context);

	SMB_ASSERT(smb_krb5_context == test_context->smb_krb5_context);

	k5ret = smb_krb5_send_and_recv_func_forced_tcp(smb_krb5_context,
						       test_context->server,
						       timeout,
						       send_buf,
						       recv_buf);
	if (k5ret != 0) {
		return k5ret;
	}

	test_context->packet_count++;

	return k5ret;
}

static int test_context_destructor(struct torture_krb5_context *test_context)
{
	freeaddrinfo(test_context->server);
	return 0;
}


static bool torture_krb5_init_context_canon(struct torture_context *tctx,
					     struct test_data *test_data,
					     struct torture_krb5_context **torture_krb5_context)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	krb5_error_code k5ret;
	bool ok;

	struct torture_krb5_context *test_context = talloc_zero(tctx, struct torture_krb5_context);
	torture_assert(tctx, test_context != NULL, "Failed to allocate");

	test_context->test_data = test_data;
	test_context->tctx = tctx;

	k5ret = smb_krb5_init_context(test_context, tctx->lp_ctx, &test_context->smb_krb5_context);
	torture_assert_int_equal(tctx, k5ret, 0, "smb_krb5_init_context failed");

	ok = interpret_string_addr_internal(&test_context->server, host, AI_NUMERICHOST);
	torture_assert(tctx, ok, "Failed to parse target server");

	talloc_set_destructor(test_context, test_context_destructor);

	set_sockaddr_port(test_context->server->ai_addr, 88);

	k5ret = smb_krb5_set_send_to_kdc_func(test_context->smb_krb5_context,
					      test_krb5_send_to_realm_canon_override,
					      NULL, /* send_to_kdc */
					      test_context);
	torture_assert_int_equal(tctx, k5ret, 0, "krb5_set_send_to_kdc_func failed");
	*torture_krb5_context = test_context;
	return true;
}


static bool torture_krb5_as_req_canon(struct torture_context *tctx, const void *tcase_data)
{
	krb5_error_code k5ret;
	krb5_get_init_creds_opt *krb_options = NULL;
	struct test_data *test_data = talloc_get_type_abort(tcase_data, struct test_data);
	krb5_principal principal;
	krb5_principal krbtgt_other;
	krb5_principal expected_principal;
	const char *principal_string = NULL;
	char *krbtgt_other_string;
	int principal_flags;
	const char *expected_principal_string = NULL;
	char *expected_unparse_principal_string;
	int expected_principal_flags;
	char *got_principal_string;
	char *assertion_message;
	const char *password = cli_credentials_get_password(
			samba_cmdline_get_creds());
	krb5_context k5_context;
	struct torture_krb5_context *test_context;
	bool ok;
	krb5_creds my_creds;
	krb5_creds *server_creds;
	krb5_ccache ccache;
	krb5_auth_context auth_context;
	char *cc_name;
	krb5_data in_data, enc_ticket;
	krb5_get_creds_opt opt;

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

	ok = torture_krb5_init_context_canon(tctx, test_data, &test_context);
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
						       expected_principal_string,
						       expected_principal_flags,
						       &expected_principal),
				 0, "krb5_parse_name_flags failed");
	
	if (test_data->as_req_spn) {
		if (test_data->upn) {
			krb5_principal_set_type(k5_context,
						principal,
						KRB5_NT_PRINCIPAL);
			krb5_principal_set_type(k5_context,
						expected_principal,
						KRB5_NT_PRINCIPAL);
		} else {
			krb5_principal_set_type(k5_context,
						principal,
						KRB5_NT_SRV_HST);
			krb5_principal_set_type(k5_context,
						expected_principal,
						KRB5_NT_SRV_HST);
		}
	}
	
	torture_assert_int_equal(tctx,
				 krb5_unparse_name(k5_context,
						   expected_principal,
						   &expected_unparse_principal_string),
				 0, "krb5_unparse_name failed");
	/*
	 * Prepare a AS-REQ and run the TEST_AS_REQ tests
	 *
	 */

	test_context->packet_count = 0;

	/*
	 * Set the canonicalize flag if this test requires it
	 */
	torture_assert_int_equal(tctx,
				 krb5_get_init_creds_opt_alloc(k5_context, &krb_options),
				 0, "krb5_get_init_creds_opt_alloc failed");

	torture_assert_int_equal(tctx,
				 krb5_get_init_creds_opt_set_canonicalize(k5_context,
									  krb_options,
									  test_data->canonicalize),
				 0, "krb5_get_init_creds_opt_set_canonicalize failed");

	torture_assert_int_equal(tctx,
				 krb5_get_init_creds_opt_set_win2k(k5_context,
								   krb_options,
								   test_data->win2k),
				 0, "krb5_get_init_creds_opt_set_win2k failed");

	k5ret = krb5_get_init_creds_password(k5_context, &my_creds, principal,
					     password, NULL, NULL, 0,
					     NULL, krb_options);

	if (test_context->test_data->as_req_spn
		   && !test_context->test_data->spn_is_upn) {
		torture_assert_int_equal(tctx, k5ret,
					 KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN,
					 "Got wrong error_code from "
					 "krb5_get_init_creds_password");
		/* We can't proceed with more checks */
		return true;
	} else {
		assertion_message = talloc_asprintf(tctx,
						    "krb5_get_init_creds_password for %s failed: %s",
						    principal_string,
						    smb_get_krb5_error_message(k5_context, k5ret, tctx));
		torture_assert_int_equal(tctx, k5ret, 0, assertion_message);
	}

	torture_assert(tctx,
		       test_context->packet_count > 1,
		       "Expected krb5_get_init_creds_password to send more packets");

	/*
	 * Assert that the reply was with the correct type of
	 * principal, depending on the flags we set
	 */
	if (test_data->canonicalize == false && test_data->as_req_spn) {
		torture_assert_int_equal(tctx,
					 krb5_principal_get_type(k5_context,
								 my_creds.client),
					 KRB5_NT_SRV_HST,
					 "smb_krb5_init_context gave incorrect client->name.name_type");
	} else {
		torture_assert_int_equal(tctx,
					 krb5_principal_get_type(k5_context,
								 my_creds.client),
					 KRB5_NT_PRINCIPAL,
					 "smb_krb5_init_context gave incorrect client->name.name_type");
	}

	torture_assert_int_equal(tctx,
				 krb5_unparse_name(k5_context,
						   my_creds.client, &got_principal_string), 0,
				 "krb5_unparse_name failed");

	assertion_message = talloc_asprintf(tctx,
					    "krb5_get_init_creds_password returned a different principal %s to what was expected %s",
					    got_principal_string, expected_principal_string);
	krb5_xfree(got_principal_string);

	torture_assert(tctx, krb5_principal_compare(k5_context,
						    my_creds.client, expected_principal),
		       assertion_message);


	torture_assert_int_equal(tctx,
				 krb5_principal_get_type(k5_context,
							 my_creds.server), KRB5_NT_SRV_INST,
				 "smb_krb5_init_context gave incorrect server->name.name_type");

	torture_assert_int_equal(tctx,
				 krb5_principal_get_num_comp(k5_context,
							     my_creds.server), 2,
				 "smb_krb5_init_context gave incorrect number of components in my_creds.server->name");

	torture_assert_str_equal(tctx,
				 krb5_principal_get_comp_string(k5_context,
								my_creds.server, 0),
				 "krbtgt",
				 "smb_krb5_init_context gave incorrect my_creds.server->name.name_string[0]");

	if (test_data->canonicalize) {
		torture_assert_str_equal(tctx,
					 krb5_principal_get_comp_string(k5_context,
									my_creds.server, 1),
					 test_data->real_realm,

					 "smb_krb5_init_context gave incorrect my_creds.server->name.name_string[1]");
	} else {
		torture_assert_str_equal(tctx,
					 krb5_principal_get_comp_string(k5_context,
									my_creds.server, 1),
					 test_data->realm,

					 "smb_krb5_init_context gave incorrect my_creds.server->name.name_string[1]");
	}
	torture_assert_str_equal(tctx,
				 krb5_principal_get_realm(k5_context,
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

	krbtgt_other_string = talloc_asprintf(test_data, "krbtgt/%s@%s", test_data->real_domain, test_data->real_realm);
	torture_assert_int_equal(tctx,
				 krb5_make_principal(k5_context, &krbtgt_other,
						     test_data->real_realm, "krbtgt",
						     test_data->real_domain, NULL),
				 0, "krb5_make_principal failed");

	test_context->packet_count = 0;

	torture_assert_int_equal(tctx,
				 krb5_get_creds_opt_alloc(k5_context, &opt),
				 0, "krb5_get_creds_opt_alloc");

	krb5_get_creds_opt_add_options(k5_context,
				       opt,
				       KRB5_GC_CANONICALIZE);

	krb5_get_creds_opt_add_options(k5_context,
				       opt,
				       KRB5_GC_NO_STORE);

	/* Confirm if we can get a ticket krbtgt/realm that we got back with the initial kinit */
	k5ret = krb5_get_creds(k5_context, opt, ccache, krbtgt_other, &server_creds);

	{
		/*
		 * In these situations, the code above does not store a
		 * principal in the credentials cache matching what
		 * krb5_get_creds() needs without talking to the KDC, so the
		 * test fails with looping detected because when we set
		 * canonicalize we confuse the client libs.
		 *
		 */
		assertion_message = talloc_asprintf(tctx,
						    "krb5_get_creds for %s should have failed with looping detected: %s",
						    krbtgt_other_string,
						    smb_get_krb5_error_message(k5_context, k5ret,
									       tctx));

		torture_assert_int_equal(tctx, k5ret, KRB5_GET_IN_TKT_LOOP, assertion_message);
		torture_assert_int_equal(tctx,
					 test_context->packet_count,
					 2, "Expected krb5_get_creds to send packets");
	}

	/*
	 * Prepare a TGS-REQ and run the TEST_TGS_REQ_CANON tests
	 *
	 * This tests krb5_get_creds behaviour, which allows us to set
	 * the KRB5_GC_CANONICALIZE option
	 */

	test_context->packet_count = 0;

	torture_assert_int_equal(tctx,
				 krb5_get_creds_opt_alloc(k5_context, &opt),
				 0, "krb5_get_creds_opt_alloc");

	krb5_get_creds_opt_add_options(k5_context,
				       opt,
				       KRB5_GC_CANONICALIZE);

	krb5_get_creds_opt_add_options(k5_context,
				       opt,
				       KRB5_GC_NO_STORE);

	if (test_data->s4u2self) {
		torture_assert_int_equal(tctx,
					 krb5_get_creds_opt_set_impersonate(k5_context,
									    opt,
									    principal),
					 0, "krb5_get_creds_opt_set_impersonate failed");
	}

	/* Confirm if we can get a ticket to our own name */
	k5ret = krb5_get_creds(k5_context, opt, ccache, principal, &server_creds);

	/*
	 * In these situations, the code above does not store a
	 * principal in the credentials cache matching what
	 * krb5_get_creds() needs, so the test fails.
	 *
	 */
	{
		assertion_message = talloc_asprintf(tctx,
						    "krb5_get_creds for %s failed: %s",
						    principal_string,
						    smb_get_krb5_error_message(k5_context, k5ret,
									       tctx));

		/*
		 * Only machine accounts (strictly, accounts with a
		 * servicePrincipalName) can expect this test to succeed
		 */
		if (torture_setting_bool(tctx, "expect_machine_account", false)
		    && (test_data->enterprise
			|| test_data->spn_is_upn
			|| test_data->upn == false)) {
			torture_assert_int_equal(tctx, k5ret, 0, assertion_message);
			torture_assert_int_equal(tctx, krb5_cc_store_cred(k5_context,
									  ccache, server_creds),
						 0, "krb5_cc_store_cred failed");

			torture_assert_int_equal(tctx,
						 krb5_free_creds(k5_context,
								 server_creds),
						 0, "krb5_free_cred_contents failed");

			torture_assert_int_equal(tctx,
						 test_context->packet_count,
						 1, "Expected krb5_get_creds to send one packet");

		} else {
			torture_assert_int_equal(tctx, k5ret, KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN,
						 assertion_message);
			/* Account for get_cred_kdc_capath() and get_cred_kdc_referral() fallback */
			torture_assert_int_equal(tctx,
						 test_context->packet_count,
						 2, "Expected krb5_get_creds to send 2 packets");
		}
	}

	/*
	 * Confirm getting a ticket to pass to the server, running
	 * either the TEST_TGS_REQ or TEST_SELF_TRUST_TGS_REQ stage.
	 *
	 * This triggers the client to attempt to get a
	 * cross-realm ticket between the alternate names of
	 * the server, and we need to confirm that behaviour.
	 *
	 */

	test_context->packet_count = 0;
	torture_assert_int_equal(tctx, krb5_auth_con_init(k5_context, &auth_context),
				 0, "krb5_auth_con_init failed");

	in_data.length = 0;
	k5ret = krb5_mk_req_exact(k5_context,
				  &auth_context,
				  AP_OPTS_USE_SUBKEY,
				  principal,
				  &in_data, ccache,
				  &enc_ticket);
	assertion_message = talloc_asprintf(tctx,
					    "krb5_mk_req_exact for %s failed: %s",
					    principal_string,
					    smb_get_krb5_error_message(k5_context, k5ret, tctx));

	/*
	 * Only machine accounts (strictly, accounts with a
	 * servicePrincipalName) can expect this test to succeed
	 */
	if (torture_setting_bool(tctx, "expect_machine_account", false)
	    && (test_data->enterprise ||
		(test_context->test_data->as_req_spn 
		 || test_context->test_data->spn_is_upn)
		|| test_data->upn == false)) {
		DATA_BLOB client_to_server;
		torture_assert_int_equal(tctx, k5ret, 0, assertion_message);
		client_to_server = data_blob_const(enc_ticket.data, enc_ticket.length);

		/* This is very weird */
		if (test_data->canonicalize == false
		    && test_context->test_data->as_req_spn
		    && test_context->test_data->spn_is_upn
		    && test_context->test_data->s4u2self) {
			
			torture_assert(tctx,
				       test_accept_ticket(tctx,
							  samba_cmdline_get_creds(),
							  spn_real_realm,
							  client_to_server),
				       "test_accept_ticket failed - failed to accept the ticket we just created");
		} else if (test_data->canonicalize == true
		    && test_context->test_data->as_req_spn
		    && test_context->test_data->spn_is_upn
		    && test_context->test_data->s4u2self) {
			
			torture_assert(tctx,
				       test_accept_ticket(tctx,
							  samba_cmdline_get_creds(),
							  expected_principal_string,
							  client_to_server),
				       "test_accept_ticket failed - failed to accept the ticket we just created");
		} else if (test_data->canonicalize == true
			   && test_data->enterprise == false
			   && test_context->test_data->upn
			   && test_context->test_data->spn_is_upn
			   && test_context->test_data->s4u2self) {
			
			torture_assert(tctx,
				       test_accept_ticket(tctx,
							  samba_cmdline_get_creds(),
							  expected_principal_string,
							  client_to_server),
				       "test_accept_ticket failed - failed to accept the ticket we just created");
		} else if (test_data->canonicalize == false
			   && test_context->test_data->upn
			   && test_context->test_data->spn_is_upn
			   && test_context->test_data->s4u2self) {
			
			const char *accept_expected_principal_string
				= talloc_asprintf(test_data,
						  "%s@%s",
						  test_data->username,
						  test_data->real_realm);
			
			torture_assert(tctx,
				       test_accept_ticket(tctx,
							  samba_cmdline_get_creds(),
							  accept_expected_principal_string,
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
		krb5_data_free(&enc_ticket);
	} else {
		torture_assert_int_equal(tctx, k5ret, KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN,
					 assertion_message);
	}

	/*
	 * Confirm getting a ticket to pass to the server, running
	 * the TEST_TGS_REQ_HOST, TEST_TGS_REQ_HOST_SRV_INST, TEST_TGS_REQ_HOST_SRV_HST stage
	 *
	 * This triggers the client to attempt to get a
	 * cross-realm ticket between the alternate names of
	 * the server, and we need to confirm that behaviour.
	 *
	 */

	if (*test_data->krb5_service && *test_data->krb5_hostname) {
		krb5_principal host_principal_srv_inst;
		/*
		 * This tries to guess when the krb5 libs will ask for a
		 * cross-realm ticket, and when they will just ask the KDC
		 * directly.
		 */
		test_context->packet_count = 0;
		torture_assert_int_equal(tctx, krb5_auth_con_init(k5_context, &auth_context),
					 0, "krb5_auth_con_init failed");

		in_data.length = 0;
		k5ret = krb5_mk_req(k5_context,
				    &auth_context,
				    0,
				    test_data->krb5_service,
				    test_data->krb5_hostname,
				    &in_data, ccache,
				    &enc_ticket);

		{
			assertion_message = talloc_asprintf(tctx,
							    "krb5_mk_req for %s/%s failed: %s",
							    test_data->krb5_service,
							    test_data->krb5_hostname,
							    smb_get_krb5_error_message(k5_context, k5ret, tctx));

			torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

			if (test_data->spn_is_upn == false) {
				/*
				 * Only in these cases would the above
				 * code have needed to send packets to
				 * the network
				 */
				torture_assert(tctx,
					       test_context->packet_count > 0,
					       "Expected krb5_get_creds to send packets");
			}
		}


		test_context->packet_count = 0;

		torture_assert_int_equal(tctx,
					 krb5_make_principal(k5_context, &host_principal_srv_inst,
							     test_data->real_realm,
							     strupper_talloc(tctx, test_data->krb5_service),
							     test_data->krb5_hostname,
							     NULL),
					 0, "krb5_make_principal failed");

		krb5_principal_set_type(k5_context, host_principal_srv_inst, KRB5_NT_SRV_INST);

		torture_assert_int_equal(tctx, krb5_auth_con_init(k5_context, &auth_context),
					 0, "krb5_auth_con_init failed");

		in_data.length = 0;
		k5ret = krb5_mk_req_exact(k5_context,
					  &auth_context,
					  0,
					  host_principal_srv_inst,
					  &in_data, ccache,
					  &enc_ticket);
		krb5_free_principal(k5_context, host_principal_srv_inst);
		{
			assertion_message = talloc_asprintf(tctx,
							    "krb5_mk_req for %s/%s KRB5_NT_SRV_INST failed: %s",
							    test_data->krb5_service,
							    test_data->krb5_hostname,
							    smb_get_krb5_error_message(k5_context, k5ret, tctx));

			torture_assert_int_equal(tctx, k5ret, 0, assertion_message);
			/*
			 * Only in these cases would the above code have needed to
			 * send packets to the network
			 */
			torture_assert(tctx,
				       test_context->packet_count > 0,
				       "Expected krb5_get_creds to send packets");
		}


		test_context->packet_count = 0;

		torture_assert_int_equal(tctx,
					 krb5_make_principal(k5_context, &host_principal_srv_inst,
							     test_data->real_realm,
							     test_data->krb5_service,
							     strupper_talloc(tctx, test_data->krb5_hostname),
							     NULL),
					 0, "krb5_make_principal failed");

		krb5_principal_set_type(k5_context, host_principal_srv_inst, KRB5_NT_SRV_HST);

		torture_assert_int_equal(tctx, krb5_auth_con_init(k5_context, &auth_context),
					 0, "krb5_auth_con_init failed");

		in_data.length = 0;
		k5ret = krb5_mk_req_exact(k5_context,
					  &auth_context,
					  0,
					  host_principal_srv_inst,
					  &in_data, ccache,
					  &enc_ticket);
		krb5_free_principal(k5_context, host_principal_srv_inst);
		{
			assertion_message = talloc_asprintf(tctx,
							    "krb5_mk_req for %s/%s KRB5_NT_SRV_INST failed: %s",
							    test_data->krb5_service,
							    test_data->krb5_hostname,
							    smb_get_krb5_error_message(k5_context, k5ret, tctx));

			torture_assert_int_equal(tctx, k5ret, 0, assertion_message);
			/*
			 * Only in these cases would the above code have needed to
			 * send packets to the network
			 */
			torture_assert(tctx,
				       test_context->packet_count > 0,
				       "Expected krb5_get_creds to send packets");
		}
	}

	/*
	 * Confirm getting a ticket for the same krbtgt/realm that we
	 * got back with the initial ticket, running the
	 * TEST_TGS_REQ_KRBTGT stage.
	 *
	 */

	test_context->packet_count = 0;

	in_data.length = 0;
	k5ret = krb5_mk_req_exact(k5_context,
				  &auth_context,
				  0,
				  my_creds.server,
				  &in_data, ccache,
				  &enc_ticket);

	assertion_message = talloc_asprintf(tctx,
					    "krb5_mk_req_exact for %s failed: %s",
					    principal_string,
					    smb_get_krb5_error_message(k5_context, k5ret, tctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	krb5_free_principal(k5_context, principal);
	krb5_get_init_creds_opt_free(k5_context, krb_options);

	torture_assert_int_equal(tctx, krb5_free_cred_contents(k5_context, &my_creds),
				 0, "krb5_free_cred_contents failed");

	return true;
}

struct torture_suite *torture_krb5_canon(TALLOC_CTX *mem_ctx)
{
	unsigned int i;
	struct torture_suite *suite = torture_suite_create(mem_ctx, "canon");
	suite->description = talloc_strdup(suite, "Kerberos Canonicalisation tests");

	for (i = 0; i < TEST_ALL; i++) {
		char *name = talloc_asprintf(suite, "%s.%s.%s.%s.%s.%s",
					     (i & TEST_CANONICALIZE) ? "canon" : "no-canon",
					     (i & TEST_ENTERPRISE) ? "enterprise" : "no-enterprise",
					     (i & TEST_UPPER_USERNAME) ? "uc-user" : "lc-user",
					     (i & TEST_WIN2K) ? "win2k" : "no-win2k",
					     (i & TEST_UPN) ? "upn" :
					     ((i & TEST_AS_REQ_SPN) ? "spn" : 
					      ((i & TEST_REMOVEDOLLAR) ? "removedollar" : "samaccountname")),
					     (i & TEST_S4U2SELF) ? "s4u2self" : "normal");
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
		test_data->win2k = (i & TEST_WIN2K) != 0;
		test_data->upn = (i & TEST_UPN) != 0;
		test_data->s4u2self = (i & TEST_S4U2SELF) != 0;
		test_data->removedollar = (i & TEST_REMOVEDOLLAR) != 0;
		test_data->as_req_spn = (i & TEST_AS_REQ_SPN) != 0;
		torture_suite_add_simple_tcase_const(sub_suite, name, torture_krb5_as_req_canon,
						     test_data);
		torture_suite_add_suite(suite, sub_suite);

	}
	return suite;
}
