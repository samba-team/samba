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
#include "lib/cmdline/popt_common.h"
#include "source4/auth/kerberos/kerberos.h"
#include "source4/auth/kerberos/kerberos_util.h"
#include "lib/util/util_net.h"

#define TEST_CANONICALIZE     0x0000001
#define TEST_ENTERPRISE       0x0000002
#define TEST_UPPER_REALM      0x0000004
#define TEST_UPPER_USERNAME   0x0000008
#define TEST_NETBIOS_REALM    0x0000010
#define TEST_ALL              0x000001F

struct test_data {
	struct smb_krb5_context *smb_krb5_context;
	const char *realm;
	const char *real_realm;
	const char *username;
	bool canonicalize;
	bool enterprise;
	bool upper_realm;
	bool upper_username;
};	
	
struct torture_krb5_context {
	struct torture_context *tctx;
	struct addrinfo *server;
	struct test_data *test_data;
	int packet_count;
	AS_REQ as_req;
	AS_REP as_rep;
};


/*
 * Confirm that the outgoing packet meets certain expectations.  This
 * should be extended to further assert the correct and expected
 * behaviour of the krb5 libs, so we know what we are sending to the
 * server.
 *
 * Additionally, this CHANGES the request to remove the canonicalize
 * flag automatically added by the krb5 libs when an enterprise
 * principal is used, so we can test what the server does in this
 * combination.
 *
 */

static bool torture_krb5_pre_send_test(struct torture_krb5_context *test_context, const krb5_data *send_buf, krb5_data *modified_send_buf)
{
	krb5_error_code k5ret;
	size_t used;
	torture_assert_int_equal(test_context->tctx,
				 decode_AS_REQ(send_buf->data, send_buf->length, &test_context->as_req, &used), 0,
				 "decode_AS_REQ failed");

	torture_assert_int_equal(test_context->tctx, used, send_buf->length, "length mismatch");
	torture_assert_int_equal(test_context->tctx, test_context->as_req.pvno, 5, "Got wrong as_req->pvno");
	if (test_context->test_data->canonicalize || test_context->test_data->enterprise) {
		torture_assert(test_context->tctx, test_context->as_req.req_body.kdc_options.canonicalize, "krb5 libs did not set canonicalize!");
	} else {
		torture_assert_int_equal(test_context->tctx, test_context->as_req.req_body.kdc_options.canonicalize, false, "krb5 libs unexpectedly set canonicalize!");
	}

	if (test_context->test_data->enterprise) {
		torture_assert_int_equal(test_context->tctx, test_context->as_req.req_body.cname->name_type, KRB5_NT_ENTERPRISE_PRINCIPAL, "krb5 libs did not pass principal as enterprise!");
	} else {
		torture_assert_int_equal(test_context->tctx, test_context->as_req.req_body.cname->name_type, KRB5_NT_PRINCIPAL, "krb5 libs unexpectedly set principal as enterprise!");
	}

	/* Force off canonicalize that was forced on by the krb5 libs */
	if (test_context->test_data->canonicalize == false && test_context->test_data->enterprise) {
		test_context->as_req.req_body.kdc_options.canonicalize = false;
	}

	ASN1_MALLOC_ENCODE(AS_REQ, modified_send_buf->data, modified_send_buf->length,
			   &test_context->as_req, &used, k5ret);
	torture_assert_int_equal(test_context->tctx,
				 k5ret, 0,
				 "encode_AS_REQ failed");
	torture_assert_int_equal(test_context->tctx, used, send_buf->length, "re-encode length mismatch");
	return true;
}

/*
 * Confirm that the incoming packet from the KDC meets certain
 * expectations.  This uses a packet count to work out what test we
 * are in, and where in the test we are, so we can assert on the
 * expected reply packets from the KDC.
 *
 */

static bool torture_krb5_post_recv_test(struct torture_krb5_context *test_context, const krb5_data *recv_buf)
{
	KRB_ERROR error;
	size_t used;
	if (test_context->packet_count == 0) {
		torture_assert_int_equal(test_context->tctx,
					 decode_KRB_ERROR(recv_buf->data, recv_buf->length, &error, &used), 0,
					 "decode_AS_REP failed");
		torture_assert_int_equal(test_context->tctx, used, recv_buf->length, "length mismatch");
		torture_assert_int_equal(test_context->tctx, error.pvno, 5, "Got wrong error.pvno");
		torture_assert_int_equal(test_context->tctx, error.error_code, KRB5KDC_ERR_PREAUTH_REQUIRED - KRB5KDC_ERR_NONE,
					 "Got wrong error.error_code");
		free_KRB_ERROR(&error);
	} else if ((decode_KRB_ERROR(recv_buf->data, recv_buf->length, &error, &used) == 0)
		   && (test_context->packet_count == 1)) {
		torture_assert_int_equal(test_context->tctx, used, recv_buf->length, "length mismatch");
		torture_assert_int_equal(test_context->tctx, error.pvno, 5, "Got wrong error.pvno");
		torture_assert_int_equal(test_context->tctx, error.error_code, KRB5KRB_ERR_RESPONSE_TOO_BIG - KRB5KDC_ERR_NONE,
					 "Got wrong error.error_code");
		free_KRB_ERROR(&error);
	} else {
		torture_assert_int_equal(test_context->tctx,
					 decode_AS_REP(recv_buf->data, recv_buf->length, &test_context->as_rep, &used), 0,
					 "decode_AS_REP failed");
		torture_assert_int_equal(test_context->tctx, used, recv_buf->length, "length mismatch");
		torture_assert_int_equal(test_context->tctx,
					 test_context->as_rep.pvno, 5,
					 "Got wrong as_rep->pvno");
		torture_assert_int_equal(test_context->tctx,
					 test_context->as_rep.ticket.tkt_vno, 5,
					 "Got wrong as_rep->ticket.tkt_vno");
		torture_assert(test_context->tctx,
			       test_context->as_rep.ticket.enc_part.kvno,
			       "Did not get a KVNO in test_context->as_rep.ticket.enc_part.kvno");
		if (torture_setting_bool(test_context->tctx, "expect_rodc", false)) {
			torture_assert_int_not_equal(test_context->tctx,
						     *test_context->as_rep.ticket.enc_part.kvno & 0xFFFF0000,
						     0, "Did not get a RODC number in the KVNO");
		} else {
			torture_assert_int_equal(test_context->tctx,
						 *test_context->as_rep.ticket.enc_part.kvno & 0xFFFF0000,
						 0, "Unexpecedly got a RODC number in the KVNO");
		}
		free_AS_REP(&test_context->as_rep);
	}
	torture_assert(test_context->tctx, test_context->packet_count < 3, "too many packets");
	free_AS_REQ(&test_context->as_req);
	return true;
}

/* 
 * This function is set in torture_krb5_init_context_canon as krb5
 * send_and_recv function.  This allows us to override what server the
 * test is aimed at, and to inspect the packets just before they are
 * sent to the network, and before they are processed on the recv
 * side.
 *
 * The torture_krb5_pre_send_test() and torture_krb5_post_recv_test()
 * functions are implement the actual tests.
 *
 * When this asserts, the caller will get a spurious 'cannot contact
 * any KDC' message.
 *
 */
static krb5_error_code smb_krb5_send_and_recv_func_canon_override(krb5_context context,
								   void *data, /* struct torture_krb5_context */
								   krb5_krbhst_info *hi,
								   time_t timeout,
								   const krb5_data *send_buf,
								   krb5_data *recv_buf)
{
	krb5_error_code k5ret;
	bool ok;
	krb5_data modified_send_buf;
	
	struct torture_krb5_context *test_context
		= talloc_get_type_abort(data, struct torture_krb5_context);

	ok = torture_krb5_pre_send_test(test_context, send_buf, &modified_send_buf);
	if (ok == false) {
		return EINVAL;
	}
	
	k5ret = smb_krb5_send_and_recv_func_forced(context, test_context->server,
						    hi, timeout, &modified_send_buf, recv_buf);

	ok = torture_krb5_post_recv_test(test_context, recv_buf);
	if (ok == false) {
		return EINVAL;
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
					     struct smb_krb5_context **smb_krb5_context)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	krb5_error_code k5ret;
	bool ok;

	struct torture_krb5_context *test_context = talloc_zero(tctx, struct torture_krb5_context);
	torture_assert(tctx, test_context != NULL, "Failed to allocate");

	test_context->test_data = test_data;
	test_context->tctx = tctx;
	
	k5ret = smb_krb5_init_context(tctx, tctx->lp_ctx, smb_krb5_context);
	torture_assert_int_equal(tctx, k5ret, 0, "smb_krb5_init_context failed");

	ok = interpret_string_addr_internal(&test_context->server, host, AI_NUMERICHOST);
	torture_assert(tctx, ok, "Failed to parse target server");

	talloc_set_destructor(test_context, test_context_destructor);
	
	set_sockaddr_port(test_context->server->ai_addr, 88);

	k5ret = krb5_set_send_to_kdc_func((*smb_krb5_context)->krb5_context,
					  smb_krb5_send_and_recv_func_canon_override,
					  test_context);
	torture_assert_int_equal(tctx, k5ret, 0, "krb5_set_send_to_kdc_func failed");
	return true;
}


static bool torture_krb5_as_req_canon(struct torture_context *tctx, const void *tcase_data)
{
	krb5_error_code k5ret;
	krb5_get_init_creds_opt *krb_options = NULL;
	struct test_data *test_data = talloc_get_type_abort(tcase_data, struct test_data);
	char *realm;
	char *upper_real_realm;
	char *username;
	krb5_principal principal;
	krb5_principal expected_principal;
	char *principal_string;
	int principal_flags;
	char *expected_principal_string;
	int expected_principal_flags;
	char *got_principal_string;
	char *assertion_message;
	const char *password = cli_credentials_get_password(cmdline_credentials);
	struct smb_krb5_context *smb_krb5_context;
	bool ok;
	krb5_creds my_creds;
	
	ok = torture_krb5_init_context_canon(tctx, test_data, &smb_krb5_context);
	torture_assert(tctx, ok, "torture_krb5_init_context failed");
	
	if (test_data->upper_realm) {
		realm = strupper_talloc(test_data, test_data->realm);
	} else {
		realm = strlower_talloc(test_data, test_data->realm);
	}
	if (test_data->upper_username) {
		username = strupper_talloc(test_data, test_data->username);
	} else {
		username = talloc_strdup(test_data, test_data->username);
	}

	principal_string = talloc_asprintf(test_data, "%s@%s", username, realm);
	
	upper_real_realm = strupper_talloc(test_data, test_data->real_realm);

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
	if (test_data->canonicalize) {
		expected_principal_string = talloc_asprintf(test_data, "%s@%s", test_data->username, upper_real_realm);
	} else if (test_data->enterprise) {
		expected_principal_string = principal_string;
	} else {
		expected_principal_string = talloc_asprintf(test_data, "%s@%s", username, upper_real_realm);
	}
	
	if (test_data->enterprise) {
		principal_flags = KRB5_PRINCIPAL_PARSE_ENTERPRISE;
	} else {
		principal_flags = 0;
	}

	if (test_data->canonicalize) {
		expected_principal_flags = 0;
	} else {
		expected_principal_flags = principal_flags;
	}

	torture_assert_int_equal(tctx,
				 krb5_parse_name_flags(smb_krb5_context->krb5_context,
						       principal_string,
						       principal_flags,
						       &principal),
					 0, "krb5_parse_name_flags failed");
	torture_assert_int_equal(tctx,
				 krb5_parse_name_flags(smb_krb5_context->krb5_context,
						       expected_principal_string,
						       expected_principal_flags,
						       &expected_principal),
				 0, "krb5_parse_name_flags failed");

	/* 
	 * Set the canonicalize flag if this test requires it
	 */
	torture_assert_int_equal(tctx,
				 krb5_get_init_creds_opt_alloc(smb_krb5_context->krb5_context, &krb_options),
				 0, "krb5_get_init_creds_opt_alloc failed");
		
	torture_assert_int_equal(tctx,
				 krb5_get_init_creds_opt_set_canonicalize(smb_krb5_context->krb5_context, krb_options, test_data->canonicalize),
				 0, "krb5_get_init_creds_opt_set_canonicalize failed");

	k5ret = krb5_get_init_creds_password(smb_krb5_context->krb5_context, &my_creds, principal,
					     password, NULL, NULL, 0,
					     NULL, krb_options);
	krb5_get_init_creds_opt_free(smb_krb5_context->krb5_context, krb_options);
	
	assertion_message = talloc_asprintf(tctx,
					    "krb5_get_init_creds_password for %s failed: %s",
					    principal_string,
					    smb_get_krb5_error_message(smb_krb5_context->krb5_context, k5ret, tctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	/*
	 * Assert that the reply was with the correct type of
	 * principal, depending on the flags we set
	 */
	if (test_data->canonicalize == false && test_data->enterprise) {
		torture_assert_int_equal(tctx,
					 krb5_principal_get_type(smb_krb5_context->krb5_context,
								 my_creds.client), KRB5_NT_ENTERPRISE_PRINCIPAL,
					 "smb_krb5_init_context gave incorrect client->name.name_type");
	} else {
		torture_assert_int_equal(tctx,
					 krb5_principal_get_type(smb_krb5_context->krb5_context,
								 my_creds.client), KRB5_NT_PRINCIPAL,
					 "smb_krb5_init_context gave incorrect client->name.name_type");
	}
	
	torture_assert_int_equal(tctx,
				 krb5_unparse_name(smb_krb5_context->krb5_context,
						   my_creds.client, &got_principal_string), 0,
				 "krb5_unparse_name failed");

	assertion_message = talloc_asprintf(tctx,
					    "krb5_get_init_creds_password returned a different principal %s to what was expected %s",
					    got_principal_string, expected_principal_string);
	krb5_free_unparsed_name(smb_krb5_context->krb5_context, got_principal_string);
	
	torture_assert(tctx, krb5_principal_compare(smb_krb5_context->krb5_context,
						    my_creds.client, expected_principal),
		       assertion_message);
	
	torture_assert_int_equal(tctx,
				 krb5_principal_get_type(smb_krb5_context->krb5_context,
							 my_creds.server), KRB5_NT_SRV_INST,
				 "smb_krb5_init_context gave incorrect client->name.name_type");

	torture_assert_str_equal(tctx, krb5_principal_get_comp_string(smb_krb5_context->krb5_context,
								      my_creds.server, 0),
				 "krbtgt",
				 "smb_krb5_init_context gave incorrect my_creds.server->name.name_string[0]");

	krb5_free_principal(smb_krb5_context->krb5_context, principal);
	
	k5ret = krb5_free_cred_contents(smb_krb5_context->krb5_context, &my_creds);
	torture_assert_int_equal(tctx, k5ret, 0, "krb5_free_creds failed");

	return true;
}

struct torture_suite *torture_krb5_canon(TALLOC_CTX *mem_ctx)
{
	unsigned int i;
	struct torture_suite *suite = torture_suite_create(mem_ctx, "canon");
	suite->description = talloc_strdup(suite, "Kerberos Canonicalisation tests");

	for (i = 0; i < TEST_ALL; i++) {
		char *name = talloc_asprintf(suite, "%s.%s.%s.%s.%s",
					     (i & TEST_CANONICALIZE) ? "canon" : "no-canon",
					     (i & TEST_ENTERPRISE) ? "enterprise" : "no-enterprise",
					     (i & TEST_UPPER_REALM) ? "uc-realm" : "lc-realm",
					     (i & TEST_UPPER_USERNAME) ? "uc-user" : "lc-user",
					     (i & TEST_NETBIOS_REALM) ? "netbios-realm" : "krb5-realm");

		struct test_data *test_data = talloc(suite, struct test_data);
		if (i & TEST_NETBIOS_REALM) {
			test_data->realm = cli_credentials_get_domain(cmdline_credentials);
		} else {
			test_data->realm = cli_credentials_get_realm(cmdline_credentials);
		}
		test_data->real_realm = cli_credentials_get_realm(cmdline_credentials);
		test_data->username = cli_credentials_get_username(cmdline_credentials);
		test_data->canonicalize = (i & TEST_CANONICALIZE) != 0;
		test_data->enterprise = (i & TEST_ENTERPRISE) != 0;
		test_data->upper_realm = (i & TEST_UPPER_REALM) != 0;
		test_data->upper_username = (i & TEST_UPPER_USERNAME) != 0;
		torture_suite_add_simple_tcase_const(suite, name, torture_krb5_as_req_canon,
						     test_data);
						     
	}
	return suite;
}
