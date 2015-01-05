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
#include "torture/winbind/proto.h"
#include "auth/credentials/credentials.h"
#include "lib/cmdline/popt_common.h"
#include "source4/auth/kerberos/kerberos.h"
#include "source4/auth/kerberos/kerberos_util.h"
#include "lib/util/util_net.h"

enum torture_krb5_test {
	TORTURE_KRB5_TEST_PLAIN,
	TORTURE_KRB5_TEST_BREAK_PW
};

struct torture_krb5_context {
	struct torture_context *tctx;
	struct addrinfo *server;
	enum torture_krb5_test test;
	int packet_count;
	AS_REQ as_req;
	AS_REP as_rep;
};

static bool torture_krb5_pre_send_test(struct torture_krb5_context *test_context, const krb5_data *send_buf)
{
	size_t used;
	switch (test_context->test)
	{
	case TORTURE_KRB5_TEST_PLAIN:
	case TORTURE_KRB5_TEST_BREAK_PW:
		torture_assert_int_equal(test_context->tctx,
					 decode_AS_REQ(send_buf->data, send_buf->length, &test_context->as_req, &used), 0,
					 "decode_AS_REQ failed");
		torture_assert_int_equal(test_context->tctx, used, send_buf->length, "length mismatch");
		torture_assert_int_equal(test_context->tctx, test_context->as_req.pvno, 5, "Got wrong as_req->pvno");
		break;
	}
	return true;
}

static bool torture_krb5_post_recv_test(struct torture_krb5_context *test_context, const krb5_data *recv_buf)
{
	KRB_ERROR error;
	size_t used;
	switch (test_context->test)
	{
	case TORTURE_KRB5_TEST_PLAIN:
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
			torture_assert_int_equal(test_context->tctx, test_context->as_rep.pvno, 5, "Got wrong as_rep->pvno");
			free_AS_REP(&test_context->as_rep);
		}
		torture_assert(test_context->tctx, test_context->packet_count < 3, "too many packets");
		free_AS_REQ(&test_context->as_req);
		break;
	case TORTURE_KRB5_TEST_BREAK_PW:
		if (test_context->packet_count == 0) {
			torture_assert_int_equal(test_context->tctx,
						 decode_KRB_ERROR(recv_buf->data, recv_buf->length, &error, &used), 0,
						 "decode_AS_REP failed");
			torture_assert_int_equal(test_context->tctx, used, recv_buf->length, "length mismatch");
			torture_assert_int_equal(test_context->tctx, error.pvno, 5, "Got wrong error.pvno");
			torture_assert_int_equal(test_context->tctx, error.error_code, KRB5KDC_ERR_PREAUTH_REQUIRED - KRB5KDC_ERR_NONE,
						 "Got wrong error.error_code");
			free_KRB_ERROR(&error);
		} else if (test_context->packet_count == 1) {
			torture_assert_int_equal(test_context->tctx,
						 decode_KRB_ERROR(recv_buf->data, recv_buf->length, &error, &used), 0,
						 "decode_AS_REP failed");
			torture_assert_int_equal(test_context->tctx, used, recv_buf->length, "length mismatch");
			torture_assert_int_equal(test_context->tctx, error.pvno, 5, "Got wrong error.pvno");
			torture_assert_int_equal(test_context->tctx, error.error_code, KRB5KDC_ERR_PREAUTH_FAILED - KRB5KDC_ERR_NONE,
						 "Got wrong error.error_code");
			free_KRB_ERROR(&error);
		}
		torture_assert(test_context->tctx, test_context->packet_count < 2, "too many packets");
		free_AS_REQ(&test_context->as_req);
		break;
	}
	return true;
}

static krb5_error_code smb_krb5_send_and_recv_func_override(krb5_context context,
						    void *data, /* struct torture_krb5_context */
						    krb5_krbhst_info *hi,
						    time_t timeout,
						    const krb5_data *send_buf,
						    krb5_data *recv_buf)
{
	krb5_error_code k5ret;
	bool ok;
	
	struct torture_krb5_context *test_context
		= talloc_get_type_abort(data, struct torture_krb5_context);

	ok = torture_krb5_pre_send_test(test_context, send_buf);
	if (ok == false) {
		return EINVAL;
	}
	
	k5ret = smb_krb5_send_and_recv_func_forced(context, test_context->server,
						    hi, timeout, send_buf, recv_buf);

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
	

static bool torture_krb5_init_context(struct torture_context *tctx,
				      enum torture_krb5_test test,
				      struct smb_krb5_context **smb_krb5_context)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	krb5_error_code k5ret;
	bool ok;

	struct torture_krb5_context *test_context = talloc_zero(tctx, struct torture_krb5_context);
	torture_assert(tctx, test_context != NULL, "Failed to allocate");

	test_context->test = test;
	test_context->tctx = tctx;
	
	k5ret = smb_krb5_init_context(tctx, tctx->lp_ctx, smb_krb5_context);
	torture_assert_int_equal(tctx, k5ret, 0, "smb_krb5_init_context failed");

	ok = interpret_string_addr_internal(&test_context->server, host, AI_NUMERICHOST);
	torture_assert(tctx, ok, "Failed to parse target server");

	talloc_set_destructor(test_context, test_context_destructor);
	
	set_sockaddr_port(test_context->server->ai_addr, 88);

	k5ret = krb5_set_send_to_kdc_func((*smb_krb5_context)->krb5_context,
					  smb_krb5_send_and_recv_func_override,
					  test_context);
	torture_assert_int_equal(tctx, k5ret, 0, "krb5_set_send_to_kdc_func failed");
	return true;
}

static bool torture_krb5_as_req_creds(struct torture_context *tctx,
				      struct cli_credentials *credentials,
				      enum torture_krb5_test test)
{
	krb5_error_code k5ret;
	bool ok;
	krb5_creds my_creds;
	krb5_principal principal;
	struct smb_krb5_context *smb_krb5_context;
	enum credentials_obtained obtained;
	const char *error_string;
	const char *password = cli_credentials_get_password(credentials);
	
	ok = torture_krb5_init_context(tctx, test, &smb_krb5_context);
	torture_assert(tctx, ok, "torture_krb5_init_context failed");
	
	k5ret = principal_from_credentials(tctx, credentials, smb_krb5_context, &principal, &obtained,  &error_string);
	torture_assert_int_equal(tctx, k5ret, 0, error_string);

	if (test == TORTURE_KRB5_TEST_BREAK_PW) {
		password = "NOT the password";
	}
	k5ret = krb5_get_init_creds_password(smb_krb5_context->krb5_context, &my_creds, principal,
					     password, NULL, NULL, 0,
					     NULL, NULL);
	if (test == TORTURE_KRB5_TEST_BREAK_PW) {
		torture_assert_int_equal(tctx, k5ret, KRB5KDC_ERR_PREAUTH_FAILED, "krb5_get_init_creds_password should have failed");
		return true;
	} else {
		torture_assert_int_equal(tctx, k5ret, 0, "krb5_get_init_creds_password failed");
	}

	torture_assert_int_equal(tctx,
				 krb5_principal_get_type(smb_krb5_context->krb5_context,
							 my_creds.client), KRB5_NT_PRINCIPAL,
				 "smb_krb5_init_context gave incorrect client->name.name_type");

	torture_assert(tctx, krb5_principal_compare(smb_krb5_context->krb5_context,
						    principal, my_creds.client),
		       "krb5_get_init_creds_password returned a different principal");
	
	torture_assert_int_equal(tctx,
				 krb5_principal_get_type(smb_krb5_context->krb5_context,
							 my_creds.server), KRB5_NT_SRV_INST,
				 "smb_krb5_init_context gave incorrect client->name.name_type");

	torture_assert_str_equal(tctx, krb5_principal_get_comp_string(smb_krb5_context->krb5_context,
								      my_creds.server, 0),
				 "krbtgt",
				 "smb_krb5_init_context gave incorrect my_creds.server->name.name_string[0]");

	k5ret = krb5_free_cred_contents(smb_krb5_context->krb5_context, &my_creds);
	torture_assert_int_equal(tctx, k5ret, 0, "krb5_free_creds failed");

	return true;
}

static bool torture_krb5_as_req_cmdline(struct torture_context *tctx)
{
	return torture_krb5_as_req_creds(tctx, cmdline_credentials, TORTURE_KRB5_TEST_PLAIN);
}

static bool torture_krb5_as_req_break_pw(struct torture_context *tctx)
{
	return torture_krb5_as_req_creds(tctx, cmdline_credentials, TORTURE_KRB5_TEST_BREAK_PW);
}

NTSTATUS torture_krb5_init(void);
NTSTATUS torture_krb5_init(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "krb5");
	struct torture_suite *kdc_suite = torture_suite_create(suite, "kdc");
	suite->description = talloc_strdup(suite, "Kerberos tests");
	kdc_suite->description = talloc_strdup(kdc_suite, "Kerberos KDC tests");

	torture_suite_add_simple_test(kdc_suite, "as-req-cmdline", 
				      torture_krb5_as_req_cmdline);

	torture_suite_add_simple_test(kdc_suite, "as-req-break-pw", 
				      torture_krb5_as_req_break_pw);

	torture_suite_add_suite(suite, kdc_suite);

	torture_register_suite(suite);
	return NT_STATUS_OK;
}
