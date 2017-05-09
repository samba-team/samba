/*
   Unix SMB/CIFS implementation.

   Validate the krb5 pac generation routines

   Copyright (c) 2016      Andreas Schneider <asn@samba.org>

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
#include "system/time.h"
#include "torture/smbtorture.h"
#include "torture/winbind/proto.h"
#include "torture/krb5/proto.h"
#include "auth/credentials/credentials.h"
#include "lib/cmdline/popt_common.h"
#include "source4/auth/kerberos/kerberos.h"
#include "source4/auth/kerberos/kerberos_util.h"
#include "lib/util/util_net.h"

#define krb5_is_app_tag(dat,tag)                          \
	((dat != NULL) && (dat)->length &&                \
	 ((((dat)->data[0] & ~0x20) == ((tag) | 0x40))))

#define krb5_is_as_req(dat)                   krb5_is_app_tag(dat, 10)
#define krb5_is_as_rep(dat)                   krb5_is_app_tag(dat, 11)
#define krb5_is_krb_error(dat)                krb5_is_app_tag(dat, 30)

enum torture_krb5_test {
	TORTURE_KRB5_TEST_PLAIN,
	TORTURE_KRB5_TEST_PAC_REQUEST,
	TORTURE_KRB5_TEST_BREAK_PW,
	TORTURE_KRB5_TEST_CLOCK_SKEW,
	TORTURE_KRB5_TEST_AES,
	TORTURE_KRB5_TEST_RC4,
	TORTURE_KRB5_TEST_AES_RC4,
};

struct torture_krb5_context {
	struct torture_context *tctx;
	krb5_context krb5_context;
	enum torture_krb5_test test;
	int recv_packet_count;
	krb5_kdc_req *as_req;
	krb5_kdc_rep *as_rep;
};

krb5_error_code decode_krb5_error(const krb5_data *output, krb5_error **rep);

krb5_error_code decode_krb5_as_req(const krb5_data *output, krb5_kdc_req **req);
krb5_error_code decode_krb5_as_rep(const krb5_data *output, krb5_kdc_rep **rep);

krb5_error_code decode_krb5_padata_sequence(const krb5_data *output, krb5_pa_data ***rep);

void krb5_free_kdc_req(krb5_context ctx, krb5_kdc_req *req);
void krb5_free_kdc_rep(krb5_context ctx, krb5_kdc_rep *rep);
void krb5_free_pa_data(krb5_context ctx, krb5_pa_data **data);

static bool torture_check_krb5_as_req(struct torture_krb5_context *test_context,
				      krb5_context context,
				      const krb5_data *message)
{
	krb5_error_code code;
	int nktypes;

	code = decode_krb5_as_req(message, &test_context->as_req);
	torture_assert_int_equal(test_context->tctx,
				 code, 0,
				 "decode_as_req failed");
	torture_assert_int_equal(test_context->tctx,
				 test_context->as_req->msg_type,
				 KRB5_AS_REQ,
				 "Not a AS REQ");

	nktypes = test_context->as_req->nktypes;
	torture_assert_int_not_equal(test_context->tctx,
				     nktypes, 0,
				     "No keytypes");

	return true;
}

static krb5_error_code torture_krb5_pre_send_test(krb5_context context,
						  void *data,
						  const krb5_data *realm,
						  const krb5_data *message,
						  krb5_data **new_message_out,
						  krb5_data **new_reply_out)
{
	bool ok;
	struct torture_krb5_context *test_context =
		(struct torture_krb5_context *)data;

	switch (test_context->test)
	{
	case TORTURE_KRB5_TEST_PLAIN:
	case TORTURE_KRB5_TEST_PAC_REQUEST:
	case TORTURE_KRB5_TEST_BREAK_PW:
	case TORTURE_KRB5_TEST_CLOCK_SKEW:
	case TORTURE_KRB5_TEST_AES:
	case TORTURE_KRB5_TEST_RC4:
	case TORTURE_KRB5_TEST_AES_RC4:
		ok = torture_check_krb5_as_req(test_context,
					       context,
					       message);
		if (!ok) {
			return KRB5KDC_ERR_BADOPTION;
		}
		break;
	}

	return 0;
}

/*
 * We need these function to validate packets because our torture macros
 * do a 'return false' on error.
 */
static bool torture_check_krb5_error(struct torture_krb5_context *test_context,
				     krb5_context context,
				     const krb5_data *reply,
				     krb5_error_code error_code,
				     bool check_pa_data)

{
	krb5_error *krb_error;
	krb5_error_code code;

	code = decode_krb5_error(reply, &krb_error);
	torture_assert_int_equal(test_context->tctx,
				 code,
				 0,
				 "decode_krb5_error failed");

	torture_assert_int_equal(test_context->tctx,
				 krb_error->error,
				 error_code - KRB5KDC_ERR_NONE,
				 "Got wrong error code");

	if (check_pa_data) {
		krb5_pa_data **d, **pa_data = NULL;
		bool timestamp_found = false;

		torture_assert_int_not_equal(test_context->tctx,
					     krb_error->e_data.length, 0,
					     "No e-data returned");

		code = decode_krb5_padata_sequence(&krb_error->e_data,
						   &pa_data);
		torture_assert_int_equal(test_context->tctx,
					 code,
					 0,
					 "decode_krb5_padata_sequence failed");

		for (d = pa_data; d != NULL; d++) {
			if ((*d)->pa_type == KRB5_PADATA_ENC_TIMESTAMP) {
				timestamp_found = true;
				break;
			}
		}
		torture_assert(test_context->tctx,
			       timestamp_found,
			       "Encrypted timestamp not found");

		krb5_free_pa_data(context, pa_data);
	}

	krb5_free_error(context, krb_error);

	return true;
}

static bool torture_check_krb5_as_rep(struct torture_krb5_context *test_context,
				      krb5_context context,
				      const krb5_data *reply)
{
	krb5_error_code code;
	bool ok;

	code = decode_krb5_as_rep(reply, &test_context->as_rep);
	torture_assert_int_equal(test_context->tctx,
				 code,
				 0,
				 "decode_krb5_as_rep failed");

	torture_assert(test_context->tctx,
		       test_context->as_rep->ticket->enc_part.kvno,
		       "No KVNO set");

	ok = torture_setting_bool(test_context->tctx,
				  "expect_cached_at_rodc",
				  false);
	if (ok) {
		torture_assert_int_not_equal(test_context->tctx,
					     test_context->as_rep->ticket->enc_part.kvno & 0xFFFF0000,
					     0,
					     "Did not get a RODC number in the KVNO");
	} else {
		torture_assert_int_equal(test_context->tctx,
					 test_context->as_rep->ticket->enc_part.kvno & 0xFFFF0000,
					 0,
					 "Unexpecedly got a RODC number in the KVNO");
	}

	return true;
}

static bool torture_check_krb5_as_rep_enctype(struct torture_krb5_context *test_context,
					      krb5_context context,
					      const krb5_data *reply,
					      krb5_enctype expected_enctype)
{
	krb5_enctype reply_enctype;
	bool ok;

	ok = torture_check_krb5_as_rep(test_context,
				       context,
				       reply);
	if (!ok) {
		return false;
	}

	reply_enctype = test_context->as_rep->enc_part.enctype;

	torture_assert_int_equal(test_context->tctx,
				 reply_enctype, expected_enctype,
				 "Ticket encrypted with invalid algorithm");

	return true;
}

static krb5_error_code torture_krb5_post_recv_test(krb5_context context,
						   void *data,
						   krb5_error_code kdc_code,
						   const krb5_data *realm,
						   const krb5_data *message,
						   const krb5_data *reply,
						   krb5_data **new_reply_out)
{
	struct torture_krb5_context *test_context =
		(struct torture_krb5_context *)data;
	krb5_error_code code;
	bool ok = true;

	torture_comment(test_context->tctx,
			"PACKET COUNT = %d\n",
			test_context->recv_packet_count);

	torture_comment(test_context->tctx,
			"KRB5_AS_REP = %d\n",
			krb5_is_as_req(reply));

	torture_comment(test_context->tctx,
			"KRB5_ERROR = %d\n",
			krb5_is_krb_error(reply));

	torture_comment(test_context->tctx,
			"KDC ERROR CODE = %d\n",
			kdc_code);

	switch (test_context->test)
	{
	case TORTURE_KRB5_TEST_PLAIN:
		if (test_context->recv_packet_count == 0) {
			ok = torture_check_krb5_error(test_context,
						      context,
						      reply,
						      KRB5KDC_ERR_PREAUTH_REQUIRED,
						      false);
			torture_assert_goto(test_context->tctx,
					    ok,
					    ok,
					    out,
					    "torture_check_krb5_error failed");
		} else {
			ok = torture_check_krb5_as_rep(test_context,
						       context,
						       reply);
			torture_assert_goto(test_context->tctx,
					    ok,
					    ok,
					    out,
					    "torture_check_krb5_as_rep failed");
		}

		torture_assert_goto(test_context->tctx,
				    test_context->recv_packet_count < 2,
				    ok,
				    out,
				    "Too many packets");

		break;
	case TORTURE_KRB5_TEST_PAC_REQUEST:
		if (test_context->recv_packet_count == 0) {
			ok = torture_check_krb5_error(test_context,
						      context,
						      reply,
						      KRB5KRB_ERR_RESPONSE_TOO_BIG,
						      false);
			torture_assert_goto(test_context->tctx,
					    ok,
					    ok,
					    out,
					    "torture_check_krb5_error failed");
		} else if (test_context->recv_packet_count == 1) {
			ok = torture_check_krb5_error(test_context,
						      context,
						      reply,
						      KRB5KDC_ERR_PREAUTH_REQUIRED,
						      false);
			torture_assert_goto(test_context->tctx,
					    ok,
					    ok,
					    out,
					    "torture_check_krb5_error failed");
		} else if (krb5_is_krb_error(reply)) {
			ok = torture_check_krb5_error(test_context,
						      context,
						      reply,
						      KRB5KRB_ERR_RESPONSE_TOO_BIG,
						      false);
			torture_assert_goto(test_context->tctx,
					    ok,
					    ok,
					    out,
					    "torture_check_krb5_error failed");
		} else {
			ok = torture_check_krb5_as_rep(test_context,
						       context,
						       reply);
			torture_assert_goto(test_context->tctx,
					    ok,
					    ok,
					    out,
					    "torture_check_krb5_as_rep failed");
		}

		torture_assert_goto(test_context->tctx,
				    test_context->recv_packet_count < 3,
				    ok,
				    out,
				    "Too many packets");
		break;
	case TORTURE_KRB5_TEST_BREAK_PW:
		if (test_context->recv_packet_count == 0) {
			ok = torture_check_krb5_error(test_context,
						      context,
						      reply,
						      KRB5KDC_ERR_PREAUTH_REQUIRED,
						      false);
			torture_assert_goto(test_context->tctx,
					    ok,
					    ok,
					    out,
					    "torture_check_krb5_error failed");
			if (!ok) {
				goto out;
			}
		} else if (test_context->recv_packet_count == 1) {
			ok = torture_check_krb5_error(test_context,
						      context,
						      reply,
						      KRB5KDC_ERR_PREAUTH_FAILED,
						      true);
			torture_assert_goto(test_context->tctx,
					    ok,
					    ok,
					    out,
					    "torture_check_krb5_error failed");
		}

		torture_assert_goto(test_context->tctx,
				    test_context->recv_packet_count < 2,
				    ok,
				    out,
				    "Too many packets");
		break;
	case TORTURE_KRB5_TEST_CLOCK_SKEW:
		if (test_context->recv_packet_count == 0) {
			ok = torture_check_krb5_error(test_context,
						      context,
						      reply,
						      KRB5KDC_ERR_PREAUTH_REQUIRED,
						      false);
			torture_assert_goto(test_context->tctx,
					    ok,
					    ok,
					    out,
					    "torture_check_krb5_error failed");
			if (!ok) {
				goto out;
			}
		} else if (test_context->recv_packet_count == 1) {
			/*
			 * This only works if kdc_timesync 0 is set in krb5.conf
			 *
			 * See commit 5f39a4438eafd693a3eb8366bbc3901efe62e538
			 * in the MIT Kerberos source tree.
			 */
			ok = torture_check_krb5_error(test_context,
						      context,
						      reply,
						      KRB5KRB_AP_ERR_SKEW,
						      false);
			torture_assert_goto(test_context->tctx,
					    ok,
					    ok,
					    out,
					    "torture_check_krb5_error failed");
		}

		torture_assert_goto(test_context->tctx,
				    test_context->recv_packet_count < 2,
				    ok,
				    out,
				    "Too many packets");
		break;
	case TORTURE_KRB5_TEST_AES:
		torture_comment(test_context->tctx, "TORTURE_KRB5_TEST_AES\n");

		if (test_context->recv_packet_count == 0) {
			ok = torture_check_krb5_error(test_context,
						      context,
						      reply,
						      KRB5KDC_ERR_PREAUTH_REQUIRED,
						      false);
			if (!ok) {
				goto out;
			}
		} else {
			ok = torture_check_krb5_as_rep_enctype(test_context,
							       context,
							       reply,
							       ENCTYPE_AES256_CTS_HMAC_SHA1_96);
			if (!ok) {
				goto out;
			}
		}
		break;
	case TORTURE_KRB5_TEST_RC4:
		torture_comment(test_context->tctx, "TORTURE_KRB5_TEST_RC4\n");

		if (test_context->recv_packet_count == 0) {
			ok = torture_check_krb5_error(test_context,
						      context,
						      reply,
						      KRB5KDC_ERR_PREAUTH_REQUIRED,
						      false);
			if (!ok) {
				goto out;
			}
		} else {
			ok = torture_check_krb5_as_rep_enctype(test_context,
							       context,
							       reply,
							       ENCTYPE_ARCFOUR_HMAC);
			if (!ok) {
				goto out;
			}
		}
		break;
	case TORTURE_KRB5_TEST_AES_RC4:
		torture_comment(test_context->tctx, "TORTURE_KRB5_TEST_AES_RC4\n");

		if (test_context->recv_packet_count == 0) {
			ok = torture_check_krb5_error(test_context,
						      context,
						      reply,
						      KRB5KDC_ERR_PREAUTH_REQUIRED,
						      false);
			if (!ok) {
				goto out;
			}
		} else {
			ok = torture_check_krb5_as_rep_enctype(test_context,
							       context,
							       reply,
							       ENCTYPE_AES256_CTS_HMAC_SHA1_96);
			if (!ok) {
				goto out;
			}
		}
		break;
	}

	code = kdc_code;
out:
	if (!ok) {
		code = EINVAL;
	}

	/* Cleanup */
	krb5_free_kdc_req(test_context->krb5_context, test_context->as_req);
	krb5_free_kdc_rep(test_context->krb5_context, test_context->as_rep);

	test_context->recv_packet_count++;

	return code;
}

static bool torture_krb5_init_context(struct torture_context *tctx,
				      enum torture_krb5_test test,
				      struct smb_krb5_context **smb_krb5_context)
{
	krb5_error_code code;

	struct torture_krb5_context *test_context = talloc_zero(tctx,
								struct torture_krb5_context);
	torture_assert(tctx, test_context != NULL, "Failed to allocate");

	test_context->test = test;
	test_context->tctx = tctx;

	code = smb_krb5_init_context(tctx, tctx->lp_ctx, smb_krb5_context);
	torture_assert_int_equal(tctx, code, 0, "smb_krb5_init_context failed");

	test_context->krb5_context = (*smb_krb5_context)->krb5_context;

	krb5_set_kdc_send_hook((*smb_krb5_context)->krb5_context,
			       torture_krb5_pre_send_test,
			       test_context);

	krb5_set_kdc_recv_hook((*smb_krb5_context)->krb5_context,
			       torture_krb5_post_recv_test,
			       test_context);

	return true;
}
static bool torture_krb5_as_req_creds(struct torture_context *tctx,
				      struct cli_credentials *credentials,
				      enum torture_krb5_test test)
{
	krb5_get_init_creds_opt *krb_options = NULL;
	struct smb_krb5_context *smb_krb5_context;
	enum credentials_obtained obtained;
	const char *error_string;
	const char *password;
	krb5_principal principal;
	krb5_error_code code;
	krb5_creds my_creds;
	bool ok;

	ok = torture_krb5_init_context(tctx, test, &smb_krb5_context);
	torture_assert(tctx, ok, "torture_krb5_init_context failed");

	code = principal_from_credentials(tctx,
					  credentials,
					  smb_krb5_context,
					  &principal,
					  &obtained,
					  &error_string);
	torture_assert_int_equal(tctx, code, 0, error_string);

	password = cli_credentials_get_password(credentials);

	switch (test)
	{
	case TORTURE_KRB5_TEST_PLAIN:
		break;
	case TORTURE_KRB5_TEST_PAC_REQUEST:
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PAC_REQUEST
		code = krb5_get_init_creds_opt_alloc(smb_krb5_context->krb5_context,
						     &krb_options);
		torture_assert_int_equal(tctx,
					 code, 0,
					 "krb5_get_init_creds_opt_alloc failed");

		code = krb5_get_init_creds_opt_set_pac_request(smb_krb5_context->krb5_context,
							       krb_options,
							       1);
		torture_assert_int_equal(tctx,
					 code, 0,
					 "krb5_get_init_creds_opt_set_pac_request failed");
#endif
		break;
	case TORTURE_KRB5_TEST_BREAK_PW:
		password = "NOT the password";
		break;
	case TORTURE_KRB5_TEST_CLOCK_SKEW:
		code = krb5_set_real_time(smb_krb5_context->krb5_context,
					  time(NULL) + 3600,
					  0);
		torture_assert_int_equal(tctx,
					 code, 0,
					 "krb5_set_real_time failed");
		break;
	case TORTURE_KRB5_TEST_AES: {
		krb5_enctype etype[] = { ENCTYPE_AES256_CTS_HMAC_SHA1_96 };

		code = krb5_get_init_creds_opt_alloc(smb_krb5_context->krb5_context,
						     &krb_options);
		torture_assert_int_equal(tctx,
					 code, 0,
					 "krb5_get_init_creds_opt_alloc failed");

		krb5_get_init_creds_opt_set_etype_list(krb_options,
						       etype,
						       1);
		break;
	}
	case TORTURE_KRB5_TEST_RC4: {
		krb5_enctype etype[] = { ENCTYPE_ARCFOUR_HMAC };

		code = krb5_get_init_creds_opt_alloc(smb_krb5_context->krb5_context,
						     &krb_options);
		torture_assert_int_equal(tctx,
					 code, 0,
					 "krb5_get_init_creds_opt_alloc failed");

		krb5_get_init_creds_opt_set_etype_list(krb_options,
						       etype,
						       1);
		break;
	}
	case TORTURE_KRB5_TEST_AES_RC4: {
		krb5_enctype etype[] = { ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_ARCFOUR_HMAC };

		code = krb5_get_init_creds_opt_alloc(smb_krb5_context->krb5_context,
						     &krb_options);
		torture_assert_int_equal(tctx,
					 code, 0,
					 "krb5_get_init_creds_opt_alloc failed");


		krb5_get_init_creds_opt_set_etype_list(krb_options,
						       etype,
						       2);
		break;
	}
	}

	code = krb5_get_init_creds_password(smb_krb5_context->krb5_context,
					    &my_creds,
					    principal,
					    password,
					    NULL,
					    NULL,
					    0,
					    NULL,
					    krb_options);
	krb5_get_init_creds_opt_free(smb_krb5_context->krb5_context,
				     krb_options);

	switch (test)
	{
	case TORTURE_KRB5_TEST_PLAIN:
	case TORTURE_KRB5_TEST_PAC_REQUEST:
	case TORTURE_KRB5_TEST_AES:
	case TORTURE_KRB5_TEST_RC4:
	case TORTURE_KRB5_TEST_AES_RC4:
		torture_assert_int_equal(tctx,
					 code,
					 0,
					 "krb5_get_init_creds_password failed");
		break;
	case TORTURE_KRB5_TEST_BREAK_PW:
		torture_assert_int_equal(tctx,
					 code,
					 KRB5KDC_ERR_PREAUTH_FAILED,
					 "krb5_get_init_creds_password should "
					 "have failed");
		return true;
	case TORTURE_KRB5_TEST_CLOCK_SKEW:
		torture_assert_int_equal(tctx,
					 code,
					 KRB5KRB_AP_ERR_SKEW,
					 "krb5_get_init_creds_password should "
					 "have failed");
		return true;
	}

	krb5_free_cred_contents(smb_krb5_context->krb5_context,
				&my_creds);

	return true;
}

static bool torture_krb5_as_req_cmdline(struct torture_context *tctx)
{
	return torture_krb5_as_req_creds(tctx,
					 popt_get_cmdline_credentials(),
					 TORTURE_KRB5_TEST_PLAIN);
}

#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PAC_REQUEST
static bool torture_krb5_as_req_pac_request(struct torture_context *tctx)
{
	bool ok;

	ok = torture_setting_bool(tctx, "expect_rodc", false);
	if (ok) {
		torture_skip(tctx,
			     "This test needs further investigation in the "
			     "RODC case against a Windows DC, in particular "
			     "with non-cached users");
	}
	return torture_krb5_as_req_creds(tctx, popt_get_cmdline_credentials(),
			TORTURE_KRB5_TEST_PAC_REQUEST);
}
#endif /* HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PAC_REQUEST */

static bool torture_krb5_as_req_break_pw(struct torture_context *tctx)
{
	return torture_krb5_as_req_creds(tctx,
					 popt_get_cmdline_credentials(),
					 TORTURE_KRB5_TEST_BREAK_PW);
}

static bool torture_krb5_as_req_clock_skew(struct torture_context *tctx)
{
	return torture_krb5_as_req_creds(tctx,
					 popt_get_cmdline_credentials(),
					 TORTURE_KRB5_TEST_CLOCK_SKEW);
}

static bool torture_krb5_as_req_aes(struct torture_context *tctx)
{
	return torture_krb5_as_req_creds(tctx,
					 popt_get_cmdline_credentials(),
					 TORTURE_KRB5_TEST_AES);
}

static bool torture_krb5_as_req_rc4(struct torture_context *tctx)
{
	return torture_krb5_as_req_creds(tctx,
					 popt_get_cmdline_credentials(),
					 TORTURE_KRB5_TEST_RC4);
}

static bool torture_krb5_as_req_aes_rc4(struct torture_context *tctx)
{
	return torture_krb5_as_req_creds(tctx,
					 popt_get_cmdline_credentials(),
					 TORTURE_KRB5_TEST_AES_RC4);
}

NTSTATUS torture_krb5_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
		torture_suite_create(ctx, "krb5");
	struct torture_suite *kdc_suite = torture_suite_create(suite, "kdc");
	suite->description = talloc_strdup(suite, "Kerberos tests");
	kdc_suite->description = talloc_strdup(kdc_suite, "Kerberos KDC tests");

	torture_suite_add_simple_test(kdc_suite,
				      "as-req-cmdline",
				      torture_krb5_as_req_cmdline);

#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PAC_REQUEST
	/* Only available with MIT Kerveros 1.15 and newer */
	torture_suite_add_simple_test(kdc_suite, "as-req-pac-request",
				      torture_krb5_as_req_pac_request);
#endif

	torture_suite_add_simple_test(kdc_suite, "as-req-break-pw",
				      torture_krb5_as_req_break_pw);

	/* This only works if kdc_timesync 0 is set in krb5.conf */
	torture_suite_add_simple_test(kdc_suite, "as-req-clock-skew",
				      torture_krb5_as_req_clock_skew);

#if 0
	torture_suite_add_suite(kdc_suite, torture_krb5_canon(kdc_suite));
#endif
	torture_suite_add_simple_test(kdc_suite,
				      "as-req-aes",
				      torture_krb5_as_req_aes);

	torture_suite_add_simple_test(kdc_suite,
				      "as-req-rc4",
				      torture_krb5_as_req_rc4);

	torture_suite_add_simple_test(kdc_suite,
				      "as-req-aes-rc4",
				      torture_krb5_as_req_aes_rc4);

	torture_suite_add_suite(suite, kdc_suite);

	torture_register_suite(ctx, suite);

	return NT_STATUS_OK;
}
