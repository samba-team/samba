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
#include "torture/krb5/proto.h"
#include "auth/credentials/credentials.h"
#include "lib/cmdline/popt_common.h"
#include "source4/auth/kerberos/kerberos.h"
#include "source4/auth/kerberos/kerberos_util.h"
#include "lib/util/util_net.h"

#define krb5_is_app_tag(dat,tag)                          \
       ((dat != NULL) && (dat)->length &&                \
        (((((char *)(dat)->data)[0] & ~0x20) == ((tag) | 0x40))))

#define krb5_is_krb_error(dat)                krb5_is_app_tag(dat, 30)

enum torture_krb5_test {
	TORTURE_KRB5_TEST_PLAIN,
	TORTURE_KRB5_TEST_PAC_REQUEST,
	TORTURE_KRB5_TEST_BREAK_PW,
	TORTURE_KRB5_TEST_CLOCK_SKEW,
	TORTURE_KRB5_TEST_AES,
	TORTURE_KRB5_TEST_RC4,
	TORTURE_KRB5_TEST_AES_RC4,

	/* 
	 * This is in and out of the client. 
	 * Out refers to requests, in refers to replies
	 */
	TORTURE_KRB5_TEST_CHANGE_SERVER_OUT,
	TORTURE_KRB5_TEST_CHANGE_SERVER_IN,
	TORTURE_KRB5_TEST_CHANGE_SERVER_BOTH,
};

struct torture_krb5_context {
	struct torture_context *tctx;
	struct addrinfo *server;
	enum torture_krb5_test test;
	int packet_count;
	AS_REQ as_req;
	AS_REP as_rep;
	const char *krb5_service;
	const char *krb5_hostname;
};

/*
 * Confirm that the outgoing packet meets certain expectations.  This
 * should be extended to further assert the correct and expected
 * behaviour of the krb5 libs, so we know what we are sending to the
 * server.
 *
 */

static bool torture_krb5_pre_send_test(struct torture_krb5_context *test_context, krb5_data *send_buf)
{
	size_t used;
	switch (test_context->test)
	{
	case TORTURE_KRB5_TEST_PLAIN:
	case TORTURE_KRB5_TEST_PAC_REQUEST:
	case TORTURE_KRB5_TEST_BREAK_PW:
	case TORTURE_KRB5_TEST_CLOCK_SKEW:
	case TORTURE_KRB5_TEST_AES:
	case TORTURE_KRB5_TEST_RC4:
	case TORTURE_KRB5_TEST_AES_RC4:
	case TORTURE_KRB5_TEST_CHANGE_SERVER_IN:
		torture_assert_int_equal(test_context->tctx,
					 decode_AS_REQ(send_buf->data, send_buf->length, &test_context->as_req, &used), 0,
					 "decode_AS_REQ failed");
		torture_assert_int_equal(test_context->tctx, used, send_buf->length, "length mismatch");
		torture_assert_int_equal(test_context->tctx, test_context->as_req.pvno, 5, "Got wrong as_req->pvno");
		break;
	case TORTURE_KRB5_TEST_CHANGE_SERVER_OUT:
	case TORTURE_KRB5_TEST_CHANGE_SERVER_BOTH:
	{
		AS_REQ mod_as_req;
		krb5_error_code k5ret;
		krb5_data modified_send_buf;
		torture_assert_int_equal(test_context->tctx,
					 decode_AS_REQ(send_buf->data, send_buf->length, &test_context->as_req, &used), 0,
					 "decode_AS_REQ failed");
		torture_assert_int_equal(test_context->tctx, used, send_buf->length, "length mismatch");
		torture_assert_int_equal(test_context->tctx, test_context->as_req.pvno, 5, "Got wrong as_req->pvno");

		/* Only change it if configured with --option=torture:krb5-hostname= */
		if (test_context->krb5_hostname[0] == '\0') {
			break;
		}

		mod_as_req = test_context->as_req;

		torture_assert_int_equal(test_context->tctx,
					 mod_as_req.req_body.sname->name_string.len, 2,
					 "Sending wrong mod_as_req.req_body->sname.name_string.len");
		free(mod_as_req.req_body.sname->name_string.val[0]);
		free(mod_as_req.req_body.sname->name_string.val[1]);
		mod_as_req.req_body.sname->name_string.val[0] = strdup(test_context->krb5_service);
		mod_as_req.req_body.sname->name_string.val[1] = strdup(test_context->krb5_hostname);

		ASN1_MALLOC_ENCODE(AS_REQ, modified_send_buf.data, modified_send_buf.length,
				   &mod_as_req, &used, k5ret);
		torture_assert_int_equal(test_context->tctx,
					 k5ret, 0,
					 "encode_AS_REQ failed");

		*send_buf = modified_send_buf;
		break;
	}
	}
	return true;
}

static bool torture_check_krb5_error(struct torture_krb5_context *test_context,
				     const krb5_data *reply,
				     krb5_error_code expected_error,
				     bool check_pa_data)
{
	KRB_ERROR error = { 0 };
	size_t used = 0;
	int rc;

	rc = decode_KRB_ERROR(reply->data, reply->length, &error, &used);
	torture_assert_int_equal(test_context->tctx,
				 rc, 0,
				 "decode_AS_REP failed");

	torture_assert_int_equal(test_context->tctx,
				 used, reply->length,
				 "length mismatch");
	torture_assert_int_equal(test_context->tctx,
				 error.pvno, 5,
				 "Got wrong error.pvno");
	torture_assert_int_equal(test_context->tctx,
				 error.error_code, expected_error - KRB5KDC_ERR_NONE,
				 "Got wrong error.error_code");

	if (check_pa_data) {
		METHOD_DATA m;
		size_t len;
		int i;
		bool found = false;
			torture_assert(test_context->tctx,
				       error.e_data != NULL,
				       "No e-data returned");

			rc = decode_METHOD_DATA(error.e_data->data,
						error.e_data->length,
						&m,
						&len);
			torture_assert_int_equal(test_context->tctx,
						 rc, 0,
						 "Got invalid method data");

			/*
			 * NOTE:
			 *
			 * Windows (eg Server 1709) only returns a
			 * KRB5_PADATA_ETYPE_INFO2 in this situation.
			 * This test should be fixed but care needs to
			 * be taken not to reintroduce
			 * https://bugzilla.samba.org/show_bug.cgi?id=11539
			 */
			torture_assert(test_context->tctx,
				       m.len > 0,
				       "No PA_DATA given");
			for (i = 0; i < m.len; i++) {
				if (m.val[i].padata_type == KRB5_PADATA_ENC_TIMESTAMP) {
					found = true;
					break;
				}
			}
			torture_assert(test_context->tctx,
				       found,
				       "Encrypted timestamp not found");
	}

	free_KRB_ERROR(&error);

	return true;
}

static bool torture_check_krb5_as_rep_enctype(struct torture_krb5_context *test_context,
					      const krb5_data *reply,
					      const krb5_enctype* allowed_enctypes)
{
	ENCTYPE reply_enctype = { 0 };
	size_t used = 0;
	int rc;
	int expected_enctype = ETYPE_NULL;

	rc = decode_AS_REP(reply->data,
			   reply->length,
			   &test_context->as_rep,
			   &used);
	torture_assert_int_equal(test_context->tctx,
				 rc, 0,
				 "decode_AS_REP failed");
	torture_assert_int_equal(test_context->tctx,
				 used, reply->length,
				 "length mismatch");
	torture_assert_int_equal(test_context->tctx,
				 test_context->as_rep.pvno, 5,
				 "Got wrong as_rep->pvno");
	torture_assert_int_equal(test_context->tctx,
				 test_context->as_rep.ticket.tkt_vno, 5,
				 "Got wrong as_rep->ticket.tkt_vno");
	torture_assert(test_context->tctx,
		       test_context->as_rep.ticket.enc_part.kvno,
		       "Did not get a KVNO in test_context->as_rep.ticket.enc_part.kvno");

	if (test_context->as_req.padata) {
		/*
		 * If the AS-REQ contains a PA-ENC-TIMESTAMP, then
		 * that encryption type is used to determine the reply
		 * enctype.
		 */
		int i = 0;
		const PA_DATA *pa = krb5_find_padata(test_context->as_req.padata->val,
						     test_context->as_req.padata->len,
						     KRB5_PADATA_ENC_TIMESTAMP,
						     &i);
		if (pa) {
			EncryptedData ed;
			size_t len;
			krb5_error_code ret = decode_EncryptedData(pa->padata_value.data,
								   pa->padata_value.length,
								   &ed, &len);
			torture_assert_int_equal(test_context->tctx,
						 ret,
						 0,
						 "decode_EncryptedData failed");
			expected_enctype = ed.etype;
			free_EncryptedData(&ed);
		}
	}
	if (expected_enctype == ETYPE_NULL) {
		/*
		 * Otherwise, find the strongest enctype contained in
		 * the AS-REQ supported enctypes list.
		 */
		const krb5_enctype *p = NULL;

		for (p = krb5_kerberos_enctypes(NULL); *p != (krb5_enctype)ETYPE_NULL; ++p) {
			int j;

			if ((*p == (krb5_enctype)ETYPE_AES256_CTS_HMAC_SHA1_96 ||
			     *p == (krb5_enctype)ETYPE_AES128_CTS_HMAC_SHA1_96) &&
			    !test_context->as_req.req_body.kdc_options.canonicalize)
			{
				/*
				 * AES encryption types are only used here when
				 * we set the canonicalize flag, as the salt
				 * needs to match.
				 */
				continue;
			}

			for (j = 0; j < test_context->as_req.req_body.etype.len; ++j) {
				krb5_enctype etype = test_context->as_req.req_body.etype.val[j];
				if (*p == etype) {
					expected_enctype = etype;
					break;
				}
			}

			if (expected_enctype != (krb5_enctype)ETYPE_NULL) {
				break;
			}
		}
	}

	{
		/* Ensure the enctype to check against is an expected type. */
		const krb5_enctype *p = NULL;
		bool found = false;
		for (p = allowed_enctypes; *p != (krb5_enctype)ETYPE_NULL; ++p) {
			if (*p == expected_enctype) {
				found = true;
				break;
			}
		}

		torture_assert(test_context->tctx,
			       found,
			       "Calculated enctype not in allowed list");
	}

	reply_enctype = test_context->as_rep.enc_part.etype;
	torture_assert_int_equal(test_context->tctx,
				 reply_enctype, expected_enctype,
				 "Ticket encrypted with invalid algorithm");

	return true;
}

/*
 * Confirm that the incoming packet from the KDC meets certain
 * expectations.  This uses a switch and the packet count to work out
 * what test we are in, and where in the test we are, so we can assert
 * on the expected reply packets from the KDC.
 *
 */

static bool torture_krb5_post_recv_test(struct torture_krb5_context *test_context, krb5_data *recv_buf)
{
	KRB_ERROR error;
	size_t used;
	bool ok;

	switch (test_context->test)
	{
	case TORTURE_KRB5_TEST_CHANGE_SERVER_OUT:
	case TORTURE_KRB5_TEST_PLAIN:
		if (test_context->packet_count == 0) {
			ok = torture_check_krb5_error(test_context,
						      recv_buf,
						      KRB5KDC_ERR_PREAUTH_REQUIRED,
						      false);
			torture_assert(test_context->tctx,
				       ok,
				       "torture_check_krb5_error failed");
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
			if (test_context->test == TORTURE_KRB5_TEST_PLAIN) {
				if (torture_setting_bool(test_context->tctx, "expect_cached_at_rodc", false)) {
					torture_assert_int_not_equal(test_context->tctx,
								     *test_context->as_rep.ticket.enc_part.kvno & 0xFFFF0000,
								     0, "Did not get a RODC number in the KVNO");
				} else {
					torture_assert_int_equal(test_context->tctx,
								 *test_context->as_rep.ticket.enc_part.kvno & 0xFFFF0000,
							 0, "Unexpecedly got a RODC number in the KVNO");
				}
			}
			free_AS_REP(&test_context->as_rep);
		}
		torture_assert(test_context->tctx, test_context->packet_count < 3, "too many packets");
		free_AS_REQ(&test_context->as_req);
		break;

		/*
		 * Confirm correct error codes when we ask for the PAC.  This behaviour is rather odd...
		 */
	case TORTURE_KRB5_TEST_PAC_REQUEST:
		if (test_context->packet_count == 0) {
			ok = torture_check_krb5_error(test_context,
						      recv_buf,
						      KRB5KDC_ERR_PREAUTH_REQUIRED,
						      false);
			torture_assert(test_context->tctx,
				       ok,
				       "torture_check_krb5_error failed");
		} else if (test_context->packet_count == 1) {
			ok = torture_check_krb5_error(test_context,
						      recv_buf,
						      KRB5KRB_ERR_RESPONSE_TOO_BIG,
						      false);
			torture_assert(test_context->tctx,
				       ok,
				       "torture_check_krb5_error failed");
		} else if ((decode_KRB_ERROR(recv_buf->data, recv_buf->length, &error, &used) == 0)
			   && (test_context->packet_count == 2)) {
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

		/*
		 * Confirm correct error codes when we deliberatly send the wrong password
		 */
	case TORTURE_KRB5_TEST_BREAK_PW:
		if (test_context->packet_count == 0) {
			ok = torture_check_krb5_error(test_context,
						      recv_buf,
						      KRB5KDC_ERR_PREAUTH_REQUIRED,
						      false);
			torture_assert(test_context->tctx,
				       ok,
				       "torture_check_krb5_error failed");
		} else if (test_context->packet_count == 1) {
			ok = torture_check_krb5_error(test_context,
						      recv_buf,
						      KRB5KDC_ERR_PREAUTH_FAILED,
						      true);
			torture_assert(test_context->tctx,
				       ok,
				       "torture_check_krb5_error failed");
		}
		torture_assert(test_context->tctx, test_context->packet_count < 2, "too many packets");
		free_AS_REQ(&test_context->as_req);
		break;

		/*
		 * Confirm correct error codes when we deliberatly skew the client clock
		 */
	case TORTURE_KRB5_TEST_CLOCK_SKEW:
		if (test_context->packet_count == 0) {
			ok = torture_check_krb5_error(test_context,
						      recv_buf,
						      KRB5KDC_ERR_PREAUTH_REQUIRED,
						      false);
			torture_assert(test_context->tctx,
				       ok,
				       "torture_check_krb5_error failed");
		} else if (test_context->packet_count == 1) {
			ok = torture_check_krb5_error(test_context,
						      recv_buf,
						      KRB5KRB_AP_ERR_SKEW,
						      false);
			torture_assert(test_context->tctx,
				       ok,
				       "torture_check_krb5_error failed");
		}
		torture_assert(test_context->tctx, test_context->packet_count < 2, "too many packets");
		free_AS_REQ(&test_context->as_req);
		break;
	case TORTURE_KRB5_TEST_AES:
		torture_comment(test_context->tctx, "TORTURE_KRB5_TEST_AES\n");

		if (test_context->packet_count == 0) {
			ok = torture_check_krb5_error(test_context,
						      recv_buf,
						      KRB5KDC_ERR_PREAUTH_REQUIRED,
						      false);
			torture_assert(test_context->tctx,
				       ok,
				       "torture_check_krb5_error failed");
		} else if (krb5_is_krb_error(recv_buf)) {
			ok = torture_check_krb5_error(test_context,
						      recv_buf,
						      KRB5KRB_ERR_RESPONSE_TOO_BIG,
						      false);
			torture_assert(test_context->tctx,
				       ok,
				       "torture_check_krb5_error failed");
		} else {
			const krb5_enctype allowed_enctypes[] = {
				KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96,
				ETYPE_NULL
			};
			ok = torture_check_krb5_as_rep_enctype(test_context,
							       recv_buf,
							       allowed_enctypes);
			torture_assert(test_context->tctx,
				       ok,
				       "torture_check_krb5_as_rep_enctype failed");
		}

		torture_assert(test_context->tctx,
			       test_context->packet_count < 3,
			       "Too many packets");
		break;
	case TORTURE_KRB5_TEST_RC4:
		torture_comment(test_context->tctx, "TORTURE_KRB5_TEST_RC4\n");

		if (test_context->packet_count == 0) {
			ok = torture_check_krb5_error(test_context,
						      recv_buf,
						      KRB5KDC_ERR_PREAUTH_REQUIRED,
						      false);
			torture_assert(test_context->tctx,
				       ok,
				       "torture_check_krb5_error failed");
		} else if (krb5_is_krb_error(recv_buf)) {
			ok = torture_check_krb5_error(test_context,
						      recv_buf,
						      KRB5KRB_ERR_RESPONSE_TOO_BIG,
						      false);
			torture_assert(test_context->tctx,
				       ok,
				       "torture_check_krb5_error failed");
		} else {
			const krb5_enctype allowed_enctypes[] = {
				KRB5_ENCTYPE_ARCFOUR_HMAC_MD5,
				ETYPE_NULL
			};
			ok = torture_check_krb5_as_rep_enctype(test_context,
							       recv_buf,
							       allowed_enctypes);
			torture_assert(test_context->tctx,
				       ok,
				       "torture_check_krb5_as_rep_enctype failed");
		}

		torture_assert(test_context->tctx,
			       test_context->packet_count < 3,
			       "Too many packets");
		break;
	case TORTURE_KRB5_TEST_AES_RC4:
		torture_comment(test_context->tctx, "TORTURE_KRB5_TEST_AES_RC4\n");

		if (test_context->packet_count == 0) {
			ok = torture_check_krb5_error(test_context,
						      recv_buf,
						      KRB5KDC_ERR_PREAUTH_REQUIRED,
						      false);
			torture_assert(test_context->tctx,
				       ok,
				       "torture_check_krb5_error failed");
		} else if (krb5_is_krb_error(recv_buf)) {
			ok = torture_check_krb5_error(test_context,
						      recv_buf,
						      KRB5KRB_ERR_RESPONSE_TOO_BIG,
						      false);
			torture_assert(test_context->tctx,
				       ok,
				       "torture_check_krb5_error failed");
		} else {
			const krb5_enctype allowed_enctypes[] = {
				KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96,
				KRB5_ENCTYPE_ARCFOUR_HMAC_MD5,
				ETYPE_NULL
			};
			ok = torture_check_krb5_as_rep_enctype(test_context,
							       recv_buf,
							       allowed_enctypes);
			torture_assert(test_context->tctx,
				       ok,
				       "torture_check_krb5_as_rep_enctype failed");
		}

		torture_assert(test_context->tctx,
			       test_context->packet_count < 3,
			       "Too many packets");
		break;
	case TORTURE_KRB5_TEST_CHANGE_SERVER_IN:
	case TORTURE_KRB5_TEST_CHANGE_SERVER_BOTH:
	{
		AS_REP mod_as_rep;
		krb5_error_code k5ret;
		krb5_data modified_recv_buf;
		if (test_context->packet_count == 0) {
			ok = torture_check_krb5_error(test_context,
						      recv_buf,
						      KRB5KDC_ERR_PREAUTH_REQUIRED,
						      false);
			torture_assert(test_context->tctx,
				       ok,
				       "torture_check_krb5_error failed");
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
			torture_assert_int_equal(test_context->tctx,
						 test_context->as_rep.ticket.sname.name_string.len, 2,
						 "Got wrong as_rep->ticket.sname.name_string.len");
			free(test_context->as_rep.ticket.sname.name_string.val[0]);
			free(test_context->as_rep.ticket.sname.name_string.val[1]);
			test_context->as_rep.ticket.sname.name_string.val[0] = strdup("bad");
			test_context->as_rep.ticket.sname.name_string.val[1] = strdup("mallory");

			mod_as_rep = test_context->as_rep;

			ASN1_MALLOC_ENCODE(AS_REP, modified_recv_buf.data, modified_recv_buf.length,
					   &mod_as_rep, &used, k5ret);
			torture_assert_int_equal(test_context->tctx,
						 k5ret, 0,
						 "encode_AS_REQ failed");
			krb5_data_free(recv_buf);

			*recv_buf = modified_recv_buf;
			free_AS_REQ(&test_context->as_req);
		}
		torture_assert(test_context->tctx, test_context->packet_count < 3, "too many packets");

		break;
	}
	}


	return true;
}


/*
 * This function is set in torture_krb5_init_context as krb5
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
static krb5_error_code smb_krb5_send_and_recv_func_override(krb5_context context,
						    void *data, /* struct torture_krb5_context */
						    krb5_krbhst_info *hi,
						    time_t timeout,
						    const krb5_data *send_buf,
						    krb5_data *recv_buf)
{
	krb5_error_code k5ret;
	bool ok;
	krb5_data modified_send_buf = *send_buf;

	struct torture_krb5_context *test_context
		= talloc_get_type_abort(data, struct torture_krb5_context);

	ok = torture_krb5_pre_send_test(test_context, &modified_send_buf);
	if (ok == false) {
		return EINVAL;
	}

	k5ret = smb_krb5_send_and_recv_func_forced(context, test_context->server,
						    hi, timeout, &modified_send_buf, recv_buf);
	if (k5ret != 0) {
		return k5ret;
	}
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

	test_context->krb5_service = torture_setting_string(tctx, "krb5-service", "host");
	test_context->krb5_hostname = torture_setting_string(tctx, "krb5-hostname", "");

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
	krb5_context k5_context;
	enum credentials_obtained obtained;
	const char *error_string;
	const char *password = cli_credentials_get_password(credentials);
	const char *expected_principal_string;
	krb5_get_init_creds_opt *krb_options = NULL;
	const char *realm;
	const char *krb5_service = torture_setting_string(tctx, "krb5-service", "host");
	const char *krb5_hostname = torture_setting_string(tctx, "krb5-hostname", "");


	ok = torture_krb5_init_context(tctx, test, &smb_krb5_context);
	torture_assert(tctx, ok, "torture_krb5_init_context failed");
	k5_context = smb_krb5_context->krb5_context;

	expected_principal_string
		= cli_credentials_get_principal(credentials,
						tctx);

	realm = strupper_talloc(tctx, cli_credentials_get_realm(credentials));
	k5ret = principal_from_credentials(tctx, credentials, smb_krb5_context,
					   &principal, &obtained,  &error_string);
	torture_assert_int_equal(tctx, k5ret, 0, error_string);

	switch (test)
	{
	case TORTURE_KRB5_TEST_PLAIN:
	case TORTURE_KRB5_TEST_CHANGE_SERVER_OUT:
	case TORTURE_KRB5_TEST_CHANGE_SERVER_IN:
	case TORTURE_KRB5_TEST_CHANGE_SERVER_BOTH:
		break;

	case TORTURE_KRB5_TEST_PAC_REQUEST:
		torture_assert_int_equal(tctx,
					 krb5_get_init_creds_opt_alloc(smb_krb5_context->krb5_context, &krb_options),
					 0, "krb5_get_init_creds_opt_alloc failed");

		torture_assert_int_equal(tctx,
					 krb5_get_init_creds_opt_set_pac_request(smb_krb5_context->krb5_context, krb_options, true),
					 0, "krb5_get_init_creds_opt_set_pac_request failed");
		break;

	case TORTURE_KRB5_TEST_BREAK_PW:
		password = "NOT the password";
		break;

	case TORTURE_KRB5_TEST_CLOCK_SKEW:
		torture_assert_int_equal(tctx,
					 krb5_set_real_time(smb_krb5_context->krb5_context, time(NULL) + 3600, 0),
					 0, "krb5_set_real_time failed");
		break;

	case TORTURE_KRB5_TEST_AES: {
		krb5_enctype etype_list[] = { KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96 };

		k5ret = krb5_get_init_creds_opt_alloc(smb_krb5_context->krb5_context,
						      &krb_options);
		torture_assert_int_equal(tctx,
					 k5ret, 0,
					 "krb5_get_init_creds_opt_alloc failed");

		krb5_get_init_creds_opt_set_etype_list(krb_options,
						       etype_list,
						       1);
		break;
	}
	case TORTURE_KRB5_TEST_RC4: {
		krb5_enctype etype_list[] = { KRB5_ENCTYPE_ARCFOUR_HMAC_MD5 };

		k5ret = krb5_get_init_creds_opt_alloc(smb_krb5_context->krb5_context,
						      &krb_options);
		torture_assert_int_equal(tctx,
					 k5ret, 0,
					 "krb5_get_init_creds_opt_alloc failed");

		krb5_get_init_creds_opt_set_etype_list(krb_options,
						       etype_list,
						       1);
		break;
	}
	case TORTURE_KRB5_TEST_AES_RC4: {
		krb5_enctype etype_list[] = { KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96,
					      KRB5_ENCTYPE_ARCFOUR_HMAC_MD5 };

		k5ret = krb5_get_init_creds_opt_alloc(smb_krb5_context->krb5_context,
						      &krb_options);
		torture_assert_int_equal(tctx,
					 k5ret, 0,
					 "krb5_get_init_creds_opt_alloc failed");

		krb5_get_init_creds_opt_set_etype_list(krb_options,
						       etype_list,
						       2);
		break;
	}

	} /* end switch */

	k5ret = krb5_get_init_creds_password(smb_krb5_context->krb5_context, &my_creds, principal,
					     password, NULL, NULL, 0,
					     NULL, krb_options);
	krb5_get_init_creds_opt_free(smb_krb5_context->krb5_context, krb_options);

	switch (test)
	{
	case TORTURE_KRB5_TEST_PLAIN:
	case TORTURE_KRB5_TEST_CHANGE_SERVER_IN:
	case TORTURE_KRB5_TEST_PAC_REQUEST:
	case TORTURE_KRB5_TEST_AES:
	case TORTURE_KRB5_TEST_RC4:
	case TORTURE_KRB5_TEST_AES_RC4:
	{
		char *got_principal_string;
		char *assertion_message;
		torture_assert_int_equal(tctx, k5ret, 0, "krb5_get_init_creds_password failed");

		torture_assert_int_equal(tctx,
					 krb5_principal_get_type(k5_context,
								 my_creds.client),
					 KRB5_NT_PRINCIPAL,
					 "smb_krb5_init_context gave incorrect client->name.name_type");

		torture_assert_int_equal(tctx,
					 krb5_unparse_name(k5_context,
							   my_creds.client,
							   &got_principal_string), 0,
					 "krb5_unparse_name failed");

		assertion_message = talloc_asprintf(tctx,
						    "krb5_get_init_creds_password returned a different principal %s to what was expected %s",
						    got_principal_string, expected_principal_string);
		krb5_free_unparsed_name(k5_context, got_principal_string);

		torture_assert(tctx, krb5_principal_compare(k5_context,
							    my_creds.client,
							    principal),
			       assertion_message);


		torture_assert_str_equal(tctx,
					 my_creds.server->name.name_string.val[0],
					 "krbtgt",
					 "Mismatch in name between AS_REP and expected response, expected krbtgt");
		torture_assert_str_equal(tctx,
					 my_creds.server->name.name_string.val[1],
					 realm,
					 "Mismatch in realm part of krbtgt/ in AS_REP, expected krbtgt/REALM@REALM");

		torture_assert_str_equal(tctx,
					 my_creds.server->realm,
					 realm,
					 "Mismatch in server realm in AS_REP, expected krbtgt/REALM@REALM");

		break;
	}
	case TORTURE_KRB5_TEST_BREAK_PW:
		torture_assert_int_equal(tctx, k5ret, KRB5KDC_ERR_PREAUTH_FAILED, "krb5_get_init_creds_password should have failed");
		return true;

	case TORTURE_KRB5_TEST_CLOCK_SKEW:
		torture_assert_int_equal(tctx, k5ret, KRB5KRB_AP_ERR_SKEW, "krb5_get_init_creds_password should have failed");
		return true;

	case TORTURE_KRB5_TEST_CHANGE_SERVER_OUT:
	case TORTURE_KRB5_TEST_CHANGE_SERVER_BOTH:
	{
		char *got_principal_string;
		char *assertion_message;
		torture_assert_int_equal(tctx, k5ret, 0, "krb5_get_init_creds_password failed");

		torture_assert_int_equal(tctx,
					 krb5_principal_get_type(k5_context,
								 my_creds.client),
					 KRB5_NT_PRINCIPAL,
					 "smb_krb5_init_context gave incorrect client->name.name_type");

		torture_assert_int_equal(tctx,
					 krb5_unparse_name(k5_context,
							   my_creds.client,
							   &got_principal_string), 0,
					 "krb5_unparse_name failed");

		assertion_message = talloc_asprintf(tctx,
						    "krb5_get_init_creds_password returned a different principal %s to what was expected %s",
						    got_principal_string, expected_principal_string);
		krb5_free_unparsed_name(k5_context, got_principal_string);

		torture_assert(tctx, krb5_principal_compare(k5_context,
							    my_creds.client,
							    principal),
			       assertion_message);

		if (krb5_hostname[0] == '\0') {
			break;
		}

		torture_assert_str_equal(tctx,
					 my_creds.server->name.name_string.val[0],
					 krb5_service,
					 "Mismatch in name[0] between AS_REP and expected response");
		torture_assert_str_equal(tctx,
					 my_creds.server->name.name_string.val[1],
					 krb5_hostname,
					 "Mismatch in name[1] between AS_REP and expected response");

		torture_assert_str_equal(tctx,
					 my_creds.server->realm,
					 realm,
					 "Mismatch in server realm in AS_REP, expected krbtgt/REALM@REALM");

		break;
	}
	}

	k5ret = krb5_free_cred_contents(smb_krb5_context->krb5_context, &my_creds);
	torture_assert_int_equal(tctx, k5ret, 0, "krb5_free_creds failed");

	return true;
}

static bool torture_krb5_as_req_cmdline(struct torture_context *tctx)
{
	return torture_krb5_as_req_creds(tctx, popt_get_cmdline_credentials(),
			TORTURE_KRB5_TEST_PLAIN);
}

static bool torture_krb5_as_req_pac_request(struct torture_context *tctx)
{
	if (torture_setting_bool(tctx, "expect_rodc", false)) {
		torture_skip(tctx, "This test needs further investigation in the RODC case against a Windows DC, in particular with non-cached users");
	}
	return torture_krb5_as_req_creds(tctx, popt_get_cmdline_credentials(),
			TORTURE_KRB5_TEST_PAC_REQUEST);
}

static bool torture_krb5_as_req_break_pw(struct torture_context *tctx)
{
	return torture_krb5_as_req_creds(tctx, popt_get_cmdline_credentials(),
			TORTURE_KRB5_TEST_BREAK_PW);
}

static bool torture_krb5_as_req_clock_skew(struct torture_context *tctx)
{
	return torture_krb5_as_req_creds(tctx, popt_get_cmdline_credentials(),
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

/* Checking for the "Orpheus' Lyre" attack */
static bool torture_krb5_as_req_change_server_out(struct torture_context *tctx)
{
	return torture_krb5_as_req_creds(tctx,
					 popt_get_cmdline_credentials(),
					 TORTURE_KRB5_TEST_CHANGE_SERVER_OUT);
}

static bool torture_krb5_as_req_change_server_in(struct torture_context *tctx)
{
	return torture_krb5_as_req_creds(tctx,
					 popt_get_cmdline_credentials(),
					 TORTURE_KRB5_TEST_CHANGE_SERVER_IN);
}

static bool torture_krb5_as_req_change_server_both(struct torture_context *tctx)
{
	return torture_krb5_as_req_creds(tctx,
					 popt_get_cmdline_credentials(),
					 TORTURE_KRB5_TEST_CHANGE_SERVER_BOTH);
}

NTSTATUS torture_krb5_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "krb5");
	struct torture_suite *kdc_suite = torture_suite_create(suite, "kdc");
	suite->description = talloc_strdup(suite, "Kerberos tests");
	kdc_suite->description = talloc_strdup(kdc_suite, "Kerberos KDC tests");

	torture_suite_add_simple_test(kdc_suite, "as-req-cmdline",
				      torture_krb5_as_req_cmdline);

	torture_suite_add_simple_test(kdc_suite, "as-req-pac-request",
				      torture_krb5_as_req_pac_request);

	torture_suite_add_simple_test(kdc_suite, "as-req-break-pw",
				      torture_krb5_as_req_break_pw);

	torture_suite_add_simple_test(kdc_suite, "as-req-clock-skew",
				      torture_krb5_as_req_clock_skew);

	torture_suite_add_simple_test(kdc_suite,
				      "as-req-aes",
				      torture_krb5_as_req_aes);

	torture_suite_add_simple_test(kdc_suite,
				      "as-req-rc4",
				      torture_krb5_as_req_rc4);

	torture_suite_add_simple_test(kdc_suite,
				      "as-req-aes-rc4",
				      torture_krb5_as_req_aes_rc4);

	/* 
	 * This is in and out of the client. 
	 * Out refers to requests, in refers to replies
	 */
	torture_suite_add_simple_test(kdc_suite,
				      "as-req-change-server-in",
				      torture_krb5_as_req_change_server_in);

	torture_suite_add_simple_test(kdc_suite,
				      "as-req-change-server-out",
				      torture_krb5_as_req_change_server_out);

	torture_suite_add_simple_test(kdc_suite,
				      "as-req-change-server-both",
				      torture_krb5_as_req_change_server_both);

	torture_suite_add_suite(kdc_suite, torture_krb5_canon(kdc_suite));
	torture_suite_add_suite(suite, kdc_suite);

	torture_register_suite(ctx, suite);
	return NT_STATUS_OK;
}
