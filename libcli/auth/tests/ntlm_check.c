/*
 * Unit tests for the ntlm_check password hash check library.
 *
 *  Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/*
 * from cmocka.c:
 * These headers or their equivalents should be included prior to
 * including
 * this header file.
 *
 * #include <stdarg.h>
 * #include <stddef.h>
 * #include <setjmp.h>
 *
 * This allows test applications to use custom definitions of C standard
 * library functions and types.
 *
 */

/*
 * Note that the messaging routines (audit_message_send and get_event_server)
 * are not tested by these unit tests.  Currently they are for integration
 * test support, and as such are exercised by the integration tests.
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "includes.h"
#include "librpc/gen_ndr/netlogon.h"
#include "libcli/auth/libcli_auth.h"
#include "auth/credentials/credentials.h"

struct ntlm_state {
	const char *username;
	const char *domain;
	DATA_BLOB challenge;
	DATA_BLOB ntlm;
	DATA_BLOB lm;
	DATA_BLOB ntlm_key;
	DATA_BLOB lm_key;
	const struct samr_Password *nt_hash;
};

static int test_ntlm_setup_with_options(void **state,
					int flags, bool upn)
{
	NTSTATUS status;
	DATA_BLOB challenge = {
		.data = discard_const_p(uint8_t, "I am a teapot"),
		.length = 8
	};
	struct ntlm_state *ntlm_state = talloc(NULL, struct ntlm_state);
	DATA_BLOB target_info = NTLMv2_generate_names_blob(ntlm_state,
							   NULL,
							   "serverdom");
	struct cli_credentials *creds = cli_credentials_init(ntlm_state);
	cli_credentials_set_username(creds,
				     "testuser",
				     CRED_SPECIFIED);
	cli_credentials_set_domain(creds,
				   "testdom",
				   CRED_SPECIFIED);
	cli_credentials_set_workstation(creds,
					"testwksta",
					CRED_SPECIFIED);
	cli_credentials_set_password(creds,
				     "testpass",
				     CRED_SPECIFIED);

	if (upn) {
		cli_credentials_set_principal(creds,
					      "testuser@samba.org",
					      CRED_SPECIFIED);
	}

	cli_credentials_get_ntlm_username_domain(creds,
						 ntlm_state,
						 &ntlm_state->username,
						 &ntlm_state->domain);

	status = cli_credentials_get_ntlm_response(creds,
						   ntlm_state,
						   &flags,
						   challenge,
						   NULL,
						   target_info,
						   &ntlm_state->lm,
						   &ntlm_state->ntlm,
						   &ntlm_state->lm_key,
						   &ntlm_state->ntlm_key);
	ntlm_state->challenge = challenge;

	ntlm_state->nt_hash = cli_credentials_get_nt_hash(creds,
							  ntlm_state);

	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}

	*state = ntlm_state;
	return 0;
}

static int test_ntlm_setup(void **state) {
	return test_ntlm_setup_with_options(state, 0, false);
}

static int test_ntlm_and_lm_setup(void **state) {
	return test_ntlm_setup_with_options(state,
					    CLI_CRED_LANMAN_AUTH,
					    false);
}

static int test_ntlm2_setup(void **state) {
	return test_ntlm_setup_with_options(state,
					    CLI_CRED_NTLM2,
					    false);
}

static int test_ntlmv2_setup(void **state) {
	return test_ntlm_setup_with_options(state,
					    CLI_CRED_NTLMv2_AUTH,
					    false);
}

static int test_ntlm_teardown(void **state)
{
	struct ntlm_state *ntlm_state
		= talloc_get_type_abort(*state,
					struct ntlm_state);
	TALLOC_FREE(ntlm_state);
	*state = NULL;
	return 0;
}

static void test_ntlm_allowed(void **state)
{
	DATA_BLOB user_sess_key, lm_sess_key;
	struct ntlm_state *ntlm_state
		= talloc_get_type_abort(*state,
					struct ntlm_state);
	NTSTATUS status;
	status = ntlm_password_check(ntlm_state,
				     false,
				     NTLM_AUTH_ON,
				     0,
				     &ntlm_state->challenge,
				     &ntlm_state->lm,
				     &ntlm_state->ntlm,
				     ntlm_state->username,
				     ntlm_state->username,
				     ntlm_state->domain,
				     NULL,
				     ntlm_state->nt_hash,
				     &user_sess_key,
				     &lm_sess_key);

	assert_int_equal(NT_STATUS_V(status), NT_STATUS_V(NT_STATUS_OK));
}

static void test_ntlm_allowed_lm_supplied(void **state)
{
	test_ntlm_allowed(state);
}

static void test_ntlm_disabled(void **state)
{
	DATA_BLOB user_sess_key, lm_sess_key;
	struct ntlm_state *ntlm_state
		= talloc_get_type_abort(*state,
					struct ntlm_state);
	NTSTATUS status;
	status = ntlm_password_check(ntlm_state,
				     false,
				     NTLM_AUTH_DISABLED,
				     0,
				     &ntlm_state->challenge,
				     &ntlm_state->lm,
				     &ntlm_state->ntlm,
				     ntlm_state->username,
				     ntlm_state->username,
				     ntlm_state->domain,
				     NULL,
				     ntlm_state->nt_hash,
				     &user_sess_key,
				     &lm_sess_key);

	assert_int_equal(NT_STATUS_V(status), NT_STATUS_V(NT_STATUS_NTLM_BLOCKED));
}

static void test_ntlm2(void **state)
{
	DATA_BLOB user_sess_key, lm_sess_key;
	struct ntlm_state *ntlm_state
		= talloc_get_type_abort(*state,
					struct ntlm_state);
	NTSTATUS status;
	status = ntlm_password_check(ntlm_state,
				     false,
				     NTLM_AUTH_ON,
				     0,
				     &ntlm_state->challenge,
				     &ntlm_state->lm,
				     &ntlm_state->ntlm,
				     ntlm_state->username,
				     ntlm_state->username,
				     ntlm_state->domain,
				     NULL,
				     ntlm_state->nt_hash,
				     &user_sess_key,
				     &lm_sess_key);

	/*
	 * NTLM2 session security (where the real challenge is the
	 * MD5(challenge, client-challenge) (in the first 8 bytes of
	 * the lm) isn't decoded by ntlm_password_check(), it must
	 * first be converted back into normal NTLM by the NTLMSSP
	 * layer
	 */
	assert_int_equal(NT_STATUS_V(status),
			 NT_STATUS_V(NT_STATUS_WRONG_PASSWORD));
}

static void test_ntlm_mschapv2_only_allowed(void **state)
{
	DATA_BLOB user_sess_key, lm_sess_key;
	struct ntlm_state *ntlm_state
		= talloc_get_type_abort(*state,
					struct ntlm_state);
	NTSTATUS status;
	status = ntlm_password_check(ntlm_state,
				     false,
				     NTLM_AUTH_MSCHAPv2_NTLMV2_ONLY,
				     MSV1_0_ALLOW_MSVCHAPV2,
				     &ntlm_state->challenge,
				     &ntlm_state->lm,
				     &ntlm_state->ntlm,
				     ntlm_state->username,
				     ntlm_state->username,
				     ntlm_state->domain,
				     NULL,
				     ntlm_state->nt_hash,
				     &user_sess_key,
				     &lm_sess_key);

	assert_int_equal(NT_STATUS_V(status), NT_STATUS_V(NT_STATUS_OK));
}

static void test_ntlm_mschapv2_only_denied(void **state)
{
	DATA_BLOB user_sess_key, lm_sess_key;
	struct ntlm_state *ntlm_state
		= talloc_get_type_abort(*state,
					struct ntlm_state);
	NTSTATUS status;
	status = ntlm_password_check(ntlm_state,
				     false,
				     NTLM_AUTH_MSCHAPv2_NTLMV2_ONLY,
				     0,
				     &ntlm_state->challenge,
				     &ntlm_state->lm,
				     &ntlm_state->ntlm,
				     ntlm_state->username,
				     ntlm_state->username,
				     ntlm_state->domain,
				     NULL,
				     ntlm_state->nt_hash,
				     &user_sess_key,
				     &lm_sess_key);

	assert_int_equal(NT_STATUS_V(status),
			 NT_STATUS_V(NT_STATUS_WRONG_PASSWORD));
}

static void test_ntlmv2_only_ntlmv2(void **state)
{
	DATA_BLOB user_sess_key, lm_sess_key;
	struct ntlm_state *ntlm_state
		= talloc_get_type_abort(*state,
					struct ntlm_state);
	NTSTATUS status;
	status = ntlm_password_check(ntlm_state,
				     false,
				     NTLM_AUTH_NTLMV2_ONLY,
				     0,
				     &ntlm_state->challenge,
				     &ntlm_state->lm,
				     &ntlm_state->ntlm,
				     ntlm_state->username,
				     ntlm_state->username,
				     ntlm_state->domain,
				     NULL,
				     ntlm_state->nt_hash,
				     &user_sess_key,
				     &lm_sess_key);

	assert_int_equal(NT_STATUS_V(status), NT_STATUS_V(NT_STATUS_OK));
}

static void test_ntlmv2_only_ntlm(void **state)
{
	DATA_BLOB user_sess_key, lm_sess_key;
	struct ntlm_state *ntlm_state
		= talloc_get_type_abort(*state,
					struct ntlm_state);
	NTSTATUS status;
	status = ntlm_password_check(ntlm_state,
				     false,
				     NTLM_AUTH_NTLMV2_ONLY,
				     0,
				     &ntlm_state->challenge,
				     &ntlm_state->lm,
				     &ntlm_state->ntlm,
				     ntlm_state->username,
				     ntlm_state->username,
				     ntlm_state->domain,
				     NULL,
				     ntlm_state->nt_hash,
				     &user_sess_key,
				     &lm_sess_key);

	assert_int_equal(NT_STATUS_V(status),
			 NT_STATUS_V(NT_STATUS_WRONG_PASSWORD));
}

static void test_ntlmv2_only_ntlm_and_lanman(void **state)
{
	test_ntlmv2_only_ntlm(state);
}

static void test_ntlmv2_only_ntlm_once(void **state)
{
	DATA_BLOB user_sess_key, lm_sess_key;
	struct ntlm_state *ntlm_state
		= talloc_get_type_abort(*state,
					struct ntlm_state);
	NTSTATUS status;
	status = ntlm_password_check(ntlm_state,
				     false,
				     NTLM_AUTH_NTLMV2_ONLY,
				     0,
				     &ntlm_state->challenge,
				     &data_blob_null,
				     &ntlm_state->ntlm,
				     ntlm_state->username,
				     ntlm_state->username,
				     ntlm_state->domain,
				     NULL,
				     ntlm_state->nt_hash,
				     &user_sess_key,
				     &lm_sess_key);

	assert_int_equal(NT_STATUS_V(status),
			 NT_STATUS_V(NT_STATUS_WRONG_PASSWORD));
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_ntlm_allowed,
						test_ntlm_setup,
						test_ntlm_teardown),
		cmocka_unit_test_setup_teardown(test_ntlm_allowed_lm_supplied,
						test_ntlm_and_lm_setup,
						test_ntlm_teardown),
		cmocka_unit_test_setup_teardown(test_ntlm_disabled,
						test_ntlm_setup,
						test_ntlm_teardown),
		cmocka_unit_test_setup_teardown(test_ntlm2,
						test_ntlm2_setup,
						test_ntlm_teardown),
		cmocka_unit_test_setup_teardown(test_ntlm_mschapv2_only_allowed,
						test_ntlm_setup,
						test_ntlm_teardown),
		cmocka_unit_test_setup_teardown(test_ntlm_mschapv2_only_denied,
						test_ntlm_setup,
						test_ntlm_teardown),
		cmocka_unit_test_setup_teardown(test_ntlmv2_only_ntlm,
						test_ntlm_setup,
						test_ntlm_teardown),
		cmocka_unit_test_setup_teardown(test_ntlmv2_only_ntlm_and_lanman,
						test_ntlm_and_lm_setup,
						test_ntlm_teardown),
		cmocka_unit_test_setup_teardown(test_ntlmv2_only_ntlm_once,
						test_ntlm_setup,
						test_ntlm_teardown),
		cmocka_unit_test_setup_teardown(test_ntlmv2_only_ntlmv2,
						test_ntlmv2_setup,
						test_ntlm_teardown)
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
