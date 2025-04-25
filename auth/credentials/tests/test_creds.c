/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) 2018-2019 Andreas Schneider <asn@samba.org>
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
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "lib/replace/replace.h"
#include "auth/credentials/credentials.c"

static int setup_talloc_context(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();

	*state = frame;
	return 0;
}

static int teardown_talloc_context(void **state)
{
	TALLOC_CTX *frame = *state;
	TALLOC_FREE(frame);
	return 0;
}

static void torture_creds_init(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	struct cli_credentials *creds = NULL;
	const char *username = NULL;
	const char *domain = NULL;
	const char *password = NULL;
	enum credentials_obtained dom_obtained = CRED_UNINITIALISED;
	enum credentials_obtained usr_obtained = CRED_UNINITIALISED;
	enum credentials_obtained pwd_obtained = CRED_UNINITIALISED;
	bool ok;

	creds = cli_credentials_init(mem_ctx);
	assert_non_null(creds);
	assert_null(creds->username);
	assert_int_equal(creds->username_obtained, CRED_UNINITIALISED);

	domain = cli_credentials_get_domain(creds);
	assert_null(domain);
	ok = cli_credentials_set_domain(creds, "WURST", CRED_SPECIFIED);
	assert_true(ok);
	assert_int_equal(creds->domain_obtained, CRED_SPECIFIED);
	domain = cli_credentials_get_domain(creds);
	assert_string_equal(domain, "WURST");

	domain = cli_credentials_get_domain_and_obtained(creds,
							 &dom_obtained);
	assert_int_equal(dom_obtained, CRED_SPECIFIED);
	assert_string_equal(domain, "WURST");

	username = cli_credentials_get_username(creds);
	assert_null(username);
	ok = cli_credentials_set_username(creds, "brot", CRED_SPECIFIED);
	assert_true(ok);
	assert_int_equal(creds->username_obtained, CRED_SPECIFIED);
	username = cli_credentials_get_username(creds);
	assert_string_equal(username, "brot");

	username = cli_credentials_get_username_and_obtained(creds,
							     &usr_obtained);
	assert_int_equal(usr_obtained, CRED_SPECIFIED);
	assert_string_equal(username, "brot");

	password = cli_credentials_get_password(creds);
	assert_null(password);
	ok = cli_credentials_set_password(creds, "SECRET", CRED_SPECIFIED);
	assert_true(ok);
	assert_int_equal(creds->password_obtained, CRED_SPECIFIED);
	password = cli_credentials_get_password(creds);
	assert_string_equal(password, "SECRET");

	password = cli_credentials_get_password_and_obtained(creds,
							     &pwd_obtained);
	assert_int_equal(pwd_obtained, CRED_SPECIFIED);
	assert_string_equal(password, "SECRET");

	/* Run dump to check it works */
	cli_credentials_dump(creds);
}

static void torture_creds_init_anonymous(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	struct cli_credentials *creds = NULL;

	creds = cli_credentials_init_anon(mem_ctx);
	assert_non_null(creds);

	assert_string_equal(creds->domain, "");
	assert_int_equal(creds->domain_obtained, CRED_SPECIFIED);

	assert_string_equal(creds->username, "");
	assert_int_equal(creds->username_obtained, CRED_SPECIFIED);

	assert_null(creds->password);
	assert_int_equal(creds->password_obtained, CRED_SPECIFIED);
}

static void torture_creds_guess(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	struct cli_credentials *creds = NULL;
	const char *env_user = getenv("USER");
	bool ok;

	creds = cli_credentials_init(mem_ctx);
	assert_non_null(creds);

	setenv("PASSWD", "SECRET", 1);
	ok = cli_credentials_guess(creds, NULL);
	assert_true(ok);

	assert_string_equal(creds->username, env_user);
	assert_int_equal(creds->username_obtained, CRED_GUESS_ENV);

	assert_string_equal(creds->password, "SECRET");
	assert_int_equal(creds->password_obtained, CRED_GUESS_ENV);
	unsetenv("PASSWD");
}

static void torture_creds_anon_guess(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	struct cli_credentials *creds = NULL;
	bool ok;

	creds = cli_credentials_init_anon(mem_ctx);
	assert_non_null(creds);

	setenv("PASSWD", "SECRET", 1);
	ok = cli_credentials_guess(creds, NULL);
	assert_true(ok);

	assert_string_equal(creds->username, "");
	assert_int_equal(creds->username_obtained, CRED_SPECIFIED);

	assert_null(creds->password);
	assert_int_equal(creds->password_obtained, CRED_SPECIFIED);
	unsetenv("PASSWD");
}

static void torture_creds_parse_string(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	struct cli_credentials *creds = NULL;
	enum credentials_obtained princ_obtained = CRED_UNINITIALISED;
	enum credentials_obtained usr_obtained = CRED_UNINITIALISED;
	enum credentials_obtained pwd_obtained = CRED_UNINITIALISED;

	creds = cli_credentials_init(mem_ctx);
	assert_non_null(creds);

	/* Anonymous */
	cli_credentials_parse_string(creds, "%", CRED_SPECIFIED);

	assert_string_equal(creds->domain, "");
	assert_int_equal(creds->domain_obtained, CRED_SPECIFIED);

	assert_string_equal(creds->username, "");
	assert_int_equal(creds->username_obtained, CRED_SPECIFIED);

	assert_null(creds->password);
	assert_int_equal(creds->password_obtained, CRED_SPECIFIED);

	/* Username + password */
	cli_credentials_parse_string(creds, "wurst%BROT", CRED_SPECIFIED);

	assert_string_equal(creds->domain, "");
	assert_int_equal(creds->domain_obtained, CRED_SPECIFIED);

	assert_string_equal(creds->username, "wurst");
	assert_int_equal(creds->username_obtained, CRED_SPECIFIED);

	assert_string_equal(creds->password, "BROT");
	assert_int_equal(creds->password_obtained, CRED_SPECIFIED);

	/* Domain + username + password */
	cli_credentials_parse_string(creds, "XXL\\wurst%BROT", CRED_SPECIFIED);

	assert_string_equal(creds->domain, "XXL");
	assert_int_equal(creds->domain_obtained, CRED_SPECIFIED);

	assert_string_equal(creds->username, "wurst");
	assert_int_equal(creds->username_obtained, CRED_SPECIFIED);

	assert_string_equal(creds->password, "BROT");
	assert_int_equal(creds->password_obtained, CRED_SPECIFIED);

	/* Principal */
	cli_credentials_parse_string(creds, "wurst@brot.realm", CRED_SPECIFIED);

	assert_string_equal(creds->domain, "");
	assert_int_equal(creds->domain_obtained, CRED_SPECIFIED);

	assert_string_equal(creds->username, "wurst@brot.realm");
	usr_obtained = cli_credentials_get_username_obtained(creds);
	assert_int_equal(usr_obtained, CRED_SPECIFIED);

	assert_string_equal(creds->principal, "wurst@BROT.REALM");
	princ_obtained = cli_credentials_get_principal_obtained(creds);
	assert_int_equal(princ_obtained, CRED_SPECIFIED);

	assert_string_equal(creds->password, "BROT");
	pwd_obtained = cli_credentials_get_password_obtained(creds);
	assert_int_equal(pwd_obtained, CRED_SPECIFIED);

}

static void torture_creds_krb5_state(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	struct cli_credentials *creds = NULL;
	struct loadparm_context *lp_ctx = NULL;
	enum credentials_obtained kerberos_state_obtained;
	enum credentials_use_kerberos kerberos_state;
	bool ok;

	lp_ctx = loadparm_init_global(true);
	assert_non_null(lp_ctx);

	creds = cli_credentials_init(mem_ctx);
	assert_non_null(creds);
	kerberos_state_obtained =
		cli_credentials_get_kerberos_state_obtained(creds);
	kerberos_state = cli_credentials_get_kerberos_state(creds);
	assert_int_equal(kerberos_state_obtained, CRED_UNINITIALISED);
	assert_int_equal(kerberos_state, CRED_USE_KERBEROS_DESIRED);

	ok = cli_credentials_set_conf(creds, lp_ctx);
	assert_true(ok);
	kerberos_state_obtained =
		cli_credentials_get_kerberos_state_obtained(creds);
	kerberos_state = cli_credentials_get_kerberos_state(creds);
	assert_int_equal(kerberos_state_obtained, CRED_SMB_CONF);
	assert_int_equal(kerberos_state, CRED_USE_KERBEROS_DESIRED);

	ok = cli_credentials_guess(creds, lp_ctx);
	assert_true(ok);
	kerberos_state_obtained =
		cli_credentials_get_kerberos_state_obtained(creds);
	kerberos_state = cli_credentials_get_kerberos_state(creds);
	assert_int_equal(kerberos_state_obtained, CRED_SMB_CONF);
	assert_int_equal(kerberos_state, CRED_USE_KERBEROS_DESIRED);
	assert_int_equal(creds->ccache_obtained, CRED_GUESS_FILE);
	assert_non_null(creds->ccache);

	ok = cli_credentials_set_kerberos_state(creds,
						CRED_USE_KERBEROS_REQUIRED,
						CRED_SPECIFIED);
	assert_true(ok);
	kerberos_state_obtained =
		cli_credentials_get_kerberos_state_obtained(creds);
	kerberos_state = cli_credentials_get_kerberos_state(creds);
	assert_int_equal(kerberos_state_obtained, CRED_SPECIFIED);
	assert_int_equal(kerberos_state, CRED_USE_KERBEROS_REQUIRED);

	ok = cli_credentials_set_kerberos_state(creds,
						CRED_USE_KERBEROS_DISABLED,
						CRED_SMB_CONF);
	assert_false(ok);
	kerberos_state_obtained =
		cli_credentials_get_kerberos_state_obtained(creds);
	kerberos_state = cli_credentials_get_kerberos_state(creds);
	assert_int_equal(kerberos_state_obtained, CRED_SPECIFIED);
	assert_int_equal(kerberos_state, CRED_USE_KERBEROS_REQUIRED);

}

static void torture_creds_gensec_feature(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	struct cli_credentials *creds = NULL;
	bool ok;

	creds = cli_credentials_init(mem_ctx);
	assert_non_null(creds);
	assert_int_equal(creds->gensec_features_obtained, CRED_UNINITIALISED);
	assert_int_equal(creds->gensec_features, 0);

	ok = cli_credentials_set_gensec_features(creds,
						 GENSEC_FEATURE_SIGN,
						 CRED_SPECIFIED);
	assert_true(ok);
	assert_int_equal(creds->gensec_features_obtained, CRED_SPECIFIED);
	assert_int_equal(creds->gensec_features, GENSEC_FEATURE_SIGN);

	ok = cli_credentials_set_gensec_features(creds,
						 GENSEC_FEATURE_SEAL,
						 CRED_SMB_CONF);
	assert_false(ok);
	assert_int_equal(creds->gensec_features_obtained, CRED_SPECIFIED);
	assert_int_equal(creds->gensec_features, GENSEC_FEATURE_SIGN);
}

static const char *torture_get_password(struct cli_credentials *creds)
{
	return talloc_strdup(creds, "SECRET");
}

static void torture_creds_password_callback(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	struct cli_credentials *creds = NULL;
	const char *password = NULL;
	enum credentials_obtained pwd_obtained = CRED_UNINITIALISED;
	bool ok;

	creds = cli_credentials_init(mem_ctx);
	assert_non_null(creds);

	ok = cli_credentials_set_domain(creds, "WURST", CRED_SPECIFIED);
	assert_true(ok);
	ok = cli_credentials_set_username(creds, "brot", CRED_SPECIFIED);
	assert_true(ok);

	ok = cli_credentials_set_password_callback(creds, torture_get_password);
	assert_true(ok);
	assert_int_equal(creds->password_obtained, CRED_CALLBACK);

	password = cli_credentials_get_password_and_obtained(creds,
							     &pwd_obtained);
	assert_int_equal(pwd_obtained, CRED_CALLBACK_RESULT);
	assert_string_equal(password, "SECRET");
}

int main(int argc, char *argv[])
{
	int rc;
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(torture_creds_init),
		cmocka_unit_test(torture_creds_init_anonymous),
		cmocka_unit_test(torture_creds_guess),
		cmocka_unit_test(torture_creds_anon_guess),
		cmocka_unit_test(torture_creds_parse_string),
		cmocka_unit_test(torture_creds_krb5_state),
		cmocka_unit_test(torture_creds_gensec_feature),
		cmocka_unit_test(torture_creds_password_callback)
	};

	if (argc == 2) {
		cmocka_set_test_filter(argv[1]);
	}
	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	rc = cmocka_run_group_tests(tests,
				    setup_talloc_context,
				    teardown_talloc_context);

	return rc;
}
