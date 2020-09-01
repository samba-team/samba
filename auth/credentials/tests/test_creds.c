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

	username = cli_credentials_get_username(creds);
	assert_null(username);
	ok = cli_credentials_set_username(creds, "brot", CRED_SPECIFIED);
	assert_true(ok);
	assert_int_equal(creds->username_obtained, CRED_SPECIFIED);
	username = cli_credentials_get_username(creds);
	assert_string_equal(username, "brot");

	password = cli_credentials_get_password(creds);
	assert_null(password);
	ok = cli_credentials_set_password(creds, "SECRET", CRED_SPECIFIED);
	assert_true(ok);
	assert_int_equal(creds->password_obtained, CRED_SPECIFIED);
	password = cli_credentials_get_password(creds);
	assert_string_equal(password, "SECRET");
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

	creds = cli_credentials_init(mem_ctx);
	assert_non_null(creds);

	setenv("PASSWD", "SECRET", 1);
	cli_credentials_guess(creds, NULL);

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

	creds = cli_credentials_init_anon(mem_ctx);
	assert_non_null(creds);

	setenv("PASSWD", "SECRET", 1);
	cli_credentials_guess(creds, NULL);

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
	assert_int_equal(creds->username_obtained, CRED_SPECIFIED);

	assert_string_equal(creds->principal, "wurst@brot.realm");
	assert_int_equal(creds->principal_obtained, CRED_SPECIFIED);

	assert_string_equal(creds->password, "BROT");
	assert_int_equal(creds->password_obtained, CRED_SPECIFIED);
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
