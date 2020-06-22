/*
 * Unit tests for ldap_message.
 *
 *  Copyright (C) Catalyst.NET Ltd 2020
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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "lib/util/attr.h"
#include "includes.h"
#include "lib/util/asn1.h"
#include "libcli/ldap/ldap_message.h"
#include "libcli/ldap/ldap_proto.h"

/*
 * declare the internal cmocka cm_print so we can output messages in
 * sub unit format
 */
void cm_print_error(const char * const format, ...);
/*
 * helper function and macro to compare an ldap error code constant with the
 * coresponding nt_status code
 */
#define NT_STATUS_LDAP_V(code) (0xF2000000 | code)
static void _assert_ldap_status_equal(
	int a,
	NTSTATUS b,
	const char * const file,
	const int line)
{
	_assert_int_equal(NT_STATUS_LDAP_V(a), NT_STATUS_V(b), file, line);
}

#define assert_ldap_status_equal(a, b) \
	_assert_ldap_status_equal((a), (b), __FILE__, __LINE__)

/*
 * helper function and macro to assert there were no errors in the last
 * file operation
 */
static void _assert_not_ferror(
	FILE *f,
	const char * const file,
	const int line)
{
	if (f == NULL || ferror(f)) {
		cm_print_error("ferror (%d) %s\n", errno, strerror(errno));
		_fail(file, line);
	}
}

#define assert_not_ferror(f) \
	_assert_not_ferror((f), __FILE__, __LINE__)

struct test_ctx {
};

static int setup(void **state)
{
	struct test_ctx *test_ctx;

	test_ctx = talloc_zero(NULL, struct test_ctx);
	*state = test_ctx;
	return 0;
}

static int teardown(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);

	TALLOC_FREE(test_ctx);
	return 0;
}

/*
 * Test that an empty request is handled correctly
 */
static void test_empty_input(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(
		*state,
		struct test_ctx);
	struct asn1_data *asn1;
	struct ldap_message *ldap_msg;
	NTSTATUS status;
	uint8_t *buf = NULL;
	size_t len = 0;
	struct ldap_request_limits limits = {
		.max_search_size = 256000,
	};


	asn1 = asn1_init(test_ctx, ASN1_MAX_TREE_DEPTH);
	assert_non_null(asn1);

	asn1_load_nocopy(asn1, buf, len);

	ldap_msg = talloc(test_ctx, struct ldap_message);
	assert_non_null(ldap_msg);

	status = ldap_decode(
		asn1, &limits, samba_ldap_control_handlers(), ldap_msg);
	assert_ldap_status_equal(LDAP_PROTOCOL_ERROR, status);
}

/*
 * Check that a request is rejected it it's recursion depth exceeds
 * the maximum value specified. This test uses a very deeply nested query,
 * 10,000 or clauses.
 *
 */
static void test_recursion_depth_large(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(
		*state,
		struct test_ctx);
	struct asn1_data *asn1;
	struct ldap_message *ldap_msg;
	NTSTATUS status;
	FILE *f = NULL;
	uint8_t *buffer = NULL;
	const size_t BUFF_SIZE = 1048576;
	size_t len;
	struct ldap_request_limits limits = {
		.max_search_size = 256000,
	};


	/*
	 * Load a test data file containg 10,000 or clauses in encoded as
	 * an ASN.1 packet.
	 */
	buffer = talloc_zero_array(test_ctx, uint8_t, BUFF_SIZE);
	f = fopen("./libcli/ldap/tests/data/10000-or.dat", "r");
	assert_not_ferror(f);
	len = fread(buffer, sizeof(uint8_t), BUFF_SIZE, f);
	assert_not_ferror(f);
	assert_true(len > 0);

	asn1 = asn1_init(test_ctx, ASN1_MAX_TREE_DEPTH);
	assert_non_null(asn1);
	asn1_load_nocopy(asn1, buffer, len);

	ldap_msg = talloc(test_ctx, struct ldap_message);
	assert_non_null(ldap_msg);

	status = ldap_decode(
		asn1, &limits, samba_ldap_control_handlers(), ldap_msg);
	assert_ldap_status_equal(LDAP_PROTOCOL_ERROR, status);
}

/*
 * Check that a request is not rejected it it's recursion depth equals the
 * maximum value
 */
static void test_recursion_depth_equals_max(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(
		*state,
		struct test_ctx);
	struct asn1_data *asn1;
	struct ldap_message *ldap_msg;
	NTSTATUS status;
	FILE *f = NULL;
	uint8_t *buffer = NULL;
	const size_t BUFF_SIZE = 1048576;
	size_t len;
	struct ldap_request_limits limits = {
		.max_search_size = 256000,
	};


	buffer = talloc_zero_array(test_ctx, uint8_t, BUFF_SIZE);
	f = fopen("./libcli/ldap/tests/data/ldap-recursive.dat", "r");
	assert_not_ferror(f);
	len = fread(buffer, sizeof(uint8_t), BUFF_SIZE, f);
	assert_not_ferror(f);
	assert_true(len > 0);

	asn1 = asn1_init(test_ctx, 4);
	assert_non_null(asn1);
	asn1_load_nocopy(asn1, buffer, len);

	ldap_msg = talloc(test_ctx, struct ldap_message);
	assert_non_null(ldap_msg);

	status = ldap_decode(
		asn1, &limits, samba_ldap_control_handlers(), ldap_msg);
	assert_true(NT_STATUS_IS_OK(status));
}

/*
 * Check that a request is rejected it it's recursion depth is greater than the
 * maximum value
 */
static void test_recursion_depth_greater_than_max(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(
		*state,
		struct test_ctx);
	struct asn1_data *asn1;
	struct ldap_message *ldap_msg;
	NTSTATUS status;
	FILE *f = NULL;
	uint8_t *buffer = NULL;
	const size_t BUFF_SIZE = 1048576;
	size_t len;
	struct ldap_request_limits limits = {
		.max_search_size = 256000,
	};


	buffer = talloc_zero_array(test_ctx, uint8_t, BUFF_SIZE);
	f = fopen("./libcli/ldap/tests/data/ldap-recursive.dat", "r");
	assert_not_ferror(f);
	len = fread(buffer, sizeof(uint8_t), BUFF_SIZE, f);
	assert_not_ferror(f);
	assert_true(len > 0);

	asn1 = asn1_init(test_ctx, 3);
	assert_non_null(asn1);
	asn1_load_nocopy(asn1, buffer, len);

	ldap_msg = talloc(test_ctx, struct ldap_message);
	assert_non_null(ldap_msg);

	status = ldap_decode(
		asn1, &limits, samba_ldap_control_handlers(), ldap_msg);
	assert_ldap_status_equal(LDAP_PROTOCOL_ERROR, status);
}

int main(_UNUSED_ int argc, _UNUSED_ const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
			test_empty_input,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_recursion_depth_large,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_recursion_depth_equals_max,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_recursion_depth_greater_than_max,
			setup,
			teardown),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
