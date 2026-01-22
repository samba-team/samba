/*
 * cmocka unit tests for the DEBUGJSON and DEBUGJSONC debug macros
 *
 *  Copyright (C) Gary Lockyer 2026 <gary@catalyst.net.nz>
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

#include "lib/util/debug.h"
#include <talloc.h>
#include <string.h>

#define MAX_CALLS 4

/*
 * This needs to be the same as the value set in lib/util/debug.c
 */
#define FORMAT_BUFR_SIZE 4096

#define FORMAT_STRING_SIZE (FORMAT_BUFR_SIZE - 1)

/*
 * Test context
 */
struct test_ctx {
	size_t calls;  /* number of times callback fn called */
	char **data;   /* data passed in each call           */
};

/*
* debug logging call back function.
*
* NOTE: The debug code calling this function debug.c:debug_callback_log
*       will replace a trailing '\n' with a '\0'
*/
static void debug_callback(void *state, int level, const char *msg) {
	struct test_ctx *test_ctx = talloc_get_type_abort(state,
							  struct test_ctx);
	assert_non_null(test_ctx);

	assert_int_not_equal(MAX_CALLS, test_ctx->calls);
	test_ctx->data[test_ctx->calls] = talloc_strdup(test_ctx, msg);
	assert_non_null(test_ctx->data[test_ctx->calls]);

	test_ctx->calls++;
}

/*
* Test set-up.
*
* creates and initializes the test context
*/
static int setup(void **state)
{
	struct test_ctx *test_ctx;

	test_ctx = talloc_zero(NULL, struct test_ctx);
	assert_non_null(test_ctx);

	test_ctx->data = talloc_array(test_ctx, char *, MAX_CALLS);

	debug_set_callback(test_ctx, debug_callback);
	debuglevel_set_class(DBGC_ALL, DBGLVL_NOTICE);
	debuglevel_set_class(DBGC_DSDB_AUDIT_JSON, DBGLVL_INFO);

	*state = test_ctx;
	return 0;
}

/*
* Test clean up
*
* deallocate any memory used by the test context
*
*/
static int teardown(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);

	talloc_free(test_ctx);
	return 0;
}
/*
* Test DEBUGJSONC with an empty message
*/
static void test_empty_message(void **state)
{
	const char *message = "";
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	assert_non_null(test_ctx);

	DEBUGJSONC(DBGC_DSDB_AUDIT_JSON, DBGLVL_INFO, (message));
	assert_int_equal(1, test_ctx->calls);
	assert_string_equal("", test_ctx->data[0]);
}

/*
* Test DEBUGJSONC with a short message
*/
static void test_short_message(void **state)
{
	const char *message = "A message";
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	assert_non_null(test_ctx);

	DEBUGJSONC(DBGC_DSDB_AUDIT_JSON, DBGLVL_INFO, (message));
	assert_int_equal(2, test_ctx->calls);
	assert_string_equal(message, test_ctx->data[0]);
	assert_string_equal("", test_ctx->data[1]);
}

/*
* Test DEBUGJSONC honours the debug class levels
*/
static void test_log_class(void **state)
{
	const char *message = "A message";
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	assert_non_null(test_ctx);

	DEBUGJSONC(DBGC_DSDB_AUDIT, DBGLVL_INFO, (message));
	assert_int_equal(0, test_ctx->calls);
}

/*
* Test DEBUGJSONC honours its debug level
*/
static void test_log_level(void **state)
{
	const char *message = "A message";
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	assert_non_null(test_ctx);

	DEBUGJSONC(DBGC_DSDB_AUDIT_JSON, DBGLVL_DEBUG, (message));
	assert_int_equal(0, test_ctx->calls);
}
/*
* Test DEBUGJSONC with a message larger than the buffer.
*/
static void test_large_message(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	char *message = talloc_zero_size(test_ctx, 5112);
	memset(message, 'x', 5111);

	assert_non_null(test_ctx);

	DEBUGJSONC(DBGC_DSDB_AUDIT_JSON, DBGLVL_INFO, (message));
	assert_int_equal(3, test_ctx->calls);
	assert_int_equal(4095, strlen(test_ctx->data[0]));
	assert_int_equal(1016, strlen(test_ctx->data[1]));
	assert_int_equal(5111, (4095+1016));
	assert_string_equal("", test_ctx->data[2]);
}

/*
* Test DEBUGJSONC with a message equal to the buffer size.
*/
static void test_buffer_size_message(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	char *message = talloc_zero_size(test_ctx, FORMAT_BUFR_SIZE);
	memset(message, 'x', FORMAT_STRING_SIZE);

	assert_non_null(test_ctx);

	DEBUGJSONC(DBGC_DSDB_AUDIT_JSON, DBGLVL_INFO, (message));
	assert_int_equal(2, test_ctx->calls);
	assert_int_equal(FORMAT_STRING_SIZE, strlen(test_ctx->data[0]));
	assert_string_equal("", test_ctx->data[1]);
}

/*
* Test DEBUGJSONC replaces '\n' with spaces
*/
static void test_embedded_new_lines(void **state)
{
	const char *message = "A \nmessage\n with new lines\n";
	const char *expected_message = "A  message  with new lines ";
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	assert_non_null(test_ctx);

	DEBUGJSONC(DBGC_DSDB_AUDIT_JSON, DBGLVL_INFO, (message));
	assert_int_equal(2, test_ctx->calls);
	assert_string_equal(expected_message, test_ctx->data[0]);
	assert_string_equal("", test_ctx->data[1]);
}

/*
* Test DEBUGJSON with a short message
*/
static void test_debugjson(void **state)
{
	const char *message = "A message";
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	assert_non_null(test_ctx);

	DEBUGJSON(DBGLVL_NOTICE, (message));
	assert_int_equal(2, test_ctx->calls);
	assert_string_equal(message, test_ctx->data[0]);
	assert_string_equal("", test_ctx->data[1]);
}

/*
* Test DEBUGJSON honours the DBGC_ALL log level
*/
static void test_debugjson_log_level(void **state)
{
	const char *message = "A message";
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	assert_non_null(test_ctx);

	DEBUGJSON(DBGLVL_INFO, (message));
	assert_int_equal(0, test_ctx->calls);
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
			test_empty_message, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_short_message, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_large_message, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_buffer_size_message, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_embedded_new_lines, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_log_class, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_log_level, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_debugjson, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_debugjson_log_level, setup, teardown),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);

}
