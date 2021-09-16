/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) 2021      Uri Simchoni <uri@samba.org>
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

#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <cmocka.h>
#include <tsocket.h>

static int setup(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	assert_non_null(mem_ctx);
	*state = mem_ctx;

	return 0;
}

static int teardown(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	TALLOC_FREE(mem_ctx);

	return 0;
}

static void test_address_inet_from_strings(void **state)
{
	int rc = 0;
	int save_errno;
	TALLOC_CTX *mem_ctx = *state;
	struct tsocket_address *addr = NULL;
	char *addr_s = NULL;

	/*
	 * Unspecified IP family, given an IPv4 address
	 */
	rc = tsocket_address_inet_from_strings(mem_ctx, "ip", "1.2.3.4", 1234,
					       &addr);
	assert_return_code(rc, errno);
	assert_non_null(addr);
	addr_s = tsocket_address_string(addr, mem_ctx);
	assert_non_null(addr_s);
	assert_string_equal(addr_s, "ipv4:1.2.3.4:1234");
	assert_true(tsocket_address_is_inet(addr, "ip"));
	assert_true(tsocket_address_is_inet(addr, "ipv4"));
	assert_false(tsocket_address_is_inet(addr, "ipv6"));
	assert_int_equal(tsocket_address_inet_port(addr), 1234);
	TALLOC_FREE(addr);
	TALLOC_FREE(addr_s);

	/*
	 * Expecting IPv4, given an IPv4 address
	 */
	rc = tsocket_address_inet_from_strings(mem_ctx, "ipv4", "1.2.3.4", 1234,
					       &addr);
	assert_return_code(rc, errno);
	assert_non_null(addr);
	addr_s = tsocket_address_string(addr, mem_ctx);
	assert_non_null(addr_s);
	assert_string_equal(addr_s, "ipv4:1.2.3.4:1234");
	assert_true(tsocket_address_is_inet(addr, "ip"));
	assert_true(tsocket_address_is_inet(addr, "ipv4"));
	assert_false(tsocket_address_is_inet(addr, "ipv6"));
	assert_int_equal(tsocket_address_inet_port(addr), 1234);
	TALLOC_FREE(addr);
	TALLOC_FREE(addr_s);

	/*
	 * Expecting IPv6, given an IPv4 address
	 */
	errno = 0;
	rc = tsocket_address_inet_from_strings(mem_ctx, "ipv6", "1.2.3.4", 1234,
					       &addr);
	save_errno = errno;
	assert_int_equal(rc, -1);
	assert_int_not_equal(save_errno, 0);
	assert_null(addr);

	/*
	 * Unspecified IP family, given an IPv6 address
	 */
	rc = tsocket_address_inet_from_strings(mem_ctx, "ip", "2001::1", 1234,
					       &addr);
	assert_return_code(rc, errno);
	assert_non_null(addr);
	addr_s = tsocket_address_string(addr, mem_ctx);
	assert_non_null(addr_s);
	assert_string_equal(addr_s, "ipv6:2001::1:1234");
	assert_true(tsocket_address_is_inet(addr, "ip"));
	assert_false(tsocket_address_is_inet(addr, "ipv4"));
	assert_true(tsocket_address_is_inet(addr, "ipv6"));
	assert_int_equal(tsocket_address_inet_port(addr), 1234);
	TALLOC_FREE(addr);
	TALLOC_FREE(addr_s);

	/*
	 * Expecting IPv4, given an IPv6 address
	 */
	errno = 0;
	rc = tsocket_address_inet_from_strings(mem_ctx, "ipv4", "2001::1", 1234,
					       &addr);
	save_errno = errno;
	assert_int_equal(rc, -1);
	assert_int_not_equal(save_errno, 0);
	assert_null(addr);

	/*
	 * expecting IPv6, given an IPv6 address
	 */
	rc = tsocket_address_inet_from_strings(mem_ctx, "ipv6", "2001::1", 1234,
					       &addr);
	assert_return_code(rc, errno);
	assert_non_null(addr);
	addr_s = tsocket_address_string(addr, mem_ctx);
	assert_non_null(addr_s);
	assert_string_equal(addr_s, "ipv6:2001::1:1234");
	assert_true(tsocket_address_is_inet(addr, "ip"));
	assert_false(tsocket_address_is_inet(addr, "ipv4"));
	assert_true(tsocket_address_is_inet(addr, "ipv6"));
	assert_int_equal(tsocket_address_inet_port(addr), 1234);
	TALLOC_FREE(addr);
	TALLOC_FREE(addr_s);

	/*
	 * Unspecified IP family, given an illegal address
	 */
	errno = 0;
	rc = tsocket_address_inet_from_strings(mem_ctx, "ip", "localhost", 1234,
					       &addr);
	save_errno = errno;
	assert_int_equal(rc, -1);
	assert_int_not_equal(save_errno, 0);
	assert_null(addr);

	/*
	 * Illegal IP family
	 */
	errno = 0;
	rc = tsocket_address_inet_from_strings(mem_ctx, "ipx", "1.2.3.4", 1234,
					       &addr);
	save_errno = errno;
	assert_int_equal(rc, -1);
	assert_int_not_equal(save_errno, 0);
	assert_null(addr);

	/*
	 * Unspecified IP family, given NULL, verify it returns something
	 */
	rc = tsocket_address_inet_from_strings(mem_ctx, "ip", NULL, 1234,
					       &addr);
	assert_return_code(rc, errno);
	assert_non_null(addr);
	TALLOC_FREE(addr);

	/*
	 * IPv4, given NULL, verify it returns 0.0.0.0
	 */
	rc = tsocket_address_inet_from_strings(mem_ctx, "ipv4", NULL, 1234,
					       &addr);
	assert_return_code(rc, errno);
	assert_non_null(addr);
	addr_s = tsocket_address_string(addr, mem_ctx);
	assert_non_null(addr_s);
	assert_string_equal(addr_s, "ipv4:0.0.0.0:1234");
	assert_true(tsocket_address_is_inet(addr, "ip"));
	assert_true(tsocket_address_is_inet(addr, "ipv4"));
	assert_false(tsocket_address_is_inet(addr, "ipv6"));
	assert_int_equal(tsocket_address_inet_port(addr), 1234);
	TALLOC_FREE(addr);
	TALLOC_FREE(addr_s);

	/*
	 * IPv6, given NULL, verify it returns ::
	 */
	rc = tsocket_address_inet_from_strings(mem_ctx, "ipv6", NULL, 1234,
					       &addr);
	assert_return_code(rc, errno);
	assert_non_null(addr);
	addr_s = tsocket_address_string(addr, mem_ctx);
	assert_non_null(addr_s);
	assert_string_equal(addr_s, "ipv6::::1234");
	assert_true(tsocket_address_is_inet(addr, "ip"));
	assert_false(tsocket_address_is_inet(addr, "ipv4"));
	assert_true(tsocket_address_is_inet(addr, "ipv6"));
	assert_int_equal(tsocket_address_inet_port(addr), 1234);
	TALLOC_FREE(addr);
	TALLOC_FREE(addr_s);
}

static void test_address_inet_from_hostport_strings(void **state)
{
	int rc = 0;
	int save_errno;
	TALLOC_CTX *mem_ctx = *state;
	struct tsocket_address *addr = NULL;
	char *addr_s = NULL;

	/*
	 * IPv4 host:port
	 */
	rc = tsocket_address_inet_from_hostport_strings(
	    mem_ctx, "ip", "1.2.3.4:5678", 1234, &addr);
	assert_return_code(rc, errno);
	assert_non_null(addr);
	addr_s = tsocket_address_string(addr, mem_ctx);
	assert_non_null(addr_s);
	assert_string_equal(addr_s, "ipv4:1.2.3.4:5678");
	TALLOC_FREE(addr);
	TALLOC_FREE(addr_s);

	/*
	 * IPv4 host
	 */
	rc = tsocket_address_inet_from_hostport_strings(
	    mem_ctx, "ip", "1.2.3.4", 1234, &addr);
	assert_return_code(rc, errno);
	assert_non_null(addr);
	addr_s = tsocket_address_string(addr, mem_ctx);
	assert_non_null(addr_s);
	assert_string_equal(addr_s, "ipv4:1.2.3.4:1234");
	TALLOC_FREE(addr);
	TALLOC_FREE(addr_s);

	/*
	 * IPv6 [host]:port
	 */
	rc = tsocket_address_inet_from_hostport_strings(
	    mem_ctx, "ip", "[2001::1]:5678", 1234, &addr);
	assert_return_code(rc, errno);
	assert_non_null(addr);
	addr_s = tsocket_address_string(addr, mem_ctx);
	assert_non_null(addr_s);
	assert_string_equal(addr_s, "ipv6:2001::1:5678");
	TALLOC_FREE(addr);
	TALLOC_FREE(addr_s);

	/*
	 * IPv6 [host]
	 */
	rc = tsocket_address_inet_from_hostport_strings(
	    mem_ctx, "ip", "[2001::1]", 1234, &addr);
	assert_return_code(rc, errno);
	assert_non_null(addr);
	addr_s = tsocket_address_string(addr, mem_ctx);
	assert_non_null(addr_s);
	assert_string_equal(addr_s, "ipv6:2001::1:1234");
	TALLOC_FREE(addr);
	TALLOC_FREE(addr_s);

	/*
	 * IPv6 host
	 */
	rc = tsocket_address_inet_from_hostport_strings(
	    mem_ctx, "ip", "2001::1", 1234, &addr);
	assert_return_code(rc, errno);
	assert_non_null(addr);
	addr_s = tsocket_address_string(addr, mem_ctx);
	assert_non_null(addr_s);
	assert_string_equal(addr_s, "ipv6:2001::1:1234");
	TALLOC_FREE(addr);
	TALLOC_FREE(addr_s);

	/*
	 * Given NULL, verify it returns something
	 */
	rc = tsocket_address_inet_from_hostport_strings(
	    mem_ctx, "ipv6", NULL, 1234, &addr);
	assert_return_code(rc, errno);
	assert_non_null(addr);
	addr_s = tsocket_address_string(addr, mem_ctx);
	assert_non_null(addr_s);
	assert_string_equal(addr_s, "ipv6::::1234");
	TALLOC_FREE(addr);
	TALLOC_FREE(addr_s);

	/*
	 * [host]grarbage
	 */
	errno = 0;
	rc = tsocket_address_inet_from_hostport_strings(
	    mem_ctx, "ip", "[2001::1]garbage", 1234, &addr);
	save_errno = errno;
	assert_int_equal(rc, -1);
	assert_int_not_equal(save_errno, 0);
	assert_null(addr);

	/*
	 * [host]:grarbage
	 */
	errno = 0;
	rc = tsocket_address_inet_from_hostport_strings(
	    mem_ctx, "ip", "[2001::1]:garbage", 1234, &addr);
	save_errno = errno;
	assert_int_equal(rc, -1);
	assert_int_not_equal(save_errno, 0);
	assert_null(addr);

	/*
	 * host:grarbage
	 */
	errno = 0;
	rc = tsocket_address_inet_from_hostport_strings(
	    mem_ctx, "ip", "1.2.3.4:garbage", 1234, &addr);
	save_errno = errno;
	assert_int_equal(rc, -1);
	assert_int_not_equal(save_errno, 0);
	assert_null(addr);

	/*
	 * [host]:<port-too-large>
	 */
	errno = 0;
	rc = tsocket_address_inet_from_hostport_strings(
	    mem_ctx, "ip", "[2001::1]:100000", 1234, &addr);
	save_errno = errno;
	assert_int_equal(rc, -1);
	assert_int_not_equal(save_errno, 0);
	assert_null(addr);

	/*
	 * host:<port-too-large>
	 */
	errno = 0;
	rc = tsocket_address_inet_from_hostport_strings(
	    mem_ctx, "ip", "1.2.3.4:100000", 1234, &addr);
	save_errno = errno;
	assert_int_equal(rc, -1);
	assert_int_not_equal(save_errno, 0);
	assert_null(addr);
}

int main(int argc, char *argv[])
{
	int rc;
	const struct CMUnitTest tests[] = {
	    cmocka_unit_test(test_address_inet_from_strings),
	    cmocka_unit_test(test_address_inet_from_hostport_strings),
	};

	if (argc == 2) {
		cmocka_set_test_filter(argv[1]);
	}
	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	rc = cmocka_run_group_tests(tests, setup, teardown);

	return rc;
}
