/*
 * Unix SMB/CIFS implementation.
 * Test suite for ldap client
 *
 * Copyright (C) 2018      Andreas Schneider <asn@samba.org>
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

#include "source3/lib/tldap.c"

static void test_tldap_unescape_ldapv3(void **state)
{
	const char *unescaped_dn = "(&(objectclass=group)(cn=Samba*))";
	char dn[] = "\\28&\\28objectclass=group\\29\\28cn=Samba\\2a\\29\\29";
	size_t dnlen = sizeof(dn);
	bool ok;

	ok = tldap_unescape_inplace(dn, &dnlen);
	assert_true(ok);

	assert_string_equal(dn, unescaped_dn);
}

static void test_tldap_unescape_ldapv2(void **state)
{
	const char *unescaped_dn = "(&(objectclass=group)(cn=Samba*))";
	char dn[] = "\\(&\\(objectclass=group\\)\\(cn=Samba\\*\\)\\)";
	size_t dnlen = sizeof(dn);
	bool ok;

	ok = tldap_unescape_inplace(dn, &dnlen);
	assert_true(ok);

	assert_string_equal(dn, unescaped_dn);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_tldap_unescape_ldapv3),
		cmocka_unit_test(test_tldap_unescape_ldapv2)
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
