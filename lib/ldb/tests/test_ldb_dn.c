/*
 * Unix SMB/CIFS implementation.
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
#include <setjmp.h>
#include <cmocka.h>

#include <ldb.h>

static void test_ldb_dn_add_child_fmt(void **state)
{
	struct ldb_context *ldb = ldb_init(NULL, NULL);

	struct ldb_dn *dn = ldb_dn_new(ldb, ldb, "dc=samba,dc=org");

	assert_true(ldb_dn_add_child_fmt(dn,
					 "DC=X"));

	assert_string_equal("DC=X,dc=samba,dc=org",
			    ldb_dn_get_linearized(dn));

	assert_string_equal("DC=X,DC=SAMBA,DC=ORG",
			    ldb_dn_get_casefold(dn));

}

static void test_ldb_dn_add_child_fmt2(void **state)
{
	struct ldb_context *ldb = ldb_init(NULL, NULL);

	struct ldb_dn *dn = ldb_dn_new(ldb, ldb, "dc=samba,dc=org");

	assert_true(ldb_dn_add_child_fmt(dn,
					 "DC=X,DC=Y"));

	assert_string_equal("DC=X,DC=Y,dc=samba,dc=org",
			    ldb_dn_get_linearized(dn));

	assert_string_equal("DC=X,DC=Y,DC=SAMBA,DC=ORG",
			    ldb_dn_get_casefold(dn));

	assert_int_equal(4,
			 ldb_dn_get_comp_num(dn));

}

static void test_ldb_dn_add_child_val(void **state)
{
	struct ldb_context *ldb = ldb_init(NULL, NULL);

	struct ldb_dn *dn = ldb_dn_new(ldb, ldb, "dc=samba,dc=org");
	struct ldb_val name = {.data = discard_const("X"),
			       .length = 1
	};

	assert_true(ldb_dn_add_child_val(dn,
					 "DC", name));

	assert_string_equal("DC=X,dc=samba,dc=org",
			    ldb_dn_get_linearized(dn));

	assert_string_equal("DC=X,DC=SAMBA,DC=ORG",
			    ldb_dn_get_casefold(dn));

}

static void test_ldb_dn_add_child_val2(void **state)
{
	struct ldb_context *ldb = ldb_init(NULL, NULL);

	struct ldb_dn *dn = ldb_dn_new(ldb, ldb, "dc=samba,dc=org");

	struct ldb_val name = {.data = discard_const("X,DC=Y"),
			       .length = 6
	};

	assert_true(ldb_dn_add_child_val(dn,
					 "DC", name));

	assert_string_equal("DC=X\\,DC\\3DY,dc=samba,dc=org",
			    ldb_dn_get_linearized(dn));

	assert_string_equal("DC=X\\,DC\\3DY,DC=SAMBA,DC=ORG",
			    ldb_dn_get_casefold(dn));

	assert_int_equal(3,
			 ldb_dn_get_comp_num(dn));

}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_ldb_dn_add_child_fmt),
		cmocka_unit_test(test_ldb_dn_add_child_fmt2),
		cmocka_unit_test(test_ldb_dn_add_child_val),
		cmocka_unit_test(test_ldb_dn_add_child_val2),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
