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
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <ldb.h>
#include "ldb_private.h"

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

struct explode_test {
	const char *strdn;
	int comp_num;
	int ext_comp_num;
	bool special;
	bool invalid;
	const char *linearized;
	const char *ext_linearized_1;
	bool explode_result;
};

static int extended_dn_read_ID(struct ldb_context *ldb, void *mem_ctx,
			       const struct ldb_val *in, struct ldb_val *out)
{

	/* Allow to check we can cope with validity checks */
	if (in->length != 4) {
		return -1;
	}

	*out = *in;
	out->data = talloc_memdup(mem_ctx, in->data, in->length);
	if (out->data == NULL) {
		return -1;
	}

	return 0;
}

/* write out (resued for both HEX and clear for now) */
static int extended_dn_write_ID(struct ldb_context *ldb, void *mem_ctx,
				 const struct ldb_val *in, struct ldb_val *out)
{
	*out = *in;

	out->data = talloc_memdup(mem_ctx, in->data, in->length);
	if (out->data == NULL) {
		return -1;
	}
	return 0;
}


static void test_ldb_dn_explode(void **state)
{
	size_t i;
	struct ldb_context *ldb = ldb_init(NULL, NULL);
	struct explode_test tests[] = {
		{"A=B", 1, 0, false, false, "A=B", "A=B", true},
		{"", 0, 0, false, false, "", "", true},
		{" ", -1, -1, false, false, " ", " ", false},
		{"<>", 0, 0, false, false, "", NULL, true},
		{"<", 0, 0, false, false, "", NULL, true},
		{"<><", 0, 0, false, false, "", NULL, true},
		{"<><>", 0, 0, false, false, "", NULL, true},
		{"A=B,C=D", 2, 0, false, false, "A=B,C=D", "A=B,C=D", true},
		{"<X=Y>A=B,C=D", -1, -1, false, false, "", NULL, false},
		{"<X=Y>;A=B,C=D", -1, -1, false, false, "A=B,C=D", NULL, false},
		{"<ID=ABC>;A=B,C=D", -1, -1, false, true, "A=B,C=D", NULL, false},
		{"<ID=ABCD>;A=B,C=D", 2, 1, false, false, "A=B,C=D", "<ID=ABCD>;A=B,C=D", true},
		{"x=🔥", 1, 0, false, false, "x=🔥", "x=🔥", true},
		{"@FOO", 0, 0, true, false, "@FOO", "@FOO", true},
	};

	struct ldb_dn_extended_syntax syntax = {
		.name		  = "ID",
		.read_fn          = extended_dn_read_ID,
		.write_clear_fn   = extended_dn_write_ID,
		.write_hex_fn     = extended_dn_write_ID
	};

	ldb_dn_extended_add_syntax(ldb, 0, &syntax);

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		bool result;
		const char *linear;
		const char *ext_linear;
		struct ldb_dn *dn = ldb_dn_new(ldb, ldb, tests[i].strdn);

		/*
		 * special, invalid, linear, and ext_linear are set before
		 * explode
		 */
		fprintf(stderr, "%zu «%s»: ", i, tests[i].strdn);
		linear = ldb_dn_get_linearized(dn);
		assert_true((linear == NULL) == (tests[i].linearized == NULL));
		assert_string_equal(linear,
				    tests[i].linearized);

		ext_linear = ldb_dn_get_extended_linearized(ldb, dn, 1);
		assert_true((ext_linear == NULL) ==
			    (tests[i].ext_linearized_1 == NULL));

		if (tests[i].ext_linearized_1 != NULL) {
			assert_string_equal(ext_linear,
					    tests[i].ext_linearized_1);
		}
		assert_true(ldb_dn_is_special(dn) == tests[i].special);
		assert_true(ldb_dn_is_valid(dn) != tests[i].invalid);

		/* comp nums are set by explode */
		result = ldb_dn_validate(dn);
		fprintf(stderr, "res %i lin «%s» ext «%s»\n",
			result, linear, ext_linear);
		
		assert_true(result == tests[i].explode_result);
		assert_int_equal(ldb_dn_get_comp_num(dn),
				 tests[i].comp_num);
		assert_int_equal(ldb_dn_get_extended_comp_num(dn),
				 tests[i].ext_comp_num);
	}
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_ldb_dn_add_child_fmt),
		cmocka_unit_test(test_ldb_dn_add_child_fmt2),
		cmocka_unit_test(test_ldb_dn_add_child_val),
		cmocka_unit_test(test_ldb_dn_add_child_val2),
		cmocka_unit_test(test_ldb_dn_explode),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
