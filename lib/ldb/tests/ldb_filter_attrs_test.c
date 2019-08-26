/*
 * Tests exercising the ldb_filter_attrs().
 *
 *
 * Copyright (C) Catalyst.NET Ltd 2017
 * Copyright (C) Andrew Bartlett <abartlet@samba.org> 2019
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
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../include/ldb.h"
#include "../include/ldb_module.h"

struct ldbtest_ctx {
	struct tevent_context *ev;
	struct ldb_context *ldb;
};

/*
 * NOTE WELL:
 *
 * This test checks the current behaviour of the function, however
 * this is not in a public ABI and many of the tested behaviours are
 * not ideal.  If the behaviour is deliberatly improved, this test
 * should be updated without worry to the new better behaviour.
 *
 * In particular the test is particularly to ensure the current
 * behaviour is memory-safe.
 */

static int setup(void **state)
{
	struct ldbtest_ctx *test_ctx;

	test_ctx = talloc_zero(NULL, struct ldbtest_ctx);
	assert_non_null(test_ctx);

	test_ctx->ev = tevent_context_init(test_ctx);
	assert_non_null(test_ctx->ev);

	test_ctx->ldb = ldb_init(test_ctx, test_ctx->ev);
	assert_non_null(test_ctx->ldb);

	*state = test_ctx;
	return 0;
}

static int teardown(void **state)
{
	talloc_free(*state);
	return 0;
}


/*
 * Test against a record with only one attribute, matching the one in
 * the list
 */
static void test_filter_attrs_one_attr_matched(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	int ret;

	struct ldb_message *filtered_msg = ldb_msg_new(ctx);

	const char *attrs[] = {"foo", NULL};

	uint8_t value[] = "The value.......end";
	struct ldb_val value_1 = {
		.data   = value,
		.length = (sizeof(value))
	};
	struct ldb_message_element element_1 = {
		.name = "foo",
		.num_values = 1,
		.values = &value_1
	};
	struct ldb_message in = {
		.dn = ldb_dn_new(ctx, ctx->ldb, "dc=samba,dc=org"),
		.num_elements = 1,
		.elements = &element_1,
	};

	assert_non_null(in.dn);

	ret = ldb_filter_attrs(ctx->ldb,
			       &in,
			       attrs,
			       filtered_msg);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(filtered_msg);

	/*
	 * assert the ldb_filter_attrs does not read or modify
	 * filtered_msg.dn in this case
	 */
	assert_null(filtered_msg->dn);
	assert_int_equal(filtered_msg->num_elements, 1);
	assert_string_equal(filtered_msg->elements[0].name, "foo");
	assert_int_equal(filtered_msg->elements[0].num_values, 1);
	assert_int_equal(filtered_msg->elements[0].values[0].length,
			 sizeof(value));
	assert_memory_equal(filtered_msg->elements[0].values[0].data,
			    value, sizeof(value));
}

/*
 * Test against a record with only one attribute, matching the one of
 * the multiple attributes in the list
 */
static void test_filter_attrs_one_attr_matched_of_many(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	int ret;

	struct ldb_message *filtered_msg = ldb_msg_new(ctx);

	const char *attrs[] = {"foo", "bar", "baz", NULL};

	uint8_t value[] = "The value.......end";
	struct ldb_val value_1 = {
		.data   = value,
		.length = (sizeof(value))
	};
	struct ldb_message_element element_1 = {
		.name = "foo",
		.num_values = 1,
		.values = &value_1
	};
	struct ldb_message in = {
		.dn = ldb_dn_new(ctx, ctx->ldb, "dc=samba,dc=org"),
		.num_elements = 1,
		.elements = &element_1,
	};

	assert_non_null(in.dn);

	ret = ldb_filter_attrs(ctx->ldb,
			       &in,
			       attrs,
			       filtered_msg);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(filtered_msg);

	/*
	 * assert the ldb_filter_attrs does not read or modify
	 * filtered_msg.dn in this case
	 */
	assert_null(filtered_msg->dn);
	assert_int_equal(filtered_msg->num_elements, 1);
	assert_string_equal(filtered_msg->elements[0].name, "foo");
	assert_int_equal(filtered_msg->elements[0].num_values, 1);
	assert_int_equal(filtered_msg->elements[0].values[0].length,
			 sizeof(value));
	assert_memory_equal(filtered_msg->elements[0].values[0].data,
			    value, sizeof(value));
}

/*
 * Test against a record with only one attribute, matching both
 * attributes in the list
 */
static void test_filter_attrs_two_attr_matched_attrs(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	int ret;

	struct ldb_message *filtered_msg = ldb_msg_new(ctx);

	/* deliberatly the other order */
	const char *attrs[] = {"bar", "foo", NULL};

	uint8_t value1[] = "The value.......end";
	uint8_t value2[] = "The value..MUST.end";
	struct ldb_val value_1 = {
		.data   = value1,
		.length = (sizeof(value1))
	};
	struct ldb_val value_2 = {
		.data   = value2,
		.length = (sizeof(value2))
	};

	/* foo and bar are the other order to in attrs */
	struct ldb_message_element elements[] = {
		{
			.name = "foo",
			.num_values = 1,
			.values = &value_1
		},
		{
			.name = "bar",
			.num_values = 1,
			.values = &value_2
		}
	};
	struct ldb_message in = {
		.dn = ldb_dn_new(ctx, ctx->ldb, "dc=samba,dc=org"),
		.num_elements = 2,
		.elements = elements,
	};

	assert_non_null(in.dn);

	ret = ldb_filter_attrs(ctx->ldb,
			       &in,
			       attrs,
			       filtered_msg);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(filtered_msg);
	assert_int_equal(filtered_msg->num_elements, 2);

	/*
	 * assert the ldb_filter_attrs does not read or modify
	 * filtered_msg.dn in this case
	 */
	assert_null(filtered_msg->dn);

	/* Assert that DB order is preserved */
	assert_string_equal(filtered_msg->elements[0].name, "foo");
	assert_int_equal(filtered_msg->elements[0].num_values, 1);
	assert_int_equal(filtered_msg->elements[0].values[0].length,
			 sizeof(value1));
	assert_memory_equal(filtered_msg->elements[0].values[0].data,
			    value1, sizeof(value1));
	assert_string_equal(filtered_msg->elements[1].name, "bar");
	assert_int_equal(filtered_msg->elements[1].num_values, 1);
	assert_int_equal(filtered_msg->elements[1].values[0].length,
			 sizeof(value2));
	assert_memory_equal(filtered_msg->elements[1].values[0].data,
			    value2, sizeof(value2));
}

/*
 * Test against a record with two attributes, only of which is in
 * the list
 */
static void test_filter_attrs_two_attr_matched_one_attr(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	int ret;

	struct ldb_message *filtered_msg = ldb_msg_new(ctx);

	/* deliberatly the other order */
	const char *attrs[] = {"bar", NULL};

	uint8_t value1[] = "The value.......end";
	uint8_t value2[] = "The value..MUST.end";
	struct ldb_val value_1 = {
		.data   = value1,
		.length = (sizeof(value1))
	};
	struct ldb_val value_2 = {
		.data   = value2,
		.length = (sizeof(value2))
	};

	/* foo and bar are the other order to in attrs */
	struct ldb_message_element elements[] = {
		{
			.name = "foo",
			.num_values = 1,
			.values = &value_1
		},
		{
			.name = "bar",
			.num_values = 1,
			.values = &value_2
		}
	};
	struct ldb_message in = {
		.dn = ldb_dn_new(ctx, ctx->ldb, "dc=samba,dc=org"),
		.num_elements = 2,
		.elements = elements,
	};

	assert_non_null(in.dn);

	ret = ldb_filter_attrs(ctx->ldb,
			       &in,
			       attrs,
			       filtered_msg);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(filtered_msg);
	assert_int_equal(filtered_msg->num_elements, 1);

	/*
	 * assert the ldb_filter_attrs does not read or modify
	 * filtered_msg.dn in this case
	 */
	assert_null(filtered_msg->dn);

	/* Assert that DB order is preserved */
	assert_string_equal(filtered_msg->elements[0].name, "bar");
	assert_int_equal(filtered_msg->elements[0].num_values, 1);
	assert_int_equal(filtered_msg->elements[0].values[0].length,
			 sizeof(value2));
	assert_memory_equal(filtered_msg->elements[0].values[0].data,
			    value2, sizeof(value2));
}

/*
 * Test against a record with two attributes, both matching the one
 * specified attribute in the list (a corrupt record)
 */
static void test_filter_attrs_two_dup_attr_matched_one_attr(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	int ret;

	struct ldb_message *filtered_msg = ldb_msg_new(ctx);

	/* deliberatly the other order */
	const char *attrs[] = {"bar", NULL};

	uint8_t value1[] = "The value.......end";
	uint8_t value2[] = "The value..MUST.end";
	struct ldb_val value_1 = {
		.data   = value1,
		.length = (sizeof(value1))
	};
	struct ldb_val value_2 = {
		.data   = value2,
		.length = (sizeof(value2))
	};

	/* foo and bar are the other order to in attrs */
	struct ldb_message_element elements[] = {
		{
			.name = "bar",
			.num_values = 1,
			.values = &value_1
		},
		{
			.name = "bar",
			.num_values = 1,
			.values = &value_2
		}
	};
	struct ldb_message in = {
		.dn = ldb_dn_new(ctx, ctx->ldb, "dc=samba,dc=org"),
		.num_elements = 2,
		.elements = elements,
	};

	assert_non_null(in.dn);

	ret = ldb_filter_attrs(ctx->ldb,
			       &in,
			       attrs,
			       filtered_msg);

	/* This should fail the pidgenhole test */
	assert_int_equal(ret, -1);
	assert_null(filtered_msg->elements);
}

/*
 * Test against a record with two attributes, both matching the one
 * specified attribute in the list (a corrupt record)
 */
static void test_filter_attrs_two_dup_attr_matched_dup(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	int ret;

	struct ldb_message *filtered_msg = ldb_msg_new(ctx);

	const char *attrs[] = {"bar", "bar", NULL};

	uint8_t value1[] = "The value.......end";
	uint8_t value2[] = "The value..MUST.end";
	struct ldb_val value_1 = {
		.data   = value1,
		.length = (sizeof(value1))
	};
	struct ldb_val value_2 = {
		.data   = value2,
		.length = (sizeof(value2))
	};

	/* foo and bar are the other order to in attrs */
	struct ldb_message_element elements[] = {
		{
			.name = "bar",
			.num_values = 1,
			.values = &value_1
		},
		{
			.name = "bar",
			.num_values = 1,
			.values = &value_2
		}
	};
	struct ldb_message in = {
		.dn = ldb_dn_new(ctx, ctx->ldb, "dc=samba,dc=org"),
		.num_elements = 2,
		.elements = elements,
	};

	assert_non_null(in.dn);

	ret = ldb_filter_attrs(ctx->ldb,
			       &in,
			       attrs,
			       filtered_msg);

	/* This does not fail the pidgenhole test */
	assert_int_equal(ret, LDB_SUCCESS);
	assert_int_equal(filtered_msg->num_elements, 2);

	/* Assert that DB order is preserved */
	assert_string_equal(filtered_msg->elements[0].name, "bar");
	assert_int_equal(filtered_msg->elements[0].num_values, 1);
	assert_int_equal(filtered_msg->elements[0].values[0].length,
			 sizeof(value1));
	assert_memory_equal(filtered_msg->elements[0].values[0].data,
			    value1, sizeof(value1));
	assert_string_equal(filtered_msg->elements[1].name, "bar");
	assert_int_equal(filtered_msg->elements[1].num_values, 1);
	assert_int_equal(filtered_msg->elements[1].values[0].length,
			 sizeof(value2));
	assert_memory_equal(filtered_msg->elements[1].values[0].data,
			    value2, sizeof(value2));
}

/*
 * Test against a record with two attributes, both matching one of the
 * specified attributes in the list (a corrupt record)
 */
static void test_filter_attrs_two_dup_attr_matched_one_of_two(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	int ret;

	struct ldb_message *filtered_msg = ldb_msg_new(ctx);

	const char *attrs[] = {"bar", "foo", NULL};

	uint8_t value1[] = "The value.......end";
	uint8_t value2[] = "The value..MUST.end";
	struct ldb_val value_1 = {
		.data   = value1,
		.length = (sizeof(value1))
	};
	struct ldb_val value_2 = {
		.data   = value2,
		.length = (sizeof(value2))
	};

	/* foo and bar are the other order to in attrs */
	struct ldb_message_element elements[] = {
		{
			.name = "bar",
			.num_values = 1,
			.values = &value_1
		},
		{
			.name = "bar",
			.num_values = 1,
			.values = &value_2
		}
	};
	struct ldb_message in = {
		.dn = ldb_dn_new(ctx, ctx->ldb, "dc=samba,dc=org"),
		.num_elements = 2,
		.elements = elements,
	};

	assert_non_null(in.dn);

	ret = ldb_filter_attrs(ctx->ldb,
			       &in,
			       attrs,
			       filtered_msg);

	/* This does not fail the pidgenhole test */
	assert_int_equal(ret, LDB_SUCCESS);
	assert_int_equal(filtered_msg->num_elements, 2);

	/* Assert that DB order is preserved */
	assert_string_equal(filtered_msg->elements[0].name, "bar");
	assert_int_equal(filtered_msg->elements[0].num_values, 1);
	assert_int_equal(filtered_msg->elements[0].values[0].length,
			 sizeof(value1));
	assert_memory_equal(filtered_msg->elements[0].values[0].data,
			    value1, sizeof(value1));
	assert_string_equal(filtered_msg->elements[1].name, "bar");
	assert_int_equal(filtered_msg->elements[1].num_values, 1);
	assert_int_equal(filtered_msg->elements[1].values[0].length,
			 sizeof(value2));
	assert_memory_equal(filtered_msg->elements[1].values[0].data,
			    value2, sizeof(value2));
}

/*
 * Test against a record with two attributes against * (but not the
 * other named attribute) (a corrupt record)
 */
static void test_filter_attrs_two_dup_attr_matched_star(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	int ret;

	struct ldb_message *filtered_msg = ldb_msg_new(ctx);

	const char *attrs[] = {"*", "foo", NULL};

	uint8_t value1[] = "The value.......end";
	uint8_t value2[] = "The value..MUST.end";
	struct ldb_val value_1 = {
		.data   = value1,
		.length = (sizeof(value1))
	};
	struct ldb_val value_2 = {
		.data   = value2,
		.length = (sizeof(value2))
	};

	/* foo and bar are the other order to in attrs */
	struct ldb_message_element elements[] = {
		{
			.name = "bar",
			.num_values = 1,
			.values = &value_1
		},
		{
			.name = "bar",
			.num_values = 1,
			.values = &value_2
		}
	};
	struct ldb_message in = {
		.dn = ldb_dn_new(ctx, ctx->ldb, "dc=samba,dc=org"),
		.num_elements = 2,
		.elements = elements,
	};

	assert_non_null(in.dn);

	/* Needed as * implies distinguishedName */
	filtered_msg->dn = in.dn;

	ret = ldb_filter_attrs(ctx->ldb,
			       &in,
			       attrs,
			       filtered_msg);

	/* This does not fail the pidgenhole test */
	assert_int_equal(ret, LDB_SUCCESS);
	assert_int_equal(filtered_msg->num_elements, 3);

	/* Assert that DB order is preserved */
	assert_string_equal(filtered_msg->elements[0].name, "bar");
	assert_int_equal(filtered_msg->elements[0].num_values, 1);
	assert_int_equal(filtered_msg->elements[0].values[0].length,
			 sizeof(value1));
	assert_memory_equal(filtered_msg->elements[0].values[0].data,
			    value1, sizeof(value1));
	assert_string_equal(filtered_msg->elements[1].name, "bar");
	assert_int_equal(filtered_msg->elements[1].num_values, 1);
	assert_int_equal(filtered_msg->elements[1].values[0].length,
			 sizeof(value2));
	assert_memory_equal(filtered_msg->elements[1].values[0].data,
			    value2, sizeof(value2));
	/*
	 * assert the ldb_filter_attrs does not modify filtered_msg.dn
	 * in this case
	 */
	assert_ptr_equal(filtered_msg->dn, in.dn);
	assert_string_equal(ldb_msg_find_attr_as_string(filtered_msg,
							"distinguishedName",
							NULL),
			    ldb_dn_get_linearized(in.dn));
}

/*
 * Test against a record with only one attribute, matching the * in
 * the list
 */
static void test_filter_attrs_one_attr_matched_star(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	int ret;

	struct ldb_message *filtered_msg = ldb_msg_new(ctx);

	const char *attrs[] = {"*", NULL};

	uint8_t value[] = "The value.......end";
	struct ldb_val value_1 = {
		.data   = value,
		.length = (sizeof(value))
	};
	struct ldb_message_element element_1 = {
		.name = "foo",
		.num_values = 1,
		.values = &value_1
	};
	struct ldb_message in = {
		.dn = ldb_dn_new(ctx, ctx->ldb, "dc=samba,dc=org"),
		.num_elements = 1,
		.elements = &element_1,
	};

	assert_non_null(in.dn);

	/* Needed as * implies distinguishedName */
	filtered_msg->dn = in.dn;

	ret = ldb_filter_attrs(ctx->ldb,
			       &in,
			       attrs,
			       filtered_msg);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(filtered_msg);
	assert_int_equal(filtered_msg->num_elements, 2);

	/*
	 * assert the ldb_filter_attrs does not modify filtered_msg.dn
	 * in this case
	 */
	assert_ptr_equal(filtered_msg->dn, in.dn);
	assert_string_equal(ldb_msg_find_attr_as_string(filtered_msg,
							"distinguishedName",
							NULL),
			    ldb_dn_get_linearized(in.dn));
	assert_string_equal(ldb_msg_find_attr_as_string(filtered_msg,
							"foo",
							NULL),
			    value);
}

/*
 * Test against a record with two attributes, matching the * in
 * the list
 */
static void test_filter_attrs_two_attr_matched_star(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	int ret;

	struct ldb_message *filtered_msg = ldb_msg_new(ctx);

	const char *attrs[] = {"*", NULL};

	uint8_t value1[] = "The value.......end";
	uint8_t value2[] = "The value..MUST.end";
	struct ldb_val value_1 = {
		.data   = value1,
		.length = (sizeof(value1))
	};
	struct ldb_val value_2 = {
		.data   = value2,
		.length = (sizeof(value2))
	};
	struct ldb_message_element elements[] = {
		{
			.name = "foo",
			.num_values = 1,
			.values = &value_1
		},
		{
			.name = "bar",
			.num_values = 1,
			.values = &value_2
		}
	};
	struct ldb_message in = {
		.dn = ldb_dn_new(ctx, ctx->ldb, "dc=samba,dc=org"),
		.num_elements = 2,
		.elements = elements,
	};

	assert_non_null(in.dn);

	/* Needed as * implies distinguishedName */
	filtered_msg->dn = in.dn;

	ret = ldb_filter_attrs(ctx->ldb,
			       &in,
			       attrs,
			       filtered_msg);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(filtered_msg);
	assert_int_equal(filtered_msg->num_elements, 3);

	/*
	 * assert the ldb_filter_attrs does not modify filtered_msg.dn
	 * in this case
	 */
	assert_ptr_equal(filtered_msg->dn, in.dn);
	assert_string_equal(ldb_msg_find_attr_as_string(filtered_msg,
							"distinguishedName",
							NULL),
			    ldb_dn_get_linearized(in.dn));
	assert_string_equal(ldb_msg_find_attr_as_string(filtered_msg,
							"foo",
							NULL),
			    value1);
	assert_string_equal(ldb_msg_find_attr_as_string(filtered_msg,
							"bar",
							NULL),
			    value2);
}

/*
 * Test against a record with only one attribute, matching the * in
 * the list, but without the DN being pre-filled.  Fails due to need
 * to contstruct the distinguishedName
 */
static void test_filter_attrs_one_attr_matched_star_no_dn(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	int ret;

	struct ldb_message *filtered_msg = ldb_msg_new(ctx);

	const char *attrs[] = {"*", NULL};

	uint8_t value[] = "The value.......end";
	struct ldb_val value_1 = {
		.data   = value,
		.length = (sizeof(value))
	};
	struct ldb_message_element element_1 = {
		.name = "foo",
		.num_values = 1,
		.values = &value_1
	};
	struct ldb_message in = {
		.dn = ldb_dn_new(ctx, ctx->ldb, "dc=samba,dc=org"),
		.num_elements = 1,
		.elements = &element_1,
	};

	assert_non_null(in.dn);

	ret = ldb_filter_attrs(ctx->ldb,
			       &in,
			       attrs,
			       filtered_msg);
	assert_int_equal(ret, -1);
	assert_null(filtered_msg->elements);
}

/*
 * Test against a record with only one attribute, matching the * in
 * the list plus requsesting distinguishedName
 */
static void test_filter_attrs_one_attr_matched_star_dn(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	int ret;

	struct ldb_message *filtered_msg = ldb_msg_new(ctx);

	const char *attrs[] = {"*", "distinguishedName", NULL};

	uint8_t value[] = "The value.......end";
	struct ldb_val value_1 = {
		.data   = value,
		.length = (sizeof(value))
	};
	struct ldb_message_element element_1 = {
		.name = "foo",
		.num_values = 1,
		.values = &value_1
	};
	struct ldb_message in = {
		.dn = ldb_dn_new(ctx, ctx->ldb, "dc=samba,dc=org"),
		.num_elements = 1,
		.elements = &element_1,
	};

	assert_non_null(in.dn);

	/* Needed for distinguishedName */
	filtered_msg->dn = in.dn;

	ret = ldb_filter_attrs(ctx->ldb,
			       &in,
			       attrs,
			       filtered_msg);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(filtered_msg);
	assert_int_equal(filtered_msg->num_elements, 2);

	/* show that ldb_filter_attrs does not modify in.dn */
	assert_ptr_equal(filtered_msg->dn, in.dn);

	assert_string_equal(ldb_msg_find_attr_as_string(filtered_msg,
							"distinguishedName",
							NULL),
			    ldb_dn_get_linearized(in.dn));
	assert_string_equal(ldb_msg_find_attr_as_string(filtered_msg,
							"foo",
							NULL),
			    value);
}

/*
 * Test against a record with only one attribute, but returning
 * distinguishedName from the list (only)
 */
static void test_filter_attrs_one_attr_matched_dn(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	int ret;

	struct ldb_message *filtered_msg = ldb_msg_new(ctx);

	const char *attrs[] = {"distinguishedName", NULL};

	uint8_t value[] = "The value.......end";
	struct ldb_val value_1 = {
		.data   = value,
		.length = (sizeof(value))
	};
	struct ldb_message_element element_1 = {
		.name = "foo",
		.num_values = 1,
		.values = &value_1
	};
	struct ldb_message in = {
		.dn = ldb_dn_new(ctx, ctx->ldb, "dc=samba,dc=org"),
		.num_elements = 1,
		.elements = &element_1,
	};

	assert_non_null(in.dn);

	/* Needed for distinguishedName */
	filtered_msg->dn = in.dn;

	ret = ldb_filter_attrs(ctx->ldb,
			       &in,
			       attrs,
			       filtered_msg);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(filtered_msg);
	assert_int_equal(filtered_msg->num_elements, 1);

	/* show that ldb_filter_attrs does not modify in.dn */
	assert_ptr_equal(filtered_msg->dn, in.dn);
	assert_string_equal(filtered_msg->elements[0].name, "distinguishedName");
	assert_int_equal(filtered_msg->elements[0].num_values, 1);
	assert_string_equal(filtered_msg->elements[0].values[0].data,
			    ldb_dn_get_linearized(in.dn));
}

/*
 * Test against a record with only one attribute, not matching the
 * empty attribute list
 */
static void test_filter_attrs_one_attr_empty_list(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	int ret;

	struct ldb_message *filtered_msg = ldb_msg_new(ctx);

	const char *attrs[] = {NULL};

	uint8_t value[] = "The value.......end";
	struct ldb_val value_1 = {
		.data   = value,
		.length = (sizeof(value))
	};
	struct ldb_message_element element_1 = {
		.name = "foo",
		.num_values = 1,
		.values = &value_1
	};
	struct ldb_message in = {
		.dn = ldb_dn_new(ctx, ctx->ldb, "dc=samba,dc=org"),
		.num_elements = 1,
		.elements = &element_1,
	};

	assert_non_null(in.dn);

	ret = ldb_filter_attrs(ctx->ldb,
			       &in,
			       attrs,
			       filtered_msg);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(filtered_msg);
	assert_int_equal(filtered_msg->num_elements, 0);
	assert_null(filtered_msg->dn);
	assert_null(filtered_msg->elements);
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
			test_filter_attrs_one_attr_matched,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_filter_attrs_one_attr_matched_of_many,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_filter_attrs_two_attr_matched_attrs,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_filter_attrs_two_attr_matched_one_attr,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_filter_attrs_two_dup_attr_matched_one_attr,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_filter_attrs_two_dup_attr_matched_dup,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_filter_attrs_two_dup_attr_matched_one_of_two,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_filter_attrs_two_dup_attr_matched_star,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_filter_attrs_one_attr_matched_star,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_filter_attrs_two_attr_matched_star,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_filter_attrs_one_attr_matched_star_no_dn,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_filter_attrs_one_attr_matched_star_dn,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_filter_attrs_one_attr_matched_dn,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_filter_attrs_one_attr_empty_list,
			setup,
			teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
