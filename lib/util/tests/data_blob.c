/*
   Unix SMB/CIFS implementation.

   data blob testing

   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "torture/torture.h"
#include "torture/local/proto.h"

static bool test_string(struct torture_context *tctx)
{
	DATA_BLOB blob = data_blob_string_const("bla");

	torture_assert_int_equal(tctx, blob.length, 3, "blob length");
	torture_assert_str_equal(tctx, (char *)blob.data, "bla", "blob data");

	return true;
}

static bool test_string_null(struct torture_context *tctx)
{
	DATA_BLOB blob = data_blob_string_const_null("bla");

	torture_assert_int_equal(tctx, blob.length, 4, "blob length");
	torture_assert_str_equal(tctx, (char *)blob.data, "bla", "blob data");

	return true;
}

static bool test_zero(struct torture_context *tctx)
{
	int i;
	DATA_BLOB z = data_blob_talloc_zero(tctx, 4);
	torture_assert_int_equal(tctx, z.length, 4, "length");
	for (i = 0; i < z.length; i++)
		torture_assert_int_equal(tctx, z.data[i], 0, "contents");
	data_blob_free(&z);
	return true;
}

static bool test_zero_s(struct torture_context *tctx)
{
	DATA_BLOB z = data_blob_talloc_zero_s(tctx, 4);
	int i;
	uint8_t *p;

	torture_assert_int_equal(tctx, z.length, 4, "length");
	for (i = 0; i < z.length; i++)
		torture_assert_int_equal(tctx, z.data[i], 0, "contents");
	z.data[0] = 'a';
	p = z.data; /* store pointer that will be freed */
	torture_assert_int_equal(tctx, *p, 'a', "contents");
	data_blob_free(&z);
	/* coverity[use_after_free] */
	torture_assert_int_equal(tctx, *p, 0, "contents");
	return true;
}

static bool test_talloc_s(struct torture_context *tctx)
{
	DATA_BLOB z = data_blob_talloc_s(tctx, "hello", 5);
	int i;
	uint8_t *p;

	torture_assert_int_equal(tctx, z.length, 5, "length");
	for (i = 0; i < z.length; i++)
		torture_assert_int_not_equal(tctx, z.data[i], 0, "data");
	p = z.data; /* store pointer that will be freed */
	data_blob_free(&z);
	for (i = 0; i < 5; i++)
		/* coverity[use_after_free] */
		torture_assert_int_equal(tctx, p[i], 0, "data");
	return true;
}

static bool test_dup_talloc_s(struct torture_context *tctx)
{
	DATA_BLOB b = data_blob_string_const("abcd");
	DATA_BLOB z = data_blob_dup_talloc_s(tctx, b);
	int i;
	uint8_t *p;

	torture_assert_int_equal(tctx, z.length, 4, "length");
	for (i = 0; i < b.length; i++)
		torture_assert_int_equal(tctx, z.data[i], b.data[i], "data");
	p = z.data; /* store pointer that will be freed */
	data_blob_free(&z);
	for (i = 0; i < b.length; i++)
		/* coverity[use_after_free] */
		torture_assert_int_equal(tctx, p[i], 0, "data");
	return true;
}

static bool test_clear(struct torture_context *tctx)
{
	int i;
	DATA_BLOB z = data_blob("lalala", 6);
	torture_assert_int_equal(tctx, z.length, 6, "length");
	data_blob_clear(&z);
	for (i = 0; i < z.length; i++)
		torture_assert_int_equal(tctx, z.data[i], 0, "contents");
	data_blob_free(&z);
	return true;
}

static bool test_cmp(struct torture_context *tctx)
{
	DATA_BLOB a = data_blob_string_const("bla");
	DATA_BLOB b = data_blob_string_const("blae");
	torture_assert(tctx, data_blob_cmp(&a, &b) != 0, "cmp different");
	torture_assert(tctx, data_blob_cmp(&a, &a) == 0, "cmp self");
	return true;
}

static bool test_equal_const_time(struct torture_context *tctx)
{
	const char *test_string = "foobarfoo";

	DATA_BLOB null = data_blob_const(NULL, 0);
	DATA_BLOB foobar = data_blob_const(test_string, 6);
	DATA_BLOB bar = data_blob_const(test_string + 3, 3);

	/* These data blobs both contain 'foo', but at different addresses. */
	DATA_BLOB foo_same = data_blob_const(test_string, 3);
	DATA_BLOB foo_other = data_blob_const(test_string + 6, 3);

	/* Test all equality combinations behave as expected. */
	torture_assert(tctx, data_blob_equal_const_time(&null, &null), "null == null");
	torture_assert(tctx, !data_blob_equal_const_time(&null, &foobar), "null != 'foobar'");
	torture_assert(tctx, !data_blob_equal_const_time(&null, &bar), "null != 'bar'");
	torture_assert(tctx, !data_blob_equal_const_time(&null, &foo_same), "null != 'foo'");
	torture_assert(tctx, !data_blob_equal_const_time(&null, &foo_other), "null != 'foo'");

	torture_assert(tctx, !data_blob_equal_const_time(&foobar, &null), "'foobar' != null");
	torture_assert(tctx, data_blob_equal_const_time(&foobar, &foobar), "'foobar' == 'foobar'");
	torture_assert(tctx, !data_blob_equal_const_time(&foobar, &bar), "'foobar' != 'bar'");
	torture_assert(tctx, !data_blob_equal_const_time(&foobar, &foo_same), "'foobar' != 'foo'");
	torture_assert(tctx, !data_blob_equal_const_time(&foobar, &foo_other), "'foobar' != 'foo'");

	torture_assert(tctx, !data_blob_equal_const_time(&foo_same, &null), "'foo' != null");
	torture_assert(tctx, !data_blob_equal_const_time(&foo_same, &foobar), "'foo' != 'foobar'");
	torture_assert(tctx, !data_blob_equal_const_time(&foo_same, &bar), "'foo' != 'bar'");
	torture_assert(tctx, data_blob_equal_const_time(&foo_same, &foo_same), "'foo' == 'foo'");
	torture_assert(tctx, data_blob_equal_const_time(&foo_same, &foo_other), "'foo' == 'foo'");

	torture_assert(tctx, !data_blob_equal_const_time(&foo_other, &null), "'foo' != null");
	torture_assert(tctx, !data_blob_equal_const_time(&foo_other, &foobar), "'foo' != 'foobar'");
	torture_assert(tctx, !data_blob_equal_const_time(&foo_other, &bar), "'foo' != 'bar'");
	torture_assert(tctx, data_blob_equal_const_time(&foo_other, &foo_same), "'foo' == 'foo'");
	torture_assert(tctx, data_blob_equal_const_time(&foo_other, &foo_other), "'foo' == 'foo'");

	torture_assert(tctx, !data_blob_equal_const_time(&bar, &null), "'bar' != null");
	torture_assert(tctx, !data_blob_equal_const_time(&bar, &foobar), "'bar' != 'foobar'");
	torture_assert(tctx, data_blob_equal_const_time(&bar, &bar), "'bar' == 'bar'");
	torture_assert(tctx, !data_blob_equal_const_time(&bar, &foo_same), "'bar' != 'foo'");
	torture_assert(tctx, !data_blob_equal_const_time(&bar, &foo_other), "'bar' != 'foo'");

	return true;
}

static bool test_hex_string(struct torture_context *tctx)
{
	DATA_BLOB a = data_blob_string_const("\xC\xA\xF\xE");
	torture_assert_str_equal(tctx, data_blob_hex_string_lower(tctx, &a), "0c0a0f0e", "hex string");
	torture_assert_str_equal(tctx, data_blob_hex_string_upper(tctx, &a), "0C0A0F0E", "hex string");
	return true;
}

static bool test_append_NULL_0(struct torture_context *tctx)
{
	DATA_BLOB z = data_blob_talloc_zero(tctx, 0);
	torture_assert_int_equal(tctx, z.length, 0, "length");
	torture_assert(tctx, z.data == NULL, "data");
	torture_assert(tctx, data_blob_append(NULL, &z, NULL, 0), "append NULL,0");
	torture_assert(tctx, data_blob_append(NULL, &z, "", 0), "append '',0");
	torture_assert_int_equal(tctx, z.length, 0, "length");
	torture_assert(tctx, z.data == NULL, "data");
	return true;
}

static bool test_append_empty_0(struct torture_context *tctx)
{
	DATA_BLOB e = data_blob_talloc(tctx, "", 0);
	torture_assert_int_equal(tctx, e.length, 0, "length");
	torture_assert(tctx, e.data != NULL, "data");
	torture_assert(tctx, data_blob_append(NULL, &e, NULL, 0), "append NULL,0");
	torture_assert(tctx, data_blob_append(NULL, &e, "", 0), "append '',0");
	torture_assert_int_equal(tctx, e.length, 0, "length");
	torture_assert(tctx, e.data != NULL, "data");
	return true;
}

struct torture_suite *torture_local_util_data_blob(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "datablob");

	torture_suite_add_simple_test(suite, "string", test_string);
	torture_suite_add_simple_test(suite, "string_null", test_string_null);
	torture_suite_add_simple_test(suite, "zero", test_zero);
	torture_suite_add_simple_test(suite, "zero_s", test_zero_s);
	torture_suite_add_simple_test(suite, "talloc_s", test_talloc_s);
	torture_suite_add_simple_test(suite, "dup_s", test_dup_talloc_s);
	torture_suite_add_simple_test(suite, "clear", test_clear);
	torture_suite_add_simple_test(suite, "cmp", test_cmp);
	torture_suite_add_simple_test(suite, "equal_const_time", test_equal_const_time);
	torture_suite_add_simple_test(suite, "hex string", test_hex_string);
	torture_suite_add_simple_test(suite, "append_NULL_0", test_append_NULL_0);
	torture_suite_add_simple_test(suite, "append_empty_0", test_append_empty_0);

	return suite;
}
