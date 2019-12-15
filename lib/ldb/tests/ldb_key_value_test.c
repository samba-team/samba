/*
 * Tests exercising the ldb key value operations.
 *
 *  Copyright (C) Andrew Bartlett <abartlet@samba.org> 2019
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

/*
 *
 * Tests for the ldb key value layer
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <unistd.h>
#include <talloc.h>
#include <tevent.h>
#include <string.h>
#include <ctype.h>

#include <sys/wait.h>

#include "ldb_key_value/ldb_kv.c"
#include "ldb_key_value/ldb_kv_index.c"
#include "ldb_key_value/ldb_kv_search.c"

#define DEFAULT_BE  "tdb"

#ifndef TEST_BE
#define TEST_BE DEFAULT_BE
#endif /* TEST_BE */

#define NUM_RECS 1024
int ldb_kv_cache_reload(struct ldb_module *module) {
	return LDB_SUCCESS;
}
int ldb_kv_cache_load(struct ldb_module *module) {
	return LDB_SUCCESS;
}
int ldb_kv_check_at_attributes_values(const struct ldb_val *value) {
	return LDB_SUCCESS;
}
int ldb_kv_increase_sequence_number(struct ldb_module *module) {
	return LDB_SUCCESS;
}

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

	talloc_free(test_ctx);
	return 0;
}

/*
 * Test that the index cache is opened by ldb_kv_index_transaction_start
 * and correctly initialised with the passed index cache size.
 */
static void test_index_cache_init(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(
		*state,
		struct test_ctx);
	struct ldb_module *module = NULL;
	struct ldb_kv_private *ldb_kv = NULL;
	int ret = LDB_SUCCESS;

	module = talloc_zero(test_ctx, struct ldb_module);
	ldb_kv = talloc_zero(test_ctx, struct ldb_kv_private);
	ldb_module_set_private(module, ldb_kv);

	ret = ldb_kv_index_transaction_start(module, 191);
	assert_int_equal(LDB_SUCCESS, ret);

	assert_non_null(ldb_kv->idxptr);
	assert_non_null(ldb_kv->idxptr->itdb);
	assert_int_equal(191, tdb_hash_size(ldb_kv->idxptr->itdb));

	TALLOC_FREE(ldb_kv);
	TALLOC_FREE(module);
}

static int mock_begin_write(struct ldb_kv_private* ldb_kv) {
	return LDB_SUCCESS;
}
static int mock_abort_write(struct ldb_kv_private* ldb_kv) {
	return LDB_SUCCESS;
}

/*
 * Test that the index cache is set to the default cache size at the start of
 * a transaction.
 */
static void test_default_index_cache_size(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(
		*state,
		struct test_ctx);
	struct ldb_module *module = NULL;
	struct ldb_kv_private *ldb_kv = NULL;
	int ret = LDB_SUCCESS;
	const struct kv_db_ops ops = {
		.begin_write = mock_begin_write,
		.abort_write = mock_abort_write
	};

	module = talloc_zero(test_ctx, struct ldb_module);
	ldb_kv = talloc_zero(test_ctx, struct ldb_kv_private);
	ldb_kv->pid = getpid();
	ldb_kv->kv_ops = &ops;
	ldb_kv->index_transaction_cache_size = DEFAULT_INDEX_CACHE_SIZE;
	ldb_module_set_private(module, ldb_kv);

	ret = ldb_kv_start_trans(module);
	assert_int_equal(LDB_SUCCESS, ret);

	assert_int_equal(
		DEFAULT_INDEX_CACHE_SIZE,
		tdb_hash_size(ldb_kv->idxptr->itdb));

	ret = ldb_kv_del_trans(module);
	assert_int_equal(LDB_SUCCESS, ret);

	TALLOC_FREE(ldb_kv);
	TALLOC_FREE(module);
}

static int db_size = 0;
static size_t mock_get_size(struct ldb_kv_private *ldb_kv) {
	return db_size;
}

static int mock_iterate(
	struct ldb_kv_private *ldb_kv,
	ldb_kv_traverse_fn fn,
	void *ctx) {
	return 1;
}

/*
 * Test that the index cache is correctly sized by the re_index call
 */
static void test_reindex_cache_size(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(
		*state,
		struct test_ctx);
	struct ldb_module *module = NULL;
	struct ldb_kv_private *ldb_kv = NULL;
	int ret = LDB_SUCCESS;
	const struct kv_db_ops ops = {
		.iterate = mock_iterate,
		.get_size = mock_get_size,
	};

	module = talloc_zero(test_ctx, struct ldb_module);
	ldb_kv = talloc_zero(test_ctx, struct ldb_kv_private);
	ldb_kv->kv_ops = &ops;
	ldb_module_set_private(module, ldb_kv);

	/*
	 * Use a value less than the DEFAULT_INDEX_CACHE_SIZE
	 * Should get the DEFAULT_INDEX_CACHE_SIZE
	 */
	db_size = DEFAULT_INDEX_CACHE_SIZE - 1;
	ret = ldb_kv_reindex(module);
	assert_int_equal(LDB_SUCCESS, ret);

	assert_int_equal(
		DEFAULT_INDEX_CACHE_SIZE,
		tdb_hash_size(ldb_kv->idxptr->itdb));

	/*
	 * Use a value greater than the DEFAULT_INDEX_CACHE_SIZE
	 * Should get the value specified.
	 */
	db_size = DEFAULT_INDEX_CACHE_SIZE + 1;
	ret = ldb_kv_reindex(module);
	assert_int_equal(LDB_SUCCESS, ret);

	assert_int_equal(db_size, tdb_hash_size(ldb_kv->idxptr->itdb));

	TALLOC_FREE(ldb_kv);
	TALLOC_FREE(module);
}

/*
 * Test that ldb_kv_init_store sets the default index transaction cache size
 * if the option is not supplied.
 */
static void test_init_store_default_index_cache_size(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(
		*state,
		struct test_ctx);
	struct ldb_module *module = NULL;
	struct ldb_kv_private *ldb_kv = NULL;
	struct ldb_context *ldb = NULL;
	int ret = LDB_SUCCESS;

	module = talloc_zero(test_ctx, struct ldb_module);
	ldb = talloc_zero(test_ctx, struct ldb_context);
	ldb_kv = talloc_zero(test_ctx, struct ldb_kv_private);

	ret = ldb_kv_init_store(ldb_kv, "test", ldb, NULL, &module);
	assert_int_equal(LDB_SUCCESS, ret);

	assert_int_equal(
		DEFAULT_INDEX_CACHE_SIZE,
		ldb_kv->index_transaction_cache_size);

	TALLOC_FREE(ldb_kv);
	TALLOC_FREE(module);
	TALLOC_FREE(ldb);
}

/*
 * Test that ldb_kv_init_store sets the index transaction cache size
 * to the value specified in the option.
 */
static void test_init_store_set_index_cache_size(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(
		*state,
		struct test_ctx);
	struct ldb_module *module = NULL;
	struct ldb_kv_private *ldb_kv = NULL;
	struct ldb_context *ldb = NULL;
	const char *options[] = {"transaction_index_cache_size:1900", NULL};
	int ret = LDB_SUCCESS;

	module = talloc_zero(test_ctx, struct ldb_module);
	ldb = talloc_zero(test_ctx, struct ldb_context);
	ldb_kv = talloc_zero(test_ctx, struct ldb_kv_private);

	ret = ldb_kv_init_store(ldb_kv, "test", ldb, options, &module);
	assert_int_equal(LDB_SUCCESS, ret);

	assert_int_equal( 1900, ldb_kv->index_transaction_cache_size);

	TALLOC_FREE(ldb_kv);
	TALLOC_FREE(module);
	TALLOC_FREE(ldb);
}

/*
 * Test that ldb_kv_init_store sets the default index transaction cache size
 * if the value specified in the option is not a number.
 */
static void test_init_store_set_index_cache_size_non_numeric(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(
		*state,
		struct test_ctx);
	struct ldb_module *module = NULL;
	struct ldb_kv_private *ldb_kv = NULL;
	struct ldb_context *ldb = NULL;
	const char *options[] = {"transaction_index_cache_size:fred", NULL};
	int ret = LDB_SUCCESS;

	module = talloc_zero(test_ctx, struct ldb_module);
	ldb = talloc_zero(test_ctx, struct ldb_context);
	ldb_kv = talloc_zero(test_ctx, struct ldb_kv_private);

	ret = ldb_kv_init_store(ldb_kv, "test", ldb, options, &module);
	assert_int_equal(LDB_SUCCESS, ret);

	assert_int_equal(
		DEFAULT_INDEX_CACHE_SIZE,
		ldb_kv->index_transaction_cache_size);

	TALLOC_FREE(ldb_kv);
	TALLOC_FREE(module);
	TALLOC_FREE(ldb);
}

/*
 * Test that ldb_kv_init_store sets the default index transaction cache size
 * if the value specified is too large
 */
static void test_init_store_set_index_cache_size_range(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(
		*state,
		struct test_ctx);
	struct ldb_module *module = NULL;
	struct ldb_kv_private *ldb_kv = NULL;
	struct ldb_context *ldb = NULL;
	const char *options[] = {
		"transaction_index_cache_size:0xfffffffffffffffffffffffffffff",
		NULL};
	int ret = LDB_SUCCESS;

	module = talloc_zero(test_ctx, struct ldb_module);
	ldb = talloc_zero(test_ctx, struct ldb_context);
	ldb_kv = talloc_zero(test_ctx, struct ldb_kv_private);

	ret = ldb_kv_init_store(ldb_kv, "test", ldb, options, &module);
	assert_int_equal(LDB_SUCCESS, ret);

	assert_int_equal(
		DEFAULT_INDEX_CACHE_SIZE,
		ldb_kv->index_transaction_cache_size);

	TALLOC_FREE(ldb_kv);
	TALLOC_FREE(module);
	TALLOC_FREE(ldb);
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
			test_index_cache_init,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_default_index_cache_size,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_reindex_cache_size,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_init_store_default_index_cache_size,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_init_store_set_index_cache_size,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_init_store_set_index_cache_size_non_numeric,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_init_store_set_index_cache_size_range,
			setup,
			teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
