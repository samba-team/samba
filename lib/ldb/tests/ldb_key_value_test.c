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
#include "ldb_key_value/ldb_kv_cache.c"
#include "ldb_key_value/ldb_kv_index.c"
#include "ldb_key_value/ldb_kv_search.c"

#define DEFAULT_BE  "tdb"

#ifndef TEST_BE
#define TEST_BE DEFAULT_BE
#endif /* TEST_BE */

#define NUM_RECS 1024


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
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
