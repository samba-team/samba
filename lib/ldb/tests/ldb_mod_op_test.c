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
#include <setjmp.h>
#include <cmocka.h>

#include <cmocka.h>

#include <errno.h>
#include <unistd.h>
#include <talloc.h>
#include <ldb.h>

#define DEFAULT_BE  "tdb"

#ifndef TEST_BE
#define TEST_BE DEFAULT_BE
#endif /* TEST_BE */

struct ldbtest_ctx {
	struct tevent_context *ev;
	struct ldb_context *ldb;

	const char *dbfile;
	const char *lockfile;

	const char *dbpath;
	const char *lockpath;   /* lockfile is separate */
};

static int ldbtest_noconn_setup(void **state)
{
	struct ldbtest_ctx *test_ctx;

	test_ctx = talloc_zero(NULL, struct ldbtest_ctx);
	assert_non_null(test_ctx);

	test_ctx->ev = tevent_context_init(test_ctx);
	assert_non_null(test_ctx->ev);

	test_ctx->ldb = ldb_init(test_ctx, test_ctx->ev);
	assert_non_null(test_ctx->ldb);

	test_ctx->dbfile = talloc_strdup(test_ctx, "apitest.ldb");
	assert_non_null(test_ctx->dbfile);

	test_ctx->lockfile = talloc_asprintf(test_ctx,
					     "%s-lock", test_ctx->dbfile);
	assert_non_null(test_ctx->lockfile);

	test_ctx->dbpath = talloc_asprintf(test_ctx,
					  TEST_BE"://%s", test_ctx->dbfile);
	assert_non_null(test_ctx->dbpath);

	test_ctx->lockpath = talloc_asprintf(test_ctx,
					     "%s-lock", test_ctx->dbpath);
	assert_non_null(test_ctx->lockpath);

	*state = test_ctx;
	return 0;
}

static int ldbtest_noconn_teardown(void **state)
{
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);

	unlink(test_ctx->lockfile);

	unlink(test_ctx->dbfile);

	talloc_free(test_ctx);
	return 0;
}

static void test_connect(void **state)
{
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	int ret;

	ret = ldb_connect(test_ctx->ldb, test_ctx->dbpath, 0, NULL);
	assert_int_equal(ret, 0);
}

static int ldbtest_setup(void **state)
{
	struct ldbtest_ctx *test_ctx;
	int ret;

	ldbtest_noconn_setup((void **) &test_ctx);

	ret = ldb_connect(test_ctx->ldb, test_ctx->dbpath, 0, NULL);
	assert_int_equal(ret, 0);

	*state = test_ctx;
	return 0;
}

static int ldbtest_teardown(void **state)
{
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	ldbtest_noconn_teardown((void **) &test_ctx);
	return 0;
}

static void test_ldb_add(void **state)
{
	int ret;
	struct ldb_message *msg;
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	msg = ldb_msg_new(tmp_ctx);
	assert_non_null(msg);

	msg->dn = ldb_dn_new_fmt(msg, test_ctx->ldb, "dc=test");
	assert_non_null(msg->dn);

	ret = ldb_msg_add_string(msg, "cn", "test_cn_val");
	assert_int_equal(ret, 0);

	ret = ldb_add(test_ctx->ldb, msg);
	assert_int_equal(ret, 0);

	talloc_free(tmp_ctx);
}

static void test_ldb_search(void **state)
{
	int ret;
	struct ldb_message *msg;
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	TALLOC_CTX *tmp_ctx;
	struct ldb_dn *basedn;
	struct ldb_dn *basedn2;
	struct ldb_result *result = NULL;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	basedn = ldb_dn_new_fmt(tmp_ctx, test_ctx->ldb, "dc=test");
	assert_non_null(basedn);

	ret = ldb_search(test_ctx->ldb, tmp_ctx, &result, basedn,
			 LDB_SCOPE_BASE, NULL, NULL);
	assert_int_equal(ret, 0);
	assert_non_null(result);
	assert_int_equal(result->count, 0);

	msg = ldb_msg_new(tmp_ctx);
	assert_non_null(msg);

	msg->dn = basedn;
	assert_non_null(msg->dn);

	ret = ldb_msg_add_string(msg, "cn", "test_cn_val1");
	assert_int_equal(ret, 0);

	ret = ldb_add(test_ctx->ldb, msg);
	assert_int_equal(ret, 0);

	basedn2 = ldb_dn_new_fmt(tmp_ctx, test_ctx->ldb, "dc=test2");
	assert_non_null(basedn2);

	msg = ldb_msg_new(tmp_ctx);
	assert_non_null(msg);

	msg->dn = basedn2;
	assert_non_null(msg->dn);

	ret = ldb_msg_add_string(msg, "cn", "test_cn_val2");
	assert_int_equal(ret, 0);

	ret = ldb_add(test_ctx->ldb, msg);
	assert_int_equal(ret, 0);

	ret = ldb_search(test_ctx->ldb, tmp_ctx, &result, basedn,
			 LDB_SCOPE_BASE, NULL, NULL);
	assert_int_equal(ret, 0);
	assert_non_null(result);
	assert_int_equal(result->count, 1);
	assert_string_equal(ldb_dn_get_linearized(result->msgs[0]->dn),
			    ldb_dn_get_linearized(basedn));

	ret = ldb_search(test_ctx->ldb, tmp_ctx, &result, basedn2,
			 LDB_SCOPE_BASE, NULL, NULL);
	assert_int_equal(ret, 0);
	assert_non_null(result);
	assert_int_equal(result->count, 1);
	assert_string_equal(ldb_dn_get_linearized(result->msgs[0]->dn),
			    ldb_dn_get_linearized(basedn2));

	talloc_free(tmp_ctx);
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_connect,
						ldbtest_noconn_setup,
						ldbtest_noconn_teardown),
		cmocka_unit_test_setup_teardown(test_ldb_add,
						ldbtest_setup,
						ldbtest_teardown),
		cmocka_unit_test_setup_teardown(test_ldb_search,
						ldbtest_setup,
						ldbtest_teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
