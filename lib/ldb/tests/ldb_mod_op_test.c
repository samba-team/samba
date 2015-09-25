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
	const char *lockfile;   /* lockfile is separate */

	const char *dbpath;
};

static void unlink_old_db(struct ldbtest_ctx *test_ctx)
{
	int ret;

	errno = 0;
	ret = unlink(test_ctx->lockfile);
	if (ret == -1 && errno != ENOENT) {
		fail();
	}

	errno = 0;
	ret = unlink(test_ctx->dbfile);
	if (ret == -1 && errno != ENOENT) {
		fail();
	}
}

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

	test_ctx->lockfile = talloc_asprintf(test_ctx, "%s-lock",
					     test_ctx->dbfile);
	assert_non_null(test_ctx->lockfile);

	test_ctx->dbpath = talloc_asprintf(test_ctx,
			TEST_BE"://%s", test_ctx->dbfile);
	assert_non_null(test_ctx->dbpath);

	unlink_old_db(test_ctx);
	*state = test_ctx;
	return 0;
}

static int ldbtest_noconn_teardown(void **state)
{
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);

	unlink_old_db(test_ctx);
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

static int base_search_count(struct ldbtest_ctx *test_ctx, const char *entry_dn)
{
	TALLOC_CTX *tmp_ctx;
	struct ldb_dn *basedn;
	struct ldb_result *result = NULL;
	int ret;
	int count;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	basedn = ldb_dn_new_fmt(tmp_ctx, test_ctx->ldb, "%s", entry_dn);
	assert_non_null(basedn);

	ret = ldb_search(test_ctx->ldb, tmp_ctx, &result, basedn,
			 LDB_SCOPE_BASE, NULL, NULL);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(result);

	count = result->count;
	talloc_free(tmp_ctx);
	return count;
}

static void assert_dn_exists(struct ldbtest_ctx *test_ctx,
			     const char *entry_dn)
{
	int count;

	count = base_search_count(test_ctx, entry_dn);
	assert_int_equal(count, 1);
}

static void assert_dn_doesnt_exist(struct ldbtest_ctx *test_ctx,
				   const char *entry_dn)
{
	int count;

	count = base_search_count(test_ctx, entry_dn);
	assert_int_equal(count, 0);
}

static void test_ldb_del(void **state)
{
	int ret;
	struct ldb_message *msg;
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	TALLOC_CTX *tmp_ctx;
	const char *basedn = "dc=ldb_del_test";

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	assert_dn_doesnt_exist(test_ctx, basedn);

	msg = ldb_msg_new(tmp_ctx);
	assert_non_null(msg);

	msg->dn = ldb_dn_new_fmt(tmp_ctx, test_ctx->ldb, "%s", basedn);
	assert_non_null(msg->dn);

	ret = ldb_msg_add_string(msg, "cn", "test_del_cn_val");
	assert_int_equal(ret, LDB_SUCCESS);

	ret = ldb_add(test_ctx->ldb, msg);
	assert_int_equal(ret, LDB_SUCCESS);

	assert_dn_exists(test_ctx, basedn);

	ret = ldb_delete(test_ctx->ldb, msg->dn);
	assert_int_equal(ret, LDB_SUCCESS);

	assert_dn_doesnt_exist(test_ctx, basedn);

	talloc_free(tmp_ctx);
}

static void test_ldb_del_noexist(void **state)
{
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							     struct ldbtest_ctx);
	struct ldb_dn *basedn;
	int ret;

	basedn = ldb_dn_new(test_ctx, test_ctx->ldb, "dc=nosuchplace");
	assert_non_null(basedn);

	ret = ldb_delete(test_ctx->ldb, basedn);
	assert_int_equal(ret, LDB_ERR_NO_SUCH_OBJECT);
}

static void add_keyval(struct ldbtest_ctx *test_ctx,
		       const char *key,
		       const char *val)
{
	int ret;
	struct ldb_message *msg;

	msg = ldb_msg_new(test_ctx);
	assert_non_null(msg);

	msg->dn = ldb_dn_new_fmt(msg, test_ctx->ldb, "%s=%s", key, val);
	assert_non_null(msg->dn);

	ret = ldb_msg_add_string(msg, key, val);
	assert_int_equal(ret, 0);

	ret = ldb_add(test_ctx->ldb, msg);
	assert_int_equal(ret, 0);

	talloc_free(msg);
}

static struct ldb_result *get_keyval(struct ldbtest_ctx *test_ctx,
				     const char *key,
				     const char *val)
{
	int ret;
	struct ldb_result *result;
	struct ldb_dn *basedn;

	basedn = ldb_dn_new_fmt(test_ctx, test_ctx->ldb, "%s=%s", key, val);
	assert_non_null(basedn);

	ret = ldb_search(test_ctx->ldb, test_ctx, &result, basedn,
			LDB_SCOPE_BASE, NULL, NULL);
	assert_int_equal(ret, 0);

	return result;
}

static void test_transactions(void **state)
{
	int ret;
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
			struct ldbtest_ctx);
	struct ldb_result *res;

	/* start lev-0 transaction */
	ret = ldb_transaction_start(test_ctx->ldb);
	assert_int_equal(ret, 0);

	add_keyval(test_ctx, "vegetable", "carrot");

	/* commit lev-0 transaction */
	ret = ldb_transaction_commit(test_ctx->ldb);
	assert_int_equal(ret, 0);

	/* start another lev-1 nested transaction */
	ret = ldb_transaction_start(test_ctx->ldb);
	assert_int_equal(ret, 0);

	add_keyval(test_ctx, "fruit", "apple");

	/* abort lev-1 nested transaction */
	ret = ldb_transaction_cancel(test_ctx->ldb);
	assert_int_equal(ret, 0);

	res = get_keyval(test_ctx, "vegetable", "carrot");
	assert_non_null(res);
	assert_int_equal(res->count, 1);

	res = get_keyval(test_ctx, "fruit", "apple");
	assert_non_null(res);
	assert_int_equal(res->count, 0);
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
		cmocka_unit_test_setup_teardown(test_ldb_del,
						ldbtest_setup,
						ldbtest_teardown),
		cmocka_unit_test_setup_teardown(test_ldb_del_noexist,
						ldbtest_setup,
						ldbtest_teardown),
		cmocka_unit_test_setup_teardown(test_transactions,
						ldbtest_setup,
						ldbtest_teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
