/*
 * lmdb backend specific tests for ldb
 *
 *  Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018
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
 * lmdb backend specific tests for ldb
 *
 * Setup and tear down code copied  from ldb_mod_op_test.c
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
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <unistd.h>
#include <talloc.h>
#include <tevent.h>
#include <ldb.h>
#include <ldb_module.h>
#include <ldb_private.h>
#include <string.h>
#include <ctype.h>

#include <sys/wait.h>

#include "../ldb_tdb/ldb_tdb.h"
#include "../ldb_key_value/ldb_kv.h"

#define TEST_BE  "tdb"

struct ldbtest_ctx {
	struct tevent_context *ev;
	struct ldb_context *ldb;

	const char *dbfile;

	const char *dbpath;
};

static void unlink_old_db(struct ldbtest_ctx *test_ctx)
{
	int ret;

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

static int ldbtest_setup(void **state)
{
	struct ldbtest_ctx *test_ctx;
	int ret;
	struct ldb_ldif *ldif;
	const char *index_ldif =		\
		"dn: @INDEXLIST\n"
		"@IDXGUID: objectUUID\n"
		"@IDX_DN_GUID: GUID\n"
		"\n";

	ldbtest_noconn_setup((void **) &test_ctx);

	ret = ldb_connect(test_ctx->ldb, test_ctx->dbpath, 0, NULL);
	assert_int_equal(ret, 0);

	while ((ldif = ldb_ldif_read_string(test_ctx->ldb, &index_ldif))) {
		ret = ldb_add(test_ctx->ldb, ldif->msg);
		assert_int_equal(ret, LDB_SUCCESS);
	}
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


static TDB_CONTEXT *get_tdb_context(struct ldb_context *ldb)
{
	void *data = NULL;
	struct ldb_kv_private *ldb_kv = NULL;
	TDB_CONTEXT *tdb = NULL;

	data = ldb_module_get_private(ldb->modules);
	assert_non_null(data);

	ldb_kv = talloc_get_type(data, struct ldb_kv_private);
	assert_non_null(ldb_kv);

	tdb = ldb_kv->tdb;
	assert_non_null(tdb);

	return tdb;
}

static void test_multiple_opens(void **state)
{
	struct ldb_context *ldb1 = NULL;
	struct ldb_context *ldb2 = NULL;
	struct ldb_context *ldb3 = NULL;
	TDB_CONTEXT *tdb1 = NULL;
	TDB_CONTEXT *tdb2 = NULL;
	TDB_CONTEXT *tdb3 = NULL;
	int ret;
	struct ldbtest_ctx *test_ctx = NULL;

	test_ctx = talloc_get_type_abort(*state, struct ldbtest_ctx);

	/*
	 * Open the database again
	 */
	ldb1 = ldb_init(test_ctx, test_ctx->ev);
	ret = ldb_connect(ldb1, test_ctx->dbpath, LDB_FLG_RDONLY, NULL);
	assert_int_equal(ret, 0);

	ldb2 = ldb_init(test_ctx, test_ctx->ev);
	ret = ldb_connect(ldb2, test_ctx->dbpath, LDB_FLG_RDONLY, NULL);
	assert_int_equal(ret, 0);

	ldb3 = ldb_init(test_ctx, test_ctx->ev);
	ret = ldb_connect(ldb3, test_ctx->dbpath, 0, NULL);
	assert_int_equal(ret, 0);
	/*
	 * We now have 3 ldb's open pointing to the same on disk database
	 * they should all share the same MDB_env
	 */
	tdb1 = get_tdb_context(ldb1);
	tdb2 = get_tdb_context(ldb2);
	tdb3 = get_tdb_context(ldb3);

	assert_ptr_equal(tdb1, tdb2);
	assert_ptr_equal(tdb1, tdb3);
}

static void test_multiple_opens_across_fork(void **state)
{
	struct ldb_context *ldb1 = NULL;
	struct ldb_context *ldb2 = NULL;
	TDB_CONTEXT *tdb1 = NULL;
	TDB_CONTEXT *tdb2 = NULL;
	int ret;
	struct ldbtest_ctx *test_ctx = NULL;
	int pipes[2];
	char buf[2];
	int wstatus;
	pid_t pid, child_pid;

	test_ctx = talloc_get_type_abort(*state, struct ldbtest_ctx);

	/*
	 * Open the database again
	 */
	ldb1 = ldb_init(test_ctx, test_ctx->ev);
	ret = ldb_connect(ldb1, test_ctx->dbpath, LDB_FLG_RDONLY, NULL);
	assert_int_equal(ret, 0);

	ldb2 = ldb_init(test_ctx, test_ctx->ev);
	ret = ldb_connect(ldb2, test_ctx->dbpath, LDB_FLG_RDONLY, NULL);
	assert_int_equal(ret, 0);

	tdb1 = get_tdb_context(ldb1);
	tdb2 = get_tdb_context(ldb2);

	ret = pipe(pipes);
	assert_int_equal(ret, 0);

	child_pid = fork();
	if (child_pid == 0) {
		struct ldb_context *ldb3 = NULL;
		TDB_CONTEXT *tdb3 = NULL;

		close(pipes[0]);
		ldb3 = ldb_init(test_ctx, test_ctx->ev);
		ret = ldb_connect(ldb3, test_ctx->dbpath, 0, NULL);
		if (ret != 0) {
			print_error(__location__": ldb_connect returned (%d)\n",
				    ret);
			exit(ret);
		}
		tdb3 = get_tdb_context(ldb3);
		if (tdb1 != tdb2) {
			print_error(__location__": tdb1 != tdb2\n");
			exit(LDB_ERR_OPERATIONS_ERROR);
		}
		if (tdb1 != tdb3) {
			print_error(__location__": tdb1 != tdb3\n");
			exit(LDB_ERR_OPERATIONS_ERROR);
		}
		ret = write(pipes[1], "GO", 2);
		if (ret != 2) {
			print_error(__location__
				      " write returned (%d)",
				      ret);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}
		exit(LDB_SUCCESS);
	}
	close(pipes[1]);
	ret = read(pipes[0], buf, 2);
	assert_int_equal(ret, 2);

	pid = waitpid(child_pid, &wstatus, 0);
	assert_int_equal(pid, child_pid);

	assert_true(WIFEXITED(wstatus));

	assert_int_equal(WEXITSTATUS(wstatus), 0);
}

static void test_multiple_opens_across_fork_triggers_reopen(void **state)
{
	struct ldb_context *ldb1 = NULL;
	struct ldb_context *ldb2 = NULL;
	TDB_CONTEXT *tdb1 = NULL;
	TDB_CONTEXT *tdb2 = NULL;
	int ret;
	struct ldbtest_ctx *test_ctx = NULL;
	int pipes[2];
	char buf[2];
	int wstatus;
	pid_t pid, child_pid;

	test_ctx = talloc_get_type_abort(*state, struct ldbtest_ctx);

	/*
	 * Open the database again
	 */
	ldb1 = ldb_init(test_ctx, test_ctx->ev);
	ret = ldb_connect(ldb1, test_ctx->dbpath, LDB_FLG_RDONLY, NULL);
	assert_int_equal(ret, 0);

	ldb2 = ldb_init(test_ctx, test_ctx->ev);
	ret = ldb_connect(ldb2, test_ctx->dbpath, LDB_FLG_RDONLY, NULL);
	assert_int_equal(ret, 0);

	tdb1 = get_tdb_context(ldb1);
	tdb2 = get_tdb_context(ldb2);
	assert_ptr_equal(tdb1, tdb2);

	/*
	 * Break the internal tdb_reopen() by making a
	 * transaction
	 *
	 * This shows that the tdb_reopen() is called, which is
	 * essential if the host OS does not have pread()
	 */
	ret = tdb_transaction_start(tdb1);
	assert_int_equal(ret, 0);

	ret = pipe(pipes);
	assert_int_equal(ret, 0);

	child_pid = fork();
	if (child_pid == 0) {
		struct ldb_context *ldb3 = NULL;

		close(pipes[0]);
		ldb3 = ldb_init(test_ctx, test_ctx->ev);

		/*
		 * This should fail as we have taken out a lock
		 * against the raw TDB above, and tdb_reopen()
		 * will fail in that state.
		 *
		 * This check matters as tdb_reopen() is important
		 * if the host does not have pread()
		 */
		ret = ldb_connect(ldb3, test_ctx->dbpath, 0, NULL);
		if (ret == 0) {
			print_error(__location__": ldb_connect expected "
				    "LDB_ERR_OPERATIONS_ERROR "
				    "returned (%d)\n",
				    ret);
			exit(5000);
		}
		ret = write(pipes[1], "GO", 2);
		if (ret != 2) {
			print_error(__location__
				      " write returned (%d)",
				      ret);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}
		exit(LDB_SUCCESS);
	}
	close(pipes[1]);
	ret = read(pipes[0], buf, 2);
	assert_int_equal(ret, 2);

	pid = waitpid(child_pid, &wstatus, 0);
	assert_int_equal(pid, child_pid);

	assert_true(WIFEXITED(wstatus));

	assert_int_equal(WEXITSTATUS(wstatus), 0);
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
			test_multiple_opens,
			ldbtest_setup,
			ldbtest_teardown),
		cmocka_unit_test_setup_teardown(
			test_multiple_opens_across_fork,
			ldbtest_setup,
			ldbtest_teardown),
		cmocka_unit_test_setup_teardown(
			test_multiple_opens_across_fork_triggers_reopen,
			ldbtest_setup,
			ldbtest_teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
