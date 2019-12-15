/*
 * lmdb backend specific tests for ldb
 * Tests for truncated index keys
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
 * These tests confirm that database sizes of > 4GB are supported
 * Due to the disk space requirement they are not run as part of the normal
 * self test runs.
 *
 * Setup and tear down code copied from ldb_mod_op_test.c
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

#include <lmdb.h>


#define TEST_BE  "mdb"

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

static int ldbtest_setup(void **state)
{
	struct ldbtest_ctx *test_ctx;
	int ret;
	/*
	 * We need to to set GUID index mode as it's required now required
	 * by LDB
	 */
	struct ldb_ldif *ldif;
	const char *index_ldif =
		"dn: @INDEXLIST\n"
		"@IDXGUID: objectUUID\n"
		"@IDX_DN_GUID: GUID\n"
		"\n";
	/*
	 * Set the lmdb map size to 8Gb
	 */
	const char *options[] = {"lmdb_env_size:8589934592", NULL};

	ldbtest_noconn_setup((void **) &test_ctx);


	ret = ldb_connect(test_ctx->ldb, test_ctx->dbpath, 0, options);
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

static void test_db_size_gt_4GB(void **state)
{
	int ret, x;
	struct ldb_message *msg;
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	const int MB = 1024 * 1024;
	char *blob = NULL;

	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);


	blob = talloc_zero_size(tmp_ctx, (MB + 1));
	assert_non_null(blob);
	memset(blob, 'x', MB);


	/*
	 * Write 6144 1Mb records to the database, this will require more than
	 * 4GiB of disk space
	 */
	for (x = 0; x < 6144; x++) {
		char uuid[24];
		msg = ldb_msg_new(tmp_ctx);
		assert_non_null(msg);

		/*
		 * Generate a unique dn for each record
		 */
		msg->dn = ldb_dn_new_fmt(msg, test_ctx->ldb, "dc=test%d", x);
		assert_non_null(msg->dn);

		/*
		 * Generate a unique uuid for each added record
		 */
		sprintf(uuid, "000000000000%04d", x);
		ret = ldb_msg_add_string(msg, "objectUUID", uuid);
		assert_int_equal(ret, 0);

		ldb_transaction_start(test_ctx->ldb);
		ret = ldb_msg_add_string(msg, "blob", blob);
		assert_int_equal(ret, 0);

		ret = ldb_add(test_ctx->ldb, msg);
		assert_int_equal(ret, 0);
		ldb_transaction_commit(test_ctx->ldb);

		TALLOC_FREE(msg);
	}
	talloc_free(tmp_ctx);
	{
		struct stat s;
		ret = stat(test_ctx->dbfile, &s);
		assert_int_equal(ret, 0);
		/*
		 * There should have been at least 6GiB written to disk
		 */
		assert_true(s.st_size > (6144LL * MB));
	}
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
			test_db_size_gt_4GB,
			ldbtest_setup,
			ldbtest_teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
