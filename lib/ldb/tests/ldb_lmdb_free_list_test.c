/*
 * Copyright (C) Catalyst.Net Ltd 2020
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
 * Tests confirming lmdb's handling of the free space list in the presence
 * of active and stale readers.  A stale reader is a process that opens a
 * read lock and then exits without releasing the lock.
 *
 * lmdb uses MVCC to maintain databased consistency, new copies of updated
 * records are written to the database. The old entries are only
 * reused when they are no longer referenced in a read transaction.
 *
 * The tests all update a single record multiple times
 *
 * If there is a read transaction or a stale reader lmdb will report
 * out of space.
 *
 * If no read transaction and no stale reader, lmdb reclaims space from the
 * free list.
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

#include "ldb_tdb/ldb_tdb.h"
#include "ldb_key_value/ldb_kv.h"

#define DEFAULT_BE "mdb"

#ifndef TEST_BE
#define TEST_BE DEFAULT_BE
#endif /* TEST_BE */

const int RECORD_SIZE = 6144;
const int ITERATIONS = 3;

struct test_ctx {
	struct tevent_context *ev;
	struct ldb_context *ldb;

	const char *dbfile;
	const char *lockfile; /* lockfile is separate */

	const char *dbpath;
};

static void unlink_old_db(struct test_ctx *test_ctx)
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

static int noconn_setup(void **state)
{
	struct test_ctx *test_ctx;

	test_ctx = talloc_zero(NULL, struct test_ctx);
	assert_non_null(test_ctx);

	test_ctx->ev = tevent_context_init(test_ctx);
	assert_non_null(test_ctx->ev);

	test_ctx->ldb = ldb_init(test_ctx, test_ctx->ev);
	assert_non_null(test_ctx->ldb);

	test_ctx->dbfile = talloc_strdup(test_ctx, "lmdb_free_list_test.ldb");
	assert_non_null(test_ctx->dbfile);

	test_ctx->lockfile =
	    talloc_asprintf(test_ctx, "%s-lock", test_ctx->dbfile);
	assert_non_null(test_ctx->lockfile);

	test_ctx->dbpath =
	    talloc_asprintf(test_ctx, TEST_BE "://%s", test_ctx->dbfile);
	assert_non_null(test_ctx->dbpath);

	unlink_old_db(test_ctx);
	*state = test_ctx;
	return 0;
}

static int noconn_teardown(void **state)
{
	struct test_ctx *test_ctx =
	    talloc_get_type_abort(*state, struct test_ctx);

	unlink_old_db(test_ctx);
	talloc_free(test_ctx);
	return 0;
}

static int setup(void **state)
{
	struct test_ctx *test_ctx;
	int ret;
	struct ldb_ldif *ldif;
	const char *index_ldif = "dn: @INDEXLIST\n"
				 "@IDXGUID: objectUUID\n"
				 "@IDX_DN_GUID: GUID\n"
				 "\n";
	/*
	 * Use a 64KiB DB for this test
	 */
	const char *options[] = {"lmdb_env_size:65536", NULL};

	noconn_setup((void **)&test_ctx);

	ret = ldb_connect(test_ctx->ldb, test_ctx->dbpath, 0, options);
	assert_int_equal(ret, 0);

	while ((ldif = ldb_ldif_read_string(test_ctx->ldb, &index_ldif))) {
		ret = ldb_add(test_ctx->ldb, ldif->msg);
		assert_int_equal(ret, LDB_SUCCESS);
	}
	*state = test_ctx;
	return 0;
}

static int teardown(void **state)
{
	struct test_ctx *test_ctx =
	    talloc_get_type_abort(*state, struct test_ctx);
	noconn_teardown((void **)&test_ctx);
	return 0;
}

static struct ldb_kv_private *get_ldb_kv(struct ldb_context *ldb)
{
	void *data = NULL;
	struct ldb_kv_private *ldb_kv = NULL;

	data = ldb_module_get_private(ldb->modules);
	assert_non_null(data);

	ldb_kv = talloc_get_type(data, struct ldb_kv_private);
	assert_non_null(ldb_kv);

	return ldb_kv;
}

static int parse(struct ldb_val key, struct ldb_val data, void *private_data)
{
	struct ldb_val *read = private_data;

	/* Yes, we leak this.  That is OK */
	read->data = talloc_size(NULL, data.length);
	assert_non_null(read->data);

	memcpy(read->data, data.data, data.length);
	read->length = data.length;
	return LDB_SUCCESS;
}

/*
 * This test has the same structure as the test_free_list_read_lock
 * except the parent process does not keep the read lock open while the
 * child process is performing an update.
 */
static void test_free_list_no_read_lock(void **state)
{
	int ret;
	struct test_ctx *test_ctx =
	    talloc_get_type_abort(*state, struct test_ctx);
	struct ldb_kv_private *ldb_kv = get_ldb_kv(test_ctx->ldb);
	struct ldb_val key;
	struct ldb_val val;

	const char *KEY1 = "KEY01";

	/*
	 * Pipes etc to co-ordinate the processes
	 */
	int to_child[2];
	int to_parent[2];
	char buf[2];
	pid_t pid;
	size_t i;

	TALLOC_CTX *tmp_ctx;
	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	ret = pipe(to_child);
	assert_int_equal(ret, 0);
	ret = pipe(to_parent);
	assert_int_equal(ret, 0);
	/*
	 * Now fork a new process
	 */

	pid = fork();
	if (pid == 0) {
		/*
		 * Child process
		 */

		struct ldb_context *ldb = NULL;
		close(to_child[1]);
		close(to_parent[0]);

		/*
		 * Wait for the parent to get ready.
		 */
		ret = read(to_child[0], buf, 2);
		assert_int_equal(ret, 2);

		ldb = ldb_init(test_ctx, test_ctx->ev);
		assert_non_null(ldb);

		ret = ldb_connect(ldb, test_ctx->dbpath, 0, NULL);
		assert_int_equal(ret, LDB_SUCCESS);

		ldb_kv = get_ldb_kv(ldb);
		assert_non_null(ldb_kv);
		/*
		 * Add a record to the database
		 */
		key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY1);
		key.length = strlen(KEY1) + 1;
		val.data = talloc_zero_size(tmp_ctx, RECORD_SIZE);
		assert_non_null(val.data);
		memset(val.data, 'x', RECORD_SIZE);
		val.length = RECORD_SIZE;
		/*
		 * Do more iterations than when a read lock, stale reader
		 * active to confirm that the space is being re-used.
		 */
		for (i = 0; i < ITERATIONS * 10; i++) {
			ret = ldb_kv->kv_ops->begin_write(ldb_kv);
			assert_int_equal(ret, LDB_SUCCESS);

			ret = ldb_kv->kv_ops->store(ldb_kv, key, val, 0);
			assert_int_equal(ret, LDB_SUCCESS);

			ret = ldb_kv->kv_ops->finish_write(ldb_kv);
			assert_int_equal(ret, LDB_SUCCESS);
		}

		/*
		 * Signal the parent that we've done the updates
		 */
		ret = write(to_parent[1], "GO", 2);
		assert_int_equal(ret, 2);
		exit(0);
	}

	close(to_child[0]);
	close(to_parent[1]);

	/*
	 * Begin a read transaction
	 */
	ret = ldb_kv->kv_ops->lock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, LDB_SUCCESS);

	/*
	 * Now close it
	 */
	ret = ldb_kv->kv_ops->unlock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, LDB_SUCCESS);

	/*
	 * Signal the child process
	 */
	ret = write(to_child[1], "GO", 2);
	assert_int_equal(2, ret);

	/*
	 * Wait for the child process to update the record
	 */
	ret = read(to_parent[0], buf, 2);
	assert_int_equal(2, ret);

	/*
	 * Begin a read transaction
	 */
	ret = ldb_kv->kv_ops->lock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, LDB_SUCCESS);
	/*
	 * read the record
	 * and close the transaction
	 */
	key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY1);
	key.length = strlen(KEY1) + 1;

	ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &val);
	assert_int_equal(ret, LDB_SUCCESS);

	ret = ldb_kv->kv_ops->unlock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, LDB_SUCCESS);

	close(to_child[1]);
	close(to_parent[0]);
	TALLOC_FREE(tmp_ctx);
}

/*
 * This test has the same structure as the test_free_list_read_lock
 * except the parent process keeps the read lock open while the
 * child process is performing an update.
 */
static void test_free_list_read_lock(void **state)
{
	int ret;
	struct test_ctx *test_ctx =
	    talloc_get_type_abort(*state, struct test_ctx);
	struct ldb_kv_private *ldb_kv = get_ldb_kv(test_ctx->ldb);
	struct ldb_val key;
	struct ldb_val val;

	const char *KEY1 = "KEY01";

	/*
	 * Pipes etc to co-ordinate the processes
	 */
	int to_child[2];
	int to_parent[2];
	char buf[2];
	pid_t pid;
	size_t i;

	TALLOC_CTX *tmp_ctx;
	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	ret = pipe(to_child);
	assert_int_equal(ret, 0);
	ret = pipe(to_parent);
	assert_int_equal(ret, 0);
	/*
	 * Now fork a new process
	 */

	pid = fork();
	if (pid == 0) {
		/*
		 * Child process
		 */

		struct ldb_context *ldb = NULL;
		close(to_child[1]);
		close(to_parent[0]);

		/*
		 * Wait for the transaction to start
		 */
		ret = read(to_child[0], buf, 2);
		assert_int_equal(ret, 2);

		ldb = ldb_init(test_ctx, test_ctx->ev);
		assert_non_null(ldb);

		ret = ldb_connect(ldb, test_ctx->dbpath, 0, NULL);
		assert_int_equal(ret, LDB_SUCCESS);

		ldb_kv = get_ldb_kv(ldb);
		assert_non_null(ldb_kv);
		/*
		 * Add a record to the database
		 */
		key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY1);
		key.length = strlen(KEY1) + 1;
		val.data = talloc_zero_size(tmp_ctx, RECORD_SIZE);
		assert_non_null(val.data);
		memset(val.data, 'x', RECORD_SIZE);
		val.length = RECORD_SIZE;
		for (i = 0; i < ITERATIONS; i++) {
			ret = ldb_kv->kv_ops->begin_write(ldb_kv);
			assert_int_equal(ret, 0);
			ret = ldb_kv->kv_ops->store(ldb_kv, key, val, 0);
			if (ret == LDB_ERR_BUSY && i > 0) {
				int rc = ldb_kv->kv_ops->abort_write(ldb_kv);
				assert_int_equal(rc, LDB_SUCCESS);
				break;
			}
			assert_int_equal(ret, LDB_SUCCESS);
			ret = ldb_kv->kv_ops->finish_write(ldb_kv);
			assert_int_equal(ret, LDB_SUCCESS);
		}
		assert_int_equal(ret, LDB_ERR_BUSY);
		assert_int_not_equal(i, 0);

		/*
		 * Begin a read transaction
		 */
		ret = ldb_kv->kv_ops->lock_read(ldb->modules);
		assert_int_equal(ret, LDB_SUCCESS);
		/*
		 * read the record
		 * and close the transaction
		 */
		key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY1);
		key.length = strlen(KEY1) + 1;

		ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &val);
		assert_int_equal(ret, LDB_SUCCESS);

		ret = ldb_kv->kv_ops->unlock_read(ldb->modules);
		assert_int_equal(ret, LDB_SUCCESS);

		/*
		 * Signal the the parent that we've done the update
		 */
		ret = write(to_parent[1], "GO", 2);
		assert_int_equal(ret, 2);
		exit(0);
	}

	close(to_child[0]);
	close(to_parent[1]);

	/*
	 * Begin a read transaction
	 */
	ret = ldb_kv->kv_ops->lock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, LDB_SUCCESS);

	/*
	 * Signal the child process
	 */
	ret = write(to_child[1], "GO", 2);
	assert_int_equal(ret, 2);

	/*
	 * Wait for the child process to update the record
	 */
	ret = read(to_parent[0], buf, 2);
	assert_int_equal(ret, 2);

	/*
	 * read the record
	 * and close the transaction
	 */
	key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY1);
	key.length = strlen(KEY1) + 1;

	ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &val);
	assert_int_equal(ret, LDB_ERR_NO_SUCH_OBJECT);
	ret = ldb_kv->kv_ops->unlock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);

	close(to_child[1]);
	close(to_parent[0]);
	TALLOC_FREE(tmp_ctx);
}

/*
 * This tests forks a child process that opens a read lock and then
 * exits. This results in a stale reader entry in the lmdb lock file.
 */
static void test_free_list_stale_reader(void **state)
{
	int ret;
	struct test_ctx *test_ctx =
	    talloc_get_type_abort(*state, struct test_ctx);
	struct ldb_kv_private *ldb_kv = get_ldb_kv(test_ctx->ldb);
	struct ldb_val key;
	struct ldb_val val;

	const char *KEY1 = "KEY01";

	/*
	 * Pipes etc to co-ordinate the processes
	 */
	int to_child[2];
	int to_parent[2];
	char buf[2];
	pid_t pid;
	size_t i;

	TALLOC_CTX *tmp_ctx;
	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	ret = pipe(to_child);
	assert_int_equal(ret, 0);
	ret = pipe(to_parent);
	assert_int_equal(ret, 0);
	/*
	 * Now fork a new process
	 */

	pid = fork();
	if (pid == 0) {
		/*
		 * Child process
		 */

		struct ldb_context *ldb = NULL;
		close(to_child[1]);
		close(to_parent[0]);

		/*
		 * Wait for the parent to get ready
		 */
		ret = read(to_child[0], buf, 2);
		assert_int_equal(ret, 2);

		ldb = ldb_init(test_ctx, test_ctx->ev);
		assert_non_null(ldb);

		ret = ldb_connect(ldb, test_ctx->dbpath, 0, NULL);
		assert_int_equal(ret, LDB_SUCCESS);

		ldb_kv = get_ldb_kv(ldb);
		assert_non_null(ldb_kv);

		/*
		 * Begin a read transaction
		 */
		ret = ldb_kv->kv_ops->lock_read(ldb->modules);
		assert_int_equal(ret, LDB_SUCCESS);

		/*
		 * Now exit with out releasing the read lock
		 * this will result in a stale entry in the
		 * read lock table.
		 */

		exit(0);
	}

	close(to_child[0]);
	close(to_parent[1]);

	/*
	 * Tell the child to start
	 */
	ret = write(to_child[1], "GO", 2);
	assert_int_equal(ret, 2);

	close(to_child[1]);
	close(to_parent[0]);

	/*
	 * Now wait for the child process to complete
	 */
	waitpid(pid, NULL, 0);

	/*
	 * Add a record to the database
	 */
	key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY1);
	key.length = strlen(KEY1) + 1;
	val.data = talloc_zero_size(tmp_ctx, RECORD_SIZE);
	assert_non_null(val.data);
	memset(val.data, 'x', RECORD_SIZE);
	val.length = RECORD_SIZE;
	for (i = 0; i < ITERATIONS; i++) {
		ret = ldb_kv->kv_ops->begin_write(ldb_kv);
		assert_int_equal(ret, LDB_SUCCESS);

		ret = ldb_kv->kv_ops->store(ldb_kv, key, val, 0);
		if (ret == LDB_ERR_BUSY && i > 0) {
			int rc = ldb_kv->kv_ops->abort_write(ldb_kv);
			assert_int_equal(rc, LDB_SUCCESS);
			break;
		}
		assert_int_equal(ret, LDB_SUCCESS);

		ret = ldb_kv->kv_ops->finish_write(ldb_kv);
		assert_int_equal(ret, LDB_SUCCESS);
	}
	/*
	 * We now do an explicit clear of stale readers at the start of a
	 * write transaction so should not get LDB_ERR_BUSY any more
	 * assert_int_equal(ret, LDB_ERR_BUSY);
	 */
	assert_int_equal(ret, LDB_SUCCESS);
	assert_int_not_equal(i, 0);

	/*
	 * Begin a read transaction
	 */
	ret = ldb_kv->kv_ops->lock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, LDB_SUCCESS);
	/*
	 * read the record
	 * and close the transaction
	 */
	key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY1);
	key.length = strlen(KEY1) + 1;

	ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &val);
	assert_int_equal(ret, LDB_SUCCESS);

	ret = ldb_kv->kv_ops->unlock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, LDB_SUCCESS);

	TALLOC_FREE(tmp_ctx);
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
	    cmocka_unit_test_setup_teardown(
		test_free_list_no_read_lock, setup, teardown),
	    cmocka_unit_test_setup_teardown(
		test_free_list_read_lock, setup, teardown),
	    cmocka_unit_test_setup_teardown(
		test_free_list_stale_reader, setup, teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
