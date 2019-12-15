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
#include "../ldb_mdb/ldb_mdb.h"
#include "../ldb_key_value/ldb_kv.h"

#define TEST_BE  "mdb"

#define LMDB_MAX_KEY_SIZE 511

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

static void test_ldb_add_key_len_gt_max(void **state)
{
	int ret;
	int xs_size = 0;
	struct ldb_message *msg;
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	char *xs = NULL;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	msg = ldb_msg_new(tmp_ctx);
	assert_non_null(msg);

	/*
	 * The zero terminator is part of the key if we were not in
	 * GUID mode
	 */

	xs_size = LMDB_MAX_KEY_SIZE - 7;  /* "dn=dc=" and the zero terminator */
	xs_size += 1;                /* want key on char too long        */
	xs = talloc_zero_size(tmp_ctx, (xs_size + 1));
	memset(xs, 'x', xs_size);

	msg->dn = ldb_dn_new_fmt(msg, test_ctx->ldb, "dc=%s", xs);
	assert_non_null(msg->dn);

	ret = ldb_msg_add_string(msg, "cn", "test_cn_val");
	assert_int_equal(ret, 0);

	ret = ldb_msg_add_string(msg, "objectUUID", "0123456789abcdef");
	assert_int_equal(ret, 0);

	ret = ldb_add(test_ctx->ldb, msg);
	assert_int_equal(ret, LDB_SUCCESS);

	talloc_free(tmp_ctx);
}

static void test_ldb_add_key_len_2x_gt_max(void **state)
{
	int ret;
	int xs_size = 0;
	struct ldb_message *msg;
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	char *xs = NULL;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	msg = ldb_msg_new(tmp_ctx);
	assert_non_null(msg);

	/*
	 * The zero terminator is part of the key if we were not in
	 * GUID mode
	 */

	xs_size = 2 * LMDB_MAX_KEY_SIZE;
	xs = talloc_zero_size(tmp_ctx, (xs_size + 1));
	memset(xs, 'x', xs_size);

	msg->dn = ldb_dn_new_fmt(msg, test_ctx->ldb, "dc=%s", xs);
	assert_non_null(msg->dn);

	ret = ldb_msg_add_string(msg, "cn", "test_cn_val");
	assert_int_equal(ret, 0);

	ret = ldb_msg_add_string(msg, "objectUUID", "0123456789abcdef");
	assert_int_equal(ret, 0);

	ret = ldb_add(test_ctx->ldb, msg);
	assert_int_equal(ret, LDB_SUCCESS);

	talloc_free(tmp_ctx);
}

static void test_ldb_add_key_len_eq_max(void **state)
{
	int ret;
	int xs_size = 0;
	struct ldb_message *msg;
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	char *xs = NULL;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	msg = ldb_msg_new(tmp_ctx);
	assert_non_null(msg);

	/*
	 * The zero terminator is part of the key if we were not in
	 * GUID mode
	 */

	xs_size = LMDB_MAX_KEY_SIZE - 7;  /* "dn=dc=" and the zero terminator */
	xs = talloc_zero_size(tmp_ctx, (xs_size + 1));
	memset(xs, 'x', xs_size);

	msg->dn = ldb_dn_new_fmt(msg, test_ctx->ldb, "dc=%s", xs);
	assert_non_null(msg->dn);

	ret = ldb_msg_add_string(msg, "cn", "test_cn_val");
	assert_int_equal(ret, 0);

	ret = ldb_msg_add_string(msg, "objectUUID", "0123456789abcdef");
	assert_int_equal(ret, 0);

	ret = ldb_add(test_ctx->ldb, msg);
	assert_int_equal(ret, 0);

	talloc_free(tmp_ctx);
}

static int ldbtest_setup_noguid(void **state)
{
	struct ldbtest_ctx *test_ctx;
	int ret;

	ldbtest_noconn_setup((void **) &test_ctx);

	ret = ldb_connect(test_ctx->ldb, test_ctx->dbpath, 0, NULL);
	assert_int_equal(ret, 0);

	*state = test_ctx;
	return 0;
}

static void test_ldb_add_special_key_len_gt_max(void **state)
{
	int ret;
	int xs_size = 0;
	struct ldb_message *msg;
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	char *xs = NULL;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	msg = ldb_msg_new(tmp_ctx);
	assert_non_null(msg);

	/*
	 * The zero terminator is part of the key if we were not in
	 * GUID mode
	 */

	xs_size = LMDB_MAX_KEY_SIZE - 5;  /* "dn=@" and the zero terminator */
	xs_size += 1;                /* want key on char too long        */
	xs = talloc_zero_size(tmp_ctx, (xs_size + 1));
	memset(xs, 'x', xs_size);

	msg->dn = ldb_dn_new_fmt(msg, test_ctx->ldb, "@%s", xs);
	assert_non_null(msg->dn);

	ret = ldb_msg_add_string(msg, "cn", "test_cn_val");
	assert_int_equal(ret, 0);

	ret = ldb_add(test_ctx->ldb, msg);
	assert_int_equal(ret, LDB_ERR_PROTOCOL_ERROR);

	talloc_free(tmp_ctx);
}

static void test_ldb_add_special_key_len_eq_max(void **state)
{
	int ret;
	int xs_size = 0;
	struct ldb_message *msg;
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	char *xs = NULL;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	msg = ldb_msg_new(tmp_ctx);
	assert_non_null(msg);

	/*
	 * The zero terminator is part of the key if we were not in
	 * GUID mode
	 */

	xs_size = LMDB_MAX_KEY_SIZE - 5;  /* "dn=@" and the zero terminator */
	xs = talloc_zero_size(tmp_ctx, (xs_size + 1));
	memset(xs, 'x', xs_size);

	msg->dn = ldb_dn_new_fmt(msg, test_ctx->ldb, "@%s", xs);
	assert_non_null(msg->dn);

	ret = ldb_msg_add_string(msg, "cn", "test_cn_val");
	assert_int_equal(ret, 0);

	ret = ldb_add(test_ctx->ldb, msg);
	assert_int_equal(ret, LDB_SUCCESS);

	talloc_free(tmp_ctx);
}

static void test_ldb_add_dn_no_guid_mode(void **state)
{
	int ret;
	int xs_size = 0;
	struct ldb_message *msg;
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	char *xs = NULL;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	msg = ldb_msg_new(tmp_ctx);
	assert_non_null(msg);

	/*
	 * The zero terminator is part of the key if we were not in
	 * GUID mode
	 */

	xs_size = LMDB_MAX_KEY_SIZE - 7;  /* "dn=dc=" and the zero terminator */
	xs_size += 1;                /* want key on char too long        */
	xs = talloc_zero_size(tmp_ctx, (xs_size + 1));
	memset(xs, 'x', xs_size);

	msg->dn = ldb_dn_new_fmt(msg, test_ctx->ldb, "dc=%s", xs);
	assert_non_null(msg->dn);

	ret = ldb_msg_add_string(msg, "cn", "test_cn_val");
	assert_int_equal(ret, 0);

	ret = ldb_msg_add_string(msg, "objectUUID", "0123456789abcdef");
	assert_int_equal(ret, 0);

	ret = ldb_add(test_ctx->ldb, msg);
	assert_int_equal(ret, LDB_ERR_UNWILLING_TO_PERFORM);

	talloc_free(tmp_ctx);
}

static struct MDB_env *get_mdb_env(struct ldb_context *ldb)
{
	void *data = NULL;
	struct ldb_kv_private *ldb_kv = NULL;
	struct lmdb_private *lmdb = NULL;
	struct MDB_env *env = NULL;

	data = ldb_module_get_private(ldb->modules);
	assert_non_null(data);

	ldb_kv = talloc_get_type(data, struct ldb_kv_private);
	assert_non_null(ldb_kv);

	lmdb = ldb_kv->lmdb_private;
	assert_non_null(lmdb);

	env = lmdb->env;
	assert_non_null(env);

	return env;
}

static void test_multiple_opens(void **state)
{
	struct ldb_context *ldb1 = NULL;
	struct ldb_context *ldb2 = NULL;
	struct ldb_context *ldb3 = NULL;
	struct MDB_env *env1 = NULL;
	struct MDB_env *env2 = NULL;
	struct MDB_env *env3 = NULL;
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
	env1 = get_mdb_env(ldb1);
	env2 = get_mdb_env(ldb2);
	env3 = get_mdb_env(ldb3);

	assert_ptr_equal(env1, env2);
	assert_ptr_equal(env1, env3);
}

static void test_multiple_opens_across_fork(void **state)
{
	struct ldb_context *ldb1 = NULL;
	struct ldb_context *ldb2 = NULL;
	struct MDB_env *env1 = NULL;
	struct MDB_env *env2 = NULL;
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

	env1 = get_mdb_env(ldb1);
	env2 = get_mdb_env(ldb2);

	ret = pipe(pipes);
	assert_int_equal(ret, 0);

	child_pid = fork();
	if (child_pid == 0) {
		struct ldb_context *ldb3 = NULL;
		struct MDB_env *env3 = NULL;

		close(pipes[0]);
		ldb3 = ldb_init(test_ctx, test_ctx->ev);
		ret = ldb_connect(ldb3, test_ctx->dbpath, 0, NULL);
		if (ret != 0) {
			print_error(__location__": ldb_connect returned (%d)\n",
				    ret);
			exit(ret);
		}
		env3 = get_mdb_env(ldb3);
		if (env1 != env2) {
			print_error(__location__": env1 != env2\n");
			exit(LDB_ERR_OPERATIONS_ERROR);
		}
		if (env1 == env3) {
			print_error(__location__": env1 == env3\n");
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

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
			test_ldb_add_key_len_eq_max,
			ldbtest_setup,
			ldbtest_teardown),
		cmocka_unit_test_setup_teardown(
			test_ldb_add_key_len_gt_max,
			ldbtest_setup,
			ldbtest_teardown),
		cmocka_unit_test_setup_teardown(
			test_ldb_add_key_len_2x_gt_max,
			ldbtest_setup,
			ldbtest_teardown),
		cmocka_unit_test_setup_teardown(
			test_ldb_add_special_key_len_eq_max,
			ldbtest_setup_noguid,
			ldbtest_teardown),
		cmocka_unit_test_setup_teardown(
			test_ldb_add_special_key_len_gt_max,
			ldbtest_setup_noguid,
			ldbtest_teardown),
		cmocka_unit_test_setup_teardown(
			test_ldb_add_dn_no_guid_mode,
			ldbtest_setup_noguid,
			ldbtest_teardown),
		cmocka_unit_test_setup_teardown(
			test_multiple_opens,
			ldbtest_setup,
			ldbtest_teardown),
		cmocka_unit_test_setup_teardown(
			test_multiple_opens_across_fork,
			ldbtest_setup,
			ldbtest_teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
