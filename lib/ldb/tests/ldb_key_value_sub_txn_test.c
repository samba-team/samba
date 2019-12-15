/*
 * Tests exercising the ldb key value operations.
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
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <limits.h>
#define NO_FAILURE INT_MAX
#define FAILURE_LDB_ERR LDB_ERR_OTHER

/*
 * To test failure in ldb_kv_add, ldb_kv_delete, ldb_kv_modify and ldb_kv_rename
 * we use the following global variables and macros to trigger a failure in
 * the ldb_kv_<op>_internal functions. This allows testing of the sub
 * transaction commits and roll backs in those operations.
 *
 * NOTE: Not all back ends support nested/sub transactions
 */
int cmocka_unit_test_fail_add_internal_after = NO_FAILURE;
#define CMOCKA_UNIT_TEST_ADD_INTERNAL_FAIL \
	{\
		cmocka_unit_test_fail_add_internal_after--;\
		if (cmocka_unit_test_fail_add_internal_after <= 0) {\
			assert_int_equal(LDB_SUCCESS, ret);\
			ret = FAILURE_LDB_ERR;\
		}\
	}\

int cmocka_unit_test_fail_delete_internal_after = NO_FAILURE;
#define CMOCKA_UNIT_TEST_DELETE_INTERNAL_FAIL \
	{\
		cmocka_unit_test_fail_delete_internal_after--;\
		if (cmocka_unit_test_fail_delete_internal_after <= 0) {\
			assert_int_equal(LDB_SUCCESS, ret);\
			ret = FAILURE_LDB_ERR;\
		}\
	}\

int cmocka_unit_test_fail_rename_internal_after = NO_FAILURE;
#define CMOCKA_UNIT_TEST_RENAME_INTERNAL_FAIL \
	{\
		cmocka_unit_test_fail_rename_internal_after--;\
		if (cmocka_unit_test_fail_rename_internal_after <= 0) {\
			assert_int_equal(LDB_SUCCESS, ret);\
			ret = FAILURE_LDB_ERR;\
		}\
	}\

int cmocka_unit_test_fail_modify_internal_after = NO_FAILURE;
#define CMOCKA_UNIT_TEST_MODIFY_INTERNAL_FAIL \
	{\
		cmocka_unit_test_fail_modify_internal_after--;\
		if (cmocka_unit_test_fail_modify_internal_after <= 0) {\
			assert_int_equal(LDB_SUCCESS, ret);\
			ret = FAILURE_LDB_ERR;\
		}\
	}\

#include "ldb_key_value/ldb_kv.c"


#define DEFAULT_BE  "tdb"

#ifndef TEST_BE
#define TEST_BE DEFAULT_BE
#endif /* TEST_BE */

#define NUM_RECS 1024


struct test_ctx {
	struct tevent_context *ev;
	struct ldb_context *ldb;

	const char *dbfile;
	const char *lockfile;   /* lockfile is separate */

	const char *dbpath;
};

/*
 * Remove the database files
 */
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

/*
 * Test setup
 */
static int noconn_setup(void **state)
{
	struct test_ctx *test_ctx;
	cmocka_unit_test_fail_add_internal_after = NO_FAILURE;
	cmocka_unit_test_fail_delete_internal_after = NO_FAILURE;
	cmocka_unit_test_fail_rename_internal_after = NO_FAILURE;
	cmocka_unit_test_fail_modify_internal_after = NO_FAILURE;

	test_ctx = talloc_zero(NULL, struct test_ctx);
	assert_non_null(test_ctx);

	test_ctx->ev = tevent_context_init(test_ctx);
	assert_non_null(test_ctx->ev);

	test_ctx->ldb = ldb_init(test_ctx, test_ctx->ev);
	assert_non_null(test_ctx->ldb);

	test_ctx->dbfile = talloc_strdup(test_ctx, "kvopstest.ldb");
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

/*
 * Test teardown
 */
static int noconn_teardown(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);

	unlink_old_db(test_ctx);
	talloc_free(test_ctx);
	return 0;
}

/*
 * Test setup
 */
static int setup(void **state)
{
	struct test_ctx *test_ctx;
	int ret;
	struct ldb_ldif *ldif;
	const char *index_ldif =		\
		"dn: @INDEXLIST\n"
		"@IDXGUID: objectUUID\n"
		"@IDX_DN_GUID: GUID\n"
		"\n";

	noconn_setup((void **) &test_ctx);

	ret = ldb_connect(test_ctx->ldb, test_ctx->dbpath, 0, NULL);
	assert_int_equal(ret, 0);

	while ((ldif = ldb_ldif_read_string(test_ctx->ldb, &index_ldif))) {
		ret = ldb_add(test_ctx->ldb, ldif->msg);
		assert_int_equal(ret, LDB_SUCCESS);
	}
	*state = test_ctx;
	return 0;
}

/*
 * Test teardown
 */
static int teardown(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	noconn_teardown((void **) &test_ctx);
	return 0;
}

/*
 * Build an ldb_kv_context that can be passed to the ldb_kv operation under test
 */
static struct ldb_kv_context* build_ldb_kv_context(
	TALLOC_CTX *ctx,
	struct ldb_module *module,
	struct ldb_request *req)
{
	struct ldb_kv_context *ldb_kv_ctx = NULL;

	ldb_kv_ctx = talloc_zero(ctx, struct ldb_kv_context);
	assert_non_null(ldb_kv_ctx);

	ldb_kv_ctx->module = module;
	ldb_kv_ctx->req = req;

	return ldb_kv_ctx;
}

/*
 * Build an add request
 */
static struct ldb_request *build_add_request(
	TALLOC_CTX *ctx,
	struct ldb_context *ldb,
	const char* dc,
	const char* uuid,
	const char* cn)
{
	int ret;
	struct ldb_message *msg;
	struct ldb_request *req;

	msg = ldb_msg_new(ctx);
	assert_non_null(msg);

	msg->dn = ldb_dn_new_fmt(msg, ldb, "dc=%s", dc);
	assert_non_null(msg->dn);

	ret = ldb_msg_add_string(msg, "cn", cn);
	assert_int_equal(ret, 0);

	ret = ldb_msg_add_string(msg, "objectUUID", uuid);
	assert_int_equal(ret, 0);

	ret = ldb_msg_sanity_check(ldb, msg);
	assert_int_equal(ret, LDB_SUCCESS);

	ret = ldb_build_add_req(
	    &req, ldb, ldb, msg, NULL, NULL, ldb_op_default_callback, NULL);
	assert_int_equal(ret, LDB_SUCCESS);
	return req;
}

/*
 * Build a delete request
 */
static struct ldb_request *build_delete_request(
	TALLOC_CTX *ctx,
	struct ldb_context *ldb,
	const char* dc)
{
	int ret = LDB_SUCCESS;
	struct ldb_dn *dn = NULL;
	struct ldb_request *req = NULL;

	dn = ldb_dn_new_fmt(ctx, ldb, "dc=%s", dc);
	assert_non_null(dn);

	ret = ldb_build_del_req(
	    &req, ldb, ctx, dn, NULL, NULL, ldb_op_default_callback, NULL);
	assert_int_equal(ret, LDB_SUCCESS);
	return req;
}

/*
 * Build a rename request
 */
static struct ldb_request *build_rename_request(
	TALLOC_CTX *ctx,
	struct ldb_context *ldb,
	const char* old_dc,
	const char* new_dc)
{
	int ret = LDB_SUCCESS;
	struct ldb_dn *old_dn = NULL;
	struct ldb_dn *new_dn = NULL;
	struct ldb_request *req = NULL;

	old_dn = ldb_dn_new_fmt(ctx, ldb, "dc=%s", old_dc);
	assert_non_null(old_dn);

	new_dn = ldb_dn_new_fmt(ctx, ldb, "dc=%s", new_dc);
	assert_non_null(new_dn);

	ret = ldb_build_rename_req(
		&req,
		ldb,
		ctx,
		old_dn,
		new_dn,
		NULL,
		NULL,
		ldb_op_default_callback,
		NULL);
	assert_int_equal(ret, LDB_SUCCESS);
	return req;
}

/*
 * Build a ldb modify request
 */
static struct ldb_request *build_modify_request(
	TALLOC_CTX *ctx,
	struct ldb_context *ldb,
	const char* dc,
	const char* cn)
{
	int ret;
	struct ldb_message *msg;
	struct ldb_request *req;

	msg = ldb_msg_new(ctx);
	assert_non_null(msg);

	msg->dn = ldb_dn_new_fmt(msg, ldb, "dc=%s", dc);
	assert_non_null(msg->dn);

	ret = ldb_msg_add_empty(msg, "cn", LDB_FLAG_MOD_REPLACE, NULL);
	assert_int_equal(ret, LDB_SUCCESS);
	ret = ldb_msg_add_string(msg, "cn", cn);
	assert_int_equal(ret, LDB_SUCCESS);

	ret = ldb_msg_sanity_check(ldb, msg);
	assert_int_equal(ret, LDB_SUCCESS);

	ret = ldb_build_mod_req(
	    &req, ldb, ldb, msg, NULL, NULL, ldb_op_default_callback, NULL);
	assert_int_equal(ret, LDB_SUCCESS);
	return req;
}

/*
 * Delete a record from the database
 */
static void delete_record(
	TALLOC_CTX *ctx,
	struct ldb_context *ldb,
	const char* dc)
{
	struct ldb_kv_context *ldb_kv_ctx = NULL;
	struct ldb_dn *basedn = NULL;
	struct ldb_result *result = NULL;
	struct ldb_request *req = NULL;
	int ret = LDB_SUCCESS;

	req = build_delete_request(ctx, ldb, dc);
	ldb_kv_ctx = build_ldb_kv_context(ctx, ldb->modules, req);

	ret = ldb_transaction_start(ldb);
	assert_int_equal(ret, LDB_SUCCESS);

	cmocka_unit_test_fail_delete_internal_after = NO_FAILURE;
	cmocka_unit_test_fail_modify_internal_after = NO_FAILURE;
	ret = ldb_kv_delete(ldb_kv_ctx);
	assert_int_equal(ret, LDB_SUCCESS);
	TALLOC_FREE(ldb_kv_ctx);
	TALLOC_FREE(req);

	ret = ldb_transaction_commit(ldb);
	assert_int_equal(ret, LDB_SUCCESS);

	/*
	 * Ensure that the record was actually deleted.
	 */
	basedn = ldb_dn_new_fmt(ctx, ldb, "dc=%s", dc);
	assert_non_null(basedn);

	/*
	 * DN search, indexed
	 */
	ret = ldb_search(ldb, ctx, &result, basedn, LDB_SCOPE_BASE, NULL, NULL);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(result);
	assert_int_equal(result->count, 0);
	TALLOC_FREE(basedn);
	TALLOC_FREE(result);
}

/*
 * Add a record to the database
 */
static void add_record(
	TALLOC_CTX *ctx,
	struct ldb_context *ldb,
	const char* dc,
	const char* uuid,
	const char* cn)
{

	struct ldb_request *req = NULL;
	int ret = LDB_SUCCESS;
	struct ldb_kv_context *ldb_kv_ctx = NULL;
	struct ldb_dn *basedn = NULL;
	struct ldb_result *result = NULL;

	req = build_add_request(ctx, ldb, dc, uuid, cn);

	ldb_req_set_location(req, "add_record");

	assert_int_equal(ret, LDB_SUCCESS);


	ldb_kv_ctx = build_ldb_kv_context(ctx, ldb->modules, req);
	cmocka_unit_test_fail_add_internal_after = NO_FAILURE;
	cmocka_unit_test_fail_modify_internal_after = NO_FAILURE;

	ret = ldb_transaction_start(ldb);
	assert_int_equal(ret, LDB_SUCCESS);

	ret = ldb_kv_add(ldb_kv_ctx);
	assert_int_equal(ret, LDB_SUCCESS);
	TALLOC_FREE(ldb_kv_ctx);
	TALLOC_FREE(req);

	ret = ldb_transaction_commit(ldb);
	assert_int_equal(ret, LDB_SUCCESS);

	/*
	 * Ensure that the record was actually written.
	 */
	basedn = ldb_dn_new_fmt(ctx, ldb, "dc=%s", dc);
	assert_non_null(basedn);

	/*
	 * DN search, indexed
	 */
	ret = ldb_search(ldb, ctx, &result, basedn, LDB_SCOPE_BASE, NULL, NULL);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(result);
	assert_int_equal(result->count, 1);
	TALLOC_FREE(result);


	/*
	 * CN search unindexed
	 */
	ret = ldb_search(
		ldb,
		ctx,
		&result,
		basedn,
		LDB_SCOPE_SUBTREE,
		NULL,
		"(cn=%s)",
		cn);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(result);
	assert_int_equal(result->count, 1);
	TALLOC_FREE(result);
	TALLOC_FREE(basedn);
}

/*
 * Test that a failed add operation does not change the database.
 */
static void test_add_failure(void **state)
{
	int ret = LDB_SUCCESS;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_request *req = NULL;
	struct ldb_dn *basedn = NULL;
	struct ldb_result *result = NULL;
	struct ldb_kv_context *ldb_kv_ctx = NULL;

	TALLOC_CTX *tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	req = build_add_request(
		tmp_ctx,
		test_ctx->ldb,
		"test_add_failure",
		"0123456789abcdef",
		"test_add_failure_value");

	ldb_req_set_location(req, "test_add_failure");

	ldb_kv_ctx = build_ldb_kv_context(tmp_ctx, test_ctx->ldb->modules, req);
	cmocka_unit_test_fail_add_internal_after = 1;

	ret = ldb_transaction_start(test_ctx->ldb);
	assert_int_equal(ret, LDB_SUCCESS);

	ret = ldb_kv_add(ldb_kv_ctx);

	assert_int_equal(ret, FAILURE_LDB_ERR);
	TALLOC_FREE(ldb_kv_ctx);
	TALLOC_FREE(req);


	/*
	 * a search for "cn=test_add_failure_value" should fail
	 * as the transaction containing the operation should have been
	 * rolled back leaving the database consistent
	 *
	 * This should be an un-indexed search so the index caches won't be
	 * used.
	 */
	basedn = ldb_dn_new_fmt(
		tmp_ctx,
		test_ctx->ldb,
		"dc=%s",
		"test_add_failure");
	assert_non_null(basedn);

	ret = ldb_search(
		test_ctx->ldb, tmp_ctx,
		&result,
		basedn,
		LDB_SCOPE_SUBTREE,
		NULL,
		"(cn=%s)",
		"test_add_failure_value");
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(result);
	assert_int_equal(result->count, 0);
	TALLOC_FREE(basedn);
	TALLOC_FREE(result);

	ldb_transaction_cancel(test_ctx->ldb);
	TALLOC_FREE(tmp_ctx);
}


/*
 * Test that a failed delete operation does not modify the database.
 */
static void test_delete_failure(void **state)
{
	int ret = LDB_SUCCESS;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_request *req = NULL;
	struct ldb_dn *basedn = NULL;
	struct ldb_result *result = NULL;
	struct ldb_kv_context *ldb_kv_ctx = NULL;

	TALLOC_CTX *tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	add_record(
		tmp_ctx,
		test_ctx->ldb,
		"test_delete_failure",
		"0123456789abcded",
		"test_delete_failure_value");

	req = build_delete_request(
		tmp_ctx,
		test_ctx->ldb,
		"test_delete_failure");

	ldb_kv_ctx = build_ldb_kv_context(tmp_ctx, test_ctx->ldb->modules, req);
	cmocka_unit_test_fail_delete_internal_after = 1;

	ret = ldb_transaction_start(test_ctx->ldb);
	assert_int_equal(ret, LDB_SUCCESS);

	ret = ldb_kv_delete(ldb_kv_ctx);
	assert_int_equal(ret, FAILURE_LDB_ERR);
	TALLOC_FREE(ldb_kv_ctx);
	TALLOC_FREE(req);

	/*
	 * a search for "cn=test_add_failure_value" should succeed
	 * as the transaction containing the operation should have been
	 * rolled back leaving the database consistent
	 *
	 * This should be an un-indexed search so the index caches won't be
	 * used.
	 */
	basedn = ldb_dn_new_fmt(
		tmp_ctx,
		test_ctx->ldb,
		"dc=%s",
		"test_delete_failure");
	assert_non_null(basedn);

	ret = ldb_search(
		test_ctx->ldb, tmp_ctx,
		&result,
		basedn,
		LDB_SCOPE_SUBTREE,
		NULL,
		"(cn=%s)",
		"test_delete_failure_value");
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(result);
	assert_int_equal(result->count, 1);
	TALLOC_FREE(basedn);
	TALLOC_FREE(result);


	ldb_transaction_cancel(test_ctx->ldb);
	delete_record(
		tmp_ctx,
		test_ctx->ldb,
		"test_delete_failure");
	TALLOC_FREE(tmp_ctx);
}

/*
 * Test that a failed rename operation dies not change the database
 */
static void test_rename_failure(void **state)
{
	int ret = LDB_SUCCESS;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_request *req = NULL;
	struct ldb_dn *basedn = NULL;
	struct ldb_result *result = NULL;
	struct ldb_kv_context *ldb_kv_ctx = NULL;

	TALLOC_CTX *tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	add_record(
		tmp_ctx,
		test_ctx->ldb,
		"test_rename_failure",
		"0123456789abcdec",
		"test_rename_failure_value");

	req = build_rename_request(
		tmp_ctx,
		test_ctx->ldb,
		"test_rename_failure",
		"test_rename_failure_renamed");

	ldb_kv_ctx = build_ldb_kv_context(tmp_ctx, test_ctx->ldb->modules, req);
	cmocka_unit_test_fail_rename_internal_after = 1;

	ret = ldb_transaction_start(test_ctx->ldb);
	assert_int_equal(ret, LDB_SUCCESS);

	ret = ldb_kv_rename(ldb_kv_ctx);
	assert_int_equal(ret, FAILURE_LDB_ERR);
	TALLOC_FREE(ldb_kv_ctx);
	TALLOC_FREE(req);

	/*
	 * The original record should be present
	 */
	basedn = ldb_dn_new_fmt(
		tmp_ctx,
		test_ctx->ldb,
		"dc=%s",
		"test_rename_failure");
	assert_non_null(basedn);

	ret = ldb_search(
		test_ctx->ldb, tmp_ctx,
		&result,
		basedn,
		LDB_SCOPE_SUBTREE,
		NULL,
		"(cn=%s)",
		"test_rename_failure_value");
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(result);
	assert_int_equal(result->count, 1);
	TALLOC_FREE(basedn);
	TALLOC_FREE(result);

	/*
	 * And the renamed record should not be present
	 */
	basedn = ldb_dn_new_fmt(
		tmp_ctx,
		test_ctx->ldb,
		"dc=%s",
		"test_rename_failure_renamed");
	assert_non_null(basedn);

	ret = ldb_search(
		test_ctx->ldb, tmp_ctx,
		&result,
		basedn,
		LDB_SCOPE_SUBTREE,
		NULL,
		"(cn=%s)",
		"test_rename_failure_value");
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(result);
	assert_int_equal(result->count, 0);
	TALLOC_FREE(basedn);
	TALLOC_FREE(result);

	ldb_transaction_cancel(test_ctx->ldb);
	delete_record(
		tmp_ctx,
		test_ctx->ldb,
		"test_rename_failure");
	TALLOC_FREE(tmp_ctx);
}

/*
 * Test that a failed modification operation does not change the database
 */
static void test_modify_failure(void **state)
{
	int ret = LDB_SUCCESS;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_request *req = NULL;
	struct ldb_dn *basedn = NULL;
	struct ldb_result *result = NULL;
	struct ldb_kv_context *ldb_kv_ctx = NULL;

	TALLOC_CTX *tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	add_record(
		tmp_ctx,
		test_ctx->ldb,
		"test_modify_failure",
		"0123456789abcdeb",
		"test_modify_failure_value");

	req = build_modify_request(
		tmp_ctx,
		test_ctx->ldb,
		"test_modify_failure",
		"test_modify_failure_value_modified");

	ldb_kv_ctx = build_ldb_kv_context(tmp_ctx, test_ctx->ldb->modules, req);
	cmocka_unit_test_fail_modify_internal_after = 2;

	ret = ldb_transaction_start(test_ctx->ldb);
	assert_int_equal(ret, LDB_SUCCESS);

	ret = ldb_kv_modify(ldb_kv_ctx);
	assert_int_equal(ret, FAILURE_LDB_ERR);
	TALLOC_FREE(ldb_kv_ctx);
	TALLOC_FREE(req);


	/*
	 * The original value should be present
	 */
	basedn = ldb_dn_new_fmt(
		tmp_ctx,
		test_ctx->ldb,
		"dc=%s",
		"test_modify_failure");
	assert_non_null(basedn);

	ret = ldb_search(
		test_ctx->ldb, tmp_ctx,
		&result,
		basedn,
		LDB_SCOPE_SUBTREE,
		NULL,
		"(cn=%s)",
		"test_modify_failure_value");
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(result);
	assert_int_equal(result->count, 1);
	TALLOC_FREE(result);

	/*
	 * And the modified record should not be present
	 */
	ret = ldb_search(
		test_ctx->ldb, tmp_ctx,
		&result,
		basedn,
		LDB_SCOPE_SUBTREE,
		NULL,
		"(cn=%s)",
		"test_modify_failure_value_modified");
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(result);
	assert_int_equal(result->count, 0);
	TALLOC_FREE(basedn);
	TALLOC_FREE(result);

	ldb_transaction_cancel(test_ctx->ldb);
	delete_record(
		tmp_ctx,
		test_ctx->ldb,
		"test_modify_failure");
	TALLOC_FREE(tmp_ctx);
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
			test_add_failure,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_delete_failure,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_rename_failure,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_modify_failure,
			setup,
			teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
