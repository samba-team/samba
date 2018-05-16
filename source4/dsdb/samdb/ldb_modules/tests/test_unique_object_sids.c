/*
   Unit tests for the unique objectSID code in unique_object_sids.c

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017

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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <unistd.h>
#include <cmocka.h>

int ldb_unique_object_sids_init(const char *version);
#include "../unique_object_sids.c"

#include "../libcli/security/dom_sid.h"
#include "librpc/gen_ndr/ndr_security.h"

#define TEST_BE "tdb"

#define DOMAIN_SID  "S-1-5-21-2470180966-3899876309-2637894779"
#define LOCAL_SID   "S-1-5-21-2470180966-3899876309-2637894779-1000"
#define FOREIGN_SID "S-1-5-21-2470180966-3899876309-2637894778-1000"

static struct ldb_request *last_request;

/*
 * ldb_next_request mock, records the request passed in last_request
 * so it can be examined in the test cases.
 */
int ldb_next_request(
	struct ldb_module *module,
	struct ldb_request *request)
{
	last_request = request;
	return ldb_module_done(request, NULL, NULL, LDB_SUCCESS);
}

/*
 * Test context
 */
struct ldbtest_ctx {
	struct tevent_context *ev;
	struct ldb_context *ldb;
	struct ldb_module *module;

	const char *dbfile;
	const char *lockfile;   /* lockfile is separate */

	const char *dbpath;
	struct dom_sid *domain_sid;
};

/*
 * Remove any database files created by the tests
 */
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

/*
 * Empty module to signal the end of the module list
 */
static const struct ldb_module_ops eol_ops = {
	.name              = "eol",
	.search            = NULL,
	.add		   = NULL,
	.modify		   = NULL,
	.del		   = NULL,
	.rename		   = NULL,
	.init_context	   = NULL
};

/*
 * Test set up
 */
static int setup(void **state)
{
	struct ldbtest_ctx *test_ctx	= NULL;
	struct ldb_module *eol		= NULL;
	int rc;

	test_ctx = talloc_zero(NULL, struct ldbtest_ctx);
	assert_non_null(test_ctx);

	test_ctx->ev = tevent_context_init(test_ctx);
	assert_non_null(test_ctx->ev);

	test_ctx->ldb = ldb_init(test_ctx, test_ctx->ev);
	assert_non_null(test_ctx->ldb);

	test_ctx->domain_sid = talloc_zero(test_ctx, struct dom_sid);
	assert_non_null(test_ctx->domain_sid);
	assert_true(string_to_sid(test_ctx->domain_sid, DOMAIN_SID));
	ldb_set_opaque(test_ctx->ldb, "cache.domain_sid", test_ctx->domain_sid);

        test_ctx->module = ldb_module_new(
		test_ctx,
		test_ctx->ldb,
		"unique_object_sids",
		&ldb_unique_object_sids_module_ops);
	assert_non_null(test_ctx->module);
	eol = ldb_module_new(test_ctx, test_ctx->ldb, "eol", &eol_ops);
	assert_non_null(eol);
	ldb_module_set_next(test_ctx->module, eol);

	test_ctx->dbfile = talloc_strdup(test_ctx, "duptest.ldb");
	assert_non_null(test_ctx->dbfile);

	test_ctx->lockfile = talloc_asprintf(test_ctx, "%s-lock",
					     test_ctx->dbfile);
	assert_non_null(test_ctx->lockfile);

	test_ctx->dbpath = talloc_asprintf(test_ctx,
			TEST_BE"://%s", test_ctx->dbfile);
	assert_non_null(test_ctx->dbpath);

	unlink_old_db(test_ctx);

	rc = ldb_connect(test_ctx->ldb, test_ctx->dbpath, 0, NULL);
	assert_int_equal(rc, LDB_SUCCESS);

	rc = unique_object_sids_init(test_ctx->module);
	assert_int_equal(rc, LDB_SUCCESS);

	*state = test_ctx;

	last_request = NULL;
	return 0;
}

/*
 * Test clean up
 */
static int teardown(void **state)
{
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);

	unlink_old_db(test_ctx);
	talloc_free(test_ctx);
	return 0;
}

/*
 * Add an objectSID in string form to the supplied message
 *
 *
 */
static void add_sid(
	struct ldb_message *msg,
	const char *sid_str)
{
	struct ldb_val v;
	enum ndr_err_code ndr_err;
	struct dom_sid *sid = NULL;

	sid = talloc_zero(msg, struct dom_sid);
	assert_non_null(sid);
	assert_true(string_to_sid(sid, sid_str));
	ndr_err = ndr_push_struct_blob(&v, msg, sid,
				       (ndr_push_flags_fn_t)ndr_push_dom_sid);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_int_equal(0, ldb_msg_add_value(msg, "objectSID", &v, NULL));
}

/*
 * The object is in the current local domain so it should have
 * DB_FLAG_INTERNAL_UNIQUE_VALUE set
 */
static void test_objectSID_in_domain(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	struct ldb_context *ldb 		= test_ctx->ldb;
	struct ldb_message *msg			= ldb_msg_new(test_ctx);
	struct ldb_message_element *el		= NULL;
	struct ldb_request *request		= NULL;
	struct ldb_request *original_request	= NULL;
	int rc;

	msg->dn = ldb_dn_new(msg, ldb, "dc=test");
	add_sid(msg, LOCAL_SID);

	rc = ldb_build_add_req(
		&request,
		test_ctx->ldb,
		test_ctx,
		msg,
		NULL,
		NULL,
		ldb_op_default_callback,
		NULL);

	assert_int_equal(rc, LDB_SUCCESS);
	assert_non_null(request);
	original_request = request;

	rc = unique_object_sids_add(test_ctx->module, request);
	assert_int_equal(rc, LDB_SUCCESS);

	/*
	 * Check that a copy of the request was passed to the next module
	 * and not the original request
	 */
	assert_ptr_not_equal(last_request, original_request);

	/*
	 * Check the flag was set on the request passed to the next
	 * module
	 */
	el = ldb_msg_find_element(last_request->op.add.message, "objectSID");
	assert_non_null(el);
	assert_true(el->flags & LDB_FLAG_INTERNAL_FORCE_UNIQUE_INDEX);

	/*
	 * Check the flag was not  set on the original request
	 */
	el = ldb_msg_find_element(request->op.add.message, "objectSID");
	assert_non_null(el);
	assert_false(el->flags & LDB_FLAG_INTERNAL_FORCE_UNIQUE_INDEX);

}

/*
 * The object is not in the current local domain so it should NOT have
 * DB_FLAG_INTERNAL_UNIQUE_VALUE set
 */
static void test_objectSID_not_in_domain(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	struct ldb_context *ldb			= test_ctx->ldb;
	struct ldb_message *msg			= ldb_msg_new(test_ctx);
	struct ldb_message_element *el		= NULL;
	struct ldb_request *request		= NULL;
	struct ldb_request *original_request	= NULL;
	int rc;

	msg->dn = ldb_dn_new(msg, ldb, "dc=test");
	add_sid(msg, FOREIGN_SID);

	rc = ldb_build_add_req(
		&request,
		test_ctx->ldb,
		test_ctx,
		msg,
		NULL,
		NULL,
		ldb_op_default_callback,
		NULL);

	assert_int_equal(rc, LDB_SUCCESS);
	assert_non_null(request);
	original_request = request;

	rc = unique_object_sids_add(test_ctx->module, request);
	assert_int_equal(rc, LDB_SUCCESS);

	/*
	 * Check that the original request was passed to the next module
	 * and not a copy
	 */
	assert_ptr_equal(last_request, original_request);

	/*
	 * Check that the flag was not set on the objectSID element
	 */
	el = ldb_msg_find_element(msg, "objectSID");
	assert_non_null(el);
	assert_false(el->flags & LDB_FLAG_INTERNAL_FORCE_UNIQUE_INDEX);
}

/*
 * No objectSID on the record so it should pass through the module untouched
 *
 */
static void test_no_objectSID(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	struct ldb_context *ldb			= test_ctx->ldb;
	struct ldb_message *msg			= ldb_msg_new(test_ctx);
	struct ldb_request *request		= NULL;
	struct ldb_request *original_request	= NULL;
	int rc;

	msg->dn = ldb_dn_new(msg, ldb, "dc=test");
	assert_int_equal(LDB_SUCCESS, ldb_msg_add_string(msg, "cn", "test"));

	rc = ldb_build_add_req(
		&request,
		test_ctx->ldb,
		test_ctx,
		msg,
		NULL,
		NULL,
		ldb_op_default_callback,
		NULL);

	assert_int_equal(rc, LDB_SUCCESS);
	assert_non_null(request);
	original_request = request;

	rc = unique_object_sids_add(test_ctx->module, request);
	assert_int_equal(rc, LDB_SUCCESS);

	/*
	 * Check that the original request was passed to the next module
	 * and not a copy
	 */
	assert_ptr_equal(last_request, original_request);

}

/*
 * Attempt to modify an objectSID DSDB_CONTROL_REPLICATED_UPDATE_OID not set
 * this should fail with LDB_ERR_UNWILLING_TO_PERFORM
 */
static void test_modify_of_objectSID_not_replicated(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	struct ldb_context *ldb 		= test_ctx->ldb;
	struct ldb_message *msg			= ldb_msg_new(test_ctx);
	struct ldb_request *request		= NULL;
	int rc;

	msg->dn = ldb_dn_new(msg, ldb, "dc=test");
	add_sid(msg, LOCAL_SID);

	rc = ldb_build_mod_req(
		&request,
		test_ctx->ldb,
		test_ctx,
		msg,
		NULL,
		NULL,
		ldb_op_default_callback,
		NULL);

	assert_int_equal(rc, LDB_SUCCESS);
	assert_non_null(request);

	rc = unique_object_sids_modify(test_ctx->module, request);

	assert_int_equal(rc, LDB_ERR_UNWILLING_TO_PERFORM);
}


/*
 * Attempt to modify an objectSID DSDB_CONTROL_REPLICATED_UPDATE_OID set
 * this should succeed
 */
static void test_modify_of_objectSID_replicated(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	struct ldb_context *ldb 		= test_ctx->ldb;
	struct ldb_message *msg			= ldb_msg_new(test_ctx);
	struct ldb_message_element *el		= NULL;
	struct ldb_request *request		= NULL;
	struct ldb_request *original_request	= NULL;
	int rc;

	msg->dn = ldb_dn_new(msg, ldb, "dc=test");
	add_sid(msg, LOCAL_SID);

	rc = ldb_build_mod_req(
		&request,
		test_ctx->ldb,
		test_ctx,
		msg,
		NULL,
		NULL,
		ldb_op_default_callback,
		NULL);
	assert_int_equal(rc, LDB_SUCCESS);
	assert_non_null(request);
	original_request = request;

	rc = ldb_request_add_control(
		request,
		DSDB_CONTROL_REPLICATED_UPDATE_OID,
		false,
		NULL);
	assert_int_equal(rc, LDB_SUCCESS);

	rc = unique_object_sids_modify(test_ctx->module, request);

	assert_int_equal(rc, LDB_SUCCESS);

	/*
	 * Check that a copy of the request was passed to the next module
	 * and not the original request
	 */
	assert_ptr_not_equal(last_request, original_request);

	/*
	 * Check the flag was set on the request passed to the next
	 * module
	 */
	el = ldb_msg_find_element(last_request->op.add.message, "objectSID");
	assert_non_null(el);
	assert_true(el->flags & LDB_FLAG_INTERNAL_FORCE_UNIQUE_INDEX);

	/*
	 * Check the flag was not  set on the original request
	 */
	el = ldb_msg_find_element(request->op.add.message, "objectSID");
	assert_non_null(el);
	assert_false(el->flags & LDB_FLAG_INTERNAL_FORCE_UNIQUE_INDEX);

}

/*
 * Test the a modify with no object SID is passed through correctly
 *
 */
static void test_modify_no_objectSID(void **state)
{
	struct ldbtest_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldbtest_ctx);
	struct ldb_context *ldb			= test_ctx->ldb;
	struct ldb_message *msg			= ldb_msg_new(test_ctx);
	struct ldb_request *request		= NULL;
	struct ldb_request *original_request	= NULL;
	int rc;

	msg->dn = ldb_dn_new(msg, ldb, "dc=test");
	assert_int_equal(LDB_SUCCESS, ldb_msg_add_string(msg, "cn", "test"));

	rc = ldb_build_mod_req(
		&request,
		test_ctx->ldb,
		test_ctx,
		msg,
		NULL,
		NULL,
		ldb_op_default_callback,
		NULL);

	assert_int_equal(rc, LDB_SUCCESS);
	assert_non_null(request);
	original_request = request;

	rc = unique_object_sids_modify(test_ctx->module, request);
	assert_int_equal(rc, LDB_SUCCESS);

	/*
	 * Check that the original request was passed to the next module
	 * and not a copy
	 */
	assert_ptr_equal(last_request, original_request);

}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
			test_objectSID_in_domain,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_objectSID_not_in_domain,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_no_objectSID,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_modify_no_objectSID,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_modify_of_objectSID_not_replicated,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_modify_of_objectSID_replicated,
			setup,
			teardown),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
