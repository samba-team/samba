/*
 * Unit tests for source4/auth/sam.c
 *
 * Copyright (C) Catalyst.NET Ltd 2021
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

#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "includes.h"
#include "auth/sam.c"
#include "ldb.h"
#include "libcli/util/ntstatus.h"
#include "librpc/gen_ndr/ndr_security.h"

/*****************************************************************************
 * wrapped functions
 *
 *****************************************************************************/
int __wrap_samdb_msg_add_int64(
	struct ldb_context *sam_ldb,
	TALLOC_CTX *mem_ctx,
	struct ldb_message *msg,
	const char *attr_name,
	int64_t v);
int __real_samdb_msg_add_int64(
	struct ldb_context *sam_ldb,
	TALLOC_CTX *mem_ctx,
	struct ldb_message *msg,
	const char *attr_name,
	int64_t v);
int __wrap_samdb_msg_add_int64(
	struct ldb_context *sam_ldb,
	TALLOC_CTX *mem_ctx,
	struct ldb_message *msg,
	const char *attr_name,
	int64_t v)
{

	int ret;
	ret = (int)mock();
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return __real_samdb_msg_add_int64(sam_ldb, mem_ctx, msg, attr_name, v);
}
/*****************************************************************************
 * Mock implementations
 *****************************************************************************/

static int check_dn(const LargestIntegralType left_value,
		    const LargestIntegralType right_value)
{
	/*
	 * We have to cast away const so we can get the linearized form with
	 * ldb_dn_get_extended_linearized().
	 */
	struct ldb_dn *left_dn = (void *)left_value;
	struct ldb_dn *right_dn = (void *)right_value;
	char *left_dn_string = NULL;
	char *right_dn_string = NULL;
	bool ok;

	if (left_dn == NULL && right_dn == NULL) {
		return true;
	}

	if (left_dn != NULL) {
		left_dn_string = ldb_dn_get_extended_linearized(NULL, left_dn, 1);
		assert_non_null(left_dn_string);
	}

	if (right_dn != NULL) {
		right_dn_string = ldb_dn_get_extended_linearized(NULL, right_dn, 1);
		assert_non_null(right_dn_string);
	}

	if (left_dn_string == NULL || right_dn_string == NULL) {
		ok = false;
		print_error("\"%s\" != \"%s\"\n",
			    left_dn_string != NULL ? left_dn_string : "<NULL>",
			    right_dn_string != NULL ? right_dn_string : "<NULL>");
	} else {
		ok = (strcmp(left_dn_string, right_dn_string) == 0);
		if (!ok) {
			print_error("\"%s\" != \"%s\"\n",
				    left_dn_string,
				    right_dn_string);
		}

	}

	TALLOC_FREE(right_dn_string);
	TALLOC_FREE(left_dn_string);

	return ok;
}

int __wrap_dsdb_search_dn(struct ldb_context *ldb,
			  TALLOC_CTX *mem_ctx,
			  struct ldb_result **_result,
			  struct ldb_dn *basedn,
			  const char * const *attrs,
			  uint32_t dsdb_flags);
int __wrap_dsdb_search_dn(struct ldb_context *ldb,
			  TALLOC_CTX *mem_ctx,
			  struct ldb_result **_result,
			  struct ldb_dn *basedn,
			  const char * const *attrs,
			  uint32_t dsdb_flags)
{
	check_expected(basedn);

	*_result = talloc_steal(mem_ctx, mock_ptr_type(struct ldb_result *));

	return mock();
}

int ldb_transaction_start_ret = LDB_SUCCESS;
bool in_transaction = false;
int ldb_transaction_start(struct ldb_context *ldb) {
	assert_false(in_transaction);
	if (ldb_transaction_start_ret == LDB_SUCCESS) {
		in_transaction = true;
	}
	return ldb_transaction_start_ret;
}

int ldb_transaction_cancel_ret = LDB_SUCCESS;
bool transaction_cancelled = false;
int ldb_transaction_cancel(struct ldb_context *ldb) {
	assert_true(in_transaction);
	if (ldb_transaction_cancel_ret == LDB_SUCCESS) {
		in_transaction = false;
		transaction_cancelled = true;
	}
	return ldb_transaction_cancel_ret;
}

int ldb_transaction_commit_ret = LDB_SUCCESS;
bool transaction_committed = false;
int ldb_transaction_commit(struct ldb_context *ldb) {
	assert_true(in_transaction);
	if (ldb_transaction_commit_ret == LDB_SUCCESS) {
		in_transaction = false;
		transaction_committed = true;
	}
	return ldb_transaction_commit_ret;
}

NTSTATUS dsdb_update_bad_pwd_count_ret = NT_STATUS_OK;
struct ldb_message *dsdb_update_bad_pwd_count_res = NULL;
NTSTATUS dsdb_update_bad_pwd_count(TALLOC_CTX *mem_ctx,
				   struct ldb_context *sam_ctx,
				   struct ldb_message *user_msg,
				   struct ldb_message *domain_msg,
				   struct ldb_message *pso_msg,
				   struct ldb_message **_mod_msg) {

	*_mod_msg = talloc_move(mem_ctx, &dsdb_update_bad_pwd_count_res);
	return dsdb_update_bad_pwd_count_ret;
}

int ldb_build_mod_req_ret = LDB_SUCCESS;
struct ldb_request *ldb_build_mod_req_res = NULL;
int ldb_build_mod_req(struct ldb_request **ret_req,
			struct ldb_context *ldb,
			TALLOC_CTX *mem_ctx,
			const struct ldb_message *message,
			struct ldb_control **controls,
			void *context,
			ldb_request_callback_t callback,
			struct ldb_request *parent)
{
	*ret_req = talloc_move(mem_ctx, &ldb_build_mod_req_res);
	return ldb_build_mod_req_ret;
}

int ldb_request_add_control_ret = LDB_SUCCESS;
int ldb_request_add_control(struct ldb_request *req,
			    const char *oid,
			    bool critical,
			    void *data)
{
	return ldb_request_add_control_ret;
}

int ldb_request_ret = LDB_SUCCESS;
int ldb_request(struct ldb_context *ldb,
		struct ldb_request *req)
{
	return ldb_request_ret;
}

int ldb_wait_ret = LDB_SUCCESS;
int ldb_wait(struct ldb_handle *handle,
	     enum ldb_wait_type type)
{
	return ldb_wait_ret;
}
bool ldb_msg_new_fail = false;
struct ldb_message *ldb_msg_new(TALLOC_CTX *mem_ctx)
{
	if (ldb_msg_new_fail) {
		return NULL;
	} else {
		return talloc_zero(mem_ctx, struct ldb_message);
	}
}

int samdb_rodc_ret = LDB_SUCCESS;
bool samdb_rodc_res = false;

int samdb_rodc(
	struct ldb_context *sam_ctx,
	bool *am_rodc)
{

	*am_rodc = samdb_rodc_res;
	return samdb_rodc_ret;
}

struct loadparm_context *ldb_get_opaque_ret = NULL;
void *ldb_get_opaque(struct ldb_context *ldb, const char *name)
{
	return ldb_get_opaque_ret;
}

struct db_context {};
struct db_context *cluster_db_tmp_open_ret = NULL;
struct db_context *cluster_db_tmp_open(
	TALLOC_CTX *mem_ctx,
	struct loadparm_context *lp_ctx,
	const char *dbbase,
	int flags)
{
	return cluster_db_tmp_open_ret;
}

NTSTATUS dbwrap_store_ret = NT_STATUS_OK;
NTSTATUS dbwrap_store(struct db_context *db, TDB_DATA key,
		      TDB_DATA data, int flags)
{
	return dbwrap_store_ret;
}
bool dbwrap_exists_ret = true;

bool dbwrap_exists(struct db_context *db, TDB_DATA key)
{
	return dbwrap_exists_ret;
}

NTSTATUS dbwrap_delete_ret = NT_STATUS_OK;
NTSTATUS dbwrap_delete(struct db_context *db, TDB_DATA key)
{
	return dbwrap_delete_ret;
}

/*
 * Set the globals used by the mocked functions to a known and consistent state
 *
 */
static void init_mock_results(TALLOC_CTX *mem_ctx)
{
	ldb_transaction_start_ret = LDB_SUCCESS;
	in_transaction = false;

	ldb_transaction_cancel_ret = LDB_SUCCESS;
	transaction_cancelled = false;

	ldb_transaction_commit_ret = LDB_SUCCESS;
	transaction_committed = false;

	dsdb_update_bad_pwd_count_ret = NT_STATUS_OK;
	dsdb_update_bad_pwd_count_res = NULL;

	ldb_build_mod_req_ret = LDB_SUCCESS;
	ldb_build_mod_req_res = NULL;

	ldb_request_add_control_ret = LDB_SUCCESS;
	ldb_request_ret = LDB_SUCCESS;
	ldb_wait_ret = LDB_SUCCESS;

	ldb_msg_new_fail = false;

	samdb_rodc_ret = LDB_SUCCESS;
	samdb_rodc_res = false;

	ldb_get_opaque_ret = loadparm_init(mem_ctx);

	cluster_db_tmp_open_ret = talloc_zero(mem_ctx, struct db_context);

	dbwrap_store_ret = NT_STATUS_OK;

	dbwrap_exists_ret = true;

	dbwrap_delete_ret = NT_STATUS_OK;

}

/*****************************************************************************
 * Unit test set up and tear down
 *****************************************************************************/
struct context {
};

static int setup(void **state) {
	struct context *ctx = talloc_zero(NULL, struct context);
	init_mock_results(ctx);

	*state = ctx;
	return 0;
}

static int teardown(void **state) {
	struct context *ctx = *state;
	TALLOC_FREE(ctx);
	return 0;
}

/******************************************************************************
 * Helper functions
 ******************************************************************************/

/*
 * Build the "Original" user details record, i.e. the user being
 * authenticated
 */
static struct ldb_message *create_message(TALLOC_CTX *ctx)
{

	int ret;
	struct timeval tv_now = timeval_current();
	NTTIME now = timeval_to_nttime(&tv_now);

	struct ldb_message *msg = ldb_msg_new(ctx);

	assert_non_null(msg);
	ret = samdb_msg_add_int(ctx, msg, msg, "badPwdCount", 10);
	assert_int_equal(LDB_SUCCESS, ret);
	ret = __real_samdb_msg_add_int64(ctx, msg, msg, "badPasswordTime", now);
	assert_int_equal(LDB_SUCCESS, ret);
	ret = __real_samdb_msg_add_int64(ctx, msg, msg, "lockoutTime", now);
	assert_int_equal(LDB_SUCCESS, ret);
	return msg;
}

/*
 * Add a binary objectSID from string form to the supplied message
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
	ndr_err = ndr_push_struct_blob(
		&v, msg, sid, (ndr_push_flags_fn_t)ndr_push_dom_sid);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_int_equal(0, ldb_msg_add_value(msg, "objectSID", &v, NULL));
}

/*
 * Build an ldb_result, for the re-reading of a user record
 *
 * if account_control < 0 then the msDS-User-Account-Control-Computed
 * element is not included
 * otherwise it is set to the value passed in account_control.
 *
 */
static struct ldb_result *build_reread_result(
	struct ldb_context *ldb,
	TALLOC_CTX *ctx,
	int account_control)
{
	struct ldb_message *msg = NULL;
	int ret;

	struct ldb_result *res = talloc_zero(ctx, struct ldb_result);

	assert_non_null(res);
	res->count = 1;
	res->msgs = talloc_array(res, struct ldb_message *, 1);

	msg = create_message(res);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");
	if (account_control >= 0) {
		ret = samdb_msg_add_int(
			ldb,
			msg,
			msg,
			"msDS-User-Account-Control-Computed",
			account_control);
		assert_int_equal(LDB_SUCCESS, ret);
	}

	res->msgs[0] = msg;
	return res;
}

/*
 * Build a mock domain pso ldb_result
 */
static struct ldb_result *build_domain_pso_result(
	struct ldb_context *ldb,
	TALLOC_CTX *ctx)
{
	struct ldb_message *msg = NULL;
	struct ldb_result *res = talloc_zero(ctx, struct ldb_result);

	assert_non_null(res);
	res->count = 1;
	res->msgs = talloc_array(res, struct ldb_message *, 1);
	assert_non_null(res->msgs);
	msg = talloc_zero(res, struct ldb_message);
	assert_non_null(msg);
	res->msgs[0] = msg;
	return res;
}

/*****************************************************************************
 * authsam_reread_user_logon_data unit tests
 *****************************************************************************/
/*
 * authsam_reread_user_logon_data unable to re-read the user record.
 *
 */
static void test_reread_read_failure(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_message *cur = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	will_return(__wrap_dsdb_search_dn, NULL);
	will_return(__wrap_dsdb_search_dn, LDB_ERR_NO_SUCH_OBJECT);

	status = authsam_reread_user_logon_data(ldb, ctx, msg, &cur);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_reread_user_logon_data account control flags missing from
 * re-read data
 *
 */
static void test_reread_missing_account_control(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_message *cur = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	will_return(__wrap_dsdb_search_dn, build_reread_result(ldb, ctx, -1));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	status = authsam_reread_user_logon_data(ldb, ctx, msg, &cur);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_reread_user_logon_data account locked
 * re-read data
 *
 */
static void test_reread_account_locked(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_message *cur = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	will_return(__wrap_dsdb_search_dn, build_reread_result(ldb, ctx, UF_LOCKOUT));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	status = authsam_reread_user_logon_data(ldb, ctx, msg, &cur);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_ACCOUNT_LOCKED_OUT));

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_reread_user_logon_data account is not locked
 * re-read data
 *
 */
static void test_reread_account_not_locked(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_message *cur = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	size_t result_size = 0;
	NTSTATUS status;
	struct ldb_result *res = NULL;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	/*
	 * authsam_reread_user_logon_data returns the ldb_message portion
	 * of the ldb_result created by build_reread_result.
	 * So the tests for memory leaks will need to adjust for that
	 */
	res = build_reread_result(ldb, ctx, 0);
	will_return(__wrap_dsdb_search_dn, res);
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	result_size = talloc_total_size(res) -
		      talloc_total_size(res->msgs[0]);
	before = talloc_total_size(ctx) - result_size;

	status = authsam_reread_user_logon_data(ldb, ctx, msg, &cur);
	assert_true(NT_STATUS_IS_OK(status));

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}


/*****************************************************************************
 * authsam_update_bad_pwd_count unit tests
 *****************************************************************************/

/*
 * authsam_update_bad_pwd_account
 *
 * Unable to read the domain_dn record
 *
 */
static void test_update_bad_domain_dn_search_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = talloc_zero(ctx, struct ldb_message);
	assert_non_null(msg);

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, NULL);
	will_return(__wrap_dsdb_search_dn, LDB_ERR_NO_SUCH_OBJECT);

	before = talloc_total_size(ctx);

	status = authsam_update_bad_pwd_count(ldb, msg, domain_dn);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_DB_CORRUPTION));

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_update_bad_pwd_account
 *
 * authsam_get_user_pso failure
 *
 */
static void test_update_bad_get_pso_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	struct ldb_dn *pso_dn = NULL;
	const char *pso_dn_str = "CN=PSO";
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;
	int ret;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	pso_dn = ldb_dn_new(ctx, ldb, pso_dn_str);
	assert_non_null(pso_dn);

	msg = talloc_zero(ctx, struct ldb_message);
	assert_non_null(msg);
	ret = ldb_msg_add_string(msg, "msDS-ResultantPSO", pso_dn_str);
	assert_int_equal(LDB_SUCCESS, ret);

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, build_domain_pso_result(ldb, ctx));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, pso_dn);
	will_return(__wrap_dsdb_search_dn, NULL);
	will_return(__wrap_dsdb_search_dn, LDB_ERR_NO_SUCH_OBJECT);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	will_return(__wrap_dsdb_search_dn, build_reread_result(ldb, ctx, 0));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	status = authsam_update_bad_pwd_count(ldb, msg, domain_dn);
	assert_true(NT_STATUS_IS_OK(status));

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}


/*
 * authsam_update_bad_pwd_account
 *
 * start_transaction failure
 *
 */
static void test_update_bad_start_txn_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = talloc_zero(ctx, struct ldb_message);
	assert_non_null(msg);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, build_domain_pso_result(ldb, ctx));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	ldb_transaction_start_ret = LDB_ERR_OPERATIONS_ERROR;

	status = authsam_update_bad_pwd_count(ldb, msg, domain_dn);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_update_bad_pwd_account
 *
 * User details re-read failed
 *
 */
static void test_update_bad_reread_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = talloc_zero(ctx, struct ldb_message);
	assert_non_null(msg);

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, build_domain_pso_result(ldb, ctx));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	will_return(__wrap_dsdb_search_dn, NULL);
	will_return(__wrap_dsdb_search_dn, LDB_ERR_NO_SUCH_OBJECT);

	status = authsam_update_bad_pwd_count(ldb, msg, domain_dn);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));
	assert_true(transaction_cancelled);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_update_bad_pwd_account
 *
 * User details re-read reported locked out.
 *
 */
static void test_update_bad_reread_locked_out(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, build_domain_pso_result(ldb, ctx));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	will_return(__wrap_dsdb_search_dn, build_reread_result(ldb, ctx, UF_LOCKOUT));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	status = authsam_update_bad_pwd_count(ldb, msg, domain_dn);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_ACCOUNT_LOCKED_OUT));
	assert_false(transaction_cancelled);
	assert_true(transaction_committed);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_update_bad_pwd_account
 *
 * Transaction cancel failure
 */
static void test_update_bad_txn_cancel_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = talloc_zero(ctx, struct ldb_message);
	assert_non_null(msg);

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, build_domain_pso_result(ldb, ctx));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	will_return(__wrap_dsdb_search_dn, NULL);
	will_return(__wrap_dsdb_search_dn, LDB_ERR_NO_SUCH_OBJECT);

	ldb_transaction_cancel_ret = LDB_ERR_OPERATIONS_ERROR;

	status = authsam_update_bad_pwd_count(ldb, msg, domain_dn);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));
	assert_true(in_transaction);
	assert_false(transaction_cancelled);
	assert_false(transaction_committed);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * The following tests all expect the same setup, that is a normal
 * good user object and empty domain object.
 *
 * returns the talloc size after result array setup for leak tests
 */
static size_t setup_bad_password_search_results(TALLOC_CTX *ctx,
						struct ldb_context *ldb,
						struct ldb_dn *domain_dn,
						struct ldb_dn *user_dn)
{
	size_t before = 0;

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, build_domain_pso_result(ldb, ctx));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, user_dn);
	will_return(__wrap_dsdb_search_dn, build_reread_result(ldb, ctx, 0));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	return before;
}


/*
 * authsam_update_bad_pwd_account
 *
 * dsdb_update_bad_pwd_count failure
 *
 */
static void test_update_bad_update_count_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = setup_bad_password_search_results(ctx, ldb,
						   domain_dn,
						   msg->dn);

	dsdb_update_bad_pwd_count_ret = NT_STATUS_INTERNAL_ERROR;

	status = authsam_update_bad_pwd_count(ldb, msg, domain_dn);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));
	assert_true(transaction_cancelled);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_update_bad_pwd_account
 *
 * No need to update the bad password stats
 *
 */
static void test_update_bad_no_update_required(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = setup_bad_password_search_results(ctx, ldb,
						   domain_dn,
						   msg->dn);

	status = authsam_update_bad_pwd_count(ldb, msg, domain_dn);
	assert_true(NT_STATUS_IS_OK(status));
	assert_true(transaction_committed);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_update_bad_pwd_account
 *
 * Transaction commit failure
 *
 */
static void test_update_bad_commit_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = setup_bad_password_search_results(ctx, ldb,
						   domain_dn,
						   msg->dn);

	ldb_transaction_commit_ret = LDB_ERR_OPERATIONS_ERROR;

	status = authsam_update_bad_pwd_count(ldb, msg, domain_dn);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));
	assert_true(in_transaction);
	assert_false(transaction_cancelled);
	assert_false(transaction_committed);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_update_bad_pwd_account
 *
 * ldb_build_mod_req failed building the user update details
 *
 */
static void test_update_bad_build_mod_request_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = setup_bad_password_search_results(ctx, ldb,
						   domain_dn,
						   msg->dn);

	dsdb_update_bad_pwd_count_res = talloc_zero(ctx, struct ldb_message);
	ldb_build_mod_req_ret = LDB_ERR_OPERATIONS_ERROR;

	status = authsam_update_bad_pwd_count(ldb, msg, domain_dn);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));
	assert_true(transaction_cancelled);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_update_bad_pwd_account
 *
 * ldb_request_add_control failed to add DSDB_CONTROL_FORCE_RODC_LOCAL_CHANGE
 * to the user update record.
 *
 */
static void test_update_bad_add_control_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = setup_bad_password_search_results(ctx, ldb,
						   domain_dn,
						   msg->dn);

	dsdb_update_bad_pwd_count_res = talloc_zero(ctx, struct ldb_message);
	ldb_build_mod_req_res = talloc_zero(ctx, struct ldb_request);
	ldb_request_add_control_ret = LDB_ERR_OPERATIONS_ERROR;

	status = authsam_update_bad_pwd_count(ldb, msg, domain_dn);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));
	assert_true(transaction_cancelled);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_update_bad_pwd_account
 *
 * call to ldb_request failed
 *
 */
static void test_update_bad_ldb_request_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = setup_bad_password_search_results(ctx, ldb,
						   domain_dn,
						   msg->dn);

	dsdb_update_bad_pwd_count_res = talloc_zero(ctx, struct ldb_message);
	ldb_build_mod_req_res = talloc_zero(ctx, struct ldb_request);
	ldb_request_ret = LDB_ERR_OPERATIONS_ERROR;

	status = authsam_update_bad_pwd_count(ldb, msg, domain_dn);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));
	assert_true(transaction_cancelled);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_update_bad_pwd_account
 *
 * call to ldb_wait failed
 *
 */
static void test_update_bad_ldb_wait_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = setup_bad_password_search_results(ctx, ldb,
						   domain_dn,
						   msg->dn);

	dsdb_update_bad_pwd_count_res = talloc_zero(ctx, struct ldb_message);
	ldb_build_mod_req_res = talloc_zero(ctx, struct ldb_request);
	ldb_wait_ret = LDB_ERR_OPERATIONS_ERROR;

	status = authsam_update_bad_pwd_count(ldb, msg, domain_dn);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));
	assert_true(transaction_cancelled);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*****************************************************************************
 * authsam_logon_success_accounting unit tests
 *****************************************************************************/
/*
 * authsam_logon_success_accounting
 *
 * start_transaction failure
 *
 */
static void test_success_accounting_start_txn_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, build_domain_pso_result(ldb, ctx));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	ldb_transaction_start_ret = LDB_ERR_OPERATIONS_ERROR;

	status = authsam_logon_success_accounting(
		ldb, msg, domain_dn, true, NULL, NULL);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_logon_success_accounting
 *
 * User details re-read failed
 *
 */
static void test_success_accounting_reread_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, build_domain_pso_result(ldb, ctx));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	will_return(__wrap_dsdb_search_dn, NULL);
	will_return(__wrap_dsdb_search_dn, LDB_ERR_NO_SUCH_OBJECT);

	status = authsam_logon_success_accounting(
		ldb, msg, domain_dn, true, NULL, NULL);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));
	assert_true(transaction_cancelled);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_logon_success_accounting
 *
 * ldb_msg_new failed
 *
 */
static void test_success_accounting_ldb_msg_new_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, build_domain_pso_result(ldb, ctx));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	will_return(__wrap_dsdb_search_dn, build_reread_result(ldb, ctx, 0));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	ldb_msg_new_fail = true;

	status = authsam_logon_success_accounting(
		ldb, msg, domain_dn, true, NULL, NULL);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_NO_MEMORY));
	assert_true(transaction_cancelled);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_logon_success_accounting
 *
 * samdb_rodc failed
 *
 */
static void test_success_accounting_samdb_rodc_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	samdb_rodc_ret = LDB_ERR_OPERATIONS_ERROR;

	status = authsam_logon_success_accounting(
		ldb, msg, domain_dn, true, NULL, NULL);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));
	assert_false(in_transaction);
	assert_false(transaction_cancelled);
	assert_false(transaction_committed);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_logon_success_accounting
 *
 * authsam_update_lastlogon_timestamp failed
 *
 */
static void test_success_accounting_update_lastlogon_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	ldb_build_mod_req_res = talloc_zero(ctx, struct ldb_request);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, build_domain_pso_result(ldb, ctx));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	will_return(__wrap_dsdb_search_dn, build_reread_result(ldb, ctx, 0));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	will_return(__wrap_samdb_msg_add_int64, LDB_ERR_OPERATIONS_ERROR);

	status = authsam_logon_success_accounting(
		ldb, msg, domain_dn, true, NULL, NULL);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_NO_MEMORY));
	assert_true(transaction_cancelled);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_logon_success_accounting
 *
 * ldb_build_mod_req failed
 *
 */
static void test_success_accounting_build_mod_req_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, build_domain_pso_result(ldb, ctx));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	will_return(__wrap_dsdb_search_dn, build_reread_result(ldb, ctx, 0));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	ldb_build_mod_req_ret = LDB_ERR_OPERATIONS_ERROR;

	will_return(__wrap_samdb_msg_add_int64, LDB_SUCCESS);
	will_return(__wrap_samdb_msg_add_int64, LDB_SUCCESS);

	status = authsam_logon_success_accounting(
		ldb, msg, domain_dn, true, NULL, NULL);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));
	assert_true(transaction_cancelled);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_logon_success_accounting
 *
 * ldb_request_add_control failed
 *
 */
static void test_success_accounting_add_control_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, build_domain_pso_result(ldb, ctx));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	will_return(__wrap_dsdb_search_dn, build_reread_result(ldb, ctx, 0));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	ldb_build_mod_req_res = talloc_zero(ldb, struct ldb_request);
	ldb_request_add_control_ret = LDB_ERR_OPERATIONS_ERROR;

	will_return(__wrap_samdb_msg_add_int64, LDB_SUCCESS);
	will_return(__wrap_samdb_msg_add_int64, LDB_SUCCESS);

	status = authsam_logon_success_accounting(
		ldb, msg, domain_dn, true, NULL, NULL);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));
	assert_true(transaction_cancelled);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_logon_success_accounting
 *
 * ldb_request failed
 *
 */
static void test_success_accounting_ldb_request_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, build_domain_pso_result(ldb, ctx));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	will_return(__wrap_dsdb_search_dn, build_reread_result(ldb, ctx, 0));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	ldb_build_mod_req_res = talloc_zero(ldb, struct ldb_request);
	ldb_request_ret = LDB_ERR_OPERATIONS_ERROR;

	will_return(__wrap_samdb_msg_add_int64, LDB_SUCCESS);
	will_return(__wrap_samdb_msg_add_int64, LDB_SUCCESS);

	status = authsam_logon_success_accounting(
		ldb, msg, domain_dn, true, NULL, NULL);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));
	assert_true(transaction_cancelled);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_logon_success_accounting
 *
 * ldb_wait failed
 *
 */
static void test_success_accounting_ldb_wait_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, build_domain_pso_result(ldb, ctx));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	will_return(__wrap_dsdb_search_dn, build_reread_result(ldb, ctx, 0));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	ldb_build_mod_req_res = talloc_zero(ldb, struct ldb_request);
	ldb_wait_ret = LDB_ERR_OPERATIONS_ERROR;

	will_return(__wrap_samdb_msg_add_int64, LDB_SUCCESS);
	will_return(__wrap_samdb_msg_add_int64, LDB_SUCCESS);

	status = authsam_logon_success_accounting(
		ldb, msg, domain_dn, true, NULL, NULL);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));
	assert_true(transaction_cancelled);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_logon_success_accounting
 *
 * ldb_transaction_commit failed
 *
 */
static void test_success_accounting_commit_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, build_domain_pso_result(ldb, ctx));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	will_return(__wrap_dsdb_search_dn, build_reread_result(ldb, ctx, 0));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	ldb_build_mod_req_res = talloc_zero(ldb, struct ldb_request);
	ldb_transaction_commit_ret = LDB_ERR_OPERATIONS_ERROR;

	will_return(__wrap_samdb_msg_add_int64, LDB_SUCCESS);
	will_return(__wrap_samdb_msg_add_int64, LDB_SUCCESS);

	status = authsam_logon_success_accounting(
		ldb, msg, domain_dn, true, NULL, NULL);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));
	assert_true(in_transaction);
	assert_false(transaction_cancelled);
	assert_false(transaction_committed);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_logon_success_accounting
 *
 * ldb_wait failed and then ldb_transaction_cancel failed
 *
 */
static void test_success_accounting_rollback_failed(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, build_domain_pso_result(ldb, ctx));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	will_return(__wrap_dsdb_search_dn, build_reread_result(ldb, ctx, 0));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	ldb_build_mod_req_res = talloc_zero(ldb, struct ldb_request);
	ldb_wait_ret = LDB_ERR_OPERATIONS_ERROR;
	ldb_transaction_cancel_ret = LDB_ERR_OPERATIONS_ERROR;

	will_return(__wrap_samdb_msg_add_int64, LDB_SUCCESS);
	will_return(__wrap_samdb_msg_add_int64, LDB_SUCCESS);

	status = authsam_logon_success_accounting(
		ldb, msg, domain_dn, true, NULL, NULL);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR));
	assert_true(in_transaction);
	assert_false(transaction_cancelled);
	assert_false(transaction_committed);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * authsam_logon_success_accounting
 *
 * The bad password indicator is set, but the account is not locked out.
 *
 */
static void test_success_accounting_spurious_bad_pwd_indicator(void **state) {
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *domain_dn = NULL;
	TALLOC_CTX *ctx = NULL;
	size_t before = 0;
	size_t after = 0;
	NTSTATUS status;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	domain_dn = ldb_dn_new(ctx, ldb, "CN=Domain");
	assert_non_null(domain_dn);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1000");

	msg->dn = ldb_dn_new(ctx, ldb, "CN=User");
	assert_non_null(msg->dn);

	before = talloc_total_size(ctx);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, domain_dn);
	will_return(__wrap_dsdb_search_dn, build_domain_pso_result(ldb, ctx));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	expect_check(__wrap_dsdb_search_dn, basedn, check_dn, msg->dn);
	will_return(__wrap_dsdb_search_dn, build_reread_result(ldb, ctx, 0));
	will_return(__wrap_dsdb_search_dn, LDB_SUCCESS);

	will_return_count(__wrap_samdb_msg_add_int64, LDB_SUCCESS, 2);

        /*
         * Set the bad password indicator.
	 */
	status = authsam_set_bad_password_indicator(ldb, ctx, msg);
	assert_true(NT_STATUS_EQUAL(NT_STATUS_OK, status));

	ldb_build_mod_req_res = talloc_zero(ctx, struct ldb_request);

	status = authsam_logon_success_accounting(
		ldb, msg, domain_dn, true, NULL, NULL);
	assert_true(NT_STATUS_EQUAL(status, NT_STATUS_OK));
	assert_false(in_transaction);
	assert_false(transaction_cancelled);
	assert_true(transaction_committed);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * get_bad_password_db
 *
 * ldb_get_opaque failure.
 */
static void test_get_bad_password_get_opaque_failed(void **state) {
	struct ldb_context *ldb = NULL;
	TALLOC_CTX *ctx = NULL;
	struct db_context *db = NULL;
	size_t before = 0;
	size_t after = 0;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	/*
	 * clear the mock ldb_get_opaque return value, so that we get a null
	 * response.
	 */
	TALLOC_FREE(ldb_get_opaque_ret);

	before = talloc_total_size(ctx);

	db = authsam_get_bad_password_db(ctx, ldb);
	assert_null(db);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * get_bad_password_db
 *
 * cluster_db_tmp_open failure.
 */
static void test_get_bad_password_db_open_failed(void **state) {
	struct ldb_context *ldb = NULL;
	TALLOC_CTX *ctx = NULL;
	struct db_context *db = NULL;
	size_t before = 0;
	size_t after = 0;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	/*
	 * Clear the mock cluster_db_tmp_open return value so that
	 * it returns NULL
	 */
	TALLOC_FREE(cluster_db_tmp_open_ret);
	before = talloc_total_size(ctx);

	db = authsam_get_bad_password_db(ctx, ldb);
	assert_null(db);

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * set_bad_password_indicator
 *
 * set_bad_password_indicator failure.
 */
static void test_set_bad_password_indicator_get_db_failed(void **state) {
	struct ldb_context *ldb = NULL;
	TALLOC_CTX *ctx = NULL;
	NTSTATUS status;
	size_t before = 0;
	size_t after = 0;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	/*
	 * Clear the mock cluster_db_tmp_open return value so that
	 * it returns NULL
	 */
	TALLOC_FREE(cluster_db_tmp_open_ret);
	before = talloc_total_size(ctx);

	status = authsam_set_bad_password_indicator(ldb, ctx, NULL);
	assert_true(NT_STATUS_EQUAL(NT_STATUS_INTERNAL_ERROR, status));

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * set_bad_password_indicator
 *
 * get_object_sid_as_tdb_data failure.
 */
static void test_set_bad_password_indicator_get_object_sid_failed(
	void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	TALLOC_CTX *ctx = NULL;
	NTSTATUS status;
	size_t before = 0;
	size_t after = 0;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	/*
	 * The created message does not contain an objectSid, so
	 * get_object_sid_as_tdb_data will fail.
	 */
	msg = create_message(ctx);

	before = talloc_total_size(ctx);

	status = authsam_set_bad_password_indicator(ldb, ctx, msg);
	assert_true(NT_STATUS_EQUAL(NT_STATUS_INTERNAL_ERROR, status));

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * set_bad_password_indicator
 *
 * dbwrap_store failure.
 */
static void test_set_bad_password_indicator_dbwrap_store_failed(
	void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	TALLOC_CTX *ctx = NULL;
	NTSTATUS status;
	size_t before = 0;
	size_t after = 0;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1010");

	dbwrap_store_ret = NT_STATUS_INTERNAL_DB_CORRUPTION;

	before = talloc_total_size(ctx);

	status = authsam_set_bad_password_indicator(ldb, ctx, msg);
	assert_true(NT_STATUS_EQUAL(NT_STATUS_INTERNAL_DB_CORRUPTION, status));

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * check_bad_password_indicator
 *
 * set_bad_password_indicator failure.
 */
static void test_check_bad_password_indicator_get_db_failed(void **state) {
	struct ldb_context *ldb = NULL;
	TALLOC_CTX *ctx = NULL;
	NTSTATUS status;
	size_t before = 0;
	size_t after = 0;
	bool exists = false;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	/*
	 * Clear the mock cluster_db_tmp_open return value so that
	 * it returns NULL
	 */
	TALLOC_FREE(cluster_db_tmp_open_ret);
	before = talloc_total_size(ctx);

	status = authsam_check_bad_password_indicator(ldb, ctx, &exists, NULL);
	assert_true(NT_STATUS_EQUAL(NT_STATUS_INTERNAL_ERROR, status));

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * check_bad_password_indicator
 *
 * get_object_sid_as_tdb_data failure.
 */
static void test_check_bad_password_indicator_get_object_sid_failed(
	void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	TALLOC_CTX *ctx = NULL;
	NTSTATUS status;
	size_t before = 0;
	size_t after = 0;
	bool exists = false;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	/*
	 * The created message does not contain an objectSid, so
	 * get_object_sid_as_tdb_data will fail.
	 */
	msg = create_message(ctx);

	before = talloc_total_size(ctx);

	status = authsam_check_bad_password_indicator(ldb, ctx, &exists, msg);
	assert_true(NT_STATUS_EQUAL(NT_STATUS_INTERNAL_ERROR, status));

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * clear_bad_password_indicator
 *
 * set_bad_password_indicator failure.
 */
static void test_clear_bad_password_indicator_get_db_failed(void **state) {
	struct ldb_context *ldb = NULL;
	TALLOC_CTX *ctx = NULL;
	NTSTATUS status;
	size_t before = 0;
	size_t after = 0;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	/*
	 * Clear the mock cluster_db_tmp_open return value so that
	 * it returns NULL
	 */
	TALLOC_FREE(cluster_db_tmp_open_ret);
	before = talloc_total_size(ctx);

	status = authsam_clear_bad_password_indicator(ldb, ctx, NULL);
	assert_true(NT_STATUS_EQUAL(NT_STATUS_INTERNAL_ERROR, status));

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * clear_bad_password_indicator
 *
 * get_object_sid_as_tdb_data failure.
 */
static void test_clear_bad_password_indicator_get_object_sid_failed(
	void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	TALLOC_CTX *ctx = NULL;
	NTSTATUS status;
	size_t before = 0;
	size_t after = 0;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	/*
	 * The created message does not contain an objectSid, so
	 * get_object_sid_as_tdb_data will fail.
	 */
	msg = create_message(ctx);

	before = talloc_total_size(ctx);

	status = authsam_clear_bad_password_indicator(ldb, ctx, msg);
	assert_true(NT_STATUS_EQUAL(NT_STATUS_INTERNAL_ERROR, status));

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * clear_bad_password_indicator
 *
 * dbwrap_delete failure.
 */
static void test_clear_bad_password_indicator_dbwrap_store_failed(
	void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	TALLOC_CTX *ctx = NULL;
	NTSTATUS status;
	size_t before = 0;
	size_t after = 0;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1010");

	dbwrap_delete_ret = NT_STATUS_INTERNAL_DB_CORRUPTION;

	before = talloc_total_size(ctx);

	status = authsam_clear_bad_password_indicator(ldb, ctx, msg);
	assert_true(NT_STATUS_EQUAL(NT_STATUS_INTERNAL_DB_CORRUPTION, status));

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

/*
 * clear_bad_password_indicator
 *
 * dbwrap_delete returns NT_STATUS_NOT_FOUND.
 */
static void test_clear_bad_pwd_indicator_dbwrap_store_not_found(
	void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;
	TALLOC_CTX *ctx = NULL;
	NTSTATUS status;
	size_t before = 0;
	size_t after = 0;

	ctx = talloc_new(*state);
	assert_non_null(ctx);

	ldb = ldb_init(ctx, NULL);
	assert_non_null(ldb);

	msg = create_message(ctx);
	add_sid(msg, "S-1-5-21-2470180966-3899876309-2637894779-1010");

	dbwrap_delete_ret = NT_STATUS_NOT_FOUND;

	before = talloc_total_size(ctx);

	status = authsam_clear_bad_password_indicator(ldb, ctx, msg);
	assert_true(NT_STATUS_IS_OK(status));

	/*
	 * Check that all allocated memory was freed
	 */
	after = talloc_total_size(ctx);
	assert_int_equal(before, after);

	/*
	 * Clean up
	 */
	TALLOC_FREE(ctx);
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
			test_reread_read_failure, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_reread_missing_account_control, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_reread_account_locked, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_reread_account_not_locked, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_update_bad_domain_dn_search_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_update_bad_get_pso_failed, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_update_bad_start_txn_failed, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_update_bad_reread_failed, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_update_bad_reread_locked_out, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_update_bad_update_count_failed, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_update_bad_no_update_required, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_update_bad_build_mod_request_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_update_bad_add_control_failed, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_update_bad_ldb_request_failed, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_update_bad_ldb_wait_failed, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_update_bad_txn_cancel_failed, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_update_bad_commit_failed, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_success_accounting_start_txn_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_success_accounting_reread_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_success_accounting_ldb_msg_new_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_success_accounting_samdb_rodc_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_success_accounting_update_lastlogon_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_success_accounting_build_mod_req_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_success_accounting_add_control_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_success_accounting_ldb_request_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_success_accounting_ldb_wait_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_success_accounting_commit_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_success_accounting_rollback_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_success_accounting_spurious_bad_pwd_indicator,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_get_bad_password_get_opaque_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_get_bad_password_db_open_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_set_bad_password_indicator_get_db_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_set_bad_password_indicator_get_object_sid_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_set_bad_password_indicator_dbwrap_store_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_check_bad_password_indicator_get_db_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_check_bad_password_indicator_get_object_sid_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_clear_bad_password_indicator_get_db_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_clear_bad_password_indicator_get_object_sid_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_clear_bad_password_indicator_dbwrap_store_failed,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_clear_bad_pwd_indicator_dbwrap_store_not_found,
			setup,
			teardown),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
