/*
   Unit tests for the dsdb group auditing code in group_audit.c

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018

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

/*
 * These tests exercise the error handling routines.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <unistd.h>
#include <cmocka.h>

int ldb_group_audit_log_module_init(const char *version);
#include "../group_audit.c"

#include "lib/ldb/include/ldb_private.h"

/*
 * cmocka wrappers for json_new_object
 */
struct json_object __wrap_json_new_object(void);
struct json_object __real_json_new_object(void);
struct json_object __wrap_json_new_object(void)
{

	bool use_real = (bool)mock();
	if (!use_real) {
		return json_empty_object;
	}
	return __real_json_new_object();
}

/*
 * cmocka wrappers for json_add_version
 */
int __wrap_json_add_version(struct json_object *object, int major, int minor);
int __real_json_add_version(struct json_object *object, int major, int minor);
int __wrap_json_add_version(struct json_object *object, int major, int minor)
{

	int ret = (int)mock();
	if (ret) {
		return ret;
	}
	return __real_json_add_version(object, major, minor);
}

/*
 * cmocka wrappers for json_add_version
 */
int __wrap_json_add_timestamp(struct json_object *object);
int __real_json_add_timestamp(struct json_object *object);
int __wrap_json_add_timestamp(struct json_object *object)
{

	int ret = (int)mock();
	if (ret) {
		return ret;
	}
	return __real_json_add_timestamp(object);
}

/*
 * Test helper to add a session id and user SID
 */
static void add_session_data(
	TALLOC_CTX *ctx,
	struct ldb_context *ldb,
	const char *session,
	const char *user_sid)
{
	struct auth_session_info *sess = NULL;
	struct security_token *token = NULL;
	struct dom_sid *sid = NULL;
	struct GUID session_id;
	bool ok;

	sess = talloc_zero(ctx, struct auth_session_info);
	token = talloc_zero(ctx, struct security_token);
	sid = talloc_zero(ctx, struct dom_sid);
	ok = string_to_sid(sid, user_sid);
	assert_true(ok);
	token->sids = sid;
	sess->security_token = token;
	GUID_from_string(session, &session_id);
	sess->unique_session_token = session_id;
	ldb_set_opaque(ldb, DSDB_SESSION_INFO, sess);
}

/*
 * Test helper to insert a transaction_id into a request.
 */
static void add_transaction_id(struct ldb_request *req, const char *id)
{
	struct GUID guid;
	struct dsdb_control_transaction_identifier *transaction_id = NULL;

	transaction_id = talloc_zero(
		req,
		struct dsdb_control_transaction_identifier);
	assert_non_null(transaction_id);
	GUID_from_string(id, &guid);
	transaction_id->transaction_guid = guid;
	ldb_request_add_control(
		req,
		DSDB_CONTROL_TRANSACTION_IDENTIFIER_OID,
		false,
		transaction_id);
}

static void test_audit_group_json(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	struct ldb_request *req = NULL;

	struct tsocket_address *ts = NULL;

	const char *const SID = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SESSION = "7130cb06-2062-6a1b-409e-3514c26b1773";

	struct GUID transaction_id;
	const char *const TRANSACTION = "7130cb06-2062-6a1b-409e-3514c26b1773";

	enum event_id_type event_id = EVT_ID_USER_REMOVED_FROM_GLOBAL_SEC_GROUP;

	struct json_object json;

	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);

	GUID_from_string(TRANSACTION, &transaction_id);

	module = talloc_zero(ctx, struct ldb_module);
	module->ldb = ldb;

	tsocket_address_inet_from_strings(ctx, "ip", "127.0.0.1", 0, &ts);
	ldb_set_opaque(ldb, "remoteAddress", ts);

	add_session_data(ctx, ldb, SESSION, SID);

	req = talloc_zero(ctx, struct ldb_request);
	req->operation =  LDB_ADD;
	add_transaction_id(req, TRANSACTION);

	/*
	 * Fail on the creation of the audit json object
	 */

	will_return(__wrap_json_new_object, false);

	json = audit_group_json(module,
				req,
				"the-action",
				"the-user-name",
				"the-group-name",
				event_id,
				LDB_ERR_OPERATIONS_ERROR);
	assert_true(json_is_invalid(&json));

	/*
	 * Fail adding the version object .
	 */

	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, JSON_ERROR);

	json = audit_group_json(module,
				req,
				"the-action",
				"the-user-name",
				"the-group-name",
				event_id,
				LDB_ERR_OPERATIONS_ERROR);
	assert_true(json_is_invalid(&json));

	/*
	 * Fail on creation of the wrapper.
	 */

	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, false);

	json = audit_group_json(module,
				req,
				"the-action",
				"the-user-name",
				"the-group-name",
				event_id,
				LDB_ERR_OPERATIONS_ERROR);
	assert_true(json_is_invalid(&json));

	/*
	 * Fail adding the timestamp to the wrapper object.
	 */
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_timestamp, JSON_ERROR);

	json = audit_group_json(module,
				req,
				"the-action",
				"the-user-name",
				"the-group-name",
				event_id,
				LDB_ERR_OPERATIONS_ERROR);
	assert_true(json_is_invalid(&json));


	/*
	 * Now test the happy path
	 */
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_timestamp, 0);

	json = audit_group_json(module,
				req,
				"the-action",
				"the-user-name",
				"the-group-name",
				event_id,
				LDB_ERR_OPERATIONS_ERROR);
	assert_false(json_is_invalid(&json));

	json_free(&json);
	TALLOC_FREE(ctx);

}

/*
 * Note: to run under valgrind us:
 *       valgrind --suppressions=test_group_audit.valgrind bin/test_group_audit
 *       This suppresses the errors generated because the ldb_modules are not
 *       de-registered.
 *
 */
int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_audit_group_json),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
