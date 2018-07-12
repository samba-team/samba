/*
   Unit tests for the dsdb audit logging code code in audit_log.c

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
 * These tests exercise the error handling code
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <unistd.h>
#include <cmocka.h>

int ldb_audit_log_module_init(const char *version);
#include "../audit_log.c"
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
 * unit test of operation_json, that ensures that all the expected
 * attributes and objects are in the json object.
 */
static void test_operation_json(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	struct ldb_request *req = NULL;
	struct ldb_reply *reply = NULL;
	struct audit_private *audit_private = NULL;

	struct tsocket_address *ts = NULL;

	struct auth_session_info *sess = NULL;
	struct security_token *token = NULL;
	struct dom_sid sid;
	const char *const SID = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SESSION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	struct GUID session_id;

	struct GUID transaction_id;
	const char *const TRANSACTION = "7130cb06-2062-6a1b-409e-3514c26b1773";

	struct ldb_dn *dn = NULL;
	const char *const DN = "dn=CN=USER,CN=Users,DC=SAMBA,DC=ORG";

	struct ldb_message *msg = NULL;

	struct json_object json;


	/*
	 * Test setup
	 */
	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);

	audit_private = talloc_zero(ctx, struct audit_private);
	GUID_from_string(TRANSACTION, &transaction_id);
	audit_private->transaction_guid = transaction_id;

	module = talloc_zero(ctx, struct ldb_module);
	module->ldb = ldb;
	ldb_module_set_private(module, audit_private);

	tsocket_address_inet_from_strings(ctx, "ip", "127.0.0.1", 0, &ts);
	ldb_set_opaque(ldb, "remoteAddress", ts);

	sess = talloc_zero(ctx, struct auth_session_info);
	token = talloc_zero(ctx, struct security_token);
	string_to_sid(&sid, SID);
	token->num_sids = 1;
	token->sids = &sid;
	sess->security_token = token;
	GUID_from_string(SESSION, &session_id);
	sess->unique_session_token = session_id;
	ldb_set_opaque(ldb, DSDB_SESSION_INFO, sess);

	msg = talloc_zero(ctx, struct ldb_message);
	dn = ldb_dn_new(ctx, ldb, DN);
	msg->dn = dn;
	ldb_msg_add_string(msg, "attribute", "the-value");

	req = talloc_zero(ctx, struct ldb_request);
	req->operation =  LDB_ADD;
	req->op.add.message = msg;

	reply = talloc_zero(ctx, struct ldb_reply);
	reply->error = LDB_ERR_OPERATIONS_ERROR;

	/*
	 * Fail on the creation of the audit json object
	 */

	will_return(__wrap_json_new_object, false);

	json = operation_json(module, req, reply);
	assert_true(json_is_invalid(&json));

	/*
	 * Fail adding the version object .
	 */

	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, JSON_ERROR);

	json = operation_json(module, req, reply);
	assert_true(json_is_invalid(&json));

	/*
	 * Fail on creation of the wrapper.
	 */

	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_new_object, false);

	json = operation_json(module, req, reply);
	assert_true(json_is_invalid(&json));

	/*
	 * Fail adding the timestamp to the wrapper object.
	 */
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_timestamp, JSON_ERROR);

	json = operation_json(module, req, reply);
	assert_true(json_is_invalid(&json));

	/*
	 * Now test the happy path
	 */
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_timestamp, 0);

	json = operation_json(module, req, reply);
	assert_false(json_is_invalid(&json));
	json_free(&json);

	TALLOC_FREE(ctx);

}

/*
 * minimal unit test of password_change_json, that ensures that all the expected
 * attributes and objects are in the json object.
 */
static void test_password_change_json(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	struct ldb_request *req = NULL;
	struct ldb_reply *reply = NULL;
	struct audit_private *audit_private = NULL;

	struct tsocket_address *ts = NULL;

	struct auth_session_info *sess = NULL;
	struct security_token *token = NULL;
	struct dom_sid sid;
	const char *const SID = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SESSION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	struct GUID session_id;

	struct GUID transaction_id;
	const char *const TRANSACTION = "7130cb06-2062-6a1b-409e-3514c26b1773";

	struct ldb_dn *dn = NULL;
	const char *const DN = "dn=CN=USER,CN=Users,DC=SAMBA,DC=ORG";

	struct ldb_message *msg = NULL;

	struct json_object json;

	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);

	audit_private = talloc_zero(ctx, struct audit_private);
	GUID_from_string(TRANSACTION, &transaction_id);
	audit_private->transaction_guid = transaction_id;

	module = talloc_zero(ctx, struct ldb_module);
	module->ldb = ldb;
	ldb_module_set_private(module, audit_private);

	tsocket_address_inet_from_strings(ctx, "ip", "127.0.0.1", 0, &ts);
	ldb_set_opaque(ldb, "remoteAddress", ts);

	sess = talloc_zero(ctx, struct auth_session_info);
	token = talloc_zero(ctx, struct security_token);
	string_to_sid(&sid, SID);
	token->num_sids = 1;
	token->sids = &sid;
	sess->security_token = token;
	GUID_from_string(SESSION, &session_id);
	sess->unique_session_token = session_id;
	ldb_set_opaque(ldb, DSDB_SESSION_INFO, sess);

	msg = talloc_zero(ctx, struct ldb_message);
	dn = ldb_dn_new(ctx, ldb, DN);
	msg->dn = dn;
	ldb_msg_add_string(msg, "planTextPassword", "super-secret");

	req = talloc_zero(ctx, struct ldb_request);
	req->operation =  LDB_ADD;
	req->op.add.message = msg;
	reply = talloc_zero(ctx, struct ldb_reply);
	reply->error = LDB_SUCCESS;


	/*
	 * Fail on the creation of the audit json object
	 */

	will_return(__wrap_json_new_object, false);
	json = password_change_json(module, req, reply);

	assert_true(json_is_invalid(&json));

	/*
	 * Fail adding the version object .
	 */

	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, JSON_ERROR);

	json = password_change_json(module, req, reply);
	assert_true(json_is_invalid(&json));

	/*
	 * Fail on creation of the wrapper.
	 */

	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, false);

	json = password_change_json(module, req, reply);
	assert_true(json_is_invalid(&json));

	/*
	 * Fail on creation of the time stamp.
	 */

	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_timestamp, JSON_ERROR);

	json = password_change_json(module, req, reply);
	assert_true(json_is_invalid(&json));

	/*
	 * Now test the happy path
	 */
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_timestamp, 0);

	json = password_change_json(module, req, reply);
	assert_false(json_is_invalid(&json));
	json_free(&json);

	TALLOC_FREE(ctx);
}


/*
 * minimal unit test of transaction_json, that ensures that all the expected
 * attributes and objects are in the json object.
 */
static void test_transaction_json(void **state)
{

	struct GUID guid;
	const char * const GUID = "7130cb06-2062-6a1b-409e-3514c26b1773";

	struct json_object json;

	GUID_from_string(GUID, &guid);


	/*
	 * Fail on the creation of the audit json object
	 */

	will_return(__wrap_json_new_object, false);

	json = transaction_json("delete", &guid, 10000099);
	assert_true(json_is_invalid(&json));

	/*
	 * Fail adding the version object .
	 */

	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, JSON_ERROR);

	json = transaction_json("delete", &guid, 10000099);
	assert_true(json_is_invalid(&json));

	/*
	 * Fail on creation of the wrapper.
	 */

	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, false);

	json = transaction_json("delete", &guid, 10000099);
	assert_true(json_is_invalid(&json));

	/*
	 * Fail on creation of the time stamp.
	 */

	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_timestamp, JSON_ERROR);

	json = transaction_json("delete", &guid, 10000099);
	assert_true(json_is_invalid(&json));

	/*
	 * Now test the happy path
	 */
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_timestamp, 0);

	json = transaction_json("delete", &guid, 10000099);
	assert_false(json_is_invalid(&json));
	json_free(&json);
}

/*
 * minimal unit test of commit_failure_json, that ensures that all the
 * expected attributes and objects are in the json object.
 */
static void test_commit_failure_json(void **state)
{

	struct GUID guid;
	const char * const GUID = "7130cb06-2062-6a1b-409e-3514c26b1773";

	struct json_object json;

	GUID_from_string(GUID, &guid);


	/*
	 * Fail on the creation of the audit json object
	 */

	will_return(__wrap_json_new_object, false);

	json = commit_failure_json(
		"prepare",
		987876,
		LDB_ERR_OPERATIONS_ERROR,
		"because",
		&guid);
	assert_true(json_is_invalid(&json));

	/*
	 * Fail adding the version object .
	 */

	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, JSON_ERROR);

	json = commit_failure_json(
		"prepare",
		987876,
		LDB_ERR_OPERATIONS_ERROR,
		"because",
		&guid);
	assert_true(json_is_invalid(&json));

	/*
	 * Fail on creation of the wrapper.
	 */

	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, false);

	json = commit_failure_json(
		"prepare",
		987876,
		LDB_ERR_OPERATIONS_ERROR,
		"because",
		&guid);
	assert_true(json_is_invalid(&json));

	/*
	 * Fail on creation of the time stamp.
	 */

	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_timestamp, JSON_ERROR);

	json = commit_failure_json(
		"prepare",
		987876,
		LDB_ERR_OPERATIONS_ERROR,
		"because",
		&guid);
	assert_true(json_is_invalid(&json));

	/*
	 * Now test the happy path
	 */

	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_timestamp, 0);

	json = commit_failure_json(
		"prepare",
		987876,
		LDB_ERR_OPERATIONS_ERROR,
		"because",
		&guid);
	assert_false(json_is_invalid(&json));
	json_free(&json);
}

/*
 * unit test of replicated_update_json, that ensures that all the expected
 * attributes and objects are in the json object.
 */
static void test_replicated_update_json(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	struct ldb_request *req = NULL;
	struct ldb_reply *reply = NULL;
	struct audit_private *audit_private = NULL;
	struct dsdb_extended_replicated_objects *ro = NULL;
	struct repsFromTo1 *source_dsa = NULL;

	struct GUID transaction_id;
	const char *const TRANSACTION = "7130cb06-2062-6a1b-409e-3514c26b1773";

	struct ldb_dn *dn = NULL;
	const char *const DN = "dn=CN=USER,CN=Users,DC=SAMBA,DC=ORG";

	struct GUID source_dsa_obj_guid;
	const char *const SOURCE_DSA = "7130cb06-2062-6a1b-409e-3514c26b1793";

	struct GUID invocation_id;
	const char *const INVOCATION_ID =
		"7130cb06-2062-6a1b-409e-3514c26b1893";
	struct json_object json;

	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);

	audit_private = talloc_zero(ctx, struct audit_private);
	GUID_from_string(TRANSACTION, &transaction_id);
	audit_private->transaction_guid = transaction_id;

	module = talloc_zero(ctx, struct ldb_module);
	module->ldb = ldb;
	ldb_module_set_private(module, audit_private);

	dn = ldb_dn_new(ctx, ldb, DN);
	GUID_from_string(SOURCE_DSA, &source_dsa_obj_guid);
	GUID_from_string(INVOCATION_ID, &invocation_id);
	source_dsa = talloc_zero(ctx, struct repsFromTo1);
	source_dsa->source_dsa_obj_guid = source_dsa_obj_guid;
	source_dsa->source_dsa_invocation_id = invocation_id;

	ro = talloc_zero(ctx, struct dsdb_extended_replicated_objects);
	ro->source_dsa = source_dsa;
	ro->num_objects = 808;
	ro->linked_attributes_count = 2910;
	ro->partition_dn = dn;
	ro->error = WERR_NOT_SUPPORTED;


	req = talloc_zero(ctx, struct ldb_request);
	req->op.extended.data = ro;
	req->operation = LDB_EXTENDED;

	reply = talloc_zero(ctx, struct ldb_reply);
	reply->error = LDB_ERR_NO_SUCH_OBJECT;


	/*
	 * Fail on the creation of the audit json object
	 */

	will_return(__wrap_json_new_object, false);

	json = replicated_update_json(module, req, reply);
	assert_true(json_is_invalid(&json));

	/*
	 * Fail adding the version object .
	 */

	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, JSON_ERROR);

	json = replicated_update_json(module, req, reply);
	assert_true(json_is_invalid(&json));

	/*
	 * Fail on creation of the wrapper.
	 */

	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, false);

	json = replicated_update_json(module, req, reply);
	assert_true(json_is_invalid(&json));

	/*
	 * Fail on creation of the time stamp.
	 */

	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_timestamp, JSON_ERROR);

	json = replicated_update_json(module, req, reply);
	assert_true(json_is_invalid(&json));

	/*
	 * Now test the happy path.
	 */
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_version, 0);
	will_return(__wrap_json_new_object, true);
	will_return(__wrap_json_add_timestamp, 0);

	json = replicated_update_json(module, req, reply);
	assert_false(json_is_invalid(&json));
	json_free(&json);

	TALLOC_FREE(ctx);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_operation_json),
		cmocka_unit_test(test_password_change_json),
		cmocka_unit_test(test_transaction_json),
		cmocka_unit_test(test_commit_failure_json),
		cmocka_unit_test(test_replicated_update_json),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
