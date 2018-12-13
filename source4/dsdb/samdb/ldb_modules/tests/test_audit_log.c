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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <unistd.h>
#include <cmocka.h>

int ldb_audit_log_module_init(const char *version);
#include "../audit_log.c"

#include "lib/ldb/include/ldb_private.h"
#include <regex.h>
#include <float.h>

/*
 * Test helper to check ISO 8601 timestamps for validity
 */
static void check_timestamp(time_t before, const char* timestamp)
{
	int rc;
	int usec, tz;
	char c[2];
	struct tm tm;
	time_t after;
	time_t actual;
	const double lower = -1;


	after = time(NULL);

	/*
	 * Convert the ISO 8601 timestamp into a time_t
	 * Note for convenience we ignore the value of the microsecond
	 * part of the time stamp.
	 */
	rc = sscanf(
		timestamp,
		"%4d-%2d-%2dT%2d:%2d:%2d.%6d%1c%4d",
		&tm.tm_year,
		&tm.tm_mon,
		&tm.tm_mday,
		&tm.tm_hour,
		&tm.tm_min,
		&tm.tm_sec,
		&usec,
		c,
		&tz);
	assert_int_equal(9, rc);
	tm.tm_year = tm.tm_year - 1900;
	tm.tm_mon = tm.tm_mon - 1;
	tm.tm_isdst = -1;
	actual = mktime(&tm);

	/*
	 * The timestamp should be before <= actual <= after
	 * Note: as the microsecond portion of the time is truncated we use
	 *       a -1 as the lower bound for the time difference instead of
	 *       zero
	 */
	assert_true(difftime(actual, before) >= lower);
	assert_true(difftime(after, actual) >= lower);
}

static void test_has_password_changed(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_message *msg = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);

	/*
	 * Empty message
	 */
	msg = ldb_msg_new(ldb);
	assert_false(has_password_changed(msg));
	TALLOC_FREE(msg);

	/*
	 * No password attributes
	 */
	msg = ldb_msg_new(ldb);
	ldb_msg_add_string(msg, "attr01", "value01");
	assert_false(has_password_changed(msg));
	TALLOC_FREE(msg);

	/*
	 * No password attributes >1 entries
	 */
	msg = ldb_msg_new(ldb);
	ldb_msg_add_string(msg, "attr01", "value01");
	ldb_msg_add_string(msg, "attr02", "value03");
	ldb_msg_add_string(msg, "attr03", "value03");
	assert_false(has_password_changed(msg));
	TALLOC_FREE(msg);

	/*
	 *  userPassword set
	 */
	msg = ldb_msg_new(ldb);
	ldb_msg_add_string(msg, "userPassword", "value01");
	assert_true(has_password_changed(msg));
	TALLOC_FREE(msg);

	/*
	 *  clearTextPassword set
	 */
	msg = ldb_msg_new(ldb);
	ldb_msg_add_string(msg, "clearTextPassword", "value01");
	assert_true(has_password_changed(msg));
	TALLOC_FREE(msg);

	/*
	 *  unicodePwd set
	 */
	msg = ldb_msg_new(ldb);
	ldb_msg_add_string(msg, "unicodePwd", "value01");
	assert_true(has_password_changed(msg));
	TALLOC_FREE(msg);

	/*
	 *  dBCSPwd set
	 */
	msg = ldb_msg_new(ldb);
	ldb_msg_add_string(msg, "dBCSPwd", "value01");
	assert_true(has_password_changed(msg));
	TALLOC_FREE(msg);

	/*
	 *  All attributes set
	 */
	msg = ldb_msg_new(ldb);
	ldb_msg_add_string(msg, "userPassword", "value01");
	ldb_msg_add_string(msg, "clearTextPassword", "value02");
	ldb_msg_add_string(msg, "unicodePwd", "value03");
	ldb_msg_add_string(msg, "dBCSPwd", "value04");
	assert_true(has_password_changed(msg));
	TALLOC_FREE(msg);

	/*
	 *  first attribute is a password attribute
	 */
	msg = ldb_msg_new(ldb);
	ldb_msg_add_string(msg, "userPassword", "value01");
	ldb_msg_add_string(msg, "attr02", "value02");
	ldb_msg_add_string(msg, "attr03", "value03");
	ldb_msg_add_string(msg, "attr04", "value04");
	assert_true(has_password_changed(msg));
	TALLOC_FREE(msg);

	/*
	 *  last attribute is a password attribute
	 */
	msg = ldb_msg_new(ldb);
	ldb_msg_add_string(msg, "attr01", "value01");
	ldb_msg_add_string(msg, "attr02", "value02");
	ldb_msg_add_string(msg, "attr03", "value03");
	ldb_msg_add_string(msg, "clearTextPassword", "value04");
	assert_true(has_password_changed(msg));
	TALLOC_FREE(msg);

	/*
	 *  middle attribute is a password attribute
	 */
	msg = ldb_msg_new(ldb);
	ldb_msg_add_string(msg, "attr01", "value01");
	ldb_msg_add_string(msg, "attr02", "value02");
	ldb_msg_add_string(msg, "unicodePwd", "pwd");
	ldb_msg_add_string(msg, "attr03", "value03");
	ldb_msg_add_string(msg, "attr04", "value04");
	assert_true(has_password_changed(msg));
	TALLOC_FREE(msg);

	TALLOC_FREE(ctx);
}

static void test_get_password_action(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_request *req = NULL;
	struct ldb_reply *reply = NULL;
	struct dsdb_control_password_acl_validation *pav = NULL;
	int ret;

	TALLOC_CTX *ctx = talloc_new(NULL);
	ldb = ldb_init(ctx, NULL);

	/*
	 * Add request, will always be a reset
	 */
	ldb_build_add_req(&req, ldb, ctx, NULL, NULL, NULL, NULL, NULL);
	reply = talloc_zero(ctx, struct ldb_reply);
	assert_string_equal("Reset", get_password_action(req, reply));
	TALLOC_FREE(req);
	TALLOC_FREE(reply);

	/*
	 * No password control acl, expect "Reset"
	 */
	ldb_build_mod_req(&req, ldb, ctx, NULL, NULL, NULL, NULL, NULL);
	reply = talloc_zero(ctx, struct ldb_reply);
	assert_string_equal("Reset", get_password_action(req, reply));
	TALLOC_FREE(req);
	TALLOC_FREE(reply);

	/*
	 * dsdb_control_password_acl_validation reset = false, expect "Change"
	 */
	ret = ldb_build_mod_req(&req, ldb, ctx, NULL, NULL, NULL, NULL, NULL);
	assert_int_equal(ret, LDB_SUCCESS);
	reply = talloc_zero(ctx, struct ldb_reply);
	pav = talloc_zero(req, struct dsdb_control_password_acl_validation);

	ldb_reply_add_control(
		reply,
		DSDB_CONTROL_PASSWORD_ACL_VALIDATION_OID,
		false,
		pav);
	assert_string_equal("Change", get_password_action(req, reply));
	TALLOC_FREE(req);
	TALLOC_FREE(reply);

	/*
	 * dsdb_control_password_acl_validation reset = true, expect "Reset"
	 */
	ldb_build_mod_req(&req, ldb, ctx, NULL, NULL, NULL, NULL, NULL);
	reply = talloc_zero(ctx, struct ldb_reply);
	pav = talloc_zero(req, struct dsdb_control_password_acl_validation);
	pav->pwd_reset = true;

	ldb_reply_add_control(
		reply,
		DSDB_CONTROL_PASSWORD_ACL_VALIDATION_OID,
		false,
		pav);
	assert_string_equal("Reset", get_password_action(req, reply));
	TALLOC_FREE(req);
	TALLOC_FREE(reply);

	TALLOC_FREE(ctx);
}

/*
 * Test helper to validate a version object.
 */
static void check_version(struct json_t *version, int major, int minor)
{
	struct json_t *v = NULL;

	assert_true(json_is_object(version));
	assert_int_equal(2, json_object_size(version));

	v = json_object_get(version, "major");
	assert_non_null(v);
	assert_int_equal(major, json_integer_value(v));

	v = json_object_get(version, "minor");
	assert_non_null(v);
	assert_int_equal(minor, json_integer_value(v));
}

/*
 * minimal unit test of operation_json, that ensures that all the expected
 * attributes and objects are in the json object.
 */
static void test_operation_json_empty(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	struct ldb_request *req = NULL;
	struct ldb_reply *reply = NULL;
	struct audit_private *audit_private = NULL;

	struct json_object json;
	json_t *audit = NULL;
	json_t *v = NULL;
	json_t *o = NULL;
	time_t before;


	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);
	audit_private = talloc_zero(ctx, struct audit_private);

	module = talloc_zero(ctx, struct ldb_module);
	module->ldb = ldb;
	ldb_module_set_private(module, audit_private);

	req = talloc_zero(ctx, struct ldb_request);
	reply = talloc_zero(ctx, struct ldb_reply);
	reply->error = LDB_SUCCESS;

	before = time(NULL);
	json = operation_json(module, req, reply);
	assert_int_equal(3, json_object_size(json.root));


	v = json_object_get(json.root, "type");
	assert_non_null(v);
	assert_string_equal("dsdbChange", json_string_value(v));

	v = json_object_get(json.root, "timestamp");
	assert_non_null(v);
	assert_true(json_is_string(v));
	check_timestamp(before, json_string_value(v));

	audit = json_object_get(json.root, "dsdbChange");
	assert_non_null(audit);
	assert_true(json_is_object(audit));
	assert_int_equal(10, json_object_size(audit));

	o = json_object_get(audit, "version");
	assert_non_null(o);
	check_version(o, OPERATION_MAJOR, OPERATION_MINOR);

	v = json_object_get(audit, "statusCode");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(LDB_SUCCESS, json_integer_value(v));

	v = json_object_get(audit, "status");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("Success", json_string_value(v));

	v = json_object_get(audit, "operation");
	assert_non_null(v);
	assert_true(json_is_string(v));
	/*
	 * Search operation constant is zero
	 */
	assert_string_equal("Search", json_string_value(v));

	v = json_object_get(audit, "remoteAddress");
	assert_non_null(v);
	assert_true(json_is_null(v));

	v = json_object_get(audit, "userSid");
	assert_non_null(v);
	assert_true(json_is_null(v));

	v = json_object_get(audit, "performedAsSystem");
	assert_non_null(v);
	assert_true(json_is_boolean(v));
	assert_true(json_is_false(v));


	v = json_object_get(audit, "dn");
	assert_non_null(v);
	assert_true(json_is_null(v));

	v = json_object_get(audit, "transactionId");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(
		"00000000-0000-0000-0000-000000000000",
		json_string_value(v));

	v = json_object_get(audit, "sessionId");
	assert_non_null(v);
	assert_true(json_is_null(v));

	json_free(&json);
	TALLOC_FREE(ctx);

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
	json_t *audit = NULL;
	json_t *v = NULL;
	json_t *o = NULL;
	json_t *a = NULL;
	json_t *b = NULL;
	json_t *c = NULL;
	json_t *d = NULL;
	json_t *e = NULL;
	json_t *f = NULL;
	json_t *g = NULL;
	time_t before;


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

	before = time(NULL);
	json = operation_json(module, req, reply);
	assert_int_equal(3, json_object_size(json.root));

	v = json_object_get(json.root, "type");
	assert_non_null(v);
	assert_string_equal("dsdbChange", json_string_value(v));

	v = json_object_get(json.root, "timestamp");
	assert_non_null(v);
	assert_true(json_is_string(v));
	check_timestamp(before, json_string_value(v));

	audit = json_object_get(json.root, "dsdbChange");
	assert_non_null(audit);
	assert_true(json_is_object(audit));
	assert_int_equal(11, json_object_size(audit));

	o = json_object_get(audit, "version");
	assert_non_null(o);
	check_version(o, OPERATION_MAJOR, OPERATION_MINOR);

	v = json_object_get(audit, "statusCode");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(LDB_ERR_OPERATIONS_ERROR, json_integer_value(v));

	v = json_object_get(audit, "status");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("Operations error", json_string_value(v));

	v = json_object_get(audit, "operation");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("Add", json_string_value(v));

	v = json_object_get(audit, "remoteAddress");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("ipv4:127.0.0.1:0", json_string_value(v));

	v = json_object_get(audit, "userSid");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(SID, json_string_value(v));

	v = json_object_get(audit, "performedAsSystem");
	assert_non_null(v);
	assert_true(json_is_boolean(v));
	assert_true(json_is_false(v));

	v = json_object_get(audit, "dn");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(DN, json_string_value(v));

	v = json_object_get(audit, "transactionId");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(TRANSACTION, json_string_value(v));

	v = json_object_get(audit, "sessionId");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(SESSION, json_string_value(v));

	o = json_object_get(audit, "attributes");
	assert_non_null(v);
	assert_true(json_is_object(o));
	assert_int_equal(1, json_object_size(o));

	a = json_object_get(o, "attribute");
	assert_non_null(a);
	assert_true(json_is_object(a));

	b = json_object_get(a, "actions");
	assert_non_null(b);
	assert_true(json_is_array(b));
	assert_int_equal(1, json_array_size(b));

	c = json_array_get(b, 0);
	assert_non_null(c);
	assert_true(json_is_object(c));

	d = json_object_get(c, "action");
	assert_non_null(d);
	assert_true(json_is_string(d));
	assert_string_equal("add", json_string_value(d));

	e = json_object_get(c, "values");
	assert_non_null(b);
	assert_true(json_is_array(e));
	assert_int_equal(1, json_array_size(e));

	f = json_array_get(e, 0);
	assert_non_null(f);
	assert_true(json_is_object(f));
	assert_int_equal(1, json_object_size(f));

	g = json_object_get(f, "value");
	assert_non_null(g);
	assert_true(json_is_string(g));
	assert_string_equal("the-value", json_string_value(g));

	json_free(&json);
	TALLOC_FREE(ctx);

}

/*
 * unit test of operation_json, that ensures that all the expected
 * attributes and objects are in the json object.
 * In this case for an operation performed as the system user.
 */
static void test_as_system_operation_json(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	struct ldb_request *req = NULL;
	struct ldb_reply *reply = NULL;
	struct audit_private *audit_private = NULL;

	struct tsocket_address *ts = NULL;

	struct auth_session_info *sess = NULL;
	struct auth_session_info *sys_sess = NULL;
	struct security_token *token = NULL;
	struct security_token *sys_token = NULL;
	struct dom_sid sid;
	const char *const SID = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SESSION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const SYS_SESSION = "7130cb06-2062-6a1b-409e-3514c26b1998";
	struct GUID session_id;
	struct GUID sys_session_id;

	struct GUID transaction_id;
	const char *const TRANSACTION = "7130cb06-2062-6a1b-409e-3514c26b1773";

	struct ldb_dn *dn = NULL;
	const char *const DN = "dn=CN=USER,CN=Users,DC=SAMBA,DC=ORG";

	struct ldb_message *msg = NULL;

	struct json_object json;
	json_t *audit = NULL;
	json_t *v = NULL;
	json_t *o = NULL;
	json_t *a = NULL;
	json_t *b = NULL;
	json_t *c = NULL;
	json_t *d = NULL;
	json_t *e = NULL;
	json_t *f = NULL;
	json_t *g = NULL;
	time_t before;


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
	ldb_set_opaque(ldb, DSDB_NETWORK_SESSION_INFO, sess);

	sys_sess = talloc_zero(ctx, struct auth_session_info);
	sys_token = talloc_zero(ctx, struct security_token);
	sys_token->num_sids = 1;
	sys_token->sids = discard_const(&global_sid_System);
	sys_sess->security_token = sys_token;
	GUID_from_string(SYS_SESSION, &sys_session_id);
	sess->unique_session_token = sys_session_id;
	ldb_set_opaque(ldb, DSDB_SESSION_INFO, sys_sess);

	msg = talloc_zero(ctx, struct ldb_message);
	dn = ldb_dn_new(ctx, ldb, DN);
	msg->dn = dn;
	ldb_msg_add_string(msg, "attribute", "the-value");

	req = talloc_zero(ctx, struct ldb_request);
	req->operation =  LDB_ADD;
	req->op.add.message = msg;

	reply = talloc_zero(ctx, struct ldb_reply);
	reply->error = LDB_ERR_OPERATIONS_ERROR;

	before = time(NULL);
	json = operation_json(module, req, reply);
	assert_int_equal(3, json_object_size(json.root));

	v = json_object_get(json.root, "type");
	assert_non_null(v);
	assert_string_equal("dsdbChange", json_string_value(v));

	v = json_object_get(json.root, "timestamp");
	assert_non_null(v);
	assert_true(json_is_string(v));
	check_timestamp(before, json_string_value(v));

	audit = json_object_get(json.root, "dsdbChange");
	assert_non_null(audit);
	assert_true(json_is_object(audit));
	assert_int_equal(11, json_object_size(audit));

	o = json_object_get(audit, "version");
	assert_non_null(o);
	check_version(o, OPERATION_MAJOR, OPERATION_MINOR);

	v = json_object_get(audit, "statusCode");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(LDB_ERR_OPERATIONS_ERROR, json_integer_value(v));

	v = json_object_get(audit, "status");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("Operations error", json_string_value(v));

	v = json_object_get(audit, "operation");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("Add", json_string_value(v));

	v = json_object_get(audit, "remoteAddress");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("ipv4:127.0.0.1:0", json_string_value(v));

	v = json_object_get(audit, "userSid");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(SID, json_string_value(v));

	v = json_object_get(audit, "performedAsSystem");
	assert_non_null(v);
	assert_true(json_is_boolean(v));
	assert_true(json_is_true(v));

	v = json_object_get(audit, "dn");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(DN, json_string_value(v));

	v = json_object_get(audit, "transactionId");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(TRANSACTION, json_string_value(v));

	v = json_object_get(audit, "sessionId");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(SYS_SESSION, json_string_value(v));

	o = json_object_get(audit, "attributes");
	assert_non_null(v);
	assert_true(json_is_object(o));
	assert_int_equal(1, json_object_size(o));

	a = json_object_get(o, "attribute");
	assert_non_null(a);
	assert_true(json_is_object(a));

	b = json_object_get(a, "actions");
	assert_non_null(b);
	assert_true(json_is_array(b));
	assert_int_equal(1, json_array_size(b));

	c = json_array_get(b, 0);
	assert_non_null(c);
	assert_true(json_is_object(c));

	d = json_object_get(c, "action");
	assert_non_null(d);
	assert_true(json_is_string(d));
	assert_string_equal("add", json_string_value(d));

	e = json_object_get(c, "values");
	assert_non_null(b);
	assert_true(json_is_array(e));
	assert_int_equal(1, json_array_size(e));

	f = json_array_get(e, 0);
	assert_non_null(f);
	assert_true(json_is_object(f));
	assert_int_equal(1, json_object_size(f));

	g = json_object_get(f, "value");
	assert_non_null(g);
	assert_true(json_is_string(g));
	assert_string_equal("the-value", json_string_value(g));

	json_free(&json);
	TALLOC_FREE(ctx);

}

/*
 * minimal unit test of password_change_json, that ensures that all the expected
 * attributes and objects are in the json object.
 */
static void test_password_change_json_empty(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	struct ldb_request *req = NULL;
	struct ldb_reply *reply = NULL;
	struct audit_private *audit_private = NULL;

	struct json_object json;
	json_t *audit = NULL;
	json_t *v = NULL;
	json_t *o = NULL;
	time_t before;


	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);
	audit_private = talloc_zero(ctx, struct audit_private);

	module = talloc_zero(ctx, struct ldb_module);
	module->ldb = ldb;
	ldb_module_set_private(module, audit_private);

	req = talloc_zero(ctx, struct ldb_request);
	reply = talloc_zero(ctx, struct ldb_reply);
	reply->error = LDB_SUCCESS;

	before = time(NULL);
	json = password_change_json(module, req, reply);
	assert_int_equal(3, json_object_size(json.root));


	v = json_object_get(json.root, "type");
	assert_non_null(v);
	assert_string_equal("passwordChange", json_string_value(v));

	v = json_object_get(json.root, "timestamp");
	assert_non_null(v);
	assert_true(json_is_string(v));
	check_timestamp(before, json_string_value(v));

	audit = json_object_get(json.root, "passwordChange");
	assert_non_null(audit);
	assert_true(json_is_object(audit));
	assert_int_equal(10, json_object_size(audit));

	o = json_object_get(audit, "version");
	assert_non_null(o);

	v = json_object_get(audit, "eventId");
	assert_non_null(v);

	v = json_object_get(audit, "statusCode");
	assert_non_null(v);

	v = json_object_get(audit, "status");
	assert_non_null(v);

	v = json_object_get(audit, "remoteAddress");
	assert_non_null(v);

	v = json_object_get(audit, "userSid");
	assert_non_null(v);

	v = json_object_get(audit, "dn");
	assert_non_null(v);

	v = json_object_get(audit, "transactionId");
	assert_non_null(v);

	v = json_object_get(audit, "sessionId");
	assert_non_null(v);

	v = json_object_get(audit, "action");
	assert_non_null(v);

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
	json_t *audit = NULL;
	json_t *v = NULL;
	json_t *o = NULL;
	time_t before;

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

	before = time(NULL);
	json = password_change_json(module, req, reply);
	assert_int_equal(3, json_object_size(json.root));


	v = json_object_get(json.root, "type");
	assert_non_null(v);
	assert_string_equal("passwordChange", json_string_value(v));

	v = json_object_get(json.root, "timestamp");
	assert_non_null(v);
	assert_true(json_is_string(v));
	check_timestamp(before, json_string_value(v));

	audit = json_object_get(json.root, "passwordChange");
	assert_non_null(audit);
	assert_true(json_is_object(audit));
	assert_int_equal(10, json_object_size(audit));

	o = json_object_get(audit, "version");
	assert_non_null(o);
	check_version(o, PASSWORD_MAJOR,PASSWORD_MINOR);

	v = json_object_get(audit, "eventId");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(EVT_ID_PASSWORD_RESET, json_integer_value(v));

	v = json_object_get(audit, "statusCode");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(LDB_SUCCESS, json_integer_value(v));

	v = json_object_get(audit, "status");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("Success", json_string_value(v));

	v = json_object_get(audit, "remoteAddress");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("ipv4:127.0.0.1:0", json_string_value(v));

	v = json_object_get(audit, "userSid");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(SID, json_string_value(v));

	v = json_object_get(audit, "dn");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(DN, json_string_value(v));

	v = json_object_get(audit, "transactionId");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(TRANSACTION, json_string_value(v));

	v = json_object_get(audit, "sessionId");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(SESSION, json_string_value(v));

	v = json_object_get(audit, "action");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("Reset", json_string_value(v));

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
	json_t *audit = NULL;
	json_t *v = NULL;
	json_t *o = NULL;
	time_t before;

	GUID_from_string(GUID, &guid);

	before = time(NULL);
	json = transaction_json("delete", &guid, 10000099);

	assert_int_equal(3, json_object_size(json.root));


	v = json_object_get(json.root, "type");
	assert_non_null(v);
	assert_string_equal("dsdbTransaction", json_string_value(v));

	v = json_object_get(json.root, "timestamp");
	assert_non_null(v);
	assert_true(json_is_string(v));
	check_timestamp(before, json_string_value(v));

	audit = json_object_get(json.root, "dsdbTransaction");
	assert_non_null(audit);
	assert_true(json_is_object(audit));
	assert_int_equal(4, json_object_size(audit));

	o = json_object_get(audit, "version");
	assert_non_null(o);
	check_version(o, TRANSACTION_MAJOR, TRANSACTION_MINOR);

	v = json_object_get(audit, "transactionId");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(GUID, json_string_value(v));

	v = json_object_get(audit, "action");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("delete", json_string_value(v));

	v = json_object_get(audit, "duration");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(10000099, json_integer_value(v));

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
	json_t *audit = NULL;
	json_t *v = NULL;
	json_t *o = NULL;
	time_t before;

	GUID_from_string(GUID, &guid);

	before = time(NULL);
	json = commit_failure_json(
		"prepare",
		987876,
		LDB_ERR_OPERATIONS_ERROR,
		"because",
		&guid);

	assert_int_equal(3, json_object_size(json.root));


	v = json_object_get(json.root, "type");
	assert_non_null(v);
	assert_string_equal("dsdbTransaction", json_string_value(v));

	v = json_object_get(json.root, "timestamp");
	assert_non_null(v);
	assert_true(json_is_string(v));
	check_timestamp(before, json_string_value(v));

	audit = json_object_get(json.root, "dsdbTransaction");
	assert_non_null(audit);
	assert_true(json_is_object(audit));
	assert_int_equal(7, json_object_size(audit));

	o = json_object_get(audit, "version");
	assert_non_null(o);
	check_version(o, TRANSACTION_MAJOR, TRANSACTION_MINOR);

	v = json_object_get(audit, "transactionId");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(GUID, json_string_value(v));

	v = json_object_get(audit, "action");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("prepare", json_string_value(v));

	v = json_object_get(audit, "statusCode");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(LDB_ERR_OPERATIONS_ERROR, json_integer_value(v));

	v = json_object_get(audit, "status");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("Operations error", json_string_value(v));
	v = json_object_get(audit, "status");
	assert_non_null(v);

	v = json_object_get(audit, "reason");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("because", json_string_value(v));

	v = json_object_get(audit, "duration");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(987876, json_integer_value(v));

	json_free(&json);

}

/*
 * minimal unit test of replicated_update_json, that ensures that all the
 * expected attributes and objects are in the json object.
 */
static void test_replicated_update_json_empty(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	struct ldb_request *req = NULL;
	struct ldb_reply *reply = NULL;
	struct audit_private *audit_private = NULL;
	struct dsdb_extended_replicated_objects *ro = NULL;
	struct repsFromTo1 *source_dsa = NULL;

	struct json_object json;
	json_t *audit = NULL;
	json_t *v = NULL;
	json_t *o = NULL;
	time_t before;


	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);
	audit_private = talloc_zero(ctx, struct audit_private);

	module = talloc_zero(ctx, struct ldb_module);
	module->ldb = ldb;
	ldb_module_set_private(module, audit_private);

	source_dsa = talloc_zero(ctx, struct repsFromTo1);
	ro = talloc_zero(ctx, struct dsdb_extended_replicated_objects);
	ro->source_dsa = source_dsa;
	req = talloc_zero(ctx, struct ldb_request);
	req->op.extended.data = ro;
	req->operation = LDB_EXTENDED;
	reply = talloc_zero(ctx, struct ldb_reply);
	reply->error = LDB_SUCCESS;

	before = time(NULL);
	json = replicated_update_json(module, req, reply);
	assert_int_equal(3, json_object_size(json.root));


	v = json_object_get(json.root, "type");
	assert_non_null(v);
	assert_string_equal("replicatedUpdate", json_string_value(v));

	v = json_object_get(json.root, "timestamp");
	assert_non_null(v);
	assert_true(json_is_string(v));
	check_timestamp(before, json_string_value(v));

	audit = json_object_get(json.root, "replicatedUpdate");
	assert_non_null(audit);
	assert_true(json_is_object(audit));
	assert_int_equal(11, json_object_size(audit));

	o = json_object_get(audit, "version");
	assert_non_null(o);
	check_version(o, REPLICATION_MAJOR, REPLICATION_MINOR);

	v = json_object_get(audit, "statusCode");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(LDB_SUCCESS, json_integer_value(v));

	v = json_object_get(audit, "status");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("Success", json_string_value(v));

	v = json_object_get(audit, "transactionId");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(
		"00000000-0000-0000-0000-000000000000",
		json_string_value(v));

	v = json_object_get(audit, "objectCount");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(0, json_integer_value(v));

	v = json_object_get(audit, "linkCount");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(0, json_integer_value(v));

	v = json_object_get(audit, "partitionDN");
	assert_non_null(v);
	assert_true(json_is_null(v));

	v = json_object_get(audit, "error");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(
		"The operation completed successfully.",
		json_string_value(v));

	v = json_object_get(audit, "errorCode");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(0, json_integer_value(v));

	v = json_object_get(audit, "sourceDsa");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(
		"00000000-0000-0000-0000-000000000000",
		json_string_value(v));

	v = json_object_get(audit, "invocationId");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(
		"00000000-0000-0000-0000-000000000000",
		json_string_value(v));

	json_free(&json);
	TALLOC_FREE(ctx);

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
	json_t *audit = NULL;
	json_t *v = NULL;
	json_t *o = NULL;
	time_t before;


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

	before = time(NULL);
	json = replicated_update_json(module, req, reply);
	assert_int_equal(3, json_object_size(json.root));


	v = json_object_get(json.root, "type");
	assert_non_null(v);
	assert_string_equal("replicatedUpdate", json_string_value(v));

	v = json_object_get(json.root, "timestamp");
	assert_non_null(v);
	assert_true(json_is_string(v));
	check_timestamp(before, json_string_value(v));

	audit = json_object_get(json.root, "replicatedUpdate");
	assert_non_null(audit);
	assert_true(json_is_object(audit));
	assert_int_equal(11, json_object_size(audit));

	o = json_object_get(audit, "version");
	assert_non_null(o);
	check_version(o, REPLICATION_MAJOR, REPLICATION_MINOR);

	v = json_object_get(audit, "statusCode");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(LDB_ERR_NO_SUCH_OBJECT, json_integer_value(v));

	v = json_object_get(audit, "status");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("No such object", json_string_value(v));

	v = json_object_get(audit, "transactionId");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(TRANSACTION, json_string_value(v));

	v = json_object_get(audit, "objectCount");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(808, json_integer_value(v));

	v = json_object_get(audit, "linkCount");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(2910, json_integer_value(v));

	v = json_object_get(audit, "partitionDN");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(DN, json_string_value(v));

	v = json_object_get(audit, "error");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(
		"The request is not supported.",
		json_string_value(v));

	v = json_object_get(audit, "errorCode");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(W_ERROR_V(WERR_NOT_SUPPORTED), json_integer_value(v));

	v = json_object_get(audit, "sourceDsa");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(SOURCE_DSA, json_string_value(v));

	v = json_object_get(audit, "invocationId");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal(INVOCATION_ID, json_string_value(v));

	json_free(&json);
	TALLOC_FREE(ctx);

}

/*
 * minimal unit test of operation_human_readable, that ensures that all the
 * expected attributes and objects are in the json object.
 */
static void test_operation_hr_empty(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	struct ldb_request *req = NULL;
	struct ldb_reply *reply = NULL;
	struct audit_private *audit_private = NULL;

	char *line = NULL;
	const char *rs = NULL;
	regex_t regex;

	int ret;

	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);
	audit_private = talloc_zero(ctx, struct audit_private);

	module = talloc_zero(ctx, struct ldb_module);
	module->ldb = ldb;
	ldb_module_set_private(module, audit_private);

	req = talloc_zero(ctx, struct ldb_request);
	reply = talloc_zero(ctx, struct ldb_reply);
	reply->error = LDB_SUCCESS;

	line = operation_human_readable(ctx, module, req, reply);
	assert_non_null(line);

	/*
	 * We ignore the timestamp to make this test a little easier
	 * to write.
	 */
	rs = 	"\\[Search] at \\["
		"[^[]*"
		"\\] status \\[Success\\] remote host \\[Unknown\\]"
		" SID \\[(NULL SID)\\] DN \\[(null)\\]";

	ret = regcomp(&regex, rs, 0);
	assert_int_equal(0, ret);

	ret = regexec(&regex, line, 0, NULL, 0);
	assert_int_equal(0, ret);

	regfree(&regex);
	TALLOC_FREE(ctx);

}

/*
 * unit test of operation_json, that ensures that all the expected
 * attributes and objects are in the json object.
 */
static void test_operation_hr(void **state)
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

	char *line = NULL;
	const char *rs = NULL;
	regex_t regex;

	int ret;


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
	reply->error = LDB_SUCCESS;

	line = operation_human_readable(ctx, module, req, reply);
	assert_non_null(line);

	/*
	 * We ignore the timestamp to make this test a little easier
	 * to write.
	 */
	rs = 	"\\[Add\\] at \\["
		"[^]]*"
		"\\] status \\[Success\\] "
		"remote host \\[ipv4:127.0.0.1:0\\] "
		"SID \\[S-1-5-21-2470180966-3899876309-2637894779\\] "
		"DN \\[dn=CN=USER,CN=Users,DC=SAMBA,DC=ORG\\] "
		"attributes \\[attribute \\[the-value\\]\\]";

	ret = regcomp(&regex, rs, 0);
	assert_int_equal(0, ret);

	ret = regexec(&regex, line, 0, NULL, 0);
	assert_int_equal(0, ret);

	regfree(&regex);
	TALLOC_FREE(ctx);
}

/*
 * unit test of operation_json, that ensures that all the expected
 * attributes and objects are in the json object.
 * In this case the operation is being performed in a system session.
 */
static void test_as_system_operation_hr(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	struct ldb_request *req = NULL;
	struct ldb_reply *reply = NULL;
	struct audit_private *audit_private = NULL;

	struct tsocket_address *ts = NULL;

	struct auth_session_info *sess = NULL;
	struct auth_session_info *sys_sess = NULL;
	struct security_token *token = NULL;
	struct security_token *sys_token = NULL;
	struct dom_sid sid;
	const char *const SID = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SESSION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const SYS_SESSION = "7130cb06-2062-6a1b-409e-3514c26b1999";
	struct GUID session_id;
	struct GUID sys_session_id;

	struct GUID transaction_id;
	const char *const TRANSACTION = "7130cb06-2062-6a1b-409e-3514c26b1773";

	struct ldb_dn *dn = NULL;
	const char *const DN = "dn=CN=USER,CN=Users,DC=SAMBA,DC=ORG";

	struct ldb_message *msg = NULL;

	char *line = NULL;
	const char *rs = NULL;
	regex_t regex;

	int ret;


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
	ldb_set_opaque(ldb, DSDB_NETWORK_SESSION_INFO, sess);

	sys_sess = talloc_zero(ctx, struct auth_session_info);
	sys_token = talloc_zero(ctx, struct security_token);
	sys_token->num_sids = 1;
	sys_token->sids = discard_const(&global_sid_System);
	sys_sess->security_token = sys_token;
	GUID_from_string(SYS_SESSION, &sys_session_id);
	sess->unique_session_token = sys_session_id;
	ldb_set_opaque(ldb, DSDB_SESSION_INFO, sys_sess);

	msg = talloc_zero(ctx, struct ldb_message);
	dn = ldb_dn_new(ctx, ldb, DN);
	msg->dn = dn;
	ldb_msg_add_string(msg, "attribute", "the-value");

	req = talloc_zero(ctx, struct ldb_request);
	req->operation =  LDB_ADD;
	req->op.add.message = msg;
	reply = talloc_zero(ctx, struct ldb_reply);
	reply->error = LDB_SUCCESS;

	line = operation_human_readable(ctx, module, req, reply);
	assert_non_null(line);

	/*
	 * We ignore the timestamp to make this test a little easier
	 * to write.
	 */
	rs = 	"\\[Add\\] at \\["
		"[^]]*"
		"\\] status \\[Success\\] "
		"remote host \\[ipv4:127.0.0.1:0\\] "
		"SID \\[S-1-5-21-2470180966-3899876309-2637894779\\] "
		"DN \\[dn=CN=USER,CN=Users,DC=SAMBA,DC=ORG\\] "
		"attributes \\[attribute \\[the-value\\]\\]";

	ret = regcomp(&regex, rs, 0);
	assert_int_equal(0, ret);

	ret = regexec(&regex, line, 0, NULL, 0);
	assert_int_equal(0, ret);

	regfree(&regex);
	TALLOC_FREE(ctx);
}

/*
 * minimal unit test of password_change_json, that ensures that all the expected
 * attributes and objects are in the json object.
 */
static void test_password_change_hr_empty(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	struct ldb_request *req = NULL;
	struct ldb_reply *reply = NULL;
	struct audit_private *audit_private = NULL;

	char *line = NULL;
	const char *rs = NULL;
	regex_t regex;
	int ret;

	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);
	audit_private = talloc_zero(ctx, struct audit_private);

	module = talloc_zero(ctx, struct ldb_module);
	module->ldb = ldb;
	ldb_module_set_private(module, audit_private);

	req = talloc_zero(ctx, struct ldb_request);
	reply = talloc_zero(ctx, struct ldb_reply);
	reply->error = LDB_SUCCESS;

	line = password_change_human_readable(ctx, module, req, reply);
	assert_non_null(line);

	/*
	 * We ignore the timestamp to make this test a little easier
	 * to write.
	 */
	rs = 	"\\[Reset] at \\["
		"[^[]*"
		"\\] status \\[Success\\] remote host \\[Unknown\\]"
		" SID \\[(NULL SID)\\] DN \\[(null)\\]";

	ret = regcomp(&regex, rs, 0);
	assert_int_equal(0, ret);

	ret = regexec(&regex, line, 0, NULL, 0);
	assert_int_equal(0, ret);

	regfree(&regex);
	TALLOC_FREE(ctx);
}

/*
 * minimal unit test of password_change_json, that ensures that all the expected
 * attributes and objects are in the json object.
 */
static void test_password_change_hr(void **state)
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

	char *line = NULL;
	const char *rs = NULL;
	regex_t regex;
	int ret;

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

	line = password_change_human_readable(ctx, module, req, reply);
	assert_non_null(line);

	/*
	 * We ignore the timestamp to make this test a little easier
	 * to write.
	 */
	rs = 	"\\[Reset\\] at \\["
		"[^[]*"
		"\\] status \\[Success\\] "
		"remote host \\[ipv4:127.0.0.1:0\\] "
		"SID \\[S-1-5-21-2470180966-3899876309-2637894779\\] "
		"DN \\[dn=CN=USER,CN=Users,DC=SAMBA,DC=ORG\\]";

	ret = regcomp(&regex, rs, 0);
	assert_int_equal(0, ret);

	ret = regexec(&regex, line, 0, NULL, 0);
	assert_int_equal(0, ret);

	regfree(&regex);
	TALLOC_FREE(ctx);

}

/*
 * minimal unit test of transaction_json, that ensures that all the expected
 * attributes and objects are in the json object.
 */
static void test_transaction_hr(void **state)
{

	struct GUID guid;
	const char * const GUID = "7130cb06-2062-6a1b-409e-3514c26b1773";

	char *line = NULL;
	const char *rs = NULL;
	regex_t regex;
	int ret;

	TALLOC_CTX *ctx = talloc_new(NULL);

	GUID_from_string(GUID, &guid);

	line = transaction_human_readable(ctx, "delete", 23);
	assert_non_null(line);

	/*
	 * We ignore the timestamp to make this test a little easier
	 * to write.
	 */
	rs = "\\[delete] at \\[[^[]*\\] duration \\[23\\]";

	ret = regcomp(&regex, rs, 0);
	assert_int_equal(0, ret);

	ret = regexec(&regex, line, 0, NULL, 0);
	assert_int_equal(0, ret);

	regfree(&regex);
	TALLOC_FREE(ctx);

}

/*
 * minimal unit test of commit_failure_hr, that ensures
 * that all the expected conten is in the log entry.
 */
static void test_commit_failure_hr(void **state)
{

	struct GUID guid;
	const char * const GUID = "7130cb06-2062-6a1b-409e-3514c26b1773";

	char *line = NULL;
	const char *rs = NULL;
	regex_t regex;
	int ret;

	TALLOC_CTX *ctx = talloc_new(NULL);

	GUID_from_string(GUID, &guid);

	line = commit_failure_human_readable(
		ctx,
		"commit",
		789345,
		LDB_ERR_OPERATIONS_ERROR,
		"because");

	assert_non_null(line);

	/*
	 * We ignore the timestamp to make this test a little easier
	 * to write.
	 */
	rs = "\\[commit\\] at \\[[^[]*\\] duration \\[789345\\] "
	     "status \\[1\\] reason \\[because\\]";

	ret = regcomp(&regex, rs, 0);
	assert_int_equal(0, ret);

	ret = regexec(&regex, line, 0, NULL, 0);
	assert_int_equal(0, ret);

	regfree(&regex);
	TALLOC_FREE(ctx);
}

static void test_add_transaction_id(void **state)
{
	struct ldb_module  *module = NULL;
	struct ldb_request *req = NULL;
	struct audit_private *audit_private = NULL;
	struct GUID guid;
	const char * const GUID = "7130cb06-2062-6a1b-409e-3514c26b1773";
	struct ldb_control * control = NULL;
	int status;

	TALLOC_CTX *ctx = talloc_new(NULL);

	audit_private = talloc_zero(ctx, struct audit_private);
	GUID_from_string(GUID, &guid);
	audit_private->transaction_guid = guid;

	module = talloc_zero(ctx, struct ldb_module);
	ldb_module_set_private(module, audit_private);

	req = talloc_zero(ctx, struct ldb_request);

	status = add_transaction_id(module, req);
	assert_int_equal(LDB_SUCCESS, status);

	control = ldb_request_get_control(
		req,
		DSDB_CONTROL_TRANSACTION_IDENTIFIER_OID);
	assert_non_null(control);
	assert_memory_equal(
		&audit_private->transaction_guid,
		control->data,
		sizeof(struct GUID));

	TALLOC_FREE(ctx);
}

static void test_log_attributes(void **state)
{
	struct ldb_message *msg = NULL;

	char *buf = NULL;
	char *str = NULL;
	char lv[MAX_LENGTH+2];
	char ex[MAX_LENGTH+80];

	TALLOC_CTX *ctx = talloc_new(NULL);


	/*
	 * Test an empty message
	 * Should get empty attributes representation.
	 */
	buf = talloc_zero(ctx, char);
	msg = talloc_zero(ctx, struct ldb_message);

	str = log_attributes(ctx, buf, LDB_ADD, msg);
	assert_string_equal("", str);

	TALLOC_FREE(str);
	TALLOC_FREE(msg);

	/*
	 * Test a message with a single secret attribute
	 */
	buf = talloc_zero(ctx, char);
	msg = talloc_zero(ctx, struct ldb_message);
	ldb_msg_add_string(msg, "clearTextPassword", "secret");

	str = log_attributes(ctx, buf, LDB_ADD, msg);
	assert_string_equal(
		"clearTextPassword [REDACTED SECRET ATTRIBUTE]",
		str);
	TALLOC_FREE(str);
	/*
	 * Test as a modify message, should add an action
	 * action will be unknown as there are no ACL's set
	 */
	buf = talloc_zero(ctx, char);
	str = log_attributes(ctx, buf, LDB_MODIFY, msg);
	assert_string_equal(
		"unknown: clearTextPassword [REDACTED SECRET ATTRIBUTE]",
		str);

	TALLOC_FREE(str);
	TALLOC_FREE(msg);

	/*
	 * Test a message with a single attribute, single valued attribute
	 */
	buf = talloc_zero(ctx, char);
	msg = talloc_zero(ctx, struct ldb_message);
	ldb_msg_add_string(msg, "attribute", "value");

	str = log_attributes(ctx, buf, LDB_ADD, msg);
	assert_string_equal(
		"attribute [value]",
		str);

	TALLOC_FREE(str);
	TALLOC_FREE(msg);

	/*
	 * Test a message with a single attribute, single valued attribute
	 * And as a modify
	 */
	buf = talloc_zero(ctx, char);
	msg = talloc_zero(ctx, struct ldb_message);
	ldb_msg_add_string(msg, "attribute", "value");

	str = log_attributes(ctx, buf, LDB_MODIFY, msg);
	assert_string_equal(
		"unknown: attribute [value]",
		str);

	TALLOC_FREE(str);
	TALLOC_FREE(msg);

	/*
	 * Test a message with multiple attributes and a multi-valued attribute
	 *
	 */
	buf = talloc_zero(ctx, char);
	msg = talloc_zero(ctx, struct ldb_message);
	ldb_msg_add_string(msg, "attribute01", "value01");
	ldb_msg_add_string(msg, "attribute02", "value02");
	ldb_msg_add_string(msg, "attribute02", "value03");

	str = log_attributes(ctx, buf, LDB_MODIFY, msg);
	assert_string_equal(
		"unknown: attribute01 [value01] "
		"unknown: attribute02 [value02] [value03]",
		str);

	TALLOC_FREE(str);
	TALLOC_FREE(msg);

	/*
	 * Test a message with a single attribute, single valued attribute
	 * with a non printable character. Should be base64 encoded
	 */
	buf = talloc_zero(ctx, char);
	msg = talloc_zero(ctx, struct ldb_message);
	ldb_msg_add_string(msg, "attribute", "value\n");

	str = log_attributes(ctx, buf, LDB_ADD, msg);
	assert_string_equal("attribute {dmFsdWUK}", str);

	TALLOC_FREE(str);
	TALLOC_FREE(msg);

	/*
	 * Test a message with a single valued attribute
	 * with more than MAX_LENGTH characters, should be truncated with
	 * trailing ...
	 */
	buf = talloc_zero(ctx, char);
	msg = talloc_zero(ctx, struct ldb_message);
	memset(lv, '\0', sizeof(lv));
	memset(lv, 'x', MAX_LENGTH+1);
	ldb_msg_add_string(msg, "attribute", lv);

	str = log_attributes(ctx, buf, LDB_ADD, msg);
	snprintf(ex, sizeof(ex), "attribute [%.*s...]", MAX_LENGTH, lv);
	assert_string_equal(ex, str);

	TALLOC_FREE(str);
	TALLOC_FREE(msg);

	TALLOC_FREE(ctx);
}

/*
 * minimal unit test of replicated_update_human_readable
 */
static void test_replicated_update_hr_empty(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	struct ldb_request *req = NULL;
	struct ldb_reply *reply = NULL;
	struct audit_private *audit_private = NULL;
	struct dsdb_extended_replicated_objects *ro = NULL;
	struct repsFromTo1 *source_dsa = NULL;

	const char* line = NULL;
	const char *rs = NULL;
	regex_t regex;
	int ret;

	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);
	audit_private = talloc_zero(ctx, struct audit_private);

	module = talloc_zero(ctx, struct ldb_module);
	module->ldb = ldb;
	ldb_module_set_private(module, audit_private);

	source_dsa = talloc_zero(ctx, struct repsFromTo1);
	ro = talloc_zero(ctx, struct dsdb_extended_replicated_objects);
	ro->source_dsa = source_dsa;
	req = talloc_zero(ctx, struct ldb_request);
	req->op.extended.data = ro;
	req->operation = LDB_EXTENDED;
	reply = talloc_zero(ctx, struct ldb_reply);
	reply->error = LDB_SUCCESS;

	line = replicated_update_human_readable(ctx, module, req, reply);
	assert_non_null(line);
	/*
	 * We ignore the timestamp to make this test a little easier
	 * to write.
	 */
	rs = 	"at \\[[^[]*\\] "
		"status \\[Success\\] "
		"error \\[The operation completed successfully.\\] "
		"partition \\[(null)\\] objects \\[0\\] links \\[0\\] "
		"object \\[00000000-0000-0000-0000-000000000000\\] "
		"invocation \\[00000000-0000-0000-0000-000000000000\\]";

	ret = regcomp(&regex, rs, 0);
	assert_int_equal(0, ret);

	ret = regexec(&regex, line, 0, NULL, 0);
	assert_int_equal(0, ret);

	regfree(&regex);
	TALLOC_FREE(ctx);

}

/*
 * unit test of replicated_update_human_readable
 */
static void test_replicated_update_hr(void **state)
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

	const char* line = NULL;
	const char *rs = NULL;
	regex_t regex;
	int ret;


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

	line = replicated_update_human_readable(ctx, module, req, reply);
	assert_non_null(line);

	/*
	 * We ignore the timestamp to make this test a little easier
	 * to write.
	 */
	rs = 	"at \\[[^[]*\\] "
		"status \\[No such object\\] "
		"error \\[The request is not supported.\\] "
		"partition \\[dn=CN=USER,CN=Users,DC=SAMBA,DC=ORG\\] "
		"objects \\[808\\] links \\[2910\\] "
		"object \\[7130cb06-2062-6a1b-409e-3514c26b1793\\] "
		"invocation \\[7130cb06-2062-6a1b-409e-3514c26b1893\\]";

	ret = regcomp(&regex, rs, 0);
	assert_int_equal(0, ret);

	ret = regexec(&regex, line, 0, NULL, 0);
	assert_int_equal(0, ret);

	regfree(&regex);
	TALLOC_FREE(ctx);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_has_password_changed),
		cmocka_unit_test(test_get_password_action),
		cmocka_unit_test(test_operation_json_empty),
		cmocka_unit_test(test_operation_json),
		cmocka_unit_test(test_as_system_operation_json),
		cmocka_unit_test(test_password_change_json_empty),
		cmocka_unit_test(test_password_change_json),
		cmocka_unit_test(test_transaction_json),
		cmocka_unit_test(test_commit_failure_json),
		cmocka_unit_test(test_replicated_update_json_empty),
		cmocka_unit_test(test_replicated_update_json),
		cmocka_unit_test(test_add_transaction_id),
		cmocka_unit_test(test_operation_hr_empty),
		cmocka_unit_test(test_operation_hr),
		cmocka_unit_test(test_as_system_operation_hr),
		cmocka_unit_test(test_password_change_hr_empty),
		cmocka_unit_test(test_password_change_hr),
		cmocka_unit_test(test_transaction_hr),
		cmocka_unit_test(test_commit_failure_hr),
		cmocka_unit_test(test_log_attributes),
		cmocka_unit_test(test_replicated_update_hr_empty),
		cmocka_unit_test(test_replicated_update_hr),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
