/*
   Unit tests for the dsdb audit logging utility code code in audit_util.c

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

#include "../audit_util.c"

#include "lib/ldb/include/ldb_private.h"

static void test_dsdb_audit_add_ldb_value(void **state)
{
	struct json_object object;
	struct json_object array;
	struct ldb_val val = data_blob_null;
	struct json_t *el  = NULL;
	struct json_t *atr = NULL;
	char* base64 = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);
	/*
	 * Test a non array object
	 */
	object = json_new_object();
	assert_false(json_is_invalid(&object));
	dsdb_audit_add_ldb_value(&object, val);
	assert_true(json_is_invalid(&object));
	json_free(&object);

	array = json_new_array();
	/*
	 * Test a data_blob_null, should encode as a JSON null value.
	 */
	val = data_blob_null;
	dsdb_audit_add_ldb_value(&array, val);
	el = json_array_get(array.root, 0);
	assert_true(json_is_null(el));

	/*
	 * Test a +ve length but a null data ptr, should encode as a null.
	 */
	val = data_blob_null;
	val.length = 1;
	dsdb_audit_add_ldb_value(&array, val);
	el = json_array_get(array.root, 1);
	assert_true(json_is_null(el));

	/*
	 * Test a zero length but a non null data ptr, should encode as a null.
	 */
	val = data_blob_null;
	val.data = discard_const("Data on the stack");
	dsdb_audit_add_ldb_value(&array, val);
	el = json_array_get(array.root, 2);
	assert_true(json_is_null(el));

	/*
	 * Test a printable value.
	 * value should not be encoded
	 * truncated and base64 should be missing
	 */
	val = data_blob_string_const("A value of interest");
	dsdb_audit_add_ldb_value(&array, val);
	el = json_array_get(array.root, 3);
	assert_true(json_is_object(el));
	atr = json_object_get(el, "value");
	assert_true(json_is_string(atr));
	assert_string_equal("A value of interest", json_string_value(atr));
	assert_null(json_object_get(el, "truncated"));
	assert_null(json_object_get(el, "base64"));

	/*
	 * Test non printable value, should be base64 encoded.
	 * truncated should be missing and base64 should be set.
	 */
	val = data_blob_string_const("A value of interest\n");
	dsdb_audit_add_ldb_value(&array, val);
	el = json_array_get(array.root, 4);
	assert_true(json_is_object(el));
	atr = json_object_get(el, "value");
	assert_true(json_is_string(atr));
	assert_string_equal(
		"QSB2YWx1ZSBvZiBpbnRlcmVzdAo=",
		json_string_value(atr));
	atr = json_object_get(el, "base64");
	assert_true(json_is_boolean(atr));
	assert_true(json_boolean(atr));
	assert_null(json_object_get(el, "truncated"));

	/*
	 * test a printable value exactly max bytes long
	 * should not be truncated or encoded.
	 */
	val = data_blob_null;
	val.length = MAX_LENGTH;
	val.data = (unsigned char *)generate_random_str_list(
		ctx,
		MAX_LENGTH,
		"abcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"1234567890!@#$%^&*()");

	dsdb_audit_add_ldb_value(&array, val);

	el = json_array_get(array.root, 5);
	assert_true(json_is_object(el));
	atr = json_object_get(el, "value");
	assert_true(json_is_string(atr));
	assert_int_equal(MAX_LENGTH, strlen(json_string_value(atr)));
	assert_memory_equal(val.data, json_string_value(atr), MAX_LENGTH);

	assert_null(json_object_get(el, "base64"));
	assert_null(json_object_get(el, "truncated"));


	/*
	 * test a printable value exactly max + 1 bytes long
	 * should be truncated and not encoded.
	 */
	val = data_blob_null;
	val.length = MAX_LENGTH + 1;
	val.data = (unsigned char *)generate_random_str_list(
		ctx,
		MAX_LENGTH + 1,
		"abcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"1234567890!@#$%^&*()");

	dsdb_audit_add_ldb_value(&array, val);

	el = json_array_get(array.root, 6);
	assert_true(json_is_object(el));
	atr = json_object_get(el, "value");
	assert_true(json_is_string(atr));
	assert_int_equal(MAX_LENGTH, strlen(json_string_value(atr)));
	assert_memory_equal(val.data, json_string_value(atr), MAX_LENGTH);

	atr = json_object_get(el, "truncated");
	assert_true(json_is_boolean(atr));
	assert_true(json_boolean(atr));

	assert_null(json_object_get(el, "base64"));

	TALLOC_FREE(val.data);

	/*
	 * test a non-printable value exactly max bytes long
	 * should not be truncated but should be encoded.
	 */
	val = data_blob_null;
	val.length = MAX_LENGTH;
	val.data = (unsigned char *)generate_random_str_list(
		ctx,
		MAX_LENGTH,
		"abcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"1234567890!@#$%^&*()");

	val.data[0] = 0x03;
	dsdb_audit_add_ldb_value(&array, val);
	base64 = ldb_base64_encode(ctx, (char*) val.data, MAX_LENGTH);

	el = json_array_get(array.root, 7);
	assert_true(json_is_object(el));
	atr = json_object_get(el, "value");
	assert_true(json_is_string(atr));
	assert_int_equal(strlen(base64), strlen(json_string_value(atr)));
	assert_string_equal(base64, json_string_value(atr));

	atr = json_object_get(el, "base64");
	assert_true(json_is_boolean(atr));
	assert_true(json_boolean(atr));

	assert_null(json_object_get(el, "truncated"));
	TALLOC_FREE(base64);
	TALLOC_FREE(val.data);

	/*
	 * test a non-printable value exactly max + 1 bytes long
	 * should be truncated and encoded.
	 */
	val = data_blob_null;
	val.length = MAX_LENGTH + 1;
	val.data = (unsigned char *)generate_random_str_list(
		ctx,
		MAX_LENGTH + 1,
		"abcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"1234567890!@#$%^&*()");

	val.data[0] = 0x03;
	dsdb_audit_add_ldb_value(&array, val);
	/*
	 * The data is truncated before it is base 64 encoded
	 */
	base64 = ldb_base64_encode(ctx, (char*) val.data, MAX_LENGTH);

	el = json_array_get(array.root, 8);
	assert_true(json_is_object(el));
	atr = json_object_get(el, "value");
	assert_true(json_is_string(atr));
	assert_int_equal(strlen(base64), strlen(json_string_value(atr)));
	assert_string_equal(base64, json_string_value(atr));

	atr = json_object_get(el, "base64");
	assert_true(json_is_boolean(atr));
	assert_true(json_boolean(atr));

	atr = json_object_get(el, "truncated");
	assert_true(json_is_boolean(atr));
	assert_true(json_boolean(atr));

	TALLOC_FREE(base64);
	TALLOC_FREE(val.data);

	json_free(&array);
	TALLOC_FREE(ctx);
}

static void test_dsdb_audit_attributes_json(void **state)
{
	struct ldb_message *msg = NULL;

	struct json_object o;
	json_t *a = NULL;
	json_t *v = NULL;
	json_t *x = NULL;
	json_t *y = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);


	/*
	 * Test an empty message
	 * Should get an empty attributes object
	 */
	msg = talloc_zero(ctx, struct ldb_message);

	o = dsdb_audit_attributes_json(LDB_ADD, msg);
	assert_true(json_is_object(o.root));
	assert_int_equal(0, json_object_size(o.root));
	json_free(&o);

	o = dsdb_audit_attributes_json(LDB_MODIFY, msg);
	assert_true(json_is_object(o.root));
	assert_int_equal(0, json_object_size(o.root));
	json_free(&o);

	/*
	 * Test a message with a single secret attribute
	 * should only have that object and it should have no value
	 * attribute and redacted should be set.
	 */
	msg = talloc_zero(ctx, struct ldb_message);
	ldb_msg_add_string(msg, "clearTextPassword", "secret");

	o = dsdb_audit_attributes_json(LDB_ADD, msg);
	assert_true(json_is_object(o.root));
	assert_int_equal(1, json_object_size(o.root));

	a = json_object_get(o.root, "clearTextPassword");
	assert_int_equal(1, json_object_size(a));

	v = json_object_get(a, "actions");
	assert_true(json_is_array(v));
	assert_int_equal(1, json_array_size(v));

	a = json_array_get(v, 0);
	v = json_object_get(a, "redacted");
	assert_true(json_is_boolean(v));
	assert_true(json_boolean(v));

	json_free(&o);

	/*
	 * Test as a modify message, should add an action attribute
	 */
	o = dsdb_audit_attributes_json(LDB_MODIFY, msg);
	assert_true(json_is_object(o.root));
	assert_int_equal(1, json_object_size(o.root));

	a = json_object_get(o.root, "clearTextPassword");
	assert_true(json_is_object(a));
	assert_int_equal(1, json_object_size(a));

	v = json_object_get(a, "actions");
	assert_true(json_is_array(v));
	assert_int_equal(1, json_array_size(v));

	a = json_array_get(v, 0);
	v = json_object_get(a, "redacted");
	assert_true(json_is_boolean(v));
	assert_true(json_boolean(v));

	v = json_object_get(a, "action");
	assert_true(json_is_string(v));
	assert_string_equal("unknown", json_string_value(v));

	json_free(&o);
	TALLOC_FREE(msg);

	/*
	 * Test a message with a single attribute, single valued attribute
	 */
	msg = talloc_zero(ctx, struct ldb_message);
	ldb_msg_add_string(msg, "attribute", "value");

	o = dsdb_audit_attributes_json(LDB_ADD, msg);
	assert_true(json_is_object(o.root));
	assert_int_equal(1, json_object_size(o.root));

	a = json_object_get(o.root, "attribute");
	assert_true(json_is_object(a));
	assert_int_equal(1, json_object_size(a));

	v = json_object_get(a, "actions");
	assert_true(json_is_array(v));
	assert_int_equal(1, json_array_size(v));

	x = json_array_get(v, 0);
	assert_int_equal(2, json_object_size(x));
	y = json_object_get(x, "action");
	assert_string_equal("add", json_string_value(y));

	y = json_object_get(x, "values");
	assert_true(json_is_array(y));
	assert_int_equal(1, json_array_size(y));

	x = json_array_get(y, 0);
	assert_true(json_is_object(x));
	assert_int_equal(1, json_object_size(x));
	y = json_object_get(x, "value");
	assert_string_equal("value", json_string_value(y));

	json_free(&o);
	TALLOC_FREE(msg);

	/*
	 * Test a message with a single attribute, single valued attribute
	 * And as a modify
	 */
	msg = talloc_zero(ctx, struct ldb_message);
	ldb_msg_add_string(msg, "attribute", "value");

	o = dsdb_audit_attributes_json(LDB_MODIFY, msg);
	assert_true(json_is_object(o.root));
	assert_int_equal(1, json_object_size(o.root));

	a = json_object_get(o.root, "attribute");
	assert_true(json_is_object(a));
	assert_int_equal(1, json_object_size(a));

	v = json_object_get(a, "actions");
	assert_true(json_is_array(v));
	assert_int_equal(1, json_array_size(v));

	x = json_array_get(v, 0);
	assert_int_equal(2, json_object_size(x));
	y = json_object_get(x, "action");
	assert_string_equal("unknown", json_string_value(y));

	y = json_object_get(x, "values");
	assert_true(json_is_array(y));
	assert_int_equal(1, json_array_size(y));

	x = json_array_get(y, 0);
	assert_true(json_is_object(x));
	assert_int_equal(1, json_object_size(x));
	y = json_object_get(x, "value");
	assert_string_equal("value", json_string_value(y));

	json_free(&o);
	TALLOC_FREE(msg);

	/*
	 * Test a message with a multivalues attributres
	 */
	msg = talloc_zero(ctx, struct ldb_message);
	ldb_msg_add_string(msg, "attribute01", "value01");
	ldb_msg_add_string(msg, "attribute02", "value02");
	ldb_msg_add_string(msg, "attribute02", "value03");

	o = dsdb_audit_attributes_json(LDB_ADD, msg);
	assert_true(json_is_object(o.root));
	assert_int_equal(2, json_object_size(o.root));

	a = json_object_get(o.root, "attribute01");
	assert_true(json_is_object(a));
	assert_int_equal(1, json_object_size(a));

	v = json_object_get(a, "actions");
	assert_true(json_is_array(v));
	assert_int_equal(1, json_array_size(v));

	x = json_array_get(v, 0);
	assert_int_equal(2, json_object_size(x));
	y = json_object_get(x, "action");
	assert_string_equal("add", json_string_value(y));

	y = json_object_get(x, "values");
	assert_true(json_is_array(y));
	assert_int_equal(1, json_array_size(y));

	x = json_array_get(y, 0);
	assert_true(json_is_object(x));
	assert_int_equal(1, json_object_size(x));
	y = json_object_get(x, "value");
	assert_string_equal("value01", json_string_value(y));

	a = json_object_get(o.root, "attribute02");
	assert_true(json_is_object(a));
	assert_int_equal(1, json_object_size(a));

	v = json_object_get(a, "actions");
	assert_true(json_is_array(v));
	assert_int_equal(1, json_array_size(v));

	x = json_array_get(v, 0);
	assert_int_equal(2, json_object_size(x));
	y = json_object_get(x, "action");
	assert_string_equal("add", json_string_value(y));

	y = json_object_get(x, "values");
	assert_true(json_is_array(y));
	assert_int_equal(2, json_array_size(y));

	x = json_array_get(y, 0);
	assert_true(json_is_object(x));
	assert_int_equal(1, json_object_size(x));
	v = json_object_get(x, "value");
	assert_string_equal("value02", json_string_value(v));

	x = json_array_get(y, 1);
	assert_true(json_is_object(x));
	assert_int_equal(1, json_object_size(x));
	v = json_object_get(x, "value");
	assert_string_equal("value03", json_string_value(v));

	json_free(&o);
	TALLOC_FREE(msg);

	TALLOC_FREE(ctx);
}

static void test_dsdb_audit_get_remote_address(void **state)
{
	struct ldb_context *ldb = NULL;
	const struct tsocket_address *ts = NULL;
	struct tsocket_address *in = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	/*
	 * Test a freshly initialized ldb
	 * should return NULL
	 */
	ldb = ldb_init(ctx, NULL);
	ts = dsdb_audit_get_remote_address(ldb);
	assert_null(ts);

	/*
	 * opaque set to null, should return NULL
	 */
	ldb_set_opaque(ldb, "remoteAddress", NULL);
	ts = dsdb_audit_get_remote_address(ldb);
	assert_null(ts);

	/*
	 * Ensure that the value set is returned
	 */
	tsocket_address_inet_from_strings(ctx, "ip", "127.0.0.1", 0, &in);
	ldb_set_opaque(ldb, "remoteAddress", in);
	ts = dsdb_audit_get_remote_address(ldb);
	assert_non_null(ts);
	assert_ptr_equal(in, ts);

	TALLOC_FREE(ldb);
	TALLOC_FREE(ctx);

}

static void test_dsdb_audit_get_ldb_error_string(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module *module = NULL;
	const char *s = NULL;
	const char * const text = "Custom reason";

	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);
	module = talloc_zero(ctx, struct ldb_module);
	module->ldb = ldb;

	/*
	 * No ldb error string set should get the default error description for
	 * the status code
	 */
	s = dsdb_audit_get_ldb_error_string(module, LDB_ERR_OPERATIONS_ERROR);
	assert_string_equal("Operations error", s);

	/*
	 * Set the error string that should now be returned instead of the
	 * default description.
	 */
	ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR, text);
	s = dsdb_audit_get_ldb_error_string(module, LDB_ERR_OPERATIONS_ERROR);
	/*
	 * Only test the start of the string as ldb_error adds location data.
	 */
	assert_int_equal(0, strncmp(text, s, strlen(text)));

	TALLOC_FREE(ctx);
}

static void test_dsdb_audit_get_user_sid(void **state)
{
	struct ldb_context *ldb        = NULL;
	struct ldb_module *module      = NULL;
	const struct dom_sid *sid      = NULL;
	struct auth_session_info *sess = NULL;
	struct security_token *token   = NULL;
	struct dom_sid sids[2];
	const char * const SID0 = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SID1 = "S-1-5-21-4284042908-2889457889-3672286761";
	struct dom_sid_buf sid_buf;


	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);
	module = talloc_zero(ctx, struct ldb_module);
	module->ldb = ldb;

	/*
	 * Freshly initialised structures, will be no session data
	 * so expect NULL
	 */
	sid = dsdb_audit_get_user_sid(module);
	assert_null(sid);

	/*
	 * Now add a NULL session info
	 */
	ldb_set_opaque(ldb, DSDB_SESSION_INFO, sess);
	sid = dsdb_audit_get_user_sid(module);
	assert_null(sid);

	/*
	 * Now add a session info with no user sid
	 */
	sess = talloc_zero(ctx, struct auth_session_info);
	ldb_set_opaque(ldb, DSDB_SESSION_INFO, sess);
	sid = dsdb_audit_get_user_sid(module);
	assert_null(sid);

	/*
	 * Now add an empty security token.
	 */
	token = talloc_zero(ctx, struct security_token);
	sess->security_token = token;
	sid = dsdb_audit_get_user_sid(module);
	assert_null(sid);

	/*
	 * Add a single SID
	 */
	string_to_sid(&sids[0], SID0);
	token->num_sids = 1;
	token->sids = sids;
	sid = dsdb_audit_get_user_sid(module);
	assert_non_null(sid);
	dom_sid_str_buf(sid, &sid_buf);
	assert_string_equal(SID0, sid_buf.buf);

	/*
	 * Add a second SID, should still use the first SID
	 */
	string_to_sid(&sids[1], SID1);
	token->num_sids = 2;
	sid = dsdb_audit_get_user_sid(module);
	assert_non_null(sid);
	dom_sid_str_buf(sid, &sid_buf);
	assert_string_equal(SID0, sid_buf.buf);


	/*
	 * Now test a null sid in the first position
	 */
	token->num_sids = 1;
	token->sids = NULL;
	sid = dsdb_audit_get_user_sid(module);
	assert_null(sid);

	TALLOC_FREE(ctx);
}

static void test_dsdb_audit_get_actual_sid(void **state)
{
	struct ldb_context *ldb        = NULL;
	const struct dom_sid *sid      = NULL;
	struct auth_session_info *sess = NULL;
	struct security_token *token   = NULL;
	struct dom_sid sids[2];
	const char * const SID0 = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SID1 = "S-1-5-21-4284042908-2889457889-3672286761";
	struct dom_sid_buf sid_buf;


	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);

	/*
	 * Freshly initialised structures, will be no session data
	 * so expect NULL
	 */
	sid = dsdb_audit_get_actual_sid(ldb);
	assert_null(sid);

	/*
	 * Now add a NULL session info
	 */
	ldb_set_opaque(ldb, DSDB_NETWORK_SESSION_INFO, NULL);
	sid = dsdb_audit_get_actual_sid(ldb);
	assert_null(sid);

	/*
	 * Now add a session info with no user sid
	 */
	sess = talloc_zero(ctx, struct auth_session_info);
	ldb_set_opaque(ldb, DSDB_NETWORK_SESSION_INFO, sess);
	sid = dsdb_audit_get_actual_sid(ldb);
	assert_null(sid);

	/*
	 * Now add an empty security token.
	 */
	token = talloc_zero(ctx, struct security_token);
	sess->security_token = token;
	sid = dsdb_audit_get_actual_sid(ldb);
	assert_null(sid);

	/*
	 * Add a single SID
	 */
	string_to_sid(&sids[0], SID0);
	token->num_sids = 1;
	token->sids = sids;
	sid = dsdb_audit_get_actual_sid(ldb);
	assert_non_null(sid);
	dom_sid_str_buf(sid, &sid_buf);
	assert_string_equal(SID0, sid_buf.buf);

	/*
	 * Add a second SID, should still use the first SID
	 */
	string_to_sid(&sids[1], SID1);
	token->num_sids = 2;
	sid = dsdb_audit_get_actual_sid(ldb);
	assert_non_null(sid);
	dom_sid_str_buf(sid, &sid_buf);
	assert_string_equal(SID0, sid_buf.buf);


	/*
	 * Now test a null sid in the first position
	 */
	token->num_sids = 1;
	token->sids = NULL;
	sid = dsdb_audit_get_actual_sid(ldb);
	assert_null(sid);

	TALLOC_FREE(ctx);
}

static void test_dsdb_audit_is_system_session(void **state)
{
	struct ldb_context *ldb        = NULL;
	struct ldb_module *module      = NULL;
	const struct dom_sid *sid      = NULL;
	struct auth_session_info *sess = NULL;
	struct security_token *token   = NULL;
	struct dom_sid sids[2];
	const char * const SID0 = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SID1 = "S-1-5-21-4284042908-2889457889-3672286761";


	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);
	module = talloc_zero(ctx, struct ldb_module);
	module->ldb = ldb;

	/*
	 * Freshly initialised structures, will be no session data
	 * so expect NULL
	 */
	assert_false(dsdb_audit_is_system_session(module));

	/*
	 * Now add a NULL session info
	 */
	ldb_set_opaque(ldb, DSDB_SESSION_INFO, NULL);
	assert_false(dsdb_audit_is_system_session(module));

	/*
	 * Now add a session info with no user sid
	 */
	sess = talloc_zero(ctx, struct auth_session_info);
	ldb_set_opaque(ldb, DSDB_SESSION_INFO, sess);
	assert_false(dsdb_audit_is_system_session(module));

	/*
	 * Now add an empty security token.
	 */
	token = talloc_zero(ctx, struct security_token);
	sess->security_token = token;
	assert_false(dsdb_audit_is_system_session(module));

	/*
	 * Add a single SID, non system sid
	 */
	string_to_sid(&sids[0], SID0);
	token->num_sids = 1;
	token->sids = sids;
	assert_false(dsdb_audit_is_system_session(module));

	/*
	 * Add the system SID to the second position,
	 * this should be ignored.
	 */
	token->num_sids = 2;
	sids[1] = global_sid_System;
	assert_false(dsdb_audit_is_system_session(module));

	/*
	 * Add a single SID, system sid
	 */
	token->num_sids = 1;
	sids[0] = global_sid_System;
	token->sids = sids;
	assert_true(dsdb_audit_is_system_session(module));

	/*
	 * Add a non system SID to position 2
	 */
	sids[0] = global_sid_System;
	string_to_sid(&sids[1], SID1);
	token->num_sids = 2;
	token->sids = sids;
	assert_true(dsdb_audit_is_system_session(module));

	/*
	 * Now test a null sid in the first position
	 */
	token->num_sids = 1;
	token->sids = NULL;
	sid = dsdb_audit_get_user_sid(module);
	assert_null(sid);

	TALLOC_FREE(ctx);
}

static void test_dsdb_audit_get_unique_session_token(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module *module = NULL;
	struct auth_session_info *sess = NULL;
	const struct GUID *guid;
	const char * const GUID_S = "7130cb06-2062-6a1b-409e-3514c26b1773";
	struct GUID in;
	char *guid_str;
	struct GUID_txt_buf guid_buff;


	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);
	module = talloc_zero(ctx, struct ldb_module);
	module->ldb = ldb;

	/*
	 * Test a freshly initialized ldb
	 * should return NULL
	 */
	guid = dsdb_audit_get_unique_session_token(module);
	assert_null(guid);

	/*
	 * Now add a NULL session info
	 */
	ldb_set_opaque(ldb, DSDB_SESSION_INFO, NULL);
	guid = dsdb_audit_get_unique_session_token(module);
	assert_null(guid);

	/*
	 * Now add a session info with no session id
	 * Note if the memory has not been zeroed correctly all bets are
	 *      probably off.
	 */
	sess = talloc_zero(ctx, struct auth_session_info);
	ldb_set_opaque(ldb, DSDB_SESSION_INFO, sess);
	guid = dsdb_audit_get_unique_session_token(module);
	/*
	 * We will get a GUID, but it's contents will be undefined
	 */
	assert_non_null(guid);

	/*
	 * Now set the session id and confirm that we get it back.
	 */
	GUID_from_string(GUID_S, &in);
	sess->unique_session_token = in;
	guid = dsdb_audit_get_unique_session_token(module);
	assert_non_null(guid);
	guid_str = GUID_buf_string(guid, &guid_buff);
	assert_string_equal(GUID_S, guid_str);

	TALLOC_FREE(ctx);

}

static void test_dsdb_audit_get_actual_unique_session_token(void **state)
{
	struct ldb_context *ldb = NULL;
	struct auth_session_info *sess = NULL;
	const struct GUID *guid;
	const char * const GUID_S = "7130cb06-2062-6a1b-409e-3514c26b1773";
	struct GUID in;
	char *guid_str;
	struct GUID_txt_buf guid_buff;


	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);

	/*
	 * Test a freshly initialized ldb
	 * should return NULL
	 */
	guid = dsdb_audit_get_actual_unique_session_token(ldb);
	assert_null(guid);

	/*
	 * Now add a NULL session info
	 */
	ldb_set_opaque(ldb, DSDB_NETWORK_SESSION_INFO, NULL);
	guid = dsdb_audit_get_actual_unique_session_token(ldb);
	assert_null(guid);

	/*
	 * Now add a session info with no session id
	 * Note if the memory has not been zeroed correctly all bets are
	 *      probably off.
	 */
	sess = talloc_zero(ctx, struct auth_session_info);
	ldb_set_opaque(ldb, DSDB_NETWORK_SESSION_INFO, sess);
	guid = dsdb_audit_get_actual_unique_session_token(ldb);
	/*
	 * We will get a GUID, but it's contents will be undefined
	 */
	assert_non_null(guid);

	/*
	 * Now set the session id and confirm that we get it back.
	 */
	GUID_from_string(GUID_S, &in);
	sess->unique_session_token = in;
	guid = dsdb_audit_get_actual_unique_session_token(ldb);
	assert_non_null(guid);
	guid_str = GUID_buf_string(guid, &guid_buff);
	assert_string_equal(GUID_S, guid_str);

	TALLOC_FREE(ctx);

}

static void test_dsdb_audit_get_remote_host(void **state)
{
	struct ldb_context *ldb = NULL;
	char *rh = NULL;
	struct tsocket_address *in = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);

	/*
	 * Test a freshly initialized ldb
	 * should return "Unknown"
	 */
	rh = dsdb_audit_get_remote_host(ldb, ctx);
	assert_string_equal("Unknown", rh);
	TALLOC_FREE(rh);

	/*
	 * opaque set to null, should return NULL
	 */
	ldb_set_opaque(ldb, "remoteAddress", NULL);
	rh = dsdb_audit_get_remote_host(ldb, ctx);
	assert_string_equal("Unknown", rh);
	TALLOC_FREE(rh);

	/*
	 * Ensure that the value set is returned
	 */
	tsocket_address_inet_from_strings(ctx, "ip", "127.0.0.1", 42, &in);
	ldb_set_opaque(ldb, "remoteAddress", in);
	rh = dsdb_audit_get_remote_host(ldb, ctx);
	assert_string_equal("ipv4:127.0.0.1:42", rh);
	TALLOC_FREE(rh);

	TALLOC_FREE(ctx);

}

static void test_dsdb_audit_get_primary_dn(void **state)
{
	struct ldb_request *req = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_context *ldb = NULL;

	struct ldb_dn *dn = NULL;

	const char * const DN = "dn=CN=USER,CN=Users,DC=SAMBA,DC=ORG";
	const char *s = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	req = talloc_zero(ctx, struct ldb_request);
	msg = talloc_zero(ctx, struct ldb_message);
	ldb = ldb_init(ctx, NULL);
	dn = ldb_dn_new(ctx, ldb, DN);

	/*
	 * Try an empty request.
	 */
	s = dsdb_audit_get_primary_dn(req);
	assert_null(s);

	/*
	 * Now try an add with a null message.
	 */
	req->operation = LDB_ADD;
	req->op.add.message = NULL;
	s = dsdb_audit_get_primary_dn(req);
	assert_null(s);

	/*
	 * Now try an mod with a null message.
	 */
	req->operation = LDB_MODIFY;
	req->op.mod.message = NULL;
	s = dsdb_audit_get_primary_dn(req);
	assert_null(s);

	/*
	 * Now try an add with a missing dn
	 */
	req->operation = LDB_ADD;
	req->op.add.message = msg;
	s = dsdb_audit_get_primary_dn(req);
	assert_null(s);

	/*
	 * Now try a mod with a messing dn
	 */
	req->operation = LDB_ADD;
	req->op.mod.message = msg;
	s = dsdb_audit_get_primary_dn(req);
	assert_null(s);

	/*
	 * Add a dn to the message
	 */
	msg->dn = dn;

	/*
	 * Now try an add with a dn
	 */
	req->operation = LDB_ADD;
	req->op.add.message = msg;
	s = dsdb_audit_get_primary_dn(req);
	assert_non_null(s);
	assert_string_equal(DN, s);

	/*
	 * Now try a mod with a dn
	 */
	req->operation = LDB_MODIFY;
	req->op.mod.message = msg;
	s = dsdb_audit_get_primary_dn(req);
	assert_non_null(s);
	assert_string_equal(DN, s);

	/*
	 * Try a delete without a dn
	 */
	req->operation = LDB_DELETE;
	req->op.del.dn = NULL;
	s = dsdb_audit_get_primary_dn(req);
	assert_null(s);

	/*
	 * Try a delete with a dn
	 */
	req->operation = LDB_DELETE;
	req->op.del.dn = dn;
	s = dsdb_audit_get_primary_dn(req);
	assert_non_null(s);
	assert_string_equal(DN, s);

	/*
	 * Try a rename without a dn
	 */
	req->operation = LDB_RENAME;
	req->op.rename.olddn = NULL;
	s = dsdb_audit_get_primary_dn(req);
	assert_null(s);

	/*
	 * Try a rename with a dn
	 */
	req->operation = LDB_RENAME;
	req->op.rename.olddn = dn;
	s = dsdb_audit_get_primary_dn(req);
	assert_non_null(s);
	assert_string_equal(DN, s);

	/*
	 * Try an extended operation, i.e. one that does not have a DN
	 * associated with it for logging purposes.
	 */
	req->operation = LDB_EXTENDED;
	s = dsdb_audit_get_primary_dn(req);
	assert_null(s);

	TALLOC_FREE(ctx);
}

static void test_dsdb_audit_get_message(void **state)
{
	struct ldb_request *req = NULL;
	struct ldb_message *msg = NULL;
	const struct ldb_message *r = NULL;


	TALLOC_CTX *ctx = talloc_new(NULL);

	req = talloc_zero(ctx, struct ldb_request);
	msg = talloc_zero(ctx, struct ldb_message);

	/*
	 * Test an empty message
	 */
	r = dsdb_audit_get_message(req);
	assert_null(r);

	/*
	 * Test an add message
	 */
	req->operation = LDB_ADD;
	req->op.add.message = msg;
	r = dsdb_audit_get_message(req);
	assert_ptr_equal(msg, r);

	/*
	 * Test a modify message
	 */
	req->operation = LDB_MODIFY;
	req->op.mod.message = msg;
	r = dsdb_audit_get_message(req);
	assert_ptr_equal(msg, r);

	/*
	 * Test a Delete message, i.e. trigger the default case
	 */
	req->operation = LDB_DELETE;
	r = dsdb_audit_get_message(req);
	assert_null(r);

	TALLOC_FREE(ctx);
}

static void test_dsdb_audit_get_secondary_dn(void **state)
{
	struct ldb_request *req = NULL;
	struct ldb_context *ldb = NULL;

	struct ldb_dn *dn = NULL;

	const char * const DN = "dn=CN=USER,CN=Users,DC=SAMBA,DC=ORG";
	const char *s = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	req = talloc_zero(ctx, struct ldb_request);
	ldb = ldb_init(ctx, NULL);
	dn = ldb_dn_new(ctx, ldb, DN);

	/*
	 * Try an empty request.
	 */
	s = dsdb_audit_get_secondary_dn(req);
	assert_null(s);

	/*
	 * Try a rename without a dn
	 */
	req->operation = LDB_RENAME;
	req->op.rename.newdn = NULL;
	s = dsdb_audit_get_secondary_dn(req);
	assert_null(s);

	/*
	 * Try a rename with a dn
	 */
	req->operation = LDB_RENAME;
	req->op.rename.newdn = dn;
	s = dsdb_audit_get_secondary_dn(req);
	assert_non_null(s);
	assert_string_equal(DN, s);

	/*
	 * Try an extended operation, i.e. one that does not have a DN
	 * associated with it for logging purposes.
	 */
	req->operation = LDB_EXTENDED;
	s = dsdb_audit_get_primary_dn(req);
	assert_null(s);

	TALLOC_FREE(ctx);
}

static void test_dsdb_audit_get_operation_name(void **state)
{
	struct ldb_request *req = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	req = talloc_zero(ctx, struct ldb_request);

	req->operation =  LDB_SEARCH;
	assert_string_equal("Search", dsdb_audit_get_operation_name(req));

	req->operation =  LDB_ADD;
	assert_string_equal("Add", dsdb_audit_get_operation_name(req));

	req->operation =  LDB_MODIFY;
	assert_string_equal("Modify", dsdb_audit_get_operation_name(req));

	req->operation =  LDB_DELETE;
	assert_string_equal("Delete", dsdb_audit_get_operation_name(req));

	req->operation =  LDB_RENAME;
	assert_string_equal("Rename", dsdb_audit_get_operation_name(req));

	req->operation =  LDB_EXTENDED;
	assert_string_equal("Extended", dsdb_audit_get_operation_name(req));

	req->operation =  LDB_REQ_REGISTER_CONTROL;
	assert_string_equal(
		"Register Control",
		dsdb_audit_get_operation_name(req));

	req->operation =  LDB_REQ_REGISTER_PARTITION;
	assert_string_equal(
		"Register Partition",
		dsdb_audit_get_operation_name(req));

	/*
	 * Trigger the default case
	 */
	req->operation =  -1;
	assert_string_equal("Unknown", dsdb_audit_get_operation_name(req));

	TALLOC_FREE(ctx);
}

static void test_dsdb_audit_get_modification_action(void **state)
{
	assert_string_equal(
		"add",
		dsdb_audit_get_modification_action(LDB_FLAG_MOD_ADD));
	assert_string_equal(
		"delete",
		dsdb_audit_get_modification_action(LDB_FLAG_MOD_DELETE));
	assert_string_equal(
		"replace",
		dsdb_audit_get_modification_action(LDB_FLAG_MOD_REPLACE));
	/*
	 * Trigger the default case
	 */
	assert_string_equal(
		"unknown",
		dsdb_audit_get_modification_action(0));
}

static void test_dsdb_audit_is_password_attribute(void **state)
{
	assert_true(dsdb_audit_is_password_attribute("userPassword"));
	assert_true(dsdb_audit_is_password_attribute("clearTextPassword"));
	assert_true(dsdb_audit_is_password_attribute("unicodePwd"));
	assert_true(dsdb_audit_is_password_attribute("dBCSPwd"));

	assert_false(dsdb_audit_is_password_attribute("xserPassword"));
}

static void test_dsdb_audit_redact_attribute(void **state)
{
	assert_true(dsdb_audit_redact_attribute("userPassword"));

	assert_true(dsdb_audit_redact_attribute("pekList"));
	assert_true(dsdb_audit_redact_attribute("clearTextPassword"));
	assert_true(dsdb_audit_redact_attribute("initialAuthIncoming"));

	assert_false(dsdb_audit_redact_attribute("supaskrt"));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_dsdb_audit_add_ldb_value),
		cmocka_unit_test(test_dsdb_audit_attributes_json),
		cmocka_unit_test(test_dsdb_audit_get_remote_address),
		cmocka_unit_test(test_dsdb_audit_get_ldb_error_string),
		cmocka_unit_test(test_dsdb_audit_get_user_sid),
		cmocka_unit_test(test_dsdb_audit_get_actual_sid),
		cmocka_unit_test(test_dsdb_audit_is_system_session),
		cmocka_unit_test(test_dsdb_audit_get_unique_session_token),
		cmocka_unit_test(test_dsdb_audit_get_actual_unique_session_token),
		cmocka_unit_test(test_dsdb_audit_get_remote_host),
		cmocka_unit_test(test_dsdb_audit_get_primary_dn),
		cmocka_unit_test(test_dsdb_audit_get_message),
		cmocka_unit_test(test_dsdb_audit_get_secondary_dn),
		cmocka_unit_test(test_dsdb_audit_get_operation_name),
		cmocka_unit_test(test_dsdb_audit_get_modification_action),
		cmocka_unit_test(test_dsdb_audit_is_password_attribute),
		cmocka_unit_test(test_dsdb_audit_redact_attribute),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
