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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <unistd.h>
#include <cmocka.h>

int ldb_group_audit_log_module_init(const char *version);
#include "../group_audit.c"

#include "lib/ldb/include/ldb_private.h"
#include <regex.h>

/*
 * Mock version of dsdb_search_one
 */
struct ldb_dn *g_basedn = NULL;
enum ldb_scope g_scope;
const char * const *g_attrs = NULL;
uint32_t g_dsdb_flags;
const char *g_exp_fmt;
const char *g_dn = NULL;
int g_status = LDB_SUCCESS;

int dsdb_search_one(struct ldb_context *ldb,
		    TALLOC_CTX *mem_ctx,
		    struct ldb_message **msg,
		    struct ldb_dn *basedn,
		    enum ldb_scope scope,
		    const char * const *attrs,
		    uint32_t dsdb_flags,
		    const char *exp_fmt, ...) _PRINTF_ATTRIBUTE(8, 9)
{
	struct ldb_dn *dn = ldb_dn_new(mem_ctx, ldb, g_dn);
	struct ldb_message *m = talloc_zero(mem_ctx, struct ldb_message);
	m->dn = dn;
	*msg = m;

	g_basedn = basedn;
	g_scope = scope;
	g_attrs = attrs;
	g_dsdb_flags = dsdb_flags;
	g_exp_fmt = exp_fmt;

	return g_status;
}

/*
 * Mocking for audit_log_hr to capture the called parameters
 */
const char *audit_log_hr_prefix = NULL;
const char *audit_log_hr_message = NULL;
int audit_log_hr_debug_class = 0;
int audit_log_hr_debug_level = 0;

static void audit_log_hr_init(void)
{
	audit_log_hr_prefix = NULL;
	audit_log_hr_message = NULL;
	audit_log_hr_debug_class = 0;
	audit_log_hr_debug_level = 0;
}

void audit_log_human_text(
	const char *prefix,
	const char *message,
	int debug_class,
	int debug_level)
{
	audit_log_hr_prefix = prefix;
	audit_log_hr_message = message;
	audit_log_hr_debug_class = debug_class;
	audit_log_hr_debug_level = debug_level;
}

/*
 * Test helper to check ISO 8601 timestamps for validity
 */
static void check_timestamp(time_t before, const char *timestamp)
{
	int rc;
	int usec, tz;
	char c[2];
	struct tm tm;
	time_t after;
	time_t actual;


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
	 */
	assert_true(difftime(actual, before) >= 0);
	assert_true(difftime(after, actual) >= 0);
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

static void test_get_transaction_id(void **state)
{
	struct ldb_request *req = NULL;
	struct GUID *guid;
	const char * const ID = "7130cb06-2062-6a1b-409e-3514c26b1773";
	char *guid_str = NULL;
	struct GUID_txt_buf guid_buff;


	TALLOC_CTX *ctx = talloc_new(NULL);


	/*
	 * No transaction id, should return a zero guid
	 */
	req = talloc_zero(ctx, struct ldb_request);
	guid = get_transaction_id(req);
	assert_null(guid);
	TALLOC_FREE(req);

	/*
	 * And now test with the transaction_id set
	 */
	req = talloc_zero(ctx, struct ldb_request);
	assert_non_null(req);
	add_transaction_id(req, ID);

	guid = get_transaction_id(req);
	guid_str = GUID_buf_string(guid, &guid_buff);
	assert_string_equal(ID, guid_str);
	TALLOC_FREE(req);

	TALLOC_FREE(ctx);
}

static void test_audit_group_hr(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	struct ldb_request *req = NULL;

	struct tsocket_address *ts = NULL;

	const char *const SID = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SESSION = "7130cb06-2062-6a1b-409e-3514c26b1773";

	struct GUID transaction_id;
	const char *const TRANSACTION = "7130cb06-2062-6a1b-409e-3514c26b1773";


	char *line = NULL;
	const char *rs = NULL;
	regex_t regex;
	int ret;


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

	line = audit_group_human_readable(
		ctx,
		module,
		req,
		"the-action",
		"the-user-name",
		"the-group-name",
		LDB_ERR_OPERATIONS_ERROR);
	assert_non_null(line);

	rs = 	"\\[the-action\\] at \\["
		"[^]]*"
		"\\] status \\[Operations error\\] "
		"Remote host \\[ipv4:127.0.0.1:0\\] "
		"SID \\[S-1-5-21-2470180966-3899876309-2637894779\\] "
		"Group \\[the-group-name\\] "
		"User \\[the-user-name\\]";

	ret = regcomp(&regex, rs, 0);
	assert_int_equal(0, ret);

	ret = regexec(&regex, line, 0, NULL, 0);
	assert_int_equal(0, ret);

	regfree(&regex);
	TALLOC_FREE(ctx);

}

/*
 * test get_parsed_dns
 * For this test we assume Valgrind or Address Sanitizer will detect any over
 * runs. Also we don't care that the values are DN's only that the value in the
 * element is copied to the parsed_dns.
 */
static void test_get_parsed_dns(void **state)
{
	struct ldb_message_element *el = NULL;
	struct parsed_dn *dns = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	el = talloc_zero(ctx, struct ldb_message_element);

	/*
	 * empty element, zero dns
	 */
	dns = get_parsed_dns(ctx, el);
	assert_null(dns);

	/*
	 * one entry
	 */
	el->num_values = 1;
	el->values = talloc_zero_array(ctx, DATA_BLOB, 1);
	el->values[0] = data_blob_string_const("The first value");

	dns = get_parsed_dns(ctx, el);

	assert_ptr_equal(el->values[0].data, dns[0].v->data);
	assert_int_equal(el->values[0].length, dns[0].v->length);

	TALLOC_FREE(dns);
	TALLOC_FREE(el);


	/*
	 * Multiple values
	 */
	el = talloc_zero(ctx, struct ldb_message_element);
	el->num_values = 2;
	el->values = talloc_zero_array(ctx, DATA_BLOB, 2);
	el->values[0] = data_blob_string_const("The first value");
	el->values[0] = data_blob_string_const("The second value");

	dns = get_parsed_dns(ctx, el);

	assert_ptr_equal(el->values[0].data, dns[0].v->data);
	assert_int_equal(el->values[0].length, dns[0].v->length);

	assert_ptr_equal(el->values[1].data, dns[1].v->data);
	assert_int_equal(el->values[1].length, dns[1].v->length);

	TALLOC_FREE(ctx);
}

static void test_dn_compare(void **state)
{

	struct ldb_context *ldb = NULL;
	struct parsed_dn *a;
	DATA_BLOB ab;

	struct parsed_dn *b;
	DATA_BLOB bb;

	int res;

	TALLOC_CTX *ctx = talloc_new(NULL);
	const struct GUID *ZERO_GUID = talloc_zero(ctx, struct GUID);

	ldb = ldb_init(ctx, NULL);
	ldb_register_samba_handlers(ldb);


	/*
	 * Identical binary DN's
	 */
	ab = data_blob_string_const(
		"<GUID=fbee08fd-6f75-4bd4-af3f-e4f063a6379e>;"
		"OU=Domain Controllers,DC=ad,DC=testing,DC=samba,DC=org");
	a = talloc_zero(ctx, struct parsed_dn);
	a->v = &ab;

	bb = data_blob_string_const(
		"<GUID=fbee08fd-6f75-4bd4-af3f-e4f063a6379e>;"
		"OU=Domain Controllers,DC=ad,DC=testing,DC=samba,DC=org");
	b = talloc_zero(ctx, struct parsed_dn);
	b->v = &bb;

	res = dn_compare(ctx, ldb, a, b);
	assert_int_equal(BINARY_EQUAL, res);
	/*
	 * DN's should not have been parsed
	 */
	assert_null(a->dsdb_dn);
	assert_memory_equal(ZERO_GUID, &a->guid, sizeof(struct GUID));
	assert_null(b->dsdb_dn);
	assert_memory_equal(ZERO_GUID, &b->guid, sizeof(struct GUID));

	TALLOC_FREE(a);
	TALLOC_FREE(b);

	/*
	 * differing binary DN's but equal GUID's
	 */
	ab = data_blob_string_const(
		"<GUID=efdc91e5-5a5a-493e-9606-166ed0c2651e>;"
		"OU=Domain Controllers,DC=ad,DC=testing,DC=samba,DC=com");
	a = talloc_zero(ctx, struct parsed_dn);
	a->v = &ab;

	bb = data_blob_string_const(
		"<GUID=efdc91e5-5a5a-493e-9606-166ed0c2651e>;"
		"OU=Domain Controllers,DC=ad,DC=testing,DC=samba,DC=org");
	b = talloc_zero(ctx, struct parsed_dn);
	b->v = &bb;

	res = dn_compare(ctx, ldb, a, b);
	assert_int_equal(EQUAL, res);
	/*
	 * DN's should have been parsed
	 */
	assert_non_null(a->dsdb_dn);
	assert_memory_not_equal(ZERO_GUID, &a->guid, sizeof(struct GUID));
	assert_non_null(b->dsdb_dn);
	assert_memory_not_equal(ZERO_GUID, &b->guid, sizeof(struct GUID));

	TALLOC_FREE(a);
	TALLOC_FREE(b);

	/*
	 * differing binary DN's but and second guid greater
	 */
	ab = data_blob_string_const(
		"<GUID=efdc91e5-5a5a-493e-9606-166ed0c2651d>;"
		"OU=Domain Controllers,DC=ad,DC=testing,DC=samba,DC=com");
	a = talloc_zero(ctx, struct parsed_dn);
	a->v = &ab;

	bb = data_blob_string_const(
		"<GUID=efdc91e5-5a5a-493e-9606-166ed0c2651e>;"
		"OU=Domain Controllers,DC=ad,DC=testing,DC=samba,DC=org");
	b = talloc_zero(ctx, struct parsed_dn);
	b->v = &bb;

	res = dn_compare(ctx, ldb, a, b);
	assert_int_equal(GREATER_THAN, res);
	/*
	 * DN's should have been parsed
	 */
	assert_non_null(a->dsdb_dn);
	assert_memory_not_equal(ZERO_GUID, &a->guid, sizeof(struct GUID));
	assert_non_null(b->dsdb_dn);
	assert_memory_not_equal(ZERO_GUID, &b->guid, sizeof(struct GUID));

	TALLOC_FREE(a);
	TALLOC_FREE(b);

	/*
	 * differing binary DN's but and second guid less
	 */
	ab = data_blob_string_const(
		"<GUID=efdc91e5-5a5a-493e-9606-166ed0c2651d>;"
		"OU=Domain Controllers,DC=ad,DC=testing,DC=samba,DC=com");
	a = talloc_zero(ctx, struct parsed_dn);
	a->v = &ab;

	bb = data_blob_string_const(
		"<GUID=efdc91e5-5a5a-493e-9606-166ed0c2651c>;"
		"OU=Domain Controllers,DC=ad,DC=testing,DC=samba,DC=org");
	b = talloc_zero(ctx, struct parsed_dn);
	b->v = &bb;

	res = dn_compare(ctx, ldb, a, b);
	assert_int_equal(LESS_THAN, res);
	/*
	 * DN's should have been parsed
	 */
	assert_non_null(a->dsdb_dn);
	assert_memory_not_equal(ZERO_GUID, &a->guid, sizeof(struct GUID));
	assert_non_null(b->dsdb_dn);
	assert_memory_not_equal(ZERO_GUID, &b->guid, sizeof(struct GUID));

	TALLOC_FREE(a);
	TALLOC_FREE(b);

	TALLOC_FREE(ctx);
}

static void test_get_primary_group_dn(void **state)
{

	struct ldb_context *ldb = NULL;
	struct ldb_module *module = NULL;
	const uint32_t RID = 71;
	struct dom_sid sid;
	const char *SID = "S-1-5-21-2470180966-3899876309-2637894779";
	const char *DN = "OU=Things,DC=ad,DC=testing,DC=samba,DC=org";
	const char *dn;

	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_init(ctx, NULL);
	ldb_register_samba_handlers(ldb);

	module = talloc_zero(ctx, struct ldb_module);
	module->ldb = ldb;

	/*
	 * Pass an empty dom sid this will cause dom_sid_split_rid to fail;
	 * assign to sid.num_auths to suppress a valgrind warning.
	 */
	sid.num_auths = 0;
	dn = get_primary_group_dn(ctx, module, &sid, RID);
	assert_null(dn);

	/*
	 * A valid dom sid
	 */
	assert_true(string_to_sid(&sid, SID));
	g_dn = DN;
	dn = get_primary_group_dn(ctx, module, &sid, RID);
	assert_non_null(dn);
	assert_string_equal(DN, dn);
	assert_int_equal(LDB_SCOPE_BASE, g_scope);
	assert_int_equal(0, g_dsdb_flags);
	assert_null(g_attrs);
	assert_null(g_exp_fmt);
	assert_string_equal
		("<SID=S-1-5-21-2470180966-3899876309-71>",
		ldb_dn_get_extended_linearized(ctx, g_basedn, 1));

	/*
	 * Test dsdb search failure
	 */
	g_status = LDB_ERR_NO_SUCH_OBJECT;
	dn = get_primary_group_dn(ctx, module, &sid, RID);
	assert_null(dn);

	TALLOC_FREE(ldb);
	TALLOC_FREE(ctx);
}

/*
 * Mocking for audit_log_json to capture the called parameters
 */
const char *audit_log_json_prefix = NULL;
struct json_object *audit_log_json_message = NULL;
int audit_log_json_debug_class = 0;
int audit_log_json_debug_level = 0;

static void audit_log_json_init(void)
{
	audit_log_json_prefix = NULL;
	audit_log_json_message = NULL;
	audit_log_json_debug_class = 0;
	audit_log_json_debug_level = 0;
}

void audit_log_json(
	const char* prefix,
	struct json_object* message,
	int debug_class,
	int debug_level)
{
	audit_log_json_prefix = prefix;
	audit_log_json_message = message;
	audit_log_json_debug_class = debug_class;
	audit_log_json_debug_level = debug_level;
}

/*
 * Mocking for audit_message_send to capture the called parameters
 */
struct imessaging_context *audit_message_send_msg_ctx = NULL;
const char *audit_message_send_server_name = NULL;
uint32_t audit_message_send_message_type = 0;
struct json_object *audit_message_send_message = NULL;

static void audit_message_send_init(void) {
	audit_message_send_msg_ctx = NULL;
	audit_message_send_server_name = NULL;
	audit_message_send_message_type = 0;
	audit_message_send_message = NULL;
}
void audit_message_send(
	struct imessaging_context *msg_ctx,
	const char *server_name,
	uint32_t message_type,
	struct json_object *message)
{
	audit_message_send_msg_ctx = msg_ctx;
	audit_message_send_server_name = server_name;
	audit_message_send_message_type = message_type;
	audit_message_send_message = message;
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


	struct json_object json;
	json_t *audit = NULL;
	json_t *v = NULL;
	json_t *o = NULL;
	time_t before;


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

	before = time(NULL);
	json = audit_group_json(
		module,
		req,
		"the-action",
		"the-user-name",
		"the-group-name",
		LDB_ERR_OPERATIONS_ERROR);
	assert_int_equal(3, json_object_size(json.root));

	v = json_object_get(json.root, "type");
	assert_non_null(v);
	assert_string_equal("groupChange", json_string_value(v));

	v = json_object_get(json.root, "timestamp");
	assert_non_null(v);
	assert_true(json_is_string(v));
	check_timestamp(before, json_string_value(v));

	audit = json_object_get(json.root, "groupChange");
	assert_non_null(audit);
	assert_true(json_is_object(audit));
	assert_int_equal(10, json_object_size(audit));

	o = json_object_get(audit, "version");
	assert_non_null(o);
	check_version(o, AUDIT_MAJOR, AUDIT_MINOR);

	v = json_object_get(audit, "statusCode");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(LDB_ERR_OPERATIONS_ERROR, json_integer_value(v));

	v = json_object_get(audit, "status");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("Operations error", json_string_value(v));

	v = json_object_get(audit, "user");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("the-user-name", json_string_value(v));

	v = json_object_get(audit, "group");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("the-group-name", json_string_value(v));

	v = json_object_get(audit, "action");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("the-action", json_string_value(v));

	json_free(&json);
	TALLOC_FREE(ctx);

}

static void test_place_holder(void **state)
{
	audit_log_json_init();
	audit_log_hr_init();
	audit_message_send_init();
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
		cmocka_unit_test(test_place_holder),
		cmocka_unit_test(test_get_transaction_id),
		cmocka_unit_test(test_audit_group_hr),
		cmocka_unit_test(test_get_parsed_dns),
		cmocka_unit_test(test_dn_compare),
		cmocka_unit_test(test_get_primary_group_dn),

	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
