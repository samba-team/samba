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
struct ldb_result *g_result = NULL;

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

int dsdb_module_search_dn(
	struct ldb_module *module,
	TALLOC_CTX *mem_ctx,
	struct ldb_result **res,
	struct ldb_dn *basedn,
	const char * const *attrs,
	uint32_t dsdb_flags,
	struct ldb_request *parent)
{

	g_basedn = basedn;
	g_attrs = attrs;
	g_dsdb_flags = dsdb_flags;

	*res = g_result;

	return g_status;
}
/*
 * Mock version of audit_log_json
 */

#define MAX_EXPECTED_MESSAGES 16
static struct json_object messages[MAX_EXPECTED_MESSAGES];
static size_t messages_sent = 0;

void audit_message_send(
	struct imessaging_context *msg_ctx,
	const char *server_name,
	uint32_t message_type,
	struct json_object *message)
{
	messages[messages_sent].root = json_deep_copy(message->root);
	messages[messages_sent].valid = message->valid;
	messages_sent++;
}

#define check_group_change_message(m, u, a, e)                                 \
	_check_group_change_message(m, u, a, e, __FILE__, __LINE__);
/*
 * declare the internal cmocka cm_print_error so that we can output messages
 * in sub unit format
 */
void cm_print_error(const char * const format, ...);

/*
 * Validate a group change JSON audit message
 *
 * It should contain 3 elements.
 * Have a type of "groupChange"
 * Have a groupChange element
 *
 * The group change element should have 10 elements.
 *
 * There should be a user element matching the expected value
 * There should be an action matching the expected value
 */
static void _check_group_change_message(const int message,
					const char *user,
					const char *action,
					enum event_id_type event_id,
					const char *file,
					const int line)
{
	struct json_object json;
	json_t *audit = NULL;
	json_t *v = NULL;
	const char* value;
	int int_value;
	int cmp;

	json = messages[message];

	/*
	 * Validate the root JSON element
	 * check the number of elements
	 */
	if (json_object_size(json.root) != 3) {
		cm_print_error(
		    "Unexpected number of elements in root %zu != %d\n",
		    json_object_size(json.root),
		    3);
		_fail(file, line);
	}

	/*
	 * Check the type element
	 */
	v = json_object_get(json.root, "type");
	if (v == NULL) {
		cm_print_error( "No \"type\" element\n");
		_fail(file, line);
	}

	value = json_string_value(v);
	cmp = strcmp("groupChange", value);
	if (cmp != 0) {
		cm_print_error(
		    "Unexpected type \"%s\" != \"groupChange\"\n",
		    value);
		_fail(file, line);
	}


	audit = json_object_get(json.root, "groupChange");
	if (audit == NULL) {
		cm_print_error("No groupChange element\n");
		_fail(file, line);
	}

	/*
	 * Validate the groupChange element
	 */
	if ((event_id == EVT_ID_NONE && json_object_size(audit) != 10) ||
	    (event_id != EVT_ID_NONE && json_object_size(audit) != 11)) {
		cm_print_error("Unexpected number of elements in groupChange "
			       "%zu != %d\n",
			       json_object_size(audit),
			       11);
		_fail(file, line);
	}
	/*
	 * Validate the user element
	 */
	v = json_object_get(audit, "user");
	if (v == NULL) {
		cm_print_error( "No user element\n");
		_fail(file, line);
	}

	value = json_string_value(v);
	cmp = strcmp(user, value);
	if (cmp != 0) {
		cm_print_error(
		    "Unexpected user name \"%s\" != \"%s\"\n",
		    value,
		    user);
		_fail(file, line);
	}
	/*
	 * Validate the action element
	 */
	v = json_object_get(audit, "action");
	if (v == NULL) {
		cm_print_error( "No action element\n");
		_fail(file, line);
	}

	value = json_string_value(v);
	cmp = strcmp(action, value);
	if (cmp != 0) {
		print_error(
		    "Unexpected action \"%s\" != \"%s\"\n",
		    value,
		    action);
		_fail(file, line);
	}

	/*
	 * Validate the eventId element
	 */
	v = json_object_get(audit, "eventId");
	if (event_id == EVT_ID_NONE) {
		if (v != NULL) {
			int_value = json_integer_value(v);
			cm_print_error("Unexpected eventId \"%d\", it should "
				       "NOT be present",
				       int_value);
			_fail(file, line);
		}
	}
	else {
		if (v == NULL) {
			cm_print_error("No eventId element\n");
			_fail(file, line);
		}

		int_value = json_integer_value(v);
		if (int_value != event_id) {
			cm_print_error("Unexpected eventId \"%d\" != \"%d\"\n",
				       int_value,
				       event_id);
			_fail(file, line);
		}
	}
}

#define check_timestamp(b, t)\
	_check_timestamp(b, t, __FILE__, __LINE__);
/*
 * Test helper to check ISO 8601 timestamps for validity
 */
static void _check_timestamp(
	time_t before,
	const char *timestamp,
	const char *file,
	const int line)
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
	 * The time stamp should be before <= actual <= after
	 */
	if (difftime(actual, before) < 0) {
		char buffer[40];
		strftime(buffer,
			 sizeof(buffer)-1,
			 "%Y-%m-%dT%T",
			 localtime(&before));
		cm_print_error(
		    "time stamp \"%s\" is before start time \"%s\"\n",
		    timestamp,
		    buffer);
		_fail(file, line);
	}
	if (difftime(after, actual) < 0) {
		char buffer[40];
		strftime(buffer,
			 sizeof(buffer)-1,
			 "%Y-%m-%dT%T",
			 localtime(&after));
		cm_print_error(
		    "time stamp \"%s\" is after finish time \"%s\"\n",
		    timestamp,
		    buffer);
		_fail(file, line);
	}
}

#define check_version(v, m, n)\
	_check_version(v, m, n, __FILE__, __LINE__);
/*
 * Test helper to validate a version object.
 */
static void _check_version(
	struct json_t *version,
	int major,
	int minor,
	const char* file,
	const int line)
{
	struct json_t *v = NULL;
	int value;

	if (!json_is_object(version)) {
		cm_print_error("version is not a JSON object\n");
		_fail(file, line);
	}

	if (json_object_size(version) != 2) {
		cm_print_error(
		    "Unexpected number of elements in version %zu != %d\n",
		    json_object_size(version),
		    2);
		_fail(file, line);
	}

	/*
	 * Validate the major version number element
	 */
	v = json_object_get(version, "major");
	if (v == NULL) {
		cm_print_error( "No major element\n");
		_fail(file, line);
	}

	value = json_integer_value(v);
	if (value != major) {
		print_error(
		    "Unexpected major version number \"%d\" != \"%d\"\n",
		    value,
		    major);
		_fail(file, line);
	}

	/*
	 * Validate the minor version number element
	 */
	v = json_object_get(version, "minor");
	if (v == NULL) {
		cm_print_error( "No minor element\n");
		_fail(file, line);
	}

	value = json_integer_value(v);
	if (value != minor) {
		print_error(
		    "Unexpected minor version number \"%d\" != \"%d\"\n",
		    value,
		    minor);
		_fail(file, line);
	}
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

	enum event_id_type event_id = EVT_ID_USER_ADDED_TO_GLOBAL_SEC_GROUP;

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
	json = audit_group_json(module,
				req,
				"the-action",
				"the-user-name",
				"the-group-name",
				event_id,
				LDB_SUCCESS);
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
	assert_int_equal(11, json_object_size(audit));

	o = json_object_get(audit, "version");
	assert_non_null(o);
	check_version(o, AUDIT_MAJOR, AUDIT_MINOR);

	v = json_object_get(audit, "eventId");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(EVT_ID_USER_ADDED_TO_GLOBAL_SEC_GROUP,
			 json_integer_value(v));

	v = json_object_get(audit, "statusCode");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(LDB_SUCCESS, json_integer_value(v));

	v = json_object_get(audit, "status");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("Success", json_string_value(v));

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

static void test_audit_group_json_error(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	struct ldb_request *req = NULL;

	struct tsocket_address *ts = NULL;

	const char *const SID = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SESSION = "7130cb06-2062-6a1b-409e-3514c26b1773";

	struct GUID transaction_id;
	const char *const TRANSACTION = "7130cb06-2062-6a1b-409e-3514c26b1773";

	enum event_id_type event_id = EVT_ID_USER_ADDED_TO_GLOBAL_SEC_GROUP;

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
	json = audit_group_json(module,
				req,
				"the-action",
				"the-user-name",
				"the-group-name",
				event_id,
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
	assert_int_equal(11, json_object_size(audit));

	o = json_object_get(audit, "version");
	assert_non_null(o);
	check_version(o, AUDIT_MAJOR, AUDIT_MINOR);

	v = json_object_get(audit, "eventId");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(
		EVT_ID_USER_ADDED_TO_GLOBAL_SEC_GROUP,
		json_integer_value(v));

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

static void test_audit_group_json_no_event(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	struct ldb_request *req = NULL;

	struct tsocket_address *ts = NULL;

	const char *const SID = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SESSION = "7130cb06-2062-6a1b-409e-3514c26b1773";

	struct GUID transaction_id;
	const char *const TRANSACTION = "7130cb06-2062-6a1b-409e-3514c26b1773";

	enum event_id_type event_id = EVT_ID_NONE;

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
	json = audit_group_json(module,
				req,
				"the-action",
				"the-user-name",
				"the-group-name",
				event_id,
				LDB_SUCCESS);
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

	v = json_object_get(audit, "eventId");
	assert_null(v);

	v = json_object_get(audit, "statusCode");
	assert_non_null(v);
	assert_true(json_is_integer(v));
	assert_int_equal(LDB_SUCCESS, json_integer_value(v));

	v = json_object_get(audit, "status");
	assert_non_null(v);
	assert_true(json_is_string(v));
	assert_string_equal("Success", json_string_value(v));

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
static void setup_ldb(
	TALLOC_CTX *ctx,
	struct ldb_context **ldb,
	struct ldb_module **module,
	const char *ip,
	const char *session,
	const char *sid)
{
	struct tsocket_address *ts = NULL;
	struct audit_context *context = NULL;

	*ldb = ldb_init(ctx, NULL);
	ldb_register_samba_handlers(*ldb);


	*module = talloc_zero(ctx, struct ldb_module);
	(*module)->ldb = *ldb;

	context = talloc_zero(*module, struct audit_context);
	context->send_events = true;
	context->msg_ctx = (struct imessaging_context *) 0x01;

	ldb_module_set_private(*module, context);

	tsocket_address_inet_from_strings(ctx, "ip", "127.0.0.1", 0, &ts);
	ldb_set_opaque(*ldb, "remoteAddress", ts);

	add_session_data(ctx, *ldb, session, sid);
}

/*
 * Test the removal of a user from a group.
 *
 * The new element contains one group member
 * The old element contains two group member
 *
 * Expect to see the removed entry logged.
 *
 * This test confirms bug 13664
 * https://bugzilla.samba.org/show_bug.cgi?id=13664
 */
static void test_log_membership_changes_removed(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	const char * const SID = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SESSION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const TRANSACTION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const IP = "127.0.0.1";
	struct ldb_request *req = NULL;
	struct ldb_message_element *new_el = NULL;
	struct ldb_message_element *old_el = NULL;
	uint32_t group_type = GTYPE_SECURITY_GLOBAL_GROUP;
	int status = 0;
	TALLOC_CTX *ctx = talloc_new(NULL);

	setup_ldb(ctx, &ldb, &module, IP, SESSION, SID);

	/*
	 * Build the ldb_request
	 */
	req = talloc_zero(ctx, struct ldb_request);
	req->operation =  LDB_ADD;
	add_transaction_id(req, TRANSACTION);

	/*
	 * Populate the new elements, containing one entry.
	 * Indicating that one element has been removed
	 */
	new_el = talloc_zero(ctx, struct ldb_message_element);
	new_el->num_values = 1;
	new_el->values = talloc_zero_array(ctx, DATA_BLOB, 1);
	new_el->values[0] = data_blob_string_const(
		"<GUID=081519b5-a709-44a0-bc95-dd4bfe809bf8>;"
		"CN=testuser131953,CN=Users,DC=addom,DC=samba,"
		"DC=example,DC=com");

	/*
	 * Populate the old elements, with two elements
	 * The first is the same as the one in new elements.
	 */
	old_el = talloc_zero(ctx, struct ldb_message_element);
	old_el->num_values = 2;
	old_el->values = talloc_zero_array(ctx, DATA_BLOB, 2);
	old_el->values[0] = data_blob_string_const(
		"<GUID=cb8c2777-dcf5-419c-ab57-f645dbdf681b>;"
		"cn=grpadttstuser01,cn=users,DC=addom,"
		"DC=samba,DC=example,DC=com");
	old_el->values[1] = data_blob_string_const(
		"<GUID=081519b5-a709-44a0-bc95-dd4bfe809bf8>;"
		"CN=testuser131953,CN=Users,DC=addom,DC=samba,"
		"DC=example,DC=com");

	/*
	 * call log_membership_changes
	 */
	messages_sent = 0;
	log_membership_changes(module, req, new_el, old_el, group_type, status);

	/*
	 * Check the results
	 */
	assert_int_equal(1, messages_sent);

	check_group_change_message(
	    0,
	    "cn=grpadttstuser01,cn=users,DC=addom,DC=samba,DC=example,DC=com",
	    "Removed",
	    EVT_ID_USER_REMOVED_FROM_GLOBAL_SEC_GROUP);

	/*
	 * Clean up
	 */
	json_free(&messages[0]);
	TALLOC_FREE(ctx);
}

/* test log_membership_changes
 *
 * old contains 2 user dn's
 * new contains 0 user dn's
 *
 * Expect to see both dn's logged as deleted.
 */
static void test_log_membership_changes_remove_all(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	const char * const SID = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SESSION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const TRANSACTION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const IP = "127.0.0.1";
	struct ldb_request *req = NULL;
	struct ldb_message_element *new_el = NULL;
	struct ldb_message_element *old_el = NULL;
	int status = 0;
	uint32_t group_type = GTYPE_SECURITY_BUILTIN_LOCAL_GROUP;
	TALLOC_CTX *ctx = talloc_new(NULL);

	setup_ldb(ctx, &ldb, &module, IP, SESSION, SID);

	/*
	 * Build the ldb_request
	 */
	req = talloc_zero(ctx, struct ldb_request);
	req->operation =  LDB_ADD;
	add_transaction_id(req, TRANSACTION);

	/*
	 * Populate the new elements, containing no entries.
	 * Indicating that all elements have been removed
	 */
	new_el = talloc_zero(ctx, struct ldb_message_element);
	new_el->num_values = 0;
	new_el->values = NULL;

	/*
	 * Populate the old elements, with two elements
	 */
	old_el = talloc_zero(ctx, struct ldb_message_element);
	old_el->num_values = 2;
	old_el->values = talloc_zero_array(ctx, DATA_BLOB, 2);
	old_el->values[0] = data_blob_string_const(
		"<GUID=cb8c2777-dcf5-419c-ab57-f645dbdf681b>;"
		"cn=grpadttstuser01,cn=users,DC=addom,"
		"DC=samba,DC=example,DC=com");
	old_el->values[1] = data_blob_string_const(
		"<GUID=081519b5-a709-44a0-bc95-dd4bfe809bf8>;"
		"CN=testuser131953,CN=Users,DC=addom,DC=samba,"
		"DC=example,DC=com");

	/*
	 * call log_membership_changes
	 */
	messages_sent = 0;
	log_membership_changes(module, req, new_el, old_el, group_type, status);

	/*
	 * Check the results
	 */
	assert_int_equal(2, messages_sent);

	check_group_change_message(
	    0,
	    "cn=grpadttstuser01,cn=users,DC=addom,DC=samba,DC=example,DC=com",
	    "Removed",
	    EVT_ID_USER_REMOVED_FROM_LOCAL_SEC_GROUP);

	check_group_change_message(
	    1,
	    "CN=testuser131953,CN=Users,DC=addom,DC=samba,DC=example,DC=com",
	    "Removed",
	    EVT_ID_USER_REMOVED_FROM_LOCAL_SEC_GROUP);

	/*
	 * Clean up
	 */
	json_free(&messages[0]);
	json_free(&messages[1]);
	TALLOC_FREE(ctx);
}

/* test log_membership_changes
 *
 * Add an entry.
 *
 * Old entries contains a single user dn
 * New entries contains 2 user dn's, one matching the dn in old entries
 *
 * Should see a single new entry logged.
 */
static void test_log_membership_changes_added(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	const char * const SID = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SESSION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const TRANSACTION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const IP = "127.0.0.1";
	struct ldb_request *req = NULL;
	struct ldb_message_element *new_el = NULL;
	struct ldb_message_element *old_el = NULL;
	uint32_t group_type = GTYPE_SECURITY_DOMAIN_LOCAL_GROUP;
	int status = 0;
	TALLOC_CTX *ctx = talloc_new(NULL);

	setup_ldb(ctx, &ldb, &module, IP, SESSION, SID);

	/*
	 * Build the ldb_request
	 */
	req = talloc_zero(ctx, struct ldb_request);
	req->operation =  LDB_ADD;
	add_transaction_id(req, TRANSACTION);

	/*
	 * Populate the old elements adding a single entry.
	 */
	old_el = talloc_zero(ctx, struct ldb_message_element);
	old_el->num_values = 1;
	old_el->values = talloc_zero_array(ctx, DATA_BLOB, 1);
	old_el->values[0] = data_blob_string_const(
		"<GUID=081519b5-a709-44a0-bc95-dd4bfe809bf8>;"
		"CN=testuser131953,CN=Users,DC=addom,DC=samba,"
		"DC=example,DC=com");

	/*
	 * Populate the new elements adding two entries. One matches the entry
	 * in old elements. We expect to see the other element logged as Added
	 */
	new_el = talloc_zero(ctx, struct ldb_message_element);
	new_el->num_values = 2;
	new_el->values = talloc_zero_array(ctx, DATA_BLOB, 2);
	new_el->values[0] = data_blob_string_const(
		"<GUID=cb8c2777-dcf5-419c-ab57-f645dbdf681b>;"
		"cn=grpadttstuser01,cn=users,DC=addom,"
		"DC=samba,DC=example,DC=com");
	new_el->values[1] = data_blob_string_const(
		"<GUID=081519b5-a709-44a0-bc95-dd4bfe809bf8>;"
		"CN=testuser131953,CN=Users,DC=addom,DC=samba,"
		"DC=example,DC=com");

	/*
	 * call log_membership_changes
	 */
	messages_sent = 0;
	log_membership_changes(module, req, new_el, old_el, group_type, status);

	/*
	 * Check the results
	 */
	assert_int_equal(1, messages_sent);

	check_group_change_message(
	    0,
	    "cn=grpadttstuser01,cn=users,DC=addom,DC=samba,DC=example,DC=com",
	    "Added",
	    EVT_ID_USER_ADDED_TO_LOCAL_SEC_GROUP);

	/*
	 * Clean up
	 */
	json_free(&messages[0]);
	TALLOC_FREE(ctx);
}

/*
 * test log_membership_changes.
 *
 * Old entries is empty
 * New entries contains 2 user dn's
 *
 * Expect to see log messages for two added users
 */
static void test_log_membership_changes_add_to_empty(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	const char * const SID = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SESSION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const TRANSACTION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const IP = "127.0.0.1";
	struct ldb_request *req = NULL;
	struct ldb_message_element *new_el = NULL;
	struct ldb_message_element *old_el = NULL;
	uint32_t group_type = GTYPE_SECURITY_UNIVERSAL_GROUP;
	int status = 0;
	TALLOC_CTX *ctx = talloc_new(NULL);

	/*
	 * Set up the ldb and module structures
	 */
	setup_ldb(ctx, &ldb, &module, IP, SESSION, SID);

	/*
	 * Build the request structure
	 */
	req = talloc_zero(ctx, struct ldb_request);
	req->operation =  LDB_ADD;
	add_transaction_id(req, TRANSACTION);

	/*
	 * Build the element containing the old values
	 */
	old_el = talloc_zero(ctx, struct ldb_message_element);
	old_el->num_values = 0;
	old_el->values = NULL;

	/*
	 * Build the element containing the new values
	 */
	new_el = talloc_zero(ctx, struct ldb_message_element);
	new_el->num_values = 2;
	new_el->values = talloc_zero_array(ctx, DATA_BLOB, 2);
	new_el->values[0] = data_blob_string_const(
		"<GUID=cb8c2777-dcf5-419c-ab57-f645dbdf681b>;"
		"cn=grpadttstuser01,cn=users,DC=addom,"
		"DC=samba,DC=example,DC=com");
	new_el->values[1] = data_blob_string_const(
		"<GUID=081519b5-a709-44a0-bc95-dd4bfe809bf8>;"
		"CN=testuser131953,CN=Users,DC=addom,DC=samba,"
		"DC=example,DC=com");

	/*
	 * Run log membership changes
	 */
	messages_sent = 0;
	log_membership_changes(module, req, new_el, old_el, group_type, status);
	assert_int_equal(2, messages_sent);

	check_group_change_message(
	    0,
	    "cn=grpadttstuser01,cn=users,DC=addom,DC=samba,DC=example,DC=com",
	    "Added",
	    EVT_ID_USER_ADDED_TO_UNIVERSAL_SEC_GROUP);

	check_group_change_message(
	    1,
	    "CN=testuser131953,CN=Users,DC=addom,DC=samba,DC=example,DC=com",
	    "Added",
	    EVT_ID_USER_ADDED_TO_UNIVERSAL_SEC_GROUP);

	json_free(&messages[0]);
	json_free(&messages[1]);
	TALLOC_FREE(ctx);
}

/* test log_membership_changes
 *
 * Test Replication Meta Data flag handling.
 *
 * 4 entries in old and new entries with their RMD_FLAGS set as below:
 *    old   new
 * 1)  0     0    Not logged
 * 2)  1     1    Both deleted, no change not logged
 * 3)  0     1    New tagged as deleted, log as deleted
 * 4)  1     0    Has been undeleted, log as an add
 *
 * Should see a single new entry logged.
 */
static void test_log_membership_changes_rmd_flags(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	const char * const SID = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SESSION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const TRANSACTION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const IP = "127.0.0.1";
	struct ldb_request *req = NULL;
	struct ldb_message_element *new_el = NULL;
	struct ldb_message_element *old_el = NULL;
	uint32_t group_type = GTYPE_SECURITY_GLOBAL_GROUP;
	int status = 0;
	TALLOC_CTX *ctx = talloc_new(NULL);

	setup_ldb(ctx, &ldb, &module, IP, SESSION, SID);

	/*
	 * Build the ldb_request
	 */
	req = talloc_zero(ctx, struct ldb_request);
	req->operation =  LDB_ADD;
	add_transaction_id(req, TRANSACTION);

	/*
	 * Populate the old elements.
	 */
	old_el = talloc_zero(ctx, struct ldb_message_element);
	old_el->num_values = 4;
	old_el->values = talloc_zero_array(ctx, DATA_BLOB, 4);
	old_el->values[0] = data_blob_string_const(
		"<GUID=cb8c2777-dcf5-419c-ab57-f645dbdf681b>;"
		"<RMD_FLAGS=0>;"
		"cn=grpadttstuser01,cn=users,DC=addom,"
		"DC=samba,DC=example,DC=com");
	old_el->values[1] = data_blob_string_const(
		"<GUID=cb8c2777-dcf5-419c-ab57-f645dbdf681c>;"
		"<RMD_FLAGS=1>;"
		"cn=grpadttstuser02,cn=users,DC=addom,"
		"DC=samba,DC=example,DC=com");
	old_el->values[2] = data_blob_string_const(
		"<GUID=cb8c2777-dcf5-419c-ab57-f645dbdf681d>;"
		"<RMD_FLAGS=0>;"
		"cn=grpadttstuser03,cn=users,DC=addom,"
		"DC=samba,DC=example,DC=com");
	old_el->values[3] = data_blob_string_const(
		"<GUID=cb8c2777-dcf5-419c-ab57-f645dbdf681e>;"
		"<RMD_FLAGS=1>;"
		"cn=grpadttstuser04,cn=users,DC=addom,"
		"DC=samba,DC=example,DC=com");

	/*
	 * Populate the new elements.
	 */
	new_el = talloc_zero(ctx, struct ldb_message_element);
	new_el->num_values = 4;
	new_el->values = talloc_zero_array(ctx, DATA_BLOB, 4);
	new_el->values[0] = data_blob_string_const(
		"<GUID=cb8c2777-dcf5-419c-ab57-f645dbdf681b>;"
		"<RMD_FLAGS=0>;"
		"cn=grpadttstuser01,cn=users,DC=addom,"
		"DC=samba,DC=example,DC=com");
	new_el->values[1] = data_blob_string_const(
		"<GUID=cb8c2777-dcf5-419c-ab57-f645dbdf681c>;"
		"<RMD_FLAGS=1>;"
		"cn=grpadttstuser02,cn=users,DC=addom,"
		"DC=samba,DC=example,DC=com");
	new_el->values[2] = data_blob_string_const(
		"<GUID=cb8c2777-dcf5-419c-ab57-f645dbdf681d>;"
		"<RMD_FLAGS=1>;"
		"cn=grpadttstuser03,cn=users,DC=addom,"
		"DC=samba,DC=example,DC=com");
	new_el->values[3] = data_blob_string_const(
		"<GUID=cb8c2777-dcf5-419c-ab57-f645dbdf681e>;"
		"<RMD_FLAGS=0>;"
		"cn=grpadttstuser04,cn=users,DC=addom,"
		"DC=samba,DC=example,DC=com");

	/*
	 * call log_membership_changes
	 */
	messages_sent = 0;
	log_membership_changes(module, req, new_el, old_el, group_type, status);

	/*
	 * Check the results
	 */
	assert_int_equal(2, messages_sent);

	check_group_change_message(
	    0,
	    "cn=grpadttstuser03,cn=users,DC=addom,DC=samba,DC=example,DC=com",
	    "Removed",
	    EVT_ID_USER_REMOVED_FROM_GLOBAL_SEC_GROUP);
	check_group_change_message(
	    1,
	    "cn=grpadttstuser04,cn=users,DC=addom,DC=samba,DC=example,DC=com",
	    "Added",
	    EVT_ID_USER_ADDED_TO_GLOBAL_SEC_GROUP);

	/*
	 * Clean up
	 */
	json_free(&messages[0]);
	json_free(&messages[1]);
	TALLOC_FREE(ctx);
}

static void test_get_add_member_event(void **state)
{
	assert_int_equal(
	    EVT_ID_USER_ADDED_TO_LOCAL_SEC_GROUP,
	    get_add_member_event(GTYPE_SECURITY_BUILTIN_LOCAL_GROUP));

	assert_int_equal(EVT_ID_USER_ADDED_TO_GLOBAL_SEC_GROUP,
			 get_add_member_event(GTYPE_SECURITY_GLOBAL_GROUP));

	assert_int_equal(
	    EVT_ID_USER_ADDED_TO_LOCAL_SEC_GROUP,
	    get_add_member_event(GTYPE_SECURITY_DOMAIN_LOCAL_GROUP));

	assert_int_equal(EVT_ID_USER_ADDED_TO_UNIVERSAL_SEC_GROUP,
			 get_add_member_event(GTYPE_SECURITY_UNIVERSAL_GROUP));

	assert_int_equal(EVT_ID_USER_ADDED_TO_GLOBAL_GROUP,
			 get_add_member_event(GTYPE_DISTRIBUTION_GLOBAL_GROUP));

	assert_int_equal(
	    EVT_ID_USER_ADDED_TO_LOCAL_GROUP,
	    get_add_member_event(GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP));

	assert_int_equal(
	    EVT_ID_USER_ADDED_TO_UNIVERSAL_GROUP,
	    get_add_member_event(GTYPE_DISTRIBUTION_UNIVERSAL_GROUP));

	assert_int_equal(EVT_ID_NONE, get_add_member_event(0));

	assert_int_equal(EVT_ID_NONE, get_add_member_event(UINT32_MAX));
}

static void test_get_remove_member_event(void **state)
{
	assert_int_equal(
	    EVT_ID_USER_REMOVED_FROM_LOCAL_SEC_GROUP,
	    get_remove_member_event(GTYPE_SECURITY_BUILTIN_LOCAL_GROUP));

	assert_int_equal(EVT_ID_USER_REMOVED_FROM_GLOBAL_SEC_GROUP,
			 get_remove_member_event(GTYPE_SECURITY_GLOBAL_GROUP));

	assert_int_equal(
	    EVT_ID_USER_REMOVED_FROM_LOCAL_SEC_GROUP,
	    get_remove_member_event(GTYPE_SECURITY_DOMAIN_LOCAL_GROUP));

	assert_int_equal(
	    EVT_ID_USER_REMOVED_FROM_UNIVERSAL_SEC_GROUP,
	    get_remove_member_event(GTYPE_SECURITY_UNIVERSAL_GROUP));

	assert_int_equal(
	    EVT_ID_USER_REMOVED_FROM_GLOBAL_GROUP,
	    get_remove_member_event(GTYPE_DISTRIBUTION_GLOBAL_GROUP));

	assert_int_equal(
	    EVT_ID_USER_REMOVED_FROM_LOCAL_GROUP,
	    get_remove_member_event(GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP));

	assert_int_equal(
	    EVT_ID_USER_REMOVED_FROM_UNIVERSAL_GROUP,
	    get_remove_member_event(GTYPE_DISTRIBUTION_UNIVERSAL_GROUP));

	assert_int_equal(EVT_ID_NONE, get_remove_member_event(0));

	assert_int_equal(EVT_ID_NONE, get_remove_member_event(UINT32_MAX));
}

/* test log_group_membership_changes
 *
 * Happy path test case
 *
 */
static void test_log_group_membership_changes(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	const char * const SID = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SESSION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const TRANSACTION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const IP = "127.0.0.1";
	struct ldb_request *req = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_message_element *el = NULL;
	struct audit_callback_context *acc = NULL;
	struct ldb_result *res = NULL;
	struct ldb_message *new_msg = NULL;
	struct ldb_message_element *group_type = NULL;
	const char *group_type_str = NULL;
	struct ldb_message_element *new_el = NULL;
	struct ldb_message_element *old_el = NULL;
	int status = 0;
	TALLOC_CTX *ctx = talloc_new(NULL);

	setup_ldb(ctx, &ldb, &module, IP, SESSION, SID);

	/*
	 * Build the ldb message
	 */
	msg = talloc_zero(ctx, struct ldb_message);

	/*
	 * Populate message elements, adding a new entry to the membership list
	 *
	 */

	el = talloc_zero(ctx, struct ldb_message_element);
	el->name = "member";
	el->num_values = 1;
	el->values = talloc_zero_array(ctx, DATA_BLOB, 1);
	el->values[0] = data_blob_string_const(
		"<GUID=081519b5-a709-44a0-bc95-dd4bfe809bf8>;"
		"CN=testuser131953,CN=Users,DC=addom,DC=samba,"
		"DC=example,DC=com");
	msg->elements = el;
	msg->num_elements = 1;

	/*
	 * Build the ldb_request
	 */
	req = talloc_zero(ctx, struct ldb_request);
	req->operation = LDB_ADD;
	req->op.add.message = msg;
	add_transaction_id(req, TRANSACTION);

	/*
	 * Build the initial state of the database
	 */
	old_el = talloc_zero(ctx, struct ldb_message_element);
	old_el->name = "member";
	old_el->num_values = 1;
	old_el->values = talloc_zero_array(ctx, DATA_BLOB, 1);
	old_el->values[0] = data_blob_string_const(
		"<GUID=cb8c2777-dcf5-419c-ab57-f645dbdf681b>;"
		"cn=grpadttstuser01,cn=users,DC=addom,"
		"DC=samba,DC=example,DC=com");

	/*
	 * Build the updated state of the database
	 */
	res = talloc_zero(ctx, struct ldb_result);
	new_msg = talloc_zero(ctx, struct ldb_message);
	new_el = talloc_zero(ctx, struct ldb_message_element);
	new_el->name = "member";
	new_el->num_values = 2;
	new_el->values = talloc_zero_array(ctx, DATA_BLOB, 2);
	new_el->values[0] = data_blob_string_const(
		"<GUID=cb8c2777-dcf5-419c-ab57-f645dbdf681b>;"
		"cn=grpadttstuser01,cn=users,DC=addom,"
		"DC=samba,DC=example,DC=com");
	new_el->values[1] = data_blob_string_const(
		"<GUID=081519b5-a709-44a0-bc95-dd4bfe809bf8>;"
		"CN=testuser131953,CN=Users,DC=addom,DC=samba,"
		"DC=example,DC=com");

	group_type = talloc_zero(ctx, struct ldb_message_element);
	group_type->name = "groupType";
	group_type->num_values = 1;
	group_type->values = talloc_zero_array(ctx, DATA_BLOB, 1);
	group_type_str = talloc_asprintf(ctx, "%u", GTYPE_SECURITY_GLOBAL_GROUP);
	group_type->values[0] = data_blob_string_const(group_type_str);


	new_msg->elements = talloc_zero_array(ctx, struct ldb_message_element, 2);
	new_msg->num_elements = 2;
	new_msg->elements[0] = *new_el;
	new_msg->elements[1] = *group_type;

	res->count = 1;
	res->msgs = &new_msg;

	acc = talloc_zero(ctx, struct audit_callback_context);
	acc->request = req;
	acc->module = module;
	acc->members = old_el;
	/*
	 * call log_membership_changes
	 */
	messages_sent = 0;
	g_result = res;
	g_status = LDB_SUCCESS;
	log_group_membership_changes(acc, status);
	g_result = NULL;

	/*
	 * Check the results
	 */
	assert_int_equal(1, messages_sent);

	check_group_change_message(
	    0,
	    "CN=testuser131953,CN=Users,DC=addom,DC=samba,DC=example,DC=com",
	    "Added",
	    EVT_ID_USER_ADDED_TO_GLOBAL_SEC_GROUP);

	/*
	 * Clean up
	 */
	json_free(&messages[0]);
	TALLOC_FREE(ctx);
}

/* test log_group_membership_changes
 *
 * The ldb query to retrieve the new values failed.
 *
 * Should generate group membership change Failure message.
 *
 */
static void test_log_group_membership_changes_read_new_failure(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	const char * const SID = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SESSION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const TRANSACTION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const IP = "127.0.0.1";
	struct ldb_request *req = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_message_element *el = NULL;
	struct audit_callback_context *acc = NULL;
	struct ldb_message_element *old_el = NULL;
	int status = 0;
	TALLOC_CTX *ctx = talloc_new(NULL);

	setup_ldb(ctx, &ldb, &module, IP, SESSION, SID);

	/*
	 * Build the ldb message
	 */
	msg = talloc_zero(ctx, struct ldb_message);

	/*
	 * Populate message elements, adding a new entry to the membership list
	 *
	 */

	el = talloc_zero(ctx, struct ldb_message_element);
	el->name = "member";
	el->num_values = 1;
	el->values = talloc_zero_array(ctx, DATA_BLOB, 1);
	el->values[0] = data_blob_string_const(
		"<GUID=081519b5-a709-44a0-bc95-dd4bfe809bf8>;"
		"CN=testuser131953,CN=Users,DC=addom,DC=samba,"
		"DC=example,DC=com");
	msg->elements = el;
	msg->num_elements = 1;

	/*
	 * Build the ldb_request
	 */
	req = talloc_zero(ctx, struct ldb_request);
	req->operation = LDB_ADD;
	req->op.add.message = msg;
	add_transaction_id(req, TRANSACTION);

	/*
	 * Build the initial state of the database
	 */
	old_el = talloc_zero(ctx, struct ldb_message_element);
	old_el->name = "member";
	old_el->num_values = 1;
	old_el->values = talloc_zero_array(ctx, DATA_BLOB, 1);
	old_el->values[0] = data_blob_string_const(
		"<GUID=cb8c2777-dcf5-419c-ab57-f645dbdf681b>;"
		"cn=grpadttstuser01,cn=users,DC=addom,"
		"DC=samba,DC=example,DC=com");

	acc = talloc_zero(ctx, struct audit_callback_context);
	acc->request = req;
	acc->module = module;
	acc->members = old_el;
	/*
	 * call log_membership_changes
	 */
	messages_sent = 0;
	g_result = NULL;
	g_status = LDB_ERR_NO_SUCH_OBJECT;
	log_group_membership_changes(acc, status);

	/*
	 * Check the results
	 */
	assert_int_equal(1, messages_sent);

	check_group_change_message(
	    0,
	    "",
	    "Failure",
	    EVT_ID_NONE);

	/*
	 * Clean up
	 */
	json_free(&messages[0]);
	TALLOC_FREE(ctx);
}

/* test log_group_membership_changes
 *
 * The operation failed.
 *
 * Should generate group membership change Failure message.
 *
 */
static void test_log_group_membership_changes_error(void **state)
{
	struct ldb_context *ldb = NULL;
	struct ldb_module  *module = NULL;
	const char * const SID = "S-1-5-21-2470180966-3899876309-2637894779";
	const char * const SESSION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const TRANSACTION = "7130cb06-2062-6a1b-409e-3514c26b1773";
	const char * const IP = "127.0.0.1";
	struct ldb_request *req = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_message_element *el = NULL;
	struct ldb_message_element *old_el = NULL;
	struct audit_callback_context *acc = NULL;
	int status = LDB_ERR_OPERATIONS_ERROR;
	TALLOC_CTX *ctx = talloc_new(NULL);

	setup_ldb(ctx, &ldb, &module, IP, SESSION, SID);

	/*
	 * Build the ldb message
	 */
	msg = talloc_zero(ctx, struct ldb_message);

	/*
	 * Populate message elements, adding a new entry to the membership list
	 *
	 */

	el = talloc_zero(ctx, struct ldb_message_element);
	el->name = "member";
	el->num_values = 1;
	el->values = talloc_zero_array(ctx, DATA_BLOB, 1);
	el->values[0] = data_blob_string_const(
		"<GUID=081519b5-a709-44a0-bc95-dd4bfe809bf8>;"
		"CN=testuser131953,CN=Users,DC=addom,DC=samba,"
		"DC=example,DC=com");
	msg->elements = el;
	msg->num_elements = 1;

	/*
	 * Build the ldb_request
	 */
	req = talloc_zero(ctx, struct ldb_request);
	req->operation = LDB_ADD;
	req->op.add.message = msg;
	add_transaction_id(req, TRANSACTION);

	/*
	 * Build the initial state of the database
	 */
	old_el = talloc_zero(ctx, struct ldb_message_element);
	old_el->name = "member";
	old_el->num_values = 1;
	old_el->values = talloc_zero_array(ctx, DATA_BLOB, 1);
	old_el->values[0] = data_blob_string_const(
		"<GUID=cb8c2777-dcf5-419c-ab57-f645dbdf681b>;"
		"cn=grpadttstuser01,cn=users,DC=addom,"
		"DC=samba,DC=example,DC=com");


	acc = talloc_zero(ctx, struct audit_callback_context);
	acc->request = req;
	acc->module = module;
	acc->members = old_el;
	/*
	 * call log_membership_changes
	 */
	messages_sent = 0;
	log_group_membership_changes(acc, status);

	/*
	 * Check the results
	 */
	assert_int_equal(1, messages_sent);

	check_group_change_message(
	    0,
	    "",
	    "Failure",
	    EVT_ID_NONE);

	/*
	 * Clean up
	 */
	json_free(&messages[0]);
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
	    cmocka_unit_test(test_audit_group_json_error),
	    cmocka_unit_test(test_audit_group_json_no_event),
	    cmocka_unit_test(test_get_transaction_id),
	    cmocka_unit_test(test_audit_group_hr),
	    cmocka_unit_test(test_get_parsed_dns),
	    cmocka_unit_test(test_dn_compare),
	    cmocka_unit_test(test_get_primary_group_dn),
	    cmocka_unit_test(test_log_membership_changes_removed),
	    cmocka_unit_test(test_log_membership_changes_remove_all),
	    cmocka_unit_test(test_log_membership_changes_added),
	    cmocka_unit_test(test_log_membership_changes_add_to_empty),
	    cmocka_unit_test(test_log_membership_changes_rmd_flags),
	    cmocka_unit_test(test_get_add_member_event),
	    cmocka_unit_test(test_get_remove_member_event),
	    cmocka_unit_test(test_log_group_membership_changes),
	    cmocka_unit_test(test_log_group_membership_changes_read_new_failure),
	    cmocka_unit_test(test_log_group_membership_changes_error),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
