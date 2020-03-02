/*
 * Unit tests for the audit_logging library.
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
 * Note that the messaging routines (audit_message_send and get_event_server)
 * are not tested by these unit tests.  Currently they are for integration
 * test support, and as such are exercised by the integration tests.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <time.h>
#include <tevent.h>
#include <config.h>
#include <talloc.h>
#include "lib/util/talloc_stack.h"

#include "lib/util/data_blob.h"
#include "lib/util/time.h"
#include "libcli/util/werror.h"
#include "lib/param/loadparm.h"
#include "libcli/security/dom_sid.h"
#include "librpc/ndr/libndr.h"

#include "lib/audit_logging/audit_logging.h"

static void test_json_add_int(_UNUSED_ void **state)
{
	struct json_object object;
	struct json_t *value = NULL;
	double n;
	int rc = 0;

	object = json_new_object();
	rc = json_add_int(&object, "positive_one", 1);
	assert_int_equal(0, rc);
	rc = json_add_int(&object, "zero", 0);
	assert_int_equal(0, rc);
	rc = json_add_int(&object, "negative_one", -1);
	assert_int_equal(0, rc);

	assert_int_equal(3, json_object_size(object.root));

	value = json_object_get(object.root, "positive_one");
	assert_true(json_is_integer(value));
	n = json_number_value(value);
	assert_true(n == 1.0);

	value = json_object_get(object.root, "zero");
	assert_true(json_is_integer(value));
	n = json_number_value(value);
	assert_true(n == 0.0);

	value = json_object_get(object.root, "negative_one");
	assert_true(json_is_integer(value));
	n = json_number_value(value);
	assert_true(n == -1.0);

	object.valid = false;
	rc = json_add_int(&object, "should fail 1", 0xf1);
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);

	rc = json_add_int(&object, "should fail 2", 0xf2);
	assert_int_equal(JSON_ERROR, rc);
}

static void test_json_add_bool(_UNUSED_ void **state)
{
	struct json_object object;
	struct json_t *value = NULL;
	int rc = 0;

	object = json_new_object();
	rc = json_add_bool(&object, "true", true);
	assert_int_equal(0, rc);
	rc = json_add_bool(&object, "false", false);
	assert_int_equal(0, rc);

	assert_int_equal(2, json_object_size(object.root));

	value = json_object_get(object.root, "true");
	assert_true(json_is_boolean(value));
	assert_true(value == json_true());

	value = json_object_get(object.root, "false");
	assert_true(json_is_boolean(value));
	assert_true(value == json_false());

	object.valid = false;
	rc = json_add_bool(&object, "should fail 1", true);
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);

	rc = json_add_bool(&object, "should fail 2", false);
	assert_int_equal(JSON_ERROR, rc);
}

static void test_json_add_string(_UNUSED_ void **state)
{
	struct json_object object;
	struct json_t *value = NULL;
	const char *s = NULL;
	int rc = 0;

	object = json_new_object();
	rc = json_add_string(&object, "null", NULL);
	assert_int_equal(0, rc);
	rc = json_add_string(&object, "empty", "");
	assert_int_equal(0, rc);
	rc = json_add_string(&object, "name", "value");
	assert_int_equal(0, rc);

	assert_int_equal(3, json_object_size(object.root));

	value = json_object_get(object.root, "null");
	assert_true(json_is_null(value));

	value = json_object_get(object.root, "empty");
	assert_true(json_is_string(value));
	s = json_string_value(value);
	assert_string_equal("", s);

	value = json_object_get(object.root, "name");
	assert_true(json_is_string(value));
	s = json_string_value(value);
	assert_string_equal("value", s);

	object.valid = false;
	rc = json_add_string(&object, "should fail 1", "A value");
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);

	rc = json_add_string(&object, "should fail 2", "Another value");
	assert_int_equal(JSON_ERROR, rc);
}

static void test_json_add_object(_UNUSED_ void **state)
{
	struct json_object object;
	struct json_object other;
	struct json_object after;
	struct json_object invalid = json_empty_object;
	struct json_t *value = NULL;
	int rc = 0;

	object = json_new_object();
	other  = json_new_object();
	rc = json_add_object(&object, "null", NULL);
	assert_int_equal(0, rc);
	rc = json_add_object(&object, "other", &other);
	assert_int_equal(0, rc);

	assert_int_equal(2, json_object_size(object.root));

	value = json_object_get(object.root, "null");
	assert_true(json_is_null(value));

	value = json_object_get(object.root, "other");
	assert_true(json_is_object(value));
	assert_ptr_equal(other.root, value);

	rc = json_add_object(&object, "invalid", &invalid);
	assert_int_equal(JSON_ERROR, rc);

	object.valid = false;
	after = json_new_object();
	rc = json_add_object(&object, "after", &after);
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);

	rc = json_add_object(&object, "after", &after);
	assert_int_equal(JSON_ERROR, rc);

	json_free(&after);
}

static void test_json_add_to_array(_UNUSED_ void **state)
{
	struct json_object array;
	struct json_object o1;
	struct json_object o2;
	struct json_object o3;
	struct json_object after;
	struct json_object invalid = json_empty_object;
	struct json_t *value = NULL;
	int rc = 0;

	array = json_new_array();
	assert_true(json_is_array(array.root));

	o1 = json_new_object();
	o2 = json_new_object();
	o3 = json_new_object();

	rc = json_add_object(&array, NULL, &o3);
	assert_int_equal(0, rc);
	rc = json_add_object(&array, "", &o2);
	assert_int_equal(0, rc);
	rc = json_add_object(&array, "will-be-ignored", &o1);
	assert_int_equal(0, rc);
	rc = json_add_object(&array, NULL, NULL);
	assert_int_equal(0, rc);

	assert_int_equal(4, json_array_size(array.root));

	value = json_array_get(array.root, 0);
	assert_ptr_equal(o3.root, value);

	value = json_array_get(array.root, 1);
	assert_ptr_equal(o2.root, value);

	value = json_array_get(array.root, 2);
	assert_ptr_equal(o1.root, value);

	value = json_array_get(array.root, 3);
	assert_true(json_is_null(value));

	rc = json_add_object(&array, "invalid", &invalid);
	assert_int_equal(JSON_ERROR, rc);

	array.valid = false;
	after = json_new_object();
	rc = json_add_object(&array, "after", &after);
	assert_int_equal(JSON_ERROR, rc);

	json_free(&array);

	rc = json_add_object(&array, "after", &after);
	assert_int_equal(JSON_ERROR, rc);

	json_free(&after);
}

static void test_json_add_timestamp(_UNUSED_ void **state)
{
	struct json_object object;
	struct json_t *ts = NULL;
	const char *t = NULL;
	int rc;
	int usec, tz;
	char c[2];
	struct tm tm;
	time_t before;
	time_t after;
	time_t actual;
	const int adjustment = 1;


	object = json_new_object();
	before = time(NULL);
	rc = json_add_timestamp(&object);
	assert_int_equal(0, rc);
	after = time(NULL);

	ts = json_object_get(object.root, "timestamp");
	assert_true(json_is_string(ts));

	/*
	 * Convert the returned ISO 8601 timestamp into a time_t
	 * Note for convenience we ignore the value of the microsecond
	 * part of the time stamp.
	 */
	t = json_string_value(ts);
	rc = sscanf(
		t,
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
	 * but we adjust the times to cater for any precision issues.
	 */
	before -= adjustment;
	after += adjustment;
	assert_true(difftime(actual, before) >= 0);
	assert_true(difftime(after, actual) >= 0);

	object.valid = false;
	rc = json_add_timestamp(&object);
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);

	rc = json_add_timestamp(&object);
	assert_int_equal(JSON_ERROR, rc);
}

static void test_json_add_stringn(_UNUSED_ void **state)
{
	struct json_object object;
	struct json_t *value = NULL;
	const char *s = NULL;
	int rc = 0;

	object = json_new_object();
	rc = json_add_stringn(&object, "null", NULL, 10);
	assert_int_equal(0, rc);
	rc = json_add_stringn(&object, "null-zero-len", NULL, 0);
	assert_int_equal(0, rc);
	rc = json_add_stringn(&object, "empty", "", 1);
	assert_int_equal(0, rc);
	rc = json_add_stringn(&object, "empty-zero-len", "", 0);
	assert_int_equal(0, rc);
	rc = json_add_stringn(&object, "value-less-than-len", "123456", 7);
	assert_int_equal(0, rc);
	rc = json_add_stringn(&object, "value-greater-than-len", "abcd", 3);
	assert_int_equal(0, rc);
	rc = json_add_stringn(&object, "value-equal-len", "ZYX", 3);
	assert_int_equal(0, rc);
	rc = json_add_stringn(
	    &object, "value-len-is-zero", "this will be null", 0);
	assert_int_equal(0, rc);

	assert_int_equal(8, json_object_size(object.root));

	value = json_object_get(object.root, "null");
	assert_true(json_is_null(value));

	value = json_object_get(object.root, "null-zero-len");
	assert_true(json_is_null(value));

	value = json_object_get(object.root, "empty");
	assert_true(json_is_string(value));
	s = json_string_value(value);
	assert_string_equal("", s);

	value = json_object_get(object.root, "empty-zero-len");
	assert_true(json_is_null(value));

	value = json_object_get(object.root, "value-greater-than-len");
	assert_true(json_is_string(value));
	s = json_string_value(value);
	assert_string_equal("abc", s);
	assert_int_equal(3, strlen(s));

	value = json_object_get(object.root, "value-equal-len");
	assert_true(json_is_string(value));
	s = json_string_value(value);
	assert_string_equal("ZYX", s);
	assert_int_equal(3, strlen(s));

	value = json_object_get(object.root, "value-len-is-zero");
	assert_true(json_is_null(value));

	object.valid = false;
	rc = json_add_stringn(&object, "fail-01", "xxxxxxx", 1);
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);

	rc = json_add_stringn(&object, "fail-02", "xxxxxxx", 1);
	assert_int_equal(JSON_ERROR, rc);
}

static void test_json_add_version(_UNUSED_ void **state)
{
	struct json_object object;
	struct json_t *version = NULL;
	struct json_t *v = NULL;
	double n;
	int rc;

	object = json_new_object();
	rc = json_add_version(&object, 3, 1);
	assert_int_equal(0, rc);

	assert_int_equal(1, json_object_size(object.root));

	version = json_object_get(object.root, "version");
	assert_true(json_is_object(version));
	assert_int_equal(2, json_object_size(version));

	v = json_object_get(version, "major");
	assert_true(json_is_integer(v));
	n = json_number_value(v);
	assert_true(n == 3.0);

	v = json_object_get(version, "minor");
	assert_true(json_is_integer(v));
	n = json_number_value(v);
	assert_true(n == 1.0);

	object.valid = false;
	rc = json_add_version(&object, 3, 1);
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);

	rc = json_add_version(&object, 3, 1);
	assert_int_equal(JSON_ERROR, rc);
}

static void test_json_add_address(_UNUSED_ void **state)
{
	struct json_object object;
	struct json_t *value = NULL;
	struct tsocket_address *ip4  = NULL;
	struct tsocket_address *ip6  = NULL;
	struct tsocket_address *pipe = NULL;

	struct tsocket_address *after = NULL;
	const char *s = NULL;
	int rc;

	TALLOC_CTX *ctx = talloc_new(NULL);

	object = json_new_object();

	rc = json_add_address(&object, "null", NULL);
	assert_int_equal(0, rc);

	rc = tsocket_address_inet_from_strings(
		ctx,
		"ip",
		"127.0.0.1",
		21,
		&ip4);
	assert_int_equal(0, rc);
	rc = json_add_address(&object, "ip4", ip4);
	assert_int_equal(0, rc);

	rc = tsocket_address_inet_from_strings(
		ctx,
		"ip",
		"2001:db8:0:0:1:0:0:1",
		42,
		&ip6);
	assert_int_equal(0, rc);
	rc = json_add_address(&object, "ip6", ip6);
	assert_int_equal(0, rc);

	rc = tsocket_address_unix_from_path(ctx, "/samba/pipe", &pipe);
	assert_int_equal(0, rc);
	rc = json_add_address(&object, "pipe", pipe);
	assert_int_equal(0, rc);

	assert_int_equal(4, json_object_size(object.root));

	value = json_object_get(object.root, "null");
	assert_true(json_is_null(value));

	value = json_object_get(object.root, "ip4");
	assert_true(json_is_string(value));
	s = json_string_value(value);
	assert_string_equal("ipv4:127.0.0.1:21", s);

	value = json_object_get(object.root, "ip6");
	assert_true(json_is_string(value));
	s = json_string_value(value);
	assert_string_equal("ipv6:2001:db8::1:0:0:1:42", s);

	value = json_object_get(object.root, "pipe");
	assert_true(json_is_string(value));
	s = json_string_value(value);
	assert_string_equal("unix:/samba/pipe", s);

	object.valid = false;
	rc = tsocket_address_inet_from_strings(
	    ctx, "ip", "127.0.0.11", 23, &after);
	assert_int_equal(0, rc);
	rc = json_add_address(&object, "invalid_object", after);
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);

	rc = json_add_address(&object, "freed object", after);
	assert_int_equal(JSON_ERROR, rc);

	TALLOC_FREE(ctx);
}

static void test_json_add_sid(_UNUSED_ void **state)
{
	struct json_object object;
	struct json_t *value = NULL;
	const char *SID = "S-1-5-21-2470180966-3899876309-2637894779";
	struct dom_sid sid;
	const char *s = NULL;
	int rc;

	object = json_new_object();

	rc = json_add_sid(&object, "null", NULL);
	assert_int_equal(0, rc);

	assert_true(string_to_sid(&sid, SID));
	rc = json_add_sid(&object, "sid", &sid);
	assert_int_equal(0, rc);

	assert_int_equal(2, json_object_size(object.root));

	value = json_object_get(object.root, "null");
	assert_true(json_is_null(value));

	value = json_object_get(object.root, "sid");
	assert_true(json_is_string(value));
	s = json_string_value(value);
	assert_string_equal(SID, s);

	object.valid = false;
	rc = json_add_sid(&object, "invalid_object", &sid);
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);

	rc = json_add_sid(&object, "freed_object", &sid);
	assert_int_equal(JSON_ERROR, rc);
}

static void test_json_add_guid(_UNUSED_ void **state)
{
	struct json_object object;
	struct json_t *value = NULL;
	const char *GUID = "3ab88633-1e57-4c1a-856c-d1bc4b15bbb1";
	struct GUID guid;
	const char *s = NULL;
	NTSTATUS status;
	int rc;

	object = json_new_object();

	rc = json_add_guid(&object, "null", NULL);
	assert_int_equal(0, rc);

	status = GUID_from_string(GUID, &guid);
	assert_true(NT_STATUS_IS_OK(status));
	rc = json_add_guid(&object, "guid", &guid);
	assert_int_equal(0, rc);

	assert_int_equal(2, json_object_size(object.root));

	value = json_object_get(object.root, "null");
	assert_true(json_is_null(value));

	value = json_object_get(object.root, "guid");
	assert_true(json_is_string(value));
	s = json_string_value(value);
	assert_string_equal(GUID, s);

	object.valid = false;
	rc = json_add_guid(&object, "invalid_object", &guid);
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);

	rc = json_add_guid(&object, "freed_object", &guid);
	assert_int_equal(JSON_ERROR, rc);
}

static void test_json_to_string(_UNUSED_ void **state)
{
	struct json_object object;
	char *s = NULL;
	int rc;

	TALLOC_CTX *ctx = talloc_new(NULL);

	object = json_new_object();

	s = json_to_string(ctx, &object);
	assert_string_equal("{}", s);
	TALLOC_FREE(s);

	rc = json_add_string(&object, "name", "value");
	assert_int_equal(0, rc);
	s = json_to_string(ctx, &object);
	assert_string_equal("{\"name\": \"value\"}", s);
	TALLOC_FREE(s);

	object.valid = false;
	s = json_to_string(ctx, &object);
	assert_null(s);

	json_free(&object);

	object.valid = true;
	object.root = NULL;

	s = json_to_string(ctx, &object);
	assert_null(s);
	TALLOC_FREE(ctx);
}

static void test_json_get_array(_UNUSED_ void **state)
{
	struct json_object object;
	struct json_object array;
	struct json_object stored_array = json_new_array();
	json_t *value = NULL;
	json_t *o = NULL;
	struct json_object o1;
	struct json_object o2;
	int rc;

	object = json_new_object();

	array = json_get_array(&object, "not-there");
	assert_true(array.valid);
	assert_non_null(array.root);
	assert_true(json_is_array(array.root));
	json_free(&array);

	o1 = json_new_object();
	rc = json_add_string(&o1, "value", "value-one");
	assert_int_equal(0, rc);
	rc = json_add_object(&stored_array, NULL, &o1);
	assert_int_equal(0, rc);
	rc = json_add_object(&object, "stored_array", &stored_array);
	assert_int_equal(0, rc);

	array = json_get_array(&object, "stored_array");
	assert_true(array.valid);
	assert_non_null(array.root);
	assert_true(json_is_array(array.root));

	assert_int_equal(1, json_array_size(array.root));

	o = json_array_get(array.root, 0);
	assert_non_null(o);
	assert_true(json_is_object(o));

	value = json_object_get(o, "value");
	assert_non_null(value);
	assert_true(json_is_string(value));

	assert_string_equal("value-one", json_string_value(value));
	json_free(&array);

	/*
	 * Now update the array and add it back to the object
	 */
	array = json_get_array(&object, "stored_array");
	assert_true(json_is_array(array.root));
	o2 = json_new_object();
	rc = json_add_string(&o2, "value", "value-two");
	assert_int_equal(0, rc);
	assert_true(o2.valid);
	rc = json_add_object(&array, NULL, &o2);
	assert_int_equal(0, rc);
	assert_true(json_is_array(array.root));
	rc = json_add_object(&object, "stored_array", &array);
	assert_int_equal(0, rc);
	assert_true(json_is_array(array.root));

	array = json_get_array(&object, "stored_array");
	assert_non_null(array.root);
	assert_true(json_is_array(array.root));
	assert_true(array.valid);
	assert_true(json_is_array(array.root));

	assert_int_equal(2, json_array_size(array.root));

	o = json_array_get(array.root, 0);
	assert_non_null(o);
	assert_true(json_is_object(o));

	assert_non_null(value);
	assert_true(json_is_string(value));

	assert_string_equal("value-one", json_string_value(value));

	o = json_array_get(array.root, 1);
	assert_non_null(o);
	assert_true(json_is_object(o));

	value = json_object_get(o, "value");
	assert_non_null(value);
	assert_true(json_is_string(value));

	assert_string_equal("value-two", json_string_value(value));

	json_free(&array);
	json_free(&object);

	array = json_get_array(&object, "stored_array");
	assert_false(array.valid);
	json_free(&array);
}

static void test_json_get_object(_UNUSED_ void **state)
{
	struct json_object object;
	struct json_object o1;
	struct json_object o2;
	struct json_object o3;
	json_t *value = NULL;
	int rc;

	object = json_new_object();

	o1 = json_get_object(&object, "not-there");
	assert_true(o1.valid);
	assert_non_null(o1.root);
	assert_true(json_is_object(o1.root));
	json_free(&o1);

	o1 = json_new_object();
	rc = json_add_string(&o1, "value", "value-one");
	assert_int_equal(0, rc);
	rc = json_add_object(&object, "stored_object", &o1);
	assert_int_equal(0, rc);

	o2 = json_get_object(&object, "stored_object");
	assert_true(o2.valid);
	assert_non_null(o2.root);
	assert_true(json_is_object(o2.root));

	value = json_object_get(o2.root, "value");
	assert_non_null(value);
	assert_true(json_is_string(value));

	assert_string_equal("value-one", json_string_value(value));

	rc = json_add_string(&o2, "value", "value-two");
	assert_int_equal(0, rc);
	rc = json_add_object(&object, "stored_object", &o2);
	assert_int_equal(0, rc);

	o3 = json_get_object(&object, "stored_object");
	assert_true(o3.valid);
	assert_non_null(o3.root);
	assert_true(json_is_object(o3.root));

	value = json_object_get(o3.root, "value");
	assert_non_null(value);
	assert_true(json_is_string(value));

	assert_string_equal("value-two", json_string_value(value));

	json_free(&o3);
	json_free(&object);

	o3 = json_get_object(&object, "stored_object");
	assert_false(o3.valid);
	json_free(&o3);
}

static void test_audit_get_timestamp(_UNUSED_ void **state)
{
	const char *t = NULL;
	char *c;
	struct tm tm;
	time_t before;
	time_t after;
	time_t actual;
	char *env_tz = NULL;
	char *orig_tz = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	/*
	 * Explicitly set the time zone to UTC to make the test easier
	 */
	env_tz = getenv("TZ");
	if (env_tz != NULL) {
		orig_tz = talloc_strdup(ctx, env_tz);
	}
	setenv("TZ", "UTC", 1);

	before = time(NULL);
	t = audit_get_timestamp(ctx);
	after = time(NULL);

	c = strptime(t, "%a, %d %b %Y %H:%M:%S", &tm);

	/*
	 * Restore the time zone if we changed it
	 */
	if (orig_tz != NULL) {
		setenv("TZ", orig_tz, 1);
		TALLOC_FREE(orig_tz);
	}

	assert_non_null(c);
	tm.tm_isdst = -1;
	if (c != NULL && *c == '.') {
		char *e;
		strtod(c, &e);
		c = e;
	}
	if (c != NULL && *c == ' ') {
		assert_string_equal(" UTC", c);
		c += 4;
	}
	assert_int_equal(0, strlen(c));

	actual = mktime(&tm);

	/*
	 * The timestamp should be before <= actual <= after
	 */
	assert_true(difftime(actual, before) >= 0);
	assert_true(difftime(after, actual) >= 0);

	TALLOC_FREE(ctx);
}

int main(_UNUSED_ int argc, _UNUSED_ const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_json_add_int),
		cmocka_unit_test(test_json_add_bool),
		cmocka_unit_test(test_json_add_string),
		cmocka_unit_test(test_json_add_object),
		cmocka_unit_test(test_json_add_to_array),
		cmocka_unit_test(test_json_add_timestamp),
		cmocka_unit_test(test_json_add_stringn),
		cmocka_unit_test(test_json_add_version),
		cmocka_unit_test(test_json_add_address),
		cmocka_unit_test(test_json_add_sid),
		cmocka_unit_test(test_json_add_guid),
		cmocka_unit_test(test_json_to_string),
		cmocka_unit_test(test_json_get_array),
		cmocka_unit_test(test_json_get_object),
		cmocka_unit_test(test_audit_get_timestamp),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
