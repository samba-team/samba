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
 * Unit tests for lib/audit_logging/audit_logging.c
 *
 * These tests exercise the error handling code and mock the jannson functions
 * to trigger errors.
 *
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "includes.h"

#include "librpc/ndr/libndr.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/security/dom_sid.h"
#include "lib/messaging/messaging.h"
#include "auth/common_auth.h"

#include "lib/audit_logging/audit_logging.h"

const int JANNASON_FAILURE = -1;
const int CALL_ORIG = -2;

/*
 * cmocka wrappers for json_object
 */
json_t *__wrap_json_object(void);
json_t *__real_json_object(void);
json_t *__wrap_json_object(void)
{

	bool fail = (bool)mock();
	if (fail) {
		return NULL;
	}
	return __real_json_object();
}

/*
 * cmocka wrappers for json_array
 */
json_t *__wrap_json_array(void);
json_t *__real_json_array(void);
json_t *__wrap_json_array(void)
{

	bool fail = (bool)mock();
	if (fail) {
		return NULL;
	}
	return __real_json_array();
}

/*
 * cmoka wrappers for json_integer
 */
json_t *__wrap_json_integer(json_int_t value);
json_t *__real_json_integer(json_int_t value);
json_t *__wrap_json_integer(json_int_t value)
{

	bool fail = (bool)mock();
	if (fail) {
		return NULL;
	}
	return __real_json_integer(value);
}

/*
 * cmocka wrappers for json_string
 */
json_t *__wrap_json_string(const char *value);
json_t *__real_json_string(const char *value);
json_t *__wrap_json_string(const char *value)
{

	bool fail = (bool)mock();
	if (fail) {
		return NULL;
	}
	return __real_json_string(value);
}

/*
 * cmocka wrappers for json_dumps
 */
char *__wrap_json_dumps(const json_t *json, size_t flags);
char *__real_json_dumps(const json_t *json, size_t flags);
char *__wrap_json_dumps(const json_t *json, size_t flags)
{

	bool fail = (bool)mock();
	if (fail) {
		return NULL;
	}
	return __real_json_dumps(json, flags);
}

/*
 * cmocka wrappers for json_object_set_new
 */
int __wrap_json_object_set_new(json_t *object, const char *key, json_t *value);
int __real_json_object_set_new(json_t *object, const char *key, json_t *value);
int __wrap_json_object_set_new(json_t *object, const char *key, json_t *value)
{
	int rc = (int)mock();
	if (rc != CALL_ORIG) {
		return rc;
	}
	return __real_json_object_set_new(object, key, value);
}

/*
 * cmocka wrappers for json_array_append_new
 */
int __wrap_json_array_append_new(json_t *object,
				 const char *key,
				 json_t *value);
int __real_json_array_append_new(json_t *object,
				 const char *key,
				 json_t *value);
int __wrap_json_array_append_new(json_t *object, const char *key, json_t *value)
{
	int rc = (int)mock();
	if (rc != CALL_ORIG) {
		return rc;
	}
	return __real_json_array_append_new(object, key, value);
}

/*
 * cmocka wrappers for json_array_extend
 */
int __wrap_json_array_extend(json_t *array, json_t *other_array);
int __real_json_array_extend(json_t *array, json_t *other_array);
int __wrap_json_array_extend(json_t *array, json_t *other_array)
{

	int rc = (int)mock();
	if (rc != CALL_ORIG) {
		return rc;
	}
	return __real_json_array_extend(array, other_array);
}

/*
 * cmocka wrappers for json_object_update
 */
int __wrap_json_object_update(json_t *object, json_t *other_object);
int __real_json_object_update(json_t *object, json_t *other_object);
int __wrap_json_object_update(json_t *object, json_t *other_object)
{

	int rc = (int)mock();
	if (rc != CALL_ORIG) {
		return rc;
	}
	return __real_json_array_extend(object, other_object);
}

/*
 * cmocka wrappers for gettimeofday
 */
int __wrap_gettimeofday(struct timeval *tv, struct timezone *tz);
int __real_gettimeofday(struct timeval *tv, struct timezone *tz);
int __wrap_gettimeofday(struct timeval *tv, struct timezone *tz)
{

	int rc = (int)mock();
	if (rc != 0) {
		return rc;
	}
	return __real_gettimeofday(tv, tz);
}

/*
 * cmocka wrappers for localtime
 */
struct tm *__wrap_localtime(const time_t *timep);
struct tm *__real_localtime(const time_t *timep);
struct tm *__wrap_localtime(const time_t *timep)
{
	bool fail = (bool)mock();
	if (fail) {
		return NULL;
	}
	return __real_localtime(timep);
}

/*
 * cmocka wrappers for talloc_named_const
 */
static const void *REAL_TALLOC = "Here";

void *__wrap_talloc_named_const(const void *context,
				size_t size,
				const char *name);
void *__real_talloc_named_const(const void *context,
				size_t size,
				const char *name);
void *__wrap_talloc_named_const(const void *context,
				size_t size,
				const char *name)
{

	void *ret = (void *)mock();

	if (ret == NULL) {
		return NULL;
	}
	return __real_talloc_named_const(context, size, name);
}

/*
 * cmocka wrappers for talloc_strdup
 */
char *__wrap_talloc_strdup(const void *t, const char *p);
char *__real_talloc_strdup(const void *t, const char *p);
char *__wrap_talloc_strdup(const void *t, const char *p)
{

	void *ret = (void *)mock();

	if (ret == NULL) {
		return NULL;
	}
	return __real_talloc_strdup(t, p);
}

char *__wrap_tsocket_address_string(const struct tsocket_address *addr,
				    TALLOC_CTX *mem_ctx);
char *__real_tsocket_address_string(const struct tsocket_address *addr,
				    TALLOC_CTX *mem_ctx);
char *__wrap_tsocket_address_string(const struct tsocket_address *addr,
				    TALLOC_CTX *mem_ctx)
{

	bool fail = (bool)mock();
	if (fail) {
		return NULL;
	}
	return __real_tsocket_address_string(addr, mem_ctx);
}

static void test_json_add_int(_UNUSED_ void **state)
{
	struct json_object object;
	int rc = 0;

	will_return(__wrap_json_object, false);
	object = json_new_object();

	/*
	 * Test json integer failure
	 */
	will_return(__wrap_json_integer, true);
	rc = json_add_int(&object, "name", 2);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	/*
	 * Test json object set new failure
	 */
	will_return(__wrap_json_integer, false);
	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_int(&object, "name", 2);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);
	json_free(&object);
}

static void test_json_add_bool(_UNUSED_ void **state)
{
	struct json_object object;
	int rc = 0;

	will_return(__wrap_json_object, false);
	object = json_new_object();

	/*
	 * json_boolean does not return an error code.
	 * Test json object set new failure
	 */
	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_bool(&object, "name", true);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);
}

static void test_json_add_string(_UNUSED_ void **state)
{
	struct json_object object;
	int rc = 0;

	will_return(__wrap_json_object, false);
	object = json_new_object();
	assert_false(json_is_invalid(&object));

	/*
	 * Test json string failure
	 */
	will_return(__wrap_json_string, true);
	rc = json_add_string(&object, "name", "value");

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	/*
	 * Test json object set new failure
	 */
	will_return(__wrap_json_string, false);
	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_string(&object, "name", "value");

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	/*
	 * Test json object set new failure for a NULL string
	 */
	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_string(&object, "null", NULL);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);
}

static void test_json_add_object(_UNUSED_ void **state)
{
	struct json_object object;
	struct json_object value;
	int rc = 0;

	will_return(__wrap_json_object, false);
	will_return(__wrap_json_object, false);

	object = json_new_object();
	value = json_new_object();

	/*
	 * Test json object set new failure
	 */
	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_object(&object, "name", &value);

	assert_false(json_is_invalid(&object));
	assert_false(json_is_invalid(&value));
	assert_int_equal(JSON_ERROR, rc);

	/*
	 * Test json object set new failure for a NULL value
	 */
	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_object(&object, "null", NULL);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);
	json_free(&value);
}

static void test_json_add_to_array(_UNUSED_ void **state)
{
	struct json_object array;
	struct json_object value;
	int rc = 0;

	will_return(__wrap_json_array, false);
	will_return(__wrap_json_object, false);

	array = json_new_array();
	value = json_new_object();

	/*
	 * Test json array append new failure
	 */
	will_return(__wrap_json_array_append_new, JANNASON_FAILURE);
	rc = json_add_object(&array, "name", &value);

	assert_false(json_is_invalid(&array));
	assert_false(json_is_invalid(&value));
	assert_int_equal(JSON_ERROR, rc);

	/*
	 * Test json append new failure with a NULL value
	 */
	will_return(__wrap_json_array_append_new, JANNASON_FAILURE);
	rc = json_add_object(&array, "null", NULL);

	assert_false(json_is_invalid(&array));
	assert_int_equal(JSON_ERROR, rc);

	json_free(&array);
	json_free(&value);
}

static void test_json_add_timestamp(_UNUSED_ void **state)
{
	struct json_object object;
	int rc = 0;

	will_return(__wrap_json_object, false);
	object = json_new_object();

	/*
	 * Test json string failure
	 */
	will_return(__wrap_gettimeofday, 0);
	will_return(__wrap_localtime, false);
	will_return(__wrap_json_string, true);
	rc = json_add_timestamp(&object);

	/*
	 * Test json_object_set_new failure
	 */
	will_return(__wrap_gettimeofday, 0);
	will_return(__wrap_localtime, false);
	will_return(__wrap_json_string, false);
	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_timestamp(&object);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	/*
	 * Test gettimeofday failure
	 */
	will_return(__wrap_gettimeofday, -1);
	rc = json_add_timestamp(&object);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	/*
	 * Test local time failure
	 */
	will_return(__wrap_gettimeofday, 0);
	will_return(__wrap_localtime, true);
	rc = json_add_timestamp(&object);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);
}

static void test_json_add_stringn(_UNUSED_ void **state)
{
	struct json_object object;
	int rc = 0;

	will_return(__wrap_json_object, false);
	object = json_new_object();
	assert_false(json_is_invalid(&object));

	/*
	 * Test json string failure
	 */
	will_return(__wrap_json_string, true);
	rc = json_add_stringn(&object, "name", "value", 3);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	/*
	 * Test json object set new failure
	 */
	will_return(__wrap_json_string, false);
	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_stringn(&object, "name", "value", 3);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	/*
	 * Test json object set new failure for a NULL string
	 */
	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_stringn(&object, "null", NULL, 2);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	/*
	 * Test json object set new failure for a zero string size
	 */
	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_stringn(&object, "zero", "no value", 0);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);
	json_free(&object);
}

static void test_json_add_version(_UNUSED_ void **state)
{
	struct json_object object;
	int rc = 0;

	/*
	 * Fail creating the version object
	 */
	will_return(__wrap_json_object, false);
	object = json_new_object();

	will_return(__wrap_json_object, true);
	rc = json_add_version(&object, 1, 11);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);

	/*
	 * Fail adding the major version
	 */
	will_return(__wrap_json_object, false);
	object = json_new_object();

	will_return(__wrap_json_object, false);
	will_return(__wrap_json_integer, false);
	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_version(&object, 2, 12);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);

	/*
	 * Fail adding the minor version
	 */
	will_return(__wrap_json_object, false);
	object = json_new_object();

	will_return(__wrap_json_object, false);
	will_return(__wrap_json_integer, false);
	will_return(__wrap_json_object_set_new, CALL_ORIG);
	will_return(__wrap_json_integer, false);
	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_version(&object, 3, 13);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);

	/*
	 * Fail adding the version object
	 */
	will_return(__wrap_json_object, false);
	object = json_new_object();

	will_return(__wrap_json_object, false);
	will_return(__wrap_json_integer, false);
	will_return(__wrap_json_object_set_new, CALL_ORIG);
	will_return(__wrap_json_integer, false);
	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_version(&object, 4, 14);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);
}

static void test_json_add_address(_UNUSED_ void **state)
{
	struct json_object object;
	int rc = 0;
	struct tsocket_address *ip = NULL;

	TALLOC_CTX *ctx = NULL;

	will_return(__wrap_talloc_named_const, REAL_TALLOC);
	ctx = talloc_new(NULL);

	/*
	 * Add a null address
	 */
	will_return(__wrap_json_object, false);
	object = json_new_object();

	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_address(&object, "name", NULL);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	/*
	 * Add a non null address, json_object_set_new failure
	 */
	rc = tsocket_address_inet_from_strings(ctx, "ip", "127.0.0.1", 21, &ip);
	assert_int_equal(0, rc);

	will_return(__wrap_talloc_named_const, REAL_TALLOC);
	will_return(__wrap_tsocket_address_string, false);
	will_return(__wrap_json_string, false);
	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_address(&object, "name", ip);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	/*
	 * Add a non null address, with a talloc failure
	 */
	rc = tsocket_address_inet_from_strings(ctx, "ip", "127.0.0.1", 21, &ip);
	assert_int_equal(0, rc);

	will_return(__wrap_talloc_named_const, NULL);
	rc = json_add_address(&object, "name", ip);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	/*
	 * Add a non null address, tsocket_address_string failure
	 */
	rc = tsocket_address_inet_from_strings(ctx, "ip", "127.0.0.1", 21, &ip);
	assert_int_equal(0, rc);

	will_return(__wrap_talloc_named_const, REAL_TALLOC);
	will_return(__wrap_tsocket_address_string, true);
	rc = json_add_address(&object, "name", ip);

	assert_false(json_is_invalid(&object));
	assert_int_equal(JSON_ERROR, rc);

	TALLOC_FREE(ctx);
	json_free(&object);
}

static void test_json_add_sid(void **state)
{
	struct json_object object;
	const char *SID = "S-1-5-21-2470180966-3899876309-2637894779";
	struct dom_sid sid;
	int rc;

	/*
	 * Add a null SID
	 */
	will_return(__wrap_json_object, false);
	object = json_new_object();

	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_sid(&object, "null", NULL);
	assert_int_equal(JSON_ERROR, rc);

	/*
	 * Add a non null SID
	 */
	assert_true(string_to_sid(&sid, SID));
	will_return(__wrap_json_string, false);
	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_sid(&object, "sid", &sid);
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);
}

static void test_json_add_guid(void **state)
{
	struct json_object object;
	const char *GUID = "3ab88633-1e57-4c1a-856c-d1bc4b15bbb1";
	struct GUID guid;
	NTSTATUS status;
	int rc;

	/*
	 * Add a null GUID
	 */
	will_return(__wrap_json_object, false);
	object = json_new_object();

	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_guid(&object, "null", NULL);
	assert_int_equal(JSON_ERROR, rc);

	/*
	 * Add a non null GUID
	 */
	status = GUID_from_string(GUID, &guid);
	assert_true(NT_STATUS_IS_OK(status));
	will_return(__wrap_json_string, false);
	will_return(__wrap_json_object_set_new, JANNASON_FAILURE);
	rc = json_add_guid(&object, "guid", &guid);
	assert_int_equal(JSON_ERROR, rc);

	json_free(&object);
}

static void test_json_to_string(_UNUSED_ void **state)
{
	struct json_object object;
	char *s = NULL;
	TALLOC_CTX *ctx = NULL;

	will_return(__wrap_talloc_named_const, REAL_TALLOC);
	ctx = talloc_new(NULL);

	will_return(__wrap_json_object, false);
	object = json_new_object();

	/*
	 * json_dumps failure
	 */
	will_return(__wrap_json_dumps, true);
	s = json_to_string(ctx, &object);
	assert_null(s);

	/*
	 * talloc failure
	 */
	will_return(__wrap_json_dumps, false);
	will_return(__wrap_talloc_strdup, NULL);
	s = json_to_string(ctx, &object);
	assert_null(s);
	TALLOC_FREE(ctx);
	json_free(&object);
}

static void test_json_get_array(_UNUSED_ void **state)
{
	struct json_object object;
	struct json_object stored_array;
	struct json_object array;

	int rc;

	will_return(__wrap_json_object, false);
	object = json_new_object();
	assert_false(json_is_invalid(&object));

	will_return(__wrap_json_array, false);
	stored_array = json_new_array();
	assert_false(json_is_invalid(&stored_array));

	will_return(__wrap_json_object_set_new, CALL_ORIG);
	rc = json_add_object(&object, "array", &stored_array);
	assert_int_equal(0, rc);

	/*
	 * json array failure
	 */
	will_return(__wrap_json_array, true);
	array = json_get_array(&object, "array");
	assert_true(json_is_invalid(&array));

	/*
	 * json array extend failure
	 */
	will_return(__wrap_json_array, false);
	will_return(__wrap_json_array_extend, true);
	array = json_get_array(&object, "array");
	assert_true(json_is_invalid(&array));

	json_free(&stored_array);
	json_free(&object);
}

static void test_json_get_object(_UNUSED_ void **state)
{
	struct json_object object;
	struct json_object stored;
	struct json_object retreived;

	int rc;

	will_return(__wrap_json_object, false);
	object = json_new_object();
	assert_false(json_is_invalid(&object));

	will_return(__wrap_json_object, false);
	stored = json_new_object();
	assert_false(json_is_invalid(&stored));

	will_return(__wrap_json_object_set_new, CALL_ORIG);
	rc = json_add_object(&object, "stored", &stored);
	assert_int_equal(0, rc);

	/*
	 * json object update failure
	 */
	will_return(__wrap_json_object, false);
	will_return(__wrap_json_object_update, true);
	retreived = json_get_object(&object, "stored");
	assert_true(json_is_invalid(&retreived));

	json_free(&object);
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
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
