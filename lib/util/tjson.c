/*
 * Talloc wrapper for jansson JSON objects
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
 */

#include "replace.h"
#include "system/time.h"
#include "lib/util/time_basic.h"
#include "tjson.h"

#ifdef HAVE_JANSSON

struct tjson {
	json_t *root;
};

static int tjson_object_destructor(struct tjson *jsobj)
{
	if (jsobj->root != NULL) {
		json_decref(jsobj->root);
		jsobj->root = NULL;
	}
	return 0;
}

struct tjson *tjson_wrap(TALLOC_CTX *mem_ctx, json_t **root)
{
	struct tjson *jsobj = NULL;

	if (*root == NULL) {
		return NULL;
	}

	jsobj = talloc(mem_ctx, struct tjson);
	if (jsobj == NULL) {
		json_decref(*root);
		*root = NULL;
		return NULL;
	}
	*jsobj = (struct tjson){.root = *root};
	*root = NULL;
	talloc_set_destructor(jsobj, tjson_object_destructor);

	return jsobj;
}

struct tjson *tjson_new_object(TALLOC_CTX *mem_ctx)
{
	json_t *o = json_object();
	struct tjson *ret = tjson_wrap(mem_ctx, &o);
	return ret;
}

struct tjson *tjson_new_array(TALLOC_CTX *mem_ctx)
{
	json_t *a = json_array();
	struct tjson *ret = tjson_wrap(mem_ctx, &a);
	return ret;
}

json_t *tjson_unwrap(struct tjson **pobject)
{
	struct tjson *object = NULL;
	json_t *root = NULL;

	if (pobject == NULL) {
		return NULL;
	}

	object = *pobject;
	if (object == NULL) {
		return NULL;
	}

	root = object->root;
	object->root = NULL;
	TALLOC_FREE(object);
	*pobject = NULL;

	return root;
}

bool tjson_has_error(struct tjson *object)
{
	return (object == NULL) || (object->root == NULL);
}

/*
 * Poison "object": release its current json_t and mark it as failed. A
 * no-op if "object" is already poisoned (or NULL).
 */
static void tjson_set_error(struct tjson *object)
{
	if ((object == NULL) || (object->root == NULL)) {
		return;
	}
	json_decref(object->root);
	object->root = NULL;
}

static void tjson_add_json(struct tjson *object,
			   const char *name,
			   json_t *value)
{
	json_type type;
	int ret;

	if (tjson_has_error(object) || (value == NULL)) {
		goto fail;
	}

	type = json_typeof(object->root);

	switch (type) {
	case JSON_ARRAY:
		if (name != NULL) {
			goto fail;
		}
		ret = json_array_append_new(object->root, value);
		break;
	case JSON_OBJECT:
		ret = json_object_set_new(object->root, name, value);
		break;
	default:
		goto fail;
	}

	if (ret != 0) {
		/*
		 * json_array_append_new()/json_object_set_new()
		 * decref "value" even on failure, so it must not be
		 * touched again here.
		 */
		tjson_set_error(object);
	}
	return;

fail:
	json_decref(value); /* accepts value==NULL */
	tjson_set_error(object);
}

void tjson_add_int(struct tjson *object, const char *name, json_int_t value)
{
	tjson_add_json(object, name, json_integer(value));
}

void tjson_add_bool(struct tjson *object, const char *name, bool value)
{
	tjson_add_json(object, name, json_boolean(value));
}

void tjson_add_stringn(struct tjson *object,
		       const char *name,
		       const char *value,
		       size_t len)
{
	json_t *jv = NULL;

	if (value == NULL) {
		jv = json_null();
	} else {
		jv = json_stringn(value, len);
	}

	tjson_add_json(object, name, jv);
}

void tjson_add_string(struct tjson *object,
		      const char *name,
		      const char *value)
{
	tjson_add_stringn(object,
			  name,
			  value,
			  (value != NULL) ? strlen(value) : 0);
}

void tjson_add_object(struct tjson *object,
		      const char *name,
		      struct tjson **pvalue)
{
	struct tjson *value = NULL;
	json_t *jv = NULL;

	if (pvalue != NULL) {
		value = *pvalue;
		*pvalue = NULL;
	}

	if (tjson_has_error(value)) {
		tjson_set_error(object);
		TALLOC_FREE(value);
		return;
	}

	jv = value->root;
	/*
	 * json_object_set_new()/json_array_append_new() steal (and
	 * decref) "jv" whether they succeed or not; keep our own
	 * reference so that freeing "value" below always releases
	 * exactly one reference, regardless of the outcome.
	 */
	json_incref(jv);
	tjson_add_json(object, name, jv);

	TALLOC_FREE(value);
}

/*
 * Add an ISO 8601 timestamp to the object.
 */
void tjson_add_time(struct tjson *object,
		    const char *name,
		    const struct timeval tv)
{
	char buffer[40] = {};
	char timestamp[65] = {};
	char tz[10] = {};
	struct tm *tm_info = NULL;

	if (tjson_has_error(object)) {
		return;
	}

	tm_info = localtime(&tv.tv_sec);
	if (tm_info == NULL) {
		tjson_set_error(object);
		return;
	}

	strftime(buffer, sizeof(buffer) - 1, "%Y-%m-%dT%T", tm_info);
	strftime(tz, sizeof(tz) - 1, "%z", tm_info);
	snprintf(timestamp,
		 sizeof(timestamp),
		 "%s.%06ld%s",
		 buffer,
		 tv.tv_usec,
		 tz);

	tjson_add_string(object, name, timestamp);
}

void tjson_add_timestamp(struct tjson *object)
{
	struct timeval tv;
	GetTimeOfDay(&tv);
	tjson_add_time(object, "timestamp", tv);
}

char *tjson_to_string_flags(TALLOC_CTX *mem_ctx,
			    struct tjson *object,
			    size_t flags)
{
	size_t len;
	char *ret = NULL;

	if (tjson_has_error(object)) {
		return NULL;
	}

	len = json_dumpb(object->root, NULL, 0, flags);

	ret = talloc_array(mem_ctx, char, len + 1);
	if (ret == NULL) {
		return NULL;
	}

	json_dumpb(object->root, ret, len, flags);
	ret[len] = '\0';

	return ret;
}

char *tjson_to_string(TALLOC_CTX *mem_ctx, struct tjson *object)
{
	return tjson_to_string_flags(mem_ctx, object, 0);
}

#endif /* HAVE_JANSSON */
