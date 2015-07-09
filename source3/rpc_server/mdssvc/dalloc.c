/*
  Copyright (c) Ralph Boehme			2012-2014

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

#include "replace.h"
#include <talloc.h>
#include "dalloc.h"

/**
 * Dynamic Datastore
 **/
struct dalloc_ctx {
	void **dd_talloc_array;
};

void *_dalloc_new(TALLOC_CTX *mem_ctx, const char *type)
{
	void *p;

	p = talloc_zero(mem_ctx, DALLOC_CTX);
	if (p == NULL) {
		return NULL;
	}
	talloc_set_name_const(p, type);

	return p;
}

int _dalloc_add_talloc_chunk(DALLOC_CTX *dd, void *obj, const char *type, size_t size)
{
	size_t array_len = talloc_array_length(dd->dd_talloc_array);

	dd->dd_talloc_array = talloc_realloc(dd,
					     dd->dd_talloc_array,
					     void *,
					     array_len + 1);
	if (dd->dd_talloc_array == NULL) {
		return -1;
	}

	if (size != 0) {
		void *p;

		p = talloc_named_const(dd->dd_talloc_array, size, type);
		if (p == NULL) {
			return -1;
		}
		memcpy(p, obj, size);
		obj = p;
	} else {
		_talloc_get_type_abort(obj, type, __location__);
	}

	dd->dd_talloc_array[array_len] = obj;

	return 0;
}

/* Get number of elements, returns 0 if the structure is empty or not initialized */
size_t dalloc_size(const DALLOC_CTX *d)
{
	if (d == NULL) {
		return 0;
	}

	if (d->dd_talloc_array == NULL) {
		return 0;
	}

	return talloc_array_length(d->dd_talloc_array);
}

/* Return element at position */
void *dalloc_get_object(const DALLOC_CTX *d, int i)
{
	size_t size = dalloc_size(d);

	if (i >= size) {
		return NULL;
	}

	return d->dd_talloc_array[i];
}

/* Return typename of element at position */
const char *dalloc_get_name(const DALLOC_CTX *d, int i)
{
	void *o = dalloc_get_object(d, i);

	if (o == NULL) {
		return NULL;
	}

	return talloc_get_name(o);
}

/*
 * Get pointer to value from a DALLOC object
 *
 * Returns pointer to object from a DALLOC object. Nested object interation
 * is supported by using the type string "DALLOC_CTX". Any other type string
 * designates the requested objects type.
 */
void *dalloc_get(const DALLOC_CTX *d, ...)
{
	int result = 0;
	void *p = NULL;
	va_list args;
	const char *type;
	int elem;

	va_start(args, d);
	type = va_arg(args, const char *);

	while (strcmp(type, "DALLOC_CTX") == 0) {
		elem = va_arg(args, int);
		if (elem >= talloc_array_length(d->dd_talloc_array)) {
			result = -1;
			goto done;
		}
		d = d->dd_talloc_array[elem];
		type = va_arg(args, const char *);
	}

	elem = va_arg(args, int);
	if (elem >= talloc_array_length(d->dd_talloc_array)) {
		result = -1;
		goto done;
	}

	p = talloc_check_name(d->dd_talloc_array[elem], type);
	if (p == NULL) {
		result = -1;
		goto done;
	}

done:
	va_end(args);
	if (result != 0) {
		p = NULL;
	}
	return p;
}

void *dalloc_value_for_key(const DALLOC_CTX *d, ...)
{
	int result = 0;
	void *p = NULL;
	va_list args;
	const char *type;
	int elem;
	size_t array_len;

	va_start(args, d);
	type = va_arg(args, const char *);

	while (strcmp(type, "DALLOC_CTX") == 0) {
		array_len = talloc_array_length(d->dd_talloc_array);
		elem = va_arg(args, int);
		if (elem >= array_len) {
			va_end(args);
			result = -1;
			goto done;
		}
		d = d->dd_talloc_array[elem];
		type = va_arg(args, const char *);
	}

	va_end(args);

	array_len = talloc_array_length(d->dd_talloc_array);

	for (elem = 0; elem + 1 < array_len; elem += 2) {
		if (strcmp(talloc_get_name(d->dd_talloc_array[elem]), "char *") != 0) {
			result = -1;
			goto done;
		}
		if (strcmp((char *)d->dd_talloc_array[elem],type) == 0) {
			p = d->dd_talloc_array[elem + 1];
			break;
		}
	}

done:
	if (result != 0) {
		p = NULL;
	}
	return p;
}

static char *dalloc_strdup(TALLOC_CTX *mem_ctx, const char *string)
{
	char *p;

	p = talloc_strdup(mem_ctx, string);
	if (p == NULL) {
		return NULL;
	}
	talloc_set_name_const(p, "char *");
	return p;
}

int dalloc_stradd(DALLOC_CTX *d, const char *string)
{
	int result;
	char *p;

	p = dalloc_strdup(d, string);
	if (p == NULL) {
		return -1;
	}

	result = dalloc_add(d, p, char *);
	if (result != 0) {
		return -1;
	}

	return 0;
}
