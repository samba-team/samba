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
#include "marshalling.h"
#include "lib/util/charset/charset.h"
#include "lib/util/talloc_stack.h"
#include "system/time.h"

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

static char *tab_level(TALLOC_CTX *mem_ctx, int level)
{
	int i;
	char *string = talloc_array(mem_ctx, char, level + 1);

	for (i = 0; i < level; i++) {
		string[i] = '\t';
	}

	string[i] = '\0';
	return string;
}

char *dalloc_dump(DALLOC_CTX *dd, int nestinglevel)
{
	const char *type;
	int n, result;
	uint64_t i;
	sl_bool_t bl;
	sl_time_t t;
	struct tm *tm;
	char datestring[256];
	sl_cnids_t cnids;
	char *logstring, *nested_logstring;
	char *tab_string1, *tab_string2;
	void *p;
	bool ok;
	char *utf8string;
	size_t utf8len;

	tab_string1 = tab_level(dd, nestinglevel);
	if (tab_string1 == NULL) {
		return NULL;
	}
	tab_string2 = tab_level(dd, nestinglevel + 1);
	if (tab_string2 == NULL) {
		return NULL;
	}

	logstring = talloc_asprintf(dd,
				    "%s%s(#%zu): {\n",
				    tab_string1,
				    talloc_get_name(dd),
				    dalloc_size(dd));
	if (logstring == NULL) {
		return NULL;
	}

	for (n = 0; n < dalloc_size(dd); n++) {
		type = dalloc_get_name(dd, n);
		if (type == NULL) {
			return NULL;
		}
		p = dalloc_get_object(dd, n);
		if (p == NULL) {
			return NULL;
		}
		if (strcmp(type, "DALLOC_CTX") == 0
		    || strcmp(type, "sl_array_t") == 0
		    || strcmp(type, "sl_filemeta_t") == 0
		    || strcmp(type, "sl_dict_t") == 0) {
			nested_logstring = dalloc_dump(p, nestinglevel + 1);
			if (nested_logstring == NULL) {
				return NULL;
			}
			logstring = talloc_strdup_append(logstring,
							 nested_logstring);
		} else if (strcmp(type, "uint64_t") == 0) {
			memcpy(&i, p, sizeof(uint64_t));
			logstring = talloc_asprintf_append(
				logstring,
				"%suint64_t: 0x%04jx\n",
				tab_string2, (uintmax_t)i);
		} else if (strcmp(type, "char *") == 0) {
			logstring = talloc_asprintf_append(
				logstring,
				"%sstring: %s\n",
				tab_string2,
				(char *)p);
		} else if (strcmp(type, "smb_ucs2_t *") == 0) {
			ok = convert_string_talloc(talloc_tos(),
						   CH_UTF16LE,
						   CH_UTF8,
						   p,
						   talloc_get_size(p),
						   &utf8string,
						   &utf8len);
			if (!ok) {
				return NULL;
			}
			logstring = talloc_asprintf_append(
				logstring,
				"%sUTF16-string: %s\n",
				tab_string2,
				utf8string);
			TALLOC_FREE(utf8string);
		} else if (strcmp(type, "sl_bool_t") == 0) {
			memcpy(&bl, p, sizeof(sl_bool_t));
			logstring = talloc_asprintf_append(
				logstring,
				"%sbool: %s\n",
				tab_string2,
				bl ? "true" : "false");
		} else if (strcmp(type, "sl_nil_t") == 0) {
			logstring = talloc_asprintf_append(
				logstring,
				"%snil\n",
				tab_string2);
		} else if (strcmp(type, "sl_time_t") == 0) {
			memcpy(&t, p, sizeof(sl_time_t));
			tm = localtime(&t.tv_sec);
			if (tm == NULL) {
				return NULL;
			}
			result = strftime(datestring,
					 sizeof(datestring),
					 "%Y-%m-%d %H:%M:%S", tm);
			if (result == 0) {
				return NULL;
			}
			logstring = talloc_asprintf_append(
				logstring,
				"%ssl_time_t: %s.%06lu\n",
				tab_string2,
				datestring,
				(unsigned long)t.tv_usec);
		} else if (strcmp(type, "sl_cnids_t") == 0) {
			memcpy(&cnids, p, sizeof(sl_cnids_t));
			logstring = talloc_asprintf_append(
				logstring,
				"%sCNIDs: unkn1: 0x%" PRIx16 ", unkn2: 0x%" PRIx32 "\n",
				tab_string2,
				cnids.ca_unkn1,
				cnids.ca_context);
			if (logstring == NULL) {
				return NULL;
			}
			if (cnids.ca_cnids) {
				nested_logstring = dalloc_dump(
					cnids.ca_cnids,
					nestinglevel + 2);
				if (!nested_logstring) {
					return NULL;
				}
				logstring = talloc_strdup_append(logstring,
								 nested_logstring);
			}
		} else {
			logstring = talloc_asprintf_append(
				logstring,
				"%stype: %s\n",
				tab_string2,
				type);
		}
		if (logstring == NULL) {
			return NULL;
		}
	}
	logstring = talloc_asprintf_append(logstring,
					   "%s}\n",
					   tab_string1);
	if (logstring == NULL) {
		return NULL;
	}
	return logstring;
}
