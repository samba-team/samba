/*
 * String Vector functions modeled after glibc argv_* functions
 *
 * Copyright Volker Lendecke <vl@samba.org> 2014
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
#include "strv.h"
#include "talloc.h"
#include <string.h>

static int _strv_append(TALLOC_CTX *mem_ctx, char **dst, const char *src,
			size_t srclen)
{
	size_t dstlen = talloc_array_length(*dst);
	size_t newlen = dstlen + srclen;
	char *new_dst;

	if ((newlen < srclen) || (newlen < dstlen)) {
		return ERANGE;
	}

	new_dst = talloc_realloc(mem_ctx, *dst, char, newlen);
	if (new_dst == NULL) {
		return ENOMEM;
	}
	memcpy(&new_dst[dstlen], src, srclen);

	*dst = new_dst;
	return 0;
}

int strv_add(TALLOC_CTX *mem_ctx, char **strv, const char *string)
{
	return _strv_append(mem_ctx, strv, string, strlen(string)+1);
}

int strv_addn(TALLOC_CTX *mem_ctx, char **strv, const char *string, size_t n)
{
        char t[n+1];

        memcpy(t, string, n);
        t[n] = '\0';
        return _strv_append(mem_ctx, strv, t, n+1);
}

int strv_append(TALLOC_CTX *mem_ctx, char **strv, const char *src)
{
	return _strv_append(mem_ctx, strv, src, talloc_array_length(src));
}

static bool strv_valid_entry(const char *strv, size_t strv_len,
			     const char *entry, size_t *entry_len)
{
	if (strv_len == 0) {
		return false;
	}
	if (strv[strv_len-1] != '\0') {
		return false;
	}

	if (entry < strv) {
		return false;
	}
	if (entry >= (strv+strv_len)) {
		return false;
	}

	if (entry_len != NULL) {
		*entry_len = strlen(entry);
	}

	return true;
}

const char *strv_len_next(const char *strv, size_t strv_len,
			  const char *entry)
{
	size_t entry_len;

	if (entry == NULL) {
		if (strv_valid_entry(strv, strv_len, strv, NULL)) {
			return strv;
		}
		return NULL;
	}

	if (!strv_valid_entry(strv, strv_len, entry, &entry_len)) {
		return NULL;
	}

	entry += entry_len+1;

	if (entry >= (strv + strv_len)) {
		return NULL;
	}
	return entry;
}

char *strv_next(char *strv, const char *entry)
{
	size_t len = talloc_array_length(strv);
	const char *result;

	result = strv_len_next(strv, len, entry);
	return discard_const_p(char, result);
}

size_t strv_count(char *strv)
{
	char *entry;
	size_t count = 0;

	for (entry = strv; entry != NULL; entry = strv_next(strv, entry)) {
		count += 1;
	}

	return count;
}

char *strv_find(char *strv, const char *entry)
{
	char *e = NULL;

	while ((e = strv_next(strv, e)) != NULL) {
		if (strcmp(e, entry) == 0) {
			return e;
		}
	}

	return NULL;
}

void strv_delete(char **strv, char *entry)
{
	size_t len = talloc_array_length(*strv);
	size_t entry_len;

	if (entry == NULL) {
		return;
	}

	if (!strv_valid_entry(*strv, len, entry, &entry_len)) {
		return;
	}
	entry_len += 1;

	memmove(entry, entry+entry_len,
		len - entry_len - (entry - *strv));

	*strv = talloc_realloc(NULL, *strv, char, len - entry_len);
}

char * const *strv_to_env(TALLOC_CTX *mem_ctx, char *strv)
{
       char **data;
       char *next = NULL;
       size_t i;
       size_t count = strv_count(strv);

       if (strv == NULL) {
               return NULL;
       }

       data = talloc_array(mem_ctx, char *, count + 1);

       if (data == NULL) {
               return NULL;
       }

       for(i = 0; i < count; i++) {
               next = strv_next(strv, next);
               data[i] = next;
       }
       data[count] = NULL;

       return data;
}
