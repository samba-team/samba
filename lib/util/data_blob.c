/*
   Unix SMB/CIFS implementation.
   Easy management of byte-length data
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Andrew Bartlett 2001

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
#include "attr.h"
#include "data_blob.h"
#include "lib/util/samba_util.h"
#include "lib/util/tsort.h"

const DATA_BLOB data_blob_null = { NULL, 0 };

/**
 * @file
 * @brief Manipulation of arbitrary data blobs
 **/

/**
 construct a data blob, must be freed with data_blob_free()
 you can pass NULL for p and get a blank data blob
**/
_PUBLIC_ DATA_BLOB data_blob_named(const void *p, size_t length, const char *name)
{
	return data_blob_talloc_named(NULL, p, length, name);
}

/**
 construct a data blob, using supplied TALLOC_CTX
**/
_PUBLIC_ DATA_BLOB data_blob_talloc_named(TALLOC_CTX *mem_ctx, const void *p, size_t length, const char *name)
{
	DATA_BLOB ret;

	if (p == NULL && length == 0) {
		ZERO_STRUCT(ret);
		return ret;
	}

	if (p) {
		ret.data = (uint8_t *)talloc_memdup(mem_ctx, p, length);
	} else {
		ret.data = talloc_array(mem_ctx, uint8_t, length);
	}
	if (ret.data == NULL) {
		ret.length = 0;
		return ret;
	}
	talloc_set_name_const(ret.data, name);
	ret.length = length;
	return ret;
}

/**
 construct a zero data blob, using supplied TALLOC_CTX.
 use this sparingly as it initialises data - better to initialise
 yourself if you want specific data in the blob
**/
_PUBLIC_ DATA_BLOB data_blob_talloc_zero(TALLOC_CTX *mem_ctx, size_t length)
{
	DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, length);
	data_blob_clear(&blob);
	return blob;
}

/**
free a data blob
**/
_PUBLIC_ void data_blob_free(DATA_BLOB *d)
{
	if (d) {
		TALLOC_FREE(d->data);
		d->length = 0;
	}
}

/**
clear a DATA_BLOB's contents
**/
_PUBLIC_ void data_blob_clear(DATA_BLOB *d)
{
	if (d->data) {
		ZERO_ARRAY_LEN(d->data, d->length);
	}
}

/**
free a data blob and clear its contents
**/
_PUBLIC_ void data_blob_clear_free(DATA_BLOB *d)
{
	data_blob_clear(d);
	data_blob_free(d);
}


/**
check if two data blobs are equal
**/
_PUBLIC_ int data_blob_cmp(const DATA_BLOB *d1, const DATA_BLOB *d2)
{
	int ret;
	if (d1->data == NULL && d2->data != NULL) {
		return -1;
	}
	if (d1->data != NULL && d2->data == NULL) {
		return 1;
	}
	if (d1->data == d2->data) {
		return NUMERIC_CMP(d1->length, d2->length);
	}
	ret = memcmp(d1->data, d2->data, MIN(d1->length, d2->length));
	if (ret == 0) {
		/* Note this ordering is used in conditional aces */
		return NUMERIC_CMP(d1->length, d2->length);
	}
	return ret;
}

/**
check if two data blobs are equal, where the time taken should not depend on the
contents of either blob.
**/
_PUBLIC_ bool data_blob_equal_const_time(const DATA_BLOB *d1, const DATA_BLOB *d2)
{
	bool ret;
	if (d1->data == NULL && d2->data != NULL) {
		return false;
	}
	if (d1->data != NULL && d2->data == NULL) {
		return false;
	}
	if (d1->length != d2->length) {
		return false;
	}
	if (d1->data == d2->data) {
		return true;
	}
	ret = mem_equal_const_time(d1->data, d2->data, d1->length);
	return ret;
}

/**
print the data_blob as hex string
**/
_PUBLIC_ char *data_blob_hex_string_lower(TALLOC_CTX *mem_ctx, const DATA_BLOB *blob)
{
	size_t i;
	char *hex_string;

	hex_string = talloc_array(mem_ctx, char, (blob->length*2)+1);
	if (!hex_string) {
		return NULL;
	}

	/* this must be lowercase or w2k8 cannot join a samba domain,
	   as this routine is used to encode extended DNs and windows
	   only accepts lowercase hexadecimal numbers */
	for (i = 0; i < blob->length; i++) {
		hex_string[i * 2] = nybble_to_hex_lower(blob->data[i] >> 4);
		hex_string[i * 2 + 1] = nybble_to_hex_lower(blob->data[i]);
	}

	hex_string[(blob->length*2)] = '\0';
	return hex_string;
}

_PUBLIC_ char *data_blob_hex_string_upper(TALLOC_CTX *mem_ctx, const DATA_BLOB *blob)
{
	size_t i;
	char *hex_string;

	hex_string = talloc_array(mem_ctx, char, (blob->length*2)+1);
	if (!hex_string) {
		return NULL;
	}

	for (i = 0; i < blob->length; i++) {
		hex_string[i * 2] = nybble_to_hex_upper(blob->data[i] >> 4);
		hex_string[i * 2 + 1] = nybble_to_hex_upper(blob->data[i]);
	}

	hex_string[(blob->length*2)] = '\0';
	return hex_string;
}

/**
  useful for constructing data blobs in test suites, while
  avoiding const warnings
**/
_PUBLIC_ DATA_BLOB data_blob_string_const(const char *str)
{
	DATA_BLOB blob;
	blob.data = discard_const_p(uint8_t, str);
	blob.length = str ? strlen(str) : 0;
	return blob;
}

/**
  useful for constructing data blobs in test suites, while
  avoiding const warnings
**/
_PUBLIC_ DATA_BLOB data_blob_string_const_null(const char *str)
{
	DATA_BLOB blob;
	blob.data = discard_const_p(uint8_t, str);
	blob.length = str ? strlen(str)+1 : 0;
	return blob;
}

/**
 * Create a new data blob from const data
 */

_PUBLIC_ DATA_BLOB data_blob_const(const void *p, size_t length)
{
	DATA_BLOB blob;
	blob.data = discard_const_p(uint8_t, p);
	blob.length = length;
	return blob;
}


/**
  realloc a data_blob
**/
_PUBLIC_ bool data_blob_realloc(TALLOC_CTX *mem_ctx, DATA_BLOB *blob, size_t length)
{
	uint8_t *tmp = talloc_realloc(mem_ctx, blob->data, uint8_t, length);
	if (tmp == NULL) {
		return false;
	}
	blob->data = tmp;
	blob->length = length;
	return true;
}


/**
  append some data to a data blob
**/
_PUBLIC_ bool data_blob_append(TALLOC_CTX *mem_ctx, DATA_BLOB *blob,
				   const void *p, size_t length)
{
	size_t old_len = blob->length;
	size_t new_len = old_len + length;

	if (length == 0) {
		return true;
	}

	if (new_len < length || new_len < old_len) {
		return false;
	}

	if ((const uint8_t *)p + length < (const uint8_t *)p) {
		return false;
	}

	if (!data_blob_realloc(mem_ctx, blob, new_len)) {
		return false;
	}

	memcpy(blob->data + old_len, p, length);
	return true;
}

/**
  pad the length of a data blob to a multiple of
  'pad'. 'pad' must be a power of two.
**/
_PUBLIC_ bool data_blob_pad(TALLOC_CTX *mem_ctx, DATA_BLOB *blob,
			    size_t pad)
{
	size_t old_len = blob->length;
	size_t new_len = (old_len + pad - 1) & ~(pad - 1);

	if (new_len < old_len || (pad & (pad - 1)) != 0) {
		return false;
	}

	if (!data_blob_realloc(mem_ctx, blob, new_len)) {
		return false;
	}

	memset(blob->data + old_len, 0, new_len - old_len);
	return true;
}
