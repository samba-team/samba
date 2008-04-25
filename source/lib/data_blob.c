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

#include "includes.h"

const DATA_BLOB data_blob_null = { NULL, 0, NULL };

/*******************************************************************
 Free() a data blob.
*******************************************************************/

static void free_data_blob(DATA_BLOB *d)
{
	if ((d) && (d->free)) {
		SAFE_FREE(d->data);
	}
}

/*******************************************************************
 Construct a data blob, must be freed with data_blob_free().
 You can pass NULL for p and get a blank data blob
*******************************************************************/

DATA_BLOB data_blob(const void *p, size_t length)
{
	DATA_BLOB ret;

	if (!length) {
		ZERO_STRUCT(ret);
		return ret;
	}

	if (p) {
		ret.data = (uint8 *)smb_xmemdup(p, length);
	} else {
		ret.data = SMB_XMALLOC_ARRAY(uint8, length);
	}
	ret.length = length;
	ret.free = free_data_blob;
	return ret;
}

/*******************************************************************
 Construct a data blob, using supplied TALLOC_CTX.
*******************************************************************/

DATA_BLOB data_blob_talloc(TALLOC_CTX *mem_ctx, const void *p, size_t length)
{
	DATA_BLOB ret;

	if (!length) {
		ZERO_STRUCT(ret);
		return ret;
	}

	if (p) {
		ret.data = (uint8 *)TALLOC_MEMDUP(mem_ctx, p, length);
		if (ret.data == NULL)
			smb_panic("data_blob_talloc: TALLOC_MEMDUP failed");
	} else {
		ret.data = (uint8 *)TALLOC(mem_ctx, length);
		if (ret.data == NULL)
			smb_panic("data_blob_talloc: TALLOC failed");
	}

	ret.length = length;
	ret.free = NULL;
	return ret;
}

/*******************************************************************
 Free a data blob.
*******************************************************************/

void data_blob_free(DATA_BLOB *d)
{
	if (d) {
		if (d->free) {
			(d->free)(d);
		}
		d->length = 0;
	}
}

/*******************************************************************
 Clear a DATA_BLOB's contents
*******************************************************************/

void data_blob_clear(DATA_BLOB *d)
{
	if (d->data) {
		memset(d->data, 0, d->length);
	}
}

/*******************************************************************
 Free a data blob and clear its contents
*******************************************************************/

void data_blob_clear_free(DATA_BLOB *d)
{
	data_blob_clear(d);
	data_blob_free(d);
}

/**
  useful for constructing data blobs in test suites, while
  avoiding const warnings
**/
DATA_BLOB data_blob_string_const(const char *str)
{
	DATA_BLOB blob;
	blob.data = CONST_DISCARD(uint8 *, str);
	blob.length = strlen(str) + 1;
	blob.free = NULL;
	return blob;
}

/**
 * Create a new data blob from const data 
 */
DATA_BLOB data_blob_const(const void *p, size_t length)
{
	DATA_BLOB blob;
	blob.data = CONST_DISCARD(uint8 *, p);
	blob.length = length;
	blob.free = NULL;
	return blob;
}

/**
 construct a zero data blob, using supplied TALLOC_CTX.
 use this sparingly as it initialises data - better to initialise
 yourself if you want specific data in the blob
**/
DATA_BLOB data_blob_talloc_zero(TALLOC_CTX *mem_ctx, size_t length)
{
	DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, length);
	data_blob_clear(&blob);
	return blob;
}

/**
print the data_blob as hex string
**/
_PUBLIC_ char *data_blob_hex_string(TALLOC_CTX *mem_ctx, const DATA_BLOB *blob)
{
	int i;
	char *hex_string;

	hex_string = talloc_array(mem_ctx, char, (blob->length*2)+1);
	if (!hex_string) {
		return NULL;
	}

	for (i = 0; i < blob->length; i++)
		slprintf(&hex_string[i*2], 3, "%02X", blob->data[i]);

	hex_string[(blob->length*2)] = '\0';
	return hex_string;
}


