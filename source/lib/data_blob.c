/* 
   Unix SMB/CIFS implementation.
   Easy management of byte-length data
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Andrew Bartlett 2001
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

/*******************************************************************
 construct a data blob, must be freed with data_blob_free()
 you can pass NULL for p and get a blank data blob
*******************************************************************/
DATA_BLOB data_blob(const void *p, size_t length)
{
	DATA_BLOB ret;

	if (length == 0) {
		ZERO_STRUCT(ret);
		return ret;
	}

	if (p) {
		ret.data = smb_xmemdup(p, length);
	} else {
		ret.data = smb_xmalloc(length);
	}
	ret.length = length;
	return ret;
}

/*******************************************************************
 construct a data blob, using supplied TALLOC_CTX
*******************************************************************/
DATA_BLOB data_blob_talloc(TALLOC_CTX *mem_ctx, const void *p, size_t length)
{
	DATA_BLOB ret;

	if (length == 0) {
		ZERO_STRUCT(ret);
		return ret;
	}

	if (p == NULL) {
		/* note that we do NOT zero memory in this case */
		ret.data = talloc(mem_ctx, length);
		if (ret.data == NULL) {
			smb_panic("data_blob_talloc: talloc_memdup failed.\n");
		}
		ret.length = length;
		return ret;
	}

	ret.data = talloc_memdup(mem_ctx, p, length);
	if (ret.data == NULL) {
		smb_panic("data_blob_talloc: talloc_memdup failed.\n");
	}

	ret.length = length;
	return ret;
}

/*******************************************************************
 construct a zero data blob, using supplied TALLOC_CTX. 
 use this sparingly as it initialises data - better to initialise
 yourself if you want specific data in the blob
*******************************************************************/
DATA_BLOB data_blob_talloc_zero(TALLOC_CTX *mem_ctx, size_t length)
{
	DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, length);
	data_blob_clear(&blob);
	return blob;
}

/**
 * Steal a talloc'ed DATA_BLOB from one context to another
 */

DATA_BLOB data_blob_talloc_steal(TALLOC_CTX *old_ctx, TALLOC_CTX *new_ctx, 
				 DATA_BLOB *old) 
{
	DATA_BLOB new;
	new = *old;
	new.data = talloc_steal(new_ctx, old->data);
	if (new.data == NULL) {
		smb_panic("data_blob_talloc_steal: talloc_steal failed.\n");
	}
	return new;
}

/*******************************************************************
free a data blob
*******************************************************************/
void data_blob_free(DATA_BLOB *d)
{
	if (d) {
		free(d->data);
		d->data = NULL;
		d->length = 0;
	}
}

/*******************************************************************
clear a DATA_BLOB's contents
*******************************************************************/
void data_blob_clear(DATA_BLOB *d)
{
	if (d->data) {
		memset(d->data, 0, d->length);
	}
}

/*******************************************************************
free a data blob and clear its contents
*******************************************************************/
void data_blob_clear_free(DATA_BLOB *d)
{
	data_blob_clear(d);
	data_blob_free(d);
}


/*******************************************************************
check if two data blobs are equal
*******************************************************************/
BOOL data_blob_equal(const DATA_BLOB *d1, const DATA_BLOB *d2)
{
	if (d1->length != d2->length) {
		return False;
	}
	if (d1->data == d2->data) {
		return True;
	}
	if (d1->data == NULL || d2->data == NULL) {
		return False;
	}
	if (memcmp(d1->data, d2->data, d1->length) == 0) {
		return True;
	}
	return False;
}

