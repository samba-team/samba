/*
   Unix SMB/CIFS implementation.
   DATA BLOB

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

/* This is a public header file that is installed as part of Samba.
 * If you remove any functions or change their signature, update
 * the so version number. */

#ifndef _SAMBA_DATABLOB_H_
#define _SAMBA_DATABLOB_H_

#ifndef _PUBLIC_
#define _PUBLIC_
#endif

#include <talloc.h>
#include <stdbool.h>
#include <stdint.h>
#include "lib/util/talloc_keep_secret.h"

/**
 * @defgroup data_blob The data_blob API
 * @brief The defines the data_blob API and provides function working with it.
 *
 * @{
 */

/* used to hold an arbitrary blob of data */
typedef struct datablob {
	uint8_t *data;
	size_t length;
} DATA_BLOB;

/* by making struct ldb_val and DATA_BLOB the same, we can simplify
   a fair bit of code */
#define ldb_val datablob

#ifdef DOXYGEN
/**
 * @brief Construct a data blob using a new top level TALLOC_CTX.
 *        You can pass NULL for ptr and get a blank data blob.
 *        Blob must be freed with data_blob_free().
 */
DATA_BLOB data_blob(const void *ptr, size_t size);
#else
#define data_blob(ptr, size) data_blob_named(ptr, size, "DATA_BLOB: " __location__)
#endif

#ifdef DOXYGEN
/**
 * @brief Construct a data blob using supplied TALLOC_CTX.
 *        You can pass NULL for ptr and get a blank data blob.
 */
DATA_BLOB data_blob_talloc(TALLOC_CTX *mem_ctx, const void *ptr, size_t size);
#else
#define data_blob_talloc(ctx, ptr, size) data_blob_talloc_named(ctx, ptr, size, "DATA_BLOB: " __location__)
#endif

#ifdef DOXYGEN
/**
 * @brief Construct a data blob using supplied TALLOC_CTX.
 *        Data is initialized using provided blob.
 */
DATA_BLOB data_blob_dup_talloc(TALLOC_CTX *mem_ctx, DATA_BLOB blob);
#else
#define data_blob_dup_talloc(ctx, blob) data_blob_talloc_named(ctx, (blob).data, (blob).length, "DATA_BLOB: " __location__)
#endif

#ifdef DOXYGEN
/**
 * @brief Construct a data blob using a new top level TALLOC_CTX.
 *        You can pass NULL for ptr and get a blank data blob.
 *        Blob must be freed with data_blob_free().
 */
DATA_BLOB data_blob_named(const void *ptr, size_t size, const char *name);
#else
#define data_blob_named(ptr, size, name) \
	data_blob_talloc_named(NULL, (ptr), (size), name)
#endif

/**
 * @brief Construct a data blob using supplied TALLOC_CTX and using data
 * supplied via ptr and length and give it an explicit talloc chunk name.
 */
/**
 * @brief Construct a data blob, using data supplied pointer and length
 *
 * @param mem_ctx  memory context, if NULL a new top level context is used
 * @param p        pointer to input data, you can pass NULL and get a blank data
 * blob
 * @param length   data length
 * @param name     talloc chunk name
 * @return         the blob
 */
_PUBLIC_ DATA_BLOB data_blob_talloc_named(TALLOC_CTX *mem_ctx, const void *p, size_t length, const char *name);

#ifdef DOXYGEN
/**
 * @brief Construct a data blob using supplied TALLOC_CTX.
 *        Data is initialized with zeros.
 */
DATA_BLOB data_blob_talloc_zero(TALLOC_CTX *mem_ctx, size_t size);
#else
#define data_blob_talloc_zero(ctx, size) \
	_data_blob_talloc_zero((ctx), (size), "DATA_BLOB: " __location__)
#endif

#ifdef DOXYGEN
/**
 * @brief Construct a data blob using supplied TALLOC_CTX.
 *        Data is initialized with zeros and zeroed out when freed.
 */
DATA_BLOB data_blob_talloc_zero_s(TALLOC_CTX *mem_ctx, size_t size);
#else
#define data_blob_talloc_zero_s(ctx, size) \
	_data_blob_talloc_zero_s((ctx), (size), "DATA_BLOB: " __location__)
#endif

#ifdef DOXYGEN
/**
 * @brief Construct a data blob using supplied TALLOC_CTX.
 *        You can pass NULL for ptr and get a blank data blob.
 *        Data is zeroed out when freed.
 */
DATA_BLOB data_blob_talloc_s(TALLOC_CTX *mem_ctx, const void *ptr, size_t size);
#else
#define data_blob_talloc_s(ctx, ptr, size) \
	_data_blob_talloc_s((ctx), (ptr), (size), "DATA_BLOB: " __location__)
#endif

#ifdef DOXYGEN
/**
 * @brief Construct a data blob using supplied TALLOC_CTX.
 *        Data is initialized using provided blob.
 *        Data is zeroed out when freed.
 */
DATA_BLOB data_blob_dup_talloc_s(TALLOC_CTX *mem_ctx, DATA_BLOB blob);
#else
#define data_blob_dup_talloc_s(ctx, blob) \
	_data_blob_dup_talloc_s((ctx), (blob), "DATA_BLOB: " __location__)
#endif

/**
free a data blob
**/
_PUBLIC_ void data_blob_free(DATA_BLOB *d);

/**
clear a DATA_BLOB's contents
**/
_PUBLIC_ void data_blob_clear(DATA_BLOB *d);

/**
free a data blob and clear its contents
**/
_PUBLIC_ void data_blob_clear_free(DATA_BLOB *d);

static inline DATA_BLOB _data_blob_talloc_zero(TALLOC_CTX *ctx,
					       size_t size,
					       const char *name)
{
	DATA_BLOB b = data_blob_talloc_named(ctx, 0, size, name);
	if (b.data != NULL) {
		data_blob_clear(&b);
	}
	return b;
}

static inline DATA_BLOB _data_blob_talloc_s(TALLOC_CTX *ctx,
					    const void *p,
					    size_t size,
					    const char *name)
{
	DATA_BLOB b = data_blob_talloc_named(ctx, p, size, name);
	if (b.data != NULL) {
		talloc_keep_secret(b.data);
	}
	return b;
}

static inline DATA_BLOB _data_blob_talloc_zero_s(TALLOC_CTX *ctx,
						 size_t size,
						 const char *name)
{
	DATA_BLOB b = data_blob_talloc_named(ctx, 0, size, name);
	if (b.data != NULL) {
		data_blob_clear(&b);
		talloc_keep_secret(b.data);
	}
	return b;
}

static inline DATA_BLOB _data_blob_dup_talloc_s(TALLOC_CTX *ctx,
						DATA_BLOB blob,
						const char *name)
{
	DATA_BLOB b = data_blob_talloc_named(ctx, blob.data, blob.length, name);
	if (b.data != NULL) {
		talloc_keep_secret(b.data);
	}
	return b;
}

/**
check if two data blobs are equal
**/
_PUBLIC_ int data_blob_cmp(const DATA_BLOB *d1, const DATA_BLOB *d2);

/**
check if two data blobs are equal, where the time taken should not depend on the
contents of either blob.
**/
_PUBLIC_ bool data_blob_equal_const_time(const DATA_BLOB *d1, const DATA_BLOB *d2);

/**
print the data_blob as hex string
**/
_PUBLIC_ char *data_blob_hex_string_upper(TALLOC_CTX *mem_ctx, const DATA_BLOB *blob);

/**
print the data_blob as hex string
**/
_PUBLIC_ char *data_blob_hex_string_lower(TALLOC_CTX *mem_ctx, const DATA_BLOB *blob);

/**
  useful for constructing data blobs in test suites, while
  avoiding const warnings
**/
_PUBLIC_ DATA_BLOB data_blob_string_const(const char *str);

/**
  useful for constructing data blobs in test suites, while
  avoiding const warnings

  includes the terminating null character (as opposed to data_blob_string_const)
**/
_PUBLIC_ DATA_BLOB data_blob_string_const_null(const char *str);

/**
 * Create a new data blob from const data
 */
_PUBLIC_ DATA_BLOB data_blob_const(const void *p, size_t length);

/**
  realloc a data_blob
**/
_PUBLIC_ bool data_blob_realloc(TALLOC_CTX *mem_ctx, DATA_BLOB *blob, size_t length);

/**
  append some data to a data blob
**/
_PUBLIC_ bool data_blob_append(TALLOC_CTX *mem_ctx, DATA_BLOB *blob,
				   const void *p, size_t length);

/**
  pad the length of a data blob to a multiple of
  'pad'. 'pad' must be a power of two.
**/
_PUBLIC_ bool data_blob_pad(TALLOC_CTX *mem_ctx, DATA_BLOB *blob,
			    size_t pad);

extern const DATA_BLOB data_blob_null;

/** @} */ /* data_blob */

#endif /* _SAMBA_DATABLOB_H_ */
