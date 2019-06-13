/* 
   Unix SMB/CIFS implementation.

   tdb utility functions

   Copyright (C) Andrew Tridgell 1992-2006
   Copyright (C) Volker Lendecke 2007-2011

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
#include "libcli/util/ntstatus.h"
#include "lib/util/memory.h"
#include "lib/util/byteorder.h"
#include "system/filesys.h"
#include "../lib/tdb/include/tdb.h"
#include "../lib/util/util_tdb.h"

/* these are little tdb utility functions that are meant to make
   dealing with a tdb database a little less cumbersome in Samba */

/***************************************************************
 Make a TDB_DATA and keep the const warning in one place
****************************************************************/

TDB_DATA make_tdb_data(const uint8_t *dptr, size_t dsize)
{
	TDB_DATA ret;
	ret.dptr = discard_const_p(uint8_t, dptr);
	ret.dsize = dsize;
	return ret;
}

bool tdb_data_equal(TDB_DATA t1, TDB_DATA t2)
{
	if (t1.dsize != t2.dsize) {
		return false;
	}
	return (memcmp(t1.dptr, t2.dptr, t1.dsize) == 0);
}

bool tdb_data_is_empty(TDB_DATA d)
{
	return (d.dsize == 0) || (d.dptr == NULL);
}

TDB_DATA string_tdb_data(const char *string)
{
	return make_tdb_data((const uint8_t *)string, string ? strlen(string) : 0 );
}

TDB_DATA string_term_tdb_data(const char *string)
{
	return make_tdb_data((const uint8_t *)string, string ? strlen(string) + 1 : 0);
}

TDB_DATA tdb_data_talloc_copy(TALLOC_CTX* mem_ctx, TDB_DATA data) {
	TDB_DATA ret = {
		.dptr  = (uint8_t *)talloc_size(mem_ctx, data.dsize+1),
		.dsize = data.dsize
	};
	if (ret.dptr == NULL) {
		ret.dsize = 0;
	} else {
		memcpy(ret.dptr, data.dptr, data.dsize);
		ret.dptr[ret.dsize] = '\0';
	}
	return ret;
}


/****************************************************************************
 Lock a chain by string. Return non-zero if lock failed.
****************************************************************************/

int tdb_lock_bystring(struct tdb_context *tdb, const char *keyval)
{
	TDB_DATA key = string_term_tdb_data(keyval);
	
	return tdb_chainlock(tdb, key);
}

/****************************************************************************
 Unlock a chain by string.
****************************************************************************/

void tdb_unlock_bystring(struct tdb_context *tdb, const char *keyval)
{
	TDB_DATA key = string_term_tdb_data(keyval);

	tdb_chainunlock(tdb, key);
}

/****************************************************************************
 Read lock a chain by string. Return non-zero if lock failed.
****************************************************************************/

int tdb_read_lock_bystring(struct tdb_context *tdb, const char *keyval)
{
	TDB_DATA key = string_term_tdb_data(keyval);
	
	return tdb_chainlock_read(tdb, key);
}

/****************************************************************************
 Read unlock a chain by string.
****************************************************************************/

void tdb_read_unlock_bystring(struct tdb_context *tdb, const char *keyval)
{
	TDB_DATA key = string_term_tdb_data(keyval);
	
	tdb_chainunlock_read(tdb, key);
}


/****************************************************************************
 Fetch a int32_t value by a arbitrary blob key, return -1 if not found.
 Output is int32_t in native byte order.
****************************************************************************/

static int32_t tdb_fetch_int32_byblob(struct tdb_context *tdb, TDB_DATA key)
{
	TDB_DATA data;
	int32_t ret;

	data = tdb_fetch(tdb, key);
	if (!data.dptr || data.dsize != sizeof(int32_t)) {
		SAFE_FREE(data.dptr);
		return -1;
	}

	ret = IVAL(data.dptr,0);
	SAFE_FREE(data.dptr);
	return ret;
}

/****************************************************************************
 Fetch a int32_t value by string key, return -1 if not found.
 Output is int32_t in native byte order.
****************************************************************************/

int32_t tdb_fetch_int32(struct tdb_context *tdb, const char *keystr)
{
	return tdb_fetch_int32_byblob(tdb, string_term_tdb_data(keystr));
}

/****************************************************************************
 Store a int32_t value by an arbitrary blob key, return 0 on success, -ve on failure.
 Input is int32_t in native byte order. Output in tdb is in little-endian.
****************************************************************************/

static int tdb_store_int32_byblob(struct tdb_context *tdb, TDB_DATA key,
				  int32_t v)
{
	TDB_DATA data;
	int32_t v_store;

	SIVAL(&v_store,0,v);
	data.dptr = (unsigned char *)&v_store;
	data.dsize = sizeof(int32_t);

	return tdb_store(tdb, key, data, TDB_REPLACE);
}

/****************************************************************************
 Store a int32_t value by string key, return 0 on success, -ve on failure.
 Input is int32_t in native byte order. Output in tdb is in little-endian.
****************************************************************************/

int tdb_store_int32(struct tdb_context *tdb, const char *keystr, int32_t v)
{
	return tdb_store_int32_byblob(tdb, string_term_tdb_data(keystr), v);
}

/****************************************************************************
 Fetch a uint32_t value by a arbitrary blob key, return false if not found.
 Output is uint32_t in native byte order.
****************************************************************************/

static bool tdb_fetch_uint32_byblob(struct tdb_context *tdb, TDB_DATA key,
				    uint32_t *value)
{
	TDB_DATA data;

	data = tdb_fetch(tdb, key);
	if (!data.dptr || data.dsize != sizeof(uint32_t)) {
		SAFE_FREE(data.dptr);
		return false;
	}

	*value = IVAL(data.dptr,0);
	SAFE_FREE(data.dptr);
	return true;
}

/****************************************************************************
 Fetch a uint32_t value by string key, return false if not found.
 Output is uint32_t in native byte order.
****************************************************************************/

bool tdb_fetch_uint32(struct tdb_context *tdb, const char *keystr, uint32_t *value)
{
	return tdb_fetch_uint32_byblob(tdb, string_term_tdb_data(keystr), value);
}

/****************************************************************************
 Store a uint32_t value by an arbitrary blob key, return true on success, false on failure.
 Input is uint32_t in native byte order. Output in tdb is in little-endian.
****************************************************************************/

static bool tdb_store_uint32_byblob(struct tdb_context *tdb, TDB_DATA key,
				    uint32_t value)
{
	TDB_DATA data;
	uint32_t v_store;
	bool ret = true;

	SIVAL(&v_store, 0, value);
	data.dptr = (unsigned char *)&v_store;
	data.dsize = sizeof(uint32_t);

	if (tdb_store(tdb, key, data, TDB_REPLACE) != 0)
		ret = false;

	return ret;
}

/****************************************************************************
 Store a uint32_t value by string key, return true on success, false on failure.
 Input is uint32_t in native byte order. Output in tdb is in little-endian.
****************************************************************************/

bool tdb_store_uint32(struct tdb_context *tdb, const char *keystr, uint32_t value)
{
	return tdb_store_uint32_byblob(tdb, string_term_tdb_data(keystr), value);
}
/****************************************************************************
 Store a buffer by a null terminated string key.  Return 0 on success, -ve
 on failure.
****************************************************************************/

int tdb_store_bystring(struct tdb_context *tdb, const char *keystr, TDB_DATA data, int flags)
{
	TDB_DATA key = string_term_tdb_data(keystr);
	
	return tdb_store(tdb, key, data, flags);
}

/****************************************************************************
 Fetch a buffer using a null terminated string key.  Don't forget to call
 free() on the result dptr.
****************************************************************************/

TDB_DATA tdb_fetch_bystring(struct tdb_context *tdb, const char *keystr)
{
	TDB_DATA key = string_term_tdb_data(keystr);

	return tdb_fetch(tdb, key);
}

/****************************************************************************
 Delete an entry using a null terminated string key. 
****************************************************************************/

int tdb_delete_bystring(struct tdb_context *tdb, const char *keystr)
{
	TDB_DATA key = string_term_tdb_data(keystr);

	return tdb_delete(tdb, key);
}

/****************************************************************************
 Atomic integer change. Returns old value. To create, set initial value in *oldval. 
****************************************************************************/

int32_t tdb_change_int32_atomic(struct tdb_context *tdb, const char *keystr, int32_t *oldval, int32_t change_val)
{
	int32_t val;
	int32_t ret = -1;

	if (tdb_lock_bystring(tdb, keystr) != 0)
		return -1;

	if ((val = tdb_fetch_int32(tdb, keystr)) == -1) {
		/* The lookup failed */
		if (tdb_error(tdb) != TDB_ERR_NOEXIST) {
			/* but not because it didn't exist */
			goto err_out;
		}
		
		/* Start with 'old' value */
		val = *oldval;

	} else {
		/* It worked, set return value (oldval) to tdb data */
		*oldval = val;
	}

	/* Increment value for storage and return next time */
	val += change_val;
		
	if (tdb_store_int32(tdb, keystr, val) != 0)
		goto err_out;

	ret = 0;

  err_out:

	tdb_unlock_bystring(tdb, keystr);
	return ret;
}

/****************************************************************************
 Atomic unsigned integer change. Returns old value. To create, set initial value in *oldval. 
****************************************************************************/

bool tdb_change_uint32_atomic(struct tdb_context *tdb, const char *keystr, uint32_t *oldval, uint32_t change_val)
{
	uint32_t val;
	bool ret = false;

	if (tdb_lock_bystring(tdb, keystr) != 0)
		return false;

	if (!tdb_fetch_uint32(tdb, keystr, &val)) {
		/* It failed */
		if (tdb_error(tdb) != TDB_ERR_NOEXIST) { 
			/* and not because it didn't exist */
			goto err_out;
		}

		/* Start with 'old' value */
		val = *oldval;

	} else {
		/* it worked, set return value (oldval) to tdb data */
		*oldval = val;

	}

	/* get a new value to store */
	val += change_val;
		
	if (!tdb_store_uint32(tdb, keystr, val))
		goto err_out;

	ret = true;

  err_out:

	tdb_unlock_bystring(tdb, keystr);
	return ret;
}

/****************************************************************************
 Allow tdb_delete to be used as a tdb_traversal_fn.
****************************************************************************/

int tdb_traverse_delete_fn(struct tdb_context *the_tdb, TDB_DATA key, TDB_DATA dbuf,
                     void *state)
{
    return tdb_delete(the_tdb, key);
}

/****************************************************************************
 Return an NTSTATUS from a TDB_ERROR
****************************************************************************/

NTSTATUS map_nt_error_from_tdb(enum TDB_ERROR err)
{
	NTSTATUS result;

	switch (err) {
	case TDB_SUCCESS:
		result = NT_STATUS_OK;
		break;
	case TDB_ERR_CORRUPT:
		result = NT_STATUS_INTERNAL_DB_CORRUPTION;
		break;
	case TDB_ERR_IO:
		result = NT_STATUS_UNEXPECTED_IO_ERROR;
		break;
	case TDB_ERR_OOM:
		result = NT_STATUS_NO_MEMORY;
		break;
	case TDB_ERR_EXISTS:
		result = NT_STATUS_OBJECT_NAME_COLLISION;
		break;

	case TDB_ERR_LOCK:
		/*
		 * TDB_ERR_LOCK is very broad, we could for example
		 * distinguish between fcntl locks and invalid lock
		 * sequences. So NT_STATUS_FILE_LOCK_CONFLICT is a
		 * compromise.
		 */
		result = NT_STATUS_FILE_LOCK_CONFLICT;
		break;

	case TDB_ERR_NOLOCK:
	case TDB_ERR_LOCK_TIMEOUT:
		/*
		 * These two ones in the enum are not actually used
		 */
		result = NT_STATUS_FILE_LOCK_CONFLICT;
		break;
	case TDB_ERR_NOEXIST:
		result = NT_STATUS_NOT_FOUND;
		break;
	case TDB_ERR_EINVAL:
		result = NT_STATUS_INVALID_PARAMETER;
		break;
	case TDB_ERR_RDONLY:
		result = NT_STATUS_ACCESS_DENIED;
		break;
	case TDB_ERR_NESTING:
		result = NT_STATUS_INTERNAL_ERROR;
		break;
	default:
		result = NT_STATUS_INTERNAL_ERROR;
		break;
	};
	return result;
}

int map_unix_error_from_tdb(enum TDB_ERROR err)
{
	int result = EINVAL;

	switch (err) {
	case TDB_SUCCESS:
		result = 0;
		break;
	case TDB_ERR_CORRUPT:
		result = EILSEQ;
		break;
	case TDB_ERR_IO:
		result = EIO;
		break;
	case TDB_ERR_OOM:
		result = ENOMEM;
		break;
	case TDB_ERR_EXISTS:
		result = EEXIST;
		break;

	case TDB_ERR_LOCK:
		/*
		 * TDB_ERR_LOCK is very broad, we could for example
		 * distinguish between fcntl locks and invalid lock
		 * sequences. EWOULDBLOCK is wrong, but there is no real
		 * generic lock error code in errno.h
		 */
		result = EWOULDBLOCK;
		break;

	case TDB_ERR_NOLOCK:
	case TDB_ERR_LOCK_TIMEOUT:
		/*
		 * These two ones in the enum are not actually used
		 */
		result = ENOLCK;
		break;
	case TDB_ERR_NOEXIST:
		result = ENOENT;
		break;
	case TDB_ERR_EINVAL:
		result = EINVAL;
		break;
	case TDB_ERR_RDONLY:
		result = EROFS;
		break;
	case TDB_ERR_NESTING:
		/*
		 * Well, this db is already busy...
		 */
		result = EBUSY;
		break;
	};
	return result;
}

struct tdb_fetch_talloc_state {
	TALLOC_CTX *mem_ctx;
	uint8_t *buf;
};

static int tdb_fetch_talloc_parser(TDB_DATA key, TDB_DATA data,
                                   void *private_data)
{
	struct tdb_fetch_talloc_state *state = private_data;
	state->buf = talloc_memdup(state->mem_ctx, data.dptr, data.dsize);
	return 0;
}

int tdb_fetch_talloc(struct tdb_context *tdb, TDB_DATA key,
		     TALLOC_CTX *mem_ctx, uint8_t **buf)
{
	struct tdb_fetch_talloc_state state = { .mem_ctx = mem_ctx };
	int ret;

	ret = tdb_parse_record(tdb, key, tdb_fetch_talloc_parser, &state);
	if (ret == -1) {
		enum TDB_ERROR err = tdb_error(tdb);
		return map_unix_error_from_tdb(err);
	}

	if (state.buf == NULL) {
		return ENOMEM;
	}

	*buf = state.buf;
	return 0;
}
