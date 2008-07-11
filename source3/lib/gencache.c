/* 
   Unix SMB/CIFS implementation.

   Generic, persistent and shared between processes cache mechanism for use
   by various parts of the Samba code

   Copyright (C) Rafal Szczesniak    2002
   
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

#undef  DBGC_CLASS
#define DBGC_CLASS DBGC_TDB

#define TIMEOUT_LEN 12
#define CACHE_DATA_FMT	"%12u/%s"
#define READ_CACHE_DATA_FMT_TEMPLATE "%%12u/%%%us"
#define BLOB_TYPE "DATA_BLOB"
#define BLOB_TYPE_LEN 9

static TDB_CONTEXT *cache;

/**
 * @file gencache.c
 * @brief Generic, persistent and shared between processes cache mechanism
 *        for use by various parts of the Samba code
 *
 **/


/**
 * Cache initialisation function. Opens cache tdb file or creates
 * it if does not exist.
 *
 * @return true on successful initialisation of the cache or
 *         false on failure
 **/

bool gencache_init(void)
{
	char* cache_fname = NULL;
	
	/* skip file open if it's already opened */
	if (cache) return True;

	cache_fname = lock_path("gencache.tdb");

	DEBUG(5, ("Opening cache file at %s\n", cache_fname));

	cache = tdb_open_log(cache_fname, 0, TDB_DEFAULT,
	                     O_RDWR|O_CREAT, 0644);

	if (!cache && (errno == EACCES)) {
		cache = tdb_open_log(cache_fname, 0, TDB_DEFAULT, O_RDONLY, 0644);
		if (cache) {
			DEBUG(5, ("gencache_init: Opening cache file %s read-only.\n", cache_fname));
		}
	}

	if (!cache) {
		DEBUG(5, ("Attempt to open gencache.tdb has failed.\n"));
		return False;
	}
	return True;
}


/**
 * Cache shutdown function. Closes opened cache tdb file.
 *
 * @return true on successful closing the cache or
 *         false on failure during cache shutdown
 **/
 
bool gencache_shutdown(void)
{
	int ret;
	/* tdb_close routine returns -1 on error */
	if (!cache) return False;
	DEBUG(5, ("Closing cache file\n"));
	ret = tdb_close(cache);
	cache = NULL;
	return ret != -1;
}


/**
 * Set an entry in the cache file. If there's no such
 * one, then add it.
 *
 * @param keystr string that represents a key of this entry
 * @param value text representation value being cached
 * @param timeout time when the value is expired
 *
 * @retval true when entry is successfuly stored
 * @retval false on failure
 **/
 
bool gencache_set(const char *keystr, const char *value, time_t timeout)
{
	int ret;
	TDB_DATA databuf;
	char* valstr = NULL;
	
	/* fail completely if get null pointers passed */
	SMB_ASSERT(keystr && value);

	if (!gencache_init()) return False;
	
	if (asprintf(&valstr, CACHE_DATA_FMT, (int)timeout, value) == -1) {
		return False;
	}

	databuf = string_term_tdb_data(valstr);
	DEBUG(10, ("Adding cache entry with key = %s; value = %s and timeout ="
	           " %s (%d seconds %s)\n", keystr, value,ctime(&timeout),
		   (int)(timeout - time(NULL)), 
		   timeout > time(NULL) ? "ahead" : "in the past"));

	ret = tdb_store_bystring(cache, keystr, databuf, 0);
	SAFE_FREE(valstr);
	
	return ret == 0;
}

/**
 * Delete one entry from the cache file.
 *
 * @param keystr string that represents a key of this entry
 *
 * @retval true upon successful deletion
 * @retval false in case of failure
 **/

bool gencache_del(const char *keystr)
{
	int ret;
	
	/* fail completely if get null pointers passed */
	SMB_ASSERT(keystr);

	if (!gencache_init()) return False;	
	
	DEBUG(10, ("Deleting cache entry (key = %s)\n", keystr));
	ret = tdb_delete_bystring(cache, keystr);
	
	return ret == 0;
}


/**
 * Get existing entry from the cache file.
 *
 * @param keystr string that represents a key of this entry
 * @param valstr buffer that is allocated and filled with the entry value
 *        buffer's disposing must be done outside
 * @param timeout pointer to a time_t that is filled with entry's
 *        timeout
 *
 * @retval true when entry is successfuly fetched
 * @retval False for failure
 **/

bool gencache_get(const char *keystr, char **valstr, time_t *timeout)
{
	TDB_DATA databuf;
	time_t t;
	char *endptr;

	/* fail completely if get null pointers passed */
	SMB_ASSERT(keystr);

	if (!gencache_init()) {
		return False;
	}

	databuf = tdb_fetch_bystring(cache, keystr);

	if (databuf.dptr == NULL) {
		DEBUG(10, ("Cache entry with key = %s couldn't be found\n",
			   keystr));
		return False;
	}

	t = strtol((const char *)databuf.dptr, &endptr, 10);

	if ((endptr == NULL) || (*endptr != '/')) {
		DEBUG(2, ("Invalid gencache data format: %s\n", databuf.dptr));
		SAFE_FREE(databuf.dptr);
		return False;
	}

	DEBUG(10, ("Returning %s cache entry: key = %s, value = %s, "
		   "timeout = %s", t > time(NULL) ? "valid" :
		   "expired", keystr, endptr+1, ctime(&t)));

	if (t <= time(NULL)) {

		/* We're expired, delete the entry */
		tdb_delete_bystring(cache, keystr);

		SAFE_FREE(databuf.dptr);
		return False;
	}

	if (valstr) {
		*valstr = SMB_STRDUP(endptr+1);
		if (*valstr == NULL) {
			SAFE_FREE(databuf.dptr);
			DEBUG(0, ("strdup failed\n"));
			return False;
		}
	}
	
	SAFE_FREE(databuf.dptr);

	if (timeout) {
		*timeout = t;
	}

	return True;
} 

/**
 * Get existing entry from the cache file.
 *
 * @param keystr string that represents a key of this entry
 * @param blob DATA_BLOB that is filled with entry's blob
 * @param expired pointer to a bool that indicates whether the entry is expired
 *
 * @retval true when entry is successfuly fetched
 * @retval False for failure
 **/

bool gencache_get_data_blob(const char *keystr, DATA_BLOB *blob, bool *expired)
{
	TDB_DATA databuf;
	time_t t;
	char *blob_type;
	unsigned char *buf = NULL;
	bool ret = False;
	fstring valstr;
	int buflen = 0, len = 0, blob_len = 0;
	unsigned char *blob_buf = NULL;

	/* fail completely if get null pointers passed */
	SMB_ASSERT(keystr);

	if (!gencache_init()) {
		return False;
	}

	databuf = tdb_fetch_bystring(cache, keystr);
	if (!databuf.dptr) {
		DEBUG(10,("Cache entry with key = %s couldn't be found\n",
			  keystr));
		return False;
	}

	buf = (unsigned char *)databuf.dptr;
	buflen = databuf.dsize;

	len += tdb_unpack(buf+len, buflen-len, "fB",
			  &valstr,
			  &blob_len, &blob_buf);
	if (len == -1) {
		goto out;
	}

	t = strtol(valstr, &blob_type, 10);

	if (strcmp(blob_type+1, BLOB_TYPE) != 0) {
		goto out;
	}

	DEBUG(10,("Returning %s cache entry: key = %s, "
		  "timeout = %s", t > time(NULL) ? "valid" :
		  "expired", keystr, ctime(&t)));

	if (t <= time(NULL)) {
		/* We're expired */
		if (expired) {
			*expired = True;
		}
	}

	if (blob) {
		*blob = data_blob(blob_buf, blob_len);
		if (!blob->data) {
			goto out;
		}
	}

	ret = True;
 out:
	SAFE_FREE(blob_buf);
	SAFE_FREE(databuf.dptr);

	return ret;
}

/**
 * Set an entry in the cache file. If there's no such
 * one, then add it.
 *
 * @param keystr string that represents a key of this entry
 * @param blob DATA_BLOB value being cached
 * @param timeout time when the value is expired
 *
 * @retval true when entry is successfuly stored
 * @retval false on failure
 **/

bool gencache_set_data_blob(const char *keystr, const DATA_BLOB *blob, time_t timeout)
{
	bool ret = False;
	int tdb_ret;
	TDB_DATA databuf;
	char *valstr = NULL;
	unsigned char *buf = NULL;
	int len = 0, buflen = 0;

	/* fail completely if get null pointers passed */
	SMB_ASSERT(keystr && blob);

	if (!gencache_init()) {
		return False;
	}

	if (asprintf(&valstr, "%12u/%s", (int)timeout, BLOB_TYPE) == -1) {
		return False;
	}

 again:
	len = 0;

	len += tdb_pack(buf+len, buflen-len, "fB",
			valstr,
			blob->length, blob->data);

	if (len == -1) {
		goto out;
	}

	if (buflen < len) {
		SAFE_FREE(buf);
		buf = SMB_MALLOC_ARRAY(unsigned char, len);
		if (!buf) {
			goto out;
		}
		buflen = len;
		goto again;
	}

	databuf = make_tdb_data(buf, len);

	DEBUG(10,("Adding cache entry with key = %s; "
		  "blob size = %d and timeout = %s"
		  "(%d seconds %s)\n", keystr, (int)databuf.dsize,
		  ctime(&timeout), (int)(timeout - time(NULL)),
		  timeout > time(NULL) ? "ahead" : "in the past"));

	tdb_ret = tdb_store_bystring(cache, keystr, databuf, 0);
	if (tdb_ret == 0) {
		ret = True;
	}

 out:
	SAFE_FREE(valstr);
	SAFE_FREE(buf);

	return ret;
}

/**
 * Iterate through all entries which key matches to specified pattern
 *
 * @param fn pointer to the function that will be supplied with each single
 *        matching cache entry (key, value and timeout) as an arguments
 * @param data void pointer to an arbitrary data that is passed directly to the fn
 *        function on each call
 * @param keystr_pattern pattern the existing entries' keys are matched to
 *
 **/

void gencache_iterate(void (*fn)(const char* key, const char *value, time_t timeout, void* dptr),
                      void* data, const char* keystr_pattern)
{
	TDB_LIST_NODE *node, *first_node;
	TDB_DATA databuf;
	char *keystr = NULL, *valstr = NULL, *entry = NULL;
	time_t timeout = 0;
	int status;
	unsigned u;

	/* fail completely if get null pointers passed */
	SMB_ASSERT(fn && keystr_pattern);

	if (!gencache_init()) return;

	DEBUG(5, ("Searching cache keys with pattern %s\n", keystr_pattern));
	node = tdb_search_keys(cache, keystr_pattern);
	first_node = node;
	
	while (node) {
		char *fmt;

		/* ensure null termination of the key string */
		keystr = SMB_STRNDUP((const char *)node->node_key.dptr, node->node_key.dsize);
		if (!keystr) {
			break;
		}
		
		/* 
		 * We don't use gencache_get function, because we need to iterate through
		 * all of the entries. Validity verification is up to fn routine.
		 */
		databuf = tdb_fetch(cache, node->node_key);
		if (!databuf.dptr || databuf.dsize <= TIMEOUT_LEN) {
			SAFE_FREE(databuf.dptr);
			SAFE_FREE(keystr);
			node = node->next;
			continue;
		}
		entry = SMB_STRNDUP((const char *)databuf.dptr, databuf.dsize);
		if (!entry) {
			SAFE_FREE(databuf.dptr);
			SAFE_FREE(keystr);
			break;
		}

		SAFE_FREE(databuf.dptr);

		valstr = (char *)SMB_MALLOC(databuf.dsize + 1 - TIMEOUT_LEN);
		if (!valstr) {
			SAFE_FREE(entry);
			SAFE_FREE(keystr);
			break;
		}

		if (asprintf(&fmt, READ_CACHE_DATA_FMT_TEMPLATE,
			     (unsigned int)databuf.dsize - TIMEOUT_LEN)
		    == -1) {
			SAFE_FREE(valstr);
			SAFE_FREE(entry);
			SAFE_FREE(keystr);
			break;
		}
		status = sscanf(entry, fmt, &u, valstr);
		SAFE_FREE(fmt);

		if ( status != 2 ) {
			DEBUG(0,("gencache_iterate: invalid return from sscanf %d\n",status));
		}
		timeout = u;
		
		DEBUG(10, ("Calling function with arguments (key = %s, value = %s, timeout = %s)\n",
		           keystr, valstr, ctime(&timeout)));
		fn(keystr, valstr, timeout, data);
		
		SAFE_FREE(valstr);
		SAFE_FREE(entry);
		SAFE_FREE(keystr);
		node = node->next;
	}
	
	tdb_search_list_free(first_node);
}

/********************************************************************
 lock a key
********************************************************************/

int gencache_lock_entry( const char *key )
{
	if (!gencache_init())
		return -1;
	
	return tdb_lock_bystring(cache, key);
}

/********************************************************************
 unlock a key
********************************************************************/

void gencache_unlock_entry( const char *key )
{
	if (!gencache_init())
		return;
	
	tdb_unlock_bystring(cache, key);
	return;
}
