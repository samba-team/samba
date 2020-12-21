/* 
   Unix SMB/CIFS implementation.

   Generic, persistent and shared between processes cache mechanism for use
   by various parts of the Samba code

   Copyright (C) Rafal Szczesniak    2002
   Copyright (C) Volker Lendecke     2009

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
#include "lib/gencache.h"
#include "system/filesys.h"
#include "system/glob.h"
#include "util_tdb.h"
#include "tdb_wrap/tdb_wrap.h"
#include "zlib.h"
#include "lib/util/strv.h"
#include "lib/util/util_paths.h"

#undef  DBGC_CLASS
#define DBGC_CLASS DBGC_TDB

#define GENCACHE_USER_PATH "~/.cache/samba/gencache.tdb"

static struct tdb_wrap *cache;

/**
 * @file gencache.c
 * @brief Generic, persistent and shared between processes cache mechanism
 *        for use by various parts of the Samba code
 *
 **/

static bool gencache_pull_timeout(TDB_DATA key,
				  TDB_DATA data,
				  time_t *pres,
				  DATA_BLOB *payload);

struct gencache_timeout {
	time_t timeout;
};

bool gencache_timeout_expired(const struct gencache_timeout *t)
{
	return t->timeout <= time(NULL);
}

/**
 * Cache initialisation function. Opens cache tdb file or creates
 * it if does not exist.
 *
 * @return true on successful initialisation of the cache or
 *         false on failure
 **/

static bool gencache_init(void)
{
	char* cache_fname = NULL;
	int open_flags = O_RDWR|O_CREAT;
	int tdb_flags = TDB_INCOMPATIBLE_HASH|TDB_NOSYNC|TDB_MUTEX_LOCKING;
	int hash_size;

	/* skip file open if it's already opened */
	if (cache) {
		return true;
	}

	hash_size = lp_parm_int(-1, "gencache", "hash_size", 10000);

	cache_fname = lock_path(talloc_tos(), "gencache.tdb");
	if (cache_fname == NULL) {
		return false;
	}

	DEBUG(5, ("Opening cache file at %s\n", cache_fname));

	cache = tdb_wrap_open(NULL, cache_fname, hash_size,
			      tdb_flags,
			      open_flags, 0644);
	/*
	 * Allow client tools to create a gencache in the home directory
	 * as a normal user.
	 */
	if (cache == NULL && errno == EACCES && geteuid() != 0) {
		char *cache_dname = NULL, *tmp = NULL;
		bool ok;

		TALLOC_FREE(cache_fname);

		cache_fname = path_expand_tilde(talloc_tos(),
						GENCACHE_USER_PATH);
		if (cache_fname == NULL) {
			DBG_ERR("Failed to expand path: %s\n",
				GENCACHE_USER_PATH);
			return false;
		}

		tmp = talloc_strdup(talloc_tos(), cache_fname);
		if (tmp == NULL) {
			DBG_ERR("No memory!\n");
			TALLOC_FREE(cache_fname);
			return false;
		}

		cache_dname = dirname(tmp);
		if (cache_dname == NULL) {
			DBG_ERR("Invalid path: %s\n", cache_fname);
			TALLOC_FREE(tmp);
			TALLOC_FREE(cache_fname);
			return false;
		}

		ok = directory_create_or_exists_recursive(cache_dname, 0700);
		if (!ok) {
			DBG_ERR("Failed to create directory: %s - %s\n",
				cache_dname, strerror(errno));
			TALLOC_FREE(tmp);
			TALLOC_FREE(cache_fname);
			return false;
		}
		TALLOC_FREE(tmp);

		cache = tdb_wrap_open(NULL,
				      cache_fname,
				      hash_size,
				      tdb_flags,
				      open_flags,
				      0644);
		if (cache != NULL) {
			DBG_INFO("Opening user cache file %s.\n",
				 cache_fname);
		}
	}

	if (cache == NULL) {
		DEBUG(5, ("Opening %s failed: %s\n", cache_fname,
			  strerror(errno)));
		TALLOC_FREE(cache_fname);
		return false;
	}
	TALLOC_FREE(cache_fname);

	return true;
}

/*
 * Walk the hash chain for "key", deleting all expired entries for
 * that hash chain
 */
struct gencache_prune_expired_state {
	TALLOC_CTX *mem_ctx;
	char *keys;
};

static int gencache_prune_expired_fn(struct tdb_context *tdb,
				     TDB_DATA key,
				     TDB_DATA data,
				     void *private_data)
{
	struct gencache_prune_expired_state *state = private_data;
	struct gencache_timeout t;
	bool ok = false;
	bool expired = false;

	if ((key.dsize == 0) || (key.dptr[key.dsize-1] != '\0')) {
		/* not a valid record, should never happen */
		return 0;
	}

	ok = gencache_pull_timeout(key, data, &t.timeout, NULL);
	if (ok) {
		expired = gencache_timeout_expired(&t);
	}

	if (!ok || expired) {
		int ret;

		ret = strv_add(state->mem_ctx, &state->keys, (char *)key.dptr);
		if (ret != 0) {
			/*
			 * Exit the loop. It's unlikely that it will
			 * succeed next time.
			 */
			return -1;
		}
	}

	return 0;
}

static void gencache_prune_expired(struct tdb_context *tdb,
				   TDB_DATA chain_key)
{
	struct gencache_prune_expired_state state = {
		.mem_ctx = talloc_tos(),
	};
	char *keystr = NULL;
	int ret;

	ret = tdb_traverse_key_chain(
		tdb, chain_key, gencache_prune_expired_fn, &state);
	if (ret == -1) {
		DBG_DEBUG("tdb_traverse_key_chain failed: %s\n",
			  tdb_errorstr(tdb));
		return;
	}

	while ((keystr = strv_next(state.keys, keystr)) != NULL) {
		TDB_DATA key = string_term_tdb_data(keystr);

		/*
		 * We expect the hash chain of "chain_key" to be
		 * locked. So between gencache_prune_expired_fn
		 * figuring out "keystr" is expired and the
		 * tdb_delete, nobody can have reset the timeout.
		 */
		tdb_delete(tdb, key);
	}

	TALLOC_FREE(state.keys);
}

/**
 * Set an entry in the cache file. If there's no such
 * one, then add it.
 *
 * @param keystr string that represents a key of this entry
 * @param blob DATA_BLOB value being cached
 * @param timeout time when the value is expired
 *
 * @retval true when entry is successfully stored
 * @retval false on failure
 **/

bool gencache_set_data_blob(const char *keystr, DATA_BLOB blob,
			    time_t timeout)
{
	TDB_DATA key;
	int ret;
	TDB_DATA dbufs[3];
	uint32_t crc;

	if ((keystr == NULL) || (blob.data == NULL)) {
		return false;
	}

	key = string_term_tdb_data(keystr);

	if (!gencache_init()) {
		return false;
	}

	dbufs[0] = (TDB_DATA) { .dptr = (uint8_t *)&timeout,
				.dsize = sizeof(time_t) };
	dbufs[1] = (TDB_DATA) { .dptr = blob.data, .dsize = blob.length };

	crc = crc32(0, Z_NULL, 0);
	crc = crc32(crc, key.dptr, key.dsize);
	crc = crc32(crc, dbufs[0].dptr, dbufs[0].dsize);
	crc = crc32(crc, dbufs[1].dptr, dbufs[1].dsize);

	dbufs[2] = (TDB_DATA) { .dptr = (uint8_t *)&crc,
				.dsize = sizeof(crc) };

	DBG_DEBUG("Adding cache entry with key=[%s] and timeout="
	           "[%s] (%ld seconds %s)\n", keystr,
		   timestring(talloc_tos(), timeout),
		   ((long int)timeout) - time(NULL),
		   timeout > time(NULL) ? "ahead" : "in the past");

	ret = tdb_chainlock(cache->tdb, key);
	if (ret == -1) {
		DBG_WARNING("tdb_chainlock for key [%s] failed: %s\n",
			    keystr, tdb_errorstr(cache->tdb));
		return false;
	}

	gencache_prune_expired(cache->tdb, key);

	ret = tdb_storev(cache->tdb, key, dbufs, ARRAY_SIZE(dbufs), 0);

	tdb_chainunlock(cache->tdb, key);

	if (ret == 0) {
		return true;
	}
	if (tdb_error(cache->tdb) != TDB_ERR_CORRUPT) {
		return false;
	}

	ret = tdb_wipe_all(cache->tdb);
	SMB_ASSERT(ret == 0);

	return false;
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
	TDB_DATA key = string_term_tdb_data(keystr);
	int ret;

	if (keystr == NULL) {
		return false;
	}

	if (!gencache_init()) {
		return false;
	}

	DEBUG(10, ("Deleting cache entry (key=[%s])\n", keystr));

	ret = tdb_delete(cache->tdb, key);

	if (ret == 0) {
		return true;
	}
	if (tdb_error(cache->tdb) != TDB_ERR_CORRUPT) {
		return false;
	}

	ret = tdb_wipe_all(cache->tdb);
	SMB_ASSERT(ret == 0);

	return true;		/* We've deleted a bit more... */
}

static bool gencache_pull_timeout(TDB_DATA key,
				  TDB_DATA data,
				  time_t *pres,
				  DATA_BLOB *payload)
{
	size_t crc_ofs;
	uint32_t crc, stored_crc;

	if ((data.dptr == NULL) ||
	    (data.dsize < (sizeof(time_t) + sizeof(uint32_t)))) {
		return false;
	}

	crc_ofs = data.dsize - sizeof(uint32_t);

	crc = crc32(0, Z_NULL, 0);
	crc = crc32(crc, key.dptr, key.dsize);
	crc = crc32(crc, data.dptr, crc_ofs);

	memcpy(&stored_crc, data.dptr + crc_ofs, sizeof(uint32_t));

	if (stored_crc != crc) {
		return false;
	}

	if (pres != NULL) {
		memcpy(pres, data.dptr, sizeof(time_t));
	}
	if (payload != NULL) {
		*payload = (DATA_BLOB) {
			.data = data.dptr+sizeof(time_t),
			.length = data.dsize-sizeof(time_t)-sizeof(uint32_t),
		};
	}
	return true;
}

struct gencache_parse_state {
	void (*parser)(const struct gencache_timeout *timeout,
		       DATA_BLOB blob,
		       void *private_data);
	void *private_data;
	bool format_error;
};

static int gencache_parse_fn(TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct gencache_parse_state *state = private_data;
	struct gencache_timeout t;
	DATA_BLOB payload;
	bool ret;

	ret = gencache_pull_timeout(key, data, &t.timeout, &payload);
	if (!ret) {
		state->format_error = true;
		return 0;
	}
	state->parser(&t, payload, state->private_data);

	return 0;
}

bool gencache_parse(const char *keystr,
		    void (*parser)(const struct gencache_timeout *timeout,
				   DATA_BLOB blob,
				   void *private_data),
		    void *private_data)
{
	struct gencache_parse_state state = {
		.parser = parser, .private_data = private_data
	};
	TDB_DATA key = string_term_tdb_data(keystr);
	int ret;

	if (keystr == NULL) {
		return false;
	}
	if (!gencache_init()) {
		return false;
	}

	ret = tdb_parse_record(cache->tdb, key,
			       gencache_parse_fn, &state);
	if ((ret == -1) && (tdb_error(cache->tdb) == TDB_ERR_CORRUPT)) {
		goto wipe;
	}
	if (ret == -1) {
		return false;
	}
	if (state.format_error) {
		ret = tdb_delete(cache->tdb, key);
		if (ret == -1) {
			goto wipe;
		}
		return false;
	}
	return true;

wipe:
	ret = tdb_wipe_all(cache->tdb);
	SMB_ASSERT(ret == 0);
	return false;
}

struct gencache_get_data_blob_state {
	TALLOC_CTX *mem_ctx;
	DATA_BLOB *blob;
	time_t timeout;
	bool result;
};

static void gencache_get_data_blob_parser(const struct gencache_timeout *t,
					  DATA_BLOB blob,
					  void *private_data)
{
	struct gencache_get_data_blob_state *state =
		(struct gencache_get_data_blob_state *)private_data;

	if (t->timeout == 0) {
		state->result = false;
		return;
	}
	state->timeout = t->timeout;

	if (state->blob == NULL) {
		state->result = true;
		return;
	}

	*state->blob = data_blob_talloc(state->mem_ctx, blob.data,
					blob.length);
	if (state->blob->data == NULL) {
		state->result = false;
		return;
	}
	state->result = true;
}

/**
 * Get existing entry from the cache file.
 *
 * @param keystr string that represents a key of this entry
 * @param blob DATA_BLOB that is filled with entry's blob
 * @param timeout pointer to a time_t that is filled with entry's
 *        timeout
 *
 * @retval true when entry is successfully fetched
 * @retval false for failure
 **/

bool gencache_get_data_blob(const char *keystr, TALLOC_CTX *mem_ctx,
			    DATA_BLOB *blob,
			    time_t *timeout, bool *was_expired)
{
	struct gencache_get_data_blob_state state;
	bool expired = false;

	state.result = false;
	state.mem_ctx = mem_ctx;
	state.blob = blob;

	if (!gencache_parse(keystr, gencache_get_data_blob_parser, &state)) {
		goto fail;
	}
	if (!state.result) {
		goto fail;
	}
	if (state.timeout <= time(NULL)) {
		/*
		 * We're expired, delete the entry. We can't use gencache_del
		 * here, because that uses gencache_get_data_blob for checking
		 * the existence of a record. We know the thing exists and
		 * directly store an empty value with 0 timeout.
		 */
		gencache_set(keystr, "", 0);
		expired = true;
		goto fail;
	}
	if (timeout) {
		*timeout = state.timeout;
	}

	return true;

fail:
	if (was_expired != NULL) {
		*was_expired = expired;
	}
	if (state.result && state.blob) {
		data_blob_free(state.blob);
	}
	return false;
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
 * @retval true when entry is successfully fetched
 * @retval false for failure
 **/

bool gencache_get(const char *keystr, TALLOC_CTX *mem_ctx, char **value,
		  time_t *ptimeout)
{
	DATA_BLOB blob;
	bool ret = false;

	ret = gencache_get_data_blob(keystr, mem_ctx, &blob, ptimeout, NULL);
	if (!ret) {
		return false;
	}
	if ((blob.data == NULL) || (blob.length == 0)) {
		data_blob_free(&blob);
		return false;
	}
	if (blob.data[blob.length-1] != '\0') {
		/* Not NULL terminated, can't be a string */
		data_blob_free(&blob);
		return false;
	}
	if (value) {
		/*
		 * talloc_move generates a type-punned warning here. As we
		 * leave the function immediately, do a simple talloc_steal.
		 */
		*value = (char *)talloc_steal(mem_ctx, blob.data);
		return true;
	}
	data_blob_free(&blob);
	return true;
}

/**
 * Set an entry in the cache file. If there's no such
 * one, then add it.
 *
 * @param keystr string that represents a key of this entry
 * @param value text representation value being cached
 * @param timeout time when the value is expired
 *
 * @retval true when entry is successfully stored
 * @retval false on failure
 **/

bool gencache_set(const char *keystr, const char *value, time_t timeout)
{
	DATA_BLOB blob = data_blob_const(value, strlen(value)+1);
	return gencache_set_data_blob(keystr, blob, timeout);
}

struct gencache_iterate_blobs_state {
	void (*fn)(const char *key, DATA_BLOB value,
		   time_t timeout, void *private_data);
	const char *pattern;
	void *private_data;
};

static int gencache_iterate_blobs_fn(struct tdb_context *tdb, TDB_DATA key,
				     TDB_DATA data, void *priv)
{
	struct gencache_iterate_blobs_state *state =
		(struct gencache_iterate_blobs_state *)priv;
	char *keystr;
	char *free_key = NULL;
	time_t timeout;
	DATA_BLOB payload;

	if (key.dptr[key.dsize-1] == '\0') {
		keystr = (char *)key.dptr;
	} else {
		/* ensure 0-termination */
		keystr = talloc_strndup(talloc_tos(), (char *)key.dptr, key.dsize);
		free_key = keystr;
		if (keystr == NULL) {
			goto done;
		}
	}

	if (!gencache_pull_timeout(key, data, &timeout, &payload)) {
		goto done;
	}

	if (timeout == 0) {
		/* delete marker */
		goto done;
	}

	if (fnmatch(state->pattern, keystr, 0) != 0) {
		goto done;
	}

	DEBUG(10, ("Calling function with arguments "
		   "(key=[%s], timeout=[%s])\n",
		   keystr, timestring(talloc_tos(), timeout)));

	state->fn(keystr, payload, timeout, state->private_data);

 done:
	TALLOC_FREE(free_key);
	return 0;
}

void gencache_iterate_blobs(void (*fn)(const char *key, DATA_BLOB value,
				       time_t timeout, void *private_data),
			    void *private_data, const char *pattern)
{
	struct gencache_iterate_blobs_state state;
	int ret;

	if ((fn == NULL) || (pattern == NULL) || !gencache_init()) {
		return;
	}

	DEBUG(5, ("Searching cache keys with pattern %s\n", pattern));

	state.fn = fn;
	state.pattern = pattern;
	state.private_data = private_data;

	ret = tdb_traverse(cache->tdb, gencache_iterate_blobs_fn, &state);

	if ((ret == -1) && (tdb_error(cache->tdb) == TDB_ERR_CORRUPT)) {
		ret = tdb_wipe_all(cache->tdb);
		SMB_ASSERT(ret == 0);
	}
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

struct gencache_iterate_state {
	void (*fn)(const char *key, const char *value, time_t timeout,
		   void *priv);
	void *private_data;
};

static void gencache_iterate_fn(const char *key, DATA_BLOB value,
				time_t timeout, void *private_data)
{
	struct gencache_iterate_state *state =
		(struct gencache_iterate_state *)private_data;
	char *valstr;
	char *free_val = NULL;

	if (value.data[value.length-1] == '\0') {
		valstr = (char *)value.data;
	} else {
		/* ensure 0-termination */
		valstr = talloc_strndup(talloc_tos(), (char *)value.data, value.length);
		free_val = valstr;
		if (valstr == NULL) {
			goto done;
		}
	}

	DEBUG(10, ("Calling function with arguments "
		   "(key=[%s], value=[%s], timeout=[%s])\n",
		   key, valstr, timestring(talloc_tos(), timeout)));

	state->fn(key, valstr, timeout, state->private_data);

  done:

	TALLOC_FREE(free_val);
}

void gencache_iterate(void (*fn)(const char *key, const char *value,
				 time_t timeout, void *dptr),
                      void *private_data, const char *pattern)
{
	struct gencache_iterate_state state;

	if (fn == NULL) {
		return;
	}
	state.fn = fn;
	state.private_data = private_data;
	gencache_iterate_blobs(gencache_iterate_fn, &state, pattern);
}
