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
#include "system/filesys.h"
#include "system/glob.h"
#include "util_tdb.h"
#include "tdb_wrap/tdb_wrap.h"
#include "../lib/util/memcache.h"

#undef  DBGC_CLASS
#define DBGC_CLASS DBGC_TDB

#define TIMEOUT_LEN 12
#define CACHE_DATA_FMT	"%12u/"
#define READ_CACHE_DATA_FMT_TEMPLATE "%%12u/%%%us"
#define BLOB_TYPE "DATA_BLOB"
#define BLOB_TYPE_LEN 9

static struct tdb_wrap *cache;
static struct tdb_wrap *cache_notrans;
static int cache_notrans_seqnum;

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

static bool gencache_init(void)
{
	char* cache_fname = NULL;
	int open_flags = O_RDWR|O_CREAT;

	/* skip file open if it's already opened */
	if (cache) return True;

	cache_fname = cache_path("gencache.tdb");

	DEBUG(5, ("Opening cache file at %s\n", cache_fname));

	cache = tdb_wrap_open(NULL, cache_fname, 0,
			      TDB_DEFAULT|TDB_INCOMPATIBLE_HASH,
			      open_flags, 0644);
	if (cache) {
		int ret;
		ret = tdb_check(cache->tdb, NULL, NULL);
		if (ret != 0) {
			TALLOC_FREE(cache);

			/*
			 * Retry with CLEAR_IF_FIRST.
			 *
			 * Warning: Converting this to dbwrap won't work
			 * directly. gencache.c does transactions on this tdb,
			 * and dbwrap forbids this for CLEAR_IF_FIRST
			 * databases. tdb does allow transactions on
			 * CLEAR_IF_FIRST databases, so lets use it here to
			 * clean up a broken database.
			 */
			cache = tdb_wrap_open(NULL, cache_fname, 0,
					      TDB_DEFAULT|
					      TDB_INCOMPATIBLE_HASH|
					      TDB_CLEAR_IF_FIRST,
					      open_flags, 0644);
		}
	}

	if (!cache && (errno == EACCES)) {
		open_flags = O_RDONLY;
		cache = tdb_wrap_open(NULL, cache_fname, 0,
				      TDB_DEFAULT|TDB_INCOMPATIBLE_HASH,
				      open_flags, 0644);
		if (cache) {
			DEBUG(5, ("gencache_init: Opening cache file %s read-only.\n", cache_fname));
		}
	}

	if (!cache) {
		DEBUG(5, ("Attempt to open gencache.tdb has failed.\n"));
		return False;
	}

	cache_fname = lock_path("gencache_notrans.tdb");

	DEBUG(5, ("Opening cache file at %s\n", cache_fname));

	cache_notrans = tdb_wrap_open(NULL, cache_fname, 0,
				      TDB_CLEAR_IF_FIRST|
				      TDB_INCOMPATIBLE_HASH|
				      TDB_SEQNUM|
				      TDB_NOSYNC|
				      TDB_MUTEX_LOCKING,
				      open_flags, 0644);
	if (cache_notrans == NULL) {
		DEBUG(5, ("Opening %s failed: %s\n", cache_fname,
			  strerror(errno)));
		TALLOC_FREE(cache);
		return false;
	}

	return True;
}

static TDB_DATA last_stabilize_key(void)
{
	TDB_DATA result;
	result.dptr = discard_const_p(uint8_t, "@LAST_STABILIZED");
	result.dsize = 17;
	return result;
}

struct gencache_have_val_state {
	time_t new_timeout;
	const DATA_BLOB *data;
	bool gotit;
};

static void gencache_have_val_parser(time_t old_timeout, DATA_BLOB data,
				     void *private_data)
{
	struct gencache_have_val_state *state =
		(struct gencache_have_val_state *)private_data;
	time_t now = time(NULL);
	int cache_time_left, new_time_left, additional_time;

	/*
	 * Excuse the many variables, but these time calculations are
	 * confusing to me. We do not want to write to gencache with a
	 * possibly expensive transaction if we are about to write the same
	 * value, just extending the remaining timeout by less than 10%.
	 */

	cache_time_left = old_timeout - now;
	if (cache_time_left <= 0) {
		/*
		 * timed out, write new value
		 */
		return;
	}

	new_time_left = state->new_timeout - now;
	if (new_time_left <= 0) {
		/*
		 * Huh -- no new timeout?? Write it.
		 */
		return;
	}

	if (new_time_left < cache_time_left) {
		/*
		 * Someone wants to shorten the timeout. Let it happen.
		 */
		return;
	}

	/*
	 * By how much does the new timeout extend the remaining cache time?
	 */
	additional_time = new_time_left - cache_time_left;

	if (additional_time * 10 < 0) {
		/*
		 * Integer overflow. We extend by so much that we have to write it.
		 */
		return;
	}

	/*
	 * The comparison below is essentially equivalent to
	 *
	 *    new_time_left > cache_time_left * 1.10
	 *
	 * but without floating point calculations.
	 */

	if (additional_time * 10 > cache_time_left) {
		/*
		 * We extend the cache timeout by more than 10%. Do it.
		 */
		return;
	}

	/*
	 * Now the more expensive data compare.
	 */
	if (data_blob_cmp(state->data, &data) != 0) {
		/*
		 * Write a new value. Certainly do it.
		 */
		return;
	}

	/*
	 * Extending the timeout by less than 10% for the same cache value is
	 * not worth the trouble writing a value into gencache under a
	 * possibly expensive transaction.
	 */
	state->gotit = true;
}

static bool gencache_have_val(const char *keystr, const DATA_BLOB *data,
			      time_t timeout)
{
	struct gencache_have_val_state state;

	state.new_timeout = timeout;
	state.data = data;
	state.gotit = false;

	if (!gencache_parse(keystr, gencache_have_val_parser, &state)) {
		return false;
	}
	return state.gotit;
}

static int last_stabilize_parser(TDB_DATA key, TDB_DATA data,
				 void *private_data)
{
	time_t *last_stabilize = private_data;

	if ((data.dsize != 0) && (data.dptr[data.dsize-1] == '\0')) {
		*last_stabilize = atoi((char *)data.dptr);
	}
	return 0;
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

bool gencache_set_data_blob(const char *keystr, const DATA_BLOB *blob,
			    time_t timeout)
{
	int ret;
	char* val;
	time_t last_stabilize;
	static int writecount;

	if (tdb_data_cmp(string_term_tdb_data(keystr),
			 last_stabilize_key()) == 0) {
		DEBUG(10, ("Can't store %s as a key\n", keystr));
		return false;
	}

	if ((keystr == NULL) || (blob == NULL)) {
		return false;
	}

	if (!gencache_init()) return False;

	if (gencache_have_val(keystr, blob, timeout)) {
		DEBUG(10, ("Did not store value for %s, we already got it\n",
			   keystr));
		return true;
	}

	val = talloc_asprintf(talloc_tos(), CACHE_DATA_FMT, (int)timeout);
	if (val == NULL) {
		return False;
	}
	val = talloc_realloc(NULL, val, char, talloc_array_length(val)-1);
	if (val == NULL) {
		return false;
	}
	val = (char *)talloc_append_blob(NULL, val, *blob);
	if (val == NULL) {
		return false;
	}

	DEBUG(10, ("Adding cache entry with key=[%s] and timeout="
	           "[%s] (%d seconds %s)\n", keystr,
		   timestring(talloc_tos(), timeout),
		   (int)(timeout - time(NULL)), 
		   timeout > time(NULL) ? "ahead" : "in the past"));

	ret = tdb_store_bystring(
		cache_notrans->tdb, keystr,
		make_tdb_data((uint8_t *)val, talloc_array_length(val)),
		0);
	TALLOC_FREE(val);

	if (ret != 0) {
		return false;
	}

	/*
	 * Every 100 writes within a single process, stabilize the cache with
	 * a transaction. This is done to prevent a single transaction to
	 * become huge and chew lots of memory.
	 */
	writecount += 1;
	if (writecount > lp_parm_int(-1, "gencache", "stabilize_count", 100)) {
		gencache_stabilize();
		writecount = 0;
		goto done;
	}

	/*
	 * Every 5 minutes, call gencache_stabilize() to not let grow
	 * gencache_notrans.tdb too large.
	 */

	last_stabilize = 0;

	tdb_parse_record(cache_notrans->tdb, last_stabilize_key(),
			 last_stabilize_parser, &last_stabilize);

	if ((last_stabilize
	     + lp_parm_int(-1, "gencache", "stabilize_interval", 300))
	    < time(NULL)) {
		gencache_stabilize();
	}

done:
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
	bool exists, was_expired;
	bool ret = false;
	DATA_BLOB value;

	if (keystr == NULL) {
		return false;
	}

	if (!gencache_init()) return False;	

	DEBUG(10, ("Deleting cache entry (key=[%s])\n", keystr));

	/*
	 * We delete an element by setting its timeout to 0. This way we don't
	 * have to do a transaction on gencache.tdb every time we delete an
	 * element.
	 */

	exists = gencache_get_data_blob(keystr, NULL, &value, NULL,
					&was_expired);

	if (!exists && was_expired) {
		/*
		 * gencache_get_data_blob has implicitly deleted this
		 * entry, so we have to return success here.
		 */
		return true;
	}

	if (exists) {
		data_blob_free(&value);
		ret = gencache_set(keystr, "", 0);
	}
	return ret;
}

static bool gencache_pull_timeout(char *val, time_t *pres, char **pendptr)
{
	time_t res;
	char *endptr;

	if (val == NULL) {
		return false;
	}

	res = strtol(val, &endptr, 10);

	if ((endptr == NULL) || (*endptr != '/')) {
		DEBUG(2, ("Invalid gencache data format: %s\n", val));
		return false;
	}
	if (pres != NULL) {
		*pres = res;
	}
	if (pendptr != NULL) {
		*pendptr = endptr;
	}
	return true;
}

struct gencache_parse_state {
	void (*parser)(time_t timeout, DATA_BLOB blob, void *private_data);
	void *private_data;
	bool is_memcache;
};

static int gencache_parse_fn(TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct gencache_parse_state *state;
	DATA_BLOB blob;
	time_t t;
	char *endptr;
	bool ret;

	if (data.dptr == NULL) {
		return -1;
	}
	ret = gencache_pull_timeout((char *)data.dptr, &t, &endptr);
	if (!ret) {
		return -1;
	}
	state = (struct gencache_parse_state *)private_data;
	blob = data_blob_const(
		endptr+1, data.dsize - PTR_DIFF(endptr+1, data.dptr));
	state->parser(t, blob, state->private_data);

	if (!state->is_memcache) {
		memcache_add(NULL, GENCACHE_RAM,
			     data_blob_const(key.dptr, key.dsize),
			     data_blob_const(data.dptr, data.dsize));
	}

	return 0;
}

bool gencache_parse(const char *keystr,
		    void (*parser)(time_t timeout, DATA_BLOB blob,
				   void *private_data),
		    void *private_data)
{
	struct gencache_parse_state state;
	TDB_DATA key = string_term_tdb_data(keystr);
	DATA_BLOB memcache_val;
	int ret;

	if (keystr == NULL) {
		return false;
	}
	if (tdb_data_cmp(key, last_stabilize_key()) == 0) {
		return false;
	}
	if (!gencache_init()) {
		return false;
	}

	state.parser = parser;
	state.private_data = private_data;

	if (memcache_lookup(NULL, GENCACHE_RAM,
			    data_blob_const(key.dptr, key.dsize),
			    &memcache_val)) {
		/*
		 * Make sure that nobody has changed the gencache behind our
		 * back.
		 */
		int current_seqnum = tdb_get_seqnum(cache_notrans->tdb);
		if (current_seqnum == cache_notrans_seqnum) {
			/*
			 * Ok, our memcache is still current, use it without
			 * going to the tdb files.
			 */
			state.is_memcache = true;
			gencache_parse_fn(key, make_tdb_data(memcache_val.data,
							     memcache_val.length),
					  &state);
			return true;
		}
		memcache_flush(NULL, GENCACHE_RAM);
		cache_notrans_seqnum = current_seqnum;
	}

	state.is_memcache = false;

	ret = tdb_parse_record(cache_notrans->tdb, key,
			       gencache_parse_fn, &state);
	if (ret == 0) {
		return true;
	}
	ret = tdb_parse_record(cache->tdb, key, gencache_parse_fn, &state);
	return (ret == 0);
}

struct gencache_get_data_blob_state {
	TALLOC_CTX *mem_ctx;
	DATA_BLOB *blob;
	time_t timeout;
	bool result;
};

static void gencache_get_data_blob_parser(time_t timeout, DATA_BLOB blob,
					  void *private_data)
{
	struct gencache_get_data_blob_state *state =
		(struct gencache_get_data_blob_state *)private_data;

	if (timeout == 0) {
		state->result = false;
		return;
	}
	state->timeout = timeout;

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
 * @retval true when entry is successfuly fetched
 * @retval False for failure
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

	return True;

fail:
	if (was_expired != NULL) {
		*was_expired = expired;
	}
	if (state.result && state.blob) {
		data_blob_free(state.blob);
	}
	return false;
} 

struct stabilize_state {
	bool written;
};
static int stabilize_fn(struct tdb_context *tdb, TDB_DATA key, TDB_DATA val,
			void *priv);

static int wipe_fn(struct tdb_context *tdb, TDB_DATA key, TDB_DATA val,
		   void *priv);

/**
 * Stabilize gencache
 *
 * Migrate the clear-if-first gencache data to the stable,
 * transaction-based gencache.tdb
 */

bool gencache_stabilize(void)
{
	struct stabilize_state state;
	int res;
	char *now;

	if (!gencache_init()) {
		return false;
	}

	res = tdb_transaction_start_nonblock(cache->tdb);
	if (res != 0) {
		if (tdb_error(cache->tdb) == TDB_ERR_NOLOCK)
		{
			/*
			 * Someone else already does the stabilize,
			 * this does not have to be done twice
			 */
			return true;
		}

		DEBUG(10, ("Could not start transaction on gencache.tdb: "
			   "%s\n", tdb_errorstr_compat(cache->tdb)));
		return false;
	}

	res = tdb_lockall(cache_notrans->tdb);
	if (res != 0) {
		tdb_transaction_cancel(cache->tdb);
		DEBUG(10, ("Could not get allrecord lock on "
			   "gencache_notrans.tdb: %s\n",
			   tdb_errorstr_compat(cache_notrans->tdb)));
		return false;
	}

	state.written = false;

	res = tdb_traverse(cache_notrans->tdb, stabilize_fn, &state);
	if (res < 0) {
		tdb_unlockall(cache_notrans->tdb);
		tdb_transaction_cancel(cache->tdb);
		return false;
	}

	if (!state.written) {
		tdb_unlockall(cache_notrans->tdb);
		tdb_transaction_cancel(cache->tdb);
		return true;
	}

	res = tdb_transaction_commit(cache->tdb);
	if (res != 0) {
		DEBUG(10, ("tdb_transaction_commit on gencache.tdb failed: "
			   "%s\n", tdb_errorstr_compat(cache->tdb)));
		tdb_unlockall(cache_notrans->tdb);
		return false;
	}

	res = tdb_traverse(cache_notrans->tdb, wipe_fn, NULL);
	if (res < 0) {
		DEBUG(10, ("tdb_traverse with wipe_fn on gencache_notrans.tdb "
			  "failed: %s\n",
			   tdb_errorstr_compat(cache_notrans->tdb)));
		tdb_unlockall(cache_notrans->tdb);
		return false;
	}

	res = tdb_unlockall(cache_notrans->tdb);
	if (res != 0) {
		DEBUG(10, ("tdb_unlockall on gencache.tdb failed: "
			   "%s\n", tdb_errorstr_compat(cache->tdb)));
		return false;
	}

	now = talloc_asprintf(talloc_tos(), "%d", (int)time(NULL));
	if (now != NULL) {
		tdb_store(cache_notrans->tdb, last_stabilize_key(),
			  string_term_tdb_data(now), 0);
		TALLOC_FREE(now);
	}

	return true;
}

static int stabilize_fn(struct tdb_context *tdb, TDB_DATA key, TDB_DATA val,
			void *priv)
{
	struct stabilize_state *state = (struct stabilize_state *)priv;
	int res;
	time_t timeout;

	if (tdb_data_cmp(key, last_stabilize_key()) == 0) {
		return 0;
	}

	if (!gencache_pull_timeout((char *)val.dptr, &timeout, NULL)) {
		DEBUG(10, ("Ignoring invalid entry\n"));
		return 0;
	}
	if ((timeout < time(NULL)) || (val.dsize == 0)) {
		res = tdb_delete(cache->tdb, key);
		if (res == 0) {
			state->written = true;
		} else if (tdb_error(cache->tdb) == TDB_ERR_NOEXIST) {
			res = 0;
		}
	} else {
		res = tdb_store(cache->tdb, key, val, 0);
		if (res == 0) {
			state->written = true;
		}
	}

	if (res != 0) {
		DEBUG(10, ("Transfer to gencache.tdb failed: %s\n",
			   tdb_errorstr_compat(cache->tdb)));
		return -1;
	}

	return 0;
}

static int wipe_fn(struct tdb_context *tdb, TDB_DATA key, TDB_DATA val,
		   void *priv)
{
	int res;
	bool ok;
	time_t timeout;

	res = tdb_data_cmp(key, last_stabilize_key());
	if (res == 0) {
		return 0;
	}

	ok = gencache_pull_timeout((char *)val.dptr, &timeout, NULL);
	if (!ok) {
		DEBUG(10, ("Ignoring invalid entry\n"));
		return 0;
	}

	res = tdb_delete(tdb, key);
	if (res != 0) {
		DEBUG(10, ("tdb_delete from gencache_notrans.tdb failed: "
			   "%s\n", tdb_errorstr_compat(cache_notrans->tdb)));
		return -1;
	}

	return 0;
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

bool gencache_get(const char *keystr, TALLOC_CTX *mem_ctx, char **value,
		  time_t *ptimeout)
{
	DATA_BLOB blob;
	bool ret = False;

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
 * @retval true when entry is successfuly stored
 * @retval false on failure
 **/

bool gencache_set(const char *keystr, const char *value, time_t timeout)
{
	DATA_BLOB blob = data_blob_const(value, strlen(value)+1);
	return gencache_set_data_blob(keystr, &blob, timeout);
}

struct gencache_iterate_blobs_state {
	void (*fn)(const char *key, DATA_BLOB value,
		   time_t timeout, void *private_data);
	const char *pattern;
	void *private_data;
	bool in_persistent;
};

static int gencache_iterate_blobs_fn(struct tdb_context *tdb, TDB_DATA key,
				     TDB_DATA data, void *priv)
{
	struct gencache_iterate_blobs_state *state =
		(struct gencache_iterate_blobs_state *)priv;
	char *keystr;
	char *free_key = NULL;
	time_t timeout;
	char *endptr;

	if (tdb_data_cmp(key, last_stabilize_key()) == 0) {
		return 0;
	}
	if (state->in_persistent && tdb_exists(cache_notrans->tdb, key)) {
		return 0;
	}

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

	if (!gencache_pull_timeout((char *)data.dptr, &timeout, &endptr)) {
		goto done;
	}
	endptr += 1;

	if (fnmatch(state->pattern, keystr, 0) != 0) {
		goto done;
	}

	DEBUG(10, ("Calling function with arguments "
		   "(key=[%s], timeout=[%s])\n",
		   keystr, timestring(talloc_tos(), timeout)));

	state->fn(keystr,
		  data_blob_const(endptr,
				  data.dsize - PTR_DIFF(endptr, data.dptr)),
		  timeout, state->private_data);

 done:
	TALLOC_FREE(free_key);
	return 0;
}

void gencache_iterate_blobs(void (*fn)(const char *key, DATA_BLOB value,
				       time_t timeout, void *private_data),
			    void *private_data, const char *pattern)
{
	struct gencache_iterate_blobs_state state;

	if ((fn == NULL) || (pattern == NULL) || !gencache_init()) {
		return;
	}

	DEBUG(5, ("Searching cache keys with pattern %s\n", pattern));

	state.fn = fn;
	state.pattern = pattern;
	state.private_data = private_data;

	state.in_persistent = false;
	tdb_traverse(cache_notrans->tdb, gencache_iterate_blobs_fn, &state);

	state.in_persistent = true;
	tdb_traverse(cache->tdb, gencache_iterate_blobs_fn, &state);
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
