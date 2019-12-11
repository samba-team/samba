/*
   Unix SMB/CIFS implementation.
   Locking functions
   Copyright (C) Andrew Tridgell 1992-2000
   Copyright (C) Jeremy Allison 1992-2006
   Copyright (C) Volker Lendecke 2005

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

   Revision History:

   12 aug 96: Erik.Devriendt@te6.siemens.be
   added support for shared memory implementation of share mode locking

   May 1997. Jeremy Allison (jallison@whistle.com). Modified share mode
   locking to deal with multiple share modes per open file.

   September 1997. Jeremy Allison (jallison@whistle.com). Added oplock
   support.

   rewritten completely to use new tdb code. Tridge, Dec '99

   Added POSIX locking support. Jeremy Allison (jeremy@valinux.com), Apr. 2000.
   Added Unix Extensions POSIX locking support. Jeremy Allison Mar 2006.
*/

#include "includes.h"
#include "system/filesys.h"
#include "lib/util/server_id.h"
#include "locking/proto.h"
#include "smbd/globals.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "../libcli/security/security.h"
#include "serverid.h"
#include "messages.h"
#include "util_tdb.h"
#include "../librpc/gen_ndr/ndr_open_files.h"
#include "source3/lib/dbwrap/dbwrap_watch.h"
#include "locking/leases_db.h"
#include "../lib/util/memcache.h"
#include "lib/util/tevent_ntstatus.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

#define NO_LOCKING_COUNT (-1)

/* the locking database handle */
static struct db_context *lock_db;
static struct db_context *share_entries_db;

static bool locking_init_internal(bool read_only)
{
	struct db_context *backend;
	char *db_path;

	brl_init(read_only);

	if (lock_db)
		return True;

	db_path = lock_path(talloc_tos(), "locking.tdb");
	if (db_path == NULL) {
		return false;
	}

	backend = db_open(NULL, db_path,
			  SMB_OPEN_DATABASE_TDB_HASH_SIZE,
			  TDB_DEFAULT|
			  TDB_VOLATILE|
			  TDB_CLEAR_IF_FIRST|
			  TDB_INCOMPATIBLE_HASH|
			  TDB_SEQNUM,
			  read_only?O_RDONLY:O_RDWR|O_CREAT, 0644,
			  DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);
	TALLOC_FREE(db_path);
	if (!backend) {
		DEBUG(0,("ERROR: Failed to initialise locking database\n"));
		return False;
	}

	lock_db = db_open_watched(NULL, &backend, global_messaging_context());
	if (lock_db == NULL) {
		DBG_ERR("db_open_watched failed\n");
		TALLOC_FREE(backend);
		return false;
	}

	db_path = lock_path(talloc_tos(), "share_entries.tdb");
	if (db_path == NULL) {
		return false;
	}

	share_entries_db = db_open(
		NULL, db_path,
		SMB_OPEN_DATABASE_TDB_HASH_SIZE,
		TDB_DEFAULT|
		TDB_VOLATILE|
		TDB_CLEAR_IF_FIRST|
		TDB_INCOMPATIBLE_HASH,
		read_only?O_RDONLY:O_RDWR|O_CREAT, 0644,
		DBWRAP_LOCK_ORDER_3, DBWRAP_FLAG_NONE);
	TALLOC_FREE(db_path);

	if (share_entries_db == NULL) {
		TALLOC_FREE(lock_db);
		return false;
	}

	if (!posix_locking_init(read_only)) {
		TALLOC_FREE(share_entries_db);
		TALLOC_FREE(lock_db);
		return False;
	}

	return True;
}

bool locking_init(void)
{
	return locking_init_internal(false);
}

bool locking_init_readonly(void)
{
	return locking_init_internal(true);
}

/*******************************************************************
 Deinitialize the share_mode management.
******************************************************************/

bool locking_end(void)
{
	brl_shutdown();
	TALLOC_FREE(lock_db);
	return true;
}

/*******************************************************************
 Form a static locking key for a dev/inode pair.
******************************************************************/

static TDB_DATA locking_key(const struct file_id *id)
{
	return make_tdb_data((const uint8_t *)id, sizeof(*id));
}

/*******************************************************************
 Share mode cache utility functions that store/delete/retrieve
 entries from memcache.

 For now share the statcache (global cache) memory space. If
 a lock record gets orphaned (which shouldn't happen as we're
 using the same locking_key data as lookup) it will eventually
 fall out of the cache via the normal LRU trim mechanism. If
 necessary we can always make this a separate (smaller) cache.
******************************************************************/

static DATA_BLOB memcache_key(const struct file_id *id)
{
	return data_blob_const((const void *)id, sizeof(*id));
}

static void share_mode_memcache_store(struct share_mode_data *d)
{
	const DATA_BLOB key = memcache_key(&d->id);
	struct file_id_buf idbuf;

	DBG_DEBUG("stored entry for file %s seq %"PRIx64" key %s\n",
		  d->base_name,
		  d->sequence_number,
		  file_id_str_buf(d->id, &idbuf));

	/* Ensure everything stored in the cache is pristine. */
	d->modified = false;
	d->fresh = false;

	/*
	 * Ensure the memory going into the cache
	 * doesn't have a destructor so it can be
	 * cleanly evicted by the memcache LRU
	 * mechanism.
	 */
	talloc_set_destructor(d, NULL);

	/* Cache will own d after this call. */
	memcache_add_talloc(NULL,
			SHARE_MODE_LOCK_CACHE,
			key,
			&d);
}

/*
 * NB. We use ndr_pull_hyper on a stack-created
 * struct ndr_pull with no talloc allowed, as we
 * need this to be really fast as an ndr-peek into
 * the first 9 bytes of the blob.
 */

static enum ndr_err_code get_share_mode_blob_header(
	DATA_BLOB *blob, uint64_t *pseq, uint16_t *pflags)
{
	struct ndr_pull ndr = {.data = blob->data, .data_size = blob->length};
	NDR_CHECK(ndr_pull_hyper(&ndr, NDR_SCALARS, pseq));
	NDR_CHECK(ndr_pull_uint16(&ndr, NDR_SCALARS, pflags));
	return NDR_ERR_SUCCESS;
}

struct fsp_update_share_mode_flags_state {
	enum ndr_err_code ndr_err;
	uint16_t share_mode_flags;
};

static void fsp_update_share_mode_flags_fn(
	TDB_DATA value, bool *modified_dependent, void *private_data)
{
	struct fsp_update_share_mode_flags_state *state = private_data;
	DATA_BLOB blob = { .data = value.dptr, .length = value.dsize };
	uint64_t seq;

	state->ndr_err = get_share_mode_blob_header(
		&blob, &seq, &state->share_mode_flags);
}

static NTSTATUS fsp_update_share_mode_flags(struct files_struct *fsp)
{
	struct fsp_update_share_mode_flags_state state = {0};
	int seqnum = dbwrap_get_seqnum(lock_db);
	NTSTATUS status;

	if (seqnum == fsp->share_mode_flags_seqnum) {
		return NT_STATUS_OK;
	}

	status = share_mode_do_locked(
		fsp->file_id, fsp_update_share_mode_flags_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("share_mode_do_locked returned %s\n",
			  nt_errstr(status));
		return status;
	}

	if (!NDR_ERR_CODE_IS_SUCCESS(state.ndr_err)) {
		DBG_DEBUG("get_share_mode_blob_header returned %s\n",
			  ndr_errstr(state.ndr_err));
		return ndr_map_error2ntstatus(state.ndr_err);
	}

	fsp->share_mode_flags_seqnum = seqnum;
	fsp->share_mode_flags = state.share_mode_flags;

	return NT_STATUS_OK;
}

bool file_has_read_lease(struct files_struct *fsp)
{
	NTSTATUS status;

	status = fsp_update_share_mode_flags(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		/* Safe default for leases */
		return true;
	}

	return (fsp->share_mode_flags & SHARE_MODE_LEASE_READ) != 0;
}

static int share_mode_data_nofree_destructor(struct share_mode_data *d)
{
	return -1;
}

static struct share_mode_data *share_mode_memcache_fetch(TALLOC_CTX *mem_ctx,
					const TDB_DATA id_key,
					DATA_BLOB *blob)
{
	enum ndr_err_code ndr_err;
	struct share_mode_data *d;
	uint64_t sequence_number;
	uint16_t flags;
	void *ptr;
	struct file_id id;
	struct file_id_buf idbuf;
	DATA_BLOB key;

	/* Ensure this is a locking_key record. */
	if (id_key.dsize != sizeof(id)) {
		return NULL;
	}

	memcpy(&id, id_key.dptr, id_key.dsize);
	key = memcache_key(&id);

	ptr = memcache_lookup_talloc(NULL,
			SHARE_MODE_LOCK_CACHE,
			key);
	if (ptr == NULL) {
		DBG_DEBUG("failed to find entry for key %s\n",
			  file_id_str_buf(id, &idbuf));
		return NULL;
	}
	/* sequence number key is at start of blob. */
	ndr_err = get_share_mode_blob_header(blob, &sequence_number, &flags);
	if (ndr_err != NDR_ERR_SUCCESS) {
		/* Bad blob. Remove entry. */
		DBG_DEBUG("bad blob %u key %s\n",
			  (unsigned int)ndr_err,
			  file_id_str_buf(id, &idbuf));
		memcache_delete(NULL,
			SHARE_MODE_LOCK_CACHE,
			key);
		return NULL;
	}

	d = (struct share_mode_data *)ptr;
	if (d->sequence_number != sequence_number) {
		DBG_DEBUG("seq changed (cached %"PRIx64") (new %"PRIx64") "
			  "for key %s\n",
			  d->sequence_number,
			  sequence_number,
			  file_id_str_buf(id, &idbuf));
		/* Cache out of date. Remove entry. */
		memcache_delete(NULL,
			SHARE_MODE_LOCK_CACHE,
			key);
		return NULL;
	}

	/* Move onto mem_ctx. */
	d = talloc_move(mem_ctx, &ptr);

	/*
	 * Now we own d, prevent the cache from freeing it
	 * when we delete the entry.
	 */
	talloc_set_destructor(d, share_mode_data_nofree_destructor);

	/* Remove from the cache. We own it now. */
	memcache_delete(NULL,
			SHARE_MODE_LOCK_CACHE,
			key);

	/* And reset the destructor to none. */
	talloc_set_destructor(d, NULL);

	DBG_DEBUG("fetched entry for file %s seq %"PRIx64" key %s\n",
		  d->base_name,
		  d->sequence_number,
		  file_id_str_buf(id, &idbuf));

	return d;
}

/*******************************************************************
 Get all share mode entries for a dev/inode pair.
********************************************************************/

static struct share_mode_data *parse_share_modes(TALLOC_CTX *mem_ctx,
						const TDB_DATA key,
						const TDB_DATA dbuf)
{
	struct share_mode_data *d;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;

	blob.data = dbuf.dptr;
	blob.length = dbuf.dsize;

	/* See if we already have a cached copy of this key. */
	d = share_mode_memcache_fetch(mem_ctx, key, &blob);
	if (d != NULL) {
		return d;
	}

	d = talloc(mem_ctx, struct share_mode_data);
	if (d == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	ndr_err = ndr_pull_struct_blob_all(
		&blob, d, d, (ndr_pull_flags_fn_t)ndr_pull_share_mode_data);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("ndr_pull_share_mode_data failed: %s\n",
			    ndr_errstr(ndr_err));
		goto fail;
	}

	if (DEBUGLEVEL >= 10) {
		DEBUG(10, ("parse_share_modes:\n"));
		NDR_PRINT_DEBUG(share_mode_data, d);
	}

	/*
	 * We have a non-zero locking.tdb record that was correctly
	 * parsed. This means a share_entries.tdb entry exists,
	 * otherwise we'd have paniced before in
	 * share_mode_data_store()
	 */
	d->have_share_modes = true;

	return d;
fail:
	TALLOC_FREE(d);
	return NULL;
}

/*******************************************************************
 If modified, store the share_mode_data back into the database.
********************************************************************/

static NTSTATUS share_mode_data_store(
	struct share_mode_data *d, struct db_record *rec)
{
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	if (!d->modified) {
		DBG_DEBUG("not modified\n");
		return NT_STATUS_OK;
	}

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("\n");
		NDR_PRINT_DEBUG(share_mode_data, d);
	}

	d->sequence_number += 1;

	if (!d->have_share_modes) {
		TDB_DATA key = dbwrap_record_get_key(rec);
		bool share_entries_exist;
		share_entries_exist = dbwrap_exists(share_entries_db, key);
		SMB_ASSERT(!share_entries_exist);

		TALLOC_FREE(d->delete_tokens);
		d->num_delete_tokens = 0;

		if (d->fresh) {
			DBG_DEBUG("Ignoring fresh empty record\n");
			return NT_STATUS_OK;
		}
		status = dbwrap_record_delete(rec);
		return status;
	}

	ndr_err = ndr_push_struct_blob(
		&blob, d, d, (ndr_push_flags_fn_t)ndr_push_share_mode_data);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_DEBUG("ndr_push_share_mode_data failed: %s\n",
			  ndr_errstr(ndr_err));
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = dbwrap_record_store(
		rec,
		(TDB_DATA) { .dptr = blob.data, .dsize = blob.length },
		TDB_REPLACE);
	TALLOC_FREE(blob.data);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dbwrap_record_store failed: %s\n",
			  nt_errstr(status));
	}

	return status;
}

/*******************************************************************
 Allocate a new share_mode_data struct, mark it unmodified.
 fresh is set to note that currently there is no database entry.
********************************************************************/

static struct share_mode_data *fresh_share_mode_lock(
	TALLOC_CTX *mem_ctx, const char *servicepath,
	const struct smb_filename *smb_fname,
	const struct timespec *old_write_time)
{
	struct share_mode_data *d;

	if ((servicepath == NULL) || (smb_fname == NULL) ||
	    (old_write_time == NULL)) {
		return NULL;
	}

	d = talloc_zero(mem_ctx, struct share_mode_data);
	if (d == NULL) {
		goto fail;
	}
	/* New record - new sequence number. */
	generate_random_buffer((uint8_t *)&d->sequence_number, 8);

	d->base_name = talloc_strdup(d, smb_fname->base_name);
	if (d->base_name == NULL) {
		goto fail;
	}
	if (smb_fname->stream_name != NULL) {
		d->stream_name = talloc_strdup(d, smb_fname->stream_name);
		if (d->stream_name == NULL) {
			goto fail;
		}
	}
	d->servicepath = talloc_strdup(d, servicepath);
	if (d->servicepath == NULL) {
		goto fail;
	}
	d->old_write_time = full_timespec_to_nt_time(old_write_time);
	d->modified = false;
	d->fresh = true;
	return d;
fail:
	DEBUG(0, ("talloc failed\n"));
	TALLOC_FREE(d);
	return NULL;
}

/*
 * We can only ever have one share mode locked. Use a static
 * share_mode_data pointer that is shared by multiple nested
 * share_mode_lock structures, explicitly refcounted.
 */
static struct share_mode_data *static_share_mode_data = NULL;
static size_t static_share_mode_data_refcount = 0;

/*
 * db_record for the above. With dbwrap_do_locked we can get a
 * db_record on the stack, which we can't TALLOC_FREE but which we
 * need to share with a nested get_share_mode_lock call.
 */
static struct db_record *static_share_mode_record = NULL;
static TDB_DATA static_share_mode_record_value = {0};
static bool static_share_mode_record_talloced = false;

/*******************************************************************
 Either fetch a share mode from the database, or allocate a fresh
 one if the record doesn't exist.
********************************************************************/

static NTSTATUS get_static_share_mode_data(
	struct db_record *rec,
	struct file_id id,
	const char *servicepath,
	const struct smb_filename *smb_fname,
	const struct timespec *old_write_time)
{
	struct share_mode_data *d;
	TDB_DATA value = dbwrap_record_get_value(rec);

	SMB_ASSERT(static_share_mode_data == NULL);

	if (value.dptr == NULL) {
		d = fresh_share_mode_lock(
			lock_db, servicepath, smb_fname, old_write_time);
		if (d == NULL) {
			if (smb_fname == NULL) {
				return NT_STATUS_NOT_FOUND;
			}
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		TDB_DATA key = locking_key(&id);
		d = parse_share_modes(lock_db, key, value);
		if (d == NULL) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	}

	d->id = id;

	static_share_mode_data = d;

	return NT_STATUS_OK;
}

/*******************************************************************
 Get a share_mode_lock, Reference counted to allow nested calls.
********************************************************************/

static int share_mode_lock_destructor(struct share_mode_lock *lck);

struct share_mode_lock *get_share_mode_lock(
	TALLOC_CTX *mem_ctx,
	struct file_id id,
	const char *servicepath,
	const struct smb_filename *smb_fname,
	const struct timespec *old_write_time)
{
	TDB_DATA key = locking_key(&id);
	struct share_mode_lock *lck = NULL;
	NTSTATUS status;

	lck = talloc(mem_ctx, struct share_mode_lock);
	if (lck == NULL) {
		DEBUG(1, ("talloc failed\n"));
		return NULL;
	}

	if (static_share_mode_data != NULL) {
		if (!file_id_equal(&static_share_mode_data->id, &id)) {
			DEBUG(1, ("Can not lock two share modes "
				  "simultaneously\n"));
			goto fail;
		}
		goto done;
	}

	SMB_ASSERT(static_share_mode_data_refcount == 0);

	if (static_share_mode_record == NULL) {
		static_share_mode_record = dbwrap_fetch_locked(
			lock_db, lock_db, key);
		if (static_share_mode_record == NULL) {
			DEBUG(3, ("Could not lock share entry\n"));
			goto fail;
		}
		static_share_mode_record_talloced = true;
		static_share_mode_record_value = dbwrap_record_get_value(
			static_share_mode_record);

	} else {
		TDB_DATA static_key;
		int cmp;

		static_key = dbwrap_record_get_key(static_share_mode_record);

		cmp = tdb_data_cmp(static_key, key);
		if (cmp != 0) {
			DBG_WARNING("Can not lock two share modes "
				    "simultaneously\n");
			return NULL;
		}
	}

	status = get_static_share_mode_data(static_share_mode_record,
					    id,
					    servicepath,
					    smb_fname,
					    old_write_time);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("get_static_share_mode_data failed: %s\n",
			  nt_errstr(status));
		TALLOC_FREE(static_share_mode_record);
		goto fail;
	}

done:
	static_share_mode_data_refcount += 1;
	lck->data = static_share_mode_data;

	talloc_set_destructor(lck, share_mode_lock_destructor);

	return lck;
fail:
	TALLOC_FREE(lck);
	return NULL;
}

static int share_mode_lock_destructor(struct share_mode_lock *lck)
{
	NTSTATUS status;

	SMB_ASSERT(static_share_mode_data_refcount > 0);
	static_share_mode_data_refcount -= 1;

	if (static_share_mode_data_refcount > 0) {
		return 0;
	}

	status = share_mode_data_store(
		static_share_mode_data, static_share_mode_record);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_data_store failed: %s\n",
			nt_errstr(status));
		smb_panic("Could not store share mode data\n");
	}

	if (static_share_mode_record_talloced) {
		TALLOC_FREE(static_share_mode_record);
	}

	if (static_share_mode_data->have_share_modes) {
		/*
		 * This is worth keeping. Without share modes,
		 * share_mode_data_store above has left nothing in the
		 * database.
		 */
		share_mode_memcache_store(static_share_mode_data);
		static_share_mode_data = NULL;
	} else {
		/*
		 * The next opener of this file will find an empty
		 * locking.tdb record. Don't store the share_mode_data
		 * in the memcache, fresh_share_mode_lock() will
		 * generate a fresh seqnum anyway, obsoleting the
		 * cache entry.
		 */
		TALLOC_FREE(static_share_mode_data);
	}

	return 0;
}

struct share_mode_do_locked_state {
	void (*fn)(TDB_DATA value,
		   bool *modified_dependent,
		   void *private_data);
	void *private_data;
};

static void share_mode_do_locked_fn(
	struct db_record *rec,
	TDB_DATA value,
	void *private_data)
{
	struct share_mode_do_locked_state *state = private_data;
	bool modified_dependent = false;
	bool reset_static_share_mode_record = false;

	if (static_share_mode_record == NULL) {
		static_share_mode_record = rec;
		static_share_mode_record_value = value;
		static_share_mode_record_talloced = false;
		reset_static_share_mode_record = true;
	} else {
		SMB_ASSERT(static_share_mode_record == rec);
	}

	state->fn(value, &modified_dependent, state->private_data);

	if (modified_dependent) {
		dbwrap_watched_wakeup(rec);
	}

	if (reset_static_share_mode_record) {
		static_share_mode_record = NULL;
	}
}

NTSTATUS share_mode_do_locked(
	struct file_id id,
	void (*fn)(TDB_DATA value,
		   bool *modified_dependent,
		   void *private_data),
	void *private_data)
{
	TDB_DATA key = locking_key(&id);
	size_t refcount = static_share_mode_data_refcount;

	if (static_share_mode_record != NULL) {
		bool modified_dependent = false;
		TDB_DATA static_key;
		int cmp;

		static_key = dbwrap_record_get_key(static_share_mode_record);

		cmp = tdb_data_cmp(static_key, key);
		if (cmp != 0) {
			DBG_WARNING("Can not lock two share modes "
				    "simultaneously\n");
			return NT_STATUS_INVALID_LOCK_SEQUENCE;
		}

		fn(static_share_mode_record_value,
		   &modified_dependent,
		   private_data);

		if (modified_dependent) {
			dbwrap_watched_wakeup(static_share_mode_record);
		}
	} else {
		struct share_mode_do_locked_state state = {
			.fn = fn, .private_data = private_data,
		};
		NTSTATUS status;

		status = dbwrap_do_locked(
			lock_db, key, share_mode_do_locked_fn, &state);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("dbwrap_do_locked failed: %s\n",
				    nt_errstr(status));
			return status;
		}
	}

	SMB_ASSERT(refcount == static_share_mode_data_refcount);

	return NT_STATUS_OK;
}

static void share_mode_wakeup_waiters_fn(TDB_DATA value,
					 bool *modified_dependent,
					 void *private_data)
{
	*modified_dependent = true;
}

NTSTATUS share_mode_wakeup_waiters(struct file_id id)
{
	return share_mode_do_locked(id, share_mode_wakeup_waiters_fn, NULL);
}

bool share_mode_have_entries(struct share_mode_lock *lck)
{
	return lck->data->have_share_modes;
}

struct share_mode_watch_state {
	struct tevent_context *ev;
	bool blockerdead;
	struct server_id blocker;
	struct tevent_req *subreq;
};

static void share_mode_watch_fn(
	TDB_DATA value, bool *modified_dependent, void *private_data)
{
	struct share_mode_watch_state *state = talloc_get_type_abort(
		private_data, struct share_mode_watch_state);

	state->subreq = dbwrap_watched_watch_send(
		state, state->ev, static_share_mode_record, state->blocker);
}

static void share_mode_watch_done(struct tevent_req *subreq);

struct tevent_req *share_mode_watch_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct file_id id,
	struct server_id blocker)
{
	struct tevent_req *req = NULL;
	struct share_mode_watch_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(
		mem_ctx, &state, struct share_mode_watch_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->blocker = blocker;

	status = share_mode_do_locked(id, share_mode_watch_fn, state);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}
	if (tevent_req_nomem(state->subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(state->subreq, share_mode_watch_done, req);
	return req;
}

static void share_mode_watch_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct share_mode_watch_state *state = tevent_req_data(
		req, struct share_mode_watch_state);
	NTSTATUS status;

	status = dbwrap_watched_watch_recv(
		subreq, &state->blockerdead, &state->blocker);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS share_mode_watch_recv(
	struct tevent_req *req, bool *blockerdead, struct server_id *blocker)
{
	struct share_mode_watch_state *state = tevent_req_data(
		req, struct share_mode_watch_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (blockerdead != NULL) {
		*blockerdead = state->blockerdead;
	}
	if (blocker != NULL) {
		*blocker = state->blocker;
	}
	return NT_STATUS_OK;
}

struct fetch_share_mode_unlocked_state {
	TALLOC_CTX *mem_ctx;
	struct share_mode_lock *lck;
};

static void fetch_share_mode_unlocked_parser(
	TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct fetch_share_mode_unlocked_state *state = private_data;

	if (data.dsize == 0) {
		/* Likely a ctdb tombstone record, ignore it */
		return;
	}

	state->lck = talloc(state->mem_ctx, struct share_mode_lock);
	if (state->lck == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return;
	}

	state->lck->data = parse_share_modes(state->lck, key, data);
}

/*******************************************************************
 Get a share_mode_lock without locking the database or reference
 counting. Used by smbstatus to display existing share modes.
********************************************************************/

struct share_mode_lock *fetch_share_mode_unlocked(TALLOC_CTX *mem_ctx,
						  struct file_id id)
{
	struct fetch_share_mode_unlocked_state state = { .mem_ctx = mem_ctx };
	TDB_DATA key = locking_key(&id);
	NTSTATUS status;

	status = dbwrap_parse_record(
		lock_db, key, fetch_share_mode_unlocked_parser, &state);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}
	return state.lck;
}

static void fetch_share_mode_done(struct tevent_req *subreq);

struct fetch_share_mode_state {
	struct file_id id;
	TDB_DATA key;
	struct fetch_share_mode_unlocked_state parser_state;
	enum dbwrap_req_state req_state;
};

/**
 * @brief Get a share_mode_lock without locking or refcounting
 *
 * This can be used in a clustered Samba environment where the async dbwrap
 * request is sent over a socket to the local ctdbd. If the send queue is full
 * and the caller was issuing multiple async dbwrap requests in a loop, the
 * caller knows it's probably time to stop sending requests for now and try
 * again later.
 *
 * @param[in]  mem_ctx The talloc memory context to use.
 *
 * @param[in]  ev      The event context to work on.
 *
 * @param[in]  id      The file id for the locking.tdb key
 *
 * @param[out] queued  This boolean out parameter tells the caller whether the
 *                     async request is blocked in a full send queue:
 *
 *                     false := request is dispatched
 *
 *                     true  := send queue is full, request waiting to be
 *                              dispatched
 *
 * @return             The new async request, NULL on error.
 **/
struct tevent_req *fetch_share_mode_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct file_id id,
					 bool *queued)
{
	struct tevent_req *req = NULL;
	struct fetch_share_mode_state *state = NULL;
	struct tevent_req *subreq = NULL;

	*queued = false;

	req = tevent_req_create(mem_ctx, &state,
				struct fetch_share_mode_state);
	if (req == NULL) {
		return NULL;
	}

	state->id = id;
	state->key = locking_key(&state->id);
	state->parser_state.mem_ctx = state;

	subreq = dbwrap_parse_record_send(state,
					  ev,
					  lock_db,
					  state->key,
					  fetch_share_mode_unlocked_parser,
					  &state->parser_state,
					  &state->req_state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, fetch_share_mode_done, req);

	if (state->req_state < DBWRAP_REQ_DISPATCHED) {
		*queued = true;
	}
	return req;
}

static void fetch_share_mode_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = dbwrap_parse_record_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
	return;
}

NTSTATUS fetch_share_mode_recv(struct tevent_req *req,
			       TALLOC_CTX *mem_ctx,
			       struct share_mode_lock **_lck)
{
	struct fetch_share_mode_state *state = tevent_req_data(
		req, struct fetch_share_mode_state);
	struct share_mode_lock *lck = NULL;

	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	if (state->parser_state.lck->data == NULL) {
		tevent_req_received(req);
		return NT_STATUS_NOT_FOUND;
	}

	lck = talloc_move(mem_ctx, &state->parser_state.lck);

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("share_mode_data:\n");
		NDR_PRINT_DEBUG(share_mode_data, lck->data);
	}

	*_lck = lck;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct share_mode_forall_state {
	int (*fn)(struct file_id fid, const struct share_mode_data *data,
		  void *private_data);
	void *private_data;
};

static int share_mode_traverse_fn(struct db_record *rec, void *_state)
{
	struct share_mode_forall_state *state =
		(struct share_mode_forall_state *)_state;
	TDB_DATA key;
	TDB_DATA value;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	struct share_mode_data *d;
	struct file_id fid;
	int ret;

	key = dbwrap_record_get_key(rec);
	value = dbwrap_record_get_value(rec);

	/* Ensure this is a locking_key record. */
	if (key.dsize != sizeof(fid)) {
		return 0;
	}
	memcpy(&fid, key.dptr, sizeof(fid));

	d = talloc(talloc_tos(), struct share_mode_data);
	if (d == NULL) {
		return 0;
	}

	blob.data = value.dptr;
	blob.length = value.dsize;

	ndr_err = ndr_pull_struct_blob_all(
		&blob, d, d, (ndr_pull_flags_fn_t)ndr_pull_share_mode_data);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1, ("ndr_pull_share_mode_lock failed\n"));
		return 0;
	}

	if (DEBUGLEVEL > 10) {
		DEBUG(11, ("parse_share_modes:\n"));
		NDR_PRINT_DEBUG(share_mode_data, d);
	}

	ret = state->fn(fid, d, state->private_data);

	TALLOC_FREE(d);
	return ret;
}

int share_mode_forall(int (*fn)(struct file_id fid,
				const struct share_mode_data *data,
				void *private_data),
		      void *private_data)
{
	struct share_mode_forall_state state = {
		.fn = fn,
		.private_data = private_data
	};
	NTSTATUS status;
	int count;

	if (lock_db == NULL) {
		return 0;
	}

	status = dbwrap_traverse_read(lock_db, share_mode_traverse_fn,
				      &state, &count);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}

	return count;
}

struct share_entry_forall_state {
	struct file_id fid;
	const struct share_mode_data *data;
	int (*fn)(struct file_id fid,
		  const struct share_mode_data *data,
		  const struct share_mode_entry *entry,
		  void *private_data);
	void *private_data;
	int ret;
};

static bool share_entry_traverse_walker(
	struct share_mode_entry *e,
	bool *modified,
	void *private_data)
{
	struct share_entry_forall_state *state = private_data;

	state->ret = state->fn(
		state->fid, state->data, e, state->private_data);
	return (state->ret != 0);
}

static int share_entry_traverse_fn(struct file_id fid,
				   const struct share_mode_data *data,
				   void *private_data)
{
	struct share_entry_forall_state *state = private_data;
	struct share_mode_lock lck = {
		.data = discard_const_p(struct share_mode_data, data)
	};
	bool ok;

	state->fid = fid;
	state->data = data;

	ok = share_mode_forall_entries(
		&lck, share_entry_traverse_walker, state);
	if (!ok) {
		DBG_DEBUG("share_mode_forall_entries failed\n");
		return false;
	}

	return state->ret;
}

/*******************************************************************
 Call the specified function on each entry under management by the
 share mode system.
********************************************************************/

int share_entry_forall(int (*fn)(struct file_id fid,
				 const struct share_mode_data *data,
				 const struct share_mode_entry *entry,
				 void *private_data),
		      void *private_data)
{
	struct share_entry_forall_state state = {
		.fn = fn, .private_data = private_data };

	return share_mode_forall(share_entry_traverse_fn, &state);
}

struct cleanup_disconnected_state {
	struct share_mode_lock *lck;
	uint64_t open_persistent_id;
	size_t num_disconnected;
	bool found_connected;
};

static bool cleanup_disconnected_lease(struct share_mode_entry *e,
				       void *private_data)
{
	struct cleanup_disconnected_state *state = private_data;
	NTSTATUS status;

	status = leases_db_del(
		&e->client_guid, &e->lease_key, &state->lck->data->id);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("leases_db_del failed: %s\n",
			  nt_errstr(status));
	}

	return false;
}

static bool share_mode_find_connected_fn(
	struct share_mode_entry *e,
	bool *modified,
	void *private_data)
{
	struct cleanup_disconnected_state *state = private_data;
	struct share_mode_data *d = state->lck->data;
	bool disconnected;

	disconnected = server_id_is_disconnected(&e->pid);
	if (!disconnected) {
		struct file_id_buf tmp1;
		struct server_id_buf tmp2;
		DBG_INFO("file (file-id='%s', servicepath='%s', "
			 "base_name='%s%s%s') "
			 "is used by server %s ==> do not cleanup\n",
			 file_id_str_buf(d->id, &tmp1),
			 d->servicepath,
			 d->base_name,
			 (d->stream_name == NULL)
			 ? "" : "', stream_name='",
			 (d->stream_name == NULL)
			 ? "" : d->stream_name,
			 server_id_str_buf(e->pid, &tmp2));
		state->found_connected = true;
		return true;
	}

	if (state->open_persistent_id != e->share_file_id) {
		struct file_id_buf tmp;
		DBG_INFO("entry for file "
			 "(file-id='%s', servicepath='%s', "
			 "base_name='%s%s%s') "
			 "has share_file_id %"PRIu64" but expected "
			 "%"PRIu64"==> do not cleanup\n",
			 file_id_str_buf(d->id, &tmp),
			 d->servicepath,
			 d->base_name,
			 (d->stream_name == NULL)
			 ? "" : "', stream_name='",
			 (d->stream_name == NULL)
			 ? "" : d->stream_name,
			 e->share_file_id,
			 state->open_persistent_id);
		state->found_connected = true;
		return true;
	}

	state->num_disconnected += 1;

	return false;
}

bool share_mode_cleanup_disconnected(struct file_id fid,
				     uint64_t open_persistent_id)
{
	struct cleanup_disconnected_state state = {
		.open_persistent_id = open_persistent_id
	};
	struct share_mode_data *data;
	bool ret = false;
	TALLOC_CTX *frame = talloc_stackframe();
	struct file_id_buf idbuf;
	NTSTATUS status;
	bool ok;

	state.lck = get_existing_share_mode_lock(frame, fid);
	if (state.lck == NULL) {
		DBG_INFO("Could not fetch share mode entry for %s\n",
			 file_id_str_buf(fid, &idbuf));
		goto done;
	}
	data = state.lck->data;

	ok = share_mode_forall_entries(
		state.lck, share_mode_find_connected_fn, &state);
	if (!ok) {
		DBG_DEBUG("share_mode_forall_entries failed\n");
		goto done;
	}
	if (state.found_connected) {
		DBG_DEBUG("Found connected entry\n");
		goto done;
	}

	ok = share_mode_forall_leases(
		state.lck, cleanup_disconnected_lease, &state);
	if (!ok) {
		DBG_DEBUG("failed to clean up leases associated "
			  "with file (file-id='%s', servicepath='%s', "
			  "base_name='%s%s%s') and open_persistent_id %"PRIu64" "
			  "==> do not cleanup\n",
			  file_id_str_buf(fid, &idbuf),
			  data->servicepath,
			  data->base_name,
			  (data->stream_name == NULL)
			  ? "" : "', stream_name='",
			  (data->stream_name == NULL)
			  ? "" : data->stream_name,
			  open_persistent_id);
	}

	ok = brl_cleanup_disconnected(fid, open_persistent_id);
	if (!ok) {
		DBG_DEBUG("failed to clean up byte range locks associated "
			  "with file (file-id='%s', servicepath='%s', "
			  "base_name='%s%s%s') and open_persistent_id %"PRIu64" "
			  "==> do not cleanup\n",
			  file_id_str_buf(fid, &idbuf),
			  data->servicepath,
			  data->base_name,
			  (data->stream_name == NULL)
			  ? "" : "', stream_name='",
			  (data->stream_name == NULL)
			  ? "" : data->stream_name,
			  open_persistent_id);
		goto done;
	}

	DBG_DEBUG("cleaning up %zu entries for file "
		  "(file-id='%s', servicepath='%s', "
		  "base_name='%s%s%s') "
		  "from open_persistent_id %"PRIu64"\n",
		  state.num_disconnected,
		  file_id_str_buf(fid, &idbuf),
		  data->servicepath,
		  data->base_name,
		  (data->stream_name == NULL)
		  ? "" : "', stream_name='",
		  (data->stream_name == NULL)
		  ? "" : data->stream_name,
		  open_persistent_id);

	/*
	 * No connected share entries left, wipe them all
	 */
	status = dbwrap_delete(share_entries_db, locking_key(&fid));
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dbwrap_delete failed: %s\n",
			  nt_errstr(status));
		goto done;
	}

	data->have_share_modes = false;
	data->modified = true;

	ret = true;
done:
	talloc_free(frame);
	return ret;
}

static int share_mode_entry_cmp(
	struct server_id pid1,
	uint64_t share_file_id1,
	struct server_id pid2,
	uint64_t share_file_id2)
{
	int cmp;

	cmp = server_id_cmp(&pid1, &pid2);
	if (cmp != 0) {
		return cmp;
	}
	if (share_file_id1 != share_file_id2) {
		return (share_file_id1 < share_file_id2) ? -1 : 1;
	}
	return 0;
}

/*
 * 132 is the sizeof an ndr-encoded struct share_mode_entry_buf.
 * Reading/writing entries will immediately error out if this
 * size differs (push/pull is done without allocs).
 */

struct share_mode_entry_buf {
	uint8_t buf[132];
};
#define SHARE_MODE_ENTRY_SIZE (sizeof(struct share_mode_entry_buf))

static bool share_mode_entry_put(
	const struct share_mode_entry *e,
	struct share_mode_entry_buf *dst)
{
	DATA_BLOB blob = { .data = dst->buf, .length = sizeof(dst->buf) };
	enum ndr_err_code ndr_err;

	if (DEBUGLEVEL>=10) {
		DBG_DEBUG("share_mode_entry:\n");
		NDR_PRINT_DEBUG(share_mode_entry, discard_const_p(void, e));
	}

	ndr_err = ndr_push_struct_into_fixed_blob(
		&blob,
		e,
		(ndr_push_flags_fn_t)ndr_push_share_mode_entry);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("ndr_push_share_mode_entry failed: %s\n",
			    ndr_errstr(ndr_err));
		return false;
	}

	return true;
}

static bool share_mode_entry_get(
	DATA_BLOB blob, struct share_mode_entry *e)
{
	enum ndr_err_code ndr_err = NDR_ERR_SUCCESS;

	ndr_err = ndr_pull_struct_blob_all_noalloc(
		&blob, e, (ndr_pull_flags_fn_t)ndr_pull_share_mode_entry);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("ndr_pull_share_mode_entry failed\n");
		return false;
	}
	return true;
}

static size_t share_mode_entry_find(
	uint8_t *data,
	size_t num_share_modes,
	struct server_id pid,
	uint64_t share_file_id,
	struct share_mode_entry *e,
	bool *match)
{
	ssize_t left, right, middle;

	if (num_share_modes == 0) {
		*match = false;
		return 0;
	}

	left = 0;
	right = (num_share_modes-1);

	while (left <= right) {
		DATA_BLOB blob;
		int cmp;
		bool ok;

		middle = left + ((right - left) / 2);

		DBG_DEBUG("left=%zu, right=%zu, middle=%zu\n",
			  left,
			  right,
			  middle);

		blob = (DATA_BLOB) {
			.data = data + middle * SHARE_MODE_ENTRY_SIZE,
			.length = SHARE_MODE_ENTRY_SIZE,
		};

		DBG_DEBUG("blob.data=%p, blob.length=%zu\n",
			  blob.data,
			  blob.length);

		ok = share_mode_entry_get(blob, e);
		if (!ok) {
			DBG_DEBUG("share_mode_entry_get failed\n");
			return false;
		}

		cmp = share_mode_entry_cmp(
			e->pid, e->share_file_id, pid, share_file_id);
		if (cmp == 0) {
			*match = true;
			return middle;
		}

		if (cmp < 0) {
			right = middle-1;
		} else {
			left = middle+1;
		}
	}

	*match = false;
	return left;
}

struct set_share_mode_state {
	struct share_mode_entry e;
	bool created_share_mode_record;
	NTSTATUS status;
};

static void set_share_mode_fn(
	struct db_record *rec,
	TDB_DATA data,
	void *private_data)
{
	struct set_share_mode_state *state = private_data;
	size_t idx, num_share_modes;
	struct share_mode_entry tmp;
	struct share_mode_entry_buf buf;
	bool ok, found;

	TDB_DATA dbufs[3];
	size_t num_dbufs = 0;

	if ((data.dsize % SHARE_MODE_ENTRY_SIZE) != 0) {
		DBG_WARNING("Got invalid record size %zu\n", data.dsize);
		state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		return;
	}
	num_share_modes = data.dsize / SHARE_MODE_ENTRY_SIZE;

	ok = share_mode_entry_put(&state->e, &buf);
	if (!ok) {
		DBG_DEBUG("share_mode_entry_put failed\n");
		state->status = NT_STATUS_INTERNAL_ERROR;
		return;
	}

	DBG_DEBUG("num_share_modes=%zu\n", num_share_modes);

	idx = share_mode_entry_find(
		data.dptr,
		num_share_modes,
		state->e.pid,
		state->e.share_file_id,
		&tmp,
		&found);
	if (found) {
		DBG_WARNING("Found duplicate share mode\n");
		state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		return;
	}

	DBG_DEBUG("idx=%zu, found=%d\n", idx, (int)found);

	if (idx > 0) {
		dbufs[num_dbufs] = (TDB_DATA) {
			.dptr = data.dptr,
			.dsize = idx * SHARE_MODE_ENTRY_SIZE,
		};
		num_dbufs += 1;
	}

	dbufs[num_dbufs] = (TDB_DATA) {
		.dptr = buf.buf, .dsize = SHARE_MODE_ENTRY_SIZE,
	};
	num_dbufs += 1;

	if (idx < num_share_modes) {
		dbufs[num_dbufs] = (TDB_DATA) {
			.dptr = data.dptr + idx * SHARE_MODE_ENTRY_SIZE,
			.dsize = (num_share_modes-idx) * SHARE_MODE_ENTRY_SIZE,
		};
		num_dbufs += 1;
	}

	{
		size_t i;
		for (i=0; i<num_dbufs; i++) {
			DBG_DEBUG("dbufs[%zu]=(%p, %zu)\n",
				  i,
				  dbufs[i].dptr,
				  dbufs[i].dsize);
		}
	}

	state->created_share_mode_record = (num_share_modes == 0);
	state->status = dbwrap_record_storev(rec, dbufs, num_dbufs, 0);
}

bool set_share_mode(struct share_mode_lock *lck,
		    struct files_struct *fsp,
		    uid_t uid,
		    uint64_t mid,
		    uint16_t op_type,
		    uint32_t share_access,
		    uint32_t access_mask)
{
	struct share_mode_data *d = lck->data;
	struct set_share_mode_state state = {
		.status = NT_STATUS_OK,
		.e.pid = messaging_server_id(fsp->conn->sconn->msg_ctx),
		.e.share_access = share_access,
		.e.private_options = fsp->fh->private_options,
		.e.access_mask = access_mask,
		.e.op_mid = mid,
		.e.op_type = op_type,
		.e.time.tv_sec = fsp->open_time.tv_sec,
		.e.time.tv_usec = fsp->open_time.tv_usec,
		.e.share_file_id = fsp->fh->gen_id,
		.e.uid = (uint32_t)uid,
		.e.flags = (fsp->posix_flags & FSP_POSIX_FLAGS_OPEN) ?
		SHARE_MODE_FLAG_POSIX_OPEN : 0,
		.e.name_hash = fsp->name_hash,
	};
	NTSTATUS status;

	if (op_type == LEASE_OPLOCK) {
		const struct GUID *client_guid = fsp_client_guid(fsp);
		state.e.client_guid = *client_guid;
		state.e.lease_key = fsp->lease->lease.lease_key;
	}

	status = dbwrap_do_locked(
		share_entries_db,
		locking_key(&d->id),
		set_share_mode_fn,
		&state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("dbwrap_do_locked failed: %s\n",
			    nt_errstr(status));
		return false;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_WARNING("set_share_mode_fn failed: %s\n",
			    nt_errstr(state.status));
		return false;
	}

	if (state.created_share_mode_record) {
		d->have_share_modes = true;
		d->modified = true;
	}

	return true;
}

struct share_mode_forall_entries_state {
	struct share_mode_lock *lck;
	bool (*fn)(struct share_mode_entry *e,
		   bool *modified,
		   void *private_data);
	void *private_data;
	bool ok;
};

static bool share_mode_for_one_entry(
	struct share_mode_forall_entries_state *state,
	size_t *i,
	size_t *num_share_modes,
	TDB_DATA data,
	bool *writeback)
{
	DATA_BLOB blob = {
		.data = data.dptr + (*i) * SHARE_MODE_ENTRY_SIZE,
		.length = SHARE_MODE_ENTRY_SIZE,
	};
	struct share_mode_entry e = {.pid.pid=0};
	enum ndr_err_code ndr_err = NDR_ERR_SUCCESS;
	bool modified = false;
	bool stop = false;
	struct server_id e_pid;
	uint64_t e_share_file_id;

	ndr_err = ndr_pull_struct_blob_all_noalloc(
		&blob,
		&e,
		(ndr_pull_flags_fn_t)ndr_pull_share_mode_entry);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("ndr_pull_share_mode_entry failed\n");
		*i += 1;
		return false;
	}
	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("entry[%zu]:\n", *i);
		NDR_PRINT_DEBUG(share_mode_entry, &e);
	}

	e_pid = e.pid;
	e_share_file_id = e.share_file_id;

	stop = state->fn(&e, &modified, state->private_data);

	DBG_DEBUG("entry[%zu]: modified=%d, e.stale=%d\n",
		  *i,
		  (int)modified,
		  (int)e.stale);

	if (modified) {
		if (DEBUGLEVEL>=10) {
			DBG_DEBUG("share_mode_entry:\n");
			NDR_PRINT_DEBUG(share_mode_entry, &e);
		}

		/*
		 * Make sure sorting order is kept intact
		 */
		SMB_ASSERT(server_id_equal(&e_pid, &e.pid));
		SMB_ASSERT(e_share_file_id == e.share_file_id);

		ndr_err = ndr_push_struct_into_fixed_blob(
			&blob,
			&e,
			(ndr_push_flags_fn_t)
			ndr_push_share_mode_entry);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DBG_WARNING("ndr_push_share_mode_entry "
				    "failed: %s\n",
				    ndr_errstr(ndr_err));
			/*
			 * Not much we can do, just ignore it
			 */
		}
		*i += 1;
		*writeback = true;
		return stop;
	}

	if (e.stale) {
		if (*i < *num_share_modes) {
			memmove(blob.data,
				blob.data + SHARE_MODE_ENTRY_SIZE,
				(*num_share_modes - *i - 1) *
				SHARE_MODE_ENTRY_SIZE);
		}
		*num_share_modes -= 1;
		*writeback = true;
		return stop;
	}

	if (stop) {
		return true;
	}

	*i += 1;
	return false;
}

static void share_mode_forall_entries_fn(
	struct db_record *rec,
	TDB_DATA data,
	void *private_data)
{
	struct share_mode_forall_entries_state *state = private_data;
	struct share_mode_data *d = state->lck->data;
	size_t num_share_modes;
	bool writeback = false;
	NTSTATUS status;
	bool stop = false;
	size_t i;

	if ((data.dsize % SHARE_MODE_ENTRY_SIZE) != 0) {
		DBG_WARNING("Invalid data size %zu\n", data.dsize);
		return;
	}
	num_share_modes = data.dsize / SHARE_MODE_ENTRY_SIZE;

	DBG_DEBUG("num_share_modes=%zu\n", num_share_modes);

	i = 0;
	while (i<num_share_modes) {
		stop = share_mode_for_one_entry(
			state, &i, &num_share_modes, data, &writeback);
		if (stop) {
			break;
		}
	}

	DBG_DEBUG("num_share_modes=%zu, writeback=%d\n",
		  num_share_modes,
		  (int)writeback);

	if (!writeback) {
		state->ok = true;
		return;
	}

	if (num_share_modes == 0) {
		if (data.dsize != 0) {
			d->have_share_modes = false;
			d->modified = true;
		}
		status = dbwrap_record_delete(rec);
	} else {
		TDB_DATA value = {
			.dptr = data.dptr,
			.dsize = num_share_modes * SHARE_MODE_ENTRY_SIZE,
		};
		status = dbwrap_record_store(rec, value, 0);
	}

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Storing record with %zu entries failed: %s\n",
			  num_share_modes,
			  nt_errstr(status));
		return;
	}


	state->ok = true;
}

bool share_mode_forall_entries(
	struct share_mode_lock *lck,
	bool (*fn)(struct share_mode_entry *e,
		   bool *modified,
		   void *private_data),
	void *private_data)
{
	struct share_mode_forall_entries_state state = {
		.lck = lck,
		.fn = fn,
		.private_data = private_data,
	};
	NTSTATUS status;

	status = dbwrap_do_locked(
		share_entries_db,
		locking_key(&lck->data->id),
		share_mode_forall_entries_fn,
		&state);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		status = NT_STATUS_OK;
		state.ok = true;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dbwrap_do_locked failed: %s\n",
			  nt_errstr(status));
		return false;
	}

	return state.ok;
}

struct share_mode_count_entries_state {
	size_t num_share_modes;
	NTSTATUS status;
};

static void share_mode_count_entries_fn(
	TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct share_mode_count_entries_state *state = private_data;

	if ((data.dsize % SHARE_MODE_ENTRY_SIZE) != 0) {
		DBG_WARNING("Invalid data size %zu\n", data.dsize);
		state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		return;
	}
	state->num_share_modes = data.dsize / SHARE_MODE_ENTRY_SIZE;
	state->status = NT_STATUS_OK;
}

NTSTATUS share_mode_count_entries(struct file_id fid, size_t *num_share_modes)
{
	struct share_mode_count_entries_state state = {
		.status = NT_STATUS_NOT_FOUND,
	};
	NTSTATUS status;

	status = dbwrap_parse_record(
		share_entries_db,
		locking_key(&fid),
		share_mode_count_entries_fn,
		&state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dbwrap_parse_record failed: %s\n",
			  nt_errstr(status));
		return status;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_DEBUG("share_mode_forall_entries_fn failed: %s\n",
			  nt_errstr(state.status));
		return state.status;
	}

	*num_share_modes = state.num_share_modes;
	return NT_STATUS_OK;
}

struct share_mode_entry_do_state {
	struct server_id pid;
	uint64_t share_file_id;
	void (*fn)(struct share_mode_entry *e,
		   size_t num_share_modes,
		   bool *modified,
		   void *private_data);
	void *private_data;
	size_t num_share_modes;
	NTSTATUS status;
};

static void share_mode_entry_do_fn(
	struct db_record *rec,
	TDB_DATA data,
	void *private_data)
{
	struct share_mode_entry_do_state *state = private_data;
	size_t idx;
	bool found = false;
	bool modified;
	struct share_mode_entry e;
	struct share_mode_entry_buf buf;
	TDB_DATA dbufs[3];
	size_t num_dbufs = 0;

	if ((data.dsize % SHARE_MODE_ENTRY_SIZE) != 0) {
		DBG_WARNING("Invalid data size %zu\n", data.dsize);
		state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		return;
	}
	state->num_share_modes = data.dsize / SHARE_MODE_ENTRY_SIZE;

	DBG_DEBUG("state->num_share_modes=%zu\n", state->num_share_modes);

	idx = share_mode_entry_find(
		data.dptr,
		state->num_share_modes,
		state->pid,
		state->share_file_id,
		&e,
		&found);
	if (!found) {
		DBG_WARNING("Did not find share mode entry for %"PRIu64"\n",
			    state->share_file_id);
		state->status = NT_STATUS_NOT_FOUND;
		return;
	}

	state->fn(&e, state->num_share_modes, &modified, state->private_data);

	if (!e.stale && !modified) {
		state->status = NT_STATUS_OK;
		return;
	}

	if (idx > 0) {
		dbufs[num_dbufs] = (TDB_DATA) {
			.dptr = data.dptr,
			.dsize = idx * SHARE_MODE_ENTRY_SIZE,
		};
		num_dbufs += 1;
	}

	if (!e.stale) {
		bool ok = share_mode_entry_put(&e, &buf);
		if (!ok) {
			DBG_DEBUG("share_mode_entry_put failed\n");
			state->status = NT_STATUS_INTERNAL_ERROR;
			return;
		}

		dbufs[num_dbufs] = (TDB_DATA) {
			.dptr = buf.buf, .dsize = SHARE_MODE_ENTRY_SIZE,
		};
		num_dbufs += 1;
	}

	idx += 1;

	if (idx < state->num_share_modes) {
		size_t behind = state->num_share_modes - idx;
		dbufs[num_dbufs] = (TDB_DATA) {
			.dptr = data.dptr + idx * SHARE_MODE_ENTRY_SIZE,
			.dsize = behind * SHARE_MODE_ENTRY_SIZE,
		};
		num_dbufs += 1;
	}

	if (e.stale) {
		state->num_share_modes -= 1;
	}

	if (state->num_share_modes == 0) {
		state->status = dbwrap_record_delete(rec);
		if (!NT_STATUS_IS_OK(state->status)) {
			DBG_DEBUG("dbwrap_record_delete failed: %s\n",
				  nt_errstr(state->status));
		}
		return;
	}

	state->status = dbwrap_record_storev(rec, dbufs, num_dbufs, 0);
	if (!NT_STATUS_IS_OK(state->status)) {
		DBG_DEBUG("dbwrap_record_storev failed: %s\n",
			  nt_errstr(state->status));
		return;
	}
}

static bool share_mode_entry_do(
	struct share_mode_lock *lck,
	struct server_id pid,
	uint64_t share_file_id,
	void (*fn)(struct share_mode_entry *e,
		   size_t num_share_modes,
		   bool *modified,
		   void *private_data),
	void *private_data)
{
	struct share_mode_data *d = lck->data;
	struct share_mode_entry_do_state state = {
		.pid = pid,
		.share_file_id = share_file_id,
		.fn = fn,
		.private_data = private_data,
	};
	NTSTATUS status;
	bool have_share_modes;

	status = dbwrap_do_locked(
		share_entries_db,
		locking_key(&d->id),
		share_mode_entry_do_fn,
		&state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("share_mode_forall_entries failed: %s\n",
			  nt_errstr(status));
		return false;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_DEBUG("share_mode_entry_do_fn failed: %s\n",
			  nt_errstr(status));
		return false;
	}

	have_share_modes = (state.num_share_modes != 0);
	if (d->have_share_modes != have_share_modes) {
		d->have_share_modes = have_share_modes;
		d->modified = true;
	}

	return true;
}

struct del_share_mode_state {
	bool ok;
};

static void del_share_mode_fn(
	struct share_mode_entry *e,
	size_t num_share_modes,
	bool *modified,
	void *private_data)
{
	struct del_share_mode_state *state = private_data;
	e->stale = true;
	state->ok = true;
}

bool del_share_mode(struct share_mode_lock *lck, files_struct *fsp)
{
	struct del_share_mode_state state = { .ok = false };
	bool ok;

	ok = share_mode_entry_do(
		lck,
		messaging_server_id(fsp->conn->sconn->msg_ctx),
		fsp->fh->gen_id,
		del_share_mode_fn,
		&state);
	if (!ok) {
		DBG_DEBUG("share_mode_entry_do failed\n");
		return false;
	}
	if (!state.ok) {
		DBG_DEBUG("del_share_mode_fn failed\n");
		return false;
	}
	return true;
}

struct remove_share_oplock_state {
	bool ok;
};

static void remove_share_oplock_fn(
	struct share_mode_entry *e,
	size_t num_share_modes,
	bool *modified,
	void *private_data)
{
	struct remove_share_oplock_state *state = private_data;

	e->op_type = NO_OPLOCK;
	*modified = true;
	state->ok = true;
}

bool remove_share_oplock(struct share_mode_lock *lck, files_struct *fsp)
{
	struct remove_share_oplock_state state = { .ok = false };
	bool ok;

	ok = share_mode_entry_do(
		lck,
		messaging_server_id(fsp->conn->sconn->msg_ctx),
		fsp->fh->gen_id,
		remove_share_oplock_fn,
		&state);
	if (!ok) {
		DBG_DEBUG("share_mode_entry_do failed\n");
		return false;
	}
	if (!state.ok) {
		DBG_DEBUG("remove_share_oplock_fn failed\n");
		return false;
	}

	if (fsp->oplock_type == LEASE_OPLOCK) {
		remove_lease_if_stale(
			lck,
			fsp_client_guid(fsp),
			&fsp->lease->lease.lease_key);
	}

	share_mode_wakeup_waiters(fsp->file_id);

	return true;
}

struct downgrade_share_oplock_state {
	bool ok;
};

static void downgrade_share_oplock_fn(
	struct share_mode_entry *e,
	size_t num_share_modes,
	bool *modified,
	void *private_data)
{
	struct downgrade_share_oplock_state *state = private_data;

	e->op_type = LEVEL_II_OPLOCK;
	*modified = true;
	state->ok = true;
}

bool downgrade_share_oplock(struct share_mode_lock *lck, files_struct *fsp)
{
	struct downgrade_share_oplock_state state = { .ok = false };
	bool ok;

	ok = share_mode_entry_do(
		lck,
		messaging_server_id(fsp->conn->sconn->msg_ctx),
		fsp->fh->gen_id,
		downgrade_share_oplock_fn,
		&state);
	if (!ok) {
		DBG_DEBUG("share_mode_entry_do failed\n");
		return false;
	}
	if (!state.ok) {
		DBG_DEBUG("downgrade_share_oplock_fn failed\n");
		return false;
	}

	lck->data->flags |= SHARE_MODE_LEASE_READ;
	lck->data->modified = true;

	return true;
}

struct mark_share_mode_disconnected_state {
	uint64_t open_persistent_id;
	bool ok;
};

static void mark_share_mode_disconnected_fn(
	struct share_mode_entry *e,
	size_t num_share_modes,
	bool *modified,
	void *private_data)
{
	struct mark_share_mode_disconnected_state *state = private_data;

	if (num_share_modes != 1) {
		state->ok = false;
		return;
	}

	server_id_set_disconnected(&e->pid);
	e->share_file_id = state->open_persistent_id;
	*modified = true;
	state->ok = true;
}

bool mark_share_mode_disconnected(struct share_mode_lock *lck,
				  struct files_struct *fsp)
{
	struct mark_share_mode_disconnected_state state;
	bool ok;

	if (fsp->op == NULL) {
		return false;
	}
	if (!fsp->op->global->durable) {
		return false;
	}

	state = (struct mark_share_mode_disconnected_state) {
		.open_persistent_id = fsp->op->global->open_persistent_id,
	};

	ok = share_mode_entry_do(
		lck,
		messaging_server_id(fsp->conn->sconn->msg_ctx),
		fsp->fh->gen_id,
		mark_share_mode_disconnected_fn,
		&state);
	if (!ok) {
		DBG_DEBUG("share_mode_entry_do failed\n");
		return false;
	}
	if (!state.ok) {
		DBG_DEBUG("mark_share_mode_disconnected_fn failed\n");
		return false;
	}

	lck->data->modified = true;
	return true;
}

static void reset_share_mode_entry_del_fn(
	struct share_mode_entry *e,
	size_t num_share_modes,
	bool *modified,
	void *private_data)
{
	struct set_share_mode_state *state = private_data;

	state->e = *e;
	e->stale = true;
	state->status = NT_STATUS_OK;
}

bool reset_share_mode_entry(
	struct share_mode_lock *lck,
	struct server_id old_pid,
	uint64_t old_share_file_id,
	struct server_id new_pid,
	uint64_t new_mid,
	uint64_t new_share_file_id)
{
	struct share_mode_data *d = lck->data;
	struct set_share_mode_state state = {
		.status = NT_STATUS_INTERNAL_ERROR,
	};
	NTSTATUS status;
	bool ok;

	ok = share_mode_entry_do(
		lck,
		old_pid,
		old_share_file_id,
		reset_share_mode_entry_del_fn,
		&state);
	if (!ok) {
		DBG_DEBUG("share_mode_entry_do failed\n");
		return false;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_DEBUG("reset_share_mode_entry_del_fn failed: %s\n",
			  nt_errstr(state.status));
		return false;
	}

	state.status = NT_STATUS_INTERNAL_ERROR;
	state.e.pid = new_pid;
	state.e.op_mid = new_mid;
	state.e.share_file_id = new_share_file_id;

	status = dbwrap_do_locked(
		share_entries_db,
		locking_key(&d->id),
		set_share_mode_fn,
		&state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("dbwrap_do_locked failed: %s\n",
			    nt_errstr(status));
		return false;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_WARNING("set_share_mode_fn failed: %s\n",
			    nt_errstr(state.status));
		return false;
	}
	d->have_share_modes = true;

	return true;
}
