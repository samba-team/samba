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

static bool locking_init_internal(bool read_only)
{
	struct db_context *backend;
	char *db_path;

	brl_init(read_only);

	if (lock_db)
		return True;

	db_path = lock_path("locking.tdb");
	if (db_path == NULL) {
		return false;
	}

	backend = db_open(NULL, db_path,
			  SMB_OPEN_DATABASE_TDB_HASH_SIZE,
			  TDB_DEFAULT|TDB_VOLATILE|TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH,
			  read_only?O_RDONLY:O_RDWR|O_CREAT, 0644,
			  DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);
	TALLOC_FREE(db_path);
	if (!backend) {
		DEBUG(0,("ERROR: Failed to initialise locking database\n"));
		return False;
	}

	lock_db = db_open_watched(NULL, backend, server_messaging_context());
	if (lock_db == NULL) {
		DBG_ERR("db_open_watched failed\n");
		TALLOC_FREE(backend);
		return false;
	}

	if (!posix_locking_init(read_only)) {
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

static const DATA_BLOB memcache_key(const struct file_id *id)
{
	return data_blob_const((const void *)id, sizeof(*id));
}

static void share_mode_memcache_delete(struct share_mode_data *d)
{
	const DATA_BLOB key = memcache_key(&d->id);

	DEBUG(10,("deleting entry for file %s seq 0x%llu key %s\n",
		d->base_name,
		(unsigned long long) d->sequence_number,
		file_id_string(talloc_tos(), &d->id)));

	memcache_delete(NULL,
			SHARE_MODE_LOCK_CACHE,
			key);
}

static void share_mode_memcache_store(struct share_mode_data *d)
{
	const DATA_BLOB key = memcache_key(&d->id);

	DEBUG(10,("stored entry for file %s seq 0x%llu key %s\n",
		d->base_name,
		(unsigned long long) d->sequence_number,
		file_id_string(talloc_tos(), &d->id)));

	/* Ensure everything stored in the cache is pristine. */
	d->modified = false;
	d->fresh = false;

	/*
	 * Ensure the memory going into the cache
	 * doesn't have a destructor so it can be
	 * cleanly freed by share_mode_memcache_delete().
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
 * the first 8 bytes of the blob.
 */

static enum ndr_err_code get_blob_sequence_number(DATA_BLOB *blob,
						uint64_t *pseq)
{
	struct ndr_pull ndr = {.data = blob->data, .data_size = blob->length};
	NDR_CHECK(ndr_pull_hyper(&ndr, NDR_SCALARS, pseq));
	return NDR_ERR_SUCCESS;
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
	void *ptr;
	struct file_id id;
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
		DEBUG(10,("failed to find entry for key %s\n",
			file_id_string(mem_ctx, &id)));
		return NULL;
	}
	/* sequence number key is at start of blob. */
	ndr_err = get_blob_sequence_number(blob, &sequence_number);
	if (ndr_err != NDR_ERR_SUCCESS) {
		/* Bad blob. Remove entry. */
		DEBUG(10,("bad blob %u key %s\n",
			(unsigned int)ndr_err,
			file_id_string(mem_ctx, &id)));
		memcache_delete(NULL,
			SHARE_MODE_LOCK_CACHE,
			key);
		return NULL;
	}

	d = (struct share_mode_data *)ptr;
	if (d->sequence_number != sequence_number) {
		DEBUG(10,("seq changed (cached 0x%llu) (new 0x%llu) "
			"for key %s\n",
			(unsigned long long)d->sequence_number,
			(unsigned long long)sequence_number,
			file_id_string(mem_ctx, &id)));
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

	DEBUG(10,("fetched entry for file %s seq 0x%llu key %s\n",
		d->base_name,
		(unsigned long long)d->sequence_number,
		file_id_string(mem_ctx, &id)));

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
	uint32_t i;
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
		DEBUG(1, ("ndr_pull_share_mode_lock failed: %s\n",
			  ndr_errstr(ndr_err)));
		goto fail;
	}

	/*
	 * Initialize the values that are [skip] or [ignore]
	 * in the idl. The NDR code does not initialize them.
	 */

	for (i=0; i<d->num_share_modes; i++) {
		struct share_mode_entry *e = &d->share_modes[i];

		e->stale = false;
		e->lease = NULL;
		if (e->op_type != LEASE_OPLOCK) {
			continue;
		}
		if (e->lease_idx >= d->num_leases) {
			continue;
		}
		e->lease = &d->leases[e->lease_idx];
	}
	d->modified = false;
	d->fresh = false;

	if (DEBUGLEVEL >= 10) {
		DEBUG(10, ("parse_share_modes:\n"));
		NDR_PRINT_DEBUG(share_mode_data, d);
	}

	return d;
fail:
	TALLOC_FREE(d);
	return NULL;
}

/*******************************************************************
 Create a storable data blob from a modified share_mode_data struct.
********************************************************************/

static TDB_DATA unparse_share_modes(struct share_mode_data *d)
{
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;

	if (DEBUGLEVEL >= 10) {
		DEBUG(10, ("unparse_share_modes:\n"));
		NDR_PRINT_DEBUG(share_mode_data, d);
	}

	share_mode_memcache_delete(d);

	/* Update the sequence number. */
	d->sequence_number += 1;

	remove_stale_share_mode_entries(d);

	if (d->num_share_modes == 0) {
		DEBUG(10, ("No used share mode found\n"));
		return make_tdb_data(NULL, 0);
	}

	ndr_err = ndr_push_struct_blob(
		&blob, d, d, (ndr_push_flags_fn_t)ndr_push_share_mode_data);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		smb_panic("ndr_push_share_mode_lock failed");
	}

	return make_tdb_data(blob.data, blob.length);
}

/*******************************************************************
 If modified, store the share_mode_data back into the database.
********************************************************************/

static int share_mode_data_destructor(struct share_mode_data *d)
{
	NTSTATUS status;
	TDB_DATA data;

	if (!d->modified) {
		return 0;
	}

	data = unparse_share_modes(d);

	if (data.dptr == NULL) {
		if (!d->fresh) {
			/* There has been an entry before, delete it */

			status = dbwrap_record_delete(d->record);
			if (!NT_STATUS_IS_OK(status)) {
				char *errmsg;

				DEBUG(0, ("delete_rec returned %s\n",
					  nt_errstr(status)));

				if (asprintf(&errmsg, "could not delete share "
					     "entry: %s\n",
					     nt_errstr(status)) == -1) {
					smb_panic("could not delete share"
						  "entry");
				}
				smb_panic(errmsg);
			}
		}
		/*
		 * Nothing to store in cache - allow the normal
		 * release of record lock and memory free.
		 */
		return 0;
	}

	status = dbwrap_record_store(d->record, data, TDB_REPLACE);
	if (!NT_STATUS_IS_OK(status)) {
		char *errmsg;

		DEBUG(0, ("store returned %s\n", nt_errstr(status)));

		if (asprintf(&errmsg, "could not store share mode entry: %s",
			     nt_errstr(status)) == -1) {
			smb_panic("could not store share mode entry");
		}
		smb_panic(errmsg);
	}

	/*
	 * Release the record lock before putting in the cache.
	 */
	TALLOC_FREE(d->record);

	/*
	 * Release the dptr as well before reparenting to NULL
	 * (in-memory cache) context.
	 */
	TALLOC_FREE(data.dptr);
	/*
	 * Reparent d into the in-memory cache so it can be reused if the
	 * sequence number matches. See parse_share_modes()
	 * for details.
	 */

	share_mode_memcache_store(d);
	return -1;
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
	d->old_write_time = *old_write_time;
	d->modified = false;
	d->fresh = true;
	return d;
fail:
	DEBUG(0, ("talloc failed\n"));
	TALLOC_FREE(d);
	return NULL;
}

/*******************************************************************
 Either fetch a share mode from the database, or allocate a fresh
 one if the record doesn't exist.
********************************************************************/

static struct share_mode_lock *get_share_mode_lock_internal(
	TALLOC_CTX *mem_ctx, struct file_id id,
	const char *servicepath, const struct smb_filename *smb_fname,
	const struct timespec *old_write_time)
{
	struct share_mode_lock *lck;
	struct share_mode_data *d;
	struct db_record *rec;
	TDB_DATA key = locking_key(&id);
	TDB_DATA value;

	rec = dbwrap_fetch_locked(lock_db, mem_ctx, key);
	if (rec == NULL) {
		DEBUG(3, ("Could not lock share entry\n"));
		return NULL;
	}

	value = dbwrap_record_get_value(rec);

	if (value.dptr == NULL) {
		d = fresh_share_mode_lock(mem_ctx, servicepath, smb_fname,
					  old_write_time);
	} else {
		d = parse_share_modes(mem_ctx, key, value);
	}

	if (d == NULL) {
		DEBUG(5, ("get_share_mode_lock_internal: "
			"Could not get share mode lock\n"));
		TALLOC_FREE(rec);
		return NULL;
	}
	d->id = id;
	d->record = talloc_move(d, &rec);
	talloc_set_destructor(d, share_mode_data_destructor);

	lck = talloc(mem_ctx, struct share_mode_lock);
	if (lck == NULL) {
		DEBUG(1, ("talloc failed\n"));
		TALLOC_FREE(d);
		return NULL;
	}
	lck->data = talloc_move(lck, &d);
	return lck;
}

/*
 * We can only ever have one share mode locked. Users of
 * get_share_mode_lock never see this, it will be refcounted by
 * talloc_reference.
 */
static struct share_mode_lock *the_lock;
static struct file_id the_lock_id;

static int the_lock_destructor(struct share_mode_lock *l)
{
	the_lock = NULL;
	ZERO_STRUCT(the_lock_id);
	return 0;
}

/*******************************************************************
 Get a share_mode_lock, Reference counted to allow nested calls.
********************************************************************/

struct share_mode_lock *get_share_mode_lock(
	TALLOC_CTX *mem_ctx,
	struct file_id id,
	const char *servicepath,
	const struct smb_filename *smb_fname,
	const struct timespec *old_write_time)
{
	struct share_mode_lock *lck;

	lck = talloc(mem_ctx, struct share_mode_lock);
	if (lck == NULL) {
		DEBUG(1, ("talloc failed\n"));
		return NULL;
	}

	if (the_lock == NULL) {
		the_lock = get_share_mode_lock_internal(
			lck, id, servicepath, smb_fname, old_write_time);
		if (the_lock == NULL) {
			goto fail;
		}
		talloc_set_destructor(the_lock, the_lock_destructor);
		the_lock_id = id;
	} else {
		if (!file_id_equal(&the_lock_id, &id)) {
			DEBUG(1, ("Can not lock two share modes "
				  "simultaneously\n"));
			goto fail;
		}
		if (talloc_reference(lck, the_lock) == NULL) {
			DEBUG(1, ("talloc_reference failed\n"));
			goto fail;
		}
	}
	lck->data = the_lock->data;
	return lck;
fail:
	TALLOC_FREE(lck);
	return NULL;
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
	struct share_mode_lock *lck;
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
	state->lck = talloc_zero(state, struct share_mode_lock);
	if (tevent_req_nomem(state->lck, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = dbwrap_parse_record_send(state,
					  ev,
					  lock_db,
					  state->key,
					  fetch_share_mode_unlocked_parser,
					  state->lck,
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

	if (state->lck->data == NULL) {
		tevent_req_received(req);
		return NT_STATUS_NOT_FOUND;
	}

	lck = talloc_move(mem_ctx, &state->lck);

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
	uint32_t i;
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

	for (i=0; i<d->num_share_modes; i++) {
		struct share_mode_entry *entry = &d->share_modes[i];
		entry->stale = false; /* [skip] in idl */
		entry->lease = &d->leases[entry->lease_idx];
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
	int (*fn)(const struct share_mode_entry *e,
		  const char *service_path,
		  const char *base_name,
		  const char *stream_name,
		  void *private_data);
	void *private_data;
};

static int share_entry_traverse_fn(struct file_id fid,
				   const struct share_mode_data *data,
				   void *private_data)
{
	struct share_entry_forall_state *state = private_data;
	uint32_t i;

	for (i=0; i<data->num_share_modes; i++) {
		int ret;

		ret = state->fn(&data->share_modes[i],
				data->servicepath,
				data->base_name,
				data->stream_name,
				state->private_data);
		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

/*******************************************************************
 Call the specified function on each entry under management by the
 share mode system.
********************************************************************/

int share_entry_forall(int (*fn)(const struct share_mode_entry *,
				 const char *, const char *,
				 const char *, void *),
		       void *private_data)
{
	struct share_entry_forall_state state = {
		.fn = fn, .private_data = private_data };

	return share_mode_forall(share_entry_traverse_fn, &state);
}

bool share_mode_cleanup_disconnected(struct file_id fid,
				     uint64_t open_persistent_id)
{
	bool ret = false;
	TALLOC_CTX *frame = talloc_stackframe();
	unsigned n;
	struct share_mode_data *data;
	struct share_mode_lock *lck;
	bool ok;

	lck = get_existing_share_mode_lock(frame, fid);
	if (lck == NULL) {
		DEBUG(5, ("share_mode_cleanup_disconnected: "
			  "Could not fetch share mode entry for %s\n",
			  file_id_string(frame, &fid)));
		goto done;
	}
	data = lck->data;

	for (n=0; n < data->num_share_modes; n++) {
		struct share_mode_entry *entry = &data->share_modes[n];

		if (!server_id_is_disconnected(&entry->pid)) {
			struct server_id_buf tmp;
			DEBUG(5, ("share_mode_cleanup_disconnected: "
				  "file (file-id='%s', servicepath='%s', "
				  "base_name='%s%s%s') "
				  "is used by server %s ==> do not cleanup\n",
				  file_id_string(frame, &fid),
				  data->servicepath,
				  data->base_name,
				  (data->stream_name == NULL)
				  ? "" : "', stream_name='",
				  (data->stream_name == NULL)
				  ? "" : data->stream_name,
				  server_id_str_buf(entry->pid, &tmp)));
			goto done;
		}
		if (open_persistent_id != entry->share_file_id) {
			DEBUG(5, ("share_mode_cleanup_disconnected: "
				  "entry for file "
				  "(file-id='%s', servicepath='%s', "
				  "base_name='%s%s%s') "
				  "has share_file_id %llu but expected %llu"
				  "==> do not cleanup\n",
				  file_id_string(frame, &fid),
				  data->servicepath,
				  data->base_name,
				  (data->stream_name == NULL)
				  ? "" : "', stream_name='",
				  (data->stream_name == NULL)
				  ? "" : data->stream_name,
				  (unsigned long long)entry->share_file_id,
				  (unsigned long long)open_persistent_id));
			goto done;
		}
	}

	for (n=0; n < data->num_leases; n++) {
		struct share_mode_lease *l = &data->leases[n];
		NTSTATUS status;

		status = leases_db_del(&l->client_guid, &l->lease_key, &fid);

		DEBUG(10, ("%s: leases_db_del returned %s\n", __func__,
			   nt_errstr(status)));
	}

	ok = brl_cleanup_disconnected(fid, open_persistent_id);
	if (!ok) {
		DEBUG(10, ("share_mode_cleanup_disconnected: "
			   "failed to clean up byte range locks associated "
			   "with file (file-id='%s', servicepath='%s', "
			   "base_name='%s%s%s') and open_persistent_id %llu "
			   "==> do not cleanup\n",
			   file_id_string(frame, &fid),
			   data->servicepath,
			   data->base_name,
			   (data->stream_name == NULL)
			   ? "" : "', stream_name='",
			   (data->stream_name == NULL)
			   ? "" : data->stream_name,
			   (unsigned long long)open_persistent_id));
		goto done;
	}

	DEBUG(10, ("share_mode_cleanup_disconnected: "
		   "cleaning up %u entries for file "
		   "(file-id='%s', servicepath='%s', "
		   "base_name='%s%s%s') "
		   "from open_persistent_id %llu\n",
		   data->num_share_modes,
		   file_id_string(frame, &fid),
		   data->servicepath,
		   data->base_name,
		   (data->stream_name == NULL)
		   ? "" : "', stream_name='",
		   (data->stream_name == NULL)
		   ? "" : data->stream_name,
		   (unsigned long long)open_persistent_id));

	data->num_share_modes = 0;
	data->num_leases = 0;
	data->modified = true;

	ret = true;
done:
	talloc_free(frame);
	return ret;
}
