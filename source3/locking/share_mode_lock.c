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
#include "dbwrap/dbwrap_private.h"
#include "../libcli/security/security.h"
#include "serverid.h"
#include "messages.h"
#include "util_tdb.h"
#include "../librpc/gen_ndr/ndr_open_files.h"
#include "source3/lib/dbwrap/dbwrap_watch.h"
#include "locking/leases_db.h"
#include "../lib/util/memcache.h"
#include "lib/util/tevent_ntstatus.h"
#include "g_lock.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

#define NO_LOCKING_COUNT (-1)

/* the locking database handle */
static struct g_lock_ctx *lock_ctx;

static bool locking_init_internal(bool read_only)
{
	struct db_context *backend;
	char *db_path;

	brl_init(read_only);

	if (lock_ctx != NULL) {
		return True;
	}

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
			  DBWRAP_LOCK_ORDER_NONE,
			  DBWRAP_FLAG_NONE);
	TALLOC_FREE(db_path);
	if (!backend) {
		DEBUG(0,("ERROR: Failed to initialise locking database\n"));
		return False;
	}

	lock_ctx = g_lock_ctx_init_backend(
		NULL, global_messaging_context(), &backend);
	if (lock_ctx == NULL) {
		TALLOC_FREE(backend);
		return false;
	}
	g_lock_set_lock_order(lock_ctx, DBWRAP_LOCK_ORDER_1);

	if (!posix_locking_init(read_only)) {
		TALLOC_FREE(lock_ctx);
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
	TALLOC_FREE(lock_ctx);
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

	DBG_DEBUG("stored entry for file %s epoch %"PRIx64" key %s\n",
		  d->base_name,
		  d->unique_content_epoch,
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
 * the first 10 bytes of the blob.
 */

static enum ndr_err_code get_share_mode_blob_header(
	const uint8_t *buf, size_t buflen, uint64_t *pepoch, uint16_t *pflags)
{
	struct ndr_pull ndr = {
		.data = discard_const_p(uint8_t, buf),
		.data_size = buflen,
	};
	NDR_CHECK(ndr_pull_hyper(&ndr, NDR_SCALARS, pepoch));
	NDR_CHECK(ndr_pull_uint16(&ndr, NDR_SCALARS, pflags));
	return NDR_ERR_SUCCESS;
}

struct fsp_update_share_mode_flags_state {
	enum ndr_err_code ndr_err;
	uint16_t share_mode_flags;
};

static void fsp_update_share_mode_flags_fn(
	const uint8_t *buf,
	size_t buflen,
	bool *modified_dependent,
	void *private_data)
{
	struct fsp_update_share_mode_flags_state *state = private_data;
	uint64_t seq;

	state->ndr_err = get_share_mode_blob_header(
		buf, buflen, &seq, &state->share_mode_flags);
}

static NTSTATUS fsp_update_share_mode_flags(struct files_struct *fsp)
{
	struct fsp_update_share_mode_flags_state state = {0};
	int seqnum = g_lock_seqnum(lock_ctx);
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

static struct share_mode_data *share_mode_memcache_fetch(
	TALLOC_CTX *mem_ctx,
	const TDB_DATA id_key,
	const uint8_t *buf,
	size_t buflen)
{
	enum ndr_err_code ndr_err;
	struct share_mode_data *d;
	uint64_t unique_content_epoch;
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
	ndr_err = get_share_mode_blob_header(
		buf, buflen, &unique_content_epoch, &flags);
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
	if (d->unique_content_epoch != unique_content_epoch) {
		DBG_DEBUG("epoch changed (cached %"PRIx64") (new %"PRIx64") "
			  "for key %s\n",
			  d->unique_content_epoch,
			  unique_content_epoch,
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

	DBG_DEBUG("fetched entry for file %s epoch %"PRIx64" key %s\n",
		  d->base_name,
		  d->unique_content_epoch,
		  file_id_str_buf(id, &idbuf));

	return d;
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
	const uint8_t ptr[SHARE_MODE_ENTRY_SIZE], struct share_mode_entry *e)
{
	enum ndr_err_code ndr_err = NDR_ERR_SUCCESS;
	DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, ptr),
		.length = SHARE_MODE_ENTRY_SIZE,
	};

	ndr_err = ndr_pull_struct_blob_all_noalloc(
		&blob, e, (ndr_pull_flags_fn_t)ndr_pull_share_mode_entry);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("ndr_pull_share_mode_entry failed\n");
		return false;
	}
	return true;
}

/*
 * locking.tdb records consist of
 *
 * uint32_t share_mode_data_len
 * uint8_t [share_mode_data]       This is struct share_mode_data in NDR
 *
 * 0 [SHARE_MODE_ENTRY_SIZE]       Sorted array of share modes,
 * 1 [SHARE_MODE_ENTRY_SIZE]       filling up the rest of the data in the
 * 2 [SHARE_MODE_ENTRY_SIZE]       g_lock.c maintained record in locking.tdb
 */

struct locking_tdb_data {
	const uint8_t *share_mode_data_buf;
	size_t share_mode_data_len;
	const uint8_t *share_entries;
	size_t num_share_entries;
};

static bool locking_tdb_data_get(
	struct locking_tdb_data *data, const uint8_t *buf, size_t buflen)
{
	uint32_t share_mode_data_len, share_entries_len;

	if (buflen == 0) {
		*data = (struct locking_tdb_data) { 0 };
		return true;
	}
	if (buflen < sizeof(uint32_t)) {
		return false;
	}

	share_mode_data_len = PULL_LE_U32(buf, 0);

	buf += sizeof(uint32_t);
	buflen -= sizeof(uint32_t);

	if (buflen < share_mode_data_len) {
		return false;
	}

	share_entries_len = buflen - share_mode_data_len;

	if ((share_entries_len % SHARE_MODE_ENTRY_SIZE) != 0) {
		return false;
	}

	*data = (struct locking_tdb_data) {
		.share_mode_data_buf = buf,
		.share_mode_data_len = share_mode_data_len,
		.share_entries = buf + share_mode_data_len,
		.num_share_entries = share_entries_len / SHARE_MODE_ENTRY_SIZE,
	};

	return true;
}

struct locking_tdb_data_fetch_state {
	TALLOC_CTX *mem_ctx;
	uint8_t *data;
	size_t datalen;
};

static void locking_tdb_data_fetch_fn(
	struct server_id exclusive,
	size_t num_shared,
	struct server_id *shared,
	const uint8_t *data,
	size_t datalen,
	void *private_data)
{
	struct locking_tdb_data_fetch_state *state = private_data;
	state->datalen = datalen;
	state->data = talloc_memdup(state->mem_ctx, data, datalen);
}

static NTSTATUS locking_tdb_data_fetch(
	TDB_DATA key, TALLOC_CTX *mem_ctx, struct locking_tdb_data **ltdb)
{
	struct locking_tdb_data_fetch_state state = { 0 };
	struct locking_tdb_data *result = NULL;
	NTSTATUS status;
	bool ok;

	result = talloc_zero(mem_ctx, struct locking_tdb_data);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state.mem_ctx = result;

	status = g_lock_dump(lock_ctx, key, locking_tdb_data_fetch_fn, &state);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		/*
		 * Just return an empty record
		 */
		goto done;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("g_lock_dump failed: %s\n", nt_errstr(status));
		return status;
	}
	if (state.datalen == 0) {
		goto done;
	}

	ok = locking_tdb_data_get(result, state.data, state.datalen);
	if (!ok) {
		DBG_DEBUG("locking_tdb_data_get failed for %zu bytes\n",
			  state.datalen);
		TALLOC_FREE(result);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

done:
	*ltdb = result;
	return NT_STATUS_OK;
}

static NTSTATUS locking_tdb_data_store(
	TDB_DATA key,
	const struct locking_tdb_data *ltdb,
	const TDB_DATA *share_mode_dbufs,
	size_t num_share_mode_dbufs)
{
	uint8_t share_mode_data_len_buf[4];
	TDB_DATA dbufs[num_share_mode_dbufs+3];
	NTSTATUS status;

	if ((ltdb->share_mode_data_len == 0) &&
	    (ltdb->num_share_entries == 0) &&
	    (num_share_mode_dbufs == 0)) {
		/*
		 * Nothing to write
		 */
		status = g_lock_write_data(lock_ctx, key, NULL, 0);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("g_lock_writev_data() failed: %s\n",
				  nt_errstr(status));
		}
		return status;
	}

	PUSH_LE_U32(share_mode_data_len_buf, 0, ltdb->share_mode_data_len);

	dbufs[0] = (TDB_DATA) {
		.dptr = share_mode_data_len_buf,
		.dsize = sizeof(share_mode_data_len_buf),
	};
	dbufs[1] = (TDB_DATA) {
		.dptr = discard_const_p(uint8_t, ltdb->share_mode_data_buf),
		.dsize = ltdb->share_mode_data_len,
	};

	if (ltdb->num_share_entries > SIZE_MAX/SHARE_MODE_ENTRY_SIZE) {
		/* overflow */
		return NT_STATUS_BUFFER_OVERFLOW;
	}
	dbufs[2] = (TDB_DATA) {
		.dptr = discard_const_p(uint8_t, ltdb->share_entries),
		.dsize = ltdb->num_share_entries * SHARE_MODE_ENTRY_SIZE,
	};

	if (num_share_mode_dbufs != 0) {
		memcpy(&dbufs[3],
		       share_mode_dbufs,
		       num_share_mode_dbufs * sizeof(TDB_DATA));
	}

	status = g_lock_writev_data(lock_ctx, key, dbufs, ARRAY_SIZE(dbufs));
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("g_lock_writev_data() failed: %s\n",
			  nt_errstr(status));
	}
	return status;
}

/*******************************************************************
 Get all share mode entries for a dev/inode pair.
********************************************************************/

static struct share_mode_data *parse_share_modes(
	TALLOC_CTX *mem_ctx,
	const TDB_DATA key,
	const uint8_t *buf,
	size_t buflen)
{
	struct share_mode_data *d;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;

	/* See if we already have a cached copy of this key. */
	d = share_mode_memcache_fetch(mem_ctx, key, buf, buflen);
	if (d != NULL) {
		return d;
	}

	d = talloc(mem_ctx, struct share_mode_data);
	if (d == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	blob = (DATA_BLOB) {
		.data = discard_const_p(uint8_t, buf),
		.length = buflen,
	};
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

static NTSTATUS share_mode_data_store(struct share_mode_data *d)
{
	TDB_DATA key = locking_key(&d->id);
	struct locking_tdb_data *ltdb = NULL;
	DATA_BLOB blob = { 0 };
	NTSTATUS status;

	if (!d->modified) {
		DBG_DEBUG("not modified\n");
		return NT_STATUS_OK;
	}

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("\n");
		NDR_PRINT_DEBUG(share_mode_data, d);
	}

	d->unique_content_epoch = generate_unique_u64(d->unique_content_epoch);

	status = locking_tdb_data_fetch(key, d, &ltdb);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (ltdb->num_share_entries != 0) {
		enum ndr_err_code ndr_err;

		ndr_err = ndr_push_struct_blob(
			&blob,
			ltdb,
			d,
			(ndr_push_flags_fn_t)ndr_push_share_mode_data);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DBG_DEBUG("ndr_push_share_mode_data failed: %s\n",
				  ndr_errstr(ndr_err));
			TALLOC_FREE(ltdb);
			return ndr_map_error2ntstatus(ndr_err);
		}
	}

	ltdb->share_mode_data_buf = blob.data;
	ltdb->share_mode_data_len = blob.length;

	status = locking_tdb_data_store(key, ltdb, NULL, 0);
	TALLOC_FREE(ltdb);
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
	d->unique_content_epoch = generate_unique_u64(0);

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
	d->flags = SHARE_MODE_SHARE_DELETE |
		SHARE_MODE_SHARE_WRITE |
		SHARE_MODE_SHARE_READ;
	d->modified = false;
	d->fresh = true;
	return d;
fail:
	DEBUG(0, ("talloc failed\n"));
	TALLOC_FREE(d);
	return NULL;
}

/*
 * Key that's locked with g_lock
 */
static uint8_t share_mode_lock_key_data[sizeof(struct file_id)];
static TDB_DATA share_mode_lock_key = {
	.dptr = share_mode_lock_key_data,
	.dsize = sizeof(share_mode_lock_key_data),
};
static size_t share_mode_lock_key_refcount = 0;

/*
 * We can only ever have one share mode locked. Use a static
 * share_mode_data pointer that is shared by multiple nested
 * share_mode_lock structures, explicitly refcounted.
 */
static struct share_mode_data *static_share_mode_data = NULL;
static size_t static_share_mode_data_refcount = 0;

/*******************************************************************
 Either fetch a share mode from the database, or allocate a fresh
 one if the record doesn't exist.
********************************************************************/

struct get_static_share_mode_data_state {
	TALLOC_CTX *mem_ctx;
	struct file_id id;
	const char *servicepath;
	const struct smb_filename *smb_fname;
	const struct timespec *old_write_time;
	NTSTATUS status;
};

static void get_static_share_mode_data_fn(
	struct server_id exclusive,
	size_t num_shared,
	struct server_id *shared,
	const uint8_t *data,
	size_t datalen,
	void *private_data)
{
	struct get_static_share_mode_data_state *state = private_data;
	TDB_DATA key = locking_key(&state->id);
	struct share_mode_data *d = NULL;
	struct locking_tdb_data ltdb = { 0 };

	if (datalen != 0) {
		bool ok;

		ok = locking_tdb_data_get(&ltdb, data, datalen);
		if (!ok) {
			DBG_DEBUG("locking_tdb_data_get failed\n");
			state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
			return;
		}
	}

	if (ltdb.share_mode_data_len == 0) {
		if (state->smb_fname == NULL) {
			state->status = NT_STATUS_NOT_FOUND;
			return;
		}
		d = fresh_share_mode_lock(
			state->mem_ctx,
			state->servicepath,
			state->smb_fname,
			state->old_write_time);
		if (d == NULL) {
			state->status = NT_STATUS_NO_MEMORY;
			return;
		}
	} else {
		d = parse_share_modes(
			lock_ctx,
			key,
			ltdb.share_mode_data_buf,
			ltdb.share_mode_data_len);
		if (d == NULL) {
			state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
			return;
		}
	}

	d->id = state->id;
	static_share_mode_data = d;
}

static NTSTATUS get_static_share_mode_data(
	struct file_id id,
	const char *servicepath,
	const struct smb_filename *smb_fname,
	const struct timespec *old_write_time)
{
	struct get_static_share_mode_data_state state = {
		.mem_ctx = lock_ctx,
		.id = id,
		.servicepath = servicepath,
		.smb_fname = smb_fname,
		.old_write_time = old_write_time,
	};
	NTSTATUS status;

	SMB_ASSERT(static_share_mode_data == NULL);

	status = g_lock_dump(
		lock_ctx,
		share_mode_lock_key,
		get_static_share_mode_data_fn,
		&state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("g_lock_dump failed: %s\n",
			  nt_errstr(status));
		return status;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_DEBUG("get_static_share_mode_data_fn failed: %s\n",
			  nt_errstr(state.status));
		return state.status;
	}

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
	int cmp;

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

	if (share_mode_lock_key_refcount == 0) {
		status = g_lock_lock(
			lock_ctx,
			key,
			G_LOCK_WRITE,
			(struct timeval) { .tv_sec = 3600 });
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("g_lock_lock failed: %s\n",
				  nt_errstr(status));
			goto fail;
		}
		memcpy(share_mode_lock_key_data, key.dptr, key.dsize);
	}

	cmp = tdb_data_cmp(share_mode_lock_key, key);
	if (cmp != 0) {
		DBG_WARNING("Can not lock two share modes simultaneously\n");
		goto fail;
	}

	SMB_ASSERT(share_mode_lock_key_refcount < SIZE_MAX);
	share_mode_lock_key_refcount += 1;

	SMB_ASSERT(static_share_mode_data_refcount == 0);

	status = get_static_share_mode_data(
		id,
		servicepath,
		smb_fname,
		old_write_time);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("get_static_share_mode_data failed: %s\n",
			  nt_errstr(status));
		share_mode_lock_key_refcount -= 1;
		goto fail;
	}
done:
	static_share_mode_data_refcount += 1;
	lck->data = static_share_mode_data;

	talloc_set_destructor(lck, share_mode_lock_destructor);

	return lck;
fail:
	TALLOC_FREE(lck);
	if (share_mode_lock_key_refcount == 0) {
		status = g_lock_unlock(lock_ctx, share_mode_lock_key);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("g_lock_unlock failed: %s\n",
				nt_errstr(status));
		}
	}
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

	status = share_mode_data_store(static_share_mode_data);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_data_store failed: %s\n",
			nt_errstr(status));
		smb_panic("Could not store share mode data\n");
	}

	SMB_ASSERT(share_mode_lock_key_refcount > 0);
	share_mode_lock_key_refcount -= 1;

	if (share_mode_lock_key_refcount == 0) {
		status = g_lock_unlock(lock_ctx, share_mode_lock_key);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("g_lock_unlock failed: %s\n",
				nt_errstr(status));
			smb_panic("Could not unlock share mode\n");
		}
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
	TDB_DATA key;
	void (*fn)(const uint8_t *buf,
		   size_t buflen,
		   bool *modified_dependent,
		   void *private_data);
	void *private_data;
};

static void share_mode_do_locked_fn(
	struct server_id exclusive,
	size_t num_shared,
	struct server_id *shared,
	const uint8_t *data,
	size_t datalen,
	void *private_data)
{
	struct share_mode_do_locked_state *state = private_data;
	bool modified_dependent = false;
	struct locking_tdb_data ltdb = { 0 };
	bool ok;

	ok = locking_tdb_data_get(
		&ltdb, discard_const_p(uint8_t, data), datalen);
	if (!ok) {
		DBG_WARNING("locking_tdb_data_get failed\n");
		return;
	}

	state->fn(ltdb.share_mode_data_buf,
		  ltdb.share_mode_data_len,
		  &modified_dependent,
		  state->private_data);

	if (modified_dependent) {
		g_lock_wake_watchers(lock_ctx, state->key);
	}
}

NTSTATUS share_mode_do_locked(
	struct file_id id,
	void (*fn)(const uint8_t *buf,
		   size_t buflen,
		   bool *modified_dependent,
		   void *private_data),
	void *private_data)
{
	TDB_DATA key = locking_key(&id);
	size_t data_refcount, key_refcount;
	struct share_mode_do_locked_state state = {
		.key = key, .fn = fn, .private_data = private_data,
	};
	NTSTATUS status;

	if (share_mode_lock_key_refcount == 0) {
		status = g_lock_lock(
			lock_ctx,
			key,
			G_LOCK_WRITE,
			(struct timeval) { .tv_sec = 3600 });
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("g_lock_lock failed: %s\n",
				  nt_errstr(status));
			return status;
		}
		memcpy(share_mode_lock_key_data, key.dptr, key.dsize);
	}

	SMB_ASSERT(share_mode_lock_key_refcount < SIZE_MAX);
	share_mode_lock_key_refcount += 1;

	key_refcount = share_mode_lock_key_refcount;
	data_refcount = static_share_mode_data_refcount;

	status = g_lock_dump(
		lock_ctx, key, share_mode_do_locked_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("g_lock_dump failed: %s\n",
			  nt_errstr(status));
	}

	SMB_ASSERT(data_refcount == static_share_mode_data_refcount);
	SMB_ASSERT(key_refcount == share_mode_lock_key_refcount);
	share_mode_lock_key_refcount -= 1;

	if (share_mode_lock_key_refcount == 0) {
		status = g_lock_unlock(lock_ctx, key);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("g_lock_unlock failed: %s\n",
				  nt_errstr(status));
		}
	}

	return status;
}

static void share_mode_wakeup_waiters_fn(
	const uint8_t *buf,
	size_t buflen,
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
	bool blockerdead;
	struct server_id blocker;
};

static void share_mode_watch_done(struct tevent_req *subreq);

struct tevent_req *share_mode_watch_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct file_id id,
	struct server_id blocker)
{
	TDB_DATA key = locking_key(&id);
	struct tevent_req *req = NULL, *subreq = NULL;
	struct share_mode_watch_state *state = NULL;

	req = tevent_req_create(
		mem_ctx, &state, struct share_mode_watch_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = g_lock_watch_data_send(state, ev, lock_ctx, key, blocker);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, share_mode_watch_done, req);
	return req;
}

static void share_mode_watch_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct share_mode_watch_state *state = tevent_req_data(
		req, struct share_mode_watch_state);
	NTSTATUS status;

	status = g_lock_watch_data_recv(
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
	TDB_DATA key;
	struct share_mode_lock *lck;
};

static void fetch_share_mode_unlocked_parser(
	struct server_id exclusive,
	size_t num_shared,
	struct server_id *shared,
	const uint8_t *data,
	size_t datalen,
	void *private_data)
{
	struct fetch_share_mode_unlocked_state *state = private_data;
	struct locking_tdb_data ltdb = { 0 };

	if (datalen != 0) {
		bool ok = locking_tdb_data_get(&ltdb, data, datalen);
		if (!ok) {
			DBG_DEBUG("locking_tdb_data_get failed\n");
			return;
		}
	}

	if (ltdb.share_mode_data_len == 0) {
		/* Likely a ctdb tombstone record, ignore it */
		return;
	}

	state->lck = talloc(state->mem_ctx, struct share_mode_lock);
	if (state->lck == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return;
	}

	state->lck->data = parse_share_modes(
		state->lck,
		state->key,
		ltdb.share_mode_data_buf,
		ltdb.share_mode_data_len);
	if (state->lck->data == NULL) {
		DBG_DEBUG("parse_share_modes failed\n");
		TALLOC_FREE(state->lck);
	}
}

/*******************************************************************
 Get a share_mode_lock without locking the database or reference
 counting. Used by smbstatus to display existing share modes.
********************************************************************/

struct share_mode_lock *fetch_share_mode_unlocked(TALLOC_CTX *mem_ctx,
						  struct file_id id)
{
	struct fetch_share_mode_unlocked_state state = {
		.mem_ctx = mem_ctx,
		.key = locking_key(&id),
	};
	NTSTATUS status;

	status = g_lock_dump(
		lock_ctx, state.key, fetch_share_mode_unlocked_parser, &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("g_lock_dump failed: %s\n", nt_errstr(status));
		return NULL;
	}
	return state.lck;
}

struct fetch_share_mode_state {
	struct file_id id;
	struct share_mode_lock *lck;
	NTSTATUS status;
};

static void fetch_share_mode_fn(
	struct server_id exclusive,
	size_t num_shared,
	struct server_id *shared,
	const uint8_t *data,
	size_t datalen,
	void *private_data);
static void fetch_share_mode_done(struct tevent_req *subreq);

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
	struct tevent_req *req = NULL, *subreq = NULL;
	struct fetch_share_mode_state *state = NULL;

	*queued = false;

	req = tevent_req_create(mem_ctx, &state,
				struct fetch_share_mode_state);
	if (req == NULL) {
		return NULL;
	}
	state->id = id;

	subreq = g_lock_dump_send(
		state,
		ev,
		lock_ctx,
		locking_key(&id),
		fetch_share_mode_fn,
		state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, fetch_share_mode_done, req);
	return req;
}

static void fetch_share_mode_fn(
	struct server_id exclusive,
	size_t num_shared,
	struct server_id *shared,
	const uint8_t *data,
	size_t datalen,
	void *private_data)
{
	struct fetch_share_mode_state *state = talloc_get_type_abort(
		private_data, struct fetch_share_mode_state);
	struct locking_tdb_data ltdb = { 0 };

	if (datalen != 0) {
		bool ok = locking_tdb_data_get(&ltdb, data, datalen);
		if (!ok) {
			DBG_DEBUG("locking_tdb_data_get failed\n");
			return;
		}
	}

	if (ltdb.share_mode_data_len == 0) {
		/* Likely a ctdb tombstone record, ignore it */
		return;
	}

	state->lck = talloc(state, struct share_mode_lock);
	if (state->lck == NULL) {
		DBG_WARNING("talloc failed\n");
		state->status = NT_STATUS_NO_MEMORY;
		return;
	}

	state->lck->data = parse_share_modes(
		state->lck,
		locking_key(&state->id),
		ltdb.share_mode_data_buf,
		ltdb.share_mode_data_len);
	if (state->lck->data == NULL) {
		DBG_DEBUG("parse_share_modes failed\n");
		TALLOC_FREE(state->lck);
	}
}

static void fetch_share_mode_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct fetch_share_mode_state *state = tevent_req_data(
		req, struct fetch_share_mode_state);
	NTSTATUS status;

	status = g_lock_dump_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	if (tevent_req_nterror(req, state->status)) {
		return;
	}
	tevent_req_done(req);
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

	if (state->lck == NULL) {
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
	TDB_DATA key;
	int (*fn)(struct file_id fid,
		  const struct share_mode_data *data,
		  void *private_data);
	void *private_data;
};

static void share_mode_forall_dump_fn(
	struct server_id exclusive,
	size_t num_shared,
	struct server_id *shared,
	const uint8_t *data,
	size_t datalen,
	void *private_data)
{
	struct share_mode_forall_state *state = private_data;
	struct file_id fid;
	struct locking_tdb_data ltdb = { 0 };
	bool ok;
	struct share_mode_data *d;

	if (state->key.dsize != sizeof(fid)) {
		DBG_DEBUG("Got invalid key length %zu\n", state->key.dsize);
		return;
	}
	memcpy(&fid, state->key.dptr, sizeof(fid));

	ok = locking_tdb_data_get(&ltdb, data, datalen);
	if (!ok) {
		DBG_DEBUG("locking_tdb_data_get() failed\n");
		return;
	}

	d = parse_share_modes(
		talloc_tos(),
		state->key,
		ltdb.share_mode_data_buf,
		ltdb.share_mode_data_len);
	if (d == NULL) {
		DBG_DEBUG("parse_share_modes() failed\n");
		return;
	}

	state->fn(fid, d, state->private_data);
	TALLOC_FREE(d);
}

static int share_mode_forall_fn(TDB_DATA key, void *private_data)
{
	struct share_mode_forall_state *state = private_data;
	NTSTATUS status;

	state->key = key;

	status = g_lock_dump(
		lock_ctx, key, share_mode_forall_dump_fn, private_data);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("g_lock_dump failed: %s\n",
			  nt_errstr(status));
	}
	return 0;
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
	int ret;

	if (lock_ctx == NULL) {
		return 0;
	}

	ret = g_lock_locks(
		lock_ctx, share_mode_forall_fn, &state);
	if (ret < 0) {
		DBG_DEBUG("g_lock_locks failed\n");
	}
	return ret;
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

static bool cleanup_disconnected_share_mode_entry_fn(
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
		DBG_ERR("file (file-id='%s', servicepath='%s', "
			"base_name='%s%s%s') "
			"is used by server %s ==> internal error\n",
			file_id_str_buf(d->id, &tmp1),
			d->servicepath,
			d->base_name,
			(d->stream_name == NULL)
			? "" : "', stream_name='",
			(d->stream_name == NULL)
			? "" : d->stream_name,
			server_id_str_buf(e->pid, &tmp2));
		smb_panic(__location__);
	}

	/*
	 * Setting e->stale = true is
	 * the indication to delete the entry.
	 */
	e->stale = true;
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
		goto done;
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

	ok = share_mode_forall_entries(
		state.lck, cleanup_disconnected_share_mode_entry_fn, &state);
	if (!ok) {
		DBG_DEBUG("failed to clean up %zu entries associated "
			  "with file (file-id='%s', servicepath='%s', "
			  "base_name='%s%s%s') and open_persistent_id %"PRIu64" "
			  "==> do not cleanup\n",
			  state.num_disconnected,
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

static size_t share_mode_entry_find(
	const uint8_t *data,
	size_t num_share_modes,
	struct server_id pid,
	uint64_t share_file_id,
	struct share_mode_entry *e,
	bool *match)
{
	ssize_t left, right, middle;

	*match = false;

	if (num_share_modes == 0) {
		return 0;
	}

	left = 0;
	right = (num_share_modes-1);

	while (left <= right) {
		const uint8_t *middle_ptr = NULL;
		int cmp;
		bool ok;

		middle = left + ((right - left) / 2);
		middle_ptr = data + middle * SHARE_MODE_ENTRY_SIZE;

		DBG_DEBUG("left=%zu, right=%zu, middle=%zu, middle_ptr=%p\n",
			  left,
			  right,
			  middle,
			  middle_ptr);

		ok = share_mode_entry_get(middle_ptr, e);
		if (!ok) {
			DBG_DEBUG("share_mode_entry_get failed\n");
			return 0;
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

	return left;
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
	TDB_DATA key = locking_key(&d->id);
	struct server_id my_pid = messaging_server_id(
		fsp->conn->sconn->msg_ctx);
	struct locking_tdb_data *ltdb = NULL;
	size_t idx;
	struct share_mode_entry e = { .pid.pid = 0 };
	struct share_mode_entry_buf e_buf;
	NTSTATUS status;
	bool ok, found;

	TDB_DATA dbufs[3];
	size_t num_dbufs = 0;

	status = locking_tdb_data_fetch(key, talloc_tos(), &ltdb);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("locking_tdb_data_fetch failed: %s\n",
			  nt_errstr(status));
		return false;
	}
	DBG_DEBUG("num_share_modes=%zu\n", ltdb->num_share_entries);

	idx = share_mode_entry_find(
		ltdb->share_entries,
		ltdb->num_share_entries,
		my_pid,
		fsp->fh->gen_id,
		&e,
		&found);
	if (found) {
		DBG_WARNING("Found duplicate share mode\n");
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto done;
	}

	e = (struct share_mode_entry) {
		.pid = my_pid,
		.share_access = share_access,
		.private_options = fsp->fh->private_options,
		.access_mask = access_mask,
		.op_mid = mid,
		.op_type = op_type,
		.time.tv_sec = fsp->open_time.tv_sec,
		.time.tv_usec = fsp->open_time.tv_usec,
		.share_file_id = fsp->fh->gen_id,
		.uid = (uint32_t)uid,
		.flags = (fsp->posix_flags & FSP_POSIX_FLAGS_OPEN) ?
			SHARE_MODE_FLAG_POSIX_OPEN : 0,
		.name_hash = fsp->name_hash,
	};

	if (op_type == LEASE_OPLOCK) {
		const struct GUID *client_guid = fsp_client_guid(fsp);
		e.client_guid = *client_guid;
		e.lease_key = fsp->lease->lease.lease_key;
	}

	ok = share_mode_entry_put(&e, &e_buf);
	if (!ok) {
		DBG_DEBUG("share_mode_entry_put failed\n");
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	DBG_DEBUG("idx=%zu, found=%d\n", idx, (int)found);

	if (idx > 0) {
		dbufs[num_dbufs] = (TDB_DATA) {
			.dptr = discard_const_p(uint8_t, ltdb->share_entries),
			.dsize = idx * SHARE_MODE_ENTRY_SIZE,
		};
		num_dbufs += 1;
	}

	dbufs[num_dbufs] = (TDB_DATA) {
		.dptr = e_buf.buf, .dsize = SHARE_MODE_ENTRY_SIZE,
	};
	num_dbufs += 1;

	if (idx < ltdb->num_share_entries) {
		size_t num_after_idx = (ltdb->num_share_entries-idx);
		dbufs[num_dbufs] = (TDB_DATA) {
			.dptr = discard_const_p(uint8_t, ltdb->share_entries) +
				idx * SHARE_MODE_ENTRY_SIZE,
			.dsize = num_after_idx * SHARE_MODE_ENTRY_SIZE,
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

	if (num_dbufs == 1) {
		/*
		 * Storing a fresh record with just one share entry
		 */
		d->have_share_modes = true;
		d->modified = true;
	}

	/*
	 * If there was any existing data in
	 * ltdb->share_entries, it's now been
	 * moved and we've split it into:
	 *
	 * num_dbufs = 3
	 * dbufs[0] -> old sorted data less than new_entry
	 * dbufs[1] -> new_share_mode_entry
	 * dbufs[2] -> old sorted_data greater than new entry.
	 *
	 * So the old data inside ltdb->share_entries is
	 * no longer valid.
	 *
	 * If we're storing a brand new entry the
	 * dbufs look like:
	 *
	 * num_dbufs = 1
	 * dbufs[0] -> new_share_mode_entry
	 *
	 * Either way we must set ltdb->share_entries = NULL
	 * and ltdb->num_share_entries = 0 so that
	 * locking_tdb_data_store() doesn't use it to
	 * store any data. It's no longer there.
	 */

	ltdb->share_entries = NULL;
	ltdb->num_share_entries = 0;

	status = locking_tdb_data_store(key, ltdb, dbufs, num_dbufs);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("locking_tdb_data_store failed: %s\n",
			  nt_errstr(status));
	}
done:
	TALLOC_FREE(ltdb);
	return NT_STATUS_IS_OK(status);
}

static bool share_mode_for_one_entry(
	bool (*fn)(struct share_mode_entry *e,
		   bool *modified,
		   void *private_data),
	void *private_data,
	size_t *i,
	uint8_t *data,
	size_t *num_share_modes,
	bool *writeback)
{
	DATA_BLOB blob = {
		.data = data + (*i) * SHARE_MODE_ENTRY_SIZE,
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

	stop = fn(&e, &modified, private_data);

	DBG_DEBUG("entry[%zu]: modified=%d, e.stale=%d\n",
		  *i,
		  (int)modified,
		  (int)e.stale);

	if (e.stale) {
		if (DEBUGLEVEL>=10) {
			DBG_DEBUG("share_mode_entry:\n");
			NDR_PRINT_DEBUG(share_mode_entry, &e);
		}

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

	if (stop) {
		return true;
	}

	*i += 1;
	return false;
}

bool share_mode_forall_entries(
	struct share_mode_lock *lck,
	bool (*fn)(struct share_mode_entry *e,
		   bool *modified,
		   void *private_data),
	void *private_data)
{
	struct share_mode_data *d = lck->data;
	TDB_DATA key = locking_key(&d->id);
	struct locking_tdb_data *ltdb = NULL;
	uint8_t *share_entries = NULL;
	size_t num_share_entries;
	bool writeback = false;
	NTSTATUS status;
	bool stop = false;
	size_t i;

	status = locking_tdb_data_fetch(key, talloc_tos(), &ltdb);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("locking_tdb_data_fetch failed: %s\n",
			  nt_errstr(status));
		return false;
	}
	DBG_DEBUG("num_share_modes=%zu\n", ltdb->num_share_entries);

	num_share_entries = ltdb->num_share_entries;
	share_entries = discard_const_p(uint8_t, ltdb->share_entries);

	i = 0;
	while (i<num_share_entries) {
		stop = share_mode_for_one_entry(
			fn,
			private_data,
			&i,
			share_entries,
			&num_share_entries,
			&writeback);
		if (stop) {
			break;
		}
	}

	DBG_DEBUG("num_share_entries=%zu, writeback=%d\n",
		  num_share_entries,
		  (int)writeback);

	if (!writeback) {
		return true;
	}

	if ((ltdb->num_share_entries != 0 ) && (num_share_entries == 0)) {
		/*
		 * This routine wiped all share entries
		 */
		d->have_share_modes = false;
		d->modified = true;
	}

	ltdb->num_share_entries = num_share_entries;
	ltdb->share_entries = share_entries;

	status = locking_tdb_data_store(key, ltdb, NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("locking_tdb_data_store failed: %s\n",
			  nt_errstr(status));
		return false;
	}

	return true;
}

struct share_mode_count_entries_state {
	size_t num_share_modes;
	NTSTATUS status;
};

static void share_mode_count_entries_fn(
	struct server_id exclusive,
	size_t num_shared,
	struct server_id *shared,
	const uint8_t *data,
	size_t datalen,
	void *private_data)
{
	struct share_mode_count_entries_state *state = private_data;
	struct locking_tdb_data ltdb = { 0 };
	bool ok;

	ok = locking_tdb_data_get(&ltdb, data, datalen);
	if (!ok) {
		DBG_WARNING("locking_tdb_data_get failed for %zu\n", datalen);
		state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		return;
	}
	state->num_share_modes = ltdb.num_share_entries;
	state->status = NT_STATUS_OK;
}

NTSTATUS share_mode_count_entries(struct file_id fid, size_t *num_share_modes)
{
	struct share_mode_count_entries_state state = {
		.status = NT_STATUS_NOT_FOUND,
	};
	NTSTATUS status;

	status = g_lock_dump(
		lock_ctx,
		locking_key(&fid),
		share_mode_count_entries_fn,
		&state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("g_lock_dump failed: %s\n",
			  nt_errstr(status));
		return status;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_DEBUG("share_mode_count_entries_fn failed: %s\n",
			  nt_errstr(state.status));
		return state.status;
	}

	*num_share_modes = state.num_share_modes;
	return NT_STATUS_OK;
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
	TDB_DATA key = locking_key(&d->id);
	struct locking_tdb_data *ltdb = NULL;
	size_t idx;
	bool found = false;
	bool modified = false;
	struct share_mode_entry e;
	uint8_t *e_ptr = NULL;
	bool have_share_modes;
	NTSTATUS status;
	bool ret = false;

	status = locking_tdb_data_fetch(key, talloc_tos(), &ltdb);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("locking_tdb_data_fetch failed: %s\n",
			  nt_errstr(status));
		return false;
	}
	DBG_DEBUG("num_share_modes=%zu\n", ltdb->num_share_entries);

	idx = share_mode_entry_find(
		ltdb->share_entries,
		ltdb->num_share_entries,
		pid,
		share_file_id,
		&e,
		&found);
	if (!found) {
		DBG_WARNING("Did not find share mode entry for %"PRIu64"\n",
			    share_file_id);
		goto done;
	}

	if (DEBUGLEVEL>=10) {
		DBG_DEBUG("entry[%zu]:\n", idx);
		NDR_PRINT_DEBUG(share_mode_entry, &e);
	}

	fn(&e, ltdb->num_share_entries, &modified, private_data);

	DBG_DEBUG("entry[%zu]: modified=%d, e.stale=%d\n",
		  idx,
		  (int)modified,
		  (int)e.stale);

	if (!e.stale && !modified) {
		ret = true;
		goto done;
	}

	e_ptr = discard_const_p(uint8_t, ltdb->share_entries) +
		idx * SHARE_MODE_ENTRY_SIZE;

	if (e.stale) {
		/*
		 * Move the rest down one entry
		 */
		size_t behind = ltdb->num_share_entries - idx - 1;
		if (behind != 0) {
			memmove(e_ptr,
				e_ptr + SHARE_MODE_ENTRY_SIZE,
				behind * SHARE_MODE_ENTRY_SIZE);
		}
		ltdb->num_share_entries -= 1;

		if (DEBUGLEVEL>=10) {
			DBG_DEBUG("share_mode_entry:\n");
			NDR_PRINT_DEBUG(share_mode_entry, &e);
		}
	} else {
		struct share_mode_entry_buf buf;
		bool ok;

		if (ltdb->num_share_entries != 1) {
			/*
			 * Make sure the sorting order stays intact
			 */
			SMB_ASSERT(server_id_equal(&e.pid, &pid));
			SMB_ASSERT(e.share_file_id == share_file_id);
		}

		ok = share_mode_entry_put(&e, &buf);
		if (!ok) {
			DBG_DEBUG("share_mode_entry_put failed\n");
			goto done;
		}
		memcpy(e_ptr, buf.buf, SHARE_MODE_ENTRY_SIZE);
	}

	status = locking_tdb_data_store(key, ltdb, NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("locking_tdb_data_store failed: %s\n",
			  nt_errstr(status));
		goto done;
	}

	have_share_modes = (ltdb->num_share_entries != 0);
	if (d->have_share_modes != have_share_modes) {
		d->have_share_modes = have_share_modes;
		d->modified = true;
	}

	ret = true;
done:
	TALLOC_FREE(ltdb);
	return ret;
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

bool reset_share_mode_entry(
	struct share_mode_lock *lck,
	struct server_id old_pid,
	uint64_t old_share_file_id,
	struct server_id new_pid,
	uint64_t new_mid,
	uint64_t new_share_file_id)
{
	struct share_mode_data *d = lck->data;
	TDB_DATA key = locking_key(&d->id);
	struct locking_tdb_data *ltdb = NULL;
	struct share_mode_entry e;
	struct share_mode_entry_buf e_buf;
	NTSTATUS status;
	bool ret = false;
	bool ok;

	status = locking_tdb_data_fetch(key, talloc_tos(), &ltdb);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("locking_tdb_data_fetch failed: %s\n",
			  nt_errstr(status));
		return false;
	}

	if (ltdb->num_share_entries != 1) {
		DBG_DEBUG("num_share_modes=%zu\n", ltdb->num_share_entries);
		goto done;
	}

	ok = share_mode_entry_get(ltdb->share_entries, &e);
	if (!ok) {
		DBG_WARNING("share_mode_entry_get failed\n");
		goto done;
	}

	ret = share_mode_entry_cmp(
		old_pid, old_share_file_id, e.pid, e.share_file_id);
	if (ret != 0) {
		struct server_id_buf tmp1, tmp2;
		DBG_WARNING("Expected pid=%s, file_id=%"PRIu64", "
			    "got pid=%s, file_id=%"PRIu64"\n",
			    server_id_str_buf(old_pid, &tmp1),
			    old_share_file_id,
			    server_id_str_buf(e.pid, &tmp2),
			    e.share_file_id);
		goto done;
	}

	e.pid = new_pid;
	e.op_mid = new_mid;
	e.share_file_id = new_share_file_id;

	ok = share_mode_entry_put(&e, &e_buf);
	if (!ok) {
		DBG_WARNING("share_mode_entry_put failed\n");
		goto done;
	}

	ltdb->share_entries = e_buf.buf;

	status = locking_tdb_data_store(key, ltdb, NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("locking_tdb_data_store failed: %s\n",
			  nt_errstr(status));
		goto done;
	}

	d->have_share_modes = true;
	ret = true;
done:
	TALLOC_FREE(ltdb);
	return true;
}
