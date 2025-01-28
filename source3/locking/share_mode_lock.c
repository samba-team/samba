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
#include "lib/util/time_basic.h"
#include "system/filesys.h"
#include "lib/util/server_id.h"
#include "share_mode_lock_private.h"
struct share_mode_lock {
	struct file_id id;
	struct share_mode_data *cached_data;
};
#define SHARE_MODE_ENTRY_PREPARE_STATE_LCK_SPACE 1
#include "share_mode_lock.h"
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
#include "smbd/fd_handle.h"
#include "lib/global_contexts.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

#define DBG_GET_SHARE_MODE_LOCK(__status, ...) \
	DBG_PREFIX( \
		NT_STATUS_EQUAL(__status, NT_STATUS_NOT_FOUND) ? \
		DBGLVL_DEBUG : DBGLVL_ERR, \
		(__VA_ARGS__))

/* the locking database handle */
static struct g_lock_ctx *lock_ctx;
static struct g_lock_lock_cb_state *current_share_mode_glck = NULL;

static bool share_mode_g_lock_within_cb(TDB_DATA key);

static NTSTATUS share_mode_g_lock_dump(TDB_DATA key,
				       void (*fn)(struct server_id exclusive,
						  size_t num_shared,
						  const struct server_id *shared,
						  const uint8_t *data,
						  size_t datalen,
						  void *private_data),
				       void *private_data)
{
	if (share_mode_g_lock_within_cb(key)) {
		return g_lock_lock_cb_dump(current_share_mode_glck,
					   fn, private_data);
	}

	return g_lock_dump(lock_ctx, key, fn, private_data);
}

static NTSTATUS share_mode_g_lock_writev(TDB_DATA key,
					 const TDB_DATA *dbufs,
					 size_t num_dbufs)
{
	if (share_mode_g_lock_within_cb(key)) {
		return g_lock_lock_cb_writev(current_share_mode_glck,
					     dbufs, num_dbufs);
	}

	return g_lock_writev_data(lock_ctx, key, dbufs, num_dbufs);
}

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
			  SMBD_VOLATILE_TDB_HASH_SIZE,
			  SMBD_VOLATILE_TDB_FLAGS |
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
	SMB_ASSERT(!d->modified);
	SMB_ASSERT(!d->not_stored);

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

static int share_mode_data_nofree_destructor(struct share_mode_data *d)
{
	return -1;
}

static struct share_mode_data *share_mode_memcache_fetch(
	TALLOC_CTX *mem_ctx,
	struct file_id id,
	const uint8_t *buf,
	size_t buflen)
{
	const DATA_BLOB key = memcache_key(&id);
	enum ndr_err_code ndr_err;
	struct share_mode_data *d;
	uint64_t unique_content_epoch;
	uint16_t flags;
	void *ptr;
	struct file_id_buf idbuf;

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

/*
 * Parse a buffer into a struct locking_tdb_data object
 */
static bool locking_tdb_data_parse(
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
	const struct server_id *shared,
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

	status = share_mode_g_lock_dump(key, locking_tdb_data_fetch_fn, &state);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		/*
		 * Just return an empty record
		 */
		goto done;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_g_lock_dump failed: %s\n",
			nt_errstr(status));
		return status;
	}
	if (state.datalen == 0) {
		goto done;
	}

	ok = locking_tdb_data_parse(result, state.data, state.datalen);
	if (!ok) {
		DBG_ERR("locking_tdb_data_get failed for %zu bytes\n",
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
		status = share_mode_g_lock_writev(key, NULL, 0);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("share_mode_g_lock_writev(NULL) failed: %s\n",
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

	status = share_mode_g_lock_writev(key, dbufs, ARRAY_SIZE(dbufs));
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_g_lock_writev() failed: %s\n",
			nt_errstr(status));
	}
	return status;
}

/*******************************************************************
 Get share_mode_data for a dev/inode pair.
********************************************************************/

static struct share_mode_data *parse_share_mode_data(
	TALLOC_CTX *mem_ctx,
	struct file_id id,
	const uint8_t *buf,
	size_t buflen)
{
	struct share_mode_data *d;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;

	/* See if we already have a cached copy of this key. */
	d = share_mode_memcache_fetch(mem_ctx, id, buf, buflen);
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

	return d;
fail:
	TALLOC_FREE(d);
	return NULL;
}

/*
 * Store share_mode_data from d and share_mode_entrys from ltdb
 */
static NTSTATUS share_mode_data_ltdb_store(struct share_mode_data *d,
					   TDB_DATA key,
					   struct locking_tdb_data *ltdb,
					   const TDB_DATA *share_mode_dbufs,
					   size_t num_share_mode_dbufs)
{
	DATA_BLOB blob = { 0 };
	NTSTATUS status;

	if (!d->modified) {
		DBG_DEBUG("share_mode_data not modified\n");
		goto store;
	}

	d->unique_content_epoch = generate_unique_u64(d->unique_content_epoch);

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("\n");
		NDR_PRINT_DEBUG(share_mode_data, d);
	}

	if (ltdb->num_share_entries != 0 || num_share_mode_dbufs != 0) {
		enum ndr_err_code ndr_err;

		ndr_err = ndr_push_struct_blob(
			&blob,
			ltdb,
			d,
			(ndr_push_flags_fn_t)ndr_push_share_mode_data);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DBG_ERR("ndr_push_share_mode_data failed: %s\n",
				  ndr_errstr(ndr_err));
			return ndr_map_error2ntstatus(ndr_err);
		}
	}

	ltdb->share_mode_data_buf = blob.data;
	ltdb->share_mode_data_len = blob.length;

store:
	status = locking_tdb_data_store(key,
					ltdb,
					share_mode_dbufs,
					num_share_mode_dbufs);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("locking_tdb_data_store failed: %s\n",
			nt_errstr(status));
		return status;
	}

	d->modified = false;
	d->not_stored = (ltdb->share_mode_data_len == 0);

	return NT_STATUS_OK;
}

/*******************************************************************
 If modified, store the share_mode_data back into the database.
********************************************************************/

static NTSTATUS share_mode_data_store(struct share_mode_data *d)
{
	TDB_DATA key = locking_key(&d->id);
	struct locking_tdb_data *ltdb = NULL;
	NTSTATUS status;

	if (!d->modified) {
		DBG_DEBUG("not modified\n");
		return NT_STATUS_OK;
	}

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("\n");
		NDR_PRINT_DEBUG(share_mode_data, d);
	}

	status = locking_tdb_data_fetch(key, d, &ltdb);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("locking_tdb_data_fetch failed: %s\n",
			nt_errstr(status));
		return status;
	}

	status = share_mode_data_ltdb_store(d, key, ltdb, NULL, 0);
	TALLOC_FREE(ltdb);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_data_ltdb_store failed: %s\n",
			nt_errstr(status));
		return status;
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 Allocate a new share_mode_data struct, mark it unmodified.
 fresh is set to note that currently there is no database entry.
********************************************************************/

static struct share_mode_data *fresh_share_mode_lock(
	TALLOC_CTX *mem_ctx, const char *servicepath,
	const struct smb_filename *smb_fname)
{
	struct share_mode_data *d;

	if ((servicepath == NULL) || (smb_fname == NULL)) {
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
	d->flags = SHARE_MODE_SHARE_DELETE |
		SHARE_MODE_SHARE_WRITE |
		SHARE_MODE_SHARE_READ;
	d->modified = false;
	d->not_stored = true;
	return d;
fail:
	DEBUG(0, ("talloc failed\n"));
	TALLOC_FREE(d);
	return NULL;
}

/*
 * Key that's locked with g_lock
 */
static struct file_id share_mode_lock_key_id = {};
static TDB_DATA share_mode_lock_key = {
	.dptr = (uint8_t *)&share_mode_lock_key_id,
	.dsize = sizeof(share_mode_lock_key_id),
};
static size_t share_mode_lock_key_refcount = 0;

static bool share_mode_g_lock_within_cb(TDB_DATA key)
{
	int cmp;

	if (current_share_mode_glck == NULL) {
		return false;
	}

	cmp = tdb_data_cmp(share_mode_lock_key, key);
	if (cmp != 0) {
		struct file_id_buf existing;

		DBG_ERR("Can not lock two share modes "
			"simultaneously: existing %s requested %s\n",
			file_id_str_buf(share_mode_lock_key_id, &existing),
			tdb_data_dbg(key));
		smb_panic(__location__);
		return false;
	}

	return true;
}

/*
 * We can only ever have one share mode locked. Use a static
 * share_mode_data pointer that is shared by multiple nested
 * share_mode_lock structures, explicitly refcounted.
 */
static struct share_mode_data *static_share_mode_data = NULL;

/*******************************************************************
 Either fetch a share mode from the database, or allocate a fresh
 one if the record doesn't exist.
********************************************************************/

struct get_static_share_mode_data_state {
	TALLOC_CTX *mem_ctx;
	struct file_id id;
	const char *servicepath;
	const struct smb_filename *smb_fname;
	NTSTATUS status;
};

static void get_static_share_mode_data_fn(
	struct server_id exclusive,
	size_t num_shared,
	const struct server_id *shared,
	const uint8_t *data,
	size_t datalen,
	void *private_data)
{
	struct get_static_share_mode_data_state *state = private_data;
	struct share_mode_data *d = NULL;
	struct locking_tdb_data ltdb = { 0 };

	if (datalen != 0) {
		bool ok;

		ok = locking_tdb_data_parse(&ltdb, data, datalen);
		if (!ok) {
			DBG_ERR("locking_tdb_data_get failed\n");
			state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
			return;
		}

		d = parse_share_mode_data(
			lock_ctx,
			state->id,
			ltdb.share_mode_data_buf,
			ltdb.share_mode_data_len);
		if (d == NULL) {
			state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
			return;
		}
	} else {
		if (state->smb_fname == NULL) {
			state->status = NT_STATUS_NOT_FOUND;
			return;
		}
		d = fresh_share_mode_lock(
			state->mem_ctx,
			state->servicepath,
			state->smb_fname);
		if (d == NULL) {
			state->status = NT_STATUS_NO_MEMORY;
			return;
		}
	}

	d->id = state->id;
	static_share_mode_data = d;
}

static NTSTATUS get_static_share_mode_data(
	struct file_id id,
	const char *servicepath,
	const struct smb_filename *smb_fname)
{
	struct get_static_share_mode_data_state state = {
		.mem_ctx = lock_ctx,
		.id = id,
		.servicepath = servicepath,
		.smb_fname = smb_fname,
	};
	NTSTATUS status;

	SMB_ASSERT(static_share_mode_data == NULL);

	status = share_mode_g_lock_dump(
		share_mode_lock_key,
		get_static_share_mode_data_fn,
		&state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_GET_SHARE_MODE_LOCK(status,
			"share_mode_g_lock_dump failed: %s\n",
			nt_errstr(status));
		return status;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_GET_SHARE_MODE_LOCK(state.status,
			"get_static_share_mode_data_fn failed: %s\n",
			nt_errstr(state.status));
		return state.status;
	}

	return NT_STATUS_OK;
}

struct file_id share_mode_lock_file_id(const struct share_mode_lock *lck)
{
	return lck->id;
}

NTSTATUS share_mode_lock_access_private_data(struct share_mode_lock *lck,
					     struct share_mode_data **data)
{
	/*
	 * For now we always have lck->cached_data,
	 * but we may change that in future.
	 */
	SMB_ASSERT(lck->cached_data != NULL);
	*data = lck->cached_data;
	return NT_STATUS_OK;
}

/*******************************************************************
 Get a share_mode_lock, Reference counted to allow nested calls.
********************************************************************/

static int share_mode_lock_destructor(struct share_mode_lock *lck);

static bool share_mode_lock_skip_g_lock;

static NTSTATUS get_share_mode_lock_internal(
	struct file_id id,
	const char *servicepath,
	const struct smb_filename *smb_fname,
	struct share_mode_lock *lck)
{
	NTSTATUS status;

	*lck = (struct share_mode_lock) {
		.id = id,
	};

	if (share_mode_lock_key_refcount == 0) {
		if (!share_mode_lock_skip_g_lock) {
			TDB_DATA key = locking_key(&id);

			status = g_lock_lock(
				lock_ctx,
				key,
				G_LOCK_WRITE,
				(struct timeval) { .tv_sec = 3600 },
				NULL, NULL);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_DEBUG("g_lock_lock failed: %s\n",
					  nt_errstr(status));
				return status;
			}
		}
		share_mode_lock_key_id = id;
	}

	if (!file_id_equal(&share_mode_lock_key_id, &id)) {
		struct file_id_buf existing;
		struct file_id_buf requested;

		DBG_ERR("Can not lock two share modes "
			"simultaneously: existing %s requested %s\n",
			file_id_str_buf(share_mode_lock_key_id, &existing),
			file_id_str_buf(id, &requested));
		smb_panic(__location__);
		goto fail;
	}

	SMB_ASSERT(share_mode_lock_key_refcount < SIZE_MAX);
	share_mode_lock_key_refcount += 1;

	if (static_share_mode_data != NULL) {
		goto done;
	}

	status = get_static_share_mode_data(
		id,
		servicepath,
		smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("get_static_share_mode_data failed: %s\n",
			  nt_errstr(status));
		share_mode_lock_key_refcount -= 1;
		goto fail;
	}
done:
	lck->cached_data = static_share_mode_data;

	if (CHECK_DEBUGLVL(DBGLVL_DEBUG)) {
		struct file_id_buf returned;

		DBG_DEBUG("Returning %s (data_cached=%u key_refcount=%zu)\n",
			  file_id_str_buf(id, &returned),
			  static_share_mode_data != NULL,
			  share_mode_lock_key_refcount);
	}

	return NT_STATUS_OK;
fail:
	if (share_mode_lock_key_refcount == 0) {
		if (!share_mode_lock_skip_g_lock) {
			NTSTATUS ulstatus = g_lock_unlock(lock_ctx, share_mode_lock_key);
			if (!NT_STATUS_IS_OK(ulstatus)) {
				DBG_ERR("g_lock_unlock failed: %s\n",
					nt_errstr(ulstatus));
			}
		}
	}
	return status;
}

/*
 * Store static_share_mode_data and unlock share_mode_lock
 */
static NTSTATUS put_share_mode_lock_internal(struct share_mode_lock *lck)
{
	NTSTATUS status;

	SMB_ASSERT(share_mode_lock_key_refcount > 0);
	share_mode_lock_key_refcount -= 1;

	if (share_mode_lock_key_refcount > 0) {
		return NT_STATUS_OK;
	}

	status = share_mode_data_store(static_share_mode_data);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_data_store failed: %s\n",
			nt_errstr(status));
		return status;
	}

	if (!share_mode_lock_skip_g_lock) {
		status = g_lock_unlock(lock_ctx, share_mode_lock_key);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("g_lock_unlock failed: %s\n",
				nt_errstr(status));
			return status;
		}
	}

	if (!static_share_mode_data->not_stored) {
		/*
		 * This is worth keeping. Without share modes,
		 * share_mode_data_store above has left nothing in the
		 * database.
		 */
		share_mode_memcache_store(static_share_mode_data);
		static_share_mode_data = NULL;
	}

	TALLOC_FREE(static_share_mode_data);
	return NT_STATUS_OK;
}

static int share_mode_lock_destructor(struct share_mode_lock *lck)
{
	NTSTATUS status;

	status = put_share_mode_lock_internal(lck);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("put_share_mode_lock_internal failed: %s\n",
			nt_errstr(status));
		smb_panic("put_share_mode_lock_internal failed\n");
	}

	return 0;
}

/*******************************************************************
 Fetch a share mode where we know one MUST exist. This call reference
 counts it internally to allow for nested lock fetches.
********************************************************************/

struct share_mode_lock *get_existing_share_mode_lock(TALLOC_CTX *mem_ctx,
						     const struct file_id id)
{
	struct share_mode_lock *lck = NULL;
	NTSTATUS status;

	lck = talloc(mem_ctx, struct share_mode_lock);
	if (lck == NULL) {
		return NULL;
	}

	status = get_share_mode_lock_internal(id,
					      NULL, /* servicepath */
					      NULL, /* smb_fname */
					      lck);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_GET_SHARE_MODE_LOCK(status,
			"get_share_mode_lock_internal() failed - %s\n",
			nt_errstr(status));
		TALLOC_FREE(lck);
		return NULL;
	}

	talloc_set_destructor(lck, share_mode_lock_destructor);
	return lck;
}

static void share_mode_wakeup_waiters_fn(
	struct share_mode_lock *lck,
	void *private_data)
{
	if (share_mode_g_lock_within_cb(share_mode_lock_key)) {
		g_lock_lock_cb_wake_watchers(current_share_mode_glck);
		return;
	}

	g_lock_wake_watchers(lock_ctx, share_mode_lock_key);
}

NTSTATUS share_mode_wakeup_waiters(struct file_id id)
{
	return share_mode_do_locked_vfs_denied(id,
					       share_mode_wakeup_waiters_fn,
					       NULL);
}

struct fsp_update_share_mode_flags_state {
	struct files_struct *fsp;
	enum ndr_err_code ndr_err;
	uint64_t share_mode_epoch;
	uint16_t share_mode_flags;
};

static void fsp_update_share_mode_flags_fn(
	struct server_id exclusive,
	size_t num_shared,
	const struct server_id *shared,
	const uint8_t *data,
	size_t datalen,
	void *private_data)
{
	struct fsp_update_share_mode_flags_state *state = private_data;
	struct locking_tdb_data ltdb = { 0 };

	if (datalen != 0) {
		bool ok = locking_tdb_data_parse(&ltdb, data, datalen);
		if (!ok) {
			DBG_DEBUG("locking_tdb_data_get failed\n");
			return;
		}
	}

	if (ltdb.share_mode_data_len == 0) {
		/* Likely a ctdb tombstone record, ignore it */
		return;
	}

	if (exclusive.pid != 0) {
		struct server_id self =
			messaging_server_id(state->fsp->conn->sconn->msg_ctx);
		bool is_self = server_id_equal(&self, &exclusive);

		if (!is_self) {
			/*
			 * If someone else is holding an exclusive
			 * lock, pretend there's a read lease
			 */
			state->share_mode_flags = SHARE_MODE_LEASE_READ;
			return;
		}
	}

	state->ndr_err = get_share_mode_blob_header(ltdb.share_mode_data_buf,
						    ltdb.share_mode_data_len,
						    &state->share_mode_epoch,
						    &state->share_mode_flags);
}

static NTSTATUS fsp_update_share_mode_flags(struct files_struct *fsp)
{
	struct fsp_update_share_mode_flags_state state = { .fsp = fsp, };
	int seqnum = g_lock_seqnum(lock_ctx);
	TDB_DATA key = {0};
	NTSTATUS status;

	if (seqnum == fsp->share_mode_flags_seqnum) {
		return NT_STATUS_OK;
	}

	key = locking_key(&fsp->file_id);
	status = share_mode_g_lock_dump(key,
			     fsp_update_share_mode_flags_fn,
			     &state);
	if (!NT_STATUS_IS_OK(status)) {
		/* no DBG_GET_SHARE_MODE_LOCK here! */
		DBG_ERR("share_mode_g_lock_dump returned %s\n",
			nt_errstr(status));
		return status;
	}

	if (!NDR_ERR_CODE_IS_SUCCESS(state.ndr_err)) {
		DBG_ERR("get_share_mode_blob_header returned %s\n",
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

#define share_mode_lock_assert_private_data(__lck) \
	_share_mode_lock_assert_private_data(__lck, __func__, __location__)
static struct share_mode_data *_share_mode_lock_assert_private_data(
					struct share_mode_lock *lck,
					const char *caller_function,
					const char *caller_location)
{
	struct share_mode_data *d = NULL;
	NTSTATUS status;

	status = share_mode_lock_access_private_data(lck, &d);
	if (!NT_STATUS_IS_OK(status)) {
		struct file_id id = share_mode_lock_file_id(lck);
		struct file_id_buf id_buf;
		/* Any error recovery possible here ? */
		D_ERR("%s:%s(): share_mode_lock_access_private_data() "
		      "failed for id=%s - %s\n",
		      caller_location, caller_function,
		      file_id_str_buf(id, &id_buf),
		      nt_errstr(status));
		smb_panic(caller_location);
		return NULL;
	}

	return d;
}

const char *share_mode_servicepath(struct share_mode_lock *lck)
{
	struct share_mode_data *d = share_mode_lock_assert_private_data(lck);
	return d->servicepath;
}

char *share_mode_filename(TALLOC_CTX *mem_ctx, struct share_mode_lock *lck)
{
	struct share_mode_data *d = share_mode_lock_assert_private_data(lck);
	bool has_stream = (d->stream_name != NULL);
	char *fname = NULL;

	fname = talloc_asprintf(
		mem_ctx,
		"%s%s%s",
		d->base_name,
		has_stream ? ":" : "",
		has_stream ? d->stream_name : "");
	return fname;
}

char *share_mode_data_dump(
	TALLOC_CTX *mem_ctx, struct share_mode_lock *lck)
{
	struct share_mode_data *d = share_mode_lock_assert_private_data(lck);
	struct ndr_print *p = talloc(mem_ctx, struct ndr_print);
	char *ret = NULL;

	if (p == NULL) {
		return NULL;
	}

	*p = (struct ndr_print) {
		.print = ndr_print_string_helper,
		.depth = 1,
		.private_data = talloc_strdup(mem_ctx, ""),
	};

	if (p->private_data == NULL) {
		TALLOC_FREE(p);
		return NULL;
	}

	ndr_print_share_mode_data(p, "SHARE_MODE_DATA", d);

	ret = p->private_data;

	TALLOC_FREE(p);

	return ret;
}

void share_mode_flags_get(
	struct share_mode_lock *lck,
	uint32_t *access_mask,
	uint32_t *share_mode,
	uint32_t *lease_type)
{
	struct share_mode_data *d = share_mode_lock_assert_private_data(lck);
	uint16_t flags = d->flags;

	if (access_mask != NULL) {
		*access_mask =
			((flags & SHARE_MODE_ACCESS_READ) ?
			 FILE_READ_DATA : 0) |
			((flags & SHARE_MODE_ACCESS_WRITE) ?
			 FILE_WRITE_DATA : 0) |
			((flags & SHARE_MODE_ACCESS_DELETE) ?
			 DELETE_ACCESS : 0);
	}
	if (share_mode != NULL) {
		*share_mode =
			((flags & SHARE_MODE_SHARE_READ) ?
			 FILE_SHARE_READ : 0) |
			((flags & SHARE_MODE_SHARE_WRITE) ?
			 FILE_SHARE_WRITE : 0) |
			((flags & SHARE_MODE_SHARE_DELETE) ?
			 FILE_SHARE_DELETE : 0);
	}
	if (lease_type != NULL) {
		*lease_type =
			((flags & SHARE_MODE_LEASE_READ) ?
			 SMB2_LEASE_READ : 0) |
			((flags & SHARE_MODE_LEASE_WRITE) ?
			 SMB2_LEASE_WRITE : 0) |
			((flags & SHARE_MODE_LEASE_HANDLE) ?
			 SMB2_LEASE_HANDLE : 0);
	}
}

void share_mode_flags_set(
	struct share_mode_lock *lck,
	uint32_t access_mask,
	uint32_t share_mode,
	uint32_t lease_type,
	bool *modified)
{
	struct share_mode_data *d = share_mode_lock_assert_private_data(lck);
	uint16_t flags = 0;

	flags |= (access_mask & (FILE_READ_DATA | FILE_EXECUTE)) ?
		SHARE_MODE_ACCESS_READ : 0;
	flags |= (access_mask & (FILE_WRITE_DATA | FILE_APPEND_DATA)) ?
		SHARE_MODE_ACCESS_WRITE : 0;
	flags |= (access_mask & (DELETE_ACCESS)) ?
		SHARE_MODE_ACCESS_DELETE : 0;

	flags |= (share_mode & FILE_SHARE_READ) ?
		SHARE_MODE_SHARE_READ : 0;
	flags |= (share_mode & FILE_SHARE_WRITE) ?
		SHARE_MODE_SHARE_WRITE : 0;
	flags |= (share_mode & FILE_SHARE_DELETE) ?
		SHARE_MODE_SHARE_DELETE : 0;

	flags |= (lease_type & SMB2_LEASE_READ) ?
		SHARE_MODE_LEASE_READ : 0;
	flags |= (lease_type & SMB2_LEASE_WRITE) ?
		SHARE_MODE_LEASE_WRITE : 0;
	flags |= (lease_type & SMB2_LEASE_HANDLE) ?
		SHARE_MODE_LEASE_HANDLE : 0;

	if (d->flags == flags) {
		return;
	}

	if (modified != NULL) {
		*modified = true;
	}
	d->flags = flags;
	d->modified = true;
}

struct share_mode_watch_state {
	bool blockerdead;
	struct server_id blocker;
	bool within_cb;
};

static void share_mode_watch_done(struct tevent_req *subreq);

struct tevent_req *share_mode_watch_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct file_id *id,
	struct server_id blocker)
{
	TDB_DATA key = locking_key(id);
	struct tevent_req *req = NULL, *subreq = NULL;
	struct share_mode_watch_state *state = NULL;

	req = tevent_req_create(
		mem_ctx, &state, struct share_mode_watch_state);
	if (req == NULL) {
		return NULL;
	}

	if (share_mode_g_lock_within_cb(key)) {
		state->within_cb = true;
		subreq = g_lock_lock_cb_watch_data_send(state, ev,
							current_share_mode_glck,
							blocker);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
	} else {
		subreq = g_lock_watch_data_send(state, ev, lock_ctx, key, blocker);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
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

	if (state->within_cb) {
		status = g_lock_lock_cb_watch_data_recv(
			subreq, &state->blockerdead, &state->blocker);
		if (tevent_req_nterror(req, status)) {
			return;
		}
	} else {
		status = g_lock_watch_data_recv(
			subreq, &state->blockerdead, &state->blocker);
		if (tevent_req_nterror(req, status)) {
			return;
		}
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
	struct file_id id;
	struct share_mode_lock *lck;
};

static void fetch_share_mode_unlocked_parser(
	struct server_id exclusive,
	size_t num_shared,
	const struct server_id *shared,
	const uint8_t *data,
	size_t datalen,
	void *private_data)
{
	struct fetch_share_mode_unlocked_state *state = private_data;
	struct locking_tdb_data ltdb = { 0 };

	if (datalen != 0) {
		bool ok = locking_tdb_data_parse(&ltdb, data, datalen);
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
	state->lck->id = state->id;

	state->lck->cached_data = parse_share_mode_data(
		state->lck,
		state->id,
		ltdb.share_mode_data_buf,
		ltdb.share_mode_data_len);
	if (state->lck->cached_data == NULL) {
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
		.id = id,
	};
	TDB_DATA key = locking_key(&id);
	NTSTATUS status;

	status = g_lock_dump(
		lock_ctx, key, fetch_share_mode_unlocked_parser, &state);
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
	const struct server_id *shared,
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
	const struct server_id *shared,
	const uint8_t *data,
	size_t datalen,
	void *private_data)
{
	struct fetch_share_mode_state *state = talloc_get_type_abort(
		private_data, struct fetch_share_mode_state);
	struct locking_tdb_data ltdb = { 0 };

	if (datalen != 0) {
		bool ok = locking_tdb_data_parse(&ltdb, data, datalen);
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
	state->lck->id = state->id,

	state->lck->cached_data = parse_share_mode_data(
		state->lck,
		state->id,
		ltdb.share_mode_data_buf,
		ltdb.share_mode_data_len);
	if (state->lck->cached_data == NULL) {
		DBG_DEBUG("parse_share_modes failed\n");
		state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		TALLOC_FREE(state->lck);
		return;
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
		NDR_PRINT_DEBUG(share_mode_data, lck->cached_data);
	}

	*_lck = lck;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct share_mode_forall_state {
	TDB_DATA key;
	int (*ro_fn)(struct file_id fid,
		     const struct share_mode_data *data,
		     void *private_data);
	int (*rw_fn)(struct file_id fid,
		     struct share_mode_data *data,
		     void *private_data);
	void *private_data;
};

static void share_mode_forall_dump_fn(
	struct server_id exclusive,
	size_t num_shared,
	const struct server_id *shared,
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

	ok = locking_tdb_data_parse(&ltdb, data, datalen);
	if (!ok) {
		DBG_DEBUG("locking_tdb_data_get() failed\n");
		return;
	}

	d = parse_share_mode_data(
		talloc_tos(),
		fid,
		ltdb.share_mode_data_buf,
		ltdb.share_mode_data_len);
	if (d == NULL) {
		DBG_DEBUG("parse_share_modes() failed\n");
		return;
	}

	if (state->ro_fn != NULL) {
		state->ro_fn(fid, d, state->private_data);
	} else {
		state->rw_fn(fid, d, state->private_data);
	}
	TALLOC_FREE(d);
}

static int share_mode_forall_fn(TDB_DATA key, void *private_data)
{
	struct share_mode_forall_state *state = private_data;
	NTSTATUS status;

	state->key = key;

	status = share_mode_g_lock_dump(
		key, share_mode_forall_dump_fn, private_data);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_GET_SHARE_MODE_LOCK(status,
			"g_lock_dump failed: %s\n",
			nt_errstr(status));
	}
	return 0;
}

int share_mode_forall_read(int (*fn)(struct file_id fid,
				     const struct share_mode_data *data,
				     void *private_data),
			   void *private_data)
{
	struct share_mode_forall_state state = {
		.ro_fn = fn,
		.private_data = private_data
	};
	int ret;

	if (lock_ctx == NULL) {
		return 0;
	}

	ret = g_lock_locks_read(
		lock_ctx, share_mode_forall_fn, &state);
	if (ret < 0) {
		DBG_ERR("g_lock_locks failed\n");
	}
	return ret;
}

int share_mode_forall(int (*fn)(struct file_id fid,
				struct share_mode_data *data,
				void *private_data),
		      void *private_data)
{
	struct share_mode_forall_state state = {
		.rw_fn = fn,
		.private_data = private_data
	};
	int ret;

	if (lock_ctx == NULL) {
		return 0;
	}

	ret = g_lock_locks(
		lock_ctx, share_mode_forall_fn, &state);
	if (ret < 0) {
		DBG_ERR("g_lock_locks failed\n");
	}
	return ret;
}

struct share_entry_forall_state {
	struct file_id fid;
	struct share_mode_data *data;
	int (*ro_fn)(struct file_id fid,
		     const struct share_mode_data *data,
		     const struct share_mode_entry *entry,
		     void *private_data);
	int (*rw_fn)(struct file_id fid,
		     struct share_mode_data *data,
		     struct share_mode_entry *entry,
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
	int ret;

	if (state->ro_fn != NULL) {
		ret = state->ro_fn(state->fid,
				   state->data,
				   e,
				   state->private_data);
	} else {
		ret = state->rw_fn(state->fid,
				   state->data,
				   e,
				   state->private_data);
	}
	if (ret == 0) {
		/* Continue the whole traverse */
		return 0;
	} else if (ret == 1) {
		/*
		 * Just stop share_mode_entry loop: by not setting
		 * state->ret (which was initialized to 0), the
		 * share_mode_data traverse will continue.
		 */
		return 1;
	}
	state->ret = ret;
	return 1;
}

static int share_entry_ro_traverse_fn(struct file_id fid,
				      const struct share_mode_data *data,
				      void *private_data)
{
	struct share_entry_forall_state *state = private_data;
	struct share_mode_lock lck = {
		.id = fid,
		.cached_data = discard_const_p(struct share_mode_data, data)
	};
	bool ok;

	state->fid = fid;
	state->data = discard_const_p(struct share_mode_data, data);
	state->ret = 0;

	ok = share_mode_forall_entries(
		&lck, share_entry_traverse_walker, state);
	if (!ok) {
		DBG_ERR("share_mode_forall_entries failed\n");
		return false;
	}

	return state->ret;
}

static int share_entry_rw_traverse_fn(struct file_id fid,
				      struct share_mode_data *data,
				      void *private_data)
{
	struct share_entry_forall_state *state = private_data;
	struct share_mode_lock lck = {
		.id = fid,
		.cached_data = data,
	};
	bool ok;

	state->fid = fid;
	state->data = data;
	state->ret = 0;

	ok = share_mode_forall_entries(
		&lck, share_entry_traverse_walker, state);
	if (!ok) {
		DBG_ERR("share_mode_forall_entries failed\n");
		return false;
	}

	return state->ret;
}

/*******************************************************************
 Call the specified function on each entry under management by the
 share mode system.  If the callback function returns:

  0 ... continue traverse
  1 ... stop loop over share_mode_entries, but continue share_mode_data traverse
 -1 ... stop whole share_mode_data traverse

 Any other return value is treated as -1.
********************************************************************/

int share_entry_forall_read(int (*fn)(struct file_id fid,
				      const struct share_mode_data *data,
				      const struct share_mode_entry *entry,
				      void *private_data),
			    void *private_data)
{
	struct share_entry_forall_state state = {
		.ro_fn = fn,
		.private_data = private_data,
	};

	return share_mode_forall_read(share_entry_ro_traverse_fn, &state);
}

int share_entry_forall(int (*fn)(struct file_id fid,
				 struct share_mode_data *data,
				 struct share_mode_entry *entry,
				 void *private_data),
		      void *private_data)
{
	struct share_entry_forall_state state = {
		.rw_fn = fn,
		.private_data = private_data,
	};

	return share_mode_forall(share_entry_rw_traverse_fn, &state);
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
		    const struct smb2_lease_key *lease_key,
		    uint32_t share_access,
		    uint32_t access_mask)
{
	struct share_mode_data *d = share_mode_lock_assert_private_data(lck);
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
		DBG_ERR("locking_tdb_data_fetch failed: %s\n",
			nt_errstr(status));
		return false;
	}
	DBG_DEBUG("num_share_modes=%zu\n", ltdb->num_share_entries);

	idx = share_mode_entry_find(
		ltdb->share_entries,
		ltdb->num_share_entries,
		my_pid,
		fh_get_gen_id(fsp->fh),
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
		.private_options = fh_get_private_options(fsp->fh),
		.access_mask = access_mask,
		.op_mid = mid,
		.op_type = op_type,
		.time.tv_sec = fsp->open_time.tv_sec,
		.time.tv_usec = fsp->open_time.tv_usec,
		.share_file_id = fh_get_gen_id(fsp->fh),
		.uid = (uint32_t)uid,
		.flags = fsp->fsp_flags.posix_open ?
			SHARE_MODE_FLAG_POSIX_OPEN : 0,
		.name_hash = fsp->name_hash,
	};

	if (op_type == LEASE_OPLOCK) {
		const struct GUID *client_guid = fsp_client_guid(fsp);
		e.client_guid = *client_guid;
		e.lease_key = *lease_key;
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

	status = share_mode_data_ltdb_store(d, key, ltdb, dbufs, num_dbufs);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_data_ltdb_store failed: %s\n",
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
	struct file_id id = share_mode_lock_file_id(lck);
	struct share_mode_data *d = NULL;
	TDB_DATA key = locking_key(&id);
	struct locking_tdb_data *ltdb = NULL;
	uint8_t *share_entries = NULL;
	size_t num_share_entries;
	bool writeback = false;
	NTSTATUS status;
	bool stop = false;
	size_t i;

	status = share_mode_lock_access_private_data(lck, &d);
	if (!NT_STATUS_IS_OK(status)) {
		struct file_id_buf id_buf;
		/* Any error recovery possible here ? */
		DBG_ERR("share_mode_lock_access_private_data() failed for "
			"%s - %s\n",
			file_id_str_buf(id, &id_buf),
			nt_errstr(status));
		return false;
	}

	status = locking_tdb_data_fetch(key, talloc_tos(), &ltdb);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("locking_tdb_data_fetch failed: %s\n",
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
		TALLOC_FREE(ltdb);
		return true;
	}

	if ((ltdb->num_share_entries != 0 ) && (num_share_entries == 0)) {
		/*
		 * This routine wiped all share entries, let
		 * share_mode_data_store() delete the record
		 */
		d->modified = true;
	}

	ltdb->num_share_entries = num_share_entries;
	ltdb->share_entries = share_entries;

	status = share_mode_data_ltdb_store(d, key, ltdb, NULL, 0);
	TALLOC_FREE(ltdb);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_data_ltdb_store failed: %s\n",
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
	const struct server_id *shared,
	const uint8_t *data,
	size_t datalen,
	void *private_data)
{
	struct share_mode_count_entries_state *state = private_data;
	struct locking_tdb_data ltdb = { 0 };
	bool ok;

	ok = locking_tdb_data_parse(&ltdb, data, datalen);
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
	struct share_mode_data *d,
	struct server_id pid,
	uint64_t share_file_id,
	void (*fn)(struct share_mode_entry *e,
		   size_t num_share_modes,
		   bool *modified,
		   void *private_data),
	void *private_data)
{
	TDB_DATA key = locking_key(&d->id);
	struct locking_tdb_data *ltdb = NULL;
	size_t idx;
	bool found = false;
	bool modified = false;
	struct share_mode_entry e;
	uint8_t *e_ptr = NULL;
	NTSTATUS status;
	bool ret = false;

	status = locking_tdb_data_fetch(key, talloc_tos(), &ltdb);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("locking_tdb_data_fetch failed: %s\n",
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

		if (ltdb->num_share_entries == 0) {
			/*
			 * Tell share_mode_lock_destructor() to delete
			 * the whole record
			 */
			d->modified = true;
		}

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

	status = share_mode_data_ltdb_store(d, key, ltdb, NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_data_ltdb_store failed: %s\n",
			nt_errstr(status));
		goto done;
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

bool del_share_mode_open_id(struct share_mode_lock *lck,
			    struct server_id open_pid,
			    uint64_t open_file_id)
{
	struct del_share_mode_state state = { .ok = false };
	struct share_mode_data *d = NULL;
	NTSTATUS status;
	bool ok;

	status = share_mode_lock_access_private_data(lck, &d);
	if (!NT_STATUS_IS_OK(status)) {
		/* Any error recovery possible here ? */
		return false;
	}

	ok = share_mode_entry_do(
		d,
		open_pid,
		open_file_id,
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

bool del_share_mode(struct share_mode_lock *lck, files_struct *fsp)
{
	struct server_id pid =
		messaging_server_id(fsp->conn->sconn->msg_ctx);
	bool ok;

	ok = del_share_mode_open_id(lck, pid, fh_get_gen_id(fsp->fh));
	if (!ok) {
		struct file_id id = share_mode_lock_file_id(lck);
		struct file_id_buf id_buf;
		DBG_ERR("share_mode_lock_access_private_data() failed for "
			"%s %s\n",
			file_id_str_buf(id, &id_buf),
			fsp_str_dbg(fsp));
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
	struct share_mode_data *d = NULL;
	NTSTATUS status;
	bool ok;

	status = share_mode_lock_access_private_data(lck, &d);
	if (!NT_STATUS_IS_OK(status)) {
		struct file_id id = share_mode_lock_file_id(lck);
		struct file_id_buf id_buf;
		/* Any error recovery possible here ? */
		DBG_ERR("share_mode_lock_access_private_data() failed for "
			"%s %s - %s\n",
			file_id_str_buf(id, &id_buf),
			fsp_str_dbg(fsp),
			nt_errstr(status));
		return false;
	}

	ok = share_mode_entry_do(
		d,
		messaging_server_id(fsp->conn->sconn->msg_ctx),
		fh_get_gen_id(fsp->fh),
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
	struct share_mode_data *d = NULL;
	NTSTATUS status;
	bool ok;

	status = share_mode_lock_access_private_data(lck, &d);
	if (!NT_STATUS_IS_OK(status)) {
		struct file_id id = share_mode_lock_file_id(lck);
		struct file_id_buf id_buf;
		/* Any error recovery possible here ? */
		DBG_ERR("share_mode_lock_access_private_data() failed for "
			"%s %s - %s\n",
			file_id_str_buf(id, &id_buf),
			fsp_str_dbg(fsp),
			nt_errstr(status));
		return false;
	}

	ok = share_mode_entry_do(
		d,
		messaging_server_id(fsp->conn->sconn->msg_ctx),
		fh_get_gen_id(fsp->fh),
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

	d->flags |= SHARE_MODE_LEASE_READ;
	d->modified = true;

	return true;
}

bool mark_share_mode_disconnected(struct share_mode_lock *lck,
				  struct files_struct *fsp)
{
	struct server_id disconnected_pid = { .pid = 0 };
	bool ok;

	if (fsp->op == NULL) {
		return false;
	}
	if (!fsp->op->global->durable) {
		return false;
	}

	server_id_set_disconnected(&disconnected_pid);

	ok = reset_share_mode_entry(
		lck,
		messaging_server_id(fsp->conn->sconn->msg_ctx),
		fh_get_gen_id(fsp->fh),
		disconnected_pid,
		UINT64_MAX,
		fsp->op->global->open_persistent_id);

	return ok;
}

bool reset_share_mode_entry(
	struct share_mode_lock *lck,
	struct server_id old_pid,
	uint64_t old_share_file_id,
	struct server_id new_pid,
	uint64_t new_mid,
	uint64_t new_share_file_id)
{
	struct file_id id = share_mode_lock_file_id(lck);
	struct share_mode_data *d = NULL;
	TDB_DATA key = locking_key(&id);
	struct locking_tdb_data *ltdb = NULL;
	struct share_mode_entry e = { .pid.pid = 0 };
	struct share_mode_entry_buf e_buf;
	size_t old_idx;
	size_t new_idx;
	bool found;
	NTSTATUS status;
	bool ret = false;
	bool ok;
	struct file_id_buf id_buf;
	struct server_id_buf pid_buf1;
	struct server_id_buf pid_buf2;
	size_t low_idx1, low_idx2, low_num;
	size_t mid_idx1, mid_idx2, mid_num;
	size_t high_idx1, high_idx2, high_num;
	TDB_DATA dbufs[4];
	size_t num_dbufs = 0;

	status = share_mode_lock_access_private_data(lck, &d);
	if (!NT_STATUS_IS_OK(status)) {
		/* Any error recovery possible here ? */
		DBG_ERR("share_mode_lock_access_private_data() failed for "
			"%s - %s\n",
			file_id_str_buf(id, &id_buf),
			nt_errstr(status));
		return false;
	}

	status = locking_tdb_data_fetch(key, talloc_tos(), &ltdb);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("locking_tdb_data_fetch failed: %s\n",
			nt_errstr(status));
		return false;
	}

	DBG_DEBUG("%s - num_share_modes=%zu\n",
		  file_id_str_buf(id, &id_buf),
		  ltdb->num_share_entries);

	new_idx = share_mode_entry_find(
		ltdb->share_entries,
		ltdb->num_share_entries,
		new_pid,
		new_share_file_id,
		&e,
		&found);
	if (found) {
		DBG_ERR("%s - num_share_modes=%zu "
			"found NEW[%s][%"PRIu64"]\n",
			file_id_str_buf(id, &id_buf),
			ltdb->num_share_entries,
			server_id_str_buf(new_pid, &pid_buf2),
			new_share_file_id);
		goto done;
	}

	old_idx = share_mode_entry_find(
		ltdb->share_entries,
		ltdb->num_share_entries,
		old_pid,
		old_share_file_id,
		&e,
		&found);
	if (!found) {
		DBG_WARNING("%s - num_share_modes=%zu "
			    "OLD[%s][%"PRIu64"] not found\n",
			    file_id_str_buf(id, &id_buf),
			    ltdb->num_share_entries,
			    server_id_str_buf(old_pid, &pid_buf1),
			    old_share_file_id);
		goto done;
	}
	DBG_DEBUG("%s - num_share_modes=%zu "
		  "OLD[%s][%"PRIu64"] => idx=%zu "
		  "NEW[%s][%"PRIu64"] => idx=%zu\n",
		  file_id_str_buf(id, &id_buf),
		  ltdb->num_share_entries,
		  server_id_str_buf(old_pid, &pid_buf1),
		  old_share_file_id,
		  old_idx,
		  server_id_str_buf(new_pid, &pid_buf2),
		  new_share_file_id,
		  new_idx);

	e.pid = new_pid;
	if (new_mid != UINT64_MAX) {
		e.op_mid = new_mid;
	}
	e.share_file_id = new_share_file_id;

	ok = share_mode_entry_put(&e, &e_buf);
	if (!ok) {
		DBG_WARNING("share_mode_entry_put failed\n");
		goto done;
	}

	/*
	 * The logic to remove the existing
	 * entry and add the new one at the
	 * same time is a bit complex because
	 * we need to keep the entries sorted.
	 *
	 * The following examples should catch
	 * the corner cases and show that
	 * the {low,mid,high}_{idx1,num} are
	 * correctly calculated and the new
	 * entry is put before or after the mid
	 * elements...
	 *
	 * 1.
	 *    0
	 *    1
	 *    2  <- old_idx
	 *          new_idx -> 3
	 *    3
	 *    4
	 *
	 *    low_idx1 = 0;
	 *    low_idx2 = MIN(old_idx, new_idx);  => 2
	 *    low_num = low_idx2 - low_idx1; => 2
	 *
	 *    if (new < old) => new; => no
	 *
	 *    mid_idx1 = MIN(old_idx+1, new_idx); => 3
	 *    mid_idx2 = MAX(old_idx, new_idx); => 3
	 *    mid_num = mid_idx2 - mid_idx1; => 0
	 *
	 *    if (new >= old) => new; => yes
	 *
	 *    high_idx1 = MAX(old_idx+1, new_idx); => 3
	 *    high_idx2 = num_share_entries; => 5
	 *    high_num = high_idx2 - high_idx1 = 2
	 *
	 * 2.
	 *    0
	 *    1
	 *          new_idx -> 2
	 *    2  <- old_idx
	 *    3
	 *    4
	 *
	 *    low_idx1 = 0;
	 *    low_idx2 = MIN(old_idx, new_idx);  => 2
	 *    low_num = low_idx2 - low_idx1; => 2
	 *
	 *    if (new < old) => new; => no
	 *
	 *    mid_idx1 = MIN(old_idx+1, new_idx); => 2
	 *    mid_idx2 = MAX(old_idx, new_idx); => 2
	 *    mid_num = mid_idx2 - mid_idx1; => 0
	 *
	 *    if (new >= old) => new; => yes
	 *
	 *    high_idx1 = MAX(old_idx+1, new_idx); => 3
	 *    high_idx2 = num_share_entries; => 5
	 *    high_num = high_idx2 - high_idx1 = 2
	 *
	 * 3.
	 *    0
	 *    1  <- old_idx
	 *    2
	 *          new_idx -> 3
	 *    3
	 *    4
	 *
	 *    low_idx1 = 0;
	 *    low_idx2 = MIN(old_idx, new_idx);  => 1
	 *    low_num = low_idx2 - low_idx1; => 1
	 *
	 *    if (new < old) => new; => no
	 *
	 *    mid_idx1 = MIN(old_idx+1, new_idx); => 2
	 *    mid_idx2 = MAX(old_idx, new_idx); => 3
	 *    mid_num = mid_idx2 - mid_idx1; => 1
	 *
	 *    if (new >= old) => new; => yes
	 *
	 *    high_idx1 = MAX(old_idx+1, new_idx); => 3
	 *    high_idx2 = num_share_entries; => 5
	 *    high_num = high_idx2 - high_idx1 = 2
	 *
	 * 4.
	 *    0
	 *          new_idx -> 1
	 *    1
	 *    2
	 *    3  <- old_idx
	 *    4
	 *
	 *    low_idx1 = 0;
	 *    low_idx2 = MIN(old_idx, new_idx);  => 1
	 *    low_num = low_idx2 - low_idx1; => 1
	 *
	 *    if (new < old) => new; => yes
	 *
	 *    mid_idx1 = MIN(old_idx+1, new_idx); => 1
	 *    mid_idx2 = MAX(old_idx, new_idx); => 3
	 *    mid_num = mid_idx2 - mid_idx1; => 2
	 *
	 *    if (new >= old) => new; => no
	 *
	 *    high_idx1 = MAX(old_idx+1, new_idx); => 4
	 *    high_idx2 = num_share_entries; => 5
	 *    high_num = high_idx2 - high_idx1 = 1
	 *
	 * 5.
	 *          new_idx -> 0
	 *    0
	 *    1
	 *    2
	 *    3
	 *    4  <- old_idx
	 *
	 *    low_idx1 = 0;
	 *    low_idx2 = MIN(old_idx, new_idx);  => 0
	 *    low_num = low_idx2 - low_idx1; => 0
	 *
	 *    if (new < old) => new; => yes
	 *
	 *    mid_idx1 = MIN(old_idx+1, new_idx); => 0
	 *    mid_idx2 = MAX(old_idx, new_idx); => 4
	 *    mid_num = mid_idx2 - mid_idx1; => 4
	 *
	 *    if (new >= old) => new; => no
	 *
	 *    high_idx1 = MAX(old_idx+1, new_idx); => 5
	 *    high_idx2 = num_share_entries; => 5
	 *    high_num = high_idx2 - high_idx1 = 0
	 *
	 * 6.
	 *          new_idx -> 0
	 *    0 <- old_idx
	 *
	 *    low_idx1 = 0;
	 *    low_idx2 = MIN(old_idx, new_idx);  => 0
	 *    low_num = low_idx2 - low_idx1; => 0
	 *
	 *    if (new < old) => new; => no
	 *
	 *    mid_idx1 = MIN(old_idx+1, new_idx); => 0
	 *    mid_idx2 = MAX(old_idx, new_idx); => 0
	 *    mid_num = mid_idx2 - mid_idx1; => 0
	 *
	 *    if (new >= old) => new; => yes
	 *
	 *    high_idx1 = MAX(old_idx+1, new_idx); => 1
	 *    high_idx2 = num_share_entries; => 1
	 *    high_num = high_idx2 - high_idx1 = 0
	 *
	 * 7.
	 *    0 <- old_idx
	 *          new_idx -> 1
	 *
	 *    low_idx1 = 0;
	 *    low_idx2 = MIN(old_idx, new_idx);  => 0
	 *    low_num = low_idx2 - low_idx1; => 0
	 *
	 *    if (new < old) => new; => no
	 *
	 *    mid_idx1 = MIN(old_idx+1, new_idx); => 1
	 *    mid_idx2 = MAX(old_idx, new_idx); => 1
	 *    mid_num = mid_idx2 - mid_idx1; => 0
	 *
	 *    if (new >= old) => new; => yes
	 *
	 *    high_idx1 = MAX(old_idx+1, new_idx); => 1
	 *    high_idx2 = num_share_entries; => 1
	 *    high_num = high_idx2 - high_idx1 = 0
	 */
	low_idx1 = 0;
	low_idx2 = MIN(old_idx, new_idx);
	low_num = low_idx2 - low_idx1;
	mid_idx1 = MIN(old_idx+1, new_idx);
	mid_idx2 = MAX(old_idx, new_idx);
	mid_num = mid_idx2 - mid_idx1;
	high_idx1 = MAX(old_idx+1, new_idx);
	high_idx2 = ltdb->num_share_entries;
	high_num = high_idx2 - high_idx1;

	if (low_num != 0) {
		dbufs[num_dbufs] = (TDB_DATA) {
			.dptr = discard_const_p(uint8_t, ltdb->share_entries) +
				low_idx1 * SHARE_MODE_ENTRY_SIZE,
			.dsize = low_num * SHARE_MODE_ENTRY_SIZE,
		};
		num_dbufs += 1;
	}

	if (new_idx < old_idx) {
		dbufs[num_dbufs] = (TDB_DATA) {
			.dptr = e_buf.buf, .dsize = SHARE_MODE_ENTRY_SIZE,
		};
		num_dbufs += 1;
	}

	if (mid_num != 0) {
		dbufs[num_dbufs] = (TDB_DATA) {
			.dptr = discard_const_p(uint8_t, ltdb->share_entries) +
				mid_idx1 * SHARE_MODE_ENTRY_SIZE,
			.dsize = mid_num * SHARE_MODE_ENTRY_SIZE,
		};
		num_dbufs += 1;
	}

	if (new_idx >= old_idx) {
		dbufs[num_dbufs] = (TDB_DATA) {
			.dptr = e_buf.buf, .dsize = SHARE_MODE_ENTRY_SIZE,
		};
		num_dbufs += 1;
	}

	if (high_num != 0) {
		dbufs[num_dbufs] = (TDB_DATA) {
			.dptr = discard_const_p(uint8_t, ltdb->share_entries) +
				high_idx1 * SHARE_MODE_ENTRY_SIZE,
			.dsize = high_num * SHARE_MODE_ENTRY_SIZE,
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

	/*
	 * We completely rewrite the entries...
	 */
	ltdb->share_entries = NULL;
	ltdb->num_share_entries = 0;
	d->modified = true;

	status = share_mode_data_ltdb_store(d, key, ltdb, dbufs, num_dbufs);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_data_ltdb_store failed: %s\n",
			nt_errstr(status));
		goto done;
	}

	ret = true;
done:
	TALLOC_FREE(ltdb);
	return ret;
}

struct share_mode_do_locked_vfs_denied_state {
	struct file_id id;
	share_mode_do_locked_vfs_fn_t fn;
	void *private_data;
	const char *location;
	NTSTATUS status;
};

static void share_mode_do_locked_vfs_denied_fn(struct g_lock_lock_cb_state *glck,
					       void *cb_private)
{
	struct share_mode_do_locked_vfs_denied_state *state =
		(struct share_mode_do_locked_vfs_denied_state *)cb_private;
	struct smb_vfs_deny_state vfs_deny = {};
	struct share_mode_lock lck;

	if (glck != NULL) {
		current_share_mode_glck = glck;
	}

	state->status = get_share_mode_lock_internal(state->id,
						     NULL,  /* servicepath */
						     NULL,  /* smb_fname */
						     &lck);
	if (!NT_STATUS_IS_OK(state->status)) {
		DBG_GET_SHARE_MODE_LOCK(state->status,
			"get_share_mode_lock_internal failed: %s\n",
			nt_errstr(state->status));
		if (glck != NULL) {
			g_lock_lock_cb_unlock(glck);
			current_share_mode_glck = NULL;
		}
		return;
	}

	_smb_vfs_deny_push(&vfs_deny, state->location);
	state->fn(&lck, state->private_data);
	_smb_vfs_deny_pop(&vfs_deny, state->location);

	state->status = put_share_mode_lock_internal(&lck);
	if (!NT_STATUS_IS_OK(state->status)) {
		DBG_ERR("put_share_mode_lock_internal failed: %s\n",
			nt_errstr(state->status));
		smb_panic("put_share_mode_lock_internal failed\n");
		return;
	}

	if (glck != NULL) {
		g_lock_lock_cb_unlock(glck);
		current_share_mode_glck = NULL;
	}
	return;
}

/**
 * @brief Run @fn protected with G_LOCK_WRITE in the given file_id
 *
 * @fn is NOT allowed to call SMB_VFS_* or similar functions,
 * which may block for some time in the kernel.
 *
 * There must be at least one share_mode_entry, otherwise
 * NT_STATUS_NOT_FOUND is returned.
 *
 * @param[in]  id           The key for the share_mode record.
 * @param[in]  fn           The function to run under the g_lock.
 * @param[in]  private_date A private pointer passed to @fn.
 */
NTSTATUS _share_mode_do_locked_vfs_denied(
	struct file_id id,
	share_mode_do_locked_vfs_fn_t fn,
	void *private_data,
	const char *location)
{
	struct share_mode_do_locked_vfs_denied_state state = {
		.id = id,
		.fn = fn,
		.private_data = private_data,
		.location = location,
	};

	if (share_mode_lock_key_refcount == 0) {
		TDB_DATA key = locking_key(&id);
		NTSTATUS status;

		share_mode_lock_skip_g_lock = true;
		status = g_lock_lock(
			lock_ctx,
			key,
			G_LOCK_WRITE,
			(struct timeval) { .tv_sec = 3600 },
			share_mode_do_locked_vfs_denied_fn,
			&state);
		share_mode_lock_skip_g_lock = false;
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("g_lock_lock failed: %s\n",
				  nt_errstr(status));
			return status;
		}
		return state.status;
	}

	share_mode_do_locked_vfs_denied_fn(NULL, &state);

	return state.status;
}

/**
 * @brief Run @fn protected with G_LOCK_WRITE in the given file_id
 *
 * @fn is allowed to call SMB_VFS_* or similar functions,
 * which may block for some time in the kernel.
 *
 * There must be at least one share_mode_entry, otherwise
 * NT_STATUS_NOT_FOUND is returned.
 *
 * @param[in]  id           The key for the share_mode record.
 * @param[in]  fn           The function to run under the g_lock.
 * @param[in]  private_date A private pointer passed to @fn.
 */
NTSTATUS _share_mode_do_locked_vfs_allowed(
	struct file_id id,
	share_mode_do_locked_vfs_fn_t fn,
	void *private_data,
	const char *location)
{
	struct share_mode_lock lck;
	NTSTATUS status;

	smb_vfs_assert_allowed();

	status = get_share_mode_lock_internal(id,
					      NULL,  /* servicepath */
					      NULL,  /* smb_fname */
					      &lck);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_GET_SHARE_MODE_LOCK(status,
			"get_share_mode_lock_internal failed: %s\n",
			nt_errstr(status));
		return status;
	}

	fn(&lck, private_data);

	status = put_share_mode_lock_internal(&lck);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("put_share_mode_lock_internal failed: %s\n",
			nt_errstr(status));
		smb_panic("put_share_mode_lock_internal failed\n");
		return status;
	}

	return NT_STATUS_OK;
}

struct share_mode_entry_prepare_lock_state {
	struct file_id id;
	const char *servicepath;
	const struct smb_filename *smb_fname;
	share_mode_entry_prepare_lock_fn_t fn;
	void *private_data;
	const char *location;
	bool keep_locked;
	struct share_mode_lock *lck;
	NTSTATUS status;
};

static void share_mode_entry_prepare_lock_fn(struct g_lock_lock_cb_state *glck,
					     void *cb_private)
{
	struct share_mode_entry_prepare_lock_state *state =
		(struct share_mode_entry_prepare_lock_state *)cb_private;
	struct smb_vfs_deny_state vfs_deny = {};

	SMB_ASSERT(glck != NULL);
	current_share_mode_glck = glck;

	state->status = get_share_mode_lock_internal(state->id,
						     state->servicepath,
						     state->smb_fname,
						     state->lck);
	if (!NT_STATUS_IS_OK(state->status)) {
		/* no DBG_GET_SHARE_MODE_LOCK here! */
		DBG_ERR("get_share_mode_lock_internal failed: %s\n",
			nt_errstr(state->status));
		g_lock_lock_cb_unlock(glck);
		current_share_mode_glck = NULL;
		return;
	}

	_smb_vfs_deny_push(&vfs_deny, state->location);
	state->fn(state->lck, &state->keep_locked, state->private_data);
	_smb_vfs_deny_pop(&vfs_deny, state->location);

	if (state->keep_locked) {
		current_share_mode_glck = NULL;
		return;
	}

	state->status = put_share_mode_lock_internal(state->lck);
	if (!NT_STATUS_IS_OK(state->status)) {
		DBG_ERR("put_share_mode_lock_internal failed: %s\n",
			nt_errstr(state->status));
		smb_panic("put_share_mode_lock_internal failed\n");
		return;
	}

	g_lock_lock_cb_unlock(glck);
	current_share_mode_glck = NULL;
	return;
}

NTSTATUS _share_mode_entry_prepare_lock(
	struct share_mode_entry_prepare_state *prepare_state,
	struct file_id id,
	const char *servicepath,
	const struct smb_filename *smb_fname,
	share_mode_entry_prepare_lock_fn_t fn,
	void *private_data,
	const char *location)
{
	struct share_mode_entry_prepare_lock_state state = {
		.id = id,
		.servicepath = servicepath,
		.smb_fname = smb_fname,
		.fn = fn,
		.private_data = private_data,
		.location = location,
	};
	TDB_DATA key = locking_key(&id);
	NTSTATUS status;

	SMB_ASSERT(share_mode_lock_key_refcount == 0);

	SMB_ASSERT(__SHARE_MODE_LOCK_SPACE >= sizeof(struct share_mode_lock));

	*prepare_state = (struct share_mode_entry_prepare_state) {
		.__fid = id,
		.__lck_ptr = &prepare_state->__lck_space,
	};

	state.lck = prepare_state->__lck_ptr;

	share_mode_lock_skip_g_lock = true;
	status = g_lock_lock(
		lock_ctx,
		key,
		G_LOCK_WRITE,
		(struct timeval) { .tv_sec = 3600 },
		share_mode_entry_prepare_lock_fn,
		&state);
	share_mode_lock_skip_g_lock = false;
	if (!state.keep_locked) {
		prepare_state->__lck_ptr = NULL;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("g_lock_lock failed: %s\n",
			  nt_errstr(status));
		return status;
	}

	return state.status;
}

struct share_mode_entry_prepare_unlock_state {
	struct file_id id;
	share_mode_entry_prepare_unlock_fn_t fn;
	void *private_data;
	const char *location;
	struct share_mode_lock *lck;
	NTSTATUS status;
};

static void share_mode_entry_prepare_unlock_existing_fn(
	struct share_mode_entry_prepare_unlock_state *state)
{
	if (state->fn != NULL) {
		struct smb_vfs_deny_state vfs_deny = {};

		_smb_vfs_deny_push(&vfs_deny, state->location);
		state->fn(state->lck, state->private_data);
		_smb_vfs_deny_pop(&vfs_deny, state->location);
	}

	state->status = put_share_mode_lock_internal(state->lck);
	if (!NT_STATUS_IS_OK(state->status)) {
		DBG_ERR("put_share_mode_lock_internal failed: %s\n",
			nt_errstr(state->status));
		smb_panic("put_share_mode_lock_internal failed\n");
		return;
	}

	return;
}

static void share_mode_entry_prepare_unlock_relock_fn(struct g_lock_lock_cb_state *glck,
						      void *cb_private)
{
	struct share_mode_entry_prepare_unlock_state *state =
		(struct share_mode_entry_prepare_unlock_state *)cb_private;
	struct smb_vfs_deny_state vfs_deny = {};

	SMB_ASSERT(glck != NULL);
	current_share_mode_glck = glck;

	state->status = get_share_mode_lock_internal(state->id,
						     NULL,  /* servicepath */
						     NULL,  /* smb_fname */
						     state->lck);
	if (!NT_STATUS_IS_OK(state->status)) {
		/* no DBG_GET_SHARE_MODE_LOCK here! */
		DBG_ERR("get_share_mode_lock_internal failed: %s\n",
			nt_errstr(state->status));
		g_lock_lock_cb_unlock(glck);
		current_share_mode_glck = NULL;
		return;
	}

	_smb_vfs_deny_push(&vfs_deny, state->location);
	state->fn(state->lck, state->private_data);
	_smb_vfs_deny_pop(&vfs_deny, state->location);

	state->status = put_share_mode_lock_internal(state->lck);
	if (!NT_STATUS_IS_OK(state->status)) {
		DBG_ERR("put_share_mode_lock_internal failed: %s\n",
			nt_errstr(state->status));
		smb_panic("put_share_mode_lock_internal failed\n");
		return;
	}

	g_lock_lock_cb_unlock(glck);
	current_share_mode_glck = NULL;
	return;
}

NTSTATUS _share_mode_entry_prepare_unlock(
	struct share_mode_entry_prepare_state *prepare_state,
	share_mode_entry_prepare_unlock_fn_t fn,
	void *private_data,
	const char *location)
{
	struct share_mode_entry_prepare_unlock_state state = {
		.id = prepare_state->__fid,
		.fn = fn,
		.private_data = private_data,
		.location = location,
	};
	TDB_DATA key = locking_key(&prepare_state->__fid);
	NTSTATUS status;

	if (prepare_state->__lck_ptr != NULL) {
		/*
		 * With an existing lock, we just run the unlock prepare
		 * function following by the unlock.
		 */

		SMB_ASSERT(share_mode_lock_key_refcount == 1);

		state.lck = prepare_state->__lck_ptr;
		prepare_state->__lck_ptr = NULL;

		share_mode_entry_prepare_unlock_existing_fn(&state);
		return state.status;
	}

	/*
	 * No existing lock, which means
	 * _share_mode_entry_prepare_lock() didn't steal
	 * the lock...
	 */
	SMB_ASSERT(share_mode_lock_key_refcount == 0);

	if (fn == NULL) {
		/*
		 * Without an existing lock and without
		 * a prepare function there's nothing to
		 * do...
		 */
		return NT_STATUS_OK;
	}

	/*
	 * In order to run the unlock prepare function
	 * we need to relock the entry.
	 */
	state.lck = &prepare_state->__lck_space;

	share_mode_lock_skip_g_lock = true;
	status = g_lock_lock(
		lock_ctx,
		key,
		G_LOCK_WRITE,
		(struct timeval) { .tv_sec = 3600 },
		share_mode_entry_prepare_unlock_relock_fn,
		&state);
	share_mode_lock_skip_g_lock = false;
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("g_lock_lock failed: %s\n",
			nt_errstr(status));
		return status;
	}

	return state.status;
}
