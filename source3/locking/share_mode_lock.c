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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

#define NO_LOCKING_COUNT (-1)

/* the locking database handle */
static struct db_context *lock_db;

static bool locking_init_internal(bool read_only)
{
	brl_init(read_only);

	if (lock_db)
		return True;

	lock_db = db_open(NULL, lock_path("locking.tdb"),
			  SMB_OPEN_DATABASE_TDB_HASH_SIZE,
			  TDB_DEFAULT|TDB_VOLATILE|TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH,
			  read_only?O_RDONLY:O_RDWR|O_CREAT, 0644,
			  DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);

	if (!lock_db) {
		DEBUG(0,("ERROR: Failed to initialise locking database\n"));
		return False;
	}

	if (!posix_locking_init(read_only))
		return False;

	dbwrap_watch_db(lock_db, server_messaging_context());

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
 Get all share mode entries for a dev/inode pair.
********************************************************************/

static struct share_mode_data *parse_share_modes(TALLOC_CTX *mem_ctx,
						 const TDB_DATA dbuf)
{
	struct share_mode_data *d;
	enum ndr_err_code ndr_err;
	uint32_t i;
	DATA_BLOB blob;

	d = talloc(mem_ctx, struct share_mode_data);
	if (d == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	blob.data = dbuf.dptr;
	blob.length = dbuf.dsize;

	ndr_err = ndr_pull_struct_blob_all(
		&blob, d, d, (ndr_pull_flags_fn_t)ndr_pull_share_mode_data);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1, ("ndr_pull_share_mode_lock failed: %s\n",
			  ndr_errstr(ndr_err)));
		goto fail;
	}

	/*
	 * Initialize the values that are [skip] in the idl. The NDR code does
	 * not initialize them.
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
		goto done;
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

 done:

	return 0;
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
		d = parse_share_modes(mem_ctx, value);
	}

	if (d == NULL) {
		DEBUG(5, ("get_share_mode_lock_internal: "
			"Could not get share mode lock\n"));
		TALLOC_FREE(rec);
		return NULL;
	}
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

static void fetch_share_mode_unlocked_parser(
	TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct share_mode_lock *lck = talloc_get_type_abort(
		private_data, struct share_mode_lock);

	lck->data = parse_share_modes(lck, data);
}

/*******************************************************************
 Get a share_mode_lock without locking the database or reference
 counting. Used by smbstatus to display existing share modes.
********************************************************************/

struct share_mode_lock *fetch_share_mode_unlocked(TALLOC_CTX *mem_ctx,
						  struct file_id id)
{
	struct share_mode_lock *lck;
	TDB_DATA key = locking_key(&id);
	NTSTATUS status;

	lck = talloc(mem_ctx, struct share_mode_lock);
	if (lck == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}
	status = dbwrap_parse_record(
		lock_db, key, fetch_share_mode_unlocked_parser, lck);
	if (!NT_STATUS_IS_OK(status) ||
	    (lck->data == NULL)) {
		TALLOC_FREE(lck);
		return NULL;
	}
	return lck;
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
	if (DEBUGLEVEL > 10) {
		DEBUG(11, ("parse_share_modes:\n"));
		NDR_PRINT_DEBUG(share_mode_data, d);
	}
	for (i=0; i<d->num_share_modes; i++) {
		d->share_modes[i].stale = false; /* [skip] in idl */
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
		  const char *service_path, const char *base_name,
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
				data->servicepath, data->base_name,
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
				 const char *, const char *, void *),
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
				  server_id_str(frame, &entry->pid)));
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
