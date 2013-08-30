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
			  lp_open_files_db_hash_size(),
			  TDB_DEFAULT|TDB_VOLATILE|TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH,
			  read_only?O_RDONLY:O_RDWR|O_CREAT, 0644,
			  DBWRAP_LOCK_ORDER_1);

	if (!lock_db) {
		DEBUG(0,("ERROR: Failed to initialise locking database\n"));
		return False;
	}

	if (!posix_locking_init(read_only))
		return False;

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

	ndr_err = ndr_pull_struct_blob(
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
		d->share_modes[i].stale = false;
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
	uint32_t i;

	if (DEBUGLEVEL >= 10) {
		DEBUG(10, ("unparse_share_modes:\n"));
		NDR_PRINT_DEBUG(share_mode_data, d);
	}

	i = 0;
	while (i < d->num_share_modes) {
		if (d->share_modes[i].stale) {
			/*
			 * Remove the stale entries before storing
			 */
			struct share_mode_entry *m = d->share_modes;
			m[i] = m[d->num_share_modes-1];
			d->num_share_modes -= 1;
		} else {
			i += 1;
		}
	}

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

static int the_lock_destructor(struct share_mode_lock *l)
{
	the_lock = NULL;
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
	TALLOC_CTX *frame = talloc_stackframe();

	struct share_mode_lock *lck;

	if (the_lock == NULL) {
		the_lock = get_share_mode_lock_internal(
			frame, id, servicepath, smb_fname, old_write_time);
		if (the_lock == NULL) {
			goto fail;
		}
		talloc_set_destructor(the_lock, the_lock_destructor);
	}
	if (!file_id_equal(&the_lock->data->id, &id)) {
		DEBUG(1, ("Can not lock two share modes simultaneously\n"));
		goto fail;
	}
	lck = talloc(mem_ctx, struct share_mode_lock);
	if (lck == NULL) {
		DEBUG(1, ("talloc failed\n"));
		goto fail;
	}
	if (talloc_reference(lck, the_lock) == NULL) {
		DEBUG(1, ("talloc_reference failed\n"));
		goto fail;
	}
	lck->data = the_lock->data;
	TALLOC_FREE(frame);
	return lck;
fail:
	TALLOC_FREE(frame);
	return NULL;
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
	TDB_DATA data;
	NTSTATUS status;

	status = dbwrap_fetch(lock_db, talloc_tos(), key, &data);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("Could not fetch share entry\n"));
		return NULL;
	}
	if (data.dptr == NULL) {
		return NULL;
	}
	lck = talloc(mem_ctx, struct share_mode_lock);
	if (lck == NULL) {
		TALLOC_FREE(data.dptr);
		return NULL;
	}
	lck->data = parse_share_modes(lck, data);
	TALLOC_FREE(data.dptr);
	if (lck->data == NULL) {
		TALLOC_FREE(lck);
		return NULL;
	}
	return lck;
}

struct forall_state {
	void (*fn)(const struct share_mode_entry *entry,
		   const char *sharepath,
		   const char *fname,
		   void *private_data);
	void *private_data;
};

static int traverse_fn(struct db_record *rec, void *_state)
{
	struct forall_state *state = (struct forall_state *)_state;
	uint32_t i;
	TDB_DATA key;
	TDB_DATA value;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	struct share_mode_data *d;

	key = dbwrap_record_get_key(rec);
	value = dbwrap_record_get_value(rec);

	/* Ensure this is a locking_key record. */
	if (key.dsize != sizeof(struct file_id))
		return 0;

	d = talloc(talloc_tos(), struct share_mode_data);
	if (d == NULL) {
		return 0;
	}

	blob.data = value.dptr;
	blob.length = value.dsize;

	ndr_err = ndr_pull_struct_blob(
		&blob, d, d, (ndr_pull_flags_fn_t)ndr_pull_share_mode_data);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1, ("ndr_pull_share_mode_lock failed\n"));
		return 0;
	}
	for (i=0; i<d->num_share_modes; i++) {
		state->fn(&d->share_modes[i],
			  d->servicepath, d->base_name,
			  state->private_data);
	}
	TALLOC_FREE(d);

	return 0;
}

/*******************************************************************
 Call the specified function on each entry under management by the
 share mode system.
********************************************************************/

int share_mode_forall(void (*fn)(const struct share_mode_entry *, const char *,
				 const char *, void *),
		      void *private_data)
{
	struct forall_state state;
	NTSTATUS status;
	int count;

	if (lock_db == NULL)
		return 0;

	state.fn = fn;
	state.private_data = private_data;

	status = dbwrap_traverse_read(lock_db, traverse_fn, (void *)&state,
				      &count);

	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	} else {
		return count;
	}
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
	data->modified = true;

	ret = true;
done:
	talloc_free(frame);
	return ret;
}
