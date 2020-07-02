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
#include "locking/proto.h"
#include "smbd/globals.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "../libcli/security/security.h"
#include "serverid.h"
#include "messages.h"
#include "util_tdb.h"
#include "../librpc/gen_ndr/ndr_open_files.h"
#include "librpc/gen_ndr/ndr_file_id.h"
#include "librpc/gen_ndr/ndr_leases_db.h"
#include "locking/leases_db.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

#define NO_LOCKING_COUNT (-1)

/****************************************************************************
 Debugging aids :-).
****************************************************************************/

const char *lock_type_name(enum brl_type lock_type)
{
	switch (lock_type) {
		case READ_LOCK:
			return "READ";
		case WRITE_LOCK:
			return "WRITE";
		default:
			return "other";
	}
}

const char *lock_flav_name(enum brl_flavour lock_flav)
{
	return (lock_flav == WINDOWS_LOCK) ? "WINDOWS_LOCK" : "POSIX_LOCK";
}

/****************************************************************************
 Utility function called to see if a file region is locked.
 Called in the read/write codepath.
****************************************************************************/

void init_strict_lock_struct(files_struct *fsp,
				uint64_t smblctx,
				br_off start,
				br_off size,
				enum brl_type lock_type,
				struct lock_struct *plock)
{
	SMB_ASSERT(lock_type == READ_LOCK || lock_type == WRITE_LOCK);

	plock->context.smblctx = smblctx;
        plock->context.tid = fsp->conn->cnum;
        plock->context.pid = messaging_server_id(fsp->conn->sconn->msg_ctx);
        plock->start = start;
        plock->size = size;
        plock->fnum = fsp->fnum;
        plock->lock_type = lock_type;
        plock->lock_flav = lp_posix_cifsu_locktype(fsp);
}

bool strict_lock_check_default(files_struct *fsp, struct lock_struct *plock)
{
	struct byte_range_lock *br_lck;
	int strict_locking = lp_strict_locking(fsp->conn->params);
	bool ret = False;

	if (plock->size == 0) {
		return True;
	}

	if (!lp_locking(fsp->conn->params) || !strict_locking) {
		return True;
	}

	if (strict_locking == Auto) {
		uint32_t lease_type = fsp_lease_type(fsp);

		if ((lease_type & SMB2_LEASE_READ) &&
		     (plock->lock_type == READ_LOCK))
		{
			DBG_DEBUG("optimisation - read lease on file %s\n",
				  fsp_str_dbg(fsp));
			return true;
		}

		if ((lease_type & SMB2_LEASE_WRITE) &&
		     (plock->lock_type == WRITE_LOCK))
		{
			DBG_DEBUG("optimisation - write lease on file %s\n",
				  fsp_str_dbg(fsp));
			return true;
		}
	}

	br_lck = brl_get_locks_readonly(fsp);
	if (!br_lck) {
		return true;
	}
	ret = brl_locktest(br_lck, plock);

	if (!ret) {
		/*
		 * We got a lock conflict. Retry with rw locks to enable
		 * autocleanup. This is the slow path anyway.
		 */
		br_lck = brl_get_locks(talloc_tos(), fsp);
		if (br_lck == NULL) {
			return true;
		}
		ret = brl_locktest(br_lck, plock);
		TALLOC_FREE(br_lck);
	}

	DEBUG(10, ("strict_lock_default: flavour = %s brl start=%ju "
		   "len=%ju %s for fnum %ju file %s\n",
		   lock_flav_name(plock->lock_flav),
		   (uintmax_t)plock->start, (uintmax_t)plock->size,
		   ret ? "unlocked" : "locked",
		   (uintmax_t)plock->fnum, fsp_str_dbg(fsp)));

	return ret;
}

/****************************************************************************
 Find out if a lock could be granted - return who is blocking us if we can't.
****************************************************************************/

NTSTATUS query_lock(files_struct *fsp,
			uint64_t *psmblctx,
			uint64_t *pcount,
			uint64_t *poffset,
			enum brl_type *plock_type,
			enum brl_flavour lock_flav)
{
	struct byte_range_lock *br_lck = NULL;

	if (!fsp->fsp_flags.can_lock) {
		return fsp->fsp_flags.is_directory ?
			NT_STATUS_INVALID_DEVICE_REQUEST :
			NT_STATUS_INVALID_HANDLE;
	}

	if (!lp_locking(fsp->conn->params)) {
		return NT_STATUS_OK;
	}

	br_lck = brl_get_locks_readonly(fsp);
	if (!br_lck) {
		return NT_STATUS_NO_MEMORY;
	}

	return brl_lockquery(br_lck,
			psmblctx,
			messaging_server_id(fsp->conn->sconn->msg_ctx),
			poffset,
			pcount,
			plock_type,
			lock_flav);
}

static void increment_current_lock_count(files_struct *fsp,
    enum brl_flavour lock_flav)
{
	if (lock_flav == WINDOWS_LOCK &&
	    fsp->current_lock_count != NO_LOCKING_COUNT) {
		/* blocking ie. pending, locks also count here,
		 * as this is an efficiency counter to avoid checking
		 * the lock db. on close. JRA. */

		fsp->current_lock_count++;
	} else {
		/* Notice that this has had a POSIX lock request.
		 * We can't count locks after this so forget them.
		 */
		fsp->current_lock_count = NO_LOCKING_COUNT;
	}
}

static void decrement_current_lock_count(files_struct *fsp,
    enum brl_flavour lock_flav)
{
	if (lock_flav == WINDOWS_LOCK &&
	    fsp->current_lock_count != NO_LOCKING_COUNT) {
		SMB_ASSERT(fsp->current_lock_count > 0);
		fsp->current_lock_count--;
	}
}

/****************************************************************************
 Utility function called by locking requests.
****************************************************************************/

struct do_lock_state {
	struct files_struct *fsp;
	TALLOC_CTX *req_mem_ctx;
	const struct GUID *req_guid;
	uint64_t smblctx;
	uint64_t count;
	uint64_t offset;
	enum brl_type lock_type;
	enum brl_flavour lock_flav;

	struct server_id blocker_pid;
	uint64_t blocker_smblctx;
	NTSTATUS status;
};

static void do_lock_fn(
	const uint8_t *buf,
	size_t buflen,
	bool *modified_dependent,
	void *private_data)
{
	struct do_lock_state *state = private_data;
	struct byte_range_lock *br_lck = NULL;

	br_lck = brl_get_locks_for_locking(talloc_tos(),
					   state->fsp,
					   state->req_mem_ctx,
					   state->req_guid);
	if (br_lck == NULL) {
		state->status = NT_STATUS_NO_MEMORY;
		return;
	}

	state->status = brl_lock(
		br_lck,
		state->smblctx,
		messaging_server_id(state->fsp->conn->sconn->msg_ctx),
		state->offset,
		state->count,
		state->lock_type,
		state->lock_flav,
		&state->blocker_pid,
		&state->blocker_smblctx);

	TALLOC_FREE(br_lck);
}

NTSTATUS do_lock(files_struct *fsp,
		 TALLOC_CTX *req_mem_ctx,
		 const struct GUID *req_guid,
		 uint64_t smblctx,
		 uint64_t count,
		 uint64_t offset,
		 enum brl_type lock_type,
		 enum brl_flavour lock_flav,
		 struct server_id *pblocker_pid,
		 uint64_t *psmblctx)
{
	struct do_lock_state state = {
		.fsp = fsp,
		.req_mem_ctx = req_mem_ctx,
		.req_guid = req_guid,
		.smblctx = smblctx,
		.count = count,
		.offset = offset,
		.lock_type = lock_type,
		.lock_flav = lock_flav,
	};
	NTSTATUS status;

	/* silently return ok on print files as we don't do locking there */
	if (fsp->print_file) {
		return NT_STATUS_OK;
	}

	if (!fsp->fsp_flags.can_lock) {
		if (fsp->fsp_flags.is_directory) {
			return NT_STATUS_INVALID_DEVICE_REQUEST;
		}
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!lp_locking(fsp->conn->params)) {
		return NT_STATUS_OK;
	}

	/* NOTE! 0 byte long ranges ARE allowed and should be stored  */

	DBG_DEBUG("lock flavour %s lock type %s start=%"PRIu64" len=%"PRIu64" "
		  "requested for %s file %s\n",
		  lock_flav_name(lock_flav),
		  lock_type_name(lock_type),
		  offset,
		  count,
		  fsp_fnum_dbg(fsp),
		  fsp_str_dbg(fsp));

	status = share_mode_do_locked(fsp->file_id, do_lock_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("share_mode_do_locked returned %s\n",
			  nt_errstr(status));
		return status;
	}

	if (psmblctx != NULL) {
		*psmblctx = state.blocker_smblctx;
	}
	if (pblocker_pid != NULL) {
		*pblocker_pid = state.blocker_pid;
	}

	DBG_DEBUG("returning status=%s\n", nt_errstr(state.status));

	increment_current_lock_count(fsp, lock_flav);

	return state.status;
}

/****************************************************************************
 Utility function called by unlocking requests.
****************************************************************************/

NTSTATUS do_unlock(files_struct *fsp,
		   uint64_t smblctx,
		   uint64_t count,
		   uint64_t offset,
		   enum brl_flavour lock_flav)
{
	bool ok = False;
	struct byte_range_lock *br_lck = NULL;

	if (!fsp->fsp_flags.can_lock) {
		return fsp->fsp_flags.is_directory ?
			NT_STATUS_INVALID_DEVICE_REQUEST :
			NT_STATUS_INVALID_HANDLE;
	}

	if (!lp_locking(fsp->conn->params)) {
		return NT_STATUS_OK;
	}

	DBG_DEBUG("unlock start=%"PRIu64" len=%"PRIu64" requested for %s file "
		  "%s\n",
		  offset,
		  count,
		  fsp_fnum_dbg(fsp),
		  fsp_str_dbg(fsp));

	br_lck = brl_get_locks(talloc_tos(), fsp);
	if (!br_lck) {
		return NT_STATUS_NO_MEMORY;
	}

	ok = brl_unlock(br_lck,
			smblctx,
			messaging_server_id(fsp->conn->sconn->msg_ctx),
			offset,
			count,
			lock_flav);

	TALLOC_FREE(br_lck);

	if (!ok) {
		DEBUG(10,("do_unlock: returning ERRlock.\n" ));
		return NT_STATUS_RANGE_NOT_LOCKED;
	}

	decrement_current_lock_count(fsp, lock_flav);
	return NT_STATUS_OK;
}

/****************************************************************************
 Remove any locks on this fd. Called from file_close().
****************************************************************************/

void locking_close_file(files_struct *fsp,
			enum file_close_type close_type)
{
	struct byte_range_lock *br_lck;

	if (!lp_locking(fsp->conn->params)) {
		return;
	}

	/* If we have no outstanding locks or pending
	 * locks then we don't need to look in the lock db.
	 */

	if (fsp->current_lock_count == 0) {
		return;
	}

	br_lck = brl_get_locks(talloc_tos(),fsp);

	if (br_lck) {
		/*
		 * Unlocks must trigger dbwrap_watch watchers,
		 * normally in smbd_do_unlocking. Here it's done
		 * implictly, we're closing the file and thus remove a
		 * share mode. This will wake the waiters.
		 */
		brl_close_fnum(br_lck);
		TALLOC_FREE(br_lck);
	}
}

/*******************************************************************
 Print out a share mode.
********************************************************************/

char *share_mode_str(TALLOC_CTX *ctx, int num,
		     const struct file_id *id,
		     const struct share_mode_entry *e)
{
	struct server_id_buf tmp;
	struct file_id_buf ftmp;

	return talloc_asprintf(ctx, "share_mode_entry[%d]: "
		 "pid = %s, share_access = 0x%x, private_options = 0x%x, "
		 "access_mask = 0x%x, mid = 0x%llx, type= 0x%x, gen_id = %llu, "
		 "uid = %u, flags = %u, file_id %s, name_hash = 0x%x",
		 num,
		 server_id_str_buf(e->pid, &tmp),
		 e->share_access, e->private_options,
		 e->access_mask, (unsigned long long)e->op_mid,
		 e->op_type, (unsigned long long)e->share_file_id,
		 (unsigned int)e->uid, (unsigned int)e->flags,
		 file_id_str_buf(*id, &ftmp),
		 (unsigned int)e->name_hash);
}

/*******************************************************************
 Fetch a share mode where we know one MUST exist. This call reference
 counts it internally to allow for nested lock fetches.
********************************************************************/

struct share_mode_lock *get_existing_share_mode_lock(TALLOC_CTX *mem_ctx,
						     const struct file_id id)
{
	return get_share_mode_lock(mem_ctx, id, NULL, NULL, NULL);
}

struct rename_share_filename_state {
	struct share_mode_lock *lck;
	struct messaging_context *msg_ctx;
	struct server_id self;
	uint32_t orig_name_hash;
	uint32_t new_name_hash;
	struct file_rename_message msg;
};

static bool rename_lease_fn(struct share_mode_entry *e,
			    void *private_data)
{
	struct rename_share_filename_state *state = private_data;
	struct share_mode_data *d = state->lck->data;
	NTSTATUS status;

	status = leases_db_rename(&e->client_guid,
				  &e->lease_key,
				  &d->id,
				  d->servicepath,
				  d->base_name,
				  d->stream_name);

	if (!NT_STATUS_IS_OK(status)) {
		/* Any error recovery possible here ? */
		DBG_WARNING("Failed to rename lease key for "
			    "renamed file %s:%s. %s\n",
			    d->base_name,
			    d->stream_name,
			    nt_errstr(status));
	}

	return false;
}

/*******************************************************************
 Sets the service name and filename for rename.
 At this point we emit "file renamed" messages to all
 process id's that have this file open.
 Based on an initial code idea from SATOH Fumiyasu <fumiya@samba.gr.jp>
********************************************************************/

static bool rename_share_filename_fn(
	struct share_mode_entry *e,
	bool *modified,
	void *private_data)
{
	struct rename_share_filename_state *state = private_data;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	bool ok;

	/*
	 * If this is a hardlink to the inode with a different name,
	 * skip this.
	 */
	if (e->name_hash != state->orig_name_hash) {
		return false;
	}
	e->name_hash = state->new_name_hash;
	*modified = true;

	ok = server_id_equal(&e->pid, &state->self);
	if (ok) {
		return false;
	}

	state->msg.share_file_id = e->share_file_id;

	ndr_err = ndr_push_struct_blob(
		&blob,
		talloc_tos(),
		&state->msg,
		(ndr_push_flags_fn_t)ndr_push_file_rename_message);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_DEBUG("ndr_push_file_rename_message failed: %s\n",
			  ndr_errstr(ndr_err));
		return false;
	}
	if (DEBUGLEVEL >= 10) {
		struct server_id_buf tmp;
		DBG_DEBUG("sending rename message to %s\n",
			  server_id_str_buf(e->pid, &tmp));
		NDR_PRINT_DEBUG(file_rename_message, &state->msg);
	}

	messaging_send(state->msg_ctx, e->pid, MSG_SMB_FILE_RENAME, &blob);

	TALLOC_FREE(blob.data);

	return false;
}

bool rename_share_filename(struct messaging_context *msg_ctx,
			struct share_mode_lock *lck,
			struct file_id id,
			const char *servicepath,
			uint32_t orig_name_hash,
			uint32_t new_name_hash,
			const struct smb_filename *smb_fname_dst)
{
	struct rename_share_filename_state state = {
		.lck = lck,
		.msg_ctx = msg_ctx,
		.self = messaging_server_id(msg_ctx),
		.orig_name_hash = orig_name_hash,
		.new_name_hash = new_name_hash,
		.msg.id = id,
		.msg.servicepath = servicepath,
		.msg.base_name = smb_fname_dst->base_name,
		.msg.stream_name = smb_fname_dst->stream_name,
	};
	struct share_mode_data *d = lck->data;
	bool ok;

	DEBUG(10, ("rename_share_filename: servicepath %s newname %s\n",
		   servicepath, smb_fname_dst->base_name));

	/*
	 * rename_internal_fsp() and rename_internals() add './' to
	 * head of newname if newname does not contain a '/'.
	 */

	if (strncmp(state.msg.base_name, "./", 2) == 0) {
		state.msg.base_name += 2;
	}

	d->servicepath = talloc_strdup(d, state.msg.servicepath);
	d->base_name = talloc_strdup(d, state.msg.base_name);
	d->stream_name = talloc_strdup(d, state.msg.stream_name);
	if ((d->servicepath == NULL) ||
	    (d->base_name == NULL) ||
	    ((state.msg.stream_name != NULL) && (d->stream_name == NULL))) {
		DBG_WARNING("talloc failed\n");
		return false;
	}
	d->modified = True;

	ok = share_mode_forall_entries(
		lck, rename_share_filename_fn, &state);
	if (!ok) {
		DBG_WARNING("share_mode_forall_entries failed\n");
	}

	ok = share_mode_forall_leases(lck, rename_lease_fn, &state);
	if (!ok) {
		/*
		 * Ignore error here. Not sure what to do..
		 */
		DBG_WARNING("share_mode_forall_leases failed\n");
	}

	return True;
}

void get_file_infos(struct file_id id,
		    uint32_t name_hash,
		    bool *delete_on_close,
		    struct timespec *write_time)
{
	struct share_mode_lock *lck;

	if (delete_on_close) {
		*delete_on_close = false;
	}

	if (write_time) {
		*write_time = make_omit_timespec();
	}

	if (!(lck = fetch_share_mode_unlocked(talloc_tos(), id))) {
		return;
	}

	if (delete_on_close) {
		*delete_on_close = is_delete_on_close_set(lck, name_hash);
	}

	if (write_time) {
		*write_time = get_share_mode_write_time(lck);
	}

	TALLOC_FREE(lck);
}

bool is_valid_share_mode_entry(const struct share_mode_entry *e)
{
	int num_props = 0;

	if (e->stale) {
		return false;
	}

	num_props += ((e->op_type == NO_OPLOCK) ? 1 : 0);
	num_props += (EXCLUSIVE_OPLOCK_TYPE(e->op_type) ? 1 : 0);
	num_props += (LEVEL_II_OPLOCK_TYPE(e->op_type) ? 1 : 0);
	num_props += (e->op_type == LEASE_OPLOCK);

	if ((num_props > 1) && serverid_exists(&e->pid)) {
		smb_panic("Invalid share mode entry");
	}
	return (num_props != 0);
}

struct find_lease_ref_state {
	const struct GUID *client_guid;
	const struct smb2_lease_key *lease_key;
	bool found_same;
};

static bool find_lease_ref_fn(
	struct share_mode_entry *e,
	bool *modified,
	void *private_data)
{
	struct find_lease_ref_state *state = private_data;

	if (e->stale) {
		return false;
	}
	if (e->op_type != LEASE_OPLOCK) {
		return false;
	}

	state->found_same = smb2_lease_equal(
		&e->client_guid,
		&e->lease_key,
		state->client_guid,
		state->lease_key);
	/*
	 * If we found a lease reference, look no further (i.e. return true)
	 */
	return state->found_same;
}

NTSTATUS remove_lease_if_stale(struct share_mode_lock *lck,
			       const struct GUID *client_guid,
			       const struct smb2_lease_key *lease_key)
{
	struct find_lease_ref_state state = {
		.client_guid = client_guid, .lease_key = lease_key,
	};
	struct share_mode_data *d = lck->data;
	NTSTATUS status;
	bool ok;

	ok = share_mode_forall_entries(lck, find_lease_ref_fn, &state);
	if (!ok) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (state.found_same) {
		return NT_STATUS_RESOURCE_IN_USE;
	}

	status = leases_db_del(client_guid, lease_key, &d->id);
	if (!NT_STATUS_IS_OK(status)) {
		int level = DBGLVL_DEBUG;

		if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
			level = DBGLVL_ERR;
		}
		DBG_PREFIX(level, ("leases_db_del failed: %s\n",
			   nt_errstr(status)));
	}
	return status;
}

bool share_entry_stale_pid(struct share_mode_entry *e)
{
	struct server_id_buf buf;
	bool exists;

	if (e->stale) {
		return true;
	}

	exists = serverid_exists(&e->pid);
	if (exists) {
		DBG_DEBUG("PID %s still exists\n",
			  server_id_str_buf(e->pid, &buf));
		return false;
	}

	DBG_DEBUG("PID %s does not exist anymore\n",
		  server_id_str_buf(e->pid, &buf));

	e->stale = true;

	return true;
}

/****************************************************************************
 Adds a delete on close token.
****************************************************************************/

static bool add_delete_on_close_token(struct share_mode_data *d,
			uint32_t name_hash,
			const struct security_token *nt_tok,
			const struct security_unix_token *tok)
{
	struct delete_token *tmp, *dtl;

	tmp = talloc_realloc(d, d->delete_tokens, struct delete_token,
			     d->num_delete_tokens+1);
	if (tmp == NULL) {
		return false;
	}
	d->delete_tokens = tmp;
	dtl = &d->delete_tokens[d->num_delete_tokens];

	dtl->name_hash = name_hash;
	dtl->delete_nt_token = dup_nt_token(d->delete_tokens, nt_tok);
	if (dtl->delete_nt_token == NULL) {
		return false;
	}
	dtl->delete_token = copy_unix_token(d->delete_tokens, tok);
	if (dtl->delete_token == NULL) {
		return false;
	}
	d->num_delete_tokens += 1;
	d->modified = true;
	return true;
}

void reset_delete_on_close_lck(files_struct *fsp,
			       struct share_mode_lock *lck)
{
	struct share_mode_data *d = lck->data;
	uint32_t i;

	for (i=0; i<d->num_delete_tokens; i++) {
		struct delete_token *dt = &d->delete_tokens[i];

		if (dt->name_hash == fsp->name_hash) {
			d->modified = true;

			/* Delete this entry. */
			TALLOC_FREE(dt->delete_nt_token);
			TALLOC_FREE(dt->delete_token);
			*dt = d->delete_tokens[d->num_delete_tokens-1];
			d->num_delete_tokens -= 1;
		}
	}
}

struct set_delete_on_close_state {
	struct messaging_context *msg_ctx;
	DATA_BLOB blob;
};

static bool set_delete_on_close_fn(
	struct share_mode_entry *e,
	bool *modified,
	void *private_data)
{
	struct set_delete_on_close_state *state = private_data;
	NTSTATUS status;

	status = messaging_send(
		state->msg_ctx,
		e->pid,
		MSG_SMB_NOTIFY_CANCEL_DELETED,
		&state->blob);

	if (!NT_STATUS_IS_OK(status)) {
		struct server_id_buf tmp;
		DBG_DEBUG("messaging_send to %s returned %s\n",
			  server_id_str_buf(e->pid, &tmp),
			  nt_errstr(status));
	}

	return false;
}

/****************************************************************************
 Sets the delete on close flag over all share modes on this file.
 Modify the share mode entry for all files open
 on this device and inode to tell other smbds we have
 changed the delete on close flag. This will be noticed
 in the close code, the last closer will delete the file
 if flag is set.
 This makes a copy of any struct security_unix_token into the
 lck entry. This function is used when the lock is already granted.
****************************************************************************/

void set_delete_on_close_lck(files_struct *fsp,
			struct share_mode_lock *lck,
			const struct security_token *nt_tok,
			const struct security_unix_token *tok)
{
	struct share_mode_data *d = lck->data;
	struct set_delete_on_close_state state = {
		.msg_ctx = fsp->conn->sconn->msg_ctx
	};
	uint32_t i;
	bool ret;
	enum ndr_err_code ndr_err;

	SMB_ASSERT(nt_tok != NULL);
	SMB_ASSERT(tok != NULL);

	for (i=0; i<d->num_delete_tokens; i++) {
		struct delete_token *dt = &d->delete_tokens[i];
		if (dt->name_hash == fsp->name_hash) {
			d->modified = true;

			/* Replace this token with the given tok. */
			TALLOC_FREE(dt->delete_nt_token);
			dt->delete_nt_token = dup_nt_token(dt, nt_tok);
			SMB_ASSERT(dt->delete_nt_token != NULL);
			TALLOC_FREE(dt->delete_token);
			dt->delete_token = copy_unix_token(dt, tok);
			SMB_ASSERT(dt->delete_token != NULL);

			return;
		}
	}

	ret = add_delete_on_close_token(lck->data, fsp->name_hash, nt_tok, tok);
	SMB_ASSERT(ret);

	ndr_err = ndr_push_struct_blob(
		&state.blob,
		talloc_tos(),
		&fsp->file_id,
		(ndr_push_flags_fn_t)ndr_push_file_id);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(10, ("ndr_push_file_id failed: %s\n",
			   ndr_errstr(ndr_err)));
	}

	ret = share_mode_forall_entries(
		lck, set_delete_on_close_fn, &state);
	if (!ret) {
		DBG_DEBUG("share_mode_forall_entries failed\n");
	}

	TALLOC_FREE(state.blob.data);
}

bool set_delete_on_close(files_struct *fsp, bool delete_on_close,
			const struct security_token *nt_tok,
			const struct security_unix_token *tok)
{
	struct share_mode_lock *lck;

	DEBUG(10,("set_delete_on_close: %s delete on close flag for "
		  "%s, file %s\n",
		  delete_on_close ? "Adding" : "Removing", fsp_fnum_dbg(fsp),
		  fsp_str_dbg(fsp)));

	lck = get_existing_share_mode_lock(talloc_tos(), fsp->file_id);
	if (lck == NULL) {
		return False;
	}

	if (delete_on_close) {
		set_delete_on_close_lck(fsp, lck, nt_tok, tok);
	} else {
		reset_delete_on_close_lck(fsp, lck);
	}

	if (fsp->fsp_flags.is_directory) {
		SMB_ASSERT(!is_ntfs_stream_smb_fname(fsp->fsp_name));
		send_stat_cache_delete_message(fsp->conn->sconn->msg_ctx,
					       fsp->fsp_name->base_name);
	}

	TALLOC_FREE(lck);

	fsp->fsp_flags.delete_on_close = delete_on_close;

	return True;
}

static struct delete_token *find_delete_on_close_token(
	struct share_mode_data *d, uint32_t name_hash)
{
	uint32_t i;

	DBG_DEBUG("name_hash = 0x%"PRIx32"\n", name_hash);

	for (i=0; i<d->num_delete_tokens; i++) {
		struct delete_token *dt = &d->delete_tokens[i];

		DBG_DEBUG("dt->name_hash = 0x%"PRIx32"\n",
			  dt->name_hash);
		if (dt->name_hash == name_hash) {
			return dt;
		}
	}
	return NULL;
}

/****************************************************************************
 Return the NT token and UNIX token if there's a match. Return true if
 found, false if not.
****************************************************************************/

bool get_delete_on_close_token(struct share_mode_lock *lck,
					uint32_t name_hash,
					const struct security_token **pp_nt_tok,
					const struct security_unix_token **pp_tok)
{
	struct delete_token *dt;

	dt = find_delete_on_close_token(lck->data, name_hash);
	if (dt == NULL) {
		return false;
	}
	*pp_nt_tok = dt->delete_nt_token;
	*pp_tok =  dt->delete_token;
	return true;
}

bool is_delete_on_close_set(struct share_mode_lock *lck, uint32_t name_hash)
{
	return find_delete_on_close_token(lck->data, name_hash) != NULL;
}

bool set_sticky_write_time(struct file_id fileid, struct timespec write_time)
{
	struct share_mode_lock *lck;
	struct file_id_buf ftmp;
	struct timeval_buf tbuf;
	NTTIME nt = full_timespec_to_nt_time(&write_time);

	DBG_INFO("%s id=%s\n",
		 timespec_string_buf(&write_time, true, &tbuf),
		 file_id_str_buf(fileid, &ftmp));

	lck = get_existing_share_mode_lock(talloc_tos(), fileid);
	if (lck == NULL) {
		return False;
	}

	if (lck->data->changed_write_time != nt) {
		lck->data->modified = True;
		lck->data->changed_write_time = nt;
	}

	TALLOC_FREE(lck);
	return True;
}

bool set_write_time(struct file_id fileid, struct timespec write_time)
{
	struct share_mode_lock *lck;
	struct file_id_buf idbuf;
	struct timeval_buf tbuf;
	NTTIME nt = full_timespec_to_nt_time(&write_time);

	DBG_INFO("%s id=%s\n",
		 timespec_string_buf(&write_time, true, &tbuf),
		 file_id_str_buf(fileid, &idbuf));

	lck = get_existing_share_mode_lock(talloc_tos(), fileid);
	if (lck == NULL) {
		return False;
	}

	if (lck->data->old_write_time != nt) {
		lck->data->modified = True;
		lck->data->old_write_time = nt;
	}

	TALLOC_FREE(lck);
	return True;
}

struct timespec get_share_mode_write_time(struct share_mode_lock *lck)
{
	struct share_mode_data *d = lck->data;

	if (!null_nttime(d->changed_write_time)) {
		return nt_time_to_full_timespec(d->changed_write_time);
	}
	return nt_time_to_full_timespec(d->old_write_time);
}

struct file_has_open_streams_state {
	bool found_one;
};

static bool file_has_open_streams_fn(
	struct share_mode_entry *e,
	bool *modified,
	void *private_data)
{
	struct file_has_open_streams_state *state = private_data;

	if ((e->private_options &
	     NTCREATEX_OPTIONS_PRIVATE_STREAM_BASEOPEN) == 0) {
		return false;
	}

	if (share_entry_stale_pid(e)) {
		return false;
	}

	state->found_one = true;
	return true;
}

bool file_has_open_streams(files_struct *fsp)
{
	struct file_has_open_streams_state state = { .found_one = false };
	struct share_mode_lock *lock = NULL;
	bool ok;

	lock = get_existing_share_mode_lock(talloc_tos(), fsp->file_id);
	if (lock == NULL) {
		return false;
	}

	ok = share_mode_forall_entries(
		lock, file_has_open_streams_fn, &state);
	TALLOC_FREE(lock);

	if (!ok) {
		DBG_DEBUG("share_mode_forall_entries failed\n");
		return false;
	}
	return state.found_one;
}

/*
 * Walk share mode entries, looking at every lease only once
 */

struct share_mode_forall_leases_state {
	TALLOC_CTX *mem_ctx;
	struct leases_db_key *leases;
	bool (*fn)(struct share_mode_entry *e,
		   void *private_data);
	void *private_data;
	NTSTATUS status;
};

static bool share_mode_forall_leases_fn(
	struct share_mode_entry *e,
	bool *modified,
	void *private_data)
{
	struct share_mode_forall_leases_state *state = private_data;
	struct leases_db_key *leases = state->leases;
	size_t i, num_leases;
	bool stop;

	if (e->op_type != LEASE_OPLOCK) {
		return false;
	}

	num_leases = talloc_array_length(leases);

	for (i=0; i<num_leases; i++) {
		struct leases_db_key *l = &leases[i];
		bool same = smb2_lease_equal(
			&e->client_guid,
			&e->lease_key,
			&l->client_guid,
			&l->lease_key);
		if (same) {
			return false;
		}
	}

	leases = talloc_realloc(
		state->mem_ctx,
		leases,
		struct leases_db_key,
		num_leases+1);
	if (leases == NULL) {
		state->status = NT_STATUS_NO_MEMORY;
		return true;
	}
	leases[num_leases] = (struct leases_db_key) {
		.client_guid = e->client_guid,
		.lease_key = e->lease_key,
	};
	state->leases = leases;

	stop = state->fn(e, state->private_data);
	return stop;
}

bool share_mode_forall_leases(
	struct share_mode_lock *lck,
	bool (*fn)(struct share_mode_entry *e,
		   void *private_data),
	void *private_data)
{
	struct share_mode_forall_leases_state state = {
		.mem_ctx = talloc_tos(),
		.fn = fn,
		.private_data = private_data
	};
	bool ok;

	ok = share_mode_forall_entries(
		lck, share_mode_forall_leases_fn, &state);
	TALLOC_FREE(state.leases);
	if (!ok) {
		DBG_DEBUG("share_mode_forall_entries failed\n");
		return false;
	}

	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_DEBUG("share_mode_forall_leases_fn returned %s\n",
			  nt_errstr(state.status));
		return false;
	}

	return true;
}
