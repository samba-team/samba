/* 
   Unix SMB/CIFS implementation.
   oplock processing
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 1998 - 2001
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
*/

#define DBGC_CLASS DBGC_LOCKING
#include "includes.h"
#include "lib/util/server_id.h"
#include "locking/share_mode_lock.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "messages.h"
#include "locking/leases_db.h"
#include "../librpc/gen_ndr/ndr_open_files.h"
#include "lib/util/tevent_ntstatus.h"
#include "source3/smbd/dir.h"

/*
 * helper function used by the kernel oplock backends to post the break message
 */
void break_kernel_oplock(struct messaging_context *msg_ctx, files_struct *fsp)
{
	struct oplock_break_message msg = {
		.id = fsp->file_id,
		.share_file_id = fh_get_gen_id(fsp->fh),
	};
	enum ndr_err_code ndr_err;
	uint8_t msgbuf[33];
	DATA_BLOB blob = {.data = msgbuf, .length = sizeof(msgbuf)};

	/* Don't need to be root here as we're only ever
	   sending to ourselves. */

	ndr_err = ndr_push_struct_into_fixed_blob(
		&blob,
		&msg,
		(ndr_push_flags_fn_t)ndr_push_oplock_break_message);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("ndr_push_oplock_break_message failed: %s\n",
			    ndr_errstr(ndr_err));
		return;
	}

	messaging_send(msg_ctx,
		       messaging_server_id(msg_ctx),
		       MSG_SMB_KERNEL_BREAK,
		       &blob);
}

/****************************************************************************
 Attempt to set an oplock on a file. Succeeds if kernel oplocks are
 disabled (just sets flags).
****************************************************************************/

NTSTATUS set_file_oplock(files_struct *fsp)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;
	struct kernel_oplocks *koplocks = sconn->oplocks.kernel_ops;
	bool use_kernel = lp_kernel_oplocks(SNUM(fsp->conn)) &&
			(koplocks != NULL);
	struct file_id_buf buf;

	smb_vfs_assert_allowed();

	if (fsp->oplock_type == LEVEL_II_OPLOCK && use_kernel) {
		DEBUG(10, ("Refusing level2 oplock, kernel oplocks "
			   "don't support them\n"));
		return NT_STATUS_NOT_SUPPORTED;
	}

	if ((fsp->oplock_type != NO_OPLOCK) &&
	    use_kernel &&
	    !koplocks->ops->set_oplock(koplocks, fsp, fsp->oplock_type))
	{
		return map_nt_error_from_unix(errno);
	}

	fsp->sent_oplock_break = NO_BREAK_SENT;
	if (fsp->oplock_type == LEVEL_II_OPLOCK) {
		sconn->oplocks.level_II_open++;
	} else if (EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		sconn->oplocks.exclusive_open++;
	}

	DBG_INFO("granted oplock on file %s, %s/%"PRIu64", "
		 "tv_sec = %x, tv_usec = %x\n",
		 fsp_str_dbg(fsp),
		 file_id_str_buf(fsp->file_id, &buf),
		 fh_get_gen_id(fsp->fh),
		 (int)fsp->open_time.tv_sec,
		 (int)fsp->open_time.tv_usec);

	return NT_STATUS_OK;
}

static void release_fsp_kernel_oplock(files_struct *fsp)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;
	struct kernel_oplocks *koplocks = sconn->oplocks.kernel_ops;
	bool use_kernel;

	smb_vfs_assert_allowed();

	if (koplocks == NULL) {
		return;
	}
	use_kernel = lp_kernel_oplocks(SNUM(fsp->conn));
	if (!use_kernel) {
		return;
	}
	if (fsp->oplock_type == NO_OPLOCK) {
		return;
	}
	if (fsp->oplock_type == LEASE_OPLOCK) {
		/*
		 * For leases we don't touch kernel oplocks at all
		 */
		return;
	}

	koplocks->ops->release_oplock(koplocks, fsp, NO_OPLOCK);
}

/****************************************************************************
 Attempt to release an oplock on a file. Decrements oplock count.
****************************************************************************/

void release_file_oplock(files_struct *fsp)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;

	release_fsp_kernel_oplock(fsp);

	if (fsp->oplock_type == LEVEL_II_OPLOCK) {
		sconn->oplocks.level_II_open--;
	} else if (EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		sconn->oplocks.exclusive_open--;
	}

	SMB_ASSERT(sconn->oplocks.exclusive_open>=0);
	SMB_ASSERT(sconn->oplocks.level_II_open>=0);

	fsp->oplock_type = NO_OPLOCK;
	fsp->sent_oplock_break = NO_BREAK_SENT;

	TALLOC_FREE(fsp->oplock_timeout);
}

/****************************************************************************
 Attempt to downgrade an oplock on a file. Doesn't decrement oplock count.
****************************************************************************/

static void downgrade_file_oplock(files_struct *fsp)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;
	struct kernel_oplocks *koplocks = sconn->oplocks.kernel_ops;
	bool use_kernel = lp_kernel_oplocks(SNUM(fsp->conn)) &&
			(koplocks != NULL);

	smb_vfs_assert_allowed();

	if (!EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		DEBUG(0, ("trying to downgrade an already-downgraded oplock!\n"));
		return;
	}

	if (use_kernel) {
		koplocks->ops->release_oplock(koplocks, fsp, LEVEL_II_OPLOCK);
	}
	fsp->oplock_type = LEVEL_II_OPLOCK;
	sconn->oplocks.exclusive_open--;
	sconn->oplocks.level_II_open++;
	fsp->sent_oplock_break = NO_BREAK_SENT;

	TALLOC_FREE(fsp->oplock_timeout);
}

uint32_t get_lease_type(struct share_mode_entry *e, struct file_id id)
{
	struct GUID_txt_buf guid_strbuf;
	struct file_id_buf file_id_strbuf;
	NTSTATUS status;
	uint32_t current_state;

	if (e->op_type != LEASE_OPLOCK) {
		return map_oplock_to_lease_type(e->op_type);
	}

	status = leases_db_get(&e->client_guid,
			       &e->lease_key,
			       &id,
			       &current_state,
			       NULL,	/* breaking */
			       NULL,	/* breaking_to_requested */
			       NULL,	/* breaking_to_required */
			       NULL,	/* lease_version */
			       NULL);	/* epoch */
	if (NT_STATUS_IS_OK(status)) {
		return current_state;
	}

	if (share_entry_stale_pid(e)) {
		return 0;
	}
	DBG_ERR("leases_db_get for client_guid [%s] "
		"lease_key [%"PRIx64"/%"PRIx64"] "
		"file_id [%s] failed: %s\n",
		GUID_buf_string(&e->client_guid, &guid_strbuf),
		e->lease_key.data[0],
		e->lease_key.data[1],
		file_id_str_buf(id, &file_id_strbuf),
		nt_errstr(status));
	smb_panic("leases_db_get() failed");
}

/****************************************************************************
 Remove a file oplock. Copes with level II and exclusive.
 Locks then unlocks the share mode lock. Client can decide to go directly
 to none even if a "break-to-level II" was sent.
****************************************************************************/

bool remove_oplock(files_struct *fsp)
{
	bool ret;
	struct share_mode_lock *lck;

	DBG_DEBUG("remove_oplock called for %s\n", fsp_str_dbg(fsp));

	/* Remove the oplock flag from the sharemode. */
	lck = get_existing_share_mode_lock(talloc_tos(), fsp->file_id);
	if (lck == NULL) {
		DBG_ERR("failed to lock share entry for "
			 "file %s\n", fsp_str_dbg(fsp));
		return false;
	}

	ret = remove_share_oplock(lck, fsp);
	if (!ret) {
		struct file_id_buf buf;

		DBG_ERR("failed to remove share oplock for "
			"file %s, %s, %s\n",
			fsp_str_dbg(fsp), fsp_fnum_dbg(fsp),
			file_id_str_buf(fsp->file_id, &buf));
	}
	release_file_oplock(fsp);

	TALLOC_FREE(lck);
	return ret;
}

/*
 * Deal with a reply when a break-to-level II was sent.
 */
bool downgrade_oplock(files_struct *fsp)
{
	bool ret;
	struct share_mode_lock *lck;

	DEBUG(10, ("downgrade_oplock called for %s\n",
		   fsp_str_dbg(fsp)));

	lck = get_existing_share_mode_lock(talloc_tos(), fsp->file_id);
	if (lck == NULL) {
		DEBUG(0,("downgrade_oplock: failed to lock share entry for "
			 "file %s\n", fsp_str_dbg(fsp)));
		return False;
	}
	ret = downgrade_share_oplock(lck, fsp);
	if (!ret) {
		struct file_id_buf idbuf;
		DBG_ERR("failed to downgrade share oplock "
			"for file %s, %s, file_id %s\n",
			fsp_str_dbg(fsp),
			fsp_fnum_dbg(fsp),
			file_id_str_buf(fsp->file_id, &idbuf));
	}
	downgrade_file_oplock(fsp);

	TALLOC_FREE(lck);
	return ret;
}

static void lease_timeout_handler(struct tevent_context *ctx,
				  struct tevent_timer *te,
				  struct timeval now,
				  void *private_data)
{
	struct fsp_lease *lease =
		talloc_get_type_abort(private_data,
		struct fsp_lease);
	struct files_struct *fsp;
	struct share_mode_lock *lck;
	uint16_t old_epoch = lease->lease.lease_epoch;

	fsp = file_find_one_fsp_from_lease_key(lease->sconn,
					       &lease->lease.lease_key);
	if (fsp == NULL) {
		/* race? */
		TALLOC_FREE(lease->timeout);
		return;
	}

	/*
	 * Paranoia check: There can only be one fsp_lease per lease
	 * key
	 */
	SMB_ASSERT(fsp->lease == lease);

	lck = get_existing_share_mode_lock(
			talloc_tos(), fsp->file_id);
	if (lck == NULL) {
		/* race? */
		TALLOC_FREE(lease->timeout);
		return;
	}

	fsp_lease_update(fsp);

	if (lease->lease.lease_epoch != old_epoch) {
		/*
		 * If the epoch changed we need to wait for
		 * the next timeout to happen.
		 */
		DEBUG(10, ("lease break timeout race (epoch) for file %s - ignoring\n",
			   fsp_str_dbg(fsp)));
		TALLOC_FREE(lck);
		return;
	}

	if (!(lease->lease.lease_flags & SMB2_LEASE_FLAG_BREAK_IN_PROGRESS)) {
		/*
		 * If the epoch changed we need to wait for
		 * the next timeout to happen.
		 */
		DEBUG(10, ("lease break timeout race (flags) for file %s - ignoring\n",
			   fsp_str_dbg(fsp)));
		TALLOC_FREE(lck);
		return;
	}

	DEBUG(1, ("lease break timed out for file %s -- replying anyway\n",
		  fsp_str_dbg(fsp)));
	(void)downgrade_lease(lease->sconn->client,
			1,
			&fsp->file_id,
			&lease->lease.lease_key,
			SMB2_LEASE_NONE);

	TALLOC_FREE(lck);
}

bool fsp_lease_update(struct files_struct *fsp)
{
	const struct GUID *client_guid = fsp_client_guid(fsp);
	struct fsp_lease *lease = fsp->lease;
	uint32_t current_state;
	bool breaking;
	uint16_t lease_version, epoch;
	NTSTATUS status;

	status = leases_db_get(client_guid,
			       &lease->lease.lease_key,
			       &fsp->file_id,
			       &current_state,
			       &breaking,
			       NULL, /* breaking_to_requested */
			       NULL, /* breaking_to_required */
			       &lease_version,
			       &epoch);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("Could not find lease entry: %s\n",
			    nt_errstr(status));
		TALLOC_FREE(lease->timeout);
		lease->lease.lease_state = SMB2_LEASE_NONE;
		lease->lease.lease_epoch += 1;
		lease->lease.lease_flags = 0;
		return false;
	}

	DEBUG(10,("%s: refresh lease state\n", __func__));

	/* Ensure we're in sync with current lease state. */
	if (lease->lease.lease_epoch != epoch) {
		DEBUG(10,("%s: cancel outdated timeout\n", __func__));
		TALLOC_FREE(lease->timeout);
	}
	lease->lease.lease_epoch = epoch;
	lease->lease.lease_state = current_state;

	if (breaking) {
		lease->lease.lease_flags |= SMB2_LEASE_FLAG_BREAK_IN_PROGRESS;

		if (lease->timeout == NULL) {
			struct timeval t = timeval_current_ofs(OPLOCK_BREAK_TIMEOUT, 0);

			DEBUG(10,("%s: setup timeout handler\n", __func__));

			lease->timeout = tevent_add_timer(lease->sconn->ev_ctx,
							  lease, t,
							  lease_timeout_handler,
							  lease);
			if (lease->timeout == NULL) {
				DEBUG(0, ("%s: Could not add lease timeout handler\n",
					  __func__));
			}
		}
	} else {
		lease->lease.lease_flags &= ~SMB2_LEASE_FLAG_BREAK_IN_PROGRESS;
		TALLOC_FREE(lease->timeout);
	}

	return true;
}

struct downgrade_lease_additional_state {
	struct tevent_immediate *im;
	struct smbXsrv_client *client;
	uint32_t break_flags;
	struct smb2_lease_key lease_key;
	uint32_t break_from;
	uint32_t break_to;
	uint16_t new_epoch;
};

static void downgrade_lease_additional_trigger(struct tevent_context *ev,
					       struct tevent_immediate *im,
					       void *private_data)
{
	struct downgrade_lease_additional_state *state =
		talloc_get_type_abort(private_data,
		struct downgrade_lease_additional_state);
	NTSTATUS status;

	status = smbd_smb2_send_lease_break(state->client,
					    state->new_epoch,
					    state->break_flags,
					    &state->lease_key,
					    state->break_from,
					    state->break_to);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_disconnect_client(state->client,
					      nt_errstr(status));
	}
	TALLOC_FREE(state);
}

struct fsps_lease_update_state {
	const struct file_id *id;
	const struct smb2_lease_key *key;
};

static struct files_struct *fsps_lease_update_fn(
	struct files_struct *fsp, void *private_data)
{
	struct fsps_lease_update_state *state =
		(struct fsps_lease_update_state *)private_data;

	if (fsp->oplock_type != LEASE_OPLOCK) {
		return NULL;
	}
	if (!smb2_lease_key_equal(&fsp->lease->lease.lease_key, state->key)) {
		return NULL;
	}
	if (!file_id_equal(&fsp->file_id, state->id)) {
		return NULL;
	}

	fsp_lease_update(fsp);

	return NULL;
}

static void fsps_lease_update(struct smbd_server_connection *sconn,
			      const struct file_id *id,
			      const struct smb2_lease_key *key)
{
	struct fsps_lease_update_state state = { .id = id, .key = key };
	files_forall(sconn, fsps_lease_update_fn, &state);
}

NTSTATUS downgrade_lease(struct smbXsrv_client *client,
			 uint32_t num_file_ids,
			 const struct file_id *ids,
			 const struct smb2_lease_key *key,
			 uint32_t lease_state)
{
	struct smbd_server_connection *sconn = client->sconn;
	const struct GUID *client_guid = NULL;
	struct share_mode_lock *lck;
	const struct file_id id = ids[0];
	uint32_t current_state, breaking_to_requested, breaking_to_required;
	bool breaking;
	uint16_t lease_version, epoch;
	NTSTATUS status;
	uint32_t i;
	struct file_id_buf idbuf;

	DBG_DEBUG("Downgrading %s to %"PRIu32"\n",
		  file_id_str_buf(id, &idbuf),
		  lease_state);

	lck = get_existing_share_mode_lock(talloc_tos(), id);
	if (lck == NULL) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	client_guid = &sconn->client->global->client_guid;

	status = leases_db_get(client_guid,
			       key,
			       &id,
			       &current_state,
			       &breaking,
			       &breaking_to_requested,
			       &breaking_to_required,
			       &lease_version,
			       &epoch);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("leases_db_get returned %s\n",
			    nt_errstr(status));
		TALLOC_FREE(lck);
		return status;
	}

	if (!breaking) {
		DBG_WARNING("Attempt to break from %"PRIu32" to %"PRIu32" - "
			    "but we're not in breaking state\n",
			    current_state, lease_state);
		TALLOC_FREE(lck);
		return NT_STATUS_UNSUCCESSFUL;
	}

	/*
	 * Can't upgrade anything: breaking_to_requested (and current_state)
	 * must be a strict bitwise superset of new_lease_state
	 */
	if ((lease_state & breaking_to_requested) != lease_state) {
		DBG_WARNING("Attempt to upgrade from %"PRIu32" to %"PRIu32" "
			    "- expected %"PRIu32"\n",
			    current_state, lease_state,
			    breaking_to_requested);
		TALLOC_FREE(lck);
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	if (current_state != lease_state) {
		current_state = lease_state;
	}

	status = NT_STATUS_OK;

	if ((lease_state & ~breaking_to_required) != 0) {
		struct downgrade_lease_additional_state *state;

		DBG_INFO("lease state %"PRIu32" not fully broken from "
			 "%"PRIu32" to %"PRIu32"\n",
			 lease_state,
			 current_state,
			 breaking_to_required);

		breaking_to_requested = breaking_to_required;

		if (current_state & (SMB2_LEASE_WRITE|SMB2_LEASE_HANDLE)) {
			/*
			 * Here we break in steps, as windows does
			 * see the breaking3 and v2_breaking3 tests.
			 */
			breaking_to_requested |= SMB2_LEASE_READ;
		}

		state = talloc_zero(client,
				    struct downgrade_lease_additional_state);
		if (state == NULL) {
			TALLOC_FREE(lck);
			return NT_STATUS_NO_MEMORY;
		}

		state->im = tevent_create_immediate(state);
		if (state->im == NULL) {
			TALLOC_FREE(state);
			TALLOC_FREE(lck);
			return NT_STATUS_NO_MEMORY;
		}

		state->client = client;
		state->lease_key = *key;
		state->break_from = current_state;
		state->break_to = breaking_to_requested;
		if (lease_version > 1) {
			state->new_epoch = epoch;
		}

		if (current_state & (SMB2_LEASE_WRITE|SMB2_LEASE_HANDLE)) {
			state->break_flags =
				SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED;
		} else {
			/*
			 * This is an async break without
			 * SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED
			 *
			 * we need to store NONE state in the
			 * database.
			 */
			current_state = 0;
			breaking_to_requested = 0;
			breaking_to_required = 0;
			breaking = false;

			{
				NTSTATUS set_status;

				set_status = leases_db_set(
					&sconn->client->global->client_guid,
					key,
					current_state,
					breaking,
					breaking_to_requested,
					breaking_to_required,
					lease_version,
					epoch);

				if (!NT_STATUS_IS_OK(set_status)) {
					DBG_DEBUG("leases_db_set failed: %s\n",
						  nt_errstr(set_status));
					return set_status;
				}
			}
		}

		tevent_schedule_immediate(state->im,
					  client->raw_ev_ctx,
					  downgrade_lease_additional_trigger,
					  state);

		status = NT_STATUS_OPLOCK_BREAK_IN_PROGRESS;
	} else {
		DBG_DEBUG("breaking from %"PRIu32" to %"PRIu32" - "
			  "expected %"PRIu32"\n",
			  current_state,
			  lease_state,
			  breaking_to_requested);

		breaking_to_requested = 0;
		breaking_to_required = 0;
		breaking = false;
	}

	{
		NTSTATUS set_status;

		set_status = leases_db_set(
			client_guid,
			key,
			current_state,
			breaking,
			breaking_to_requested,
			breaking_to_required,
			lease_version,
			epoch);

		if (!NT_STATUS_IS_OK(set_status)) {
			DBG_DEBUG("leases_db_set failed: %s\n",
				  nt_errstr(set_status));
			TALLOC_FREE(lck);
			return set_status;
		}
	}

	DBG_DEBUG("Downgrading %s to %"PRIu32" => %s\n",
		  file_id_str_buf(id, &idbuf),
		  lease_state,
		  nt_errstr(status));

	share_mode_wakeup_waiters(id);

	fsps_lease_update(sconn, &id, key);

	TALLOC_FREE(lck);

	DBG_DEBUG("Downgrading %s to %"PRIu32" => %s\n",
		  file_id_str_buf(id, &idbuf),
		  lease_state,
		  nt_errstr(status));

	/*
	 * Dynamic share case. Ensure other opens are copies.
	 * This will only be breaking to NONE.
	 */

	for (i = 1; i < num_file_ids; i++) {
		lck = get_existing_share_mode_lock(talloc_tos(), ids[i]);
		if (lck == NULL) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

		fsps_lease_update(sconn, &ids[i], key);

		DBG_DEBUG("Downgrading %s to %"PRIu32" => %s\n",
			  file_id_str_buf(ids[i], &idbuf),
			  lease_state,
			  nt_errstr(status));

		TALLOC_FREE(lck);
	}

	return status;
}

#define SMB1_BREAK_MESSAGE_LENGTH (smb_size + 8*2)

/****************************************************************************
 Function to do the waiting before sending a local break.
****************************************************************************/

static void wait_before_sending_break(void)
{
	long wait_time = (long)lp_oplock_break_wait_time();

	if (wait_time) {
		smb_msleep(wait_time);
	}
}

/****************************************************************************
 Ensure that we have a valid oplock.
****************************************************************************/

static files_struct *initial_break_processing(
	struct smbd_server_connection *sconn, struct file_id id,
	unsigned long file_id)
{
	files_struct *fsp = NULL;
	struct file_id_buf idbuf;

	DBG_NOTICE("called for %s/%u\n"
		   "Current oplocks_open (exclusive = %d, levelII = %d)\n",
		   file_id_str_buf(id, &idbuf),
		   (int)file_id,
		   sconn->oplocks.exclusive_open,
		   sconn->oplocks.level_II_open);

	/*
	 * We need to search the file open table for the
	 * entry containing this dev and inode, and ensure
	 * we have an oplock on it.
	 */

	fsp = file_find_dif(sconn, id, file_id);

	if(fsp == NULL) {
		/* The file could have been closed in the meantime - return success. */
		DBG_NOTICE("cannot find open file "
			   "with file_id %s gen_id = %lu, allowing break to "
			   "succeed.\n",
			   file_id_str_buf(id, &idbuf),
			   file_id);
		return NULL;
	}

	/* Ensure we have an oplock on the file */

	/*
	 * There is a potential race condition in that an oplock could
	 * have been broken due to another udp request, and yet there are
	 * still oplock break messages being sent in the udp message
	 * queue for this file. So return true if we don't have an oplock,
	 * as we may have just freed it.
	 */

	if(fsp->oplock_type == NO_OPLOCK) {
		DBG_NOTICE("file %s (file_id = %s gen_id = %"PRIu64") "
			   "has no oplock. "
			   "Allowing break to succeed regardless.\n",
			   fsp_str_dbg(fsp),
			   file_id_str_buf(id, &idbuf),
			   fh_get_gen_id(fsp->fh));
		return NULL;
	}

	return fsp;
}

static void oplock_timeout_handler(struct tevent_context *ctx,
				   struct tevent_timer *te,
				   struct timeval now,
				   void *private_data)
{
	files_struct *fsp = (files_struct *)private_data;

	SMB_ASSERT(fsp->sent_oplock_break != NO_BREAK_SENT);

	/* Remove the timed event handler. */
	TALLOC_FREE(fsp->oplock_timeout);
	DEBUG(0, ("Oplock break failed for file %s -- replying anyway\n",
		  fsp_str_dbg(fsp)));
	remove_oplock(fsp);
}

/*******************************************************************
 Add a timeout handler waiting for the client reply.
*******************************************************************/

static void add_oplock_timeout_handler(files_struct *fsp)
{
	if (fsp->oplock_timeout != NULL) {
		DEBUG(0, ("Logic problem -- have an oplock event hanging "
			  "around\n"));
	}

	fsp->oplock_timeout =
		tevent_add_timer(fsp->conn->sconn->ev_ctx, fsp,
				 timeval_current_ofs(OPLOCK_BREAK_TIMEOUT, 0),
				 oplock_timeout_handler, fsp);

	if (fsp->oplock_timeout == NULL) {
		DEBUG(0, ("Could not add oplock timeout handler\n"));
	}
}

/*******************************************************************
 This handles the generic oplock break message from another smbd.
*******************************************************************/

static void process_oplock_break_message(struct messaging_context *msg_ctx,
					 void *private_data,
					 uint32_t msg_type,
					 struct server_id src,
					 DATA_BLOB *data)
{
	struct oplock_break_message msg;
	enum ndr_err_code ndr_err;
	files_struct *fsp;
	bool use_kernel;
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);
	struct server_id self = messaging_server_id(sconn->msg_ctx);
	struct kernel_oplocks *koplocks = sconn->oplocks.kernel_ops;
	uint16_t break_from;
	uint16_t break_to;
	bool break_needed = true;

	smb_vfs_assert_allowed();

	ndr_err = ndr_pull_struct_blob_all_noalloc(
		data, &msg, (ndr_pull_flags_fn_t)ndr_pull_oplock_break_message);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_DEBUG("ndr_pull_oplock_break_message failed: %s\n",
			  ndr_errstr(ndr_err));
		return;
	}
	if (DEBUGLEVEL >= 10) {
		struct server_id_buf buf;
		DBG_DEBUG("Got break message from %s\n",
			  server_id_str_buf(src, &buf));
		NDR_PRINT_DEBUG(oplock_break_message, &msg);
	}

	break_to = msg.break_to;
	fsp = initial_break_processing(sconn, msg.id, msg.share_file_id);

	if (fsp == NULL) {
		/* We hit a race here. Break messages are sent, and before we
		 * get to process this message, we have closed the file. */
		DEBUG(3, ("Did not find fsp\n"));
		return;
	}

	break_from = fsp_lease_type(fsp);

	if (fsp->oplock_type != LEASE_OPLOCK) {
		if (fsp->sent_oplock_break != NO_BREAK_SENT) {
			/*
			 * Nothing to do anymore
			 */
			DEBUG(10, ("fsp->sent_oplock_break = %d\n",
				   fsp->sent_oplock_break));
			return;
		}
	}

	if (!(global_client_caps & CAP_LEVEL_II_OPLOCKS)) {
		DEBUG(10, ("client_caps without level2 oplocks\n"));
		break_to &= ~SMB2_LEASE_READ;
	}

	use_kernel = lp_kernel_oplocks(SNUM(fsp->conn)) &&
			(koplocks != NULL);
	if (use_kernel) {
		DEBUG(10, ("Kernel oplocks don't allow level2\n"));
		break_to &= ~SMB2_LEASE_READ;
	}

	if (!lp_level2_oplocks(SNUM(fsp->conn))) {
		DEBUG(10, ("no level2 oplocks by config\n"));
		break_to &= ~SMB2_LEASE_READ;
	}

	if (fsp->oplock_type == LEASE_OPLOCK) {
		const struct GUID *client_guid = fsp_client_guid(fsp);
		struct share_mode_lock *lck;
		uint32_t current_state;
		uint32_t breaking_to_requested, breaking_to_required;
		bool breaking;
		uint16_t lease_version, epoch;
		NTSTATUS status;

		lck = get_existing_share_mode_lock(
			talloc_tos(), fsp->file_id);
		if (lck == NULL) {
			/*
			 * We hit a race here. Break messages are sent, and
			 * before we get to process this message, we have closed
			 * the file.
			 */
			DEBUG(3, ("Did not find share_mode\n"));
			return;
		}

		status = leases_db_get(client_guid,
				       &fsp->lease->lease.lease_key,
				       &fsp->file_id,
				       &current_state,
				       &breaking,
				       &breaking_to_requested,
				       &breaking_to_required,
				       &lease_version,
				       &epoch);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("leases_db_get returned %s\n",
				    nt_errstr(status));
			TALLOC_FREE(lck);
			return;
		}

		break_from = current_state;
		break_to &= current_state;

		if (breaking) {
			break_to &= breaking_to_required;
			if (breaking_to_required != break_to) {
				/*
				 * Note we don't increment the epoch
				 * here, which might be a bug in
				 * Windows too...
				 */
				breaking_to_required = break_to;
			}
			break_needed = false;
		} else if (current_state == break_to) {
			break_needed = false;
		} else if (current_state == SMB2_LEASE_READ) {
			current_state = SMB2_LEASE_NONE;
			/* Need to increment the epoch */
			epoch += 1;
		} else {
			breaking = true;
			breaking_to_required = break_to;
			breaking_to_requested = break_to;
			/* Need to increment the epoch */
			epoch += 1;
		}

		{
			NTSTATUS set_status;

			set_status = leases_db_set(
				client_guid,
				&fsp->lease->lease.lease_key,
				current_state,
				breaking,
				breaking_to_requested,
				breaking_to_required,
				lease_version,
				epoch);

			if (!NT_STATUS_IS_OK(set_status)) {
				DBG_DEBUG("leases_db_set failed: %s\n",
					  nt_errstr(set_status));
				return;
			}
		}

		/* Ensure we're in sync with current lease state. */
		fsp_lease_update(fsp);

		TALLOC_FREE(lck);
	}

	if (!break_needed) {
		DEBUG(10,("%s: skip break\n", __func__));
		return;
	}

	if (break_from == SMB2_LEASE_NONE) {
		struct file_id_buf idbuf;
		DBG_NOTICE("Already downgraded oplock to none on %s: %s\n",
			   file_id_str_buf(fsp->file_id, &idbuf),
			   fsp_str_dbg(fsp));
		return;
	}

	DEBUG(10, ("break_from=%u, break_to=%u\n",
		   (unsigned)break_from, (unsigned)break_to));

	if (break_from == break_to) {
		struct file_id_buf idbuf;
		DBG_NOTICE("Already downgraded oplock to %u on %s: %s\n",
			   (unsigned)break_to,
			   file_id_str_buf(fsp->file_id, &idbuf),
			   fsp_str_dbg(fsp));
		return;
	}

	/* Need to wait before sending a break
	   message if we sent ourselves this message. */
	if (server_id_equal(&self, &src)) {
		wait_before_sending_break();
	}

#if defined(WITH_SMB1SERVER)
	if (conn_using_smb2(sconn)) {
#endif
		send_break_message_smb2(fsp, break_from, break_to);
#if defined(WITH_SMB1SERVER)
	} else {
		send_break_message_smb1(fsp, (break_to & SMB2_LEASE_READ) ?
					OPLOCKLEVEL_II : OPLOCKLEVEL_NONE);
	}
#endif

	if ((break_from == SMB2_LEASE_READ) &&
	    (break_to == SMB2_LEASE_NONE)) {
		/*
		 * This is an async break without a reply and thus no timeout
		 *
		 * leases are handled above.
		 */
		if (fsp->oplock_type != LEASE_OPLOCK) {
			remove_oplock(fsp);
		}
		return;
	}
	if (fsp->oplock_type == LEASE_OPLOCK) {
		return;
	}

	fsp->sent_oplock_break = (break_to & SMB2_LEASE_READ) ?
		LEVEL_II_BREAK_SENT:BREAK_TO_NONE_SENT;

	add_oplock_timeout_handler(fsp);
}

/*******************************************************************
 This handles the kernel oplock break message.
*******************************************************************/

static void process_kernel_oplock_break(struct messaging_context *msg_ctx,
					void *private_data,
					uint32_t msg_type,
					struct server_id src,
					DATA_BLOB *data)
{
	struct oplock_break_message msg;
	enum ndr_err_code ndr_err;
	struct file_id_buf idbuf;
	files_struct *fsp;
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);
	struct server_id_buf tmp;

	ndr_err = ndr_pull_struct_blob_all_noalloc(
		data,
		&msg,
		(ndr_pull_flags_fn_t)ndr_pull_oplock_break_message);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_DEBUG("ndr_pull_oplock_break_message failed: %s\n",
			  ndr_errstr(ndr_err));
		return;
	}

	DBG_DEBUG("Got kernel oplock break message from pid %s: %s/%u\n",
		  server_id_str_buf(src, &tmp),
		  file_id_str_buf(msg.id, &idbuf),
		  (unsigned int)msg.share_file_id);

	fsp = initial_break_processing(sconn, msg.id, msg.share_file_id);

	if (fsp == NULL) {
		DEBUG(3, ("Got a kernel oplock break message for a file "
			  "I don't know about\n"));
		return;
	}

	if (fsp->sent_oplock_break != NO_BREAK_SENT) {
		/* This is ok, kernel oplocks come in completely async */
		DEBUG(3, ("Got a kernel oplock request while waiting for a "
			  "break reply\n"));
		return;
	}

#if defined(WITH_SMB1SERVER)
	if (conn_using_smb2(sconn)) {
#endif
		send_break_message_smb2(fsp, 0, OPLOCKLEVEL_NONE);
#if defined(WITH_SMB1SERVER)
	} else {
		send_break_message_smb1(fsp, OPLOCKLEVEL_NONE);
	}
#endif

	fsp->sent_oplock_break = BREAK_TO_NONE_SENT;

	add_oplock_timeout_handler(fsp);
}

static void send_break_to_none(struct messaging_context *msg_ctx,
			       const struct file_id *id,
			       const struct share_mode_entry *e)
{
	NTSTATUS status;
	status = send_break_message(msg_ctx, id, e, OPLOCK_NONE);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("send_break_message failed: %s\n",
			  nt_errstr(status));
	}
}
struct break_to_none_state {
	struct smbd_server_connection *sconn;
	struct file_id id;
	struct smb2_lease_key lease_key;
	struct GUID client_guid;
	size_t num_read_leases;
	uint32_t total_lease_types;
};

static bool do_break_lease_to_none(struct share_mode_entry *e,
				   void *private_data)
{
	struct break_to_none_state *state = private_data;
	uint32_t current_state = 0;
	bool our_own;
	NTSTATUS status;

	DBG_DEBUG("lease_key=%"PRIu64"/%"PRIu64"\n",
		  e->lease_key.data[0],
		  e->lease_key.data[1]);

	status = leases_db_get(&e->client_guid,
			       &e->lease_key,
			       &state->id,
			       &current_state,
			       NULL, /* breaking */
			       NULL, /* breaking_to_requested */
			       NULL, /* breaking_to_required */
			       NULL, /* lease_version */
			       NULL); /* epoch */
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("leases_db_get failed: %s\n",
			    nt_errstr(status));
		return false;
	}

	state->total_lease_types |= current_state;

	if ((current_state & SMB2_LEASE_READ) == 0) {
		return false;
	}

	state->num_read_leases += 1;

	our_own = smb2_lease_equal(&state->client_guid,
				   &state->lease_key,
				   &e->client_guid,
				   &e->lease_key);
	if (our_own) {
		DEBUG(10, ("Don't break our own lease\n"));
		return false;
	}

	DBG_DEBUG("Breaking %"PRIu64"/%"PRIu64" to none\n",
		  e->lease_key.data[0],
		  e->lease_key.data[1]);

	send_break_to_none(state->sconn->msg_ctx, &state->id, e);

	return false;
}

static bool do_break_oplock_to_none(struct share_mode_entry *e,
				    bool *modified,
				    void *private_data)
{
	struct break_to_none_state *state = private_data;

	if (e->op_type == LEASE_OPLOCK) {
		/*
		 * Already being taken care of
		 */
		return false;
	}

	/*
	 * As there could have been multiple writes waiting at the
	 * lock_share_entry gate we may not be the first to
	 * enter. Hence the state of the op_types in the share mode
	 * entries may be partly NO_OPLOCK and partly LEVEL_II
	 * oplock. It will do no harm to re-send break messages to
	 * those smbd's that are still waiting their turn to remove
	 * their LEVEL_II state, and also no harm to ignore existing
	 * NO_OPLOCK states. JRA.
	 */

	DBG_DEBUG("e->op_type == %d\n", e->op_type);

	state->total_lease_types |= map_oplock_to_lease_type(e->op_type);

	if (e->op_type == NO_OPLOCK) {
		return false;
	}

	state->num_read_leases += 1;

	/* Paranoia .... */
	SMB_ASSERT(!EXCLUSIVE_OPLOCK_TYPE(e->op_type));

	send_break_to_none(state->sconn->msg_ctx, &state->id, e);

	return false;
}

struct dirlease_break_state {
	struct smbd_server_connection *sconn;
	struct file_id file_id;
	struct smb2_lease_key parent_lease_key;
	uint32_t total_lease_types;
};

static bool do_dirlease_break_to_none(struct share_mode_entry *e,
				      void *private_data)
{
	struct dirlease_break_state *state = private_data;
	uint32_t current_state = 0;
	NTSTATUS status;

	DBG_DEBUG("lease_key=%"PRIu64"/%"PRIu64"\n",
		  e->lease_key.data[0],
		  e->lease_key.data[1]);

	status = leases_db_get(&e->client_guid,
			       &e->lease_key,
			       &state->file_id,
			       &current_state,
			       NULL, /* breaking */
			       NULL, /* breaking_to_requested */
			       NULL, /* breaking_to_required */
			       NULL, /* lease_version */
			       NULL); /* epoch */
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("leases_db_get failed: %s\n",
			    nt_errstr(status));
		return false;
	}

	if (share_entry_stale_pid(e)) {
		return false;
	}

	state->total_lease_types |= current_state;

	if (smb2_lease_key_equal(&state->parent_lease_key, &e->lease_key)) {
		return false;
	}

	if ((current_state & (SMB2_LEASE_READ | SMB2_LEASE_HANDLE)) == 0) {
		return false;
	}

	DBG_DEBUG("Breaking %"PRIu64"/%"PRIu64" to none\n",
		  e->lease_key.data[0],
		  e->lease_key.data[1]);

	send_break_to_none(state->sconn->msg_ctx, &state->file_id, e);
	return false;
}

void contend_dirleases(struct connection_struct *conn,
		       const struct smb_filename *smb_fname,
		       const struct smb2_lease *lease)
{
	struct dirlease_break_state state = {
		.sconn = conn->sconn,
	};
	struct share_mode_lock *lck = NULL;
	struct smb_filename *parent_fname = NULL;
	uint32_t access_mask, share_mode;
	NTSTATUS status;
	int ret;
	bool ok;

	if (lease != NULL) {
		DBG_DEBUG("Parent leasekey %"PRIx64"/%"PRIx64"\n",
			  lease->parent_lease_key.data[0],
			  lease->parent_lease_key.data[1]);
		state.parent_lease_key = lease->parent_lease_key;
	}

	status = SMB_VFS_PARENT_PATHNAME(conn,
					 talloc_tos(),
					 smb_fname,
					 &parent_fname,
					 NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("parent_smb_fname() for [%s] failed: %s\n",
			smb_fname_str_dbg(smb_fname), strerror(errno));
		return;
	}

	ret = SMB_VFS_STAT(conn, parent_fname);
	if (ret != 0) {
		DBG_ERR("Trigger [conn: %s] [smb_fname: %s] cwd [%s], "
			"failed to stat parent [%s]: %s\n",
			conn->connectpath,
			smb_fname_str_dbg(smb_fname),
			get_current_dir_name(),
			smb_fname_str_dbg(parent_fname),
			strerror(errno));
		TALLOC_FREE(parent_fname);
		return;
	}

	state.file_id = vfs_file_id_from_sbuf(conn, &parent_fname->st);
	TALLOC_FREE(parent_fname);

	lck = get_existing_share_mode_lock(talloc_tos(), state.file_id);
	if (lck == NULL) {
		/*
		 * No sharemode db entry -> no leases.
		 */
		return;
	}

	ok = share_mode_forall_leases(lck, do_dirlease_break_to_none, &state);
	if (!ok) {
		DBG_WARNING("share_mode_forall_leases failed\n");
	}

	/*
	 * While we're at it, update lease type.
	 */
	share_mode_flags_get(lck,
			     &access_mask,
			     &share_mode,
			     NULL);
	share_mode_flags_set(lck,
			     access_mask,
			     share_mode,
			     state.total_lease_types,
			     NULL);

	TALLOC_FREE(lck);
}

/****************************************************************************
 This function is called on any file modification or lock request. If a file
 is level 2 oplocked then it must tell all other level 2 holders to break to
 none.
****************************************************************************/

static void contend_level2_oplocks_begin_default(files_struct *fsp,
					      enum level2_contention_type type)
{
	struct break_to_none_state state = {
		.sconn = fsp->conn->sconn, .id = fsp->file_id,
	};
	struct share_mode_lock *lck = NULL;
	uint32_t fsp_lease = fsp_lease_type(fsp);
	bool ok, has_read_lease;

	/*
	 * If this file is level II oplocked then we need
	 * to grab the shared memory lock and inform all
	 * other files with a level II lock that they need
	 * to flush their read caches. We keep the lock over
	 * the shared memory area whilst doing this.
	 */

	if (fsp_lease & SMB2_LEASE_WRITE) {
		/*
		 * There can't be any level2 oplocks, we're alone.
		 */
		return;
	}

	has_read_lease = file_has_read_lease(fsp);
	if (!has_read_lease) {
		DEBUG(10, ("No read oplocks around\n"));
		return;
	}

	if (fsp->oplock_type == LEASE_OPLOCK) {
		state.client_guid = *fsp_client_guid(fsp);
		state.lease_key = fsp->lease->lease.lease_key;
		DEBUG(10, ("Breaking through lease key %"PRIu64"/%"PRIu64"\n",
			   state.lease_key.data[0],
			   state.lease_key.data[1]));
	}

	lck = get_existing_share_mode_lock(talloc_tos(), fsp->file_id);
	if (lck == NULL) {
		struct file_id_buf idbuf;
		DBG_WARNING("failed to lock share mode entry for file %s.\n",
			    file_id_str_buf(state.id, &idbuf));
		return;
	}

	/*
	 * Walk leases and oplocks separately: We have to send one break per
	 * lease. If we have multiple share_mode_entry having a common lease,
	 * we would break the lease twice if we don't walk the leases list
	 * separately.
	 */

	ok = share_mode_forall_leases(lck, do_break_lease_to_none, &state);
	if (!ok) {
		DBG_WARNING("share_mode_forall_leases failed\n");
	}

	ok = share_mode_forall_entries(lck, do_break_oplock_to_none, &state);
	if (!ok) {
		DBG_WARNING("share_mode_forall_entries failed\n");
	}

	{
		/*
		 * Lazy update here. It might be that all leases
		 * have gone in the meantime.
		 */
		uint32_t acc, sh, ls;
		share_mode_flags_get(lck, &acc, &sh, &ls);
		ls = state.total_lease_types;
		share_mode_flags_set(lck, acc, sh, ls, NULL);
	}

	TALLOC_FREE(lck);
}

void smbd_contend_level2_oplocks_begin(files_struct *fsp,
				  enum level2_contention_type type)
{
	contend_level2_oplocks_begin_default(fsp, type);
}

void smbd_contend_level2_oplocks_end(files_struct *fsp,
				enum level2_contention_type type)
{
	return;
}

/****************************************************************************
 Setup oplocks for this process.
****************************************************************************/

bool init_oplocks(struct smbd_server_connection *sconn)
{
	DEBUG(3,("init_oplocks: initializing messages.\n"));

	messaging_register(sconn->msg_ctx, sconn, MSG_SMB_BREAK_REQUEST,
			   process_oplock_break_message);
	messaging_register(sconn->msg_ctx, sconn, MSG_SMB_KERNEL_BREAK,
			   process_kernel_oplock_break);
	return true;
}

void init_kernel_oplocks(struct smbd_server_connection *sconn)
{
	struct kernel_oplocks *koplocks = sconn->oplocks.kernel_ops;

	/* only initialize once */
	if (koplocks == NULL) {
#ifdef HAVE_KERNEL_OPLOCKS_LINUX
		koplocks = linux_init_kernel_oplocks(sconn);
#endif
		sconn->oplocks.kernel_ops = koplocks;
	}
}

struct pending_hlease_break {
	struct pending_hlease_break *prev;
	struct pending_hlease_break *next;
	struct server_id pid;
	struct file_id id;
	uint64_t share_file_id;
	uint16_t break_to;
};

struct delay_for_handle_lease_break_state {
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct timeval timeout;
	uint32_t access_mask;
	bool recursive;
	bool recursive_h_leases_break;
	struct files_struct *fsp;
	struct share_mode_lock *lck;
	bool delay;
	struct pending_hlease_break *breaks;
	struct file_id break_id;
	bool found_open;
	uint32_t num_watches;
};

static void delay_for_handle_lease_break_cleanup(struct tevent_req *req,
						 enum tevent_req_state req_state)
{
	struct delay_for_handle_lease_break_state *state =
		tevent_req_data(req, struct delay_for_handle_lease_break_state);

	if (req_state == TEVENT_REQ_DONE) {
		return;
	}
	TALLOC_FREE(state->lck);
}

static void delay_for_handle_lease_break_check(struct tevent_req *req);

struct tevent_req *delay_for_handle_lease_break_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct timeval timeout,
	struct files_struct *fsp,
	uint32_t access_mask,
	bool recursive,
	struct share_mode_lock **lck)
{
	struct tevent_req *req = NULL;
	struct delay_for_handle_lease_break_state *state = NULL;

	req = tevent_req_create(
		mem_ctx, &state, struct delay_for_handle_lease_break_state);
	if (req == NULL) {
		return NULL;
	}

	tevent_req_set_cleanup_fn(req, delay_for_handle_lease_break_cleanup);

	*state = (struct delay_for_handle_lease_break_state) {
		.mem_ctx = mem_ctx,
		.ev = ev,
		.timeout = timeout,
		.access_mask = access_mask,
		.recursive = recursive,
		.recursive_h_leases_break = recursive,
		.fsp = fsp,
		.lck = talloc_move(state, lck),
	};

	delay_for_handle_lease_break_check(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	/* Ensure we can't be closed in flight. */
	if (!aio_add_req_to_fsp(fsp, req)) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return tevent_req_post(req, ev);
	}

	return req;
}

static bool delay_for_handle_lease_break_fn(struct share_mode_entry *e,
					    void *private_data)
{
	struct delay_for_handle_lease_break_state *state = talloc_get_type_abort(
		private_data, struct delay_for_handle_lease_break_state);
	struct files_struct *fsp = state->fsp;
	struct server_id_buf buf;
	uint32_t lease_type;
	bool ours, stale;

	if (fsp->lease != NULL) {
		ours = smb2_lease_equal(fsp_client_guid(fsp),
					&fsp->lease->lease.lease_key,
					&e->client_guid,
					&e->lease_key);
		if (ours) {
			return false;
		}
	}

	if ((state->access_mask & e->access_mask) == 0) {
		return false;
	}

	lease_type = get_lease_type(e, fsp->file_id);
	if ((lease_type & SMB2_LEASE_HANDLE) == 0) {
		return false;
	}

	stale = share_entry_stale_pid(e);
	if (stale) {
		return false;
	}

	state->delay = true;

	DBG_DEBUG("Breaking h-lease on [%s] pid [%s]\n",
		  fsp_str_dbg(fsp),
		  server_id_str_buf(e->pid, &buf));

	send_break_message(fsp->conn->sconn->msg_ctx,
			   &fsp->file_id,
			   e,
			   lease_type & ~SMB2_LEASE_HANDLE);

	return false;
}

static void delay_for_handle_lease_break_fsp_done(struct tevent_req *subreq);

static void delay_for_handle_lease_break_fsp_check(struct tevent_req *req)
{
	struct delay_for_handle_lease_break_state *state = tevent_req_data(
		req, struct delay_for_handle_lease_break_state);
	struct tevent_req *subreq = NULL;
	bool ok;

	DBG_DEBUG("fsp [%s]\n", fsp_str_dbg(state->fsp));

	if (state->lck == NULL) {
		DBG_DEBUG("fsp [%s] all opens are gone\n",
			  fsp_str_dbg(state->fsp));
		return;
	}

	ok = share_mode_forall_leases(state->lck,
				      delay_for_handle_lease_break_fn,
				      state);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}
	if (state->delay) {
		DBG_DEBUG("Delaying fsp [%s]\n", fsp_str_dbg(state->fsp));

		subreq = share_mode_watch_send(state,
					       state->ev,
					       &state->fsp->file_id,
					       (struct server_id){0});
		if (tevent_req_nomem(subreq, req)) {
			return;
		}

		tevent_req_set_callback(subreq,
					delay_for_handle_lease_break_fsp_done,
					req);

		if (!tevent_req_set_endtime(subreq, state->ev, state->timeout)) {
			tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
			return;
		}
		return;
	}
}

static void delay_for_handle_lease_break_fsp_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct delay_for_handle_lease_break_state *state = tevent_req_data(
		req, struct delay_for_handle_lease_break_state);
	NTSTATUS status;

	DBG_DEBUG("Watch returned for fsp [%s]\n", fsp_str_dbg(state->fsp));

	status = share_mode_watch_recv(subreq, NULL, NULL);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_watch_recv returned %s\n",
			nt_errstr(status));
		if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
			/*
			 * The sharemode-watch timer fired because a client
			 * didn't respond to the lease break.
			 */
			status = NT_STATUS_ACCESS_DENIED;
		}
		tevent_req_nterror(req, status);
		return;
	}

	state->lck = get_existing_share_mode_lock(state, state->fsp->file_id);
	/*
	 * This could potentially end up looping for some if a client
	 * aggressively reaquires H-leases on the file, but we have a
	 * timeout on the tevent req as upper bound.
	 */
	delay_for_handle_lease_break_check(req);
}

static int delay_for_handle_lease_break_below_fn(struct share_mode_data *d,
						 struct share_mode_entry *e,
						 void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct delay_for_handle_lease_break_state *state = tevent_req_data(
		req, struct delay_for_handle_lease_break_state);
	struct pending_hlease_break *b = NULL;
	struct file_id_buf fid_buf;
	const char *fid_bufp = NULL;
	struct server_id_buf sid_buf;
	uint32_t lease = 0;
	bool stale;

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		fid_bufp = file_id_str_buf(d->id, &fid_buf);
	}

	DBG_DEBUG("Breaking [%s] file-id [%s]\n",
		  state->recursive_h_leases_break ? "yes" : "no",
		  fid_bufp);

	stale = share_entry_stale_pid(e);
	if (stale) {
		return 0;
	}

	if (state->recursive_h_leases_break) {
		lease = get_lease_type(e, d->id);
	}

	if ((lease & SMB2_LEASE_HANDLE) == 0) {
		if (e->flags & SHARE_MODE_FLAG_POSIX_OPEN) {
			DBG_DEBUG("POSIX open file-id [%s]\n", fid_bufp);
			/* Ignore POSIX opens. */
			return 0;
		}
		state->found_open = true;
		DBG_DEBUG("Unbreakable open [%s]\n", fid_bufp);
		if (!state->recursive_h_leases_break) {
			/* Second round, stop */
			DBG_DEBUG("Stopping\n");
			return -1;
		}
		return 0;
	}
	lease &= ~SMB2_LEASE_HANDLE;

	b = talloc_zero(state, struct pending_hlease_break);
	if (b == NULL) {
		DBG_ERR("talloc_zero failed\n");
		return -1;
	}
	b->id = d->id;
	b->break_to = lease;
	b->pid = e->pid;
	b->share_file_id = e->share_file_id;

	DLIST_ADD_END(state->breaks, b);

	DBG_DEBUG("Queued h-lease break on file-id [%s] pid [%s]\n",
		  fid_bufp,
		  server_id_str_buf(b->pid, &sid_buf));

	state->delay = true;
	return 0;
}

static void delay_for_handle_lease_break_below_send_breaks(
	struct tevent_req *req);

static void delay_for_handle_lease_break_below_check(struct tevent_req *req)
{
	struct delay_for_handle_lease_break_state *state = tevent_req_data(
		req, struct delay_for_handle_lease_break_state);
	int ret;

	DBG_DEBUG("fsp [%s]\n", fsp_str_dbg(state->fsp));

	if (!state->recursive) {
		return;
	}
	if (!S_ISDIR(state->fsp->fsp_name->st.st_ex_mode)) {
		return;
	}
	if (!lp_strict_rename(SNUM(state->fsp->conn))) {
		/*
		 * This will also not do h-lease breaks
		 */
		state->found_open = file_find_subpath(state->fsp);
		return;
	}

	ret = opens_below_forall(state->fsp->conn,
				 state->fsp->fsp_name,
				 delay_for_handle_lease_break_below_fn,
				 req);
	if (ret == -1) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}
	if (!state->delay) {
		DBG_DEBUG("No delay for [%s]\n", fsp_str_dbg(state->fsp));
		return;
	}
	/*
	 * Ignore any opens without h-lease in the first round of listing opens
	 */
	state->found_open = false;
	delay_for_handle_lease_break_below_send_breaks(req);
	return;
}

static void delay_for_handle_lease_break_below_done(struct tevent_req *subreq);

static void delay_for_handle_lease_break_below_send_breaks(
	struct tevent_req *req)
{
	struct delay_for_handle_lease_break_state *state = tevent_req_data(
		req, struct delay_for_handle_lease_break_state);
	struct messaging_context *msg_ctx = state->fsp->conn->sconn->msg_ctx;
	struct pending_hlease_break *b = NULL;
	struct file_id last_file_id;
	struct tevent_req *subreq = NULL;
	NTSTATUS status;

	DBG_DEBUG("Sending breaks\n");

	if (state->breaks == NULL) {
		return;
	}

	for (b = state->breaks, last_file_id = b->id; b != NULL; b = b->next) {
		struct share_mode_entry e;
		struct file_id_buf fid_buf;
		struct server_id_buf sid_buf;

		if (!file_id_equal(&b->id, &last_file_id)) {
			break;
		}

		e = (struct share_mode_entry) {
			.share_file_id = b->share_file_id,
			.pid = b->pid,
		};

		status = send_break_message(msg_ctx,
					    &b->id,
					    &e,
					    b->break_to);
		if (tevent_req_nterror(req, status)) {
			DBG_ERR("send_break_message failed\n");
			return;
		}

		DLIST_REMOVE(state->breaks, b);

		DBG_DEBUG("Sent h-lease break on file-id [%s] pid [%s]\n",
			  file_id_str_buf(b->id, &fid_buf),
			  server_id_str_buf(b->pid, &sid_buf));

		subreq = share_mode_watch_send(state,
					       state->ev,
					       &b->id,
					       (struct server_id){0});
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq,
					delay_for_handle_lease_break_below_done,
					req);
		if (!tevent_req_set_endtime(subreq, state->ev, state->timeout)) {
			tevent_req_oom(req);
			return;
		}
		state->num_watches++;
	}

	state->break_id = last_file_id;
	DBG_DEBUG("Stopped sending breaks\n");
}

static void delay_for_handle_lease_break_below_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct delay_for_handle_lease_break_state *state = tevent_req_data(
		req, struct delay_for_handle_lease_break_state);
	struct share_mode_lock *lck = NULL;
	struct file_id_buf fid_buf;
	const char *fid_bufp = NULL;
	NTSTATUS status;

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		fid_bufp = file_id_str_buf(state->break_id, &fid_buf);
	}

	DBG_DEBUG("Watch finished for file-id [%s]\n", fid_bufp);

	status = share_mode_watch_recv(subreq, NULL, NULL);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_watch_recv returned %s\n",
			nt_errstr(status));
		if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
			/*
			 * The sharemode-watch timer fired because a client
			 * didn't respond to the lease break.
			 */
			status = NT_STATUS_ACCESS_DENIED;
		}
		tevent_req_nterror(req, status);
		return;
	}

	state->num_watches--;
	if (state->num_watches > 0) {
		return;
	}

	/*
	 * If the client just sends a break ACK, but doesn't close the file,
	 * Windows server directly returns NT_STATUS_ACCESS_DENIED.
	 */

	DBG_DEBUG("Checking for remaining opens on [%s]\n", fid_bufp);

	lck = fetch_share_mode_unlocked(state, state->break_id);
	if (lck != NULL) {
		bool has_nonposix_open;

		has_nonposix_open = has_nonposix_opens(lck);
		TALLOC_FREE(lck);
		if (has_nonposix_open) {
			DBG_DEBUG("Found open\n");
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return;
		}
	}

	if (state->breaks != NULL) {
		delay_for_handle_lease_break_below_send_breaks(req);
		return;
	}

	/*
	 * We've sent lease breaks recursively once, don't do that again. So we
	 * do a recursive scan a second time to check for new opens and if there
	 * are any, with or without h-leases, just fail with
	 * NT_STATUS_ACCESS_DENIED.
	 */
	state->recursive_h_leases_break = false;

	state->lck = get_existing_share_mode_lock(state, state->fsp->file_id);
	delay_for_handle_lease_break_check(req);
}

static void delay_for_handle_lease_break_check(struct tevent_req *req)
{
	struct delay_for_handle_lease_break_state *state = tevent_req_data(
		req, struct delay_for_handle_lease_break_state);

	state->delay = false;

	DBG_DEBUG("fsp [%s]\n", fsp_str_dbg(state->fsp));

	delay_for_handle_lease_break_fsp_check(req);
	if (!tevent_req_is_in_progress(req)) {
		return;
	}
	if (state->delay) {
		DBG_DEBUG("Delaying fsp [%s]\n", fsp_str_dbg(state->fsp));
		TALLOC_FREE(state->lck);
		return;
	}

	delay_for_handle_lease_break_below_check(req);
	if (!tevent_req_is_in_progress(req)) {
		return;
	}
	if (state->found_open) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}
	if (state->delay) {
		TALLOC_FREE(state->lck);
		return;
	}

	tevent_req_done(req);
}

NTSTATUS delay_for_handle_lease_break_recv(struct tevent_req *req,
					   TALLOC_CTX *mem_ctx,
					   struct share_mode_lock **lck)
{
	NTSTATUS status;

	struct delay_for_handle_lease_break_state *state =
		tevent_req_data(req, struct delay_for_handle_lease_break_state);

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*lck = talloc_move(mem_ctx, &state->lck);
	tevent_req_received(req);
	return NT_STATUS_OK;
}

const struct smb2_lease *fsp_get_smb2_lease(const struct files_struct *fsp)
{
	if (fsp == NULL) {
		return NULL;
	}
	if (fsp->lease == NULL) {
		return NULL;
	}
	return &fsp->lease->lease;
}
