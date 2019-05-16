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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "messages.h"
#include "locking/leases_db.h"
#include "../librpc/gen_ndr/ndr_open_files.h"

/*
 * helper function used by the kernel oplock backends to post the break message
 */
void break_kernel_oplock(struct messaging_context *msg_ctx, files_struct *fsp)
{
	uint8_t msg[MSG_SMB_KERNEL_BREAK_SIZE];

	/* Put the kernel break info into the message. */
	push_file_id_24((char *)msg, &fsp->file_id);
	SIVAL(msg,24,fsp->fh->gen_id);

	/* Don't need to be root here as we're only ever
	   sending to ourselves. */

	messaging_send_buf(msg_ctx, messaging_server_id(msg_ctx),
			   MSG_SMB_KERNEL_BREAK,
			   msg, MSG_SMB_KERNEL_BREAK_SIZE);
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

	DEBUG(5,("set_file_oplock: granted oplock on file %s, %s/%lu, "
		    "tv_sec = %x, tv_usec = %x\n",
		 fsp_str_dbg(fsp), file_id_string_tos(&fsp->file_id),
		 fsp->fh->gen_id, (int)fsp->open_time.tv_sec,
		 (int)fsp->open_time.tv_usec ));

	return NT_STATUS_OK;
}

static void release_fsp_kernel_oplock(files_struct *fsp)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;
	struct kernel_oplocks *koplocks = sconn->oplocks.kernel_ops;
	bool use_kernel;

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

static void release_file_oplock(files_struct *fsp)
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

	flush_write_cache(fsp, SAMBA_OPLOCK_RELEASE_FLUSH);
	delete_write_cache(fsp);

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

	flush_write_cache(fsp, SAMBA_OPLOCK_RELEASE_FLUSH);
	delete_write_cache(fsp);

	TALLOC_FREE(fsp->oplock_timeout);
}

uint32_t get_lease_type(const struct share_mode_data *d,
			const struct share_mode_entry *e)
{
	if (e->op_type == LEASE_OPLOCK) {
		NTSTATUS status;
		uint32_t current_state;

		status = leases_db_get(
			&e->client_guid,
			&e->lease_key,
			&d->id,
			&current_state,
			NULL,	/* breaking */
			NULL,	/* breaking_to_requested */
			NULL,	/* breaking_to_required */
			NULL,	/* lease_version */
			NULL);	/* epoch */
		SMB_ASSERT(NT_STATUS_IS_OK(status));
		return current_state;
	}
	return map_oplock_to_lease_type(e->op_type);
}

bool update_num_read_oplocks(files_struct *fsp, struct share_mode_lock *lck)
{
	struct share_mode_data *d = lck->data;
	struct byte_range_lock *br_lck;
	uint32_t num_read_oplocks = 0;
	uint32_t i;

	if (fsp_lease_type_is_exclusive(fsp)) {
		const struct share_mode_entry *e = NULL;
		uint32_t e_lease_type = 0;

		/*
		 * If we're fully exclusive, we don't need a brlock entry
		 */
		remove_stale_share_mode_entries(d);

		e = find_share_mode_entry(lck, fsp);
		if (e != NULL) {
			e_lease_type = get_lease_type(d, e);
		}

		if (!lease_type_is_exclusive(e_lease_type)) {
			char *timestr = NULL;

			timestr = timeval_string(talloc_tos(),
						 &fsp->open_time,
						 true);

			NDR_PRINT_DEBUG(share_mode_data, d);
			DBG_ERR("file [%s] file_id [%s] gen_id [%lu] "
				"open_time[%s] lease_type [0x%x] "
				"oplock_type [0x%x]\n",
				fsp_str_dbg(fsp),
				file_id_string_tos(&fsp->file_id),
				fsp->fh->gen_id, timestr,
				e_lease_type, fsp->oplock_type);

			smb_panic("Found non-exclusive lease");
		}

		return true;
	}

	for (i=0; i<d->num_share_modes; i++) {
		struct share_mode_entry *e = &d->share_modes[i];
		uint32_t e_lease_type = get_lease_type(d, e);

		if (e_lease_type & SMB2_LEASE_READ) {
			num_read_oplocks += 1;
		}
	}

	br_lck = brl_get_locks_readonly(fsp);
	if (br_lck == NULL) {
		return false;
	}
	if (brl_num_read_oplocks(br_lck) == num_read_oplocks) {
		return true;
	}

	br_lck = brl_get_locks(talloc_tos(), fsp);
	if (br_lck == NULL) {
		return false;
	}
	brl_set_num_read_oplocks(br_lck, num_read_oplocks);
	TALLOC_FREE(br_lck);
	return true;
}

/****************************************************************************
 Remove a file oplock with lock already held. Copes with level II and exclusive.
****************************************************************************/

bool remove_oplock_under_lock(files_struct *fsp, struct share_mode_lock *lck)
{
	bool ret;

	ret = remove_share_oplock(lck, fsp);
	if (!ret) {
		DBG_ERR("failed to remove share oplock for "
			"file %s, %s, %s\n",
			fsp_str_dbg(fsp), fsp_fnum_dbg(fsp),
			file_id_string_tos(&fsp->file_id));
	}
	release_file_oplock(fsp);

	ret = update_num_read_oplocks(fsp, lck);
	if (!ret) {
		DBG_ERR("update_num_read_oplocks failed for "
			"file %s, %s, %s\n",
			fsp_str_dbg(fsp), fsp_fnum_dbg(fsp),
			file_id_string_tos(&fsp->file_id));
	}

	return ret;
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

	ret = remove_oplock_under_lock(fsp, lck);

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
		DEBUG(0,("downgrade_oplock: failed to downgrade share oplock "
			 "for file %s, %s, file_id %s\n",
			 fsp_str_dbg(fsp), fsp_fnum_dbg(fsp),
			 file_id_string_tos(&fsp->file_id)));
	}
	downgrade_file_oplock(fsp);

	ret = update_num_read_oplocks(fsp, lck);
	if (!ret) {
		DEBUG(0, ("%s: update_num_read_oplocks failed for "
			 "file %s, %s, %s\n",
			  __func__, fsp_str_dbg(fsp), fsp_fnum_dbg(fsp),
			 file_id_string_tos(&fsp->file_id)));
	}

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

	fsp_lease_update(lck, fsp_client_guid(fsp), lease);

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
	(void)downgrade_lease(lease->sconn->client->connections,
			1,
			&fsp->file_id,
			&lease->lease.lease_key,
			SMB2_LEASE_NONE);

	TALLOC_FREE(lck);
}

bool fsp_lease_update(struct share_mode_lock *lck,
		      const struct GUID *client_guid,
		      struct fsp_lease *lease)
{
	uint32_t current_state;
	bool breaking;
	uint16_t lease_version, epoch;
	NTSTATUS status;

	status = leases_db_get(client_guid,
			       &lease->lease.lease_key,
			       &lck->data->id,
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
	struct smbXsrv_connection *xconn;
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
	struct smbXsrv_connection *xconn = state->xconn;
	NTSTATUS status;

	status = smbd_smb2_send_lease_break(xconn,
					    state->new_epoch,
					    state->break_flags,
					    &state->lease_key,
					    state->break_from,
					    state->break_to);
	TALLOC_FREE(state);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn,
						 nt_errstr(status));
		return;
	}
}

struct downgrade_lease_fsps_state {
	struct file_id id;
	struct share_mode_lock *lck;
	const struct smb2_lease_key *key;
};

static struct files_struct *downgrade_lease_fsps(struct files_struct *fsp,
						 void *private_data)
{
	struct downgrade_lease_fsps_state *state =
		(struct downgrade_lease_fsps_state *)private_data;

	if (fsp->oplock_type != LEASE_OPLOCK) {
		return NULL;
	}
	if (!smb2_lease_key_equal(&fsp->lease->lease.lease_key, state->key)) {
		return NULL;
	}
	if (!file_id_equal(&fsp->file_id, &state->id)) {
		return NULL;
	}

	fsp_lease_update(state->lck, fsp_client_guid(fsp), fsp->lease);

	return NULL;
}

NTSTATUS downgrade_lease(struct smbXsrv_connection *xconn,
			 uint32_t num_file_ids,
			 const struct file_id *ids,
			 const struct smb2_lease_key *key,
			 uint32_t lease_state)
{
	struct smbd_server_connection *sconn = xconn->client->sconn;
	const struct GUID *client_guid = NULL;
	struct share_mode_lock *lck;
	const struct file_id id = ids[0];
	uint32_t current_state, breaking_to_requested, breaking_to_required;
	bool breaking;
	uint16_t lease_version, epoch;
	NTSTATUS status;
	uint32_t i;

	DEBUG(10, ("%s: Downgrading %s to %x\n", __func__,
		   file_id_string_tos(&id), (unsigned)lease_state));

	lck = get_existing_share_mode_lock(talloc_tos(), id);
	if (lck == NULL) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	client_guid = &sconn->client->connections->smb2.client.guid;

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

		state = talloc_zero(xconn,
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

		state->xconn = xconn;
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
					&sconn->client->connections->
					smb2.client.guid,
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
					  xconn->client->raw_ev_ctx,
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

	DEBUG(10, ("%s: Downgrading %s to %x => %s\n", __func__,
		   file_id_string_tos(&id), (unsigned)lease_state, nt_errstr(status)));

	/*
	 * No, we did not modify the share mode array. We did modify
	 * the leases_db. But without this we don't notify a lease
	 * break waiter via dbwrap_watch_record. We need to make
	 * leases_db watched too.
	 */
	lck->data->modified = true;

	{
		struct downgrade_lease_fsps_state state = {
			.id = id, .lck = lck, .key = key,
		};

		files_forall(sconn, downgrade_lease_fsps, &state);
	}

	TALLOC_FREE(lck);
	DEBUG(10, ("%s: Downgrading %s to %x => %s\n", __func__,
		   file_id_string_tos(&id), (unsigned)lease_state, nt_errstr(status)));

	/*
	 * Dynamic share case. Ensure other opens are copies.
	 * This will only be breaking to NONE.
	 */

	for (i = 1; i < num_file_ids; i++) {
		lck = get_existing_share_mode_lock(talloc_tos(), ids[i]);
		if (lck == NULL) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

		{
			struct downgrade_lease_fsps_state state = {
				.id = ids[i], .lck = lck, .key = key,
			};

			files_forall(sconn, downgrade_lease_fsps, &state);
		}

		DEBUG(10, ("%s: Downgrading %s to %x => %s\n", __func__,
			file_id_string_tos(&ids[i]), (unsigned)lease_state, nt_errstr(status)));

		TALLOC_FREE(lck);
	}

	return status;
}

/****************************************************************************
 Set up an oplock break message.
****************************************************************************/

#define SMB1_BREAK_MESSAGE_LENGTH (smb_size + 8*2)

static void new_break_message_smb1(files_struct *fsp, int cmd,
				   char result[SMB1_BREAK_MESSAGE_LENGTH])
{
	memset(result,'\0',smb_size);
	srv_set_message(result,8,0,true);
	SCVAL(result,smb_com,SMBlockingX);
	SSVAL(result,smb_tid,fsp->conn->cnum);
	SSVAL(result,smb_pid,0xFFFF);
	SSVAL(result,smb_uid,0);
	SSVAL(result,smb_mid,0xFFFF);
	SCVAL(result,smb_vwv0,0xFF);
	SSVAL(result,smb_vwv2,fsp->fnum);
	SCVAL(result,smb_vwv3,LOCKING_ANDX_OPLOCK_RELEASE);
	SCVAL(result,smb_vwv3+1,cmd);
}

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

	DEBUG(3, ("initial_break_processing: called for %s/%u\n"
		  "Current oplocks_open (exclusive = %d, levelII = %d)\n",
		  file_id_string_tos(&id), (int)file_id,
		  sconn->oplocks.exclusive_open,
		  sconn->oplocks.level_II_open));

	/*
	 * We need to search the file open table for the
	 * entry containing this dev and inode, and ensure
	 * we have an oplock on it.
	 */

	fsp = file_find_dif(sconn, id, file_id);

	if(fsp == NULL) {
		/* The file could have been closed in the meantime - return success. */
		DEBUG(3, ("initial_break_processing: cannot find open file "
			  "with file_id %s gen_id = %lu, allowing break to "
			  "succeed.\n", file_id_string_tos(&id), file_id));
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
		DEBUG(3, ("initial_break_processing: file %s (file_id = %s "
			  "gen_id = %lu) has no oplock. Allowing break to "
			  "succeed regardless.\n", fsp_str_dbg(fsp),
			  file_id_string_tos(&id), fsp->fh->gen_id));
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

static void send_break_message_smb1(files_struct *fsp, int level)
{
	struct smbXsrv_connection *xconn = NULL;
	char break_msg[SMB1_BREAK_MESSAGE_LENGTH];

	/*
	 * For SMB1 we only have one connection
	 */
	xconn = fsp->conn->sconn->client->connections;

	new_break_message_smb1(fsp, level, break_msg);

	show_msg(break_msg);
	if (!srv_send_smb(xconn,
			break_msg, false, 0,
			IS_CONN_ENCRYPTED(fsp->conn),
			NULL)) {
		exit_server_cleanly("send_break_message_smb1: "
			"srv_send_smb failed.");
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
	struct oplock_break_message *msg = NULL;
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

	msg = talloc(talloc_tos(), struct oplock_break_message);
	if (msg == NULL) {
		DBG_WARNING("talloc failed\n");
		return;
	}

	ndr_err = ndr_pull_struct_blob_all(
		data,
		msg,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_oplock_break_message);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_DEBUG("ndr_pull_oplock_break_message failed: %s\n",
			  ndr_errstr(ndr_err));
		TALLOC_FREE(msg);
		return;
	}
	if (DEBUGLEVEL >= 10) {
		struct server_id_buf buf;
		DBG_DEBUG("Got break message from %s\n",
			  server_id_str_buf(src, &buf));
		NDR_PRINT_DEBUG(oplock_break_message, msg);
	}

	break_to = msg->break_to;
	fsp = initial_break_processing(sconn, msg->id, msg->share_file_id);

	TALLOC_FREE(msg);

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
		fsp_lease_update(lck, fsp_client_guid(fsp), fsp->lease);

		TALLOC_FREE(lck);
	}

	if (!break_needed) {
		DEBUG(10,("%s: skip break\n", __func__));
		return;
	}

	if ((break_from == SMB2_LEASE_NONE) && !break_needed) {
		DEBUG(3, ("Already downgraded oplock to none on %s: %s\n",
			  file_id_string_tos(&fsp->file_id),
			  fsp_str_dbg(fsp)));
		return;
	}

	DEBUG(10, ("break_from=%u, break_to=%u\n",
		   (unsigned)break_from, (unsigned)break_to));

	if ((break_from == break_to) && !break_needed) {
		DEBUG(3, ("Already downgraded oplock to %u on %s: %s\n",
			  (unsigned)break_to,
			  file_id_string_tos(&fsp->file_id),
			  fsp_str_dbg(fsp)));
		return;
	}

	/* Need to wait before sending a break
	   message if we sent ourselves this message. */
	if (serverid_equal(&self, &src)) {
		wait_before_sending_break();
	}

	if (sconn->using_smb2) {
		send_break_message_smb2(fsp, break_from, break_to);
	} else {
		send_break_message_smb1(fsp, (break_to & SMB2_LEASE_READ) ?
					OPLOCKLEVEL_II : OPLOCKLEVEL_NONE);
	}

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
	struct file_id id;
	unsigned long file_id;
	files_struct *fsp;
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);
	struct server_id_buf tmp;

	if (data->data == NULL) {
		DEBUG(0, ("Got NULL buffer\n"));
		return;
	}

	if (data->length != MSG_SMB_KERNEL_BREAK_SIZE) {
		DEBUG(0, ("Got invalid msg len %d\n", (int)data->length));
		return;
	}

	/* Pull the data from the message. */
	pull_file_id_24((char *)data->data, &id);
	file_id = (unsigned long)IVAL(data->data, 24);

	DEBUG(10, ("Got kernel oplock break message from pid %s: %s/%u\n",
		   server_id_str_buf(src, &tmp), file_id_string_tos(&id),
		   (unsigned int)file_id));

	fsp = initial_break_processing(sconn, id, file_id);

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

	if (sconn->using_smb2) {
		send_break_message_smb2(fsp, 0, OPLOCKLEVEL_NONE);
	} else {
		send_break_message_smb1(fsp, OPLOCKLEVEL_NONE);
	}

	fsp->sent_oplock_break = BREAK_TO_NONE_SENT;

	add_oplock_timeout_handler(fsp);
}

static bool file_has_read_oplocks(struct files_struct *fsp)
{
	struct byte_range_lock *brl;
	uint32_t num_read_oplocks = 0;

	brl = brl_get_locks_readonly(fsp);
	if (brl == NULL) {
		return false;
	}

	num_read_oplocks = brl_num_read_oplocks(brl);

	DBG_DEBUG("num_read_oplocks = %"PRIu32"\n", num_read_oplocks);

	return (num_read_oplocks != 0);
}

struct break_to_none_state {
	struct smbd_server_connection *sconn;
	struct file_id id;
	struct smb2_lease_key lease_key;
	struct GUID client_guid;
};
static void do_break_to_none(struct tevent_context *ctx,
			     struct tevent_immediate *im,
			     void *private_data);

/****************************************************************************
 This function is called on any file modification or lock request. If a file
 is level 2 oplocked then it must tell all other level 2 holders to break to
 none.
****************************************************************************/

static void contend_level2_oplocks_begin_default(files_struct *fsp,
					      enum level2_contention_type type)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;
	struct tevent_immediate *im;
	struct break_to_none_state *state;
	bool has_read_oplocks;

	/*
	 * If this file is level II oplocked then we need
	 * to grab the shared memory lock and inform all
	 * other files with a level II lock that they need
	 * to flush their read caches. We keep the lock over
	 * the shared memory area whilst doing this.
	 */

	if (fsp_lease_type_is_exclusive(fsp)) {
		/*
		 * There can't be any level2 oplocks, we're alone.
		 */
		return;
	}

	has_read_oplocks = file_has_read_oplocks(fsp);
	if (!has_read_oplocks) {
		DEBUG(10, ("No read oplocks around\n"));
		return;
	}

	/*
	 * When we get here we might have a brlock entry locked. Also
	 * locking the share mode entry would violate the locking
	 * order. Breaking level2 oplocks to none is asynchronous
	 * anyway, so we postpone this into an immediate event.
	 */

	state = talloc(sconn, struct break_to_none_state);
	if (state == NULL) {
		DEBUG(1, ("talloc failed\n"));
		return;
	}
	*state = (struct break_to_none_state) {
		.sconn = sconn, .id = fsp->file_id,
	};

	if (fsp->oplock_type == LEASE_OPLOCK) {
		state->client_guid = *fsp_client_guid(fsp);
		state->lease_key = fsp->lease->lease.lease_key;
		DEBUG(10, ("Breaking through lease key %"PRIu64"/%"PRIu64"\n",
			   state->lease_key.data[0],
			   state->lease_key.data[1]));
	}

	im = tevent_create_immediate(state);
	if (im == NULL) {
		DEBUG(1, ("tevent_create_immediate failed\n"));
		TALLOC_FREE(state);
		return;
	}
	tevent_schedule_immediate(im, sconn->ev_ctx, do_break_to_none, state);
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

static bool do_break_lease_to_none(struct share_mode_lock *lck,
				   struct share_mode_entry *e,
				   void *private_data)
{
	struct break_to_none_state *state = talloc_get_type_abort(
		private_data, struct break_to_none_state);
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

	if ((current_state & SMB2_LEASE_READ) == 0) {
		return false;
	}

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

static void do_break_to_none(struct tevent_context *ctx,
			     struct tevent_immediate *im,
			     void *private_data)
{
	struct break_to_none_state *state = talloc_get_type_abort(
		private_data, struct break_to_none_state);
	uint32_t i;
	struct share_mode_lock *lck;
	struct share_mode_data *d;
	bool ok;

	lck = get_existing_share_mode_lock(talloc_tos(), state->id);
	if (lck == NULL) {
		DEBUG(1, ("%s: failed to lock share mode entry for file %s.\n",
			  __func__, file_id_string_tos(&state->id)));
		goto done;
	}
	d = lck->data;

	/*
	 * Walk leases and oplocks separately: We have to send one break per
	 * lease. If we have multiple share_mode_entry having a common lease,
	 * we would break the lease twice if we don't walk the leases list
	 * separately.
	 */

	ok = share_mode_forall_leases(lck, do_break_lease_to_none, state);
	if (!ok) {
		DBG_WARNING("share_mode_forall_leases failed\n");
	}

	for(i = 0; i < d->num_share_modes; i++) {
		struct share_mode_entry *e = &d->share_modes[i];

		if (!is_valid_share_mode_entry(e)) {
			continue;
		}
		if (e->op_type == LEASE_OPLOCK) {
			/*
			 * Took care of those in the loop above
			 */
			continue;
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

		DEBUG(10, ("%s: share_entry[%i]->op_type == %d\n", __func__,
			   i, e->op_type ));

		if (e->op_type == NO_OPLOCK) {
			continue;
		}

		/* Paranoia .... */
		if (EXCLUSIVE_OPLOCK_TYPE(e->op_type)) {
			DEBUG(0,("%s: PANIC. "
				 "share mode entry %d is an exclusive "
				 "oplock !\n", __func__, i ));
			TALLOC_FREE(lck);
			abort();
		}

		send_break_to_none(state->sconn->msg_ctx, &state->id, e);
	}

	/* We let the message receivers handle removing the oplock state
	   in the share mode lock db. */

	TALLOC_FREE(lck);
done:
	TALLOC_FREE(state);
	return;
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
 Linearize a share mode entry struct to an internal oplock break message.
****************************************************************************/

void share_mode_entry_to_message(char *msg, const struct file_id *id,
				 const struct share_mode_entry *e)
{
	SIVAL(msg,OP_BREAK_MSG_PID_OFFSET,(uint32_t)e->pid.pid);
	SBVAL(msg,OP_BREAK_MSG_MID_OFFSET,e->op_mid);
	SSVAL(msg,OP_BREAK_MSG_OP_TYPE_OFFSET,e->op_type);
	SIVAL(msg,OP_BREAK_MSG_ACCESS_MASK_OFFSET,e->access_mask);
	SIVAL(msg,OP_BREAK_MSG_SHARE_ACCESS_OFFSET,e->share_access);
	SIVAL(msg,OP_BREAK_MSG_PRIV_OFFSET,e->private_options);
	SIVAL(msg,OP_BREAK_MSG_TIME_SEC_OFFSET,(uint32_t)e->time.tv_sec);
	SIVAL(msg,OP_BREAK_MSG_TIME_USEC_OFFSET,(uint32_t)e->time.tv_usec);
	/*
	 * "id" used to be part of share_mode_entry, thus the strange
	 * place to put this. Feel free to move somewhere else :-)
	 */
	push_file_id_24(msg+OP_BREAK_MSG_DEV_OFFSET, id);
	SIVAL(msg,OP_BREAK_MSG_FILE_ID_OFFSET,e->share_file_id);
	SIVAL(msg,OP_BREAK_MSG_UID_OFFSET,e->uid);
	SSVAL(msg,OP_BREAK_MSG_FLAGS_OFFSET,e->flags);
	SIVAL(msg,OP_BREAK_MSG_NAME_HASH_OFFSET,e->name_hash);
	SIVAL(msg,OP_BREAK_MSG_VNN_OFFSET,e->pid.vnn);
}

/****************************************************************************
 De-linearize an internal oplock break message to a share mode entry struct.
****************************************************************************/

void message_to_share_mode_entry(struct file_id *id,
				 struct share_mode_entry *e,
				 const char *msg)
{
	e->pid.pid = (pid_t)IVAL(msg,OP_BREAK_MSG_PID_OFFSET);
	e->op_mid = BVAL(msg,OP_BREAK_MSG_MID_OFFSET);
	e->op_type = SVAL(msg,OP_BREAK_MSG_OP_TYPE_OFFSET);
	e->access_mask = IVAL(msg,OP_BREAK_MSG_ACCESS_MASK_OFFSET);
	e->share_access = IVAL(msg,OP_BREAK_MSG_SHARE_ACCESS_OFFSET);
	e->private_options = IVAL(msg,OP_BREAK_MSG_PRIV_OFFSET);
	e->time.tv_sec = (time_t)IVAL(msg,OP_BREAK_MSG_TIME_SEC_OFFSET);
	e->time.tv_usec = (int)IVAL(msg,OP_BREAK_MSG_TIME_USEC_OFFSET);
	/*
	 * "id" used to be part of share_mode_entry, thus the strange
	 * place to put this. Feel free to move somewhere else :-)
	 */
	pull_file_id_24(msg+OP_BREAK_MSG_DEV_OFFSET, id);
	e->share_file_id = (unsigned long)IVAL(msg,OP_BREAK_MSG_FILE_ID_OFFSET);
	e->uid = (uint32_t)IVAL(msg,OP_BREAK_MSG_UID_OFFSET);
	e->flags = (uint16_t)SVAL(msg,OP_BREAK_MSG_FLAGS_OFFSET);
	e->name_hash = IVAL(msg,OP_BREAK_MSG_NAME_HASH_OFFSET);
	e->pid.vnn = IVAL(msg,OP_BREAK_MSG_VNN_OFFSET);
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
