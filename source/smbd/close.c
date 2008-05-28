/*
   Unix SMB/CIFS implementation.
   file closing
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 1992-2007.
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

#include "includes.h"

extern struct current_user current_user;

/****************************************************************************
 Run a file if it is a magic script.
****************************************************************************/

static void check_magic(struct files_struct *fsp)
{
	int ret;
	const char *magic_output = NULL;
	SMB_STRUCT_STAT st;
	int tmp_fd, outfd;
	TALLOC_CTX *ctx = NULL;
	const char *p;
	struct connection_struct *conn = fsp->conn;

	if (!*lp_magicscript(SNUM(conn))) {
		return;
	}

	DEBUG(5,("checking magic for %s\n",fsp->fsp_name));

	if (!(p = strrchr_m(fsp->fsp_name,'/'))) {
		p = fsp->fsp_name;
	} else {
		p++;
	}

	if (!strequal(lp_magicscript(SNUM(conn)),p)) {
		return;
	}

	ctx = talloc_stackframe();

	if (*lp_magicoutput(SNUM(conn))) {
		magic_output = lp_magicoutput(SNUM(conn));
	} else {
		magic_output = talloc_asprintf(ctx,
				"%s.out",
				fsp->fsp_name);
	}
	if (!magic_output) {
		TALLOC_FREE(ctx);
		return;
	}

	chmod(fsp->fsp_name,0755);
	ret = smbrun(fsp->fsp_name,&tmp_fd);
	DEBUG(3,("Invoking magic command %s gave %d\n",
		fsp->fsp_name,ret));

	unlink(fsp->fsp_name);
	if (ret != 0 || tmp_fd == -1) {
		if (tmp_fd != -1) {
			close(tmp_fd);
		}
		TALLOC_FREE(ctx);
		return;
	}
	outfd = open(magic_output, O_CREAT|O_EXCL|O_RDWR, 0600);
	if (outfd == -1) {
		close(tmp_fd);
		TALLOC_FREE(ctx);
		return;
	}

	if (sys_fstat(tmp_fd,&st) == -1) {
		close(tmp_fd);
		close(outfd);
		return;
	}

	transfer_file(tmp_fd,outfd,(SMB_OFF_T)st.st_size);
	close(tmp_fd);
	close(outfd);
	TALLOC_FREE(ctx);
}

/****************************************************************************
  Common code to close a file or a directory.
****************************************************************************/

static NTSTATUS close_filestruct(files_struct *fsp)
{
	NTSTATUS status = NT_STATUS_OK;
	connection_struct *conn = fsp->conn;
    
	if (fsp->fh->fd != -1) {
		if(flush_write_cache(fsp, CLOSE_FLUSH) == -1) {
			status = map_nt_error_from_unix(errno);
		}
		delete_write_cache(fsp);
	}

	conn->num_files_open--;
	return status;
}    

/****************************************************************************
 If any deferred opens are waiting on this close, notify them.
****************************************************************************/

static void notify_deferred_opens(struct share_mode_lock *lck)
{
 	int i;
 
 	for (i=0; i<lck->num_share_modes; i++) {
 		struct share_mode_entry *e = &lck->share_modes[i];
 
 		if (!is_deferred_open_entry(e)) {
 			continue;
 		}
 
 		if (procid_is_me(&e->pid)) {
 			/*
 			 * We need to notify ourself to retry the open.  Do
 			 * this by finding the queued SMB record, moving it to
 			 * the head of the queue and changing the wait time to
 			 * zero.
 			 */
 			schedule_deferred_open_smb_message(e->op_mid);
 		} else {
			char msg[MSG_SMB_SHARE_MODE_ENTRY_SIZE];

			share_mode_entry_to_message(msg, e);

 			messaging_send_buf(smbd_messaging_context(),
					   e->pid, MSG_SMB_OPEN_RETRY,
					   (uint8 *)msg,
					   MSG_SMB_SHARE_MODE_ENTRY_SIZE);
 		}
 	}
}

/****************************************************************************
 Delete all streams
****************************************************************************/

static NTSTATUS delete_all_streams(connection_struct *conn, const char *fname)
{
	struct stream_struct *stream_info;
	int i;
	unsigned int num_streams;
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;

	status = SMB_VFS_STREAMINFO(conn, NULL, fname, talloc_tos(),
				    &num_streams, &stream_info);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_IMPLEMENTED)) {
		DEBUG(10, ("no streams around\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("SMB_VFS_STREAMINFO failed: %s\n",
			   nt_errstr(status)));
		goto fail;
	}

	DEBUG(10, ("delete_all_streams found %d streams\n",
		   num_streams));

	if (num_streams == 0) {
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	for (i=0; i<num_streams; i++) {
		int res;
		char *streamname;

		if (strequal(stream_info[i].name, "::$DATA")) {
			continue;
		}

		streamname = talloc_asprintf(talloc_tos(), "%s%s", fname,
					     stream_info[i].name);

		if (streamname == NULL) {
			DEBUG(0, ("talloc_aprintf failed\n"));
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}

		res = SMB_VFS_UNLINK(conn, streamname);

		TALLOC_FREE(streamname);

		if (res == -1) {
			status = map_nt_error_from_unix(errno);
			DEBUG(10, ("Could not delete stream %s: %s\n",
				   streamname, strerror(errno)));
			break;
		}
	}

 fail:
	TALLOC_FREE(frame);
	return status;
}

/****************************************************************************
 Deal with removing a share mode on last close.
****************************************************************************/

static NTSTATUS close_remove_share_mode(files_struct *fsp,
					enum file_close_type close_type)
{
	connection_struct *conn = fsp->conn;
	bool delete_file = false;
	bool changed_user = false;
	struct share_mode_lock *lck;
	SMB_STRUCT_STAT sbuf;
	NTSTATUS status = NT_STATUS_OK;
	int ret;
	struct file_id id;

	/*
	 * Lock the share entries, and determine if we should delete
	 * on close. If so delete whilst the lock is still in effect.
	 * This prevents race conditions with the file being created. JRA.
	 */

	lck = get_share_mode_lock(talloc_tos(), fsp->file_id, NULL, NULL,
				  NULL);

	if (lck == NULL) {
		DEBUG(0, ("close_remove_share_mode: Could not get share mode "
			  "lock for file %s\n", fsp->fsp_name));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (fsp->write_time_forced) {
		set_close_write_time(fsp, lck->changed_write_time);
	}

	if (!del_share_mode(lck, fsp)) {
		DEBUG(0, ("close_remove_share_mode: Could not delete share "
			  "entry for file %s\n", fsp->fsp_name));
	}

	if (fsp->initial_delete_on_close && (lck->delete_token == NULL)) {
		bool became_user = False;

		/* Initial delete on close was set and no one else
		 * wrote a real delete on close. */

		if (current_user.vuid != fsp->vuid) {
			become_user(conn, fsp->vuid);
			became_user = True;
		}
		set_delete_on_close_lck(lck, True, &current_user.ut);
		if (became_user) {
			unbecome_user();
		}
	}

	delete_file = lck->delete_on_close;

	if (delete_file) {
		int i;
		/* See if others still have the file open. If this is the
		 * case, then don't delete. If all opens are POSIX delete now. */
		for (i=0; i<lck->num_share_modes; i++) {
			struct share_mode_entry *e = &lck->share_modes[i];
			if (is_valid_share_mode_entry(e)) {
				if (fsp->posix_open && (e->flags & SHARE_MODE_FLAG_POSIX_OPEN)) {
					continue;
				}
				delete_file = False;
				break;
			}
		}
	}

	/* Notify any deferred opens waiting on this close. */
	notify_deferred_opens(lck);
	reply_to_oplock_break_requests(fsp);

	/*
	 * NT can set delete_on_close of the last open
	 * reference to a file.
	 */

	if (!(close_type == NORMAL_CLOSE || close_type == SHUTDOWN_CLOSE)
	    || !delete_file
	    || (lck->delete_token == NULL)) {
		TALLOC_FREE(lck);
		return NT_STATUS_OK;
	}

	/*
	 * Ok, we have to delete the file
	 */

	DEBUG(5,("close_remove_share_mode: file %s. Delete on close was set "
		 "- deleting file.\n", fsp->fsp_name));

	/*
	 * Don't try to update the write time when we delete the file
	 */
	fsp->update_write_time_on_close = false;

	if (!unix_token_equal(lck->delete_token, &current_user.ut)) {
		/* Become the user who requested the delete. */

		DEBUG(5,("close_remove_share_mode: file %s. "
			"Change user to uid %u\n",
			fsp->fsp_name,
			(unsigned int)lck->delete_token->uid));

		if (!push_sec_ctx()) {
			smb_panic("close_remove_share_mode: file %s. failed to push "
				  "sec_ctx.\n");
		}

		set_sec_ctx(lck->delete_token->uid,
			    lck->delete_token->gid,
			    lck->delete_token->ngroups,
			    lck->delete_token->groups,
			    NULL);

		changed_user = true;
	}

	/* We can only delete the file if the name we have is still valid and
	   hasn't been renamed. */

	if (fsp->posix_open) {
		ret = SMB_VFS_LSTAT(conn,fsp->fsp_name,&sbuf);
	} else {
		ret = SMB_VFS_STAT(conn,fsp->fsp_name,&sbuf);
	}

	if (ret != 0) {
		DEBUG(5,("close_remove_share_mode: file %s. Delete on close "
			 "was set and stat failed with error %s\n",
			 fsp->fsp_name, strerror(errno) ));
		/*
		 * Don't save the errno here, we ignore this error
		 */
		goto done;
	}

	id = vfs_file_id_from_sbuf(conn, &sbuf);

	if (!file_id_equal(&fsp->file_id, &id)) {
		DEBUG(5,("close_remove_share_mode: file %s. Delete on close "
			 "was set and dev and/or inode does not match\n",
			 fsp->fsp_name ));
		DEBUG(5,("close_remove_share_mode: file %s. stored file_id %s, "
			 "stat file_id %s\n",
			 fsp->fsp_name,
			 file_id_string_tos(&fsp->file_id),
			 file_id_string_tos(&id)));
		/*
		 * Don't save the errno here, we ignore this error
		 */
		goto done;
	}

	if ((conn->fs_capabilities & FILE_NAMED_STREAMS)
	    && !is_ntfs_stream_name(fsp->fsp_name)) {

		status = delete_all_streams(conn, fsp->fsp_name);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(5, ("delete_all_streams failed: %s\n",
				  nt_errstr(status)));
			goto done;
		}
	}


	if (SMB_VFS_UNLINK(conn,fsp->fsp_name) != 0) {
		/*
		 * This call can potentially fail as another smbd may
		 * have had the file open with delete on close set and
		 * deleted it when its last reference to this file
		 * went away. Hence we log this but not at debug level
		 * zero.
		 */

		DEBUG(5,("close_remove_share_mode: file %s. Delete on close "
			 "was set and unlink failed with error %s\n",
			 fsp->fsp_name, strerror(errno) ));

		status = map_nt_error_from_unix(errno);
	}

	notify_fname(conn, NOTIFY_ACTION_REMOVED,
		     FILE_NOTIFY_CHANGE_FILE_NAME,
		     fsp->fsp_name);

	/* As we now have POSIX opens which can unlink
 	 * with other open files we may have taken
 	 * this code path with more than one share mode
 	 * entry - ensure we only delete once by resetting
 	 * the delete on close flag. JRA.
 	 */

	set_delete_on_close_lck(lck, False, NULL);

 done:

	if (changed_user) {
		/* unbecome user. */
		pop_sec_ctx();
	}

	TALLOC_FREE(lck);
	return status;
}

void set_close_write_time(struct files_struct *fsp, struct timespec ts)
{
	DEBUG(6,("close_write_time: %s" , time_to_asc(convert_timespec_to_time_t(ts))));

	if (null_timespec(ts)) {
		return;
	}
	/*
	 * if the write time on close is explict set, then don't
	 * need to fix it up to the value in the locking db
	 */
	fsp->write_time_forced = false;

	fsp->update_write_time_on_close = true;
	fsp->close_write_time = ts;
}

static NTSTATUS update_write_time_on_close(struct files_struct *fsp)
{
	SMB_STRUCT_STAT sbuf;
	struct timespec ts[2];
	NTSTATUS status;

	ZERO_STRUCT(sbuf);
	ZERO_STRUCT(ts);

	if (!fsp->update_write_time_on_close) {
		return NT_STATUS_OK;
	}

	if (null_timespec(fsp->close_write_time)) {
		fsp->close_write_time = timespec_current();
	}

	/* Ensure we have a valid stat struct for the source. */
	if (fsp->fh->fd != -1) {
		if (SMB_VFS_FSTAT(fsp, &sbuf) == -1) {
			return map_nt_error_from_unix(errno);
		}
	} else {
		if (SMB_VFS_STAT(fsp->conn,fsp->fsp_name,&sbuf) == -1) {
			return map_nt_error_from_unix(errno);
		}
	}

	if (!VALID_STAT(sbuf)) {
		/* if it doesn't seem to be a real file */
		return NT_STATUS_OK;
	}

	ts[1] = fsp->close_write_time;
	status = smb_set_file_time(fsp->conn, fsp, fsp->fsp_name,
				   &sbuf, ts, true);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Close a file.

 close_type can be NORMAL_CLOSE=0,SHUTDOWN_CLOSE,ERROR_CLOSE.
 printing and magic scripts are only run on normal close.
 delete on close is done on normal and shutdown close.
****************************************************************************/

static NTSTATUS close_normal_file(files_struct *fsp, enum file_close_type close_type)
{
	NTSTATUS status = NT_STATUS_OK;
	NTSTATUS saved_status1 = NT_STATUS_OK;
	NTSTATUS saved_status2 = NT_STATUS_OK;
	NTSTATUS saved_status3 = NT_STATUS_OK;
	NTSTATUS saved_status4 = NT_STATUS_OK;
	connection_struct *conn = fsp->conn;

	if (fsp->aio_write_behind) {
		/*
	 	 * If we're finishing write behind on a close we can get a write
		 * error here, we must remember this.
		 */
		int ret = wait_for_aio_completion(fsp);
		if (ret) {
			saved_status1 = map_nt_error_from_unix(ret);
		}
	} else {
		cancel_aio_by_fsp(fsp);
	}
 
	/*
	 * If we're flushing on a close we can get a write
	 * error here, we must remember this.
	 */

	saved_status2 = close_filestruct(fsp);

	if (fsp->print_file) {
		print_fsp_end(fsp, close_type);
		file_free(fsp);
		return NT_STATUS_OK;
	}

	/* If this is an old DOS or FCB open and we have multiple opens on
	   the same handle we only have one share mode. Ensure we only remove
	   the share mode on the last close. */

	if (fsp->fh->ref_count == 1) {
		/* Should we return on error here... ? */
		saved_status3 = close_remove_share_mode(fsp, close_type);
	}

	if(fsp->oplock_type) {
		release_file_oplock(fsp);
	}

	locking_close_file(smbd_messaging_context(), fsp);

	status = fd_close(fsp);

	/* check for magic scripts */
	if (close_type == NORMAL_CLOSE) {
		check_magic(fsp);
	}

	/*
	 * Ensure pending modtime is set after close.
	 */

	saved_status4 = update_write_time_on_close(fsp);

	if (NT_STATUS_IS_OK(status)) {
		if (!NT_STATUS_IS_OK(saved_status1)) {
			status = saved_status1;
		} else if (!NT_STATUS_IS_OK(saved_status2)) {
			status = saved_status2;
		} else if (!NT_STATUS_IS_OK(saved_status3)) {
			status = saved_status3;
		} else if (!NT_STATUS_IS_OK(saved_status4)) {
			status = saved_status4;
		}
	}

	DEBUG(2,("%s closed file %s (numopen=%d) %s\n",
		conn->user,fsp->fsp_name,
		conn->num_files_open,
		nt_errstr(status) ));

	file_free(fsp);
	return status;
}

/****************************************************************************
 Close a directory opened by an NT SMB call. 
****************************************************************************/
  
static NTSTATUS close_directory(files_struct *fsp, enum file_close_type close_type)
{
	struct share_mode_lock *lck = 0;
	bool delete_dir = False;
	NTSTATUS status = NT_STATUS_OK;

	/*
	 * NT can set delete_on_close of the last open
	 * reference to a directory also.
	 */

	lck = get_share_mode_lock(talloc_tos(), fsp->file_id, NULL, NULL,
				  NULL);

	if (lck == NULL) {
		DEBUG(0, ("close_directory: Could not get share mode lock for %s\n", fsp->fsp_name));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!del_share_mode(lck, fsp)) {
		DEBUG(0, ("close_directory: Could not delete share entry for %s\n", fsp->fsp_name));
	}

	if (fsp->initial_delete_on_close) {
		bool became_user = False;

		/* Initial delete on close was set - for
		 * directories we don't care if anyone else
		 * wrote a real delete on close. */

		if (current_user.vuid != fsp->vuid) {
			become_user(fsp->conn, fsp->vuid);
			became_user = True;
		}
		send_stat_cache_delete_message(fsp->fsp_name);
		set_delete_on_close_lck(lck, True, &current_user.ut);
		if (became_user) {
			unbecome_user();
		}
	}

	delete_dir = lck->delete_on_close;

	if (delete_dir) {
		int i;
		/* See if others still have the dir open. If this is the
		 * case, then don't delete. If all opens are POSIX delete now. */
		for (i=0; i<lck->num_share_modes; i++) {
			struct share_mode_entry *e = &lck->share_modes[i];
			if (is_valid_share_mode_entry(e)) {
				if (fsp->posix_open && (e->flags & SHARE_MODE_FLAG_POSIX_OPEN)) {
					continue;
				}
				delete_dir = False;
				break;
			}
		}
	}

	if ((close_type == NORMAL_CLOSE || close_type == SHUTDOWN_CLOSE) &&
				delete_dir &&
				lck->delete_token) {
	
		/* Become the user who requested the delete. */

		if (!push_sec_ctx()) {
			smb_panic("close_directory: failed to push sec_ctx.\n");
		}

		set_sec_ctx(lck->delete_token->uid,
				lck->delete_token->gid,
				lck->delete_token->ngroups,
				lck->delete_token->groups,
				NULL);

		TALLOC_FREE(lck);

		status = rmdir_internals(talloc_tos(),
				fsp->conn, fsp->fsp_name);

		DEBUG(5,("close_directory: %s. Delete on close was set - "
			 "deleting directory returned %s.\n",
			 fsp->fsp_name, nt_errstr(status)));

		/* unbecome user. */
		pop_sec_ctx();

		/*
		 * Ensure we remove any change notify requests that would
		 * now fail as the directory has been deleted.
		 */

		if(NT_STATUS_IS_OK(status)) {
			remove_pending_change_notify_requests_by_fid(fsp, NT_STATUS_DELETE_PENDING);
		}
	} else {
		TALLOC_FREE(lck);
		remove_pending_change_notify_requests_by_fid(
			fsp, NT_STATUS_OK);
	}

	/*
	 * Do the code common to files and directories.
	 */
	close_filestruct(fsp);
	file_free(fsp);
	return status;
}

/****************************************************************************
 Close a 'stat file' opened internally.
****************************************************************************/
  
static NTSTATUS close_stat(files_struct *fsp)
{
	/*
	 * Do the code common to files and directories.
	 */
	close_filestruct(fsp);
	file_free(fsp);
	return NT_STATUS_OK;
}

/****************************************************************************
 Close a files_struct.
****************************************************************************/
  
NTSTATUS close_file(files_struct *fsp, enum file_close_type close_type)
{
	NTSTATUS status;
	struct files_struct *base_fsp = fsp->base_fsp;

	if(fsp->is_directory) {
		status = close_directory(fsp, close_type);
	} else if (fsp->is_stat) {
		status = close_stat(fsp);
	} else if (fsp->fake_file_handle != NULL) {
		status = close_fake_file(fsp);
	} else {
		status = close_normal_file(fsp, close_type);
	}

	if ((base_fsp != NULL) && (close_type != SHUTDOWN_CLOSE)) {

		/*
		 * fsp was a stream, the base fsp can't be a stream as well
		 *
		 * For SHUTDOWN_CLOSE this is not possible here, because
		 * SHUTDOWN_CLOSE only happens from files.c which walks the
		 * complete list of files. If we mess with more than one fsp
		 * those loops will become confused.
		 */

		SMB_ASSERT(base_fsp->base_fsp == NULL);
		close_file(base_fsp, close_type);
	}

	return status;
}

/****************************************************************************
 Deal with an (authorized) message to close a file given the share mode
 entry.
****************************************************************************/

void msg_close_file(struct messaging_context *msg_ctx,
			void *private_data,
			uint32_t msg_type,
			struct server_id server_id,
			DATA_BLOB *data)
{
	files_struct *fsp = NULL;
	struct share_mode_entry e;

	message_to_share_mode_entry(&e, (char *)data->data);

	if(DEBUGLVL(10)) {
		char *sm_str = share_mode_str(NULL, 0, &e);
		if (!sm_str) {
			smb_panic("talloc failed");
		}
		DEBUG(10,("msg_close_file: got request to close share mode "
			"entry %s\n", sm_str));
		TALLOC_FREE(sm_str);
	}

	fsp = file_find_dif(e.id, e.share_file_id);
	if (!fsp) {
		DEBUG(10,("msg_close_file: failed to find file.\n"));
		return;
	}
	close_file(fsp, NORMAL_CLOSE);
}
