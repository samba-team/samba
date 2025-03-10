/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   read/write to a files_struct
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2000-2002. - write cache.

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
#include "printing.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "smbprofile.h"

/****************************************************************************
 Read from a file.
****************************************************************************/

ssize_t read_file(files_struct *fsp,char *data,off_t pos,size_t n)
{
	off_t new_pos;
	ssize_t ret = 0;
	bool ok;

	/* you can't read from print files */
	if (fsp->print_file) {
		errno = EBADF;
		return -1;
	}

	ok = vfs_valid_pread_range(pos, n);
	if (!ok) {
		errno = EINVAL;
		return -1;
	}

	fh_set_pos(fsp->fh, pos);

	if (n > 0) {
		ret = SMB_VFS_PREAD(fsp,data,n,pos);

		if (ret == -1) {
			return -1;
		}
	}

	DEBUG(10,("read_file (%s): pos = %.0f, size = %lu, returned %lu\n",
		  fsp_str_dbg(fsp), (double)pos, (unsigned long)n, (long)ret));

	new_pos = fh_get_pos(fsp->fh) + ret;
	fh_set_pos(fsp->fh, new_pos);
	fh_set_position_information(fsp->fh, new_pos);

	return(ret);
}

/****************************************************************************
 *Really* write to a file.
****************************************************************************/

static ssize_t real_write_file(struct smb_request *req,
				files_struct *fsp,
				const char *data,
				off_t pos,
				size_t n)
{
	ssize_t ret;
	bool ok;

	ok = vfs_valid_pwrite_range(fsp, pos, n);
	if (!ok) {
		errno = EINVAL;
		return -1;
	}

	if (n == 0) {
		return 0;
	}

	fh_set_pos(fsp->fh, pos);
	if (pos &&
	    lp_strict_allocate(SNUM(fsp->conn)) &&
	    !fsp->fsp_flags.is_sparse)
	{
		if (vfs_fill_sparse(fsp, pos) == -1) {
			return -1;
		}
	}
	ret = vfs_pwrite_data(req, fsp, data, n, pos);

	DEBUG(10,("real_write_file (%s): pos = %.0f, size = %lu, returned %ld\n",
		  fsp_str_dbg(fsp), (double)pos, (unsigned long)n, (long)ret));

	if (ret != -1) {
		off_t new_pos = fh_get_pos(fsp->fh) + ret;
		fh_set_pos(fsp->fh, new_pos);

/* Yes - this is correct - writes don't update this. JRA. */
/* Found by Samba4 tests. */
#if 0
		fsp->position_information = fsp->pos;
#endif
	}

	return ret;
}

/*********************************************************
 Immediately update write time
*********************************************************/

void trigger_write_time_update_immediate(struct files_struct *fsp,
					 bool update_mtime,
					 bool update_ctime)
{
	struct smb_file_time ft;

	init_smb_file_time(&ft);

	if (fsp->fsp_flags.posix_open) {
		return;
	}

        if (fsp->fsp_flags.write_time_forced) {
		/*
		 * No point - "sticky" write times
		 * in effect.
		 */
                return;
        }

	DEBUG(5, ("Update write time immediate on %s\n",
		  fsp_str_dbg(fsp)));

	if (update_mtime) {
		/*
		 * Changing mtime would also update ctime and so implicitly
		 * handle the update_ctime=true case.
		 */
		ft.mtime = timespec_current();
	} else if (update_ctime && !update_mtime) {
		/*
		 * The only way to update ctime is by changing *something* in
		 * the inode, atime being the only file metadata I could come up
		 * with we can fiddle with to achieve this.
		 */
		ft.atime.tv_nsec = UTIME_NOW;
	}

	/* Now set on disk - takes care of notify. */
	(void)smb_set_file_time(fsp->conn, fsp, fsp->fsp_name, &ft, false);
}

/*
 * If this is a sticky-write time handle, refresh the current mtime
 * so we can restore it after a modification.
 */
void prepare_file_modified(files_struct *fsp,
			   struct file_modified_state *state)
{
	int ret;

	if (!fsp->fsp_flags.write_time_forced) {
		return;
	}

	ZERO_STRUCTP(state);

	ret = SMB_VFS_FSTAT(fsp, &state->st);
	if (ret != 0) {
		DBG_ERR("Prepare [%s] failed: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
		return;
	}

	state->valid = true;
	return;
}

void mark_file_modified(files_struct *fsp,
			bool modified,
			struct file_modified_state *modified_state)
{
	int dosmode;
	NTSTATUS status;

	if (fsp->fsp_flags.write_time_forced &&
	    modified_state->valid)
	{
		struct smb_file_time ft;

		init_smb_file_time(&ft);
		ft.mtime = modified_state->st.st_ex_mtime;

		/*
		 * Pave over the "cached" stat info mtime in the fsp,
		 * vfs_default checks this and if the existing time matches what
		 * we're trying to set, it skips setting the time. file_ntimes()
		 * will fill the value with what we've set.
		 */
		fsp->fsp_name->st.st_ex_mtime = (struct timespec){};

		status = smb_set_file_time(fsp->conn,
					   fsp,
					   fsp->fsp_name,
					   &ft,
					   false);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("smb_set_file_time [%s] failed: %s\n",
				fsp_str_dbg(fsp), nt_errstr(status));
		}
	}

	if (fsp->fsp_flags.modified) {
		return;
	}

	/*
	 * The modified fsp_flag triggers a directory lease breaks when closing
	 * the handle and this must only happen after writing to a
	 * file. Modifying a file by other means that affect the file state
	 * causing directory lease breaks is handled in the corresponding
	 * functions explicitly by calling notify_fname() with
	 * NOTIFY_ACTION_DIRLEASE_BREAK.
	 */
	fsp->fsp_flags.modified = modified;

	if (!(lp_store_dos_attributes(SNUM(fsp->conn)) ||
	      MAP_ARCHIVE(fsp->conn))) {
		return;
	}

	dosmode = fdos_mode(fsp);
	if (dosmode & FILE_ATTRIBUTE_ARCHIVE) {
		return;
	}
	file_set_dosmode(fsp->conn, fsp->fsp_name,
			 dosmode | FILE_ATTRIBUTE_ARCHIVE, NULL, false);
}

/****************************************************************************
 Write to a file.
****************************************************************************/

ssize_t write_file(struct smb_request *req,
			files_struct *fsp,
			const char *data,
			off_t pos,
			size_t n)
{
	struct file_modified_state state;
	ssize_t total_written = 0;

	if (fsp->print_file) {
		uint32_t t;
		int ret;

		ret = print_spool_write(fsp, data, n, pos, &t);
		if (ret) {
			errno = ret;
			return -1;
		}
		return t;
	}

	if (!fsp->fsp_flags.can_write) {
		errno = EPERM;
		return -1;
	}

	/* This should actually be improved to span the write. */
	contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_WRITE);
	contend_level2_oplocks_end(fsp, LEVEL2_CONTEND_WRITE);

	prepare_file_modified(fsp, &state);

	total_written = real_write_file(req, fsp, data, pos, n);
	if (total_written != -1) {
		mark_file_modified(fsp, true, &state);
	}
	return total_written;
}

/*******************************************************************
sync a file
********************************************************************/

NTSTATUS sync_file(connection_struct *conn, files_struct *fsp, bool write_through)
{
	if (fsp_get_io_fd(fsp) == -1)
		return NT_STATUS_INVALID_HANDLE;

	if (lp_strict_sync(SNUM(conn)) &&
	    (lp_sync_always(SNUM(conn)) || write_through)) {
		int ret;
		ret = smb_vfs_fsync_sync(fsp);
		if (ret == -1) {
			return map_nt_error_from_unix(errno);
		}
	}
	return NT_STATUS_OK;
}
