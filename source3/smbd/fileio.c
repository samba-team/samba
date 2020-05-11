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

	fsp->fh->pos = pos;

	if (n > 0) {
		ret = SMB_VFS_PREAD(fsp,data,n,pos);

		if (ret == -1) {
			return -1;
		}
	}

	DEBUG(10,("read_file (%s): pos = %.0f, size = %lu, returned %lu\n",
		  fsp_str_dbg(fsp), (double)pos, (unsigned long)n, (long)ret));

	fsp->fh->pos += ret;
	fsp->fh->position_information = fsp->fh->pos;

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

	ok = vfs_valid_pwrite_range(pos, n);
	if (!ok) {
		errno = EINVAL;
		return -1;
	}

	if (n == 0) {
		return 0;
	}

	fsp->fh->pos = pos;
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
		fsp->fh->pos += ret;

/* Yes - this is correct - writes don't update this. JRA. */
/* Found by Samba4 tests. */
#if 0
		fsp->position_information = fsp->pos;
#endif
	}

	return ret;
}

void fsp_flush_write_time_update(struct files_struct *fsp)
{
	/*
	 * Note this won't expect any impersonation!
	 * So don't call any SMB_VFS operations here!
	 */

	DEBUG(5, ("Update write time on %s\n", fsp_str_dbg(fsp)));

	trigger_write_time_update_immediate(fsp);
}

static void update_write_time_handler(struct tevent_context *ctx,
				      struct tevent_timer *te,
				      struct timeval now,
				      void *private_data)
{
	files_struct *fsp = (files_struct *)private_data;
	fsp_flush_write_time_update(fsp);
}

/*********************************************************
 Schedule a write time update for WRITE_TIME_UPDATE_USEC_DELAY
 in the future.
*********************************************************/

void trigger_write_time_update(struct files_struct *fsp)
{
	int delay;

	if (fsp->posix_flags & FSP_POSIX_FLAGS_OPEN) {
		/* Don't use delayed writes on POSIX files. */
		return;
	}

	if (fsp->fsp_flags.write_time_forced) {
		/* No point - "sticky" write times
		 * in effect.
		 */
		return;
	}

	/* We need to remember someone did a write
	 * and update to current time on close. */

	fsp->fsp_flags.update_write_time_on_close = true;

	if (fsp->fsp_flags.update_write_time_triggered) {
		/*
		 * We only update the write time after 2 seconds
		 * on the first normal write. After that
		 * no other writes affect this until close.
		 */
		return;
	}
	fsp->fsp_flags.update_write_time_triggered = true;

	delay = lp_parm_int(SNUM(fsp->conn),
			    "smbd", "writetimeupdatedelay",
			    WRITE_TIME_UPDATE_USEC_DELAY);

	DEBUG(5, ("Update write time %d usec later on %s\n",
		  delay, fsp_str_dbg(fsp)));

	/* trigger the update 2 seconds later */
	fsp->update_write_time_event =
		tevent_add_timer(fsp->conn->sconn->ev_ctx, NULL,
				 timeval_current_ofs_usec(delay),
				 update_write_time_handler, fsp);
}

void trigger_write_time_update_immediate(struct files_struct *fsp)
{
	struct smb_file_time ft;

	init_smb_file_time(&ft);

	if (fsp->posix_flags & FSP_POSIX_FLAGS_OPEN) {
		/* Don't use delayed writes on POSIX files. */
		return;
	}

        if (fsp->fsp_flags.write_time_forced) {
		/*
		 * No point - "sticky" write times
		 * in effect.
		 */
                return;
        }

	TALLOC_FREE(fsp->update_write_time_event);
	DEBUG(5, ("Update write time immediate on %s\n",
		  fsp_str_dbg(fsp)));

	/* After an immediate update, reset the trigger. */
	fsp->fsp_flags.update_write_time_triggered = true;
        fsp->fsp_flags.update_write_time_on_close = false;

	ft.mtime = timespec_current();

	/* Update the time in the open file db. */
	(void)set_write_time(fsp->file_id, ft.mtime);

	/* Now set on disk - takes care of notify. */
	(void)smb_set_file_time(fsp->conn, fsp, fsp->fsp_name, &ft, false);
}

void mark_file_modified(files_struct *fsp)
{
	int dosmode;

	trigger_write_time_update(fsp);

	if (fsp->fsp_flags.modified) {
		return;
	}

	fsp->fsp_flags.modified = true;

	if (fsp->posix_flags & FSP_POSIX_FLAGS_OPEN) {
		return;
	}
	if (!(lp_store_dos_attributes(SNUM(fsp->conn)) ||
	      MAP_ARCHIVE(fsp->conn))) {
		return;
	}

	dosmode = dos_mode(fsp->conn, fsp->fsp_name);
	if (IS_DOS_ARCHIVE(dosmode)) {
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

	mark_file_modified(fsp);

	/*
	 * If this file is level II oplocked then we need
	 * to grab the shared memory lock and inform all
	 * other files with a level II lock that they need
	 * to flush their read caches. We keep the lock over
	 * the shared memory area whilst doing this.
	 */

	/* This should actually be improved to span the write. */
	contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_WRITE);
	contend_level2_oplocks_end(fsp, LEVEL2_CONTEND_WRITE);

	total_written = real_write_file(req, fsp, data, pos, n);
	return total_written;
}

/*******************************************************************
sync a file
********************************************************************/

NTSTATUS sync_file(connection_struct *conn, files_struct *fsp, bool write_through)
{
       	if (fsp->fh->fd == -1)
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
