/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   file closing
   Copyright (C) Andrew Tridgell 1992-1998
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

/****************************************************************************
run a file if it is a magic script
****************************************************************************/
static void check_magic(files_struct *fsp,connection_struct *conn)
{
  if (!*lp_magicscript(SNUM(conn)))
    return;

  DEBUG(5,("checking magic for %s\n",fsp->fsp_name));

  {
    char *p;
    if (!(p = strrchr(fsp->fsp_name,'/')))
      p = fsp->fsp_name;
    else
      p++;

    if (!strequal(lp_magicscript(SNUM(conn)),p))
      return;
  }

  {
    int ret;
    pstring magic_output;
    pstring fname;
	SMB_STRUCT_STAT st;
	int tmp_fd, outfd;

    pstrcpy(fname,fsp->fsp_name);
    if (*lp_magicoutput(SNUM(conn)))
      pstrcpy(magic_output,lp_magicoutput(SNUM(conn)));
    else
      slprintf(magic_output,sizeof(fname)-1, "%s.out",fname);

    chmod(fname,0755);
    ret = smbrun(fname,&tmp_fd);
    DEBUG(3,("Invoking magic command %s gave %d\n",fname,ret));
    unlink(fname);
	if (ret != 0 || tmp_fd == -1) {
		if (tmp_fd != -1)
			close(tmp_fd);
		return;
	}
	outfd = open(magic_output, O_CREAT|O_EXCL|O_RDWR, 0600);
	if (outfd == -1) {
		close(tmp_fd);
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
  }
}

/****************************************************************************
  Common code to close a file or a directory.
****************************************************************************/

static int close_filestruct(files_struct *fsp)
{   
	connection_struct *conn = fsp->conn;
	int ret = 0;
    
	if (fsp->fd != -1) {
		if(flush_write_cache(fsp, CLOSE_FLUSH) == -1)
			ret = -1;

		delete_write_cache(fsp);
	}

	fsp->is_directory = False; 
    
	conn->num_files_open--;
	SAFE_FREE(fsp->wbmpx_ptr);

	return ret;
}    

/****************************************************************************
 Close a file.

 If normal_close is 1 then this came from a normal SMBclose (or equivalent)
 operation otherwise it came as the result of some other operation such as
 the closing of the connection. In the latter case printing and
 magic scripts are not run.
****************************************************************************/

static int close_normal_file(files_struct *fsp, BOOL normal_close)
{
	share_mode_entry *share_entry = NULL;
	size_t share_entry_count = 0;
	BOOL delete_on_close = False;
	connection_struct *conn = fsp->conn;
	int err = 0;
	int err1 = 0;

	remove_pending_lock_requests_by_fid(fsp);

	/*
	 * If we're flushing on a close we can get a write
	 * error here, we must remember this.
	 */

	if (close_filestruct(fsp) == -1)
		err1 = -1;

	if (fsp->print_file) {
		print_fsp_end(fsp, normal_close);
		file_free(fsp);
		return 0;
	}

	/*
	 * Lock the share entries, and determine if we should delete
	 * on close. If so delete whilst the lock is still in effect.
	 * This prevents race conditions with the file being created. JRA.
	 */

	lock_share_entry_fsp(fsp);

	if (fsp->delete_on_close) {

		/*
		 * Modify the share mode entry for all files open
		 * on this device and inode to tell other smbds we have
		 * changed the delete on close flag. The last closer will delete the file
		 * if flag is set.
		 */

		NTSTATUS status =set_delete_on_close_over_all(fsp, fsp->delete_on_close);
		if (NT_STATUS_V(status) !=  NT_STATUS_V(NT_STATUS_OK))
			DEBUG(0,("close_normal_file: failed to change delete on close flag for file %s\n",
				fsp->fsp_name ));
	}

	share_entry_count = del_share_mode(fsp, &share_entry);

	DEBUG(10,("close_normal_file: share_entry_count = %d for file %s\n",
		share_entry_count, fsp->fsp_name ));

	/*
	 * We delete on close if it's the last open, and the
	 * delete on close flag was set in the entry we just deleted.
	 */

	if ((share_entry_count == 0) && share_entry && 
			GET_DELETE_ON_CLOSE_FLAG(share_entry->share_mode) )
		delete_on_close = True;

	SAFE_FREE(share_entry);

	/*
	 * NT can set delete_on_close of the last open
	 * reference to a file.
	 */

	if (normal_close && delete_on_close) {
		DEBUG(5,("close_file: file %s. Delete on close was set - deleting file.\n",
			fsp->fsp_name));
		if(fsp->conn->vfs_ops.unlink(conn,dos_to_unix_static(fsp->fsp_name)) != 0) {
			/*
			 * This call can potentially fail as another smbd may have
			 * had the file open with delete on close set and deleted
			 * it when its last reference to this file went away. Hence
			 * we log this but not at debug level zero.
			 */

			DEBUG(5,("close_file: file %s. Delete on close was set and unlink failed \
with error %s\n", fsp->fsp_name, strerror(errno) ));
		}
	}

	unlock_share_entry_fsp(fsp);

	if(EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type))
		release_file_oplock(fsp);

	locking_close_file(fsp);

	err = fd_close(conn, fsp);

	/* check for magic scripts */
	if (normal_close) {
		check_magic(fsp,conn);
	}

	/*
	 * Ensure pending modtime is set after close.
	 */

	if(fsp->pending_modtime) {
		int saved_errno = errno;
		set_filetime(conn, fsp->fsp_name, fsp->pending_modtime);
		errno = saved_errno;
	}

	DEBUG(2,("%s closed file %s (numopen=%d) %s\n",
		 conn->user,fsp->fsp_name,
		 conn->num_files_open, err ? strerror(err) : ""));

	if (fsp->fsp_name)
		string_free(&fsp->fsp_name);

	file_free(fsp);

	if (err == -1 || err1 == -1)
		return -1;
	else
		return 0;
}

/****************************************************************************
 Close a directory opened by an NT SMB call. 
****************************************************************************/
  
static int close_directory(files_struct *fsp, BOOL normal_close)
{
	remove_pending_change_notify_requests_by_fid(fsp);

	/*
	 * NT can set delete_on_close of the last open
	 * reference to a directory also.
	 */

	if (normal_close && fsp->directory_delete_on_close) {
		BOOL ok = rmdir_internals(fsp->conn, fsp->fsp_name);
		DEBUG(5,("close_directory: %s. Delete on close was set - deleting directory %s.\n",
			fsp->fsp_name, ok ? "succeeded" : "failed" ));

		/*
		 * Ensure we remove any change notify requests that would
		 * now fail as the directory has been deleted.
		 */

		if(ok)
			remove_pending_change_notify_requests_by_filename(fsp);
	}

	/*
	 * Do the code common to files and directories.
	 */
	close_filestruct(fsp);
	
	if (fsp->fsp_name)
		string_free(&fsp->fsp_name);
	
	file_free(fsp);

	return 0;
}

/****************************************************************************
 Close a 'stat file' opened internally.
****************************************************************************/

static int close_stat(files_struct *fsp)
{
	/*
	 * Do the code common to files and directories.
	 */
	close_filestruct(fsp);

	if (fsp->fsp_name)
		string_free(&fsp->fsp_name);

	file_free(fsp);
	return 0;
}

/****************************************************************************
 Close a directory opened by an NT SMB call. 
****************************************************************************/
  
int close_file(files_struct *fsp, BOOL normal_close)
{
	if(fsp->is_directory)
		return close_directory(fsp, normal_close);
	else if (fsp->is_stat)
		return close_stat(fsp);
	else
		return close_normal_file(fsp, normal_close);
}
