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

extern int DEBUGLEVEL;

extern int32 global_oplocks_open;


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
    pstrcpy(fname,fsp->fsp_name);

    if (*lp_magicoutput(SNUM(conn)))
      pstrcpy(magic_output,lp_magicoutput(SNUM(conn)));
    else
      slprintf(magic_output,sizeof(fname)-1, "%s.out",fname);

    chmod(fname,0755);
    ret = smbrun(fname,magic_output,False);
    DEBUG(3,("Invoking magic command %s gave %d\n",fname,ret));
    unlink(fname);
  }
}

/****************************************************************************
  Common code to close a file or a directory.
****************************************************************************/
static void close_filestruct(files_struct *fsp)
{   
	connection_struct *conn = fsp->conn;
    
	fsp->open = False;
	fsp->is_directory = False; 
    
	conn->num_files_open--;
	if(fsp->wbmpx_ptr) {  
		free((char *)fsp->wbmpx_ptr);
		fsp->wbmpx_ptr = NULL; 
	}  
     
#if WITH_MMAP
	if(fsp->mmap_ptr) {
		munmap(fsp->mmap_ptr,fsp->mmap_size);
		fsp->mmap_ptr = NULL;
	}  
#endif 
}    

/****************************************************************************
 Close a file - possibly invalidating the read prediction.

 If normal_close is 1 then this came from a normal SMBclose (or equivalent)
 operation otherwise it came as the result of some other operation such as
 the closing of the connection. In the latter case printing and
 magic scripts are not run.
****************************************************************************/
void close_file(files_struct *fsp, BOOL normal_close)
{
	SMB_DEV_T dev = fsp->fd_ptr->dev;
	SMB_INO_T inode = fsp->fd_ptr->inode;
    BOOL last_reference = False;
    BOOL delete_on_close = fsp->fd_ptr->delete_on_close;
	connection_struct *conn = fsp->conn;

	remove_pending_lock_requests_by_fid(fsp);

	close_filestruct(fsp);

#if USE_READ_PREDICTION
	invalidate_read_prediction(fsp->fd_ptr->fd);
#endif

	if (lp_share_modes(SNUM(conn))) {
		lock_share_entry(conn, dev, inode);
		del_share_mode(fsp);
	}

	if(fd_attempt_close(fsp) == 0)
		last_reference = True;

    fsp->fd_ptr = NULL;

	if (lp_share_modes(SNUM(conn)))
		unlock_share_entry(conn, dev, inode);

	/* NT uses smbclose to start a print - weird */
	if (normal_close && fsp->print_file)
		print_file(conn, SNUM(conn), fsp);

	/* check for magic scripts */
	if (normal_close) {
		check_magic(fsp,conn);
	}

	/*
	 * NT can set delete_on_close of the last open
	 * reference to a file.
	 */

    if (normal_close && last_reference && delete_on_close) {
        DEBUG(5,("close_file: file %s. Delete on close was set - deleting file.\n",
	    fsp->fsp_name));
		if(fsp->conn->vfs_ops.unlink(dos_to_unix(fsp->fsp_name, False)) != 0) {
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

	if(fsp->granted_oplock == True)
		global_oplocks_open--;

	fsp->sent_oplock_break = False;

	DEBUG(2,("%s closed file %s (numopen=%d)\n",
		 conn->user,fsp->fsp_name,
		 conn->num_files_open));

	if (fsp->fsp_name) {
		string_free(&fsp->fsp_name);
	}

	file_free(fsp);
}

/****************************************************************************
 Close a directory opened by an NT SMB call. 
****************************************************************************/
  
void close_directory(files_struct *fsp)
{
	remove_pending_change_notify_requests_by_fid(fsp);

	/*
	 * Do the code common to files and directories.
	 */
	close_filestruct(fsp);
	
	if (fsp->fsp_name)
		string_free(&fsp->fsp_name);
	
	file_free(fsp);
}

