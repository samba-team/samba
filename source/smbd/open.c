/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   file opening and share modes
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

extern pstring sesssetup_user;
extern uint16 global_oplock_port;


/****************************************************************************
fd support routines - attempt to do a dos_open
****************************************************************************/
static int fd_attempt_open(struct connection_struct *conn, char *fname, 
			   int flags, mode_t mode)
{
  int fd = conn->vfs_ops.open(fname,flags,mode);

  /* Fix for files ending in '.' */
  if((fd == -1) && (errno == ENOENT) &&
     (strchr(fname,'.')==NULL))
    {
      pstrcat(fname,".");
      fd = conn->vfs_ops.open(fname,flags,mode);
    }

#if (defined(ENAMETOOLONG) && defined(HAVE_PATHCONF))
  if ((fd == -1) && (errno == ENAMETOOLONG))
    {
      int max_len;
      char *p = strrchr(fname, '/');

      if (p == fname)   /* name is "/xxx" */
        {
          max_len = pathconf("/", _PC_NAME_MAX);
          p++;
        }
      else if ((p == NULL) || (p == fname))
        {
          p = fname;
          max_len = pathconf(".", _PC_NAME_MAX);
        }
      else
        {
          *p = '\0';
          max_len = pathconf(fname, _PC_NAME_MAX);
          *p = '/';
          p++;
        }
      if (strlen(p) > max_len)
        {
          char tmp = p[max_len];

          p[max_len] = '\0';
          if ((fd = conn->vfs_ops.open(fname,flags,mode)) == -1)
            p[max_len] = tmp;
        }
    }
#endif
  return fd;
}

/****************************************************************************
Cache a uid_t currently with this file open. This is an optimization only
used when multiple sessionsetup's have been done to one smbd.
****************************************************************************/
void fd_add_to_uid_cache(file_fd_struct *fd_ptr, uid_t u)
{
  if(fd_ptr->uid_cache_count >= sizeof(fd_ptr->uid_users_cache)/sizeof(uid_t))
    return;
  fd_ptr->uid_users_cache[fd_ptr->uid_cache_count++] = u;
}

/****************************************************************************
Remove a uid_t that currently has this file open. This is an optimization only
used when multiple sessionsetup's have been done to one smbd.
****************************************************************************/
static void fd_remove_from_uid_cache(file_fd_struct *fd_ptr, uid_t u)
{
  int i;
  for(i = 0; i < fd_ptr->uid_cache_count; i++)
    if(fd_ptr->uid_users_cache[i] == u) {
      if(i < (fd_ptr->uid_cache_count-1))
        memmove((char *)&fd_ptr->uid_users_cache[i], (char *)&fd_ptr->uid_users_cache[i+1],
               sizeof(uid_t)*(fd_ptr->uid_cache_count-1-i) );
      fd_ptr->uid_cache_count--;
    }
  return;
}

/****************************************************************************
Check if a uid_t that currently has this file open is present. This is an
optimization only used when multiple sessionsetup's have been done to one smbd.
****************************************************************************/
static BOOL fd_is_in_uid_cache(file_fd_struct *fd_ptr, uid_t u)
{
  int i;
  for(i = 0; i < fd_ptr->uid_cache_count; i++)
    if(fd_ptr->uid_users_cache[i] == u)
      return True;
  return False;
}


/****************************************************************************
fd support routines - attempt to re-open an already open fd as O_RDWR.
Save the already open fd (we cannot close due to POSIX file locking braindamage.
****************************************************************************/
static void fd_attempt_reopen(char *fname, mode_t mode, file_fd_struct *fd_ptr)
{
  int fd = dos_open( fname, O_RDWR, mode);

  if(fd == -1)
    return;

  if(fd_ptr->real_open_flags == O_RDONLY)
    fd_ptr->fd_readonly = fd_ptr->fd;
  if(fd_ptr->real_open_flags == O_WRONLY)
    fd_ptr->fd_writeonly = fd_ptr->fd;

  fd_ptr->fd = fd;
  fd_ptr->real_open_flags = O_RDWR;
}

/****************************************************************************
fd support routines - attempt to close the file referenced by this fd.
Decrements the ref_count and returns it.
****************************************************************************/
uint16 fd_attempt_close(files_struct *fsp)
{
  extern struct current_user current_user;
  file_fd_struct *fd_ptr = fsp->fd_ptr;
  uint16 ret_ref;

  if (fd_ptr != NULL) {
      ret_ref = fd_ptr->ref_count;
  } else {
      return 0;
  }

  DEBUG(3,("fd_attempt_close fd = %d, dev = %x, inode = %.0f, open_flags = %d, ref_count = %d.\n",
          fd_ptr->fd, (unsigned int)fd_ptr->dev, (double)fd_ptr->inode,
          fd_ptr->real_open_flags,
          fd_ptr->ref_count));

  SMB_ASSERT(fd_ptr->ref_count != 0);

  fd_ptr->ref_count--;
  ret_ref = fd_ptr->ref_count;

  if(fd_ptr->ref_count == 0) {
    if(fd_ptr->fd != -1)
      fsp->conn->vfs_ops.close(fd_ptr->fd);
    if(fd_ptr->fd_readonly != -1)
      fsp->conn->vfs_ops.close(fd_ptr->fd_readonly);
    if(fd_ptr->fd_writeonly != -1)
      fsp->conn->vfs_ops.close(fd_ptr->fd_writeonly);
    /*
     * Delete this fd_ptr.
     */
    fd_ptr_free(fd_ptr);
  } else {
    fd_remove_from_uid_cache(fd_ptr, (uid_t)current_user.uid);
  }

 return ret_ref;
}

/****************************************************************************
fd support routines - check that current user has permissions
to open this file. Used when uid not found in optimization cache.
This is really ugly code, as due to POSIX locking braindamage we must
fork and then attempt to open the file, and return success or failure
via an exit code.
****************************************************************************/
static BOOL check_access_allowed_for_current_user(struct connection_struct
						  *conn, char *fname, 
						  int accmode )
{
  pid_t child_pid;

  if((child_pid = fork()) < 0) {
    DEBUG(0,("check_access_allowed_for_current_user: fork failed.\n"));
    return False;
  }

  if(child_pid) {
    /*
     * Parent.
     */
    pid_t wpid;
    int status_code;
    if ((wpid = sys_waitpid(child_pid, &status_code, 0)) < 0) {
      DEBUG(0,("check_access_allowed_for_current_user: The process is no longer waiting!\n"));
      return(False);
    }

    if (child_pid != wpid) {
      DEBUG(0,("check_access_allowed_for_current_user: We were waiting for the wrong process ID\n"));
      return(False);
    }
#if defined(WIFEXITED) && defined(WEXITSTATUS)
    if (WIFEXITED(status_code) == 0) {
      DEBUG(0,("check_access_allowed_for_current_user: The process exited while we were waiting\n"));
      return(False);
    }
    if (WEXITSTATUS(status_code) != 0) {
      DEBUG(9,("check_access_allowed_for_current_user: The status of the process exiting was %d. Returning access denied.\n", status_code));
      return(False);
    }
#else /* defined(WIFEXITED) && defined(WEXITSTATUS) */
    if(status_code != 0) {
      DEBUG(9,("check_access_allowed_for_current_user: The status of the process exiting was %d. Returning access denied.\n", status_code));
      return(False);
    }
#endif /* defined(WIFEXITED) && defined(WEXITSTATUS) */

    /*
     * Success - the child could open the file.
     */
    DEBUG(9,("check_access_allowed_for_current_user: The status of the process exiting was %d. Returning access allowed.\n", status_code));
    return True;
  } else {
    /*
     * Child.
     */
    int fd;
    DEBUG(9,("check_access_allowed_for_current_user: Child - attempting to open %s with mode %d.\n", fname, accmode ));
    if((fd = fd_attempt_open(conn, fname, accmode, 0)) < 0) {
      /* Access denied. */
      _exit(EACCES);
    }
    close(fd);
    DEBUG(9,("check_access_allowed_for_current_user: Child - returning ok.\n"));
    _exit(0);
  }

  return False;
}

/****************************************************************************
check a filename for the pipe string
****************************************************************************/
static void check_for_pipe(char *fname)
{
	/* special case of pipe opens */
	char s[10];
	StrnCpy(s,fname,9);
	strlower(s);
	if (strstr(s,"pipe/")) {
		DEBUG(3,("Rejecting named pipe open for %s\n",fname));
		unix_ERR_class = ERRSRV;
		unix_ERR_code = ERRaccess;
	}
}

/****************************************************************************
open a file
****************************************************************************/
static void open_file(files_struct *fsp,connection_struct *conn,
		      char *fname1,int flags,mode_t mode, SMB_STRUCT_STAT *sbuf)
{
  extern struct current_user current_user;
  pstring fname;
  SMB_STRUCT_STAT statbuf;
  file_fd_struct *fd_ptr;
  int accmode = (flags & O_ACCMODE);

  fsp->open = False;
  fsp->fd_ptr = 0;
  fsp->granted_oplock = False;
  errno = EPERM;

  pstrcpy(fname,fname1);

  /* check permissions */

  /*
   * This code was changed after seeing a client open request 
   * containing the open mode of (DENY_WRITE/read-only) with
   * the 'create if not exist' bit set. The previous code
   * would fail to open the file read only on a read-only share
   * as it was checking the flags parameter  directly against O_RDONLY,
   * this was failing as the flags parameter was set to O_RDONLY|O_CREAT.
   * JRA.
   */

  if (conn->read_only && !conn->printer) {
    /* It's a read-only share - fail if we wanted to write. */
    if(accmode != O_RDONLY) {
      DEBUG(3,("Permission denied opening %s\n",fname));
      check_for_pipe(fname);
      return;
    } else if(flags & O_CREAT) {
      /* We don't want to write - but we must make sure that O_CREAT
         doesn't create the file if we have write access into the
         directory.
       */
      flags &= ~O_CREAT;
    }
  }

  /* this handles a bug in Win95 - it doesn't say to create the file when it 
     should */
  if (conn->printer) {
	  flags |= (O_CREAT|O_EXCL);
  }

/*
  if (flags == O_WRONLY)
    DEBUG(3,("Bug in client? Set O_WRONLY without O_CREAT\n"));
*/

  /*
   * Ensure we have a valid struct stat so we can search the
   * open fd table.
   */
  if(sbuf == 0) {
    if(conn->vfs_ops.stat(dos_to_unix(fname,False), &statbuf) < 0) {
      if(errno != ENOENT) {
        DEBUG(3,("Error doing stat on file %s (%s)\n",
                 fname,strerror(errno)));

        check_for_pipe(fname);
        return;
      }
      sbuf = 0;
    } else {
      sbuf = &statbuf;
    }
  }

  /*
   * Check to see if we have this file already
   * open. If we do, just use the already open fd and increment the
   * reference count (fd_get_already_open increments the ref_count).
   */
  if((fd_ptr = fd_get_already_open(sbuf))!= 0) {
    /*
     * File was already open.
     */

    /* 
     * Check it wasn't open for exclusive use.
     */
    if((flags & O_CREAT) && (flags & O_EXCL)) {
      fd_ptr->ref_count--;
      errno = EEXIST;
      return;
    }

    /*
     * Ensure that the user attempting to open
     * this file has permissions to do so, if
     * the user who originally opened the file wasn't
     * the same as the current user.
     */

    if(!fd_is_in_uid_cache(fd_ptr, (uid_t)current_user.uid)) {
      if(!check_access_allowed_for_current_user(conn, fname, accmode )) {
        /* Error - permission denied. */
        DEBUG(3,("Permission denied opening file %s (flags=%d, accmode = %d)\n",
              fname, flags, accmode));
        /* Ensure the ref_count is decremented. */
        fd_ptr->ref_count--;
        fd_remove_from_uid_cache(fd_ptr, (uid_t)current_user.uid);
        errno = EACCES;
        return;
      }
    }

    fd_add_to_uid_cache(fd_ptr, (uid_t)current_user.uid);

    /* 
     * If not opened O_RDWR try
     * and do that here - a chmod may have been done
     * between the last open and now. 
     */
    if(fd_ptr->real_open_flags != O_RDWR)
      fd_attempt_reopen(fname, mode, fd_ptr);

    /*
     * Ensure that if we wanted write access
     * it has been opened for write, and if we wanted read it
     * was open for read. 
     */
    if(((accmode == O_WRONLY) && (fd_ptr->real_open_flags == O_RDONLY)) ||
       ((accmode == O_RDONLY) && (fd_ptr->real_open_flags == O_WRONLY)) ||
       ((accmode == O_RDWR) && (fd_ptr->real_open_flags != O_RDWR))) {
      DEBUG(3,("Error opening (already open for flags=%d) file %s (%s) (flags=%d)\n",
               fd_ptr->real_open_flags, fname,strerror(EACCES),flags));
      check_for_pipe(fname);
      fd_remove_from_uid_cache(fd_ptr, (uid_t)current_user.uid);
      fd_ptr->ref_count--;
      return;
    }

  } else {
    int open_flags;
    /* We need to allocate a new file_fd_struct (this increments the
       ref_count). */
    if((fd_ptr = fd_get_new()) == 0)
      return;
    /*
     * Whatever the requested flags, attempt read/write access,
     * as we don't know what flags future file opens may require.
     * If this fails, try again with the required flags. 
     * Even if we open read/write when only read access was 
     * requested the setting of the can_write flag in
     * the file_struct will protect us from errant
     * write requests. We never need to worry about O_APPEND
     * as this is not set anywhere in Samba.
     */
    fd_ptr->real_open_flags = O_RDWR;
    /* Set the flags as needed without the read/write modes. */
    open_flags = flags & ~(O_RDWR|O_WRONLY|O_RDONLY);
    fd_ptr->fd = fd_attempt_open(conn, fname, open_flags|O_RDWR, mode);
    /*
     * On some systems opening a file for R/W access on a read only
     * filesystems sets errno to EROFS.
     */
#ifdef EROFS
    if((fd_ptr->fd == -1) && ((errno == EACCES) || (errno == EROFS))) {
#else /* No EROFS */
    if((fd_ptr->fd == -1) && (errno == EACCES)) {
#endif /* EROFS */
      if(accmode != O_RDWR) {
        fd_ptr->fd = fd_attempt_open(conn, fname, open_flags|accmode, mode);
        fd_ptr->real_open_flags = accmode;
      }
    }
  }

  if ((fd_ptr->fd >=0) && 
      conn->printer && lp_minprintspace(SNUM(conn))) {
    pstring dname;
    SMB_BIG_UINT dum1,dum2,dum3;
    char *p;
    pstrcpy(dname,fname);
    p = strrchr(dname,'/');
    if (p) *p = 0;
    if (conn->vfs_ops.disk_free(dname,&dum1,&dum2,&dum3) < 
	(SMB_BIG_UINT)lp_minprintspace(SNUM(conn))) {
      if(fd_attempt_close(fsp) == 0)
        conn->vfs_ops.unlink(fname);
      fsp->fd_ptr = 0;
      errno = ENOSPC;
      return;
    }
  }
    
  if (fd_ptr->fd < 0)
  {
    DEBUG(3,("Error opening file %s (%s) (flags=%d)\n",
      fname,strerror(errno),flags));
    /* Ensure the ref_count is decremented. */
    fd_attempt_close(fsp);
    check_for_pipe(fname);
    return;
  }

  if (fd_ptr->fd >= 0)
  {
    if(sbuf == 0) {
      /* Do the fstat */
      if(conn->vfs_ops.fstat(fd_ptr->fd, &statbuf) == -1) {
        /* Error - backout !! */
        DEBUG(3,("Error doing fstat on fd %d, file %s (%s)\n",
                 fd_ptr->fd, fname,strerror(errno)));
        /* Ensure the ref_count is decremented. */
        fd_attempt_close(fsp);
        return;
      }
      sbuf = &statbuf;
    }

    /* Set the correct entries in fd_ptr. */
    fd_ptr->dev = sbuf->st_dev;
    fd_ptr->inode = sbuf->st_ino;

    fsp->fd_ptr = fd_ptr;
    conn->num_files_open++;
    fsp->mode = sbuf->st_mode;
    GetTimeOfDay(&fsp->open_time);
    fsp->vuid = current_user.vuid;
    fsp->size = 0;
    fsp->pos = -1;
    fsp->open = True;
    fsp->mmap_ptr = NULL;
    fsp->mmap_size = 0;
    fsp->can_lock = True;
    fsp->can_read = ((flags & O_WRONLY)==0);
    fsp->can_write = ((flags & (O_WRONLY|O_RDWR))!=0);
    fsp->share_mode = 0;
    fsp->print_file = conn->printer;
    fsp->modified = False;
    fsp->granted_oplock = False;
    fsp->sent_oplock_break = False;
    fsp->is_directory = False;
    fsp->conn = conn;
    /*
     * Note that the file name here is the *untranslated* name
     * ie. it is still in the DOS codepage sent from the client.
     * All use of this filename will pass though the sys_xxxx
     * functions which will do the dos_to_unix translation before
     * mapping into a UNIX filename. JRA.
     */
    string_set(&fsp->fsp_name,fname);
    fsp->wbmpx_ptr = NULL;      

    /*
     * If the printer is marked as postscript output a leading
     * file identifier to ensure the file is treated as a raw
     * postscript file.
     * This has a similar effect as CtrlD=0 in WIN.INI file.
     * tim@fsg.com 09/06/94
     */
    if (fsp->print_file && lp_postscript(SNUM(conn)) && fsp->can_write) {
	    DEBUG(3,("Writing postscript line\n"));
	    conn->vfs_ops.write(fsp->fd_ptr->fd,"%!\n",3);
    }
      
    DEBUG(2,("%s opened file %s read=%s write=%s (numopen=%d)\n",
	     *sesssetup_user ? sesssetup_user : conn->user,fsp->fsp_name,
	     BOOLSTR(fsp->can_read), BOOLSTR(fsp->can_write),
	     conn->num_files_open));

  }
}

/****************************************************************************
 If it's a read-only file, and we were compiled with mmap enabled,
 try and mmap the file. This is split out from open_file() above
 as mmap'ing the file can cause the kernel reference count to
 be incremented, which can cause kernel oplocks to be refused.
 Splitting this call off allows the kernel oplock to be granted, then
 the file mmap'ed.
****************************************************************************/

static void mmap_open_file(files_struct *fsp)
{
#if WITH_MMAP
  /* mmap it if read-only */
  if (!fsp->can_write) {
	  fsp->mmap_size = dos_file_size(fsp->fsp_name);
	  if (fsp->mmap_size < MAX_MMAP_SIZE) {
		  fsp->mmap_ptr = (char *)sys_mmap(NULL,fsp->mmap_size,
					       PROT_READ,MAP_SHARED,fsp->fd_ptr->fd,(SMB_OFF_T)0);

		  if (fsp->mmap_ptr == (char *)-1 || !fsp->mmap_ptr) {
			  DEBUG(3,("Failed to mmap() %s - %s\n",
				   fsp->fsp_name,strerror(errno)));
			  fsp->mmap_ptr = NULL;
		  }
	  }
  }
#endif
}

/****************************************************************************
  C. Hoch 11/22/95
  Helper for open_file_shared. 
  Truncate a file after checking locking; close file if locked.
  **************************************************************************/
static void truncate_unless_locked(files_struct *fsp, connection_struct *conn, 
				   BOOL *share_locked)
{
	if (fsp->can_write){
		SMB_OFF_T mask2 = ((SMB_OFF_T)0x3) << (SMB_OFF_T_BITS-4);
		SMB_OFF_T mask = (mask2<<2);
		
		if (is_locked(fsp,conn,~mask,0,F_WRLCK)){
			/* If share modes are in force for this connection we
			   have the share entry locked. Unlock it before closing. */
			if (*share_locked && lp_share_modes(SNUM(conn)))
				unlock_share_entry( conn, fsp->fd_ptr->dev, 
						    fsp->fd_ptr->inode);
			close_file(fsp,False);   
			/* Share mode no longer locked. */
			*share_locked = False;
			errno = EACCES;
			unix_ERR_class = ERRDOS;
		  unix_ERR_code = ERRlock;
		} else {
			sys_ftruncate(fsp->fd_ptr->fd,0); 
		}
	}
}


enum {AFAIL,AREAD,AWRITE,AALL};

/*******************************************************************
reproduce the share mode access table
********************************************************************/
static int access_table(int new_deny,int old_deny,int old_mode,
			int share_pid,char *fname)
{
  if (new_deny == DENY_ALL || old_deny == DENY_ALL) return(AFAIL);

  if (new_deny == DENY_DOS || old_deny == DENY_DOS) {
    int pid = getpid();
    if (old_deny == new_deny && share_pid == pid) 
	return(AALL);    

    if (old_mode == 0) return(AREAD);

    /* the new smbpub.zip spec says that if the file extension is
       .com, .dll, .exe or .sym then allow the open. I will force
       it to read-only as this seems sensible although the spec is
       a little unclear on this. */
    if ((fname = strrchr(fname,'.'))) {
      if (strequal(fname,".com") ||
	  strequal(fname,".dll") ||
	  strequal(fname,".exe") ||
	  strequal(fname,".sym"))
	return(AREAD);
    }

    return(AFAIL);
  }

  switch (new_deny) 
    {
    case DENY_WRITE:
      if (old_deny==DENY_WRITE && old_mode==0) return(AREAD);
      if (old_deny==DENY_READ && old_mode==0) return(AWRITE);
      if (old_deny==DENY_NONE && old_mode==0) return(AALL);
      return(AFAIL);
    case DENY_READ:
      if (old_deny==DENY_WRITE && old_mode==1) return(AREAD);
      if (old_deny==DENY_READ && old_mode==1) return(AWRITE);
      if (old_deny==DENY_NONE && old_mode==1) return(AALL);
      return(AFAIL);
    case DENY_NONE:
      if (old_deny==DENY_WRITE) return(AREAD);
      if (old_deny==DENY_READ) return(AWRITE);
      if (old_deny==DENY_NONE) return(AALL);
      return(AFAIL);      
    }
  return(AFAIL);      
}


/****************************************************************************
check if we can open a file with a share mode
****************************************************************************/
static int check_share_mode( share_mode_entry *share, int deny_mode, 
			     char *fname,
			     BOOL fcbopen, int *flags)
{
  int old_open_mode = GET_OPEN_MODE(share->share_mode);
  int old_deny_mode = GET_DENY_MODE(share->share_mode);

  /*
   * Don't allow any open once the delete on close flag has been
   * set.
   */

  if(GET_DELETE_ON_CLOSE_FLAG(share->share_mode))
  {
    DEBUG(5,("check_share_mode: Failing open on file %s as delete on close flag is set.\n",
          fname ));
    unix_ERR_class = ERRDOS;
    unix_ERR_code = ERRnoaccess;
    return False;
  }

  if (old_deny_mode > 4 || old_open_mode > 2)
  {
    DEBUG(0,("Invalid share mode found (%d,%d,%d) on file %s\n",
               deny_mode,old_deny_mode,old_open_mode,fname));

    unix_ERR_class = ERRDOS;
    unix_ERR_code = ERRbadshare;

    return False;
  }

  {
    int access_allowed = access_table(deny_mode,old_deny_mode,old_open_mode,
                                share->pid,fname);

    if ((access_allowed == AFAIL) ||
        (!fcbopen && (access_allowed == AREAD && *flags == O_RDWR)) ||
        (access_allowed == AREAD && *flags == O_WRONLY) ||
        (access_allowed == AWRITE && *flags == O_RDONLY))
    {
      DEBUG(2,("Share violation on file (%d,%d,%d,%d,%s,fcbopen = %d, flags = %d) = %d\n",
                deny_mode,old_deny_mode,old_open_mode,
                share->pid,fname, fcbopen, *flags, access_allowed));

      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadshare;

      return False;
    }

    if (access_allowed == AREAD)
      *flags = O_RDONLY;

    if (access_allowed == AWRITE)
      *flags = O_WRONLY;

  }

  return True;
}


/****************************************************************************
open a file with a share mode
****************************************************************************/
void open_file_shared(files_struct *fsp, connection_struct *conn,
			   char *fname, int share_mode, int ofun, 
			   mode_t mode, int oplock_request, int *Access,
			   int *action)
{
  int flags=0;
  int flags2=0;
  int deny_mode = GET_DENY_MODE(share_mode);
  BOOL allow_share_delete = GET_ALLOW_SHARE_DELETE(share_mode);
  SMB_STRUCT_STAT sbuf;
  BOOL file_existed = vfs_file_exist(conn, dos_to_unix(fname,False), &sbuf);
  BOOL share_locked = False;
  BOOL fcbopen = False;
  SMB_DEV_T dev = 0;
  SMB_INO_T inode = 0;
  int num_share_modes = 0;

  fsp->open = False;
  fsp->fd_ptr = 0;

  DEBUG(10,("open_file_shared: fname = %s, share_mode = %x, ofun = %x, mode = %o, oplock request = %d\n",
        fname, share_mode, ofun, (int)mode,  oplock_request ));

  /* this is for OS/2 EAs - try and say we don't support them */
  if (strstr(fname,".+,;=[].")) 
  {
    unix_ERR_class = ERRDOS;
    /* OS/2 Workplace shell fix may be main code stream in a later release. */ 
#if 1 /* OS2_WPS_FIX - Recent versions of OS/2 need this. */
    unix_ERR_code = ERRcannotopen;
#else /* OS2_WPS_FIX */
    unix_ERR_code = ERROR_EAS_NOT_SUPPORTED;
#endif /* OS2_WPS_FIX */

    DEBUG(5,("open_file_shared: OS/2 EA's are not supported.\n"));
    return;
  }

  if ((GET_FILE_OPEN_DISPOSITION(ofun) == FILE_EXISTS_FAIL) && file_existed)  
  {
    DEBUG(5,("open_file_shared: create new requested for file %s and file already exists.\n",
          fname ));
    errno = EEXIST;
    return;
  }
      
  if (GET_FILE_CREATE_DISPOSITION(ofun) == FILE_CREATE_IF_NOT_EXIST)
    flags2 |= O_CREAT;

  if (GET_FILE_OPEN_DISPOSITION(ofun) == FILE_EXISTS_TRUNCATE)
    flags2 |= O_TRUNC;

  if (GET_FILE_OPEN_DISPOSITION(ofun) == FILE_EXISTS_FAIL)
    flags2 |= O_EXCL;

  /* note that we ignore the append flag as 
     append does not mean the same thing under dos and unix */

  switch (GET_OPEN_MODE(share_mode))
  {
    case DOS_OPEN_WRONLY: 
      flags = O_WRONLY; 
      break;
    case DOS_OPEN_FCB: 
      fcbopen = True;
      flags = O_RDWR; 
      break;
    case DOS_OPEN_RDWR: 
      flags = O_RDWR; 
      break;
    default:
      flags = O_RDONLY;
      break;
  }

#if defined(O_SYNC)
  if (GET_FILE_SYNC_OPENMODE(share_mode)) {
	  flags2 |= O_SYNC;
  }
#endif /* O_SYNC */
  
  if (flags != O_RDONLY && file_existed && 
      (!CAN_WRITE(conn) || IS_DOS_READONLY(dos_mode(conn,fname,&sbuf)))) 
  {
    if (!fcbopen) 
    {
      DEBUG(5,("open_file_shared: read/write access requested for file %s on read only %s\n",
            fname, !CAN_WRITE(conn) ? "share" : "file" ));
      errno = EACCES;
      return;
    }
    flags = O_RDONLY;
  }

  if (deny_mode > DENY_NONE && deny_mode!=DENY_FCB) 
  {
    DEBUG(2,("Invalid deny mode %d on file %s\n",deny_mode,fname));
    errno = EINVAL;
    return;
  }

  if (deny_mode == DENY_FCB)
    deny_mode = DENY_DOS;

  if (lp_share_modes(SNUM(conn))) 
  {
    int i;
    share_mode_entry *old_shares = 0;

    if (file_existed)
    {
      dev = sbuf.st_dev;
      inode = sbuf.st_ino;
      lock_share_entry(conn, dev, inode);
      share_locked = True;
      num_share_modes = get_share_modes(conn, dev, inode, &old_shares);
    }

    /*
     * Check if the share modes will give us access.
     */

    if(share_locked && (num_share_modes != 0))
    {
      BOOL broke_oplock;

      do
      {

        broke_oplock = False;
        for(i = 0; i < num_share_modes; i++)
        {
          share_mode_entry *share_entry = &old_shares[i];

          /* 
           * By observation of NetBench, oplocks are broken *before* share
           * modes are checked. This allows a file to be closed by the client
           * if the share mode would deny access and the client has an oplock. 
           * Check if someone has an oplock on this file. If so we must break 
           * it before continuing. 
           */
          if(share_entry->op_type & (EXCLUSIVE_OPLOCK|BATCH_OPLOCK))
          {

            DEBUG(5,("open_file_shared: breaking oplock (%x) on file %s, \
dev = %x, inode = %.0f\n", share_entry->op_type, fname, (unsigned int)dev, (double)inode));

            /* Oplock break.... */
            unlock_share_entry(conn, dev, inode);
            if(request_oplock_break(share_entry, dev, inode) == False)
            {
              free((char *)old_shares);

              DEBUG(0,("open_file_shared: FAILED when breaking oplock (%x) on file %s, \
dev = %x, inode = %.0f\n", old_shares[i].op_type, fname, (unsigned int)dev, (double)inode));

              errno = EACCES;
              unix_ERR_class = ERRDOS;
              unix_ERR_code = ERRbadshare;
              return;
            }
            lock_share_entry(conn, dev, inode);
            broke_oplock = True;
            break;
          }

          /* someone else has a share lock on it, check to see 
             if we can too */
          if(check_share_mode(share_entry, deny_mode, fname, fcbopen, &flags) == False)
          {
            free((char *)old_shares);
            unlock_share_entry(conn, dev, inode);
            errno = EACCES;
            return;
          }

        } /* end for */

        if(broke_oplock)
        {
          free((char *)old_shares);
          num_share_modes = get_share_modes(conn, dev, inode, &old_shares);
        }
      } while(broke_oplock);
    }

    if(old_shares != 0)
      free((char *)old_shares);
  }

  DEBUG(4,("calling open_file with flags=0x%X flags2=0x%X mode=0%o\n",
	   flags,flags2,(int)mode));

  open_file(fsp,conn,fname,flags|(flags2&~(O_TRUNC)),mode,file_existed ? &sbuf : 0);
  if (!fsp->open && flags==O_RDWR && errno!=ENOENT && fcbopen) 
  {
    flags = O_RDONLY;
    open_file(fsp,conn,fname,flags,mode,file_existed ? &sbuf : 0 );
  }

  if (fsp->open) 
  {
    int open_mode=0;

    if((share_locked == False) && lp_share_modes(SNUM(conn)))
    {
      /* We created the file - thus we must now lock the share entry before creating it. */
      dev = fsp->fd_ptr->dev;
      inode = fsp->fd_ptr->inode;
      lock_share_entry(conn, dev, inode);
      share_locked = True;
    }

    switch (flags) 
    {
      case O_RDONLY:
        open_mode = DOS_OPEN_RDONLY;
        break;
      case O_RDWR:
        open_mode = DOS_OPEN_RDWR;
        break;
      case O_WRONLY:
        open_mode = DOS_OPEN_WRONLY;
        break;
    }

    fsp->share_mode = SET_DENY_MODE(deny_mode) | 
                      SET_OPEN_MODE(open_mode) | 
                      SET_ALLOW_SHARE_DELETE(allow_share_delete);

    if (Access)
      (*Access) = open_mode;

    if (action) 
    {
      if (file_existed && !(flags2 & O_TRUNC)) *action = FILE_WAS_OPENED;
      if (!file_existed) *action = FILE_WAS_CREATED;
      if (file_existed && (flags2 & O_TRUNC)) *action = FILE_WAS_OVERWRITTEN;
    }
    /* We must create the share mode entry before truncate as
       truncate can fail due to locking and have to close the
       file (which expects the share_mode_entry to be there).
     */
    if (lp_share_modes(SNUM(conn)))
    {
      uint16 port = 0;

      /* JRA. Currently this only services Exlcusive and batch
         oplocks (no other opens on this file). This needs to
         be extended to level II oplocks (multiple reader
         oplocks). */

      if((oplock_request) && (num_share_modes == 0) && lp_oplocks(SNUM(conn)) && 
	      !IS_VETO_OPLOCK_PATH(conn,fname) && set_file_oplock(fsp) )
      {
        port = global_oplock_port;
      }
      else
      {
        port = 0;
        oplock_request = 0;
      }

      set_share_mode(fsp, port, oplock_request);
    }

    if ((flags2&O_TRUNC) && file_existed)
      truncate_unless_locked(fsp,conn,&share_locked);

    /*
     * Attempt to mmap a read only file.
     * Moved until after a kernel oplock may
     * be granted due to reference count issues. JRA.
     */
    mmap_open_file(fsp);
  }

  if (share_locked && lp_share_modes(SNUM(conn)))
    unlock_share_entry( conn, dev, inode);
}

/****************************************************************************
 Open a directory from an NT SMB call.
****************************************************************************/

int open_directory(files_struct *fsp,connection_struct *conn,
		   char *fname, int smb_ofun, mode_t unixmode, int *action)
{
	extern struct current_user current_user;
	SMB_STRUCT_STAT st;

	if (smb_ofun & 0x10) {
		/*
		 * Create the directory.
		 */

		if(conn->vfs_ops.mkdir(dos_to_unix(fname,False), 
				       unix_mode(conn,aDIR)) < 0) {
			DEBUG(0,("open_directory: unable to create %s. Error was %s\n",
				 fname, strerror(errno) ));
			return -1;
		}

		*action = FILE_WAS_CREATED;
	} else {
		/*
		 * Check that it *was* a directory.
		 */

		if(conn->vfs_ops.stat(dos_to_unix(fname,False), &st) < 0) {
			DEBUG(0,("open_directory: unable to stat name = %s. Error was %s\n",
				 fname, strerror(errno) ));
			return -1;
		}

		if(!S_ISDIR(st.st_mode)) {
			DEBUG(0,("open_directory: %s is not a directory !\n", fname ));
			return -1;
		}
		*action = FILE_WAS_OPENED;
	}
	
	DEBUG(5,("open_directory: opening directory %s\n",
		 fname));

	/*
	 * Setup the files_struct for it.
	 */
	
	fsp->fd_ptr = NULL;
	conn->num_files_open++;
	fsp->mode = 0;
	GetTimeOfDay(&fsp->open_time);
	fsp->vuid = current_user.vuid;
	fsp->size = 0;
	fsp->pos = -1;
	fsp->open = True;
	fsp->mmap_ptr = NULL;
	fsp->mmap_size = 0;
	fsp->can_lock = True;
	fsp->can_read = False;
	fsp->can_write = False;
	fsp->share_mode = 0;
	fsp->print_file = False;
	fsp->modified = False;
	fsp->granted_oplock = False;
	fsp->sent_oplock_break = False;
	fsp->is_directory = True;
	fsp->conn = conn;
	/*
	 * Note that the file name here is the *untranslated* name
	 * ie. it is still in the DOS codepage sent from the client.
	 * All use of this filename will pass though the sys_xxxx
	 * functions which will do the dos_to_unix translation before
	 * mapping into a UNIX filename. JRA.
	 */
	string_set(&fsp->fsp_name,fname);
	fsp->wbmpx_ptr = NULL;

	return 0;
}


/*******************************************************************
check if the share mode on a file allows it to be deleted or unlinked
return True if sharing doesn't prevent the operation
********************************************************************/

BOOL check_file_sharing(connection_struct *conn,char *fname, BOOL rename_op)
{
  int i;
  int ret = False;
  share_mode_entry *old_shares = 0;
  int num_share_modes;
  SMB_STRUCT_STAT sbuf;
  int pid = getpid();
  SMB_DEV_T dev;
  SMB_INO_T inode;

  if(!lp_share_modes(SNUM(conn)))
    return True;

  if (conn->vfs_ops.stat(dos_to_unix(fname,False),&sbuf) == -1) return(True);

  dev = sbuf.st_dev;
  inode = sbuf.st_ino;

  lock_share_entry(conn, dev, inode);
  num_share_modes = get_share_modes(conn, dev, inode, &old_shares);

  /*
   * Check if the share modes will give us access.
   */

  if(num_share_modes != 0)
  {
    BOOL broke_oplock;

    do
    {

      broke_oplock = False;
      for(i = 0; i < num_share_modes; i++)
      {
        share_mode_entry *share_entry = &old_shares[i];

        /* 
         * Break oplocks before checking share modes. See comment in
         * open_file_shared for details. 
         * Check if someone has an oplock on this file. If so we must 
         * break it before continuing. 
         */
        if(share_entry->op_type & BATCH_OPLOCK)
        {

          /*
           * It appears that the NT redirector may have a bug, in that
           * it tries to do an SMBmv on a file that it has open with a
           * batch oplock, and then fails to respond to the oplock break
           * request. This only seems to occur when the client is doing an
           * SMBmv to the smbd it is using - thus we try and detect this
           * condition by checking if the file being moved is open and oplocked by
           * this smbd process, and then not sending the oplock break in this
           * special case. If the file was open with a deny mode that 
           * prevents the move the SMBmv will fail anyway with a share
           * violation error. JRA.
           */
          if(rename_op && (share_entry->pid == pid))
          {

            DEBUG(0,("check_file_sharing: NT redirector workaround - rename attempted on \
batch oplocked file %s, dev = %x, inode = %.0f\n", fname, (unsigned int)dev, (double)inode));

            /* 
             * This next line is a test that allows the deny-mode
             * processing to be skipped. This seems to be needed as
             * NT insists on the rename succeeding (in Office 9x no less !).
             * This should be removed as soon as (a) MS fix the redirector
             * bug or (b) NT SMB support in Samba makes NT not issue the
             * call (as is my fervent hope). JRA.
             */ 
            continue;
          }
          else
          {

            DEBUG(5,("check_file_sharing: breaking oplock (%x) on file %s, \
dev = %x, inode = %.0f\n", share_entry->op_type, fname, (unsigned int)dev, (double)inode));

            /* Oplock break.... */
            unlock_share_entry(conn, dev, inode);
            if(request_oplock_break(share_entry, dev, inode) == False)
            {
              free((char *)old_shares);

              DEBUG(0,("check_file_sharing: FAILED when breaking oplock (%x) on file %s, \
dev = %x, inode = %.0f\n", old_shares[i].op_type, fname, (unsigned int)dev, (double)inode));

              return False;
            }
            lock_share_entry(conn, dev, inode);
            broke_oplock = True;
            break;
          }
        }

        /* 
         * If this is a delete request and ALLOW_SHARE_DELETE is set then allow 
         * this to proceed. This takes precedence over share modes.
         */

        if(!rename_op && GET_ALLOW_SHARE_DELETE(share_entry->share_mode))
          continue;

        /* 
         * Someone else has a share lock on it, check to see 
         * if we can too.
         */

        if ((GET_DENY_MODE(share_entry->share_mode) != DENY_DOS) || (share_entry->pid != pid))
          goto free_and_exit;

      } /* end for */

      if(broke_oplock)
      {
        free((char *)old_shares);
        num_share_modes = get_share_modes(conn, dev, inode, &old_shares);
      }
    } while(broke_oplock);
  }

  /* XXXX exactly what share mode combinations should be allowed for
     deleting/renaming? */
  /* 
   * If we got here then either there were no share modes or
   * all share modes were DENY_DOS and the pid == getpid() or
   * delete access was requested and all share modes had the
   * ALLOW_SHARE_DELETE bit set (takes precedence over other
   * share modes).
   */

  ret = True;

free_and_exit:

  unlock_share_entry(conn, dev, inode);
  if(old_shares != NULL)
    free((char *)old_shares);
  return(ret);
}
