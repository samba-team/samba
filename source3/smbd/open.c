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
extern BOOL global_client_failed_oplock_break;

/****************************************************************************
 fd support routines - attempt to do a dos_open.
****************************************************************************/

static int fd_open(struct connection_struct *conn, char *fname, 
		   int flags, mode_t mode)
{
	int fd = conn->vfs_ops.open(dos_to_unix(fname,False),flags,mode);

	/* Fix for files ending in '.' */
	if((fd == -1) && (errno == ENOENT) &&
	   (strchr(fname,'.')==NULL)) {
		pstrcat(fname,".");
		fd = conn->vfs_ops.open(dos_to_unix(fname,False),flags,mode);
	}

	DEBUG(10,("fd_open: name %s, mode = %d, fd = %d. %s\n", fname, (int)mode, fd,
		(fd == -1) ? strerror(errno) : "" ));

	return fd;
}

/****************************************************************************
  Take care of moving any POSIX pending close fd's to another fsp.
****************************************************************************/

static BOOL fd_close_posix_locks(files_struct *fsp)
{
	files_struct *other_fsp;

	DEBUG(10,("fd_close_posix_locks: file %s: fsp->num_posix_pending_closes = %u.\n", fsp->fsp_name,
				(unsigned int)fsp->num_posix_pending_closes ));

	for(other_fsp = file_find_di_first(fsp->dev, fsp->inode); other_fsp;
					other_fsp = file_find_di_next(other_fsp)) {

		if ((other_fsp->fd != -1) && other_fsp->num_posix_locks) {

			/*
			 * POSIX locks pending on another fsp held open, transfer
			 * the fd in this fsp and all the pending fd's in this fsp pending close array
			 * to the other_fsp pending close array.
			 */

			unsigned int extra_fds = fsp->num_posix_pending_closes + 1;

			DEBUG(10,("fd_close_posix_locks: file %s: Transferring to \
file %s, other_fsp->num_posix_pending_closes = %u.\n",
				fsp->fsp_name, other_fsp->fsp_name, (unsigned int)other_fsp->num_posix_pending_closes ));

			other_fsp->posix_pending_close_fds = (int *)Realloc(other_fsp->posix_pending_close_fds,
																(other_fsp->num_posix_pending_closes +
																	extra_fds)*sizeof(int));

			if(other_fsp->posix_pending_close_fds == NULL) {
				DEBUG(0,("fd_close_posix_locks: Unable to increase posix_pending_close_fds array size !\n"));
				return False;
			}

			/*
			 * Copy over any fd's in the existing fsp's pending array.
			 */

			if(fsp->posix_pending_close_fds) {
				memcpy(&other_fsp->posix_pending_close_fds[other_fsp->num_posix_pending_closes],
					&fsp->posix_pending_close_fds[0], fsp->num_posix_pending_closes * sizeof(int) );

				free((char *)fsp->posix_pending_close_fds);
				fsp->posix_pending_close_fds = NULL;
				fsp->num_posix_pending_closes = 0;
			}			

			other_fsp->posix_pending_close_fds[other_fsp->num_posix_pending_closes+extra_fds-1] = fsp->fd;
			other_fsp->num_posix_pending_closes += extra_fds;

			fsp->fd = -1; /* We have moved this fd to other_fsp's pending close array.... */

			break;
		}
	}

	return True;
}

/****************************************************************************
 Close the file associated with a fsp.

 This is where we must deal with POSIX "first close drops all locks"
 locking braindamage. We do this by searching for any other fsp open
 on the same dev/inode with open POSIX locks, and then transferring this
 fd (and all pending fd's attached to this fsp) to the posix_pending_close_fds
 array in that fsp.

 If there are no open fsp's on the same dev/inode then we close all the
 fd's in the posix_pending_close_fds array and then close the fd.

****************************************************************************/

int fd_close(struct connection_struct *conn, files_struct *fsp)
{
	int ret = 0;
	int saved_errno = 0;
	unsigned int i;

	/*
	 * Deal with transferring any pending fd's if there
	 * are POSIX locks outstanding.
	 */

	if(!fd_close_posix_locks(fsp))
		return -1;

	/*
	 * Close and free any pending closes given to use from
	 * other fsp's.
	 */

	if (fsp->posix_pending_close_fds) {

		for(i = 0; i < fsp->num_posix_pending_closes; i++) {
			if (fsp->posix_pending_close_fds[i] != -1) {
				if (conn->vfs_ops.close(fsp->posix_pending_close_fds[i]) == -1) {
					saved_errno = errno;
				}
			}
		}

		free((char *)fsp->posix_pending_close_fds);
		fsp->posix_pending_close_fds = NULL;
		fsp->num_posix_pending_closes = 0;
	}

	if(fsp->fd != -1)
		ret = conn->vfs_ops.close(fsp->fd);

	fsp->fd = -1;

	if (saved_errno != 0) {
		errno = saved_errno;
		ret = -1;
	}

	return ret;
}


/****************************************************************************
 Check a filename for the pipe string.
****************************************************************************/

static void check_for_pipe(char *fname)
{
	/* special case of pipe opens */
	char s[10];
	StrnCpy(s,fname,sizeof(s)-1);
	strlower(s);
	if (strstr(s,"pipe/")) {
		DEBUG(3,("Rejecting named pipe open for %s\n",fname));
		unix_ERR_class = ERRSRV;
		unix_ERR_code = ERRaccess;
	}
}

/****************************************************************************
 Open a file.
****************************************************************************/

static BOOL open_file(files_struct *fsp,connection_struct *conn,
		      char *fname1,int flags,mode_t mode)
{
	extern struct current_user current_user;
	pstring fname;
	int accmode = (flags & O_ACCMODE);
	SMB_STRUCT_STAT sbuf;

	fsp->fd = -1;
	fsp->oplock_type = NO_OPLOCK;
	errno = EPERM;

	pstrcpy(fname,fname1);

	/* Check permissions */

	/*
	 * This code was changed after seeing a client open request 
	 * containing the open mode of (DENY_WRITE/read-only) with
	 * the 'create if not exist' bit set. The previous code
	 * would fail to open the file read only on a read-only share
	 * as it was checking the flags parameter  directly against O_RDONLY,
	 * this was failing as the flags parameter was set to O_RDONLY|O_CREAT.
	 * JRA.
	 */

	if (!CAN_WRITE(conn)) {
		/* It's a read-only share - fail if we wanted to write. */
		if(accmode != O_RDONLY) {
			DEBUG(3,("Permission denied opening %s\n",fname));
			check_for_pipe(fname);
			return False;
		} else if(flags & O_CREAT) {
			/* We don't want to write - but we must make sure that O_CREAT
			   doesn't create the file if we have write access into the
			   directory.
			*/
			flags &= ~O_CREAT;
		}
	}

	/* actually do the open */
	fsp->fd = fd_open(conn, fname, flags, mode);

	if (fsp->fd == -1)  {
		DEBUG(3,("Error opening file %s (%s) (flags=%d)\n",
			 fname,strerror(errno),flags));
		check_for_pipe(fname);
		return False;
	}

	conn->vfs_ops.fstat(fsp->fd, &sbuf);

	/*
	 * POSIX allows read-only opens of directories. We don't
	 * want to do this (we use a different code path for this)
	 * so catch a directory open and return an EISDIR. JRA.
	 */

	if(S_ISDIR(sbuf.st_mode)) {
		fd_close(conn, fsp);
		errno = EISDIR;
		return False;
	}

	fsp->mode = sbuf.st_mode;
	fsp->inode = sbuf.st_ino;
	fsp->dev = sbuf.st_dev;
	GetTimeOfDay(&fsp->open_time);
	fsp->vuid = current_user.vuid;
	fsp->size = 0;
	fsp->pos = -1;
	fsp->can_lock = True;
	fsp->can_read = ((flags & O_WRONLY)==0);
	fsp->can_write = ((flags & (O_WRONLY|O_RDWR))!=0);
	fsp->share_mode = 0;
	fsp->print_file = False;
	fsp->modified = False;
	fsp->oplock_type = NO_OPLOCK;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->num_posix_locks = 0;
	fsp->num_posix_pending_closes = 0;
	fsp->posix_pending_close_fds = NULL;
	fsp->is_directory = False;
	fsp->stat_open = False;
	fsp->directory_delete_on_close = False;
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
	fsp->wcp = NULL; /* Write cache pointer. */

	DEBUG(2,("%s opened file %s read=%s write=%s (numopen=%d)\n",
		 *sesssetup_user ? sesssetup_user : conn->user,fsp->fsp_name,
		 BOOLSTR(fsp->can_read), BOOLSTR(fsp->can_write),
		 conn->num_files_open + 1));

	return True;
}

/****************************************************************************
  C. Hoch 11/22/95
  Helper for open_file_shared. 
  Truncate a file after checking locking; close file if locked.
  **************************************************************************/

static int truncate_unless_locked(struct connection_struct *conn, files_struct *fsp)
{
	SMB_BIG_UINT mask = (SMB_BIG_UINT)-1;

	if (!fsp->can_write)
		return -1;

	if (is_locked(fsp,fsp->conn,mask,0,WRITE_LOCK)){
		errno = EACCES;
		unix_ERR_class = ERRDOS;
		unix_ERR_code = ERRlock;
		return -1;
	} else {
		return conn->vfs_ops.ftruncate(fsp->fd,0); 
	}
}

/*******************************************************************
return True if the filename is one of the special executable types
********************************************************************/
static BOOL is_executable(const char *fname)
{
	if ((fname = strrchr(fname,'.'))) {
		if (strequal(fname,".com") ||
		    strequal(fname,".dll") ||
		    strequal(fname,".exe") ||
		    strequal(fname,".sym")) {
			return True;
		}
	}
	return False;
}

enum {AFAIL,AREAD,AWRITE,AALL};

/*******************************************************************
reproduce the share mode access table
this is horrendoously complex, and really can't be justified on any
rational grounds except that this is _exactly_ what NT does. See
the DENY1 and DENY2 tests in smbtorture for a comprehensive set of
test routines.
********************************************************************/
static int access_table(int new_deny,int old_deny,int old_mode,
			BOOL same_pid, BOOL isexe)
{
	  if (new_deny == DENY_ALL || old_deny == DENY_ALL) return(AFAIL);

	  if (same_pid) {
		  if (isexe && old_mode == DOS_OPEN_RDONLY && 
		      old_deny == DENY_DOS && new_deny == DENY_READ) {
			  return AFAIL;
		  }
		  if (!isexe && old_mode == DOS_OPEN_RDONLY && 
		      old_deny == DENY_DOS && new_deny == DENY_DOS) {
			  return AREAD;
		  }
		  if (new_deny == DENY_FCB && old_deny == DENY_DOS) {
			  if (isexe) return AFAIL;
			  if (old_mode == DOS_OPEN_RDONLY) return AFAIL;
			  return AALL;
		  }
		  if (old_mode == DOS_OPEN_RDONLY && old_deny == DENY_DOS) {
			  if (new_deny == DENY_FCB || new_deny == DENY_READ) {
				  if (isexe) return AREAD;
				  return AFAIL;
			  }
		  }
		  if (old_deny == DENY_FCB) {
			  if (new_deny == DENY_DOS || new_deny == DENY_FCB) return AALL;
			  return AFAIL;
		  }
	  }

	  if (old_deny == DENY_DOS || new_deny == DENY_DOS || 
	      old_deny == DENY_FCB || new_deny == DENY_FCB) {
		  if (isexe) {
			  if (old_deny == DENY_FCB || new_deny == DENY_FCB) {
				  return AFAIL;
			  }
			  if (old_deny == DENY_DOS) {
				  if (new_deny == DENY_READ && 
				      (old_mode == DOS_OPEN_RDONLY || 
				       old_mode == DOS_OPEN_RDWR)) {
					  return AFAIL;
				  }
				  if (new_deny == DENY_WRITE && 
				      (old_mode == DOS_OPEN_WRONLY || 
				       old_mode == DOS_OPEN_RDWR)) {
					  return AFAIL;
				  }
				  return AALL;
			  }
			  if (old_deny == DENY_NONE) return AALL;
			  if (old_deny == DENY_READ) return AWRITE;
			  if (old_deny == DENY_WRITE) return AREAD;
		  }
		  /* it isn't a exe, dll, sym or com file */
		  if (old_deny == new_deny && same_pid)
			  return(AALL);    

		  if (old_deny == DENY_READ || new_deny == DENY_READ) return AFAIL;
		  if (old_mode == DOS_OPEN_RDONLY) return(AREAD);
		  
		  return(AFAIL);
	  }
	  
	  switch (new_deny) 
		  {
		  case DENY_WRITE:
			  if (old_deny==DENY_WRITE && old_mode==DOS_OPEN_RDONLY) return(AREAD);
			  if (old_deny==DENY_READ && old_mode==DOS_OPEN_RDONLY) return(AWRITE);
			  if (old_deny==DENY_NONE && old_mode==DOS_OPEN_RDONLY) return(AALL);
			  return(AFAIL);
		  case DENY_READ:
			  if (old_deny==DENY_WRITE && old_mode==DOS_OPEN_WRONLY) return(AREAD);
			  if (old_deny==DENY_READ && old_mode==DOS_OPEN_WRONLY) return(AWRITE);
			  if (old_deny==DENY_NONE && old_mode==DOS_OPEN_WRONLY) return(AALL);
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
			     const char *fname, BOOL fcbopen, int *flags)
{
	int old_open_mode = GET_OPEN_MODE(share->share_mode);
	int old_deny_mode = GET_DENY_MODE(share->share_mode);

	/*
	 * Don't allow any open once the delete on close flag has been
	 * set.
	 */

	if(GET_DELETE_ON_CLOSE_FLAG(share->share_mode)) {
		DEBUG(5,("check_share_mode: Failing open on file %s as delete on close flag is set.\n",
			fname ));
		unix_ERR_class = ERRDOS;
		unix_ERR_code = ERRnoaccess;
		return False;
	}

	{
		int access_allowed = access_table(deny_mode,old_deny_mode,old_open_mode,
										(share->pid == getpid()),is_executable(fname));

		if ((access_allowed == AFAIL) ||
			(!fcbopen && (access_allowed == AREAD && *flags == O_RDWR)) ||
			(access_allowed == AREAD && *flags != O_RDONLY) ||
			(access_allowed == AWRITE && *flags != O_WRONLY)) {

			DEBUG(2,("Share violation on file (%d,%d,%d,%d,%s,fcbopen = %d, flags = %d) = %d\n",
				deny_mode,old_deny_mode,old_open_mode,
				(int)share->pid,fname, fcbopen, *flags, access_allowed));

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
 Deal with open deny mode and oplock break processing.
 Invarient: Share mode must be locked on entry and exit.
 Returns -1 on error, or number of share modes on success (may be zero).
****************************************************************************/

static int open_mode_check(connection_struct *conn, const char *fname, SMB_DEV_T dev,
							SMB_INO_T inode, int share_mode, int *p_flags, int *p_oplock_request,
							BOOL *p_all_current_opens_are_level_II)
{
  int i;
  int num_share_modes;
  int oplock_contention_count = 0;
  share_mode_entry *old_shares = 0;
  BOOL fcbopen = False;
  int deny_mode = GET_DENY_MODE(share_mode);
  BOOL broke_oplock;	

  if(GET_OPEN_MODE(share_mode) == DOS_OPEN_FCB)
    fcbopen = True;

  num_share_modes = get_share_modes(conn, dev, inode, &old_shares);

  if(num_share_modes == 0)
    return 0;

  /*
   * Check if the share modes will give us access.
   */

  do {

    broke_oplock = False;
    *p_all_current_opens_are_level_II = True;

    for(i = 0; i < num_share_modes; i++) {
      share_mode_entry *share_entry = &old_shares[i];

      /* 
       * By observation of NetBench, oplocks are broken *before* share
       * modes are checked. This allows a file to be closed by the client
       * if the share mode would deny access and the client has an oplock. 
       * Check if someone has an oplock on this file. If so we must break 
       * it before continuing. 
       */

      if((*p_oplock_request && EXCLUSIVE_OPLOCK_TYPE(share_entry->op_type)) ||
         (!*p_oplock_request && (share_entry->op_type != NO_OPLOCK))) {

        BOOL opb_ret;

        DEBUG(5,("open_mode_check: breaking oplock (%x) on file %s, \
dev = %x, inode = %.0f\n", share_entry->op_type, fname, (unsigned int)dev, (double)inode));

        /* Oplock break - unlock to request it. */
        unlock_share_entry(conn, dev, inode);

        opb_ret = request_oplock_break(share_entry, dev, inode);

        /* Now relock. */
        lock_share_entry(conn, dev, inode);

        if(opb_ret == False) {
          free((char *)old_shares);
          DEBUG(0,("open_mode_check: FAILED when breaking oplock (%x) on file %s, \
dev = %x, inode = %.0f\n", old_shares[i].op_type, fname, (unsigned int)dev, (double)inode));
          errno = EACCES;
          unix_ERR_class = ERRDOS;
          unix_ERR_code = ERRbadshare;
          return -1;
        }

        broke_oplock = True;
        *p_all_current_opens_are_level_II = False;
        break;

      } else if (!LEVEL_II_OPLOCK_TYPE(share_entry->op_type)) {
        *p_all_current_opens_are_level_II = False;
      }

      /* someone else has a share lock on it, check to see 
         if we can too */

      if(check_share_mode(share_entry, deny_mode, fname, fcbopen, p_flags) == False) {
        free((char *)old_shares);
        errno = EACCES;
        return -1;
      }

    } /* end for */

    if(broke_oplock) {
      free((char *)old_shares);
      num_share_modes = get_share_modes(conn, dev, inode, &old_shares);
      oplock_contention_count++;
    }
  } while(broke_oplock);

  if(old_shares != 0)
    free((char *)old_shares);

  /*
   * Refuse to grant an oplock in case the contention limit is
   * reached when going through the lock list multiple times.
   */

  if(oplock_contention_count >= lp_oplock_contention_limit(SNUM(conn))) {
    *p_oplock_request = 0;
    DEBUG(4,("open_mode_check: oplock contention = %d. Not granting oplock.\n",
          oplock_contention_count ));
  }

  return num_share_modes;
}

/****************************************************************************
 Open a file with a share mode.
****************************************************************************/

files_struct *open_file_shared(connection_struct *conn,char *fname,int share_mode,int ofun,
		      mode_t mode,int oplock_request, int *Access,int *action)
{
	int flags=0;
	int flags2=0;
	int deny_mode = GET_DENY_MODE(share_mode);
	BOOL allow_share_delete = GET_ALLOW_SHARE_DELETE(share_mode);
	SMB_STRUCT_STAT sbuf;
	BOOL file_existed = vfs_file_exist(conn, fname, &sbuf);
	BOOL fcbopen = False;
	SMB_DEV_T dev = 0;
	SMB_INO_T inode = 0;
	int num_share_modes = 0;
	BOOL all_current_opens_are_level_II = False;
	BOOL fsp_open = False;
	files_struct *fsp = NULL;
	int open_mode=0;
	uint16 port = 0;

	if (conn->printer) {
		/* printers are handled completely differently. Most of the passed parameters are
			ignored */
		*Access = DOS_OPEN_WRONLY;
		*action = FILE_WAS_CREATED;
		return print_fsp_open(conn, fname);
	}

	fsp = file_new();
	if(!fsp)
		return NULL;

	fsp->fd = -1;

	DEBUG(10,("open_file_shared: fname = %s, share_mode = %x, ofun = %x, mode = %o, oplock request = %d\n",
		fname, share_mode, ofun, (int)mode,  oplock_request ));

	if (!check_name(fname,conn)) {
		file_free(fsp);
		return NULL;
	} 

	/* ignore any oplock requests if oplocks are disabled */
	if (!lp_oplocks(SNUM(conn)) || global_client_failed_oplock_break) {
		oplock_request = 0;
	}

	/* this is for OS/2 EAs - try and say we don't support them */
	if (strstr(fname,".+,;=[].")) {
		unix_ERR_class = ERRDOS;
		/* OS/2 Workplace shell fix may be main code stream in a later release. */ 
#if 1 /* OS2_WPS_FIX - Recent versions of OS/2 need this. */
		unix_ERR_code = ERRcannotopen;
#else /* OS2_WPS_FIX */
		unix_ERR_code = ERROR_EAS_NOT_SUPPORTED;
#endif /* OS2_WPS_FIX */

		DEBUG(5,("open_file_shared: OS/2 EA's are not supported.\n"));
		file_free(fsp);
		return NULL;
	}

	if ((GET_FILE_OPEN_DISPOSITION(ofun) == FILE_EXISTS_FAIL) && file_existed)  {
		DEBUG(5,("open_file_shared: create new requested for file %s and file already exists.\n",
			fname ));
		file_free(fsp);
		errno = EEXIST;
		return NULL;
	}
      
	if (GET_FILE_CREATE_DISPOSITION(ofun) == FILE_CREATE_IF_NOT_EXIST)
		flags2 |= O_CREAT;

	if (GET_FILE_OPEN_DISPOSITION(ofun) == FILE_EXISTS_TRUNCATE)
		flags2 |= O_TRUNC;

	if (GET_FILE_OPEN_DISPOSITION(ofun) == FILE_EXISTS_FAIL)
		flags2 |= O_EXCL;

	/* note that we ignore the append flag as 
		append does not mean the same thing under dos and unix */

	switch (GET_OPEN_MODE(share_mode)) {
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
			(!CAN_WRITE(conn) || IS_DOS_READONLY(dos_mode(conn,fname,&sbuf)))) {
		if (!fcbopen) {
			DEBUG(5,("open_file_shared: read/write access requested for file %s on read only %s\n",
				fname, !CAN_WRITE(conn) ? "share" : "file" ));
			file_free(fsp);
			errno = EACCES;
			return NULL;
		}
		flags = O_RDONLY;
	}

	if (deny_mode > DENY_NONE && deny_mode!=DENY_FCB) {
		DEBUG(2,("Invalid deny mode %d on file %s\n",deny_mode,fname));
		file_free(fsp);
		errno = EINVAL;
		return NULL;
	}

	if (file_existed) {
		dev = sbuf.st_dev;
		inode = sbuf.st_ino;

		lock_share_entry(conn, dev, inode);

		num_share_modes = open_mode_check(conn, fname, dev, inode, share_mode,
								&flags, &oplock_request, &all_current_opens_are_level_II);
		if(num_share_modes == -1) {
			unlock_share_entry(conn, dev, inode);
			file_free(fsp);
			return NULL;
		}

		/*
		 * We exit this block with the share entry *locked*.....
		 */
	}

	DEBUG(4,("calling open_file with flags=0x%X flags2=0x%X mode=0%o\n",
			flags,flags2,(int)mode));

	fsp_open = open_file(fsp,conn,fname,flags|(flags2&~(O_TRUNC)),mode);

	if (!fsp_open && (flags == O_RDWR) && (errno != ENOENT) && fcbopen) {
		if((fsp_open = open_file(fsp,conn,fname,O_RDONLY,mode)) == True)
			flags = O_RDONLY;
	}

	if (!fsp_open) {
		if(file_existed)
			unlock_share_entry(conn, dev, inode);
		file_free(fsp);
		return NULL;
	}

	/*
	 * Deal with the race condition where two smbd's detect the file doesn't
	 * exist and do the create at the same time. One of them will win and
	 * set a share mode, the other (ie. this one) should check if the
	 * requested share mode for this create is allowed.
	 */

	if (!file_existed) { 

		lock_share_entry_fsp(fsp);

		num_share_modes = open_mode_check(conn, fname, dev, inode, share_mode,
								&flags, &oplock_request, &all_current_opens_are_level_II);

		if(num_share_modes == -1) {
			unlock_share_entry_fsp(fsp);
			fd_close(conn,fsp);
			file_free(fsp);
			return NULL;
		}

		/*
		 * We exit this block with the share entry *locked*.....
		 */
	}

	/*
	 * At this point onwards, we can guarentee that the share entry
	 * is locked, whether we created the file or not, and that the
	 * deny mode is compatible with all current opens.
	 */

	/*
	 * If requested, truncate the file.
	 */

	if ((flags2&O_TRUNC) && (truncate_unless_locked(conn,fsp) == -1)) {
		unlock_share_entry_fsp(fsp);
		fd_close(conn,fsp);
		file_free(fsp);
		return NULL;
	}

	switch (flags) {
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

	if (action) {
		if (file_existed && !(flags2 & O_TRUNC))
			*action = FILE_WAS_OPENED;
		if (!file_existed)
			*action = FILE_WAS_CREATED;
		if (file_existed && (flags2 & O_TRUNC))
			*action = FILE_WAS_OVERWRITTEN;
	}

	/* 
	 * Setup the oplock info in both the shared memory and
	 * file structs.
	 */

	if(oplock_request && (num_share_modes == 0) && 
			!IS_VETO_OPLOCK_PATH(conn,fname) && set_file_oplock(fsp, oplock_request) ) {
		port = global_oplock_port;
	} else if (oplock_request && all_current_opens_are_level_II) {
		port = global_oplock_port;
		oplock_request = LEVEL_II_OPLOCK;
		set_file_oplock(fsp, oplock_request);
	} else {
		port = 0;
		oplock_request = 0;
	}

	set_share_mode(fsp, port, oplock_request);

	unlock_share_entry_fsp(fsp);

	conn->num_files_open++;

	return fsp;
}

/****************************************************************************
 Open a file for permissions read only. Return a pseudo file entry
 with the 'stat_open' flag set 
****************************************************************************/

files_struct *open_file_stat(connection_struct *conn,
		   char *fname, int smb_ofun, SMB_STRUCT_STAT *pst, int *action)
{
	extern struct current_user current_user;
	files_struct *fsp = file_new();

	if(!fsp)
		return NULL;

	if(conn->vfs_ops.stat(dos_to_unix(fname, False), pst) < 0) {
		DEBUG(0,("open_file_stat: unable to stat name = %s. Error was %s\n",
			 fname, strerror(errno) ));
		file_free(fsp);
		return NULL;
	}

	if(S_ISDIR(pst->st_mode)) {
		DEBUG(0,("open_file_stat: %s is a directory !\n", fname ));
		file_free(fsp);
		return NULL;
	}

	*action = FILE_WAS_OPENED;
	
	DEBUG(5,("open_file_stat: opening file %s as a stat entry\n", fname));

	/*
	 * Setup the files_struct for it.
	 */
	
	fsp->fd = -1;
	fsp->mode = 0;
	GetTimeOfDay(&fsp->open_time);
	fsp->vuid = current_user.vuid;
	fsp->size = 0;
	fsp->pos = -1;
	fsp->can_lock = False;
	fsp->can_read = False;
	fsp->can_write = False;
	fsp->share_mode = 0;
	fsp->print_file = False;
	fsp->modified = False;
	fsp->oplock_type = NO_OPLOCK;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->num_posix_locks = 0;
	fsp->num_posix_pending_closes = 0;
	fsp->posix_pending_close_fds = NULL;
	fsp->is_directory = False;
	fsp->stat_open = True;
	fsp->directory_delete_on_close = False;
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
    fsp->wcp = NULL; /* Write cache pointer. */

	conn->num_files_open++;

	return fsp;
}

/****************************************************************************
 Open a directory from an NT SMB call.
****************************************************************************/

files_struct *open_directory(connection_struct *conn,
		   char *fname, int smb_ofun, mode_t unixmode, int *action)
{
	extern struct current_user current_user;
	SMB_STRUCT_STAT st;
	BOOL got_stat = False;
	files_struct *fsp = file_new();

	if(!fsp)
		return NULL;

	if(conn->vfs_ops.stat(dos_to_unix(fname, False), &st) == 0) {
		got_stat = True;
	}

	if (got_stat && (GET_FILE_OPEN_DISPOSITION(smb_ofun) == FILE_EXISTS_FAIL)) {
		file_free(fsp);
		errno = EEXIST; /* Setup so correct error is returned to client. */
		return NULL;
	}

	if (GET_FILE_CREATE_DISPOSITION(smb_ofun) == FILE_CREATE_IF_NOT_EXIST) {

		if (got_stat) {

			if(!S_ISDIR(st.st_mode)) {
				DEBUG(0,("open_directory: %s is not a directory !\n", fname ));
				file_free(fsp);
				errno = EACCES;
				return NULL;
			}
			*action = FILE_WAS_OPENED;

		} else {

			/*
			 * Try and create the directory.
			 */

			if(!CAN_WRITE(conn)) {
				DEBUG(2,("open_directory: failing create on read-only share\n"));
				file_free(fsp);
				errno = EACCES;
				return NULL;
			}

			if(conn->vfs_ops.mkdir(dos_to_unix(fname, False), 
                                               unix_mode(conn,aDIR, fname)) < 0) {
				DEBUG(0,("open_directory: unable to create %s. Error was %s\n",
					 fname, strerror(errno) ));
				file_free(fsp);
				return NULL;
			}
			*action = FILE_WAS_CREATED;

		}
	} else {

		/*
		 * Don't create - just check that it *was* a directory.
		 */

		if(!got_stat) {
			DEBUG(0,("open_directory: unable to stat name = %s. Error was %s\n",
				 fname, strerror(errno) ));
			file_free(fsp);
			return NULL;
		}

		if(!S_ISDIR(st.st_mode)) {
			DEBUG(0,("open_directory: %s is not a directory !\n", fname ));
			file_free(fsp);
			return NULL;
		}

		*action = FILE_WAS_OPENED;
	}
	
	DEBUG(5,("open_directory: opening directory %s\n",
		 fname));

	/*
	 * Setup the files_struct for it.
	 */
	
	fsp->fd = -1;
	fsp->mode = 0;
	GetTimeOfDay(&fsp->open_time);
	fsp->vuid = current_user.vuid;
	fsp->size = 0;
	fsp->pos = -1;
	fsp->can_lock = True;
	fsp->can_read = False;
	fsp->can_write = False;
	fsp->share_mode = 0;
	fsp->print_file = False;
	fsp->modified = False;
	fsp->oplock_type = NO_OPLOCK;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->num_posix_locks = 0;
	fsp->num_posix_pending_closes = 0;
	fsp->posix_pending_close_fds = NULL;
	fsp->is_directory = True;
	fsp->directory_delete_on_close = False;
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

	conn->num_files_open++;

	return fsp;
}

/*******************************************************************
 Check if the share mode on a file allows it to be deleted or unlinked.
 Return True if sharing doesn't prevent the operation.
********************************************************************/

BOOL check_file_sharing(connection_struct *conn,char *fname, BOOL rename_op)
{
  int i;
  int ret = False;
  share_mode_entry *old_shares = 0;
  int num_share_modes;
  SMB_STRUCT_STAT sbuf;
  pid_t pid = getpid();
  SMB_DEV_T dev;
  SMB_INO_T inode;

  if (conn->vfs_ops.stat(dos_to_unix(fname,False),&sbuf) == -1)
    return(True);

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
        if(BATCH_OPLOCK_TYPE(share_entry->op_type))
        {

#if 0

/* JRA. Try removing this code to see if the new oplock changes
   fix the problem. I'm dubious, but Andrew is recommending we
   try this....
*/

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
#endif /* 0 */
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

        if ((GET_DENY_MODE(share_entry->share_mode) != DENY_DOS) || 
	    (share_entry->pid != pid))
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
