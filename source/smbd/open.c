/* 
   Unix SMB/CIFS implementation.
   file opening and share modes
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2004
   
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

extern userdom_struct current_user_info;
extern uint16 global_oplock_port;
extern uint16 global_smbpid;
extern BOOL global_client_failed_oplock_break;

struct dev_inode_bundle {
	SMB_DEV_T dev;
	SMB_INO_T inode;
};

/****************************************************************************
 fd support routines - attempt to do a dos_open.
****************************************************************************/

static int fd_open(struct connection_struct *conn, const char *fname, 
		   int flags, mode_t mode)
{
	int fd;
#ifdef O_NOFOLLOW
	if (!lp_symlinks(SNUM(conn)))
		flags |= O_NOFOLLOW;
#endif

	fd = SMB_VFS_OPEN(conn,fname,flags,mode);

	DEBUG(10,("fd_open: name %s, flags = 0%o mode = 0%o, fd = %d. %s\n", fname,
		flags, (int)mode, fd, (fd == -1) ? strerror(errno) : "" ));

	return fd;
}

/****************************************************************************
 Close the file associated with a fsp.
****************************************************************************/

int fd_close(struct connection_struct *conn, files_struct *fsp)
{
	if (fsp->fd == -1)
		return 0; /* what we used to call a stat open. */
	return fd_close_posix(conn, fsp);
}


/****************************************************************************
 Check a filename for the pipe string.
****************************************************************************/

static void check_for_pipe(const char *fname)
{
	/* special case of pipe opens */
	char s[10];
	StrnCpy(s,fname,sizeof(s)-1);
	strlower_m(s);
	if (strstr(s,"pipe/")) {
		DEBUG(3,("Rejecting named pipe open for %s\n",fname));
		unix_ERR_class = ERRSRV;
		unix_ERR_code = ERRaccess;
		unix_ERR_ntstatus = NT_STATUS_ACCESS_DENIED;
	}
}

/****************************************************************************
 Open a file.
****************************************************************************/

static BOOL open_file(files_struct *fsp,connection_struct *conn,
		      const char *fname,SMB_STRUCT_STAT *psbuf,int flags,mode_t mode, uint32 desired_access)
{
	extern struct current_user current_user;
	int accmode = (flags & O_ACCMODE);
	int local_flags = flags;

	fsp->fd = -1;
	fsp->oplock_type = NO_OPLOCK;
	errno = EPERM;

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
			local_flags &= ~O_CREAT;
		}
	}

	/*
	 * This little piece of insanity is inspired by the
	 * fact that an NT client can open a file for O_RDONLY,
	 * but set the create disposition to FILE_EXISTS_TRUNCATE.
	 * If the client *can* write to the file, then it expects to
	 * truncate the file, even though it is opening for readonly.
	 * Quicken uses this stupid trick in backup file creation...
	 * Thanks *greatly* to "David W. Chapman Jr." <dwcjr@inethouston.net>
	 * for helping track this one down. It didn't bite us in 2.0.x
	 * as we always opened files read-write in that release. JRA.
	 */

	if ((accmode == O_RDONLY) && ((flags & O_TRUNC) == O_TRUNC)) {
		DEBUG(10,("open_file: truncate requested on read-only open for file %s\n",fname ));
		local_flags = (flags & ~O_ACCMODE)|O_RDWR;
	}

	if ((desired_access & (FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_EXECUTE)) ||
			(local_flags & O_CREAT) || ((local_flags & O_TRUNC) == O_TRUNC) ) {

		/*
		 * We can't actually truncate here as the file may be locked.
		 * open_file_shared will take care of the truncate later. JRA.
		 */

		local_flags &= ~O_TRUNC;

#if defined(O_NONBLOCK) && defined(S_ISFIFO)
		/*
		 * We would block on opening a FIFO with no one else on the
		 * other end. Do what we used to do and add O_NONBLOCK to the
		 * open flags. JRA.
		 */

		if (VALID_STAT(*psbuf) && S_ISFIFO(psbuf->st_mode))
			local_flags |= O_NONBLOCK;
#endif

		/* Don't create files with Microsoft wildcard characters. */
		if ((local_flags & O_CREAT) && !VALID_STAT(*psbuf) && ms_has_wild(fname))  {
			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRinvalidname;
			unix_ERR_ntstatus = NT_STATUS_OBJECT_NAME_INVALID;
			return False;
		}

		/* Actually do the open */
		fsp->fd = fd_open(conn, fname, local_flags, mode);
		if (fsp->fd == -1)  {
			DEBUG(3,("Error opening file %s (%s) (local_flags=%d) (flags=%d)\n",
				 fname,strerror(errno),local_flags,flags));
			check_for_pipe(fname);
			return False;
		}

		/* Inherit the ACL if the file was created. */
		if ((local_flags & O_CREAT) && !VALID_STAT(*psbuf))
			inherit_access_acl(conn, fname, mode);

	} else
		fsp->fd = -1; /* What we used to call a stat open. */

	if (!VALID_STAT(*psbuf)) {
		int ret;

		if (fsp->fd == -1)
			ret = SMB_VFS_STAT(conn, fname, psbuf);
		else {
			ret = SMB_VFS_FSTAT(fsp,fsp->fd,psbuf);
			/* If we have an fd, this stat should succeed. */
			if (ret == -1)
				DEBUG(0,("Error doing fstat on open file %s (%s)\n", fname,strerror(errno) ));
		}

		/* For a non-io open, this stat failing means file not found. JRA */
		if (ret == -1) {
			fd_close(conn, fsp);
			return False;
		}
	}

	/*
	 * POSIX allows read-only opens of directories. We don't
	 * want to do this (we use a different code path for this)
	 * so catch a directory open and return an EISDIR. JRA.
	 */

	if(S_ISDIR(psbuf->st_mode)) {
		fd_close(conn, fsp);
		errno = EISDIR;
		return False;
	}

	fsp->mode = psbuf->st_mode;
	fsp->inode = psbuf->st_ino;
	fsp->dev = psbuf->st_dev;
	fsp->vuid = current_user.vuid;
	fsp->file_pid = global_smbpid;
	fsp->size = psbuf->st_size;
	fsp->can_lock = True;
	fsp->can_read = ((flags & O_WRONLY)==0);
	fsp->can_write = ((flags & (O_WRONLY|O_RDWR))!=0);
	fsp->share_mode = 0;
	fsp->desired_access = desired_access;
	fsp->print_file = False;
	fsp->modified = False;
	fsp->oplock_type = NO_OPLOCK;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->is_directory = False;
	fsp->is_stat = False;
	fsp->directory_delete_on_close = False;
	string_set(&fsp->fsp_name,fname);
	fsp->wcp = NULL; /* Write cache pointer. */

	DEBUG(2,("%s opened file %s read=%s write=%s (numopen=%d)\n",
		 *current_user_info.smb_name ? current_user_info.smb_name : conn->user,fsp->fsp_name,
		 BOOLSTR(fsp->can_read), BOOLSTR(fsp->can_write),
		 conn->num_files_open + 1));

	errno = 0;
	return True;
}

/*******************************************************************
 Return True if the filename is one of the special executable types.
********************************************************************/

static BOOL is_executable(const char *fname)
{
	if ((fname = strrchr_m(fname,'.'))) {
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
 Reproduce the share mode access table.
 This is horrendoously complex, and really can't be justified on any
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
 Check if we can open a file with a share mode.
****************************************************************************/

static BOOL check_share_mode(connection_struct *conn, share_mode_entry *share, int share_mode, uint32 desired_access,
			     const char *fname, BOOL fcbopen, int *flags)
{
	int deny_mode = GET_DENY_MODE(share_mode);
	int old_open_mode = GET_OPEN_MODE(share->share_mode);
	int old_deny_mode = GET_DENY_MODE(share->share_mode);
	BOOL non_io_open_request;
	BOOL non_io_open_existing;

	/*
	 * share modes = false means don't bother to check for
	 * DENY mode conflict. This is a *really* bad idea :-). JRA.
	 */

	if(!lp_share_modes(SNUM(conn)))
		return True;

	if (desired_access & ~(SYNCHRONIZE_ACCESS|READ_CONTROL_ACCESS|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES)) {
		non_io_open_request = False;
	} else {
		non_io_open_request = True;
	}

	if (share->desired_access & ~(SYNCHRONIZE_ACCESS|READ_CONTROL_ACCESS|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES)) {
		non_io_open_existing = False;
	} else {
		non_io_open_existing = True;
	}

	/*
	 * Don't allow any opens once the delete on close flag has been
	 * set.
	 */

	if (GET_DELETE_ON_CLOSE_FLAG(share->share_mode)) {
		DEBUG(5,("check_share_mode: Failing open on file %s as delete on close flag is set.\n",
			fname ));
		/* Use errno to map to correct error. */
		unix_ERR_class = SMB_SUCCESS;
		unix_ERR_code = 0;
		unix_ERR_ntstatus = NT_STATUS_OK;
		return False;
	}

	/* this is a nasty hack, but necessary until we rewrite our open
	   handling to use a NTCreateX call as the basic call.
	   NT may open a file with neither read nor write access, and in
		   this case it expects the open not to conflict with any
		   existing deny modes. This happens (for example) during a
		   "xcopy /o" where the second file descriptor is used for
		   ACL sets
		   (tridge)
	*/

	/*
	 * This is a bit wierd - the test for desired access not having the
	 * critical bits seems seems odd. Firstly, if both opens have no
	 * critical bits then always ignore. Then check the "allow delete"
	 * then check for either. This probably isn't quite right yet but
	 * gets us much closer. JRA.
	 */

	/*
	 * If desired_access doesn't contain READ_DATA,WRITE_DATA,APPEND_DATA or EXECUTE
	 * and the existing desired_acces then share modes don't conflict.
	 */

	if (non_io_open_request && non_io_open_existing) {

		/*
		 * Wrinkle discovered by smbtorture....
		 * If both are non-io open and requester is asking for delete and current open has delete access
		 * but neither open has allowed file share delete then deny.... this is very strange and
		 * seems to be the only case in which non-io opens conflict. JRA.
		 */

		if ((desired_access & DELETE_ACCESS) && (share->desired_access & DELETE_ACCESS) && 
				(!GET_ALLOW_SHARE_DELETE(share->share_mode) || !GET_ALLOW_SHARE_DELETE(share_mode))) {
			DEBUG(5,("check_share_mode: Failing open on file %s as delete access requests conflict.\n",
				fname ));
			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRbadshare;
			unix_ERR_ntstatus = NT_STATUS_SHARING_VIOLATION;

			return False;
		}

		DEBUG(5,("check_share_mode: Allowing open on file %s as both desired access (0x%x) \
and existing desired access (0x%x) are non-data opens\n", 
			fname, (unsigned int)desired_access, (unsigned int)share->desired_access ));
		return True;
	} else if (non_io_open_request || non_io_open_existing) {
		/*
		 * If either are non-io opens then share modes don't conflict.
		 */
		DEBUG(5,("check_share_mode: One non-io open. Allowing open on file %s as desired access (0x%x) doesn't conflict with\
existing desired access (0x%x).\n", fname, (unsigned int)desired_access, (unsigned int)share->desired_access ));
		return True;
	}

	/*
	 * If delete access was requested and the existing share mode doesn't have
	 * ALLOW_SHARE_DELETE then deny.
	 */

	if ((desired_access & DELETE_ACCESS) && !GET_ALLOW_SHARE_DELETE(share->share_mode)) {
		DEBUG(5,("check_share_mode: Failing open on file %s as delete access requested and allow share delete not set.\n",
			fname ));
		unix_ERR_class = ERRDOS;
		unix_ERR_code = ERRbadshare;
		unix_ERR_ntstatus = NT_STATUS_SHARING_VIOLATION;

		return False;
	}

	/*
	 * The inverse of the above.
	 * If delete access was granted and the new share mode doesn't have
	 * ALLOW_SHARE_DELETE then deny.
	 */

	if ((share->desired_access & DELETE_ACCESS) && !GET_ALLOW_SHARE_DELETE(share_mode)) {
		DEBUG(5,("check_share_mode: Failing open on file %s as delete access granted and allow share delete not requested.\n",
			fname ));
		unix_ERR_class = ERRDOS;
		unix_ERR_code = ERRbadshare;
		unix_ERR_ntstatus = NT_STATUS_SHARING_VIOLATION;

		return False;
	}

	/*
	 * If desired_access doesn't contain READ_DATA,WRITE_DATA,APPEND_DATA or EXECUTE
	 * then share modes don't conflict. Likewise with existing desired access.
	 */

	if ( !(desired_access & (FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_EXECUTE)) ||
		!(share->desired_access & (FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_EXECUTE)) ) {
		DEBUG(5,("check_share_mode: Allowing open on file %s as desired access (0x%x) doesn't conflict with\
existing desired access (0x%x).\n", fname, (unsigned int)desired_access, (unsigned int)share->desired_access ));
		return True;
	}

	{
		int access_allowed = access_table(deny_mode,old_deny_mode,old_open_mode,
						(share->pid == sys_getpid()),is_executable(fname));

		if ((access_allowed == AFAIL) ||
			(!fcbopen && (access_allowed == AREAD && *flags == O_RDWR)) ||
			(access_allowed == AREAD && *flags != O_RDONLY) ||
			(access_allowed == AWRITE && *flags != O_WRONLY)) {

			DEBUG(2,("Share violation on file (%d,%d,%d,%d,%s,fcbopen = %d, flags = %d) = %d\n",
				deny_mode,old_deny_mode,old_open_mode,
				(int)share->pid,fname, fcbopen, *flags, access_allowed));

			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRbadshare;
			unix_ERR_ntstatus = NT_STATUS_SHARING_VIOLATION;

			return False;
		}

		if (access_allowed == AREAD)
			*flags = O_RDONLY;

		if (access_allowed == AWRITE)
			*flags = O_WRONLY;

	}

	return True;
}


#if defined(DEVELOPER)
static void validate_my_share_entries(int num, share_mode_entry *share_entry)
{
	files_struct *fsp;

	if (share_entry->pid != sys_getpid())
		return;

	fsp = file_find_dif(share_entry->dev, share_entry->inode, share_entry->share_file_id);
	if (!fsp) {
		DEBUG(0,("validate_my_share_entries: PANIC : %s\n", share_mode_str(num, share_entry) ));
		smb_panic("validate_my_share_entries: Cannot match a share entry with an open file\n");
	}

	if (((uint16)fsp->oplock_type) != share_entry->op_type) {
		pstring str;
		DEBUG(0,("validate_my_share_entries: PANIC : %s\n", share_mode_str(num, share_entry) ));
		slprintf(str, sizeof(str)-1, "validate_my_share_entries: file %s, oplock_type = 0x%x, op_type = 0x%x\n",
				fsp->fsp_name, (unsigned int)fsp->oplock_type, (unsigned int)share_entry->op_type );
		smb_panic(str);
	}
}
#endif

struct share_mode_entry_list {
	struct share_mode_entry_list *next, *prev;
	share_mode_entry entry;
};

static void free_broken_entry_list(struct share_mode_entry_list *broken_entry_list)
{
	while (broken_entry_list) {
		struct share_mode_entry_list *broken_entry = broken_entry_list;
		DLIST_REMOVE(broken_entry_list, broken_entry);
		SAFE_FREE(broken_entry);
	}
}

/****************************************************************************
 Deal with open deny mode and oplock break processing.
 Invarient: Share mode must be locked on entry and exit.
 Returns -1 on error, or number of share modes on success (may be zero).
****************************************************************************/

static int open_mode_check(connection_struct *conn, const char *fname, SMB_DEV_T dev,
			   SMB_INO_T inode, 
			   uint32 desired_access,
			   int share_mode, int *p_flags, int *p_oplock_request,
			   BOOL *p_all_current_opens_are_level_II)
{
	int i;
	int num_share_modes;
	int oplock_contention_count = 0;
	share_mode_entry *old_shares = NULL;
	BOOL fcbopen = False;
	BOOL broke_oplock;

	if(GET_OPEN_MODE(share_mode) == DOS_OPEN_FCB)
		fcbopen = True;
	
	num_share_modes = get_share_modes(conn, dev, inode, &old_shares);
	
	if(num_share_modes == 0) {
		SAFE_FREE(old_shares);
		return 0;
	}
	
	if (desired_access && ((desired_access & ~(SYNCHRONIZE_ACCESS|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES))==0) &&
		((desired_access & (SYNCHRONIZE_ACCESS|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES)) != 0)) {
		/* Stat open that doesn't trigger oplock breaks or share mode checks... ! JRA. */
		SAFE_FREE(old_shares);
		return num_share_modes;
	}

	/*
	 * Check if the share modes will give us access.
	 */
	
	do {
		struct share_mode_entry_list *broken_entry_list = NULL;
		struct share_mode_entry_list *broken_entry = NULL;

		broke_oplock = False;
		*p_all_current_opens_are_level_II = True;
		
		for(i = 0; i < num_share_modes; i++) {
			BOOL cause_oplock_break = False;
			share_mode_entry *share_entry = &old_shares[i];
			
#if defined(DEVELOPER)
			validate_my_share_entries(i, share_entry);
#endif

			/* 
			 * By observation of NetBench, oplocks are broken *before* share
			 * modes are checked. This allows a file to be closed by the client
			 * if the share mode would deny access and the client has an oplock. 
			 * Check if someone has an oplock on this file. If so we must break 
			 * it before continuing. 
			 */
			
			/* Was this a delete this file request ? */
			if (!*p_oplock_request && desired_access == DELETE_ACCESS &&
					!BATCH_OPLOCK_TYPE(share_entry->op_type)) {
				/* Don't break the oplock in this case. */
				cause_oplock_break = False;
			} else if((*p_oplock_request && EXCLUSIVE_OPLOCK_TYPE(share_entry->op_type)) ||
			   (!*p_oplock_request && (share_entry->op_type != NO_OPLOCK))) {
				cause_oplock_break = True;
			}

			if(cause_oplock_break) {
				BOOL opb_ret;

				DEBUG(5,("open_mode_check: oplock_request = %d, breaking oplock (%x) on file %s, \
dev = %x, inode = %.0f\n", *p_oplock_request, share_entry->op_type, fname, (unsigned int)dev, (double)inode));
				
				/* Ensure the reply for the open uses the correct sequence number. */
				/* This isn't a real deferred packet as it's response will also increment
				 * the sequence.
				 */
				srv_defer_sign_response(get_current_mid());

				/* Oplock break - unlock to request it. */
				unlock_share_entry(conn, dev, inode);
				
				opb_ret = request_oplock_break(share_entry, False);
				
				/* Now relock. */
				lock_share_entry(conn, dev, inode);
				
				if(opb_ret == False) {
					DEBUG(0,("open_mode_check: FAILED when breaking oplock (%x) on file %s, \
dev = %x, inode = %.0f\n", old_shares[i].op_type, fname, (unsigned int)dev, (double)inode));
					SAFE_FREE(old_shares);
					errno = EACCES;
					unix_ERR_class = ERRDOS;
					unix_ERR_code = ERRbadshare;
					unix_ERR_ntstatus = NT_STATUS_SHARING_VIOLATION;
					return -1;
				}
				
				broken_entry = SMB_MALLOC_P(struct share_mode_entry_list);
				if (!broken_entry) {
					smb_panic("open_mode_check: malloc fail.\n");
				}
				broken_entry->entry = *share_entry;
				DLIST_ADD(broken_entry_list, broken_entry);
				broke_oplock = True;
				
			} else if (!LEVEL_II_OPLOCK_TYPE(share_entry->op_type)) {
				*p_all_current_opens_are_level_II = False;
			}
		} /* end for */
		
		if (broke_oplock) {
			/* Update the current open table. */
			SAFE_FREE(old_shares);
			num_share_modes = get_share_modes(conn, dev, inode, &old_shares);
		}

		/* Now we check the share modes, after any oplock breaks. */
		for(i = 0; i < num_share_modes; i++) {
			share_mode_entry *share_entry = &old_shares[i];

			/* someone else has a share lock on it, check to see if we can too */
			if (!check_share_mode(conn, share_entry, share_mode, desired_access,
						fname, fcbopen, p_flags)) {
				SAFE_FREE(old_shares);
				free_broken_entry_list(broken_entry_list);
				errno = EACCES;
				return -1;
                        }
		}

		for(broken_entry = broken_entry_list; broken_entry; broken_entry = broken_entry->next) {
			oplock_contention_count++;
			
			/* Paranoia check that this is no longer an exlusive entry. */
			for(i = 0; i < num_share_modes; i++) {
				share_mode_entry *share_entry = &old_shares[i];
				
				if (share_modes_identical(&broken_entry->entry, share_entry) && 
					    EXCLUSIVE_OPLOCK_TYPE(share_entry->op_type) ) {
					
					/*
					 * This should not happen. The target left this oplock
					 * as exlusive.... The process *must* be dead.... 
					 */
					
					DEBUG(0,("open_mode_check: exlusive oplock left by process %d \
after break ! For file %s, dev = %x, inode = %.0f. Deleting it to continue...\n",
						(int)broken_entry->entry.pid, fname, (unsigned int)dev, (double)inode));
					
					if (process_exists(broken_entry->entry.pid)) {
						DEBUG(0,("open_mode_check: Existent process %lu left active oplock.\n",
							 (unsigned long)broken_entry->entry.pid ));
					}
					
					if (del_share_entry(dev, inode, &broken_entry->entry, NULL) == -1) {
						free_broken_entry_list(broken_entry_list);
						errno = EACCES;
						unix_ERR_class = ERRDOS;
						unix_ERR_code = ERRbadshare;
						unix_ERR_ntstatus = NT_STATUS_SHARING_VIOLATION;
						return -1;
					}
					
					/*
					 * We must reload the share modes after deleting the 
					 * other process's entry.
					 */
					
					SAFE_FREE(old_shares);
					num_share_modes = get_share_modes(conn, dev, inode, &old_shares);
					break;
				}
			} /* end for paranoia... */
		} /* end for broken_entry */
		free_broken_entry_list(broken_entry_list);
	} while(broke_oplock);
	
	/*
	 * Refuse to grant an oplock in case the contention limit is
	 * reached when going through the lock list multiple times.
	 */
	
	if(oplock_contention_count >= lp_oplock_contention_limit(SNUM(conn))) {
		*p_oplock_request = 0;
		DEBUG(4,("open_mode_check: oplock contention = %d. Not granting oplock.\n",
			 oplock_contention_count ));
	}
	
	SAFE_FREE(old_shares);
	return num_share_modes;
}

/****************************************************************************
 Delete the record for a handled deferred open entry.
****************************************************************************/

static void delete_defered_open_entry_record(connection_struct *conn, SMB_DEV_T dev, SMB_INO_T inode)
{
	uint16 mid = get_current_mid();
	pid_t mypid = sys_getpid();
	deferred_open_entry *de_array = NULL;
	int num_de_entries, i;

	if (!lp_defer_sharing_violations()) {
		return;
	}

	num_de_entries = get_deferred_opens(conn, dev, inode, &de_array);
	for (i = 0; i < num_de_entries; i++) {
		deferred_open_entry *entry = &de_array[i];
		if (entry->pid == mypid && entry->mid == mid && entry->dev == dev &&
			entry->inode == inode) {

			/* Remove the deferred open entry from the array. */
			delete_deferred_open_entry(entry);
			SAFE_FREE(de_array);
			return;
		}
	}
	SAFE_FREE(de_array);
}

/****************************************************************************
 Handle the 1 second delay in returning a SHARING_VIOLATION error.
****************************************************************************/

void defer_open_sharing_error(connection_struct *conn, struct timeval *ptv,
		char *fname, SMB_DEV_T dev, SMB_INO_T inode)
{
	uint16 mid = get_current_mid();
	pid_t mypid = sys_getpid();
	deferred_open_entry *de_array = NULL;
	int num_de_entries, i;
	struct dev_inode_bundle dib;

	if (!lp_defer_sharing_violations()) {
		return;
	}

	dib.dev = dev;
	dib.inode = inode;

	num_de_entries = get_deferred_opens(conn, dev, inode, &de_array);
	for (i = 0; i < num_de_entries; i++) {
		deferred_open_entry *entry = &de_array[i];
		if (entry->pid == mypid && entry->mid == mid) {
			/*
			 * Check if a 1 second timeout has expired.
			 */
			if (usec_time_diff(ptv, &entry->time) > SHARING_VIOLATION_USEC_WAIT) {
				DEBUG(10,("defer_open_sharing_error: Deleting deferred open entry for mid %u, \
file %s\n",
					(unsigned int)mid, fname ));

				/* Expired, return a real error. */
				/* Remove the deferred open entry from the array. */

				delete_deferred_open_entry(entry);
				SAFE_FREE(de_array);
				return;
			}
			/*
			 * If the timeout hasn't expired yet and we still have a sharing violation,
			 * just leave the entry in the deferred open array alone. We do need to
			 * reschedule this open call though (with the original created time).
			 */
			DEBUG(10,("defer_open_sharing_error: time [%u.%06u] updating \
deferred open entry for mid %u, file %s\n",
				(unsigned int)entry->time.tv_sec,
				(unsigned int)entry->time.tv_usec,
				(unsigned int)mid, fname ));

			push_sharing_violation_open_smb_message(&entry->time, (char *)&dib, sizeof(dib));
			SAFE_FREE(de_array);
			return;
		}
	}

	DEBUG(10,("defer_open_sharing_error: time [%u.%06u] adding deferred open entry for mid %u, file %s\n",
		(unsigned int)ptv->tv_sec, (unsigned int)ptv->tv_usec, (unsigned int)mid, fname ));

	if (!push_sharing_violation_open_smb_message(ptv, (char *)&dib, sizeof(dib))) {
		SAFE_FREE(de_array);
		return;
	}
	if (!add_deferred_open(mid, ptv, dev, inode, global_oplock_port, fname)) {
		remove_sharing_violation_open_smb_message(mid);
	}

	/*
	 * Push the MID of this packet on the signing queue.
	 * We only do this once, the first time we push the packet
	 * onto the deferred open queue, as this has a side effect
	 * of incrementing the response sequence number.
	 */

	srv_defer_sign_response(mid);

	SAFE_FREE(de_array);
}

/****************************************************************************
 Set a kernel flock on a file for NFS interoperability.
 This requires a patch to Linux.
****************************************************************************/

static void kernel_flock(files_struct *fsp, int deny_mode)
{
#if HAVE_KERNEL_SHARE_MODES
	int kernel_mode = 0;
	if (deny_mode == DENY_READ) kernel_mode = LOCK_MAND|LOCK_WRITE;
	else if (deny_mode == DENY_WRITE) kernel_mode = LOCK_MAND|LOCK_READ;
	else if (deny_mode == DENY_ALL) kernel_mode = LOCK_MAND;
	if (kernel_mode) flock(fsp->fd, kernel_mode);
#endif
	;;
}


static BOOL open_match_attributes(connection_struct *conn, const char *path, uint32 old_dos_mode, uint32 new_dos_mode,
		mode_t existing_mode, mode_t new_mode, mode_t *returned_mode)
{
	uint32 noarch_old_dos_mode, noarch_new_dos_mode;

	noarch_old_dos_mode = (old_dos_mode & ~FILE_ATTRIBUTE_ARCHIVE);
	noarch_new_dos_mode = (new_dos_mode & ~FILE_ATTRIBUTE_ARCHIVE);

	if((noarch_old_dos_mode == 0 && noarch_new_dos_mode != 0) || 
	   (noarch_old_dos_mode != 0 && ((noarch_old_dos_mode & noarch_new_dos_mode) == noarch_old_dos_mode)))
		*returned_mode = new_mode;
	else
		*returned_mode = (mode_t)0;

	DEBUG(10,("open_match_attributes: file %s old_dos_mode = 0x%x, existing_mode = 0%o, new_dos_mode = 0x%x returned_mode = 0%o\n",
		path,
		old_dos_mode, (unsigned int)existing_mode, new_dos_mode, (unsigned int)*returned_mode ));

	/* If we're mapping SYSTEM and HIDDEN ensure they match. */
	if (lp_map_system(SNUM(conn)) || lp_store_dos_attributes(SNUM(conn))) {
		if ((old_dos_mode & FILE_ATTRIBUTE_SYSTEM) && !(new_dos_mode & FILE_ATTRIBUTE_SYSTEM))
			return False;
	}
	if (lp_map_hidden(SNUM(conn)) || lp_store_dos_attributes(SNUM(conn))) {
		if ((old_dos_mode & FILE_ATTRIBUTE_HIDDEN) && !(new_dos_mode & FILE_ATTRIBUTE_HIDDEN))
			return False;
	}
	return True;
}

/****************************************************************************
 Open a file with a share mode.
****************************************************************************/

files_struct *open_file_shared(connection_struct *conn,char *fname, SMB_STRUCT_STAT *psbuf, 
			       int share_mode,int ofun, uint32 new_dos_mode, int oplock_request, 
			       int *Access,int *action)
{
	return open_file_shared1(conn, fname, psbuf, 0, share_mode, ofun, new_dos_mode,
				 oplock_request, Access, action);
}

/****************************************************************************
 Open a file with a share mode.
****************************************************************************/

files_struct *open_file_shared1(connection_struct *conn,char *fname, SMB_STRUCT_STAT *psbuf, 
				uint32 desired_access, 
				int share_mode,int ofun, uint32 new_dos_mode,
				int oplock_request, 
				int *Access,int *paction)
{
	int flags=0;
	int flags2=0;
	int deny_mode = GET_DENY_MODE(share_mode);
	BOOL allow_share_delete = GET_ALLOW_SHARE_DELETE(share_mode);
	BOOL delete_on_close = GET_DELETE_ON_CLOSE_FLAG(share_mode);
	BOOL file_existed = VALID_STAT(*psbuf);
	BOOL fcbopen = False;
	BOOL def_acl = False;
	BOOL add_share_mode = True;
	BOOL internal_only_open = False;
	SMB_DEV_T dev = 0;
	SMB_INO_T inode = 0;
	int num_share_modes = 0;
	BOOL all_current_opens_are_level_II = False;
	BOOL fsp_open = False;
	files_struct *fsp = NULL;
	int open_mode=0;
	uint16 port = 0;
	mode_t new_mode = (mode_t)0;
	int action;
	uint32 existing_dos_mode = 0;
	struct pending_message_list *pml = NULL;
	uint16 mid = get_current_mid();
	/* We add aARCH to this as this mode is only used if the file is created new. */
	mode_t mode = unix_mode(conn,new_dos_mode | aARCH,fname);

	if (oplock_request == INTERNAL_OPEN_ONLY) {
		internal_only_open = True;
		oplock_request = 0;
	}

	if ((pml = get_open_deferred_message(mid)) != NULL) {
		struct dev_inode_bundle dib;

		memcpy(&dib, pml->private_data.data, sizeof(dib));

		/* There could be a race condition where the dev/inode pair
			has changed since we deferred the message. If so, just
			remove the deferred open entry and return sharing violation. */

		/* If the timeout value is non-zero, we need to just
			return sharing violation. Don't retry the open
			as we were not notified of a close and we don't want to
			trigger another spurious oplock break. */

		if (!file_existed || dib.dev != psbuf->st_dev || dib.inode != psbuf->st_ino ||
				pml->msg_time.tv_sec || pml->msg_time.tv_usec) {
			/* Ensure we don't reprocess this message. */
			remove_sharing_violation_open_smb_message(mid);

			/* Now remove the deferred open entry under lock. */
			lock_share_entry(conn, dib.dev, dib.inode);
			delete_defered_open_entry_record(conn, dib.dev, dib.inode);
			unlock_share_entry(conn, dib.dev, dib.inode);

			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRbadshare;
			unix_ERR_ntstatus = NT_STATUS_SHARING_VIOLATION;
			return NULL;
		}
		/* Ensure we don't reprocess this message. */
		remove_sharing_violation_open_smb_message(mid);

	}

	if (conn->printer) {
		/* printers are handled completely differently. Most of the passed parameters are
			ignored */
		if (Access)
			*Access = DOS_OPEN_WRONLY;
		if (paction)
			*paction = FILE_WAS_CREATED;
		return print_fsp_open(conn, fname);
	}

	fsp = file_new(conn);
	if(!fsp)
		return NULL;

	DEBUG(10,("open_file_shared: fname = %s, dos_attrs = %x, share_mode = %x, ofun = %x, mode = %o, oplock request = %d\n",
		fname, new_dos_mode, share_mode, ofun, (int)mode,  oplock_request ));

	if (!check_name(fname,conn)) {
		file_free(fsp);
		return NULL;
	} 

	new_dos_mode &= SAMBA_ATTRIBUTES_MASK;
	if (file_existed) {
		existing_dos_mode = dos_mode(conn, fname, psbuf);
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
		if (S_ISDIR(psbuf->st_mode)) {
			errno = EISDIR;
		} else {
			errno = EEXIST;
		}
		return NULL;
	}
      
	if (CAN_WRITE(conn) && (GET_FILE_CREATE_DISPOSITION(ofun) == FILE_CREATE_IF_NOT_EXIST))
		flags2 |= O_CREAT;

	if (CAN_WRITE(conn) && (GET_FILE_OPEN_DISPOSITION(ofun) == FILE_EXISTS_TRUNCATE))
		flags2 |= O_TRUNC;

	/* We only care about matching attributes on file exists and truncate. */
	if (file_existed && (GET_FILE_OPEN_DISPOSITION(ofun) == FILE_EXISTS_TRUNCATE)) {
		if (!open_match_attributes(conn, fname, existing_dos_mode, new_dos_mode,
					psbuf->st_mode, mode, &new_mode)) {
			DEBUG(5,("open_file_shared: attributes missmatch for file %s (%x %x) (0%o, 0%o)\n",
						fname, existing_dos_mode, new_dos_mode,
						(int)psbuf->st_mode, (int)mode ));
			file_free(fsp);
			errno = EACCES;
			return NULL;
		}
	}

	if (GET_FILE_OPEN_DISPOSITION(ofun) == FILE_EXISTS_FAIL)
		flags2 |= O_EXCL;

	/* note that we ignore the append flag as 
		append does not mean the same thing under dos and unix */

	switch (GET_OPEN_MODE(share_mode)) {
		case DOS_OPEN_WRONLY: 
			flags = O_WRONLY; 
			if (desired_access == 0)
				desired_access = FILE_WRITE_DATA;
			break;
		case DOS_OPEN_FCB: 
			fcbopen = True;
			flags = O_RDWR; 
			if (desired_access == 0)
				desired_access = FILE_READ_DATA|FILE_WRITE_DATA;
			break;
		case DOS_OPEN_RDWR: 
			flags = O_RDWR; 
			if (desired_access == 0)
				desired_access = FILE_READ_DATA|FILE_WRITE_DATA;
			break;
		default:
			flags = O_RDONLY;
			if (desired_access == 0)
				desired_access = FILE_READ_DATA;
			break;
	}

#if defined(O_SYNC)
	if (GET_FILE_SYNC_OPENMODE(share_mode)) {
		flags2 |= O_SYNC;
	}
#endif /* O_SYNC */
  
	if (flags != O_RDONLY && file_existed && 
			(!CAN_WRITE(conn) || IS_DOS_READONLY(existing_dos_mode))) {
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

	if (desired_access && ((desired_access & ~(SYNCHRONIZE_ACCESS|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES))==0) &&
		((desired_access & (SYNCHRONIZE_ACCESS|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES)) != 0)) {
		/* Stat open that doesn't trigger oplock breaks or share mode checks... ! JRA. */
		deny_mode = DENY_NONE;
		if (file_existed) {
			oplock_request = 0;
			add_share_mode = False;
			flags2 &= ~O_CREAT;
		}
	}

	if (file_existed) {

		dev = psbuf->st_dev;
		inode = psbuf->st_ino;

		lock_share_entry(conn, dev, inode);

		num_share_modes = open_mode_check(conn, fname, dev, inode, 
						  desired_access,
						  share_mode,
						  &flags, &oplock_request, &all_current_opens_are_level_II);
		if(num_share_modes == -1) {

			/*
			 * This next line is a subtlety we need for MS-Access. If a file open will
			 * fail due to share permissions and also for security (access)
			 * reasons, we need to return the access failed error, not the
			 * share error. This means we must attempt to open the file anyway
			 * in order to get the UNIX access error - even if we're going to
			 * fail the open for share reasons. This is bad, as we're burning
			 * another fd if there are existing locks but there's nothing else
			 * we can do. We also ensure we're not going to create or tuncate
			 * the file as we only want an access decision at this stage. JRA.
			 */
			errno = 0;
			fsp_open = open_file(fsp,conn,fname,psbuf,
						flags|(flags2&~(O_TRUNC|O_CREAT)),mode,desired_access);

			DEBUG(4,("open_file_shared : share_mode deny - calling open_file with \
flags=0x%X flags2=0x%X mode=0%o returned %d\n",
				flags,(flags2&~(O_TRUNC|O_CREAT)),(int)mode,(int)fsp_open ));

			if (!fsp_open && errno) {
				unix_ERR_class = ERRDOS;
				unix_ERR_code = ERRnoaccess;
				unix_ERR_ntstatus = NT_STATUS_ACCESS_DENIED;
			}

			/* 
			 * If we're returning a share violation, ensure we cope with
			 * the braindead 1 second delay.
			 */

			if (!internal_only_open && NT_STATUS_EQUAL(unix_ERR_ntstatus,NT_STATUS_SHARING_VIOLATION)) {
				/* The fsp->open_time here represents the current time of day. */
				defer_open_sharing_error(conn, &fsp->open_time, fname, dev, inode);
			}

			unlock_share_entry(conn, dev, inode);
			if (fsp_open) {
				fd_close(conn, fsp);
				/*
				 * We have detected a sharing violation here
				 * so return the correct error code
				 */
				unix_ERR_class = ERRDOS;
				unix_ERR_code = ERRbadshare;
				unix_ERR_ntstatus = NT_STATUS_SHARING_VIOLATION;
			}
			file_free(fsp);
			return NULL;
		}

		/*
		 * We exit this block with the share entry *locked*.....
		 */
	}

	/*
	 * Ensure we pay attention to default ACLs on directories if required.
	 */

        if ((flags2 & O_CREAT) && lp_inherit_acls(SNUM(conn)) &&
			(def_acl = directory_has_default_acl(conn, parent_dirname(fname))))
                mode = 0777;

	DEBUG(4,("calling open_file with flags=0x%X flags2=0x%X mode=0%o\n",
			flags,flags2,(int)mode));

	/*
	 * open_file strips any O_TRUNC flags itself.
	 */

	fsp_open = open_file(fsp,conn,fname,psbuf,flags|flags2,mode,desired_access);

	if (!fsp_open && (flags == O_RDWR) && (errno != ENOENT) && fcbopen) {
		if((fsp_open = open_file(fsp,conn,fname,psbuf,O_RDONLY,mode,desired_access)) == True)
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

		/*
		 * Now the file exists and fsp is successfully opened,
		 * fsp->dev and fsp->inode are valid and should replace the
		 * dev=0,inode=0 from a non existent file. Spotted by
		 * Nadav Danieli <nadavd@exanet.com>. JRA.
		 */

		dev = fsp->dev;
		inode = fsp->inode;

		lock_share_entry_fsp(fsp);

		num_share_modes = open_mode_check(conn, fname, dev, inode, 
						  desired_access,
						  share_mode,
						  &flags, &oplock_request, &all_current_opens_are_level_II);

		if(num_share_modes == -1) {
			/* 
			 * If we're returning a share violation, ensure we cope with
			 * the braindead 1 second delay.
			 */

			if (!internal_only_open && NT_STATUS_EQUAL(unix_ERR_ntstatus,NT_STATUS_SHARING_VIOLATION)) {
				/* The fsp->open_time here represents the current time of day. */
				defer_open_sharing_error(conn, &fsp->open_time, fname, dev, inode);
			}

			unlock_share_entry_fsp(fsp);
			fd_close(conn,fsp);
			file_free(fsp);
			/*
			 * We have detected a sharing violation here, so
			 * return the correct code.
			 */
                        unix_ERR_class = ERRDOS;
                        unix_ERR_code = ERRbadshare;
                        unix_ERR_ntstatus = NT_STATUS_SHARING_VIOLATION;
			return NULL;
		}

		/*
		 * If there are any share modes set then the file *did*
		 * exist. Ensure we return the correct value for action.
		 */

		if (num_share_modes > 0)
			file_existed = True;

		/*
		 * We exit this block with the share entry *locked*.....
		 */
	}

	/* note that we ignore failure for the following. It is
           basically a hack for NFS, and NFS will never set one of
           these only read them. Nobody but Samba can ever set a deny
           mode and we have already checked our more authoritative
           locking database for permission to set this deny mode. If
           the kernel refuses the operations then the kernel is wrong */
	kernel_flock(fsp, deny_mode);

	/*
	 * At this point onwards, we can guarentee that the share entry
	 * is locked, whether we created the file or not, and that the
	 * deny mode is compatible with all current opens.
	 */

	/*
	 * If requested, truncate the file.
	 */

	if (flags2&O_TRUNC) {
		/*
		 * We are modifing the file after open - update the stat struct..
		 */
		if ((SMB_VFS_FTRUNCATE(fsp,fsp->fd,0) == -1) || (SMB_VFS_FSTAT(fsp,fsp->fd,psbuf)==-1)) {
			unlock_share_entry_fsp(fsp);
			fd_close(conn,fsp);
			file_free(fsp);
			return NULL;
		}
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

	DEBUG(10,("open_file_shared : share_mode = %x\n", fsp->share_mode ));

	if (Access) {
		(*Access) = open_mode;
	}

	if (file_existed && !(flags2 & O_TRUNC))
		action = FILE_WAS_OPENED;
	if (file_existed && (flags2 & O_TRUNC))
		action = FILE_WAS_OVERWRITTEN;
	if (!file_existed) 
		action = FILE_WAS_CREATED;

	if (paction) {
		*paction = action;
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

	if (add_share_mode) {
		set_share_mode(fsp, port, oplock_request);
	}

	if (delete_on_close) {
		uint32 dosmode = existing_dos_mode;
		NTSTATUS result;

		if (action == FILE_WAS_OVERWRITTEN || action == FILE_WAS_CREATED) {
			dosmode = new_dos_mode;
		}
		result = set_delete_on_close_internal(fsp, delete_on_close, dosmode);

		if (NT_STATUS_V(result) !=  NT_STATUS_V(NT_STATUS_OK)) {
			uint8 u_e_c;
			uint32 u_e_code;
			/* Remember to delete the mode we just added. */
			if (add_share_mode) {
				del_share_mode(fsp, NULL);
			}
			unlock_share_entry_fsp(fsp);
			fd_close(conn,fsp);
			file_free(fsp);
			ntstatus_to_dos(result, &u_e_c, &u_e_code);
                        unix_ERR_ntstatus = result;
                        unix_ERR_class = u_e_c;
                        unix_ERR_code = u_e_code;
			return NULL;
		}
	}
	
	if (action == FILE_WAS_OVERWRITTEN || action == FILE_WAS_CREATED) {
		/* Files should be initially set as archive */
		if (lp_map_archive(SNUM(conn)) || lp_store_dos_attributes(SNUM(conn))) {
			file_set_dosmode(conn, fname, new_dos_mode | aARCH, NULL);
		}
	}

	/*
	 * Take care of inherited ACLs on created files - if default ACL not
	 * selected.
	 */

	if (!file_existed && !def_acl) {

		int saved_errno = errno; /* We might get ENOSYS in the next call.. */

		if (SMB_VFS_FCHMOD_ACL(fsp, fsp->fd, mode) == -1 && errno == ENOSYS)
			errno = saved_errno; /* Ignore ENOSYS */

	} else if (new_mode) {

		int ret = -1;

		/* Attributes need changing. File already existed. */

		{
			int saved_errno = errno; /* We might get ENOSYS in the next call.. */
			ret = SMB_VFS_FCHMOD_ACL(fsp, fsp->fd, new_mode);

			if (ret == -1 && errno == ENOSYS) {
				errno = saved_errno; /* Ignore ENOSYS */
			} else {
				DEBUG(5, ("open_file_shared: failed to reset attributes of file %s to 0%o\n",
					fname, (int)new_mode));
				ret = 0; /* Don't do the fchmod below. */
			}
		}

		if ((ret == -1) && (SMB_VFS_FCHMOD(fsp, fsp->fd, new_mode) == -1))
			DEBUG(5, ("open_file_shared: failed to reset attributes of file %s to 0%o\n",
				fname, (int)new_mode));
	}

	/* If this is a successful open, we must remove any deferred open records. */
	delete_defered_open_entry_record(conn, fsp->dev, fsp->inode);
	unlock_share_entry_fsp(fsp);

	conn->num_files_open++;

	return fsp;
}

/****************************************************************************
 Open a file for for write to ensure that we can fchmod it.
****************************************************************************/

files_struct *open_file_fchmod(connection_struct *conn, const char *fname, SMB_STRUCT_STAT *psbuf)
{
	files_struct *fsp = NULL;
	BOOL fsp_open;

	if (!VALID_STAT(*psbuf))
		return NULL;

	fsp = file_new(conn);
	if(!fsp)
		return NULL;

	/* note! we must use a non-zero desired access or we don't get
           a real file descriptor. Oh what a twisted web we weave. */
	fsp_open = open_file(fsp,conn,fname,psbuf,O_WRONLY,0,FILE_WRITE_DATA);

	/* 
	 * This is not a user visible file open.
	 * Don't set a share mode and don't increment
	 * the conn->num_files_open.
	 */

	if (!fsp_open) {
		file_free(fsp);
		return NULL;
	}

	return fsp;
}

/****************************************************************************
 Close the fchmod file fd - ensure no locks are lost.
****************************************************************************/

int close_file_fchmod(files_struct *fsp)
{
	int ret = fd_close(fsp->conn, fsp);
	file_free(fsp);
	return ret;
}

/****************************************************************************
 Open a directory from an NT SMB call.
****************************************************************************/

files_struct *open_directory(connection_struct *conn, char *fname, SMB_STRUCT_STAT *psbuf,
			uint32 desired_access, int share_mode, int smb_ofun, int *action)
{
	extern struct current_user current_user;
	BOOL got_stat = False;
	files_struct *fsp = file_new(conn);
	BOOL delete_on_close = GET_DELETE_ON_CLOSE_FLAG(share_mode);

	if(!fsp)
		return NULL;

	if (VALID_STAT(*psbuf))
		got_stat = True;

	if (got_stat && (GET_FILE_OPEN_DISPOSITION(smb_ofun) == FILE_EXISTS_FAIL)) {
		file_free(fsp);
		errno = EEXIST; /* Setup so correct error is returned to client. */
		return NULL;
	}

	if (GET_FILE_CREATE_DISPOSITION(smb_ofun) == FILE_CREATE_IF_NOT_EXIST) {

		if (got_stat) {

			if(!S_ISDIR(psbuf->st_mode)) {
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

			if (ms_has_wild(fname))  {
				file_free(fsp);
				DEBUG(5,("open_directory: failing create on filename %s with wildcards\n", fname));
				unix_ERR_class = ERRDOS;
				unix_ERR_code = ERRinvalidname;
				unix_ERR_ntstatus = NT_STATUS_OBJECT_NAME_INVALID;
				return NULL;
			}

			if( strchr_m(fname, ':')) {
				file_free(fsp);
				DEBUG(5,("open_directory: failing create on filename %s with colon in name\n", fname));
				unix_ERR_class = ERRDOS;
				unix_ERR_code = ERRinvalidname;
				unix_ERR_ntstatus = NT_STATUS_NOT_A_DIRECTORY;
				return NULL;
			}

			if(vfs_MkDir(conn,fname, unix_mode(conn,aDIR, fname)) < 0) {
				DEBUG(2,("open_directory: unable to create %s. Error was %s\n",
					 fname, strerror(errno) ));
				file_free(fsp);
				return NULL;
			}

			if(SMB_VFS_STAT(conn,fname, psbuf) != 0) {
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
			DEBUG(3,("open_directory: unable to stat name = %s. Error was %s\n",
				 fname, strerror(errno) ));
			file_free(fsp);
			return NULL;
		}

		if(!S_ISDIR(psbuf->st_mode)) {
			DEBUG(0,("open_directory: %s is not a directory !\n", fname ));
			file_free(fsp);
			return NULL;
		}

		*action = FILE_WAS_OPENED;
	}
	
	DEBUG(5,("open_directory: opening directory %s\n", fname));

	/*
	 * Setup the files_struct for it.
	 */
	
	fsp->mode = psbuf->st_mode;
	fsp->inode = psbuf->st_ino;
	fsp->dev = psbuf->st_dev;
	fsp->size = psbuf->st_size;
	fsp->vuid = current_user.vuid;
	fsp->file_pid = global_smbpid;
	fsp->can_lock = True;
	fsp->can_read = False;
	fsp->can_write = False;
	fsp->share_mode = share_mode;
	fsp->desired_access = desired_access;
	fsp->print_file = False;
	fsp->modified = False;
	fsp->oplock_type = NO_OPLOCK;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->is_directory = True;
	fsp->is_stat = False;
	fsp->directory_delete_on_close = False;
	string_set(&fsp->fsp_name,fname);

	if (delete_on_close) {
		NTSTATUS result = set_delete_on_close_internal(fsp, delete_on_close, 0);

		if (NT_STATUS_V(result) !=  NT_STATUS_V(NT_STATUS_OK)) {
			file_free(fsp);
			return NULL;
		}
	}
	conn->num_files_open++;

	return fsp;
}

/****************************************************************************
 Open a pseudo-file (no locking checks - a 'stat' open).
****************************************************************************/

files_struct *open_file_stat(connection_struct *conn, char *fname, SMB_STRUCT_STAT *psbuf)
{
	extern struct current_user current_user;
	files_struct *fsp = NULL;

	if (!VALID_STAT(*psbuf))
		return NULL;

	/* Can't 'stat' open directories. */
	if(S_ISDIR(psbuf->st_mode))
		return NULL;

	fsp = file_new(conn);
	if(!fsp)
		return NULL;

	DEBUG(5,("open_file_stat: 'opening' file %s\n", fname));

	/*
	 * Setup the files_struct for it.
	 */
	
	fsp->mode = psbuf->st_mode;
	fsp->inode = psbuf->st_ino;
	fsp->dev = psbuf->st_dev;
	fsp->size = psbuf->st_size;
	fsp->vuid = current_user.vuid;
	fsp->file_pid = global_smbpid;
	fsp->can_lock = False;
	fsp->can_read = False;
	fsp->can_write = False;
	fsp->share_mode = 0;
	fsp->desired_access = 0;
	fsp->print_file = False;
	fsp->modified = False;
	fsp->oplock_type = NO_OPLOCK;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->is_directory = False;
	fsp->is_stat = True;
	fsp->directory_delete_on_close = False;
	string_set(&fsp->fsp_name,fname);

	conn->num_files_open++;

	return fsp;
}
