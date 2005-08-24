/* 
   Unix SMB/CIFS implementation.
   file opening and share modes
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2004
   Copyright (C) Volker Lendecke 2005
   
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

extern struct current_user current_user;
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

static int fd_open(struct connection_struct *conn,
			const char *fname, 
			int flags,
			mode_t mode)
{
	int fd;
#ifdef O_NOFOLLOW
	if (!lp_symlinks(SNUM(conn))) {
		flags |= O_NOFOLLOW;
	}
#endif

	fd = SMB_VFS_OPEN(conn,fname,flags,mode);

	DEBUG(10,("fd_open: name %s, flags = 0%o mode = 0%o, fd = %d. %s\n", fname,
		flags, (int)mode, fd, (fd == -1) ? strerror(errno) : "" ));

	return fd;
}

/****************************************************************************
 Close the file associated with a fsp.
****************************************************************************/

int fd_close(struct connection_struct *conn,
		files_struct *fsp)
{
	if (fsp->fh->fd == -1) {
		return 0; /* What we used to call a stat open. */
	}
	if (fsp->fh->ref_count > 1) {
		return 0; /* Shared handle. Only close last reference. */
	}
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
		set_saved_error_triple(ERRSRV, ERRaccess, NT_STATUS_ACCESS_DENIED);
	}
}

/****************************************************************************
 Change the ownership of a file to that of the parent directory.
 Do this by fd if possible.
****************************************************************************/

void change_owner_to_parent(connection_struct *conn,
				files_struct *fsp,
				const char *fname,
				SMB_STRUCT_STAT *psbuf)
{
	const char *parent_path = parent_dirname(fname);
	SMB_STRUCT_STAT parent_st;
	int ret;

	ret = SMB_VFS_STAT(conn, parent_path, &parent_st);
	if (ret == -1) {
		DEBUG(0,("change_owner_to_parent: failed to stat parent "
			 "directory %s. Error was %s\n",
			 parent_path, strerror(errno) ));
		return;
	}

	if (fsp && fsp->fh->fd != -1) {
		become_root();
		ret = SMB_VFS_FCHOWN(fsp, fsp->fh->fd, parent_st.st_uid, (gid_t)-1);
		unbecome_root();
		if (ret == -1) {
			DEBUG(0,("change_owner_to_parent: failed to fchown "
				 "file %s to parent directory uid %u. Error "
				 "was %s\n", fname,
				 (unsigned int)parent_st.st_uid,
				 strerror(errno) ));
		}

		DEBUG(10,("change_owner_to_parent: changed new file %s to "
			  "parent directory uid %u.\n",	fname,
			  (unsigned int)parent_st.st_uid ));

	} else {
		/* We've already done an lstat into psbuf, and we know it's a
		   directory. If we can cd into the directory and the dev/ino
		   are the same then we can safely chown without races as
		   we're locking the directory in place by being in it.  This
		   should work on any UNIX (thanks tridge :-). JRA.
		*/

		pstring saved_dir;
		SMB_STRUCT_STAT sbuf;

		if (!vfs_GetWd(conn,saved_dir)) {
			DEBUG(0,("change_owner_to_parent: failed to get "
				 "current working directory\n"));
			return;
		}

		/* Chdir into the new path. */
		if (vfs_ChDir(conn, fname) == -1) {
			DEBUG(0,("change_owner_to_parent: failed to change "
				 "current working directory to %s. Error "
				 "was %s\n", fname, strerror(errno) ));
			goto out;
		}

		if (SMB_VFS_STAT(conn,".",&sbuf) == -1) {
			DEBUG(0,("change_owner_to_parent: failed to stat "
				 "directory '.' (%s) Error was %s\n",
				 fname, strerror(errno)));
			goto out;
		}

		/* Ensure we're pointing at the same place. */
		if (sbuf.st_dev != psbuf->st_dev ||
		    sbuf.st_ino != psbuf->st_ino ||
		    sbuf.st_mode != psbuf->st_mode ) {
			DEBUG(0,("change_owner_to_parent: "
				 "device/inode/mode on directory %s changed. "
				 "Refusing to chown !\n", fname ));
			goto out;
		}

		become_root();
		ret = SMB_VFS_CHOWN(conn, ".", parent_st.st_uid, (gid_t)-1);
		unbecome_root();
		if (ret == -1) {
			DEBUG(10,("change_owner_to_parent: failed to chown "
				  "directory %s to parent directory uid %u. "
				  "Error was %s\n", fname,
				  (unsigned int)parent_st.st_uid, strerror(errno) ));
			goto out;
		}

		DEBUG(10,("change_owner_to_parent: changed ownership of new "
			  "directory %s to parent directory uid %u.\n",
			  fname, (unsigned int)parent_st.st_uid ));

  out:

		vfs_ChDir(conn,saved_dir);
	}
}

/****************************************************************************
 Open a file.
****************************************************************************/

static BOOL open_file(files_struct *fsp,
			connection_struct *conn,
			const char *fname,
			SMB_STRUCT_STAT *psbuf,
			int flags,
			mode_t unx_mode,
			uint32 access_mask)
{
	int accmode = (flags & O_ACCMODE);
	int local_flags = flags;
	BOOL file_existed = VALID_STAT(*psbuf);

	fsp->fh->fd = -1;
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
			/* We don't want to write - but we must make sure that
			   O_CREAT doesn't create the file if we have write
			   access into the directory.
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
		DEBUG(10,("open_file: truncate requested on read-only open "
			  "for file %s\n",fname ));
		local_flags = (flags & ~O_ACCMODE)|O_RDWR;
	}

	if ((access_mask & (FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_EXECUTE)) ||
	    (local_flags & O_CREAT) ||
	    ((local_flags & O_TRUNC) == O_TRUNC) ) {

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

		if (file_existed && S_ISFIFO(psbuf->st_mode)) {
			local_flags |= O_NONBLOCK;
		}
#endif

		/* Don't create files with Microsoft wildcard characters. */
		if ((local_flags & O_CREAT) && !file_existed &&
		    ms_has_wild(fname))  {
			set_saved_error_triple(ERRDOS, ERRinvalidname,
					       NT_STATUS_OBJECT_NAME_INVALID);
			return False;
		}

		/* Actually do the open */
		fsp->fh->fd = fd_open(conn, fname, local_flags, unx_mode);
		if (fsp->fh->fd == -1)  {
			DEBUG(3,("Error opening file %s (%s) (local_flags=%d) "
				 "(flags=%d)\n",
				 fname,strerror(errno),local_flags,flags));
			check_for_pipe(fname);
			return False;
		}

		/* Inherit the ACL if the file was created. */
		if ((local_flags & O_CREAT) && !file_existed) {
			inherit_access_acl(conn, fname, unx_mode);
		}

	} else {
		fsp->fh->fd = -1; /* What we used to call a stat open. */
	}

	if (!file_existed) {
		int ret;

		if (fsp->fh->fd == -1) {
			ret = SMB_VFS_STAT(conn, fname, psbuf);
		} else {
			ret = SMB_VFS_FSTAT(fsp,fsp->fh->fd,psbuf);
			/* If we have an fd, this stat should succeed. */
			if (ret == -1) {
				DEBUG(0,("Error doing fstat on open file %s "
					 "(%s)\n", fname,strerror(errno) ));
			}
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
	fsp->can_lock = True;
	fsp->can_read = (access_mask & (FILE_READ_DATA)) ? True : False;
	if (!CAN_WRITE(conn)) {
		fsp->can_write = False;
	} else {
		fsp->can_write = (access_mask & (FILE_WRITE_DATA | FILE_APPEND_DATA)) ? True : False;
	}
	fsp->print_file = False;
	fsp->modified = False;
	fsp->oplock_type = NO_OPLOCK;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->is_directory = False;
	fsp->is_stat = False;
	if (conn->aio_write_behind_list &&
	    is_in_path(fname, conn->aio_write_behind_list, conn->case_sensitive)) {
		fsp->aio_write_behind = True;
	}

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

/****************************************************************************
 Check if we can open a file with a share mode.
 Returns True if conflict, False if not.
****************************************************************************/

static BOOL share_conflict(share_mode_entry *entry,
			   uint32 access_mask,
			   uint32 share_access)
{
	DEBUG(10,("share_conflict: entry->access_mask = 0x%x, "
		  "entry->share_access = 0x%x, "
		  "entry->private_options = 0x%x\n",
		  (unsigned int)entry->access_mask,
		  (unsigned int)entry->share_access,
		  (unsigned int)entry->private_options));

	DEBUG(10,("share_conflict: access_mask = 0x%x, share_access = 0x%x\n",
		  (unsigned int)access_mask, (unsigned int)share_access));

	if ((entry->access_mask & (FILE_WRITE_DATA|
				   FILE_APPEND_DATA|
				   FILE_READ_DATA|
				   FILE_EXECUTE|
				   DELETE_ACCESS)) == 0) {
		DEBUG(10,("share_conflict: No conflict due to "
			  "entry->access_mask = 0x%x\n",
			  (unsigned int)entry->access_mask ));
		return False;
	}

	if ((access_mask & (FILE_WRITE_DATA|
			    FILE_APPEND_DATA|
			    FILE_READ_DATA|
			    FILE_EXECUTE|
			    DELETE_ACCESS)) == 0) {
		DEBUG(10,("share_conflict: No conflict due to "
			  "access_mask = 0x%x\n",
			  (unsigned int)access_mask ));
		return False;
	}

#if 1 /* JRA TEST - Superdebug. */
#define CHECK_MASK(num, am, right, sa, share) \
	DEBUG(10,("share_conflict: [%d] am (0x%x) & right (0x%x) = 0x%x\n", \
		(unsigned int)(num), (unsigned int)(am), \
		(unsigned int)(right), (unsigned int)(am)&(right) )); \
	DEBUG(10,("share_conflict: [%d] sa (0x%x) & share (0x%x) = 0x%x\n", \
		(unsigned int)(num), (unsigned int)(sa), \
		(unsigned int)(share), (unsigned int)(sa)&(share) )); \
	if (((am) & (right)) && !((sa) & (share))) { \
		DEBUG(10,("share_conflict: check %d conflict am = 0x%x, right = 0x%x, \
sa = 0x%x, share = 0x%x\n", (num), (unsigned int)(am), (unsigned int)(right), (unsigned int)(sa), \
			(unsigned int)(share) )); \
		set_saved_error_triple(ERRDOS, ERRbadshare, NT_STATUS_SHARING_VIOLATION); \
		return True; \
	}
#else
#define CHECK_MASK(num, am, right, sa, share) \
	if (((am) & (right)) && !((sa) & (share))) { \
		DEBUG(10,("share_conflict: check %d conflict am = 0x%x, right = 0x%x, \
sa = 0x%x, share = 0x%x\n", (num), (unsigned int)(am), (unsigned int)(right), (unsigned int)(sa), \
			(unsigned int)(share) )); \
		set_saved_error_triple(ERRDOS, ERRbadshare, NT_STATUS_SHARING_VIOLATION); \
		return True; \
	}
#endif

	CHECK_MASK(1, entry->access_mask, FILE_WRITE_DATA | FILE_APPEND_DATA,
		   share_access, FILE_SHARE_WRITE);
	CHECK_MASK(2, access_mask, FILE_WRITE_DATA | FILE_APPEND_DATA,
		   entry->share_access, FILE_SHARE_WRITE);
	
	CHECK_MASK(3, entry->access_mask, FILE_READ_DATA | FILE_EXECUTE,
		   share_access, FILE_SHARE_READ);
	CHECK_MASK(4, access_mask, FILE_READ_DATA | FILE_EXECUTE,
		   entry->share_access, FILE_SHARE_READ);

	CHECK_MASK(5, entry->access_mask, DELETE_ACCESS,
		   share_access, FILE_SHARE_DELETE);
	CHECK_MASK(6, access_mask, DELETE_ACCESS,
		   entry->share_access, FILE_SHARE_DELETE);

	DEBUG(10,("share_conflict: No conflict.\n"));
	return False;
}

#if defined(DEVELOPER)
static void validate_my_share_entries(int num,
					share_mode_entry *share_entry)
{
	files_struct *fsp;

	if (share_entry->pid != sys_getpid()) {
		return;
	}

	fsp = file_find_dif(share_entry->dev, share_entry->inode,
			    share_entry->share_file_id);
	if (!fsp) {
		DEBUG(0,("validate_my_share_entries: PANIC : %s\n",
			 share_mode_str(num, share_entry) ));
		smb_panic("validate_my_share_entries: Cannot match a "
			  "share entry with an open file\n");
	}

	if (((uint16)fsp->oplock_type) != share_entry->op_type) {
		pstring str;
		DEBUG(0,("validate_my_share_entries: PANIC : %s\n",
			 share_mode_str(num, share_entry) ));
		slprintf(str, sizeof(str)-1, "validate_my_share_entries: "
			 "file %s, oplock_type = 0x%x, op_type = 0x%x\n",
			 fsp->fsp_name, (unsigned int)fsp->oplock_type,
			 (unsigned int)share_entry->op_type );
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

static BOOL cause_oplock_break(int request, int existing, uint32 access_mask)
{
	if ((access_mask == DELETE_ACCESS) &&
	    (request == NO_OPLOCK)) {
		/* This is a delete request */
		return (BATCH_OPLOCK_TYPE(existing) != 0);
	}

	if (EXCLUSIVE_OPLOCK_TYPE(existing) && (request != NO_OPLOCK)) {
		return True;
	}

	if ((existing != NO_OPLOCK) && (request == NO_OPLOCK)) {
		return True;
	}

	return False;
}

/****************************************************************************
 Deal with open deny mode and oplock break processing.
 Invarient: Share mode must be locked on entry and exit.
 Returns -1 on error, or number of share modes on success (may be zero).
****************************************************************************/

static int open_mode_check(connection_struct *conn,
			   const char *fname,
			   SMB_DEV_T dev,
			   SMB_INO_T inode, 
			   uint32 access_mask,
			   uint32 share_access,
			   uint32 create_options,
			   int *p_oplock_request,
			   BOOL *p_all_current_opens_are_level_II)
{
	int i;
	int num_share_modes;
	int oplock_contention_count = 0;
	share_mode_entry *old_shares = NULL;
	BOOL broke_oplock;
	BOOL delete_on_close;

	num_share_modes = get_share_modes(dev, inode, &old_shares, &delete_on_close);
	
	if(num_share_modes == 0) {
		SAFE_FREE(old_shares);
		return 0;
	}
	
	if (access_mask &&
	    ((access_mask & ~(SYNCHRONIZE_ACCESS| FILE_READ_ATTRIBUTES|
			      FILE_WRITE_ATTRIBUTES))==0) &&
	    ((access_mask & (SYNCHRONIZE_ACCESS|FILE_READ_ATTRIBUTES|
			     FILE_WRITE_ATTRIBUTES)) != 0)) {
		/* Stat open that doesn't trigger oplock breaks or share mode
		 * checks... ! JRA. */
		SAFE_FREE(old_shares);
		return num_share_modes;
	}

	/* A delete on close prohibits everything */

	if (delete_on_close) {
		SAFE_FREE(old_shares);
		errno = EACCES;
		return -1;
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
			share_mode_entry *share_entry = &old_shares[i];
			BOOL opb_ret;
			
#if defined(DEVELOPER)
			validate_my_share_entries(i, share_entry);
#endif

			/* 
			 * By observation of NetBench, oplocks are broken
			 * *before* share modes are checked. This allows a
			 * file to be closed by the client if the share mode
			 * would deny access and the client has an oplock.
			 * Check if someone has an oplock on this file. If so
			 * we must break it before continuing.
			 */

			if (!cause_oplock_break(*p_oplock_request,
						share_entry->op_type,
						access_mask)) {
				if (!LEVEL_II_OPLOCK_TYPE(share_entry->op_type)) {
					*p_all_current_opens_are_level_II = False;
				}
				continue;
			}

			/* This is an oplock break */

			DEBUG(5,("open_mode_check: oplock_request = %d, "
				 "breaking oplock (%x) on file %s, "
				 "dev = %x, inode = %.0f\n",
				 *p_oplock_request, share_entry->op_type,
				 fname, (unsigned int)dev, (double)inode));
				
			/* Ensure the reply for the open uses the correct
			 * sequence number. */
			/* This isn't a real deferred packet as it's response
			 * will also increment the sequence.
			 */
			srv_defer_sign_response(get_current_mid());

			/* Oplock break - unlock to request it. */
			unlock_share_entry(conn, dev, inode);
				
			opb_ret = request_oplock_break(share_entry);
				
			/* Now relock. */
			lock_share_entry(conn, dev, inode);
				
			if (!opb_ret) {
				DEBUG(0,("open_mode_check: FAILED when breaking "
					 "oplock (%x) on file %s, dev = %x, "
					 "inode = %.0f\n",
					 old_shares[i].op_type, fname,
					 (unsigned int)dev, (double)inode));
				SAFE_FREE(old_shares);
				set_saved_error_triple(ERRDOS, ERRbadshare,
						       NT_STATUS_SHARING_VIOLATION);
				return -1;
			}
				
			broken_entry = SMB_MALLOC_P(struct share_mode_entry_list);
			if (!broken_entry) {
				smb_panic("open_mode_check: malloc fail.\n");
			}
			broken_entry->entry = *share_entry;
			DLIST_ADD(broken_entry_list, broken_entry);
			broke_oplock = True;
				
		} /* end for */
		
		if (broke_oplock) {
			/* Update the current open table. */
			SAFE_FREE(old_shares);
			num_share_modes = get_share_modes(dev, inode,
							  &old_shares,
							  &delete_on_close);
		}

		if (lp_share_modes(SNUM(conn))) {
			/* Now we check the share modes, after any oplock breaks. */
			for(i = 0; i < num_share_modes; i++) {
				share_mode_entry *share_entry = &old_shares[i];

				/* someone else has a share lock on it, check to see
				 * if we can too */
				if (share_conflict(share_entry, access_mask,
						   share_access)) {
					SAFE_FREE(old_shares);
					free_broken_entry_list(broken_entry_list);
					errno = EACCES;
					return -1;
				}
			}
		}

		for(broken_entry = broken_entry_list; broken_entry;
		    broken_entry = broken_entry->next) {
			oplock_contention_count++;
			
			/* Paranoia check that this is no longer an exlusive entry. */
			for(i = 0; i < num_share_modes; i++) {
				share_mode_entry *share_entry = &old_shares[i];
				
				if (!(share_modes_identical(&broken_entry->entry,
							    share_entry) && 
				      EXCLUSIVE_OPLOCK_TYPE(share_entry->op_type))) {
					continue;
				}
					
				/*
				 * This should not happen. The target left this oplock
				 * as exlusive.... The process *must* be dead.... 
				 */
					
				DEBUG(0,("open_mode_check: exlusive oplock left by "
					 "process %d after break ! For file %s, "
					 "dev = %x, inode = %.0f. Deleting it to "
					 "continue...\n",
					 (int)broken_entry->entry.pid, fname,
					 (unsigned int)dev, (double)inode));
					
				if (process_exists(broken_entry->entry.pid)) {
					DEBUG(0,("open_mode_check: Existent process "
						 "%lu left active oplock.\n",
						 (unsigned long)broken_entry->entry.pid ));
				}
					
				if (del_share_entry(dev, inode, &broken_entry->entry,
						    NULL, &delete_on_close) == -1) {
					free_broken_entry_list(broken_entry_list);
					errno = EACCES;
					set_saved_error_triple(ERRDOS, ERRbadshare,
							       NT_STATUS_SHARING_VIOLATION);
					return -1;
				}
					
				/*
				 * We must reload the share modes after deleting the 
				 * other process's entry.
				 */
					
				SAFE_FREE(old_shares);
				num_share_modes = get_share_modes(dev, inode,
								  &old_shares,
								  &delete_on_close);
				break;
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

static void delete_defered_open_entry_record(connection_struct *conn,
						SMB_DEV_T dev,
						SMB_INO_T inode)
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

static void defer_open_sharing_error(connection_struct *conn,
				     struct timeval *ptv,
				     const char *fname,
				     SMB_DEV_T dev,
				     SMB_INO_T inode)
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
			if (usec_time_diff(ptv, &entry->time) >
			    SHARING_VIOLATION_USEC_WAIT) {
				DEBUG(10,("defer_open_sharing_error: Deleting "
					  "deferred open entry for mid %u, "
					  "file %s\n",
					  (unsigned int)mid, fname ));

				/* Expired, return a real error. */
				/* Remove the deferred open entry from the array. */

				delete_deferred_open_entry(entry);
				SAFE_FREE(de_array);
				return;
			}
			/*
			 * If the timeout hasn't expired yet and we still have
			 * a sharing violation, just leave the entry in the
			 * deferred open array alone. We do need to reschedule
			 * this open call though (with the original created
			 * time).
			 */
			DEBUG(10,("defer_open_sharing_error: time [%u.%06u] "
				  "updating deferred open entry for mid %u, file %s\n",
				  (unsigned int)entry->time.tv_sec,
				  (unsigned int)entry->time.tv_usec,
				  (unsigned int)mid, fname ));

			push_sharing_violation_open_smb_message(&entry->time,
								(char *)&dib,
								sizeof(dib));
			SAFE_FREE(de_array);
			return;
		}
	}

	DEBUG(10,("defer_open_sharing_error: time [%u.%06u] adding deferred "
		  "open entry for mid %u, file %s\n",
		  (unsigned int)ptv->tv_sec, (unsigned int)ptv->tv_usec,
		  (unsigned int)mid, fname ));

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

static void kernel_flock(files_struct *fsp, uint32 share_mode)
{
#if HAVE_KERNEL_SHARE_MODES
	int kernel_mode = 0;
	if (share_mode == FILE_SHARE_WRITE) {
		kernel_mode = LOCK_MAND|LOCK_WRITE;
	} else if (share_mode == FILE_SHARE_READ) {
		kernel_mode = LOCK_MAND|LOCK_READ;
	} else if (share_mode == FILE_SHARE_NONE) {
		kernel_mode = LOCK_MAND;
	}
	if (kernel_mode) {
		flock(fsp->fh->fd, kernel_mode);
	}
#endif
	;
}

/****************************************************************************
 On overwrite open ensure that the attributes match.
****************************************************************************/

static BOOL open_match_attributes(connection_struct *conn,
				const char *path,
				uint32 old_dos_attr,
				uint32 new_dos_attr,
				mode_t existing_unx_mode,
				mode_t new_unx_mode,
				mode_t *returned_unx_mode)
{
	uint32 noarch_old_dos_attr, noarch_new_dos_attr;

	noarch_old_dos_attr = (old_dos_attr & ~FILE_ATTRIBUTE_ARCHIVE);
	noarch_new_dos_attr = (new_dos_attr & ~FILE_ATTRIBUTE_ARCHIVE);

	if((noarch_old_dos_attr == 0 && noarch_new_dos_attr != 0) || 
	   (noarch_old_dos_attr != 0 && ((noarch_old_dos_attr & noarch_new_dos_attr) == noarch_old_dos_attr))) {
		*returned_unx_mode = new_unx_mode;
	} else {
		*returned_unx_mode = (mode_t)0;
	}

	DEBUG(10,("open_match_attributes: file %s old_dos_attr = 0x%x, "
		  "existing_unx_mode = 0%o, new_dos_attr = 0x%x "
		  "returned_unx_mode = 0%o\n",
		  path,
		  (unsigned int)old_dos_attr,
		  (unsigned int)existing_unx_mode,
		  (unsigned int)new_dos_attr,
		  (unsigned int)*returned_unx_mode ));

	/* If we're mapping SYSTEM and HIDDEN ensure they match. */
	if (lp_map_system(SNUM(conn)) || lp_store_dos_attributes(SNUM(conn))) {
		if ((old_dos_attr & FILE_ATTRIBUTE_SYSTEM) &&
		    !(new_dos_attr & FILE_ATTRIBUTE_SYSTEM)) {
			return False;
		}
	}
	if (lp_map_hidden(SNUM(conn)) || lp_store_dos_attributes(SNUM(conn))) {
		if ((old_dos_attr & FILE_ATTRIBUTE_HIDDEN) &&
		    !(new_dos_attr & FILE_ATTRIBUTE_HIDDEN)) {
			return False;
		}
	}
	return True;
}

/****************************************************************************
 Special FCB or DOS processing in the case of a sharing violation.
 Try and find a duplicated file handle.
****************************************************************************/

static files_struct *fcb_or_dos_open(connection_struct *conn,
				     const char *fname, SMB_DEV_T dev,
				     SMB_INO_T inode,
				     uint32 access_mask,
				     uint32 share_access,
				     uint32 create_options)
{
	files_struct *fsp;
	files_struct *dup_fsp;

	DEBUG(5,("fcb_or_dos_open: attempting old open semantics for "
		 "file %s.\n", fname ));

	for(fsp = file_find_di_first(dev, inode); fsp;
	    fsp = file_find_di_next(fsp)) {

		DEBUG(10,("fcb_or_dos_open: checking file %s, fd = %d, "
			  "vuid = %u, file_pid = %u, private_options = 0x%x "
			  "access_mask = 0x%x\n", fsp->fsp_name,
			  fsp->fh->fd, (unsigned int)fsp->vuid,
			  (unsigned int)fsp->file_pid,
			  (unsigned int)fsp->fh->private_options,
			  (unsigned int)fsp->access_mask ));

		if (fsp->fh->fd != -1 &&
		    fsp->vuid == current_user.vuid &&
		    fsp->file_pid == global_smbpid &&
		    (fsp->fh->private_options & (NTCREATEX_OPTIONS_PRIVATE_DENY_DOS |
						 NTCREATEX_OPTIONS_PRIVATE_DENY_FCB)) &&
		    (fsp->access_mask & FILE_WRITE_DATA) &&
		    strequal(fsp->fsp_name, fname)) {
			DEBUG(10,("fcb_or_dos_open: file match\n"));
			break;
		}
	}

	if (!fsp) {
		return NULL;
	}

	/* quite an insane set of semantics ... */
	if (is_executable(fname) &&
	    (fsp->fh->private_options & NTCREATEX_OPTIONS_PRIVATE_DENY_DOS)) {
		DEBUG(10,("fcb_or_dos_open: file fail due to is_executable.\n"));
		return NULL;
	}

	/* We need to duplicate this fsp. */
	dup_fsp = dup_file_fsp(fsp, access_mask, share_access, create_options);
	if (!dup_fsp) {
		return NULL;
	}

	return dup_fsp;
}

/****************************************************************************
 Open a file with a share mode - old openX method - map into NTCreate.
****************************************************************************/

BOOL map_open_params_to_ntcreate(const char *fname, int deny_mode, int open_func,
				uint32 *paccess_mask,
				uint32 *pshare_mode,
				uint32 *pcreate_disposition,
				uint32 *pcreate_options)
{
	uint32 access_mask;
	uint32 share_mode;
	uint32 create_disposition;
	uint32 create_options = 0;

	DEBUG(10,("map_open_params_to_ntcreate: fname = %s, deny_mode = 0x%x, "
		  "open_func = 0x%x\n",
		  fname, (unsigned int)deny_mode, (unsigned int)open_func ));

	/* Create the NT compatible access_mask. */
	switch (GET_OPENX_MODE(deny_mode)) {
		case DOS_OPEN_RDONLY:
			access_mask = FILE_GENERIC_READ;
			break;
		case DOS_OPEN_WRONLY:
			access_mask = FILE_GENERIC_WRITE;
			break;
		case DOS_OPEN_EXEC: /* This used to be FILE_READ_DATA... */
		case DOS_OPEN_RDWR:
		case DOS_OPEN_FCB:
			access_mask = FILE_GENERIC_READ|FILE_GENERIC_WRITE;
			break;
		default:
			DEBUG(10,("map_open_params_to_ntcreate: bad open mode = 0x%x\n",
				  (unsigned int)GET_OPENX_MODE(deny_mode)));
			return False;
	}

	/* Create the NT compatible create_disposition. */
	switch (open_func) {
		case OPENX_FILE_EXISTS_FAIL|OPENX_FILE_CREATE_IF_NOT_EXIST:
			create_disposition = FILE_CREATE;
			break;

		case OPENX_FILE_EXISTS_OPEN:
			create_disposition = FILE_OPEN;
			break;

		case OPENX_FILE_EXISTS_OPEN|OPENX_FILE_CREATE_IF_NOT_EXIST:
			create_disposition = FILE_OPEN_IF;
			break;
       
		case OPENX_FILE_EXISTS_TRUNCATE:
			create_disposition = FILE_OVERWRITE;
			break;

		case OPENX_FILE_EXISTS_TRUNCATE|OPENX_FILE_CREATE_IF_NOT_EXIST:
			create_disposition = FILE_OVERWRITE_IF;
			break;

		default:
			/* From samba4 - to be confirmed. */
			if (GET_OPENX_MODE(deny_mode) == DOS_OPEN_EXEC) {
				create_disposition = FILE_CREATE;
				break;
			}
			DEBUG(10,("map_open_params_to_ntcreate: bad "
				  "open_func 0x%x\n", (unsigned int)open_func));
			return False;
	}
 
	/* Create the NT compatible share modes. */
	switch (GET_DENY_MODE(deny_mode)) {
		case DENY_ALL:
			share_mode = FILE_SHARE_NONE;
			break;

		case DENY_WRITE:
			share_mode = FILE_SHARE_READ;
			break;

		case DENY_READ:
			share_mode = FILE_SHARE_WRITE;
			break;

		case DENY_NONE:
			share_mode = FILE_SHARE_READ|FILE_SHARE_WRITE;
			break;

		case DENY_DOS:
			create_options |= NTCREATEX_OPTIONS_PRIVATE_DENY_DOS;
	                if (is_executable(fname)) {
				share_mode = FILE_SHARE_READ|FILE_SHARE_WRITE;
			} else {
				if (GET_OPENX_MODE(deny_mode) == DOS_OPEN_RDONLY) {
					share_mode = FILE_SHARE_READ;
				} else {
					share_mode = FILE_SHARE_NONE;
				}
			}
			break;

		case DENY_FCB:
			create_options |= NTCREATEX_OPTIONS_PRIVATE_DENY_FCB;
			share_mode = FILE_SHARE_NONE;
			break;

		default:
			DEBUG(10,("map_open_params_to_ntcreate: bad deny_mode 0x%x\n",
				(unsigned int)GET_DENY_MODE(deny_mode) ));
			return False;
	}

	DEBUG(10,("map_open_params_to_ntcreate: file %s, access_mask = 0x%x, "
		  "share_mode = 0x%x, create_disposition = 0x%x, "
		  "create_options = 0x%x\n",
		  fname,
		  (unsigned int)access_mask,
		  (unsigned int)share_mode,
		  (unsigned int)create_disposition,
		  (unsigned int)create_options ));

	if (paccess_mask) {
		*paccess_mask = access_mask;
	}
	if (pshare_mode) {
		*pshare_mode = share_mode;
	}
	if (pcreate_disposition) {
		*pcreate_disposition = create_disposition;
	}
	if (pcreate_options) {
		*pcreate_options = create_options;
	}

	return True;

}

/* Map generic permissions to file object specific permissions */
                                                                                                               
struct generic_mapping file_generic_mapping = {
	FILE_GENERIC_READ,
	FILE_GENERIC_WRITE,
	FILE_GENERIC_EXECUTE,
	FILE_GENERIC_ALL
};

/****************************************************************************
 Open a file with a share mode.
****************************************************************************/

files_struct *open_file_ntcreate(connection_struct *conn,
				 const char *fname,
				 SMB_STRUCT_STAT *psbuf,
				 uint32 access_mask,		/* access bits (FILE_READ_DATA etc.) */
				 uint32 share_access,		/* share constants (FILE_SHARE_READ etc). */
				 uint32 create_disposition,	/* FILE_OPEN_IF etc. */
				 uint32 create_options,		/* options such as delete on close. */
				 uint32 new_dos_attributes,	/* attributes used for new file. */
				 int oplock_request, 		/* internal Samba oplock codes. */
				 				/* Information (FILE_EXISTS etc.) */
				 int *pinfo)
{
	int flags=0;
	int flags2=0;
	BOOL file_existed = VALID_STAT(*psbuf);
	BOOL def_acl = False;
	BOOL internal_only_open = False;
	SMB_DEV_T dev = 0;
	SMB_INO_T inode = 0;
	int num_share_modes = 0;
	BOOL all_current_opens_are_level_II = False;
	BOOL fsp_open = False;
	files_struct *fsp = NULL;
	mode_t new_unx_mode = (mode_t)0;
	mode_t unx_mode = (mode_t)0;
	int info;
	uint32 existing_dos_attributes = 0;
	struct pending_message_list *pml = NULL;
	uint16 port = 0;
	uint16 mid = get_current_mid();

	if (conn->printer) {
		/* 
		 * Printers are handled completely differently.
		 * Most of the passed parameters are ignored.
		 */

		if (pinfo) {
			*pinfo = FILE_WAS_CREATED;
		}

		DEBUG(10, ("open_file_ntcreate: printer open fname=%s\n", fname));

		return print_fsp_open(conn, fname);
	}

	/* We add aARCH to this as this mode is only used if the file is
	 * created new. */
	unx_mode = unix_mode(conn, new_dos_attributes | aARCH,fname, True);

	DEBUG(10, ("open_file_ntcreate: fname=%s, dos_attrs=0x%x "
		   "access_mask=0x%x share_access=0x%x "
		   "create_disposition = 0x%x create_options=0x%x "
		   "unix mode=0%o oplock_request=%d\n",
		   fname, new_dos_attributes, access_mask, share_access,
		   create_disposition, create_options, unx_mode,
		   oplock_request));

	if (oplock_request == INTERNAL_OPEN_ONLY) {
		internal_only_open = True;
		oplock_request = 0;
	}

	if ((pml = get_open_deferred_message(mid)) != NULL) {
		struct dev_inode_bundle dib;

		memcpy(&dib, pml->private_data.data, sizeof(dib));

		/* There could be a race condition where the dev/inode pair
		   has changed since we deferred the message. If so, just
		   remove the deferred open entry and return sharing
		   violation. */

		/* If the timeout value is non-zero, we need to just return
		   sharing violation. Don't retry the open as we were not
		   notified of a close and we don't want to trigger another
		   spurious oplock break. */

		if (!file_existed || dib.dev != psbuf->st_dev ||
		    dib.inode != psbuf->st_ino || pml->msg_time.tv_sec ||
		    pml->msg_time.tv_usec) {
			/* Ensure we don't reprocess this message. */
			remove_sharing_violation_open_smb_message(mid);

			/* Now remove the deferred open entry under lock. */
			lock_share_entry(conn, dib.dev, dib.inode);
			delete_defered_open_entry_record(conn, dib.dev,
							 dib.inode);
			unlock_share_entry(conn, dib.dev, dib.inode);

			set_saved_error_triple(ERRDOS, ERRbadshare,
					       NT_STATUS_SHARING_VIOLATION);
			return NULL;
		}
		/* Ensure we don't reprocess this message. */
		remove_sharing_violation_open_smb_message(mid);
	}

	if (!check_name(fname,conn)) {
		return NULL;
	} 

	new_dos_attributes &= SAMBA_ATTRIBUTES_MASK;
	if (file_existed) {
		existing_dos_attributes = dos_mode(conn, fname, psbuf);
	}

	/* ignore any oplock requests if oplocks are disabled */
	if (!lp_oplocks(SNUM(conn)) || global_client_failed_oplock_break) {
		oplock_request = 0;
	}

	/* this is for OS/2 long file names - say we don't support them */
	if (!lp_posix_pathnames() && strstr(fname,".+,;=[].")) {
		/* OS/2 Workplace shell fix may be main code stream in a later
		 * release. */ 
		set_saved_error_triple(ERRDOS, ERRcannotopen,
				       NT_STATUS_OBJECT_NAME_NOT_FOUND);
		DEBUG(5,("open_file_ntcreate: OS/2 long filenames are not "
			 "supported.\n"));
		return NULL;
	}

	switch( create_disposition ) {
		/*
		 * Currently we're using FILE_SUPERSEDE as the same as
		 * FILE_OVERWRITE_IF but they really are
		 * different. FILE_SUPERSEDE deletes an existing file
		 * (requiring delete access) then recreates it.
		 */
		case FILE_SUPERSEDE:
			/* If file exists replace/overwrite. If file doesn't
			 * exist create. */
			flags2 |= (O_CREAT | O_TRUNC);
			break;

		case FILE_OVERWRITE_IF:
			/* If file exists replace/overwrite. If file doesn't
			 * exist create. */
			flags2 |= (O_CREAT | O_TRUNC);
			break;

		case FILE_OPEN:
			/* If file exists open. If file doesn't exist error. */
			if (!file_existed) {
				DEBUG(5,("open_file_ntcreate: FILE_OPEN "
					 "requested for file %s and file "
					 "doesn't exist.\n", fname ));
				set_saved_error_triple(ERRDOS, ERRbadfile, NT_STATUS_OBJECT_NAME_NOT_FOUND);
				errno = ENOENT;
				return NULL;
			}
			break;

		case FILE_OVERWRITE:
			/* If file exists overwrite. If file doesn't exist
			 * error. */
			if (!file_existed) {
				DEBUG(5,("open_file_ntcreate: FILE_OVERWRITE "
					 "requested for file %s and file "
					 "doesn't exist.\n", fname ));
				set_saved_error_triple(ERRDOS, ERRbadfile, NT_STATUS_OBJECT_NAME_NOT_FOUND);
				errno = ENOENT;
				return NULL;
			}
			flags2 |= O_TRUNC;
			break;

		case FILE_CREATE:
			/* If file exists error. If file doesn't exist
			 * create. */
			if (file_existed) {
				DEBUG(5,("open_file_ntcreate: FILE_CREATE "
					 "requested for file %s and file "
					 "already exists.\n", fname ));
				if (S_ISDIR(psbuf->st_mode)) {
					errno = EISDIR;
				} else {
					errno = EEXIST;
				}
				return NULL;
			}
			flags2 |= (O_CREAT|O_EXCL);
			break;

		case FILE_OPEN_IF:
			/* If file exists open. If file doesn't exist
			 * create. */
			flags2 |= O_CREAT;
			break;

		default:
			set_saved_error_triple(ERRDOS, ERRinvalidparam,
					       NT_STATUS_INVALID_PARAMETER);
			return NULL;
	}

	/* We only care about matching attributes on file exists and
	 * overwrite. */

	if (file_existed && ((create_disposition == FILE_OVERWRITE) ||
			     (create_disposition == FILE_OVERWRITE_IF))) {
		if (!open_match_attributes(conn, fname,
					   existing_dos_attributes,
					   new_dos_attributes, psbuf->st_mode,
					   unx_mode, &new_unx_mode)) {
			DEBUG(5,("open_file_ntcreate: attributes missmatch "
				 "for file %s (%x %x) (0%o, 0%o)\n",
				 fname, existing_dos_attributes,
				 new_dos_attributes,
				 (unsigned int)psbuf->st_mode,
				 (unsigned int)unx_mode ));
			errno = EACCES;
			return NULL;
		}
	}

	/* This is a nasty hack - must fix... JRA. */
	if (access_mask == MAXIMUM_ALLOWED_ACCESS) {
		access_mask = FILE_GENERIC_ALL;
	}

	/*
	 * Convert GENERIC bits to specific bits.
	 */

	se_map_generic(&access_mask, &file_generic_mapping);

	DEBUG(10, ("open_file_ntcreate: fname=%s, after mapping "
		   "access_mask=0x%x\n", fname, access_mask ));

	/*
	 * Note that we ignore the append flag as append does not
	 * mean the same thing under DOS and Unix.
	 */

	if (access_mask & (FILE_WRITE_DATA | FILE_APPEND_DATA)) {
		flags = O_RDWR;
	} else {
		flags = O_RDONLY;
	}

	/*
	 * Currently we only look at FILE_WRITE_THROUGH for create options.
	 */

#if defined(O_SYNC)
	if (create_options & FILE_WRITE_THROUGH) {
		flags2 |= O_SYNC;
	}
#endif /* O_SYNC */
  
	if (!CAN_WRITE(conn)) {
		/*
		 * We should really return a permission denied error if either
		 * O_CREAT or O_TRUNC are set, but for compatibility with
		 * older versions of Samba we just AND them out.
		 */
		flags2 &= ~(O_CREAT|O_TRUNC);
	}

	/*
	 * Ensure we can't write on a read-only share or file.
	 */

	if (flags != O_RDONLY && file_existed &&
	    (!CAN_WRITE(conn) || IS_DOS_READONLY(existing_dos_attributes))) {
		DEBUG(5,("open_file_ntcreate: write access requested for "
			 "file %s on read only %s\n",
			 fname, !CAN_WRITE(conn) ? "share" : "file" ));
		set_saved_error_triple(ERRDOS, ERRnoaccess,
				       NT_STATUS_ACCESS_DENIED);
		errno = EACCES;
		return NULL;
	}

	fsp = file_new(conn);
	if(!fsp) {
		return NULL;
	}

	if (file_existed) {

		dev = psbuf->st_dev;
		inode = psbuf->st_ino;

		lock_share_entry(conn, dev, inode);

		num_share_modes = open_mode_check(conn, fname, dev, inode,
						  access_mask, share_access,
						  create_options,
						  &oplock_request,
						  &all_current_opens_are_level_II);
		if(num_share_modes == -1) {

			if (!internal_only_open) {
				NTSTATUS status;
				get_saved_error_triple(NULL, NULL, &status);
				if (NT_STATUS_EQUAL(status,NT_STATUS_SHARING_VIOLATION)) {
					/* Check if this can be done with the
					 * deny_dos and fcb calls. */
					if (create_options &
					    (NTCREATEX_OPTIONS_PRIVATE_DENY_DOS|
					     NTCREATEX_OPTIONS_PRIVATE_DENY_FCB)) {
						files_struct *fsp_dup;
						fsp_dup = fcb_or_dos_open(conn, fname, dev,
									  inode, access_mask,
									  share_access,
									  create_options);

						if (fsp_dup) {
							unlock_share_entry(conn, dev, inode);
							file_free(fsp);
							if (pinfo) {
								*pinfo = FILE_WAS_OPENED;
							}
							conn->num_files_open++;
							return fsp_dup;
						}
					}
				}
			}

			/*
			 * This next line is a subtlety we need for
			 * MS-Access. If a file open will fail due to share
			 * permissions and also for security (access) reasons,
			 * we need to return the access failed error, not the
			 * share error. This means we must attempt to open the
			 * file anyway in order to get the UNIX access error -
			 * even if we're going to fail the open for share
			 * reasons. This is bad, as we're burning another fd
			 * if there are existing locks but there's nothing
			 * else we can do. We also ensure we're not going to
			 * create or tuncate the file as we only want an
			 * access decision at this stage. JRA.
			 */
			errno = 0;
			fsp_open = open_file(fsp,conn,fname,psbuf,
					     flags|(flags2&~(O_TRUNC|O_CREAT)),
					     unx_mode,access_mask);

			DEBUG(4,("open_file_ntcreate : share_mode deny - "
				 "calling open_file with flags=0x%X "
				 "flags2=0x%X mode=0%o returned %d\n",
				 flags, (flags2&~(O_TRUNC|O_CREAT)),
				 (unsigned int)unx_mode, (int)fsp_open ));

			if (!fsp_open && errno) {
				/* Default error. */
				set_saved_error_triple(ERRDOS, ERRnoaccess,
						       NT_STATUS_ACCESS_DENIED);
			}

			/* 
			 * If we're returning a share violation, ensure we
			 * cope with the braindead 1 second delay.
			 */

			if (!internal_only_open) {
				NTSTATUS status;
				get_saved_error_triple(NULL, NULL, &status);
				if (NT_STATUS_EQUAL(status,NT_STATUS_SHARING_VIOLATION)) {
					/* The fsp->open_time here represents
					 * the current time of day. */
					defer_open_sharing_error(conn,
								 &fsp->open_time,
								 fname, dev, inode);
				}
			}

			unlock_share_entry(conn, dev, inode);
			if (fsp_open) {
				fd_close(conn, fsp);
				/*
				 * We have detected a sharing violation here
				 * so return the correct error code
				 */
				set_saved_error_triple(ERRDOS, ERRbadshare,
						       NT_STATUS_SHARING_VIOLATION);
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
			(def_acl = directory_has_default_acl(conn, parent_dirname(fname)))) {
		unx_mode = 0777;
	}

	DEBUG(4,("calling open_file with flags=0x%X flags2=0x%X mode=0%o\n",
			(unsigned int)flags,(unsigned int)flags2,(unsigned int)unx_mode));

	/*
	 * open_file strips any O_TRUNC flags itself.
	 */

	fsp_open = open_file(fsp,conn,fname,psbuf,flags|flags2,unx_mode,access_mask);

	if (!fsp_open && (flags2 & O_EXCL) && (errno == EEXIST)) {
		/*
		 * Two smbd's tried to open exclusively, but only one of them
		 * succeeded.
		 */
		file_free(fsp);
		return NULL;
	}

	if (!fsp_open && (flags == O_RDWR) && (errno != ENOENT)) {
		if((fsp_open = open_file(fsp,conn,fname,psbuf,
					 O_RDONLY,unx_mode,access_mask)) == True) {
			flags = O_RDONLY;
		}
	}

	if (!fsp_open) {
		if(file_existed) {
			unlock_share_entry(conn, dev, inode);
		}
		file_free(fsp);
		return NULL;
	}

	/*
	 * Deal with the race condition where two smbd's detect the file
	 * doesn't exist and do the create at the same time. One of them will
	 * win and set a share mode, the other (ie. this one) should check if
	 * the requested share mode for this create is allowed.
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
						  access_mask, share_access,
						  create_options,
						  &oplock_request,
						  &all_current_opens_are_level_II);

		if(num_share_modes == -1) {
			NTSTATUS status;
			get_saved_error_triple(NULL, NULL, &status);
			if (NT_STATUS_EQUAL(status,NT_STATUS_SHARING_VIOLATION)) {
				/* Check if this can be done with the deny_dos
				 * and fcb calls. */
				if (create_options &
				    (NTCREATEX_OPTIONS_PRIVATE_DENY_DOS|
				     NTCREATEX_OPTIONS_PRIVATE_DENY_FCB)) {
					files_struct *fsp_dup;
					fsp_dup = fcb_or_dos_open(conn, fname, dev, inode,
								  access_mask, share_access,
								  create_options);
					if (fsp_dup) {
						unlock_share_entry(conn, dev, inode);
						fd_close(conn, fsp);
						file_free(fsp);
						if (pinfo) {
							*pinfo = FILE_WAS_OPENED;
						}
						conn->num_files_open++;
						return fsp_dup;
					}
				}

				/* 
				 * If we're returning a share violation,
				 * ensure we cope with the braindead 1 second
				 * delay.
				 */

				/* The fsp->open_time here represents the
				 * current time of day. */
				defer_open_sharing_error(conn, &fsp->open_time,
							 fname, dev, inode);
			}

			unlock_share_entry_fsp(fsp);
			fd_close(conn,fsp);
			file_free(fsp);
			/*
			 * We have detected a sharing violation here, so
			 * return the correct code.
			 */
			set_saved_error_triple(ERRDOS, ERRbadshare,
					       NT_STATUS_SHARING_VIOLATION);
			return NULL;
		}

		/*
		 * If there are any share modes set then the file *did*
		 * exist. Ensure we return the correct value for action.
		 */

		if (num_share_modes > 0) {
			file_existed = True;
		}

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

	kernel_flock(fsp, share_access);

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
		 * We are modifing the file after open - update the stat
		 * struct..
		 */
		if ((SMB_VFS_FTRUNCATE(fsp,fsp->fh->fd,0) == -1) ||
		    (SMB_VFS_FSTAT(fsp,fsp->fh->fd,psbuf)==-1)) {
			unlock_share_entry_fsp(fsp);
			fd_close(conn,fsp);
			file_free(fsp);
			return NULL;
		}
	}

	/* Record the options we were opened with. */
	fsp->share_access = share_access;
	fsp->fh->private_options = create_options;
	fsp->access_mask = access_mask;

	if (file_existed) {
		if (!(flags2 & O_TRUNC)) {
			info = FILE_WAS_OPENED;
		} else {
			info = FILE_WAS_OVERWRITTEN;
		}
	} else {
		info = FILE_WAS_CREATED;
		/* Change the owner if required. */
		if (lp_inherit_owner(SNUM(conn))) {
			change_owner_to_parent(conn, fsp, fsp->fsp_name,
					       psbuf);
		}
	}

	if (pinfo) {
		*pinfo = info;
	}

	/* 
	 * Setup the oplock info in both the shared memory and
	 * file structs.
	 */

	if(oplock_request && (num_share_modes == 0) && 
	   !IS_VETO_OPLOCK_PATH(conn,fname) &&
	   set_file_oplock(fsp, oplock_request) ) {
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

	if (create_options & FILE_DELETE_ON_CLOSE) {
		uint32 dosattr= existing_dos_attributes;
		NTSTATUS result;

		if (info == FILE_WAS_OVERWRITTEN || info == FILE_WAS_CREATED ||
				info == FILE_WAS_SUPERSEDED) {
			dosattr = new_dos_attributes;
		}

		result = can_set_delete_on_close(fsp, True, dosattr);

		if (!NT_STATUS_IS_OK(result)) {
			uint8 u_e_c;
			uint32 u_e_code;
			BOOL dummy_del_on_close;
			/* Remember to delete the mode we just added. */
			del_share_mode(fsp, NULL, &dummy_del_on_close);
			unlock_share_entry_fsp(fsp);
			fd_close(conn,fsp);
			file_free(fsp);
			ntstatus_to_dos(result, &u_e_c, &u_e_code);
			set_saved_error_triple(u_e_c, u_e_code, result);
			return NULL;
		}
		set_delete_on_close(fsp, True);
	}
	
	if (info == FILE_WAS_OVERWRITTEN || info == FILE_WAS_CREATED ||
				info == FILE_WAS_SUPERSEDED) {
		/* Files should be initially set as archive */
		if (lp_map_archive(SNUM(conn)) ||
		    lp_store_dos_attributes(SNUM(conn))) {
			file_set_dosmode(conn, fname,
					 new_dos_attributes | aARCH, NULL,
					 True);
		}
	}

	/*
	 * Take care of inherited ACLs on created files - if default ACL not
	 * selected.
	 */

	if (!file_existed && !def_acl) {

		int saved_errno = errno; /* We might get ENOSYS in the next
					  * call.. */

		if (SMB_VFS_FCHMOD_ACL(fsp, fsp->fh->fd, unx_mode) == -1
		    && errno == ENOSYS) {
			errno = saved_errno; /* Ignore ENOSYS */
		}

	} else if (new_unx_mode) {

		int ret = -1;

		/* Attributes need changing. File already existed. */

		{
			int saved_errno = errno; /* We might get ENOSYS in the
						  * next call.. */
			ret = SMB_VFS_FCHMOD_ACL(fsp, fsp->fh->fd,
						 new_unx_mode);

			if (ret == -1 && errno == ENOSYS) {
				errno = saved_errno; /* Ignore ENOSYS */
			} else {
				DEBUG(5, ("open_file_shared: failed to reset "
					  "attributes of file %s to 0%o\n",
					fname, (unsigned int)new_unx_mode));
				ret = 0; /* Don't do the fchmod below. */
			}
		}

		if ((ret == -1) &&
		    (SMB_VFS_FCHMOD(fsp, fsp->fh->fd, new_unx_mode) == -1))
			DEBUG(5, ("open_file_shared: failed to reset "
				  "attributes of file %s to 0%o\n",
				fname, (unsigned int)new_unx_mode));
	}

	/* If this is a successful open, we must remove any deferred open
	 * records. */
	delete_defered_open_entry_record(conn, fsp->dev, fsp->inode);
	unlock_share_entry_fsp(fsp);

	conn->num_files_open++;

	return fsp;
}

/****************************************************************************
 Open a file for for write to ensure that we can fchmod it.
****************************************************************************/

files_struct *open_file_fchmod(connection_struct *conn, const char *fname,
			       SMB_STRUCT_STAT *psbuf)
{
	files_struct *fsp = NULL;
	BOOL fsp_open;

	if (!VALID_STAT(*psbuf)) {
		return NULL;
	}

	fsp = file_new(conn);
	if(!fsp) {
		return NULL;
	}

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

files_struct *open_directory(connection_struct *conn,
				const char *fname,
				SMB_STRUCT_STAT *psbuf,
				uint32 access_mask,
				uint32 share_access,
				uint32 create_disposition,
				uint32 create_options,
				int *pinfo)
{
	files_struct *fsp = NULL;
	BOOL dir_existed = VALID_STAT(*psbuf) ? True : False;
	BOOL create_dir = False;
	int info = 0;

	DEBUG(5,("open_directory: opening directory %s, access_mask = 0x%x, "
		 "share_access = 0x%x create_options = 0x%x, "
		 "create_disposition = 0x%x\n",
		 fname,
		 (unsigned int)access_mask,
		 (unsigned int)share_access,
		 (unsigned int)create_options,
		 (unsigned int)create_disposition));

	if (is_ntfs_stream_name(fname)) {
		DEBUG(0,("open_directory: %s is a stream name!\n", fname ));
		/* NB. Is the DOS error ERRbadpath or ERRbaddirectory ? */
		set_saved_error_triple(ERRDOS, ERRbadpath,
				       NT_STATUS_NOT_A_DIRECTORY);
		return NULL;
	}

	if (dir_existed && !S_ISDIR(psbuf->st_mode)) {
		DEBUG(0,("open_directory: %s is not a directory !\n", fname ));
		/* NB. Is the DOS error ERRbadpath or ERRbaddirectory ? */
		set_saved_error_triple(ERRDOS, ERRbadpath,
				       NT_STATUS_NOT_A_DIRECTORY);
		return NULL;
	}

	switch( create_disposition ) {
		case FILE_OPEN:
			/* If directory exists open. If directory doesn't
			 * exist error. */
			if (!dir_existed) {
				DEBUG(5,("open_directory: FILE_OPEN requested "
					 "for directory %s and it doesn't "
					 "exist.\n", fname ));
				set_saved_error_triple(ERRDOS, ERRbadfile,
						       NT_STATUS_OBJECT_NAME_NOT_FOUND);
				return NULL;
			}
			info = FILE_WAS_OPENED;
			break;

		case FILE_CREATE:
			/* If directory exists error. If directory doesn't
			 * exist create. */
			if (dir_existed) {
				DEBUG(5,("open_directory: FILE_CREATE "
					 "requested for directory %s and it "
					 "already exists.\n", fname ));
				set_saved_error_triple(ERRDOS, ERRfilexists,
						       NT_STATUS_OBJECT_NAME_COLLISION);
				return NULL;
			}
			create_dir = True;
			info = FILE_WAS_CREATED;
			break;

		case FILE_OPEN_IF:
			/* If directory exists open. If directory doesn't
			 * exist create. */
			if (!dir_existed) {
				create_dir = True;
				info = FILE_WAS_CREATED;
			} else {
				info = FILE_WAS_OPENED;
			}
			break;

		case FILE_SUPERSEDE:
		case FILE_OVERWRITE:
		case FILE_OVERWRITE_IF:
		default:
			DEBUG(5,("open_directory: invalid create_disposition "
				 "0x%x for directory %s\n",
				 (unsigned int)create_disposition, fname));
			file_free(fsp);
			set_saved_error_triple(ERRDOS, ERRinvalidparam,
					       NT_STATUS_INVALID_PARAMETER);
			return NULL;
	}

	if (create_dir) {
		/*
		 * Try and create the directory.
		 */

		/* We know bad_path is false as it's caught earlier. */

		NTSTATUS status = mkdir_internal(conn, fname, False);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(2,("open_directory: unable to create %s. "
				 "Error was %s\n", fname, strerror(errno) ));
			/* Ensure we return the correct NT status to the
			 * client. */
			set_saved_error_triple(0, 0, status);
			return NULL;
		}

		/* Ensure we're checking for a symlink here.... */
		/* We don't want to get caught by a symlink racer. */

		if(SMB_VFS_LSTAT(conn,fname, psbuf) != 0) {
			return NULL;
		}

		if(!S_ISDIR(psbuf->st_mode)) {
			DEBUG(0,("open_directory: %s is not a directory !\n",
				 fname ));
			return NULL;
		}
	}

	fsp = file_new(conn);
	if(!fsp) {
		return NULL;
	}

	/*
	 * Setup the files_struct for it.
	 */
	
	fsp->mode = psbuf->st_mode;
	fsp->inode = psbuf->st_ino;
	fsp->dev = psbuf->st_dev;
	fsp->vuid = current_user.vuid;
	fsp->file_pid = global_smbpid;
	fsp->can_lock = True;
	fsp->can_read = False;
	fsp->can_write = False;

	fsp->share_access = share_access;
	fsp->fh->private_options = create_options;
	fsp->access_mask = access_mask;

	fsp->print_file = False;
	fsp->modified = False;
	fsp->oplock_type = NO_OPLOCK;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->is_directory = True;
	fsp->is_stat = False;
	string_set(&fsp->fsp_name,fname);

	if (create_options & FILE_DELETE_ON_CLOSE) {
		NTSTATUS status = can_set_delete_on_close(fsp, True, 0);
		if (!NT_STATUS_IS_OK(status)) {
			file_free(fsp);
			return NULL;
		}
	}

	/* Change the owner if required. */
	if ((info == FILE_WAS_CREATED) && lp_inherit_owner(SNUM(conn))) {
		change_owner_to_parent(conn, fsp, fsp->fsp_name, psbuf);
	}

	if (pinfo) {
		*pinfo = info;
	}

	conn->num_files_open++;

	return fsp;
}

/****************************************************************************
 Open a pseudo-file (no locking checks - a 'stat' open).
****************************************************************************/

files_struct *open_file_stat(connection_struct *conn, char *fname,
			     SMB_STRUCT_STAT *psbuf)
{
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
	fsp->vuid = current_user.vuid;
	fsp->file_pid = global_smbpid;
	fsp->can_lock = False;
	fsp->can_read = False;
	fsp->can_write = False;
	fsp->print_file = False;
	fsp->modified = False;
	fsp->oplock_type = NO_OPLOCK;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->is_directory = False;
	fsp->is_stat = True;
	string_set(&fsp->fsp_name,fname);

	conn->num_files_open++;

	return fsp;
}
