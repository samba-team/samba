/* 
   Unix SMB/CIFS implementation.
   file opening and share modes
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2004
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
#include "smbd/globals.h"

extern const struct generic_mapping file_generic_mapping;

struct deferred_open_record {
	bool delayed_for_oplocks;
	struct file_id id;
};

static NTSTATUS create_file_unixpath(connection_struct *conn,
				     struct smb_request *req,
				     const char *fname,
				     uint32_t access_mask,
				     uint32_t share_access,
				     uint32_t create_disposition,
				     uint32_t create_options,
				     uint32_t file_attributes,
				     uint32_t oplock_request,
				     uint64_t allocation_size,
				     struct security_descriptor *sd,
				     struct ea_list *ea_list,

				     files_struct **result,
				     int *pinfo,
				     SMB_STRUCT_STAT *psbuf);

/****************************************************************************
 SMB1 file varient of se_access_check. Never test FILE_READ_ATTRIBUTES.
****************************************************************************/

NTSTATUS smb1_file_se_access_check(const struct security_descriptor *sd,
                          const NT_USER_TOKEN *token,
                          uint32_t access_desired,
                          uint32_t *access_granted)
{
	return se_access_check(sd,
				token,
				(access_desired & ~FILE_READ_ATTRIBUTES),
				access_granted);
}

/****************************************************************************
 Check if we have open rights.
****************************************************************************/

static NTSTATUS check_open_rights(struct connection_struct *conn,
				const char *fname,
				uint32_t access_mask,
				uint32_t *access_granted)
{
	/* Check if we have rights to open. */
	NTSTATUS status;
	struct security_descriptor *sd;

	*access_granted = 0;

	if (conn->server_info->utok.uid == 0 || conn->admin_user) {
		/* I'm sorry sir, I didn't know you were root... */
		*access_granted = access_mask;
		if (access_mask & SEC_FLAG_MAXIMUM_ALLOWED) {
			*access_granted |= FILE_GENERIC_ALL;
		}
		return NT_STATUS_OK;
	}

	status = SMB_VFS_GET_NT_ACL(conn, fname,
			(OWNER_SECURITY_INFORMATION |
			GROUP_SECURITY_INFORMATION |
			DACL_SECURITY_INFORMATION),&sd);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("check_open_rights: Could not get acl "
			"on %s: %s\n",
			fname,
			nt_errstr(status)));
		return status;
	}

	status = smb1_file_se_access_check(sd,
				conn->server_info->ptok,
				access_mask,
				access_granted);

	TALLOC_FREE(sd);

	DEBUG(10,("check_open_rights: file %s requesting "
		"0x%x returning 0x%x (%s)\n",
		fname,
		(unsigned int)access_mask,
		(unsigned int)*access_granted,
		nt_errstr(status) ));

	return status;
}

/****************************************************************************
 fd support routines - attempt to do a dos_open.
****************************************************************************/

static NTSTATUS fd_open(struct connection_struct *conn,
		    const char *fname, 
		    files_struct *fsp,
		    int flags,
		    mode_t mode)
{
	NTSTATUS status = NT_STATUS_OK;

#ifdef O_NOFOLLOW
	/* 
	 * Never follow symlinks on a POSIX client. The
	 * client should be doing this.
	 */

	if (fsp->posix_open || !lp_symlinks(SNUM(conn))) {
		flags |= O_NOFOLLOW;
	}
#endif

	fsp->fh->fd = SMB_VFS_OPEN(conn,fname,fsp,flags,mode);
	if (fsp->fh->fd == -1) {
		status = map_nt_error_from_unix(errno);
		if (errno == EMFILE) {
			static time_t last_warned = 0L;

			if (time((time_t *) NULL) > last_warned) {
				DEBUG(0,("Too many open files, unable "
					"to open more!  smbd's max "
					"open files = %d\n",
					lp_max_open_files()));
				last_warned = time((time_t *) NULL);
			}
		}

	}

	DEBUG(10,("fd_open: name %s, flags = 0%o mode = 0%o, fd = %d. %s\n",
		    fname, flags, (int)mode, fsp->fh->fd,
		(fsp->fh->fd == -1) ? strerror(errno) : "" ));

	return status;
}

/****************************************************************************
 Close the file associated with a fsp.
****************************************************************************/

NTSTATUS fd_close(files_struct *fsp)
{
	int ret;

	if (fsp->fh->fd == -1) {
		return NT_STATUS_OK; /* What we used to call a stat open. */
	}
	if (fsp->fh->ref_count > 1) {
		return NT_STATUS_OK; /* Shared handle. Only close last reference. */
	}

	ret = SMB_VFS_CLOSE(fsp);
	fsp->fh->fd = -1;
	if (ret == -1) {
		return map_nt_error_from_unix(errno);
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Change the ownership of a file to that of the parent directory.
 Do this by fd if possible.
****************************************************************************/

void change_file_owner_to_parent(connection_struct *conn,
					const char *inherit_from_dir,
					files_struct *fsp)
{
	SMB_STRUCT_STAT parent_st;
	int ret;

	ret = SMB_VFS_STAT(conn, inherit_from_dir, &parent_st);
	if (ret == -1) {
		DEBUG(0,("change_file_owner_to_parent: failed to stat parent "
			 "directory %s. Error was %s\n",
			 inherit_from_dir, strerror(errno) ));
		return;
	}

	become_root();
	ret = SMB_VFS_FCHOWN(fsp, parent_st.st_uid, (gid_t)-1);
	unbecome_root();
	if (ret == -1) {
		DEBUG(0,("change_file_owner_to_parent: failed to fchown "
			 "file %s to parent directory uid %u. Error "
			 "was %s\n", fsp->fsp_name,
			 (unsigned int)parent_st.st_uid,
			 strerror(errno) ));
	}

	DEBUG(10,("change_file_owner_to_parent: changed new file %s to "
		  "parent directory uid %u.\n",	fsp->fsp_name,
		  (unsigned int)parent_st.st_uid ));
}

NTSTATUS change_dir_owner_to_parent(connection_struct *conn,
				       const char *inherit_from_dir,
				       const char *fname,
				       SMB_STRUCT_STAT *psbuf)
{
	char *saved_dir = NULL;
	SMB_STRUCT_STAT sbuf;
	SMB_STRUCT_STAT parent_st;
	TALLOC_CTX *ctx = talloc_tos();
	NTSTATUS status = NT_STATUS_OK;
	int ret;

	ret = SMB_VFS_STAT(conn, inherit_from_dir, &parent_st);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		DEBUG(0,("change_dir_owner_to_parent: failed to stat parent "
			 "directory %s. Error was %s\n",
			 inherit_from_dir, strerror(errno) ));
		return status;
	}

	/* We've already done an lstat into psbuf, and we know it's a
	   directory. If we can cd into the directory and the dev/ino
	   are the same then we can safely chown without races as
	   we're locking the directory in place by being in it.  This
	   should work on any UNIX (thanks tridge :-). JRA.
	*/

	saved_dir = vfs_GetWd(ctx,conn);
	if (!saved_dir) {
		status = map_nt_error_from_unix(errno);
		DEBUG(0,("change_dir_owner_to_parent: failed to get "
			 "current working directory. Error was %s\n",
			 strerror(errno)));
		return status;
	}

	/* Chdir into the new path. */
	if (vfs_ChDir(conn, fname) == -1) {
		status = map_nt_error_from_unix(errno);
		DEBUG(0,("change_dir_owner_to_parent: failed to change "
			 "current working directory to %s. Error "
			 "was %s\n", fname, strerror(errno) ));
		goto out;
	}

	if (SMB_VFS_STAT(conn,".",&sbuf) == -1) {
		status = map_nt_error_from_unix(errno);
		DEBUG(0,("change_dir_owner_to_parent: failed to stat "
			 "directory '.' (%s) Error was %s\n",
			 fname, strerror(errno)));
		goto out;
	}

	/* Ensure we're pointing at the same place. */
	if (sbuf.st_dev != psbuf->st_dev ||
	    sbuf.st_ino != psbuf->st_ino ||
	    sbuf.st_mode != psbuf->st_mode ) {
		DEBUG(0,("change_dir_owner_to_parent: "
			 "device/inode/mode on directory %s changed. "
			 "Refusing to chown !\n", fname ));
		status = NT_STATUS_ACCESS_DENIED;
		goto out;
	}

	become_root();
	ret = SMB_VFS_CHOWN(conn, ".", parent_st.st_uid, (gid_t)-1);
	unbecome_root();
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		DEBUG(10,("change_dir_owner_to_parent: failed to chown "
			  "directory %s to parent directory uid %u. "
			  "Error was %s\n", fname,
			  (unsigned int)parent_st.st_uid, strerror(errno) ));
		goto out;
	}

	DEBUG(10,("change_dir_owner_to_parent: changed ownership of new "
		  "directory %s to parent directory uid %u.\n",
		  fname, (unsigned int)parent_st.st_uid ));

 out:

	vfs_ChDir(conn,saved_dir);
	return status;
}

/****************************************************************************
 Open a file.
****************************************************************************/

static NTSTATUS open_file(files_struct *fsp,
			  connection_struct *conn,
			  struct smb_request *req,
			  const char *parent_dir,
			  const char *name,
			  const char *path,
			  SMB_STRUCT_STAT *psbuf,
			  int flags,
			  mode_t unx_mode,
			  uint32 access_mask, /* client requested access mask. */
			  uint32 open_access_mask) /* what we're actually using in the open. */
{
	NTSTATUS status = NT_STATUS_OK;
	int accmode = (flags & O_ACCMODE);
	int local_flags = flags;
	bool file_existed = VALID_STAT(*psbuf);

	fsp->fh->fd = -1;
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
		if(accmode != O_RDONLY || (flags & O_TRUNC) || (flags & O_APPEND)) {
			DEBUG(3,("Permission denied opening %s\n", path));
			return NT_STATUS_ACCESS_DENIED;
		} else if(flags & O_CREAT) {
			/* We don't want to write - but we must make sure that
			   O_CREAT doesn't create the file if we have write
			   access into the directory.
			*/
			flags &= ~(O_CREAT|O_EXCL);
			local_flags &= ~(O_CREAT|O_EXCL);
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
			  "for file %s\n", path));
		local_flags = (flags & ~O_ACCMODE)|O_RDWR;
	}

	if ((open_access_mask & (FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_EXECUTE)) ||
	    (!file_existed && (local_flags & O_CREAT)) ||
	    ((local_flags & O_TRUNC) == O_TRUNC) ) {
		const char *wild;

		/*
		 * We can't actually truncate here as the file may be locked.
		 * open_file_ntcreate will take care of the truncate later. JRA.
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
		if (fsp->base_fsp) {
			/*
			 * wildcard characters are allowed in stream names
			 * only test the basefilename
			 */
			wild = fsp->base_fsp->fsp_name;
		} else {
			wild = path;
		}
		if ((local_flags & O_CREAT) && !file_existed &&
		    ms_has_wild(wild))  {
			return NT_STATUS_OBJECT_NAME_INVALID;
		}

		/* Actually do the open */
		status = fd_open(conn, path, fsp, local_flags, unx_mode);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3,("Error opening file %s (%s) (local_flags=%d) "
				 "(flags=%d)\n",
				 path,nt_errstr(status),local_flags,flags));
			return status;
		}

		if ((local_flags & O_CREAT) && !file_existed) {

			/* Inherit the ACL if required */
			if (lp_inherit_perms(SNUM(conn))) {
				inherit_access_posix_acl(conn, parent_dir, path,
						   unx_mode);
			}

			/* Change the owner if required. */
			if (lp_inherit_owner(SNUM(conn))) {
				change_file_owner_to_parent(conn, parent_dir,
							    fsp);
			}

			notify_fname(conn, NOTIFY_ACTION_ADDED,
				     FILE_NOTIFY_CHANGE_FILE_NAME, path);
		}

	} else {
		fsp->fh->fd = -1; /* What we used to call a stat open. */
		if (file_existed) {
			uint32_t access_granted = 0;

			status = check_open_rights(conn,
					path,
					access_mask,
					&access_granted);
			if (!NT_STATUS_IS_OK(status)) {
				if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
					/*
					 * On NT_STATUS_ACCESS_DENIED, access_granted
					 * contains the denied bits.
					 */

					if ((access_mask & FILE_WRITE_ATTRIBUTES) &&
							(access_granted & FILE_WRITE_ATTRIBUTES) &&
							(lp_map_readonly(SNUM(conn)) ||
							 lp_map_archive(SNUM(conn)) ||
							 lp_map_hidden(SNUM(conn)) ||
							 lp_map_system(SNUM(conn)))) {
						access_granted &= ~FILE_WRITE_ATTRIBUTES;

						DEBUG(10,("open_file: overrode FILE_WRITE_ATTRIBUTES "
							"on file %s\n",
							path ));
					}

					if ((access_mask & DELETE_ACCESS) &&
							(access_granted & DELETE_ACCESS) &&
							can_delete_file_in_directory(conn, path)) {
						/* Were we trying to do a stat open
						 * for delete and didn't get DELETE
						 * access (only) ? Check if the
						 * directory allows DELETE_CHILD.
						 * See here:
						 * http://blogs.msdn.com/oldnewthing/archive/2004/06/04/148426.aspx
						 * for details. */

						access_granted &= ~DELETE_ACCESS;

						DEBUG(10,("open_file: overrode DELETE_ACCESS "
							"on file %s\n",
							path ));
					}

					if (access_granted != 0) {
						DEBUG(10, ("open_file: Access denied on "
							"file %s\n",
							path));
						return status;
					}
				} else if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND) &&
							fsp->posix_open &&
							S_ISLNK(psbuf->st_mode)) {
					/* This is a POSIX stat open for delete
					 * or rename on a symlink that points
					 * nowhere. Allow. */
					DEBUG(10, ("open_file: allowing POSIX open "
						"on bad symlink %s\n",
						path ));
				} else {
					DEBUG(10, ("open_file: check_open_rights "
						"on file %s returned %s\n",
						path, nt_errstr(status) ));
					return status;
				}
			}
		}
	}

	if (!file_existed) {
		int ret;

		if (fsp->fh->fd == -1) {
			ret = SMB_VFS_STAT(conn, path, psbuf);
		} else {
			ret = SMB_VFS_FSTAT(fsp, psbuf);
			/* If we have an fd, this stat should succeed. */
			if (ret == -1) {
				DEBUG(0,("Error doing fstat on open file %s "
					 "(%s)\n", path,strerror(errno) ));
			}
		}

		/* For a non-io open, this stat failing means file not found. JRA */
		if (ret == -1) {
			status = map_nt_error_from_unix(errno);
			fd_close(fsp);
			return status;
		}
	}

	/*
	 * POSIX allows read-only opens of directories. We don't
	 * want to do this (we use a different code path for this)
	 * so catch a directory open and return an EISDIR. JRA.
	 */

	if(S_ISDIR(psbuf->st_mode)) {
		fd_close(fsp);
		errno = EISDIR;
		return NT_STATUS_FILE_IS_A_DIRECTORY;
	}

	fsp->mode = psbuf->st_mode;
	fsp->file_id = vfs_file_id_from_sbuf(conn, psbuf);
	fsp->vuid = req ? req->vuid : UID_FIELD_INVALID;
	fsp->file_pid = req ? req->smbpid : 0;
	fsp->can_lock = True;
	fsp->can_read = (access_mask & (FILE_READ_DATA)) ? True : False;
	if (!CAN_WRITE(conn)) {
		fsp->can_write = False;
	} else {
		fsp->can_write = (access_mask & (FILE_WRITE_DATA | FILE_APPEND_DATA)) ?
			True : False;
	}
	fsp->print_file = False;
	fsp->modified = False;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->is_directory = False;
	if (conn->aio_write_behind_list &&
	    is_in_path(path, conn->aio_write_behind_list, conn->case_sensitive)) {
		fsp->aio_write_behind = True;
	}

	string_set(&fsp->fsp_name, path);
	fsp->wcp = NULL; /* Write cache pointer. */

	DEBUG(2,("%s opened file %s read=%s write=%s (numopen=%d)\n",
		 conn->server_info->unix_name,
		 fsp->fsp_name,
		 BOOLSTR(fsp->can_read), BOOLSTR(fsp->can_write),
		 conn->num_files_open));

	errno = 0;
	return NT_STATUS_OK;
}

/*******************************************************************
 Return True if the filename is one of the special executable types.
********************************************************************/

bool is_executable(const char *fname)
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

static bool share_conflict(struct share_mode_entry *entry,
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
		return True; \
	}
#else
#define CHECK_MASK(num, am, right, sa, share) \
	if (((am) & (right)) && !((sa) & (share))) { \
		DEBUG(10,("share_conflict: check %d conflict am = 0x%x, right = 0x%x, \
sa = 0x%x, share = 0x%x\n", (num), (unsigned int)(am), (unsigned int)(right), (unsigned int)(sa), \
			(unsigned int)(share) )); \
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
				      struct share_mode_entry *share_entry)
{
	files_struct *fsp;

	if (!procid_is_me(&share_entry->pid)) {
		return;
	}

	if (is_deferred_open_entry(share_entry) &&
	    !open_was_deferred(share_entry->op_mid)) {
		char *str = talloc_asprintf(talloc_tos(),
			"Got a deferred entry without a request: "
			"PANIC: %s\n",
			share_mode_str(talloc_tos(), num, share_entry));
		smb_panic(str);
	}

	if (!is_valid_share_mode_entry(share_entry)) {
		return;
	}

	fsp = file_find_dif(share_entry->id,
			    share_entry->share_file_id);
	if (!fsp) {
		DEBUG(0,("validate_my_share_entries: PANIC : %s\n",
			 share_mode_str(talloc_tos(), num, share_entry) ));
		smb_panic("validate_my_share_entries: Cannot match a "
			  "share entry with an open file\n");
	}

	if (is_deferred_open_entry(share_entry) ||
	    is_unused_share_mode_entry(share_entry)) {
		goto panic;
	}

	if ((share_entry->op_type == NO_OPLOCK) &&
	    (fsp->oplock_type == FAKE_LEVEL_II_OPLOCK)) {
		/* Someone has already written to it, but I haven't yet
		 * noticed */
		return;
	}

	if (((uint16)fsp->oplock_type) != share_entry->op_type) {
		goto panic;
	}

	return;

 panic:
	{
		char *str;
		DEBUG(0,("validate_my_share_entries: PANIC : %s\n",
			 share_mode_str(talloc_tos(), num, share_entry) ));
		str = talloc_asprintf(talloc_tos(),
			"validate_my_share_entries: "
			"file %s, oplock_type = 0x%x, op_type = 0x%x\n",
			 fsp->fsp_name, (unsigned int)fsp->oplock_type,
			 (unsigned int)share_entry->op_type );
		smb_panic(str);
	}
}
#endif

bool is_stat_open(uint32 access_mask)
{
	return (access_mask &&
		((access_mask & ~(SYNCHRONIZE_ACCESS| FILE_READ_ATTRIBUTES|
				  FILE_WRITE_ATTRIBUTES))==0) &&
		((access_mask & (SYNCHRONIZE_ACCESS|FILE_READ_ATTRIBUTES|
				 FILE_WRITE_ATTRIBUTES)) != 0));
}

/****************************************************************************
 Deal with share modes
 Invarient: Share mode must be locked on entry and exit.
 Returns -1 on error, or number of share modes on success (may be zero).
****************************************************************************/

static NTSTATUS open_mode_check(connection_struct *conn,
				const char *fname,
				struct share_mode_lock *lck,
				uint32 access_mask,
				uint32 share_access,
				uint32 create_options,
				bool *file_existed)
{
	int i;

	if(lck->num_share_modes == 0) {
		return NT_STATUS_OK;
	}

	*file_existed = True;

	/* A delete on close prohibits everything */

	if (lck->delete_on_close) {
		return NT_STATUS_DELETE_PENDING;
	}

	if (is_stat_open(access_mask)) {
		/* Stat open that doesn't trigger oplock breaks or share mode
		 * checks... ! JRA. */
		return NT_STATUS_OK;
	}

	/*
	 * Check if the share modes will give us access.
	 */
	
#if defined(DEVELOPER)
	for(i = 0; i < lck->num_share_modes; i++) {
		validate_my_share_entries(i, &lck->share_modes[i]);
	}
#endif

	if (!lp_share_modes(SNUM(conn))) {
		return NT_STATUS_OK;
	}

	/* Now we check the share modes, after any oplock breaks. */
	for(i = 0; i < lck->num_share_modes; i++) {

		if (!is_valid_share_mode_entry(&lck->share_modes[i])) {
			continue;
		}

		/* someone else has a share lock on it, check to see if we can
		 * too */
		if (share_conflict(&lck->share_modes[i],
				   access_mask, share_access)) {
			return NT_STATUS_SHARING_VIOLATION;
		}
	}
	
	return NT_STATUS_OK;
}

static bool is_delete_request(files_struct *fsp) {
	return ((fsp->access_mask == DELETE_ACCESS) &&
		(fsp->oplock_type == NO_OPLOCK));
}

/*
 * Send a break message to the oplock holder and delay the open for
 * our client.
 */

static NTSTATUS send_break_message(files_struct *fsp,
					struct share_mode_entry *exclusive,
					uint16 mid,
					int oplock_request)
{
	NTSTATUS status;
	char msg[MSG_SMB_SHARE_MODE_ENTRY_SIZE];

	DEBUG(10, ("Sending break request to PID %s\n",
		   procid_str_static(&exclusive->pid)));
	exclusive->op_mid = mid;

	/* Create the message. */
	share_mode_entry_to_message(msg, exclusive);

	/* Add in the FORCE_OPLOCK_BREAK_TO_NONE bit in the message if set. We
	   don't want this set in the share mode struct pointed to by lck. */

	if (oplock_request & FORCE_OPLOCK_BREAK_TO_NONE) {
		SSVAL(msg,6,exclusive->op_type | FORCE_OPLOCK_BREAK_TO_NONE);
	}

	status = messaging_send_buf(smbd_messaging_context(), exclusive->pid,
				    MSG_SMB_BREAK_REQUEST,
				    (uint8 *)msg,
				    MSG_SMB_SHARE_MODE_ENTRY_SIZE);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("Could not send oplock break message: %s\n",
			  nt_errstr(status)));
	}

	return status;
}

/*
 * 1) No files open at all or internal open: Grant whatever the client wants.
 *
 * 2) Exclusive (or batch) oplock around: If the requested access is a delete
 *    request, break if the oplock around is a batch oplock. If it's another
 *    requested access type, break.
 *
 * 3) Only level2 around: Grant level2 and do nothing else.
 */

static bool delay_for_oplocks(struct share_mode_lock *lck,
			      files_struct *fsp,
			      uint16 mid,
			      int pass_number,
			      int oplock_request)
{
	int i;
	struct share_mode_entry *exclusive = NULL;
	bool valid_entry = false;
	bool have_level2 = false;
	bool have_a_none_oplock = false;
	bool allow_level2 = (global_client_caps & CAP_LEVEL_II_OPLOCKS) &&
		            lp_level2_oplocks(SNUM(fsp->conn));

	if (oplock_request & INTERNAL_OPEN_ONLY) {
		fsp->oplock_type = NO_OPLOCK;
	}

	if ((oplock_request & INTERNAL_OPEN_ONLY) || is_stat_open(fsp->access_mask)) {
		return false;
	}

	for (i=0; i<lck->num_share_modes; i++) {

		if (!is_valid_share_mode_entry(&lck->share_modes[i])) {
			continue;
		}

		/* At least one entry is not an invalid or deferred entry. */
		valid_entry = true;

		if (pass_number == 1) {
			if (BATCH_OPLOCK_TYPE(lck->share_modes[i].op_type)) {
				SMB_ASSERT(exclusive == NULL);
				exclusive = &lck->share_modes[i];
			}
		} else {
			if (EXCLUSIVE_OPLOCK_TYPE(lck->share_modes[i].op_type)) {
				SMB_ASSERT(exclusive == NULL);
				exclusive = &lck->share_modes[i];
			}
		}

		if (LEVEL_II_OPLOCK_TYPE(lck->share_modes[i].op_type)) {
			SMB_ASSERT(exclusive == NULL);
			have_level2 = true;
		}

		if (lck->share_modes[i].op_type == NO_OPLOCK) {
			have_a_none_oplock = true;
		}
	}

	if (exclusive != NULL) { /* Found an exclusive oplock */
		bool delay_it = is_delete_request(fsp) ?
				BATCH_OPLOCK_TYPE(exclusive->op_type) :	true;
		SMB_ASSERT(!have_level2);
		if (delay_it) {
			send_break_message(fsp, exclusive, mid, oplock_request);
			return true;
		}
	}

	/*
	 * Match what was requested (fsp->oplock_type) with
 	 * what was found in the existing share modes.
 	 */

	if (!valid_entry) {
		/* All entries are placeholders or deferred.
		 * Directly grant whatever the client wants. */
		if (fsp->oplock_type == NO_OPLOCK) {
			/* Store a level2 oplock, but don't tell the client */
			fsp->oplock_type = FAKE_LEVEL_II_OPLOCK;
		}
	} else if (have_a_none_oplock) {
		fsp->oplock_type = NO_OPLOCK;
	} else if (have_level2) {
		if (fsp->oplock_type == NO_OPLOCK ||
				fsp->oplock_type == FAKE_LEVEL_II_OPLOCK) {
			/* Store a level2 oplock, but don't tell the client */
			fsp->oplock_type = FAKE_LEVEL_II_OPLOCK;
		} else {
			fsp->oplock_type = LEVEL_II_OPLOCK;
		}
	} else {
		/* This case can never happen. */
		SMB_ASSERT(1);
	}

	/*
	 * Don't grant level2 to clients that don't want them
	 * or if we've turned them off.
	 */
	if (fsp->oplock_type == LEVEL_II_OPLOCK && !allow_level2) {
		fsp->oplock_type = FAKE_LEVEL_II_OPLOCK;
	}

	DEBUG(10,("delay_for_oplocks: oplock type 0x%x on file %s\n",
		fsp->oplock_type, fsp->fsp_name));

	/* No delay. */
	return false;
}

bool request_timed_out(struct timeval request_time,
		       struct timeval timeout)
{
	struct timeval now, end_time;
	GetTimeOfDay(&now);
	end_time = timeval_sum(&request_time, &timeout);
	return (timeval_compare(&end_time, &now) < 0);
}

/****************************************************************************
 Handle the 1 second delay in returning a SHARING_VIOLATION error.
****************************************************************************/

static void defer_open(struct share_mode_lock *lck,
		       struct timeval request_time,
		       struct timeval timeout,
		       struct smb_request *req,
		       struct deferred_open_record *state)
{
	int i;

	/* Paranoia check */

	for (i=0; i<lck->num_share_modes; i++) {
		struct share_mode_entry *e = &lck->share_modes[i];

		if (!is_deferred_open_entry(e)) {
			continue;
		}

		if (procid_is_me(&e->pid) && (e->op_mid == req->mid)) {
			DEBUG(0, ("Trying to defer an already deferred "
				  "request: mid=%d, exiting\n", req->mid));
			exit_server("attempt to defer a deferred request");
		}
	}

	/* End paranoia check */

	DEBUG(10,("defer_open_sharing_error: time [%u.%06u] adding deferred "
		  "open entry for mid %u\n",
		  (unsigned int)request_time.tv_sec,
		  (unsigned int)request_time.tv_usec,
		  (unsigned int)req->mid));

	if (!push_deferred_smb_message(req, request_time, timeout,
				       (char *)state, sizeof(*state))) {
		exit_server("push_deferred_smb_message failed");
	}
	add_deferred_open(lck, req->mid, request_time, state->id);

	/*
	 * Push the MID of this packet on the signing queue.
	 * We only do this once, the first time we push the packet
	 * onto the deferred open queue, as this has a side effect
	 * of incrementing the response sequence number.
	 */

	srv_defer_sign_response(req->mid);
}


/****************************************************************************
 On overwrite open ensure that the attributes match.
****************************************************************************/

bool open_match_attributes(connection_struct *conn,
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

NTSTATUS fcb_or_dos_open(struct smb_request *req,
				     connection_struct *conn,
				     files_struct *fsp_to_dup_into,
				     const char *fname,
				     struct file_id id,
				     uint16 file_pid,
				     uint16 vuid,
				     uint32 access_mask,
				     uint32 share_access,
				     uint32 create_options)
{
	files_struct *fsp;

	DEBUG(5,("fcb_or_dos_open: attempting old open semantics for "
		 "file %s.\n", fname ));

	for(fsp = file_find_di_first(id); fsp;
	    fsp = file_find_di_next(fsp)) {

		DEBUG(10,("fcb_or_dos_open: checking file %s, fd = %d, "
			  "vuid = %u, file_pid = %u, private_options = 0x%x "
			  "access_mask = 0x%x\n", fsp->fsp_name,
			  fsp->fh->fd, (unsigned int)fsp->vuid,
			  (unsigned int)fsp->file_pid,
			  (unsigned int)fsp->fh->private_options,
			  (unsigned int)fsp->access_mask ));

		if (fsp->fh->fd != -1 &&
		    fsp->vuid == vuid &&
		    fsp->file_pid == file_pid &&
		    (fsp->fh->private_options & (NTCREATEX_OPTIONS_PRIVATE_DENY_DOS |
						 NTCREATEX_OPTIONS_PRIVATE_DENY_FCB)) &&
		    (fsp->access_mask & FILE_WRITE_DATA) &&
		    strequal(fsp->fsp_name, fname)) {
			DEBUG(10,("fcb_or_dos_open: file match\n"));
			break;
		}
	}

	if (!fsp) {
		return NT_STATUS_NOT_FOUND;
	}

	/* quite an insane set of semantics ... */
	if (is_executable(fname) &&
	    (fsp->fh->private_options & NTCREATEX_OPTIONS_PRIVATE_DENY_DOS)) {
		DEBUG(10,("fcb_or_dos_open: file fail due to is_executable.\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* We need to duplicate this fsp. */
	dup_file_fsp(req, fsp, access_mask, share_access,
			create_options, fsp_to_dup_into);

	return NT_STATUS_OK;
}

/****************************************************************************
 Open a file with a share mode - old openX method - map into NTCreate.
****************************************************************************/

bool map_open_params_to_ntcreate(const char *fname, int deny_mode, int open_func,
				 uint32 *paccess_mask,
				 uint32 *pshare_mode,
				 uint32 *pcreate_disposition,
				 uint32 *pcreate_options)
{
	uint32 access_mask;
	uint32 share_mode;
	uint32 create_disposition;
	uint32 create_options = FILE_NON_DIRECTORY_FILE;

	DEBUG(10,("map_open_params_to_ntcreate: fname = %s, deny_mode = 0x%x, "
		  "open_func = 0x%x\n",
		  fname, (unsigned int)deny_mode, (unsigned int)open_func ));

	/* Create the NT compatible access_mask. */
	switch (GET_OPENX_MODE(deny_mode)) {
		case DOS_OPEN_EXEC: /* Implies read-only - used to be FILE_READ_DATA */
		case DOS_OPEN_RDONLY:
			access_mask = FILE_GENERIC_READ;
			break;
		case DOS_OPEN_WRONLY:
			access_mask = FILE_GENERIC_WRITE;
			break;
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

static void schedule_defer_open(struct share_mode_lock *lck,
				struct timeval request_time,
				struct smb_request *req)
{
	struct deferred_open_record state;

	/* This is a relative time, added to the absolute
	   request_time value to get the absolute timeout time.
	   Note that if this is the second or greater time we enter
	   this codepath for this particular request mid then
	   request_time is left as the absolute time of the *first*
	   time this request mid was processed. This is what allows
	   the request to eventually time out. */

	struct timeval timeout;

	/* Normally the smbd we asked should respond within
	 * OPLOCK_BREAK_TIMEOUT seconds regardless of whether
	 * the client did, give twice the timeout as a safety
	 * measure here in case the other smbd is stuck
	 * somewhere else. */

	timeout = timeval_set(OPLOCK_BREAK_TIMEOUT*2, 0);

	/* Nothing actually uses state.delayed_for_oplocks
	   but it's handy to differentiate in debug messages
	   between a 30 second delay due to oplock break, and
	   a 1 second delay for share mode conflicts. */

	state.delayed_for_oplocks = True;
	state.id = lck->id;

	if (!request_timed_out(request_time, timeout)) {
		defer_open(lck, request_time, timeout, req, &state);
	}
}

/****************************************************************************
 Work out what access_mask to use from what the client sent us.
****************************************************************************/

static NTSTATUS calculate_access_mask(connection_struct *conn,
					const char *fname,
					bool file_existed,
					uint32_t access_mask,
					uint32_t *access_mask_out)
{
	NTSTATUS status;

	/*
	 * Convert GENERIC bits to specific bits.
	 */

	se_map_generic(&access_mask, &file_generic_mapping);

	/* Calculate MAXIMUM_ALLOWED_ACCESS if requested. */
	if (access_mask & MAXIMUM_ALLOWED_ACCESS) {
		if (file_existed) {

			struct security_descriptor *sd;
			uint32_t access_granted = 0;

			status = SMB_VFS_GET_NT_ACL(conn, fname,
					(OWNER_SECURITY_INFORMATION |
					GROUP_SECURITY_INFORMATION |
					DACL_SECURITY_INFORMATION),&sd);

			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(10, ("calculate_access_mask: Could not get acl "
					"on file %s: %s\n",
					fname,
					nt_errstr(status)));
				return NT_STATUS_ACCESS_DENIED;
			}

			status = smb1_file_se_access_check(sd,
					conn->server_info->ptok,
					access_mask,
					&access_granted);

			TALLOC_FREE(sd);

			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(10, ("calculate_access_mask: Access denied on "
					"file %s: when calculating maximum access\n",
					fname));
				return NT_STATUS_ACCESS_DENIED;
			}

			access_mask = access_granted;
		} else {
			access_mask = FILE_GENERIC_ALL;
		}
	}

	*access_mask_out = access_mask;
	return NT_STATUS_OK;
}

/****************************************************************************
 Open a file with a share mode. Passed in an already created files_struct *.
****************************************************************************/

static NTSTATUS open_file_ntcreate(connection_struct *conn,
			    struct smb_request *req,
			    const char *fname,
			    SMB_STRUCT_STAT *psbuf,
			    uint32 access_mask,		/* access bits (FILE_READ_DATA etc.) */
			    uint32 share_access,	/* share constants (FILE_SHARE_READ etc) */
			    uint32 create_disposition,	/* FILE_OPEN_IF etc. */
			    uint32 create_options,	/* options such as delete on close. */
			    uint32 new_dos_attributes,	/* attributes used for new file. */
			    int oplock_request, 	/* internal Samba oplock codes. */
				 			/* Information (FILE_EXISTS etc.) */
			    int *pinfo,
			    files_struct *fsp)
{
	int flags=0;
	int flags2=0;
	bool file_existed = VALID_STAT(*psbuf);
	bool def_acl = False;
	bool posix_open = False;
	bool new_file_created = False;
	bool clear_ads = false;
	struct file_id id;
	NTSTATUS fsp_open = NT_STATUS_ACCESS_DENIED;
	mode_t new_unx_mode = (mode_t)0;
	mode_t unx_mode = (mode_t)0;
	int info;
	uint32 existing_dos_attributes = 0;
	struct pending_message_list *pml = NULL;
	struct timeval request_time = timeval_zero();
	struct share_mode_lock *lck = NULL;
	uint32 open_access_mask = access_mask;
	NTSTATUS status;
	int ret_flock;
	char *parent_dir;
	const char *newname;

	ZERO_STRUCT(id);

	if (conn->printer) {
		/*
		 * Printers are handled completely differently.
		 * Most of the passed parameters are ignored.
		 */

		if (pinfo) {
			*pinfo = FILE_WAS_CREATED;
		}

		DEBUG(10, ("open_file_ntcreate: printer open fname=%s\n", fname));

		return print_fsp_open(req, conn, fname, req->vuid, fsp, psbuf);
	}

	if (!parent_dirname(talloc_tos(), fname, &parent_dir, &newname)) {
		return NT_STATUS_NO_MEMORY;
	}

	if (new_dos_attributes & FILE_FLAG_POSIX_SEMANTICS) {
		posix_open = True;
		unx_mode = (mode_t)(new_dos_attributes & ~FILE_FLAG_POSIX_SEMANTICS);
		new_dos_attributes = 0;
	} else {
		/* We add aARCH to this as this mode is only used if the file is
		 * created new. */
		unx_mode = unix_mode(conn, new_dos_attributes | aARCH, fname,
				     parent_dir);
	}

	DEBUG(10, ("open_file_ntcreate: fname=%s, dos_attrs=0x%x "
		   "access_mask=0x%x share_access=0x%x "
		   "create_disposition = 0x%x create_options=0x%x "
		   "unix mode=0%o oplock_request=%d\n",
		   fname, new_dos_attributes, access_mask, share_access,
		   create_disposition, create_options, (unsigned int)unx_mode,
		   oplock_request));

	if ((req == NULL) && ((oplock_request & INTERNAL_OPEN_ONLY) == 0)) {
		DEBUG(0, ("No smb request but not an internal only open!\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	/*
	 * Only non-internal opens can be deferred at all
	 */

	if ((req != NULL)
	    && ((pml = get_open_deferred_message(req->mid)) != NULL)) {
		struct deferred_open_record *state =
			(struct deferred_open_record *)pml->private_data.data;

		/* Remember the absolute time of the original
		   request with this mid. We'll use it later to
		   see if this has timed out. */

		request_time = pml->request_time;

		/* Remove the deferred open entry under lock. */
		lck = get_share_mode_lock(talloc_tos(), state->id, NULL, NULL,
					  NULL);
		if (lck == NULL) {
			DEBUG(0, ("could not get share mode lock\n"));
		} else {
			del_deferred_open_entry(lck, req->mid);
			TALLOC_FREE(lck);
		}

		/* Ensure we don't reprocess this message. */
		remove_deferred_open_smb_message(req->mid);
	}

	status = check_name(conn, fname);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!posix_open) {
		new_dos_attributes &= SAMBA_ATTRIBUTES_MASK;
		if (file_existed) {
			existing_dos_attributes = dos_mode(conn, fname, psbuf);
		}
	}

	/* ignore any oplock requests if oplocks are disabled */
	if (!lp_oplocks(SNUM(conn)) || global_client_failed_oplock_break ||
	    IS_VETO_OPLOCK_PATH(conn, fname)) {
		/* Mask off everything except the private Samba bits. */
		oplock_request &= SAMBA_PRIVATE_OPLOCK_MASK;
	}

	/* this is for OS/2 long file names - say we don't support them */
	if (!lp_posix_pathnames() && strstr(fname,".+,;=[].")) {
		/* OS/2 Workplace shell fix may be main code stream in a later
		 * release. */
		DEBUG(5,("open_file_ntcreate: OS/2 long filenames are not "
			 "supported.\n"));
		if (use_nt_status()) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		return NT_STATUS_DOS(ERRDOS, ERRcannotopen);
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
			clear_ads = true;
			break;

		case FILE_OVERWRITE_IF:
			/* If file exists replace/overwrite. If file doesn't
			 * exist create. */
			flags2 |= (O_CREAT | O_TRUNC);
			clear_ads = true;
			break;

		case FILE_OPEN:
			/* If file exists open. If file doesn't exist error. */
			if (!file_existed) {
				DEBUG(5,("open_file_ntcreate: FILE_OPEN "
					 "requested for file %s and file "
					 "doesn't exist.\n", fname ));
				errno = ENOENT;
				return NT_STATUS_OBJECT_NAME_NOT_FOUND;
			}
			break;

		case FILE_OVERWRITE:
			/* If file exists overwrite. If file doesn't exist
			 * error. */
			if (!file_existed) {
				DEBUG(5,("open_file_ntcreate: FILE_OVERWRITE "
					 "requested for file %s and file "
					 "doesn't exist.\n", fname ));
				errno = ENOENT;
				return NT_STATUS_OBJECT_NAME_NOT_FOUND;
			}
			flags2 |= O_TRUNC;
			clear_ads = true;
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
				return map_nt_error_from_unix(errno);
			}
			flags2 |= (O_CREAT|O_EXCL);
			break;

		case FILE_OPEN_IF:
			/* If file exists open. If file doesn't exist
			 * create. */
			flags2 |= O_CREAT;
			break;

		default:
			return NT_STATUS_INVALID_PARAMETER;
	}

	/* We only care about matching attributes on file exists and
	 * overwrite. */

	if (!posix_open && file_existed && ((create_disposition == FILE_OVERWRITE) ||
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
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	status = calculate_access_mask(conn, fname, file_existed,
					access_mask,
					&access_mask); 
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("open_file_ntcreate: calculate_access_mask "
			"on file %s returned %s\n",
			fname,
			nt_errstr(status)));
		return status;
	}

	open_access_mask = access_mask;

	if ((flags2 & O_TRUNC) || (oplock_request & FORCE_OPLOCK_BREAK_TO_NONE)) {
		open_access_mask |= FILE_WRITE_DATA; /* This will cause oplock breaks. */
	}

	DEBUG(10, ("open_file_ntcreate: fname=%s, after mapping "
		   "access_mask=0x%x\n", fname, access_mask ));

	/*
	 * Note that we ignore the append flag as append does not
	 * mean the same thing under DOS and Unix.
	 */

	if ((access_mask & (FILE_WRITE_DATA | FILE_APPEND_DATA)) ||
			(oplock_request & FORCE_OPLOCK_BREAK_TO_NONE)) {
		/* DENY_DOS opens are always underlying read-write on the
		   file handle, no matter what the requested access mask
		    says. */
		if ((create_options & NTCREATEX_OPTIONS_PRIVATE_DENY_DOS) ||
			access_mask & (FILE_READ_ATTRIBUTES|FILE_READ_DATA|FILE_READ_EA|FILE_EXECUTE)) {
			flags = O_RDWR;
		} else {
			flags = O_WRONLY;
		}
	} else {
		flags = O_RDONLY;
	}

	/*
	 * Currently we only look at FILE_WRITE_THROUGH for create options.
	 */

#if defined(O_SYNC)
	if ((create_options & FILE_WRITE_THROUGH) && lp_strict_sync(SNUM(conn))) {
		flags2 |= O_SYNC;
	}
#endif /* O_SYNC */

	if (posix_open && (access_mask & FILE_APPEND_DATA)) {
		flags2 |= O_APPEND;
	}

	if (!posix_open && !CAN_WRITE(conn)) {
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
		errno = EACCES;
		return NT_STATUS_ACCESS_DENIED;
	}

	fsp->file_id = vfs_file_id_from_sbuf(conn, psbuf);
	fsp->share_access = share_access;
	fsp->fh->private_options = create_options;
	fsp->access_mask = open_access_mask; /* We change this to the
					      * requested access_mask after
					      * the open is done. */
	fsp->posix_open = posix_open;

	/* Ensure no SAMBA_PRIVATE bits can be set. */
	fsp->oplock_type = (oplock_request & ~SAMBA_PRIVATE_OPLOCK_MASK);

	if (timeval_is_zero(&request_time)) {
		request_time = fsp->open_time;
	}

	if (file_existed) {
		struct timespec old_write_time = get_mtimespec(psbuf);
		id = vfs_file_id_from_sbuf(conn, psbuf);

		lck = get_share_mode_lock(talloc_tos(), id,
					  conn->connectpath,
					  fname, &old_write_time);

		if (lck == NULL) {
			DEBUG(0, ("Could not get share mode lock\n"));
			return NT_STATUS_SHARING_VIOLATION;
		}

		/* First pass - send break only on batch oplocks. */
		if ((req != NULL)
		    && delay_for_oplocks(lck, fsp, req->mid, 1,
					 oplock_request)) {
			schedule_defer_open(lck, request_time, req);
			TALLOC_FREE(lck);
			return NT_STATUS_SHARING_VIOLATION;
		}

		/* Use the client requested access mask here, not the one we
		 * open with. */
		status = open_mode_check(conn, fname, lck,
					 access_mask, share_access,
					 create_options, &file_existed);

		if (NT_STATUS_IS_OK(status)) {
			/* We might be going to allow this open. Check oplock
			 * status again. */
			/* Second pass - send break for both batch or
			 * exclusive oplocks. */
			if ((req != NULL)
			     && delay_for_oplocks(lck, fsp, req->mid, 2,
						  oplock_request)) {
				schedule_defer_open(lck, request_time, req);
				TALLOC_FREE(lck);
				return NT_STATUS_SHARING_VIOLATION;
			}
		}

		if (NT_STATUS_EQUAL(status, NT_STATUS_DELETE_PENDING)) {
			/* DELETE_PENDING is not deferred for a second */
			TALLOC_FREE(lck);
			return status;
		}

		if (!NT_STATUS_IS_OK(status)) {
			uint32 can_access_mask;
			bool can_access = True;

			SMB_ASSERT(NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION));

			/* Check if this can be done with the deny_dos and fcb
			 * calls. */
			if (create_options &
			    (NTCREATEX_OPTIONS_PRIVATE_DENY_DOS|
			     NTCREATEX_OPTIONS_PRIVATE_DENY_FCB)) {
				if (req == NULL) {
					DEBUG(0, ("DOS open without an SMB "
						  "request!\n"));
					TALLOC_FREE(lck);
					return NT_STATUS_INTERNAL_ERROR;
				}

				/* Use the client requested access mask here,
				 * not the one we open with. */
				status = fcb_or_dos_open(req,
							conn,
							fsp,
							fname,
							id,
							req->smbpid,
							req->vuid,
							access_mask,
							share_access,
							create_options);

				if (NT_STATUS_IS_OK(status)) {
					TALLOC_FREE(lck);
					if (pinfo) {
						*pinfo = FILE_WAS_OPENED;
					}
					return NT_STATUS_OK;
				}
			}

			/*
			 * This next line is a subtlety we need for
			 * MS-Access. If a file open will fail due to share
			 * permissions and also for security (access) reasons,
			 * we need to return the access failed error, not the
			 * share error. We can't open the file due to kernel
			 * oplock deadlock (it's possible we failed above on
			 * the open_mode_check()) so use a userspace check.
			 */

			if (flags & O_RDWR) {
				can_access_mask = FILE_READ_DATA|FILE_WRITE_DATA;
			} else if (flags & O_WRONLY) {
				can_access_mask = FILE_WRITE_DATA;
			} else {
				can_access_mask = FILE_READ_DATA;
			}

			if (((can_access_mask & FILE_WRITE_DATA) && !CAN_WRITE(conn)) ||
			    !can_access_file_data(conn,fname,psbuf,can_access_mask)) {
				can_access = False;
			}

			/*
			 * If we're returning a share violation, ensure we
			 * cope with the braindead 1 second delay.
			 */

			if (!(oplock_request & INTERNAL_OPEN_ONLY) &&
			    lp_defer_sharing_violations()) {
				struct timeval timeout;
				struct deferred_open_record state;
				int timeout_usecs;

				/* this is a hack to speed up torture tests
				   in 'make test' */
				timeout_usecs = lp_parm_int(SNUM(conn),
							    "smbd","sharedelay",
							    SHARING_VIOLATION_USEC_WAIT);

				/* This is a relative time, added to the absolute
				   request_time value to get the absolute timeout time.
				   Note that if this is the second or greater time we enter
				   this codepath for this particular request mid then
				   request_time is left as the absolute time of the *first*
				   time this request mid was processed. This is what allows
				   the request to eventually time out. */

				timeout = timeval_set(0, timeout_usecs);

				/* Nothing actually uses state.delayed_for_oplocks
				   but it's handy to differentiate in debug messages
				   between a 30 second delay due to oplock break, and
				   a 1 second delay for share mode conflicts. */

				state.delayed_for_oplocks = False;
				state.id = id;

				if ((req != NULL)
				    && !request_timed_out(request_time,
							  timeout)) {
					defer_open(lck, request_time, timeout,
						   req, &state);
				}
			}

			TALLOC_FREE(lck);
			if (can_access) {
				/*
				 * We have detected a sharing violation here
				 * so return the correct error code
				 */
				status = NT_STATUS_SHARING_VIOLATION;
			} else {
				status = NT_STATUS_ACCESS_DENIED;
			}
			return status;
		}

		/*
		 * We exit this block with the share entry *locked*.....
		 */
	}

	SMB_ASSERT(!file_existed || (lck != NULL));

	/*
	 * Ensure we pay attention to default ACLs on directories if required.
	 */

        if ((flags2 & O_CREAT) && lp_inherit_acls(SNUM(conn)) &&
	    (def_acl = directory_has_default_acl(conn, parent_dir))) {
		unx_mode = 0777;
	}

	DEBUG(4,("calling open_file with flags=0x%X flags2=0x%X mode=0%o, "
		"access_mask = 0x%x, open_access_mask = 0x%x\n",
		 (unsigned int)flags, (unsigned int)flags2,
		 (unsigned int)unx_mode, (unsigned int)access_mask,
		 (unsigned int)open_access_mask));

	/*
	 * open_file strips any O_TRUNC flags itself.
	 */

	fsp_open = open_file(fsp, conn, req, parent_dir, newname, fname, psbuf,
			     flags|flags2, unx_mode, access_mask,
			     open_access_mask);

	if (!NT_STATUS_IS_OK(fsp_open)) {
		if (lck != NULL) {
			TALLOC_FREE(lck);
		}
		return fsp_open;
	}

	if (!file_existed) {
		struct timespec old_write_time = get_mtimespec(psbuf);
		/*
		 * Deal with the race condition where two smbd's detect the
		 * file doesn't exist and do the create at the same time. One
		 * of them will win and set a share mode, the other (ie. this
		 * one) should check if the requested share mode for this
		 * create is allowed.
		 */

		/*
		 * Now the file exists and fsp is successfully opened,
		 * fsp->dev and fsp->inode are valid and should replace the
		 * dev=0,inode=0 from a non existent file. Spotted by
		 * Nadav Danieli <nadavd@exanet.com>. JRA.
		 */

		id = fsp->file_id;

		lck = get_share_mode_lock(talloc_tos(), id,
					  conn->connectpath,
					  fname, &old_write_time);

		if (lck == NULL) {
			DEBUG(0, ("open_file_ntcreate: Could not get share "
				  "mode lock for %s\n", fname));
			fd_close(fsp);
			return NT_STATUS_SHARING_VIOLATION;
		}

		/* First pass - send break only on batch oplocks. */
		if ((req != NULL)
		    && delay_for_oplocks(lck, fsp, req->mid, 1,
					 oplock_request)) {
			schedule_defer_open(lck, request_time, req);
			TALLOC_FREE(lck);
			fd_close(fsp);
			return NT_STATUS_SHARING_VIOLATION;
		}

		status = open_mode_check(conn, fname, lck,
					 access_mask, share_access,
					 create_options, &file_existed);

		if (NT_STATUS_IS_OK(status)) {
			/* We might be going to allow this open. Check oplock
			 * status again. */
			/* Second pass - send break for both batch or
			 * exclusive oplocks. */
			if ((req != NULL)
			    && delay_for_oplocks(lck, fsp, req->mid, 2,
						 oplock_request)) {
				schedule_defer_open(lck, request_time, req);
				TALLOC_FREE(lck);
				fd_close(fsp);
				return NT_STATUS_SHARING_VIOLATION;
			}
		}

		if (!NT_STATUS_IS_OK(status)) {
			struct deferred_open_record state;

			fd_close(fsp);

			state.delayed_for_oplocks = False;
			state.id = id;

			/* Do it all over again immediately. In the second
			 * round we will find that the file existed and handle
			 * the DELETE_PENDING and FCB cases correctly. No need
			 * to duplicate the code here. Essentially this is a
			 * "goto top of this function", but don't tell
			 * anybody... */

			if (req != NULL) {
				defer_open(lck, request_time, timeval_zero(),
					   req, &state);
			}
			TALLOC_FREE(lck);
			return status;
		}

		/*
		 * We exit this block with the share entry *locked*.....
		 */

	}

	SMB_ASSERT(lck != NULL);

	/* Delete streams if create_disposition requires it */
	if (file_existed && clear_ads && !is_ntfs_stream_name(fname)) {
		status = delete_all_streams(conn, fname);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(lck);
			fd_close(fsp);
			return status;
		}
	}

	/* note that we ignore failure for the following. It is
           basically a hack for NFS, and NFS will never set one of
           these only read them. Nobody but Samba can ever set a deny
           mode and we have already checked our more authoritative
           locking database for permission to set this deny mode. If
           the kernel refuses the operations then the kernel is wrong.
	   note that GPFS supports it as well - jmcd */

	if (fsp->fh->fd != -1) {
		ret_flock = SMB_VFS_KERNEL_FLOCK(fsp, share_access);
		if(ret_flock == -1 ){

			TALLOC_FREE(lck);
			fd_close(fsp);

			return NT_STATUS_SHARING_VIOLATION;
		}
	}

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
		if ((SMB_VFS_FTRUNCATE(fsp, 0) == -1) ||
		    (SMB_VFS_FSTAT(fsp, psbuf)==-1)) {
			status = map_nt_error_from_unix(errno);
			TALLOC_FREE(lck);
			fd_close(fsp);
			return status;
		}
	}

	/* Record the options we were opened with. */
	fsp->share_access = share_access;
	fsp->fh->private_options = create_options;
	/*
	 * According to Samba4, SEC_FILE_READ_ATTRIBUTE is always granted,
	 */
	fsp->access_mask = access_mask | FILE_READ_ATTRIBUTES;

	if (file_existed) {
		/* stat opens on existing files don't get oplocks. */
		if (is_stat_open(open_access_mask)) {
			fsp->oplock_type = NO_OPLOCK;
		}

		if (!(flags2 & O_TRUNC)) {
			info = FILE_WAS_OPENED;
		} else {
			info = FILE_WAS_OVERWRITTEN;
		}
	} else {
		info = FILE_WAS_CREATED;
	}

	if (pinfo) {
		*pinfo = info;
	}

	/*
	 * Setup the oplock info in both the shared memory and
	 * file structs.
	 */

	if (!set_file_oplock(fsp, fsp->oplock_type)) {
		/* Could not get the kernel oplock */
		fsp->oplock_type = NO_OPLOCK;
	}

	if (info == FILE_WAS_OVERWRITTEN || info == FILE_WAS_CREATED || info == FILE_WAS_SUPERSEDED) {
		new_file_created = True;
	}

	set_share_mode(lck, fsp, conn->server_info->utok.uid, 0,
		       fsp->oplock_type);

	/* Handle strange delete on close create semantics. */
	if (create_options & FILE_DELETE_ON_CLOSE) {

		status = can_set_delete_on_close(fsp, True, new_dos_attributes);

		if (!NT_STATUS_IS_OK(status)) {
			/* Remember to delete the mode we just added. */
			del_share_mode(lck, fsp);
			TALLOC_FREE(lck);
			fd_close(fsp);
			return status;
		}
		/* Note that here we set the *inital* delete on close flag,
		   not the regular one. The magic gets handled in close. */
		fsp->initial_delete_on_close = True;
	}

	if (new_file_created) {
		/* Files should be initially set as archive */
		if (lp_map_archive(SNUM(conn)) ||
		    lp_store_dos_attributes(SNUM(conn))) {
			if (!posix_open) {
				SMB_STRUCT_STAT tmp_sbuf;
				SET_STAT_INVALID(tmp_sbuf);
				if (file_set_dosmode(
					    conn, fname,
					    new_dos_attributes | aARCH,
					    &tmp_sbuf, parent_dir,
					    true) == 0) {
					unx_mode = tmp_sbuf.st_mode;
				}
			}
		}
	}

	/*
	 * Take care of inherited ACLs on created files - if default ACL not
	 * selected.
	 */

	if (!posix_open && !file_existed && !def_acl) {

		int saved_errno = errno; /* We might get ENOSYS in the next
					  * call.. */

		if (SMB_VFS_FCHMOD_ACL(fsp, unx_mode) == -1 &&
		    errno == ENOSYS) {
			errno = saved_errno; /* Ignore ENOSYS */
		}

	} else if (new_unx_mode) {

		int ret = -1;

		/* Attributes need changing. File already existed. */

		{
			int saved_errno = errno; /* We might get ENOSYS in the
						  * next call.. */
			ret = SMB_VFS_FCHMOD_ACL(fsp, new_unx_mode);

			if (ret == -1 && errno == ENOSYS) {
				errno = saved_errno; /* Ignore ENOSYS */
			} else {
				DEBUG(5, ("open_file_ntcreate: reset "
					  "attributes of file %s to 0%o\n",
					  fname, (unsigned int)new_unx_mode));
				ret = 0; /* Don't do the fchmod below. */
			}
		}

		if ((ret == -1) &&
		    (SMB_VFS_FCHMOD(fsp, new_unx_mode) == -1))
			DEBUG(5, ("open_file_ntcreate: failed to reset "
				  "attributes of file %s to 0%o\n",
				  fname, (unsigned int)new_unx_mode));
	}

	/* If this is a successful open, we must remove any deferred open
	 * records. */
	if (req != NULL) {
		del_deferred_open_entry(lck, req->mid);
	}
	TALLOC_FREE(lck);

	return NT_STATUS_OK;
}


/****************************************************************************
 Open a file for for write to ensure that we can fchmod it.
****************************************************************************/

NTSTATUS open_file_fchmod(struct smb_request *req, connection_struct *conn,
			  const char *fname,
			  SMB_STRUCT_STAT *psbuf, files_struct **result)
{
	files_struct *fsp = NULL;
	NTSTATUS status;

	if (!VALID_STAT(*psbuf)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = file_new(req, conn, &fsp);
	if(!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		NULL,					/* req */
		0,					/* root_dir_fid */
		fname,					/* fname */
		0,					/* create_file_flags */
		FILE_WRITE_DATA,			/* access_mask */
		(FILE_SHARE_READ | FILE_SHARE_WRITE |	/* share_access */
		    FILE_SHARE_DELETE),
		FILE_OPEN,				/* create_disposition*/
		0,					/* create_options */
		0,					/* file_attributes */
		0,					/* oplock_request */
		0,					/* allocation_size */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		NULL,					/* pinfo */
		psbuf);					/* psbuf */

	/*
	 * This is not a user visible file open.
	 * Don't set a share mode.
	 */

	if (!NT_STATUS_IS_OK(status)) {
		file_free(req, fsp);
		return status;
	}

	*result = fsp;
	return NT_STATUS_OK;
}

/****************************************************************************
 Close the fchmod file fd - ensure no locks are lost.
****************************************************************************/

NTSTATUS close_file_fchmod(struct smb_request *req, files_struct *fsp)
{
	NTSTATUS status = fd_close(fsp);
	file_free(req, fsp);
	return status;
}

static NTSTATUS mkdir_internal(connection_struct *conn,
				const char *name,
				uint32 file_attributes,
				SMB_STRUCT_STAT *psbuf)
{
	mode_t mode;
	char *parent_dir;
	const char *dirname;
	NTSTATUS status;
	bool posix_open = false;

	if(!CAN_WRITE(conn)) {
		DEBUG(5,("mkdir_internal: failing create on read-only share "
			 "%s\n", lp_servicename(SNUM(conn))));
		return NT_STATUS_ACCESS_DENIED;
	}

	status = check_name(conn, name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!parent_dirname(talloc_tos(), name, &parent_dir, &dirname)) {
		return NT_STATUS_NO_MEMORY;
	}

	if (file_attributes & FILE_FLAG_POSIX_SEMANTICS) {
		posix_open = true;
		mode = (mode_t)(file_attributes & ~FILE_FLAG_POSIX_SEMANTICS);
	} else {
		mode = unix_mode(conn, aDIR, name, parent_dir);
	}

	if (SMB_VFS_MKDIR(conn, name, mode) != 0) {
		return map_nt_error_from_unix(errno);
	}

	/* Ensure we're checking for a symlink here.... */
	/* We don't want to get caught by a symlink racer. */

	if (SMB_VFS_LSTAT(conn, name, psbuf) == -1) {
		DEBUG(2, ("Could not stat directory '%s' just created: %s\n",
			  name, strerror(errno)));
		return map_nt_error_from_unix(errno);
	}

	if (!S_ISDIR(psbuf->st_mode)) {
		DEBUG(0, ("Directory just '%s' created is not a directory\n",
			  name));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (lp_store_dos_attributes(SNUM(conn))) {
		if (!posix_open) {
			file_set_dosmode(conn, name,
				 file_attributes | aDIR, NULL,
				 parent_dir,
				 true);
		}
	}

	if (lp_inherit_perms(SNUM(conn))) {
		inherit_access_posix_acl(conn, parent_dir, name, mode);
	}

	if (!(file_attributes & FILE_FLAG_POSIX_SEMANTICS)) {
		/*
		 * Check if high bits should have been set,
		 * then (if bits are missing): add them.
		 * Consider bits automagically set by UNIX, i.e. SGID bit from parent
		 * dir.
		 */
		if (mode & ~(S_IRWXU|S_IRWXG|S_IRWXO) && (mode & ~psbuf->st_mode)) {
			SMB_VFS_CHMOD(conn, name,
				      psbuf->st_mode | (mode & ~psbuf->st_mode));
		}
	}

	/* Change the owner if required. */
	if (lp_inherit_owner(SNUM(conn))) {
		change_dir_owner_to_parent(conn, parent_dir, name, psbuf);
	}

	notify_fname(conn, NOTIFY_ACTION_ADDED, FILE_NOTIFY_CHANGE_DIR_NAME,
		     name);

	return NT_STATUS_OK;
}

/****************************************************************************
 Open a directory from an NT SMB call.
****************************************************************************/

static NTSTATUS open_directory(connection_struct *conn,
			       struct smb_request *req,
			       const char *fname,
			       SMB_STRUCT_STAT *psbuf,
			       uint32 access_mask,
			       uint32 share_access,
			       uint32 create_disposition,
			       uint32 create_options,
			       uint32 file_attributes,
			       int *pinfo,
			       files_struct **result)
{
	files_struct *fsp = NULL;
	bool dir_existed = VALID_STAT(*psbuf) ? True : False;
	struct share_mode_lock *lck = NULL;
	NTSTATUS status;
	struct timespec mtimespec;
	int info = 0;

	DEBUG(5,("open_directory: opening directory %s, access_mask = 0x%x, "
		 "share_access = 0x%x create_options = 0x%x, "
		 "create_disposition = 0x%x, file_attributes = 0x%x\n",
		 fname,
		 (unsigned int)access_mask,
		 (unsigned int)share_access,
		 (unsigned int)create_options,
		 (unsigned int)create_disposition,
		 (unsigned int)file_attributes));

	if (!(file_attributes & FILE_FLAG_POSIX_SEMANTICS) &&
			(conn->fs_capabilities & FILE_NAMED_STREAMS) &&
			is_ntfs_stream_name(fname)) {
		DEBUG(2, ("open_directory: %s is a stream name!\n", fname));
		return NT_STATUS_NOT_A_DIRECTORY;
	}

	status = calculate_access_mask(conn, fname, dir_existed,
					access_mask,
					&access_mask); 
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("open_directory: calculate_access_mask "
			"on file %s returned %s\n",
			fname,
			nt_errstr(status)));
		return status;
	}

	/* We need to support SeSecurityPrivilege for this. */
	if (access_mask & SEC_FLAG_SYSTEM_SECURITY) {
		DEBUG(10, ("open_directory: open on %s "
			"failed - SEC_FLAG_SYSTEM_SECURITY denied.\n",
			fname));
		return NT_STATUS_PRIVILEGE_NOT_HELD;
	}

	switch( create_disposition ) {
		case FILE_OPEN:

			info = FILE_WAS_OPENED;

			/*
			 * We want to follow symlinks here.
			 */

			if (SMB_VFS_STAT(conn, fname, psbuf) != 0) {
				return map_nt_error_from_unix(errno);
			}
				
			break;

		case FILE_CREATE:

			/* If directory exists error. If directory doesn't
			 * exist create. */

			status = mkdir_internal(conn,
						fname,
						file_attributes,
						psbuf);

			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(2, ("open_directory: unable to create "
					  "%s. Error was %s\n", fname,
					  nt_errstr(status)));
				return status;
			}

			info = FILE_WAS_CREATED;
			break;

		case FILE_OPEN_IF:
			/*
			 * If directory exists open. If directory doesn't
			 * exist create.
			 */

			status = mkdir_internal(conn,
						fname,
						file_attributes,
						psbuf);

			if (NT_STATUS_IS_OK(status)) {
				info = FILE_WAS_CREATED;
			}

			if (NT_STATUS_EQUAL(status,
					    NT_STATUS_OBJECT_NAME_COLLISION)) {
				info = FILE_WAS_OPENED;
				status = NT_STATUS_OK;
			}
				
			break;

		case FILE_SUPERSEDE:
		case FILE_OVERWRITE:
		case FILE_OVERWRITE_IF:
		default:
			DEBUG(5,("open_directory: invalid create_disposition "
				 "0x%x for directory %s\n",
				 (unsigned int)create_disposition, fname));
			return NT_STATUS_INVALID_PARAMETER;
	}

	if(!S_ISDIR(psbuf->st_mode)) {
		DEBUG(5,("open_directory: %s is not a directory !\n",
			 fname ));
		return NT_STATUS_NOT_A_DIRECTORY;
	}

	if (info == FILE_WAS_OPENED) {
		uint32_t access_granted = 0;
		status = check_open_rights(conn,
					fname,
					access_mask,
					&access_granted);

		/* Were we trying to do a directory open
		 * for delete and didn't get DELETE
		 * access (only) ? Check if the
		 * directory allows DELETE_CHILD.
		 * See here:
		 * http://blogs.msdn.com/oldnewthing/archive/2004/06/04/148426.aspx
		 * for details. */

		if ((NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) &&
				(access_mask & DELETE_ACCESS) &&
				(access_granted == DELETE_ACCESS) &&
				can_delete_file_in_directory(conn, fname))) {
			DEBUG(10,("open_directory: overrode ACCESS_DENIED "
				"on directory %s\n",
				fname ));
			status = NT_STATUS_OK;
		}

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("open_directory: check_open_rights on "
				"file %s failed with %s\n",
				fname,
				nt_errstr(status)));
			return status;
		}
	}

	status = file_new(req, conn, &fsp);
	if(!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * Setup the files_struct for it.
	 */
	
	fsp->mode = psbuf->st_mode;
	fsp->file_id = vfs_file_id_from_sbuf(conn, psbuf);
	fsp->vuid = req ? req->vuid : UID_FIELD_INVALID;
	fsp->file_pid = req ? req->smbpid : 0;
	fsp->can_lock = False;
	fsp->can_read = False;
	fsp->can_write = False;

	fsp->share_access = share_access;
	fsp->fh->private_options = create_options;
	/*
	 * According to Samba4, SEC_FILE_READ_ATTRIBUTE is always granted,
	 */
	fsp->access_mask = access_mask | FILE_READ_ATTRIBUTES;
	fsp->print_file = False;
	fsp->modified = False;
	fsp->oplock_type = NO_OPLOCK;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->is_directory = True;
	fsp->posix_open = (file_attributes & FILE_FLAG_POSIX_SEMANTICS) ? True : False;

	string_set(&fsp->fsp_name,fname);

	mtimespec = get_mtimespec(psbuf);

	lck = get_share_mode_lock(talloc_tos(), fsp->file_id,
				  conn->connectpath,
				  fname, &mtimespec);

	if (lck == NULL) {
		DEBUG(0, ("open_directory: Could not get share mode lock for %s\n", fname));
		file_free(req, fsp);
		return NT_STATUS_SHARING_VIOLATION;
	}

	status = open_mode_check(conn, fname, lck,
				access_mask, share_access,
				create_options, &dir_existed);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(lck);
		file_free(req, fsp);
		return status;
	}

	set_share_mode(lck, fsp, conn->server_info->utok.uid, 0, NO_OPLOCK);

	/* For directories the delete on close bit at open time seems
	   always to be honored on close... See test 19 in Samba4 BASE-DELETE. */
	if (create_options & FILE_DELETE_ON_CLOSE) {
		status = can_set_delete_on_close(fsp, True, 0);
		if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, NT_STATUS_DIRECTORY_NOT_EMPTY)) {
			TALLOC_FREE(lck);
			file_free(req, fsp);
			return status;
		}

		if (NT_STATUS_IS_OK(status)) {
			/* Note that here we set the *inital* delete on close flag,
			   not the regular one. The magic gets handled in close. */
			fsp->initial_delete_on_close = True;
		}
	}

	TALLOC_FREE(lck);

	if (pinfo) {
		*pinfo = info;
	}

	*result = fsp;
	return NT_STATUS_OK;
}

NTSTATUS create_directory(connection_struct *conn, struct smb_request *req, const char *directory)
{
	NTSTATUS status;
	SMB_STRUCT_STAT sbuf;
	files_struct *fsp;

	SET_STAT_INVALID(sbuf);
	
	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		0,					/* root_dir_fid */
		directory,				/* fname */
		0,					/* create_file_flags */
		FILE_READ_ATTRIBUTES,			/* access_mask */
		FILE_SHARE_NONE,			/* share_access */
		FILE_CREATE,				/* create_disposition*/
		FILE_DIRECTORY_FILE,			/* create_options */
		FILE_ATTRIBUTE_DIRECTORY,		/* file_attributes */
		0,					/* oplock_request */
		0,					/* allocation_size */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		NULL,					/* pinfo */
		&sbuf);					/* psbuf */

	if (NT_STATUS_IS_OK(status)) {
		close_file(req, fsp, NORMAL_CLOSE);
	}

	return status;
}

/****************************************************************************
 Receive notification that one of our open files has been renamed by another
 smbd process.
****************************************************************************/

void msg_file_was_renamed(struct messaging_context *msg,
			  void *private_data,
			  uint32_t msg_type,
			  struct server_id server_id,
			  DATA_BLOB *data)
{
	files_struct *fsp;
	char *frm = (char *)data->data;
	struct file_id id;
	const char *sharepath;
	const char *newname;
	size_t sp_len;

	if (data->data == NULL
	    || data->length < MSG_FILE_RENAMED_MIN_SIZE + 2) {
                DEBUG(0, ("msg_file_was_renamed: Got invalid msg len %d\n",
			  (int)data->length));
                return;
        }

	/* Unpack the message. */
	pull_file_id_24(frm, &id);
	sharepath = &frm[24];
	newname = sharepath + strlen(sharepath) + 1;
	sp_len = strlen(sharepath);

	DEBUG(10,("msg_file_was_renamed: Got rename message for sharepath %s, new name %s, "
		"file_id %s\n",
		  sharepath, newname, file_id_string_tos(&id)));

	for(fsp = file_find_di_first(id); fsp; fsp = file_find_di_next(fsp)) {
		if (memcmp(fsp->conn->connectpath, sharepath, sp_len) == 0) {
	                DEBUG(10,("msg_file_was_renamed: renaming file fnum %d from %s -> %s\n",
				fsp->fnum, fsp->fsp_name, newname ));
			string_set(&fsp->fsp_name, newname);
		} else {
			/* TODO. JRA. */
			/* Now we have the complete path we can work out if this is
			   actually within this share and adjust newname accordingly. */
	                DEBUG(10,("msg_file_was_renamed: share mismatch (sharepath %s "
				"not sharepath %s) "
				"fnum %d from %s -> %s\n",
				fsp->conn->connectpath,
				sharepath,
				fsp->fnum,
				fsp->fsp_name,
				newname ));
		}
        }
}

struct case_semantics_state {
	connection_struct *conn;
	bool case_sensitive;
	bool case_preserve;
	bool short_case_preserve;
};

/****************************************************************************
 Restore case semantics.
****************************************************************************/
static int restore_case_semantics(struct case_semantics_state *state)
{
	state->conn->case_sensitive = state->case_sensitive;
	state->conn->case_preserve = state->case_preserve;
	state->conn->short_case_preserve = state->short_case_preserve;
	return 0;
}

/****************************************************************************
 Save case semantics.
****************************************************************************/
struct case_semantics_state *set_posix_case_semantics(TALLOC_CTX *mem_ctx,
						      connection_struct *conn)
{
	struct case_semantics_state *result;

	if (!(result = talloc(mem_ctx, struct case_semantics_state))) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	result->conn = conn;
	result->case_sensitive = conn->case_sensitive;
	result->case_preserve = conn->case_preserve;
	result->short_case_preserve = conn->short_case_preserve;

	/* Set to POSIX. */
	conn->case_sensitive = True;
	conn->case_preserve = True;
	conn->short_case_preserve = True;

	talloc_set_destructor(result, restore_case_semantics);

	return result;
}

/*
 * If a main file is opened for delete, all streams need to be checked for
 * !FILE_SHARE_DELETE. Do this by opening with DELETE_ACCESS.
 * If that works, delete them all by setting the delete on close and close.
 */

NTSTATUS open_streams_for_delete(connection_struct *conn,
					const char *fname)
{
	struct stream_struct *stream_info;
	files_struct **streams;
	int i;
	unsigned int num_streams;
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;

	status = SMB_VFS_STREAMINFO(conn, NULL, fname, talloc_tos(),
				    &num_streams, &stream_info);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_IMPLEMENTED)
	    || NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		DEBUG(10, ("no streams around\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("SMB_VFS_STREAMINFO failed: %s\n",
			   nt_errstr(status)));
		goto fail;
	}

	DEBUG(10, ("open_streams_for_delete found %d streams\n",
		   num_streams));

	if (num_streams == 0) {
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	streams = TALLOC_ARRAY(talloc_tos(), files_struct *, num_streams);
	if (streams == NULL) {
		DEBUG(0, ("talloc failed\n"));
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	for (i=0; i<num_streams; i++) {
		char *streamname;

		if (strequal(stream_info[i].name, "::$DATA")) {
			streams[i] = NULL;
			continue;
		}

		streamname = talloc_asprintf(talloc_tos(), "%s%s", fname,
					     stream_info[i].name);

		if (streamname == NULL) {
			DEBUG(0, ("talloc_aprintf failed\n"));
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}

		status = SMB_VFS_CREATE_FILE(
			 conn,			/* conn */
			 NULL,			/* req */
			 0,			/* root_dir_fid */
			 streamname,		/* fname */
			 0,			/* create_file_flags */
			 DELETE_ACCESS,		/* access_mask */
			 (FILE_SHARE_READ |	/* share_access */
			     FILE_SHARE_WRITE | FILE_SHARE_DELETE),
			 FILE_OPEN,		/* create_disposition*/
			 NTCREATEX_OPTIONS_PRIVATE_STREAM_DELETE, /* create_options */
			 FILE_ATTRIBUTE_NORMAL,	/* file_attributes */
			 0,			/* oplock_request */
			 0,			/* allocation_size */
			 NULL,			/* sd */
			 NULL,			/* ea_list */
			 &streams[i],		/* result */
			 NULL,			/* pinfo */
			 NULL);			/* psbuf */

		TALLOC_FREE(streamname);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("Could not open stream %s: %s\n",
				   streamname, nt_errstr(status)));
			break;
		}
	}

	/*
	 * don't touch the variable "status" beyond this point :-)
	 */

	for (i -= 1 ; i >= 0; i--) {
		if (streams[i] == NULL) {
			continue;
		}

		DEBUG(10, ("Closing stream # %d, %s\n", i,
			   streams[i]->fsp_name));
		close_file(NULL, streams[i], NORMAL_CLOSE);
	}

 fail:
	TALLOC_FREE(frame);
	return status;
}

/*
 * Wrapper around open_file_ntcreate and open_directory
 */

static NTSTATUS create_file_unixpath(connection_struct *conn,
				     struct smb_request *req,
				     const char *fname,
				     uint32_t access_mask,
				     uint32_t share_access,
				     uint32_t create_disposition,
				     uint32_t create_options,
				     uint32_t file_attributes,
				     uint32_t oplock_request,
				     uint64_t allocation_size,
				     struct security_descriptor *sd,
				     struct ea_list *ea_list,

				     files_struct **result,
				     int *pinfo,
				     SMB_STRUCT_STAT *psbuf)
{
	SMB_STRUCT_STAT sbuf;
	int info = FILE_WAS_OPENED;
	files_struct *base_fsp = NULL;
	files_struct *fsp = NULL;
	NTSTATUS status;

	DEBUG(10,("create_file_unixpath: access_mask = 0x%x "
		  "file_attributes = 0x%x, share_access = 0x%x, "
		  "create_disposition = 0x%x create_options = 0x%x "
		  "oplock_request = 0x%x ea_list = 0x%p, sd = 0x%p, "
		  "fname = %s\n",
		  (unsigned int)access_mask,
		  (unsigned int)file_attributes,
		  (unsigned int)share_access,
		  (unsigned int)create_disposition,
		  (unsigned int)create_options,
		  (unsigned int)oplock_request,
		  ea_list, sd, fname));

	if (create_options & FILE_OPEN_BY_FILE_ID) {
		status = NT_STATUS_NOT_SUPPORTED;
		goto fail;
	}

	if (create_options & NTCREATEX_OPTIONS_INVALID_PARAM_MASK) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (req == NULL) {
		oplock_request |= INTERNAL_OPEN_ONLY;
	}

	if (psbuf != NULL) {
		sbuf = *psbuf;
	}
	else {
		if (SMB_VFS_STAT(conn, fname, &sbuf) == -1) {
			SET_STAT_INVALID(sbuf);
		}
	}

	if ((conn->fs_capabilities & FILE_NAMED_STREAMS)
	    && (access_mask & DELETE_ACCESS)
	    && !is_ntfs_stream_name(fname)) {
		/*
		 * We can't open a file with DELETE access if any of the
		 * streams is open without FILE_SHARE_DELETE
		 */
		status = open_streams_for_delete(conn, fname);

		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	/* This is the correct thing to do (check every time) but can_delete
	 * is expensive (it may have to read the parent directory
	 * permissions). So for now we're not doing it unless we have a strong
	 * hint the client is really going to delete this file. If the client
	 * is forcing FILE_CREATE let the filesystem take care of the
	 * permissions. */

	/* Setting FILE_SHARE_DELETE is the hint. */

	if (lp_acl_check_permissions(SNUM(conn))
	    && (create_disposition != FILE_CREATE)
	    && (share_access & FILE_SHARE_DELETE)
	    && (access_mask & DELETE_ACCESS)
	    && (!(can_delete_file_in_directory(conn, fname) ||
		 can_access_file_acl(conn, fname, DELETE_ACCESS)))) {
		status = NT_STATUS_ACCESS_DENIED;
		DEBUG(10,("create_file_unixpath: open file %s "
			"for delete ACCESS_DENIED\n", fname ));
		goto fail;
	}

#if 0
	/* We need to support SeSecurityPrivilege for this. */
	if ((access_mask & SEC_FLAG_SYSTEM_SECURITY) &&
	    !user_has_privileges(current_user.nt_user_token,
				 &se_security)) {
		status = NT_STATUS_PRIVILEGE_NOT_HELD;
		goto fail;
	}
#else
	/* We need to support SeSecurityPrivilege for this. */
	if (access_mask & SEC_FLAG_SYSTEM_SECURITY) {
		status = NT_STATUS_PRIVILEGE_NOT_HELD;
		goto fail;
	}
	/* Don't allow a SACL set from an NTtrans create until we
	 * support SeSecurityPrivilege. */
	if (!VALID_STAT(sbuf) &&
			lp_nt_acl_support(SNUM(conn)) &&
			sd && (sd->sacl != NULL)) {
		status = NT_STATUS_PRIVILEGE_NOT_HELD;
		goto fail;
	}
#endif

	if ((conn->fs_capabilities & FILE_NAMED_STREAMS)
	    && is_ntfs_stream_name(fname)
	    && (!(create_options & NTCREATEX_OPTIONS_PRIVATE_STREAM_DELETE))) {
		char *base;
		uint32 base_create_disposition;

		if (create_options & FILE_DIRECTORY_FILE) {
			status = NT_STATUS_NOT_A_DIRECTORY;
			goto fail;
		}

		status = split_ntfs_stream_name(talloc_tos(), fname,
						&base, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("create_file_unixpath: "
				"split_ntfs_stream_name failed: %s\n",
				nt_errstr(status)));
			goto fail;
		}

		SMB_ASSERT(!is_ntfs_stream_name(base));	/* paranoia.. */

		switch (create_disposition) {
		case FILE_OPEN:
			base_create_disposition = FILE_OPEN;
			break;
		default:
			base_create_disposition = FILE_OPEN_IF;
			break;
		}

		status = create_file_unixpath(conn, NULL, base, 0,
					      FILE_SHARE_READ
					      | FILE_SHARE_WRITE
					      | FILE_SHARE_DELETE,
					      base_create_disposition,
					      0, 0, 0, 0, NULL, NULL,
					      &base_fsp, NULL, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("create_file_unixpath for base %s failed: "
				   "%s\n", base, nt_errstr(status)));
			goto fail;
		}
		/* we don't need to low level fd */
		fd_close(base_fsp);
	}

	/*
	 * If it's a request for a directory open, deal with it separately.
	 */

	if (create_options & FILE_DIRECTORY_FILE) {

		if (create_options & FILE_NON_DIRECTORY_FILE) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto fail;
		}

		/* Can't open a temp directory. IFS kit test. */
		if (!(file_attributes & FILE_FLAG_POSIX_SEMANTICS) &&
		     (file_attributes & FILE_ATTRIBUTE_TEMPORARY)) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto fail;
		}

		/*
		 * We will get a create directory here if the Win32
		 * app specified a security descriptor in the
		 * CreateDirectory() call.
		 */

		oplock_request = 0;
		status = open_directory(
			conn, req, fname, &sbuf, access_mask, share_access,
			create_disposition, create_options, file_attributes,
			&info, &fsp);
	} else {

		/*
		 * Ordinary file case.
		 */

		status = file_new(req, conn, &fsp);
		if(!NT_STATUS_IS_OK(status)) {
			goto fail;
		}

		/*
		 * We're opening the stream element of a base_fsp
		 * we already opened. Set up the base_fsp pointer.
		 */
		if (base_fsp) {
			fsp->base_fsp = base_fsp;
		}

		status = open_file_ntcreate(conn,
					    req,
					    fname,
					    &sbuf,
					    access_mask,
					    share_access,
					    create_disposition,
					    create_options,
					    file_attributes,
					    oplock_request,
					    &info,
					    fsp);

		if(!NT_STATUS_IS_OK(status)) {
			file_free(req, fsp);
			fsp = NULL;
		}

		if (NT_STATUS_EQUAL(status, NT_STATUS_FILE_IS_A_DIRECTORY)) {

			/* A stream open never opens a directory */

			if (base_fsp) {
				status = NT_STATUS_FILE_IS_A_DIRECTORY;
				goto fail;
			}

			/*
			 * Fail the open if it was explicitly a non-directory
			 * file.
			 */

			if (create_options & FILE_NON_DIRECTORY_FILE) {
				status = NT_STATUS_FILE_IS_A_DIRECTORY;
				goto fail;
			}

			oplock_request = 0;
			status = open_directory(
				conn, req, fname, &sbuf, access_mask,
				share_access, create_disposition,
				create_options,	file_attributes,
				&info, &fsp);
		}
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	fsp->base_fsp = base_fsp;

	/*
	 * According to the MS documentation, the only time the security
	 * descriptor is applied to the opened file is iff we *created* the
	 * file; an existing file stays the same.
	 *
	 * Also, it seems (from observation) that you can open the file with
	 * any access mask but you can still write the sd. We need to override
	 * the granted access before we call set_sd
	 * Patch for bug #2242 from Tom Lackemann <cessnatomny@yahoo.com>.
	 */

	if ((sd != NULL) && (info == FILE_WAS_CREATED)
	    && lp_nt_acl_support(SNUM(conn))) {

		uint32_t sec_info_sent;
		uint32_t saved_access_mask = fsp->access_mask;

		sec_info_sent = get_sec_info(sd);

		fsp->access_mask = FILE_GENERIC_ALL;

		/* Convert all the generic bits. */
		security_acl_map_generic(sd->dacl, &file_generic_mapping);
		security_acl_map_generic(sd->sacl, &file_generic_mapping);

		if (sec_info_sent & (OWNER_SECURITY_INFORMATION|
					GROUP_SECURITY_INFORMATION|
					DACL_SECURITY_INFORMATION|
					SACL_SECURITY_INFORMATION)) {
			status = SMB_VFS_FSET_NT_ACL(fsp, sec_info_sent, sd);
		}

		fsp->access_mask = saved_access_mask;

		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	if ((ea_list != NULL) && (info == FILE_WAS_CREATED)) {
		status = set_ea(conn, fsp, fname, ea_list);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	if (!fsp->is_directory && S_ISDIR(sbuf.st_mode)) {
		status = NT_STATUS_ACCESS_DENIED;
		goto fail;
	}

	/* Save the requested allocation size. */
	if ((info == FILE_WAS_CREATED) || (info == FILE_WAS_OVERWRITTEN)) {
		if (allocation_size
		    && (allocation_size > sbuf.st_size)) {
			fsp->initial_allocation_size = smb_roundup(
				fsp->conn, allocation_size);
			if (fsp->is_directory) {
				/* Can't set allocation size on a directory. */
				status = NT_STATUS_ACCESS_DENIED;
				goto fail;
			}
			if (vfs_allocate_file_space(
				    fsp, fsp->initial_allocation_size) == -1) {
				status = NT_STATUS_DISK_FULL;
				goto fail;
			}
		} else {
			fsp->initial_allocation_size = smb_roundup(
				fsp->conn, (uint64_t)sbuf.st_size);
		}
	}

	DEBUG(10, ("create_file_unixpath: info=%d\n", info));

	*result = fsp;
	if (pinfo != NULL) {
		*pinfo = info;
	}
	if (psbuf != NULL) {
		if ((fsp->fh == NULL) || (fsp->fh->fd == -1)) {
			*psbuf = sbuf;
		}
		else {
			SMB_VFS_FSTAT(fsp, psbuf);
		}
	}
	return NT_STATUS_OK;

 fail:
	DEBUG(10, ("create_file_unixpath: %s\n", nt_errstr(status)));

	if (fsp != NULL) {
		if (base_fsp && fsp->base_fsp == base_fsp) {
			/*
			 * The close_file below will close
			 * fsp->base_fsp.
			 */
			base_fsp = NULL;
		}
		close_file(req, fsp, ERROR_CLOSE);
		fsp = NULL;
	}
	if (base_fsp != NULL) {
		close_file(req, base_fsp, ERROR_CLOSE);
		base_fsp = NULL;
	}
	return status;
}

/*
 * Calculate the full path name given a relative fid.
 */
NTSTATUS get_relative_fid_filename(connection_struct *conn,
				   struct smb_request *req,
				   uint16_t root_dir_fid,
				   const char *fname, char **new_fname)
{
	files_struct *dir_fsp;
	char *parent_fname = NULL;

	if (root_dir_fid == 0 || !fname || !new_fname) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	dir_fsp = file_fsp(req, root_dir_fid);

	if (dir_fsp == NULL) {
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!dir_fsp->is_directory) {

		/*
		 * Check to see if this is a mac fork of some kind.
		 */

		if ((conn->fs_capabilities & FILE_NAMED_STREAMS) &&
		    is_ntfs_stream_name(fname)) {
			return NT_STATUS_OBJECT_PATH_NOT_FOUND;
		}

		/*
		  we need to handle the case when we get a
		  relative open relative to a file and the
		  pathname is blank - this is a reopen!
		  (hint from demyn plantenberg)
		*/

		return NT_STATUS_INVALID_HANDLE;
	}

	if (ISDOT(dir_fsp->fsp_name)) {
		/*
		 * We're at the toplevel dir, the final file name
		 * must not contain ./, as this is filtered out
		 * normally by srvstr_get_path and unix_convert
		 * explicitly rejects paths containing ./.
		 */
		parent_fname = talloc_strdup(talloc_tos(), "");
		if (parent_fname == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		size_t dir_name_len = strlen(dir_fsp->fsp_name);

		/*
		 * Copy in the base directory name.
		 */

		parent_fname = TALLOC_ARRAY(talloc_tos(), char,
		    dir_name_len+2);
		if (parent_fname == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		memcpy(parent_fname, dir_fsp->fsp_name,
		    dir_name_len+1);

		/*
		 * Ensure it ends in a '/'.
		 * We used TALLOC_SIZE +2 to add space for the '/'.
		 */

		if(dir_name_len
		    && (parent_fname[dir_name_len-1] != '\\')
		    && (parent_fname[dir_name_len-1] != '/')) {
			parent_fname[dir_name_len] = '/';
			parent_fname[dir_name_len+1] = '\0';
		}
	}

	*new_fname = talloc_asprintf(talloc_tos(), "%s%s", parent_fname,
	    fname);
	if (*new_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

NTSTATUS create_file_default(connection_struct *conn,
			     struct smb_request *req,
			     uint16_t root_dir_fid,
			     const char *fname,
			     uint32_t create_file_flags,
			     uint32_t access_mask,
			     uint32_t share_access,
			     uint32_t create_disposition,
			     uint32_t create_options,
			     uint32_t file_attributes,
			     uint32_t oplock_request,
			     uint64_t allocation_size,
			     struct security_descriptor *sd,
			     struct ea_list *ea_list,

			     files_struct **result,
			     int *pinfo,
			     SMB_STRUCT_STAT *psbuf)
{
	struct case_semantics_state *case_state = NULL;
	SMB_STRUCT_STAT sbuf;
	int info = FILE_WAS_OPENED;
	files_struct *fsp = NULL;
	NTSTATUS status;

	DEBUG(10,("create_file: access_mask = 0x%x "
		  "file_attributes = 0x%x, share_access = 0x%x, "
		  "create_disposition = 0x%x create_options = 0x%x "
		  "oplock_request = 0x%x "
		  "root_dir_fid = 0x%x, ea_list = 0x%p, sd = 0x%p, "
		  "create_file_flags = 0x%x, fname = %s\n",
		  (unsigned int)access_mask,
		  (unsigned int)file_attributes,
		  (unsigned int)share_access,
		  (unsigned int)create_disposition,
		  (unsigned int)create_options,
		  (unsigned int)oplock_request,
		  (unsigned int)root_dir_fid,
		  ea_list, sd, create_file_flags, fname));

	/* MSDFS pathname processing must be done FIRST.
	   MSDFS pathnames containing IPv6 addresses can
	   be confused with NTFS stream names (they contain
	   ":" characters. JRA. */

	if ((req != NULL) && (req->flags2 & FLAGS2_DFS_PATHNAMES)) {
		char *resolved_fname;

		status = resolve_dfspath(talloc_tos(), conn, true, fname,
					 &resolved_fname);

		if (!NT_STATUS_IS_OK(status)) {
			/*
			 * For PATH_NOT_COVERED we had
			 * reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
			 *		   ERRSRV, ERRbadpath);
			 * Need to fix in callers
			 */
			goto fail;
		}
		fname = resolved_fname;
	}

	/*
	 * Calculate the filename from the root_dir_if if necessary.
	 */

	if (root_dir_fid != 0) {
		char *new_fname;

		status = get_relative_fid_filename(conn, req, root_dir_fid,
						   fname, &new_fname);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}

		fname = new_fname;
	}

	/*
	 * Check to see if this is a mac fork of some kind.
	 */

	if (is_ntfs_stream_name(fname)) {
		enum FAKE_FILE_TYPE fake_file_type;

		fake_file_type = is_fake_file(fname);

		if (fake_file_type != FAKE_FILE_TYPE_NONE) {

			/*
			 * Here we go! support for changing the disk quotas
			 * --metze
			 *
			 * We need to fake up to open this MAGIC QUOTA file
			 * and return a valid FID.
			 *
			 * w2k close this file directly after openening xp
			 * also tries a QUERY_FILE_INFO on the file and then
			 * close it
			 */
			status = open_fake_file(req, conn, req->vuid,
						fake_file_type, fname,
						access_mask, &fsp);
			if (!NT_STATUS_IS_OK(status)) {
				goto fail;
			}

			ZERO_STRUCT(sbuf);
			goto done;
		}

		if (!(conn->fs_capabilities & FILE_NAMED_STREAMS)) {
			status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
			goto fail;
		}
	}

	/*
	 * Check if POSIX semantics are wanted.
	 */

	if (file_attributes & FILE_FLAG_POSIX_SEMANTICS) {
		case_state = set_posix_case_semantics(talloc_tos(), conn);
	}

	if (create_file_flags & CFF_DOS_PATH) {
		char *converted_fname;

		SET_STAT_INVALID(sbuf);

		status = unix_convert(talloc_tos(), conn, fname, False,
				      &converted_fname, NULL, &sbuf);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
		fname = converted_fname;
	} else {
		if (psbuf != NULL) {
			sbuf = *psbuf;
		} else {
			if (SMB_VFS_STAT(conn, fname, &sbuf) == -1) {
				SET_STAT_INVALID(sbuf);
			}
		}

	}

	TALLOC_FREE(case_state);

	/* All file access must go through check_name() */

	status = check_name(conn, fname);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = create_file_unixpath(
		conn, req, fname, access_mask, share_access,
		create_disposition, create_options, file_attributes,
		oplock_request, allocation_size, sd, ea_list,
		&fsp, &info, &sbuf);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

 done:
	DEBUG(10, ("create_file: info=%d\n", info));

	*result = fsp;
	if (pinfo != NULL) {
		*pinfo = info;
	}
	if (psbuf != NULL) {
		*psbuf = sbuf;
	}
	return NT_STATUS_OK;

 fail:
	DEBUG(10, ("create_file: %s\n", nt_errstr(status)));

	if (fsp != NULL) {
		close_file(req, fsp, ERROR_CLOSE);
		fsp = NULL;
	}
	return status;
}
