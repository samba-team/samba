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
#include "system/filesys.h"
#include "printing.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "fake_file.h"
#include "../libcli/security/security.h"
#include "../librpc/gen_ndr/ndr_security.h"
#include "../librpc/gen_ndr/open_files.h"
#include "../librpc/gen_ndr/idmap.h"
#include "../librpc/gen_ndr/ioctl.h"
#include "passdb/lookup_sid.h"
#include "auth.h"
#include "serverid.h"
#include "messages.h"
#include "source3/lib/dbwrap/dbwrap_watch.h"
#include "locking/leases_db.h"
#include "librpc/gen_ndr/ndr_leases_db.h"

extern const struct generic_mapping file_generic_mapping;

struct deferred_open_record {
        bool delayed_for_oplocks;
	bool async_open;
        struct file_id id;
};

/****************************************************************************
 If the requester wanted DELETE_ACCESS and was rejected because
 the file ACL didn't include DELETE_ACCESS, see if the parent ACL
 overrides this.
****************************************************************************/

static bool parent_override_delete(connection_struct *conn,
					const struct smb_filename *smb_fname,
					uint32_t access_mask,
					uint32_t rejected_mask)
{
	if ((access_mask & DELETE_ACCESS) &&
		    (rejected_mask & DELETE_ACCESS) &&
		    can_delete_file_in_directory(conn, smb_fname)) {
		return true;
	}
	return false;
}

/****************************************************************************
 Check if we have open rights.
****************************************************************************/

NTSTATUS smbd_check_access_rights(struct connection_struct *conn,
				const struct smb_filename *smb_fname,
				bool use_privs,
				uint32_t access_mask)
{
	/* Check if we have rights to open. */
	NTSTATUS status;
	struct security_descriptor *sd = NULL;
	uint32_t rejected_share_access;
	uint32_t rejected_mask = access_mask;
	uint32_t do_not_check_mask = 0;

	rejected_share_access = access_mask & ~(conn->share_access);

	if (rejected_share_access) {
		DEBUG(10, ("smbd_check_access_rights: rejected share access 0x%x "
			"on %s (0x%x)\n",
			(unsigned int)access_mask,
			smb_fname_str_dbg(smb_fname),
			(unsigned int)rejected_share_access ));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!use_privs && get_current_uid(conn) == (uid_t)0) {
		/* I'm sorry sir, I didn't know you were root... */
		DEBUG(10,("smbd_check_access_rights: root override "
			"on %s. Granting 0x%x\n",
			smb_fname_str_dbg(smb_fname),
			(unsigned int)access_mask ));
		return NT_STATUS_OK;
	}

	if ((access_mask & DELETE_ACCESS) && !lp_acl_check_permissions(SNUM(conn))) {
		DEBUG(10,("smbd_check_access_rights: not checking ACL "
			"on DELETE_ACCESS on file %s. Granting 0x%x\n",
			smb_fname_str_dbg(smb_fname),
			(unsigned int)access_mask ));
		return NT_STATUS_OK;
	}

	if (access_mask == DELETE_ACCESS &&
			VALID_STAT(smb_fname->st) &&
			S_ISLNK(smb_fname->st.st_ex_mode)) {
		/* We can always delete a symlink. */
		DEBUG(10,("smbd_check_access_rights: not checking ACL "
			"on DELETE_ACCESS on symlink %s.\n",
			smb_fname_str_dbg(smb_fname) ));
		return NT_STATUS_OK;
	}

	status = SMB_VFS_GET_NT_ACL(conn, smb_fname->base_name,
			(SECINFO_OWNER |
			SECINFO_GROUP |
			 SECINFO_DACL), talloc_tos(), &sd);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("smbd_check_access_rights: Could not get acl "
			"on %s: %s\n",
			smb_fname_str_dbg(smb_fname),
			nt_errstr(status)));

		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			goto access_denied;
		}

		return status;
	}

 	/*
	 * If we can access the path to this file, by
	 * default we have FILE_READ_ATTRIBUTES from the
	 * containing directory. See the section:
	 * "Algorithm to Check Access to an Existing File"
	 * in MS-FSA.pdf.
	 *
	 * se_file_access_check() also takes care of
	 * owner WRITE_DAC and READ_CONTROL.
	 */
	do_not_check_mask = FILE_READ_ATTRIBUTES;

	/*
	 * Samba 3.6 and earlier granted execute access even
	 * if the ACL did not contain execute rights.
	 * Samba 4.0 is more correct and checks it.
	 * The compatibilty mode allows to skip this check
	 * to smoothen upgrades.
	 */
	if (lp_acl_allow_execute_always(SNUM(conn))) {
		do_not_check_mask |= FILE_EXECUTE;
	}

	status = se_file_access_check(sd,
				get_current_nttok(conn),
				use_privs,
				(access_mask & ~do_not_check_mask),
				&rejected_mask);

	DEBUG(10,("smbd_check_access_rights: file %s requesting "
		"0x%x returning 0x%x (%s)\n",
		smb_fname_str_dbg(smb_fname),
		(unsigned int)access_mask,
		(unsigned int)rejected_mask,
		nt_errstr(status) ));

	if (!NT_STATUS_IS_OK(status)) {
		if (DEBUGLEVEL >= 10) {
			DEBUG(10,("smbd_check_access_rights: acl for %s is:\n",
				smb_fname_str_dbg(smb_fname) ));
			NDR_PRINT_DEBUG(security_descriptor, sd);
		}
	}

	TALLOC_FREE(sd);

	if (NT_STATUS_IS_OK(status) ||
			!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		return status;
	}

	/* Here we know status == NT_STATUS_ACCESS_DENIED. */

  access_denied:

	if ((access_mask & FILE_WRITE_ATTRIBUTES) &&
			(rejected_mask & FILE_WRITE_ATTRIBUTES) &&
			!lp_store_dos_attributes(SNUM(conn)) &&
			(lp_map_readonly(SNUM(conn)) ||
			lp_map_archive(SNUM(conn)) ||
			lp_map_hidden(SNUM(conn)) ||
			lp_map_system(SNUM(conn)))) {
		rejected_mask &= ~FILE_WRITE_ATTRIBUTES;

		DEBUG(10,("smbd_check_access_rights: "
			"overrode "
			"FILE_WRITE_ATTRIBUTES "
			"on file %s\n",
			smb_fname_str_dbg(smb_fname)));
	}

	if (parent_override_delete(conn,
				smb_fname,
				access_mask,
				rejected_mask)) {
		/* Were we trying to do an open
		 * for delete and didn't get DELETE
		 * access (only) ? Check if the
		 * directory allows DELETE_CHILD.
		 * See here:
		 * http://blogs.msdn.com/oldnewthing/archive/2004/06/04/148426.aspx
		 * for details. */

		rejected_mask &= ~DELETE_ACCESS;

		DEBUG(10,("smbd_check_access_rights: "
			"overrode "
			"DELETE_ACCESS on "
			"file %s\n",
			smb_fname_str_dbg(smb_fname)));
	}

	if (rejected_mask != 0) {
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

static NTSTATUS check_parent_access(struct connection_struct *conn,
				struct smb_filename *smb_fname,
				uint32_t access_mask)
{
	NTSTATUS status;
	char *parent_dir = NULL;
	struct security_descriptor *parent_sd = NULL;
	uint32_t access_granted = 0;

	if (!parent_dirname(talloc_tos(),
				smb_fname->base_name,
				&parent_dir,
				NULL)) {
		return NT_STATUS_NO_MEMORY;
	}

	if (get_current_uid(conn) == (uid_t)0) {
		/* I'm sorry sir, I didn't know you were root... */
		DEBUG(10,("check_parent_access: root override "
			"on %s. Granting 0x%x\n",
			smb_fname_str_dbg(smb_fname),
			(unsigned int)access_mask ));
		return NT_STATUS_OK;
	}

	status = SMB_VFS_GET_NT_ACL(conn,
				parent_dir,
				SECINFO_DACL,
				    talloc_tos(),
				&parent_sd);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("check_parent_access: SMB_VFS_GET_NT_ACL failed for "
			"%s with error %s\n",
			parent_dir,
			nt_errstr(status)));
		return status;
	}

 	/*
	 * If we can access the path to this file, by
	 * default we have FILE_READ_ATTRIBUTES from the
	 * containing directory. See the section:
	 * "Algorithm to Check Access to an Existing File"
	 * in MS-FSA.pdf.
	 *
	 * se_file_access_check() also takes care of
	 * owner WRITE_DAC and READ_CONTROL.
	 */
	status = se_file_access_check(parent_sd,
				get_current_nttok(conn),
				false,
				(access_mask & ~FILE_READ_ATTRIBUTES),
				&access_granted);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("check_parent_access: access check "
			"on directory %s for "
			"path %s for mask 0x%x returned (0x%x) %s\n",
			parent_dir,
			smb_fname->base_name,
			access_mask,
			access_granted,
			nt_errstr(status) ));
		return status;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Ensure when opening a base file for a stream open that we have permissions
 to do so given the access mask on the base file.
****************************************************************************/

static NTSTATUS check_base_file_access(struct connection_struct *conn,
				struct smb_filename *smb_fname,
				uint32_t access_mask)
{
	NTSTATUS status;

	status = smbd_calculate_access_mask(conn, smb_fname,
					false,
					access_mask,
					&access_mask);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("smbd_calculate_access_mask "
			"on file %s returned %s\n",
			smb_fname_str_dbg(smb_fname),
			nt_errstr(status)));
		return status;
	}

	if (access_mask & (FILE_WRITE_DATA|FILE_APPEND_DATA)) {
		uint32_t dosattrs;
		if (!CAN_WRITE(conn)) {
			return NT_STATUS_ACCESS_DENIED;
		}
		dosattrs = dos_mode(conn, smb_fname);
		if (IS_DOS_READONLY(dosattrs)) {
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	return smbd_check_access_rights(conn,
					smb_fname,
					false,
					access_mask);
}

/****************************************************************************
 fd support routines - attempt to do a dos_open.
****************************************************************************/

NTSTATUS fd_open(struct connection_struct *conn,
		 files_struct *fsp,
		 int flags,
		 mode_t mode)
{
	struct smb_filename *smb_fname = fsp->fsp_name;
	NTSTATUS status = NT_STATUS_OK;

#ifdef O_NOFOLLOW
	/* 
	 * Never follow symlinks on a POSIX client. The
	 * client should be doing this.
	 */

	if (fsp->posix_open || !lp_follow_symlinks(SNUM(conn))) {
		flags |= O_NOFOLLOW;
	}
#endif

	fsp->fh->fd = SMB_VFS_OPEN(conn, smb_fname, fsp, flags, mode);
	if (fsp->fh->fd == -1) {
		int posix_errno = errno;
#ifdef O_NOFOLLOW
#if defined(ENOTSUP) && defined(OSF1)
		/* handle special Tru64 errno */
		if (errno == ENOTSUP) {
			posix_errno = ELOOP;
		}
#endif /* ENOTSUP */
#ifdef EFTYPE
		/* fix broken NetBSD errno */
		if (errno == EFTYPE) {
			posix_errno = ELOOP;
		}
#endif /* EFTYPE */
		/* fix broken FreeBSD errno */
		if (errno == EMLINK) {
			posix_errno = ELOOP;
		}
#endif /* O_NOFOLLOW */
		status = map_nt_error_from_unix(posix_errno);
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
		  smb_fname_str_dbg(smb_fname), flags, (int)mode, fsp->fh->fd,
		(fsp->fh->fd == -1) ? strerror(errno) : "" ));

	return status;
}

/****************************************************************************
 Close the file associated with a fsp.
****************************************************************************/

NTSTATUS fd_close(files_struct *fsp)
{
	int ret;

	if (fsp->dptr) {
		dptr_CloseDir(fsp);
	}
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
	struct smb_filename *smb_fname_parent;
	int ret;

	smb_fname_parent = synthetic_smb_fname(talloc_tos(), inherit_from_dir,
					       NULL, NULL);
	if (smb_fname_parent == NULL) {
		return;
	}

	ret = SMB_VFS_STAT(conn, smb_fname_parent);
	if (ret == -1) {
		DEBUG(0,("change_file_owner_to_parent: failed to stat parent "
			 "directory %s. Error was %s\n",
			 smb_fname_str_dbg(smb_fname_parent),
			 strerror(errno)));
		TALLOC_FREE(smb_fname_parent);
		return;
	}

	if (smb_fname_parent->st.st_ex_uid == fsp->fsp_name->st.st_ex_uid) {
		/* Already this uid - no need to change. */
		DEBUG(10,("change_file_owner_to_parent: file %s "
			"is already owned by uid %d\n",
			fsp_str_dbg(fsp),
			(int)fsp->fsp_name->st.st_ex_uid ));
		TALLOC_FREE(smb_fname_parent);
		return;
	}

	become_root();
	ret = SMB_VFS_FCHOWN(fsp, smb_fname_parent->st.st_ex_uid, (gid_t)-1);
	unbecome_root();
	if (ret == -1) {
		DEBUG(0,("change_file_owner_to_parent: failed to fchown "
			 "file %s to parent directory uid %u. Error "
			 "was %s\n", fsp_str_dbg(fsp),
			 (unsigned int)smb_fname_parent->st.st_ex_uid,
			 strerror(errno) ));
	} else {
		DEBUG(10,("change_file_owner_to_parent: changed new file %s to "
			"parent directory uid %u.\n", fsp_str_dbg(fsp),
			(unsigned int)smb_fname_parent->st.st_ex_uid));
		/* Ensure the uid entry is updated. */
		fsp->fsp_name->st.st_ex_uid = smb_fname_parent->st.st_ex_uid;
	}

	TALLOC_FREE(smb_fname_parent);
}

NTSTATUS change_dir_owner_to_parent(connection_struct *conn,
				       const char *inherit_from_dir,
				       const char *fname,
				       SMB_STRUCT_STAT *psbuf)
{
	struct smb_filename *smb_fname_parent;
	struct smb_filename *smb_fname_cwd = NULL;
	char *saved_dir = NULL;
	TALLOC_CTX *ctx = talloc_tos();
	NTSTATUS status = NT_STATUS_OK;
	int ret;

	smb_fname_parent = synthetic_smb_fname(ctx, inherit_from_dir,
					       NULL, NULL);
	if (smb_fname_parent == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = SMB_VFS_STAT(conn, smb_fname_parent);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		DEBUG(0,("change_dir_owner_to_parent: failed to stat parent "
			 "directory %s. Error was %s\n",
			 smb_fname_str_dbg(smb_fname_parent),
			 strerror(errno)));
		goto out;
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
		goto out;
	}

	/* Chdir into the new path. */
	if (vfs_ChDir(conn, fname) == -1) {
		status = map_nt_error_from_unix(errno);
		DEBUG(0,("change_dir_owner_to_parent: failed to change "
			 "current working directory to %s. Error "
			 "was %s\n", fname, strerror(errno) ));
		goto chdir;
	}

	smb_fname_cwd = synthetic_smb_fname(ctx, ".", NULL, NULL);
	if (smb_fname_cwd == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto chdir;
	}

	ret = SMB_VFS_STAT(conn, smb_fname_cwd);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		DEBUG(0,("change_dir_owner_to_parent: failed to stat "
			 "directory '.' (%s) Error was %s\n",
			 fname, strerror(errno)));
		goto chdir;
	}

	/* Ensure we're pointing at the same place. */
	if (smb_fname_cwd->st.st_ex_dev != psbuf->st_ex_dev ||
	    smb_fname_cwd->st.st_ex_ino != psbuf->st_ex_ino) {
		DEBUG(0,("change_dir_owner_to_parent: "
			 "device/inode on directory %s changed. "
			 "Refusing to chown !\n", fname ));
		status = NT_STATUS_ACCESS_DENIED;
		goto chdir;
	}

	if (smb_fname_parent->st.st_ex_uid == smb_fname_cwd->st.st_ex_uid) {
		/* Already this uid - no need to change. */
		DEBUG(10,("change_dir_owner_to_parent: directory %s "
			"is already owned by uid %d\n",
			fname,
			(int)smb_fname_cwd->st.st_ex_uid ));
		status = NT_STATUS_OK;
		goto chdir;
	}

	become_root();
	ret = SMB_VFS_LCHOWN(conn, ".", smb_fname_parent->st.st_ex_uid,
			    (gid_t)-1);
	unbecome_root();
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		DEBUG(10,("change_dir_owner_to_parent: failed to chown "
			  "directory %s to parent directory uid %u. "
			  "Error was %s\n", fname,
			  (unsigned int)smb_fname_parent->st.st_ex_uid,
			  strerror(errno) ));
	} else {
		DEBUG(10,("change_dir_owner_to_parent: changed ownership of new "
			"directory %s to parent directory uid %u.\n",
			fname, (unsigned int)smb_fname_parent->st.st_ex_uid ));
		/* Ensure the uid entry is updated. */
		psbuf->st_ex_uid = smb_fname_parent->st.st_ex_uid;
	}

 chdir:
	vfs_ChDir(conn,saved_dir);
 out:
	TALLOC_FREE(smb_fname_parent);
	TALLOC_FREE(smb_fname_cwd);
	return status;
}

/****************************************************************************
 Open a file - returning a guaranteed ATOMIC indication of if the
 file was created or not.
****************************************************************************/

static NTSTATUS fd_open_atomic(struct connection_struct *conn,
			files_struct *fsp,
			int flags,
			mode_t mode,
			bool *file_created)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	bool file_existed = VALID_STAT(fsp->fsp_name->st);

	*file_created = false;

	if (!(flags & O_CREAT)) {
		/*
		 * We're not creating the file, just pass through.
		 */
		return fd_open(conn, fsp, flags, mode);
	}

	if (flags & O_EXCL) {
		/*
		 * Fail if already exists, just pass through.
		 */
		status = fd_open(conn, fsp, flags, mode);

		/*
		 * Here we've opened with O_CREAT|O_EXCL. If that went
		 * NT_STATUS_OK, we *know* we created this file.
		 */
		*file_created = NT_STATUS_IS_OK(status);

		return status;
	}

	/*
	 * Now it gets tricky. We have O_CREAT, but not O_EXCL.
	 * To know absolutely if we created the file or not,
	 * we can never call O_CREAT without O_EXCL. So if
	 * we think the file existed, try without O_CREAT|O_EXCL.
	 * If we think the file didn't exist, try with
	 * O_CREAT|O_EXCL. Keep bouncing between these two
	 * requests until either the file is created, or
	 * opened. Either way, we keep going until we get
	 * a returnable result (error, or open/create).
	 */

	while(1) {
		int curr_flags = flags;

		if (file_existed) {
			/* Just try open, do not create. */
			curr_flags &= ~(O_CREAT);
			status = fd_open(conn, fsp, curr_flags, mode);
			if (NT_STATUS_EQUAL(status,
					NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
				/*
				 * Someone deleted it in the meantime.
				 * Retry with O_EXCL.
				 */
				file_existed = false;
				DEBUG(10,("fd_open_atomic: file %s existed. "
					"Retry.\n",
					smb_fname_str_dbg(fsp->fsp_name)));
					continue;
			}
		} else {
			/* Try create exclusively, fail if it exists. */
			curr_flags |= O_EXCL;
			status = fd_open(conn, fsp, curr_flags, mode);
			if (NT_STATUS_EQUAL(status,
					NT_STATUS_OBJECT_NAME_COLLISION)) {
				/*
				 * Someone created it in the meantime.
				 * Retry without O_CREAT.
				 */
				file_existed = true;
				DEBUG(10,("fd_open_atomic: file %s "
					"did not exist. Retry.\n",
					smb_fname_str_dbg(fsp->fsp_name)));
				continue;
			}
			if (NT_STATUS_IS_OK(status)) {
				/*
				 * Here we've opened with O_CREAT|O_EXCL
				 * and got success. We *know* we created
				 * this file.
				 */
				*file_created = true;
			}
		}
		/* Create is done, or failed. */
		break;
	}
	return status;
}

/****************************************************************************
 Open a file.
****************************************************************************/

static NTSTATUS open_file(files_struct *fsp,
			  connection_struct *conn,
			  struct smb_request *req,
			  const char *parent_dir,
			  int flags,
			  mode_t unx_mode,
			  uint32 access_mask, /* client requested access mask. */
			  uint32 open_access_mask, /* what we're actually using in the open. */
			  bool *p_file_created)
{
	struct smb_filename *smb_fname = fsp->fsp_name;
	NTSTATUS status = NT_STATUS_OK;
	int accmode = (flags & O_ACCMODE);
	int local_flags = flags;
	bool file_existed = VALID_STAT(fsp->fsp_name->st);

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
			DEBUG(3,("Permission denied opening %s\n",
				 smb_fname_str_dbg(smb_fname)));
			return NT_STATUS_ACCESS_DENIED;
		}
		if (flags & O_CREAT) {
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
			  "for file %s\n", smb_fname_str_dbg(smb_fname)));
		local_flags = (flags & ~O_ACCMODE)|O_RDWR;
	}

	if ((open_access_mask & (FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_EXECUTE)) ||
	    (!file_existed && (local_flags & O_CREAT)) ||
	    ((local_flags & O_TRUNC) == O_TRUNC) ) {
		const char *wild;
		int ret;

#if defined(O_NONBLOCK) && defined(S_ISFIFO)
		/*
		 * We would block on opening a FIFO with no one else on the
		 * other end. Do what we used to do and add O_NONBLOCK to the
		 * open flags. JRA.
		 */

		if (file_existed && S_ISFIFO(smb_fname->st.st_ex_mode)) {
			local_flags &= ~O_TRUNC; /* Can't truncate a FIFO. */
			local_flags |= O_NONBLOCK;
		}
#endif

		/* Don't create files with Microsoft wildcard characters. */
		if (fsp->base_fsp) {
			/*
			 * wildcard characters are allowed in stream names
			 * only test the basefilename
			 */
			wild = fsp->base_fsp->fsp_name->base_name;
		} else {
			wild = smb_fname->base_name;
		}
		if ((local_flags & O_CREAT) && !file_existed &&
		    ms_has_wild(wild))  {
			return NT_STATUS_OBJECT_NAME_INVALID;
		}

		/* Can we access this file ? */
		if (!fsp->base_fsp) {
			/* Only do this check on non-stream open. */
			if (file_existed) {
				status = smbd_check_access_rights(conn,
						smb_fname,
						false,
						access_mask);

				if (!NT_STATUS_IS_OK(status)) {
					DEBUG(10, ("open_file: "
						   "smbd_check_access_rights "
						   "on file %s returned %s\n",
						   smb_fname_str_dbg(smb_fname),
						   nt_errstr(status)));
				}

				if (!NT_STATUS_IS_OK(status) &&
				    !NT_STATUS_EQUAL(status,
					NT_STATUS_OBJECT_NAME_NOT_FOUND))
				{
					return status;
				}

				if (NT_STATUS_EQUAL(status,
					NT_STATUS_OBJECT_NAME_NOT_FOUND))
				{
					DEBUG(10, ("open_file: "
						"file %s vanished since we "
						"checked for existence.\n",
						smb_fname_str_dbg(smb_fname)));
					file_existed = false;
					SET_STAT_INVALID(fsp->fsp_name->st);
				}
			}

			if (!file_existed) {
				if (!(local_flags & O_CREAT)) {
					/* File didn't exist and no O_CREAT. */
					return NT_STATUS_OBJECT_NAME_NOT_FOUND;
				}

				status = check_parent_access(conn,
							     smb_fname,
							     SEC_DIR_ADD_FILE);
				if (!NT_STATUS_IS_OK(status)) {
					DEBUG(10, ("open_file: "
						   "check_parent_access on "
						   "file %s returned %s\n",
						   smb_fname_str_dbg(smb_fname),
						   nt_errstr(status) ));
					return status;
				}
			}
		}

		/*
		 * Actually do the open - if O_TRUNC is needed handle it
		 * below under the share mode lock.
		 */
		status = fd_open_atomic(conn, fsp, local_flags & ~O_TRUNC,
				unx_mode, p_file_created);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3,("Error opening file %s (%s) (local_flags=%d) "
				 "(flags=%d)\n", smb_fname_str_dbg(smb_fname),
				 nt_errstr(status),local_flags,flags));
			return status;
		}

		ret = SMB_VFS_FSTAT(fsp, &smb_fname->st);
		if (ret == -1) {
			/* If we have an fd, this stat should succeed. */
			DEBUG(0,("Error doing fstat on open file %s "
				"(%s)\n",
				smb_fname_str_dbg(smb_fname),
				strerror(errno) ));
			status = map_nt_error_from_unix(errno);
			fd_close(fsp);
			return status;
		}

		if (*p_file_created) {
			/* We created this file. */

			bool need_re_stat = false;
			/* Do all inheritance work after we've
			   done a successful fstat call and filled
			   in the stat struct in fsp->fsp_name. */

			/* Inherit the ACL if required */
			if (lp_inherit_permissions(SNUM(conn))) {
				inherit_access_posix_acl(conn, parent_dir,
							 smb_fname->base_name,
							 unx_mode);
				need_re_stat = true;
			}

			/* Change the owner if required. */
			if (lp_inherit_owner(SNUM(conn))) {
				change_file_owner_to_parent(conn, parent_dir,
							    fsp);
				need_re_stat = true;
			}

			if (need_re_stat) {
				ret = SMB_VFS_FSTAT(fsp, &smb_fname->st);
				/* If we have an fd, this stat should succeed. */
				if (ret == -1) {
					DEBUG(0,("Error doing fstat on open file %s "
						 "(%s)\n",
						 smb_fname_str_dbg(smb_fname),
						 strerror(errno) ));
				}
			}

			notify_fname(conn, NOTIFY_ACTION_ADDED,
				     FILE_NOTIFY_CHANGE_FILE_NAME,
				     smb_fname->base_name);
		}
	} else {
		fsp->fh->fd = -1; /* What we used to call a stat open. */
		if (!file_existed) {
			/* File must exist for a stat open. */
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

		status = smbd_check_access_rights(conn,
				smb_fname,
				false,
				access_mask);

		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND) &&
				fsp->posix_open &&
				S_ISLNK(smb_fname->st.st_ex_mode)) {
			/* This is a POSIX stat open for delete
			 * or rename on a symlink that points
			 * nowhere. Allow. */
			DEBUG(10,("open_file: allowing POSIX "
				  "open on bad symlink %s\n",
				  smb_fname_str_dbg(smb_fname)));
			status = NT_STATUS_OK;
		}

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10,("open_file: "
				"smbd_check_access_rights on file "
				"%s returned %s\n",
				smb_fname_str_dbg(smb_fname),
				nt_errstr(status) ));
			return status;
		}
	}

	/*
	 * POSIX allows read-only opens of directories. We don't
	 * want to do this (we use a different code path for this)
	 * so catch a directory open and return an EISDIR. JRA.
	 */

	if(S_ISDIR(smb_fname->st.st_ex_mode)) {
		fd_close(fsp);
		errno = EISDIR;
		return NT_STATUS_FILE_IS_A_DIRECTORY;
	}

	fsp->file_id = vfs_file_id_from_sbuf(conn, &smb_fname->st);
	fsp->vuid = req ? req->vuid : UID_FIELD_INVALID;
	fsp->file_pid = req ? req->smbpid : 0;
	fsp->can_lock = True;
	fsp->can_read = ((access_mask & FILE_READ_DATA) != 0);
	fsp->can_write =
		CAN_WRITE(conn) &&
		((access_mask & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0);
	fsp->print_file = NULL;
	fsp->modified = False;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->is_directory = False;
	if (conn->aio_write_behind_list &&
	    is_in_path(smb_fname->base_name, conn->aio_write_behind_list,
		       conn->case_sensitive)) {
		fsp->aio_write_behind = True;
	}

	fsp->wcp = NULL; /* Write cache pointer. */

	DEBUG(2,("%s opened file %s read=%s write=%s (numopen=%d)\n",
		 conn->session_info->unix_info->unix_name,
		 smb_fname_str_dbg(smb_fname),
		 BOOLSTR(fsp->can_read), BOOLSTR(fsp->can_write),
		 conn->num_files_open));

	errno = 0;
	return NT_STATUS_OK;
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

	if (server_id_is_disconnected(&entry->pid)) {
		/*
		 * note: cleanup should have been done by
		 * delay_for_batch_oplocks()
		 */
		return false;
	}

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
static void validate_my_share_entries(struct smbd_server_connection *sconn,
				      int num,
				      struct share_mode_entry *share_entry)
{
	struct server_id self = messaging_server_id(sconn->msg_ctx);
	files_struct *fsp;

	if (!serverid_equal(&self, &share_entry->pid)) {
		return;
	}

	if (share_entry->op_mid == 0) {
		/* INTERNAL_OPEN_ONLY */
		return;
	}

	if (!is_valid_share_mode_entry(share_entry)) {
		return;
	}

	fsp = file_find_dif(sconn, share_entry->id,
			    share_entry->share_file_id);
	if (!fsp) {
		DEBUG(0,("validate_my_share_entries: PANIC : %s\n",
			 share_mode_str(talloc_tos(), num, share_entry) ));
		smb_panic("validate_my_share_entries: Cannot match a "
			  "share entry with an open file\n");
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
			 fsp->fsp_name->base_name,
			 (unsigned int)fsp->oplock_type,
			 (unsigned int)share_entry->op_type );
		smb_panic(str);
	}
}
#endif

bool is_stat_open(uint32 access_mask)
{
	const uint32_t stat_open_bits =
		(SYNCHRONIZE_ACCESS|
		 FILE_READ_ATTRIBUTES|
		 FILE_WRITE_ATTRIBUTES);

	return (((access_mask &  stat_open_bits) != 0) &&
		((access_mask & ~stat_open_bits) == 0));
}

static bool has_delete_on_close(struct share_mode_lock *lck,
				uint32_t name_hash)
{
	struct share_mode_data *d = lck->data;
	uint32_t i;

	if (d->num_share_modes == 0) {
		return false;
	}
	if (!is_delete_on_close_set(lck, name_hash)) {
		return false;
	}
	for (i=0; i<d->num_share_modes; i++) {
		if (!share_mode_stale_pid(d, i)) {
			return true;
		}
	}
	return false;
}

/****************************************************************************
 Deal with share modes
 Invariant: Share mode must be locked on entry and exit.
 Returns -1 on error, or number of share modes on success (may be zero).
****************************************************************************/

static NTSTATUS open_mode_check(connection_struct *conn,
				struct share_mode_lock *lck,
				uint32 access_mask,
				uint32 share_access)
{
	int i;

	if(lck->data->num_share_modes == 0) {
		return NT_STATUS_OK;
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
	for(i = 0; i < lck->data->num_share_modes; i++) {
		validate_my_share_entries(conn->sconn, i,
					  &lck->data->share_modes[i]);
	}
#endif

	/* Now we check the share modes, after any oplock breaks. */
	for(i = 0; i < lck->data->num_share_modes; i++) {

		if (!is_valid_share_mode_entry(&lck->data->share_modes[i])) {
			continue;
		}

		/* someone else has a share lock on it, check to see if we can
		 * too */
		if (share_conflict(&lck->data->share_modes[i],
				   access_mask, share_access)) {

			if (share_mode_stale_pid(lck->data, i)) {
				continue;
			}

			return NT_STATUS_SHARING_VIOLATION;
		}
	}

	return NT_STATUS_OK;
}

/*
 * Send a break message to the oplock holder and delay the open for
 * our client.
 */

NTSTATUS send_break_message(struct messaging_context *msg_ctx,
				   const struct share_mode_entry *exclusive,
				   uint16_t break_to)
{
	NTSTATUS status;
	char msg[MSG_SMB_SHARE_MODE_ENTRY_SIZE];

	DEBUG(10, ("Sending break request to PID %s\n",
		   procid_str_static(&exclusive->pid)));

	/* Create the message. */
	share_mode_entry_to_message(msg, exclusive);

	/* Overload entry->op_type */
	/*
	 * This is a cut from uint32 to uint16, but so far only the lower 3
	 * bits (LEASE_WRITE/HANDLE/READ are used anyway.
	 */
	SSVAL(msg,OP_BREAK_MSG_OP_TYPE_OFFSET, break_to);

	status = messaging_send_buf(msg_ctx, exclusive->pid,
				    MSG_SMB_BREAK_REQUEST,
				    (uint8 *)msg, sizeof(msg));
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("Could not send oplock break message: %s\n",
			  nt_errstr(status)));
	}

	return status;
}

/*
 * Do internal consistency checks on the share mode for a file.
 */

static bool validate_oplock_types(struct share_mode_lock *lck)
{
	struct share_mode_data *d = lck->data;
	bool batch = false;
	bool ex_or_batch = false;
	bool level2 = false;
	bool no_oplock = false;
	uint32_t num_non_stat_opens = 0;
	uint32_t i;

	for (i=0; i<d->num_share_modes; i++) {
		struct share_mode_entry *e = &d->share_modes[i];

		if (!is_valid_share_mode_entry(e)) {
			continue;
		}

		if (e->op_mid == 0) {
			/* INTERNAL_OPEN_ONLY */
			continue;
		}

		if (e->op_type == NO_OPLOCK && is_stat_open(e->access_mask)) {
			/* We ignore stat opens in the table - they
			   always have NO_OPLOCK and never get or
			   cause breaks. JRA. */
			continue;
		}

		num_non_stat_opens += 1;

		if (BATCH_OPLOCK_TYPE(e->op_type)) {
			/* batch - can only be one. */
			if (share_mode_stale_pid(d, i)) {
				DEBUG(10, ("Found stale batch oplock\n"));
				continue;
			}
			if (ex_or_batch || batch || level2 || no_oplock) {
				DEBUG(0, ("Bad batch oplock entry %u.",
					  (unsigned)i));
				return false;
			}
			batch = true;
		}

		if (EXCLUSIVE_OPLOCK_TYPE(e->op_type)) {
			if (share_mode_stale_pid(d, i)) {
				DEBUG(10, ("Found stale duplicate oplock\n"));
				continue;
			}
			/* Exclusive or batch - can only be one. */
			if (ex_or_batch || level2 || no_oplock) {
				DEBUG(0, ("Bad exclusive or batch oplock "
					  "entry %u.", (unsigned)i));
				return false;
			}
			ex_or_batch = true;
		}

		if (LEVEL_II_OPLOCK_TYPE(e->op_type)) {
			if (batch || ex_or_batch) {
				if (share_mode_stale_pid(d, i)) {
					DEBUG(10, ("Found stale LevelII "
						   "oplock\n"));
					continue;
				}
				DEBUG(0, ("Bad levelII oplock entry %u.",
					  (unsigned)i));
				return false;
			}
			level2 = true;
		}

		if (e->op_type == NO_OPLOCK) {
			if (batch || ex_or_batch) {
				if (share_mode_stale_pid(d, i)) {
					DEBUG(10, ("Found stale NO_OPLOCK "
						   "entry\n"));
					continue;
				}
				DEBUG(0, ("Bad no oplock entry %u.",
					  (unsigned)i));
				return false;
			}
			no_oplock = true;
		}
	}

	remove_stale_share_mode_entries(d);

	if ((batch || ex_or_batch) && (num_non_stat_opens != 1)) {
		DEBUG(1, ("got batch (%d) or ex (%d) non-exclusively (%d)\n",
			  (int)batch, (int)ex_or_batch,
			  (int)d->num_share_modes));
		return false;
	}

	return true;
}

static bool delay_for_oplock(files_struct *fsp,
			     int oplock_request,
			     const struct smb2_lease *lease,
			     struct share_mode_lock *lck,
			     bool have_sharing_violation,
			     uint32_t create_disposition,
			     bool first_open_attempt)
{
	struct share_mode_data *d = lck->data;
	uint32_t i;
	bool delay = false;
	bool will_overwrite;

	if ((oplock_request & INTERNAL_OPEN_ONLY) ||
	    is_stat_open(fsp->access_mask)) {
		return false;
	}

	switch (create_disposition) {
	case FILE_SUPERSEDE:
	case FILE_OVERWRITE:
	case FILE_OVERWRITE_IF:
		will_overwrite = true;
		break;
	default:
		will_overwrite = false;
		break;
	}

	for (i=0; i<d->num_share_modes; i++) {
		struct share_mode_entry *e = &d->share_modes[i];
		struct share_mode_lease *l = NULL;
		uint32_t e_lease_type = get_lease_type(d, e);
		uint32_t break_to;
		uint32_t delay_mask = 0;

		if (e->op_type == LEASE_OPLOCK) {
			l = &d->leases[e->lease_idx];
		}

		if (have_sharing_violation) {
			delay_mask = SMB2_LEASE_HANDLE;
		} else {
			delay_mask = SMB2_LEASE_WRITE;
		}

		break_to = e_lease_type & ~delay_mask;

		if (will_overwrite) {
			/*
			 * we'll decide about SMB2_LEASE_READ later.
			 *
			 * Maybe the break will be defered
			 */
			break_to &= ~SMB2_LEASE_HANDLE;
		}

		DEBUG(10, ("entry %u: e_lease_type %u, will_overwrite: %u\n",
			   (unsigned)i, (unsigned)e_lease_type,
			   (unsigned)will_overwrite));

		if (lease != NULL && l != NULL) {
			bool ign;

			ign = smb2_lease_equal(fsp_client_guid(fsp),
					       &lease->lease_key,
					       &l->client_guid,
					       &l->lease_key);
			if (ign) {
				continue;
			}
		}

		if ((e_lease_type & ~break_to) == 0) {
			if (l != NULL && l->breaking) {
				delay = true;
			}
			continue;
		}

		if (share_mode_stale_pid(d, i)) {
			continue;
		}

		if (will_overwrite) {
			/*
			 * If we break anyway break to NONE directly.
			 * Otherwise vfs_set_filelen() will trigger the
			 * break.
			 */
			break_to &= ~(SMB2_LEASE_READ|SMB2_LEASE_WRITE);
		}

		if (e->op_type != LEASE_OPLOCK) {
			/*
			 * Oplocks only support breaking to R or NONE.
			 */
			break_to &= ~(SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE);
		}

		DEBUG(10, ("breaking from %d to %d\n",
			   (int)e_lease_type, (int)break_to));
		send_break_message(fsp->conn->sconn->msg_ctx, e,
				   break_to);
		if (e_lease_type & delay_mask) {
			delay = true;
		}
		if (l != NULL && l->breaking && !first_open_attempt) {
			delay = true;
		}
		continue;
	}

	return delay;
}

static bool file_has_brlocks(files_struct *fsp)
{
	struct byte_range_lock *br_lck;

	br_lck = brl_get_locks_readonly(fsp);
	if (!br_lck)
		return false;

	return (brl_num_locks(br_lck) > 0);
}

int find_share_mode_lease(struct share_mode_data *d,
			  const struct GUID *client_guid,
			  const struct smb2_lease_key *key)
{
	uint32_t i;

	for (i=0; i<d->num_leases; i++) {
		struct share_mode_lease *l = &d->leases[i];

		if (smb2_lease_equal(client_guid,
				     key,
				     &l->client_guid,
				     &l->lease_key)) {
			return i;
		}
	}

	return -1;
}

struct fsp_lease *find_fsp_lease(struct files_struct *new_fsp,
				 const struct smb2_lease_key *key,
				 const struct share_mode_lease *l)
{
	struct files_struct *fsp;

	/*
	 * TODO: Measure how expensive this loop is with thousands of open
	 * handles...
	 */

	for (fsp = file_find_di_first(new_fsp->conn->sconn, new_fsp->file_id);
	     fsp != NULL;
	     fsp = file_find_di_next(fsp)) {

		if (fsp == new_fsp) {
			continue;
		}
		if (fsp->oplock_type != LEASE_OPLOCK) {
			continue;
		}
		if (smb2_lease_key_equal(&fsp->lease->lease.lease_key, key)) {
			fsp->lease->ref_count += 1;
			return fsp->lease;
		}
	}

	/* Not found - must be leased in another smbd. */
	new_fsp->lease = talloc_zero(new_fsp->conn->sconn, struct fsp_lease);
	if (new_fsp->lease == NULL) {
		return NULL;
	}
	new_fsp->lease->ref_count = 1;
	new_fsp->lease->sconn = new_fsp->conn->sconn;
	new_fsp->lease->lease.lease_key = *key;
	new_fsp->lease->lease.lease_state = l->current_state;
	/*
	 * We internally treat all leases as V2 and update
	 * the epoch, but when sending breaks it matters if
	 * the requesting lease was v1 or v2.
	 */
	new_fsp->lease->lease.lease_version = l->lease_version;
	new_fsp->lease->lease.lease_epoch = l->epoch;
	return new_fsp->lease;
}

static NTSTATUS grant_fsp_lease(struct files_struct *fsp,
				struct share_mode_lock *lck,
				const struct smb2_lease *lease,
				uint32_t *p_lease_idx,
				uint32_t granted)
{
	struct share_mode_data *d = lck->data;
	const struct GUID *client_guid = fsp_client_guid(fsp);
	struct share_mode_lease *tmp;
	NTSTATUS status;
	int idx;

	idx = find_share_mode_lease(d, client_guid, &lease->lease_key);

	if (idx != -1) {
		struct share_mode_lease *l = &d->leases[idx];
		bool do_upgrade;
		uint32_t existing, requested;

		fsp->lease = find_fsp_lease(fsp, &lease->lease_key, l);
		if (fsp->lease == NULL) {
			DEBUG(1, ("Did not find existing lease for file %s\n",
				  fsp_str_dbg(fsp)));
			return NT_STATUS_NO_MEMORY;
		}

		*p_lease_idx = idx;

		/*
		 * Upgrade only if the requested lease is a strict upgrade.
		 */
		existing = l->current_state;
		requested = lease->lease_state;

		/*
		 * Tricky: This test makes sure that "requested" is a
		 * strict bitwise superset of "existing".
		 */
		do_upgrade = ((existing & requested) == existing);

		/*
		 * Upgrade only if there's a change.
		 */
		do_upgrade &= (granted != existing);

		/*
		 * Upgrade only if other leases don't prevent what was asked
		 * for.
		 */
		do_upgrade &= (granted == requested);

		/*
		 * only upgrade if we are not in breaking state
		 */
		do_upgrade &= !l->breaking;

		DEBUG(10, ("existing=%"PRIu32", requested=%"PRIu32", "
			   "granted=%"PRIu32", do_upgrade=%d\n",
			   existing, requested, granted, (int)do_upgrade));

		if (do_upgrade) {
			l->current_state = granted;
			l->epoch += 1;
		}

		/* Ensure we're in sync with current lease state. */
		fsp_lease_update(lck, fsp_client_guid(fsp), fsp->lease);
		return NT_STATUS_OK;
	}

	/*
	 * Create new lease
	 */

	tmp = talloc_realloc(d, d->leases, struct share_mode_lease,
			     d->num_leases+1);
	if (tmp == NULL) {
		/*
		 * See [MS-SMB2]
		 */
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}
	d->leases = tmp;

	fsp->lease = talloc_zero(fsp->conn->sconn, struct fsp_lease);
	if (fsp->lease == NULL) {
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}
	fsp->lease->ref_count = 1;
	fsp->lease->sconn = fsp->conn->sconn;
	fsp->lease->lease.lease_version = lease->lease_version;
	fsp->lease->lease.lease_key = lease->lease_key;
	fsp->lease->lease.lease_state = granted;
	fsp->lease->lease.lease_epoch = lease->lease_epoch + 1;

	*p_lease_idx = d->num_leases;

	d->leases[d->num_leases] = (struct share_mode_lease) {
		.client_guid = *client_guid,
		.lease_key = fsp->lease->lease.lease_key,
		.current_state = fsp->lease->lease.lease_state,
		.lease_version = fsp->lease->lease.lease_version,
		.epoch = fsp->lease->lease.lease_epoch,
	};

	status = leases_db_add(client_guid,
			       &lease->lease_key,
			       &fsp->file_id,
			       fsp->conn->connectpath,
			       fsp->fsp_name->base_name,
			       fsp->fsp_name->stream_name);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("%s: leases_db_add failed: %s\n", __func__,
			   nt_errstr(status)));
		TALLOC_FREE(fsp->lease);
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	d->num_leases += 1;
	d->modified = true;

	return NT_STATUS_OK;
}

static bool is_same_lease(const files_struct *fsp,
			  const struct share_mode_data *d,
			  const struct share_mode_entry *e,
			  const struct smb2_lease *lease)
{
	if (e->op_type != LEASE_OPLOCK) {
		return false;
	}
	if (lease == NULL) {
		return false;
	}

	return smb2_lease_equal(fsp_client_guid(fsp),
				&lease->lease_key,
				&d->leases[e->lease_idx].client_guid,
				&d->leases[e->lease_idx].lease_key);
}

static NTSTATUS grant_fsp_oplock_type(struct smb_request *req,
				      struct files_struct *fsp,
				      struct share_mode_lock *lck,
				      int oplock_request,
				      struct smb2_lease *lease)
{
	struct share_mode_data *d = lck->data;
	bool got_handle_lease = false;
	bool got_oplock = false;
	uint32_t i;
	uint32_t granted;
	uint32_t lease_idx = UINT32_MAX;
	bool ok;
	NTSTATUS status;

	if (oplock_request & INTERNAL_OPEN_ONLY) {
		/* No oplocks on internal open. */
		oplock_request = NO_OPLOCK;
		DEBUG(10,("grant_fsp_oplock_type: oplock type 0x%x on file %s\n",
			fsp->oplock_type, fsp_str_dbg(fsp)));
	}

	if (oplock_request == LEASE_OPLOCK) {
		if (lease == NULL) {
			/*
			 * The SMB2 layer should have checked this
			 */
			return NT_STATUS_INTERNAL_ERROR;
		}

		granted = lease->lease_state;

		if (lp_kernel_oplocks(SNUM(fsp->conn))) {
			DEBUG(10, ("No lease granted because kernel oplocks are enabled\n"));
			granted = SMB2_LEASE_NONE;
		}
		if ((granted & (SMB2_LEASE_READ|SMB2_LEASE_WRITE)) == 0) {
			DEBUG(10, ("No read or write lease requested\n"));
			granted = SMB2_LEASE_NONE;
		}
		if (granted == SMB2_LEASE_WRITE) {
			DEBUG(10, ("pure write lease requested\n"));
			granted = SMB2_LEASE_NONE;
		}
		if (granted == (SMB2_LEASE_WRITE|SMB2_LEASE_HANDLE)) {
			DEBUG(10, ("write and handle lease requested\n"));
			granted = SMB2_LEASE_NONE;
		}
	} else {
		granted = map_oplock_to_lease_type(
			oplock_request & ~SAMBA_PRIVATE_OPLOCK_MASK);
	}

	if (lp_locking(fsp->conn->params) && file_has_brlocks(fsp)) {
		DEBUG(10,("grant_fsp_oplock_type: file %s has byte range locks\n",
			fsp_str_dbg(fsp)));
		granted &= ~SMB2_LEASE_READ;
	}

	for (i=0; i<d->num_share_modes; i++) {
		struct share_mode_entry *e = &d->share_modes[i];
		uint32_t e_lease_type;

		e_lease_type = get_lease_type(d, e);

		if ((granted & SMB2_LEASE_WRITE) &&
		    !is_same_lease(fsp, d, e, lease) &&
		    !share_mode_stale_pid(d, i)) {
			/*
			 * Can grant only one writer
			 */
			granted &= ~SMB2_LEASE_WRITE;
		}

		if ((e_lease_type & SMB2_LEASE_HANDLE) && !got_handle_lease &&
		    !share_mode_stale_pid(d, i)) {
			got_handle_lease = true;
		}

		if ((e->op_type != LEASE_OPLOCK) && !got_oplock &&
		    !share_mode_stale_pid(d, i)) {
			got_oplock = true;
		}
	}

	if ((granted & SMB2_LEASE_READ) && !(granted & SMB2_LEASE_WRITE)) {
		bool allow_level2 =
			(global_client_caps & CAP_LEVEL_II_OPLOCKS) &&
			lp_level2_oplocks(SNUM(fsp->conn));

		if (!allow_level2) {
			granted = SMB2_LEASE_NONE;
		}
	}

	if (oplock_request == LEASE_OPLOCK) {
		if (got_oplock) {
			granted &= ~SMB2_LEASE_HANDLE;
		}

		fsp->oplock_type = LEASE_OPLOCK;

		status = grant_fsp_lease(fsp, lck, lease, &lease_idx,
					 granted);
		if (!NT_STATUS_IS_OK(status)) {
			return status;

		}
		*lease = fsp->lease->lease;
		DEBUG(10, ("lease_state=%d\n", lease->lease_state));
	} else {
		if (got_handle_lease) {
			granted = SMB2_LEASE_NONE;
		}

		switch (granted) {
		case SMB2_LEASE_READ|SMB2_LEASE_WRITE|SMB2_LEASE_HANDLE:
			fsp->oplock_type = BATCH_OPLOCK|EXCLUSIVE_OPLOCK;
			break;
		case SMB2_LEASE_READ|SMB2_LEASE_WRITE:
			fsp->oplock_type = EXCLUSIVE_OPLOCK;
			break;
		case SMB2_LEASE_READ|SMB2_LEASE_HANDLE:
		case SMB2_LEASE_READ:
			fsp->oplock_type = LEVEL_II_OPLOCK;
			break;
		default:
			fsp->oplock_type = NO_OPLOCK;
			break;
		}

		status = set_file_oplock(fsp);
		if (!NT_STATUS_IS_OK(status)) {
			/*
			 * Could not get the kernel oplock
			 */
			fsp->oplock_type = NO_OPLOCK;
		}
	}

	ok = set_share_mode(lck, fsp, get_current_uid(fsp->conn),
			    req ? req->mid : 0,
			    fsp->oplock_type,
			    lease_idx);
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	ok = update_num_read_oplocks(fsp, lck);
	if (!ok) {
		del_share_mode(lck, fsp);
		return NT_STATUS_INTERNAL_ERROR;
	}

	DEBUG(10,("grant_fsp_oplock_type: oplock type 0x%x on file %s\n",
		  fsp->oplock_type, fsp_str_dbg(fsp)));

	return NT_STATUS_OK;
}

static bool request_timed_out(struct timeval request_time,
			      struct timeval timeout)
{
	struct timeval now, end_time;
	GetTimeOfDay(&now);
	end_time = timeval_sum(&request_time, &timeout);
	return (timeval_compare(&end_time, &now) < 0);
}

struct defer_open_state {
	struct smbXsrv_connection *xconn;
	uint64_t mid;
};

static void defer_open_done(struct tevent_req *req);

/****************************************************************************
 Handle the 1 second delay in returning a SHARING_VIOLATION error.
****************************************************************************/

static void defer_open(struct share_mode_lock *lck,
		       struct timeval request_time,
		       struct timeval timeout,
		       struct smb_request *req,
		       struct deferred_open_record *state)
{
	struct deferred_open_record *open_rec;

	DEBUG(10,("defer_open_sharing_error: time [%u.%06u] adding deferred "
		  "open entry for mid %llu\n",
		  (unsigned int)request_time.tv_sec,
		  (unsigned int)request_time.tv_usec,
		  (unsigned long long)req->mid));

	open_rec = talloc(NULL, struct deferred_open_record);
	if (open_rec == NULL) {
		TALLOC_FREE(lck);
		exit_server("talloc failed");
	}

	*open_rec = *state;

	if (lck) {
		struct defer_open_state *watch_state;
		struct tevent_req *watch_req;
		bool ret;

		watch_state = talloc(open_rec, struct defer_open_state);
		if (watch_state == NULL) {
			exit_server("talloc failed");
		}
		watch_state->xconn = req->xconn;
		watch_state->mid = req->mid;

		DEBUG(10, ("defering mid %llu\n",
			   (unsigned long long)req->mid));

		watch_req = dbwrap_record_watch_send(
			watch_state, req->sconn->ev_ctx, lck->data->record,
			req->sconn->msg_ctx);
		if (watch_req == NULL) {
			exit_server("Could not watch share mode record");
		}
		tevent_req_set_callback(watch_req, defer_open_done,
					watch_state);

		ret = tevent_req_set_endtime(
			watch_req, req->sconn->ev_ctx,
			timeval_sum(&request_time, &timeout));
		SMB_ASSERT(ret);
	}

	if (!push_deferred_open_message_smb(req, request_time, timeout,
					    state->id, open_rec)) {
		TALLOC_FREE(lck);
		exit_server("push_deferred_open_message_smb failed");
	}
}

static void defer_open_done(struct tevent_req *req)
{
	struct defer_open_state *state = tevent_req_callback_data(
		req, struct defer_open_state);
	NTSTATUS status;
	bool ret;

	status = dbwrap_record_watch_recv(req, talloc_tos(), NULL);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("dbwrap_record_watch_recv returned %s\n",
			  nt_errstr(status)));
		/*
		 * Even if it failed, retry anyway. TODO: We need a way to
		 * tell a re-scheduled open about that error.
		 */
	}

	DEBUG(10, ("scheduling mid %llu\n", (unsigned long long)state->mid));

	ret = schedule_deferred_open_message_smb(state->xconn, state->mid);
	SMB_ASSERT(ret);
	TALLOC_FREE(state);
}


/****************************************************************************
 On overwrite open ensure that the attributes match.
****************************************************************************/

static bool open_match_attributes(connection_struct *conn,
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

	DEBUG(10,("open_match_attributes: old_dos_attr = 0x%x, "
		  "existing_unx_mode = 0%o, new_dos_attr = 0x%x "
		  "returned_unx_mode = 0%o\n",
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

static NTSTATUS fcb_or_dos_open(struct smb_request *req,
				connection_struct *conn,
				files_struct *fsp_to_dup_into,
				const struct smb_filename *smb_fname,
				struct file_id id,
				uint16 file_pid,
				uint64_t vuid,
				uint32 access_mask,
				uint32 share_access,
				uint32 create_options)
{
	files_struct *fsp;

	DEBUG(5,("fcb_or_dos_open: attempting old open semantics for "
		 "file %s.\n", smb_fname_str_dbg(smb_fname)));

	for(fsp = file_find_di_first(conn->sconn, id); fsp;
	    fsp = file_find_di_next(fsp)) {

		DEBUG(10,("fcb_or_dos_open: checking file %s, fd = %d, "
			  "vuid = %llu, file_pid = %u, private_options = 0x%x "
			  "access_mask = 0x%x\n", fsp_str_dbg(fsp),
			  fsp->fh->fd, (unsigned long long)fsp->vuid,
			  (unsigned int)fsp->file_pid,
			  (unsigned int)fsp->fh->private_options,
			  (unsigned int)fsp->access_mask ));

		if (fsp != fsp_to_dup_into &&
		    fsp->fh->fd != -1 &&
		    fsp->vuid == vuid &&
		    fsp->file_pid == file_pid &&
		    (fsp->fh->private_options & (NTCREATEX_OPTIONS_PRIVATE_DENY_DOS |
						 NTCREATEX_OPTIONS_PRIVATE_DENY_FCB)) &&
		    (fsp->access_mask & FILE_WRITE_DATA) &&
		    strequal(fsp->fsp_name->base_name, smb_fname->base_name) &&
		    strequal(fsp->fsp_name->stream_name,
			     smb_fname->stream_name)) {
			DEBUG(10,("fcb_or_dos_open: file match\n"));
			break;
		}
	}

	if (!fsp) {
		return NT_STATUS_NOT_FOUND;
	}

	/* quite an insane set of semantics ... */
	if (is_executable(smb_fname->base_name) &&
	    (fsp->fh->private_options & NTCREATEX_OPTIONS_PRIVATE_DENY_DOS)) {
		DEBUG(10,("fcb_or_dos_open: file fail due to is_executable.\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* We need to duplicate this fsp. */
	return dup_file_fsp(req, fsp, access_mask, share_access,
			    create_options, fsp_to_dup_into);
}

static void schedule_defer_open(struct share_mode_lock *lck,
				struct file_id id,
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
	state.async_open = false;
	state.id = id;

	if (!request_timed_out(request_time, timeout)) {
		defer_open(lck, request_time, timeout, req, &state);
	}
}

/****************************************************************************
 Reschedule an open call that went asynchronous.
****************************************************************************/

static void schedule_async_open(struct timeval request_time,
				struct smb_request *req)
{
	struct deferred_open_record state;
	struct timeval timeout;

	timeout = timeval_set(20, 0);

	ZERO_STRUCT(state);
	state.delayed_for_oplocks = false;
	state.async_open = true;

	if (!request_timed_out(request_time, timeout)) {
		defer_open(NULL, request_time, timeout, req, &state);
	}
}

/****************************************************************************
 Work out what access_mask to use from what the client sent us.
****************************************************************************/

static NTSTATUS smbd_calculate_maximum_allowed_access(
	connection_struct *conn,
	const struct smb_filename *smb_fname,
	bool use_privs,
	uint32_t *p_access_mask)
{
	struct security_descriptor *sd;
	uint32_t access_granted;
	NTSTATUS status;

	if (!use_privs && (get_current_uid(conn) == (uid_t)0)) {
		*p_access_mask |= FILE_GENERIC_ALL;
		return NT_STATUS_OK;
	}

	status = SMB_VFS_GET_NT_ACL(conn, smb_fname->base_name,
				    (SECINFO_OWNER |
				     SECINFO_GROUP |
				     SECINFO_DACL),
				    talloc_tos(), &sd);

	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		/*
		 * File did not exist
		 */
		*p_access_mask = FILE_GENERIC_ALL;
		return NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("Could not get acl on file %s: %s\n",
			  smb_fname_str_dbg(smb_fname),
			  nt_errstr(status)));
		return NT_STATUS_ACCESS_DENIED;
	}

	/*
	 * If we can access the path to this file, by
	 * default we have FILE_READ_ATTRIBUTES from the
	 * containing directory. See the section:
	 * "Algorithm to Check Access to an Existing File"
	 * in MS-FSA.pdf.
	 *
	 * se_file_access_check()
	 * also takes care of owner WRITE_DAC and READ_CONTROL.
	 */
	status = se_file_access_check(sd,
				 get_current_nttok(conn),
				 use_privs,
				 (*p_access_mask & ~FILE_READ_ATTRIBUTES),
				 &access_granted);

	TALLOC_FREE(sd);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Access denied on file %s: "
			   "when calculating maximum access\n",
			   smb_fname_str_dbg(smb_fname)));
		return NT_STATUS_ACCESS_DENIED;
	}
	*p_access_mask = (access_granted | FILE_READ_ATTRIBUTES);

	if (!(access_granted & DELETE_ACCESS)) {
		if (can_delete_file_in_directory(conn, smb_fname)) {
			*p_access_mask |= DELETE_ACCESS;
		}
	}

	return NT_STATUS_OK;
}

NTSTATUS smbd_calculate_access_mask(connection_struct *conn,
				    const struct smb_filename *smb_fname,
				    bool use_privs,
				    uint32_t access_mask,
				    uint32_t *access_mask_out)
{
	NTSTATUS status;
	uint32_t orig_access_mask = access_mask;
	uint32_t rejected_share_access;

	/*
	 * Convert GENERIC bits to specific bits.
	 */

	se_map_generic(&access_mask, &file_generic_mapping);

	/* Calculate MAXIMUM_ALLOWED_ACCESS if requested. */
	if (access_mask & MAXIMUM_ALLOWED_ACCESS) {

		status = smbd_calculate_maximum_allowed_access(
			conn, smb_fname, use_privs, &access_mask);

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		access_mask &= conn->share_access;
	}

	rejected_share_access = access_mask & ~(conn->share_access);

	if (rejected_share_access) {
		DEBUG(10, ("smbd_calculate_access_mask: Access denied on "
			"file %s: rejected by share access mask[0x%08X] "
			"orig[0x%08X] mapped[0x%08X] reject[0x%08X]\n",
			smb_fname_str_dbg(smb_fname),
			conn->share_access,
			orig_access_mask, access_mask,
			rejected_share_access));
		return NT_STATUS_ACCESS_DENIED;
	}

	*access_mask_out = access_mask;
	return NT_STATUS_OK;
}

/****************************************************************************
 Remove the deferred open entry under lock.
****************************************************************************/

/****************************************************************************
 Return true if this is a state pointer to an asynchronous create.
****************************************************************************/

bool is_deferred_open_async(const struct deferred_open_record *rec)
{
	return rec->async_open;
}

static bool clear_ads(uint32_t create_disposition)
{
	bool ret = false;

	switch (create_disposition) {
	case FILE_SUPERSEDE:
	case FILE_OVERWRITE_IF:
	case FILE_OVERWRITE:
		ret = true;
		break;
	default:
		break;
	}
	return ret;
}

static int disposition_to_open_flags(uint32_t create_disposition)
{
	int ret = 0;

	/*
	 * Currently we're using FILE_SUPERSEDE as the same as
	 * FILE_OVERWRITE_IF but they really are
	 * different. FILE_SUPERSEDE deletes an existing file
	 * (requiring delete access) then recreates it.
	 */

	switch (create_disposition) {
	case FILE_SUPERSEDE:
	case FILE_OVERWRITE_IF:
		/*
		 * If file exists replace/overwrite. If file doesn't
		 * exist create.
		 */
		ret = O_CREAT|O_TRUNC;
		break;

	case FILE_OPEN:
		/*
		 * If file exists open. If file doesn't exist error.
		 */
		ret = 0;
		break;

	case FILE_OVERWRITE:
		/*
		 * If file exists overwrite. If file doesn't exist
		 * error.
		 */
		ret = O_TRUNC;
		break;

	case FILE_CREATE:
		/*
		 * If file exists error. If file doesn't exist create.
		 */
		ret = O_CREAT|O_EXCL;
		break;

	case FILE_OPEN_IF:
		/*
		 * If file exists open. If file doesn't exist create.
		 */
		ret = O_CREAT;
		break;
	}
	return ret;
}

static int calculate_open_access_flags(uint32_t access_mask,
				       int oplock_request,
				       uint32_t private_flags)
{
	bool need_write, need_read;

	/*
	 * Note that we ignore the append flag as append does not
	 * mean the same thing under DOS and Unix.
	 */

	need_write = (access_mask & (FILE_WRITE_DATA | FILE_APPEND_DATA));
	if (!need_write) {
		return O_RDONLY;
	}

	/* DENY_DOS opens are always underlying read-write on the
	   file handle, no matter what the requested access mask
	   says. */

	need_read =
		((private_flags & NTCREATEX_OPTIONS_PRIVATE_DENY_DOS) ||
		 access_mask & (FILE_READ_ATTRIBUTES|FILE_READ_DATA|
				FILE_READ_EA|FILE_EXECUTE));

	if (!need_read) {
		return O_WRONLY;
	}
	return O_RDWR;
}

/****************************************************************************
 Open a file with a share mode. Passed in an already created files_struct *.
****************************************************************************/

static NTSTATUS open_file_ntcreate(connection_struct *conn,
			    struct smb_request *req,
			    uint32 access_mask,		/* access bits (FILE_READ_DATA etc.) */
			    uint32 share_access,	/* share constants (FILE_SHARE_READ etc) */
			    uint32 create_disposition,	/* FILE_OPEN_IF etc. */
			    uint32 create_options,	/* options such as delete on close. */
			    uint32 new_dos_attributes,	/* attributes used for new file. */
			    int oplock_request, 	/* internal Samba oplock codes. */
			    struct smb2_lease *lease,
				 			/* Information (FILE_EXISTS etc.) */
			    uint32_t private_flags,     /* Samba specific flags. */
			    int *pinfo,
			    files_struct *fsp)
{
	struct smb_filename *smb_fname = fsp->fsp_name;
	int flags=0;
	int flags2=0;
	bool file_existed = VALID_STAT(smb_fname->st);
	bool def_acl = False;
	bool posix_open = False;
	bool new_file_created = False;
	bool first_open_attempt = true;
	NTSTATUS fsp_open = NT_STATUS_ACCESS_DENIED;
	mode_t new_unx_mode = (mode_t)0;
	mode_t unx_mode = (mode_t)0;
	int info;
	uint32 existing_dos_attributes = 0;
	struct timeval request_time = timeval_zero();
	struct share_mode_lock *lck = NULL;
	uint32 open_access_mask = access_mask;
	NTSTATUS status;
	char *parent_dir;
	SMB_STRUCT_STAT saved_stat = smb_fname->st;
	struct timespec old_write_time;
	struct file_id id;

	if (conn->printer) {
		/*
		 * Printers are handled completely differently.
		 * Most of the passed parameters are ignored.
		 */

		if (pinfo) {
			*pinfo = FILE_WAS_CREATED;
		}

		DEBUG(10, ("open_file_ntcreate: printer open fname=%s\n",
			   smb_fname_str_dbg(smb_fname)));

		if (!req) {
			DEBUG(0,("open_file_ntcreate: printer open without "
				"an SMB request!\n"));
			return NT_STATUS_INTERNAL_ERROR;
		}

		return print_spool_open(fsp, smb_fname->base_name,
					req->vuid);
	}

	if (!parent_dirname(talloc_tos(), smb_fname->base_name, &parent_dir,
			    NULL)) {
		return NT_STATUS_NO_MEMORY;
	}

	if (new_dos_attributes & FILE_FLAG_POSIX_SEMANTICS) {
		posix_open = True;
		unx_mode = (mode_t)(new_dos_attributes & ~FILE_FLAG_POSIX_SEMANTICS);
		new_dos_attributes = 0;
	} else {
		/* Windows allows a new file to be created and
		   silently removes a FILE_ATTRIBUTE_DIRECTORY
		   sent by the client. Do the same. */

		new_dos_attributes &= ~FILE_ATTRIBUTE_DIRECTORY;

		/* We add FILE_ATTRIBUTE_ARCHIVE to this as this mode is only used if the file is
		 * created new. */
		unx_mode = unix_mode(conn, new_dos_attributes | FILE_ATTRIBUTE_ARCHIVE,
				     smb_fname, parent_dir);
	}

	DEBUG(10, ("open_file_ntcreate: fname=%s, dos_attrs=0x%x "
		   "access_mask=0x%x share_access=0x%x "
		   "create_disposition = 0x%x create_options=0x%x "
		   "unix mode=0%o oplock_request=%d private_flags = 0x%x\n",
		   smb_fname_str_dbg(smb_fname), new_dos_attributes,
		   access_mask, share_access, create_disposition,
		   create_options, (unsigned int)unx_mode, oplock_request,
		   (unsigned int)private_flags));

	if (req == NULL) {
		/* Ensure req == NULL means INTERNAL_OPEN_ONLY */
		SMB_ASSERT(((oplock_request & INTERNAL_OPEN_ONLY) != 0));
	} else {
		/* And req != NULL means no INTERNAL_OPEN_ONLY */
		SMB_ASSERT(((oplock_request & INTERNAL_OPEN_ONLY) == 0));
	}

	/*
	 * Only non-internal opens can be deferred at all
	 */

	if (req) {
		struct deferred_open_record *open_rec;
		if (get_deferred_open_message_state(req,
				&request_time,
				&open_rec)) {
			/* Remember the absolute time of the original
			   request with this mid. We'll use it later to
			   see if this has timed out. */

			/* If it was an async create retry, the file
			   didn't exist. */

			if (is_deferred_open_async(open_rec)) {
				SET_STAT_INVALID(smb_fname->st);
				file_existed = false;
			}

			/* Ensure we don't reprocess this message. */
			remove_deferred_open_message_smb(req->xconn, req->mid);

			first_open_attempt = false;
		}
	}

	if (!posix_open) {
		new_dos_attributes &= SAMBA_ATTRIBUTES_MASK;
		if (file_existed) {
			existing_dos_attributes = dos_mode(conn, smb_fname);
		}
	}

	/* ignore any oplock requests if oplocks are disabled */
	if (!lp_oplocks(SNUM(conn)) ||
	    IS_VETO_OPLOCK_PATH(conn, smb_fname->base_name)) {
		/* Mask off everything except the private Samba bits. */
		oplock_request &= SAMBA_PRIVATE_OPLOCK_MASK;
	}

	/* this is for OS/2 long file names - say we don't support them */
	if (!lp_posix_pathnames() && strstr(smb_fname->base_name,".+,;=[].")) {
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
		case FILE_OPEN:
			/* If file exists open. If file doesn't exist error. */
			if (!file_existed) {
				DEBUG(5,("open_file_ntcreate: FILE_OPEN "
					 "requested for file %s and file "
					 "doesn't exist.\n",
					 smb_fname_str_dbg(smb_fname)));
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
					 "doesn't exist.\n",
					 smb_fname_str_dbg(smb_fname) ));
				errno = ENOENT;
				return NT_STATUS_OBJECT_NAME_NOT_FOUND;
			}
			break;

		case FILE_CREATE:
			/* If file exists error. If file doesn't exist
			 * create. */
			if (file_existed) {
				DEBUG(5,("open_file_ntcreate: FILE_CREATE "
					 "requested for file %s and file "
					 "already exists.\n",
					 smb_fname_str_dbg(smb_fname)));
				if (S_ISDIR(smb_fname->st.st_ex_mode)) {
					errno = EISDIR;
				} else {
					errno = EEXIST;
				}
				return map_nt_error_from_unix(errno);
			}
			break;

		case FILE_SUPERSEDE:
		case FILE_OVERWRITE_IF:
		case FILE_OPEN_IF:
			break;
		default:
			return NT_STATUS_INVALID_PARAMETER;
	}

	flags2 = disposition_to_open_flags(create_disposition);

	/* We only care about matching attributes on file exists and
	 * overwrite. */

	if (!posix_open && file_existed &&
	    ((create_disposition == FILE_OVERWRITE) ||
	     (create_disposition == FILE_OVERWRITE_IF))) {
		if (!open_match_attributes(conn, existing_dos_attributes,
					   new_dos_attributes,
					   smb_fname->st.st_ex_mode,
					   unx_mode, &new_unx_mode)) {
			DEBUG(5,("open_file_ntcreate: attributes missmatch "
				 "for file %s (%x %x) (0%o, 0%o)\n",
				 smb_fname_str_dbg(smb_fname),
				 existing_dos_attributes,
				 new_dos_attributes,
				 (unsigned int)smb_fname->st.st_ex_mode,
				 (unsigned int)unx_mode ));
			errno = EACCES;
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	status = smbd_calculate_access_mask(conn, smb_fname,
					false,
					access_mask,
					&access_mask); 
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("open_file_ntcreate: smbd_calculate_access_mask "
			"on file %s returned %s\n",
			smb_fname_str_dbg(smb_fname), nt_errstr(status)));
		return status;
	}

	open_access_mask = access_mask;

	if (flags2 & O_TRUNC) {
		open_access_mask |= FILE_WRITE_DATA; /* This will cause oplock breaks. */
	}

	DEBUG(10, ("open_file_ntcreate: fname=%s, after mapping "
		   "access_mask=0x%x\n", smb_fname_str_dbg(smb_fname),
		    access_mask));

	/*
	 * Note that we ignore the append flag as append does not
	 * mean the same thing under DOS and Unix.
	 */

	flags = calculate_open_access_flags(access_mask, oplock_request,
					    private_flags);

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

	if (first_open_attempt && lp_kernel_oplocks(SNUM(conn))) {
		/*
		 * With kernel oplocks the open breaking an oplock
		 * blocks until the oplock holder has given up the
		 * oplock or closed the file. We prevent this by first
		 * trying to open the file with O_NONBLOCK (see "man
		 * fcntl" on Linux). For the second try, triggered by
		 * an oplock break response, we do not need this
		 * anymore.
		 *
		 * This is true under the assumption that only Samba
		 * requests kernel oplocks. Once someone else like
		 * NFSv4 starts to use that API, we will have to
		 * modify this by communicating with the NFSv4 server.
		 */
		flags2 |= O_NONBLOCK;
	}

	/*
	 * Ensure we can't write on a read-only share or file.
	 */

	if (flags != O_RDONLY && file_existed &&
	    (!CAN_WRITE(conn) || IS_DOS_READONLY(existing_dos_attributes))) {
		DEBUG(5,("open_file_ntcreate: write access requested for "
			 "file %s on read only %s\n",
			 smb_fname_str_dbg(smb_fname),
			 !CAN_WRITE(conn) ? "share" : "file" ));
		errno = EACCES;
		return NT_STATUS_ACCESS_DENIED;
	}

	fsp->file_id = vfs_file_id_from_sbuf(conn, &smb_fname->st);
	fsp->share_access = share_access;
	fsp->fh->private_options = private_flags;
	fsp->access_mask = open_access_mask; /* We change this to the
					      * requested access_mask after
					      * the open is done. */
	fsp->posix_open = posix_open;

	if (timeval_is_zero(&request_time)) {
		request_time = fsp->open_time;
	}

	/*
	 * Ensure we pay attention to default ACLs on directories if required.
	 */

        if ((flags2 & O_CREAT) && lp_inherit_acls(SNUM(conn)) &&
	    (def_acl = directory_has_default_acl(conn, parent_dir))) {
		unx_mode = (0777 & lp_create_mask(SNUM(conn)));
	}

	DEBUG(4,("calling open_file with flags=0x%X flags2=0x%X mode=0%o, "
		"access_mask = 0x%x, open_access_mask = 0x%x\n",
		 (unsigned int)flags, (unsigned int)flags2,
		 (unsigned int)unx_mode, (unsigned int)access_mask,
		 (unsigned int)open_access_mask));

	fsp_open = open_file(fsp, conn, req, parent_dir,
			     flags|flags2, unx_mode, access_mask,
			     open_access_mask, &new_file_created);

	if (NT_STATUS_EQUAL(fsp_open, NT_STATUS_NETWORK_BUSY)) {
		struct deferred_open_record state;

		/*
		 * EWOULDBLOCK/EAGAIN maps to NETWORK_BUSY.
		 */
		if (file_existed && S_ISFIFO(fsp->fsp_name->st.st_ex_mode)) {
			DEBUG(10, ("FIFO busy\n"));
			return NT_STATUS_NETWORK_BUSY;
		}
		if (req == NULL) {
			DEBUG(10, ("Internal open busy\n"));
			return NT_STATUS_NETWORK_BUSY;
		}

		/*
		 * From here on we assume this is an oplock break triggered
		 */

		lck = get_existing_share_mode_lock(talloc_tos(), fsp->file_id);
		if (lck == NULL) {
			state.delayed_for_oplocks = false;
			state.async_open = false;
			state.id = fsp->file_id;
			defer_open(NULL, request_time, timeval_set(0, 0),
				   req, &state);
			DEBUG(10, ("No share mode lock found after "
				   "EWOULDBLOCK, retrying sync\n"));
			return NT_STATUS_SHARING_VIOLATION;
		}

		if (!validate_oplock_types(lck)) {
			smb_panic("validate_oplock_types failed");
		}

		if (delay_for_oplock(fsp, 0, lease, lck, false,
				     create_disposition, first_open_attempt)) {
			schedule_defer_open(lck, fsp->file_id, request_time,
					    req);
			TALLOC_FREE(lck);
			DEBUG(10, ("Sent oplock break request to kernel "
				   "oplock holder\n"));
			return NT_STATUS_SHARING_VIOLATION;
		}

		/*
		 * No oplock from Samba around. Immediately retry with
		 * a blocking open.
		 */
		state.delayed_for_oplocks = false;
		state.async_open = false;
		state.id = fsp->file_id;
		defer_open(lck, request_time, timeval_set(0, 0), req, &state);
		TALLOC_FREE(lck);
		DEBUG(10, ("No Samba oplock around after EWOULDBLOCK. "
			   "Retrying sync\n"));
		return NT_STATUS_SHARING_VIOLATION;
	}

	if (!NT_STATUS_IS_OK(fsp_open)) {
		if (NT_STATUS_EQUAL(fsp_open, NT_STATUS_RETRY)) {
			schedule_async_open(request_time, req);
		}
		return fsp_open;
	}

	if (new_file_created) {
		/*
		 * As we atomically create using O_CREAT|O_EXCL,
		 * then if new_file_created is true, then
		 * file_existed *MUST* have been false (even
		 * if the file was previously detected as being
		 * there).
		 */
		file_existed = false;
	}

	if (file_existed && !check_same_dev_ino(&saved_stat, &smb_fname->st)) {
		/*
		 * The file did exist, but some other (local or NFS)
		 * process either renamed/unlinked and re-created the
		 * file with different dev/ino after we walked the path,
		 * but before we did the open. We could retry the
		 * open but it's a rare enough case it's easier to
		 * just fail the open to prevent creating any problems
		 * in the open file db having the wrong dev/ino key.
		 */
		fd_close(fsp);
		DEBUG(1,("open_file_ntcreate: file %s - dev/ino mismatch. "
			"Old (dev=0x%llu, ino =0x%llu). "
			"New (dev=0x%llu, ino=0x%llu). Failing open "
			" with NT_STATUS_ACCESS_DENIED.\n",
			 smb_fname_str_dbg(smb_fname),
			 (unsigned long long)saved_stat.st_ex_dev,
			 (unsigned long long)saved_stat.st_ex_ino,
			 (unsigned long long)smb_fname->st.st_ex_dev,
			 (unsigned long long)smb_fname->st.st_ex_ino));
		return NT_STATUS_ACCESS_DENIED;
	}

	old_write_time = smb_fname->st.st_ex_mtime;

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
				  smb_fname, &old_write_time);

	if (lck == NULL) {
		DEBUG(0, ("open_file_ntcreate: Could not get share "
			  "mode lock for %s\n",
			  smb_fname_str_dbg(smb_fname)));
		fd_close(fsp);
		return NT_STATUS_SHARING_VIOLATION;
	}

	/* Get the types we need to examine. */
	if (!validate_oplock_types(lck)) {
		smb_panic("validate_oplock_types failed");
	}

	if (has_delete_on_close(lck, fsp->name_hash)) {
		TALLOC_FREE(lck);
		fd_close(fsp);
		return NT_STATUS_DELETE_PENDING;
	}

	status = open_mode_check(conn, lck,
				 access_mask, share_access);

	if (NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION) ||
	    (lck->data->num_share_modes > 0)) {
		/*
		 * This comes from ancient times out of open_mode_check. I
		 * have no clue whether this is still necessary. I can't think
		 * of a case where this would actually matter further down in
		 * this function. I leave it here for further investigation
		 * :-)
		 */
		file_existed = true;
	}

	if ((req != NULL) &&
	    delay_for_oplock(
		    fsp, oplock_request, lease, lck,
		    NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION),
		    create_disposition, first_open_attempt)) {
		schedule_defer_open(lck, fsp->file_id, request_time, req);
		TALLOC_FREE(lck);
		fd_close(fsp);
		return NT_STATUS_SHARING_VIOLATION;
	}

	if (!NT_STATUS_IS_OK(status)) {
		uint32 can_access_mask;
		bool can_access = True;

		SMB_ASSERT(NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION));

		/* Check if this can be done with the deny_dos and fcb
		 * calls. */
		if (private_flags &
		    (NTCREATEX_OPTIONS_PRIVATE_DENY_DOS|
		     NTCREATEX_OPTIONS_PRIVATE_DENY_FCB)) {
			if (req == NULL) {
				DEBUG(0, ("DOS open without an SMB "
					  "request!\n"));
				TALLOC_FREE(lck);
				fd_close(fsp);
				return NT_STATUS_INTERNAL_ERROR;
			}

			/* Use the client requested access mask here,
			 * not the one we open with. */
			status = fcb_or_dos_open(req,
						 conn,
						 fsp,
						 smb_fname,
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

		if (((can_access_mask & FILE_WRITE_DATA) &&
		     !CAN_WRITE(conn)) ||
		    !NT_STATUS_IS_OK(smbd_check_access_rights(conn,
							      smb_fname,
							      false,
							      can_access_mask))) {
			can_access = False;
		}

		/*
		 * If we're returning a share violation, ensure we
		 * cope with the braindead 1 second delay (SMB1 only).
		 */

		if (!(oplock_request & INTERNAL_OPEN_ONLY) &&
		    !conn->sconn->using_smb2 &&
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
			state.async_open = false;
			state.id = id;

			if ((req != NULL)
			    && !request_timed_out(request_time,
						  timeout)) {
				defer_open(lck, request_time, timeout,
					   req, &state);
			}
		}

		TALLOC_FREE(lck);
		fd_close(fsp);
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

	/* Should we atomically (to the client at least) truncate ? */
	if ((!new_file_created) &&
	    (flags2 & O_TRUNC) &&
	    (!S_ISFIFO(fsp->fsp_name->st.st_ex_mode))) {
		int ret;

		ret = vfs_set_filelen(fsp, 0);
		if (ret != 0) {
			status = map_nt_error_from_unix(errno);
			TALLOC_FREE(lck);
			fd_close(fsp);
			return status;
		}
	}

	/*
	 * We have the share entry *locked*.....
	 */

	/* Delete streams if create_disposition requires it */
	if (!new_file_created && clear_ads(create_disposition) &&
	    !is_ntfs_stream_smb_fname(smb_fname)) {
		status = delete_all_streams(conn, smb_fname->base_name);
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

	if (fsp->fh->fd != -1 && lp_kernel_share_modes(SNUM(conn))) {
		int ret_flock;
		/*
		 * Beware: streams implementing VFS modules may
		 * implement streams in a way that fsp will have the
		 * basefile open in the fsp fd, so lacking a distinct
		 * fd for the stream kernel_flock will apply on the
		 * basefile which is wrong. The actual check is
		 * deffered to the VFS module implementing the
		 * kernel_flock call.
		 */
		ret_flock = SMB_VFS_KERNEL_FLOCK(fsp, share_access, access_mask);
		if(ret_flock == -1 ){

			TALLOC_FREE(lck);
			fd_close(fsp);

			return NT_STATUS_SHARING_VIOLATION;
		}
	}

	/*
	 * At this point onwards, we can guarantee that the share entry
	 * is locked, whether we created the file or not, and that the
	 * deny mode is compatible with all current opens.
	 */

	/*
	 * According to Samba4, SEC_FILE_READ_ATTRIBUTE is always granted,
	 * but we don't have to store this - just ignore it on access check.
	 */
	if (conn->sconn->using_smb2) {
		/*
		 * SMB2 doesn't return it (according to Microsoft tests).
		 * Test Case: TestSuite_ScenarioNo009GrantedAccessTestS0
		 * File created with access = 0x7 (Read, Write, Delete)
		 * Query Info on file returns 0x87 (Read, Write, Delete, Read Attributes)
		 */
		fsp->access_mask = access_mask;
	} else {
		/* But SMB1 does. */
		fsp->access_mask = access_mask | FILE_READ_ATTRIBUTES;
	}

	if (file_existed) {
		/*
		 * stat opens on existing files don't get oplocks.
		 * They can get leases.
		 *
		 * Note that we check for stat open on the *open_access_mask*,
		 * i.e. the access mask we actually used to do the open,
		 * not the one the client asked for (which is in
		 * fsp->access_mask). This is due to the fact that
		 * FILE_OVERWRITE and FILE_OVERWRITE_IF add in O_TRUNC,
		 * which adds FILE_WRITE_DATA to open_access_mask.
		 */
		if (is_stat_open(open_access_mask) && lease == NULL) {
			oplock_request = NO_OPLOCK;
		}
	}

	if (new_file_created) {
		info = FILE_WAS_CREATED;
	} else {
		if (flags2 & O_TRUNC) {
			info = FILE_WAS_OVERWRITTEN;
		} else {
			info = FILE_WAS_OPENED;
		}
	}

	if (pinfo) {
		*pinfo = info;
	}

	/*
	 * Setup the oplock info in both the shared memory and
	 * file structs.
	 */
	status = grant_fsp_oplock_type(req, fsp, lck, oplock_request, lease);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(lck);
		fd_close(fsp);
		return status;
	}

	/* Handle strange delete on close create semantics. */
	if (create_options & FILE_DELETE_ON_CLOSE) {

		status = can_set_delete_on_close(fsp, new_dos_attributes);

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

	if (info != FILE_WAS_OPENED) {
		/* Files should be initially set as archive */
		if (lp_map_archive(SNUM(conn)) ||
		    lp_store_dos_attributes(SNUM(conn))) {
			if (!posix_open) {
				if (file_set_dosmode(conn, smb_fname,
					    new_dos_attributes | FILE_ATTRIBUTE_ARCHIVE,
					    parent_dir, true) == 0) {
					unx_mode = smb_fname->st.st_ex_mode;
				}
			}
		}
	}

	/* Determine sparse flag. */
	if (posix_open) {
		/* POSIX opens are sparse by default. */
		fsp->is_sparse = true;
	} else {
		fsp->is_sparse = (file_existed &&
			(existing_dos_attributes & FILE_ATTRIBUTE_SPARSE));
	}

	/*
	 * Take care of inherited ACLs on created files - if default ACL not
	 * selected.
	 */

	if (!posix_open && new_file_created && !def_acl) {

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
					  smb_fname_str_dbg(smb_fname),
					  (unsigned int)new_unx_mode));
				ret = 0; /* Don't do the fchmod below. */
			}
		}

		if ((ret == -1) &&
		    (SMB_VFS_FCHMOD(fsp, new_unx_mode) == -1))
			DEBUG(5, ("open_file_ntcreate: failed to reset "
				  "attributes of file %s to 0%o\n",
				  smb_fname_str_dbg(smb_fname),
				  (unsigned int)new_unx_mode));
	}

	{
		/*
		 * Deal with other opens having a modified write time.
		 */
		struct timespec write_time = get_share_mode_write_time(lck);

		if (!null_timespec(write_time)) {
			update_stat_ex_mtime(&fsp->fsp_name->st, write_time);
		}
	}

	TALLOC_FREE(lck);

	return NT_STATUS_OK;
}

static NTSTATUS mkdir_internal(connection_struct *conn,
			       struct smb_filename *smb_dname,
			       uint32 file_attributes)
{
	mode_t mode;
	char *parent_dir = NULL;
	NTSTATUS status;
	bool posix_open = false;
	bool need_re_stat = false;
	uint32_t access_mask = SEC_DIR_ADD_SUBDIR;

	if (!CAN_WRITE(conn) || (access_mask & ~(conn->share_access))) {
		DEBUG(5,("mkdir_internal: failing share access "
			 "%s\n", lp_servicename(talloc_tos(), SNUM(conn))));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!parent_dirname(talloc_tos(), smb_dname->base_name, &parent_dir,
			    NULL)) {
		return NT_STATUS_NO_MEMORY;
	}

	if (file_attributes & FILE_FLAG_POSIX_SEMANTICS) {
		posix_open = true;
		mode = (mode_t)(file_attributes & ~FILE_FLAG_POSIX_SEMANTICS);
	} else {
		mode = unix_mode(conn, FILE_ATTRIBUTE_DIRECTORY, smb_dname, parent_dir);
	}

	status = check_parent_access(conn,
					smb_dname,
					access_mask);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("mkdir_internal: check_parent_access "
			"on directory %s for path %s returned %s\n",
			parent_dir,
			smb_dname->base_name,
			nt_errstr(status) ));
		return status;
	}

	if (SMB_VFS_MKDIR(conn, smb_dname->base_name, mode) != 0) {
		return map_nt_error_from_unix(errno);
	}

	/* Ensure we're checking for a symlink here.... */
	/* We don't want to get caught by a symlink racer. */

	if (SMB_VFS_LSTAT(conn, smb_dname) == -1) {
		DEBUG(2, ("Could not stat directory '%s' just created: %s\n",
			  smb_fname_str_dbg(smb_dname), strerror(errno)));
		return map_nt_error_from_unix(errno);
	}

	if (!S_ISDIR(smb_dname->st.st_ex_mode)) {
		DEBUG(0, ("Directory '%s' just created is not a directory !\n",
			  smb_fname_str_dbg(smb_dname)));
		return NT_STATUS_NOT_A_DIRECTORY;
	}

	if (lp_store_dos_attributes(SNUM(conn))) {
		if (!posix_open) {
			file_set_dosmode(conn, smb_dname,
					 file_attributes | FILE_ATTRIBUTE_DIRECTORY,
					 parent_dir, true);
		}
	}

	if (lp_inherit_permissions(SNUM(conn))) {
		inherit_access_posix_acl(conn, parent_dir,
					 smb_dname->base_name, mode);
		need_re_stat = true;
	}

	if (!posix_open) {
		/*
		 * Check if high bits should have been set,
		 * then (if bits are missing): add them.
		 * Consider bits automagically set by UNIX, i.e. SGID bit from parent
		 * dir.
		 */
		if ((mode & ~(S_IRWXU|S_IRWXG|S_IRWXO)) &&
		    (mode & ~smb_dname->st.st_ex_mode)) {
			SMB_VFS_CHMOD(conn, smb_dname->base_name,
				      (smb_dname->st.st_ex_mode |
					  (mode & ~smb_dname->st.st_ex_mode)));
			need_re_stat = true;
		}
	}

	/* Change the owner if required. */
	if (lp_inherit_owner(SNUM(conn))) {
		change_dir_owner_to_parent(conn, parent_dir,
					   smb_dname->base_name,
					   &smb_dname->st);
		need_re_stat = true;
	}

	if (need_re_stat) {
		if (SMB_VFS_LSTAT(conn, smb_dname) == -1) {
			DEBUG(2, ("Could not stat directory '%s' just created: %s\n",
			  smb_fname_str_dbg(smb_dname), strerror(errno)));
			return map_nt_error_from_unix(errno);
		}
	}

	notify_fname(conn, NOTIFY_ACTION_ADDED, FILE_NOTIFY_CHANGE_DIR_NAME,
		     smb_dname->base_name);

	return NT_STATUS_OK;
}

/****************************************************************************
 Open a directory from an NT SMB call.
****************************************************************************/

static NTSTATUS open_directory(connection_struct *conn,
			       struct smb_request *req,
			       struct smb_filename *smb_dname,
			       uint32 access_mask,
			       uint32 share_access,
			       uint32 create_disposition,
			       uint32 create_options,
			       uint32 file_attributes,
			       int *pinfo,
			       files_struct **result)
{
	files_struct *fsp = NULL;
	bool dir_existed = VALID_STAT(smb_dname->st) ? True : False;
	struct share_mode_lock *lck = NULL;
	NTSTATUS status;
	struct timespec mtimespec;
	int info = 0;
	bool ok;

	if (is_ntfs_stream_smb_fname(smb_dname)) {
		DEBUG(2, ("open_directory: %s is a stream name!\n",
			  smb_fname_str_dbg(smb_dname)));
		return NT_STATUS_NOT_A_DIRECTORY;
	}

	if (!(file_attributes & FILE_FLAG_POSIX_SEMANTICS)) {
		/* Ensure we have a directory attribute. */
		file_attributes |= FILE_ATTRIBUTE_DIRECTORY;
	}

	DEBUG(5,("open_directory: opening directory %s, access_mask = 0x%x, "
		 "share_access = 0x%x create_options = 0x%x, "
		 "create_disposition = 0x%x, file_attributes = 0x%x\n",
		 smb_fname_str_dbg(smb_dname),
		 (unsigned int)access_mask,
		 (unsigned int)share_access,
		 (unsigned int)create_options,
		 (unsigned int)create_disposition,
		 (unsigned int)file_attributes));

	status = smbd_calculate_access_mask(conn, smb_dname, false,
					    access_mask, &access_mask);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("open_directory: smbd_calculate_access_mask "
			"on file %s returned %s\n",
			smb_fname_str_dbg(smb_dname),
			nt_errstr(status)));
		return status;
	}

	if ((access_mask & SEC_FLAG_SYSTEM_SECURITY) &&
			!security_token_has_privilege(get_current_nttok(conn),
					SEC_PRIV_SECURITY)) {
		DEBUG(10, ("open_directory: open on %s "
			"failed - SEC_FLAG_SYSTEM_SECURITY denied.\n",
			smb_fname_str_dbg(smb_dname)));
		return NT_STATUS_PRIVILEGE_NOT_HELD;
	}

	switch( create_disposition ) {
		case FILE_OPEN:

			if (!dir_existed) {
				return NT_STATUS_OBJECT_NAME_NOT_FOUND;
			}

			info = FILE_WAS_OPENED;
			break;

		case FILE_CREATE:

			/* If directory exists error. If directory doesn't
			 * exist create. */

			if (dir_existed) {
				status = NT_STATUS_OBJECT_NAME_COLLISION;
				DEBUG(2, ("open_directory: unable to create "
					  "%s. Error was %s\n",
					  smb_fname_str_dbg(smb_dname),
					  nt_errstr(status)));
				return status;
			}

			status = mkdir_internal(conn, smb_dname,
						file_attributes);

			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(2, ("open_directory: unable to create "
					  "%s. Error was %s\n",
					  smb_fname_str_dbg(smb_dname),
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

			if (dir_existed) {
				status = NT_STATUS_OK;
				info = FILE_WAS_OPENED;
			} else {
				status = mkdir_internal(conn, smb_dname,
						file_attributes);

				if (NT_STATUS_IS_OK(status)) {
					info = FILE_WAS_CREATED;
				} else {
					/* Cope with create race. */
					if (!NT_STATUS_EQUAL(status,
							NT_STATUS_OBJECT_NAME_COLLISION)) {
						DEBUG(2, ("open_directory: unable to create "
							"%s. Error was %s\n",
							smb_fname_str_dbg(smb_dname),
							nt_errstr(status)));
						return status;
					}
					info = FILE_WAS_OPENED;
				}
			}

			break;

		case FILE_SUPERSEDE:
		case FILE_OVERWRITE:
		case FILE_OVERWRITE_IF:
		default:
			DEBUG(5,("open_directory: invalid create_disposition "
				 "0x%x for directory %s\n",
				 (unsigned int)create_disposition,
				 smb_fname_str_dbg(smb_dname)));
			return NT_STATUS_INVALID_PARAMETER;
	}

	if(!S_ISDIR(smb_dname->st.st_ex_mode)) {
		DEBUG(5,("open_directory: %s is not a directory !\n",
			 smb_fname_str_dbg(smb_dname)));
		return NT_STATUS_NOT_A_DIRECTORY;
	}

	if (info == FILE_WAS_OPENED) {
		status = smbd_check_access_rights(conn,
						smb_dname,
						false,
						access_mask);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("open_directory: smbd_check_access_rights on "
				"file %s failed with %s\n",
				smb_fname_str_dbg(smb_dname),
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

	fsp->file_id = vfs_file_id_from_sbuf(conn, &smb_dname->st);
	fsp->vuid = req ? req->vuid : UID_FIELD_INVALID;
	fsp->file_pid = req ? req->smbpid : 0;
	fsp->can_lock = False;
	fsp->can_read = False;
	fsp->can_write = False;

	fsp->share_access = share_access;
	fsp->fh->private_options = 0;
	/*
	 * According to Samba4, SEC_FILE_READ_ATTRIBUTE is always granted,
	 */
	fsp->access_mask = access_mask | FILE_READ_ATTRIBUTES;
	fsp->print_file = NULL;
	fsp->modified = False;
	fsp->oplock_type = NO_OPLOCK;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->is_directory = True;
	fsp->posix_open = (file_attributes & FILE_FLAG_POSIX_SEMANTICS) ? True : False;
	status = fsp_set_smb_fname(fsp, smb_dname);
	if (!NT_STATUS_IS_OK(status)) {
		file_free(req, fsp);
		return status;
	}

	/* Don't store old timestamps for directory
	   handles in the internal database. We don't
	   update them in there if new objects
	   are creaded in the directory. Currently
	   we only update timestamps on file writes.
	   See bug #9870.
	*/
	ZERO_STRUCT(mtimespec);

	if (access_mask & (FILE_LIST_DIRECTORY|
			   FILE_ADD_FILE|
			   FILE_ADD_SUBDIRECTORY|
			   FILE_TRAVERSE|
			   DELETE_ACCESS|
			   FILE_DELETE_CHILD)) {
#ifdef O_DIRECTORY
		status = fd_open(conn, fsp, O_RDONLY|O_DIRECTORY, 0);
#else
		/* POSIX allows us to open a directory with O_RDONLY. */
		status = fd_open(conn, fsp, O_RDONLY, 0);
#endif
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(5, ("open_directory: Could not open fd for "
				"%s (%s)\n",
				smb_fname_str_dbg(smb_dname),
				nt_errstr(status)));
			file_free(req, fsp);
			return status;
		}
	} else {
		fsp->fh->fd = -1;
		DEBUG(10, ("Not opening Directory %s\n",
			smb_fname_str_dbg(smb_dname)));
	}

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		fd_close(fsp);
		file_free(req, fsp);
		return status;
	}

	/* Ensure there was no race condition. */
	if (!check_same_stat(&smb_dname->st, &fsp->fsp_name->st)) {
		DEBUG(5,("open_directory: stat struct differs for "
			"directory %s.\n",
			smb_fname_str_dbg(smb_dname)));
		fd_close(fsp);
		file_free(req, fsp);
		return NT_STATUS_ACCESS_DENIED;
	}

	lck = get_share_mode_lock(talloc_tos(), fsp->file_id,
				  conn->connectpath, smb_dname,
				  &mtimespec);

	if (lck == NULL) {
		DEBUG(0, ("open_directory: Could not get share mode lock for "
			  "%s\n", smb_fname_str_dbg(smb_dname)));
		fd_close(fsp);
		file_free(req, fsp);
		return NT_STATUS_SHARING_VIOLATION;
	}

	if (has_delete_on_close(lck, fsp->name_hash)) {
		TALLOC_FREE(lck);
		fd_close(fsp);
		file_free(req, fsp);
		return NT_STATUS_DELETE_PENDING;
	}

	status = open_mode_check(conn, lck,
				 access_mask, share_access);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(lck);
		fd_close(fsp);
		file_free(req, fsp);
		return status;
	}

	ok = set_share_mode(lck, fsp, get_current_uid(conn),
			    req ? req->mid : 0, NO_OPLOCK,
			    UINT32_MAX);
	if (!ok) {
		TALLOC_FREE(lck);
		fd_close(fsp);
		file_free(req, fsp);
		return NT_STATUS_NO_MEMORY;
	}

	/* For directories the delete on close bit at open time seems
	   always to be honored on close... See test 19 in Samba4 BASE-DELETE. */
	if (create_options & FILE_DELETE_ON_CLOSE) {
		status = can_set_delete_on_close(fsp, 0);
		if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, NT_STATUS_DIRECTORY_NOT_EMPTY)) {
			del_share_mode(lck, fsp);
			TALLOC_FREE(lck);
			fd_close(fsp);
			file_free(req, fsp);
			return status;
		}

		if (NT_STATUS_IS_OK(status)) {
			/* Note that here we set the *inital* delete on close flag,
			   not the regular one. The magic gets handled in close. */
			fsp->initial_delete_on_close = True;
		}
	}

	{
		/*
		 * Deal with other opens having a modified write time. Is this
		 * possible for directories?
		 */
		struct timespec write_time = get_share_mode_write_time(lck);

		if (!null_timespec(write_time)) {
			update_stat_ex_mtime(&fsp->fsp_name->st, write_time);
		}
	}

	TALLOC_FREE(lck);

	if (pinfo) {
		*pinfo = info;
	}

	*result = fsp;
	return NT_STATUS_OK;
}

NTSTATUS create_directory(connection_struct *conn, struct smb_request *req,
			  struct smb_filename *smb_dname)
{
	NTSTATUS status;
	files_struct *fsp;

	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		0,					/* root_dir_fid */
		smb_dname,				/* fname */
		FILE_READ_ATTRIBUTES,			/* access_mask */
		FILE_SHARE_NONE,			/* share_access */
		FILE_CREATE,				/* create_disposition*/
		FILE_DIRECTORY_FILE,			/* create_options */
		FILE_ATTRIBUTE_DIRECTORY,		/* file_attributes */
		0,					/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		NULL,					/* pinfo */
		NULL, NULL);				/* create context */

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
	const char *base_name;
	const char *stream_name;
	struct smb_filename *smb_fname = NULL;
	size_t sp_len, bn_len;
	NTSTATUS status;
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);

	if (data->data == NULL
	    || data->length < MSG_FILE_RENAMED_MIN_SIZE + 2) {
                DEBUG(0, ("msg_file_was_renamed: Got invalid msg len %d\n",
			  (int)data->length));
                return;
        }

	/* Unpack the message. */
	pull_file_id_24(frm, &id);
	sharepath = &frm[24];
	sp_len = strlen(sharepath);
	base_name = sharepath + sp_len + 1;
	bn_len = strlen(base_name);
	stream_name = sharepath + sp_len + 1 + bn_len + 1;

	/* stream_name must always be NULL if there is no stream. */
	if (stream_name[0] == '\0') {
		stream_name = NULL;
	}

	smb_fname = synthetic_smb_fname(talloc_tos(), base_name,
					stream_name, NULL);
	if (smb_fname == NULL) {
		return;
	}

	DEBUG(10,("msg_file_was_renamed: Got rename message for sharepath %s, new name %s, "
		"file_id %s\n",
		sharepath, smb_fname_str_dbg(smb_fname),
		file_id_string_tos(&id)));

	for(fsp = file_find_di_first(sconn, id); fsp;
	    fsp = file_find_di_next(fsp)) {
		if (memcmp(fsp->conn->connectpath, sharepath, sp_len) == 0) {

			DEBUG(10,("msg_file_was_renamed: renaming file %s from %s -> %s\n",
				fsp_fnum_dbg(fsp), fsp_str_dbg(fsp),
				smb_fname_str_dbg(smb_fname)));
			status = fsp_set_smb_fname(fsp, smb_fname);
			if (!NT_STATUS_IS_OK(status)) {
				goto out;
			}
		} else {
			/* TODO. JRA. */
			/* Now we have the complete path we can work out if this is
			   actually within this share and adjust newname accordingly. */
	                DEBUG(10,("msg_file_was_renamed: share mismatch (sharepath %s "
				"not sharepath %s) "
				"%s from %s -> %s\n",
				fsp->conn->connectpath,
				sharepath,
				fsp_fnum_dbg(fsp),
				fsp_str_dbg(fsp),
				smb_fname_str_dbg(smb_fname)));
		}
        }
 out:
	TALLOC_FREE(smb_fname);
	return;
}

/*
 * If a main file is opened for delete, all streams need to be checked for
 * !FILE_SHARE_DELETE. Do this by opening with DELETE_ACCESS.
 * If that works, delete them all by setting the delete on close and close.
 */

NTSTATUS open_streams_for_delete(connection_struct *conn,
					const char *fname)
{
	struct stream_struct *stream_info = NULL;
	files_struct **streams = NULL;
	int i;
	unsigned int num_streams = 0;
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;

	status = vfs_streaminfo(conn, NULL, fname, talloc_tos(),
				&num_streams, &stream_info);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_IMPLEMENTED)
	    || NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		DEBUG(10, ("no streams around\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("vfs_streaminfo failed: %s\n",
			   nt_errstr(status)));
		goto fail;
	}

	DEBUG(10, ("open_streams_for_delete found %d streams\n",
		   num_streams));

	if (num_streams == 0) {
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	streams = talloc_array(talloc_tos(), files_struct *, num_streams);
	if (streams == NULL) {
		DEBUG(0, ("talloc failed\n"));
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	for (i=0; i<num_streams; i++) {
		struct smb_filename *smb_fname;

		if (strequal(stream_info[i].name, "::$DATA")) {
			streams[i] = NULL;
			continue;
		}

		smb_fname = synthetic_smb_fname(
			talloc_tos(), fname, stream_info[i].name, NULL);
		if (smb_fname == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}

		if (SMB_VFS_STAT(conn, smb_fname) == -1) {
			DEBUG(10, ("Unable to stat stream: %s\n",
				   smb_fname_str_dbg(smb_fname)));
		}

		status = SMB_VFS_CREATE_FILE(
			 conn,			/* conn */
			 NULL,			/* req */
			 0,			/* root_dir_fid */
			 smb_fname,		/* fname */
			 DELETE_ACCESS,		/* access_mask */
			 (FILE_SHARE_READ |	/* share_access */
			     FILE_SHARE_WRITE | FILE_SHARE_DELETE),
			 FILE_OPEN,		/* create_disposition*/
			 0, 			/* create_options */
			 FILE_ATTRIBUTE_NORMAL,	/* file_attributes */
			 0,			/* oplock_request */
			 NULL,			/* lease */
			 0,			/* allocation_size */
			 NTCREATEX_OPTIONS_PRIVATE_STREAM_DELETE, /* private_flags */
			 NULL,			/* sd */
			 NULL,			/* ea_list */
			 &streams[i],		/* result */
			 NULL,			/* pinfo */
			 NULL, NULL);		/* create context */

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("Could not open stream %s: %s\n",
				   smb_fname_str_dbg(smb_fname),
				   nt_errstr(status)));

			TALLOC_FREE(smb_fname);
			break;
		}
		TALLOC_FREE(smb_fname);
	}

	/*
	 * don't touch the variable "status" beyond this point :-)
	 */

	for (i -= 1 ; i >= 0; i--) {
		if (streams[i] == NULL) {
			continue;
		}

		DEBUG(10, ("Closing stream # %d, %s\n", i,
			   fsp_str_dbg(streams[i])));
		close_file(NULL, streams[i], NORMAL_CLOSE);
	}

 fail:
	TALLOC_FREE(frame);
	return status;
}

/*********************************************************************
 Create a default ACL by inheriting from the parent. If no inheritance
 from the parent available, don't set anything. This will leave the actual
 permissions the new file or directory already got from the filesystem
 as the NT ACL when read.
*********************************************************************/

static NTSTATUS inherit_new_acl(files_struct *fsp)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *parent_name = NULL;
	struct security_descriptor *parent_desc = NULL;
	NTSTATUS status = NT_STATUS_OK;
	struct security_descriptor *psd = NULL;
	const struct dom_sid *owner_sid = NULL;
	const struct dom_sid *group_sid = NULL;
	uint32_t security_info_sent = (SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL);
	struct security_token *token = fsp->conn->session_info->security_token;
	bool inherit_owner = lp_inherit_owner(SNUM(fsp->conn));
	bool inheritable_components = false;
	bool try_builtin_administrators = false;
	const struct dom_sid *BA_U_sid = NULL;
	const struct dom_sid *BA_G_sid = NULL;
	bool try_system = false;
	const struct dom_sid *SY_U_sid = NULL;
	const struct dom_sid *SY_G_sid = NULL;
	size_t size = 0;

	if (!parent_dirname(frame, fsp->fsp_name->base_name, &parent_name, NULL)) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	status = SMB_VFS_GET_NT_ACL(fsp->conn,
				    parent_name,
				    (SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL),
				    frame,
				    &parent_desc);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	inheritable_components = sd_has_inheritable_components(parent_desc,
					fsp->is_directory);

	if (!inheritable_components && !inherit_owner) {
		TALLOC_FREE(frame);
		/* Nothing to inherit and not setting owner. */
		return NT_STATUS_OK;
	}

	/* Create an inherited descriptor from the parent. */

	if (DEBUGLEVEL >= 10) {
		DEBUG(10,("inherit_new_acl: parent acl for %s is:\n",
			fsp_str_dbg(fsp) ));
		NDR_PRINT_DEBUG(security_descriptor, parent_desc);
	}

	/* Inherit from parent descriptor if "inherit owner" set. */
	if (inherit_owner) {
		owner_sid = parent_desc->owner_sid;
		group_sid = parent_desc->group_sid;
	}

	if (owner_sid == NULL) {
		if (security_token_has_builtin_administrators(token)) {
			try_builtin_administrators = true;
		} else if (security_token_is_system(token)) {
			try_builtin_administrators = true;
			try_system = true;
		}
	}

	if (group_sid == NULL &&
	    token->num_sids == PRIMARY_GROUP_SID_INDEX)
	{
		if (security_token_is_system(token)) {
			try_builtin_administrators = true;
			try_system = true;
		}
	}

	if (try_builtin_administrators) {
		struct unixid ids;
		bool ok;

		ZERO_STRUCT(ids);
		ok = sids_to_unixids(&global_sid_Builtin_Administrators, 1, &ids);
		if (ok) {
			switch (ids.type) {
			case ID_TYPE_BOTH:
				BA_U_sid = &global_sid_Builtin_Administrators;
				BA_G_sid = &global_sid_Builtin_Administrators;
				break;
			case ID_TYPE_UID:
				BA_U_sid = &global_sid_Builtin_Administrators;
				break;
			case ID_TYPE_GID:
				BA_G_sid = &global_sid_Builtin_Administrators;
				break;
			default:
				break;
			}
		}
	}

	if (try_system) {
		struct unixid ids;
		bool ok;

		ZERO_STRUCT(ids);
		ok = sids_to_unixids(&global_sid_System, 1, &ids);
		if (ok) {
			switch (ids.type) {
			case ID_TYPE_BOTH:
				SY_U_sid = &global_sid_System;
				SY_G_sid = &global_sid_System;
				break;
			case ID_TYPE_UID:
				SY_U_sid = &global_sid_System;
				break;
			case ID_TYPE_GID:
				SY_G_sid = &global_sid_System;
				break;
			default:
				break;
			}
		}
	}

	if (owner_sid == NULL) {
		owner_sid = BA_U_sid;
	}

	if (owner_sid == NULL) {
		owner_sid = SY_U_sid;
	}

	if (group_sid == NULL) {
		group_sid = SY_G_sid;
	}

	if (try_system && group_sid == NULL) {
		group_sid = BA_G_sid;
	}

	if (owner_sid == NULL) {
		owner_sid = &token->sids[PRIMARY_USER_SID_INDEX];
	}
	if (group_sid == NULL) {
		if (token->num_sids == PRIMARY_GROUP_SID_INDEX) {
			group_sid = &token->sids[PRIMARY_USER_SID_INDEX];
		} else {
			group_sid = &token->sids[PRIMARY_GROUP_SID_INDEX];
		}
	}

	status = se_create_child_secdesc(frame,
			&psd,
			&size,
			parent_desc,
			owner_sid,
			group_sid,
			fsp->is_directory);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	/* If inheritable_components == false,
	   se_create_child_secdesc()
	   creates a security desriptor with a NULL dacl
	   entry, but with SEC_DESC_DACL_PRESENT. We need
	   to remove that flag. */

	if (!inheritable_components) {
		security_info_sent &= ~SECINFO_DACL;
		psd->type &= ~SEC_DESC_DACL_PRESENT;
	}

	if (DEBUGLEVEL >= 10) {
		DEBUG(10,("inherit_new_acl: child acl for %s is:\n",
			fsp_str_dbg(fsp) ));
		NDR_PRINT_DEBUG(security_descriptor, psd);
	}

	if (inherit_owner) {
		/* We need to be root to force this. */
		become_root();
	}
	status = SMB_VFS_FSET_NT_ACL(fsp,
			security_info_sent,
			psd);
	if (inherit_owner) {
		unbecome_root();
	}
	TALLOC_FREE(frame);
	return status;
}

/*
 * If we already have a lease, it must match the new file id. [MS-SMB2]
 * 3.3.5.9.8 speaks about INVALID_PARAMETER if an already used lease key is
 * used for a different file name.
 */

struct lease_match_state {
	/* Input parameters. */
	TALLOC_CTX *mem_ctx;
	const char *servicepath;
	const struct smb_filename *fname;
	bool file_existed;
	struct file_id id;
	/* Return parameters. */
	uint32_t num_file_ids;
	struct file_id *ids;
	NTSTATUS match_status;
};

/*************************************************************
 File doesn't exist but this lease key+guid is already in use.

 This is only allowable in the dynamic share case where the
 service path must be different.

 There is a small race condition here in the multi-connection
 case where a client sends two create calls on different connections,
 where the file doesn't exist and one smbd creates the leases_db
 entry first, but this will get fixed by the multichannel cleanup
 when all identical client_guids get handled by a single smbd.
**************************************************************/

static void lease_match_parser_new_file(
	uint32_t num_files,
	const struct leases_db_file *files,
	struct lease_match_state *state)
{
	uint32_t i;

	for (i = 0; i < num_files; i++) {
		const struct leases_db_file *f = &files[i];
		if (strequal(state->servicepath, f->servicepath)) {
			state->match_status = NT_STATUS_INVALID_PARAMETER;
			return;
		}
	}

	/* Dynamic share case. Break leases on all other files. */
	state->match_status = leases_db_copy_file_ids(state->mem_ctx,
					num_files,
					files,
					&state->ids);
	if (!NT_STATUS_IS_OK(state->match_status)) {
		return;
	}

	state->num_file_ids = num_files;
	state->match_status = NT_STATUS_OPLOCK_NOT_GRANTED;
	return;
}

static void lease_match_parser(
	uint32_t num_files,
	const struct leases_db_file *files,
	void *private_data)
{
	struct lease_match_state *state =
		(struct lease_match_state *)private_data;
	uint32_t i;

	if (!state->file_existed) {
		/*
		 * Deal with name mismatch or
		 * possible dynamic share case separately
		 * to make code clearer.
		 */
		lease_match_parser_new_file(num_files,
						files,
						state);
		return;
	}

	/* File existed. */
	state->match_status = NT_STATUS_OK;

	for (i = 0; i < num_files; i++) {
		const struct leases_db_file *f = &files[i];

		/* Everything should be the same. */
		if (!file_id_equal(&state->id, &f->id)) {
			/* This should catch all dynamic share cases. */
			state->match_status = NT_STATUS_OPLOCK_NOT_GRANTED;
			break;
		}
		if (!strequal(f->servicepath, state->servicepath)) {
			state->match_status = NT_STATUS_INVALID_PARAMETER;
			break;
		}
		if (!strequal(f->base_name, state->fname->base_name)) {
			state->match_status = NT_STATUS_INVALID_PARAMETER;
			break;
		}
		if (!strequal(f->stream_name, state->fname->stream_name)) {
			state->match_status = NT_STATUS_INVALID_PARAMETER;
			break;
		}
	}

	if (NT_STATUS_IS_OK(state->match_status)) {
		/*
		 * Common case - just opening another handle on a
		 * file on a non-dynamic share.
		 */
		return;
	}

	if (NT_STATUS_EQUAL(state->match_status, NT_STATUS_INVALID_PARAMETER)) {
		/* Mismatched path. Error back to client. */
		return;
	}

	/*
	 * File id mismatch. Dynamic share case NT_STATUS_OPLOCK_NOT_GRANTED.
	 * Don't allow leases.
	 */

	state->match_status = leases_db_copy_file_ids(state->mem_ctx,
					num_files,
					files,
					&state->ids);
	if (!NT_STATUS_IS_OK(state->match_status)) {
		return;
	}

	state->num_file_ids = num_files;
	state->match_status = NT_STATUS_OPLOCK_NOT_GRANTED;
	return;
}

static NTSTATUS lease_match(connection_struct *conn,
			    struct smb_request *req,
			    struct smb2_lease_key *lease_key,
			    const char *servicepath,
			    const struct smb_filename *fname,
			    uint16_t *p_version,
			    uint16_t *p_epoch)
{
	struct smbd_server_connection *sconn = req->sconn;
	TALLOC_CTX *tos = talloc_tos();
	struct lease_match_state state = {
		.mem_ctx = tos,
		.servicepath = servicepath,
		.fname = fname,
		.match_status = NT_STATUS_OK
	};
	uint32_t i;
	NTSTATUS status;

	state.file_existed = VALID_STAT(fname->st);
	if (state.file_existed) {
		state.id = vfs_file_id_from_sbuf(conn, &fname->st);
	} else {
		memset(&state.id, '\0', sizeof(state.id));
	}

	status = leases_db_parse(&sconn->client->connections->smb2.client.guid,
				 lease_key, lease_match_parser, &state);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * Not found or error means okay: We can make the lease pass
		 */
		return NT_STATUS_OK;
	}
	if (!NT_STATUS_EQUAL(state.match_status, NT_STATUS_OPLOCK_NOT_GRANTED)) {
		/*
		 * Anything but NT_STATUS_OPLOCK_NOT_GRANTED, let the caller
		 * deal with it.
		 */
		return state.match_status;
	}

	/* We have to break all existing leases. */
	for (i = 0; i < state.num_file_ids; i++) {
		struct share_mode_lock *lck;
		struct share_mode_data *d;
		uint32_t j;

		if (file_id_equal(&state.ids[i], &state.id)) {
			/* Don't need to break our own file. */
			continue;
		}

		lck = get_existing_share_mode_lock(talloc_tos(), state.ids[i]);
		if (lck == NULL) {
			/* Race condition - file already closed. */
			continue;
		}
		d = lck->data;
		for (j=0; j<d->num_share_modes; j++) {
			struct share_mode_entry *e = &d->share_modes[j];
			uint32_t e_lease_type = get_lease_type(d, e);
			struct share_mode_lease *l = NULL;

			if (share_mode_stale_pid(d, j)) {
				continue;
			}

			if (e->op_type == LEASE_OPLOCK) {
				l = &lck->data->leases[e->lease_idx];
				if (!smb2_lease_key_equal(&l->lease_key,
							  lease_key)) {
					continue;
				}
				*p_epoch = l->epoch;
				*p_version = l->lease_version;
			}

			if (e_lease_type == SMB2_LEASE_NONE) {
				continue;
			}

			send_break_message(conn->sconn->msg_ctx, e,
					   SMB2_LEASE_NONE);

			/*
			 * Windows 7 and 8 lease clients
			 * are broken in that they will not
			 * respond to lease break requests
			 * whilst waiting for an outstanding
			 * open request on that lease handle
			 * on the same TCP connection, due
			 * to holding an internal inode lock.
			 *
			 * This means we can't reschedule
			 * ourselves here, but must return
			 * from the create.
			 *
			 * Work around:
			 *
			 * Send the breaks and then return
			 * SMB2_LEASE_NONE in the lease handle
			 * to cause them to acknowledge the
			 * lease break. Consulatation with
			 * Microsoft engineering confirmed
			 * this approach is safe.
			 */

		}
		TALLOC_FREE(lck);
	}
	/*
	 * Ensure we don't grant anything more so we
	 * never upgrade.
	 */
	return NT_STATUS_OPLOCK_NOT_GRANTED;
}

/*
 * Wrapper around open_file_ntcreate and open_directory
 */

static NTSTATUS create_file_unixpath(connection_struct *conn,
				     struct smb_request *req,
				     struct smb_filename *smb_fname,
				     uint32_t access_mask,
				     uint32_t share_access,
				     uint32_t create_disposition,
				     uint32_t create_options,
				     uint32_t file_attributes,
				     uint32_t oplock_request,
				     struct smb2_lease *lease,
				     uint64_t allocation_size,
				     uint32_t private_flags,
				     struct security_descriptor *sd,
				     struct ea_list *ea_list,

				     files_struct **result,
				     int *pinfo)
{
	int info = FILE_WAS_OPENED;
	files_struct *base_fsp = NULL;
	files_struct *fsp = NULL;
	NTSTATUS status;

	DEBUG(10,("create_file_unixpath: access_mask = 0x%x "
		  "file_attributes = 0x%x, share_access = 0x%x, "
		  "create_disposition = 0x%x create_options = 0x%x "
		  "oplock_request = 0x%x private_flags = 0x%x "
		  "ea_list = 0x%p, sd = 0x%p, "
		  "fname = %s\n",
		  (unsigned int)access_mask,
		  (unsigned int)file_attributes,
		  (unsigned int)share_access,
		  (unsigned int)create_disposition,
		  (unsigned int)create_options,
		  (unsigned int)oplock_request,
		  (unsigned int)private_flags,
		  ea_list, sd, smb_fname_str_dbg(smb_fname)));

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

	if (lease != NULL) {
		uint16_t epoch = lease->lease_epoch;
		uint16_t version = lease->lease_version;
		status = lease_match(conn,
				req,
				&lease->lease_key,
				conn->connectpath,
				smb_fname,
				&version,
				&epoch);
		if (NT_STATUS_EQUAL(status, NT_STATUS_OPLOCK_NOT_GRANTED)) {
			/* Dynamic share file. No leases and update epoch... */
			lease->lease_state = SMB2_LEASE_NONE;
			lease->lease_epoch = epoch;
			lease->lease_version = version;
		} else if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	if ((conn->fs_capabilities & FILE_NAMED_STREAMS)
	    && (access_mask & DELETE_ACCESS)
	    && !is_ntfs_stream_smb_fname(smb_fname)) {
		/*
		 * We can't open a file with DELETE access if any of the
		 * streams is open without FILE_SHARE_DELETE
		 */
		status = open_streams_for_delete(conn, smb_fname->base_name);

		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	if ((access_mask & SEC_FLAG_SYSTEM_SECURITY) &&
			!security_token_has_privilege(get_current_nttok(conn),
					SEC_PRIV_SECURITY)) {
		DEBUG(10, ("create_file_unixpath: open on %s "
			"failed - SEC_FLAG_SYSTEM_SECURITY denied.\n",
			smb_fname_str_dbg(smb_fname)));
		status = NT_STATUS_PRIVILEGE_NOT_HELD;
		goto fail;
	}

	if ((conn->fs_capabilities & FILE_NAMED_STREAMS)
	    && is_ntfs_stream_smb_fname(smb_fname)
	    && (!(private_flags & NTCREATEX_OPTIONS_PRIVATE_STREAM_DELETE))) {
		uint32 base_create_disposition;
		struct smb_filename *smb_fname_base = NULL;

		if (create_options & FILE_DIRECTORY_FILE) {
			status = NT_STATUS_NOT_A_DIRECTORY;
			goto fail;
		}

		switch (create_disposition) {
		case FILE_OPEN:
			base_create_disposition = FILE_OPEN;
			break;
		default:
			base_create_disposition = FILE_OPEN_IF;
			break;
		}

		/* Create an smb_filename with stream_name == NULL. */
		smb_fname_base = synthetic_smb_fname(talloc_tos(),
						     smb_fname->base_name,
						     NULL, NULL);
		if (smb_fname_base == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}

		if (SMB_VFS_STAT(conn, smb_fname_base) == -1) {
			DEBUG(10, ("Unable to stat stream: %s\n",
				   smb_fname_str_dbg(smb_fname_base)));
		} else {
			/*
			 * https://bugzilla.samba.org/show_bug.cgi?id=10229
			 * We need to check if the requested access mask
			 * could be used to open the underlying file (if
			 * it existed), as we're passing in zero for the
			 * access mask to the base filename.
			 */
			status = check_base_file_access(conn,
							smb_fname_base,
							access_mask);

			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(10, ("Permission check "
					"for base %s failed: "
					"%s\n", smb_fname->base_name,
					nt_errstr(status)));
				goto fail;
			}
		}

		/* Open the base file. */
		status = create_file_unixpath(conn, NULL, smb_fname_base, 0,
					      FILE_SHARE_READ
					      | FILE_SHARE_WRITE
					      | FILE_SHARE_DELETE,
					      base_create_disposition,
					      0, 0, 0, NULL, 0, 0, NULL, NULL,
					      &base_fsp, NULL);
		TALLOC_FREE(smb_fname_base);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("create_file_unixpath for base %s failed: "
				   "%s\n", smb_fname->base_name,
				   nt_errstr(status)));
			goto fail;
		}
		/* we don't need the low level fd */
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
			conn, req, smb_fname, access_mask, share_access,
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

		status = fsp_set_smb_fname(fsp, smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}

		if (base_fsp) {
			/*
			 * We're opening the stream element of a
			 * base_fsp we already opened. Set up the
			 * base_fsp pointer.
			 */
			fsp->base_fsp = base_fsp;
		}

		if (allocation_size) {
			fsp->initial_allocation_size = smb_roundup(fsp->conn,
							allocation_size);
		}

		status = open_file_ntcreate(conn,
					    req,
					    access_mask,
					    share_access,
					    create_disposition,
					    create_options,
					    file_attributes,
					    oplock_request,
					    lease,
					    private_flags,
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
				conn, req, smb_fname, access_mask,
				share_access, create_disposition,
				create_options,	file_attributes,
				&info, &fsp);
		}
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	fsp->base_fsp = base_fsp;

	if ((ea_list != NULL) &&
	    ((info == FILE_WAS_CREATED) || (info == FILE_WAS_OVERWRITTEN))) {
		status = set_ea(conn, fsp, fsp->fsp_name, ea_list);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	if (!fsp->is_directory && S_ISDIR(fsp->fsp_name->st.st_ex_mode)) {
		status = NT_STATUS_ACCESS_DENIED;
		goto fail;
	}

	/* Save the requested allocation size. */
	if ((info == FILE_WAS_CREATED) || (info == FILE_WAS_OVERWRITTEN)) {
		if (allocation_size
		    && (allocation_size > fsp->fsp_name->st.st_ex_size)) {
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
				fsp->conn, (uint64_t)fsp->fsp_name->st.st_ex_size);
		}
	} else {
		fsp->initial_allocation_size = 0;
	}

	if ((info == FILE_WAS_CREATED) && lp_nt_acl_support(SNUM(conn)) &&
				fsp->base_fsp == NULL) {
		if (sd != NULL) {
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

			uint32_t sec_info_sent;
			uint32_t saved_access_mask = fsp->access_mask;

			sec_info_sent = get_sec_info(sd);

			fsp->access_mask = FILE_GENERIC_ALL;

			if (sec_info_sent & (SECINFO_OWNER|
						SECINFO_GROUP|
						SECINFO_DACL|
						SECINFO_SACL)) {
				status = set_sd(fsp, sd, sec_info_sent);
			}

			fsp->access_mask = saved_access_mask;

			if (!NT_STATUS_IS_OK(status)) {
				goto fail;
			}
		} else if (lp_inherit_acls(SNUM(conn))) {
			/* Inherit from parent. Errors here are not fatal. */
			status = inherit_new_acl(fsp);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(10,("inherit_new_acl: failed for %s with %s\n",
					fsp_str_dbg(fsp),
					nt_errstr(status) ));
			}
		}
	}

	if ((conn->fs_capabilities & FILE_FILE_COMPRESSION)
	 && (create_options & FILE_NO_COMPRESSION)
	 && (info == FILE_WAS_CREATED)) {
		status = SMB_VFS_SET_COMPRESSION(conn, fsp, fsp,
						 COMPRESSION_FORMAT_NONE);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("failed to disable compression: %s\n",
				  nt_errstr(status)));
		}
	}

	DEBUG(10, ("create_file_unixpath: info=%d\n", info));

	*result = fsp;
	if (pinfo != NULL) {
		*pinfo = info;
	}

	smb_fname->st = fsp->fsp_name->st;

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
				   const struct smb_filename *smb_fname,
				   struct smb_filename **smb_fname_out)
{
	files_struct *dir_fsp;
	char *parent_fname = NULL;
	char *new_base_name = NULL;
	NTSTATUS status;

	if (root_dir_fid == 0 || !smb_fname) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}

	dir_fsp = file_fsp(req, root_dir_fid);

	if (dir_fsp == NULL) {
		status = NT_STATUS_INVALID_HANDLE;
		goto out;
	}

	if (is_ntfs_stream_smb_fname(dir_fsp->fsp_name)) {
		status = NT_STATUS_INVALID_HANDLE;
		goto out;
	}

	if (!dir_fsp->is_directory) {

		/*
		 * Check to see if this is a mac fork of some kind.
		 */

		if ((conn->fs_capabilities & FILE_NAMED_STREAMS) &&
		    is_ntfs_stream_smb_fname(smb_fname)) {
			status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
			goto out;
		}

		/*
		  we need to handle the case when we get a
		  relative open relative to a file and the
		  pathname is blank - this is a reopen!
		  (hint from demyn plantenberg)
		*/

		status = NT_STATUS_INVALID_HANDLE;
		goto out;
	}

	if (ISDOT(dir_fsp->fsp_name->base_name)) {
		/*
		 * We're at the toplevel dir, the final file name
		 * must not contain ./, as this is filtered out
		 * normally by srvstr_get_path and unix_convert
		 * explicitly rejects paths containing ./.
		 */
		parent_fname = talloc_strdup(talloc_tos(), "");
		if (parent_fname == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	} else {
		size_t dir_name_len = strlen(dir_fsp->fsp_name->base_name);

		/*
		 * Copy in the base directory name.
		 */

		parent_fname = talloc_array(talloc_tos(), char,
		    dir_name_len+2);
		if (parent_fname == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
		memcpy(parent_fname, dir_fsp->fsp_name->base_name,
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

	new_base_name = talloc_asprintf(talloc_tos(), "%s%s", parent_fname,
					smb_fname->base_name);
	if (new_base_name == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	status = filename_convert(req,
				conn,
				req->flags2 & FLAGS2_DFS_PATHNAMES,
				new_base_name,
				0,
				NULL,
				smb_fname_out);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

 out:
	TALLOC_FREE(parent_fname);
	TALLOC_FREE(new_base_name);
	return status;
}

NTSTATUS create_file_default(connection_struct *conn,
			     struct smb_request *req,
			     uint16_t root_dir_fid,
			     struct smb_filename *smb_fname,
			     uint32_t access_mask,
			     uint32_t share_access,
			     uint32_t create_disposition,
			     uint32_t create_options,
			     uint32_t file_attributes,
			     uint32_t oplock_request,
			     struct smb2_lease *lease,
			     uint64_t allocation_size,
			     uint32_t private_flags,
			     struct security_descriptor *sd,
			     struct ea_list *ea_list,
			     files_struct **result,
			     int *pinfo,
			     const struct smb2_create_blobs *in_context_blobs,
			     struct smb2_create_blobs *out_context_blobs)
{
	int info = FILE_WAS_OPENED;
	files_struct *fsp = NULL;
	NTSTATUS status;
	bool stream_name = false;

	DEBUG(10,("create_file: access_mask = 0x%x "
		  "file_attributes = 0x%x, share_access = 0x%x, "
		  "create_disposition = 0x%x create_options = 0x%x "
		  "oplock_request = 0x%x "
		  "private_flags = 0x%x "
		  "root_dir_fid = 0x%x, ea_list = 0x%p, sd = 0x%p, "
		  "fname = %s\n",
		  (unsigned int)access_mask,
		  (unsigned int)file_attributes,
		  (unsigned int)share_access,
		  (unsigned int)create_disposition,
		  (unsigned int)create_options,
		  (unsigned int)oplock_request,
		  (unsigned int)private_flags,
		  (unsigned int)root_dir_fid,
		  ea_list, sd, smb_fname_str_dbg(smb_fname)));

	/*
	 * Calculate the filename from the root_dir_if if necessary.
	 */

	if (root_dir_fid != 0) {
		struct smb_filename *smb_fname_out = NULL;
		status = get_relative_fid_filename(conn, req, root_dir_fid,
						   smb_fname, &smb_fname_out);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
		smb_fname = smb_fname_out;
	}

	/*
	 * Check to see if this is a mac fork of some kind.
	 */

	stream_name = is_ntfs_stream_smb_fname(smb_fname);
	if (stream_name) {
		enum FAKE_FILE_TYPE fake_file_type;

		fake_file_type = is_fake_file(smb_fname);

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
						fake_file_type, smb_fname,
						access_mask, &fsp);
			if (!NT_STATUS_IS_OK(status)) {
				goto fail;
			}

			ZERO_STRUCT(smb_fname->st);
			goto done;
		}

		if (!(conn->fs_capabilities & FILE_NAMED_STREAMS)) {
			status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
			goto fail;
		}
	}

	if (is_ntfs_default_stream_smb_fname(smb_fname)) {
		int ret;
		smb_fname->stream_name = NULL;
		/* We have to handle this error here. */
		if (create_options & FILE_DIRECTORY_FILE) {
			status = NT_STATUS_NOT_A_DIRECTORY;
			goto fail;
		}
		if (lp_posix_pathnames()) {
			ret = SMB_VFS_LSTAT(conn, smb_fname);
		} else {
			ret = SMB_VFS_STAT(conn, smb_fname);
		}

		if (ret == 0 && VALID_STAT_OF_DIR(smb_fname->st)) {
			status = NT_STATUS_FILE_IS_A_DIRECTORY;
			goto fail;
		}
	}

	status = create_file_unixpath(
		conn, req, smb_fname, access_mask, share_access,
		create_disposition, create_options, file_attributes,
		oplock_request, lease, allocation_size, private_flags,
		sd, ea_list,
		&fsp, &info);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

 done:
	DEBUG(10, ("create_file: info=%d\n", info));

	*result = fsp;
	if (pinfo != NULL) {
		*pinfo = info;
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
