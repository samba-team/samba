/* 
   Unix SMB/CIFS implementation.
   file opening and share modes
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2004
   Copyright (C) Volker Lendecke 2005
   Copyright (C) Ralph Boehme 2017

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
#include "smb1_utils.h"
#include "system/filesys.h"
#include "lib/util/server_id.h"
#include "printing.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "fake_file.h"
#include "../libcli/security/security.h"
#include "../librpc/gen_ndr/ndr_security.h"
#include "../librpc/gen_ndr/ndr_open_files.h"
#include "../librpc/gen_ndr/idmap.h"
#include "../librpc/gen_ndr/ioctl.h"
#include "passdb/lookup_sid.h"
#include "auth.h"
#include "serverid.h"
#include "messages.h"
#include "source3/lib/dbwrap/dbwrap_watch.h"
#include "locking/leases_db.h"
#include "librpc/gen_ndr/ndr_leases_db.h"
#include "lib/util/time_basic.h"

extern const struct generic_mapping file_generic_mapping;

struct deferred_open_record {
	struct smbXsrv_connection *xconn;
	uint64_t mid;

	bool async_open;

	/*
	 * Timer for async opens, needed because they don't use a watch on
	 * a locking.tdb record. This is currently only used for real async
	 * opens and just terminates smbd if the async open times out.
	 */
	struct tevent_timer *te;

	/*
	 * For the samba kernel oplock case we use both a timeout and
	 * a watch on locking.tdb. This way in case it's smbd holding
	 * the kernel oplock we get directly notified for the retry
	 * once the kernel oplock is properly broken. Store the req
	 * here so that it can be timely discarded once the timer
	 * above fires.
	 */
	struct tevent_req *watch_req;
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
		    can_delete_file_in_directory(conn,
				conn->cwd_fsp,
				smb_fname))
	{
		return true;
	}
	return false;
}

/****************************************************************************
 Check if we have open rights.
****************************************************************************/

NTSTATUS smbd_check_access_rights(struct connection_struct *conn,
				struct files_struct *dirfsp,
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

	SMB_ASSERT(dirfsp == conn->cwd_fsp);

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

	status = SMB_VFS_GET_NT_ACL_AT(conn,
			dirfsp,
			smb_fname,
			(SECINFO_OWNER |
				SECINFO_GROUP |
				SECINFO_DACL),
			talloc_tos(),
			&sd);

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
	 * The compatibilty mode allows one to skip this check
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

NTSTATUS check_parent_access(struct connection_struct *conn,
				struct files_struct *dirfsp,
				struct smb_filename *smb_fname,
				uint32_t access_mask)
{
	NTSTATUS status;
	struct security_descriptor *parent_sd = NULL;
	uint32_t access_granted = 0;
	struct smb_filename *parent_dir = NULL;
	struct share_mode_lock *lck = NULL;
	struct file_id id = {0};
	uint32_t name_hash;
	bool delete_on_close_set;
	int ret;
	TALLOC_CTX *frame = talloc_stackframe();
	bool ok;

	/*
	 * NB. When dirfsp != conn->cwd_fsp, we must
	 * change parent_dir to be "." for the name here.
	 */

	SMB_ASSERT(dirfsp == conn->cwd_fsp);

	ok = parent_smb_fname(frame, smb_fname, &parent_dir, NULL);
	if (!ok) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	if (get_current_uid(conn) == (uid_t)0) {
		/* I'm sorry sir, I didn't know you were root... */
		DEBUG(10,("check_parent_access: root override "
			"on %s. Granting 0x%x\n",
			smb_fname_str_dbg(smb_fname),
			(unsigned int)access_mask ));
		status = NT_STATUS_OK;
		goto out;
	}

	status = SMB_VFS_GET_NT_ACL_AT(conn,
				dirfsp,
				parent_dir,
				SECINFO_DACL,
				frame,
				&parent_sd);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_INFO("SMB_VFS_GET_NT_ACL_AT failed for "
			"%s with error %s\n",
			smb_fname_str_dbg(parent_dir),
			nt_errstr(status));
		goto out;
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
			smb_fname_str_dbg(parent_dir),
			smb_fname->base_name,
			access_mask,
			access_granted,
			nt_errstr(status) ));
		goto out;
	}

	if (!(access_mask & (SEC_DIR_ADD_FILE | SEC_DIR_ADD_SUBDIR))) {
		status = NT_STATUS_OK;
		goto out;
	}
	if (!lp_check_parent_directory_delete_on_close(SNUM(conn))) {
		status = NT_STATUS_OK;
		goto out;
	}

	/* Check if the directory has delete-on-close set */
	ret = SMB_VFS_STAT(conn, parent_dir);
	if (ret != 0) {
		status = map_nt_error_from_unix(errno);
		goto out;
	}

	id = SMB_VFS_FILE_ID_CREATE(conn, &parent_dir->st);

	status = file_name_hash(conn, parent_dir->base_name, &name_hash);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	lck = get_existing_share_mode_lock(frame, id);
	if (lck == NULL) {
		status = NT_STATUS_OK;
		goto out;
	}

	delete_on_close_set = is_delete_on_close_set(lck, name_hash);
	if (delete_on_close_set) {
		status = NT_STATUS_DELETE_PENDING;
		goto out;
	}

	status = NT_STATUS_OK;

out:
	TALLOC_FREE(frame);
	return status;
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

	status = smbd_calculate_access_mask(conn,
					conn->cwd_fsp,
					smb_fname,
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
					conn->cwd_fsp,
					smb_fname,
					false,
					access_mask);
}

/****************************************************************************
 Handle differing symlink errno's
****************************************************************************/

static int link_errno_convert(int err)
{
#if defined(ENOTSUP) && defined(OSF1)
	/* handle special Tru64 errno */
	if (err == ENOTSUP) {
		err = ELOOP;
	}
#endif /* ENOTSUP */
#ifdef EFTYPE
	/* fix broken NetBSD errno */
	if (err == EFTYPE) {
		err = ELOOP;
	}
#endif /* EFTYPE */
	/* fix broken FreeBSD errno */
	if (err == EMLINK) {
		err = ELOOP;
	}
	return err;
}

static int non_widelink_open(files_struct *fsp,
			struct smb_filename *smb_fname,
			int flags,
			mode_t mode,
			unsigned int link_depth);

/****************************************************************************
 Follow a symlink in userspace.
****************************************************************************/

static int process_symlink_open(struct connection_struct *conn,
			files_struct *fsp,
			struct smb_filename *smb_fname,
			int flags,
			mode_t mode,
			unsigned int link_depth)
{
	const char *conn_rootdir = NULL;
	struct smb_filename conn_rootdir_fname = { 0 };
	int fd = -1;
	char *link_target = NULL;
	int link_len = -1;
	struct smb_filename *oldwd_fname = NULL;
	size_t rootdir_len = 0;
	struct smb_filename *resolved_fname = NULL;
	char *resolved_name = NULL;
	bool matched = false;
	int saved_errno = 0;

	conn_rootdir = SMB_VFS_CONNECTPATH(conn, smb_fname);
	if (conn_rootdir == NULL) {
		errno = ENOMEM;
		return -1;
	}
	/*
	 * With shadow_copy2 conn_rootdir can be talloc_freed
	 * whilst we use it in this function. We must take a copy.
	 */
	conn_rootdir_fname.base_name = talloc_strdup(talloc_tos(),
						     conn_rootdir);
	if (conn_rootdir_fname.base_name == NULL) {
		errno = ENOMEM;
		return -1;
	}

	/*
	 * Ensure we don't get stuck in a symlink loop.
	 */
	link_depth++;
	if (link_depth >= 20) {
		errno = ELOOP;
		goto out;
	}

	/* Allocate space for the link target. */
	link_target = talloc_array(talloc_tos(), char, PATH_MAX);
	if (link_target == NULL) {
		errno = ENOMEM;
		goto out;
	}

	/*
	 * Read the link target. We do this just to verify that smb_fname indeed
	 * points at a symbolic link and return the SMB_VFS_READLINKAT() errno
	 * and failure in case smb_fname is NOT a symlink.
	 *
	 * The caller needs this piece of information to distinguish two cases
	 * where open() fails with errno=ENOTDIR, cf the comment in
	 * non_widelink_open().
	 *
	 * We rely on SMB_VFS_REALPATH() to resolve the path including the
	 * symlink. Once we have SMB_VFS_STATX() or something similar in our VFS
	 * we may want to use that instead of SMB_VFS_READLINKAT().
	 */
	link_len = SMB_VFS_READLINKAT(conn,
				conn->cwd_fsp,
				smb_fname,
				link_target,
				PATH_MAX - 1);
	if (link_len == -1) {
		goto out;
	}

	/* Convert to an absolute path. */
	resolved_fname = SMB_VFS_REALPATH(conn, talloc_tos(), smb_fname);
	if (resolved_fname == NULL) {
		goto out;
	}
	resolved_name = resolved_fname->base_name;

	/*
	 * We know conn_rootdir starts with '/' and
	 * does not end in '/'. FIXME ! Should we
	 * smb_assert this ?
	 */
	rootdir_len = strlen(conn_rootdir_fname.base_name);

	matched = (strncmp(conn_rootdir_fname.base_name,
				resolved_name,
				rootdir_len) == 0);
	if (!matched) {
		errno = EACCES;
		goto out;
	}

	/*
	 * Turn into a path relative to the share root.
	 */
	if (resolved_name[rootdir_len] == '\0') {
		/* Link to the root of the share. */
		TALLOC_FREE(smb_fname->base_name);
		smb_fname->base_name = talloc_strdup(smb_fname, ".");
	} else if (resolved_name[rootdir_len] == '/') {
		TALLOC_FREE(smb_fname->base_name);
		smb_fname->base_name = talloc_strdup(smb_fname,
					&resolved_name[rootdir_len+1]);
	} else {
		errno = EACCES;
		goto out;
	}

	if (smb_fname->base_name == NULL) {
		errno = ENOMEM;
		goto out;
	}

	oldwd_fname = vfs_GetWd(talloc_tos(), conn);
	if (oldwd_fname == NULL) {
		goto out;
	}

	/* Ensure we operate from the root of the share. */
	if (vfs_ChDir(conn, &conn_rootdir_fname) == -1) {
		goto out;
	}

	/* And do it all again.. */
	fd = non_widelink_open(fsp,
				smb_fname,
				flags,
				mode,
				link_depth);
	if (fd == -1) {
		saved_errno = errno;
	}

  out:

	TALLOC_FREE(resolved_fname);
	TALLOC_FREE(link_target);
	TALLOC_FREE(conn_rootdir_fname.base_name);
	if (oldwd_fname != NULL) {
		int ret = vfs_ChDir(conn, oldwd_fname);
		if (ret == -1) {
			smb_panic("unable to get back to old directory\n");
		}
		TALLOC_FREE(oldwd_fname);
	}
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return fd;
}

/****************************************************************************
 Non-widelink open.
****************************************************************************/

static int non_widelink_open(files_struct *fsp,
			     struct smb_filename *smb_fname,
			     int flags,
			     mode_t mode,
			     unsigned int link_depth)
{
	struct connection_struct *conn = fsp->conn;
	NTSTATUS status;
	int fd = -1;
	struct smb_filename *smb_fname_rel = NULL;
	int saved_errno = 0;
	struct smb_filename *oldwd_fname = NULL;
	struct smb_filename *parent_dir_fname = NULL;
	struct files_struct *cwdfsp = NULL;
	bool ok;

	if (fsp->fsp_flags.is_directory) {
		parent_dir_fname = cp_smb_filename(talloc_tos(), smb_fname);
		if (parent_dir_fname == NULL) {
			saved_errno = errno;
			goto out;
		}

		smb_fname_rel = synthetic_smb_fname(parent_dir_fname,
						    ".",
						    smb_fname->stream_name,
						    &smb_fname->st,
						    smb_fname->twrp,
						    smb_fname->flags);
		if (smb_fname_rel == NULL) {
			saved_errno = errno;
			goto out;
		}
	} else {
		ok = parent_smb_fname(talloc_tos(),
				      smb_fname,
				      &parent_dir_fname,
				      &smb_fname_rel);
		if (!ok) {
			saved_errno = errno;
			goto out;
		}
	}

	oldwd_fname = vfs_GetWd(talloc_tos(), conn);
	if (oldwd_fname == NULL) {
		goto out;
	}

	/* Pin parent directory in place. */
	if (vfs_ChDir(conn, parent_dir_fname) == -1) {
		goto out;
	}

	/* Ensure the relative path is below the share. */
	status = check_reduced_name(conn, parent_dir_fname, smb_fname_rel);
	if (!NT_STATUS_IS_OK(status)) {
		saved_errno = map_errno_from_nt_status(status);
		goto out;
	}

	status = vfs_at_fspcwd(talloc_tos(),
			       conn,
			       &cwdfsp);
	if (!NT_STATUS_IS_OK(status)) {
		saved_errno = map_errno_from_nt_status(status);
		goto out;
	}

	flags |= O_NOFOLLOW;

	{
		struct smb_filename *tmp_name = fsp->fsp_name;

		fsp->fsp_name = smb_fname_rel;

		fd = SMB_VFS_OPENAT(conn,
				    cwdfsp,
				    smb_fname_rel,
				    fsp,
				    flags,
				    mode);

		fsp->fsp_name = tmp_name;
	}

	if (fd == -1) {
		saved_errno = link_errno_convert(errno);
		/*
		 * Trying to open a symlink to a directory with O_NOFOLLOW and
		 * O_DIRECTORY can return either of ELOOP and ENOTDIR. So
		 * ENOTDIR really means: might be a symlink, but we're not sure.
		 * In this case, we just assume there's a symlink. If we were
		 * wrong, process_symlink_open() will return EINVAL. We check
		 * this below, and fall back to returning the initial
		 * saved_errno.
		 *
		 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=12860
		 */
		if (saved_errno == ELOOP || saved_errno == ENOTDIR) {
			if (fsp->posix_flags & FSP_POSIX_FLAGS_OPEN) {
				/* Never follow symlinks on posix open. */
				goto out;
			}
			if (!lp_follow_symlinks(SNUM(conn))) {
				/* Explicitly no symlinks. */
				goto out;
			}
			/*
			 * We may have a symlink. Follow in userspace
			 * to ensure it's under the share definition.
			 */
			fd = process_symlink_open(conn,
					fsp,
					smb_fname_rel,
					flags,
					mode,
					link_depth);
			if (fd == -1) {
				if (saved_errno == ENOTDIR &&
						errno == EINVAL) {
					/*
					 * O_DIRECTORY on neither a directory,
					 * nor a symlink. Just return
					 * saved_errno from initial open()
					 */
					goto out;
				}
				saved_errno =
					link_errno_convert(errno);
			}
		}
	}

  out:

	TALLOC_FREE(parent_dir_fname);
	TALLOC_FREE(cwdfsp);

	if (oldwd_fname != NULL) {
		int ret = vfs_ChDir(conn, oldwd_fname);
		if (ret == -1) {
			smb_panic("unable to get back to old directory\n");
		}
		TALLOC_FREE(oldwd_fname);
	}
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return fd;
}

/****************************************************************************
 fd support routines - attempt to do a dos_open.
****************************************************************************/

NTSTATUS fd_open(files_struct *fsp,
		 int flags,
		 mode_t mode)
{
	struct connection_struct *conn = fsp->conn;
	struct smb_filename *smb_fname = fsp->fsp_name;
	NTSTATUS status = NT_STATUS_OK;
	int saved_errno = 0;

	/*
	 * Never follow symlinks on a POSIX client. The
	 * client should be doing this.
	 */

	if ((fsp->posix_flags & FSP_POSIX_FLAGS_OPEN) || !lp_follow_symlinks(SNUM(conn))) {
		flags |= O_NOFOLLOW;
	}

	/*
	 * Only follow symlinks within a share
	 * definition.
	 */
	fsp->fh->fd = non_widelink_open(fsp,
					smb_fname,
					flags,
					mode,
					0);
	if (fsp->fh->fd == -1) {
		saved_errno = errno;
	}
	if (saved_errno != 0) {
		errno = saved_errno;
	}

	if (fsp->fh->fd == -1) {
		int posix_errno = link_errno_convert(errno);
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

		DBG_DEBUG("name %s, flags = 0%o mode = 0%o, fd = %d. %s\n",
			  smb_fname_str_dbg(smb_fname), flags, (int)mode,
			  fsp->fh->fd, strerror(errno));
		return status;
	}

	DBG_DEBUG("name %s, flags = 0%o mode = 0%o, fd = %d\n",
		  smb_fname_str_dbg(smb_fname), flags, (int)mode, fsp->fh->fd);

	return status;
}

NTSTATUS fd_openat(files_struct *fsp,
		   int flags,
		   mode_t mode)
{
	NTSTATUS status = NT_STATUS_OK;
	int saved_errno = 0;

	if (fsp->dirfsp == fsp->conn->cwd_fsp) {
		return fd_open(fsp, flags, mode);
	}

	/*
	 * Never follow symlinks at this point, filename_convert() should have
	 * resolved any symlink.
	 */

	flags |= O_NOFOLLOW;

	/*
	 * Only follow symlinks within a share
	 * definition.
	 */
	fsp->fh->fd = SMB_VFS_OPENAT(fsp->conn,
				     fsp->dirfsp,
				     fsp->fsp_name,
				     fsp,
				     flags,
				     mode);
	if (fsp->fh->fd == -1) {
		saved_errno = errno;
	}
	if (saved_errno != 0) {
		errno = saved_errno;
	}

	if (fsp->fh->fd == -1) {
		int posix_errno = link_errno_convert(errno);

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

		DBG_DEBUG("name %s, flags = 0%o mode = 0%o, fd = %d. %s\n",
			  fsp_str_dbg(fsp), flags, (int)mode,
			  fsp->fh->fd, strerror(errno));
		return status;
	}

	DBG_DEBUG("name %s, flags = 0%o mode = 0%o, fd = %d\n",
		  fsp_str_dbg(fsp), flags, (int)mode, fsp->fh->fd);

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
		/*
		 * Either a directory where the dptr_CloseDir() already closed
		 * the fd or a stat open.
		 */
		return NT_STATUS_OK;
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
				 struct smb_filename *smb_fname_parent,
				 files_struct *fsp)
{
	int ret;

	ret = SMB_VFS_STAT(conn, smb_fname_parent);
	if (ret == -1) {
		DEBUG(0,("change_file_owner_to_parent: failed to stat parent "
			 "directory %s. Error was %s\n",
			 smb_fname_str_dbg(smb_fname_parent),
			 strerror(errno)));
		return;
	}

	if (smb_fname_parent->st.st_ex_uid == fsp->fsp_name->st.st_ex_uid) {
		/* Already this uid - no need to change. */
		DEBUG(10,("change_file_owner_to_parent: file %s "
			"is already owned by uid %d\n",
			fsp_str_dbg(fsp),
			(int)fsp->fsp_name->st.st_ex_uid ));
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
}

static NTSTATUS change_dir_owner_to_parent(connection_struct *conn,
					struct smb_filename *smb_fname_parent,
					struct smb_filename *smb_dname,
					SMB_STRUCT_STAT *psbuf)
{
	struct smb_filename *smb_fname_cwd = NULL;
	struct smb_filename *saved_dir_fname = NULL;
	TALLOC_CTX *ctx = talloc_tos();
	NTSTATUS status = NT_STATUS_OK;
	int ret;

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

	saved_dir_fname = vfs_GetWd(ctx,conn);
	if (!saved_dir_fname) {
		status = map_nt_error_from_unix(errno);
		DEBUG(0,("change_dir_owner_to_parent: failed to get "
			 "current working directory. Error was %s\n",
			 strerror(errno)));
		goto out;
	}

	/* Chdir into the new path. */
	if (vfs_ChDir(conn, smb_dname) == -1) {
		status = map_nt_error_from_unix(errno);
		DEBUG(0,("change_dir_owner_to_parent: failed to change "
			 "current working directory to %s. Error "
			 "was %s\n", smb_dname->base_name, strerror(errno) ));
		goto chdir;
	}

	smb_fname_cwd = synthetic_smb_fname(ctx,
					    ".",
					    NULL,
					    NULL,
					    smb_dname->twrp,
					    0);
	if (smb_fname_cwd == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto chdir;
	}

	ret = SMB_VFS_STAT(conn, smb_fname_cwd);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		DEBUG(0,("change_dir_owner_to_parent: failed to stat "
			 "directory '.' (%s) Error was %s\n",
			 smb_dname->base_name, strerror(errno)));
		goto chdir;
	}

	/* Ensure we're pointing at the same place. */
	if (smb_fname_cwd->st.st_ex_dev != psbuf->st_ex_dev ||
	    smb_fname_cwd->st.st_ex_ino != psbuf->st_ex_ino) {
		DEBUG(0,("change_dir_owner_to_parent: "
			 "device/inode on directory %s changed. "
			 "Refusing to chown !\n",
			smb_dname->base_name ));
		status = NT_STATUS_ACCESS_DENIED;
		goto chdir;
	}

	if (smb_fname_parent->st.st_ex_uid == smb_fname_cwd->st.st_ex_uid) {
		/* Already this uid - no need to change. */
		DEBUG(10,("change_dir_owner_to_parent: directory %s "
			"is already owned by uid %d\n",
			smb_dname->base_name,
			(int)smb_fname_cwd->st.st_ex_uid ));
		status = NT_STATUS_OK;
		goto chdir;
	}

	become_root();
	ret = SMB_VFS_LCHOWN(conn,
			smb_fname_cwd,
			smb_fname_parent->st.st_ex_uid,
			(gid_t)-1);
	unbecome_root();
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		DEBUG(10,("change_dir_owner_to_parent: failed to chown "
			  "directory %s to parent directory uid %u. "
			  "Error was %s\n",
			  smb_dname->base_name,
			  (unsigned int)smb_fname_parent->st.st_ex_uid,
			  strerror(errno) ));
	} else {
		DEBUG(10,("change_dir_owner_to_parent: changed ownership of new "
			"directory %s to parent directory uid %u.\n",
			smb_dname->base_name,
			(unsigned int)smb_fname_parent->st.st_ex_uid ));
		/* Ensure the uid entry is updated. */
		psbuf->st_ex_uid = smb_fname_parent->st.st_ex_uid;
	}

 chdir:
	vfs_ChDir(conn, saved_dir_fname);
 out:
	TALLOC_FREE(saved_dir_fname);
	TALLOC_FREE(smb_fname_cwd);
	return status;
}

/****************************************************************************
 Open a file - returning a guaranteed ATOMIC indication of if the
 file was created or not.
****************************************************************************/

static NTSTATUS fd_open_atomic(files_struct *fsp,
			       int flags,
			       mode_t mode,
			       bool *file_created)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	NTSTATUS retry_status;
	bool file_existed = VALID_STAT(fsp->fsp_name->st);
	int curr_flags;

	if (!(flags & O_CREAT)) {
		/*
		 * We're not creating the file, just pass through.
		 */
		status = fd_openat(fsp, flags, mode);
		*file_created = false;
		return status;
	}

	if (flags & O_EXCL) {
		/*
		 * Fail if already exists, just pass through.
		 */
		status = fd_openat(fsp, flags, mode);

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
	 * O_CREAT|O_EXCL.
	 *
	 * The big problem here is dangling symlinks. Opening
	 * without O_NOFOLLOW means both bad symlink
	 * and missing path return -1, ENOENT from open(). As POSIX
	 * is pathname based it's not possible to tell
	 * the difference between these two cases in a
	 * non-racy way, so change to try only two attempts before
	 * giving up.
	 *
	 * We don't have this problem for the O_NOFOLLOW
	 * case as it just returns NT_STATUS_OBJECT_PATH_NOT_FOUND
	 * mapped from the ELOOP POSIX error.
	 */

	if (file_existed) {
		curr_flags = flags & ~(O_CREAT);
		retry_status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	} else {
		curr_flags = flags | O_EXCL;
		retry_status = NT_STATUS_OBJECT_NAME_COLLISION;
	}

	status = fd_openat(fsp, curr_flags, mode);
	if (NT_STATUS_IS_OK(status)) {
		*file_created = !file_existed;
		return NT_STATUS_OK;
	}
	if (NT_STATUS_EQUAL(status, retry_status)) {

		file_existed = !file_existed;

		DBG_DEBUG("File %s %s. Retry.\n",
			  fsp_str_dbg(fsp),
			  file_existed ? "existed" : "did not exist");

		if (file_existed) {
			curr_flags = flags & ~(O_CREAT);
		} else {
			curr_flags = flags | O_EXCL;
		}

		status = fd_openat(fsp, curr_flags, mode);
	}

	*file_created = (NT_STATUS_IS_OK(status) && !file_existed);
	return status;
}

/****************************************************************************
 Open a file.
****************************************************************************/

static NTSTATUS open_file(files_struct *fsp,
			  struct smb_request *req,
			  struct smb_filename *parent_dir,
			  int flags,
			  mode_t unx_mode,
			  uint32_t access_mask, /* client requested access mask. */
			  uint32_t open_access_mask, /* what we're actually using in the open. */
			  bool *p_file_created)
{
	connection_struct *conn = fsp->conn;
	struct smb_filename *smb_fname = fsp->fsp_name;
	NTSTATUS status = NT_STATUS_OK;
	int accmode = (flags & O_ACCMODE);
	int local_flags = flags;
	bool file_existed = VALID_STAT(fsp->fsp_name->st);
	uint32_t need_fd_mask =
		FILE_READ_DATA |
		FILE_WRITE_DATA |
		FILE_APPEND_DATA |
		FILE_EXECUTE |
		WRITE_DAC_ACCESS |
		WRITE_OWNER_ACCESS |
		SEC_FLAG_SYSTEM_SECURITY |
		READ_CONTROL_ACCESS;
	bool creating = !file_existed && (flags & O_CREAT);
	bool truncating = (flags & O_TRUNC);

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

	if ((open_access_mask & need_fd_mask) || creating || truncating) {
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
			truncating = false;
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
		    !(fsp->posix_flags & FSP_POSIX_FLAGS_PATHNAMES) &&
		    ms_has_wild(wild))  {
			return NT_STATUS_OBJECT_NAME_INVALID;
		}

		/* Can we access this file ? */
		if (!fsp->base_fsp) {
			/* Only do this check on non-stream open. */
			if (file_existed) {
				status = smbd_check_access_rights(conn,
						conn->cwd_fsp,
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
							conn->cwd_fsp,
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
		status = fd_open_atomic(fsp,
					local_flags & ~O_TRUNC,
					unx_mode,
					p_file_created);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3,("Error opening file %s (%s) (local_flags=%d) "
				 "(flags=%d)\n", smb_fname_str_dbg(smb_fname),
				 nt_errstr(status),local_flags,flags));
			return status;
		}

		if (local_flags & O_NONBLOCK) {
			/*
			 * GPFS can return ETIMEDOUT for pread on
			 * nonblocking file descriptors when files
			 * migrated to tape need to be recalled. I
			 * could imagine this happens elsewhere
			 * too. With blocking file descriptors this
			 * does not happen.
			 */
			ret = vfs_set_blocking(fsp, true);
			if (ret == -1) {
				status = map_nt_error_from_unix(errno);
				DBG_WARNING("Could not set fd to blocking: "
					    "%s\n", strerror(errno));
				fd_close(fsp);
				return status;
			}
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
				inherit_access_posix_acl(conn,
							 parent_dir,
							 smb_fname,
							 unx_mode);
				need_re_stat = true;
			}

			/* Change the owner if required. */
			if (lp_inherit_owner(SNUM(conn)) != INHERIT_OWNER_NO) {
				change_file_owner_to_parent(conn,
							    parent_dir,
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
				conn->cwd_fsp,
				smb_fname,
				false,
				access_mask);

		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND) &&
				(fsp->posix_flags & FSP_POSIX_FLAGS_OPEN) &&
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
	fsp->fsp_flags.can_lock = true;
	fsp->fsp_flags.can_read = ((access_mask & FILE_READ_DATA) != 0);
	fsp->fsp_flags.can_write =
		CAN_WRITE(conn) &&
		((access_mask & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0);
	fsp->print_file = NULL;
	fsp->fsp_flags.modified = false;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->fsp_flags.is_directory = false;
	if (conn->aio_write_behind_list &&
	    is_in_path(smb_fname->base_name, conn->aio_write_behind_list,
		       conn->case_sensitive)) {
		fsp->fsp_flags.aio_write_behind = true;
	}

	DEBUG(2,("%s opened file %s read=%s write=%s (numopen=%d)\n",
		 conn->session_info->unix_info->unix_name,
		 smb_fname_str_dbg(smb_fname),
		 BOOLSTR(fsp->fsp_flags.can_read),
		 BOOLSTR(fsp->fsp_flags.can_write),
		 conn->num_files_open));

	errno = 0;
	return NT_STATUS_OK;
}

static bool mask_conflict(
	uint32_t new_access,
	uint32_t existing_access,
	uint32_t access_mask,
	uint32_t new_sharemode,
	uint32_t existing_sharemode,
	uint32_t sharemode_mask)
{
	bool want_access = (new_access & access_mask);
	bool allow_existing = (existing_sharemode & sharemode_mask);
	bool have_access = (existing_access & access_mask);
	bool allow_new = (new_sharemode & sharemode_mask);

	if (want_access && !allow_existing) {
		DBG_DEBUG("Access request 0x%"PRIx32"/0x%"PRIx32" conflicts "
			  "with existing sharemode 0x%"PRIx32"/0x%"PRIx32"\n",
			  new_access,
			  access_mask,
			  existing_sharemode,
			  sharemode_mask);
		return true;
	}
	if (have_access && !allow_new) {
		DBG_DEBUG("Sharemode request 0x%"PRIx32"/0x%"PRIx32" conflicts "
			  "with existing access 0x%"PRIx32"/0x%"PRIx32"\n",
			  new_sharemode,
			  sharemode_mask,
			  existing_access,
			  access_mask);
		return true;
	}
	return false;
}

/****************************************************************************
 Check if we can open a file with a share mode.
 Returns True if conflict, False if not.
****************************************************************************/

static const uint32_t conflicting_access =
	FILE_WRITE_DATA|
	FILE_APPEND_DATA|
	FILE_READ_DATA|
	FILE_EXECUTE|
	DELETE_ACCESS;

static bool share_conflict(uint32_t e_access_mask,
			   uint32_t e_share_access,
			   uint32_t access_mask,
			   uint32_t share_access)
{
	bool conflict;

	DBG_DEBUG("existing access_mask = 0x%"PRIx32", "
		  "existing share access = 0x%"PRIx32", "
		  "access_mask = 0x%"PRIx32", "
		  "share_access = 0x%"PRIx32"\n",
		  e_access_mask,
		  e_share_access,
		  access_mask,
		  share_access);

	if ((e_access_mask & conflicting_access) == 0) {
		DBG_DEBUG("No conflict due to "
			  "existing access_mask = 0x%"PRIx32"\n",
			  e_access_mask);
		return false;
	}
	if ((access_mask & conflicting_access) == 0) {
		DBG_DEBUG("No conflict due to access_mask = 0x%"PRIx32"\n",
			  access_mask);
		return false;
	}

	conflict = mask_conflict(
		access_mask, e_access_mask, FILE_WRITE_DATA | FILE_APPEND_DATA,
		share_access, e_share_access, FILE_SHARE_WRITE);
	conflict |= mask_conflict(
		access_mask, e_access_mask, FILE_READ_DATA | FILE_EXECUTE,
		share_access, e_share_access, FILE_SHARE_READ);
	conflict |= mask_conflict(
		access_mask, e_access_mask, DELETE_ACCESS,
		share_access, e_share_access, FILE_SHARE_DELETE);

	DBG_DEBUG("conflict=%s\n", conflict ? "true" : "false");
	return conflict;
}

#if defined(DEVELOPER)

struct validate_my_share_entries_state {
	struct smbd_server_connection *sconn;
	struct file_id fid;
	struct server_id self;
};

static bool validate_my_share_entries_fn(
	struct share_mode_entry *e,
	bool *modified,
	void *private_data)
{
	struct validate_my_share_entries_state *state = private_data;
	files_struct *fsp;

	if (!server_id_equal(&state->self, &e->pid)) {
		return false;
	}

	if (e->op_mid == 0) {
		/* INTERNAL_OPEN_ONLY */
		return false;
	}

	fsp = file_find_dif(state->sconn, state->fid, e->share_file_id);
	if (!fsp) {
		DBG_ERR("PANIC : %s\n",
			share_mode_str(talloc_tos(), 0, &state->fid, e));
		smb_panic("validate_my_share_entries: Cannot match a "
			  "share entry with an open file\n");
	}

	if (((uint16_t)fsp->oplock_type) != e->op_type) {
		goto panic;
	}

	return false;

 panic:
	{
		char *str;
		DBG_ERR("validate_my_share_entries: PANIC : %s\n",
			share_mode_str(talloc_tos(), 0, &state->fid, e));
		str = talloc_asprintf(talloc_tos(),
			"validate_my_share_entries: "
			"file %s, oplock_type = 0x%x, op_type = 0x%x\n",
			 fsp->fsp_name->base_name,
			 (unsigned int)fsp->oplock_type,
			 (unsigned int)e->op_type);
		smb_panic(str);
	}

	return false;
}
#endif

/**
 * Allowed access mask for stat opens relevant to oplocks
 **/
bool is_oplock_stat_open(uint32_t access_mask)
{
	const uint32_t stat_open_bits =
		(SYNCHRONIZE_ACCESS|
		 FILE_READ_ATTRIBUTES|
		 FILE_WRITE_ATTRIBUTES);

	return (((access_mask &  stat_open_bits) != 0) &&
		((access_mask & ~stat_open_bits) == 0));
}

/**
 * Allowed access mask for stat opens relevant to leases
 **/
bool is_lease_stat_open(uint32_t access_mask)
{
	const uint32_t stat_open_bits =
		(SYNCHRONIZE_ACCESS|
		 FILE_READ_ATTRIBUTES|
		 FILE_WRITE_ATTRIBUTES|
		 READ_CONTROL_ACCESS);

	return (((access_mask &  stat_open_bits) != 0) &&
		((access_mask & ~stat_open_bits) == 0));
}

struct has_delete_on_close_state {
	bool ret;
};

static bool has_delete_on_close_fn(
	struct share_mode_entry *e,
	bool *modified,
	void *private_data)
{
	struct has_delete_on_close_state *state = private_data;
	state->ret = !share_entry_stale_pid(e);
	return state->ret;
}

static bool has_delete_on_close(struct share_mode_lock *lck,
				uint32_t name_hash)
{
	struct has_delete_on_close_state state = { .ret = false };
	bool ok;

	if (!is_delete_on_close_set(lck, name_hash)) {
		return false;
	}

	ok= share_mode_forall_entries(lck, has_delete_on_close_fn, &state);
	if (!ok) {
		DBG_DEBUG("share_mode_forall_entries failed\n");
		return false;
	}
	return state.ret;
}

static void share_mode_flags_get(
	uint16_t flags,
	uint32_t *access_mask,
	uint32_t *share_mode,
	uint32_t *lease_type)
{
	if (access_mask != NULL) {
		*access_mask =
			((flags & SHARE_MODE_ACCESS_READ) ?
			 FILE_READ_DATA : 0) |
			((flags & SHARE_MODE_ACCESS_WRITE) ?
			 FILE_WRITE_DATA : 0) |
			((flags & SHARE_MODE_ACCESS_DELETE) ?
			 DELETE_ACCESS : 0);
	}
	if (share_mode != NULL) {
		*share_mode =
			((flags & SHARE_MODE_SHARE_READ) ?
			 FILE_SHARE_READ : 0) |
			((flags & SHARE_MODE_SHARE_WRITE) ?
			 FILE_SHARE_WRITE : 0) |
			((flags & SHARE_MODE_SHARE_DELETE) ?
			 FILE_SHARE_DELETE : 0);
	}
	if (lease_type != NULL) {
		*lease_type =
			((flags & SHARE_MODE_LEASE_READ) ?
			 SMB2_LEASE_READ : 0) |
			((flags & SHARE_MODE_LEASE_WRITE) ?
			 SMB2_LEASE_WRITE : 0) |
			((flags & SHARE_MODE_LEASE_HANDLE) ?
			 SMB2_LEASE_HANDLE : 0);
	}
}

static uint16_t share_mode_flags_set(
	uint16_t flags,
	uint32_t access_mask,
	uint32_t share_mode,
	uint32_t lease_type)
{
	if (access_mask != UINT32_MAX) {
		flags &= ~(SHARE_MODE_ACCESS_READ|
			   SHARE_MODE_ACCESS_WRITE|
			   SHARE_MODE_ACCESS_DELETE);
		flags |= (access_mask & (FILE_READ_DATA | FILE_EXECUTE)) ?
			SHARE_MODE_ACCESS_READ : 0;
		flags |= (access_mask & (FILE_WRITE_DATA | FILE_APPEND_DATA)) ?
			SHARE_MODE_ACCESS_WRITE : 0;
		flags |= (access_mask & (DELETE_ACCESS)) ?
			SHARE_MODE_ACCESS_DELETE : 0;
	}
	if (share_mode != UINT32_MAX) {
		flags &= ~(SHARE_MODE_SHARE_READ|
			   SHARE_MODE_SHARE_WRITE|
			   SHARE_MODE_SHARE_DELETE);
		flags |= (share_mode & FILE_SHARE_READ) ?
			SHARE_MODE_SHARE_READ : 0;
		flags |= (share_mode & FILE_SHARE_WRITE) ?
			SHARE_MODE_SHARE_WRITE : 0;
		flags |= (share_mode & FILE_SHARE_DELETE) ?
			SHARE_MODE_SHARE_DELETE : 0;
	}
	if (lease_type != UINT32_MAX) {
		flags &= ~(SHARE_MODE_LEASE_READ|
			   SHARE_MODE_LEASE_WRITE|
			   SHARE_MODE_LEASE_HANDLE);
		flags |= (lease_type & SMB2_LEASE_READ) ?
			SHARE_MODE_LEASE_READ : 0;
		flags |= (lease_type & SMB2_LEASE_WRITE) ?
			SHARE_MODE_LEASE_WRITE : 0;
		flags |= (lease_type & SMB2_LEASE_HANDLE) ?
			SHARE_MODE_LEASE_HANDLE : 0;
	}

	return flags;
}

static uint16_t share_mode_flags_restrict(
	uint16_t flags,
	uint32_t access_mask,
	uint32_t share_mode,
	uint32_t lease_type)
{
	uint32_t existing_access_mask, existing_share_mode;
	uint32_t existing_lease_type;
	uint16_t ret;

	share_mode_flags_get(
		flags,
		&existing_access_mask,
		&existing_share_mode,
		&existing_lease_type);

	existing_access_mask |= access_mask;
	if (access_mask & conflicting_access) {
		existing_share_mode &= share_mode;
	}
	existing_lease_type |= lease_type;

	ret = share_mode_flags_set(
		flags,
		existing_access_mask,
		existing_share_mode,
		existing_lease_type);
	return ret;
}

/****************************************************************************
 Deal with share modes
 Invariant: Share mode must be locked on entry and exit.
 Returns -1 on error, or number of share modes on success (may be zero).
****************************************************************************/

struct open_mode_check_state {
	struct file_id fid;
	uint32_t access_mask;
	uint32_t share_access;
	uint32_t lease_type;
};

static bool open_mode_check_fn(
	struct share_mode_entry *e,
	bool *modified,
	void *private_data)
{
	struct open_mode_check_state *state = private_data;
	bool disconnected, stale;
	uint32_t access_mask, share_access, lease_type;

	disconnected = server_id_is_disconnected(&e->pid);
	if (disconnected) {
		return false;
	}

	access_mask = state->access_mask | e->access_mask;
	share_access = state->share_access;
	if (e->access_mask & conflicting_access) {
		share_access &= e->share_access;
	}
	lease_type = state->lease_type | get_lease_type(e, state->fid);

	if ((access_mask == state->access_mask) &&
	    (share_access == state->share_access) &&
	    (lease_type == state->lease_type)) {
		return false;
	}

	stale = share_entry_stale_pid(e);
	if (stale) {
		return false;
	}

	state->access_mask = access_mask;
	state->share_access = share_access;
	state->lease_type = lease_type;

	return false;
}

static NTSTATUS open_mode_check(connection_struct *conn,
				struct share_mode_lock *lck,
				uint32_t access_mask,
				uint32_t share_access)
{
	struct share_mode_data *d = lck->data;
	struct open_mode_check_state state;
	uint16_t new_flags;
	bool ok, conflict, have_share_entries;

	if (is_oplock_stat_open(access_mask)) {
		/* Stat open that doesn't trigger oplock breaks or share mode
		 * checks... ! JRA. */
		return NT_STATUS_OK;
	}

	/*
	 * Check if the share modes will give us access.
	 */

#if defined(DEVELOPER)
	{
		struct validate_my_share_entries_state validate_state = {
			.sconn = conn->sconn,
			.fid = d->id,
			.self = messaging_server_id(conn->sconn->msg_ctx),
		};
		ok = share_mode_forall_entries(
			lck, validate_my_share_entries_fn, &validate_state);
		SMB_ASSERT(ok);
	}
#endif

	have_share_entries = share_mode_have_entries(lck);
	if (!have_share_entries) {
		/*
		 * This is a fresh share mode lock where no conflicts
		 * can happen.
		 */
		return NT_STATUS_OK;
	}

	share_mode_flags_get(
		d->flags, &state.access_mask, &state.share_access, NULL);

	conflict = share_conflict(
		state.access_mask,
		state.share_access,
		access_mask,
		share_access);
	if (!conflict) {
		DBG_DEBUG("No conflict due to share_mode_flags access\n");
		return NT_STATUS_OK;
	}

	state = (struct open_mode_check_state) {
		.fid = d->id,
		.share_access = (FILE_SHARE_READ|
				 FILE_SHARE_WRITE|
				 FILE_SHARE_DELETE),
	};

	/*
	 * Walk the share mode array to recalculate d->flags
	 */

	ok = share_mode_forall_entries(lck, open_mode_check_fn, &state);
	if (!ok) {
		DBG_DEBUG("share_mode_forall_entries failed\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	new_flags = share_mode_flags_set(
		0, state.access_mask, state.share_access, state.lease_type);
	if (new_flags == d->flags) {
		/*
		 * We only end up here if we had a sharing violation
		 * from d->flags and have recalculated it.
		 */
		return NT_STATUS_SHARING_VIOLATION;
	}

	d->flags = new_flags;
	d->modified = true;

	conflict = share_conflict(
		state.access_mask,
		state.share_access,
		access_mask,
		share_access);
	if (!conflict) {
		DBG_DEBUG("No conflict due to share_mode_flags access\n");
		return NT_STATUS_OK;
	}

	return NT_STATUS_SHARING_VIOLATION;
}

/*
 * Send a break message to the oplock holder and delay the open for
 * our client.
 */

NTSTATUS send_break_message(struct messaging_context *msg_ctx,
			    const struct file_id *id,
			    const struct share_mode_entry *exclusive,
			    uint16_t break_to)
{
	struct oplock_break_message msg = {
		.id = *id,
		.share_file_id = exclusive->share_file_id,
		.break_to = break_to,
	};
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	NTSTATUS status;

	if (DEBUGLVL(10)) {
		struct server_id_buf buf;
		DBG_DEBUG("Sending break message to %s\n",
			  server_id_str_buf(exclusive->pid, &buf));
		NDR_PRINT_DEBUG(oplock_break_message, &msg);
	}

	ndr_err = ndr_push_struct_blob(
		&blob,
		talloc_tos(),
		&msg,
		(ndr_push_flags_fn_t)ndr_push_oplock_break_message);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("ndr_push_oplock_break_message failed: %s\n",
			    ndr_errstr(ndr_err));
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send(
		msg_ctx, exclusive->pid, MSG_SMB_BREAK_REQUEST, &blob);
	TALLOC_FREE(blob.data);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("Could not send oplock break message: %s\n",
			  nt_errstr(status)));
	}

	return status;
}

struct validate_oplock_types_state {
	bool valid;
	bool batch;
	bool ex_or_batch;
	bool level2;
	bool no_oplock;
	uint32_t num_non_stat_opens;
};

static bool validate_oplock_types_fn(
	struct share_mode_entry *e,
	bool *modified,
	void *private_data)
{
	struct validate_oplock_types_state *state = private_data;

	if (e->op_mid == 0) {
		/* INTERNAL_OPEN_ONLY */
		return false;
	}

	if (e->op_type == NO_OPLOCK && is_oplock_stat_open(e->access_mask)) {
		/*
		 * We ignore stat opens in the table - they always
		 * have NO_OPLOCK and never get or cause breaks. JRA.
		 */
		return false;
	}

	state->num_non_stat_opens += 1;

	if (BATCH_OPLOCK_TYPE(e->op_type)) {
		/* batch - can only be one. */
		if (share_entry_stale_pid(e)) {
			DBG_DEBUG("Found stale batch oplock\n");
			return false;
		}
		if (state->ex_or_batch ||
		    state->batch ||
		    state->level2 ||
		    state->no_oplock) {
			DBG_ERR("Bad batch oplock entry\n");
			state->valid = false;
			return true;
		}
		state->batch = true;
	}

	if (EXCLUSIVE_OPLOCK_TYPE(e->op_type)) {
		if (share_entry_stale_pid(e)) {
			DBG_DEBUG("Found stale duplicate oplock\n");
			return false;
		}
		/* Exclusive or batch - can only be one. */
		if (state->ex_or_batch ||
		    state->level2 ||
		    state->no_oplock) {
			DBG_ERR("Bad exclusive or batch oplock entry\n");
			state->valid = false;
			return true;
		}
		state->ex_or_batch = true;
	}

	if (LEVEL_II_OPLOCK_TYPE(e->op_type)) {
		if (state->batch || state->ex_or_batch) {
			if (share_entry_stale_pid(e)) {
				DBG_DEBUG("Found stale LevelII oplock\n");
				return false;
			}
			DBG_DEBUG("Bad levelII oplock entry\n");
			state->valid = false;
			return true;
		}
		state->level2 = true;
	}

	if (e->op_type == NO_OPLOCK) {
		if (state->batch || state->ex_or_batch) {
			if (share_entry_stale_pid(e)) {
				DBG_DEBUG("Found stale NO_OPLOCK entry\n");
				return false;
			}
			DBG_ERR("Bad no oplock entry\n");
			state->valid = false;
			return true;
		}
		state->no_oplock = true;
	}

	return false;
}

/*
 * Do internal consistency checks on the share mode for a file.
 */

static bool validate_oplock_types(struct share_mode_lock *lck)
{
	struct validate_oplock_types_state state = { .valid = true };
	bool ok;

	ok = share_mode_forall_entries(lck, validate_oplock_types_fn, &state);
	if (!ok) {
		DBG_DEBUG("share_mode_forall_entries failed\n");
		return false;
	}
	if (!state.valid) {
		DBG_DEBUG("Got invalid oplock configuration\n");
		return false;
	}

	if ((state.batch || state.ex_or_batch) &&
	    (state.num_non_stat_opens != 1)) {
		DBG_WARNING("got batch (%d) or ex (%d) non-exclusively "
			    "(%"PRIu32")\n",
			    (int)state.batch,
			    (int)state.ex_or_batch,
			    state.num_non_stat_opens);
		return false;
	}

	return true;
}

static bool is_same_lease(const files_struct *fsp,
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
				&e->client_guid,
				&e->lease_key);
}

static bool file_has_brlocks(files_struct *fsp)
{
	struct byte_range_lock *br_lck;

	br_lck = brl_get_locks_readonly(fsp);
	if (!br_lck)
		return false;

	return (brl_num_locks(br_lck) > 0);
}

struct fsp_lease *find_fsp_lease(struct files_struct *new_fsp,
				 const struct smb2_lease_key *key,
				 uint32_t current_state,
				 uint16_t lease_version,
				 uint16_t lease_epoch)
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
	new_fsp->lease->lease.lease_state = current_state;
	/*
	 * We internally treat all leases as V2 and update
	 * the epoch, but when sending breaks it matters if
	 * the requesting lease was v1 or v2.
	 */
	new_fsp->lease->lease.lease_version = lease_version;
	new_fsp->lease->lease.lease_epoch = lease_epoch;
	return new_fsp->lease;
}

static NTSTATUS try_lease_upgrade(struct files_struct *fsp,
				  struct share_mode_lock *lck,
				  const struct GUID *client_guid,
				  const struct smb2_lease *lease,
				  uint32_t granted)
{
	bool do_upgrade;
	uint32_t current_state, breaking_to_requested, breaking_to_required;
	bool breaking;
	uint16_t lease_version, epoch;
	uint32_t existing, requested;
	NTSTATUS status;

	status = leases_db_get(
		client_guid,
		&lease->lease_key,
		&fsp->file_id,
		&current_state,
		&breaking,
		&breaking_to_requested,
		&breaking_to_required,
		&lease_version,
		&epoch);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	fsp->lease = find_fsp_lease(
		fsp,
		&lease->lease_key,
		current_state,
		lease_version,
		epoch);
	if (fsp->lease == NULL) {
		DEBUG(1, ("Did not find existing lease for file %s\n",
			  fsp_str_dbg(fsp)));
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Upgrade only if the requested lease is a strict upgrade.
	 */
	existing = current_state;
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
	do_upgrade &= !breaking;

	DEBUG(10, ("existing=%"PRIu32", requested=%"PRIu32", "
		   "granted=%"PRIu32", do_upgrade=%d\n",
		   existing, requested, granted, (int)do_upgrade));

	if (do_upgrade) {
		NTSTATUS set_status;

		current_state = granted;
		epoch += 1;

		set_status = leases_db_set(
			client_guid,
			&lease->lease_key,
			current_state,
			breaking,
			breaking_to_requested,
			breaking_to_required,
			lease_version,
			epoch);

		if (!NT_STATUS_IS_OK(set_status)) {
			DBG_DEBUG("leases_db_set failed: %s\n",
				  nt_errstr(set_status));
			return set_status;
		}
	}

	fsp_lease_update(fsp);

	return NT_STATUS_OK;
}

static NTSTATUS grant_new_fsp_lease(struct files_struct *fsp,
				    struct share_mode_lock *lck,
				    const struct GUID *client_guid,
				    const struct smb2_lease *lease,
				    uint32_t granted)
{
	struct share_mode_data *d = lck->data;
	NTSTATUS status;

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

	status = leases_db_add(client_guid,
			       &lease->lease_key,
			       &fsp->file_id,
			       fsp->lease->lease.lease_state,
			       fsp->lease->lease.lease_version,
			       fsp->lease->lease.lease_epoch,
			       fsp->conn->connectpath,
			       fsp->fsp_name->base_name,
			       fsp->fsp_name->stream_name);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("%s: leases_db_add failed: %s\n", __func__,
			   nt_errstr(status)));
		TALLOC_FREE(fsp->lease);
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	d->modified = true;

	return NT_STATUS_OK;
}

static NTSTATUS grant_fsp_lease(struct files_struct *fsp,
				struct share_mode_lock *lck,
				const struct smb2_lease *lease,
				uint32_t granted)
{
	const struct GUID *client_guid = fsp_client_guid(fsp);
	NTSTATUS status;

	status = try_lease_upgrade(fsp, lck, client_guid, lease, granted);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		status = grant_new_fsp_lease(
			fsp, lck, client_guid, lease, granted);
	}

	return status;
}

static int map_lease_type_to_oplock(uint32_t lease_type)
{
	int result = NO_OPLOCK;

	switch (lease_type) {
	case SMB2_LEASE_READ|SMB2_LEASE_WRITE|SMB2_LEASE_HANDLE:
		result = BATCH_OPLOCK|EXCLUSIVE_OPLOCK;
		break;
	case SMB2_LEASE_READ|SMB2_LEASE_WRITE:
		result = EXCLUSIVE_OPLOCK;
		break;
	case SMB2_LEASE_READ|SMB2_LEASE_HANDLE:
	case SMB2_LEASE_READ:
		result = LEVEL_II_OPLOCK;
		break;
	}

	return result;
}

struct delay_for_oplock_state {
	struct files_struct *fsp;
	const struct smb2_lease *lease;
	bool will_overwrite;
	uint32_t delay_mask;
	bool first_open_attempt;
	bool got_handle_lease;
	bool got_oplock;
	bool have_other_lease;
	bool delay;
};

static bool delay_for_oplock_fn(
	struct share_mode_entry *e,
	bool *modified,
	void *private_data)
{
	struct delay_for_oplock_state *state = private_data;
	struct files_struct *fsp = state->fsp;
	const struct smb2_lease *lease = state->lease;
	bool e_is_lease = (e->op_type == LEASE_OPLOCK);
	uint32_t e_lease_type = get_lease_type(e, fsp->file_id);
	uint32_t break_to;
	bool lease_is_breaking = false;

	if (e_is_lease) {
		NTSTATUS status;

		if (lease != NULL) {
			bool our_lease = is_same_lease(fsp, e, lease);
			if (our_lease) {
				DBG_DEBUG("Ignoring our own lease\n");
				return false;
			}
		}

		status = leases_db_get(
			&e->client_guid,
			&e->lease_key,
			&fsp->file_id,
			NULL, /* current_state */
			&lease_is_breaking,
			NULL, /* breaking_to_requested */
			NULL, /* breaking_to_required */
			NULL, /* lease_version */
			NULL); /* epoch */

		/*
		 * leases_db_get() can return NT_STATUS_NOT_FOUND
		 * if the share_mode_entry e is stale and the
		 * lease record was already removed. In this case return
		 * false so the traverse continues.
		 */

		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND) &&
		    share_entry_stale_pid(e))
		{
			struct GUID_txt_buf guid_strbuf;
			struct file_id_buf file_id_strbuf;
			DBG_DEBUG("leases_db_get for client_guid [%s] "
				  "lease_key [%"PRIu64"/%"PRIu64"] "
				  "file_id [%s] failed for stale "
				  "share_mode_entry\n",
				  GUID_buf_string(&e->client_guid, &guid_strbuf),
				  e->lease_key.data[0],
				  e->lease_key.data[1],
				  file_id_str_buf(fsp->file_id, &file_id_strbuf));
			return false;
		}
		if (!NT_STATUS_IS_OK(status)) {
			struct GUID_txt_buf guid_strbuf;
			struct file_id_buf file_id_strbuf;
			DBG_ERR("leases_db_get for client_guid [%s] "
				"lease_key [%"PRIu64"/%"PRIu64"] "
				"file_id [%s] failed: %s\n",
				GUID_buf_string(&e->client_guid, &guid_strbuf),
				e->lease_key.data[0],
				e->lease_key.data[1],
				file_id_str_buf(fsp->file_id, &file_id_strbuf),
				nt_errstr(status));
			smb_panic("leases_db_get() failed");
		}
	}

	if (!state->got_handle_lease &&
	    ((e_lease_type & SMB2_LEASE_HANDLE) != 0) &&
	    !share_entry_stale_pid(e)) {
		state->got_handle_lease = true;
	}

	if (!state->got_oplock &&
	    (e->op_type != LEASE_OPLOCK) &&
	    !share_entry_stale_pid(e)) {
		state->got_oplock = true;
	}

	if (!state->have_other_lease &&
	    !is_same_lease(fsp, e, lease) &&
	    !share_entry_stale_pid(e)) {
		state->have_other_lease = true;
	}

	if (e_is_lease && is_lease_stat_open(fsp->access_mask)) {
		return false;
	}

	break_to = e_lease_type & ~state->delay_mask;

	if (state->will_overwrite) {
		break_to &= ~(SMB2_LEASE_HANDLE|SMB2_LEASE_READ);
	}

	DBG_DEBUG("e_lease_type %u, will_overwrite: %u\n",
		  (unsigned)e_lease_type,
		  (unsigned)state->will_overwrite);

	if ((e_lease_type & ~break_to) == 0) {
		if (lease_is_breaking) {
			state->delay = true;
		}
		return false;
	}

	if (share_entry_stale_pid(e)) {
		return false;
	}

	if (state->will_overwrite) {
		/*
		 * If we break anyway break to NONE directly.
		 * Otherwise vfs_set_filelen() will trigger the
		 * break.
		 */
		break_to &= ~(SMB2_LEASE_READ|SMB2_LEASE_WRITE);
	}

	if (!e_is_lease) {
		/*
		 * Oplocks only support breaking to R or NONE.
		 */
		break_to &= ~(SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE);
	}

	DBG_DEBUG("breaking from %d to %d\n",
		  (int)e_lease_type,
		  (int)break_to);
	send_break_message(
		fsp->conn->sconn->msg_ctx, &fsp->file_id, e, break_to);
	if (e_lease_type & state->delay_mask) {
		state->delay = true;
	}
	if (lease_is_breaking && !state->first_open_attempt) {
		state->delay = true;
	}

	return false;
};

static NTSTATUS delay_for_oplock(files_struct *fsp,
				 int oplock_request,
				 const struct smb2_lease *lease,
				 struct share_mode_lock *lck,
				 bool have_sharing_violation,
				 uint32_t create_disposition,
				 bool first_open_attempt)
{
	struct delay_for_oplock_state state = {
		.fsp = fsp,
		.lease = lease,
		.first_open_attempt = first_open_attempt,
	};
	uint32_t granted;
	NTSTATUS status;
	bool ok;

	if (is_oplock_stat_open(fsp->access_mask)) {
		goto grant;
	}

	state.delay_mask = have_sharing_violation ?
		SMB2_LEASE_HANDLE : SMB2_LEASE_WRITE;

	switch (create_disposition) {
	case FILE_SUPERSEDE:
	case FILE_OVERWRITE:
	case FILE_OVERWRITE_IF:
		state.will_overwrite = true;
		break;
	default:
		state.will_overwrite = false;
		break;
	}

	ok = share_mode_forall_entries(lck, delay_for_oplock_fn, &state);
	if (!ok) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (state.delay) {
		return NT_STATUS_RETRY;
	}

grant:
	if (have_sharing_violation) {
		return NT_STATUS_SHARING_VIOLATION;
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
		DBG_DEBUG("file %s has byte range locks\n",
			  fsp_str_dbg(fsp));
		granted &= ~SMB2_LEASE_READ;
	}

	if (state.have_other_lease) {
		/*
		 * Can grant only one writer
		 */
		granted &= ~SMB2_LEASE_WRITE;
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
		if (state.got_oplock) {
			granted &= ~SMB2_LEASE_HANDLE;
		}

		fsp->oplock_type = LEASE_OPLOCK;

		status = grant_fsp_lease(fsp, lck, lease, granted);
		if (!NT_STATUS_IS_OK(status)) {
			return status;

		}

		DBG_DEBUG("lease_state=%d\n", fsp->lease->lease.lease_state);
	} else {
		if (state.got_handle_lease) {
			granted = SMB2_LEASE_NONE;
		}

		fsp->oplock_type = map_lease_type_to_oplock(granted);

		status = set_file_oplock(fsp);
		if (!NT_STATUS_IS_OK(status)) {
			/*
			 * Could not get the kernel oplock
			 */
			fsp->oplock_type = NO_OPLOCK;
		}
	}

	if ((granted & SMB2_LEASE_READ) &&
	    ((lck->data->flags & SHARE_MODE_LEASE_READ) == 0)) {
		lck->data->flags |= SHARE_MODE_LEASE_READ;
		lck->data->modified = true;
	}

	DBG_DEBUG("oplock type 0x%x on file %s\n",
		  fsp->oplock_type, fsp_str_dbg(fsp));

	return NT_STATUS_OK;
}

static NTSTATUS handle_share_mode_lease(
	files_struct *fsp,
	struct share_mode_lock *lck,
	uint32_t create_disposition,
	uint32_t access_mask,
	uint32_t share_access,
	int oplock_request,
	const struct smb2_lease *lease,
	bool first_open_attempt)
{
	bool sharing_violation = false;
	NTSTATUS status;

	status = open_mode_check(
		fsp->conn, lck, access_mask, share_access);
	if (NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
		sharing_violation = true;
		status = NT_STATUS_OK; /* handled later */
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (oplock_request == INTERNAL_OPEN_ONLY) {
		if (sharing_violation) {
			DBG_DEBUG("Sharing violation for internal open\n");
			return NT_STATUS_SHARING_VIOLATION;
		}

		/*
		 * Internal opens never do oplocks or leases. We don't
		 * need to go through delay_for_oplock().
		 */
		fsp->oplock_type = NO_OPLOCK;

		return NT_STATUS_OK;
	}

	status = delay_for_oplock(
		fsp,
		oplock_request,
		lease,
		lck,
		sharing_violation,
		create_disposition,
		first_open_attempt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static bool request_timed_out(struct smb_request *req, struct timeval timeout)
{
	struct timeval now, end_time;
	GetTimeOfDay(&now);
	end_time = timeval_sum(&req->request_time, &timeout);
	return (timeval_compare(&end_time, &now) < 0);
}

struct defer_open_state {
	struct smbXsrv_connection *xconn;
	uint64_t mid;
};

static void defer_open_done(struct tevent_req *req);

/**
 * Defer an open and watch a locking.tdb record
 *
 * This defers an open that gets rescheduled once the locking.tdb record watch
 * is triggered by a change to the record.
 *
 * It is used to defer opens that triggered an oplock break and for the SMB1
 * sharing violation delay.
 **/
static void defer_open(struct share_mode_lock *lck,
		       struct timeval timeout,
		       struct smb_request *req,
		       struct file_id id)
{
	struct deferred_open_record *open_rec = NULL;
	struct timeval abs_timeout;
	struct defer_open_state *watch_state;
	struct tevent_req *watch_req;
	struct timeval_buf tvbuf1, tvbuf2;
	struct file_id_buf fbuf;
	bool ok;

	abs_timeout = timeval_sum(&req->request_time, &timeout);

	DBG_DEBUG("request time [%s] timeout [%s] mid [%" PRIu64 "] "
		  "file_id [%s]\n",
		  timeval_str_buf(&req->request_time, false, true, &tvbuf1),
		  timeval_str_buf(&abs_timeout, false, true, &tvbuf2),
		  req->mid,
		  file_id_str_buf(id, &fbuf));

	open_rec = talloc_zero(NULL, struct deferred_open_record);
	if (open_rec == NULL) {
		TALLOC_FREE(lck);
		exit_server("talloc failed");
	}

	watch_state = talloc(open_rec, struct defer_open_state);
	if (watch_state == NULL) {
		exit_server("talloc failed");
	}
	watch_state->xconn = req->xconn;
	watch_state->mid = req->mid;

	DBG_DEBUG("defering mid %" PRIu64 "\n", req->mid);

	watch_req = share_mode_watch_send(
		watch_state,
		req->sconn->ev_ctx,
		lck->data->id,
		(struct server_id){0});
	if (watch_req == NULL) {
		exit_server("Could not watch share mode record");
	}
	tevent_req_set_callback(watch_req, defer_open_done, watch_state);

	ok = tevent_req_set_endtime(watch_req, req->sconn->ev_ctx, abs_timeout);
	if (!ok) {
		exit_server("tevent_req_set_endtime failed");
	}

	ok = push_deferred_open_message_smb(req, timeout, id, open_rec);
	if (!ok) {
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

	status = share_mode_watch_recv(req, NULL, NULL);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("dbwrap_watched_watch_recv returned %s\n",
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

/**
 * Actually attempt the kernel oplock polling open.
 */

static void poll_open_fn(struct tevent_context *ev,
			 struct tevent_timer *te,
			 struct timeval current_time,
			 void *private_data)
{
	struct deferred_open_record *open_rec = talloc_get_type_abort(
		private_data, struct deferred_open_record);
	bool ok;

	TALLOC_FREE(open_rec->watch_req);

	ok = schedule_deferred_open_message_smb(
		open_rec->xconn, open_rec->mid);
	if (!ok) {
		exit_server("schedule_deferred_open_message_smb failed");
	}
	DBG_DEBUG("timer fired. Retrying open !\n");
}

static void poll_open_done(struct tevent_req *subreq);

/**
 * Reschedule an open for 1 second from now, if not timed out.
 **/
static bool setup_poll_open(
	struct smb_request *req,
	struct share_mode_lock *lck,
	struct file_id id,
	struct timeval max_timeout,
	struct timeval interval)
{
	bool ok;
	struct deferred_open_record *open_rec = NULL;
	struct timeval endtime, next_interval;
	struct file_id_buf ftmp;

	if (request_timed_out(req, max_timeout)) {
		return false;
	}

	open_rec = talloc_zero(NULL, struct deferred_open_record);
	if (open_rec == NULL) {
		DBG_WARNING("talloc failed\n");
		return false;
	}
	open_rec->xconn = req->xconn;
	open_rec->mid = req->mid;

	/*
	 * Make sure open_rec->te does not come later than the
	 * request's maximum endtime.
	 */

	endtime = timeval_sum(&req->request_time, &max_timeout);
	next_interval = timeval_current_ofs(interval.tv_sec, interval.tv_usec);
	next_interval = timeval_min(&endtime, &next_interval);

	open_rec->te = tevent_add_timer(
		req->sconn->ev_ctx,
		open_rec,
		next_interval,
		poll_open_fn,
		open_rec);
	if (open_rec->te == NULL) {
		DBG_WARNING("tevent_add_timer failed\n");
		TALLOC_FREE(open_rec);
		return false;
	}

	if (lck != NULL) {
		open_rec->watch_req = share_mode_watch_send(
			open_rec,
			req->sconn->ev_ctx,
			lck->data->id,
			(struct server_id) {0});
		if (open_rec->watch_req == NULL) {
			DBG_WARNING("share_mode_watch_send failed\n");
			TALLOC_FREE(open_rec);
			return false;
		}
		tevent_req_set_callback(
			open_rec->watch_req, poll_open_done, open_rec);
	}

	ok = push_deferred_open_message_smb(req, max_timeout, id, open_rec);
	if (!ok) {
		DBG_WARNING("push_deferred_open_message_smb failed\n");
		TALLOC_FREE(open_rec);
		return false;
	}

	DBG_DEBUG("poll request time [%s] mid [%" PRIu64 "] file_id [%s]\n",
		  timeval_string(talloc_tos(), &req->request_time, false),
		  req->mid,
		  file_id_str_buf(id, &ftmp));

	return true;
}

static void poll_open_done(struct tevent_req *subreq)
{
	struct deferred_open_record *open_rec = tevent_req_callback_data(
		subreq, struct deferred_open_record);
	NTSTATUS status;
	bool ok;

	status = share_mode_watch_recv(subreq, NULL, NULL);
	TALLOC_FREE(subreq);
	open_rec->watch_req = NULL;
	TALLOC_FREE(open_rec->te);

	DBG_DEBUG("dbwrap_watched_watch_recv returned %s\n",
		  nt_errstr(status));

	ok = schedule_deferred_open_message_smb(
		open_rec->xconn, open_rec->mid);
	if (!ok) {
		exit_server("schedule_deferred_open_message_smb failed");
	}
}

bool defer_smb1_sharing_violation(struct smb_request *req)
{
	bool ok;
	int timeout_usecs;

	if (!lp_defer_sharing_violations()) {
		return false;
	}

	/*
	 * Try every 200msec up to (by default) one second. To be
	 * precise, according to behaviour note <247> in [MS-CIFS],
	 * the server tries 5 times. But up to one second should be
	 * close enough.
	 */

	timeout_usecs = lp_parm_int(
		SNUM(req->conn),
		"smbd",
		"sharedelay",
		SHARING_VIOLATION_USEC_WAIT);

	ok = setup_poll_open(
		req,
		NULL,
		(struct file_id) {0},
		(struct timeval) { .tv_usec = timeout_usecs },
		(struct timeval) { .tv_usec = 200000 });
	return ok;
}

/****************************************************************************
 On overwrite open ensure that the attributes match.
****************************************************************************/

static bool open_match_attributes(connection_struct *conn,
				  uint32_t old_dos_attr,
				  uint32_t new_dos_attr,
				  mode_t new_unx_mode,
				  mode_t *returned_unx_mode)
{
	uint32_t noarch_old_dos_attr, noarch_new_dos_attr;

	noarch_old_dos_attr = (old_dos_attr & ~FILE_ATTRIBUTE_ARCHIVE);
	noarch_new_dos_attr = (new_dos_attr & ~FILE_ATTRIBUTE_ARCHIVE);

	if((noarch_old_dos_attr == 0 && noarch_new_dos_attr != 0) || 
	   (noarch_old_dos_attr != 0 && ((noarch_old_dos_attr & noarch_new_dos_attr) == noarch_old_dos_attr))) {
		*returned_unx_mode = new_unx_mode;
	} else {
		*returned_unx_mode = (mode_t)0;
	}

	DEBUG(10,("open_match_attributes: old_dos_attr = 0x%x, "
		  "new_dos_attr = 0x%x "
		  "returned_unx_mode = 0%o\n",
		  (unsigned int)old_dos_attr,
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

static void schedule_defer_open(struct share_mode_lock *lck,
				struct file_id id,
				struct smb_request *req)
{
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

	if (request_timed_out(req, timeout)) {
		return;
	}

	defer_open(lck, timeout, req, id);
}

/****************************************************************************
 Reschedule an open call that went asynchronous.
****************************************************************************/

static void schedule_async_open_timer(struct tevent_context *ev,
				      struct tevent_timer *te,
				      struct timeval current_time,
				      void *private_data)
{
	exit_server("async open timeout");
}

static void schedule_async_open(struct smb_request *req)
{
	struct deferred_open_record *open_rec = NULL;
	struct timeval timeout = timeval_set(20, 0);
	bool ok;

	if (request_timed_out(req, timeout)) {
		return;
	}

	open_rec = talloc_zero(NULL, struct deferred_open_record);
	if (open_rec == NULL) {
		exit_server("deferred_open_record_create failed");
	}
	open_rec->async_open = true;

	ok = push_deferred_open_message_smb(
		req, timeout, (struct file_id){0}, open_rec);
	if (!ok) {
		exit_server("push_deferred_open_message_smb failed");
	}

	open_rec->te = tevent_add_timer(req->sconn->ev_ctx,
					req,
					timeval_current_ofs(20, 0),
					schedule_async_open_timer,
					open_rec);
	if (open_rec->te == NULL) {
		exit_server("tevent_add_timer failed");
	}
}

/****************************************************************************
 Work out what access_mask to use from what the client sent us.
****************************************************************************/

static NTSTATUS smbd_calculate_maximum_allowed_access(
	connection_struct *conn,
	struct files_struct *dirfsp,
	const struct smb_filename *smb_fname,
	bool use_privs,
	uint32_t *p_access_mask)
{
	struct security_descriptor *sd;
	uint32_t access_granted;
	NTSTATUS status;

	SMB_ASSERT(dirfsp == conn->cwd_fsp);

	if (!use_privs && (get_current_uid(conn) == (uid_t)0)) {
		*p_access_mask |= FILE_GENERIC_ALL;
		return NT_STATUS_OK;
	}

	status = SMB_VFS_GET_NT_ACL_AT(conn,
				dirfsp,
				smb_fname,
				(SECINFO_OWNER |
					SECINFO_GROUP |
					SECINFO_DACL),
				talloc_tos(),
				&sd);

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
		if (can_delete_file_in_directory(conn,
				conn->cwd_fsp,
				smb_fname))
		{
			*p_access_mask |= DELETE_ACCESS;
		}
	}

	return NT_STATUS_OK;
}

NTSTATUS smbd_calculate_access_mask(connection_struct *conn,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			bool use_privs,
			uint32_t access_mask,
			uint32_t *access_mask_out)
{
	NTSTATUS status;
	uint32_t orig_access_mask = access_mask;
	uint32_t rejected_share_access;

	SMB_ASSERT(dirfsp == conn->cwd_fsp);

	if (access_mask & SEC_MASK_INVALID) {
		DBG_DEBUG("access_mask [%8x] contains invalid bits\n",
			  access_mask);
		return NT_STATUS_ACCESS_DENIED;
	}

	/*
	 * Convert GENERIC bits to specific bits.
	 */

	se_map_generic(&access_mask, &file_generic_mapping);

	/* Calculate MAXIMUM_ALLOWED_ACCESS if requested. */
	if (access_mask & MAXIMUM_ALLOWED_ACCESS) {

		status = smbd_calculate_maximum_allowed_access(conn,
					dirfsp,
					smb_fname,
					use_privs,
					&access_mask);

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
			    uint32_t access_mask,		/* access bits (FILE_READ_DATA etc.) */
			    uint32_t share_access,	/* share constants (FILE_SHARE_READ etc) */
			    uint32_t create_disposition,	/* FILE_OPEN_IF etc. */
			    uint32_t create_options,	/* options such as delete on close. */
			    uint32_t new_dos_attributes,	/* attributes used for new file. */
			    int oplock_request, 	/* internal Samba oplock codes. */
			    const struct smb2_lease *lease,
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
	uint32_t existing_dos_attributes = 0;
	struct share_mode_lock *lck = NULL;
	uint32_t open_access_mask = access_mask;
	NTSTATUS status;
	struct smb_filename *parent_dir_fname = NULL;
	SMB_STRUCT_STAT saved_stat = smb_fname->st;
	struct timespec old_write_time;
	struct file_id id;
	bool setup_poll = false;
	bool ok;

	SMB_ASSERT(fsp->dirfsp == conn->cwd_fsp);

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

	ok = parent_smb_fname(talloc_tos(),
			      smb_fname,
			      &parent_dir_fname,
			      NULL);
	if (!ok) {
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
				     smb_fname, parent_dir_fname);
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
		SMB_ASSERT(oplock_request == INTERNAL_OPEN_ONLY);
	} else {
		/* And req != NULL means no INTERNAL_OPEN_ONLY */
		SMB_ASSERT(((oplock_request & INTERNAL_OPEN_ONLY) == 0));
	}

	/*
	 * Only non-internal opens can be deferred at all
	 */

	if (req) {
		struct deferred_open_record *open_rec;
		if (get_deferred_open_message_state(req, NULL, &open_rec)) {

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
			/*
			 * Only use stored DOS attributes for checks
			 * against requested attributes (below via
			 * open_match_attributes()), cf bug #11992
			 * for details. -slow
			 */
			uint32_t attr = 0;

			status = SMB_VFS_GET_DOS_ATTRIBUTES(conn, smb_fname, &attr);
			if (NT_STATUS_IS_OK(status)) {
				existing_dos_attributes = attr;
			}
		}
	}

	/* ignore any oplock requests if oplocks are disabled */
	if (!lp_oplocks(SNUM(conn)) ||
	    IS_VETO_OPLOCK_PATH(conn, smb_fname->base_name)) {
		/* Mask off everything except the private Samba bits. */
		oplock_request &= SAMBA_PRIVATE_OPLOCK_MASK;
	}

	/* this is for OS/2 long file names - say we don't support them */
	if (req != NULL && !req->posix_pathnames &&
			strstr(smb_fname->base_name,".+,;=[].")) {
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
					   unx_mode, &new_unx_mode)) {
			DEBUG(5,("open_file_ntcreate: attributes mismatch "
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

	status = smbd_calculate_access_mask(conn,
					conn->cwd_fsp,
					smb_fname,
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
		if (is_oplock_stat_open(open_access_mask) && lease == NULL) {
			oplock_request = NO_OPLOCK;
		}
	}

	DEBUG(10, ("open_file_ntcreate: fname=%s, after mapping "
		   "access_mask=0x%x\n", smb_fname_str_dbg(smb_fname),
		    access_mask));

	/*
	 * Note that we ignore the append flag as append does not
	 * mean the same thing under DOS and Unix.
	 */

	flags = calculate_open_access_flags(access_mask, private_flags);

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
	 * With kernel oplocks the open breaking an oplock
	 * blocks until the oplock holder has given up the
	 * oplock or closed the file. We prevent this by always
	 * trying to open the file with O_NONBLOCK (see "man
	 * fcntl" on Linux).
	 *
	 * If a process that doesn't use the smbd open files
	 * database or communication methods holds a kernel
	 * oplock we must periodically poll for available open
	 * using O_NONBLOCK.
	 */
	flags2 |= O_NONBLOCK;

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

	if (VALID_STAT(smb_fname->st)) {
		/*
		 * Only try and create a file id before open
		 * for an existing file. For a file being created
		 * this won't do anything useful until the file
		 * exists and has a valid stat struct.
		 */
		fsp->file_id = vfs_file_id_from_sbuf(conn, &smb_fname->st);
	}
	fsp->fh->private_options = private_flags;
	fsp->access_mask = open_access_mask; /* We change this to the
					      * requested access_mask after
					      * the open is done. */
	if (posix_open) {
		fsp->posix_flags |= FSP_POSIX_FLAGS_ALL;
	}

	if ((create_options & FILE_DELETE_ON_CLOSE) &&
			(flags2 & O_CREAT) &&
			!file_existed) {
		/* Delete on close semantics for new files. */
		status = can_set_delete_on_close(fsp,
						new_dos_attributes);
		if (!NT_STATUS_IS_OK(status)) {
			fd_close(fsp);
			return status;
		}
	}

	/*
	 * Ensure we pay attention to default ACLs on directories if required.
	 */

        if ((flags2 & O_CREAT) && lp_inherit_acls(SNUM(conn)) &&
	    (def_acl = directory_has_default_acl(conn,
				conn->cwd_fsp,
				parent_dir_fname)))
	{
		unx_mode = (0777 & lp_create_mask(SNUM(conn)));
	}

	DEBUG(4,("calling open_file with flags=0x%X flags2=0x%X mode=0%o, "
		"access_mask = 0x%x, open_access_mask = 0x%x\n",
		 (unsigned int)flags, (unsigned int)flags2,
		 (unsigned int)unx_mode, (unsigned int)access_mask,
		 (unsigned int)open_access_mask));

	fsp_open = open_file(fsp,
			     req,
			     parent_dir_fname,
			     flags|flags2,
			     unx_mode,
			     access_mask,
			     open_access_mask,
			     &new_file_created);
	if (NT_STATUS_EQUAL(fsp_open, NT_STATUS_NETWORK_BUSY)) {
		if (file_existed && S_ISFIFO(fsp->fsp_name->st.st_ex_mode)) {
			DEBUG(10, ("FIFO busy\n"));
			return NT_STATUS_NETWORK_BUSY;
		}
		if (req == NULL) {
			DEBUG(10, ("Internal open busy\n"));
			return NT_STATUS_NETWORK_BUSY;
		}
		/*
		 * This handles the kernel oplock case:
		 *
		 * the file has an active kernel oplock and the open() returned
		 * EWOULDBLOCK/EAGAIN which maps to NETWORK_BUSY.
		 *
		 * "Samba locking.tdb oplocks" are handled below after acquiring
		 * the sharemode lock with get_share_mode_lock().
		 */
		setup_poll = true;
	}

	if (NT_STATUS_EQUAL(fsp_open, NT_STATUS_RETRY)) {
		/*
		 * EINTR from the open(2) syscall. Just setup a retry
		 * in a bit. We can't use the sys_write() tight retry
		 * loop here, as we might have to actually deal with
		 * lease-break signals to avoid a deadlock.
		 */
		setup_poll = true;
	}

	if (setup_poll) {
		/*
		 * From here on we assume this is an oplock break triggered
		 */

		lck = get_existing_share_mode_lock(talloc_tos(), fsp->file_id);

		if ((lck != NULL) && !validate_oplock_types(lck)) {
			smb_panic("validate_oplock_types failed");
		}

		/*
		 * Retry once a second. If there's a share_mode_lock
		 * around, also wait for it in case it was smbd
		 * holding that kernel oplock that can quickly tell us
		 * the oplock got removed.
		 */

		setup_poll_open(
			req,
			lck,
			fsp->file_id,
			timeval_set(OPLOCK_BREAK_TIMEOUT*2, 0),
			timeval_set(1, 0));

		TALLOC_FREE(lck);

		return NT_STATUS_SHARING_VIOLATION;
	}

	if (!NT_STATUS_IS_OK(fsp_open)) {
		bool wait_for_aio = NT_STATUS_EQUAL(
			fsp_open, NT_STATUS_MORE_PROCESSING_REQUIRED);
		if (wait_for_aio) {
			schedule_async_open(req);
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
		DBG_WARNING("file %s - dev/ino mismatch. "
			    "Old (dev=%ju, ino=%ju). "
			    "New (dev=%ju, ino=%ju). Failing open "
			    "with NT_STATUS_ACCESS_DENIED.\n",
			    smb_fname_str_dbg(smb_fname),
			    (uintmax_t)saved_stat.st_ex_dev,
			    (uintmax_t)saved_stat.st_ex_ino,
			    (uintmax_t)smb_fname->st.st_ex_dev,
			    (uintmax_t)smb_fname->st.st_ex_ino);
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

	status = handle_share_mode_lease(
		fsp,
		lck,
		create_disposition,
		access_mask,
		share_access,
		oplock_request,
		lease,
		first_open_attempt);

	if (NT_STATUS_EQUAL(status, NT_STATUS_RETRY)) {
		schedule_defer_open(lck, fsp->file_id, req);
		TALLOC_FREE(lck);
		fd_close(fsp);
		return NT_STATUS_SHARING_VIOLATION;
	}

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(lck);
		fd_close(fsp);
		return status;
	}

	{
		struct share_mode_data *d = lck->data;
		uint16_t new_flags = share_mode_flags_restrict(
			d->flags, access_mask, share_access, UINT32_MAX);

		if (new_flags != d->flags) {
			d->flags = new_flags;
			d->modified = true;
		}
	}

	ok = set_share_mode(
		lck,
		fsp,
		get_current_uid(fsp->conn),
		req ? req->mid : 0,
		fsp->oplock_type,
		share_access,
		access_mask);
	if (!ok) {
		if (fsp->oplock_type == LEASE_OPLOCK) {
			status = remove_lease_if_stale(
				lck,
				fsp_client_guid(fsp),
				&fsp->lease->lease.lease_key);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_WARNING("remove_lease_if_stale "
					    "failed: %s\n",
					    nt_errstr(status));
			}
		}
		return NT_STATUS_NO_MEMORY;
	}

	/* Should we atomically (to the client at least) truncate ? */
	if ((!new_file_created) &&
	    (flags2 & O_TRUNC) &&
	    (S_ISREG(fsp->fsp_name->st.st_ex_mode))) {
		int ret;

		ret = SMB_VFS_FTRUNCATE(fsp, 0);
		if (ret != 0) {
			status = map_nt_error_from_unix(errno);
			del_share_mode(lck, fsp);
			TALLOC_FREE(lck);
			fd_close(fsp);
			return status;
		}
		notify_fname(fsp->conn, NOTIFY_ACTION_MODIFIED,
			     FILE_NOTIFY_CHANGE_SIZE
			     | FILE_NOTIFY_CHANGE_ATTRIBUTES,
			     fsp->fsp_name->base_name);
	}

	/*
	 * We have the share entry *locked*.....
	 */

	/* Delete streams if create_disposition requires it */
	if (!new_file_created && clear_ads(create_disposition) &&
	    !is_ntfs_stream_smb_fname(smb_fname)) {
		status = delete_all_streams(conn, smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			del_share_mode(lck, fsp);
			TALLOC_FREE(lck);
			fd_close(fsp);
			return status;
		}
	}

	if (fsp->fh->fd != -1 && lp_kernel_share_modes(SNUM(conn))) {
		int ret_flock;
		/*
		 * Beware: streams implementing VFS modules may
		 * implement streams in a way that fsp will have the
		 * basefile open in the fsp fd, so lacking a distinct
		 * fd for the stream kernel_flock will apply on the
		 * basefile which is wrong. The actual check is
		 * deferred to the VFS module implementing the
		 * kernel_flock call.
		 */
		ret_flock = SMB_VFS_KERNEL_FLOCK(fsp, share_access, access_mask);
		if(ret_flock == -1 ){

			del_share_mode(lck, fsp);
			TALLOC_FREE(lck);
			fd_close(fsp);

			return NT_STATUS_SHARING_VIOLATION;
		}

		fsp->fsp_flags.kernel_share_modes_taken = true;
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

	/* Handle strange delete on close create semantics. */
	if (create_options & FILE_DELETE_ON_CLOSE) {
		if (!new_file_created) {
			status = can_set_delete_on_close(fsp,
					 existing_dos_attributes);

			if (!NT_STATUS_IS_OK(status)) {
				/* Remember to delete the mode we just added. */
				del_share_mode(lck, fsp);
				TALLOC_FREE(lck);
				fd_close(fsp);
				return status;
			}
		}
		/* Note that here we set the *initial* delete on close flag,
		   not the regular one. The magic gets handled in close. */
		fsp->fsp_flags.initial_delete_on_close = true;
	}

	/*
	 * If we created a file and it's not a stream, this is the point where
	 * we set the itime (aka invented time) that get's stored in the DOS
	 * attribute xattr. The value is going to be either what the filesystem
	 * provided or a copy of the creation date.
	 *
	 * Either way, we turn the itime into a File-ID, unless the filesystem
	 * provided one (unlikely).
	 */
	if (info == FILE_WAS_CREATED && !is_named_stream(smb_fname)) {
		smb_fname->st.st_ex_iflags &= ~ST_EX_IFLAG_CALCULATED_ITIME;

		if (lp_store_dos_attributes(SNUM(conn)) &&
		    smb_fname->st.st_ex_iflags & ST_EX_IFLAG_CALCULATED_FILE_ID)
		{
			uint64_t file_id;

			file_id = make_file_id_from_itime(&smb_fname->st);
			update_stat_ex_file_id(&smb_fname->st, file_id);
		}
	}

	if (info != FILE_WAS_OPENED) {
		/* Overwritten files should be initially set as archive */
		if ((info == FILE_WAS_OVERWRITTEN && lp_map_archive(SNUM(conn))) ||
		    lp_store_dos_attributes(SNUM(conn))) {
			(void)dos_mode(conn, smb_fname);
			if (!posix_open) {
				if (file_set_dosmode(conn, smb_fname,
					    new_dos_attributes | FILE_ATTRIBUTE_ARCHIVE,
					    parent_dir_fname, true) == 0) {
					unx_mode = smb_fname->st.st_ex_mode;
				}
			}
		}
	}

	/* Determine sparse flag. */
	if (posix_open) {
		/* POSIX opens are sparse by default. */
		fsp->fsp_flags.is_sparse = true;
	} else {
		fsp->fsp_flags.is_sparse =
			(existing_dos_attributes & FILE_ATTRIBUTE_SPARSE);
	}

	/*
	 * Take care of inherited ACLs on created files - if default ACL not
	 * selected.
	 */

	if (!posix_open && new_file_created && !def_acl) {
		if (unx_mode != smb_fname->st.st_ex_mode) {
			int ret = SMB_VFS_FCHMOD(fsp, unx_mode);
			if (ret == -1) {
				DBG_INFO("failed to reset "
				  "attributes of file %s to 0%o\n",
				  smb_fname_str_dbg(smb_fname),
				  (unsigned int)unx_mode);
			}
		}

	} else if (new_unx_mode) {
		/*
		 * We only get here in the case of:
		 *
		 * a). Not a POSIX open.
		 * b). File already existed.
		 * c). File was overwritten.
		 * d). Requested DOS attributes didn't match
		 *     the DOS attributes on the existing file.
		 *
		 * In that case new_unx_mode has been set
		 * equal to the calculated mode (including
		 * possible inheritance of the mode from the
		 * containing directory).
		 *
		 * Note this mode was calculated with the
		 * DOS attribute FILE_ATTRIBUTE_ARCHIVE added,
		 * so the mode change here is suitable for
		 * an overwritten file.
		 */

		if (new_unx_mode != smb_fname->st.st_ex_mode) {
			int ret = SMB_VFS_FCHMOD(fsp, new_unx_mode);
			if (ret == -1) {
				DBG_INFO("failed to reset "
				  "attributes of file %s to 0%o\n",
				  smb_fname_str_dbg(smb_fname),
				  (unsigned int)new_unx_mode);
			}
		}
	}

	{
		/*
		 * Deal with other opens having a modified write time.
		 */
		struct timespec write_time = get_share_mode_write_time(lck);

		if (!is_omit_timespec(&write_time)) {
			update_stat_ex_mtime(&fsp->fsp_name->st, write_time);
		}
	}

	TALLOC_FREE(lck);

	return NT_STATUS_OK;
}

static NTSTATUS mkdir_internal(connection_struct *conn,
			       struct files_struct **dirfsp,
			       struct smb_filename *smb_dname,
			       uint32_t file_attributes)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	mode_t mode;
	struct smb_filename *parent_dir_fname = NULL;
	NTSTATUS status;
	bool posix_open = false;
	bool need_re_stat = false;
	uint32_t access_mask = SEC_DIR_ADD_SUBDIR;
	int ret;
	bool ok;
	struct smb_filename *oldwd_fname = NULL;
	struct smb_filename *smb_fname_rel = NULL;

	SMB_ASSERT(*dirfsp == conn->cwd_fsp);

	if (!CAN_WRITE(conn) || (access_mask & ~(conn->share_access))) {
		DEBUG(5,("mkdir_internal: failing share access "
			 "%s\n", lp_servicename(talloc_tos(), lp_sub, SNUM(conn))));
		return NT_STATUS_ACCESS_DENIED;
	}

	ok = parent_smb_fname(talloc_tos(),
			      smb_dname,
			      &parent_dir_fname,
			      &smb_fname_rel);
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	if (file_attributes & FILE_FLAG_POSIX_SEMANTICS) {
		posix_open = true;
		mode = (mode_t)(file_attributes & ~FILE_FLAG_POSIX_SEMANTICS);
	} else {
		mode = unix_mode(conn,
				 FILE_ATTRIBUTE_DIRECTORY,
				 smb_dname,
				 parent_dir_fname);
	}

	status = check_parent_access(conn,
				     *dirfsp,
				     smb_dname,
				     access_mask);
	if(!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("mkdir_internal: check_parent_access "
			"on directory %s for path %s returned %s\n",
			smb_fname_str_dbg(parent_dir_fname),
			smb_dname->base_name,
			nt_errstr(status) ));
		return status;
	}

	oldwd_fname = vfs_GetWd(talloc_tos(), conn);
	if (oldwd_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Pin parent directory in place. */
	if (vfs_ChDir(conn, parent_dir_fname) == -1) {
		status = map_nt_error_from_unix(errno);
		TALLOC_FREE(oldwd_fname);
		return status;
	}

	/* Ensure the relative path is below the share. */
	status = check_reduced_name(conn, parent_dir_fname, smb_fname_rel);
	if (!NT_STATUS_IS_OK(status)) {
		goto need_chdir_err;
	}

	ret = SMB_VFS_MKDIRAT(conn,
			      *dirfsp,
			      smb_fname_rel,
			      mode);
	if (ret != 0) {
		status = map_nt_error_from_unix(errno);
		goto need_chdir_err;
	}

	/* Return to share $cwd. */
	ret = vfs_ChDir(conn, oldwd_fname);
	if (ret == -1) {
		smb_panic("unable to get back to old directory\n");
	}
	TALLOC_FREE(oldwd_fname);

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

	smb_dname->st.st_ex_iflags &= ~ST_EX_IFLAG_CALCULATED_ITIME;

	if (lp_store_dos_attributes(SNUM(conn))) {
		if (smb_dname->st.st_ex_iflags & ST_EX_IFLAG_CALCULATED_FILE_ID)
		{
			uint64_t file_id;

			file_id = make_file_id_from_itime(&smb_dname->st);
			update_stat_ex_file_id(&smb_dname->st, file_id);
		}

		if (!posix_open) {
			file_set_dosmode(conn, smb_dname,
					 file_attributes | FILE_ATTRIBUTE_DIRECTORY,
					 parent_dir_fname, true);
		}
	}

	if (lp_inherit_permissions(SNUM(conn))) {
		inherit_access_posix_acl(conn, parent_dir_fname,
					 smb_dname, mode);
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
			SMB_VFS_CHMOD(conn, smb_dname,
				      (smb_dname->st.st_ex_mode |
					  (mode & ~smb_dname->st.st_ex_mode)));
			need_re_stat = true;
		}
	}

	/* Change the owner if required. */
	if (lp_inherit_owner(SNUM(conn)) != INHERIT_OWNER_NO) {
		change_dir_owner_to_parent(conn, parent_dir_fname,
					   smb_dname,
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

  need_chdir_err:

	ret = vfs_ChDir(conn, oldwd_fname);
	if (ret == -1) {
		smb_panic("unable to get back to old directory\n");
	}
	TALLOC_FREE(oldwd_fname);
	return status;
}

/****************************************************************************
 Open a directory from an NT SMB call.
****************************************************************************/

static NTSTATUS open_directory(connection_struct *conn,
			       struct smb_request *req,
			       struct files_struct **dirfsp,
			       struct smb_filename *smb_dname,
			       uint32_t access_mask,
			       uint32_t share_access,
			       uint32_t create_disposition,
			       uint32_t create_options,
			       uint32_t file_attributes,
			       int *pinfo,
			       files_struct **result)
{
	files_struct *fsp = NULL;
	bool dir_existed = VALID_STAT(smb_dname->st);
	struct share_mode_lock *lck = NULL;
	NTSTATUS status;
	struct timespec mtimespec;
	int info = 0;
	int flags;
	bool ok;

	SMB_ASSERT(*dirfsp == conn->cwd_fsp);

	if (is_ntfs_stream_smb_fname(smb_dname)) {
		DEBUG(2, ("open_directory: %s is a stream name!\n",
			  smb_fname_str_dbg(smb_dname)));
		return NT_STATUS_NOT_A_DIRECTORY;
	}

	if (!(file_attributes & FILE_FLAG_POSIX_SEMANTICS)) {
		/* Ensure we have a directory attribute. */
		file_attributes |= FILE_ATTRIBUTE_DIRECTORY;
	}

	DBG_INFO("opening directory %s, access_mask = 0x%"PRIx32", "
		 "share_access = 0x%"PRIx32" create_options = 0x%"PRIx32", "
		 "create_disposition = 0x%"PRIx32", "
		 "file_attributes = 0x%"PRIx32"\n",
		 smb_fname_str_dbg(smb_dname),
		 access_mask,
		 share_access,
		 create_options,
		 create_disposition,
		 file_attributes);

	status = smbd_calculate_access_mask(conn,
					*dirfsp,
					smb_dname,
					false,
					access_mask,
					&access_mask);
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

			status = mkdir_internal(conn, dirfsp, smb_dname,
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
				status = mkdir_internal(conn, dirfsp, smb_dname,
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

					/*
					 * If mkdir_internal() returned
					 * NT_STATUS_OBJECT_NAME_COLLISION
					 * we still must lstat the path.
					 */

					if (SMB_VFS_LSTAT(conn, smb_dname)
							== -1) {
						DEBUG(2, ("Could not stat "
							"directory '%s' just "
							"opened: %s\n",
							smb_fname_str_dbg(
								smb_dname),
							strerror(errno)));
						return map_nt_error_from_unix(
								errno);
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
						*dirfsp,
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
	fsp->fsp_flags.can_lock = false;
	fsp->fsp_flags.can_read = false;
	fsp->fsp_flags.can_write = false;

	fsp->fh->private_options = 0;
	/*
	 * According to Samba4, SEC_FILE_READ_ATTRIBUTE is always granted,
	 */
	fsp->access_mask = access_mask | FILE_READ_ATTRIBUTES;
	fsp->print_file = NULL;
	fsp->fsp_flags.modified = false;
	fsp->oplock_type = NO_OPLOCK;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->fsp_flags.is_directory = true;
	if (file_attributes & FILE_FLAG_POSIX_SEMANTICS) {
		fsp->posix_flags |= FSP_POSIX_FLAGS_ALL;
	}
	status = fsp_set_smb_fname(fsp, smb_dname);
	if (!NT_STATUS_IS_OK(status)) {
		file_free(req, fsp);
		return status;
	}

	if (*dirfsp == fsp->conn->cwd_fsp) {
		fsp->dirfsp = fsp->conn->cwd_fsp;
	} else {
		fsp->dirfsp = talloc_move(fsp, dirfsp);
	}

	/* Don't store old timestamps for directory
	   handles in the internal database. We don't
	   update them in there if new objects
	   are created in the directory. Currently
	   we only update timestamps on file writes.
	   See bug #9870.
	*/
	mtimespec = make_omit_timespec();

	/* POSIX allows us to open a directory with O_RDONLY. */
	flags = O_RDONLY;
#ifdef O_DIRECTORY
	flags |= O_DIRECTORY;
#endif

	status = fd_openat(fsp, flags, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_INFO("Could not open fd for "
			"%s (%s)\n",
			smb_fname_str_dbg(smb_dname),
			nt_errstr(status));
		file_free(req, fsp);
		return status;
	}

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		fd_close(fsp);
		file_free(req, fsp);
		return status;
	}

	if(!S_ISDIR(fsp->fsp_name->st.st_ex_mode)) {
		DEBUG(5,("open_directory: %s is not a directory !\n",
			 smb_fname_str_dbg(smb_dname)));
                fd_close(fsp);
                file_free(req, fsp);
		return NT_STATUS_NOT_A_DIRECTORY;
	}

	/* Ensure there was no race condition.  We need to check
	 * dev/inode but not permissions, as these can change
	 * legitimately */
	if (!check_same_dev_ino(&smb_dname->st, &fsp->fsp_name->st)) {
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

	{
		struct share_mode_data *d = lck->data;
		uint16_t new_flags = share_mode_flags_restrict(
			d->flags, access_mask, share_access, UINT32_MAX);

		if (new_flags != d->flags) {
			d->flags = new_flags;
			d->modified = true;
		}
	}

	ok = set_share_mode(
		lck,
		fsp,
		get_current_uid(conn),
		req ? req->mid : 0,
		NO_OPLOCK,
		share_access,
		fsp->access_mask);
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
			/* Note that here we set the *initial* delete on close flag,
			   not the regular one. The magic gets handled in close. */
			fsp->fsp_flags.initial_delete_on_close = true;
		}
	}

	{
		/*
		 * Deal with other opens having a modified write time. Is this
		 * possible for directories?
		 */
		struct timespec write_time = get_share_mode_write_time(lck);

		if (!is_omit_timespec(&write_time)) {
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
		&conn->cwd_fsp,				/* dirfsp */
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

void msg_file_was_renamed(struct messaging_context *msg_ctx,
			  void *private_data,
			  uint32_t msg_type,
			  struct server_id src,
			  DATA_BLOB *data)
{
	struct file_rename_message *msg = NULL;
	enum ndr_err_code ndr_err;
	files_struct *fsp;
	struct smb_filename *smb_fname = NULL;
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);

	msg = talloc(talloc_tos(), struct file_rename_message);
	if (msg == NULL) {
		DBG_WARNING("talloc failed\n");
		return;
	}

	ndr_err = ndr_pull_struct_blob_all(
		data,
		msg,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_file_rename_message);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_DEBUG("ndr_pull_oplock_break_message failed: %s\n",
			  ndr_errstr(ndr_err));
		goto out;
	}
	if (DEBUGLEVEL >= 10) {
		struct server_id_buf buf;
		DBG_DEBUG("Got rename message from %s\n",
			  server_id_str_buf(src, &buf));
		NDR_PRINT_DEBUG(file_rename_message, msg);
	}

	/* stream_name must always be NULL if there is no stream. */
	if ((msg->stream_name != NULL) && (msg->stream_name[0] == '\0')) {
		msg->stream_name = NULL;
	}

	smb_fname = synthetic_smb_fname(msg,
					msg->base_name,
					msg->stream_name,
					NULL,
					0,
					0);
	if (smb_fname == NULL) {
		DBG_DEBUG("synthetic_smb_fname failed\n");
		goto out;
	}

	fsp = file_find_dif(sconn, msg->id, msg->share_file_id);
	if (fsp == NULL) {
		DBG_DEBUG("fsp not found\n");
		goto out;
	}

	if (strcmp(fsp->conn->connectpath, msg->servicepath) == 0) {
		NTSTATUS status;
		DBG_DEBUG("renaming file %s from %s -> %s\n",
			  fsp_fnum_dbg(fsp),
			  fsp_str_dbg(fsp),
			  smb_fname_str_dbg(smb_fname));
		status = fsp_set_smb_fname(fsp, smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("fsp_set_smb_fname failed: %s\n",
				  nt_errstr(status));
		}
	} else {
		/* TODO. JRA. */
		/*
		 * Now we have the complete path we can work out if
		 * this is actually within this share and adjust
		 * newname accordingly.
		 */
		DBG_DEBUG("share mismatch (sharepath %s not sharepath %s) "
			  "%s from %s -> %s\n",
			  fsp->conn->connectpath,
			  msg->servicepath,
			  fsp_fnum_dbg(fsp),
			  fsp_str_dbg(fsp),
			  smb_fname_str_dbg(smb_fname));
	}
 out:
	TALLOC_FREE(msg);
}

/*
 * If a main file is opened for delete, all streams need to be checked for
 * !FILE_SHARE_DELETE. Do this by opening with DELETE_ACCESS.
 * If that works, delete them all by setting the delete on close and close.
 */

static NTSTATUS open_streams_for_delete(connection_struct *conn,
					const struct smb_filename *smb_fname)
{
	struct stream_struct *stream_info = NULL;
	files_struct **streams = NULL;
	int j;
	unsigned int i, num_streams = 0;
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;

	status = vfs_streaminfo(conn, NULL, smb_fname, talloc_tos(),
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
		struct smb_filename *smb_fname_cp;

		if (strequal(stream_info[i].name, "::$DATA")) {
			streams[i] = NULL;
			continue;
		}

		smb_fname_cp = synthetic_smb_fname(talloc_tos(),
					smb_fname->base_name,
					stream_info[i].name,
					NULL,
					smb_fname->twrp,
					(smb_fname->flags &
						~SMB_FILENAME_POSIX_PATH));
		if (smb_fname_cp == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}

		if (SMB_VFS_STAT(conn, smb_fname_cp) == -1) {
			DEBUG(10, ("Unable to stat stream: %s\n",
				   smb_fname_str_dbg(smb_fname_cp)));
		}

		status = SMB_VFS_CREATE_FILE(
			 conn,			/* conn */
			 NULL,			/* req */
			 &conn->cwd_fsp,	/* dirfsp */
			 smb_fname_cp,		/* fname */
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
				   smb_fname_str_dbg(smb_fname_cp),
				   nt_errstr(status)));

			TALLOC_FREE(smb_fname_cp);
			break;
		}
		TALLOC_FREE(smb_fname_cp);
	}

	/*
	 * don't touch the variable "status" beyond this point :-)
	 */

	for (j = i-1 ; j >= 0; j--) {
		if (streams[j] == NULL) {
			continue;
		}

		DEBUG(10, ("Closing stream # %d, %s\n", j,
			   fsp_str_dbg(streams[j])));
		close_file(NULL, streams[j], NORMAL_CLOSE);
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
	struct security_descriptor *parent_desc = NULL;
	NTSTATUS status = NT_STATUS_OK;
	struct security_descriptor *psd = NULL;
	const struct dom_sid *owner_sid = NULL;
	const struct dom_sid *group_sid = NULL;
	uint32_t security_info_sent = (SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL);
	struct security_token *token = fsp->conn->session_info->security_token;
	bool inherit_owner =
	    (lp_inherit_owner(SNUM(fsp->conn)) == INHERIT_OWNER_WINDOWS_AND_UNIX);
	bool inheritable_components = false;
	bool try_builtin_administrators = false;
	const struct dom_sid *BA_U_sid = NULL;
	const struct dom_sid *BA_G_sid = NULL;
	bool try_system = false;
	const struct dom_sid *SY_U_sid = NULL;
	const struct dom_sid *SY_G_sid = NULL;
	size_t size = 0;
	struct smb_filename *parent_dir = NULL;
	bool ok;

	ok = parent_smb_fname(frame,
			      fsp->fsp_name,
			      &parent_dir,
			      NULL);
	if (!ok) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	status = SMB_VFS_GET_NT_ACL_AT(fsp->conn,
				fsp->conn->cwd_fsp,
				parent_dir,
				(SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL),
				frame,
				&parent_desc);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	inheritable_components = sd_has_inheritable_components(parent_desc,
					fsp->fsp_flags.is_directory);

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
			fsp->fsp_flags.is_directory);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	/* If inheritable_components == false,
	   se_create_child_secdesc()
	   creates a security descriptor with a NULL dacl
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

struct lease_match_break_state {
	struct messaging_context *msg_ctx;
	const struct smb2_lease_key *lease_key;
	struct file_id id;

	bool found_lease;
	uint16_t version;
	uint16_t epoch;
};

static bool lease_match_break_fn(
	struct share_mode_entry *e,
	void *private_data)
{
	struct lease_match_break_state *state = private_data;
	bool stale, equal;
	uint32_t e_lease_type;
	NTSTATUS status;

	stale = share_entry_stale_pid(e);
	if (stale) {
		return false;
	}

	equal = smb2_lease_key_equal(&e->lease_key, state->lease_key);
	if (!equal) {
		return false;
	}

	status = leases_db_get(
		&e->client_guid,
		&e->lease_key,
		&state->id,
		NULL, /* current_state */
		NULL, /* breaking */
		NULL, /* breaking_to_requested */
		NULL, /* breaking_to_required */
		&state->version, /* lease_version */
		&state->epoch); /* epoch */
	if (NT_STATUS_IS_OK(status)) {
		state->found_lease = true;
	} else {
		DBG_WARNING("Could not find version/epoch: %s\n",
			    nt_errstr(status));
	}

	e_lease_type = get_lease_type(e, state->id);
	if (e_lease_type == SMB2_LEASE_NONE) {
		return false;
	}
	send_break_message(state->msg_ctx, &state->id, e, SMB2_LEASE_NONE);

	/*
	 * Windows 7 and 8 lease clients are broken in that they will
	 * not respond to lease break requests whilst waiting for an
	 * outstanding open request on that lease handle on the same
	 * TCP connection, due to holding an internal inode lock.
	 *
	 * This means we can't reschedule ourselves here, but must
	 * return from the create.
	 *
	 * Work around:
	 *
	 * Send the breaks and then return SMB2_LEASE_NONE in the
	 * lease handle to cause them to acknowledge the lease
	 * break. Consultation with Microsoft engineering confirmed
	 * this approach is safe.
	 */

	return false;
}

static NTSTATUS lease_match(connection_struct *conn,
			    struct smb_request *req,
			    const struct smb2_lease_key *lease_key,
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
	}

	status = leases_db_parse(&sconn->client->global->client_guid,
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
		struct lease_match_break_state break_state = {
			.msg_ctx = conn->sconn->msg_ctx,
			.lease_key = lease_key,
		};
		struct share_mode_lock *lck;
		bool ok;

		if (file_id_equal(&state.ids[i], &state.id)) {
			/* Don't need to break our own file. */
			continue;
		}

		break_state.id = state.ids[i];

		lck = get_existing_share_mode_lock(
			talloc_tos(), break_state.id);
		if (lck == NULL) {
			/* Race condition - file already closed. */
			continue;
		}

		ok = share_mode_forall_leases(
			lck, lease_match_break_fn, &break_state);
		if (!ok) {
			DBG_DEBUG("share_mode_forall_leases failed\n");
			continue;
		}

		TALLOC_FREE(lck);

		if (break_state.found_lease) {
			*p_version = break_state.version;
			*p_epoch = break_state.epoch;
		}
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
				     struct files_struct **dirfsp,
				     struct smb_filename *smb_fname,
				     uint32_t access_mask,
				     uint32_t share_access,
				     uint32_t create_disposition,
				     uint32_t create_options,
				     uint32_t file_attributes,
				     uint32_t oplock_request,
				     const struct smb2_lease *lease,
				     uint64_t allocation_size,
				     uint32_t private_flags,
				     struct security_descriptor *sd,
				     struct ea_list *ea_list,

				     files_struct **result,
				     int *pinfo)
{
	struct smb2_lease none_lease;
	int info = FILE_WAS_OPENED;
	files_struct *base_fsp = NULL;
	files_struct *fsp = NULL;
	NTSTATUS status;

	SMB_ASSERT(*dirfsp == conn->cwd_fsp);

	DBG_DEBUG("create_file_unixpath: access_mask = 0x%x "
		  "file_attributes = 0x%x, share_access = 0x%x, "
		  "create_disposition = 0x%x create_options = 0x%x "
		  "oplock_request = 0x%x private_flags = 0x%x "
		  "ea_list = %p, sd = %p, "
		  "fname = %s\n",
		  (unsigned int)access_mask,
		  (unsigned int)file_attributes,
		  (unsigned int)share_access,
		  (unsigned int)create_disposition,
		  (unsigned int)create_options,
		  (unsigned int)oplock_request,
		  (unsigned int)private_flags,
		  ea_list, sd, smb_fname_str_dbg(smb_fname));

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

		if (req == NULL) {
			DBG_WARNING("Got lease on internal open\n");
			status = NT_STATUS_INTERNAL_ERROR;
			goto fail;
		}

		status = lease_match(conn,
				req,
				&lease->lease_key,
				conn->connectpath,
				smb_fname,
				&version,
				&epoch);
		if (NT_STATUS_EQUAL(status, NT_STATUS_OPLOCK_NOT_GRANTED)) {
			/* Dynamic share file. No leases and update epoch... */
			none_lease = *lease;
			none_lease.lease_state = SMB2_LEASE_NONE;
			none_lease.lease_epoch = epoch;
			none_lease.lease_version = version;
			lease = &none_lease;
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
		status = open_streams_for_delete(conn, smb_fname);

		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	if (access_mask & SEC_FLAG_SYSTEM_SECURITY) {
		bool ok;

		ok = security_token_has_privilege(get_current_nttok(conn),
						  SEC_PRIV_SECURITY);
		if (!ok) {
			DBG_DEBUG("open on %s failed - "
				"SEC_FLAG_SYSTEM_SECURITY denied.\n",
				smb_fname_str_dbg(smb_fname));
			status = NT_STATUS_PRIVILEGE_NOT_HELD;
			goto fail;
		}

		if (conn->sconn->using_smb2 &&
		    (access_mask == SEC_FLAG_SYSTEM_SECURITY))
		{
			/*
			 * No other bits set. Windows SMB2 refuses this.
			 * See smbtorture3 SMB2-SACL test.
			 *
			 * Note this is an SMB2-only behavior,
			 * smbtorture3 SMB1-SYSTEM-SECURITY already tests
			 * that SMB1 allows this.
			 */
			status = NT_STATUS_ACCESS_DENIED;
			goto fail;
		}
	}

	/*
	 * Files or directories can't be opened DELETE_ON_CLOSE without
	 * delete access.
	 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=13358
	 */
	if (create_options & FILE_DELETE_ON_CLOSE) {
		if ((access_mask & DELETE_ACCESS) == 0) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto fail;
		}
	}

	if ((conn->fs_capabilities & FILE_NAMED_STREAMS)
	    && is_ntfs_stream_smb_fname(smb_fname)
	    && (!(private_flags & NTCREATEX_OPTIONS_PRIVATE_STREAM_DELETE))) {
		uint32_t base_create_disposition;
		struct smb_filename *smb_fname_base = NULL;
		uint32_t base_privflags;

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
						NULL,
						NULL,
						smb_fname->twrp,
						smb_fname->flags);
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

		base_privflags = NTCREATEX_OPTIONS_PRIVATE_STREAM_BASEOPEN;

		/* Open the base file. */
		status = create_file_unixpath(conn,
					      NULL,
					      dirfsp,
					      smb_fname_base,
					      0,
					      FILE_SHARE_READ
					      | FILE_SHARE_WRITE
					      | FILE_SHARE_DELETE,
					      base_create_disposition,
					      0,
					      0,
					      0,
					      NULL,
					      0,
					      base_privflags,
					      NULL,
					      NULL,
					      &base_fsp,
					      NULL);
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
		status = open_directory(conn,
					req,
					dirfsp,
					smb_fname,
					access_mask,
					share_access,
					create_disposition,
					create_options,
					file_attributes,
					&info,
					&fsp);
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

		if (*dirfsp == fsp->conn->cwd_fsp) {
			fsp->dirfsp = fsp->conn->cwd_fsp;
		} else {
			fsp->dirfsp = talloc_move(fsp, dirfsp);
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
			status = open_directory(conn,
						req,
						dirfsp,
						smb_fname,
						access_mask,
						share_access,
						create_disposition,
						create_options,
						file_attributes,
						&info,
						&fsp);
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

	if (!fsp->fsp_flags.is_directory &&
	    S_ISDIR(fsp->fsp_name->st.st_ex_mode))
	{
		status = NT_STATUS_ACCESS_DENIED;
		goto fail;
	}

	/* Save the requested allocation size. */
	if ((info == FILE_WAS_CREATED) || (info == FILE_WAS_OVERWRITTEN)) {
		if ((allocation_size > (uint64_t)fsp->fsp_name->st.st_ex_size)
		    && !(fsp->fsp_flags.is_directory))
		{
			fsp->initial_allocation_size = smb_roundup(
				fsp->conn, allocation_size);
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

NTSTATUS create_file_default(connection_struct *conn,
			     struct smb_request *req,
			     struct files_struct **_dirfsp,
			     struct smb_filename *smb_fname,
			     uint32_t access_mask,
			     uint32_t share_access,
			     uint32_t create_disposition,
			     uint32_t create_options,
			     uint32_t file_attributes,
			     uint32_t oplock_request,
			     const struct smb2_lease *lease,
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
	struct smb2_create_blob *posx = NULL;
	struct files_struct *dirfsp = *_dirfsp;

	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);

	DBG_DEBUG("create_file: access_mask = 0x%x "
		  "file_attributes = 0x%x, share_access = 0x%x, "
		  "create_disposition = 0x%x create_options = 0x%x "
		  "oplock_request = 0x%x "
		  "private_flags = 0x%x "
		  "ea_list = %p, sd = %p, "
		  "dirfsp = %s, "
		  "fname = %s\n",
		  (unsigned int)access_mask,
		  (unsigned int)file_attributes,
		  (unsigned int)share_access,
		  (unsigned int)create_disposition,
		  (unsigned int)create_options,
		  (unsigned int)oplock_request,
		  (unsigned int)private_flags,
		  ea_list,
		  sd,
		  fsp_str_dbg(dirfsp),
		  smb_fname_str_dbg(smb_fname));

	if (req != NULL) {
		/*
		 * Remember the absolute time of the original request
		 * with this mid. We'll use it later to see if this
		 * has timed out.
		 */
		get_deferred_open_message_state(req, &req->request_time, NULL);
	}

	/*
	 * Check to see if this is a mac fork of some kind.
	 */

	stream_name = is_ntfs_stream_smb_fname(smb_fname);
	if (stream_name) {
		enum FAKE_FILE_TYPE fake_file_type;

		fake_file_type = is_fake_file(smb_fname);

		if (req != NULL && fake_file_type != FAKE_FILE_TYPE_NONE) {

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
		if (req != NULL && req->posix_pathnames) {
			ret = SMB_VFS_LSTAT(conn, smb_fname);
		} else {
			ret = SMB_VFS_STAT(conn, smb_fname);
		}

		if (ret == 0 && VALID_STAT_OF_DIR(smb_fname->st)) {
			status = NT_STATUS_FILE_IS_A_DIRECTORY;
			goto fail;
		}
	}

	posx = smb2_create_blob_find(
		in_context_blobs, SMB2_CREATE_TAG_POSIX);
	if (posx != NULL) {
		uint32_t wire_mode_bits = 0;
		mode_t mode_bits = 0;
		SMB_STRUCT_STAT sbuf = { 0 };
		enum perm_type ptype =
			(create_options & FILE_DIRECTORY_FILE) ?
			PERM_NEW_DIR : PERM_NEW_FILE;

		if (posx->data.length != 4) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto fail;
		}

		wire_mode_bits = IVAL(posx->data.data, 0);
		status = unix_perms_from_wire(
			conn, &sbuf, wire_mode_bits, ptype, &mode_bits);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
		/*
		 * Remove type info from mode, leaving only the
		 * permissions and setuid/gid bits.
		 */
		mode_bits &= ~S_IFMT;

		file_attributes = (FILE_FLAG_POSIX_SEMANTICS | mode_bits);
	}

	status = create_file_unixpath(conn,
				      req,
				      _dirfsp,
				      smb_fname,
				      access_mask,
				      share_access,
				      create_disposition,
				      create_options,
				      file_attributes,
				      oplock_request,
				      lease,
				      allocation_size,
				      private_flags,
				      sd,
				      ea_list,
				      &fsp,
				      &info);
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
