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
#include "system/filesys.h"
#include "lib/util/server_id.h"
#include "printing.h"
#include "locking/share_mode_lock.h"
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
#include "source3/lib/server_id_watch.h"
#include "locking/leases_db.h"
#include "librpc/gen_ndr/ndr_leases_db.h"
#include "lib/util/time_basic.h"
#include "source3/smbd/dir.h"

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
					struct files_struct *dirfsp,
					const struct smb_filename *smb_fname,
					uint32_t access_mask,
					uint32_t rejected_mask)
{
	if ((access_mask & DELETE_ACCESS) &&
		    (rejected_mask & DELETE_ACCESS) &&
		    can_delete_file_in_directory(conn,
				dirfsp,
				smb_fname))
	{
		return true;
	}
	return false;
}

/****************************************************************************
 Check if we have open rights.
****************************************************************************/

static NTSTATUS smbd_check_access_rights_fname(
				struct connection_struct *conn,
				const struct smb_filename *smb_fname,
				bool use_privs,
				uint32_t access_mask,
				uint32_t do_not_check_mask)
{
	uint32_t rejected_share_access;
	uint32_t effective_access;

	rejected_share_access = access_mask & ~(conn->share_access);

	if (rejected_share_access) {
		DBG_DEBUG("rejected share access 0x%"PRIx32" on "
			  "%s (0x%"PRIx32")\n",
			  access_mask,
			  smb_fname_str_dbg(smb_fname),
			  rejected_share_access);
		return NT_STATUS_ACCESS_DENIED;
	}

	effective_access = access_mask & ~do_not_check_mask;
	if (effective_access == 0) {
		DBG_DEBUG("do_not_check_mask override on %s. Granting 0x%x for free.\n",
			  smb_fname_str_dbg(smb_fname),
			  (unsigned int)access_mask);
		return NT_STATUS_OK;
	}

	if (!use_privs && get_current_uid(conn) == (uid_t)0) {
		/* I'm sorry sir, I didn't know you were root... */
		DBG_DEBUG("root override on %s. Granting 0x%x\n",
			  smb_fname_str_dbg(smb_fname),
			  (unsigned int)access_mask);
		return NT_STATUS_OK;
	}

	if ((access_mask & DELETE_ACCESS) &&
	    !lp_acl_check_permissions(SNUM(conn)))
	{
		DBG_DEBUG("Not checking ACL on DELETE_ACCESS on file %s. "
			  "Granting 0x%"PRIx32"\n",
			  smb_fname_str_dbg(smb_fname),
			  access_mask);
		return NT_STATUS_OK;
	}

	if (access_mask == DELETE_ACCESS &&
	    VALID_STAT(smb_fname->st) &&
	    S_ISLNK(smb_fname->st.st_ex_mode))
	{
		/* We can always delete a symlink. */
		DBG_DEBUG("Not checking ACL on DELETE_ACCESS on symlink %s.\n",
			  smb_fname_str_dbg(smb_fname));
		return NT_STATUS_OK;
	}

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS smbd_check_access_rights_sd(
				struct connection_struct *conn,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				struct security_descriptor *sd,
				bool use_privs,
				uint32_t access_mask,
				uint32_t do_not_check_mask)
{
	uint32_t rejected_mask = access_mask;
	NTSTATUS status;

	if (sd == NULL) {
		goto access_denied;
	}

	status = se_file_access_check(sd,
				get_current_nttok(conn),
				use_privs,
				(access_mask & ~do_not_check_mask),
				&rejected_mask);

	DBG_DEBUG("File [%s] requesting [0x%"PRIx32"] "
		  "returning [0x%"PRIx32"] (%s)\n",
		  smb_fname_str_dbg(smb_fname),
		  access_mask,
		  rejected_mask,
		  nt_errstr(status));

	if (!NT_STATUS_IS_OK(status)) {
		if (DEBUGLEVEL >= 10) {
			DBG_DEBUG("acl for %s is:\n",
				  smb_fname_str_dbg(smb_fname));
			NDR_PRINT_DEBUG(security_descriptor, sd);
		}
	}

	TALLOC_FREE(sd);

	if (NT_STATUS_IS_OK(status) ||
	    !NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED))
	{
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
	     lp_map_system(SNUM(conn))))
	{
		rejected_mask &= ~FILE_WRITE_ATTRIBUTES;

		DBG_DEBUG("overrode FILE_WRITE_ATTRIBUTES on file %s\n",
			  smb_fname_str_dbg(smb_fname));
	}

	if (parent_override_delete(conn,
				   dirfsp,
				   smb_fname,
				   access_mask,
				   rejected_mask))
	{
		/*
		 * Were we trying to do an open for delete and didn't get DELETE
		 * access. Check if the directory allows DELETE_CHILD.
		 * See here:
		 * http://blogs.msdn.com/oldnewthing/archive/2004/06/04/148426.aspx
		 * for details.
		 */

		rejected_mask &= ~DELETE_ACCESS;

		DBG_DEBUG("Overrode DELETE_ACCESS on file %s\n",
			  smb_fname_str_dbg(smb_fname));
	}

	if (rejected_mask != 0) {
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

NTSTATUS smbd_check_access_rights_fsp(struct files_struct *dirfsp,
				      struct files_struct *fsp,
				      bool use_privs,
				      uint32_t access_mask)
{
	struct security_descriptor *sd = NULL;
	uint32_t do_not_check_mask = 0;
	NTSTATUS status;

	/* Cope with fake/printer fsp's. */
	if (fsp->fake_file_handle != NULL || fsp->print_file != NULL) {
		if ((fsp->access_mask & access_mask) != access_mask) {
			return NT_STATUS_ACCESS_DENIED;
		}
		return NT_STATUS_OK;
	}

	if (fsp_get_pathref_fd(fsp) == -1) {
		/*
		 * This is a POSIX open on a symlink. For the pathname
		 * version of this function we used to return the st_mode
		 * bits turned into an NT ACL. For a symlink the mode bits
		 * are always rwxrwxrwx which means the pathname version always
		 * returned NT_STATUS_OK for a symlink. For the handle reference
		 * to a symlink use the handle access bits.
		 */
		if ((fsp->access_mask & access_mask) != access_mask) {
			return NT_STATUS_ACCESS_DENIED;
		}
		return NT_STATUS_OK;
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
	 * The compatibility mode allows one to skip this check
	 * to smoothen upgrades.
	 */
	if (lp_acl_allow_execute_always(SNUM(fsp->conn))) {
		do_not_check_mask |= FILE_EXECUTE;
	}

	status = smbd_check_access_rights_fname(fsp->conn,
						fsp->fsp_name,
						use_privs,
						access_mask,
						do_not_check_mask);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		return status;
	}

	status = SMB_VFS_FGET_NT_ACL(metadata_fsp(fsp),
				     (SECINFO_OWNER |
				      SECINFO_GROUP |
				      SECINFO_DACL),
				     talloc_tos(),
				     &sd);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Could not get acl on %s: %s\n",
			  fsp_str_dbg(fsp),
			  nt_errstr(status));
		return status;
	}

	return smbd_check_access_rights_sd(fsp->conn,
					   dirfsp,
					   fsp->fsp_name,
					   sd,
					   use_privs,
					   access_mask,
					   do_not_check_mask);
}

/*
 * Given an fsp that represents a parent directory,
 * check if the requested access can be granted.
 */
NTSTATUS check_parent_access_fsp(struct files_struct *fsp,
				 uint32_t access_mask)
{
	NTSTATUS status;
	struct security_descriptor *parent_sd = NULL;
	uint32_t access_granted = 0;
	struct share_mode_lock *lck = NULL;
	uint32_t name_hash;
	bool delete_on_close_set;
	TALLOC_CTX *frame = talloc_stackframe();

	if (get_current_uid(fsp->conn) == (uid_t)0) {
		/* I'm sorry sir, I didn't know you were root... */
		DBG_DEBUG("root override on %s. Granting 0x%x\n",
			fsp_str_dbg(fsp),
			(unsigned int)access_mask);
		status = NT_STATUS_OK;
		goto out;
	}

	status = SMB_VFS_FGET_NT_ACL(fsp,
				SECINFO_DACL,
				frame,
				&parent_sd);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_INFO("SMB_VFS_FGET_NT_ACL failed for "
			"%s with error %s\n",
			fsp_str_dbg(fsp),
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
				get_current_nttok(fsp->conn),
				false,
				(access_mask & ~FILE_READ_ATTRIBUTES),
				&access_granted);
	if(!NT_STATUS_IS_OK(status)) {
		DBG_INFO("access check "
			"on directory %s for mask 0x%x returned (0x%x) %s\n",
			fsp_str_dbg(fsp),
			access_mask,
			access_granted,
			nt_errstr(status));
		goto out;
	}

	if (!(access_mask & (SEC_DIR_ADD_FILE | SEC_DIR_ADD_SUBDIR))) {
		status = NT_STATUS_OK;
		goto out;
	}
	if (!lp_check_parent_directory_delete_on_close(SNUM(fsp->conn))) {
		status = NT_STATUS_OK;
		goto out;
	}

	/* Check if the directory has delete-on-close set */
	status = file_name_hash(fsp->conn,
				fsp->fsp_name->base_name,
				&name_hash);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	/*
	 * Don't take a lock here. We just need a snapshot
	 * of the current state of delete on close and this is
	 * called in a codepath where we may already have a lock
	 * (and we explicitly can't hold 2 locks at the same time
	 * as that may deadlock).
	 */
	lck = fetch_share_mode_unlocked(frame, fsp->file_id);
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

static NTSTATUS check_base_file_access(struct files_struct *fsp,
				uint32_t access_mask)
{
	NTSTATUS status;

	status = smbd_calculate_access_mask_fsp(fsp->conn->cwd_fsp,
					fsp,
					false,
					access_mask,
					&access_mask);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("smbd_calculate_access_mask "
			"on file %s returned %s\n",
			fsp_str_dbg(fsp),
			nt_errstr(status)));
		return status;
	}

	if (access_mask & (FILE_WRITE_DATA|FILE_APPEND_DATA)) {
		uint32_t dosattrs;
		if (!CAN_WRITE(fsp->conn)) {
			return NT_STATUS_ACCESS_DENIED;
		}
		dosattrs = fdos_mode(fsp);
		if (dosattrs & FILE_ATTRIBUTE_READONLY) {
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	return smbd_check_access_rights_fsp(fsp->conn->cwd_fsp,
					fsp,
					false,
					access_mask);
}

static NTSTATUS chdir_below_conn(
	TALLOC_CTX *mem_ctx,
	connection_struct *conn,
	const char *connectpath,
	size_t connectpath_len,
	struct smb_filename *dir_fname,
	struct smb_filename **_oldwd_fname)
{
	struct smb_filename *oldwd_fname = NULL;
	struct smb_filename *smb_fname_dot = NULL;
	struct smb_filename *real_fname = NULL;
	const char *relative = NULL;
	NTSTATUS status;
	int ret;
	bool ok;

	if (!ISDOT(dir_fname->base_name)) {

		oldwd_fname = vfs_GetWd(talloc_tos(), conn);
		if (oldwd_fname == NULL) {
			status = map_nt_error_from_unix(errno);
			goto out;
		}

		/* Pin parent directory in place. */
		ret = vfs_ChDir(conn, dir_fname);
		if (ret == -1) {
			status = map_nt_error_from_unix(errno);
			DBG_DEBUG("chdir to %s failed: %s\n",
				  dir_fname->base_name,
				  strerror(errno));
			goto out;
		}
	}

	smb_fname_dot = synthetic_smb_fname(
		talloc_tos(),
		".",
		NULL,
		NULL,
		dir_fname->twrp,
		dir_fname->flags);
	if (smb_fname_dot == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	real_fname = SMB_VFS_REALPATH(conn, talloc_tos(), smb_fname_dot);
	if (real_fname == NULL) {
		status = map_nt_error_from_unix(errno);
		DBG_DEBUG("realpath in %s failed: %s\n",
			  dir_fname->base_name,
			  strerror(errno));
		goto out;
	}
	TALLOC_FREE(smb_fname_dot);

	ok = subdir_of(connectpath,
		       connectpath_len,
		       real_fname->base_name,
		       &relative);
	if (ok) {
		TALLOC_FREE(real_fname);
		*_oldwd_fname = oldwd_fname;
		return NT_STATUS_OK;
	}

	DBG_NOTICE("Bad access attempt: %s is a symlink "
		   "outside the share path\n"
		   "conn_rootdir =%s\n"
		   "resolved_name=%s\n",
		   dir_fname->base_name,
		   connectpath,
		   real_fname->base_name);
	TALLOC_FREE(real_fname);

	status = NT_STATUS_OBJECT_NAME_NOT_FOUND;

out:
	if (oldwd_fname != NULL) {
		ret = vfs_ChDir(conn, oldwd_fname);
		SMB_ASSERT(ret == 0);
		TALLOC_FREE(oldwd_fname);
	}

	return status;
}

/*
 * Get the symlink target of dirfsp/symlink_name, making sure the
 * target is below connection_path.
 */

static NTSTATUS symlink_target_below_conn(
	TALLOC_CTX *mem_ctx,
	const char *connection_path,
	struct files_struct *fsp,
	struct files_struct *dirfsp,
	struct smb_filename *symlink_name,
	char **_target)
{
	char *target = NULL;
	char *absolute = NULL;
	NTSTATUS status;

	if (fsp_get_pathref_fd(fsp) != -1) {
		/*
		 * fsp is an O_PATH open, Linux does a "freadlink"
		 * with an empty name argument to readlinkat
		 */
		status = readlink_talloc(talloc_tos(), fsp, NULL, &target);
	} else {
		status = readlink_talloc(
			talloc_tos(), dirfsp, symlink_name, &target);
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = safe_symlink_target_path(talloc_tos(),
					  connection_path,
					  dirfsp->fsp_name->base_name,
					  target,
					  0,
					  &absolute);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("safe_symlink_target_path() failed: %s\n",
			  nt_errstr(status));
		return status;
	}

	if (absolute[0] == '\0') {
		/*
		 * special case symlink to share root: "." is our
		 * share root filename
		 */
		TALLOC_FREE(absolute);
		absolute = talloc_strdup(talloc_tos(), ".");
		if (absolute == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	*_target = absolute;
	return NT_STATUS_OK;
}

/****************************************************************************
 Non-widelink open.
****************************************************************************/

static NTSTATUS non_widelink_open(const struct files_struct *dirfsp,
			     files_struct *fsp,
			     struct smb_filename *smb_fname,
			     const struct vfs_open_how *_how)
{
	struct connection_struct *conn = fsp->conn;
	const char *connpath = SMB_VFS_CONNECTPATH(conn, dirfsp, smb_fname);
	size_t connpath_len;
	NTSTATUS status = NT_STATUS_OK;
	int fd = -1;
	char *orig_smb_fname_base = smb_fname->base_name;
	struct smb_filename *orig_fsp_name = fsp->fsp_name;
	struct smb_filename *smb_fname_rel = NULL;
	struct smb_filename *oldwd_fname = NULL;
	struct smb_filename *parent_dir_fname = NULL;
	struct vfs_open_how how = *_how;
	char *target = NULL;
	size_t link_depth = 0;
	int ret;

	SMB_ASSERT(!fsp_is_alternate_stream(fsp));

	if (connpath == NULL) {
		/*
		 * This can happen with shadow_copy2 if the snapshot
		 * path is not found
		 */
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	connpath_len = strlen(connpath);

again:
	if (smb_fname->base_name[0] == '/') {
		int cmp = strcmp(connpath, smb_fname->base_name);
		if (cmp == 0) {
			smb_fname->base_name = talloc_strdup(smb_fname, "");
			if (smb_fname->base_name == NULL) {
				status = NT_STATUS_NO_MEMORY;
				goto out;
			}
		}
	}

	if (dirfsp == conn->cwd_fsp) {

		status = SMB_VFS_PARENT_PATHNAME(fsp->conn,
						 talloc_tos(),
						 smb_fname,
						 &parent_dir_fname,
						 &smb_fname_rel);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		status = chdir_below_conn(
			talloc_tos(),
			conn,
			connpath,
			connpath_len,
			parent_dir_fname,
			&oldwd_fname);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		/* Setup fsp->fsp_name to be relative to cwd */
		fsp->fsp_name = smb_fname_rel;
	} else {
		/*
		 * fsp->fsp_name is unchanged as it is already correctly
		 * relative to conn->cwd.
		 */
		smb_fname_rel = smb_fname;
	}

	{
		/*
		 * Assert nobody can step in with a symlink on the
		 * path, there is no path anymore and we'll use
		 * O_NOFOLLOW to open.
		 */
		char *slash = strchr_m(smb_fname_rel->base_name, '/');
		SMB_ASSERT(slash == NULL);
	}

	how.flags |= O_NOFOLLOW;

	fd = SMB_VFS_OPENAT(conn,
			    dirfsp,
			    smb_fname_rel,
			    fsp,
			    &how);
	fsp_set_fd(fsp, fd);	/* This preserves errno */

	if (fd == -1) {
		status = map_nt_error_from_unix(errno);

		if (errno == ENOENT) {
			goto out;
		}

		/*
		 * ENOENT makes it worthless retrying with a
		 * stat, we know for sure the file does not
		 * exist. For everything else we want to know
		 * what's there.
		 */
		ret = SMB_VFS_FSTATAT(
			fsp->conn,
			dirfsp,
			smb_fname_rel,
			&fsp->fsp_name->st,
			AT_SYMLINK_NOFOLLOW);

		if (ret == -1) {
			/*
			 * Keep the original error. Otherwise we would
			 * mask for example EROFS for open(O_CREAT),
			 * turning it into ENOENT.
			 */
			goto out;
		}
	} else {
		ret = SMB_VFS_FSTAT(fsp, &fsp->fsp_name->st);
	}

	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		DBG_DEBUG("fstat[at](%s) failed: %s\n",
			  smb_fname_str_dbg(smb_fname),
			  strerror(errno));
		goto out;
	}

	fsp->fsp_flags.is_directory = S_ISDIR(fsp->fsp_name->st.st_ex_mode);
	orig_fsp_name->st = fsp->fsp_name->st;

	if (!S_ISLNK(fsp->fsp_name->st.st_ex_mode)) {
		goto out;
	}

	/*
	 * Found a symlink to follow in user space
	 */

	if (fsp->fsp_name->flags & SMB_FILENAME_POSIX_PATH) {
		/* Never follow symlinks on posix open. */
		status = NT_STATUS_STOPPED_ON_SYMLINK;
		goto out;
	}
	if (!lp_follow_symlinks(SNUM(conn))) {
		/* Explicitly no symlinks. */
		status = NT_STATUS_STOPPED_ON_SYMLINK;
		goto out;
	}

	link_depth += 1;
	if (link_depth >= 40) {
		status = NT_STATUS_STOPPED_ON_SYMLINK;
		goto out;
	}

	fsp->fsp_name = orig_fsp_name;

	status = symlink_target_below_conn(
		talloc_tos(),
		connpath,
		fsp,
		discard_const_p(files_struct, dirfsp),
		smb_fname_rel,
		&target);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("symlink_target_below_conn() failed: %s\n",
			  nt_errstr(status));
		goto out;
	}

	/*
	 * Close what openat(O_PATH) potentially left behind
	 */
	fd_close(fsp);

	if (smb_fname->base_name != orig_smb_fname_base) {
		TALLOC_FREE(smb_fname->base_name);
	}
	smb_fname->base_name = target;

	if (oldwd_fname != NULL) {
		ret = vfs_ChDir(conn, oldwd_fname);
		if (ret == -1) {
			smb_panic("unable to get back to old directory\n");
		}
		TALLOC_FREE(oldwd_fname);
	}

	/*
	 * And do it all again... As smb_fname is not relative to the passed in
	 * dirfsp anymore, we pass conn->cwd_fsp as dirfsp to
	 * non_widelink_open() to trigger the chdir(parentdir) logic.
	 */
	dirfsp = conn->cwd_fsp;

	goto again;

  out:
	fsp->fsp_name = orig_fsp_name;
	smb_fname->base_name = orig_smb_fname_base;

	TALLOC_FREE(parent_dir_fname);

	if (!NT_STATUS_IS_OK(status)) {
		fd_close(fsp);
	}

	if (oldwd_fname != NULL) {
		ret = vfs_ChDir(conn, oldwd_fname);
		if (ret == -1) {
			smb_panic("unable to get back to old directory\n");
		}
		TALLOC_FREE(oldwd_fname);
	}
	return status;
}

/****************************************************************************
 fd support routines - attempt to do a dos_open.
****************************************************************************/

NTSTATUS fd_openat(const struct files_struct *dirfsp,
		   struct smb_filename *smb_fname,
		   files_struct *fsp,
		   const struct vfs_open_how *_how)
{
	struct vfs_open_how how = *_how;
	struct connection_struct *conn = fsp->conn;
	NTSTATUS status = NT_STATUS_OK;
	bool fsp_is_stream = fsp_is_alternate_stream(fsp);
	bool smb_fname_is_stream = is_named_stream(smb_fname);

	SMB_ASSERT(fsp_is_stream == smb_fname_is_stream);

	/*
	 * Never follow symlinks on a POSIX client. The
	 * client should be doing this.
	 */

	if ((fsp->posix_flags & FSP_POSIX_FLAGS_OPEN) || !lp_follow_symlinks(SNUM(conn))) {
		how.flags |= O_NOFOLLOW;
	}

	if (fsp_is_stream) {
		int fd;

		fd = SMB_VFS_OPENAT(
			conn,
			NULL,	/* stream open is relative to fsp->base_fsp */
			smb_fname,
			fsp,
			&how);
		if (fd == -1) {
			status = map_nt_error_from_unix(errno);
		}
		fsp_set_fd(fsp, fd);

		if (fd != -1) {
			status = vfs_stat_fsp(fsp);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_DEBUG("vfs_stat_fsp failed: %s\n",
					  nt_errstr(status));
				fd_close(fsp);
			}
		}

		return status;
	}

	/*
	 * Only follow symlinks within a share
	 * definition.
	 */
	status = non_widelink_open(dirfsp, fsp, smb_fname, &how);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_TOO_MANY_OPENED_FILES)) {
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
			  smb_fname_str_dbg(smb_fname),
			  how.flags,
			  (int)how.mode,
			  fsp_get_pathref_fd(fsp),
			  nt_errstr(status));
		return status;
	}

	DBG_DEBUG("name %s, flags = 0%o mode = 0%o, fd = %d\n",
		  smb_fname_str_dbg(smb_fname),
		  how.flags,
		  (int)how.mode,
		  fsp_get_pathref_fd(fsp));

	return status;
}

/****************************************************************************
 Close the file associated with a fsp.
****************************************************************************/

NTSTATUS fd_close(files_struct *fsp)
{
	NTSTATUS stat_status = NT_STATUS_OK;
	int ret;

	if (fsp == fsp->conn->cwd_fsp) {
		return NT_STATUS_OK;
	}

	if (fsp->fsp_flags.fstat_before_close) {
		/*
		 * capture status, if failure
		 * continue close processing
		 * and return status
		 */
		stat_status = vfs_stat_fsp(fsp);
	}

	if (fsp->dptr) {
		dptr_CloseDir(fsp);
	}
	if (fsp_get_pathref_fd(fsp) == -1) {
		/*
		 * Either a directory where the dptr_CloseDir() already closed
		 * the fd or a stat open.
		 */
		return NT_STATUS_OK;
	}
	if (fh_get_refcount(fsp->fh) > 1) {
		return NT_STATUS_OK; /* Shared handle. Only close last reference. */
	}

	ret = SMB_VFS_CLOSE(fsp);
	fsp_set_fd(fsp, -1);
	if (ret == -1) {
		return map_nt_error_from_unix(errno);
	}
	return stat_status;
}

/****************************************************************************
 Change the ownership of a file to that of the parent directory.
 Do this by fd if possible.
****************************************************************************/

static void change_file_owner_to_parent_fsp(struct files_struct *parent_fsp,
					    struct files_struct *fsp)
{
	int ret;

	if (parent_fsp->fsp_name->st.st_ex_uid == fsp->fsp_name->st.st_ex_uid) {
		/* Already this uid - no need to change. */
		DBG_DEBUG("file %s is already owned by uid %u\n",
			fsp_str_dbg(fsp),
			(unsigned int)fsp->fsp_name->st.st_ex_uid);
                return;
	}

	become_root();
	ret = SMB_VFS_FCHOWN(fsp,
			     parent_fsp->fsp_name->st.st_ex_uid,
			     (gid_t)-1);
	unbecome_root();
	if (ret == -1) {
		DBG_ERR("failed to fchown "
			"file %s to parent directory uid %u. Error "
			"was %s\n",
			fsp_str_dbg(fsp),
			(unsigned int)parent_fsp->fsp_name->st.st_ex_uid,
			strerror(errno));
	} else {
		DBG_DEBUG("changed new file %s to "
			  "parent directory uid %u.\n",
			  fsp_str_dbg(fsp),
			  (unsigned int)parent_fsp->fsp_name->st.st_ex_uid);
		/* Ensure the uid entry is updated. */
		fsp->fsp_name->st.st_ex_uid =
			parent_fsp->fsp_name->st.st_ex_uid;
	}
}

static NTSTATUS change_dir_owner_to_parent_fsp(struct files_struct *parent_fsp,
					       struct files_struct *fsp)
{
	NTSTATUS status;
	int ret;

	if (parent_fsp->fsp_name->st.st_ex_uid == fsp->fsp_name->st.st_ex_uid) {
		/* Already this uid - no need to change. */
		DBG_DEBUG("directory %s is already owned by uid %u\n",
			fsp_str_dbg(fsp),
			(unsigned int)fsp->fsp_name->st.st_ex_uid);
		return NT_STATUS_OK;
	}

	become_root();
	ret = SMB_VFS_FCHOWN(fsp,
			     parent_fsp->fsp_name->st.st_ex_uid,
			     (gid_t)-1);
	unbecome_root();
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		DBG_ERR("failed to chown "
			  "directory %s to parent directory uid %u. "
			  "Error was %s\n",
			  fsp_str_dbg(fsp),
			  (unsigned int)parent_fsp->fsp_name->st.st_ex_uid,
			  nt_errstr(status));
		return status;
	}

	DBG_DEBUG("changed ownership of new "
		  "directory %s to parent directory uid %u.\n",
		  fsp_str_dbg(fsp),
		  (unsigned int)parent_fsp->fsp_name->st.st_ex_uid);

	/* Ensure the uid entry is updated. */
	fsp->fsp_name->st.st_ex_uid = parent_fsp->fsp_name->st.st_ex_uid;

	return NT_STATUS_OK;
}

/****************************************************************************
 Open a file - returning a guaranteed ATOMIC indication of if the
 file was created or not.
****************************************************************************/

static NTSTATUS fd_open_atomic(struct files_struct *dirfsp,
			       struct smb_filename *smb_fname,
			       files_struct *fsp,
			       const struct vfs_open_how *_how,
			       bool *file_created)
{
	struct vfs_open_how how = *_how;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	NTSTATUS retry_status;
	bool file_existed = VALID_STAT(smb_fname->st);

	if (!(how.flags & O_CREAT)) {
		/*
		 * We're not creating the file, just pass through.
		 */
		status = fd_openat(dirfsp, smb_fname, fsp, &how);
		*file_created = false;
		return status;
	}

	if (how.flags & O_EXCL) {
		/*
		 * Fail if already exists, just pass through.
		 */
		status = fd_openat(dirfsp, smb_fname, fsp, &how);

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
		how.flags = _how->flags & ~(O_CREAT);
		retry_status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	} else {
		how.flags = _how->flags | O_EXCL;
		retry_status = NT_STATUS_OBJECT_NAME_COLLISION;
	}

	status = fd_openat(dirfsp, smb_fname, fsp, &how);
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
			how.flags = _how->flags & ~(O_CREAT);
		} else {
			how.flags = _how->flags | O_EXCL;
		}

		status = fd_openat(dirfsp, smb_fname, fsp, &how);
	}

	*file_created = (NT_STATUS_IS_OK(status) && !file_existed);
	return status;
}

static NTSTATUS reopen_from_fsp(struct files_struct *dirfsp,
				struct smb_filename *smb_fname,
				struct files_struct *fsp,
				const struct vfs_open_how *how,
				bool *p_file_created)
{
	NTSTATUS status;
	int old_fd;

	if (fsp->fsp_flags.have_proc_fds &&
	    ((old_fd = fsp_get_pathref_fd(fsp)) != -1)) {

		struct sys_proc_fd_path_buf buf;
		struct smb_filename proc_fname = (struct smb_filename){
			.base_name = sys_proc_fd_path(old_fd, &buf),
		};
		mode_t mode = fsp->fsp_name->st.st_ex_mode;
		int new_fd;

		SMB_ASSERT(fsp->fsp_flags.is_pathref);

		if (S_ISLNK(mode)) {
			return NT_STATUS_STOPPED_ON_SYMLINK;
		}
		if (!(S_ISREG(mode) || S_ISDIR(mode))) {
			return NT_STATUS_IO_REPARSE_TAG_NOT_HANDLED;
		}

		fsp->fsp_flags.is_pathref = false;

		new_fd = SMB_VFS_OPENAT(fsp->conn,
					fsp->conn->cwd_fsp,
					&proc_fname,
					fsp,
					how);
		if (new_fd == -1) {
			status = map_nt_error_from_unix(errno);
			fd_close(fsp);
			return status;
		}

		status = fd_close(fsp);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		fsp_set_fd(fsp, new_fd);
		return NT_STATUS_OK;
	}

	/*
	 * Close the existing pathref fd and set the fsp flag
	 * is_pathref to false so we get a "normal" fd this time.
	 */
	status = fd_close(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	fsp->fsp_flags.is_pathref = false;

	status = fd_open_atomic(dirfsp, smb_fname, fsp, how, p_file_created);
	return status;
}

/****************************************************************************
 Open a file.
****************************************************************************/

static NTSTATUS open_file(
	struct smb_request *req,
	struct files_struct *dirfsp,
	struct smb_filename *smb_fname_atname,
	files_struct *fsp,
	const struct vfs_open_how *_how,
	uint32_t access_mask,	   /* client requested access mask. */
	uint32_t open_access_mask, /* what we're actually using in the open. */
	uint32_t private_flags,
	bool *p_file_created)
{
	connection_struct *conn = fsp->conn;
	struct smb_filename *smb_fname = fsp->fsp_name;
	struct vfs_open_how how = *_how;
	NTSTATUS status = NT_STATUS_OK;
	bool file_existed = VALID_STAT(fsp->fsp_name->st);
	const uint32_t need_fd_mask =
		FILE_READ_DATA |
		FILE_WRITE_DATA |
		FILE_APPEND_DATA |
		FILE_EXECUTE |
		SEC_FLAG_SYSTEM_SECURITY;
	bool creating = !file_existed && (how.flags & O_CREAT);
	bool open_fd = false;
	bool posix_open = (fsp->posix_flags & FSP_POSIX_FLAGS_OPEN);

	/*
	 * Catch early an attempt to open an existing
	 * directory as a file.
	 */
	if (file_existed && S_ISDIR(fsp->fsp_name->st.st_ex_mode)) {
		return NT_STATUS_FILE_IS_A_DIRECTORY;
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

	if (((how.flags & O_ACCMODE) == O_RDONLY) && (how.flags & O_TRUNC)) {
		DBG_DEBUG("truncate requested on read-only open for file %s\n",
			  smb_fname_str_dbg(smb_fname));
		how.flags = (how.flags & ~O_ACCMODE) | O_RDWR;
	}

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
		if ((how.flags & O_ACCMODE) != O_RDONLY ||
		    (how.flags & O_TRUNC) || (how.flags & O_APPEND)) {
			DEBUG(3,("Permission denied opening %s\n",
				 smb_fname_str_dbg(smb_fname)));
			return NT_STATUS_ACCESS_DENIED;
		}
		/*
		 * We don't want to write - but we must make sure that
		 * O_CREAT doesn't create the file if we have write
		 * access into the directory.
		 */
		how.flags &= ~(O_CREAT | O_EXCL);
	}

	if ((open_access_mask & need_fd_mask) || creating ||
	    (how.flags & O_TRUNC)) {
		open_fd = true;
	}

	if (open_fd) {
		int ret;

#if defined(O_NONBLOCK) && defined(S_ISFIFO)
		/*
		 * We would block on opening a FIFO with no one else on the
		 * other end. Do what we used to do and add O_NONBLOCK to the
		 * open flags. JRA.
		 */

		if (file_existed && S_ISFIFO(smb_fname->st.st_ex_mode)) {
			how.flags |= O_NONBLOCK;
		}
#endif

		if (!posix_open) {
			const char *wild = smb_fname->base_name;
			/*
			 * Don't open files with Microsoft wildcard characters.
			 */
			if (fsp_is_alternate_stream(fsp)) {
				/*
				 * wildcard characters are allowed in stream
				 * names only test the basefilename
				 */
				wild = fsp->base_fsp->fsp_name->base_name;
			}

			if (ms_has_wild(wild)) {
				return NT_STATUS_OBJECT_NAME_INVALID;
			}
		}

		/* Can we access this file ? */
		if (!fsp_is_alternate_stream(fsp)) {
			/* Only do this check on non-stream open. */
			if (file_existed) {
				status = smbd_check_access_rights_fsp(
						dirfsp,
						fsp,
						false,
						open_access_mask);

				if (!NT_STATUS_IS_OK(status)) {
					DBG_DEBUG("smbd_check_access_rights_fsp"
						  " on file %s returned %s\n",
						  fsp_str_dbg(fsp),
						  nt_errstr(status));
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
				if (!(how.flags & O_CREAT)) {
					/* File didn't exist and no O_CREAT. */
					return NT_STATUS_OBJECT_NAME_NOT_FOUND;
				}

				status = check_parent_access_fsp(
							dirfsp,
							SEC_DIR_ADD_FILE);
				if (!NT_STATUS_IS_OK(status)) {
					DBG_DEBUG("check_parent_access_fsp on "
						  "directory %s for file %s "
						  "returned %s\n",
						  smb_fname_str_dbg(
							  dirfsp->fsp_name),
						  smb_fname_str_dbg(smb_fname),
						  nt_errstr(status));
					return status;
				}
			}
		}

		/*
		 * Actually do the open - if O_TRUNC is needed handle it
		 * below under the share mode lock.
		 */
		how.flags &= ~O_TRUNC;
		status = reopen_from_fsp(dirfsp,
					 smb_fname_atname,
					 fsp,
					 &how,
					 p_file_created);
		if (NT_STATUS_EQUAL(status, NT_STATUS_STOPPED_ON_SYMLINK)) {
			/*
			 * Non-O_PATH reopen that hit a race
			 * condition: Someone has put a symlink where
			 * we used to have a file. Can't happen with
			 * O_PATH and reopening from /proc/self/fd/ or
			 * equivalent.
			 */
			status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		if (!NT_STATUS_IS_OK(status)) {
			DBG_NOTICE("Error opening file %s (%s) (in_flags=%d) "
				   "(flags=%d)\n",
				   smb_fname_str_dbg(smb_fname),
				   nt_errstr(status),
				   _how->flags,
				   how.flags);
			return status;
		}

		if (how.flags & O_NONBLOCK) {
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

		if (*p_file_created) {
			/* We created this file. */

			bool need_re_stat = false;
			/* Do all inheritance work after we've
			   done a successful fstat call and filled
			   in the stat struct in fsp->fsp_name. */

			/* Inherit the ACL if required */
			if (lp_inherit_permissions(SNUM(conn))) {
				inherit_access_posix_acl(conn,
							 dirfsp,
							 smb_fname,
							 how.mode);
				need_re_stat = true;
			}

			/* Change the owner if required. */
			if (lp_inherit_owner(SNUM(conn)) != INHERIT_OWNER_NO) {
				change_file_owner_to_parent_fsp(dirfsp, fsp);
				need_re_stat = true;
			}

			if (need_re_stat) {
				status = vfs_stat_fsp(fsp);
				/*
				 * If we have an fd, this stat should succeed.
				 */
				if (!NT_STATUS_IS_OK(status)) {
					DBG_ERR("Error doing fstat on open "
						"file %s (%s)\n",
						 smb_fname_str_dbg(smb_fname),
						 nt_errstr(status));
					fd_close(fsp);
					return status;
				}
			}

			notify_fname(conn, NOTIFY_ACTION_ADDED,
				     FILE_NOTIFY_CHANGE_FILE_NAME,
				     smb_fname->base_name);
		}
	} else {
		if (!file_existed) {
			/* File must exist for a stat open. */
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

		if (S_ISLNK(smb_fname->st.st_ex_mode) &&
		    !posix_open)
		{
			/*
			 * Don't allow stat opens on symlinks directly unless
			 * it's a POSIX open. Match the return code from
			 * openat_pathref_fsp().
			 */
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

		if (!fsp->fsp_flags.is_pathref) {
			/*
			 * There is only one legit case where end up here:
			 * openat_pathref_fsp() failed to open a symlink, so the
			 * fsp was created by fsp_new() which doesn't set
			 * is_pathref. Other than that, we should always have a
			 * pathref fsp at this point. The subsequent checks
			 * assert this.
			 */
			if (!(smb_fname->flags & SMB_FILENAME_POSIX_PATH)) {
				DBG_ERR("[%s] is not a POSIX pathname\n",
					smb_fname_str_dbg(smb_fname));
				return NT_STATUS_INTERNAL_ERROR;
			}
			if (!S_ISLNK(smb_fname->st.st_ex_mode)) {
				DBG_ERR("[%s] is not a symlink\n",
					smb_fname_str_dbg(smb_fname));
				return NT_STATUS_INTERNAL_ERROR;
			}
			if (fsp_get_pathref_fd(fsp) != -1) {
				DBG_ERR("fd for [%s] is not -1: fd [%d]\n",
					smb_fname_str_dbg(smb_fname),
					fsp_get_pathref_fd(fsp));
				return NT_STATUS_INTERNAL_ERROR;
			}
		}

		/*
		 * Access to streams is checked by checking the basefile and
		 * that has already been checked by check_base_file_access()
		 * in create_file_unixpath().
		 */
		if (!fsp_is_alternate_stream(fsp)) {
			status = smbd_check_access_rights_fsp(dirfsp,
							      fsp,
							      false,
							      open_access_mask);

			if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND) &&
			    posix_open &&
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
				DBG_DEBUG("smbd_check_access_rights_fsp on file "
					  "%s returned %s\n",
					  fsp_str_dbg(fsp),
					  nt_errstr(status));
				return status;
			}
		}
	}

	fsp->file_id = vfs_file_id_from_sbuf(conn, &smb_fname->st);
	fsp->vuid = req ? req->vuid : UID_FIELD_INVALID;
	fsp->file_pid = req ? req->smbpid : 0;
	fsp->fsp_flags.can_lock = true;
	fsp->fsp_flags.can_read = ((access_mask & FILE_READ_DATA) != 0);
	fsp->fsp_flags.can_write =
		CAN_WRITE(conn) &&
		((access_mask & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0);
	if (fsp->fsp_name->twrp != 0) {
		fsp->fsp_flags.can_write = false;
	}
	fsp->print_file = NULL;
	fsp->fsp_flags.modified = false;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->fsp_flags.is_directory = false;
	if (is_in_path(smb_fname->base_name,
		       conn->aio_write_behind_list,
		       posix_open ? true : conn->case_sensitive)) {
		fsp->fsp_flags.aio_write_behind = true;
	}

	DEBUG(2,("%s opened file %s read=%s write=%s (numopen=%d)\n",
		 conn->session_info->unix_info->unix_name,
		 smb_fname_str_dbg(smb_fname),
		 BOOLSTR(fsp->fsp_flags.can_read),
		 BOOLSTR(fsp->fsp_flags.can_write),
		 conn->num_files_open));

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

static void share_mode_flags_restrict(
	struct share_mode_lock *lck,
	uint32_t access_mask,
	uint32_t share_mode,
	uint32_t lease_type)
{
	uint32_t existing_access_mask, existing_share_mode;
	uint32_t existing_lease_type;

	share_mode_flags_get(
		lck,
		&existing_access_mask,
		&existing_share_mode,
		&existing_lease_type);

	existing_access_mask |= access_mask;
	if (access_mask & conflicting_access) {
		existing_share_mode &= share_mode;
	}
	existing_lease_type |= lease_type;

	share_mode_flags_set(
		lck,
		existing_access_mask,
		existing_share_mode,
		existing_lease_type,
		NULL);
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
				struct file_id fid,
				struct share_mode_lock *lck,
				uint32_t access_mask,
				uint32_t share_access)
{
	struct open_mode_check_state state;
	bool ok, conflict;
	bool modified = false;

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
			.fid = fid,
			.self = messaging_server_id(conn->sconn->msg_ctx),
		};
		ok = share_mode_forall_entries(
			lck, validate_my_share_entries_fn, &validate_state);
		SMB_ASSERT(ok);
	}
#endif

	share_mode_flags_get(
		lck, &state.access_mask, &state.share_access, NULL);

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
		.fid = fid,
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

	share_mode_flags_set(
		lck,
		state.access_mask,
		state.share_access,
		state.lease_type,
		&modified);
	if (!modified) {
		/*
		 * We only end up here if we had a sharing violation
		 * from d->flags and have recalculated it.
		 */
		return NT_STATUS_SHARING_VIOLATION;
	}

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
	static bool skip_validation;
	bool validate;
	bool ok;

	if (skip_validation) {
		return true;
	}

	validate = lp_parm_bool(-1, "smbd", "validate_oplock_types", false);
	if (!validate) {
		DBG_DEBUG("smbd:validate_oplock_types not set to yes\n");
		skip_validation = true;
		return true;
	}

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

	for (fsp = file_find_di_first(new_fsp->conn->sconn, new_fsp->file_id, true);
	     fsp != NULL;
	     fsp = file_find_di_next(fsp, true)) {

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

	/*
	 * We used to set lck->data->modified=true here without
	 * actually modifying lck->data, triggering a needless
	 * writeback of lck->data.
	 *
	 * Apart from that writeback, setting modified=true has the
	 * effect of triggering all waiters for this file to
	 * retry. This only makes sense if any blocking condition
	 * (i.e. waiting for a lease to be downgraded or removed) is
	 * gone. This routine here only adds a lease, so it will never
	 * free up resources that blocked waiters can now claim. So
	 * that second effect also does not matter in this
	 * routine. Thus setting lck->data->modified=true does not
	 * need to be done here.
	 */

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

struct blocker_debug_state {
	size_t num_blockers;
};

struct delay_for_oplock_state {
	struct files_struct *fsp;
	const struct smb2_lease *lease;
	bool will_overwrite;
	uint32_t delay_mask;
	bool first_open_attempt;
	bool got_handle_lease;
	bool got_oplock;
	bool disallow_write_lease;
	uint32_t total_lease_types;
	bool delay;
	struct blocker_debug_state *blocker_debug_state;
};

static int blocker_debug_state_destructor(struct blocker_debug_state *state)
{
	if (state->num_blockers == 0) {
		return 0;
	}

	DBG_DEBUG("blocker_debug_state [%p] num_blockers [%zu]\n",
		  state, state->num_blockers);
	return 0;
}

static void delay_for_oplock_fn_watch_done(struct tevent_req *subreq);

static bool delay_for_oplock_fn(
	struct share_mode_entry *e,
	bool *modified,
	void *private_data)
{
	struct delay_for_oplock_state *state = private_data;
	struct files_struct *fsp = state->fsp;
	const struct smb2_lease *lease = state->lease;
	bool e_is_lease = (e->op_type == LEASE_OPLOCK);
	uint32_t e_lease_type = SMB2_LEASE_NONE;
	uint32_t break_to;
	bool lease_is_breaking = false;
	struct tevent_req *subreq = NULL;
	struct server_id_buf idbuf = {};

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
			&e_lease_type, /* current_state */
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
	} else {
		e_lease_type = get_lease_type(e, fsp->file_id);
	}

	if (((e_lease_type & ~state->total_lease_types) != 0) &&
	    !share_entry_stale_pid(e))
	{
		state->total_lease_types |= e_lease_type;
	}

	if (!state->got_handle_lease &&
	    ((e_lease_type & SMB2_LEASE_HANDLE) != 0) &&
	    !share_entry_stale_pid(e)) {
		state->got_handle_lease = true;
	}

	if (!state->got_oplock &&
	    (e->op_type != NO_OPLOCK) &&
	    (e->op_type != LEASE_OPLOCK) &&
	    !share_entry_stale_pid(e)) {
		state->got_oplock = true;
	}

	/*
	 * Two things prevent a write lease
	 * to be granted:
	 *
	 * 1. Any oplock or lease (even broken to NONE)
	 * 2. An open with an access mask other than
	 *    FILE_READ_ATTRIBUTES, FILE_WRITE_ATTRIBUTES
	 *    or SYNCHRONIZE_ACCESS
	 */
	if (!state->disallow_write_lease &&
	    (e->op_type != NO_OPLOCK || !is_oplock_stat_open(e->access_mask)) &&
	    !is_same_lease(fsp, e, lease) &&
	    !share_entry_stale_pid(e))
	{
		state->disallow_write_lease = true;
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

	if (!state->delay) {
		return false;
	}

	if (state->blocker_debug_state == NULL) {
		return false;
	}

	subreq = server_id_watch_send(state->blocker_debug_state,
				      fsp->conn->sconn->ev_ctx,
				      e->pid);
	if (subreq == NULL) {
		DBG_ERR("server_id_watch_send(%s) returned NULL\n",
			server_id_str_buf(e->pid, &idbuf));
		return false;
	}

	tevent_req_set_callback(subreq,
				delay_for_oplock_fn_watch_done,
				state->blocker_debug_state);

	state->blocker_debug_state->num_blockers++;

	DBG_DEBUG("Starting to watch pid [%s] state [%p] num_blockers [%zu]\n",
		  server_id_str_buf(e->pid, &idbuf),
		  state->blocker_debug_state,
		  state->blocker_debug_state->num_blockers);

	return false;
};

static void delay_for_oplock_fn_watch_done(struct tevent_req *subreq)
{
	struct blocker_debug_state *blocker_debug_state = tevent_req_callback_data(
		subreq, struct blocker_debug_state);
	struct server_id pid = {};
	struct server_id_buf idbuf = {};
	int ret;

	ret = server_id_watch_recv(subreq, &pid);
	if (ret != 0) {
		DBG_ERR("server_id_watch_recv failed %s\n", strerror(ret));
		return;
	}

	DBG_DEBUG("state [%p] server_id_watch_recv() returned pid [%s] exited\n",
		  blocker_debug_state,
		  server_id_str_buf(pid, &idbuf));
}

static NTSTATUS delay_for_oplock(files_struct *fsp,
				 int oplock_request,
				 const struct smb2_lease *lease,
				 struct share_mode_lock *lck,
				 bool have_sharing_violation,
				 uint32_t create_disposition,
				 bool first_open_attempt,
				 int *poplock_type,
				 uint32_t *pgranted,
				 struct blocker_debug_state **blocker_debug_state)
{
	struct delay_for_oplock_state state = {
		.fsp = fsp,
		.lease = lease,
		.first_open_attempt = first_open_attempt,
	};
	uint32_t requested;
	uint32_t granted;
	int oplock_type;
	bool ok;

	*poplock_type = NO_OPLOCK;
	*pgranted = 0;

	if (fsp->fsp_flags.is_directory) {
		/*
		 * No directory leases yet
		 */
		SMB_ASSERT(oplock_request == NO_OPLOCK);
		if (have_sharing_violation) {
			return NT_STATUS_SHARING_VIOLATION;
		}
		return NT_STATUS_OK;
	}

	if (oplock_request == LEASE_OPLOCK) {
		if (lease == NULL) {
			/*
			 * The SMB2 layer should have checked this
			 */
			return NT_STATUS_INTERNAL_ERROR;
		}

		requested = lease->lease_state;
	} else {
		requested = map_oplock_to_lease_type(
			oplock_request & ~SAMBA_PRIVATE_OPLOCK_MASK);
	}

	share_mode_flags_get(lck, NULL, NULL, &state.total_lease_types);

	if (is_oplock_stat_open(fsp->access_mask)) {
		goto grant;
	}

	if (lp_parm_bool(GLOBAL_SECTION_SNUM,
			 "smbd lease break",
			 "debug hung procs",
			 false))
	{
		state.blocker_debug_state = talloc_zero(fsp,
						struct blocker_debug_state);
		if (state.blocker_debug_state == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		talloc_steal(talloc_tos(), state.blocker_debug_state);

		talloc_set_destructor(state.blocker_debug_state,
				      blocker_debug_state_destructor);
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

	state.total_lease_types = SMB2_LEASE_NONE;
	ok = share_mode_forall_entries(lck, delay_for_oplock_fn, &state);
	if (!ok) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (state.delay) {
		*blocker_debug_state = state.blocker_debug_state;
		return NT_STATUS_RETRY;
	}

grant:
	if (have_sharing_violation) {
		return NT_STATUS_SHARING_VIOLATION;
	}

	granted = requested;

	if (oplock_request == LEASE_OPLOCK) {
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
	}

	if (lp_locking(fsp->conn->params) && file_has_brlocks(fsp)) {
		DBG_DEBUG("file %s has byte range locks\n",
			  fsp_str_dbg(fsp));
		granted &= ~SMB2_LEASE_READ;
	}

	if (state.disallow_write_lease) {
		/*
		 * Can grant only a write lease
		 * if there are no other leases
		 * and no other non-stat opens.
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

		oplock_type = LEASE_OPLOCK;
	} else {
		if (state.got_handle_lease) {
			granted = SMB2_LEASE_NONE;
		}

		/*
		 * Reflect possible downgrades from:
		 * - map_lease_type_to_oplock() => "RH" to just LEVEL_II
		 */
		oplock_type = map_lease_type_to_oplock(granted);
		granted = map_oplock_to_lease_type(oplock_type);
	}

	state.total_lease_types |= granted;

	{
		uint32_t acc, sh, ls;
		share_mode_flags_get(lck, &acc, &sh, &ls);
		ls = state.total_lease_types;
		share_mode_flags_set(lck, acc, sh, ls, NULL);
	}

	DBG_DEBUG("oplock type 0x%x granted (%s%s%s)(0x%x), on file %s, "
		  "requested 0x%x (%s%s%s)(0x%x) => total (%s%s%s)(0x%x)\n",
		  fsp->oplock_type,
		  granted & SMB2_LEASE_READ ? "R":"",
		  granted & SMB2_LEASE_WRITE ? "W":"",
		  granted & SMB2_LEASE_HANDLE ? "H":"",
		  granted,
		  fsp_str_dbg(fsp),
		  oplock_request,
		  requested & SMB2_LEASE_READ ? "R":"",
		  requested & SMB2_LEASE_WRITE ? "W":"",
		  requested & SMB2_LEASE_HANDLE ? "H":"",
		  requested,
		  state.total_lease_types & SMB2_LEASE_READ ? "R":"",
		  state.total_lease_types & SMB2_LEASE_WRITE ? "W":"",
		  state.total_lease_types & SMB2_LEASE_HANDLE ? "H":"",
		  state.total_lease_types);

	*poplock_type = oplock_type;
	*pgranted = granted;
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
	bool first_open_attempt,
	int *poplock_type,
	uint32_t *pgranted,
	struct blocker_debug_state **blocker_debug_state)
{
	bool sharing_violation = false;
	NTSTATUS status;

	*poplock_type = NO_OPLOCK;
	*pgranted = 0;

	status = open_mode_check(
		fsp->conn, fsp->file_id, lck, access_mask, share_access);
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
		return NT_STATUS_OK;
	}

	status = delay_for_oplock(
		fsp,
		oplock_request,
		lease,
		lck,
		sharing_violation,
		create_disposition,
		first_open_attempt,
		poplock_type,
		pgranted,
		blocker_debug_state);
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
		       struct file_id id,
		       struct blocker_debug_state **blocker_debug_state)
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

	DBG_DEBUG("deferring mid %" PRIu64 "\n", req->mid);

	watch_req = share_mode_watch_send(
		watch_state,
		req->sconn->ev_ctx,
		lck,
		(struct server_id){0});
	if (watch_req == NULL) {
		exit_server("Could not watch share mode record");
	}
	tevent_req_set_callback(watch_req, defer_open_done, watch_state);

	talloc_move(watch_req, blocker_debug_state);

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
		DBG_ERR("share_mode_watch_recv() returned %s, "
			"rescheduling mid %" PRIu64 "\n",
			nt_errstr(status), state->mid);
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

struct poll_open_setup_watcher_state {
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev_ctx;
	struct tevent_req *watch_req;
};

static void poll_open_setup_watcher_fn(struct share_mode_lock *lck,
					     void *private_data)
{
	struct poll_open_setup_watcher_state *state =
		(struct poll_open_setup_watcher_state *)private_data;

	if (!validate_oplock_types(lck)) {
		smb_panic("validate_oplock_types failed");
	}

	state->watch_req = share_mode_watch_send(
			state->mem_ctx,
			state->ev_ctx,
			lck,
			(struct server_id) {0});
	if (state->watch_req == NULL) {
		DBG_WARNING("share_mode_watch_send failed\n");
		return;
	}
}

/**
 * Reschedule an open for 1 second from now, if not timed out.
 **/
static bool setup_poll_open(
	struct smb_request *req,
	const struct file_id *id,
	struct timeval max_timeout,
	struct timeval interval)
{
	static struct file_id zero_id = {};
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

	if (id != NULL) {
		struct poll_open_setup_watcher_state wstate = {
			.mem_ctx = open_rec,
			.ev_ctx = req->sconn->ev_ctx,
		};
		NTSTATUS status;

		status = share_mode_do_locked_vfs_denied(*id,
						poll_open_setup_watcher_fn,
						&wstate);
		if (NT_STATUS_IS_OK(status)) {
			if (wstate.watch_req == NULL) {
				DBG_WARNING("share_mode_watch_send failed\n");
				TALLOC_FREE(open_rec);
				return false;
			}
			open_rec->watch_req = wstate.watch_req;
			tevent_req_set_callback(open_rec->watch_req,
						poll_open_done,
						open_rec);
		} else if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
			DBG_WARNING("share_mode_do_locked_vfs_denied failed - %s\n",
				    nt_errstr(status));
			TALLOC_FREE(open_rec);
			return false;
		}
	} else {
		id = &zero_id;
	}

	ok = push_deferred_open_message_smb(req, max_timeout, *id, open_rec);
	if (!ok) {
		DBG_WARNING("push_deferred_open_message_smb failed\n");
		TALLOC_FREE(open_rec);
		return false;
	}

	DBG_DEBUG("poll request time [%s] mid [%" PRIu64 "] file_id [%s]\n",
		  timeval_string(talloc_tos(), &req->request_time, false),
		  req->mid,
		  file_id_str_buf(*id, &ftmp));

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
				struct smb_request *req,
				struct blocker_debug_state **blocker_debug_state)
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

	defer_open(lck, timeout, req, id, blocker_debug_state);
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

static NTSTATUS check_and_store_share_mode(
	struct files_struct *fsp,
	struct smb_request *req,
	struct share_mode_lock *lck,
	uint32_t create_disposition,
	uint32_t access_mask,
	uint32_t share_access,
	int oplock_request,
	const struct smb2_lease *lease,
	bool first_open_attempt)
{
	NTSTATUS status;
	int oplock_type = NO_OPLOCK;
	uint32_t granted_lease = 0;
	const struct smb2_lease_key *lease_key = NULL;
	struct blocker_debug_state *blocker_debug_state = NULL;
	bool delete_on_close;
	bool ok;

	/* Get the types we need to examine. */
	if (!validate_oplock_types(lck)) {
		smb_panic("validate_oplock_types failed");
	}

	delete_on_close = has_delete_on_close(lck, fsp->name_hash);
	if (delete_on_close) {
		return NT_STATUS_DELETE_PENDING;
	}

	status = handle_share_mode_lease(fsp,
					 lck,
					 create_disposition,
					 access_mask,
					 share_access,
					 oplock_request,
					 lease,
					 first_open_attempt,
					 &oplock_type,
					 &granted_lease,
					 &blocker_debug_state);
	if (NT_STATUS_EQUAL(status, NT_STATUS_RETRY)) {
		schedule_defer_open(lck, fsp->file_id, req, &blocker_debug_state);
		return NT_STATUS_SHARING_VIOLATION;
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (oplock_type == LEASE_OPLOCK) {
		lease_key = &lease->lease_key;
	}

	share_mode_flags_restrict(lck, access_mask, share_access, 0);

	ok = set_share_mode(lck,
			    fsp,
			    get_current_uid(fsp->conn),
			    req ? req->mid : 0,
			    oplock_type,
			    lease_key,
			    share_access,
			    access_mask);
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	if (oplock_type == LEASE_OPLOCK) {
		status = grant_fsp_lease(fsp, lck, lease, granted_lease);
		if (!NT_STATUS_IS_OK(status)) {
			del_share_mode(lck, fsp);
			return status;
		}

		DBG_DEBUG("lease_state=%d\n", fsp->lease->lease.lease_state);
	}

	fsp->oplock_type = oplock_type;

	return NT_STATUS_OK;
}

/****************************************************************************
 Work out what access_mask to use from what the client sent us.
****************************************************************************/

static NTSTATUS smbd_calculate_maximum_allowed_access_fsp(
			struct files_struct *dirfsp,
			struct files_struct *fsp,
			bool use_privs,
			uint32_t *p_access_mask)
{
	struct security_descriptor *sd = NULL;
	uint32_t access_granted = 0;
	uint32_t dosattrs;
	NTSTATUS status;

	/* Cope with symlinks */
	if (fsp == NULL || fsp_get_pathref_fd(fsp) == -1) {
		*p_access_mask = FILE_GENERIC_ALL;
		return NT_STATUS_OK;
	}

	/* Cope with fake/printer fsp's. */
	if (fsp->fake_file_handle != NULL || fsp->print_file != NULL) {
		*p_access_mask = FILE_GENERIC_ALL;
		return NT_STATUS_OK;
	}

	if (!use_privs && (get_current_uid(fsp->conn) == (uid_t)0)) {
		*p_access_mask |= FILE_GENERIC_ALL;
		return NT_STATUS_OK;
	}

	status = SMB_VFS_FGET_NT_ACL(metadata_fsp(fsp),
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
		DBG_ERR("Could not get acl on file %s: %s\n",
			fsp_str_dbg(fsp),
			nt_errstr(status));
		return status;
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
				get_current_nttok(fsp->conn),
				use_privs,
				(*p_access_mask & ~FILE_READ_ATTRIBUTES),
				&access_granted);

	TALLOC_FREE(sd);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Status %s on file %s: "
			"when calculating maximum access\n",
			nt_errstr(status),
			fsp_str_dbg(fsp));
		return status;
	}

	*p_access_mask = (access_granted | FILE_READ_ATTRIBUTES);

	if (!(access_granted & DELETE_ACCESS)) {
		if (can_delete_file_in_directory(fsp->conn,
				dirfsp,
				fsp->fsp_name)) {
			*p_access_mask |= DELETE_ACCESS;
		}
	}

	dosattrs = fdos_mode(fsp);
	if ((dosattrs & FILE_ATTRIBUTE_READONLY) || !CAN_WRITE(fsp->conn)) {
		*p_access_mask &= ~(FILE_GENERIC_WRITE | DELETE_ACCESS);
	}

	return NT_STATUS_OK;
}

NTSTATUS smbd_calculate_access_mask_fsp(struct files_struct *dirfsp,
			struct files_struct *fsp,
			bool use_privs,
			uint32_t access_mask,
			uint32_t *access_mask_out)
{
	NTSTATUS status;
	uint32_t orig_access_mask = access_mask;
	uint32_t rejected_share_access;

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

		status = smbd_calculate_maximum_allowed_access_fsp(
						   dirfsp,
						   fsp,
						   use_privs,
						   &access_mask);

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		access_mask &= fsp->conn->share_access;
	}

	rejected_share_access = access_mask & ~(fsp->conn->share_access);

	if (rejected_share_access) {
		DBG_INFO("Access denied on file %s: "
			"rejected by share access mask[0x%08X] "
			"orig[0x%08X] mapped[0x%08X] reject[0x%08X]\n",
			fsp_str_dbg(fsp),
			fsp->conn->share_access,
			orig_access_mask, access_mask,
			rejected_share_access);
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
				       uint32_t private_flags,
				       NTTIME twrp)
{
	bool need_write, need_read;

	/*
	 * Note that we ignore the append flag as append does not
	 * mean the same thing under DOS and Unix.
	 */

	if (twrp != 0) {
		/*
		 * Pave over the user requested mode and force O_RDONLY for the
		 * file handle. Windows allows opening a VSS file with O_RDWR,
		 * even though actual writes on the handle will fail.
		 */
		return O_RDONLY;
	}

	need_write = (access_mask & (FILE_WRITE_DATA | FILE_APPEND_DATA));
	if (!need_write) {
		return O_RDONLY;
	}

	/* DENY_DOS opens are always underlying read-write on the
	   file handle, no matter what the requested access mask
	   says. */

	need_read =
		((private_flags & NTCREATEX_FLAG_DENY_DOS) ||
		 access_mask & (FILE_READ_ATTRIBUTES|FILE_READ_DATA|
				FILE_READ_EA|FILE_EXECUTE));

	if (!need_read) {
		return O_WRONLY;
	}
	return O_RDWR;
}

struct open_ntcreate_lock_state {
	struct share_mode_entry_prepare_state prepare_state;
	struct files_struct *fsp;
	const char *object_type;
	struct smb_request *req;
	uint32_t create_disposition;
	uint32_t access_mask;
	uint32_t share_access;
	int oplock_request;
	const struct smb2_lease *lease;
	bool first_open_attempt;
	bool keep_locked;
	NTSTATUS status;
	struct timespec write_time;
	share_mode_entry_prepare_unlock_fn_t cleanup_fn;
};

static void open_ntcreate_lock_add_entry(struct share_mode_lock *lck,
					 bool *keep_locked,
					 void *private_data)
{
	struct open_ntcreate_lock_state *state =
		(struct open_ntcreate_lock_state *)private_data;

	/*
	 * By default drop the g_lock again if we leave the
	 * tdb chainlock.
	 */
	*keep_locked = false;

	state->status = check_and_store_share_mode(state->fsp,
						   state->req,
						   lck,
						   state->create_disposition,
						   state->access_mask,
						   state->share_access,
						   state->oplock_request,
						   state->lease,
						   state->first_open_attempt);
	if (!NT_STATUS_IS_OK(state->status)) {
		return;
	}

	state->write_time = get_share_mode_write_time(lck);

	/*
	 * keep the g_lock while existing the tdb chainlock,
	 * we we're asked to, which mean we'll keep
	 * the share_mode_lock during object creation,
	 * or setting delete on close.
	 */
	*keep_locked = state->keep_locked;
}

static void open_ntcreate_lock_cleanup_oplock(struct share_mode_lock *lck,
					      void *private_data)
{
	struct open_ntcreate_lock_state *state =
		(struct open_ntcreate_lock_state *)private_data;
	bool ok;

	ok = remove_share_oplock(lck, state->fsp);
	if (!ok) {
		DBG_ERR("Could not remove oplock for %s %s\n",
			state->object_type, fsp_str_dbg(state->fsp));
	}
}

static void open_ntcreate_lock_cleanup_entry(struct share_mode_lock *lck,
					     void *private_data)
{
	struct open_ntcreate_lock_state *state =
		(struct open_ntcreate_lock_state *)private_data;
	bool ok;

	ok = del_share_mode(lck, state->fsp);
	if (!ok) {
		DBG_ERR("Could not delete share entry for %s %s\n",
			state->object_type, fsp_str_dbg(state->fsp));
	}
}

static void possibly_set_archive(struct connection_struct *conn,
				 struct files_struct *fsp,
				 struct smb_filename *smb_fname,
				 struct smb_filename *parent_dir_fname,
				 int info,
				 uint32_t dosattrs,
				 mode_t *unx_mode)
{
	bool set_archive = false;
	int ret;

	if (info == FILE_WAS_OPENED) {
		return;
	}

	/* Overwritten files should be initially set as archive */
	if ((info == FILE_WAS_OVERWRITTEN && lp_map_archive(SNUM(conn)))) {
		set_archive = true;
	} else if (lp_store_dos_attributes(SNUM(conn))) {
		set_archive = true;
	}
	if (!set_archive) {
		return;
	}

	ret = file_set_dosmode(conn,
			       smb_fname,
			       dosattrs | FILE_ATTRIBUTE_ARCHIVE,
			       parent_dir_fname,
			       true);
	if (ret != 0) {
		return;
	}
	*unx_mode = smb_fname->st.st_ex_mode;
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
			    struct smb_filename *parent_dir_fname, /* parent. */
			    struct smb_filename *smb_fname_atname, /* atname relative to parent. */
			    int *pinfo,
			    files_struct *fsp)
{
	struct smb_filename *smb_fname = fsp->fsp_name;
	int flags=0;
	bool file_existed = VALID_STAT(smb_fname->st);
	bool def_acl = False;
	bool posix_open = False;
	bool new_file_created = False;
	bool first_open_attempt = true;
	bool is_twrp = (smb_fname_atname->twrp != 0);
	NTSTATUS fsp_open = NT_STATUS_ACCESS_DENIED;
	mode_t new_unx_mode = (mode_t)0;
	mode_t unx_mode = (mode_t)0;
	int info;
	uint32_t existing_dos_attributes = 0;
	struct open_ntcreate_lock_state lck_state = {};
	bool keep_locked = false;
	uint32_t open_access_mask = access_mask;
	NTSTATUS status;
	SMB_STRUCT_STAT saved_stat = smb_fname->st;
	struct timespec old_write_time;
	bool setup_poll = false;
	NTSTATUS ulstatus;

	if (conn->printer) {
		/*
		 * Printers are handled completely differently.
		 * Most of the passed parameters are ignored.
		 */

		if (pinfo) {
			*pinfo = FILE_WAS_CREATED;
		}

		DBG_DEBUG("printer open fname=%s\n",
			  smb_fname_str_dbg(smb_fname));

		if (!req) {
			DBG_ERR("printer open without an SMB request!\n");
			return NT_STATUS_INTERNAL_ERROR;
		}

		return print_spool_open(fsp, smb_fname->base_name,
					req->vuid);
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
		unx_mode = unix_mode(
			conn,
			new_dos_attributes | FILE_ATTRIBUTE_ARCHIVE,
			smb_fname,
			parent_dir_fname->fsp);
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

			status = SMB_VFS_FGET_DOS_ATTRIBUTES(
				conn,
				metadata_fsp(smb_fname->fsp),
				&attr);
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
				return NT_STATUS_OBJECT_NAME_NOT_FOUND;
			}
			if (is_twrp) {
				return NT_STATUS_MEDIA_WRITE_PROTECTED;
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
					return NT_STATUS_FILE_IS_A_DIRECTORY;
				}
				return NT_STATUS_OBJECT_NAME_COLLISION;
			}
			if (is_twrp) {
				return NT_STATUS_MEDIA_WRITE_PROTECTED;
			}
			break;

		case FILE_SUPERSEDE:
		case FILE_OVERWRITE_IF:
			if (is_twrp) {
				return NT_STATUS_MEDIA_WRITE_PROTECTED;
			}
			break;
		case FILE_OPEN_IF:
			if (is_twrp) {
				if (!file_existed) {
					return NT_STATUS_MEDIA_WRITE_PROTECTED;
				}
				create_disposition = FILE_OPEN;
			}
			break;
		default:
			return NT_STATUS_INVALID_PARAMETER;
	}

	flags = disposition_to_open_flags(create_disposition);

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
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	status = smbd_calculate_access_mask_fsp(parent_dir_fname->fsp,
						smb_fname->fsp,
						false,
						access_mask,
						&access_mask);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("smbd_calculate_access_mask_fsp "
			"on file %s returned %s\n",
			smb_fname_str_dbg(smb_fname),
			nt_errstr(status));
		return status;
	}

	open_access_mask = access_mask;

	if (flags & O_TRUNC) {
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

	flags |= calculate_open_access_flags(access_mask,
					     private_flags,
					     smb_fname->twrp);

	/*
	 * Currently we only look at FILE_WRITE_THROUGH for create options.
	 */

#if defined(O_SYNC)
	if ((create_options & FILE_WRITE_THROUGH) && lp_strict_sync(SNUM(conn))) {
		flags |= O_SYNC;
	}
#endif /* O_SYNC */

	if (posix_open && (access_mask & FILE_APPEND_DATA)) {
		flags |= O_APPEND;
	}

	if (!posix_open && !CAN_WRITE(conn)) {
		/*
		 * We should really return a permission denied error if either
		 * O_CREAT or O_TRUNC are set, but for compatibility with
		 * older versions of Samba we just AND them out.
		 */
		flags &= ~(O_CREAT | O_TRUNC);
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
	flags |= O_NONBLOCK;

	/*
	 * Ensure we can't write on a read-only share or file.
	 */

	if (((flags & O_ACCMODE) != O_RDONLY) && file_existed &&
	    (!CAN_WRITE(conn) ||
	     (existing_dos_attributes & FILE_ATTRIBUTE_READONLY))) {
		DEBUG(5,("open_file_ntcreate: write access requested for "
			 "file %s on read only %s\n",
			 smb_fname_str_dbg(smb_fname),
			 !CAN_WRITE(conn) ? "share" : "file" ));
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
	fh_set_private_options(fsp->fh, private_flags);
	fsp->access_mask = open_access_mask; /* We change this to the
					      * requested access_mask after
					      * the open is done. */
	if (posix_open) {
		fsp->posix_flags |= FSP_POSIX_FLAGS_ALL;
	}

	if ((create_options & FILE_DELETE_ON_CLOSE) && (flags & O_CREAT) &&
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

	if ((flags & O_CREAT) && lp_inherit_acls(SNUM(conn)) &&
	    (def_acl = directory_has_default_acl_fsp(parent_dir_fname->fsp))) {
		unx_mode = (0777 & lp_create_mask(SNUM(conn)));
	}

	DEBUG(4,
	      ("calling open_file with flags=0x%X mode=0%o, "
	       "access_mask = 0x%x, open_access_mask = 0x%x\n",
	       (unsigned int)flags,
	       (unsigned int)unx_mode,
	       (unsigned int)access_mask,
	       (unsigned int)open_access_mask));

	{
		struct vfs_open_how how = {
			.flags = flags,
			.mode = unx_mode,
		};

		if (create_options & FILE_OPEN_FOR_BACKUP_INTENT) {
			how.resolve |= VFS_OPEN_HOW_WITH_BACKUP_INTENT;
		}

		fsp_open = open_file(req,
				     parent_dir_fname->fsp,
				     smb_fname_atname,
				     fsp,
				     &how,
				     access_mask,
				     open_access_mask,
				     private_flags,
				     &new_file_created);
	}
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
		 * Retry once a second. If there's a share_mode_lock
		 * around, also wait for it in case it was smbd
		 * holding that kernel oplock that can quickly tell us
		 * the oplock got removed.
		 */

		setup_poll_open(
			req,
			&fsp->file_id,
			timeval_set(OPLOCK_BREAK_TIMEOUT*2, 0),
			timeval_set(1, 0));

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

	if (new_file_created) {
		info = FILE_WAS_CREATED;
	} else {
		if (flags & O_TRUNC) {
			info = FILE_WAS_OVERWRITTEN;
		} else {
			info = FILE_WAS_OPENED;
		}
	}

	/*
	 * If we created a new file, overwrite an existing one
	 * or going to delete it later, we should keep
	 * the share_mode_lock (g_lock) until we call
	 * share_mode_entry_prepare_unlock()
	 */
	if (info != FILE_WAS_OPENED) {
		keep_locked = true;
	} else if (create_options & FILE_DELETE_ON_CLOSE) {
		keep_locked = true;
	}

	lck_state = (struct open_ntcreate_lock_state) {
		.fsp			= fsp,
		.object_type		= "file",
		.req			= req,
		.create_disposition	= create_disposition,
		.access_mask		= access_mask,
		.share_access		= share_access,
		.oplock_request		= oplock_request,
		.lease			= lease,
		.first_open_attempt	= first_open_attempt,
		.keep_locked		= keep_locked,
	};

	status = share_mode_entry_prepare_lock_add(&lck_state.prepare_state,
						   fsp->file_id,
						   conn->connectpath,
						   smb_fname,
						   &old_write_time,
						   open_ntcreate_lock_add_entry,
						   &lck_state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_entry_prepare_lock_add() failed for %s - %s\n",
			smb_fname_str_dbg(smb_fname), nt_errstr(status));
		fd_close(fsp);
		return status;
	}

	status = lck_state.status;
	if (!NT_STATUS_IS_OK(status)) {
		fd_close(fsp);
		return status;
	}

	/*
	 * From here we need to use 'goto unlock;' instead of return !!!
	 */

	if (fsp->oplock_type != NO_OPLOCK && fsp->oplock_type != LEASE_OPLOCK) {
		/*
		 * Now ask for kernel oplocks
		 * and cleanup on failure.
		 */
		status = set_file_oplock(fsp);
		if (!NT_STATUS_IS_OK(status)) {
			/*
			 * Could not get the kernel oplock
			 */
			lck_state.cleanup_fn =
				open_ntcreate_lock_cleanup_oplock;
			fsp->oplock_type = NO_OPLOCK;
		}
	}

	/* Should we atomically (to the client at least) truncate ? */
	if ((!new_file_created) && (flags & O_TRUNC) &&
	    (S_ISREG(fsp->fsp_name->st.st_ex_mode))) {
		int ret;

		ret = SMB_VFS_FTRUNCATE(fsp, 0);
		if (ret != 0) {
			status = map_nt_error_from_unix(errno);
			lck_state.cleanup_fn =
				open_ntcreate_lock_cleanup_entry;
			goto unlock;
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
	if (!new_file_created &&
	    clear_ads(create_disposition) &&
	    !fsp_is_alternate_stream(fsp)) {
		status = delete_all_streams(conn, smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			lck_state.cleanup_fn =
				open_ntcreate_lock_cleanup_entry;
			goto unlock;
		}
	}

	if (!fsp->fsp_flags.is_pathref &&
	    fsp_get_io_fd(fsp) != -1 &&
	    lp_kernel_share_modes(SNUM(conn)))
	{
		int ret;
		/*
		 * Beware: streams implementing VFS modules may
		 * implement streams in a way that fsp will have the
		 * basefile open in the fsp fd, so lacking a distinct
		 * fd for the stream the file-system sharemode will
		 * apply on the basefile which is wrong. The actual
		 * check is deferred to the VFS module implementing
		 * the file-system sharemode call.
		 */
		ret = SMB_VFS_FILESYSTEM_SHAREMODE(fsp,
						   share_access,
						   access_mask);
		if (ret == -1){
			status = NT_STATUS_SHARING_VIOLATION;
			lck_state.cleanup_fn =
				open_ntcreate_lock_cleanup_entry;
			goto unlock;
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
				lck_state.cleanup_fn =
					open_ntcreate_lock_cleanup_entry;
				goto unlock;
			}
		}
		/* Note that here we set the *initial* delete on close flag,
		   not the regular one. The magic gets handled in close. */
		fsp->fsp_flags.initial_delete_on_close = true;
	}

	possibly_set_archive(conn,
			     fsp,
			     smb_fname,
			     parent_dir_fname,
			     info,
			     new_dos_attributes,
			     &smb_fname->st.st_ex_mode);

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

	/*
	 * Deal with other opens having a modified write time.
	 */
	if (fsp_getinfo_ask_sharemode(fsp) &&
	    !is_omit_timespec(&lck_state.write_time))
	{
		update_stat_ex_mtime(&fsp->fsp_name->st, lck_state.write_time);
	}

	status = NT_STATUS_OK;

unlock:
	ulstatus = share_mode_entry_prepare_unlock(&lck_state.prepare_state,
						   lck_state.cleanup_fn,
						   &lck_state);
	if (!NT_STATUS_IS_OK(ulstatus)) {
		DBG_ERR("share_mode_entry_prepare_unlock() failed for %s - %s\n",
			smb_fname_str_dbg(smb_fname), nt_errstr(ulstatus));
		smb_panic("share_mode_entry_prepare_unlock() failed!");
	}

	if (!NT_STATUS_IS_OK(status)) {
		fd_close(fsp);
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS mkdir_internal(connection_struct *conn,
			       struct smb_filename *parent_dir_fname, /* parent. */
			       struct smb_filename *smb_fname_atname, /* atname relative to parent. */
			       struct smb_filename *smb_dname, /* full pathname from root of share. */
			       uint32_t file_attributes,
			       struct files_struct *fsp)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	mode_t mode;
	NTSTATUS status;
	bool posix_open = false;
	bool need_re_stat = false;
	uint32_t access_mask = SEC_DIR_ADD_SUBDIR;
	struct vfs_open_how how = { .flags = O_RDONLY|O_DIRECTORY, };
	int ret;

	if (!CAN_WRITE(conn) || (access_mask & ~(conn->share_access))) {
		DEBUG(5,("mkdir_internal: failing share access "
			 "%s\n", lp_servicename(talloc_tos(), lp_sub, SNUM(conn))));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (file_attributes & FILE_FLAG_POSIX_SEMANTICS) {
		posix_open = true;
		mode = (mode_t)(file_attributes & ~FILE_FLAG_POSIX_SEMANTICS);
	} else {
		mode = unix_mode(conn,
				 FILE_ATTRIBUTE_DIRECTORY,
				 smb_dname,
				 parent_dir_fname->fsp);
	}

	status = check_parent_access_fsp(parent_dir_fname->fsp, access_mask);
	if(!NT_STATUS_IS_OK(status)) {
		DBG_INFO("check_parent_access_fsp "
			"on directory %s for path %s returned %s\n",
			smb_fname_str_dbg(parent_dir_fname),
			smb_dname->base_name,
			nt_errstr(status));
		return status;
	}

	if (lp_inherit_acls(SNUM(conn))) {
		if (directory_has_default_acl_fsp(parent_dir_fname->fsp)) {
			mode = (0777 & lp_directory_mask(SNUM(conn)));
		}
	}

	ret = SMB_VFS_MKDIRAT(conn,
			      parent_dir_fname->fsp,
			      smb_fname_atname,
			      mode);
	if (ret != 0) {
		return map_nt_error_from_unix(errno);
	}

	/*
	 * Make this a pathref fsp for now. open_directory() will reopen as a
	 * full fsp.
	 */
	fsp->fsp_flags.is_pathref = true;

	status = fd_openat(parent_dir_fname->fsp, smb_fname_atname, fsp, &how);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Ensure we're checking for a symlink here.... */
	/* We don't want to get caught by a symlink racer. */

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("Could not stat directory '%s' just created: %s\n",
			  smb_fname_str_dbg(smb_dname), nt_errstr(status)));
		return status;
	}

	if (!S_ISDIR(smb_dname->st.st_ex_mode)) {
		DEBUG(0, ("Directory '%s' just created is not a directory !\n",
			  smb_fname_str_dbg(smb_dname)));
		return NT_STATUS_NOT_A_DIRECTORY;
	}

	if (lp_store_dos_attributes(SNUM(conn))) {
		file_set_dosmode(conn,
				 smb_dname,
				 file_attributes | FILE_ATTRIBUTE_DIRECTORY,
				 parent_dir_fname,
				 true);
	}

	if (lp_inherit_permissions(SNUM(conn))) {
		inherit_access_posix_acl(conn, parent_dir_fname->fsp,
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
			SMB_VFS_FCHMOD(fsp,
				      (smb_dname->st.st_ex_mode |
					  (mode & ~smb_dname->st.st_ex_mode)));
			need_re_stat = true;
		}
	}

	/* Change the owner if required. */
	if (lp_inherit_owner(SNUM(conn)) != INHERIT_OWNER_NO) {
		change_dir_owner_to_parent_fsp(parent_dir_fname->fsp,
					       fsp);
		need_re_stat = true;
	}

	if (need_re_stat) {
		status = vfs_stat_fsp(fsp);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(2, ("Could not stat directory '%s' just created: %s\n",
			  smb_fname_str_dbg(smb_dname), nt_errstr(status)));
			return status;
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
			       uint32_t access_mask,
			       uint32_t share_access,
			       uint32_t create_disposition,
			       uint32_t create_options,
			       uint32_t file_attributes,
			       struct smb_filename *parent_dir_fname,
			       struct smb_filename *smb_fname_atname,
			       int *pinfo,
			       struct files_struct *fsp)
{
	struct smb_filename *smb_dname = fsp->fsp_name;
	bool dir_existed = VALID_STAT(smb_dname->st);
	struct open_ntcreate_lock_state lck_state = {};
	bool keep_locked = false;
	NTSTATUS status;
	struct timespec mtimespec;
	int info = 0;
	uint32_t need_fd_access;
	NTSTATUS ulstatus;

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

	status = smbd_calculate_access_mask_fsp(parent_dir_fname->fsp,
					smb_dname->fsp,
					false,
					access_mask,
					&access_mask);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("smbd_calculate_access_mask_fsp "
			"on file %s returned %s\n",
			smb_fname_str_dbg(smb_dname),
			nt_errstr(status));
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

			if (smb_fname_atname->twrp != 0) {
				return NT_STATUS_MEDIA_WRITE_PROTECTED;
			}

			status = mkdir_internal(conn,
						parent_dir_fname,
						smb_fname_atname,
						smb_dname,
						file_attributes,
						fsp);

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
				if (smb_fname_atname->twrp != 0) {
					return NT_STATUS_MEDIA_WRITE_PROTECTED;
				}
				status = mkdir_internal(conn,
							parent_dir_fname,
							smb_fname_atname,
							smb_dname,
							file_attributes,
							fsp);

				if (NT_STATUS_IS_OK(status)) {
					info = FILE_WAS_CREATED;
				} else {
					int ret;
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
					ret = SMB_VFS_FSTATAT(
						conn,
						parent_dir_fname->fsp,
						smb_fname_atname,
						&smb_dname->st,
						AT_SYMLINK_NOFOLLOW);
					if (ret == -1) {
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

	/*
	 * Setup the files_struct for it.
	 */

	fsp->file_id = vfs_file_id_from_sbuf(conn, &smb_dname->st);
	fsp->vuid = req ? req->vuid : UID_FIELD_INVALID;
	fsp->file_pid = req ? req->smbpid : 0;
	fsp->fsp_flags.can_lock = false;
	fsp->fsp_flags.can_read = false;
	fsp->fsp_flags.can_write = false;

	fh_set_private_options(fsp->fh, 0);
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

	/* Don't store old timestamps for directory
	   handles in the internal database. We don't
	   update them in there if new objects
	   are created in the directory. Currently
	   we only update timestamps on file writes.
	   See bug #9870.
	*/
	mtimespec = make_omit_timespec();

	/*
	 * Obviously for FILE_LIST_DIRECTORY we need to reopen to get an fd
	 * usable for reading a directory. SMB2_FLUSH may be called on
	 * directories opened with FILE_ADD_FILE and FILE_ADD_SUBDIRECTORY so
	 * for those we need to reopen as well.
	 */
	need_fd_access =
		FILE_LIST_DIRECTORY |
		FILE_ADD_FILE |
		FILE_ADD_SUBDIRECTORY;

	if (access_mask & need_fd_access) {
		struct vfs_open_how how = {
			.flags = O_RDONLY | O_DIRECTORY,
		};
		bool file_created;

		status = reopen_from_fsp(parent_dir_fname->fsp,
					 smb_fname_atname,
					 fsp,
					 &how,
					 &file_created);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_INFO("Could not open fd for [%s]: %s\n",
				 smb_fname_str_dbg(smb_dname),
				 nt_errstr(status));
			return status;
		}
	}

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		fd_close(fsp);
		return status;
	}

	if(!S_ISDIR(fsp->fsp_name->st.st_ex_mode)) {
		DEBUG(5,("open_directory: %s is not a directory !\n",
			 smb_fname_str_dbg(smb_dname)));
                fd_close(fsp);
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
		return NT_STATUS_ACCESS_DENIED;
	}

	if (info == FILE_WAS_OPENED) {
		status = smbd_check_access_rights_fsp(parent_dir_fname->fsp,
						fsp,
						false,
						access_mask);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("smbd_check_access_rights_fsp on "
				  "file %s failed with %s\n",
				  fsp_str_dbg(fsp),
				  nt_errstr(status));
			fd_close(fsp);
			return status;
		}
	}

	/*
	 * If we created a new directory or going to delete it later,
	 * we should keep * the share_mode_lock (g_lock) until we call
	 * share_mode_entry_prepare_unlock()
	 */
	if (info != FILE_WAS_OPENED) {
		keep_locked = true;
	} else if (create_options & FILE_DELETE_ON_CLOSE) {
		keep_locked = true;
	}

	lck_state = (struct open_ntcreate_lock_state) {
		.fsp			= fsp,
		.object_type		= "directory",
		.req			= req,
		.create_disposition	= create_disposition,
		.access_mask		= access_mask,
		.share_access		= share_access,
		.oplock_request		= NO_OPLOCK,
		.lease			= NULL,
		.first_open_attempt	= true,
		.keep_locked		= keep_locked,
	};

	status = share_mode_entry_prepare_lock_add(&lck_state.prepare_state,
						   fsp->file_id,
						   conn->connectpath,
						   smb_dname,
						   &mtimespec,
						   open_ntcreate_lock_add_entry,
						   &lck_state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_entry_prepare_lock_add() failed for %s - %s\n",
			smb_fname_str_dbg(smb_dname), nt_errstr(status));
		fd_close(fsp);
		return status;
	}

	status = lck_state.status;
	if (!NT_STATUS_IS_OK(status)) {
		fd_close(fsp);
		return status;
	}

	/*
	 * From here we need to use 'goto unlock;' instead of return !!!
	 */

	/* For directories the delete on close bit at open time seems
	   always to be honored on close... See test 19 in Samba4 BASE-DELETE. */
	if (create_options & FILE_DELETE_ON_CLOSE) {
		status = can_set_delete_on_close(fsp, 0);
		if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, NT_STATUS_DIRECTORY_NOT_EMPTY)) {
			lck_state.cleanup_fn =
				open_ntcreate_lock_cleanup_entry;
			goto unlock;
		}

		if (NT_STATUS_IS_OK(status)) {
			/* Note that here we set the *initial* delete on close flag,
			   not the regular one. The magic gets handled in close. */
			fsp->fsp_flags.initial_delete_on_close = true;
		}
	}

	/*
	 * Deal with other opens having a modified write time.
	 */
	if (!is_omit_timespec(&lck_state.write_time)) {
		update_stat_ex_mtime(&fsp->fsp_name->st, lck_state.write_time);
	}

	if (pinfo) {
		*pinfo = info;
	}

	status = NT_STATUS_OK;

unlock:
	ulstatus = share_mode_entry_prepare_unlock(&lck_state.prepare_state,
						   lck_state.cleanup_fn,
						   &lck_state);
	if (!NT_STATUS_IS_OK(ulstatus)) {
		DBG_ERR("share_mode_entry_prepare_unlock() failed for %s - %s\n",
			smb_fname_str_dbg(smb_dname), nt_errstr(ulstatus));
		smb_panic("share_mode_entry_prepare_unlock() failed!");
	}

	if (!NT_STATUS_IS_OK(status)) {
		fd_close(fsp);
		return status;
	}

	return NT_STATUS_OK;
}

NTSTATUS create_directory(connection_struct *conn,
			  struct smb_request *req,
			  struct files_struct *dirfsp,
			  struct smb_filename *smb_dname)
{
	NTSTATUS status;
	files_struct *fsp;

	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		dirfsp,					/* dirfsp */
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
		close_file_free(req, &fsp, NORMAL_CLOSE);
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
		SMB_STRUCT_STAT fsp_orig_sbuf;
		NTSTATUS status;
		DBG_DEBUG("renaming file %s from %s -> %s\n",
			  fsp_fnum_dbg(fsp),
			  fsp_str_dbg(fsp),
			  smb_fname_str_dbg(smb_fname));

		/*
		 * The incoming smb_fname here has an
		 * invalid stat struct from synthetic_smb_fname()
		 * above.
		 * Preserve the existing stat from the
		 * open fsp after fsp_set_smb_fname()
		 * overwrites with the invalid stat.
		 *
		 * (We could just copy this into
		 * smb_fname->st, but keep this code
		 * identical to the fix in rename_open_files()
		 * for clarity.
		 *
		 * We will do an fstat before returning
		 * any of this metadata to the client anyway.
		 */
		fsp_orig_sbuf = fsp->fsp_name->st;
		status = fsp_set_smb_fname(fsp, smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("fsp_set_smb_fname failed: %s\n",
				  nt_errstr(status));
		}
		fsp->fsp_name->st = fsp_orig_sbuf;
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
	const struct smb_filename *pathref = NULL;
	NTSTATUS status;

	if (smb_fname->fsp == NULL) {
		struct smb_filename *tmp = NULL;
		status = synthetic_pathref(frame,
					conn->cwd_fsp,
					smb_fname->base_name,
					NULL,
					NULL,
					smb_fname->twrp,
					smb_fname->flags,
					&tmp);
		if (!NT_STATUS_IS_OK(status)) {
			if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_IMPLEMENTED)
			    || NT_STATUS_EQUAL(status,
				       NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
				DBG_DEBUG("no streams around\n");
				TALLOC_FREE(frame);
				return NT_STATUS_OK;
			}
			DBG_DEBUG("synthetic_pathref failed: %s\n",
			   nt_errstr(status));
			goto fail;
		}
		pathref = tmp;
	} else {
		pathref = smb_fname;
	}
	status = vfs_fstreaminfo(pathref->fsp, talloc_tos(),
				&num_streams, &stream_info);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_IMPLEMENTED)
	    || NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		DEBUG(10, ("no streams around\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("vfs_fstreaminfo failed: %s\n",
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

		status = openat_pathref_fsp(conn->cwd_fsp, smb_fname_cp);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("Unable to open stream [%s]: %s\n",
				  smb_fname_str_dbg(smb_fname_cp),
				  nt_errstr(status));
			TALLOC_FREE(smb_fname_cp);
			break;
		}

		status = SMB_VFS_CREATE_FILE(
			 conn,			/* conn */
			 NULL,			/* req */
			 NULL,			/* dirfsp */
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
			 0,			/* private_flags */
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
		close_file_free(NULL, &streams[j], NORMAL_CLOSE);
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

static NTSTATUS inherit_new_acl(files_struct *dirfsp, files_struct *fsp)
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
	bool ok;

	status = SMB_VFS_FGET_NT_ACL(dirfsp,
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
		struct unixid ids = { .id = 0 };

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
		struct unixid ids = { .id = 0 };

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
	status = SMB_VFS_FSET_NT_ACL(metadata_fsp(fsp),
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
			/*
			 * The client asked for a lease on a
			 * file that doesn't match the file_id
			 * in the database.
			 *
			 * Maybe this is a dynamic share, i.e.
			 * a share where the servicepath is
			 * different for different users (e.g.
			 * the [HOMES] share.
			 *
			 * If the servicepath is different, but the requested
			 * file name + stream name is the same then this is
			 * a dynamic share, the client is using the same share
			 * name and doesn't know that the underlying servicepath
			 * is different. It was expecting a lease on the
			 * same file. Return NT_STATUS_OPLOCK_NOT_GRANTED
			 * to break leases
			 *
			 * Otherwise the client has messed up, or is
			 * testing our error codes, so return
			 * NT_STATUS_INVALID_PARAMETER.
			 */
			if (!strequal(f->servicepath, state->servicepath) &&
			    strequal(f->base_name, state->fname->base_name) &&
			    strequal(f->stream_name, state->fname->stream_name))
			{
				/*
				 * Name is the same but servicepath is
				 * different, dynamic share. Break leases.
				 */
				state->match_status =
					NT_STATUS_OPLOCK_NOT_GRANTED;
			} else {
				state->match_status =
					NT_STATUS_INVALID_PARAMETER;
			}
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
	uint32_t e_lease_type = SMB2_LEASE_NONE;
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
		&e_lease_type, /* current_state */
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
		return false;
	}

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

static void lease_match_fid_fn(struct share_mode_lock *lck,
			       void *private_data)
{
	bool ok;

	ok = share_mode_forall_leases(lck, lease_match_break_fn, private_data);
	if (!ok) {
		DBG_DEBUG("share_mode_forall_leases failed\n");
	}
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

		if (file_id_equal(&state.ids[i], &state.id)) {
			/* Don't need to break our own file. */
			continue;
		}

		break_state.id = state.ids[i];

		status = share_mode_do_locked_vfs_denied(break_state.id,
							 lease_match_fid_fn,
							 &break_state);
		if (!NT_STATUS_IS_OK(status)) {
			/* Race condition - file already closed. */
			continue;
		}

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
				     struct files_struct *dirfsp,
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
	bool free_fsp_on_error = false;
	NTSTATUS status;
	int ret;
	struct smb_filename *parent_dir_fname = NULL;
	struct smb_filename *smb_fname_atname = NULL;

	DBG_DEBUG("access_mask = 0x%"PRIx32" "
		  "file_attributes = 0x%"PRIx32" "
		  "share_access = 0x%"PRIx32" "
		  "create_disposition = 0x%"PRIx32" "
		  "create_options = 0x%"PRIx32" "
		  "oplock_request = 0x%"PRIx32" "
		  "private_flags = 0x%"PRIx32" "
		  "ea_list = %p, "
		  "sd = %p, "
		  "fname = %s\n",
		  access_mask,
		  file_attributes,
		  share_access,
		  create_disposition,
		  create_options,
		  oplock_request,
		  private_flags,
		  ea_list,
		  sd,
		  smb_fname_str_dbg(smb_fname));

	if (create_options & FILE_OPEN_BY_FILE_ID) {
		status = NT_STATUS_NOT_SUPPORTED;
		goto fail;
	}

	if (create_options & NTCREATEX_OPTIONS_INVALID_PARAM_MASK) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (!(create_options & FILE_OPEN_REPARSE_POINT) &&
	    (smb_fname->fsp != NULL) && /* new files don't have an fsp */
	    VALID_STAT(smb_fname->fsp->fsp_name->st))
	{
		mode_t type = (smb_fname->fsp->fsp_name->st.st_ex_mode &
			       S_IFMT);

		switch (type) {
		case S_IFREG:
			FALL_THROUGH;
		case S_IFDIR:
			break;
		case S_IFLNK:
			/*
			 * We should never get this far with a symlink
			 * "as such". Report as not existing.
			 */
			status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
			goto fail;
		default:
			status = NT_STATUS_IO_REPARSE_TAG_NOT_HANDLED;
			goto fail;
		}
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
	    && !is_named_stream(smb_fname)) {
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
	if ((create_options & FILE_DELETE_ON_CLOSE) &&
	    ((access_mask & DELETE_ACCESS) == 0)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if ((conn->fs_capabilities & FILE_NAMED_STREAMS)
	    && is_named_stream(smb_fname))
	{
		uint32_t base_create_disposition;
		struct smb_filename *smb_fname_base = NULL;
		uint32_t base_privflags;

		if (create_options & FILE_DIRECTORY_FILE) {
			DBG_DEBUG("Can't open a stream as directory\n");
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

		smb_fname_base = cp_smb_filename_nostream(
			talloc_tos(), smb_fname);

		if (smb_fname_base == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}

		/*
		 * We may be creating the basefile as part of creating the
		 * stream, so it's legal if the basefile doesn't exist at this
		 * point, the create_file_unixpath() below will create it. But
		 * if the basefile exists we want a handle so we can fstat() it.
		 */

		ret = vfs_stat(conn, smb_fname_base);
		if (ret == -1 && errno != ENOENT) {
			status = map_nt_error_from_unix(errno);
			TALLOC_FREE(smb_fname_base);
			goto fail;
		}
		if (ret == 0) {
			status = openat_pathref_fsp(conn->cwd_fsp,
						    smb_fname_base);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_ERR("open_smb_fname_fsp [%s] failed: %s\n",
					smb_fname_str_dbg(smb_fname_base),
					nt_errstr(status));
				TALLOC_FREE(smb_fname_base);
				goto fail;
			}

			/*
			 * https://bugzilla.samba.org/show_bug.cgi?id=10229
			 * We need to check if the requested access mask
			 * could be used to open the underlying file (if
			 * it existed), as we're passing in zero for the
			 * access mask to the base filename.
			 */
			status = check_base_file_access(smb_fname_base->fsp,
							access_mask);

			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(10, ("Permission check "
					"for base %s failed: "
					"%s\n", smb_fname->base_name,
					nt_errstr(status)));
				TALLOC_FREE(smb_fname_base);
				goto fail;
			}
		}

		base_privflags = NTCREATEX_FLAG_STREAM_BASEOPEN;

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
	}

	if (smb_fname->fsp != NULL) {

		fsp = smb_fname->fsp;

		/*
		 * We're about to use smb_fname->fsp for the fresh open.
		 *
		 * Every fsp passed in via smb_fname->fsp already
		 * holds a fsp->fsp_name. If it is already this
		 * fsp->fsp_name that we got passed in as our input
		 * argument smb_fname, these two are assumed to have
		 * the same lifetime: Every fsp hangs of "conn", and
		 * fsp->fsp_name is its talloc child.
		 */

		if (smb_fname != smb_fname->fsp->fsp_name) {
			/*
			 * "smb_fname" is temporary in this case, but
			 * the destructor of smb_fname would also tear
			 * down the fsp we're about to use. Unlink
			 * them from each other.
			 */
			smb_fname_fsp_unlink(smb_fname);

			/*
			 * "fsp" is ours now
			 */
			free_fsp_on_error = true;
		}

		status = fsp_bind_smb(fsp, req);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}

		if (fsp_is_alternate_stream(fsp)) {
			struct files_struct *tmp_base_fsp = fsp->base_fsp;

			fsp_set_base_fsp(fsp, NULL);

			fd_close(tmp_base_fsp);
			file_free(NULL, tmp_base_fsp);
		}
	} else {
		/*
		 * No fsp passed in that we can use, create one
		 */
		status = file_new(req, conn, &fsp);
		if(!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
		free_fsp_on_error = true;

		status = fsp_set_smb_fname(fsp, smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	SMB_ASSERT(fsp->fsp_name->fsp != NULL);
	SMB_ASSERT(fsp->fsp_name->fsp == fsp);

	if (base_fsp) {
		/*
		 * We're opening the stream element of a
		 * base_fsp we already opened. Set up the
		 * base_fsp pointer.
		 */
		fsp_set_base_fsp(fsp, base_fsp);
	}

	if (dirfsp != NULL) {
		status = SMB_VFS_PARENT_PATHNAME(
			conn,
			talloc_tos(),
			smb_fname,
			&parent_dir_fname,
			&smb_fname_atname);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	} else {
		/*
		 * Get a pathref on the parent. We can re-use this for
		 * multiple calls to check parent ACLs etc. to avoid
		 * pathname calls.
		 */
		status = parent_pathref(talloc_tos(),
					conn->cwd_fsp,
					smb_fname,
					&parent_dir_fname,
					&smb_fname_atname);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}

		dirfsp = parent_dir_fname->fsp;
		status = fsp_set_smb_fname(dirfsp, parent_dir_fname);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
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
					access_mask,
					share_access,
					create_disposition,
					create_options,
					file_attributes,
					dirfsp->fsp_name,
					smb_fname_atname,
					&info,
					fsp);
	} else {

		/*
		 * Ordinary file case.
		 */

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
					    dirfsp->fsp_name,
					    smb_fname_atname,
					    &info,
					    fsp);
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
						access_mask,
						share_access,
						create_disposition,
						create_options,
						file_attributes,
						dirfsp->fsp_name,
						smb_fname_atname,
						&info,
						fsp);
		}
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	fsp->fsp_flags.is_fsa = true;

	if ((ea_list != NULL) &&
	    ((info == FILE_WAS_CREATED) || (info == FILE_WAS_OVERWRITTEN))) {
		status = set_ea(conn, fsp, ea_list);
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

	if ((info == FILE_WAS_CREATED) &&
	    lp_nt_acl_support(SNUM(conn)) &&
	    !fsp_is_alternate_stream(fsp)) {
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
			status = inherit_new_acl(dirfsp, fsp);
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

	TALLOC_FREE(parent_dir_fname);

	return NT_STATUS_OK;

 fail:
	DEBUG(10, ("create_file_unixpath: %s\n", nt_errstr(status)));

	if (fsp != NULL) {
		/*
		 * The close_file below will close
		 * fsp->base_fsp.
		 */
		base_fsp = NULL;
		close_file_smb(req, fsp, ERROR_CLOSE);
		if (free_fsp_on_error) {
			file_free(req, fsp);
			fsp = NULL;
		}
	}
	if (base_fsp != NULL) {
		close_file_free(req, &base_fsp, ERROR_CLOSE);
	}

	TALLOC_FREE(parent_dir_fname);

	return status;
}

NTSTATUS create_file_default(connection_struct *conn,
			     struct smb_request *req,
			     struct files_struct *dirfsp,
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

	DBG_DEBUG("access_mask = 0x%" PRIu32
		  " file_attributes = 0x%" PRIu32
		  " share_access = 0x%" PRIu32
		  " create_disposition = 0x%" PRIu32
		  " create_options = 0x%" PRIu32
		  " oplock_request = 0x%" PRIu32
		  " private_flags = 0x%" PRIu32
		  " ea_list = %p, sd = %p, fname = %s\n",
		  access_mask,
		  file_attributes,
		  share_access,
		  create_disposition,
		  create_options,
		  oplock_request,
		  private_flags,
		  ea_list,
		  sd,
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
			 * w2k close this file directly after opening xp
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
			status = NT_STATUS_OBJECT_NAME_INVALID;
			goto fail;
		}
	}

	if (is_ntfs_default_stream_smb_fname(smb_fname)) {
		int ret;
		/* We have to handle this error here. */
		if (create_options & FILE_DIRECTORY_FILE) {
			status = NT_STATUS_NOT_A_DIRECTORY;
			goto fail;
		}
		ret = vfs_stat(conn, smb_fname);
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
				      dirfsp,
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
		close_file_free(req, &fsp, ERROR_CLOSE);
	}
	return status;
}
