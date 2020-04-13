/*
   Unix SMB/CIFS implementation.
   Check access to files based on security descriptors.
   Copyright (C) Jeremy Allison 2005-2006.
   Copyright (C) Michael Adam 2007.

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
#include "../libcli/security/security.h"
#include "../librpc/gen_ndr/ndr_security.h"
#include "smbd/smbd.h"

#undef  DBGC_CLASS
#define DBGC_CLASS DBGC_ACLS

/****************************************************************************
 Actually emulate the in-kernel access checking for delete access. We need
 this to successfully return ACCESS_DENIED on a file open for delete access.
****************************************************************************/

bool can_delete_file_in_directory(connection_struct *conn,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname)
{
	TALLOC_CTX *ctx = talloc_tos();
	struct smb_filename *smb_fname_parent = NULL;
	bool ret;

	SMB_ASSERT(dirfsp == conn->cwd_fsp);

	if (!CAN_WRITE(conn)) {
		return False;
	}

	if (!lp_acl_check_permissions(SNUM(conn))) {
		/* This option means don't check. */
		return true;
	}

	/* Get the parent directory permission mask and owners. */
	ret = parent_smb_fname(ctx, smb_fname, &smb_fname_parent, NULL);
	if (ret != true) {
		return false;
	}

	if(SMB_VFS_STAT(conn, smb_fname_parent) != 0) {
		ret = false;
		goto out;
	}

	/* fast paths first */

	if (!S_ISDIR(smb_fname_parent->st.st_ex_mode)) {
		ret = false;
		goto out;
	}
	if (get_current_uid(conn) == (uid_t)0) {
		/* I'm sorry sir, I didn't know you were root... */
		ret = true;
		goto out;
	}

#ifdef S_ISVTX
	/* sticky bit means delete only by owner of file or by root or
	 * by owner of directory. */
	if (smb_fname_parent->st.st_ex_mode & S_ISVTX) {
		if (!VALID_STAT(smb_fname->st)) {
			/* If the file doesn't already exist then
			 * yes we'll be able to delete it. */
			ret = true;
			goto out;
		}

		/*
		 * Patch from SATOH Fumiyasu <fumiyas@miraclelinux.com>
		 * for bug #3348. Don't assume owning sticky bit
		 * directory means write access allowed.
		 * Fail to delete if we're not the owner of the file,
		 * or the owner of the directory as we have no possible
		 * chance of deleting. Otherwise, go on and check the ACL.
		 */
		if ((get_current_uid(conn) !=
			smb_fname_parent->st.st_ex_uid) &&
		    (get_current_uid(conn) != smb_fname->st.st_ex_uid)) {
			DEBUG(10,("can_delete_file_in_directory: not "
				  "owner of file %s or directory %s",
				  smb_fname_str_dbg(smb_fname),
				  smb_fname_str_dbg(smb_fname_parent)));
			ret = false;
			goto out;
		}
	}
#endif

	/* now for ACL checks */

	/*
	 * There's two ways to get the permission to delete a file: First by
	 * having the DELETE bit on the file itself and second if that does
	 * not help, by the DELETE_CHILD bit on the containing directory.
	 *
	 * Here we only check the directory permissions, we will
	 * check the file DELETE permission separately.
	 */

	/*
	 * NB. When dirfsp != conn->cwd_fsp, we must
	 * change smb_fname_parent to be "." for the name here.
	 */
	ret = NT_STATUS_IS_OK(smbd_check_access_rights(conn,
				dirfsp,
				smb_fname_parent,
				false,
				FILE_DELETE_CHILD));
 out:
	TALLOC_FREE(smb_fname_parent);
	return ret;
}

/****************************************************************************
 Userspace check for write access.
****************************************************************************/

bool can_write_to_file(connection_struct *conn,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname)
{
	SMB_ASSERT(dirfsp == conn->cwd_fsp);
	return NT_STATUS_IS_OK(smbd_check_access_rights(conn,
				dirfsp,
				smb_fname,
				false,
				FILE_WRITE_DATA));
}

/****************************************************************************
 Check for an existing default Windows ACL on a directory.
****************************************************************************/

bool directory_has_default_acl(connection_struct *conn,
		struct files_struct *dirfsp,
		struct smb_filename *smb_fname)
{
	struct security_descriptor *secdesc = NULL;
	unsigned int i;
	NTSTATUS status;

	status = SMB_VFS_GET_NT_ACL_AT(conn,
				dirfsp,
				smb_fname,
				SECINFO_DACL,
				talloc_tos(),
				&secdesc);

	if (!NT_STATUS_IS_OK(status) ||
			secdesc == NULL ||
			secdesc->dacl == NULL) {
		TALLOC_FREE(secdesc);
		return false;
	}

	for (i = 0; i < secdesc->dacl->num_aces; i++) {
		struct security_ace *psa = &secdesc->dacl->aces[i];
		if (psa->flags & (SEC_ACE_FLAG_OBJECT_INHERIT|
				SEC_ACE_FLAG_CONTAINER_INHERIT)) {
			TALLOC_FREE(secdesc);
			return true;
		}
	}
	TALLOC_FREE(secdesc);
	return false;
}

/****************************************************************************
 Check if setting delete on close is allowed on this fsp.
****************************************************************************/

NTSTATUS can_set_delete_on_close(files_struct *fsp, uint32_t dosmode)
{
	/*
	 * Only allow delete on close for writable files.
	 */

	if ((dosmode & FILE_ATTRIBUTE_READONLY) &&
	    !lp_delete_readonly(SNUM(fsp->conn))) {
		DEBUG(10,("can_set_delete_on_close: file %s delete on close "
			  "flag set but file attribute is readonly.\n",
			  fsp_str_dbg(fsp)));
		return NT_STATUS_CANNOT_DELETE;
	}

	/*
	 * Only allow delete on close for writable shares.
	 */

	if (!CAN_WRITE(fsp->conn)) {
		DEBUG(10,("can_set_delete_on_close: file %s delete on "
			  "close flag set but write access denied on share.\n",
			  fsp_str_dbg(fsp)));
		return NT_STATUS_ACCESS_DENIED;
	}

	/*
	 * Only allow delete on close for files/directories opened with delete
	 * intent.
	 */

	if (!(fsp->access_mask & DELETE_ACCESS)) {
		DEBUG(10,("can_set_delete_on_close: file %s delete on "
			  "close flag set but delete access denied.\n",
			  fsp_str_dbg(fsp)));
		return NT_STATUS_ACCESS_DENIED;
	}

	/* Don't allow delete on close for non-empty directories. */
	if (fsp->fsp_flags.is_directory) {
		SMB_ASSERT(!is_ntfs_stream_smb_fname(fsp->fsp_name));

		/* Or the root of a share. */
		if (ISDOT(fsp->fsp_name->base_name)) {
			DEBUG(10,("can_set_delete_on_close: can't set delete on "
				  "close for the root of a share.\n"));
			return NT_STATUS_ACCESS_DENIED;
		}

		return can_delete_directory_fsp(fsp);
	}

	return NT_STATUS_OK;
}
