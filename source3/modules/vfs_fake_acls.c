/* 
 * Fake ACLs VFS module.  Implements passthrough operation of all VFS
 * calls to disk functions, except for file ownership and ACLs, which
 * are stored in xattrs.
 *
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002
 * Copyright (C) Andrew Bartlett, 2002,2012
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "auth.h"
#include "librpc/gen_ndr/ndr_smb_acl.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#define FAKE_UID "system.fake_uid"
#define FAKE_GID "system.fake_gid"
#define FAKE_ACL_ACCESS_XATTR "system.fake_access_acl"
#define FAKE_ACL_DEFAULT_XATTR "system.fake_default_acl"

static int fake_acls_uid(vfs_handle_struct *handle,
			 struct smb_filename *smb_fname,
			 uid_t *uid)
{
	ssize_t size;
	uint8_t uid_buf[4];
	size = SMB_VFS_NEXT_GETXATTR(handle, smb_fname,
			FAKE_UID, uid_buf, sizeof(uid_buf));
	if (size == -1 && errno == ENOATTR) {
		return 0;
	}
	if (size != 4) {
		return -1;
	}
	*uid = IVAL(uid_buf, 0);
	return 0;
}

static int fake_acls_gid(vfs_handle_struct *handle,
			 struct smb_filename *smb_fname,
			 uid_t *gid)
{
	ssize_t size;
	uint8_t gid_buf[4];

	size = SMB_VFS_NEXT_GETXATTR(handle, smb_fname,
			FAKE_GID, gid_buf, sizeof(gid_buf));
	if (size == -1 && errno == ENOATTR) {
		return 0;
	}
	if (size != 4) {
		return -1;
	}
	*gid = IVAL(gid_buf, 0);
	return 0;
}

static int fake_acls_fuid(vfs_handle_struct *handle,
			   files_struct *fsp,
			   uid_t *uid)
{
	ssize_t size;
	uint8_t uid_buf[4];

	size = SMB_VFS_NEXT_FGETXATTR(handle, fsp, FAKE_UID, uid_buf, sizeof(uid_buf));
	if (size == -1 && errno == ENOATTR) {
		return 0;
	}
	if (size != 4) {
		return -1;
	}
	*uid = IVAL(uid_buf, 0);
	return 0;
}

static int fake_acls_fgid(vfs_handle_struct *handle,
			   files_struct *fsp,
			  uid_t *gid)
{
	ssize_t size;
	uint8_t gid_buf[4];

	size = SMB_VFS_NEXT_FGETXATTR(handle, fsp, FAKE_GID, gid_buf, sizeof(gid_buf));
	if (size == -1 && errno == ENOATTR) {
		return 0;
	}
	if (size != 4) {
		return -1;
	}
	*gid = IVAL(gid_buf, 0);
	return 0;
}

static int fake_acls_stat(vfs_handle_struct *handle,
			   struct smb_filename *smb_fname)
{
	int ret = -1;

	ret = SMB_VFS_NEXT_STAT(handle, smb_fname);
	if (ret == 0) {
		TALLOC_CTX *frame = talloc_stackframe();
		char *path;
		struct smb_filename smb_fname_base = {
			.base_name = smb_fname->base_name
		};
		NTSTATUS status;
		/*
		 * As we're calling getxattr directly here
		 * we need to use only the base_name, not
		 * the full name containing any stream name.
		 */
		status = get_full_smb_filename(frame, &smb_fname_base, &path);
		if (!NT_STATUS_IS_OK(status)) {
			errno = map_errno_from_nt_status(status);
			TALLOC_FREE(frame);
			return -1;
		}
		
		ret = fake_acls_uid(handle, &smb_fname_base,
					&smb_fname->st.st_ex_uid);
		if (ret != 0) {
			TALLOC_FREE(frame);
			return ret;
		}
		ret = fake_acls_gid(handle, &smb_fname_base,
					&smb_fname->st.st_ex_gid);
		if (ret != 0) {
			TALLOC_FREE(frame);
			return ret;
		}
		TALLOC_FREE(frame);
	}

	return ret;
}

static int fake_acls_lstat(vfs_handle_struct *handle,
			   struct smb_filename *smb_fname)
{
	int ret = -1;

	ret = SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	if (ret == 0) {
		TALLOC_CTX *frame = talloc_stackframe();
		char *path;
		struct smb_filename smb_fname_base = {
			.base_name = smb_fname->base_name
		};
		NTSTATUS status;
		/*
		 * As we're calling getxattr directly here
		 * we need to use only the base_name, not
		 * the full name containing any stream name.
		 */
		status = get_full_smb_filename(frame, &smb_fname_base, &path);
		if (!NT_STATUS_IS_OK(status)) {
			errno = map_errno_from_nt_status(status);
			TALLOC_FREE(frame);
			return -1;
		}

		/* This isn't quite right (calling getxattr not
		 * lgetxattr), but for the test purposes of this
		 * module (fake NT ACLs from windows clients), it is
		 * close enough.  We removed the l*xattr functions
		 * because linux doesn't support using them, but we
		 * could fake them in xattr_tdb if we really wanted
		 * to.  We ignore errors because the link might not point anywhere */
		fake_acls_uid(handle, &smb_fname_base,
			&smb_fname->st.st_ex_uid);
		fake_acls_gid(handle, &smb_fname_base,
			&smb_fname->st.st_ex_gid);
		TALLOC_FREE(frame);
	}

	return ret;
}

static int fake_acls_fstat(vfs_handle_struct *handle, files_struct *fsp, SMB_STRUCT_STAT *sbuf)
{
	int ret = -1;

	ret = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	if (ret == 0) {
		ret = fake_acls_fuid(handle, fsp, &sbuf->st_ex_uid);
		if (ret != 0) {
			return ret;
		}
		ret = fake_acls_fgid(handle, fsp, &sbuf->st_ex_gid);
		if (ret != 0) {
			return ret;
		}
	}
	return ret;
}

static SMB_ACL_T fake_acls_blob2acl(DATA_BLOB *blob, TALLOC_CTX *mem_ctx)
{
	enum ndr_err_code ndr_err;
	struct smb_acl_t *acl = talloc(mem_ctx, struct smb_acl_t);
	if (!acl) {
		errno = ENOMEM;
		return NULL;
	}

	ndr_err = ndr_pull_struct_blob(blob, acl, acl, 
		(ndr_pull_flags_fn_t)ndr_pull_smb_acl_t);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("ndr_pull_acl_t failed: %s\n",
			  ndr_errstr(ndr_err)));
		TALLOC_FREE(acl);
		return NULL;
	}
	return acl;
}

static DATA_BLOB fake_acls_acl2blob(TALLOC_CTX *mem_ctx, SMB_ACL_T acl)
{
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	ndr_err = ndr_push_struct_blob(&blob, mem_ctx, acl, 
		(ndr_push_flags_fn_t)ndr_push_smb_acl_t);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("ndr_push_acl_t failed: %s\n",
			  ndr_errstr(ndr_err)));
		return data_blob_null;
	}
	return blob;
}

static SMB_ACL_T fake_acls_sys_acl_get_file(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				SMB_ACL_TYPE_T type,
				TALLOC_CTX *mem_ctx)
{
	DATA_BLOB blob = data_blob_null;
	ssize_t length;
	const char *name = NULL;
	struct smb_acl_t *acl = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	switch (type) {
	case SMB_ACL_TYPE_ACCESS:
		name = FAKE_ACL_ACCESS_XATTR;
		break;
	case SMB_ACL_TYPE_DEFAULT:
		name = FAKE_ACL_DEFAULT_XATTR;
		break;
	}

	do {
		blob.length += 1000;
		blob.data = talloc_realloc(frame, blob.data, uint8_t, blob.length);
		if (!blob.data) {
			errno = ENOMEM;
			TALLOC_FREE(frame);
			return NULL;
		}
		length = SMB_VFS_NEXT_GETXATTR(handle, smb_fname,
				name, blob.data, blob.length);
		blob.length = length;
	} while (length == -1 && errno == ERANGE);
	if (length == -1 && errno == ENOATTR) {
		TALLOC_FREE(frame);
		return NULL;
	}
	if (length != -1) {
		acl = fake_acls_blob2acl(&blob, mem_ctx);
	}
	TALLOC_FREE(frame);
	return acl;
}

static SMB_ACL_T fake_acls_sys_acl_get_fd(struct vfs_handle_struct *handle,
					  files_struct *fsp,
					  TALLOC_CTX *mem_ctx)
{
	DATA_BLOB blob = data_blob_null;
	ssize_t length;
	const char *name = FAKE_ACL_ACCESS_XATTR;
	struct smb_acl_t *acl = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
		
	do {
		blob.length += 1000;
		blob.data = talloc_realloc(frame, blob.data, uint8_t, blob.length);
		if (!blob.data) {
			errno = ENOMEM;
			TALLOC_FREE(frame);
			return NULL;
		}
		length = SMB_VFS_NEXT_FGETXATTR(handle, fsp, name, blob.data, blob.length);
		blob.length = length;
	} while (length == -1 && errno == ERANGE);
	if (length == -1 && errno == ENOATTR) {
		TALLOC_FREE(frame);
		return NULL;
	}
	if (length != -1) {
		acl = fake_acls_blob2acl(&blob, mem_ctx);
	}
	TALLOC_FREE(frame);
	return acl;
}


static int fake_acls_sys_acl_set_file(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			SMB_ACL_TYPE_T acltype,
			SMB_ACL_T theacl)
{
	int ret;
	const char *name = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	DATA_BLOB blob = fake_acls_acl2blob(frame, theacl);
	if (!blob.data) {
		DEBUG(0, ("Failed to convert ACL to linear blob for xattr storage\n"));
		TALLOC_FREE(frame);
		errno = EINVAL;
		return -1;
	}
	switch (acltype) {
	case SMB_ACL_TYPE_ACCESS:
		name = FAKE_ACL_ACCESS_XATTR;
		break;
	case SMB_ACL_TYPE_DEFAULT:
		name = FAKE_ACL_DEFAULT_XATTR;
		break;
	}
	ret = SMB_VFS_NEXT_SETXATTR(handle, smb_fname,
			name, blob.data, blob.length, 0);
	TALLOC_FREE(frame);
	return ret;
}

static int fake_acls_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp, SMB_ACL_T theacl)
{
	int ret;
	const char *name = FAKE_ACL_ACCESS_XATTR;
	TALLOC_CTX *frame = talloc_stackframe();
	DATA_BLOB blob = fake_acls_acl2blob(frame, theacl);
	if (!blob.data) {
		DEBUG(0, ("Failed to convert ACL to linear blob for xattr storage\n"));
		TALLOC_FREE(frame);
		errno = EINVAL;
		return -1;
	}
	ret = SMB_VFS_NEXT_FSETXATTR(handle, fsp, name, blob.data, blob.length, 0);
	TALLOC_FREE(frame);
	return ret;
}

static int fake_acls_sys_acl_delete_def_file(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname_in)
{
	int ret;
	const char *name = FAKE_ACL_DEFAULT_XATTR;
	TALLOC_CTX *frame = talloc_stackframe();
	struct smb_filename *smb_fname = cp_smb_filename_nostream(talloc_tos(),
						smb_fname_in);

	if (smb_fname == NULL) {
		TALLOC_FREE(frame);
		errno = ENOMEM;
		return -1;
	}

	ret = SMB_VFS_NEXT_STAT(handle, smb_fname);
	if (ret == -1) {
		TALLOC_FREE(frame);
		return -1;
	}

	if (!S_ISDIR(smb_fname->st.st_ex_mode)) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	ret = SMB_VFS_NEXT_REMOVEXATTR(handle, smb_fname, name);
	if (ret == -1 && errno == ENOATTR) {
		ret = 0;
		errno = 0;
	}

	TALLOC_FREE(frame);
	return ret;
}

static int fake_acls_lchown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	int ret;
	uint8_t id_buf[4];
	if (uid != -1) {
		uid_t current_uid = get_current_uid(handle->conn);

		if (current_uid != 0 && current_uid != uid) {
			return EACCES;
		}

		/* This isn't quite right (calling setxattr not
		 * lsetxattr), but for the test purposes of this
		 * module (fake NT ACLs from windows clients), it is
		 * close enough.  We removed the l*xattr functions
		 * because linux doesn't support using them, but we
		 * could fake them in xattr_tdb if we really wanted
		 * to.
		 */
		SIVAL(id_buf, 0, uid);
		ret = SMB_VFS_NEXT_SETXATTR(handle,
				smb_fname,
				FAKE_UID,
				id_buf,
				sizeof(id_buf),
				0);
		if (ret != 0) {
			return ret;
		}
	}
	if (gid != -1) {
		SIVAL(id_buf, 0, gid);
		ret = SMB_VFS_NEXT_SETXATTR(handle,
				smb_fname,
				FAKE_GID,
				id_buf,
				sizeof(id_buf),
				0);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

static int fake_acls_fchown(vfs_handle_struct *handle, files_struct *fsp, uid_t uid, gid_t gid)
{
	int ret;
	uint8_t id_buf[4];
	if (uid != -1) {
		uid_t current_uid = get_current_uid(handle->conn);

		if (current_uid != 0 && current_uid != uid) {
			return EACCES;
		}

		SIVAL(id_buf, 0, uid);
		ret = SMB_VFS_NEXT_FSETXATTR(handle, fsp, FAKE_UID, id_buf, sizeof(id_buf), 0);
		if (ret != 0) {
			return ret;
		}
	}
	if (gid != -1) {
		SIVAL(id_buf, 0, gid);
		ret = SMB_VFS_NEXT_FSETXATTR(handle, fsp, FAKE_GID, id_buf, sizeof(id_buf), 0);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

/*
 * Implement the chmod uid/mask/other mode changes on a fake ACL.
 */

static int fake_acl_process_chmod(SMB_ACL_T *pp_the_acl,
				uid_t owner,
				mode_t mode)
{
	bool got_mask = false;
	int entry_id = SMB_ACL_FIRST_ENTRY;
	mode_t umode = 0;
	mode_t mmode = 0;
	mode_t omode = 0;
	int ret = -1;
	SMB_ACL_T the_acl = *pp_the_acl;

	/* Split the mode into u/mask/other masks. */
	umode = unix_perms_to_acl_perms(mode, S_IRUSR, S_IWUSR, S_IXUSR);
	mmode = unix_perms_to_acl_perms(mode, S_IRGRP, S_IWGRP, S_IXGRP);
	omode = unix_perms_to_acl_perms(mode, S_IROTH, S_IWOTH, S_IXOTH);

	while (1) {
		SMB_ACL_ENTRY_T entry;
		SMB_ACL_TAG_T tagtype;
		SMB_ACL_PERMSET_T permset;
		uid_t *puid = NULL;

		ret = sys_acl_get_entry(the_acl,
					entry_id,
					&entry);
		if (ret == 0) {
			/* End of ACL */
			break;
		}
		if (ret == -1) {
			return -1;
		}

		ret = sys_acl_get_tag_type(entry, &tagtype);
		if (ret == -1) {
			return -1;
		}
		ret = sys_acl_get_permset(entry, &permset);
		if (ret == -1) {
			return -1;
		}
		switch (tagtype) {
			case SMB_ACL_USER_OBJ:
				ret = map_acl_perms_to_permset(umode, &permset);
				if (ret == -1) {
					return -1;
				}
				break;
			case SMB_ACL_USER:
				puid = (uid_t *)sys_acl_get_qualifier(entry);
				if (puid == NULL) {
					return -1;
				}
				if (owner != *puid) {
					break;
				}
				ret = map_acl_perms_to_permset(umode, &permset);
				if (ret == -1) {
					return -1;
				}
				break;
			case SMB_ACL_GROUP_OBJ:
			case SMB_ACL_GROUP:
				/* Ignore all group entries. */
				break;
			case SMB_ACL_MASK:
				ret = map_acl_perms_to_permset(mmode, &permset);
				if (ret == -1) {
					return -1;
				}
				got_mask = true;
				break;
			case SMB_ACL_OTHER:
				ret = map_acl_perms_to_permset(omode, &permset);
				if (ret == -1) {
					return -1;
				}
				break;
			default:
				errno = EINVAL;
				return -1;
		}
		ret = sys_acl_set_permset(entry, permset);
		if (ret == -1) {
			return -1;
		}
		/* Move to next entry. */
		entry_id = SMB_ACL_NEXT_ENTRY;
	}

	/*
	 * If we didn't see a mask entry, add one.
	 */

	if (!got_mask) {
		SMB_ACL_ENTRY_T mask_entry;
		SMB_ACL_PERMSET_T mask_permset;
		ret = sys_acl_create_entry(&the_acl, &mask_entry);
		if (ret == -1) {
			return -1;
		}
		ret = map_acl_perms_to_permset(mmode, &mask_permset);
		if (ret == -1) {
			return -1;
		}
		ret = sys_acl_set_permset(mask_entry, mask_permset);
		if (ret == -1) {
			return -1;
		}
		ret = sys_acl_set_tag_type(mask_entry, SMB_ACL_MASK);
		if (ret == -1) {
			return -1;
		}
		/* In case we were realloced and moved. */
		*pp_the_acl = the_acl;
	}

	return 0;
}

static int fake_acls_chmod(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname_in,
			mode_t mode)
{
	TALLOC_CTX *frame = talloc_stackframe();
	int ret = -1;
	SMB_ACL_T the_acl = NULL;
	struct smb_filename *smb_fname = cp_smb_filename_nostream(talloc_tos(),
						smb_fname_in);

	if (smb_fname == NULL) {
		TALLOC_FREE(frame);
		return -1;
	}

	/*
	 * Passthrough first to preserve the
	 * S_ISUID | S_ISGID | S_ISVTX
	 * bits.
	 */

	ret = SMB_VFS_NEXT_CHMOD(handle,
				smb_fname,
				mode);
	if (ret == -1) {
		TALLOC_FREE(frame);
		return -1;
	}

	the_acl = fake_acls_sys_acl_get_file(handle,
				smb_fname,
				SMB_ACL_TYPE_ACCESS,
				talloc_tos());
	if (the_acl == NULL) {
		TALLOC_FREE(frame);
		if (errno == ENOATTR) {
			/* No ACL on this file. Just passthrough. */
			return 0;
		}
		return -1;
	}
	ret = fake_acl_process_chmod(&the_acl,
			smb_fname->st.st_ex_uid,
			mode);
	if (ret == -1) {
		TALLOC_FREE(frame);
		return -1;
	}
	ret = fake_acls_sys_acl_set_file(handle,
				smb_fname,
				SMB_ACL_TYPE_ACCESS,
				the_acl);
	TALLOC_FREE(frame);
	return ret;
}

static int fake_acls_fchmod(vfs_handle_struct *handle,
			files_struct *fsp,
			mode_t mode)
{
	TALLOC_CTX *frame = talloc_stackframe();
	int ret = -1;
	SMB_ACL_T the_acl = NULL;

	/*
	 * Passthrough first to preserve the
	 * S_ISUID | S_ISGID | S_ISVTX
	 * bits.
	 */

	ret = SMB_VFS_NEXT_FCHMOD(handle,
				fsp,
				mode);
	if (ret == -1) {
		TALLOC_FREE(frame);
		return -1;
	}

	the_acl = fake_acls_sys_acl_get_fd(handle,
				fsp,
				talloc_tos());
	if (the_acl == NULL) {
		TALLOC_FREE(frame);
		if (errno == ENOATTR) {
			/* No ACL on this file. Just passthrough. */
			return 0;
		}
		return -1;
	}
	ret = fake_acl_process_chmod(&the_acl,
			fsp->fsp_name->st.st_ex_uid,
			mode);
	if (ret == -1) {
		TALLOC_FREE(frame);
		return -1;
	}
	ret = fake_acls_sys_acl_set_fd(handle,
				fsp,
				the_acl);
	TALLOC_FREE(frame);
	return ret;
}

static struct vfs_fn_pointers vfs_fake_acls_fns = {
	.stat_fn = fake_acls_stat,
	.lstat_fn = fake_acls_lstat,
	.fstat_fn = fake_acls_fstat,
	.chmod_fn = fake_acls_chmod,
	.fchmod_fn = fake_acls_fchmod,
	.sys_acl_get_file_fn = fake_acls_sys_acl_get_file,
	.sys_acl_get_fd_fn = fake_acls_sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = posix_sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = posix_sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = fake_acls_sys_acl_set_file,
	.sys_acl_set_fd_fn = fake_acls_sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = fake_acls_sys_acl_delete_def_file,
	.lchown_fn = fake_acls_lchown,
	.fchown_fn = fake_acls_fchown,
	
};

static_decl_vfs;
NTSTATUS vfs_fake_acls_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "fake_acls",
				&vfs_fake_acls_fns);
}
