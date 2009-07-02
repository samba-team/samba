/*
 * Catia VFS module
 *
 * Implement a fixed mapping of forbidden NT characters in filenames that are
 * used a lot by the CAD package Catia.
 *
 * Yes, this a BAD BAD UGLY INCOMPLETE hack, but it helps quite some people
 * out there. Catia V4 on AIX uses characters like "<*$ a *lot*, all forbidden
 * under Windows...
 *
 * Copyright (C) Volker Lendecke, 2005
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

static char *catia_string_replace(TALLOC_CTX *ctx,
			const char *s,
			unsigned char oldc,
			unsigned char newc)
{
	smb_ucs2_t *tmpbuf = NULL;
	smb_ucs2_t *ptr = NULL;
	smb_ucs2_t old = oldc;
	char *ret = NULL;
	size_t converted_size;

	if (!s) {
		return NULL;
	}

	if (!push_ucs2_talloc(ctx, &tmpbuf, s, &converted_size)) {
		return NULL;
	}

	ptr = tmpbuf;

	for (;*ptr;ptr++) {
		if (*ptr==old) {
			*ptr=newc;
		}
	}

	if (!pull_ucs2_talloc(ctx, &ret, tmpbuf, &converted_size)) {
		TALLOC_FREE(tmpbuf);
		return NULL;
	}
	TALLOC_FREE(tmpbuf);
	return ret;
}

static char *from_unix(TALLOC_CTX *ctx, const char *s)
{
	char *ret = catia_string_replace(ctx, s, '\x22', '\xa8');
	ret = catia_string_replace(ctx, ret, '\x2a', '\xa4');
	ret = catia_string_replace(ctx, ret, '\x2f', '\xf8');
	ret = catia_string_replace(ctx, ret, '\x3a', '\xf7');
	ret = catia_string_replace(ctx, ret, '\x3c', '\xab');
	ret = catia_string_replace(ctx, ret, '\x3e', '\xbb');
	ret = catia_string_replace(ctx, ret, '\x3f', '\xbf');
	ret = catia_string_replace(ctx, ret, '\x5c', '\xff');
	ret = catia_string_replace(ctx, ret, '\x7c', '\xa6');
	return catia_string_replace(ctx, ret, ' ', '\xb1');
}

static char *to_unix(TALLOC_CTX *ctx, const char *s)
{
	char *ret = catia_string_replace(ctx, s, '\xa8', '\x22');
	ret = catia_string_replace(ctx, ret, '\xa4', '\x2a');
	ret = catia_string_replace(ctx, ret, '\xf8', '\x2f');
	ret = catia_string_replace(ctx, ret, '\xf7', '\x3a');
	ret = catia_string_replace(ctx, ret, '\xab', '\x3c');
	ret = catia_string_replace(ctx, ret, '\xbb', '\x3e');
	ret = catia_string_replace(ctx, ret, '\xbf', '\x3f');
	ret = catia_string_replace(ctx, ret, '\xff', '\x5c');
	ret = catia_string_replace(ctx, ret, '\xa6', '\x7c');
	return catia_string_replace(ctx, ret, '\xb1', ' ');
}

static SMB_STRUCT_DIR *catia_opendir(vfs_handle_struct *handle,
			  const char *fname, const char *mask, uint32 attr)
{
	char *name = to_unix(talloc_tos(), fname);

	if (!name) {
		errno = ENOMEM;
		return NULL;
	}
        return SMB_VFS_NEXT_OPENDIR(handle, name, mask, attr);
}

static SMB_STRUCT_DIRENT *catia_readdir(vfs_handle_struct *handle,
					SMB_STRUCT_DIR *dirp)
{
	SMB_STRUCT_DIRENT *result = NULL;
	SMB_STRUCT_DIRENT *newdirent = NULL;
	char *newname;
	size_t newnamelen;

	result = SMB_VFS_NEXT_READDIR(handle, dirp, NULL);
	if (result == NULL) {
		return result;
	}

	newname = from_unix(talloc_tos(), result->d_name);
	if (!newname) {
		return NULL;
	}
	newnamelen = strlen(newname)+1;
	newdirent = (SMB_STRUCT_DIRENT *)TALLOC_ARRAY(talloc_tos(),
						char,
						sizeof(SMB_STRUCT_DIRENT)+
							newnamelen);
	if (!newdirent) {
		return NULL;
	}
	memcpy(newdirent, result, sizeof(SMB_STRUCT_DIRENT));
	memcpy(&newdirent->d_name, newname, newnamelen);
	return newdirent;
}

static int catia_open(vfs_handle_struct *handle,
		      struct smb_filename *smb_fname,
		      files_struct *fsp,
		      int flags,
		      mode_t mode)
{
	char *name;
	char *tmp_base_name;
	int ret;

	name = to_unix(talloc_tos(), smb_fname->base_name);
	if (!name) {
		errno = ENOMEM;
		return -1;
	}

	tmp_base_name = smb_fname->base_name;
	smb_fname->base_name = name;

	ret = SMB_VFS_NEXT_OPEN(handle, name, fsp, flags, mode);

	smb_fname->base_name = tmp_base_name;
	TALLOC_FREE(name);

	return ret;
}

static int catia_rename(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname_src,
			const struct smb_filename *smb_fname_dst)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *oname = NULL;
	char *nname = NULL;
	struct smb_filename *smb_fname_src_tmp = NULL;
	struct smb_filename *smb_fname_dst_tmp = NULL;
	NTSTATUS status;
	int ret = -1;

	oname = to_unix(ctx, smb_fname_src->base_name);
	nname = to_unix(ctx, smb_fname_dst->base_name);
	if (!oname || !nname) {
		errno = ENOMEM;
		goto out;
	}

	/* Setup temporary smb_filename structs. */
	status = copy_smb_filename(talloc_tos(), smb_fname_src,
				   &smb_fname_src_tmp);
	if (!NT_STATUS_IS_OK(status)) {
		errno = map_errno_from_nt_status(status);
		goto out;
	}
	status = copy_smb_filename(talloc_tos(), smb_fname_dst,
				   &smb_fname_dst_tmp);
	if (!NT_STATUS_IS_OK(status)) {
		errno = map_errno_from_nt_status(status);
		goto out;
	}

	smb_fname_src_tmp->base_name = oname;
	smb_fname_dst_tmp->base_name = nname;

	DEBUG(10, ("converted old name: %s\n",
		   smb_fname_str_dbg(smb_fname_src_tmp)));
	DEBUG(10, ("converted new name: %s\n",
		   smb_fname_str_dbg(smb_fname_dst_tmp)));

        ret = SMB_VFS_NEXT_RENAME(handle, smb_fname_src_tmp,
				  smb_fname_dst_tmp);
 out:
	TALLOC_FREE(oname);
	TALLOC_FREE(newname);
	TALLOC_FREE(smb_fname_src_tmp);
	TALLOC_FREE(smb_fname_dst_tmp);
	return ret;
}

static int catia_stat(vfs_handle_struct *handle,
		      struct smb_filename *smb_fname)
{
	char *name;
	char *tmp_base_name;
	int ret;

	name = to_unix(talloc_tos(), smb_fname->base_name);
	if (!name) {
		errno = ENOMEM;
		return -1;
	}

	tmp_base_name = smb_fname->base_name;
	smb_fname->base_name = name;

	ret = SMB_VFS_NEXT_STAT(handle, smb_fname);

	smb_fname->base_name = tmp_base_name;
	TALLOC_FREE(name);

	return ret;
}

static int catia_lstat(vfs_handle_struct *handle,
		       struct smb_filename *smb_fname)
{
	char *name;
	char *tmp_base_name;
	int ret;

	name = to_unix(talloc_tos(), smb_fname->base_name);
	if (!name) {
		errno = ENOMEM;
		return -1;
	}

	tmp_base_name = smb_fname->base_name;
	smb_fname->base_name = name;

	ret = SMB_VFS_NEXT_LSTAT(handle, smb_fname);

	smb_fname->base_name = tmp_base_name;
	TALLOC_FREE(name);

	return ret;
}

static int catia_unlink(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	struct smb_filename *smb_fname_tmp = NULL;
	char *name = NULL;
	NTSTATUS status;
	int ret;

	name = to_unix(talloc_tos(), smb_fname->base_name);
	if (!name) {
		errno = ENOMEM;
		return -1;
	}

	/* Setup temporary smb_filename structs. */
	status = copy_smb_filename(talloc_tos(), smb_fname,
				   &smb_fname_tmp);
	if (!NT_STATUS_IS_OK(status)) {
		errno = map_errno_from_nt_status(status);
		return -1;
	}

	smb_fname_tmp->base_name = name;

        ret = SMB_VFS_NEXT_UNLINK(handle, smb_fname_tmp);

	TALLOC_FREE(smb_fname_tmp);
	return ret;
}

static int catia_chmod(vfs_handle_struct *handle,
		       const char *path, mode_t mode)
{
	char *name = to_unix(talloc_tos(), path);

	if (!name) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_CHMOD(handle, name, mode);
}

static int catia_chown(vfs_handle_struct *handle,
		       const char *path, uid_t uid, gid_t gid)
{
	char *name = to_unix(talloc_tos(), path);

	if (!name) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_CHOWN(handle, name, uid, gid);
}

static int catia_lchown(vfs_handle_struct *handle,
		       const char *path, uid_t uid, gid_t gid)
{
	char *name = to_unix(talloc_tos(), path);

	if (!name) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_LCHOWN(handle, name, uid, gid);
}

static int catia_chdir(vfs_handle_struct *handle,
		       const char *path)
{
	char *name = to_unix(talloc_tos(), path);

	if (!name) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_CHDIR(handle, name);
}

static char *catia_getwd(vfs_handle_struct *handle, char *buf)
{
        return SMB_VFS_NEXT_GETWD(handle, buf);
}

static int catia_ntimes(vfs_handle_struct *handle,
		       const char *path, struct smb_file_time *ft)
{
        return SMB_VFS_NEXT_NTIMES(handle, path, ft);
}

static bool catia_symlink(vfs_handle_struct *handle,
			  const char *oldpath, const char *newpath)
{
        return SMB_VFS_NEXT_SYMLINK(handle, oldpath, newpath);
}

static bool catia_readlink(vfs_handle_struct *handle,
			   const char *path, char *buf, size_t bufsiz)
{
        return SMB_VFS_NEXT_READLINK(handle, path, buf, bufsiz);
}

static int catia_link(vfs_handle_struct *handle,
		      const char *oldpath, const char *newpath)
{
        return SMB_VFS_NEXT_LINK(handle, oldpath, newpath);
}

static int catia_mknod(vfs_handle_struct *handle,
		       const char *path, mode_t mode, SMB_DEV_T dev)
{
        return SMB_VFS_NEXT_MKNOD(handle, path, mode, dev);
}

static char *catia_realpath(vfs_handle_struct *handle,
			    const char *path, char *resolved_path)
{
        return SMB_VFS_NEXT_REALPATH(handle, path, resolved_path);
}

static NTSTATUS catia_get_nt_acl(vfs_handle_struct *handle,
			       const char *name, uint32 security_info,
			       struct  security_descriptor **ppdesc)
{
        return SMB_VFS_NEXT_GET_NT_ACL(handle, name, security_info, ppdesc);
}

static int catia_chmod_acl(vfs_handle_struct *handle,
			   const char *name, mode_t mode)
{
        /* If the underlying VFS doesn't have ACL support... */
        if (!handle->vfs_next.ops.chmod_acl) {
                errno = ENOSYS;
                return -1;
        }
        return SMB_VFS_NEXT_CHMOD_ACL(handle, name, mode);
}

/* VFS operations structure */

static vfs_op_tuple catia_op_tuples[] = {

        /* Directory operations */

        {SMB_VFS_OP(catia_opendir), SMB_VFS_OP_OPENDIR,
SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(catia_readdir), SMB_VFS_OP_READDIR,
SMB_VFS_LAYER_TRANSPARENT},

        /* File operations */

        {SMB_VFS_OP(catia_open), SMB_VFS_OP_OPEN,
SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(catia_rename),                      SMB_VFS_OP_RENAME,
        SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(catia_stat), SMB_VFS_OP_STAT,
SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(catia_lstat),                       SMB_VFS_OP_LSTAT,
SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(catia_unlink),                      SMB_VFS_OP_UNLINK,
        SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(catia_chmod),                       SMB_VFS_OP_CHMOD,
SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(catia_chown),                       SMB_VFS_OP_CHOWN,
SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(catia_lchown),                      SMB_VFS_OP_LCHOWN,
SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(catia_chdir),                       SMB_VFS_OP_CHDIR,
SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(catia_getwd),                       SMB_VFS_OP_GETWD,
SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(catia_ntimes),                       SMB_VFS_OP_NTIMES,
SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(catia_symlink), SMB_VFS_OP_SYMLINK,
SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(catia_readlink), SMB_VFS_OP_READLINK,
SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(catia_link), SMB_VFS_OP_LINK,
SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(catia_mknod),                       SMB_VFS_OP_MKNOD,
SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(catia_realpath), SMB_VFS_OP_REALPATH,
SMB_VFS_LAYER_TRANSPARENT},

        /* NT File ACL operations */

        {SMB_VFS_OP(catia_get_nt_acl), SMB_VFS_OP_GET_NT_ACL,
SMB_VFS_LAYER_TRANSPARENT},

        /* POSIX ACL operations */

        {SMB_VFS_OP(catia_chmod_acl), SMB_VFS_OP_CHMOD_ACL,
SMB_VFS_LAYER_TRANSPARENT},


        {NULL,                                          SMB_VFS_OP_NOOP,
SMB_VFS_LAYER_NOOP}
};

NTSTATUS vfs_catia_init(void);
NTSTATUS vfs_catia_init(void)
{
        return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "catia",
catia_op_tuples);
}
