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
					SMB_STRUCT_DIR *dirp,
					SMB_STRUCT_STAT *sbuf)
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

	ret = SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);

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
	TALLOC_FREE(nname);
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

static struct vfs_fn_pointers vfs_catia_fns = {
        .opendir = catia_opendir,
        .readdir = catia_readdir,
        .open = catia_open,
        .rename = catia_rename,
        .stat = catia_stat,
        .lstat = catia_lstat,
        .unlink = catia_unlink,
        .chmod = catia_chmod,
        .chown = catia_chown,
        .lchown = catia_lchown,
        .chdir = catia_chdir,
};

NTSTATUS vfs_catia_init(void);
NTSTATUS vfs_catia_init(void)
{
        return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "catia",
				&vfs_catia_fns);
}
