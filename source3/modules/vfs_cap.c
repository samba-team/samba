/*
 * CAP VFS module for Samba 3.x Version 0.3
 *
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002-2003
 * Copyright (C) Stefan (metze) Metzmacher, 2003
 * Copyright (C) TAKAHASHI Motonobu (monyo), 2003
 * Copyright (C) Jeremy Allison, 2007
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

/* cap functions */
static char *capencode(TALLOC_CTX *ctx, const char *from);
static char *capdecode(TALLOC_CTX *ctx, const char *from);

static SMB_BIG_UINT cap_disk_free(vfs_handle_struct *handle, const char *path,
	bool small_query, SMB_BIG_UINT *bsize,
	SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return (SMB_BIG_UINT)-1;
	}
	return SMB_VFS_NEXT_DISK_FREE(handle, cappath, small_query, bsize,
					dfree, dsize);
}

static SMB_STRUCT_DIR *cap_opendir(vfs_handle_struct *handle, const char *fname, const char *mask, uint32 attr)
{
	char *capname = capencode(talloc_tos(), fname);

	if (!capname) {
		errno = ENOMEM;
		return NULL;
	}
	return SMB_VFS_NEXT_OPENDIR(handle, capname, mask, attr);
}

static SMB_STRUCT_DIRENT *cap_readdir(vfs_handle_struct *handle, SMB_STRUCT_DIR *dirp)
{
	SMB_STRUCT_DIRENT *result;
	SMB_STRUCT_DIRENT *newdirent;
	char *newname;
	size_t newnamelen;
	DEBUG(3,("cap: cap_readdir\n"));

	result = SMB_VFS_NEXT_READDIR(handle, dirp);
	if (!result) {
		return NULL;
	}

	newname = capdecode(talloc_tos(), result->d_name);
	if (!newname) {
		return NULL;
	}
	DEBUG(3,("cap: cap_readdir: %s\n", newname));
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

static int cap_mkdir(vfs_handle_struct *handle, const char *path, mode_t mode)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_MKDIR(handle, cappath, mode);
}

static int cap_rmdir(vfs_handle_struct *handle, const char *path)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_RMDIR(handle, cappath);
}

static int cap_open(vfs_handle_struct *handle, const char *fname, files_struct *fsp, int flags, mode_t mode)
{
	char *cappath = capencode(talloc_tos(), fname);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	DEBUG(3,("cap: cap_open for %s\n", fname));
	return SMB_VFS_NEXT_OPEN(handle, cappath, fsp, flags, mode);
}

static int cap_rename(vfs_handle_struct *handle, const char *oldname, const char *newname)
{
	char *capold = capencode(talloc_tos(), oldname);
	char *capnew = capencode(talloc_tos(), newname);

	if (!capold || !capnew) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_RENAME(handle, capold, capnew);
}

static int cap_stat(vfs_handle_struct *handle, const char *path, SMB_STRUCT_STAT *sbuf)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_STAT(handle, cappath, sbuf);
}

static int cap_lstat(vfs_handle_struct *handle, const char *path, SMB_STRUCT_STAT *sbuf)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_LSTAT(handle, cappath, sbuf);
}

static int cap_unlink(vfs_handle_struct *handle, const char *path)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_UNLINK(handle, cappath);
}

static int cap_chmod(vfs_handle_struct *handle, const char *path, mode_t mode)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_CHMOD(handle, cappath, mode);
}

static int cap_chown(vfs_handle_struct *handle, const char *path, uid_t uid, gid_t gid)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_CHOWN(handle, cappath, uid, gid);
}

static int cap_lchown(vfs_handle_struct *handle, const char *path, uid_t uid, gid_t gid)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_LCHOWN(handle, cappath, uid, gid);
}

static int cap_chdir(vfs_handle_struct *handle, const char *path)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	DEBUG(3,("cap: cap_chdir for %s\n", path));
	return SMB_VFS_NEXT_CHDIR(handle, cappath);
}

static int cap_ntimes(vfs_handle_struct *handle, const char *path, const struct timespec ts[2])
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_NTIMES(handle, cappath, ts);
}


static bool cap_symlink(vfs_handle_struct *handle, const char *oldpath, const char *newpath)
{
	char *capold = capencode(talloc_tos(), oldpath);
	char *capnew = capencode(talloc_tos(), newpath);

	if (!capold || !capnew) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_SYMLINK(handle, capold, capnew);
}

static bool cap_readlink(vfs_handle_struct *handle, const char *path, char *buf, size_t bufsiz)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_READLINK(handle, cappath, buf, bufsiz);
}

static int cap_link(vfs_handle_struct *handle, const char *oldpath, const char *newpath)
{
	char *capold = capencode(talloc_tos(), oldpath);
	char *capnew = capencode(talloc_tos(), newpath);

	if (!capold || !capnew) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_LINK(handle, capold, capnew);
}

static int cap_mknod(vfs_handle_struct *handle, const char *path, mode_t mode, SMB_DEV_T dev)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_MKNOD(handle, cappath, mode, dev);
}

static char *cap_realpath(vfs_handle_struct *handle, const char *path, char *resolved_path)
{
        /* monyo need capencode'ed and capdecode'ed? */
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return NULL;
	}
	return SMB_VFS_NEXT_REALPATH(handle, path, resolved_path);
}

static int cap_chmod_acl(vfs_handle_struct *handle, const char *path, mode_t mode)
{
	char *cappath = capencode(talloc_tos(), path);

	/* If the underlying VFS doesn't have ACL support... */
	if (!handle->vfs_next.ops.chmod_acl) {
		errno = ENOSYS;
		return -1;
	}
	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_CHMOD_ACL(handle, cappath, mode);
}

static SMB_ACL_T cap_sys_acl_get_file(vfs_handle_struct *handle, const char *path, SMB_ACL_TYPE_T type)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return (SMB_ACL_T)NULL;
	}
	return SMB_VFS_NEXT_SYS_ACL_GET_FILE(handle, cappath, type);
}

static int cap_sys_acl_set_file(vfs_handle_struct *handle, const char *path, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle, cappath, acltype, theacl);
}

static int cap_sys_acl_delete_def_file(vfs_handle_struct *handle, const char *path)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_SYS_ACL_DELETE_DEF_FILE(handle, cappath);
}

static ssize_t cap_getxattr(vfs_handle_struct *handle, const char *path, const char *name, void *value, size_t size)
{
	char *cappath = capencode(talloc_tos(), path);
	char *capname = capencode(talloc_tos(), name);

	if (!cappath || !capname) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_GETXATTR(handle, cappath, capname, value, size);
}

static ssize_t cap_lgetxattr(vfs_handle_struct *handle, const char *path, const char *name, void *value, size_t
size)
{
	char *cappath = capencode(talloc_tos(), path);
	char *capname = capencode(talloc_tos(), name);

	if (!cappath || !capname) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_LGETXATTR(handle, cappath, capname, value, size);
}

static ssize_t cap_fgetxattr(vfs_handle_struct *handle, struct files_struct *fsp, const char *path, void *value, size_t size)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_FGETXATTR(handle, fsp, cappath, value, size);
}

static ssize_t cap_listxattr(vfs_handle_struct *handle, const char *path, char *list, size_t size)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_LISTXATTR(handle, cappath, list, size);
}

static ssize_t cap_llistxattr(vfs_handle_struct *handle, const char *path, char *list, size_t size)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_LLISTXATTR(handle, cappath, list, size);
}

static int cap_removexattr(vfs_handle_struct *handle, const char *path, const char *name)
{
	char *cappath = capencode(talloc_tos(), path);
	char *capname = capencode(talloc_tos(), name);

	if (!cappath || !capname) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_REMOVEXATTR(handle, cappath, capname);
}

static int cap_lremovexattr(vfs_handle_struct *handle, const char *path, const char *name)
{
	char *cappath = capencode(talloc_tos(), path);
	char *capname = capencode(talloc_tos(), name);

	if (!cappath || !capname) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_LREMOVEXATTR(handle, cappath, capname);
}

static int cap_fremovexattr(vfs_handle_struct *handle, struct files_struct *fsp, const char *path)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, cappath);
}

static int cap_setxattr(vfs_handle_struct *handle, const char *path, const char *name, const void *value, size_t size, int flags)
{
	char *cappath = capencode(talloc_tos(), path);
	char *capname = capencode(talloc_tos(), name);

	if (!cappath || !capname) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_SETXATTR(handle, cappath, capname, value, size, flags);
}

static int cap_lsetxattr(vfs_handle_struct *handle, const char *path, const char *name, const void *value, size_t size, int flags)
{
	char *cappath = capencode(talloc_tos(), path);
	char *capname = capencode(talloc_tos(), name);

	if (!cappath || !capname) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_LSETXATTR(handle, cappath, capname, value, size, flags);
}

static int cap_fsetxattr(vfs_handle_struct *handle, struct files_struct *fsp, const char *path, const void *value, size_t size, int flags)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_FSETXATTR(handle, fsp, cappath, value, size, flags);
}

/* VFS operations structure */

static vfs_op_tuple cap_op_tuples[] = {

	/* Disk operations */

	{SMB_VFS_OP(cap_disk_free),			SMB_VFS_OP_DISK_FREE,		SMB_VFS_LAYER_TRANSPARENT},

	/* Directory operations */

	{SMB_VFS_OP(cap_opendir),			SMB_VFS_OP_OPENDIR,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_readdir),			SMB_VFS_OP_READDIR,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_mkdir),			SMB_VFS_OP_MKDIR,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_rmdir),			SMB_VFS_OP_RMDIR,		SMB_VFS_LAYER_TRANSPARENT},

	/* File operations */

	{SMB_VFS_OP(cap_open),				SMB_VFS_OP_OPEN,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_rename),			SMB_VFS_OP_RENAME,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_stat),				SMB_VFS_OP_STAT,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_lstat),			SMB_VFS_OP_LSTAT,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_unlink),			SMB_VFS_OP_UNLINK,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_chmod),			SMB_VFS_OP_CHMOD,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_chown),			SMB_VFS_OP_CHOWN,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_lchown),		SMB_VFS_OP_LCHOWN,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_chdir),			SMB_VFS_OP_CHDIR,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_ntimes),			SMB_VFS_OP_NTIMES,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_symlink),			SMB_VFS_OP_SYMLINK,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_readlink),			SMB_VFS_OP_READLINK,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_link),				SMB_VFS_OP_LINK,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_mknod),			SMB_VFS_OP_MKNOD,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_realpath),			SMB_VFS_OP_REALPATH,		SMB_VFS_LAYER_TRANSPARENT},

	/* POSIX ACL operations */

	{SMB_VFS_OP(cap_chmod_acl),			SMB_VFS_OP_CHMOD_ACL,		SMB_VFS_LAYER_TRANSPARENT},

	{SMB_VFS_OP(cap_sys_acl_get_file),		SMB_VFS_OP_SYS_ACL_GET_FILE,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_sys_acl_set_file),		SMB_VFS_OP_SYS_ACL_SET_FILE,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_sys_acl_delete_def_file),	SMB_VFS_OP_SYS_ACL_DELETE_DEF_FILE,	SMB_VFS_LAYER_TRANSPARENT},

	/* EA operations. */
	{SMB_VFS_OP(cap_getxattr),			SMB_VFS_OP_GETXATTR,			SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_lgetxattr),			SMB_VFS_OP_LGETXATTR,			SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_fgetxattr),			SMB_VFS_OP_FGETXATTR,			SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_listxattr),			SMB_VFS_OP_LISTXATTR,			SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_llistxattr),			SMB_VFS_OP_LLISTXATTR,			SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_removexattr),			SMB_VFS_OP_REMOVEXATTR,			SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_lremovexattr),			SMB_VFS_OP_LREMOVEXATTR,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_fremovexattr),			SMB_VFS_OP_FREMOVEXATTR,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_setxattr),			SMB_VFS_OP_SETXATTR,			SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_lsetxattr),			SMB_VFS_OP_LSETXATTR,			SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(cap_fsetxattr),			SMB_VFS_OP_FSETXATTR,			SMB_VFS_LAYER_TRANSPARENT},

	{NULL,						SMB_VFS_OP_NOOP,			SMB_VFS_LAYER_NOOP}
};

NTSTATUS vfs_cap_init(void);
NTSTATUS vfs_cap_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "cap", cap_op_tuples);
}

/* For CAP functions */
#define hex_tag ':'
#define hex2bin(c)		hex2bin_table[(unsigned char)(c)]
#define bin2hex(c)		bin2hex_table[(unsigned char)(c)]
#define is_hex(s)		((s)[0] == hex_tag)

static unsigned char hex2bin_table[256] = {
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x00 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x10 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x20 */
0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, /* 0x30 */
0000, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0000, /* 0x40 */
0000, 0000, 0000, 0000, 0000, 0000, 0000, 0000,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x50 */
0000, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0000, /* 0x60 */
0000, 0000, 0000, 0000, 0000, 0000, 0000, 0000,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x70 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x80 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x90 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xa0 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xb0 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xc0 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xd0 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xe0 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  /* 0xf0 */
};
static unsigned char bin2hex_table[256] = "0123456789abcdef";

/*******************************************************************
  original code -> ":xx"  - CAP format
********************************************************************/

static char *capencode(TALLOC_CTX *ctx, const char *from)
{
	char *out = NULL;
	const char *p1;
	char *to = NULL;
	size_t len = 0;

	for (p1 = from; *p1; p1++) {
		if ((unsigned char)*p1 >= 0x80) {
			len += 3;
		} else {
			len++;
		}
	}
	len++;

	to = TALLOC_ARRAY(ctx, char, len);
	if (!to) {
		return NULL;
	}

	for (out = to; *from;) {
		/* buffer husoku error */
		if ((unsigned char)*from >= 0x80) {
			*out++ = hex_tag;
			*out++ = bin2hex (((*from)>>4)&0x0f);
			*out++ = bin2hex ((*from)&0x0f);
			from++;
		} else {
			*out++ = *from++;
		}
  	}
	*out = '\0';
	return to;
}

/*******************************************************************
  CAP -> original code
********************************************************************/
/* ":xx" -> a byte */

static char *capdecode(TALLOC_CTX *ctx, const char *from)
{
	const char *p1;
	char *out = NULL;
	char *to = NULL;
	size_t len = 0;

	for (p1 = from; *p1; len++) {
		if (is_hex(from)) {
			p1 += 3;
		} else {
			p1++;
		}
	}

	to = TALLOC_ARRAY(ctx, char, len);
	if (!to) {
		return NULL;
	}

	for (out = to; *from;) {
		if (is_hex(from)) {
			*out++ = (hex2bin(from[1])<<4) | (hex2bin(from[2]));
			from += 3;
		} else {
			*out++ = *from++;
		}
	}
	*out = '\0';
	return to;
}
