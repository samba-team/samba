/* 
 * implementation of an Shadow Copy module - version 2
 *
 * Copyright (C) Andrew Tridgell     2007
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

/*

  This is a 2nd implemetation of a shadow copy module for exposing
  snapshots to windows clients as shadow copies. This version has the
  following features:

     1) you don't need to populate your shares with symlinks to the
     snapshots. This can be very important when you have thousands of
     shares, or use [homes]

     2) the inode number of the files is altered so it is different
     from the original. This allows the 'restore' button to work
     without a sharing violation

  Module options:

      shadow:snapdir = <directory where snapshots are kept>

      This is the directory containing the @GMT-* snapshot directories. If it is an absolute
      path it is used as-is. If it is a relative path, then it is taken relative to the mount
      point of the filesystem that the root of this share is on

      shadow:basedir = <base directory that snapshots are from>

      This is an optional parameter that specifies the directory that
      the snapshots are relative to. It defaults to the filesystem
      mount point

      shadow:fixinodes = yes/no

      If you enable shadow:fixinodes then this module will modify the
      apparent inode number of files in the snapshot directories using
      a hash of the files path. This is needed for snapshot systems
      where the snapshots have the same device:inode number as the
      original files (such as happens with GPFS snapshots). If you
      don't set this option then the 'restore' button in the shadow
      copy UI will fail with a sharing violation.

  Note that the directory names in the snapshot directory must take the form
  @GMT-YYYY.MM.DD-HH.MM.SS
  
  The following command would generate a correctly formatted directory name:
     date -u +@GMT-%Y.%m.%d-%H.%M.%S
  
 */

static int vfs_shadow_copy2_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_shadow_copy2_debug_level

#define GMT_NAME_LEN 24 /* length of a @GMT- name */

/*
  make very sure it is one of our special names 
 */
static inline bool shadow_copy2_match_name(const char *name)
{
	unsigned year, month, day, hr, min, sec;
	if (name[0] != '@') return False;
	if (strncmp(name, "@GMT-", 5) != 0) return False;
	if (sscanf(name, "@GMT-%04u.%02u.%02u-%02u.%02u.%02u", &year, &month,
		   &day, &hr, &min, &sec) != 6) {
		return False;
	}
	if (name[24] != 0 && name[24] != '/') {
		return False;
	}
	return True;
}

/*
  convert a name to the shadow directory
 */

#define _SHADOW2_NEXT(op, args, rtype, eret, extra) do { \
	const char *name = fname; \
	if (shadow_copy2_match_name(fname)) { \
		char *name2; \
		rtype ret; \
		name2 = convert_shadow2_name(handle, fname); \
		if (name2 == NULL) { \
			errno = EINVAL; \
			return eret; \
		} \
		name = name2; \
		ret = SMB_VFS_NEXT_ ## op args; \
		talloc_free(name2); \
		if (ret != eret) extra; \
		return ret; \
	} else { \
		return SMB_VFS_NEXT_ ## op args; \
	} \
} while (0)

/*
  convert a name to the shadow directory: NTSTATUS-specific handling
 */

#define _SHADOW2_NTSTATUS_NEXT(op, args, eret, extra) do { \
        const char *name = fname; \
        if (shadow_copy2_match_name(fname)) { \
                char *name2; \
                NTSTATUS ret; \
                name2 = convert_shadow2_name(handle, fname); \
                if (name2 == NULL) { \
                        errno = EINVAL; \
                        return eret; \
                } \
                name = name2; \
                ret = SMB_VFS_NEXT_ ## op args; \
                talloc_free(name2); \
                if (!NT_STATUS_EQUAL(ret, eret)) extra; \
                return ret; \
        } else { \
                return SMB_VFS_NEXT_ ## op args; \
        } \
} while (0)

#define SHADOW2_NTSTATUS_NEXT(op, args, eret) _SHADOW2_NTSTATUS_NEXT(op, args, eret, )

#define SHADOW2_NEXT(op, args, rtype, eret) _SHADOW2_NEXT(op, args, rtype, eret, )

#define SHADOW2_NEXT2(op, args) do { \
	if (shadow_copy2_match_name(oldname) || shadow_copy2_match_name(newname)) { \
		errno = EROFS; \
		return -1; \
	} else { \
		return SMB_VFS_NEXT_ ## op args; \
	} \
} while (0)


/*
  find the mount point of a filesystem
 */
static char *find_mount_point(TALLOC_CTX *mem_ctx, vfs_handle_struct *handle)
{
	char *path = talloc_strdup(mem_ctx, handle->conn->connectpath);
	dev_t dev;
	struct stat st;
	char *p;

	if (stat(path, &st) != 0) {
		talloc_free(path);
		return NULL;
	}

	dev = st.st_dev;

	while ((p = strrchr(path, '/')) && p > path) {
		*p = 0;
		if (stat(path, &st) != 0) {
			talloc_free(path);
			return NULL;
		}
		if (st.st_dev != dev) {
			*p = '/';
			break;
		}
	}

	return path;	
}

/*
  work out the location of the snapshot for this share
 */
static const char *shadow_copy2_find_snapdir(TALLOC_CTX *mem_ctx, vfs_handle_struct *handle)
{
	const char *snapdir;
	char *mount_point;
	const char *ret;

	snapdir = lp_parm_const_string(SNUM(handle->conn), "shadow", "snapdir", NULL);
	if (snapdir == NULL) {
		return NULL;
	}
	/* if its an absolute path, we're done */
	if (*snapdir == '/') {
		return snapdir;
	}

	/* other its relative to the filesystem mount point */
	mount_point = find_mount_point(mem_ctx, handle);
	if (mount_point == NULL) {
		return NULL;
	}

	ret = talloc_asprintf(mem_ctx, "%s/%s", mount_point, snapdir);
	talloc_free(mount_point);
	return ret;
}

/*
  work out the location of the base directory for snapshots of this share
 */
static const char *shadow_copy2_find_basedir(TALLOC_CTX *mem_ctx, vfs_handle_struct *handle)
{
	const char *basedir = lp_parm_const_string(SNUM(handle->conn), "shadow", "basedir", NULL);

	/* other its the filesystem mount point */
	if (basedir == NULL) {
		basedir = find_mount_point(mem_ctx, handle);
	}

	return basedir;
}

/*
  convert a filename from a share relative path, to a path in the
  snapshot directory
 */
static char *convert_shadow2_name(vfs_handle_struct *handle, const char *fname)
{
	TALLOC_CTX *tmp_ctx = talloc_new(handle->data);
	const char *snapdir, *relpath, *baseoffset, *basedir;
	size_t baselen;
	char *ret;

	snapdir = shadow_copy2_find_snapdir(tmp_ctx, handle);
	if (snapdir == NULL) {
		DEBUG(2,("no snapdir found for share at %s\n", handle->conn->connectpath));
		talloc_free(tmp_ctx);
		return NULL;
	}

	basedir = shadow_copy2_find_basedir(tmp_ctx, handle);
	if (basedir == NULL) {
		DEBUG(2,("no basedir found for share at %s\n", handle->conn->connectpath));
		talloc_free(tmp_ctx);
		return NULL;
	}

	relpath = fname + GMT_NAME_LEN;
	baselen = strlen(basedir);
	baseoffset = handle->conn->connectpath + baselen;

	/* some sanity checks */
	if (strncmp(basedir, handle->conn->connectpath, baselen) != 0 ||
	    (handle->conn->connectpath[baselen] != 0 && handle->conn->connectpath[baselen] != '/')) {
		DEBUG(0,("convert_shadow2_name: basedir %s is not a parent of %s\n",
			 basedir, handle->conn->connectpath));
		talloc_free(tmp_ctx);
		return NULL;
	}

	if (*relpath == '/') relpath++;
	if (*baseoffset == '/') baseoffset++;

	ret = talloc_asprintf(handle->data, "%s/%.*s/%s/%s", 
			      snapdir, 
			      GMT_NAME_LEN, fname, 
			      baseoffset, 
			      relpath);
	DEBUG(6,("convert_shadow2_name: '%s' -> '%s'\n", fname, ret));
	talloc_free(tmp_ctx);
	return ret;
}


/*
  simple string hash
 */
static uint32 string_hash(const char *s)
{
        uint32 n = 0;
	while (*s) {
                n = ((n << 5) + n) ^ (uint32)(*s++);
        }
        return n;
}

/*
  modify a sbuf return to ensure that inodes in the shadow directory
  are different from those in the main directory
 */
static void convert_sbuf(vfs_handle_struct *handle, const char *fname, SMB_STRUCT_STAT *sbuf)
{
	if (lp_parm_bool(SNUM(handle->conn), "shadow", "fixinodes", False)) {		
		/* some snapshot systems, like GPFS, return the name
		   device:inode for the snapshot files as the current
		   files. That breaks the 'restore' button in the shadow copy
		   GUI, as the client gets a sharing violation.

		   This is a crude way of allowing both files to be
		   open at once. It has a slight chance of inode
		   number collision, but I can't see a better approach
		   without significant VFS changes
		*/
		uint32_t shash = string_hash(fname) & 0xFF000000;
		if (shash == 0) {
			shash = 1;
		}
		sbuf->st_ino ^= shash;
	}
}

static int shadow_copy2_rename(vfs_handle_struct *handle,
			const char *oldname, const char *newname)
{
	SHADOW2_NEXT2(RENAME, (handle, oldname, newname));
}

static int shadow_copy2_symlink(vfs_handle_struct *handle,
				const char *oldname, const char *newname)
{
	SHADOW2_NEXT2(SYMLINK, (handle, oldname, newname));
}

static int shadow_copy2_link(vfs_handle_struct *handle,
			  const char *oldname, const char *newname)
{
	SHADOW2_NEXT2(LINK, (handle, oldname, newname));
}

static int shadow_copy2_open(vfs_handle_struct *handle,
			     const char *fname, files_struct *fsp, int flags, mode_t mode)
{
	SHADOW2_NEXT(OPEN, (handle, name, fsp, flags, mode), int, -1);
}

static SMB_STRUCT_DIR *shadow_copy2_opendir(vfs_handle_struct *handle,
			  const char *fname, const char *mask, uint32 attr)
{
        SHADOW2_NEXT(OPENDIR, (handle, name, mask, attr), SMB_STRUCT_DIR *, NULL);
}

static int shadow_copy2_stat(vfs_handle_struct *handle,
		      const char *fname, SMB_STRUCT_STAT *sbuf)
{
        _SHADOW2_NEXT(STAT, (handle, name, sbuf), int, -1, convert_sbuf(handle, fname, sbuf));
}

static int shadow_copy2_lstat(vfs_handle_struct *handle,
		       const char *fname, SMB_STRUCT_STAT *sbuf)
{
        _SHADOW2_NEXT(LSTAT, (handle, name, sbuf), int, -1, convert_sbuf(handle, fname, sbuf));
}

static int shadow_copy2_fstat(vfs_handle_struct *handle, files_struct *fsp, SMB_STRUCT_STAT *sbuf)
{
	int ret = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	if (ret == 0 && shadow_copy2_match_name(fsp->fsp_name)) {
		convert_sbuf(handle, fsp->fsp_name, sbuf);
	}
	return ret;
}

static int shadow_copy2_unlink(vfs_handle_struct *handle, const char *fname)
{
        SHADOW2_NEXT(UNLINK, (handle, name), int, -1);
}

static int shadow_copy2_chmod(vfs_handle_struct *handle,
		       const char *fname, mode_t mode)
{
        SHADOW2_NEXT(CHMOD, (handle, name, mode), int, -1);
}

static int shadow_copy2_chown(vfs_handle_struct *handle,
		       const char *fname, uid_t uid, gid_t gid)
{
        SHADOW2_NEXT(CHOWN, (handle, name, uid, gid), int, -1);
}

static int shadow_copy2_chdir(vfs_handle_struct *handle,
		       const char *fname)
{
	SHADOW2_NEXT(CHDIR, (handle, name), int, -1);
}

static int shadow_copy2_ntimes(vfs_handle_struct *handle,
		       const char *fname, struct smb_file_time *ft)
{
        SHADOW2_NEXT(NTIMES, (handle, name, ft), int, -1);
}

static int shadow_copy2_readlink(vfs_handle_struct *handle,
				 const char *fname, char *buf, size_t bufsiz)
{
        SHADOW2_NEXT(READLINK, (handle, name, buf, bufsiz), int, -1);
}

static int shadow_copy2_mknod(vfs_handle_struct *handle,
		       const char *fname, mode_t mode, SMB_DEV_T dev)
{
        SHADOW2_NEXT(MKNOD, (handle, name, mode, dev), int, -1);
}

static char *shadow_copy2_realpath(vfs_handle_struct *handle,
			    const char *fname, char *resolved_path)
{
        SHADOW2_NEXT(REALPATH, (handle, name, resolved_path), char *, NULL);
}

static NTSTATUS shadow_copy2_get_nt_acl(vfs_handle_struct *handle,
			       const char *fname, uint32 security_info,
			       struct security_descriptor **ppdesc)
{
        SHADOW2_NTSTATUS_NEXT(GET_NT_ACL, (handle, name, security_info, ppdesc), NT_STATUS_ACCESS_DENIED);
}

static int shadow_copy2_mkdir(vfs_handle_struct *handle,  const char *fname, mode_t mode)
{
        SHADOW2_NEXT(MKDIR, (handle, name, mode), int, -1);
}

static int shadow_copy2_rmdir(vfs_handle_struct *handle,  const char *fname)
{
        SHADOW2_NEXT(RMDIR, (handle, name), int, -1);
}

static int shadow_copy2_chflags(vfs_handle_struct *handle, const char *fname, int flags)
{
        SHADOW2_NEXT(CHFLAGS, (handle, name, flags), int, -1);
}

static ssize_t shadow_copy2_getxattr(vfs_handle_struct *handle,
				  const char *fname, const char *aname, void *value, size_t size)
{
        SHADOW2_NEXT(GETXATTR, (handle, name, aname, value, size), ssize_t, -1);
}

static ssize_t shadow_copy2_lgetxattr(vfs_handle_struct *handle,
				      const char *fname, const char *aname, void *value, size_t size)
{
        SHADOW2_NEXT(LGETXATTR, (handle, name, aname, value, size), ssize_t, -1);
}

static ssize_t shadow_copy2_listxattr(struct vfs_handle_struct *handle, const char *fname, 
				      char *list, size_t size)
{
	SHADOW2_NEXT(LISTXATTR, (handle, name, list, size), ssize_t, -1);
}

static int shadow_copy2_removexattr(struct vfs_handle_struct *handle, const char *fname, 
				    const char *aname)
{
	SHADOW2_NEXT(REMOVEXATTR, (handle, name, aname), int, -1);
}

static int shadow_copy2_lremovexattr(struct vfs_handle_struct *handle, const char *fname, 
				     const char *aname)
{
	SHADOW2_NEXT(LREMOVEXATTR, (handle, name, aname), int, -1);
}

static int shadow_copy2_setxattr(struct vfs_handle_struct *handle, const char *fname, 
				 const char *aname, const void *value, size_t size, int flags)
{
	SHADOW2_NEXT(SETXATTR, (handle, name, aname, value, size, flags), int, -1);
}

static int shadow_copy2_lsetxattr(struct vfs_handle_struct *handle, const char *fname, 
				  const char *aname, const void *value, size_t size, int flags)
{
	SHADOW2_NEXT(LSETXATTR, (handle, name, aname, value, size, flags), int, -1);
}

static int shadow_copy2_chmod_acl(vfs_handle_struct *handle,
			   const char *fname, mode_t mode)
{
        /* If the underlying VFS doesn't have ACL support... */
        if (!handle->vfs_next.ops.chmod_acl) {
                errno = ENOSYS;
                return -1;
        }
        SHADOW2_NEXT(CHMOD_ACL, (handle, name, mode), int, -1);
}

static int shadow_copy2_get_shadow_copy2_data(vfs_handle_struct *handle, 
					      files_struct *fsp, 
					      SHADOW_COPY_DATA *shadow_copy2_data, 
					      bool labels)
{
	SMB_STRUCT_DIR *p;
	const char *snapdir;
	SMB_STRUCT_DIRENT *d;
	TALLOC_CTX *tmp_ctx = talloc_new(handle->data);

	snapdir = shadow_copy2_find_snapdir(tmp_ctx, handle);
	if (snapdir == NULL) {
		DEBUG(0,("shadow:snapdir not found for %s in get_shadow_copy_data\n",
			 handle->conn->connectpath));
		errno = EINVAL;
		talloc_free(tmp_ctx);
		return -1;
	}

	p = SMB_VFS_NEXT_OPENDIR(handle, snapdir, NULL, 0);

	if (!p) {
		DEBUG(2,("shadow_copy2: SMB_VFS_NEXT_OPENDIR() failed for '%s'"
			 " - %s\n", snapdir, strerror(errno)));
		talloc_free(tmp_ctx);
		errno = ENOSYS;
		return -1;
	}

	talloc_free(tmp_ctx);

	shadow_copy2_data->num_volumes = 0;
	shadow_copy2_data->labels      = NULL;

	while ((d = SMB_VFS_NEXT_READDIR(handle, p, NULL))) {
		SHADOW_COPY_LABEL *tlabels;

		/* ignore names not of the right form in the snapshot directory */
		if (!shadow_copy2_match_name(d->d_name)) {
			continue;
		}

		if (!labels) {
			/* the caller doesn't want the labels */
			shadow_copy2_data->num_volumes++;
			continue;
		}

		tlabels = talloc_realloc(shadow_copy2_data->mem_ctx,
					 shadow_copy2_data->labels,
					 SHADOW_COPY_LABEL, shadow_copy2_data->num_volumes+1);
		if (tlabels == NULL) {
			DEBUG(0,("shadow_copy2: out of memory\n"));
			SMB_VFS_NEXT_CLOSEDIR(handle, p);
			return -1;
		}

		strlcpy(tlabels[shadow_copy2_data->num_volumes], d->d_name, sizeof(*tlabels));
		shadow_copy2_data->num_volumes++;
		shadow_copy2_data->labels = tlabels;
	}

	SMB_VFS_NEXT_CLOSEDIR(handle,p);
	return 0;
}

/* VFS operations structure */

static vfs_op_tuple shadow_copy2_ops[] = {
        {SMB_VFS_OP(shadow_copy2_opendir),  SMB_VFS_OP_OPENDIR,  SMB_VFS_LAYER_TRANSPARENT},

	/* directory operations */
        {SMB_VFS_OP(shadow_copy2_mkdir),       SMB_VFS_OP_MKDIR,       SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_rmdir),       SMB_VFS_OP_RMDIR,       SMB_VFS_LAYER_TRANSPARENT},

	/* xattr and flags operations */
        {SMB_VFS_OP(shadow_copy2_chflags),     SMB_VFS_OP_CHFLAGS,     SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_getxattr),    SMB_VFS_OP_GETXATTR,    SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_lgetxattr),   SMB_VFS_OP_LGETXATTR,   SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_listxattr),   SMB_VFS_OP_LISTXATTR,   SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_removexattr), SMB_VFS_OP_REMOVEXATTR, SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_lremovexattr),SMB_VFS_OP_LREMOVEXATTR,SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_setxattr),    SMB_VFS_OP_SETXATTR,    SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_lsetxattr),   SMB_VFS_OP_LSETXATTR,   SMB_VFS_LAYER_TRANSPARENT},

        /* File operations */
        {SMB_VFS_OP(shadow_copy2_open),       SMB_VFS_OP_OPEN,     SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_rename),     SMB_VFS_OP_RENAME,   SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_stat),       SMB_VFS_OP_STAT,     SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_lstat),      SMB_VFS_OP_LSTAT,    SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_fstat),      SMB_VFS_OP_FSTAT,    SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_unlink),     SMB_VFS_OP_UNLINK,   SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_chmod),      SMB_VFS_OP_CHMOD,    SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_chown),      SMB_VFS_OP_CHOWN,    SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_chdir),      SMB_VFS_OP_CHDIR,    SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_ntimes),     SMB_VFS_OP_NTIMES,   SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_symlink),    SMB_VFS_OP_SYMLINK,  SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_readlink),   SMB_VFS_OP_READLINK, SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_link),       SMB_VFS_OP_LINK,     SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_mknod),      SMB_VFS_OP_MKNOD,    SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(shadow_copy2_realpath),   SMB_VFS_OP_REALPATH, SMB_VFS_LAYER_TRANSPARENT},

        /* NT File ACL operations */
        {SMB_VFS_OP(shadow_copy2_get_nt_acl), SMB_VFS_OP_GET_NT_ACL, SMB_VFS_LAYER_TRANSPARENT},

        /* POSIX ACL operations */
        {SMB_VFS_OP(shadow_copy2_chmod_acl), SMB_VFS_OP_CHMOD_ACL, SMB_VFS_LAYER_TRANSPARENT},

	/* special shadown copy op */
	{SMB_VFS_OP(shadow_copy2_get_shadow_copy2_data), 
	 SMB_VFS_OP_GET_SHADOW_COPY_DATA,SMB_VFS_LAYER_OPAQUE},

	{SMB_VFS_OP(NULL), SMB_VFS_OP_NOOP, SMB_VFS_LAYER_NOOP}
};

NTSTATUS vfs_shadow_copy2_init(void);
NTSTATUS vfs_shadow_copy2_init(void)
{
	NTSTATUS ret;

	ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "shadow_copy2", shadow_copy2_ops);

	if (!NT_STATUS_IS_OK(ret))
		return ret;

	vfs_shadow_copy2_debug_level = debug_add_class("shadow_copy2");
	if (vfs_shadow_copy2_debug_level == -1) {
		vfs_shadow_copy2_debug_level = DBGC_VFS;
		DEBUG(0, ("%s: Couldn't register custom debugging class!\n",
			"vfs_shadow_copy2_init"));
	} else {
		DEBUG(10, ("%s: Debug class number of '%s': %d\n", 
			"vfs_shadow_copy2_init","shadow_copy2",vfs_shadow_copy2_debug_level));
	}

	return ret;
}
