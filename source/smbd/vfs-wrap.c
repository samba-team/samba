/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Wrap disk only vfs functions to sidestep dodgy compilers.
   Copyright (C) Tim Potter 1998
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

/* Check for NULL pointer parameters in vfswrap_* functions */

#define VFS_CHECK_NULL

/* We don't want to have NULL function pointers lying around.  Someone
   is sure to try and execute them.  These stubs are used to prevent
   this possibility. */

int vfswrap_dummy_connect(connection_struct *conn, char *service, char *user)
{
    return 0;    /* Return >= 0 for success */
}

void vfswrap_dummy_disconnect(connection_struct *conn)
{
}

/* Disk operations */

SMB_BIG_UINT vfswrap_disk_free(connection_struct *conn, char *path, BOOL small_query, SMB_BIG_UINT *bsize, 
			       SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize)
{
    SMB_BIG_UINT result;

#ifdef VFS_CHECK_NULL
    if ((path == NULL) || (bsize == NULL) || (dfree == NULL) ||
	(dsize == NULL)) {
	
	smb_panic("NULL pointer passed to vfswrap_disk_free() function\n");
    }
#endif

    result = sys_disk_free(path, small_query, bsize, dfree, dsize);
    return result;
}
    
/* Directory operations */

DIR *vfswrap_opendir(connection_struct *conn, char *fname)
{
    DIR *result;

    START_PROFILE(syscall_opendir);

#ifdef VFS_CHECK_NULL
    if (fname == NULL) {
	smb_panic("NULL pointer passed to vfswrap_opendir()\n");
    }
#endif

    result = opendir(fname);
    END_PROFILE(syscall_opendir);
    return result;
}

struct dirent *vfswrap_readdir(connection_struct *conn, DIR *dirp)
{
    struct dirent *result;

    START_PROFILE(syscall_readdir);

#ifdef VFS_CHECK_NULL
    if (dirp == NULL) {
	smb_panic("NULL pointer passed to vfswrap_readdir()\n");
    }
#endif

    result = readdir(dirp);
    END_PROFILE(syscall_readdir);
    return result;
}

int vfswrap_mkdir(connection_struct *conn, char *path, mode_t mode)
{
	int result;
	BOOL has_dacl = False;

	START_PROFILE(syscall_mkdir);

#ifdef VFS_CHECK_NULL
	if (path == NULL) {
		smb_panic("NULL pointer passed to vfswrap_mkdir()\n");
	}
#endif

	if (lp_inherit_acls(SNUM(conn)) && (has_dacl = directory_has_default_acl(parent_dirname(path))))
		mode = 0777;

	result = mkdir(path, mode);

	if (result == 0 && !has_dacl) {
		/*
		 * We need to do this as the default behavior of POSIX ACLs	
		 * is to set the mask to be the requested group permission
		 * bits, not the group permission bits to be the requested
		 * group permission bits. This is not what we want, as it will
		 * mess up any inherited ACL bits that were set. JRA.
		 */
		int saved_errno = errno; /* We may get ENOSYS */
		if (conn->vfs_ops.chmod_acl != NULL) {
			if ((conn->vfs_ops.chmod_acl(conn, path, mode) == -1) && (errno == ENOSYS))
				errno = saved_errno;
		}
	}

	END_PROFILE(syscall_mkdir);
	return result;
}

int vfswrap_rmdir(connection_struct *conn, char *path)
{
    int result;

    START_PROFILE(syscall_rmdir);

#ifdef VFS_CHECK_NULL
    if (path == NULL) {
	smb_panic("NULL pointer passed to vfswrap_rmdir()\n");
    }
#endif

    result = rmdir(path);
    END_PROFILE(syscall_rmdir);
    return result;
}

int vfswrap_closedir(connection_struct *conn, DIR *dirp)
{
    int result;

    START_PROFILE(syscall_closedir);

#ifdef VFS_CHECK_NULL
    if (dirp == NULL) {
	smb_panic("NULL pointer passed to vfswrap_closedir()\n");
    }
#endif

    result = closedir(dirp);
    END_PROFILE(syscall_closedir);
    return result;
}

/* File operations */
    
int vfswrap_open(connection_struct *conn, char *fname, int flags, mode_t mode)
{
	int result;

	START_PROFILE(syscall_open);

#ifdef VFS_CHECK_NULL
	if (fname == NULL) {
		smb_panic("NULL pointer passed to vfswrap_open()\n");
	}
#endif

	result = sys_open(fname, flags, mode);
	END_PROFILE(syscall_open);
	return result;
}

int vfswrap_close(files_struct *fsp, int fd)
{
    int result;

    START_PROFILE(syscall_close);

    result = close(fd);
    END_PROFILE(syscall_close);
    return result;
}

ssize_t vfswrap_read(files_struct *fsp, int fd, void *data, size_t n)
{
    ssize_t result;

    START_PROFILE_BYTES(syscall_read, n);

#ifdef VFS_CHECK_NULL
    if (data == NULL) {
	smb_panic("NULL pointer passed to vfswrap_read()\n");
    }
#endif

    result = read(fd, data, n);
    END_PROFILE(syscall_read);
    return result;
}

ssize_t vfswrap_write(files_struct *fsp, int fd, const void *data, size_t n)
{
    ssize_t result;

    START_PROFILE_BYTES(syscall_write, n);

#ifdef VFS_CHECK_NULL
    if (data == NULL) {
	smb_panic("NULL pointer passed to vfswrap_write()\n");
    }
#endif

    result = write(fd, data, n);
    END_PROFILE(syscall_write);
    return result;
}

SMB_OFF_T vfswrap_lseek(files_struct *fsp, int filedes, SMB_OFF_T offset, int whence)
{
	SMB_OFF_T result;

	START_PROFILE(syscall_lseek);

	result = sys_lseek(filedes, offset, whence);

	/*
	 * We want to maintain the fiction that we can seek
	 * on a fifo for file system purposes. This allows
	 * people to set up UNIX fifo's that feed data to Windows
	 * applications. JRA.
	 */

	if((result == -1) && (errno == ESPIPE)) {
		result = 0;
		errno = 0;
	}

	END_PROFILE(syscall_lseek);
	return result;
}

/*********************************************************
 For rename across filesystems Patch from Warren Birnbaum 
 <warrenb@hpcvscdp.cv.hp.com>
**********************************************************/

static int copy_reg(char *source, const char *dest)
{
	SMB_STRUCT_STAT source_stats;
	int ifd;
	int ofd;

	if (sys_lstat (source, &source_stats) == -1)
		return -1;

	if (!S_ISREG (source_stats.st_mode))
		return -1;

	if (unlink (dest) && errno != ENOENT)
		return -1;

	if((ifd = sys_open (source, O_RDONLY, 0)) < 0)
		return -1;

	if((ofd = sys_open (dest, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0 ) {
		int saved_errno = errno;
		close (ifd);
		errno = saved_errno;
		return -1;
	}

	if (transfer_file(ifd, ofd, (size_t)-1) == -1) {
		int saved_errno = errno;
		close (ifd);
		close (ofd);
		unlink (dest);
		errno = saved_errno;
		return -1;
	}

	if (close (ifd) == -1) {
		int saved_errno = errno;
		close (ofd);
		errno = saved_errno;
		return -1;
	}
	if (close (ofd) == -1) 
		return -1;

	/*
	 * chown turns off set[ug]id bits for non-root,
	 * so do the chmod last.
	 */

	/* Try to copy the old file's modtime and access time.  */
	{
		struct utimbuf tv;

		tv.actime = source_stats.st_atime;
		tv.modtime = source_stats.st_mtime;
		utime (dest, &tv);
	}

	/*
	 * Try to preserve ownership.  For non-root it might fail, but that's ok.
	 * But root probably wants to know, e.g. if NFS disallows it.
	 */

	if ((chown(dest, source_stats.st_uid, source_stats.st_gid) == -1) && (errno != EPERM))
		return -1;

	if (chmod (dest, source_stats.st_mode & 07777))
		return -1;

	if (unlink (source) == -1)
		return -1;

	return 0;
}

int vfswrap_rename(connection_struct *conn, char *oldname, char *newname)
{
	int result;

	START_PROFILE(syscall_rename);

#ifdef VFS_CHECK_NULL
	if ((oldname == NULL) || (newname == NULL)) {
		smb_panic("NULL pointer passed to vfswrap_rename()\n");
	}
#endif

	result = rename(oldname, newname);
	if (errno == EXDEV) {
		/* Rename across filesystems needed. */
		result = copy_reg(oldname, newname);
	}
	END_PROFILE(syscall_rename);
	return result;
}

int vfswrap_fsync(files_struct *fsp, int fd)
{
#ifdef HAVE_FSYNC
    int result;

    START_PROFILE(syscall_fsync);

    result = fsync(fd);
    END_PROFILE(syscall_fsync);
    return result;
#else
	return 0;
#endif
}

int vfswrap_stat(connection_struct *conn, char *fname, SMB_STRUCT_STAT *sbuf)
{
    int result;

    START_PROFILE(syscall_stat);

#ifdef VFS_CHECK_NULL
    if ((fname == NULL) || (sbuf == NULL)) {
	smb_panic("NULL pointer passed to vfswrap_stat()\n");
    }
#endif

    result = sys_stat(fname, sbuf);
    END_PROFILE(syscall_stat);
    return result;
}

int vfswrap_fstat(files_struct *fsp, int fd, SMB_STRUCT_STAT *sbuf)
{
    int result;

    START_PROFILE(syscall_fstat);

#ifdef VFS_CHECK_NULL
    if (sbuf == NULL) {
	smb_panic("NULL pointer passed to vfswrap_fstat()\n");
    }
#endif

    result = sys_fstat(fd, sbuf);
    END_PROFILE(syscall_fstat);
    return result;
}

int vfswrap_lstat(connection_struct *conn, char *path, SMB_STRUCT_STAT *sbuf)
{
    int result;

    START_PROFILE(syscall_lstat);

#ifdef VFS_CHECK_NULL
    if ((path == NULL) || (sbuf == NULL)) {
	smb_panic("NULL pointer passed to vfswrap_lstat()\n");
    }
#endif

    result = sys_lstat(path, sbuf);
    END_PROFILE(syscall_lstat);
    return result;
}

int vfswrap_unlink(connection_struct *conn, char *path)
{
    int result;

    START_PROFILE(syscall_unlink);

#ifdef VFS_CHECK_NULL
    if (path == NULL) {
	smb_panic("NULL pointer passed to vfswrap_unlink()\n");
    }
#endif

    result = unlink(path);
    END_PROFILE(syscall_unlink);
    return result;
}

int vfswrap_chmod(connection_struct *conn, char *path, mode_t mode)
{
    int result;

    START_PROFILE(syscall_chmod);

#ifdef VFS_CHECK_NULL
    if (path == NULL) {
	smb_panic("NULL pointer passed to vfswrap_chmod()\n");
    }
#endif

	/*
	 * We need to do this due to the fact that the default POSIX ACL
	 * chmod modifies the ACL *mask* for the group owner, not the
	 * group owner bits directly. JRA.
	 */

	
	if (conn->vfs_ops.chmod_acl != NULL) {
		int saved_errno = errno; /* We might get ENOSYS */
		if ((result = conn->vfs_ops.chmod_acl(conn, path, mode)) == 0) {
			END_PROFILE(syscall_chmod);
			return result;
		}
		/* Error - return the old errno. */
		errno = saved_errno;
	}

    result = chmod(path, mode);
    END_PROFILE(syscall_chmod);
    return result;
}

int vfswrap_fchmod(files_struct *fsp, int fd, mode_t mode)
{
    int result;
	struct vfs_ops *vfs_ops = &fsp->conn->vfs_ops;
	
    START_PROFILE(syscall_fchmod);

	/*
	 * We need to do this due to the fact that the default POSIX ACL
	 * chmod modifies the ACL *mask* for the group owner, not the
	 * group owner bits directly. JRA.
	 */
	
	if (vfs_ops->fchmod_acl != NULL) {
		int saved_errno = errno; /* We might get ENOSYS */
		if ((result = vfs_ops->fchmod_acl(fsp, fd, mode)) == 0) {
			END_PROFILE(syscall_chmod);
			return result;
		}
		/* Error - return the old errno. */
		errno = saved_errno;
	}

    result = fchmod(fd, mode);
    END_PROFILE(syscall_fchmod);
    return result;
}

int vfswrap_chown(connection_struct *conn, char *path, uid_t uid, gid_t gid)
{
    int result;

    START_PROFILE(syscall_chown);

#ifdef VFS_CHECK_NULL
    if (path == NULL) {
	smb_panic("NULL pointer passed to vfswrap_chown()\n");
    }
#endif

    result = sys_chown(path, uid, gid);
    END_PROFILE(syscall_chown);
    return result;
}

int vfswrap_fchown(files_struct *fsp, int fd, uid_t uid, gid_t gid)
{
    int result;

    START_PROFILE(syscall_fchown);

    result = fchown(fd, uid, gid);
    END_PROFILE(syscall_fchown);
    return result;
}

int vfswrap_chdir(connection_struct *conn, char *path)
{
    int result;

    START_PROFILE(syscall_chdir);

#ifdef VFS_CHECK_NULL
    if (path == NULL) {
	smb_panic("NULL pointer passed to vfswrap_chdir()\n");
    }
#endif

    result = chdir(path);
    END_PROFILE(syscall_chdir);
    return result;
}

char *vfswrap_getwd(connection_struct *conn, char *path)
{
    char *result;

    START_PROFILE(syscall_getwd);

#ifdef VFS_CHECK_NULL
    if (path == NULL) {
	smb_panic("NULL pointer passed to vfswrap_getwd()\n");
    }
#endif

    result = sys_getwd(path);
    END_PROFILE(syscall_getwd);
    return result;
}

int vfswrap_utime(connection_struct *conn, char *path, struct utimbuf *times)
{
    int result;

    START_PROFILE(syscall_utime);

#ifdef VFS_CHECK_NULL
    if ((path == NULL) || (times == NULL)) {
	smb_panic("NULL pointer passed to vfswrap_utime()\n");
    }
#endif

    result = utime(path, times);
    END_PROFILE(syscall_utime);
    return result;
}

/*********************************************************************
 A version of ftruncate that will write the space on disk if strict
 allocate is set.
**********************************************************************/

static int strict_allocate_ftruncate(files_struct *fsp, int fd, SMB_OFF_T len)
{
	struct vfs_ops *vfs_ops = &fsp->conn->vfs_ops;
	SMB_STRUCT_STAT st;
	SMB_OFF_T currpos = vfs_ops->lseek(fsp, fd, 0, SEEK_CUR);
	unsigned char zero_space[4096];
	SMB_OFF_T space_to_write;

	if (currpos == -1)
		return -1;

	if (vfs_ops->fstat(fsp, fd, &st) == -1)
		return -1;

#ifdef S_ISFIFO
	if (S_ISFIFO(st.st_mode))
		return 0;
#endif

	if (st.st_size == len)
		return 0;

	/* Shrink - just ftruncate. */
	if (st.st_size > len)
		return sys_ftruncate(fd, len);

	/* Write out the real space on disk. */
	if (vfs_ops->lseek(fsp, fd, st.st_size, SEEK_SET) != st.st_size)
		return -1;

	space_to_write = len - st.st_size;

	memset(zero_space, '\0', sizeof(zero_space));
	while ( space_to_write > 0) {
		SMB_OFF_T retlen;
		SMB_OFF_T current_len_to_write = MIN(sizeof(zero_space),space_to_write);

		retlen = vfs_ops->write(fsp,fsp->fd,(char *)zero_space,current_len_to_write);
		if (retlen <= 0)
			return -1;

		space_to_write -= retlen;
	}

	/* Seek to where we were */
	if (vfs_ops->lseek(fsp, fd, currpos, SEEK_SET) != currpos)
		return -1;

	return 0;
}

int vfswrap_ftruncate(files_struct *fsp, int fd, SMB_OFF_T len)
{
	int result = -1;
	struct vfs_ops *vfs_ops = &fsp->conn->vfs_ops;
	SMB_STRUCT_STAT st;
	char c = 0;
	SMB_OFF_T currpos;

	START_PROFILE(syscall_ftruncate);

	if (lp_strict_allocate(SNUM(fsp->conn))) {
		result = strict_allocate_ftruncate(fsp, fd, len);
		END_PROFILE(syscall_ftruncate);
		return result;
	}

	/* we used to just check HAVE_FTRUNCATE_EXTEND and only use
	   sys_ftruncate if the system supports it. Then I discovered that
	   you can have some filesystems that support ftruncate
	   expansion and some that don't! On Linux fat can't do
	   ftruncate extend but ext2 can. */

	result = sys_ftruncate(fd, len);
	if (result == 0)
		goto done;

	/* According to W. R. Stevens advanced UNIX prog. Pure 4.3 BSD cannot
	   extend a file with ftruncate. Provide alternate implementation
	   for this */
	currpos = vfs_ops->lseek(fsp, fd, 0, SEEK_CUR);
	if (currpos == -1) {
		goto done;
	}

	/* Do an fstat to see if the file is longer than the requested
	   size in which case the ftruncate above should have
	   succeeded or shorter, in which case seek to len - 1 and
	   write 1 byte of zero */
	if (vfs_ops->fstat(fsp, fd, &st) == -1) {
		goto done;
	}

#ifdef S_ISFIFO
	if (S_ISFIFO(st.st_mode)) {
		result = 0;
		goto done;
	}
#endif

	if (st.st_size == len) {
		result = 0;
		goto done;
	}

	if (st.st_size > len) {
		/* the sys_ftruncate should have worked */
		goto done;
	}

	if (vfs_ops->lseek(fsp, fd, len-1, SEEK_SET) != len -1)
		goto done;

	if (vfs_ops->write(fsp, fd, &c, 1)!=1)
		goto done;

	/* Seek to where we were */
	if (vfs_ops->lseek(fsp, fd, currpos, SEEK_SET) != currpos)
		goto done;
	result = 0;

  done:

	END_PROFILE(syscall_ftruncate);
	return result;
}

BOOL vfswrap_lock(files_struct *fsp, int fd, int op, SMB_OFF_T offset, SMB_OFF_T count, int type)
{
    BOOL result;

    START_PROFILE(syscall_fcntl_lock);

    result =  fcntl_lock(fd, op, offset, count,type);
    END_PROFILE(syscall_fcntl_lock);
    return result;
}

int vfswrap_symlink(connection_struct *conn, const char *oldpath, const char *newpath)
{
    int result;

    START_PROFILE(syscall_symlink);

#ifdef VFS_CHECK_NULL
    if ((oldpath == NULL) || (newpath == NULL))
		smb_panic("NULL pointer passed to vfswrap_symlink()\n");
#endif

    result = sys_symlink(oldpath, newpath);
    END_PROFILE(syscall_symlink);
    return result;
}

int vfswrap_readlink(connection_struct *conn, const char *path, char *buf, size_t bufsiz)
{
    int result;

    START_PROFILE(syscall_readlink);

#ifdef VFS_CHECK_NULL
    if ((path == NULL) || (buf == NULL))
		smb_panic("NULL pointer passed to vfswrap_readlink()\n");
#endif

    result = sys_readlink(path, buf, bufsiz);
    END_PROFILE(syscall_readlink);
    return result;
}

int vfswrap_link(connection_struct *conn, const char *oldpath, const char *newpath)
{
	int result;

	START_PROFILE(syscall_link);

#ifdef VFS_CHECK_NULL
	if ((oldpath == NULL) || (newpath == NULL))
                smb_panic("NULL pointer passed to vfswrap_link()\n");
#endif
	result = sys_link(oldpath, newpath);
	END_PROFILE(syscall_link);
	return result;
}

int vfswrap_mknod(connection_struct *conn, const char *pathname, mode_t mode, SMB_DEV_T dev)
{
	int result;

	START_PROFILE(syscall_mknod);

#ifdef VFS_CHECK_NULL
	if (pathname == NULL)
                smb_panic("NULL pointer passed to vfswrap_mknod()\n");
#endif
	result = sys_mknod(pathname, mode, dev);
	END_PROFILE(syscall_mknod);
	return result;
}

char *vfswrap_realpath(connection_struct *conn, const char *path, char *resolved_path)
{
	char *result;

	START_PROFILE(syscall_realpath);

#ifdef VFS_CHECK_NULL
	if ((path == NULL) || (resolved_path == NULL))
                smb_panic("NULL pointer passed to vfswrap_realpath()\n");
#endif
	result = sys_realpath(path, resolved_path);
	END_PROFILE(syscall_realpath);
	return result;
}

size_t vfswrap_fget_nt_acl(files_struct *fsp, int fd, SEC_DESC **ppdesc)
{
	size_t result;

	START_PROFILE(fget_nt_acl);
	result = get_nt_acl(fsp, ppdesc);
	END_PROFILE(fget_nt_acl);
	return result;
}

size_t vfswrap_get_nt_acl(files_struct *fsp, char *name, SEC_DESC **ppdesc)
{
	size_t result;

	START_PROFILE(get_nt_acl);
	result = get_nt_acl(fsp, ppdesc);
	END_PROFILE(get_nt_acl);
	return result;
}

BOOL vfswrap_fset_nt_acl(files_struct *fsp, int fd, uint32 security_info_sent, SEC_DESC *psd)
{
	BOOL result;

	START_PROFILE(fset_nt_acl);
	result = set_nt_acl(fsp, security_info_sent, psd);
	END_PROFILE(fset_nt_acl);
	return result;
}

BOOL vfswrap_set_nt_acl(files_struct *fsp, char *name, uint32 security_info_sent, SEC_DESC *psd)
{
	BOOL result;

	START_PROFILE(set_nt_acl);
	result = set_nt_acl(fsp, security_info_sent, psd);
	END_PROFILE(set_nt_acl);
	return result;
}

int vfswrap_chmod_acl(connection_struct *conn, char *name, mode_t mode)
{
	int result;

	START_PROFILE(chmod_acl);
	result = chmod_acl(name, mode);
	END_PROFILE(chmod_acl);
	return result;
}

int vfswrap_fchmod_acl(files_struct *fsp, int fd, mode_t mode)
{
	int result;

	START_PROFILE(fchmod_acl);
	result = fchmod_acl(fd, mode);
	END_PROFILE(fchmod_acl);
	return result;
}
