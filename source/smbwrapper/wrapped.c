/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   SMB wrapper functions
   Copyright (C) Andrew Tridgell 1998
   
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


/* we don't want prototypes for this code */
#define NO_PROTO

#include "wrapper.h"

 int open(const char *name, int flags, mode_t mode)
{
	if (smbw_path(name)) {
		return smbw_open(name, flags, mode);
	}

	return real_open(name, flags, mode);
}

#ifdef HAVE__OPEN
 int _open(const char *name, int flags, mode_t mode) 
{
	return open(name, flags, mode);
}
#elif HAVE___OPEN
 int __open(const char *name, int flags, mode_t mode) 
{
	return open(name, flags, mode);
}
#endif


#ifdef HAVE_OPEN64
 int open64(const char *name, int flags, mode_t mode)
{
	if (smbw_path(name)) {
		return smbw_open(name, flags, mode);
	}

	return real_open64(name, flags, mode);
}
#endif

#ifndef NO_OPEN64_ALIAS
#ifdef HAVE__OPEN64
 int _open64(const char *name, int flags, mode_t mode) 
{
   return open64(name, flags, mode);
}
#elif HAVE___OPEN64
 int __open64(const char *name, int flags, mode_t mode) 
{
   return open64(name, flags, mode);
}
#endif
#endif

#ifdef HAVE_PREAD
 ssize_t pread(int fd, void *buf, size_t size, off_t ofs)
{
	if (smbw_fd(fd)) {
		return smbw_pread(fd, buf, size, ofs);
	}

	return real_pread(fd, buf, size, ofs);
}
#endif

#ifdef HAVE_PREAD64
 ssize_t pread64(int fd, void *buf, size_t size, off64_t ofs)
{
	if (smbw_fd(fd)) {
		return smbw_pread(fd, buf, size, ofs);
	}

	return real_pread64(fd, buf, size, ofs);
}
#endif

#ifdef HAVE_PWRITE
 ssize_t pwrite(int fd, void *buf, size_t size, off_t ofs)
{
	if (smbw_fd(fd)) {
		return smbw_pwrite(fd, buf, size, ofs);
	}

	return real_pwrite(fd, buf, size, ofs);
}
#endif

#ifdef HAVE_PWRITE64
 ssize_t pwrite64(int fd, void *buf, size_t size, off64_t ofs)
{
	if (smbw_fd(fd)) {
		return smbw_pwrite(fd, buf, size, ofs);
	}

	return real_pwrite64(fd, buf, size, ofs);
}
#endif


 int chdir(const char *name)
{
	return smbw_chdir(name);
}

#ifdef HAVE___CHDIR
 int __chdir(const char *name)
{
	return chdir(name);
}
#elif HAVE__CHDIR
 int _chdir(const char *name)
{
	return chdir(name);
}
#endif


 int close(int fd)
{
	if (smbw_fd(fd)) {
		return smbw_close(fd);
	}

	return real_close(fd);
}

#ifdef HAVE___CLOSE
 int __close(int fd)
{
	return close(fd);
}
#elif HAVE__CLOSE
 int _close(int fd)
{
	return close(fd);
}
#endif


 int fchdir(int fd)
{
	if (smbw_fd(fd)) {
		return smbw_fchdir(fd);
	}

	return real_fchdir(fd);
}

#ifdef HAVE___FCHDIR
 int __fchdir(int fd)
{
	return fchdir(fd);
}
#elif HAVE__FCHDIR
 int _fchdir(int fd)
{
	return fchdir(fd);
}
#endif


 int fcntl(int fd, int cmd, long arg)
{
	if (smbw_fd(fd)) {
		return smbw_fcntl(fd, cmd, arg);
	}

	return real_fcntl(fd, cmd, arg);
}


#ifdef HAVE___FCNTL
 int __fcntl(int fd, int cmd, long arg)
{
	return fcntl(fd, cmd, arg);
}
#elif HAVE__FCNTL
 int _fcntl(int fd, int cmd, long arg)
{
	return fcntl(fd, cmd, arg);
}
#endif



#ifdef HAVE_GETDENTS
 int getdents(int fd, struct dirent *dirp, unsigned int count)
{
	if (smbw_fd(fd)) {
		return smbw_getdents(fd, dirp, count);
	}

	return real_getdents(fd, dirp, count);
}
#endif

#ifdef HAVE___GETDENTS
 int __getdents(int fd, struct dirent *dirp, unsigned int count)
{
	return getdents(fd, dirp, count);
}
#elif HAVE__GETDENTS
 int _getdents(int fd, struct dirent *dirp, unsigned int count)
{
	return getdents(fd, dirp, count);
}
#endif


 off_t lseek(int fd, off_t offset, int whence)
{
	if (smbw_fd(fd)) {
		return smbw_lseek(fd, offset, whence);
	}

	return real_lseek(fd, offset, whence);
}

#ifdef HAVE___LSEEK
 off_t __lseek(int fd, off_t offset, int whence)
{
	return lseek(fd, offset, whence);
}
#elif HAVE__LSEEK
 off_t _lseek(int fd, off_t offset, int whence)
{
	return lseek(fd, offset, whence);
}
#endif


 ssize_t read(int fd, void *buf, size_t count)
{
	if (smbw_fd(fd)) {
		return smbw_read(fd, buf, count);
	}

	return real_read(fd, buf, count);
}

#ifdef HAVE___READ
 ssize_t __read(int fd, void *buf, size_t count)
{
	return read(fd, buf, count);
}
#elif HAVE__READ
 ssize_t _read(int fd, void *buf, size_t count)
{
	return read(fd, buf, count);
}
#endif


 ssize_t write(int fd, void *buf, size_t count)
{
	if (smbw_fd(fd)) {
		return smbw_write(fd, buf, count);
	}

	return real_write(fd, buf, count);
}

#ifdef HAVE___WRITE
 ssize_t __write(int fd, void *buf, size_t count)
{
	return write(fd, buf, count);
}
#elif HAVE__WRITE
 ssize_t _write(int fd, void *buf, size_t count)
{
	return write(fd, buf, count);
}
#endif



 int access(const char *name, int mode)
{
	if (smbw_path(name)) {
		return smbw_access(name, mode);
	}

	return real_access(name, mode);
}



 int chmod(const char *name,mode_t mode)
{
	if (smbw_path(name)) {
		return smbw_chmod(name, mode);
	}

	return real_chmod(name, mode);
}



 int chown(const char *name,uid_t owner, gid_t group)
{
	if (smbw_path(name)) {
		return smbw_chown(name, owner, group);
	}

	return real_chown(name, owner, group);
}

#ifdef LINUX
 int __fxstat(int vers, int fd, struct stat *st)
{
	struct kernel_stat kbuf;
	int ret;

	if (smbw_fd(fd)) {
		return smbw_fstat(fd, st);
	}

	switch (vers) {
	case _STAT_VER_LINUX_OLD:
		/* Nothing to do.  The struct is in the form the kernel expects
		   it to be.  */
		return real_fstat(fd, (struct kernel_stat *)st);
		break;

	case _STAT_VER_LINUX:
		/* Do the system call.  */
		ret = real_fstat(fd, &kbuf);

		st->st_dev = kbuf.st_dev;
#ifdef _HAVE___PAD1
		st->__pad1 = 0;
#endif
		st->st_ino = kbuf.st_ino;
		st->st_mode = kbuf.st_mode;
		st->st_nlink = kbuf.st_nlink;
		st->st_uid = kbuf.st_uid;
		st->st_gid = kbuf.st_gid;
		st->st_rdev = kbuf.st_rdev;
#ifdef _HAVE___PAD2
		st->__pad2 = 0;
#endif
		st->st_size = kbuf.st_size;
		st->st_blksize = kbuf.st_blksize;
		st->st_blocks = kbuf.st_blocks;
		st->st_atime = kbuf.st_atime;
#ifdef _HAVE___UNUSED1
		st->__unused1 = 0;
#endif
		st->st_mtime = kbuf.st_mtime;
#ifdef _HAVE___UNUSED2
		st->__unused2 = 0;
#endif
		st->st_ctime = kbuf.st_ctime;
#ifdef _HAVE___UNUSED3
		st->__unused3 = 0;
#endif
#ifdef _HAVE___UNUSED4
		st->__unused4 = 0;
#endif
#ifdef _HAVE___UNUSED5
		st->__unused5 = 0;
#endif
		return ret;

	default:
		errno = EINVAL;
		return -1;
	}
}
#endif


 char *getcwd(char *buf, size_t size)
{
	return smbw_getcwd(buf, size);
}


#ifdef LINUX
 int __lxstat(int vers, const char *name, struct stat *st)
{
	struct kernel_stat kbuf;
	int ret;

	if (smbw_path(name)) {
		return smbw_stat(name, st);
	}

	switch (vers) {
	case _STAT_VER_LINUX_OLD:
		/* Nothing to do.  The struct is in the form the kernel expects
		   it to be.  */
		return real_lstat(name, (struct kernel_stat *)st);
		break;

	case _STAT_VER_LINUX:
		/* Do the system call.  */
		ret = real_lstat(name, &kbuf);

		st->st_dev = kbuf.st_dev;
#ifdef _HAVE___PAD1
		st->__pad1 = 0;
#endif
		st->st_ino = kbuf.st_ino;
		st->st_mode = kbuf.st_mode;
		st->st_nlink = kbuf.st_nlink;
		st->st_uid = kbuf.st_uid;
		st->st_gid = kbuf.st_gid;
		st->st_rdev = kbuf.st_rdev;
#ifdef _HAVE___PAD2
		st->__pad2 = 0;
#endif
		st->st_size = kbuf.st_size;
		st->st_blksize = kbuf.st_blksize;
		st->st_blocks = kbuf.st_blocks;
		st->st_atime = kbuf.st_atime;
#ifdef _HAVE___UNUSED1
		st->__unused1 = 0;
#endif
		st->st_mtime = kbuf.st_mtime;
#ifdef _HAVE___UNUSED2
		st->__unused2 = 0;
#endif
		st->st_ctime = kbuf.st_ctime;
#ifdef _HAVE___UNUSED3
		st->__unused3 = 0;
#endif
#ifdef _HAVE___UNUSED4
		st->__unused4 = 0;
#endif
#ifdef _HAVE___UNUSED5
		st->__unused5 = 0;
#endif
		return ret;

	default:
		errno = EINVAL;
		return -1;
	}
}
#endif


 int mkdir(const char *name, mode_t mode)
{
	if (smbw_path(name)) {
		return smbw_mkdir(name, mode);
	}

	return real_mkdir(name, mode);
}


#ifdef LINUX
 int __xstat(int vers, const char *name, struct stat *st)
{
	struct kernel_stat kbuf;
	int ret;

	if (smbw_path(name)) {
		return smbw_stat(name, st);
	}

	switch (vers) {
	case _STAT_VER_LINUX_OLD:
		/* Nothing to do.  The struct is in the form the kernel expects
		   it to be.  */
		return real_stat(name, (struct kernel_stat *)st);
		break;

	case _STAT_VER_LINUX:
		/* Do the system call.  */
		ret = real_stat(name, &kbuf);

		st->st_dev = kbuf.st_dev;
#ifdef _HAVE___PAD1
		st->__pad1 = 0;
#endif
		st->st_ino = kbuf.st_ino;
		st->st_mode = kbuf.st_mode;
		st->st_nlink = kbuf.st_nlink;
		st->st_uid = kbuf.st_uid;
		st->st_gid = kbuf.st_gid;
		st->st_rdev = kbuf.st_rdev;
#ifdef _HAVE___PAD2
		st->__pad2 = 0;
#endif
		st->st_size = kbuf.st_size;
		st->st_blksize = kbuf.st_blksize;
		st->st_blocks = kbuf.st_blocks;
		st->st_atime = kbuf.st_atime;
#ifdef _HAVE___UNUSED1
		st->__unused1 = 0;
#endif
		st->st_mtime = kbuf.st_mtime;
#ifdef _HAVE___UNUSED2
		st->__unused2 = 0;
#endif
		st->st_ctime = kbuf.st_ctime;
#ifdef _HAVE___UNUSED3
		st->__unused3 = 0;
#endif
#ifdef _HAVE___UNUSED4
		st->__unused4 = 0;
#endif
#ifdef _HAVE___UNUSED5
		st->__unused5 = 0;
#endif
		return ret;

	default:
		errno = EINVAL;
		return -1;
	}
}
#endif

 int stat(const char *name, struct stat *st)
{
#if HAVE___XSTAT
	return __xstat(_STAT_VER, name, st);
#else
	if (smbw_path(name)) {
		return smbw_stat(name, st);
	}
	return real_stat(name, st);
#endif
}

 int lstat(const char *name, struct stat *st)
{
#if HAVE___LXSTAT
	return __lxstat(_STAT_VER, name, st);
#else
	if (smbw_path(name)) {
		return smbw_stat(name, st);
	}
	return real_lstat(name, st);
#endif
}

 int fstat(int fd, struct stat *st)
{
#if HAVE___LXSTAT
	return __fxstat(_STAT_VER, fd, st);
#else
	if (smbw_fd(fd)) {
		return smbw_fstat(fd, st);
	}
	return real_fstat(fd, st);
#endif
}


 int unlink(const char *name)
{
	if (smbw_path(name)) {
		return smbw_unlink(name);
	}

	return real_unlink(name);
}


#ifdef HAVE_UTIME
 int utime(const char *name,void *tvp)
{
	if (smbw_path(name)) {
		return smbw_utime(name, tvp);
	}

	return real_utime(name, tvp);
}
#endif

#ifdef HAVE_UTIMES
 int utimes(const char *name,const struct timeval tvp[2])
{
	if (smbw_path(name)) {
		return smbw_utimes(name, tvp);
	}

	return real_utimes(name, tvp);
}
#endif

 int readlink(char *path, char *buf, size_t bufsize)
{
	if (smbw_path(path)) {
		return smbw_readlink(path, buf, bufsize);
	}

	return real_readlink(path, buf, bufsize);
}


 int rename(const char *oldname,const char *newname)
{
	int p1, p2;
	p1 = smbw_path(oldname); 
	p2 = smbw_path(newname); 
	if (p1 ^ p2) {
		/* can't cross filesystem boundaries */
		errno = EXDEV;
		return -1;
	}
	if (p1 && p2) {
		return smbw_rename(oldname, newname);
	}

	return real_rename(oldname, newname);
}

 int rmdir(const char *name)
{
	if (smbw_path(name)) {
		return smbw_rmdir(name);
	}

	return real_rmdir(name);
}


 int symlink(const char *topath,const char *frompath)
{
	int p1, p2;
	p1 = smbw_path(topath); 
	p2 = smbw_path(frompath); 
	if (p1 || p2) {
		/* can't handle symlinks */
		errno = EPERM;
		return -1;
	}

	return real_symlink(topath, frompath);
}

 int dup(int fd)
{
	if (smbw_fd(fd)) {
		return smbw_dup(fd);
	}

	return real_dup(fd);
}

 int dup2(int oldfd, int newfd)
{
	if (smbw_fd(newfd)) {
		close(newfd);
	}

	if (smbw_fd(oldfd)) {
		return smbw_dup2(oldfd, newfd);
	}

	return real_dup2(oldfd, newfd);
}

#ifdef real_opendir
 DIR *opendir(const char *name)
{
	if (smbw_path(name)) {
		return smbw_opendir(name);
	}

	return real_opendir(name);
}
#endif

#ifdef real_readdir
 struct dirent *readdir(DIR *dir)
{
	if (smbw_dirp(dir)) {
		return smbw_readdir(dir);
	}

	return real_readdir(dir);
}
#endif

#ifdef real_closedir
 int closedir(DIR *dir)
{
	if (smbw_dirp(dir)) {
		return smbw_closedir(dir);
	}

	return real_closedir(dir);
}
#endif

#ifdef real_telldir
 off_t telldir(DIR *dir)
{
	if (smbw_dirp(dir)) {
		return smbw_telldir(dir);
	}

	return real_telldir(dir);
}
#endif

#ifdef real_seekdir
#if SEEKDIR_RETURNS_VOID
 void 
#else
 int
#endif
seekdir(DIR *dir, off_t offset)
{
	if (smbw_dirp(dir)) {
		smbw_seekdir(dir, offset);
		goto done;
	}

	real_seekdir(dir, offset);
 done:
#ifndef SEEKDIR_RETURNS_VOID
	return 0;
#endif
}
#endif


#ifndef NO_ACL_WRAPPER
 int  acl(const char  *pathp,  int  cmd,  int  nentries, aclent_t *aclbufp)
{
	if (smbw_path(pathp)) {
		switch (cmd) {
		case GETACL:
		case GETACLCNT:
			return 0;
		default:
			errno = ENOSYS;
			return -1;
		}
	}

	real_acl(pathp, cmd, nentries, aclbufp);
}
#endif

#ifndef NO_FACL_WRAPPER
 int  facl(int fd,  int  cmd,  int  nentries, aclent_t *aclbufp)
{
	if (smbw_fd(fd)) {
		switch (cmd) {
		case GETACL:
		case GETACLCNT:
			return 0;
		default:
			errno = ENOSYS;
			return -1;
		}
	}

	real_facl(fd, cmd, nentries, aclbufp);
}
#endif

 int creat(const char *path, mode_t mode)
{
	return open(path, O_WRONLY|O_CREAT|O_TRUNC, mode);
}

#ifdef HAVE_CREAT64
 int creat64(const char *path, mode_t mode)
{
	return open64(path, O_WRONLY|O_CREAT|O_TRUNC, mode);
}
#endif

#ifdef HAVE_STAT64
static void stat64_convert(struct stat *st, struct stat64 *st64)
{
	st64->st_size = st->st_size;
	st64->st_mode = st->st_mode;
	st64->st_ino = st->st_ino;
	st64->st_dev = st->st_dev;
	st64->st_rdev = st->st_rdev;
	st64->st_nlink = st->st_nlink;
	st64->st_uid = st->st_uid;
	st64->st_gid = st->st_gid;
	st64->st_atime = st->st_atime;
	st64->st_mtime = st->st_mtime;
	st64->st_ctime = st->st_ctime;
	st64->st_blksize = st->st_blksize;
	st64->st_blocks = st->st_blocks;
}

  int stat64(const char *name, struct stat64 *st64)
{
	if (smbw_path(name)) {
		struct stat st;
		int ret = stat(name, &st);
		stat64_convert(&st, st64);
		return ret;
	}
	return real_stat64(name, st64);
}

  int fstat64(int fd, struct stat64 *st64)
{
	if (smbw_fd(fd)) {
		struct stat st;
		int ret = fstat(fd, &st);
		stat64_convert(&st, st64);
		return ret;
	}
	return real_fstat64(fd, st64);
}

  int lstat64(const char *name, struct stat64 *st64)
{
	if (smbw_path(name)) {
		struct stat st;
		int ret = lstat(name, &st);
		stat64_convert(&st, st64);
		return ret;
	}
	return real_lstat64(name, st64);
}
#endif

#ifdef HAVE_LLSEEK
  offset_t llseek(int fd, offset_t ofs, int whence)
{
	if (smbw_fd(fd)) {
		return lseek(fd, ofs, whence);
	}
	return real_llseek(fd, ofs, whence);
}
#endif

#ifdef HAVE_READDIR64
static void dirent64_convert(struct dirent *d, struct dirent64 *d64)
{
	d64->d_ino = d->d_ino;
	d64->d_off = d->d_off;
	d64->d_reclen = d->d_reclen;
	strcpy(d64->d_name, d->d_name);
}

 struct dirent64 *readdir64(DIR *dir)
{
	if (smbw_dirp(dir)) {
		struct dirent *d;
		static union {
			char buf[DIRP_SIZE];
			struct dirent64 d64;
		} dbuf;
		d = readdir(dir);
		if (!d) return NULL;
		dirent64_convert(d, &dbuf.d64);
		return &dbuf.d64;
	}
	return real_readdir64(dir);
}
#endif

 int fork(void)
{
	return smbw_fork();
}
