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


#include "wrapper.h"

#ifdef linux
__asm__(".globl __open; __open = open");
#endif

 int open(const char *name, int flags, mode_t mode)
{
	if (smbw_path(name)) {
		return smbw_open(name, flags, mode);
	}

	return real_open(name, flags, mode);
}


#ifdef linux
__asm__(".globl __chdir; __chdir = chdir");
#endif

 int chdir(const char *name)
{
	return smbw_chdir(name);
}



#ifdef linux
__asm__(".globl __close; __close = close");
#endif

 ssize_t close(int fd)
{
	if (smbw_fd(fd)) {
		return smbw_close(fd);
	}

	return real_close(fd);
}


#ifdef linux
__asm__(".globl __fchdir; __fchdir = fchdir");
#endif

 int fchdir(int fd)
{
	if (smbw_fd(fd)) {
		return smbw_fchdir(fd);
	}

	return real_fchdir(fd);
}


#ifdef linux
__asm__(".globl __fcntl; __fcntl = fcntl");
#endif

 int fcntl(int fd, int cmd, long arg)
{
	if (smbw_fd(fd)) {
		return smbw_fcntl(fd, cmd, arg);
	}

	return real_fcntl(fd, cmd, arg);
}



#ifdef linux
__asm__(".globl __getdents; __getdents = getdents");
#endif

 int getdents(unsigned int fd, struct dirent *dirp, unsigned int count)
{
	if (smbw_fd(fd)) {
		return smbw_getdents(fd, dirp, count);
	}

	return real_getdents(fd, dirp, count);
}


#ifdef linux
__asm__(".globl __lseek; __lseek = lseek");
#endif

 ssize_t lseek(int fd, off_t offset, int whence)
{
	if (smbw_fd(fd)) {
		return smbw_lseek(fd, offset, whence);
	}

	return real_lseek(fd, offset, whence);
}



#ifdef linux
__asm__(".globl __read; __read = read");
#endif

 ssize_t read(int fd, void *buf, size_t count)
{
	if (smbw_fd(fd)) {
		return smbw_read(fd, buf, count);
	}

	return real_read(fd, buf, count);
}


#ifdef linux
__asm__(".globl __write; __write = write");
#endif

 ssize_t write(int fd, void *buf, size_t count)
{
	if (smbw_fd(fd)) {
		return smbw_write(fd, buf, count);
	}

	return real_write(fd, buf, count);
}


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

 int closedir(DIR *dir)
{
	if (smbw_dirp(dir)) {
		return smbw_closedir(dir);
	}

	return real_closedir(dir);
}


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


 char *getcwd(char *buf, size_t size)
{
	return smbw_getcwd(buf, size);
}



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



 int mkdir(const char *name, mode_t mode)
{
	if (smbw_path(name)) {
		return smbw_mkdir(name, mode);
	}

	return real_mkdir(name, mode);
}


 void seekdir(DIR *dir, off_t offset)
{
	if (smbw_dirp(dir)) {
		smbw_seekdir(dir, offset);
		return;
	}

	real_seekdir(dir, offset);
}


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

 int stat(const char *name, struct stat *st)
{
	return __xstat(_STAT_VER, name, st);
}


 off_t telldir(DIR *dir)
{
	if (smbw_dirp(dir)) {
		return smbw_telldir(dir);
	}

	return real_telldir(dir);
}


 int unlink(const char *name)
{
	if (smbw_path(name)) {
		return smbw_unlink(name);
	}

	return real_unlink(name);
}


 int utime(const char *name,void *tvp)
{
	if (smbw_path(name)) {
		return smbw_utime(name, tvp);
	}

	return real_utime(name, tvp);
}

 DIR *opendir(const char *name)
{
	if (smbw_path(name)) {
		return smbw_opendir(name);
	}

	return real_opendir(name);
}


 struct dirent *readdir(DIR *dir)
{
	if (smbw_dirp(dir)) {
		return smbw_readdir(dir);
	}

	return real_readdir(dir);
}

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
