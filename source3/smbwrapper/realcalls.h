/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   defintions of syscall entries
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


/* this file is partly derived from zlibc by Alain Knaff */

#define real_access(fn, mode)		(syscall(SYS_access, (fn), (mode)))
#define real_chdir(fn)		        (syscall(SYS_chdir, (fn)))
#define real_chmod(fn, mode)		(syscall(SYS_chmod,(fn), (mode)))
#define real_chown(fn, owner, group)	(syscall(SYS_chown,(fn),(owner),(group)))

#define real_getdents(fd, dirp, count)	(syscall(SYS_getdents, (fd), (dirp), (count)))
/* if needed define SYS_getdents so that getdents gets compiled */

#define real_link(fn1, fn2)		(syscall(SYS_link, (fn1), (fn2)))

#define real_lstat(fn, buf )		(syscall(SYS_lstat, (fn), (buf)))
#define real_open(fn,flags,mode)	(syscall(SYS_open, (fn), (flags), (mode)))
#define real_prev_lstat(fn, buf )	(syscall(SYS_prev_lstat, (fn), (buf)))
#define real_prev_stat(fn, buf )	(syscall(SYS_prev_stat, (fn), (buf)))

#ifdef linux
#define real_readdir(dir)		(__readdir(dir))
#define real_opendir(fn)            	(__opendir(fn))
#define real_telldir(dir)            	(__telldir(dir))
#define real_closedir(dir)            	(__closedir(dir))
#define real_seekdir(dir, ofs)          (__seekdir(dir, ofs))
#else
#define real_readdir(dirp)		((struct dirent *)syscall(SYS_readdir,(dirp)))
#define real_opendir(fn)		((DIR *)syscall(SYS_opendir,(fn)))
/* if needed define SYS_readdir so that readdir gets compiled */
#endif

#define real_readlink(fn,buf,len)	(syscall(SYS_readlink, (fn), (buf), (len)))
#define real_rename(fn1, fn2)		(syscall(SYS_rename, (fn1), (fn2)))
#define real_symlink(fn1, fn2)		(syscall(SYS_symlink, (fn1), (fn2)))
#define real_stat(fn, buf )		(syscall(SYS_stat, (fn), (buf)))
#define real_fstat(fd, buf )		(syscall(SYS_fstat, (fd), (buf)))
#define real_read(fd, buf, count )	(syscall(SYS_read, (fd), (buf), (count)))
#define real_lseek(fd, offset, whence)	(syscall(SYS_lseek, (fd), (offset), (whence)))
#define real_write(fd, buf, count )	(syscall(SYS_write, (fd), (buf), (count)))
#define real_close(fd)	                (syscall(SYS_close, (fd)))
#define real_fchdir(fd)	                (syscall(SYS_fchdir, (fd)))
#define real_fcntl(fd,cmd,arg)	        (syscall(SYS_fcntl, (fd), (cmd), (arg)))
#define real_symlink(fn1, fn2)		(syscall(SYS_symlink, (fn1), (fn2)))
#define real_unlink(fn)			(syscall(SYS_unlink, (fn)))
#define real_rmdir(fn)			(syscall(SYS_rmdir, (fn)))
#define real_mkdir(fn, mode)		(syscall(SYS_mkdir, (fn), (mode)))
#define real_utime(fn, buf)		(syscall(SYS_utime, (fn), (buf)))
#define real_utimes(fn, buf)		(syscall(SYS_utimes, (fn), (buf)))


