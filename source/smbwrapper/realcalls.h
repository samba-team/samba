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
#define real_link(fn1, fn2)		(syscall(SYS_link, (fn1), (fn2)))

#define real_open(fn,flags,mode)	(syscall(SYS_open, (fn), (flags), (mode)))


#ifdef HAVE__OPENDIR
#define real_opendir(fn)            	(_opendir(fn))
#elif SYS_opendir
#define real_opendir(fn)		((DIR *)syscall(SYS_opendir,(fn)))
#elif HAVE___OPENDIR
#define real_opendir(fn)            	(__opendir(fn))
#endif

#ifdef HAVE__READDIR
#define real_readdir(d)            	(_readdir(d))
#elif SYS_readdir
#define real_readdir(d)		(syscall(SYS_readdir,(d)))
#elif HAVE___READDIR
#define real_readdir(d)            	(__readdir(d))
#endif

#ifdef HAVE__CLOSEDIR
#define real_closedir(d)            	(_closedir(d))
#elif SYS_closedir
#define real_closedir(d)		(syscall(SYS_closedir,(d)))
#elif HAVE___CLOSEDIR
#define real_closedir(d)            	(__closedir(d))
#endif

#ifdef HAVE__SEEKDIR
#define real_seekdir(d,l)            	(_seekdir(d,l))
#elif SYS_seekdir
#define real_seekdir(d,l)		(syscall(SYS_seekdir,(d),(l)))
#elif HAVE___SEEKDIR
#define real_seekdir(d)            	(__seekdir(d,l))
#else
#define NO_SEEKDIR
#endif

#ifdef HAVE__TELLDIR
#define real_telldir(d)            	(_telldir(d))
#elif SYS_telldir
#define real_telldir(d)		(syscall(SYS_telldir,(d)))
#elif HAVE___TELLDIR
#define real_telldir(d)            	(__telldir(d))
#else
#define NO_TELLDIR
#endif

#ifdef HAVE__DUP
#define real_dup(d)            	(_dup(d))
#elif SYS_dup
#define real_dup(d)		(syscall(SYS_dup,(d)))
#elif HAVE___DUP
#define real_dup(d)            	(__dup(d))
#endif

#ifdef HAVE__DUP2
#define real_dup2(d1,d2)            	(_dup2(d1,d2))
#elif SYS_dup2
#define real_dup2(d1,d2)		(syscall(SYS_dup2,(d1),(d2)))
#elif HAVE___DUP2
#define real_dup2(d1,d2)            	(__dup2(d1,d2))
#endif

#ifdef HAVE__GETCWD
#define real_getcwd(b,s)            	(_getcwd(b,s))
#elif SYS_getcwd
#define real_getcwd(b,s)		(syscall(SYS_getcwd,(b),(s)))
#elif HAVE___GETCWD
#define real_getcwd(b,s)            	(__getcwd(b,s))
#endif

#ifdef HAVE__STAT
#define real_stat(fn,st)            	(_stat(fn,st))
#elif SYS_stat
#define real_stat(fn,st)		(syscall(SYS_stat,(fn),(st)))
#elif HAVE___STAT
#define real_stat(fn,st)            	(__stat(fn,st))
#endif

#ifdef HAVE__LSTAT
#define real_lstat(fn,st)            	(_lstat(fn,st))
#elif SYS_lstat
#define real_lstat(fn,st)		(syscall(SYS_lstat,(fn),(st)))
#elif HAVE___LSTAT
#define real_lstat(fn,st)            	(__lstat(fn,st))
#endif

#ifdef HAVE__FSTAT
#define real_fstat(fd,st)            	(_fstat(fd,st))
#elif SYS_fstat
#define real_fstat(fd,st)		(syscall(SYS_fstat,(fd),(st)))
#elif HAVE___FSTAT
#define real_fstat(fd,st)            	(__fstat(fd,st))
#endif


#define real_readlink(fn,buf,len)	(syscall(SYS_readlink, (fn), (buf), (len)))
#define real_rename(fn1, fn2)		(syscall(SYS_rename, (fn1), (fn2)))
#define real_symlink(fn1, fn2)		(syscall(SYS_symlink, (fn1), (fn2)))
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
