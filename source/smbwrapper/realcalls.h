#ifdef aix

#include "aix-syscall.h"

#else

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
struct dirent *__libc_readdir(DIR * dir);
#define real_readdir(dir)		(__libc_readdir(dirp))
#else
#define real_readdir(dirp)		((struct dirent *)syscall(SYS_readdir,(dirp)))
/* if needed define SYS_readdir so that readdir gets compiled */
#endif

#define real_readlink(fn,buf,len)	(syscall(SYS_readlink, (fn), (buf), (len)))
#define real_rename(fn1, fn2)		(syscall(SYS_rename, (fn1), (fn2)))
#define real_stat(fn, buf )		(syscall(SYS_stat, (fn), (buf)))
#define real_fstat(fd, buf )		(syscall(SYS_fstat, (fd), (buf)))
#define real_read(fd, buf, count )	(syscall(SYS_read, (fd), (buf), (count)))
#define real_lseek(fd, offset, whence)	(syscall(SYS_lseek, (fd), (offset), (whence)))
#define real_write(fd, buf, count )	(syscall(SYS_write, (fd), (buf), (count)))
#define real_close(fd)	                (syscall(SYS_close, (fd)))
#define real_fcntl(fd,cmd,arg)	        (syscall(SYS_fcntl, (fd), (cmd), (arg)))
#define real_symlink(fn1, fn2)		(syscall(SYS_symlink, (fn1), (fn2)))
#define real_unlink(fn)			(syscall(SYS_unlink, (fn)))
#define real_utime(fn, buf)		(syscall(SYS_utime, (fn), (buf)))
#define real_utimes(fn, buf)		(syscall(SYS_utimes, (fn), (buf)))
#define real_readlink(fn, buf, bufs)	(syscall(SYS_readlink, (fn), (buf), (bufs)))

#endif

