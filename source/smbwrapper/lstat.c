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

 int __lxstat(int vers, __const char *name, struct stat *st)
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

