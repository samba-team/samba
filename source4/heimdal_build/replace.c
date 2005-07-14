/* 
   Unix SMB/CIFS implementation.

   some replacement functions for parts of roken that don't fit easily into 
   our build system

   Copyright (C) Andrew Tridgell 2005
   
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

#include "config.h"
#include <stdio.h>
#include "err.h"
#include "roken.h"

#ifndef HAVE_ERR
 void err(int eval, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	perror("");
	va_end(ap);
	exit(eval);
}
#endif

#ifndef HAVE_ERRX
 void errx(int eval, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	exit(eval);
}
#endif

#ifndef HAVE_WARNX
 void warnx(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}
#endif

#ifndef HAVE_FLOCK
 int flock(int fd, int op)
{
	switch (op & (LOCK_UN|LOCK_SH|LOCK_EX)) {
	case LOCK_UN:
		return fcntl_lock(fd, F_SETLK, 0, 0, F_UNLCK);
	case LOCK_SH:
		return fcntl_lock(fd, (op&LOCK_NB)?F_SETLK:F_SETLKW, 
				  0, 0, F_RDLCK);
	case LOCK_EX:
		return fcntl_lock(fd, (op&LOCK_NB)?F_SETLK:F_SETLKW, 
				  0, 0, F_WRLCK);
	}
	errno = EINVAL;
	return -1;
}
#endif
