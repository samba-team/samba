/*
 * Unix SMB/CIFS implementation.
 * Samba system utilities
 * Copyright (C) Andrew Tridgell 1992-1998
 * Copyright (C) Jeremy Allison  1998-2005
 * Copyright (C) Timur Bakeyev        2005
 * Copyright (C) Bjoern Jacke    2006-2007
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include "system/filesys.h"
#include "lib/util/sys_rw.h"

/*******************************************************************
A read wrapper that will deal with EINTR/EWOULDBLOCK
********************************************************************/

ssize_t sys_read(int fd, void *buf, size_t count)
{
	ssize_t ret;

	do {
		ret = read(fd, buf, count);
	} while (ret == -1 && (errno == EINTR || errno == EAGAIN ||
			       errno == EWOULDBLOCK));

	return ret;
}

/**
 * read wrapper, void variant:
 * This is intended to be used as a void variant of
 * read in situations where the caller wants to ignore
 * the result. Hence not checking for EAGAIN|EWOULDBLOCK.
 */
void sys_read_v(int fd, void *buf, size_t count)
{
	ssize_t ret;

	do {
		ret = read(fd, buf, count);
	} while (ret == -1 && errno == EINTR);
}


/*******************************************************************
A write wrapper that will deal with EINTR/EWOULDBLOCK.
********************************************************************/

ssize_t sys_write(int fd, const void *buf, size_t count)
{
	ssize_t ret;

	do {
		ret = write(fd, buf, count);
	} while (ret == -1 && (errno == EINTR || errno == EAGAIN ||
			       errno == EWOULDBLOCK));

	return ret;
}

/**
 * write wrapper to deal with EINTR and friends.
 * void-variant that ignores the number of bytes written.
 * This is intended to be used as a void variant of
 * write in situations where the caller wants to ignore
 * the result. Hence not checking for EAGAIN|EWOULDBLOCK.
 */
void sys_write_v(int fd, const void *buf, size_t count)
{
	ssize_t ret;

	do {
		ret = write(fd, buf, count);
	} while (ret == -1 && errno == EINTR);
}


/*******************************************************************
A writev wrapper that will deal with EINTR.
********************************************************************/

ssize_t sys_writev(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t ret;

	do {
		ret = writev(fd, iov, iovcnt);
	} while (ret == -1 && (errno == EINTR || errno == EAGAIN ||
			       errno == EWOULDBLOCK));

	return ret;
}

/*******************************************************************
A pread wrapper that will deal with EINTR
********************************************************************/

ssize_t sys_pread(int fd, void *buf, size_t count, off_t off)
{
	ssize_t ret;

	do {
		ret = pread(fd, buf, count, off);
	} while (ret == -1 && errno == EINTR);
	return ret;
}

/*******************************************************************
A write wrapper that will deal with EINTR
********************************************************************/

ssize_t sys_pwrite(int fd, const void *buf, size_t count, off_t off)
{
	ssize_t ret;

	do {
		ret = pwrite(fd, buf, count, off);
	} while (ret == -1 && errno == EINTR);
	return ret;
}
