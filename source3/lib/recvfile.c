/*
 Unix SMB/Netbios implementation.
 Version 3.2.x
 recvfile implementations.
 Copyright (C) Jeremy Allison 2007.

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 3 of the License, or
 (at your option) any later version.
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 * This file handles the OS dependent recvfile implementations.
 * The API is such that it returns -1 on error, else returns the
 * number of bytes written.
 */

#include "includes.h"

/* Do this on our own in TRANSFER_BUF_SIZE chunks.
 * It's safe to make direct syscalls to lseek/write here
 * as we're below the Samba vfs layer.
 *
 * If tofd is -1 we just drain the incoming socket of count
 * bytes without writing to the outgoing fd.
 * If a write fails we do the same (to cope with disk full)
 * errors.
 *
 * Returns -1 on short reads from fromfd (read error)
 * and sets errno.
 *
 * Returns number of bytes written to 'tofd'
 * or thrown away if 'tofd == -1'.
 * eturn != count then sets errno.
 * Returns count if complete success.
 */

#ifndef TRANSFER_BUF_SIZE
#define TRANSFER_BUF_SIZE (128*1024)
#endif

static ssize_t default_sys_recvfile(int fromfd,
			int tofd,
			SMB_OFF_T offset,
			size_t count)
{
	int saved_errno = 0;
	size_t total = 0;
	size_t bufsize = MIN(TRANSFER_BUF_SIZE,count);
	size_t total_written = 0;
	char *buffer = NULL;

	if (count == 0) {
		return 0;
	}

	if (tofd != -1 && offset != (SMB_OFF_T)-1) {
		if (sys_lseek(tofd, offset, SEEK_SET) == -1) {
			if (errno != ESPIPE) {
				return -1;
			}
		}
	}

	buffer = SMB_MALLOC_ARRAY(char, bufsize);
	if (buffer == NULL) {
		return -1;
	}

	while (total < count) {
		size_t num_written = 0;
		ssize_t read_ret;
		size_t toread = MIN(bufsize,count - total);

		/* Read from socket - ignore EINTR. */
		read_ret = sys_read(fromfd, buffer, toread);
		if (read_ret <= 0) {
			/* EOF or socket error. */
			free(buffer);
			return -1;
		}

		num_written = 0;

		while (num_written < read_ret) {
			ssize_t write_ret;

			if (tofd == -1) {
				write_ret = read_ret;
			} else {
				/* Write to file - ignore EINTR. */
				write_ret = sys_write(tofd,
						buffer + num_written,
						read_ret - num_written);

				if (write_ret <= 0) {
					/* write error - stop writing. */
					tofd = -1;
					saved_errno = errno;
					continue;
				}
			}

			num_written += (size_t)write_ret;
			total_written += (size_t)write_ret;
		}

		total += read_ret;
	}

	free(buffer);
	if (saved_errno) {
		/* Return the correct write error. */
		errno = saved_errno;
	}
	return (ssize_t)total_written;
}

#if defined(HAVE_SPLICE_SYSCALL)

#ifdef JRA_SPLICE_TEST
#include <linux/unistd.h>
#include <sys/syscall.h>

#define __NR_splice             313
_syscall6( long, splice,
		int, fromfd,
		loff_t *, fromoffset,
		int, tofd,
		loff_t *, tooffset,
		size_t, count,
		unsigned int, flags);
#endif

ssize_t sys_recvfile(int fromfd,
			int tofd,
			SMB_OFF_T offset,
			size_t count)
{
	size_t total = 0;

	if (count == 0) {
		return 0;
	}

	while (total < count) {
		ssize_t ret = splice(fromfd,
					NULL,
					tofd,
					&offset,
					count,
					0);
		if (ret == -1) {
			if (errno != EINTR) {
				return -1;
			}
			continue;
		}
		total += ret;
		count -= ret;
	}
	return total;
}
#else

/*****************************************************************
 No recvfile system call - use the default 128 chunk implementation.
*****************************************************************/

ssize_t sys_recvfile(int fromfd,
			int tofd,
			SMB_OFF_T offset,
			size_t count)
{
	return default_sys_recvfile(fromfd, tofd, offset, count);
}
#endif

/*****************************************************************
 Throw away "count" bytes from the client socket.
*****************************************************************/

ssize_t drain_socket(int sockfd, size_t count)
{
	return default_sys_recvfile(sockfd, -1, (SMB_OFF_T)-1, count);
}
