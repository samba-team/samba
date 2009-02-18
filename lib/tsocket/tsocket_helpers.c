/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2009

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"
#include "tsocket.h"
#include "tsocket_internal.h"

int tsocket_error_from_errno(int ret,
			     int sys_errno,
			     bool *retry)
{
	*retry = false;

	if (ret >= 0) {
		return 0;
	}

	if (ret != -1) {
		return EIO;
	}

	if (sys_errno == 0) {
		return EIO;
	}

	if (sys_errno == EINTR) {
		*retry = true;
		return sys_errno;
	}

	if (sys_errno == EINPROGRESS) {
		*retry = true;
		return sys_errno;
	}

	if (sys_errno == EAGAIN) {
		*retry = true;
		return sys_errno;
	}

#ifdef EWOULDBLOCK
	if (sys_errno == EWOULDBLOCK) {
		*retry = true;
		return sys_errno;
	}
#endif

	return sys_errno;
}

int tsocket_simple_int_recv(struct tevent_req *req, int *perrno)
{
	enum tevent_req_state state;
	uint64_t error;

	if (!tevent_req_is_error(req, &state, &error)) {
		return 0;
	}

	switch (state) {
	case TEVENT_REQ_NO_MEMORY:
		*perrno = ENOMEM;
		return -1;
	case TEVENT_REQ_TIMED_OUT:
		*perrno = ETIMEDOUT;
		return -1;
	case TEVENT_REQ_USER_ERROR:
		*perrno = (int)error;
		return -1;
	default:
		*perrno = EIO;
		return -1;
	}

	*perrno = EIO;
	return -1;
}

int tsocket_common_prepare_fd(int fd, bool high_fd)
{
	int i;
	int sys_errno = 0;
	int fds[3];
	int num_fds = 0;

	int result, flags;

	if (fd == -1) {
		return -1;
	}

	/* first make a fd >= 3 */
	if (high_fd) {
		while (fd < 3) {
			fds[num_fds++] = fd;
			fd = dup(fd);
			if (fd == -1) {
				sys_errno = errno;
				break;
			}
		}
		for (i=0; i<num_fds; i++) {
			close(fds[i]);
		}
		if (fd == -1) {
			errno = sys_errno;
			return fd;
		}
	}

	/* fd should be nonblocking. */

#ifdef O_NONBLOCK
#define FLAG_TO_SET O_NONBLOCK
#else
#ifdef SYSV
#define FLAG_TO_SET O_NDELAY
#else /* BSD */
#define FLAG_TO_SET FNDELAY
#endif
#endif

	if ((flags = fcntl(fd, F_GETFL)) == -1) {
		goto fail;
	}

	flags |= FLAG_TO_SET;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		goto fail;
	}

#undef FLAG_TO_SET

	/* fd should be closed on exec() */
#ifdef FD_CLOEXEC
	result = flags = fcntl(fd, F_GETFD, 0);
	if (flags >= 0) {
		flags |= FD_CLOEXEC;
		result = fcntl(fd, F_SETFD, flags);
	}
	if (result < 0) {
		goto fail;
	}
#endif
	return fd;

 fail:
	if (fd != -1) {
		sys_errno = errno;
		close(fd);
		errno = sys_errno;
	}
	return -1;
}

