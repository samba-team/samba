/*
 * Unix SMB/CIFS implementation.
 * Copyright (C) Volker Lendecke 2014
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
#include "lib/util/msghdr.h"
#include "lib/util/iov_buf.h"
#include <sys/socket.h>

#if defined(HAVE_STRUCT_MSGHDR_MSG_CONTROL)

ssize_t msghdr_prep_fds(struct msghdr *msg, uint8_t *buf, size_t bufsize,
			const int *fds, size_t num_fds)
{
	size_t fds_size = sizeof(int) * MIN(num_fds, INT8_MAX);
	size_t cmsg_len = CMSG_LEN(fds_size);
	size_t cmsg_space = CMSG_SPACE(fds_size);
	struct cmsghdr *cmsg;
	void *fdptr;

	if (num_fds == 0) {
		if (msg != NULL) {
			msg->msg_control = NULL;
			msg->msg_controllen = 0;
		}
		/*
		 * C99 doesn't allow 0-length arrays
		 */
		return 1;
	}
	if (num_fds > INT8_MAX) {
		return -1;
	}
	if ((msg == NULL) || (cmsg_space > bufsize)) {
		/*
		 * C99 doesn't allow 0-length arrays
		 */
		return MAX(cmsg_space, 1);
	}

	msg->msg_control = buf;
	msg->msg_controllen = cmsg_space;

	cmsg = CMSG_FIRSTHDR(msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = cmsg_len;
	fdptr = CMSG_DATA(cmsg);
	memcpy(fdptr, fds, fds_size);
	msg->msg_controllen = cmsg->cmsg_len;

	return cmsg_space;
}

size_t msghdr_prep_recv_fds(struct msghdr *msg, uint8_t *buf, size_t bufsize,
			    size_t num_fds)
{
	size_t ret = CMSG_SPACE(sizeof(int) * num_fds);

	if (bufsize < ret) {
		return ret;
	}
	if (msg != NULL) {
		if (num_fds != 0) {
			msg->msg_control = buf;
			msg->msg_controllen = ret;
		} else {
			msg->msg_control = NULL;
			msg->msg_controllen = 0;
		}
	}
	return ret;
}

size_t msghdr_extract_fds(struct msghdr *msg, int *fds, size_t fds_size)
{
	struct cmsghdr *cmsg;
	size_t num_fds;

	for(cmsg = CMSG_FIRSTHDR(msg);
	    cmsg != NULL;
	    cmsg = CMSG_NXTHDR(msg, cmsg))
	{
		if ((cmsg->cmsg_type == SCM_RIGHTS) &&
		    (cmsg->cmsg_level == SOL_SOCKET)) {
			break;
		}
	}

	if (cmsg == NULL) {
		return 0;
	}

	num_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);

	if ((num_fds != 0) && (fds != NULL) && (fds_size >= num_fds)) {
		memcpy(fds, CMSG_DATA(cmsg), num_fds * sizeof(int));
	}

	return num_fds;
}

#elif defined(HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS)

ssize_t msghdr_prep_fds(struct msghdr *msg, uint8_t *buf, size_t bufsize,
			const int *fds, size_t num_fds)
{
	size_t needed;

	if (num_fds > INT8_MAX) {
		return -1;
	}

	needed = sizeof(int) * num_fds;

	if ((msg == NULL) || (needed > bufsize)) {
		return needed;
	}

	memcpy(buf, fds, needed);

	msg->msg_accrights = (caddr_t) buf;
	msg->msg_accrightslen = needed;

	return needed;
}

size_t msghdr_prep_recv_fds(struct msghdr *msg, uint8_t *buf, size_t bufsize,
			    size_t num_fds)
{
	size_t ret = num_fds * sizeof(int);

	if (bufsize < ret) {
		return ret;
	}

	if (msg != NULL) {
		if (num_fds != 0) {
			msg->msg_accrights = (caddr_t) buf;
			msg->msg_accrightslen = ret;
		} else {
			msg->msg_accrights = NULL;
			msg->msg_accrightslen = 0;
		}
	}
	return ret;
}

size_t msghdr_extract_fds(struct msghdr *msg, int *fds, size_t fds_size)
{
	size_t num_fds = msg->msg_accrightslen / sizeof(int);

	if ((fds != 0) && (num_fds <= fds_size)) {
		memcpy(fds, msg->msg_accrights, msg->msg_accrightslen);
	}

	return num_fds;
}

#else

ssize_t msghdr_prep_fds(struct msghdr *msg, uint8_t *buf, size_t bufsize,
			const int *fds, size_t num_fds)
{
	return -1;
}

size_t msghdr_prep_recv_fds(struct msghdr *msg, uint8_t *buf, size_t bufsize,
			    size_t num_fds)
{
	return 0;
}

size_t msghdr_extract_fds(struct msghdr *msg, int *fds, size_t fds_size)
{
	return 0;
}

#endif

struct msghdr_buf {
	struct msghdr msg;
	struct sockaddr_storage addr;
	struct iovec iov;
	uint8_t buf[];
};

ssize_t msghdr_copy(struct msghdr_buf *msg, size_t msgsize,
		    const void *addr, socklen_t addrlen,
		    const struct iovec *iov, int iovcnt,
		    const int *fds, size_t num_fds)
{
	ssize_t fd_len;
	size_t iov_len, needed, bufsize;

	bufsize = (msgsize > offsetof(struct msghdr_buf, buf)) ?
		msgsize - offsetof(struct msghdr_buf, buf) : 0;

	if (msg != NULL) {
		msg->msg = (struct msghdr) { 0 };

		fd_len = msghdr_prep_fds(&msg->msg, msg->buf, bufsize,
					 fds, num_fds);
	} else {
		fd_len = msghdr_prep_fds(NULL, NULL, bufsize, fds, num_fds);
	}

	if (fd_len == -1) {
		return -1;
	}

	if (bufsize >= (size_t)fd_len) {
		bufsize -= fd_len;
	} else {
		bufsize = 0;
	}

	if (msg != NULL) {

		if (addr != NULL) {
			if (addrlen > sizeof(struct sockaddr_storage)) {
				errno = EMSGSIZE;
				return -1;
			}
			memcpy(&msg->addr, addr, addrlen);
			msg->msg.msg_name = &msg->addr;
			msg->msg.msg_namelen = addrlen;
		} else {
			msg->msg.msg_name = NULL;
			msg->msg.msg_namelen = 0;
		}

		msg->iov.iov_base = msg->buf + fd_len;
		msg->iov.iov_len = iov_buf(
			iov, iovcnt, msg->iov.iov_base, bufsize);
		iov_len = msg->iov.iov_len;

		msg->msg.msg_iov = &msg->iov;
		msg->msg.msg_iovlen = 1;
	} else {
		iov_len = iov_buflen(iov, iovcnt);
	}

	needed = offsetof(struct msghdr_buf, buf) + fd_len;
	if (needed < (size_t)fd_len) {
		return -1;
	}
	needed += iov_len;
	if (needed < iov_len) {
		return -1;
	}

	return needed;
}

struct msghdr *msghdr_buf_msghdr(struct msghdr_buf *msg)
{
	return &msg->msg;
}
