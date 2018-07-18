/*
 Unix SMB/Netbios implementation.
 Version 2.2.x / 3.0.x
 sendfile implementations.
 Copyright (C) Jeremy Allison 2002.

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
 * This file handles the OS dependent sendfile implementations.
 * The API is such that it returns -1 on error, else returns the
 * number of bytes written.
 */

#include "includes.h"
#include "system/filesys.h"

#if defined(LINUX_SENDFILE_API)

#include <sys/sendfile.h>

#ifndef MSG_MORE
#define MSG_MORE 0x8000
#endif

ssize_t sys_sendfile(int tofd, int fromfd, const DATA_BLOB *header, off_t offset, size_t count)
{
	size_t total=0;
	ssize_t ret = -1;
	size_t hdr_len = 0;
	int old_flags = 0;
	bool socket_flags_changed = false;

	/*
	 * Send the header first.
	 * Use MSG_MORE to cork the TCP output until sendfile is called.
	 */

	if (header) {
		hdr_len = header->length;
		while (total < hdr_len) {
			ret = sys_send(tofd, header->data + total,hdr_len - total, MSG_MORE);
			if (ret == -1) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					/*
					 * send() must complete before we can
					 * send any other outgoing data on the
					 * socket. Ensure socket is in blocking
					 * mode. For SMB2 by default the socket
					 * is in non-blocking mode.
					 */
					old_flags = fcntl(tofd, F_GETFL, 0);
					ret = set_blocking(tofd, true);
					if (ret == -1) {
						goto out;
					}
					socket_flags_changed = true;
					continue;
				}
				goto out;
			}
			total += ret;
		}
	}

	total = count;
	while (total) {
		ssize_t nwritten;
		do {
			nwritten = sendfile(tofd, fromfd, &offset, total);
		} while (nwritten == -1 && errno == EINTR);
		if (nwritten == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				if (socket_flags_changed) {
					/*
					 * We're already in blocking
					 * mode. This is an error.
					 */
					ret = -1;
					goto out;
				}

				/*
				 * Sendfile must complete before we can
				 * send any other outgoing data on the socket.
				 * Ensure socket is in blocking mode.
				 * For SMB2 by default the socket is in
				 * non-blocking mode.
				 */
				old_flags = fcntl(tofd, F_GETFL, 0);
				ret = set_blocking(tofd, true);
				if (ret == -1) {
					goto out;
				}
				socket_flags_changed = true;
				continue;
			}

			if (errno == ENOSYS || errno == EINVAL) {
				/* Ok - we're in a world of pain here. We just sent
				 * the header, but the sendfile failed. We have to
				 * emulate the sendfile at an upper layer before we
				 * disable it's use. So we do something really ugly.
				 * We set the errno to a strange value so we can detect
				 * this at the upper level and take care of it without
				 * layer violation. JRA.
				 */
				errno = EINTR; /* Normally we can never return this. */
			}
			ret = -1;
			goto out;
		}
		if (nwritten == 0) {
			/*
			 * EOF, return a short read
			 */
			ret = hdr_len + (count - total);
			goto out;
		}
		total -= nwritten;
	}

	ret = count + hdr_len;

  out:

	if (socket_flags_changed) {
		int saved_errno;
		int err;

		if (ret == -1) {
			saved_errno = errno;
		}
		/* Restore the old state of the socket. */
		err = fcntl(tofd, F_SETFL, old_flags);
		if (err == -1) {
			return -1;
		}
		if (ret == -1) {
			errno = saved_errno;
		}
	}

	return ret;
}

#elif defined(SOLARIS_SENDFILE_API)

/*
 * Solaris sendfile code written by Pierre Belanger <belanger@pobox.com>.
 */

#include <sys/sendfile.h>

ssize_t sys_sendfile(int tofd, int fromfd, const DATA_BLOB *header, off_t offset, size_t count)
{
	int sfvcnt;
	size_t total, xferred;
	struct sendfilevec vec[2];
	ssize_t hdr_len = 0;
	int old_flags = 0;
	ssize_t ret = -1;
	bool socket_flags_changed = false;

	if (header) {
		sfvcnt = 2;

		vec[0].sfv_fd = SFV_FD_SELF;
		vec[0].sfv_flag = 0;
		vec[0].sfv_off = (off_t)header->data;
		vec[0].sfv_len = hdr_len = header->length;

		vec[1].sfv_fd = fromfd;
		vec[1].sfv_flag = 0;
		vec[1].sfv_off = offset;
		vec[1].sfv_len = count;

	} else {
		sfvcnt = 1;

		vec[0].sfv_fd = fromfd;
		vec[0].sfv_flag = 0;
		vec[0].sfv_off = offset;
		vec[0].sfv_len = count;
	}

	total = count + hdr_len;

	while (total) {
		ssize_t nwritten;

		/*
		 * Although not listed in the API error returns, this is almost certainly
		 * a slow system call and will be interrupted by a signal with EINTR. JRA.
		 */

		xferred = 0;

			nwritten = sendfilev(tofd, vec, sfvcnt, &xferred);
		if  (nwritten == -1 && errno == EINTR) {
			if (xferred == 0)
				continue; /* Nothing written yet. */
			else
				nwritten = xferred;
		}

		if (nwritten == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/*
				 * Sendfile must complete before we can
				 * send any other outgoing data on the socket.
				 * Ensure socket is in blocking mode.
				 * For SMB2 by default the socket is in
				 * non-blocking mode.
				 */
				old_flags = fcntl(tofd, F_GETFL, 0);
				ret = set_blocking(tofd, true);
				if (ret == -1) {
					goto out;
				}
				socket_flags_changed = true;
				continue;
			}
			ret = -1;
			goto out;
		}
		if (nwritten == 0) {
			ret = -1;
			goto out; /* I think we're at EOF here... */
		}

		/*
		 * If this was a short (signal interrupted) write we may need
		 * to subtract it from the header data, or null out the header
		 * data altogether if we wrote more than vec[0].sfv_len bytes.
		 * We move vec[1].* to vec[0].* and set sfvcnt to 1
		 */

		if (sfvcnt == 2 && nwritten >= vec[0].sfv_len) {
			vec[1].sfv_off += nwritten - vec[0].sfv_len;
			vec[1].sfv_len -= nwritten - vec[0].sfv_len;

			/* Move vec[1].* to vec[0].* and set sfvcnt to 1 */
			vec[0] = vec[1];
			sfvcnt = 1;
		} else {
			vec[0].sfv_off += nwritten;
			vec[0].sfv_len -= nwritten;
		}
		total -= nwritten;
	}
	ret = count + hdr_len;

  out:

	if (socket_flags_changed) {
		int saved_errno;
		int err;

		if (ret == -1) {
			saved_errno = errno;
		}
		/* Restore the old state of the socket. */
		err = fcntl(tofd, F_SETFL, old_flags);
		if (err == -1) {
			return -1;
		}
		if (ret == -1) {
			errno = saved_errno;
		}
	}

	return ret;
}

#elif defined(HPUX_SENDFILE_API)

#include <sys/socket.h>
#include <sys/uio.h>

ssize_t sys_sendfile(int tofd, int fromfd, const DATA_BLOB *header, off_t offset, size_t count)
{
	size_t total=0;
	struct iovec hdtrl[2];
	size_t hdr_len = 0;
	int old_flags = 0;
	ssize_t ret = -1;
	bool socket_flags_changed = false;

	if (header) {
		/* Set up the header/trailer iovec. */
		hdtrl[0].iov_base = (void *)header->data;
		hdtrl[0].iov_len = hdr_len = header->length;
	} else {
		hdtrl[0].iov_base = NULL;
		hdtrl[0].iov_len = hdr_len = 0;
	}
	hdtrl[1].iov_base = NULL;
	hdtrl[1].iov_len = 0;

	total = count;
	while (total + hdtrl[0].iov_len) {
		ssize_t nwritten;

		/*
		 * HPUX guarantees that if any data was written before
		 * a signal interrupt then sendfile returns the number of
		 * bytes written (which may be less than requested) not -1.
		 * nwritten includes the header data sent.
		 */

		do {
			nwritten = sendfile(tofd, fromfd, offset, total, &hdtrl[0], 0);
		} while (nwritten == -1 && errno == EINTR);
		if (nwritten == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/*
				 * Sendfile must complete before we can
				 * send any other outgoing data on the socket.
				 * Ensure socket is in blocking mode.
				 * For SMB2 by default the socket is in
				 * non-blocking mode.
				 */
				old_flags = fcntl(tofd, F_GETFL, 0);
				ret = set_blocking(tofd, true);
				if (ret == -1) {
					goto out;
				}
				socket_flags_changed = true;
				continue;
			}
			ret = -1;
			goto out;
		}
		if (nwritten == 0) {
			ret = -1; /* I think we're at EOF here... */
			goto out;
		}

		/*
		 * If this was a short (signal interrupted) write we may need
		 * to subtract it from the header data, or null out the header
		 * data altogether if we wrote more than hdtrl[0].iov_len bytes.
		 * We change nwritten to be the number of file bytes written.
		 */

		if (hdtrl[0].iov_base && hdtrl[0].iov_len) {
			if (nwritten >= hdtrl[0].iov_len) {
				nwritten -= hdtrl[0].iov_len;
				hdtrl[0].iov_base = NULL;
				hdtrl[0].iov_len = 0;
			} else {
				/* iov_base is defined as a void *... */
				hdtrl[0].iov_base = (void *)(((char *)hdtrl[0].iov_base) + nwritten);
				hdtrl[0].iov_len -= nwritten;
				nwritten = 0;
			}
		}
		total -= nwritten;
		offset += nwritten;
	}
	ret = count + hdr_len;

  out:

	if (socket_flags_changed) {
		int saved_errno;
		int err;

		if (ret == -1) {
			saved_errno = errno;
		}
		/* Restore the old state of the socket. */
		err = fcntl(tofd, F_SETFL, old_flags);
		if (err == -1) {
			return -1;
		}
		if (ret == -1) {
			errno = saved_errno;
		}
	}

	return ret;
}

#elif defined(FREEBSD_SENDFILE_API) || defined(DARWIN_SENDFILE_API)

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

ssize_t sys_sendfile(int tofd, int fromfd,
	    const DATA_BLOB *header, off_t offset, size_t count)
{
	struct sf_hdtr	sf_header = {0};
	struct iovec	io_header = {0};
	int old_flags = 0;

	off_t	nwritten;
	ssize_t	ret = -1;
	bool socket_flags_changed = false;

	if (header) {
		sf_header.headers = &io_header;
		sf_header.hdr_cnt = 1;
		io_header.iov_base = header->data;
		io_header.iov_len = header->length;
		sf_header.trailers = NULL;
		sf_header.trl_cnt = 0;
	}

	while (count != 0) {

		nwritten = count;
#if defined(DARWIN_SENDFILE_API)
		/* Darwin recycles nwritten as a value-result parameter, apart from that this
		   sendfile implementation is quite the same as the FreeBSD one */
		ret = sendfile(fromfd, tofd, offset, &nwritten, &sf_header, 0);
#else
		ret = sendfile(fromfd, tofd, offset, count, &sf_header, &nwritten, 0);
#endif
		if (ret == -1 && errno != EINTR) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/*
				 * Sendfile must complete before we can
				 * send any other outgoing data on the socket.
				 * Ensure socket is in blocking mode.
				 * For SMB2 by default the socket is in
				 * non-blocking mode.
				 */
				old_flags = fcntl(tofd, F_GETFL, 0);
				ret = set_blocking(tofd, true);
				if (ret == -1) {
					goto out;
				}
				socket_flags_changed = true;
				continue;
			}
			/* Send failed, we are toast. */
			ret = -1;
			goto out;
		}

		if (nwritten == 0) {
			/* EOF of offset is after EOF. */
			break;
		}

		if (sf_header.hdr_cnt) {
			if (io_header.iov_len <= nwritten) {
				/* Entire header was sent. */
				sf_header.headers = NULL;
				sf_header.hdr_cnt = 0;
				nwritten -= io_header.iov_len;
			} else {
				/* Partial header was sent. */
				io_header.iov_len -= nwritten;
				io_header.iov_base =
				    ((uint8_t *)io_header.iov_base) + nwritten;
				nwritten = 0;
			}
		}

		offset += nwritten;
		count -= nwritten;
	}

	ret = nwritten;

  out:

	if (socket_flags_changed) {
		int saved_errno;
		int err;

		if (ret == -1) {
			saved_errno = errno;
		}
		/* Restore the old state of the socket. */
		err = fcntl(tofd, F_SETFL, old_flags);
		if (err == -1) {
			return -1;
		}
		if (ret == -1) {
			errno = saved_errno;
		}
	}

	return ret;
}

#elif defined(AIX_SENDFILE_API)

/* BEGIN AIX SEND_FILE */

/* Contributed by William Jojo <jojowil@hvcc.edu> */
#include <sys/socket.h>

ssize_t sys_sendfile(int tofd, int fromfd, const DATA_BLOB *header, off_t offset, size_t count)
{
	struct sf_parms hdtrl;
	int old_flags = 0;
	ssize_t ret = -1;
	bool socket_flags_changed = false;

	/* Set up the header/trailer struct params. */
	if (header) {
		hdtrl.header_data = header->data;
		hdtrl.header_length = header->length;
	} else {
		hdtrl.header_data = NULL;
		hdtrl.header_length = 0;
	}
	hdtrl.trailer_data = NULL;
	hdtrl.trailer_length = 0;

	hdtrl.file_descriptor = fromfd;
	hdtrl.file_offset = offset;
	hdtrl.file_bytes = count;

	while ( hdtrl.file_bytes + hdtrl.header_length ) {
		/*
		 Return Value

		 There are three possible return values from send_file:

		 Value Description

		 -1 an error has occurred, errno contains the error code.

		 0 the command has completed successfully.

		 1 the command was completed partially, some data has been
		 transmitted but the command has to return for some reason,
		 for example, the command was interrupted by signals.
		*/
		do {
			ret = send_file(&tofd, &hdtrl, 0);
		} while ((ret == 1) || (ret == -1 && errno == EINTR));
		if ( ret == -1 ) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/*
				 * Sendfile must complete before we can
				 * send any other outgoing data on the socket.
				 * Ensure socket is in blocking mode.
				 * For SMB2 by default the socket is in
				 * non-blocking mode.
				 */
				old_flags = fcntl(tofd, F_GETFL, 0);
				ret = set_blocking(tofd, true);
				if (ret == -1) {
					goto out;
				}
				socket_flags_changed = true;
				continue;
			}
			goto out;
		}
	}

	ret = count + header->length;

  out:

	if (socket_flags_changed) {
		int saved_errno;
		int err;

		if (ret == -1) {
			saved_errno = errno;
		}
		/* Restore the old state of the socket. */
		err = fcntl(tofd, F_SETFL, old_flags);
		if (err == -1) {
			return -1;
		}
		if (ret == -1) {
			errno = saved_errno;
		}
	}

	return ret;
}
/* END AIX SEND_FILE */

#else /* No sendfile implementation. Return error. */

ssize_t sys_sendfile(int tofd, int fromfd, const DATA_BLOB *header, off_t offset, size_t count)
{
	/* No sendfile syscall. */
	errno = ENOSYS;
	return -1;
}
#endif
