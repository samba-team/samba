/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   Samba select/poll implementation
   Copyright (C) Andrew Tridgell 1992-1998
   
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

#include "includes.h"

/* This is here because it allows us to avoid a nasty race in signal handling. 
   We need to guarantee that when we get a signal we get out of a select immediately
   but doing that involves a race condition. We can avoid the race by getting the 
   signal handler to write to a pipe that is in the select/poll list 

   This means all Samba signal handlers should call sys_select_signal().
*/

static pid_t initialised;
static int select_pipe[2];
static VOLATILE unsigned pipe_written, pipe_read;

/*******************************************************************
 Call this from all Samba signal handlers if you want to avoid a 
 nasty signal race condition.
********************************************************************/

void sys_select_signal(void)
{
	char c = 1;
	if (!initialised) return;

	if (pipe_written > pipe_read+256) return;

	if (write(select_pipe[1], &c, 1) == 1) pipe_written++;
}

/*******************************************************************
 Like select() but avoids the signal race using a pipe
 it also guuarantees that fds on return only ever contains bits set
 for file descriptors that were readable.
********************************************************************/

int sys_select(int maxfd, fd_set *readfds, fd_set *writefds, fd_set *errorfds, struct timeval *tval)
{
	int ret, saved_errno;
	fd_set *readfds2, readfds_buf;

	if (initialised != sys_getpid()) {
		pipe(select_pipe);

		/*
		 * These next two lines seem to fix a bug with the Linux
		 * 2.0.x kernel (and probably other UNIXes as well) where
		 * the one byte read below can block even though the
		 * select returned that there is data in the pipe and
		 * the pipe_written variable was incremented. Thanks to
		 * HP for finding this one. JRA.
		 */

		if(set_blocking(select_pipe[0],0)==-1)
			smb_panic("select_pipe[0]: O_NONBLOCK failed.\n");
		if(set_blocking(select_pipe[1],0)==-1)
			smb_panic("select_pipe[1]: O_NONBLOCK failed.\n");

		initialised = sys_getpid();
	}

	maxfd = MAX(select_pipe[0]+1, maxfd);

	/* If readfds is NULL we need to provide our own set. */
	if (readfds) {
		readfds2 = readfds;
	} else {
		readfds2 = &readfds_buf;
		FD_ZERO(readfds2);
	}
	FD_SET(select_pipe[0], readfds2);

	errno = 0;
	ret = select(maxfd,readfds2,writefds,errorfds,tval);

	if (ret <= 0) {
		FD_ZERO(readfds2);
		if (writefds)
			FD_ZERO(writefds);
		if (errorfds)
			FD_ZERO(errorfds);
	}

	if (FD_ISSET(select_pipe[0], readfds2)) {
		char c;
		saved_errno = errno;
		if (read(select_pipe[0], &c, 1) == 1) {
			pipe_read++;
		}
		errno = saved_errno;
		FD_CLR(select_pipe[0], readfds2);
		ret--;
		if (ret == 0) {
			ret = -1;
			errno = EINTR;
		}
	}

	return ret;
}

/*******************************************************************
 Similar to sys_select() but catch EINTR and continue.
 This is what sys_select() used to do in Samba.
********************************************************************/

int sys_select_intr(int maxfd, fd_set *readfds, fd_set *writefds, fd_set *errorfds, struct timeval *tval)
{
	int ret;
	fd_set *readfds2, readfds_buf, *writefds2, writefds_buf, *errorfds2, errorfds_buf;
	struct timeval tval2, *ptval;

	readfds2 = (readfds ? &readfds_buf : NULL);
	writefds2 = (writefds ? &writefds_buf : NULL);
	errorfds2 = (errorfds ? &errorfds_buf : NULL);
	ptval = (tval ? &tval2 : NULL);

	do {
		if (readfds)
			readfds_buf = *readfds;
		if (writefds)
			writefds_buf = *writefds;
		if (errorfds)
			errorfds_buf = *errorfds;
		if (tval)
			tval2 = *tval;

		ret = sys_select(maxfd, readfds2, writefds2, errorfds2, ptval);
	} while (ret == -1 && errno == EINTR);

	if (readfds)
		*readfds = readfds_buf;
	if (writefds)
		*writefds = writefds_buf;
	if (errorfds)
		*errorfds = errorfds_buf;

	return ret;
}
