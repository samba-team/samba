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

/* this is here because it allows us to avoid a nasty race in signal handling. 
   We need to guarantee that when we get a signal we get out of a select immediately
   but doing that involves a race condition. We can avoid the race by getting the 
   signal handler to write to a pipe that is in the select/poll list 

   this means all Samba signal handlers should call sys_select_signal()
*/
static pid_t initialised;
static int select_pipe[2];
static VOLATILE unsigned pipe_written, pipe_read;


/*******************************************************************
call this from all Samba signal handlers if you want to avoid a 
nasty signal race condition
********************************************************************/
void sys_select_signal(void)
{
	char c = 1;
	if (!initialised) return;

	if (pipe_written > pipe_read+256) return;

	if (write(select_pipe[1], &c, 1) == 1) pipe_written++;
}

/*******************************************************************
like select() but avoids the signal race using a pipe
it also guuarantees that fds on return only ever contains bits set
for file descriptors that were readable
********************************************************************/
int sys_select(int maxfd, fd_set *fds,struct timeval *tval)
{
	int ret;

	if (initialised != sys_getpid()) {
		initialised = sys_getpid();
		pipe(select_pipe);
	}

	maxfd = MAX(select_pipe[0]+1, maxfd);
	FD_SET(select_pipe[0], fds);
	errno = 0;
	ret = select(maxfd,fds,NULL,NULL,tval);

	if (ret <= 0) {
		FD_ZERO(fds);
	}

	if (FD_ISSET(select_pipe[0], fds)) {
		FD_CLR(select_pipe[0], fds);
		ret--;
		if (ret == 0) {
			ret = -1;
			errno = EINTR;
		}
	}

	while (pipe_written != pipe_read) {
		char c;
		if (read(select_pipe[0], &c, 1) == 1) pipe_read++;
	}

	return ret;
}

/*******************************************************************
similar to sys_select() but catch EINTR and continue
this is what sys_select() used to do in Samba
********************************************************************/
int sys_select_intr(int maxfd, fd_set *fds,struct timeval *tval)
{
	int ret;
	fd_set fds2;

	do {
		fds2 = *fds;
		ret = sys_select(maxfd, &fds2, tval);
	} while (ret == -1 && errno == EINTR);

	*fds = fds2;

	return ret;
}
