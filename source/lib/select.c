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

/*******************************************************************
this replaces the normal select() system call
return if some data has arrived on one of the file descriptors
return -1 means error
********************************************************************/
#ifndef HAVE_SELECT
static int pollfd(int fd)
{
  int     r=0;

#ifdef HAS_RDCHK
  r = rdchk(fd);
#elif defined(TCRDCHK)
  (void)ioctl(fd, TCRDCHK, &r);
#else
  (void)ioctl(fd, FIONREAD, &r);
#endif

  return(r);
}

int sys_select(int maxfd, fd_set *fds,struct timeval *tval)
{
  fd_set fds2;
  int counter=0;
  int found=0;

  FD_ZERO(&fds2);

  while (1) 
  {
    int i;
    for (i=0;i<maxfd;i++) {
      if (FD_ISSET(i,fds) && pollfd(i)>0) {
        found++;
        FD_SET(i,&fds2);
      }
    }

    if (found) {
      memcpy((void *)fds,(void *)&fds2,sizeof(fds2));
      return(found);
    }
      
    if (tval && tval->tv_sec < counter) return(0);
      sleep(1);
      counter++;
  }
}

#else /* !NO_SELECT */
int sys_select(int maxfd, fd_set *fds,struct timeval *tval)
{
#ifdef USE_POLL
  struct pollfd pfd[256];
  int i;
  int maxpoll;
  int timeout;
  int pollrtn;

  maxpoll = 0;
  for( i = 0; i < maxfd; i++) {
    if(FD_ISSET(i,fds)) {
      struct pollfd *pfdp = &pfd[maxpoll++];
      pfdp->fd = i;
      pfdp->events = POLLIN;
      pfdp->revents = 0;
    }
  }

  timeout = (tval != NULL) ? (tval->tv_sec * 1000) + (tval->tv_usec/1000) :
                -1;
  errno = 0;
  do {
    pollrtn = poll( &pfd[0], maxpoll, timeout);
  } while (pollrtn<0 && errno == EINTR);

  FD_ZERO(fds);

  for( i = 0; i < maxpoll; i++)
    if( pfd[i].revents & POLLIN )
      FD_SET(pfd[i].fd,fds);

  return pollrtn;
#else /* USE_POLL */

  struct timeval t2;
  int selrtn;

  do {
    if (tval) memcpy((void *)&t2,(void *)tval,sizeof(t2));
    errno = 0;
    selrtn = select(maxfd,SELECT_CAST fds,NULL,NULL,tval?&t2:NULL);
  } while (selrtn<0 && errno == EINTR);

  return(selrtn);
}
#endif /* USE_POLL */
#endif /* NO_SELECT */
