/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba system utilities
   Copyright (C) Andrew Tridgell 1992-1995
   
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

extern int DEBUGLEVEL;

/*
   The idea is that this file will eventually have wrappers around all
   important system calls in samba. The aims are:

   - to enable easier porting by putting OS dependent stuff in here

   - to allow for hooks into other "pseudo-filesystems"

   - to allow easier integration of things like the japanese extensions

   - to support the philosophy of Samba to expose the features of
     the OS within the SMB model. In general whatever file/printer/variable
     expansions/etc make sense to the OS should be acceptable to Samba.
*/


/*******************************************************************
this replaces the normal select() system call
return if some data has arrived on one of the file descriptors
return -1 means error
********************************************************************/
#ifdef NO_SELECT
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

int sys_select(fd_set *fds,struct timeval *tval)
{
  fd_set fds2;
  int counter=0;
  int found=0;

  FD_ZERO(&fds2);

  while (1) 
    {
      int i;
      for (i=0;i<255;i++) {
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

#else
int sys_select(fd_set *fds,struct timeval *tval)
{
  struct timeval t2;
  int selrtn;

  do {
    if (tval) memcpy((void *)&t2,(void *)tval,sizeof(t2));
    errno = 0;
    selrtn = select(255,SELECT_CAST fds,NULL,NULL,tval?&t2:NULL);
  } while (selrtn<0 && errno == EINTR);

  return(selrtn);
}
#endif


/*******************************************************************
just a unlink wrapper
********************************************************************/
int sys_unlink(char *fname)
{
  return(unlink(dos_to_unix(fname,False)));
}


/*******************************************************************
a simple open() wrapper
********************************************************************/
int sys_open(char *fname,int flags,int mode)
{
  return(open(dos_to_unix(fname,False),flags,mode));
}


/*******************************************************************
a simple opendir() wrapper
********************************************************************/
DIR *sys_opendir(char *dname)
{
  return(opendir(dos_to_unix(dname,False)));
}


/*******************************************************************
and a stat() wrapper
********************************************************************/
int sys_stat(char *fname,struct stat *sbuf)
{
  return(stat(dos_to_unix(fname,False),sbuf));
}

/*******************************************************************
don't forget lstat()
********************************************************************/
int sys_lstat(char *fname,struct stat *sbuf)
{
  return(lstat(dos_to_unix(fname,False),sbuf));
}


/*******************************************************************
mkdir() gets a wrapper
********************************************************************/
int sys_mkdir(char *dname,int mode)
{
  return(mkdir(dos_to_unix(dname,False),mode));
}


/*******************************************************************
do does rmdir()
********************************************************************/
int sys_rmdir(char *dname)
{
  return(rmdir(dos_to_unix(dname,False)));
}


/*******************************************************************
I almost forgot chdir()
********************************************************************/
int sys_chdir(char *dname)
{
  return(chdir(dos_to_unix(dname,False)));
}


/*******************************************************************
now for utime()
********************************************************************/
int sys_utime(char *fname,struct utimbuf *times)
{
  return(utime(dos_to_unix(fname,False),times));
}

/*******************************************************************
for rename()
********************************************************************/
int sys_rename(char *from, char *to)
{
#ifdef KANJI
    pstring zfrom, zto;
    strcpy (zfrom, dos_to_unix (from, False));
    strcpy (zto, dos_to_unix (to, False));
    return rename (zfrom, zto);
#else 
    return rename (from, to);
#endif /* KANJI */
}

/*******************************************************************
for chmod
********************************************************************/
int sys_chmod(char *fname,int mode)
{
  return(chmod(dos_to_unix(fname,False),mode));
}

/*******************************************************************
chown isn't used much but OS/2 doesn't have it
********************************************************************/
int sys_chown(char *fname,int uid,int gid)
{
#ifdef NO_CHOWN
  DEBUG(1,("Warning - chown(%s,%d,%d) not done\n",fname,uid,gid));
#else
  return(chown(fname,uid,gid));
#endif
}

/*******************************************************************
os/2 also doesn't have chroot
********************************************************************/
int sys_chroot(char *dname)
{
#ifdef NO_CHROOT
  DEBUG(1,("Warning - chroot(%s) not done\n",dname));
#else
  return(chroot(dname));
#endif
}
