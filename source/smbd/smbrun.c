/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   external program running routine
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
close the low 3 fd's and open dev/null in their place
********************************************************************/
static void close_fds(void)
{
  int fd;
  int i;
  close(0); close(1); close(2);
  /* try and use up these file descriptors, so silly
     library routines writing to stdout etc won't cause havoc */
  for (i=0;i<3;i++) {
    fd = open("/dev/null",O_RDWR,0);
    if (fd < 0) fd = open("/dev/null",O_WRONLY,0);
    if (fd != i) return;
  }
}


/*
This is a wrapper around the system() call to allow commands to run correctly 
as non root from a program which is switching between root and non-root 

It takes 3 arguments as uid,gid,command and runs command after
becoming a non-root user */
 int main(int argc,char *argv[])
{
  int uid,gid;

  close_fds();

  if (argc != 4) exit(2);

  uid = atoi(argv[1]);
  gid = atoi(argv[2]);

  /* first become root - we may need to do this in order to lose
     our privilages! */
#ifdef USE_SETRES
  setresgid(0,0,0);
  setresuid(0,0,0);
#else      
  setuid(0);
  seteuid(0);
#endif

#ifdef USE_SETFS
  setfsuid(uid);
  setfsgid(gid);
#endif

#ifdef USE_SETRES
  setresgid(gid,gid,gid);
  setresuid(uid,uid,uid);      
#else
  setgid(gid);
  setegid(gid);
  setuid(uid);
  seteuid(uid);
#endif


  /* paranoia :-) */
  if (getuid() != uid)
    return(3);

  if (geteuid() != getuid())
    return(4);

  /* this is to make sure that the system() call doesn't run forever */
  alarm(30);

  return(system(argv[3]));
}
