/* 
   Unix SMB/CIFS implementation.

   Winbind daemon for ntdom nss module

   Copyright (C) Tim Potter 2000
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the
   Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA  02111-1307, USA.   
*/

#ifndef _WINBIND_NSS_CONFIG_H
#define _WINBIND_NSS_CONFIG_H

/* Include header files from data in config.h file */

#ifndef NO_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_UNIXSOCKET
#include <sys/un.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#else
#ifdef HAVE_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#include "nsswitch/winbind_nss.h"

#ifndef Auto
#define False (0)
#define True (1)
#define Auto (2)
typedef int BOOL;
#endif

/* zero a structure */
#ifndef ZERO_STRUCT
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))
#endif

/* zero a structure given a pointer to the structure */
#ifndef ZERO_STRUCTP
#define ZERO_STRUCTP(x) { if ((x) != NULL) memset((char *)(x), 0, sizeof(*(x))); }
#endif

/* Some systems (SCO) treat UNIX domain sockets as FIFOs */

#ifndef S_IFSOCK
#define S_IFSOCK S_IFIFO
#endif

#ifndef S_ISSOCK
#define S_ISSOCK(mode)  ((mode & S_IFSOCK) == S_IFSOCK)
#endif

#endif
