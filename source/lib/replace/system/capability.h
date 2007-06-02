#ifndef _system_capability_h
#define _system_capability_h
/* 
   Unix SMB/CIFS implementation.

   capability system include wrappers

   Copyright (C) Andrew Tridgell 2004
   
     ** NOTE! The following LGPL license applies to the replace
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifdef HAVE_SYS_CAPABILITY_H

#if defined(BROKEN_REDHAT_7_SYSTEM_HEADERS) && !defined(_I386_STATFS_H)
#define _I386_STATFS_H
#define BROKEN_REDHAT_7_STATFS_WORKAROUND
#endif

#include <sys/capability.h>

#ifdef BROKEN_REDHAT_7_STATFS_WORKAROUND
#undef _I386_STATFS_H
#undef BROKEN_REDHAT_7_STATFS_WORKAROUND
#endif

#endif

#endif
