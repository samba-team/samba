#ifndef _system_threads_h
#define _system_threads_h
/*
   Unix SMB/CIFS implementation.

   macros to go along with the lib/replace/ portability layer code

   Copyright (C) Volker Lendecke 2012

     ** NOTE! The following LGPL license applies to the replace
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

#include <pthread.h>

#if defined(HAVE_PTHREAD_MUTEXATTR_SETROBUST_NP) && \
	!defined(HAVE_PTHREAD_MUTEXATTR_SETROBUST)
#define pthread_mutexattr_setrobust pthread_mutexattr_setrobust_np
#endif

#if defined(HAVE_DECL_PTHREAD_MUTEX_ROBUST_NP) && \
	!defined(HAVE_DECL_PTHREAD_MUTEX_ROBUST)
#define PTHREAD_MUTEX_ROBUST PTHREAD_MUTEX_ROBUST_NP
#endif

#if defined(HAVE_PTHREAD_MUTEX_CONSISTENT_NP) && \
	!defined(HAVE_PTHREAD_MUTEX_CONSISTENT)
#define pthread_mutex_consistent pthread_mutex_consistent_np
#endif

#endif
