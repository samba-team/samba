/* 
   Unix SMB/CIFS implementation.
   Samba system utilities
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 1998-2002
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/network.h"
#include "system/filesys.h"

#undef malloc

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
 A wrapper for memalign
********************************************************************/

void *sys_memalign( size_t align, size_t size )
{
#if defined(HAVE_POSIX_MEMALIGN)
	void *p = NULL;
	int ret = posix_memalign( &p, align, size );
	if ( ret == 0 )
		return p;

	return NULL;
#elif defined(HAVE_MEMALIGN)
	return memalign( align, size );
#else
	/* On *BSD systems memaligns doesn't exist, but memory will
	 * be aligned on allocations of > pagesize. */
#if defined(SYSCONF_SC_PAGESIZE)
	size_t pagesize = (size_t)sysconf(_SC_PAGESIZE);
#elif defined(HAVE_GETPAGESIZE)
	size_t pagesize = (size_t)getpagesize();
#else
	size_t pagesize = (size_t)-1;
#endif
	if (pagesize == (size_t)-1) {
		DEBUG(0,("memalign functionalaity not available on this platform!\n"));
		return NULL;
	}
	if (size < pagesize) {
		size = pagesize;
	}
	return malloc(size);
#endif
}

/**************************************************************************
 Wrapper for fork. Ensures we clear our pid cache.
****************************************************************************/

static pid_t mypid = (pid_t)-1;

_PUBLIC_ pid_t sys_fork(void)
{
	pid_t forkret = fork();

	if (forkret == (pid_t)0) {
		/* Child - reset mypid so sys_getpid does a system call. */
		mypid = (pid_t) -1;
	}

	return forkret;
}

/**************************************************************************
 Wrapper for getpid. Ensures we only do a system call *once*.
****************************************************************************/

_PUBLIC_ pid_t sys_getpid(void)
{
	if (mypid == (pid_t)-1)
		mypid = getpid();

	return mypid;
}


_PUBLIC_ int sys_getpeereid( int s, uid_t *uid)
{
#if defined(HAVE_PEERCRED)
	struct ucred cred;
	socklen_t cred_len = sizeof(struct ucred);
	int ret;

	ret = getsockopt(s, SOL_SOCKET, SO_PEERCRED, (void *)&cred, &cred_len);
	if (ret != 0) {
		return -1;
	}

	if (cred_len != sizeof(struct ucred)) {
		errno = EINVAL;
		return -1;
	}

	*uid = cred.uid;
	return 0;
#else
#if defined(HAVE_GETPEEREID)
	gid_t gid;
	return getpeereid(s, uid, &gid);
#endif
	errno = ENOSYS;
	return -1;
#endif
}

_PUBLIC_ int sys_getnameinfo(const struct sockaddr *psa,
			     int salen,
			     char *host,
			     size_t hostlen,
			     char *service,
			     size_t servlen,
			     int flags)
{
	/*
	 * For Solaris we must make sure salen is the
	 * correct length for the incoming sa_family.
	 */

	if (salen == sizeof(struct sockaddr_storage)) {
		salen = sizeof(struct sockaddr_in);
#if defined(HAVE_IPV6)
		if (psa->sa_family == AF_INET6) {
			salen = sizeof(struct sockaddr_in6);
		}
#endif
	}
	return getnameinfo(psa, salen, host, hostlen, service, servlen, flags);
}

_PUBLIC_ int sys_connect(int fd, const struct sockaddr * addr)
{
	socklen_t salen = (socklen_t)-1;

	if (addr->sa_family == AF_INET) {
	    salen = sizeof(struct sockaddr_in);
	} else if (addr->sa_family == AF_UNIX) {
	    salen = sizeof(struct sockaddr_un);
	}
#if defined(HAVE_IPV6)
	else if (addr->sa_family == AF_INET6) {
	    salen = sizeof(struct sockaddr_in6);
	}
#endif

	return connect(fd, addr, salen);
}

