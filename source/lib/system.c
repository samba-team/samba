/* 
   Unix SMB/CIFS implementation.
   Samba system utilities
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 1998-2002
   
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
 A wrapper for usleep in case we don't have one.
********************************************************************/

int sys_usleep(long usecs)
{
#ifndef HAVE_USLEEP
	struct timeval tval;
#endif

	/*
	 * We need this braindamage as the glibc usleep
	 * is not SPEC1170 complient... grumble... JRA.
	 */

	if(usecs < 0 || usecs > 1000000) {
		errno = EINVAL;
		return -1;
	}

#if HAVE_USLEEP
	usleep(usecs);
	return 0;
#else /* HAVE_USLEEP */
	/*
	 * Fake it with select...
	 */
	tval.tv_sec = 0;
	tval.tv_usec = usecs/1000;
	select(0,NULL,NULL,NULL,&tval);
	return 0;
#endif /* HAVE_USLEEP */
}

/*******************************************************************
A read wrapper that will deal with EINTR.
********************************************************************/

ssize_t sys_read(int fd, void *buf, size_t count)
{
	ssize_t ret;

	do {
		ret = read(fd, buf, count);
	} while (ret == -1 && errno == EINTR);
	return ret;
}

/*******************************************************************
A write wrapper that will deal with EINTR.
********************************************************************/

ssize_t sys_write(int fd, const void *buf, size_t count)
{
	ssize_t ret;

	do {
		ret = write(fd, buf, count);
	} while (ret == -1 && errno == EINTR);
	return ret;
}

/*******************************************************************
A send wrapper that will deal with EINTR.
********************************************************************/

ssize_t sys_send(int s, const void *msg, size_t len, int flags)
{
	ssize_t ret;

	do {
		ret = send(s, msg, len, flags);
	} while (ret == -1 && errno == EINTR);
	return ret;
}

/*******************************************************************
A sendto wrapper that will deal with EINTR.
********************************************************************/

ssize_t sys_sendto(int s,  const void *msg, size_t len, int flags, const struct sockaddr *to, socklen_t tolen)
{
	ssize_t ret;

	do {
		ret = sendto(s, msg, len, flags, to, tolen);
	} while (ret == -1 && errno == EINTR);
	return ret;
}

/*******************************************************************
A recvfrom wrapper that will deal with EINTR.
********************************************************************/

ssize_t sys_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{
	ssize_t ret;

	do {
		ret = recvfrom(s, buf, len, flags, from, fromlen);
	} while (ret == -1 && errno == EINTR);
	return ret;
}

/*******************************************************************
A fcntl wrapper that will deal with EINTR.
********************************************************************/

int sys_fcntl_ptr(int fd, int cmd, void *arg)
{
	int ret;

	do {
		ret = fcntl(fd, cmd, arg);
	} while (ret == -1 && errno == EINTR);
	return ret;
}

/*******************************************************************
A fcntl wrapper that will deal with EINTR.
********************************************************************/

int sys_fcntl_long(int fd, int cmd, long arg)
{
	int ret;

	do {
		ret = fcntl(fd, cmd, arg);
	} while (ret == -1 && errno == EINTR);
	return ret;
}

/*******************************************************************
A stat() wrapper that will deal with 64 bit filesizes.
********************************************************************/

int sys_stat(const char *fname,SMB_STRUCT_STAT *sbuf)
{
	int ret;
#if defined(HAVE_EXPLICIT_LARGEFILE_SUPPORT) && defined(HAVE_OFF64_T) && defined(HAVE_STAT64)
	ret = stat64(fname, sbuf);
#else
	ret = stat(fname, sbuf);
#endif
	/* we always want directories to appear zero size */
	if (ret == 0 && S_ISDIR(sbuf->st_mode)) sbuf->st_size = 0;
	return ret;
}

/*******************************************************************
 An fstat() wrapper that will deal with 64 bit filesizes.
********************************************************************/

int sys_fstat(int fd,SMB_STRUCT_STAT *sbuf)
{
	int ret;
#if defined(HAVE_EXPLICIT_LARGEFILE_SUPPORT) && defined(HAVE_OFF64_T) && defined(HAVE_FSTAT64)
	ret = fstat64(fd, sbuf);
#else
	ret = fstat(fd, sbuf);
#endif
	/* we always want directories to appear zero size */
	if (ret == 0 && S_ISDIR(sbuf->st_mode)) sbuf->st_size = 0;
	return ret;
}

/*******************************************************************
 An lstat() wrapper that will deal with 64 bit filesizes.
********************************************************************/

int sys_lstat(const char *fname,SMB_STRUCT_STAT *sbuf)
{
	int ret;
#if defined(HAVE_EXPLICIT_LARGEFILE_SUPPORT) && defined(HAVE_OFF64_T) && defined(HAVE_LSTAT64)
	ret = lstat64(fname, sbuf);
#else
	ret = lstat(fname, sbuf);
#endif
	/* we always want directories to appear zero size */
	if (ret == 0 && S_ISDIR(sbuf->st_mode)) sbuf->st_size = 0;
	return ret;
}

/*******************************************************************
 An ftruncate() wrapper that will deal with 64 bit filesizes.
********************************************************************/

int sys_ftruncate(int fd, SMB_OFF_T offset)
{
#if defined(HAVE_EXPLICIT_LARGEFILE_SUPPORT) && defined(HAVE_OFF64_T) && defined(HAVE_FTRUNCATE64)
	return ftruncate64(fd, offset);
#else
	return ftruncate(fd, offset);
#endif
}

/*******************************************************************
 An lseek() wrapper that will deal with 64 bit filesizes.
********************************************************************/

SMB_OFF_T sys_lseek(int fd, SMB_OFF_T offset, int whence)
{
#if defined(HAVE_EXPLICIT_LARGEFILE_SUPPORT) && defined(HAVE_OFF64_T) && defined(HAVE_LSEEK64)
	return lseek64(fd, offset, whence);
#else
	return lseek(fd, offset, whence);
#endif
}

/*******************************************************************
 A creat() wrapper that will deal with 64 bit filesizes.
********************************************************************/

int sys_creat(const char *path, mode_t mode)
{
#if defined(HAVE_EXPLICIT_LARGEFILE_SUPPORT) && defined(HAVE_CREAT64)
	return creat64(path, mode);
#else
	/*
	 * If creat64 isn't defined then ensure we call a potential open64.
	 * JRA.
	 */
	return sys_open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
#endif
}

/*******************************************************************
 An open() wrapper that will deal with 64 bit filesizes.
********************************************************************/

int sys_open(const char *path, int oflag, mode_t mode)
{
#if defined(HAVE_EXPLICIT_LARGEFILE_SUPPORT) && defined(HAVE_OPEN64)
	return open64(path, oflag, mode);
#else
	return open(path, oflag, mode);
#endif
}

/*******************************************************************
 An fopen() wrapper that will deal with 64 bit filesizes.
********************************************************************/

FILE *sys_fopen(const char *path, const char *type)
{
#if defined(HAVE_EXPLICIT_LARGEFILE_SUPPORT) && defined(HAVE_FOPEN64)
	return fopen64(path, type);
#else
	return fopen(path, type);
#endif
}

/*******************************************************************
 A readdir wrapper that will deal with 64 bit filesizes.
********************************************************************/

struct smb_dirent *sys_readdir(DIR *dirp)
{
#if defined(HAVE_EXPLICIT_LARGEFILE_SUPPORT) && defined(HAVE_READDIR64)
	return readdir64(dirp);
#else
	return readdir(dirp);
#endif
}

/*******************************************************************
The wait() calls vary between systems
********************************************************************/

int sys_waitpid(pid_t pid,int *status,int options)
{
#ifdef HAVE_WAITPID
	return waitpid(pid,status,options);
#else /* HAVE_WAITPID */
	return wait4(pid, status, options, NULL);
#endif /* HAVE_WAITPID */
}

/*******************************************************************
 System wrapper for getwd
********************************************************************/

char *sys_getwd(char *s)
{
	char *wd;
#ifdef HAVE_GETCWD
	wd = (char *)getcwd(s, sizeof (pstring));
#else
	wd = (char *)getwd(s);
#endif
	return wd;
}

/*******************************************************************
system wrapper for link
********************************************************************/

int sys_link(const char *oldpath, const char *newpath)
{
#ifndef HAVE_LINK
	errno = ENOSYS;
	return -1;
#else
	return link(oldpath, newpath);
#endif
}

/*******************************************************************
os/2 also doesn't have chroot
********************************************************************/
int sys_chroot(const char *dname)
{
#ifndef HAVE_CHROOT
	static int done;
	if (!done) {
		DEBUG(1,("WARNING: no chroot!\n"));
		done=1;
	}
	errno = ENOSYS;
	return -1;
#else
	return(chroot(dname));
#endif
}

/**************************************************************************
A wrapper for gethostbyname() that tries avoids looking up hostnames 
in the root domain, which can cause dial-on-demand links to come up for no
apparent reason.
****************************************************************************/

struct hostent *sys_gethostbyname(const char *name)
{
#ifdef REDUCE_ROOT_DNS_LOOKUPS
	char query[256], hostname[256];
	char *domain;

	/* Does this name have any dots in it? If so, make no change */

	if (strchr_m(name, '.'))
		return(gethostbyname(name));

	/* Get my hostname, which should have domain name 
		attached. If not, just do the gethostname on the
		original string. 
	*/

	gethostname(hostname, sizeof(hostname) - 1);
	hostname[sizeof(hostname) - 1] = 0;
	if ((domain = strchr_m(hostname, '.')) == NULL)
		return(gethostbyname(name));

	/* Attach domain name to query and do modified query.
		If names too large, just do gethostname on the
		original string.
	*/

	if((strlen(name) + strlen(domain)) >= sizeof(query))
		return(gethostbyname(name));

	slprintf(query, sizeof(query)-1, "%s%s", name, domain);
	return(gethostbyname(query));
#else /* REDUCE_ROOT_DNS_LOOKUPS */
	return(gethostbyname(name));
#endif /* REDUCE_ROOT_DNS_LOOKUPS */
}


#if defined(HAVE_IRIX_SPECIFIC_CAPABILITIES)
/**************************************************************************
 Try and abstract process capabilities (for systems that have them).
****************************************************************************/
static BOOL set_process_capability( uint32_t cap_flag, BOOL enable )
{
	if(cap_flag == KERNEL_OPLOCK_CAPABILITY) {
		cap_t cap = cap_get_proc();

		if (cap == NULL) {
			DEBUG(0,("set_process_capability: cap_get_proc failed. Error was %s\n",
				strerror(errno)));
			return False;
		}

		if(enable)
			cap->cap_effective |= CAP_NETWORK_MGT;
		else
			cap->cap_effective &= ~CAP_NETWORK_MGT;

		if (cap_set_proc(cap) == -1) {
			DEBUG(0,("set_process_capability: cap_set_proc failed. Error was %s\n",
				strerror(errno)));
			cap_free(cap);
			return False;
		}

		cap_free(cap);

		DEBUG(10,("set_process_capability: Set KERNEL_OPLOCK_CAPABILITY.\n"));
	}
	return True;
}

/**************************************************************************
 Try and abstract inherited process capabilities (for systems that have them).
****************************************************************************/

static BOOL set_inherited_process_capability( uint32_t cap_flag, BOOL enable )
{
	if(cap_flag == KERNEL_OPLOCK_CAPABILITY) {
		cap_t cap = cap_get_proc();

		if (cap == NULL) {
			DEBUG(0,("set_inherited_process_capability: cap_get_proc failed. Error was %s\n",
				strerror(errno)));
			return False;
		}

		if(enable)
			cap->cap_inheritable |= CAP_NETWORK_MGT;
		else
			cap->cap_inheritable &= ~CAP_NETWORK_MGT;

		if (cap_set_proc(cap) == -1) {
			DEBUG(0,("set_inherited_process_capability: cap_set_proc failed. Error was %s\n", 
				strerror(errno)));
			cap_free(cap);
			return False;
		}

		cap_free(cap);

		DEBUG(10,("set_inherited_process_capability: Set KERNEL_OPLOCK_CAPABILITY.\n"));
	}
	return True;
}
#endif

/****************************************************************************
 Gain the oplock capability from the kernel if possible.
****************************************************************************/

void oplock_set_capability(BOOL this_process, BOOL inherit)
{
#if HAVE_KERNEL_OPLOCKS_IRIX
	set_process_capability(KERNEL_OPLOCK_CAPABILITY,this_process);
	set_inherited_process_capability(KERNEL_OPLOCK_CAPABILITY,inherit);
#endif
}

/**************************************************************************
 Wrapper for random().
****************************************************************************/

long sys_random(void)
{
#if defined(HAVE_RANDOM)
	return (long)random();
#elif defined(HAVE_RAND)
	return (long)rand();
#else
	DEBUG(0,("Error - no random function available !\n"));
	exit(1);
#endif
}

/**************************************************************************
 Wrapper for srandom().
****************************************************************************/

void sys_srandom(uint_t seed)
{
#if defined(HAVE_SRANDOM)
	srandom(seed);
#elif defined(HAVE_SRAND)
	srand(seed);
#else
	DEBUG(0,("Error - no srandom function available !\n"));
	exit(1);
#endif
}

/**************************************************************************
 Returns equivalent to NGROUPS_MAX - using sysconf if needed.
****************************************************************************/

int groups_max(void)
{
#if defined(SYSCONF_SC_NGROUPS_MAX)
	int ret = sysconf(_SC_NGROUPS_MAX);
	return (ret == -1) ? NGROUPS_MAX : ret;
#else
	return NGROUPS_MAX;
#endif
}

/**************************************************************************
 Wrapper for getgroups. Deals with broken (int) case.
****************************************************************************/

int sys_getgroups(int setlen, gid_t *gidset)
{
#if !defined(HAVE_BROKEN_GETGROUPS)
	return getgroups(setlen, gidset);
#else

	GID_T gid;
	GID_T *group_list;
	int i, ngroups;

	if(setlen == 0) {
		return getgroups(setlen, &gid);
	}

	/*
	 * Broken case. We need to allocate a
	 * GID_T array of size setlen.
	 */

	if(setlen < 0) {
		errno = EINVAL; 
		return -1;
	} 

	if (setlen == 0)
		setlen = groups_max();

	if((group_list = (GID_T *)malloc(setlen * sizeof(GID_T))) == NULL) {
		DEBUG(0,("sys_getgroups: Malloc fail.\n"));
		return -1;
	}

	if((ngroups = getgroups(setlen, group_list)) < 0) {
		int saved_errno = errno;
		SAFE_FREE(group_list);
		errno = saved_errno;
		return -1;
	}

	for(i = 0; i < ngroups; i++)
		gidset[i] = (gid_t)group_list[i];

	SAFE_FREE(group_list);
	return ngroups;
#endif /* HAVE_BROKEN_GETGROUPS */
}

#ifdef HAVE_SETGROUPS

/**************************************************************************
 Wrapper for setgroups. Deals with broken (int) case. Automatically used
 if we have broken getgroups.
****************************************************************************/

int sys_setgroups(int setlen, gid_t *gidset)
{
#if !defined(HAVE_BROKEN_GETGROUPS)
	return setgroups(setlen, gidset);
#else

	GID_T *group_list;
	int i ; 

	if (setlen == 0)
		return 0 ;

	if (setlen < 0 || setlen > groups_max()) {
		errno = EINVAL; 
		return -1;   
	}

	/*
	 * Broken case. We need to allocate a
	 * GID_T array of size setlen.
	 */

	if((group_list = (GID_T *)malloc(setlen * sizeof(GID_T))) == NULL) {
		DEBUG(0,("sys_setgroups: Malloc fail.\n"));
		return -1;    
	}
 
	for(i = 0; i < setlen; i++) 
		group_list[i] = (GID_T) gidset[i]; 

	if(setgroups(setlen, group_list) != 0) {
		int saved_errno = errno;
		SAFE_FREE(group_list);
		errno = saved_errno;
		return -1;
	}
 
	SAFE_FREE(group_list);
	return 0 ;
#endif /* HAVE_BROKEN_GETGROUPS */
}

#endif /* HAVE_SETGROUPS */

struct passwd *sys_getpwent(void)
{
	return getpwent();
}

void sys_endpwent(void)
{
	endpwent();
}

/**************************************************************************
 Wrappers for getpwnam(), getpwuid(), getgrnam(), getgrgid()
****************************************************************************/

struct passwd *sys_getpwnam(const char *name)
{
	return getpwnam(name);
}

struct passwd *sys_getpwuid(uid_t uid)
{
	return getpwuid(uid);
}

struct group *sys_getgrnam(const char *name)
{
	return getgrnam(name);
}

struct group *sys_getgrgid(gid_t gid)
{
	return getgrgid(gid);
}


/**************************************************************************
 Wrappers for dlopen, dlsym, dlclose.
****************************************************************************/

void *sys_dlopen(const char *name, int flags)
{
#if defined(HAVE_DLOPEN)
	return dlopen(name, flags);
#else
	return NULL;
#endif
}

void *sys_dlsym(void *handle, const char *symbol)
{
#if defined(HAVE_DLSYM)
    return dlsym(handle, symbol);
#else
    return NULL;
#endif
}

int sys_dlclose (void *handle)
{
#if defined(HAVE_DLCLOSE)
	return dlclose(handle);
#else
	return 0;
#endif
}

const char *sys_dlerror(void)
{
#if defined(HAVE_DLERROR)
	return dlerror();
#else
	return NULL;
#endif
}

int sys_dup2(int oldfd, int newfd) 
{
#if defined(HAVE_DUP2)
	return dup2(oldfd, newfd);
#else
	errno = ENOSYS;
	return -1;
#endif
}

