/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba system utilities
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

/*******************************************************************
A stat() wrapper that will deal with 64 bit filesizes.
********************************************************************/

int sys_stat(char *fname,SMB_STRUCT_STAT *sbuf)
{
#if defined(HAVE_OFF64_T) && defined(HAVE_STAT64)
  return stat64(fname, sbuf);
#else
  return stat(fname, sbuf);
#endif
}

/*******************************************************************
 An fstat() wrapper that will deal with 64 bit filesizes.
********************************************************************/

int sys_fstat(int fd,SMB_STRUCT_STAT *sbuf)
{
#if defined(HAVE_OFF64_T) && defined(HAVE_FSTAT64)
  return fstat64(fd, sbuf);
#else
  return fstat(fd, sbuf);
#endif
}

/*******************************************************************
 An lstat() wrapper that will deal with 64 bit filesizes.
********************************************************************/

int sys_lstat(char *fname,SMB_STRUCT_STAT *sbuf)
{
#if defined(HAVE_OFF64_T) && defined(HAVE_LSTAT64)
  return lstat64(fname, sbuf);
#else
  return lstat(fname, sbuf);
#endif
}

/*******************************************************************
 An ftruncate() wrapper that will deal with 64 bit filesizes.
********************************************************************/

int sys_ftruncate(int fd, SMB_OFF_T offset)
{
#if defined(HAVE_OFF64_T) && defined(HAVE_FTRUNCATE64)
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
#if defined(HAVE_OFF64_T) && defined(HAVE_LSEEK64)
  return lseek64(fd, offset, whence);
#else
  return lseek(fd, offset, whence);
#endif
}

/*******************************************************************
 An fseek() wrapper that will deal with 64 bit filesizes.
********************************************************************/

int sys_fseek(FILE *fp, SMB_OFF_T offset, int whence)
{
#if defined(LARGE_SMB_OFF_T) && defined(HAVE_FSEEK64)
  return fseek64(fp, offset, whence);
#else
  return fseek(fp, offset, whence);
#endif
}

/*******************************************************************
 An ftell() wrapper that will deal with 64 bit filesizes.
********************************************************************/

SMB_OFF_T sys_ftell(FILE *fp)
{
#if defined(LARGE_SMB_OFF_T) && defined(HAVE_FTELL64)
  return (SMB_OFF_T)ftell64(fp);
#else
  return (SMB_OFF_T)ftell(fp);
#endif
}

/*******************************************************************
 A creat() wrapper that will deal with 64 bit filesizes.
********************************************************************/

int sys_creat(const char *path, mode_t mode)
{
#if defined(HAVE_CREAT64)
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
#if defined(HAVE_OPEN64)
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
#if defined(HAVE_FOPEN64)
  return fopen64(path, type);
#else
  return fopen(path, type);
#endif
}

/*******************************************************************
 An mmap() wrapper that will deal with 64 bit filesizes.
********************************************************************/

void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, SMB_OFF_T offset)
{
#if defined(LARGE_SMB_OFF_T) && defined(HAVE_MMAP64)
  return mmap64(addr, len, prot, flags, fd, offset);
#else
  return mmap(addr, len, prot, flags, fd, offset);
#endif
}

/*******************************************************************
just a unlink wrapper that calls dos_to_unix.
********************************************************************/
int dos_unlink(char *fname)
{
  return(unlink(dos_to_unix(fname,False)));
}


/*******************************************************************
a simple open() wrapper that calls dos_to_unix.
********************************************************************/
int dos_open(char *fname,int flags,mode_t mode)
{
  return(sys_open(dos_to_unix(fname,False),flags,mode));
}


/*******************************************************************
a simple opendir() wrapper that calls dos_to_unix
********************************************************************/
DIR *dos_opendir(char *dname)
{
	return(opendir(dos_to_unix(dname,False)));
}

/*******************************************************************
and a stat() wrapper that calls dos_to_unix.
********************************************************************/
int dos_stat(char *fname,SMB_STRUCT_STAT *sbuf)
{
  return(sys_stat(dos_to_unix(fname,False),sbuf));
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
don't forget lstat() that calls dos_to_unix.
********************************************************************/
int dos_lstat(char *fname,SMB_STRUCT_STAT *sbuf)
{
  return(sys_lstat(dos_to_unix(fname,False),sbuf));
}

/*******************************************************************
mkdir() gets a wrapper that calls dos_to_unix.
********************************************************************/
int dos_mkdir(char *dname,mode_t mode)
{
  return(mkdir(dos_to_unix(dname,False),mode));
}

/*******************************************************************
do does rmdir() - call dos_to_unix
********************************************************************/
int dos_rmdir(char *dname)
{
  return(rmdir(dos_to_unix(dname,False)));
}

/*******************************************************************
I almost forgot chdir() - call dos_to_unix.
********************************************************************/
int dos_chdir(char *dname)
{
  return(chdir(dos_to_unix(dname,False)));
}

/*******************************************************************
now for utime() - call dos_to_unix.
********************************************************************/
int dos_utime(char *fname,struct utimbuf *times)
{
  /* if the modtime is 0 or -1 then ignore the call and
     return success */
  if (times->modtime == (time_t)0 || times->modtime == (time_t)-1)
    return 0;
  
  /* if the access time is 0 or -1 then set it to the modtime */
  if (times->actime == (time_t)0 || times->actime == (time_t)-1)
    times->actime = times->modtime;
   
  return(utime(dos_to_unix(fname,False),times));
}

/*********************************************************
for rename across filesystems Patch from Warren Birnbaum 
<warrenb@hpcvscdp.cv.hp.com>
**********************************************************/

static int copy_reg(char *source, const char *dest)
{
  SMB_STRUCT_STAT source_stats;
  int ifd;
  int ofd;
  char *buf;
  int len;                      /* Number of bytes read into `buf'. */

  sys_lstat (source, &source_stats);
  if (!S_ISREG (source_stats.st_mode))
    return 1;

  if (unlink (dest) && errno != ENOENT)
    return 1;

  if((ifd = sys_open (source, O_RDONLY, 0)) < 0)
    return 1;

  if((ofd = sys_open (dest, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0 )
  {
    close (ifd);
    return 1;
  }

  if((buf = malloc( COPYBUF_SIZE )) == NULL)
  {
    close (ifd);  
    close (ofd);  
    unlink (dest);
    return 1;
  }

  while ((len = read(ifd, buf, COPYBUF_SIZE)) > 0)
  {
    if (write_data(ofd, buf, len) < 0)
    {
      close (ifd);
      close (ofd);
      unlink (dest);
      free(buf);
      return 1;
    }
  }
  free(buf);
  if (len < 0)
  {
    close (ifd);
    close (ofd);
    unlink (dest);
    return 1;
  }

  if (close (ifd) < 0)
  {
    close (ofd);
    return 1;
  }
  if (close (ofd) < 0)
    return 1;

  /* chown turns off set[ug]id bits for non-root,
     so do the chmod last.  */

  /* Try to copy the old file's modtime and access time.  */
  {
    struct utimbuf tv;

    tv.actime = source_stats.st_atime;
    tv.modtime = source_stats.st_mtime;
    if (utime (dest, &tv))
      return 1;
  }

  /* Try to preserve ownership.  For non-root it might fail, but that's ok.
     But root probably wants to know, e.g. if NFS disallows it.  */
  if (chown (dest, source_stats.st_uid, source_stats.st_gid)
      && (errno != EPERM))
    return 1;

  if (chmod (dest, source_stats.st_mode & 07777))
    return 1;

  unlink (source);
  return 0;
}

/*******************************************************************
for rename() - call dos_to_unix.
********************************************************************/
int dos_rename(char *from, char *to)
{
    int rcode;  
    pstring zfrom, zto;

    pstrcpy (zfrom, dos_to_unix (from, False));
    pstrcpy (zto, dos_to_unix (to, False));
    rcode = rename (zfrom, zto);

    if (errno == EXDEV) 
    {
      /* Rename across filesystems needed. */
      rcode = copy_reg (zfrom, zto);        
    }
    return rcode;
}

/*******************************************************************
for chmod - call dos_to_unix.
********************************************************************/
int dos_chmod(char *fname,mode_t mode)
{
  return(chmod(dos_to_unix(fname,False),mode));
}

/*******************************************************************
system wrapper for getwd
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
for getwd - takes a UNIX directory name and returns the name
in dos format.
********************************************************************/
char *dos_getwd(char *s)
{
	char *wd;
	wd = sys_getwd(s);
	if (wd)
		unix_to_dos(wd, True);
	return wd;
}

/*******************************************************************
chown isn't used much but OS/2 doesn't have it
********************************************************************/
int sys_chown(char *fname,uid_t uid,gid_t gid)
{
#ifndef HAVE_CHOWN
	static int done;
	if (!done) {
		DEBUG(1,("WARNING: no chown!\n"));
		done=1;
	}
#else
	return(chown(fname,uid,gid));
#endif
}

/*******************************************************************
os/2 also doesn't have chroot
********************************************************************/
int sys_chroot(char *dname)
{
#ifndef HAVE_CHROOT
	static int done;
	if (!done) {
		DEBUG(1,("WARNING: no chroot!\n"));
		done=1;
	}
#else
	return(chroot(dname));
#endif
}

/**************************************************************************
A wrapper for gethostbyname() that tries avoids looking up hostnames 
in the root domain, which can cause dial-on-demand links to come up for no
apparent reason.
****************************************************************************/
struct hostent *sys_gethostbyname(char *name)
{
#ifdef REDUCE_ROOT_DNS_LOOKUPS
  char query[256], hostname[256];
  char *domain;

  /* Does this name have any dots in it? If so, make no change */

  if (strchr(name, '.'))
    return(gethostbyname(name));

  /* Get my hostname, which should have domain name 
     attached. If not, just do the gethostname on the
     original string. 
  */

  gethostname(hostname, sizeof(hostname) - 1);
  hostname[sizeof(hostname) - 1] = 0;
  if ((domain = strchr(hostname, '.')) == NULL)
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


/**************************************************************************
 Try and abstract process capabilities (for systems that have them).
****************************************************************************/

BOOL set_process_capability( uint32 cap_flag, BOOL enable )
{
#if defined(HAVE_IRIX_SPECIFIC_CAPABILITIES)
  if(cap_flag == KERNEL_OPLOCK_CAPABILITY)
  {
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
      return False;
    }

    DEBUG(10,("set_process_capability: Set KERNEL_OPLOCK_CAPABILITY.\n"));
  }
#endif
  return True;
}

/**************************************************************************
 Try and abstract inherited process capabilities (for systems that have them).
****************************************************************************/

BOOL set_inherited_process_capability( uint32 cap_flag, BOOL enable )
{
#if defined(HAVE_IRIX_SPECIFIC_CAPABILITIES)
  if(cap_flag == KERNEL_OPLOCK_CAPABILITY)
  {
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
      return False;
    }

    DEBUG(10,("set_inherited_process_capability: Set KERNEL_OPLOCK_CAPABILITY.\n"));
  }
#endif
  return True;
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

void sys_srandom(unsigned int seed)
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

  if (setlen == 0) setlen = 1;

  if((group_list = (GID_T *)malloc(setlen * sizeof(GID_T))) == NULL) {
    DEBUG(0,("sys_getgroups: Malloc fail.\n"));
    return -1;
  }

  if((ngroups = getgroups(setlen, group_list)) < 0) {
    int saved_errno = errno;
    free((char *)group_list);
    errno = saved_errno;
    return -1;
  }

  for(i = 0; i < ngroups; i++)
    gidset[i] = (gid_t)group_list[i];

  free((char *)group_list);
  return ngroups;
#endif /* HAVE_BROKEN_GETGROUPS */
}
