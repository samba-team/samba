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
The wait() calls vary between systems
********************************************************************/
int sys_waitpid(pid_t pid,int *status,int options)
{
#ifdef USE_WAITPID
  return waitpid(pid,status,options);
#else /* USE_WAITPID */
  return wait4(pid, status, options, NULL);
#endif /* USE_WAITPID */
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
  struct stat source_stats;
  int ifd;
  int ofd;
  char *buf;
  int len;                      /* Number of bytes read into `buf'. */

  lstat (source, &source_stats);
  if (!S_ISREG (source_stats.st_mode))
    {
      return 1;
    }

  if (unlink (dest) && errno != ENOENT)
    {
      return 1;
    }

  if((ifd = open (source, O_RDONLY, 0)) < 0)
    {
      return 1;
    }
  if((ofd = open (dest, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0 )
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
    {
      return 1;
    }

  /* chown turns off set[ug]id bits for non-root,
     so do the chmod last.  */

  /* Try to copy the old file's modtime and access time.  */
  {
    struct utimbuf tv;

    tv.actime = source_stats.st_atime;
    tv.modtime = source_stats.st_mtime;
    if (utime (dest, &tv))
      {
        return 1;
      }
  }

  /* Try to preserve ownership.  For non-root it might fail, but that's ok.
     But root probably wants to know, e.g. if NFS disallows it.  */
  if (chown (dest, source_stats.st_uid, source_stats.st_gid)
      && (errno != EPERM))
    {
      return 1;
    }

  if (chmod (dest, source_stats.st_mode & 07777))
    {
      return 1;
    }
  unlink (source);
  return 0;
}

/*******************************************************************
for rename()
********************************************************************/
int sys_rename(char *from, char *to)
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
for chmod
********************************************************************/
int sys_chmod(char *fname,int mode)
{
  return(chmod(dos_to_unix(fname,False),mode));
}

/*******************************************************************
for getwd
********************************************************************/
char *sys_getwd(char *s)
{
  char *wd;
#ifdef USE_GETCWD
  wd = (char *) getcwd (s, sizeof (pstring));
#else
  wd = (char *) getwd (s);
#endif
  if (wd)
    unix_to_dos (wd, True);
  return wd;
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

