/* 
   Unix SMB/CIFS implementation.
   replacement routines for broken systems
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
#include "system/locale.h"
#include "system/wait.h"
#include "system/time.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/syslog.h"

 void replace_dummy(void);
 void replace_dummy(void) {}

#ifndef HAVE_FTRUNCATE
 /*******************************************************************
ftruncate for operating systems that don't have it
********************************************************************/
 int ftruncate(int f,off_t l)
{
#ifdef HAVE_CHSIZE
      return chsize(f,l);
#else
      struct  flock   fl;

      fl.l_whence = 0;
      fl.l_len = 0;
      fl.l_start = l;
      fl.l_type = F_WRLCK;
      return fcntl(f, F_FREESP, &fl);
#endif
}
#endif /* HAVE_FTRUNCATE */


#ifndef HAVE_STRLCPY
/* like strncpy but does not 0 fill the buffer and always null 
   terminates. bufsize is the size of the destination buffer */
 size_t strlcpy(char *d, const char *s, size_t bufsize)
{
	size_t len = strlen(s);
	size_t ret = len;
	if (bufsize <= 0) return 0;
	if (len >= bufsize) len = bufsize-1;
	memcpy(d, s, len);
	d[len] = 0;
	return ret;
}
#endif

#ifndef HAVE_STRLCAT
/* like strncat but does not 0 fill the buffer and always null 
   terminates. bufsize is the length of the buffer, which should
   be one more than the maximum resulting string length */
 size_t strlcat(char *d, const char *s, size_t bufsize)
{
	size_t len1 = strlen(d);
	size_t len2 = strlen(s);
	size_t ret = len1 + len2;

	if (len1+len2 >= bufsize) {
		len2 = bufsize - (len1+1);
	}
	if (len2 > 0) {
		memcpy(d+len1, s, len2);
		d[len1+len2] = 0;
	}
	return ret;
}
#endif

#ifndef HAVE_MKTIME
/*******************************************************************
a mktime() replacement for those who don't have it - contributed by 
C.A. Lademann <cal@zls.com>
Corrections by richard.kettlewell@kewill.com
********************************************************************/

#define  MINUTE  60
#define  HOUR    60*MINUTE
#define  DAY             24*HOUR
#define  YEAR    365*DAY
 time_t mktime(struct tm *t)
{
  struct tm       *u;
  time_t  epoch = 0;
  int n;
  int             mon [] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
  y, m, i;

  if(t->tm_year < 70)
    return((time_t)-1);

  n = t->tm_year + 1900 - 1;
  epoch = (t->tm_year - 70) * YEAR + 
    ((n / 4 - n / 100 + n / 400) - (1969 / 4 - 1969 / 100 + 1969 / 400)) * DAY;

  y = t->tm_year + 1900;
  m = 0;

  for(i = 0; i < t->tm_mon; i++) {
    epoch += mon [m] * DAY;
    if(m == 1 && y % 4 == 0 && (y % 100 != 0 || y % 400 == 0))
      epoch += DAY;
    
    if(++m > 11) {
      m = 0;
      y++;
    }
  }

  epoch += (t->tm_mday - 1) * DAY;
  epoch += t->tm_hour * HOUR + t->tm_min * MINUTE + t->tm_sec;
  
  if((u = localtime(&epoch)) != NULL) {
    t->tm_sec = u->tm_sec;
    t->tm_min = u->tm_min;
    t->tm_hour = u->tm_hour;
    t->tm_mday = u->tm_mday;
    t->tm_mon = u->tm_mon;
    t->tm_year = u->tm_year;
    t->tm_wday = u->tm_wday;
    t->tm_yday = u->tm_yday;
    t->tm_isdst = u->tm_isdst;
  }

  return(epoch);
}
#endif /* !HAVE_MKTIME */



#ifndef HAVE_RENAME
/* Rename a file. (from libiberty in GNU binutils)  */
 int rename(const char *zfrom, const char *zto)
{
  if (link (zfrom, zto) < 0)
    {
      if (errno != EEXIST)
	return -1;
      if (unlink (zto) < 0
	  || link (zfrom, zto) < 0)
	return -1;
    }
  return unlink (zfrom);
}
#endif /* HAVE_RENAME */


#ifndef HAVE_INNETGR
#if defined(HAVE_SETNETGRENT) && defined(HAVE_GETNETGRENT) && defined(HAVE_ENDNETGRENT)
/*
 * Search for a match in a netgroup. This replaces it on broken systems.
 */
 int innetgr(const char *group,const char *host,const char *user,const char *dom)
{
	char *hst, *usr, *dm;
  
	setnetgrent(group);
	while (getnetgrent(&hst, &usr, &dm)) {
		if (((host == 0) || (hst == 0) || !strcmp(host, hst)) &&
		    ((user == 0) || (usr == 0) || !strcmp(user, usr)) &&
		    ((dom == 0) || (dm == 0) || !strcmp(dom, dm))) {
			endnetgrent();
			return (1);
		}
	}
	endnetgrent();
	return (0);
}
#endif /* HAVE_SETNETGRENT HAVE_GETNETGRENT HAVE_ENDNETGRENT */
#endif /* HAVE_INNETGR */



#ifndef HAVE_INITGROUPS
/****************************************************************************
 some systems don't have an initgroups call 
****************************************************************************/
 int initgroups(char *name, gid_t id)
{
#ifndef HAVE_SETGROUPS
	/* yikes! no SETGROUPS or INITGROUPS? how can this work? */
	errno = ENOSYS;
	return -1;
#else /* HAVE_SETGROUPS */

#include <grp.h>

	gid_t *grouplst = NULL;
	int max_gr = groups_max();
	int ret;
	int    i,j;
	struct group *g;
	char   *gr;
	
	if((grouplst = malloc(sizeof(gid_t) * max_gr)) == NULL) {
		errno = ENOMEM;
		return -1;
	}

	grouplst[0] = id;
	i = 1;
	while (i < max_gr && ((g = (struct group *)getgrent()) != (struct group *)NULL)) {
		if (g->gr_gid == id)
			continue;
		j = 0;
		gr = g->gr_mem[0];
		while (gr && (*gr != (char)NULL)) {
			if (strcmp(name,gr) == 0) {
				grouplst[i] = g->gr_gid;
				i++;
				gr = (char *)NULL;
				break;
			}
			gr = g->gr_mem[++j];
		}
	}
	endgrent();
	ret = setgroups(i, grouplst);
	free(grouplst);
	return ret;
#endif /* HAVE_SETGROUPS */
}
#endif /* HAVE_INITGROUPS */


#if (defined(SecureWare) && defined(SCO))
/* This is needed due to needing the nap() function but we don't want
   to include the Xenix libraries since that will break other things...
   BTW: system call # 0x0c28 is the same as calling nap() */
 long nap(long milliseconds) {
	 return syscall(0x0c28, milliseconds);
 }
#endif


#ifndef HAVE_MEMMOVE
/*******************************************************************
safely copies memory, ensuring no overlap problems.
this is only used if the machine does not have it's own memmove().
this is not the fastest algorithm in town, but it will do for our
needs.
********************************************************************/
 void *memmove(void *dest,const void *src,int size)
{
	unsigned long d,s;
	int i;
	if (dest==src || !size) return(dest);

	d = (unsigned long)dest;
	s = (unsigned long)src;

	if ((d >= (s+size)) || (s >= (d+size))) {
		/* no overlap */
		memcpy(dest,src,size);
		return(dest);
	}

	if (d < s) {
		/* we can forward copy */
		if (s-d >= sizeof(int) && 
		    !(s%sizeof(int)) && 
		    !(d%sizeof(int)) && 
		    !(size%sizeof(int))) {
			/* do it all as words */
			int *idest = (int *)dest;
			int *isrc = (int *)src;
			size /= sizeof(int);
			for (i=0;i<size;i++) idest[i] = isrc[i];
		} else {
			/* simplest */
			char *cdest = (char *)dest;
			char *csrc = (char *)src;
			for (i=0;i<size;i++) cdest[i] = csrc[i];
		}
	} else {
		/* must backward copy */
		if (d-s >= sizeof(int) && 
		    !(s%sizeof(int)) && 
		    !(d%sizeof(int)) && 
		    !(size%sizeof(int))) {
			/* do it all as words */
			int *idest = (int *)dest;
			int *isrc = (int *)src;
			size /= sizeof(int);
			for (i=size-1;i>=0;i--) idest[i] = isrc[i];
		} else {
			/* simplest */
			char *cdest = (char *)dest;
			char *csrc = (char *)src;
			for (i=size-1;i>=0;i--) cdest[i] = csrc[i];
		}      
	}
	return(dest);
}
#endif /* HAVE_MEMMOVE */

#ifndef HAVE_STRDUP
/****************************************************************************
duplicate a string
****************************************************************************/
 char *strdup(const char *s)
{
	size_t len;
	char *ret;

	if (!s) return(NULL);

	len = strlen(s)+1;
	ret = (char *)malloc(len);
	if (!ret) return(NULL);
	memcpy(ret,s,len);
	return(ret);
}
#endif /* HAVE_STRDUP */

#ifndef WITH_PTHREADS
/* REWRITE: not thread safe */
#ifdef REPLACE_INET_NTOA
 char *rep_inet_ntoa(struct in_addr ip)
{
	uint8_t *p = (uint8_t *)&ip.s_addr;
	static char buf[18];
	slprintf(buf, 17, "%d.%d.%d.%d", 
		 (int)p[0], (int)p[1], (int)p[2], (int)p[3]);
	return buf;
}
#endif /* REPLACE_INET_NTOA */
#endif

#ifndef HAVE_SETLINEBUF
 int setlinebuf(FILE *stream)
{
	return setvbuf(stream, (char *)NULL, _IOLBF, 0);
}
#endif /* HAVE_SETLINEBUF */

#ifndef HAVE_VSYSLOG
#ifdef HAVE_SYSLOG
 void vsyslog (int facility_priority, char *format, va_list arglist)
{
	char *msg = NULL;
	vasprintf(&msg, format, arglist);
	if (!msg)
		return;
	syslog(facility_priority, "%s", msg);
	free(msg);
}
#endif /* HAVE_SYSLOG */
#endif /* HAVE_VSYSLOG */


#ifndef HAVE_STRNDUP
/**
 Some platforms don't have strndup.
**/
 char *strndup(const char *s, size_t n)
{
	char *ret;
	
	n = strnlen(s, n);
	ret = malloc(n+1);
	if (!ret)
		return NULL;
	memcpy(ret, s, n);
	ret[n] = 0;

	return ret;
}
#endif

#ifndef HAVE_STRNLEN
/**
 Some platforms don't have strnlen
**/

 size_t strnlen(const char *s, size_t n)
{
	size_t i;
	for (i=0; i<n && s[i] != '\0'; i++)
		/* noop */ ;
	return i;
}
#endif

#ifndef HAVE_WAITPID
int waitpid(pid_t pid,int *status,int options)
{
  return wait4(pid, status, options, NULL);
}
#endif

#ifndef HAVE_SETEUID
 int seteuid(uid_t euid)
{
#ifdef HAVE_SETRESUID
	return setresuid(-1, euid, -1);
#else
#  error "You need a seteuid function"
#endif
}
#endif

#ifndef HAVE_SETEGID
 int setegid(gid_t egid)
{
#ifdef HAVE_SETRESGID
	return setresgid(-1, egid, -1);
#else
#  error "You need a setegid function"
#endif
}
#endif

/*******************************************************************
os/2 also doesn't have chroot
********************************************************************/
#ifndef HAVE_CHROOT
int chroot(const char *dname)
{
	errno = ENOSYS;
	return -1;
}
#endif

/*****************************************************************
 Possibly replace mkstemp if it is broken.
*****************************************************************/  

#ifndef HAVE_SECURE_MKSTEMP
int rep_mkstemp(char *template)
{
	/* have a reasonable go at emulating it. Hope that
	   the system mktemp() isn't completly hopeless */
	char *p = mktemp(template);
	if (!p)
		return -1;
	return open(p, O_CREAT|O_EXCL|O_RDWR, 0600);
}
#endif

#ifndef HAVE_MKDTEMP
char * mkdtemp(char *template)
{
	char *dname;
	
	if (dname = mktemp(template)) {
		if (mkdir(dname, 0700) >= 0) {
			return dname;
		}
	}

	return NULL;
}
#endif

#ifndef HAVE_PREAD
static ssize_t pread(int __fd, void *__buf, size_t __nbytes, off_t __offset)
{
	if (lseek(__fd, __offset, SEEK_SET) != __offset) {
		return -1;
	}
	return read(__fd, __buf, __nbytes);
}
#endif

#ifndef HAVE_PWRITE
static ssize_t pwrite(int __fd, const void *__buf, size_t __nbytes, off_t __offset)
{
	if (lseek(__fd, __offset, SEEK_SET) != __offset) {
		return -1;
	}
	return write(__fd, __buf, __nbytes);
}
#endif

#ifndef HAVE_STRCASESTR
char *strcasestr(const char *haystack, const char *needle)
{
	const char *s;
	size_t nlen = strlen(needle);
	for (s=haystack;*s;s++) {
		if (toupper(*needle) == toupper(*s) &&
		    strncasecmp(s, needle, nlen) == 0) {
			return discard_const_p(char, s);
		}
	}
	return NULL;
}
#endif

#ifndef HAVE_STRTOK_R
/* based on GLIBC version, copyright Free Software Foundation */
char *strtok_r(char *s, const char *delim, char **save_ptr)
{
	char *token;

	if (s == NULL) s = *save_ptr;

	s += strspn(s, delim);
	if (*s == '\0') {
		*save_ptr = s;
		return NULL;
	}

	token = s;
	s = strpbrk(token, delim);
	if (s == NULL) {
		*save_ptr = token + strlen(token);
	} else {
		*s = '\0';
		*save_ptr = s + 1;
	}

	return token;
}
#endif
