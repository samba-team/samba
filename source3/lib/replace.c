/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
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

extern int DEBUGLEVEL;


 void replace_dummy(void) 
{}

#ifdef REPLACE_STRLEN
/****************************************************************************
a replacement strlen() that returns int for solaris
****************************************************************************/
 int Strlen(char *s)
{
  int ret=0;
  if (!s) return(0);
  while (*s++) ret++;
  return(ret);
}
#endif

#ifdef NO_FTRUNCATE
 /*******************************************************************
ftruncate for operating systems that don't have it
********************************************************************/
 int ftruncate(int f,long l)
{
      struct  flock   fl;

      fl.l_whence = 0;
      fl.l_len = 0;
      fl.l_start = l;
      fl.l_type = F_WRLCK;
      return fcntl(f, F_FREESP, &fl);
}
#endif


#ifdef REPLACE_STRSTR
/****************************************************************************
Mips version of strstr doesn't seem to work correctly.
There is a #define in includes.h to redirect calls to this function.
****************************************************************************/
char *Strstr(char *s, char *p)
{
	int len = strlen(p);

	while ( *s != '\0' ) {
		if ( strncmp(s, p, len) == 0 )
		return s;
		s++;
	}

	return NULL;
}
#endif /* REPLACE_STRSTR */


#ifdef REPLACE_MKTIME
/*******************************************************************
a mktime() replacement for those who don't have it - contributed by 
C.A. Lademann <cal@zls.com>
********************************************************************/
#define  MINUTE  60
#define  HOUR    60*MINUTE
#define  DAY             24*HOUR
#define  YEAR    365*DAY
time_t Mktime(struct tm      *t)
{
  struct tm       *u;
  time_t  epoch = 0;
  int             mon [] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
  y, m, i;

  if(t->tm_year < 70)
    return((time_t)-1);

  epoch = (t->tm_year - 70) * YEAR + 
    (t->tm_year / 4 - 70 / 4 - t->tm_year / 100) * DAY;

  y = t->tm_year;
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
#ifndef NO_TM_NAME
    memcpy(t->tm_name, u->tm_name, LTZNMAX);
#endif
  }

  return(epoch);
}
#endif /* REPLACE_MKTIME */



#ifdef REPLACE_RENAME
/* Rename a file. (from libiberty in GNU binutils)  */
 int rename (zfrom, zto)
     const char *zfrom;
     const char *zto;
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
#endif


#ifdef REPLACE_INNETGR
/*
 * Search for a match in a netgroup. This replaces it on broken systems.
 */
int InNetGr(char *group,char *host,char *user,char *dom)
{
  char *hst, *usr, *dm;
  
  setnetgrent(group);
  while (getnetgrent(&hst, &usr, &dm))
    if (((host == 0) || (hst == 0) || !strcmp(host, hst)) &&
	((user == 0) || (usr == 0) || !strcmp(user, usr)) &&
	((dom == 0) || (dm == 0) || !strcmp(dom, dm))) {
      endnetgrent();
      return (1);
    }
  endnetgrent();
  return (0);
}
#endif



#ifdef NO_INITGROUPS
#include <sys/types.h>
#include <limits.h>
#include <grp.h>

#ifndef NULL
#define NULL (void *)0
#endif

/****************************************************************************
 some systems don't have an initgroups call 
****************************************************************************/
 int initgroups(char *name,gid_t id)
{
#ifdef NO_SETGROUPS
  /* yikes! no SETGROUPS or INITGROUPS? how can this work? */
  return(0);
#else
  gid_t  grouplst[NGROUPS_MAX];
  int    i,j;
  struct group *g;
  char   *gr;

  grouplst[0] = id;
  i = 1;
  while (i < NGROUPS_MAX && 
	 ((g = (struct group *)getgrent()) != (struct group *)NULL)) 
    {
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
  return(setgroups(i,grouplst));
#endif
}
#endif


#if (defined(SecureWare) && defined(SCO))
/* This is needed due to needing the nap() function but we don't want
   to include the Xenix libraries since that will break other things...
   BTW: system call # 0x0c28 is the same as calling nap() */
long nap(long milliseconds) {
  return syscall(0x0c28, milliseconds);
}
#endif


#if WRAP_MEMCPY
#undef memcpy
/*******************************************************************
a wrapper around memcpy for diagnostic purposes
********************************************************************/
void *memcpy_wrapped(void *d,void *s,int l,char *fname,int line)
{
  if (l>64 && (((int)d)%4) != (((int)s)%4))
    DEBUG(4,("Misaligned memcpy(0x%X,0x%X,%d) at %s(%d)\n",d,s,l,fname,line));
#ifdef xx_old_memcpy  
  return(xx_old_memcpy(d,s,l));
#else
  return(memcpy(d,s,l));
#endif
}
#define memcpy(d,s,l) memcpy_wrapped(d,s,l,__FILE__,__LINE__)
#endif

