/*
 *
 * Some systems doesn't have gethostid(2) (e.g Solaris if you don't
 * link with libucb - and we don't want that...
 *
 * $Id$
 *
 */


#include "config.h"

#ifndef HAVE_GETHOSTID

#include <stdio.h>
#include <sys/systeminfo.h>

long gethostid(void)
{
  static int flag=0;
  static long hostid;
  if(!flag){
    char s[32];
    sysinfo(SI_HW_SERIAL, s, 32);
    sscanf(s, "%u", &hostid);
    flag=1;
  }
  return hostid;
}

#endif
