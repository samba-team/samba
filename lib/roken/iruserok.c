#include "bsd_locl.h"

RCSID("$Header$");

#ifndef HAVE_IRUSEROK

int     __check_rhosts_file = 1;
char    *__rcmd_errstr = 0;


/*
 * Returns 0 if ok, -1 if not ok.
 */
int
iruserok(u_int32_t raddr, int superuser, const char *ruser, const char *luser)
{
  return -1;
}

#endif /* !HAVE_IRUSEROK */
