#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "roken.h"

#ifndef HAVE_HSTRERROR

RCSID("$Id$");

#include <stdio.h>
#include <netdb.h>

#ifndef HAVE_H_ERRLIST
static
const
char *const h_errlist[] = {
  "Resolver Error 0 (no error)",
  "Unknown host",		/* 1 HOST_NOT_FOUND */
  "Host name lookup failure",	/* 2 TRY_AGAIN */
  "Unknown server error",	/* 3 NO_RECOVERY */
  "No address associated with name", /* 4 NO_ADDRESS */
};

static
const
int h_nerr = { sizeof h_errlist / sizeof h_errlist[0] };
#else

#ifdef NEED_H_ERRLIST_PROTO
extern const char *h_errlist[];
extern int h_nerr;
#endif

#endif

char *
hstrerror(int herr)
{
  if (0 <= herr && herr < h_nerr)
    return (char *) h_errlist[herr];
  else
    return "Error number out of range (hstrerror)";
}

#endif
