#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#ifndef HAVE_GETTIMEOFDAY
/*
 * Simple gettimeofday that only returns seconds.
 */
int
gettimeofday (struct timeval *tp, void *ignore)
{
     time_t t;

     t = time(NULL);
     tp->tv_sec  = t;
     tp->tv_usec = 0;
     return 0;
}
#endif
