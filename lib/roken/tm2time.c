#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#include <time.h>
#include <sys/time.h>

time_t
tm2time (struct tm tm, int local)
{
     time_t t;

     tm.tm_isdst = -1;

     t = mktime (&tm);

     if (!local)
       t += t - mktime (gmtime (&t));
     return t;
}
