#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

RCSID("$Id$");

#include <stdlib.h>

/*
 * This is the easy way out, use putenv to implement setenv. We might
 * leak some memory but that is ok since we are usally about to exec
 * anyway.
 */

int
setenv(const char *var, const char *val, int rewrite)
{
    char *t;

    if (!rewrite && getenv(var) != 0)
	return 0;
  
    if ((t = malloc(strlen(var) + strlen(val) + 2)) == 0)
	return -1;

    strcpy(t, var);
    strcat(t, "=");
    strcat(t, val);
    if (putenv(t) == 0)
	return 0;
    else
	return -1;
}
