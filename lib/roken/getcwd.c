#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#include <sys/param.h>

char*
getcwd(char *path, int size)
{
    char xxx[MaxPathLen];
    char *ret;
    ret = getwd(xxx);
    if(ret)
	strncpy(path, xxx, size);
    return ret;
}
