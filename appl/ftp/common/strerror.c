#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>

RCSID("$Id$");

static char emsg[1024];

char*
strerror(int eno)
{
    if(eno < 0 || eno >= sys_nerr)
	sprintf(emsg, "Error %d occurred.", eno);
    else
	strcpy(emsg, sys_errlist[eno]);

    return emsg;
}
