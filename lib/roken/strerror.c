#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#include <errno.h>
#include <string.h>

extern int sys_nerr;
extern char *sys_errlist[];

char*
strerror(int eno)
{
    static char emsg[1024];

    if(eno < 0 || eno >= sys_nerr)
	sprintf(emsg, "Error %d occurred.", eno);
    else
	strcpy(emsg, sys_errlist[eno]);

    return emsg;
}
