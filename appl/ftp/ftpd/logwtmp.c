#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#include <fcntl.h>
#include <utmp.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "extern.h"


void
logwtmp(char *line, char *name, char *host)
{
    static int init = 0;
    static int fd;

    struct utmp ut;

    memset(&ut, 0, sizeof(struct utmp));
#ifdef HAVE_UT_TYPE
    if(name[0])
	ut.ut_type = USER_PROCESS;
    else
	ut.ut_type = DEAD_PROCESS;
#endif
    strncpy(ut.ut_line, line, sizeof(ut.ut_line));
    strncpy(ut.ut_name, name, sizeof(ut.ut_name));
#ifdef HAVE_UT_PID
    ut.ut_pid = getpid();
#endif
#ifdef HAVE_UT_HOST
    strncpy(ut.ut_host, host, sizeof(ut.ut_host));
#endif
    
    ut.ut_time = time(NULL);

    if(!init){
	fd = open(WTMP_PATH, O_WRONLY|O_APPEND, 0);
	init = 1;
    }
    if(fd >= 0)
	write(fd, &ut, sizeof(struct utmp)); /* XXX */
}
