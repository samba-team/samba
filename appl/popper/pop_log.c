/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <popper.h>
RCSID("$Id$");

/* 
 *  log:    Make a log entry
 */

int
pop_log(POP *p, int stat, char *format, ...)
{
    static char msgbuf[MAXLINELEN];
    va_list     ap;

    va_start(ap, format);
    vsprintf(msgbuf,format,ap);

    if (p->debug && p->trace) {
        fprintf(p->trace,"%s\n",msgbuf);
        fflush(p->trace);
    }
    else {
        syslog (stat,"%s",msgbuf);
    }
    va_end(ap);

    return(stat);
}
