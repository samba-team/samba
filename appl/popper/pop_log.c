/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef lint
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
static char SccsId[] = "@(#)@(#)pop_log.c	2.1  2.1 3/18/91";
#endif not lint

#include <stdio.h>
#include <sys/types.h>
#include <varargs.h>
#include "popper.h"

/* 
 *  log:    Make a log entry
 */

static char msgbuf[MAXLINELEN];

pop_log(va_alist)
va_dcl
{
    va_list     ap;
    POP     *   p;
    int         stat;
    char    *   format;

    va_start(ap);
    p = va_arg(ap,POP *);
    stat = va_arg(ap,int);
    format = va_arg(ap,char *);
    va_end(ap);

#ifdef HAVE_VSPRINTF
        vsprintf(msgbuf,format,ap);
#else
        (void)sprintf (msgbuf,format,((int *)ap)[0],((int *)ap)[1],((int *)ap)[2],
                ((int *)ap)[3],((int *)ap)[4],((int *)ap)[5]);
#endif HAVE_VSPRINTF

    if (p->debug && p->trace) {
        (void)fprintf(p->trace,"%s\n",msgbuf);
        (void)fflush(p->trace);
    }
    else {
        syslog (stat,"%s",msgbuf);
    }

    return(stat);
}
