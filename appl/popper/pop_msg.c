/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef lint
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
static char SccsId[] = "@(#)@(#)pop_msg.c	2.1  2.1 3/18/91";
#endif not lint

#include <stdio.h>
#include <sys/types.h>
#include <strings.h>
#if __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include "popper.h"

/* 
 *  msg:    Send a formatted line to the POP client
 */

int
#ifdef __STDC__
pop_msg(POP *p, int stat, char *format, ...)
#else
pop_msg(va_alist)
va_dcl
#endif
{
    register char   *   mp;
    char                message[MAXLINELEN];
    va_list             ap;
#ifdef __STDC__
    va_start(ap, format);
#else
    POP             *   p;
    int                 stat;               /*  POP status indicator */
    char            *   format;             /*  Format string for the message */

    va_start(ap);
    p = va_arg(ap, POP *);
    stat = va_arg(ap, int);
    format = va_arg(ap, char *);
#endif
    
    /*  Point to the message buffer */
    mp = message;

    /*  Format the POP status code at the beginning of the message */
    if (stat == POP_SUCCESS)
        (void)sprintf (mp,"%s ",POP_OK);
    else
        (void)sprintf (mp,"%s ",POP_ERR);

    /*  Point past the POP status indicator in the message message */
    mp += strlen(mp);

    /*  Append the message (formatted, if necessary) */
    if (format) 
#ifdef HAVE_VSPRINTF
        vsprintf(mp,format,ap);
#else
        {
	    int a0 = va_arg(ap, int);
	    int a1 = va_arg(ap, int);
	    int a2 = va_arg(ap, int);
	    int a3 = va_arg(ap, int);
	    int a4 = va_arg(ap, int);
	    int a5 = va_arg(ap, int);
	    (void)sprintf(mp, format, a0, a1, a2, a3, a4, a5, 0, 4711);
	}
#endif /* HAVE_VSPRINTF */
    
    /*  Log the message if debugging is turned on */
#ifdef DEBUG
    if (p->debug && stat == POP_SUCCESS)
        pop_log(p,POP_DEBUG,"%s",message);
#endif DEBUG

    /*  Log the message if a failure occurred */
    if (stat != POP_SUCCESS) 
        pop_log(p,POP_PRIORITY,"%s",message);

    /*  Append the <CR><LF> */
    (void)strcat(message, "\r\n");
        
    /*  Send the message to the client */
    (void)fputs(message,p->output);
    (void)fflush(p->output);

    va_end(ap);
    return(stat);
}
