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
#include <varargs.h>
#include "popper.h"

/* 
 *  msg:    Send a formatted line to the POP client
 */

pop_msg(va_alist)
va_dcl
{
    POP             *   p;
    int                 stat;               /*  POP status indicator */
    char            *   format;             /*  Format string for the message */
    va_list             ap;
    register char   *   mp;
    char                message[MAXLINELEN];

    va_start(ap);
    p = va_arg(ap, POP *);
    stat = va_arg(ap, int);
    format = va_arg(ap, char *);
    va_end(ap);

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
        (void)sprintf(mp,format,((int *)ap)[0],((int *)ap)[1],((int *)ap)[2],
                ((int *)ap)[3],((int *)ap)[4]);
#endif HAVE_VSPRINTF
    
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

    return(stat);
}
