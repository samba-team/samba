/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#if 0
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
static char SccsId[] = "@(#)@(#)pop_msg.c	2.1  2.1 3/18/91";
#endif /* not lint */

#include <popper.h>

/* 
 *  msg:    Send a formatted line to the POP client
 */

int
pop_msg(POP *p, int stat, char *format, ...)
{
    register char   *   mp;
    char                message[MAXLINELEN];
    va_list             ap;
    va_start(ap, format);
    
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
#endif /* DEBUG */

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
