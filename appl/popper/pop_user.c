/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef lint
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
static char SccsId[] = "@(#)@(#)pop_user.c	2.1  2.1 3/18/91";
#endif not lint

#include <stdio.h>
#include <sys/types.h>
#include <strings.h>
#include "popper.h"

/* 
 *  user:   Prompt for the user name at the start of a POP session
 */

int pop_user (p)
POP     *   p;
{
    /*  Save the user name */
    (void)strcpy(p->user, p->pop_parm[1]);

    /*  Tell the user that the password is required */
    return (pop_msg(p,POP_SUCCESS,"Password required for %s.",p->user));
}
