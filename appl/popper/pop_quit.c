/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef lint
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
static char SccsId[] = "@(#)@(#)pop_quit.c	2.1  2.1 3/18/91";
#endif not lint

#include <stdio.h>
#include <sys/types.h>
#include "popper.h"

/* 
 *  quit:   Terminate a POP session
 */

int pop_quit (p)
POP     *   p;
{
    /*  Release the message information list */
    if (p->mlp) free ((char *)p->mlp);

    return(POP_SUCCESS);
}
