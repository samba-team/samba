/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <popper.h>
RCSID("$Id$");

/* 
 *  xtnd:   Handle extensions to the POP protocol suite
 */

int
pop_xtnd (POP *p)
{
    xtnd_table  *   x;

    /*  Convert the XTND subcommand to lower case */
    pop_lower(p->pop_subcommand);

    /*  Search for the subcommand in the XTND command table */
    if ((x = pop_get_subcommand(p)) == NULL) return(POP_FAILURE);

    /*  Call the function associated with this subcommand */
    if (x->function) return((*x->function)(p));

    /*  Otherwise assume NOOP */
    return (pop_msg(p,POP_SUCCESS,NULL));
}
