/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef lint
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
static char SccsId[] = "@(#)@(#)pop_stat.c	2.2  2.2 3/18/91";
#endif not lint

#include <stdio.h>
#include <sys/types.h>
#include "popper.h"

/* 
 *  stat:   Display the status of a POP maildrop to its client
 */

int pop_stat (p)
POP     *   p;
{
#ifdef DEBUG
    if (p->debug) pop_log(p,POP_DEBUG,"%d message(s) (%d octets).",p->msg_count-p->msgs_deleted,p->drop_size-p->bytes_deleted);
#endif DEBUG
    return (pop_msg (p,POP_SUCCESS,
        "%u %u",p->msg_count-p->msgs_deleted,p->drop_size-p->bytes_deleted));
}
