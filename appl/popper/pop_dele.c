/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <popper.h>
RCSID("$Id$");

/* 
 *  dele:   Delete a message from the POP maildrop
 */
int
pop_dele (POP *p)
{
    MsgInfoList     *   mp;         /*  Pointer to message info list */
    int                 msg_num;

    /*  Convert the message number parameter to an integer */
    msg_num = atoi(p->pop_parm[1]);

    /*  Is requested message out of range? */
    if ((msg_num < 1) || (msg_num > p->msg_count))
        return (pop_msg (p,POP_FAILURE,"Message %d does not exist.",msg_num));

    /*  Get a pointer to the message in the message list */
    mp = &(p->mlp[msg_num-1]);

    /*  Is the message already flagged for deletion? */
    if (mp->flags & DEL_FLAG)
        return (pop_msg (p,POP_FAILURE,"Message %d has already been deleted.",
            msg_num));

    /*  Flag the message for deletion */
    mp->flags |= DEL_FLAG;

#ifdef DEBUG
    if(p->debug)
        pop_log(p, POP_DEBUG,
		"Deleting message %u at offset %ld of length %ld\n",
		mp->number, mp->offset, mp->length);
#endif /* DEBUG */

    /*  Update the messages_deleted and bytes_deleted counters */
    p->msgs_deleted++;
    p->bytes_deleted += mp->length;

    /*  Update the last-message-accessed number if it is lower than 
        the deleted message */
    if (p->last_msg < msg_num) p->last_msg = msg_num;

    return (pop_msg (p,POP_SUCCESS,"Message %d has been deleted.",msg_num));
}
