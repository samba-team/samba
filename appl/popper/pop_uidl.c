#include <popper.h>
RCSID("$Id$");

#ifdef UIDL
/* 
 *  uidl:   Uidl the contents of a POP maildrop
 */

int
pop_uidl (POP *p)
{
    MsgInfoList         *   mp;         /*  Pointer to message info list */
    register int            i;
    register int            msg_num;

    /*  Was a message number provided? */
    if (p->parm_count > 0) {
        msg_num = atoi(p->pop_parm[1]);

        /*  Is requested message out of range? */
        if ((msg_num < 1) || (msg_num > p->msg_count))
            return (pop_msg (p,POP_FAILURE,
                "Message %d does not exist.",msg_num));

        /*  Get a pointer to the message in the message list */
        mp = &p->mlp[msg_num-1];

        /*  Is the message already flagged for deletion? */
        if (mp->del_flag)
            return (pop_msg (p,POP_FAILURE,
                "Message %d has been deleted.",msg_num));

        /*  Display message information */
        return (pop_msg(p,POP_SUCCESS,"%u %s",msg_num,mp->msg_id));
    }
    
    /*  Display the entire list of messages */
    pop_msg(p,POP_SUCCESS,
        "%u messages (%u octets)",
            p->msg_count-p->msgs_deleted,p->drop_size-p->bytes_deleted);

    /*  Loop through the message information list.  Skip deleted messages */
    for (i = p->msg_count, mp = p->mlp; i > 0; i--, mp++) {
        if (!mp->del_flag) 
            (void)fprintf(p->output,"%u %s\r\n",mp->number,mp->msg_id);
    }

    /*  "." signals the end of a multi-line transmission */
    (void)fprintf(p->output,".\r\n");
    (void)fflush(p->output);

    return(POP_SUCCESS);
}
#endif /* UIDL */
