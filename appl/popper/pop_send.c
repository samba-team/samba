/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef lint
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
static char SccsId[] = "@(#)@(#)pop_send.c	2.1  2.1 3/18/91";
#endif not lint

#include <stdio.h>
#include <sys/types.h>
#include <strings.h>
#include "popper.h"

/* 
 *  send:   Send the header and a specified number of lines 
 *          from a mail message to a POP client.
 */

pop_send(p)
POP     *   p;
{
    MsgInfoList         *   mp;         /*  Pointer to message info list */
    register int            msg_num;
    register int            msg_lines;
    char                    buffer[MAXMSGLINELEN];
#ifdef RETURN_PATH_HANDLING
    char		*   return_path_adr;
    char		*   return_path_end;
    int			    return_path_sent;
    int			    return_path_linlen;
#endif

    /*  Convert the first parameter into an integer */
    msg_num = atoi(p->pop_parm[1]);

    /*  Is requested message out of range? */
    if ((msg_num < 1) || (msg_num > p->msg_count))
        return (pop_msg (p,POP_FAILURE,"Message %d does not exist.",msg_num));

    /*  Get a pointer to the message in the message list */
    mp = &p->mlp[msg_num-1];

    /*  Is the message flagged for deletion? */
    if (mp->del_flag)
        return (pop_msg (p,POP_FAILURE,
            "Message %d has been deleted.",msg_num));

    /*  If this is a TOP command, get the number of lines to send */
    if (strcmp(p->pop_command,"top") == 0) {
        /*  Convert the second parameter into an integer */
        msg_lines = atoi(p->pop_parm[2]);
    }
    else {
        /*  Assume that a RETR (retrieve) command was issued */
        msg_lines = -1;
        /*  Flag the message as retreived */
        mp->retr_flag = TRUE;
    }
    
    /*  Display the number of bytes in the message */
    pop_msg(p,POP_SUCCESS,"%u octets",mp->length);

    /*  Position to the start of the message */
    (void)fseek(p->drop,mp->offset,0);

    /*  Skip the first line (the sendmail "From" line) */
    (void)fgets (buffer,MAXMSGLINELEN,p->drop);

#ifdef RETURN_PATH_HANDLING
    return_path_sent = 0;
    if (strncmp(buffer,"From ",5) == 0) {
	return_path_linlen = strlen(buffer);
	for (return_path_adr = buffer+5;
	     (*return_path_adr == ' ' || *return_path_adr == '\t') &&
	     return_path_adr < buffer + return_path_linlen;
	     return_path_adr++)
	    ;
	if (return_path_adr < buffer + return_path_linlen) {
	    if ((return_path_end = index(return_path_adr, ' ')) != NULL)
		*return_path_end = '\0';
	    if (strlen(return_path_adr) != 0 && *return_path_adr != '\n') {
		static char tmpbuf[MAXMSGLINELEN + 20];
		strcpy(tmpbuf, "Return-Path: ");
		strcat(tmpbuf, return_path_adr);
		strcat(tmpbuf, "\n");
		if (strlen(tmpbuf) < MAXMSGLINELEN) {
		    pop_sendline (p,tmpbuf);
		    return_path_sent++;
		}
	    }
	}
    }
#endif

    /*  Send the header of the message followed by a blank line */
    while (fgets(buffer,MAXMSGLINELEN,p->drop)) {
#ifdef RETURN_PATH_HANDLING
	/* Don't send existing Return-Path-header if already sent own */
	if (strncasecmp(buffer,"Return-Path:", 12) != 0 ||
	    !return_path_sent)
#endif
        pop_sendline (p,buffer);
        /*  A single newline (blank line) signals the 
            end of the header.  sendline() converts this to a NULL, 
            so that's what we look for. */
        if (*buffer == 0) break;
    }
    /*  Send the message body */
    while (fgets(buffer,MAXMSGLINELEN,p->drop)) {
        /*  Look for the start of the next message */
        if (strncmp(buffer,"From ",5) == 0) break;
        /*  Decrement the lines sent (for a TOP command) */
        if (msg_lines >= 0 && msg_lines-- == 0) break;
        pop_sendline(p,buffer);
    }
    /*  "." signals the end of a multi-line transmission */
    (void)fputs(".\r\n",p->output);
    (void)fflush(p->output);

    return(POP_SUCCESS);
}

/*
 *  sendline:   Send a line of a multi-line response to a client.
 */
pop_sendline(p,buffer)
POP         *   p;
char        *   buffer;
{
    char        *   bp;

    /*  Byte stuff lines that begin with the temirnation octet */
    if (*buffer == POP_TERMINATE) (void)fputc(POP_TERMINATE,p->output);

    /*  Look for a <NL> in the buffer */
    if (bp = index(buffer,NEWLINE)) *bp = 0;

    /*  Send the line to the client */
    (void)fputs(buffer,p->output);

#ifdef DEBUG
    if(p->debug)pop_log(p,POP_DEBUG,"Sending line \"%s\"",buffer);
#endif DEBUG

    /*  Put a <CR><NL> if a newline was removed from the buffer */
    if (bp) (void)fputs ("\r\n",p->output);
}
