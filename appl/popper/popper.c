/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef lint
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
static char SccsId[] = "@(#)@(#)popper.c	2.1  2.1 3/18/91";
#endif /* not lint */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <setjmp.h>
#include "popper.h"

extern  state_table *   pop_get_command();

int hangup = FALSE ;

static RETSIGTYPE
catchSIGHUP()
{
    hangup = TRUE ;

    /* This should not be a problem on BSD systems */
    signal(SIGHUP,  catchSIGHUP);
    signal(SIGPIPE, catchSIGHUP);
}

int     pop_timeout = POP_TIMEOUT;

jmp_buf env;

static int
ring()
{
  longjmp(env,1);
}
  
/*
 * fgets, but with a timeout
 */
static char *
tgets(char *str, int size, FILE *fp, int timeout)
{
  int ring();
  (void) signal(SIGALRM, (void *)ring);
  alarm(timeout);
  if (setjmp(env))
    str = NULL;
  else
    str = fgets(str,size,fp);
  alarm(0);
  signal(SIGALRM,SIG_DFL);
  return(str);
}

/* 
 *  popper: Handle a Post Office Protocol version 3 session
 */
main (argc, argv)
int         argc;
char    **  argv;
{
    POP                 p;
    state_table     *   s;
    char                message[MAXLINELEN];

    (void) signal(SIGHUP,(void *)catchSIGHUP);
    (void) signal(SIGPIPE,(void *)catchSIGHUP);

    /*  Start things rolling */
    pop_init(&p,argc,argv);

    /*  Tell the user that we are listenting */
    pop_msg(&p,POP_SUCCESS,
        "UCB Pop server (version %s) at %s starting.",VERSION,p.myhost);

    /*  State loop.  The POP server is always in a particular state in 
        which a specific suite of commands can be executed.  The following 
        loop reads a line from the client, gets the command, and processes 
        it in the current context (if allowed) or rejects it.  This continues 
        until the client quits or an error occurs. */

    for (p.CurrentState=auth1;p.CurrentState!=halt&&p.CurrentState!=error;) {
        if (hangup) {
            pop_msg(&p,POP_FAILURE,"POP hangup",p.myhost);
            if (p.CurrentState > auth2 && !pop_updt(&p))
                pop_msg(&p,POP_FAILURE,"POP mailbox update failed.",p.myhost);
            p.CurrentState = error;
        } else if (tgets(message,MAXLINELEN,p.input,pop_timeout) == NULL) {
	    pop_msg(&p,POP_FAILURE,"POP timeout",p.myhost);
	    if (p.CurrentState > auth2 && !pop_updt(&p))
                pop_msg(&p,POP_FAILURE,"POP mailbox update failed!",p.myhost);
            p.CurrentState = error;
        }
        else {
            /*  Search for the command in the command/state table */
            if ((s = pop_get_command(&p,message)) == NULL) continue;

            /*  Call the function associated with this command in 
                the current state */
            if (s->function) p.CurrentState = s->result[(*s->function)(&p)];

            /*  Otherwise assume NOOP and send an OK message to the client */
            else {
                p.CurrentState = s->success_state;
                pop_msg(&p,POP_SUCCESS,NULL);
            }
        }       
    }

    /*  Say goodbye to the client */
    pop_msg(&p,POP_SUCCESS,"Pop server at %s signing off.",p.myhost);

    /*  Log the end of activity */
    pop_log(&p,POP_PRIORITY,
        "(v%s) Ending request from \"%s\" at %s\n",VERSION,p.client,p.ipaddr);

    /*  Stop logging */
    closelog();

    return(0);
}

#ifdef STRNCASECMP
/*
 *  Perform a case-insensitive string comparision
 */
#include <ctype.h>
strncasecmp(str1,str2,len)
register char   *   str1;
register char   *   str2;
register int        len;
{
    register int    i;
    char            a,
                    b;

    for (i=len-1;i>=0;i--){
        a = str1[i];
        b = str2[i];
        if (isupper(a)) a = tolower(str1[i]);
        if (isupper(b)) b = tolower(str2[i]);
        if (a > b) return (1);
        if (a < b) return(-1);
    }
    return(0);
}
#endif /* STRNCASECMP */
