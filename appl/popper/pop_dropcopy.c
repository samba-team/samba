/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef lint
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
static char SccsId[] = "@(#)@(#)pop_dropcopy.c	2.6  2.6 4/3/91";
#endif not lint

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <pwd.h>
#include "popper.h"

extern int      errno;
extern int      sys_nerr;
extern char    *sys_errlist[];

/* 
 *  dropcopy:   Make a temporary copy of the user's mail drop and 
 *  save a stream pointer for it.
 */

pop_dropcopy(p,pwp)
POP     *   p;
struct passwd	*	pwp;
{
    int                     mfd;                    /*  File descriptor for 
                                                        the user's maildrop */
    int                     dfd;                    /*  File descriptor for 
                                                        the SERVER maildrop */
    FILE		    *tf;		    /*  The temp file */
    char		    template[POP_TMPSIZE];  /*  Temp name holder */
    char                    buffer[BUFSIZ];         /*  Read buffer */
    long                    offset;                 /*  Old/New boundary */
    int                     nchar;                  /*  Bytes written/read */
    struct stat             mybuf;                  /*  For lstat() */

    /*  Create a temporary maildrop into which to copy the updated maildrop */
    (void)sprintf(p->temp_drop,POP_DROP,p->user);

#ifdef DEBUG
    if(p->debug)
        pop_log(p,POP_DEBUG,"Creating temporary maildrop '%s'",
            p->temp_drop);
#endif DEBUG

    /* Here we work to make sure the user doesn't cause us to remove or
     * write over existing files by limiting how much work we do while
     * running as root.
     */

    /* First create a unique file.  Would prefer mkstemp, but Ultrix...*/
    strcpy(template,POP_TMPDROP);
    (void) mktemp(template);
    if ( (tf=fopen(template,"w+")) == NULL ) {	/* failure, bail out	*/
        pop_log(p,POP_PRIORITY,
            "Unable to create temporary temporary maildrop '%s': %s",template,
                (errno < sys_nerr) ? sys_errlist[errno] : "") ;
        return pop_msg(p,POP_FAILURE,
		"System error, can't create temporary file.");
    }

    /* Now give this file to the user	*/
    if (pwp) {
    	(void) chown(template,pwp->pw_uid, pwp->pw_gid);
    }
    (void) chmod(template,0600);

    /* Now link this file to the temporary maildrop.  If this fails it
     * is probably because the temporary maildrop already exists.  If so,
     * this is ok.  We can just go on our way, because by the time we try
     * to write into the file we will be running as the user.
     */
    (void) link(template,p->temp_drop);
    (void) fclose(tf);
    (void) unlink(template);

    /* Now we run as the user. */
    if (pwp) {
    	(void) setuid(pwp->pw_uid);
    	(void) setgid(pwp->pw_gid);
    }
#ifdef DEBUG
    if(p->debug)pop_log(p,POP_DEBUG,"uid = %d, gid = %d",getuid(),getgid());
#endif DEBUG

    /* Open for append,  this solves the crash recovery problem */
    if ((dfd = open(p->temp_drop,O_RDWR|O_APPEND|O_CREAT,0600)) == -1){
        pop_log(p,POP_PRIORITY,
            "Unable to open temporary maildrop '%s': %s",p->temp_drop,
                (errno < sys_nerr) ? sys_errlist[errno] : "") ;
        return pop_msg(p,POP_FAILURE,
		"System error, can't open temporary file, do you own it?");
    }

    /*  Lock the temporary maildrop */
    if ( k_flock (dfd, (K_LOCK_EX | K_LOCK_NB)) == -1 ) 
    switch(errno) {
        case EWOULDBLOCK:
            return pop_msg(p,POP_FAILURE,
                 "Maildrop lock busy!  Is another session active?");
            /* NOTREACHED */
        default:
            return pop_msg(p,POP_FAILURE,"flock: '%s': %s", p->temp_drop,
                (errno < sys_nerr) ? sys_errlist[errno] : "");
            /* NOTREACHED */
        }
    
    /* May have grown or shrunk between open and lock! */
    offset = lseek(dfd,0, SEEK_END);

    /*  Open the user's maildrop, If this fails,  no harm in assuming empty */
    if ((mfd = open(p->drop_name,O_RDWR)) > 0) {

        /*  Lock the maildrop */
        if (k_flock (mfd, K_LOCK_EX) == -1) {
            (void)close(mfd) ;
            return pop_msg(p,POP_FAILURE, "flock: '%s': %s", p->temp_drop,
                (errno < sys_nerr) ? sys_errlist[errno] : "");
        }

        /*  Copy the actual mail drop into the temporary mail drop */
        while ( (nchar=read(mfd,buffer,BUFSIZ)) > 0 )
            if ( nchar != write(dfd,buffer,nchar) ) {
                nchar = -1 ;
                break ;
            }

        if ( nchar != 0 ) {
            /* Error adding new mail.  Truncate to original size,
               and leave the maildrop as is.  The user will not 
               see the new mail until the error goes away.
               Should let them process the current backlog,  in case
               the error is a quota problem requiring deletions! */
            (void)ftruncate(dfd,(int)offset) ;
        } else {
            /* Mail transferred!  Zero the mail drop NOW,  that we
               do not have to do gymnastics to figure out what's new
               and what is old later */
            (void)ftruncate(mfd,0) ;
        }

        /*  Close the actual mail drop */
        (void)close (mfd);
    }

    /*  Acquire a stream pointer for the temporary maildrop */
    if ( (p->drop = fdopen(dfd,"a+")) == NULL ) {
        (void)close(dfd) ;
        return pop_msg(p,POP_FAILURE,"Cannot assign stream for %s",
            p->temp_drop);
    }

    rewind (p->drop);

    return(POP_SUCCESS);
}
