/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#if 0
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
static char SccsId[] = "@(#)@(#)pop_user.c	2.1  2.1 3/18/91";
#endif /* not lint */

#include <popper.h>
RCSID("$Id$");

/* 
 *  user:   Prompt for the user name at the start of a POP session
 */

int
pop_user (POP *p)
{
#ifdef SKEY
    char ss[256], msg[256];
#endif

    /*  Save the user name */
    strcpy(p->user, p->pop_parm[1]);

#ifdef SKEY
    p->permit_passwd = skeyaccess(k_getpwnam (p->user), NULL,
				  p->client, NULL);
    if (skeychallenge (&p->sk, p->user, ss) == 0) {
	return pop_msg(p, POP_SUCCESS, "Password [%s] required for %s.",
		       ss, p->user);
    } else if (!p->permit_passwd)
	return pop_msg(p, POP_FAILURE, "Access unauthorized for %s.",
		       p->user);
#endif
    /*  Tell the user that the password is required */
    return pop_msg(p, POP_SUCCESS, "Password required for %s.", p->user);
}
