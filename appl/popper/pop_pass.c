/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#if 0
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
static char SccsId[] = "@(#)@(#)pop_pass.c	2.3  2.3 4/2/91";
#endif /* not lint */

#include <popper.h>
RCSID("$Id$");

#ifdef KERBEROS
extern AUTH_DAT kdata;
#endif /* KERBEROS */

/* 
 *  pass:   Obtain the user password from a POP client
 */

int
pop_pass (POP *p)
{
    struct passwd  *   pw;
    char lrealm[REALM_SZ];
    int status; 

    /*  Look for the user in the password file */
    if ((pw = k_getpwnam(p->user)) == NULL)
        return (pop_msg(p,POP_FAILURE,
            "Password supplied for \"%s\" is incorrect.",p->user));

    if ((status = krb_get_lrealm(lrealm,1)) == KFAILURE) {
        pop_log(p, POP_FAILURE, "%s: (%s.%s@%s) %s", p->client, kdata.pname, 
                kdata.pinst, kdata.prealm, krb_get_err_text(status));
        return(pop_msg(p,POP_FAILURE,
            "Kerberos error:  \"%s\".", krb_get_err_text(status)));
    }

    if (!p->kerberosp) {
	 char tkt[MaxPathLen];

	 /*  We don't accept connections from users with null passwords */
	 if (pw->pw_passwd == NULL)
	      return (pop_msg(p,
			      POP_FAILURE,
			      "Password supplied for \"%s\" is incorrect.",
			      p->user));

	 sprintf (tkt, TKT_ROOT "_popper.%d", (int)getpid());
	 krb_set_tkt_string (tkt);
	 if (krb_verify_user(p->user, "", lrealm, p->pop_parm[1], 1, "pop") &&
	     unix_verify_user(p->user, p->pop_parm[1])) {
	      dest_tkt ();
	      return (pop_msg(p,POP_FAILURE,
			      "Password supplied for \"%s\" is incorrect.",
			      p->user));
	 }
	 dest_tkt ();
    } else {
	 if (kuserok (&kdata, p->user)) {
	      pop_log(p, POP_FAILURE,
		      "%s: (%s.%s@%s) tried to retrieve mail for %s.",
		      p->client, kdata.pname, kdata.pinst, kdata.prealm,
		      p->user);
	      return(pop_msg(p,POP_FAILURE,
			     "Popping not authorized"));
	 }
    }

    /*  Build the name of the user's maildrop */
    (void)sprintf(p->drop_name,"%s/%s",POP_MAILDIR,p->user);

    /*  Make a temporary copy of the user's maildrop */
    /*    and set the group and user id */
    if (pop_dropcopy(p,pw) != POP_SUCCESS) return (POP_FAILURE);

    /*  Get information about the maildrop */
    if (pop_dropinfo(p) != POP_SUCCESS) return(POP_FAILURE);

    /*  Initialize the last-message-accessed number */
    p->last_msg = 0;

    /*  Authorization completed successfully */
    return (pop_msg (p,POP_SUCCESS,
        "%s has %d message(s) (%d octets).",
            p->user,p->msg_count,p->drop_size));
}
