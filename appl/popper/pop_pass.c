/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <popper.h>
RCSID("$Id$");

/* 
 *  pass:   Obtain the user password from a POP client
 */

int
pop_pass (POP *p)
{
    struct passwd  *pw;
    char lrealm[REALM_SZ + 1];
    int status; 
    int i;

    /* Make one string of all these parameters */
    
    for (i = 1; i < p->parm_count; ++i)
	p->pop_parm[i][strlen(p->pop_parm[i])] = ' ';

    /*  Look for the user in the password file */
    if ((pw = k_getpwnam(p->user)) == NULL)
	return (pop_msg(p,POP_FAILURE,
			"Password supplied for \"%s\" is incorrect.",
			p->user));

    if ((status = krb_get_lrealm(lrealm,1)) == KFAILURE) {
        pop_log(p, POP_FAILURE, "%s: (%s.%s@%s) %s", p->client,
		p->kdata.pname, p->kdata.pinst, p->kdata.prealm,
		krb_get_err_text(status));
        return(pop_msg(p,POP_FAILURE,
		       "Kerberos error:  \"%s\".",
		       krb_get_err_text(status)));
    }

    if (!p->kerberosp) {
	 char tkt[MaxPathLen];

	 /*  We don't accept connections from users with null passwords */
	 if (pw->pw_passwd == NULL)
	      return (pop_msg(p,
			      POP_FAILURE,
			      "Password supplied for \"%s\" is incorrect.",
			      p->user));

	 snprintf (tkt, sizeof(tkt),
		   TKT_ROOT "_popper.%u", (unsigned)getpid());
	 krb_set_tkt_string (tkt);
	 if (otp_verify_user (&p->otp_ctx, p->pop_parm[1]) == 0)
	     ;
	 else if(p->auth_level != AUTH_NONE)
	     return pop_msg(p, POP_FAILURE,
			    "Password supplied for \"%s\" is incorrect.",
			    p->user);
	 else if (krb_verify_user(p->user, "", lrealm, p->pop_parm[1],
				  1, "pop") &&
		  unix_verify_user(p->user, p->pop_parm[1])) {
	     dest_tkt ();
	     return (pop_msg(p,POP_FAILURE,
			     "Password supplied for \"%s\" is incorrect.",
			     p->user));
	 }
	 dest_tkt ();
    } else {
	 if (kuserok (&p->kdata, p->user)) {
	      pop_log(p, POP_FAILURE,
		      "%s: (%s.%s@%s) tried to retrieve mail for %s.",
		      p->client, p->kdata.pname, p->kdata.pinst,
		      p->kdata.prealm, p->user);
	      return(pop_msg(p,POP_FAILURE,
			     "Popping not authorized"));
	 }
    }

    /*  Build the name of the user's maildrop */
    snprintf(p->drop_name, sizeof(p->drop_name), "%s/%s", POP_MAILDIR, p->user);

    /*  Make a temporary copy of the user's maildrop */
    /*    and set the group and user id */
    if (pop_dropcopy(p,pw) != POP_SUCCESS) return (POP_FAILURE);

    /*  Get information about the maildrop */
    if (pop_dropinfo(p) != POP_SUCCESS) return(POP_FAILURE);

    /*  Initialize the last-message-accessed number */
    p->last_msg = 0;

    /*  Authorization completed successfully */
    return (pop_msg (p, POP_SUCCESS,
		     "%s has %d message(s) (%ld octets).",
		     p->user, p->msg_count, p->drop_size));
}
