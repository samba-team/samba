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
#ifdef KERBEROS
    char lrealm[REALM_SZ];
    int status; 
#else
    char *crypt();
#endif /* KERBEROS */

    /*  Look for the user in the password file */
    if ((pw = getpwnam(p->user)) == NULL)
        return (pop_msg(p,POP_FAILURE,
            "Password supplied for \"%s\" is incorrect.",p->user));

#ifdef KERBEROS
    if ((status = krb_get_lrealm(lrealm,1)) == KFAILURE) {
        pop_log(p, POP_FAILURE, "%s: (%s.%s@%s) %s", p->client, kdata.pname, 
                kdata.pinst, kdata.prealm, krb_get_err_text(status));
        return(pop_msg(p,POP_FAILURE,
            "Kerberos error:  \"%s\".", krb_get_err_text(status)));
    }

    if (kuserok (&kdata, p->user)) {
	 pop_log(p, POP_FAILURE,
		 "%s: (%s.%s@%s) tried to retrieve mail for %s.",
		 p->client, kdata.pname, kdata.pinst, kdata.prealm,
		 p->user);
	 return(pop_msg(p,POP_FAILURE,
			"Popping not authorized"));
    }

#if 0
    if (strcmp(kdata.prealm,lrealm))  {
         pop_log(p, POP_FAILURE, "%s: (%s.%s@%s) realm not accepted.", 
                 p->client, kdata.pname, kdata.pinst, kdata.prealm);
         return(pop_msg(p,POP_FAILURE,
                     "Kerberos realm \"%s\" not accepted.", kdata.prealm));
    }

    if (strcmp(kdata.pinst,"")) {
        pop_log(p, POP_FAILURE, "%s: (%s.%s@%s) instance not accepted.", 
                 p->client, kdata.pname, kdata.pinst, kdata.prealm);
        return(pop_msg(p,POP_FAILURE,
              "Must use null Kerberos(tm) instance -  \"%s.%s\" not accepted.",
              kdata.pname, kdata.pinst));
    }
#endif

#else /* !KERBEROS */

    /*  We don't accept connections from users with null passwords */
    if (pw->pw_passwd == NULL)
        return (pop_msg(p,POP_FAILURE,
            "Password supplied for \"%s\" is incorrect.",p->user));

    /*  Compare the supplied password with the password file entry */
    if (strcmp (crypt (p->pop_parm[1], pw->pw_passwd), pw->pw_passwd) != 0)
        return (pop_msg(p,POP_FAILURE,
            "Password supplied for \"%s\" is incorrect.",p->user));

#endif /* !KERBEROS */

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
