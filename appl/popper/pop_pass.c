/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <popper.h>
RCSID("$Id$");

#ifdef KRB4
static int
krb4_verify_password (POP *p)
{
    int status;
    char lrealm[REALM_SZ + 1];
    char tkt[MaxPathLen];

    status = krb_get_lrealm(lrealm,1);
    if (status == KFAILURE) {
        pop_log(p, POP_FAILURE, "%s: (%s.%s@%s) %s", p->client,
		p->kdata.pname, p->kdata.pinst, p->kdata.prealm,
		krb_get_err_text(status));
	return 1;
    }
    snprintf (tkt, sizeof(tkt),
	      TKT_ROOT "_popper.%u", (unsigned)getpid());
    krb_set_tkt_string (tkt);

    return krb_verify_user(p->user, "", lrealm, p->pop_parm[1],
			   1, "pop");
}
#endif /* KRB4 */

static int
krb5_verify_password (POP *p)
{
    krb5_preauthtype pre_auth_types[] = {KRB5_PADATA_ENC_TIMESTAMP};
    krb5_get_init_creds_opt get_options;
    krb5_verify_init_creds_opt verify_options;
    krb5_error_code ret;
    krb5_principal client, server;
    krb5_creds creds;

    krb5_get_init_creds_opt_init (&get_options);

    krb5_get_init_creds_opt_set_preauth_list (&get_options,
					      pre_auth_types,
					      1);

    krb5_verify_init_creds_opt_init (&verify_options);
    
    ret = krb5_parse_name (p->context, p->user, &client);
    if (ret) {
	pop_log(p, POP_FAILURE, "krb5_parse_name: %s",
		krb5_get_err_text (p->context, ret));
	return 1;
    }

    ret = krb5_get_init_creds_password (p->context,
					&creds,
					client,
					p->pop_parm[1],
					NULL,
					NULL,
					0,
					NULL,
					&get_options);
    if (ret) {
	pop_log(p, POP_FAILURE,
		"krb5_get_init_creds_password: %s",
		krb5_get_err_text (p->context, ret));
	return 1;
    }

    ret = krb5_sname_to_principal (p->context,
				   p->myhost,
				   "pop",
				   KRB5_NT_SRV_HST,
				   &server);
    if (ret) {
	pop_log(p, POP_FAILURE,
		"krb5_get_init_creds_password: %s",
		krb5_get_err_text (p->context, ret));
	return 1;
    }

    ret = krb5_verify_init_creds (p->context,
				  &creds,
				  server,
				  NULL,
				  NULL,
				  &verify_options);
    krb5_free_principal (p->context, client);
    krb5_free_principal (p->context, server);
    krb5_free_creds_contents (p->context, &creds);
    return ret;
}

/* 
 *  pass:   Obtain the user password from a POP client
 */

int
pop_pass (POP *p)
{
    struct passwd  *pw;
    int i;

    /* Make one string of all these parameters */
    
    for (i = 1; i < p->parm_count; ++i)
	p->pop_parm[i][strlen(p->pop_parm[i])] = ' ';

    /*  Look for the user in the password file */
    if ((pw = k_getpwnam(p->user)) == NULL)
	return (pop_msg(p,POP_FAILURE,
			"Password supplied for \"%s\" is incorrect.",
			p->user));

    if (p->kerberosp) {
#ifdef KRB4
	if (p->version == 4) {
	    if(kuserok (&p->kdata, p->user)) {
		pop_log(p, POP_FAILURE,
			"%s: (%s.%s@%s) tried to retrieve mail for %s.",
			p->client, p->kdata.pname, p->kdata.pinst,
			p->kdata.prealm, p->user);
		return(pop_msg(p,POP_FAILURE,
			       "Popping not authorized"));
	    }
	} else
#endif /* KRB4 */
	    if (p->version == 5) {
		if (!krb5_kuserok (p->context, p->principal, p->user)) {
		    pop_log (p, POP_FAILURE,
			     "krb5 permission denied");
		    return pop_msg(p, POP_FAILURE,
				   "Popping not authorized");
		}
	    } else {
		pop_log (p, POP_FAILURE, "kerberos authentication failed");
		return pop_msg (p, POP_FAILURE,
				"kerberos authentication failed");
	    }
    } else {
	 /*  We don't accept connections from users with null passwords */
	 if (pw->pw_passwd == NULL)
	      return (pop_msg(p,
			      POP_FAILURE,
			      "Password supplied for \"%s\" is incorrect.",
			      p->user));

	 if (otp_verify_user (&p->otp_ctx, p->pop_parm[1]) == 0)
	     ;
	 else if(p->auth_level != AUTH_NONE)
	     return pop_msg(p, POP_FAILURE,
			    "Password supplied for \"%s\" is incorrect.",
			    p->user);
	 else {
#ifdef KRB4
	     if (krb4_verify_password (p) == 0)
		 ;
	     else
#endif /* KRB4 */
		 if (krb5_verify_password (p) == 0)
		     ;
	     else
		 return pop_msg(p, POP_FAILURE,
				"Password incorrect");
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
