/*
 * Copyright Alexander O. Yuriev, 1996.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 * 
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* 
   This code has been changed heavily for smb authentication by

   pam_ntdom_auth -- David Airlie 1998 v1.3a ( airlied@samba.org ) 
   http://www.csn.ul.ie/~airlied

   all changes are (C) David Airlie 1998.
*/

#include "includes.h"

#ifdef HAVE_SECURITY_PAM_APPL_H

#include <security/pam_appl.h>

#endif

#define _PAM_EXTERN_FUNCTIONS

#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN extern
#endif

extern int DEBUGLEVEL;

#include "pam_ntdom_proto.h"

#if 0
extern int converse(pam_handle_t * pamh,
		    int nargs,
		    struct pam_message **message,
		    struct pam_response **response);

extern int _set_auth_tok(pam_handle_t * pamh,
			 int flags, int argc, const char **argv);

static int _pam_auth_smb(pam_handle_t * pamh,
			 int flags, int argc, const char **argv);

static int _pam_set_credentials_smb(pam_handle_t * pamh,
				    int flags, int argc, const char **argv);


#endif

/* 
 * 
 * _pam_auth_smb() actually performs UNIX/shadow authentication and
 * then performs the NT Validation.
 *
 *	First, if shadow support is available, attempt to perform
 *	authentication using shadow passwords. If shadow is not
 *	available, or user does not have a shadow password, fallback
 *	onto a normal UNIX authentication
 *      If neither shadow nor normal succeed it will send the username
 *      and password to a local server, which will do the authentication.
 */

static int _pam_auth_smb(pam_handle_t * pamh,
			 int flags, int argc, const char **argv)
{
	int retval;
	struct passwd *pw;
	const char *name;
	char *p, *pp;
	int w, loop;
	const char *salt;
	fstring domain;
	fstring ntname;
	int debug = 0, use_first_pass = 0;
	int unknown_user = 0;
	int nolocal = 0;

#ifdef HAVE_SHADOW_H

	struct spwd *sp;

#endif

	DEBUGLEVEL = 0;

	/* Parse Command line options */

	for (loop = 0; loop < argc; loop++)
	{
		if (!strcmp(argv[loop], "debug"))
		{
			debug = 1;
			DEBUGLEVEL = 100;
		}
		else if (!strcmp(argv[loop], "use_first_pass"))
			use_first_pass = 1;
		else if (!strcmp(argv[loop], "nolocal"))
			nolocal = 1;
#ifdef USE_LOGAUTH
		else
			syslog(LOG_AUTHPRIV | LOG_ERR,
			       "pam_ntdom: Unknown Command Line Option in pam.d : %s",
			       argv[loop]);
#endif
	}

	if (!rpc_initialise())
	{
#ifdef USE_LOGAUTH
		if (debug)
		{
			syslog(LOG_AUTHPRIV | LOG_ERR,
			       "pam_ntdom: initialisation failed\n");
		}
#endif
		return PAM_SERVICE_ERR;
	}
	/* get the user'name' */

	if ((retval = pam_get_user(pamh, &name, "login: ")) != PAM_SUCCESS)
	{
#ifdef USE_LOGAUTH
		syslog(LOG_AUTHPRIV | LOG_ERR, "pam_ntdom: User not found");
#endif
		return retval;
	}

	pam_get_item(pamh, PAM_AUTHTOK, (void *)&p);

	if (!p)
	{
		if (use_first_pass != 1)
		{
			retval = _set_auth_tok(pamh, flags, argc, argv);
			if (retval != PAM_SUCCESS)
				return retval;
		}
		else
			return PAM_AUTH_ERR;
	}

	/* 
	   We have to call pam_get_item() again because value of p should
	   change 
	 */

	pam_get_item(pamh, PAM_AUTHTOK, (void *)&p);

	if (!split_domain_name(name, domain, ntname))
	{
		return PAM_BUF_ERR;
	}

	/* If nolocal is specified pam_ntdom does not try and do local
	   username/password authentication .. this is a command line option
	   to pam_ntdom_auth.so in /etc/pam.d/ */

	if (nolocal == 0)
	{
		pw = getpwnam(name);

		if (pw)
		{

#ifdef HAVE_SHADOW_H

			/*
			 * Support for shadow passwords on Linux and SVR4-based
			 * systems.  Shadow passwords are optional on Linux - if
			 * there is no shadow password, use the non-shadow one.
			 */

			sp = getspnam(name);
			if (sp && (!strcmp(pw->pw_passwd, "x")))
			{
				/* TODO: check if password has expired etc. */
				salt = sp->sp_pwdp;
			}
			else
#endif
				salt = pw->pw_passwd;
		}
		else
			unknown_user = 1;

		/* The 'always-encrypt' method does not make sense in PAM
		   because the framework requires return of a different
		   error code for non-existant users -- alex */
		if (!unknown_user)
		{
			if ((!pw->pw_passwd) && (!p))
				if (flags && PAM_DISALLOW_NULL_AUTHTOK)
					return PAM_SUCCESS;

			pp = crypt(p, salt);

			if (strcmp(pp, salt) == 0)
			{
				if (debug)
#ifdef USE_LOGAUTH
					syslog(LOG_AUTHPRIV | LOG_DEBUG,
					       "pam_ntdom: Local UNIX username/password pair correct.");
#endif
				return PAM_SUCCESS;
			}

			if (debug)
			{
#ifdef USE_LOGAUTH
				syslog(LOG_AUTHPRIV | LOG_DEBUG,
				       "pam_ntdom: Local UNIX username/password check incorrect.");
#endif
			}
		}
	}			/* End of Local Section */
	else
	{			/* If Local System Authentication is switched off */
#ifdef USE_LOGAUTH
		if (debug)
			syslog(LOG_AUTHPRIV | LOG_DEBUG,
			       "No Local authentication done, relying on other modules for password file entry.");
#endif
	}

#ifdef USE_LOGAUTH
	if (debug)
	{
		syslog(LOG_AUTHPRIV | LOG_DEBUG,
		       "pam_ntdom: Configuration Data, Domain %s.", domain);
	}
#endif

#ifdef USE_LOGAUTH
	if (debug)
	{
		syslog(LOG_AUTHPRIV | LOG_DEBUG,
		       "pam_ntdom: user: %s domain: %s password: %s",
		       ntname, domain, p);
	}
#endif

	w = Valid_User(ntname, p, domain);

	/* Users valid user for return value 0 is success
	   1 and 2 indicate Network and protocol failures and
	   3 is not logged on 
	 */

	switch (w)
	{
		case 0:
#ifdef USE_LOGAUTH
			if (debug)
			{
				syslog(LOG_AUTHPRIV | LOG_DEBUG,
				       "pam_ntdom: Correct NT username/password pair");
			}
#endif
			return PAM_SUCCESS;
		case 1:
		case 2:
#ifdef USE_LOGAUTH
			if (debug)
			{
				syslog(LOG_AUTHPRIV | LOG_DEBUG,
				       "pam_ntdom: Authentication unavailable\n");
			}
#endif
			return PAM_AUTHINFO_UNAVAIL;
			break;
		case 3:
		default:
#ifdef USE_LOGAUTH
			syslog(LOG_AUTHPRIV | LOG_NOTICE,
			       "pam_ntdom: Incorrect NT password for username : %s",
			       ntname);
#endif
			return PAM_AUTH_ERR;
			break;
	}

#ifdef USE_LOGAUTH
	if (debug)
	{
		syslog(LOG_AUTHPRIV | LOG_DEBUG,
		       "pam_ntdom: Authentication failed\n");
	}
#endif
	return PAM_AUTH_ERR;

}

/* 
 * The _pam_set_credentials_smb() does nothing.
  */

static int _pam_set_credentials_smb(pam_handle_t * pamh,
				    int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;	/* This is a wrong result code. From what I
				   remember from reafing one of the guides
				   there's an error-level saying 'N/A func'
				   -- AOY
				 */
}

/*
 * PAM framework looks for these entry-points to pass control to the
 * authentication module.
 */

PAM_EXTERN
	int pam_sm_authenticate(pam_handle_t * pamh,
				int flags, int argc, const char **argv)
{
	return _pam_auth_smb(pamh, flags, argc, argv);
}

PAM_EXTERN
	int pam_sm_setcred(pam_handle_t * pamh,
			   int flags, int argc, const char **argv)
{
	return _pam_set_credentials_smb(pamh, flags, argc, argv);
}
