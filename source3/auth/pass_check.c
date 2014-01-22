/*
   Unix SMB/CIFS implementation.
   Password checking
   Copyright (C) Andrew Tridgell 1992-1998

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* this module is for checking a username/password against a system
   password database. The SMB encrypted password support is elsewhere */

#include "includes.h"
#include "system/passwd.h"
#include "auth.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

#if !defined(WITH_PAM)
static char *ths_salt;
/* This must be writable. */
static char *get_this_salt(void)
{
	return ths_salt;
}

/* We may be setting a modified version of the same
 * string, so don't free before use. */

static const char *set_this_salt(const char *newsalt)
{
	char *orig_salt = ths_salt;
	ths_salt = SMB_STRDUP(newsalt);
	SAFE_FREE(orig_salt);
	return ths_salt;
}

static char *ths_crypted;
static const char *get_this_crypted(void)
{
	if (!ths_crypted) {
		return "";
	}
	return ths_crypted;
}

static const char *set_this_crypted(const char *newcrypted)
{
	char *orig_crypted = ths_crypted;
	ths_crypted = SMB_STRDUP(newcrypted);
	SAFE_FREE(orig_crypted);
	return ths_crypted;
}
#endif







/****************************************************************************
core of password checking routine
****************************************************************************/
static NTSTATUS password_check(const char *user, const char *password, const void *private_data)
{
#ifdef WITH_PAM
	const char *rhost = (const char *)private_data;
	return smb_pam_passcheck(user, rhost, password);
#else

	bool ret;




#ifdef ULTRIX_AUTH
	ret = (strcmp((char *)crypt16(password, get_this_salt()), get_this_crypted()) == 0);
	if (ret) {
		return NT_STATUS_OK;
        } else {
		return NT_STATUS_WRONG_PASSWORD;
	}

#endif /* ULTRIX_AUTH */



#ifdef HAVE_BIGCRYPT
	ret = (strcmp(bigcrypt(password, get_this_salt()), get_this_crypted()) == 0);
        if (ret) {
		return NT_STATUS_OK;
	} else {
		return NT_STATUS_WRONG_PASSWORD;
	}
#endif /* HAVE_BIGCRYPT */

#ifndef HAVE_CRYPT
	DEBUG(1, ("Warning - no crypt available\n"));
	return NT_STATUS_LOGON_FAILURE;
#else /* HAVE_CRYPT */
	ret = (strcmp((char *)crypt(password, get_this_salt()), get_this_crypted()) == 0);
        if (ret) {
		return NT_STATUS_OK;
	} else {
		return NT_STATUS_WRONG_PASSWORD;
	}
#endif /* HAVE_CRYPT */
#endif /* WITH_PAM */
}



/****************************************************************************
CHECK if a username/password is OK
the function pointer fn() points to a function to call when a successful
match is found and is used to update the encrypted password file 
return NT_STATUS_OK on correct match, appropriate error otherwise
****************************************************************************/

NTSTATUS pass_check(const struct passwd *pass,
		    const char *user,
		    const char *rhost,
		    const char *password,
		    bool run_cracker)
{
	char *pass2 = NULL;

	NTSTATUS nt_status;

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("checking user=[%s] pass=[%s]\n", user, password));
#endif

	if (!password)
		return NT_STATUS_LOGON_FAILURE;

	if ((!*password) && !lp_null_passwords())
		return NT_STATUS_LOGON_FAILURE;

#if defined(WITH_PAM) 

	/*
	 * If we're using PAM we want to short-circuit all the 
	 * checks below and dive straight into the PAM code.
	 */

	DEBUG(4, ("pass_check: Checking (PAM) password for user %s\n", user));

#else /* Not using PAM */

	DEBUG(4, ("pass_check: Checking password for user %s\n", user));

	if (!pass) {
		DEBUG(3, ("Couldn't find user %s\n", user));
		return NT_STATUS_NO_SUCH_USER;
	}


	/* Copy into global for the convenience of looping code */
	/* Also the place to keep the 'password' no matter what
	   crazy struct it started in... */
	if (set_this_crypted(pass->pw_passwd) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	if (set_this_salt(pass->pw_passwd) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

#ifdef HAVE_GETSPNAM
	{
		struct spwd *spass;

		/* many shadow systems require you to be root to get
		   the password, in most cases this should already be
		   the case when this function is called, except
		   perhaps for IPC password changing requests */

		spass = getspnam(pass->pw_name);
		if (spass && spass->sp_pwdp) {
			if (set_this_crypted(spass->sp_pwdp) == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			if (set_this_salt(spass->sp_pwdp) == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
		}
	}
#elif defined(IA_UINFO)
	{
		/* Need to get password with SVR4.2's ia_ functions
		   instead of get{sp,pw}ent functions. Required by
		   UnixWare 2.x, tested on version
		   2.1. (tangent@cyberport.com) */
		uinfo_t uinfo;
		if (ia_openinfo(pass->pw_name, &uinfo) != -1)
			ia_get_logpwd(uinfo, &(pass->pw_passwd));
	}
#endif


#ifdef HAVE_GETPWANAM
	{
		struct passwd_adjunct *pwret;
		pwret = getpwanam(s);
		if (pwret && pwret->pwa_passwd) {
			if (set_this_crypted(pwret->pwa_passwd) == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
		}
	}
#endif


#ifdef ULTRIX_AUTH
	{
		AUTHORIZATION *ap = getauthuid(pass->pw_uid);
		if (ap) {
			if (set_this_crypted(ap->a_password) == NULL) {
				endauthent();
				return NT_STATUS_NO_MEMORY;
			}
			endauthent();
		}
	}
#endif


	if (!get_this_crypted() || !*get_this_crypted()) {
		if (!lp_null_passwords()) {
			DEBUG(2, ("Disallowing %s with null password\n",
				  user));
			return NT_STATUS_LOGON_FAILURE;
		}
		if (!*password) {
			DEBUG(3,
			      ("Allowing access to %s with null password\n",
			       user));
			return NT_STATUS_OK;
		}
	}

#endif /* defined(WITH_PAM) */

	/* try it as it came to us */
	nt_status = password_check(user, password, (const void *)rhost);
        if NT_STATUS_IS_OK(nt_status) {
		return (nt_status);
	} else if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_WRONG_PASSWORD)) {
                /* No point continuing if its not the password thats to blame (ie PAM disabled). */
                return (nt_status);
        }

	if (!run_cracker) {
		return (nt_status);
	}

	/* if the password was given to us with mixed case then we don't
	 * need to proceed as we know it hasn't been case modified by the
	 * client */
	if (strhasupper(password) && strhaslower(password)) {
		return nt_status;
	}

	/* make a copy of it */
	pass2 = talloc_strdup(talloc_tos(), password);
	if (!pass2) {
		return NT_STATUS_NO_MEMORY;
	}

	/* try all lowercase if it's currently all uppercase */
	if (strhasupper(pass2)) {
		if (!strlower_m(pass2)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		nt_status = password_check(user, pass2, (const void *)rhost);
		if (NT_STATUS_IS_OK(nt_status)) {
			return (nt_status);
		}
	}

	return NT_STATUS_WRONG_PASSWORD;
}
