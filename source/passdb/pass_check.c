/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password checking
   Copyright (C) Andrew Tridgell 1992-2000
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* this module is for checking a username/password against a system
   password database. The SMB encrypted password support is elsewhere */

#include "includes.h"

extern int DEBUGLEVEL;

/* these are kept here to keep the string_combinations function simple */
static char this_user[100] = "";
static char this_salt[100] = "";
static char this_crypted[100] = "";


#ifdef HAVE_PAM
/*******************************************************************
check on PAM authentication
********************************************************************/

/* We first need some helper functions */
#include <security/pam_appl.h>
/* Static variables used to communicate between the conversation function
 * and the server_login function
 */
static char *PAM_username;
static char *PAM_password;

/* PAM conversation function
 * Here we assume (for now, at least) that echo on means login name, and
 * echo off means password.
 */
static int PAM_conv(int num_msg,
		    const struct pam_message **msg,
		    struct pam_response **resp, void *appdata_ptr)
{
	int replies = 0;
	struct pam_response *reply = NULL;

#define COPY_STRING(s) (s) ? strdup(s) : NULL

	reply = malloc(sizeof(struct pam_response) * num_msg);
	if (!reply)
		return PAM_CONV_ERR;

	for (replies = 0; replies < num_msg; replies++)
	{
		switch (msg[replies]->msg_style)
		{
			case PAM_PROMPT_ECHO_ON:
				reply[replies].resp_retcode = PAM_SUCCESS;
				reply[replies].resp =
					COPY_STRING(PAM_username);
				/* PAM frees resp */
				break;
			case PAM_PROMPT_ECHO_OFF:
				reply[replies].resp_retcode = PAM_SUCCESS;
				reply[replies].resp =
					COPY_STRING(PAM_password);
				/* PAM frees resp */
				break;
			case PAM_TEXT_INFO:
				/* fall through */
			case PAM_ERROR_MSG:
				/* ignore it... */
				reply[replies].resp_retcode = PAM_SUCCESS;
				reply[replies].resp = NULL;
				break;
			default:
				/* Must be an error of some sort... */
				free(reply);
				return PAM_CONV_ERR;
		}
	}
	if (reply)
		*resp = reply;
	return PAM_SUCCESS;
}
static struct pam_conv PAM_conversation = {
	&PAM_conv,
	NULL
};


static BOOL pam_auth(char *user, char *password)
{
	pam_handle_t *pamh;
	int pam_error;

	/* Now use PAM to do authentication.  For now, we won't worry about
	 * session logging, only authentication.  Bail out if there are any
	 * errors.  Since this is a limited protocol, and an even more limited
	 * function within a server speaking this protocol, we can't be as
	 * verbose as would otherwise make sense.
	 * Query: should we be using PAM_SILENT to shut PAM up?
	 */
#define PAM_BAIL if (pam_error != PAM_SUCCESS) { \
     pam_end(pamh, 0); return False; \
   }
	PAM_password = password;
	PAM_username = user;
	pam_error = pam_start("samba", user, &PAM_conversation, &pamh);
	PAM_BAIL;
/* Setting PAM_SILENT stops generation of error messages to syslog
 * to enable debugging on Red Hat Linux set:
 * /etc/pam.d/samba:
 *	auth required /lib/security/pam_pwdb.so nullok shadow audit
 * _OR_ change PAM_SILENT to 0 to force detailed reporting (logging)
 */
	pam_error = pam_authenticate(pamh, PAM_SILENT);
	PAM_BAIL;
	/* It is not clear to me that account management is the right thing
	 * to do, but it is not clear that it isn't, either.  This can be
	 * removed if no account management should be done.  Alternately,
	 * put a pam_allow.so entry in /etc/pam.conf for account handling. */
	pam_error = pam_acct_mgmt(pamh, PAM_SILENT);
	PAM_BAIL;
	pam_end(pamh, PAM_SUCCESS);
	/* If this point is reached, the user has been authenticated. */
	return (True);
}
#endif


#ifdef WITH_AFS
/*******************************************************************
check on AFS authentication
********************************************************************/
static BOOL afs_auth(char *user, char *password)
{
	long password_expires = 0;
	char *reason;

	/* For versions of AFS prior to 3.3, this routine has few arguments, */
	/* but since I can't find the old documentation... :-)               */
	setpag();
	if (ka_UserAuthenticateGeneral
	    (KA_USERAUTH_VERSION + KA_USERAUTH_DOSETPAG, user, (char *)0,	/* instance */
	     (char *)0,		/* cell */
	     password, 0,	/* lifetime, default */
	     &password_expires,	/*days 'til it expires */
	     0,			/* spare 2 */
	     &reason) == 0)
	{
		return (True);
	}
	return (False);
}
#endif


#ifdef WITH_DFS

/*****************************************************************
 This new version of the DFS_AUTH code was donated by Karsten Muuss
 <muuss@or.uni-bonn.de>. It fixes the following problems with the
 old code :

  - Server credentials may expire
  - Client credential cache files have wrong owner
  - purge_context() function is called with invalid argument

 This new code was modified to ensure that on exit the uid/gid is
 still root, and the original directory is restored. JRA.
******************************************************************/

sec_login_handle_t my_dce_sec_context;
int dcelogin_atmost_once = 0;

/*******************************************************************
check on a DCE/DFS authentication
********************************************************************/
static BOOL dfs_auth(char *user, char *password)
{
	error_status_t err;
	int err2;
	int prterr;
	signed32 expire_time, current_time;
	boolean32 password_reset;
	struct passwd *pw;
	sec_passwd_rec_t passwd_rec;
	sec_login_auth_src_t auth_src = sec_login_auth_src_network;
	unsigned char dce_errstr[dce_c_error_string_len];
	gid_t egid;

	if (dcelogin_atmost_once)
		return (False);

#ifdef HAVE_CRYPT
	{
		char *c = (char *)crypt(password, this_salt)
			/*
			 * We only go for a DCE login context if the given password
			 * matches that stored in the local password file.. 
			 * Assumes local passwd file is kept in sync w/ DCE RGY!
			 */
			if (c == NULL)
		{
			DEBUG(1, ("dfs_auth: crypt returned NULL!\n"));
			return False;
		}
		if (strcmp(c, this_crypted))
		{
			return (False);
		}
	}
#endif

	sec_login_get_current_context(&my_dce_sec_context, &err);
	if (err != error_status_ok)
	{
		dce_error_inq_text(err, dce_errstr, &err2);
		DEBUG(0, ("DCE can't get current context. %s\n", dce_errstr));

		return (False);
	}

	sec_login_certify_identity(my_dce_sec_context, &err);
	if (err != error_status_ok)
	{
		dce_error_inq_text(err, dce_errstr, &err2);
		DEBUG(0, ("DCE can't get current context. %s\n", dce_errstr));

		return (False);
	}

	sec_login_get_expiration(my_dce_sec_context, &expire_time, &err);
	if (err != error_status_ok)
	{
		dce_error_inq_text(err, dce_errstr, &err2);
		DEBUG(0, ("DCE can't get expiration. %s\n", dce_errstr));

		return (False);
	}

	time(&current_time);

	if (expire_time < (current_time + 60))
	{
		struct passwd *pw;
		sec_passwd_rec_t *key;

		sec_login_get_pwent(my_dce_sec_context,
				    (sec_login_passwd_t *) & pw, &err);
		if (err != error_status_ok)
		{
			dce_error_inq_text(err, dce_errstr, &err2);
			DEBUG(0, ("DCE can't get pwent. %s\n", dce_errstr));

			return (False);
		}

		sec_login_refresh_identity(my_dce_sec_context, &err);
		if (err != error_status_ok)
		{
			dce_error_inq_text(err, dce_errstr, &err2);
			DEBUG(0, ("DCE can't refresh identity. %s\n",
				  dce_errstr));

			return (False);
		}

		sec_key_mgmt_get_key(rpc_c_authn_dce_secret, NULL,
				     (unsigned char *)pw->pw_name,
				     sec_c_key_version_none,
				     (void **)&key, &err);
		if (err != error_status_ok)
		{
			dce_error_inq_text(err, dce_errstr, &err2);
			DEBUG(0, ("DCE can't get key for %s. %s\n",
				  pw->pw_name, dce_errstr));

			return (False);
		}

		sec_login_valid_and_cert_ident(my_dce_sec_context, key,
					       &password_reset, &auth_src,
					       &err);
		if (err != error_status_ok)
		{
			dce_error_inq_text(err, dce_errstr, &err2);
			DEBUG(0,
			      ("DCE can't validate and certify identity for %s. %s\n",
			       pw->pw_name, dce_errstr));
		}

		sec_key_mgmt_free_key(key, &err);
		if (err != error_status_ok)
		{
			dce_error_inq_text(err, dce_errstr, &err2);
			DEBUG(0, ("DCE can't free key.\n", dce_errstr));
		}
	}

	if (sec_login_setup_identity((unsigned char *)user,
				     sec_login_no_flags,
				     &my_dce_sec_context, &err) == 0)
	{
		dce_error_inq_text(err, dce_errstr, &err2);
		DEBUG(0, ("DCE Setup Identity for %s failed: %s\n",
			  user, dce_errstr));
		return (False);
	}

	sec_login_get_pwent(my_dce_sec_context,
			    (sec_login_passwd_t *) & pw, &err);
	if (err != error_status_ok)
	{
		dce_error_inq_text(err, dce_errstr, &err2);
		DEBUG(0, ("DCE can't get pwent. %s\n", dce_errstr));

		return (False);
	}

	sec_login_purge_context(&my_dce_sec_context, &err);
	if (err != error_status_ok)
	{
		dce_error_inq_text(err, dce_errstr, &err2);
		DEBUG(0, ("DCE can't purge context. %s\n", dce_errstr));

		return (False);
	}

	/*
	 * NB. I'd like to change these to call something like become_user()
	 * instead but currently we don't have a connection
	 * context to become the correct user. This is already
	 * fairly platform specific code however, so I think
	 * this should be ok. I have added code to go
	 * back to being root on error though. JRA.
	 */

	egid = getegid();

	if (set_effective_gid(pw->pw_gid) != 0)
	{
		DEBUG(0, ("Can't set egid to %d (%s)\n",
			  pw->pw_gid, strerror(errno)));
		return False;
	}

	if (set_effective_uid(pw->pw_uid) != 0)
	{
		set_effective_gid(egid);
		DEBUG(0, ("Can't set euid to %d (%s)\n",
			  pw->pw_uid, strerror(errno)));
		return False;
	}

	if (sec_login_setup_identity((unsigned char *)user,
				     sec_login_no_flags,
				     &my_dce_sec_context, &err) == 0)
	{
		dce_error_inq_text(err, dce_errstr, &err2);
		DEBUG(0, ("DCE Setup Identity for %s failed: %s\n",
			  user, dce_errstr));
		goto err;
	}

	sec_login_get_pwent(my_dce_sec_context,
			    (sec_login_passwd_t *) & pw, &err);
	if (err != error_status_ok)
	{
		dce_error_inq_text(err, dce_errstr, &err2);
		DEBUG(0, ("DCE can't get pwent. %s\n", dce_errstr));
		goto err;
	}

	passwd_rec.version_number = sec_passwd_c_version_none;
	passwd_rec.pepper = NULL;
	passwd_rec.key.key_type = sec_passwd_plain;
	passwd_rec.key.tagged_union.plain = (idl_char *) password;

	sec_login_validate_identity(my_dce_sec_context,
				    &passwd_rec, &password_reset,
				    &auth_src, &err);
	if (err != error_status_ok)
	{
		dce_error_inq_text(err, dce_errstr, &err2);
		DEBUG(0,
		      ("DCE Identity Validation failed for principal %s: %s\n",
		       user, dce_errstr));
		goto err;
	}

	sec_login_certify_identity(my_dce_sec_context, &err);
	if (err != error_status_ok)
	{
		dce_error_inq_text(err, dce_errstr, &err2);
		DEBUG(0, ("DCE certify identity failed: %s\n", dce_errstr));
		goto err;
	}

	if (auth_src != sec_login_auth_src_network)
	{
		DEBUG(0, ("DCE context has no network credentials.\n"));
	}

	sec_login_set_context(my_dce_sec_context, &err);
	if (err != error_status_ok)
	{
		dce_error_inq_text(err, dce_errstr, &err2);
		DEBUG(0,
		      ("DCE login failed for principal %s, cant set context: %s\n",
		       user, dce_errstr));

		sec_login_purge_context(&my_dce_sec_context, &err);
		goto err;
	}

	sec_login_get_pwent(my_dce_sec_context,
			    (sec_login_passwd_t *) & pw, &err);
	if (err != error_status_ok)
	{
		dce_error_inq_text(err, dce_errstr, &err2);
		DEBUG(0, ("DCE can't get pwent. %s\n", dce_errstr));
		goto err;
	}

	DEBUG(0, ("DCE login succeeded for principal %s on pid %d\n",
		  user, getpid()));

	DEBUG(3, ("DCE principal: %s\n"
		  "          uid: %d\n"
		  "          gid: %d\n",
		  pw->pw_name, pw->pw_uid, pw->pw_gid));
	DEBUG(3, ("         info: %s\n"
		  "          dir: %s\n"
		  "        shell: %s\n",
		  pw->pw_gecos, pw->pw_dir, pw->pw_shell));

	sec_login_get_expiration(my_dce_sec_context, &expire_time, &err);
	if (err != error_status_ok)
	{
		dce_error_inq_text(err, dce_errstr, &err2);
		DEBUG(0, ("DCE can't get expiration. %s\n", dce_errstr));
		goto err;
	}

	set_effective_uid(0);
	set_effective_gid(0);

	DEBUG(0,
	      ("DCE context expires: %s", asctime(localtime(&expire_time))));

	dcelogin_atmost_once = 1;
	return (True);

      err:

	/* Go back to root, JRA. */
	set_effective_uid(0);
	set_effective_gid(egid);
	return (False);
}

void dfs_unlogin(void)
{
	error_status_t err;
	int err2;
	unsigned char dce_errstr[dce_c_error_string_len];

	sec_login_purge_context(&my_dce_sec_context, &err);
	if (err != error_status_ok)
	{
		dce_error_inq_text(err, dce_errstr, &err2);
		DEBUG(0,
		      ("DCE purge login context failed for server instance %d: %s\n",
		       getpid(), dce_errstr));
	}
}
#endif

#ifdef KRB5_AUTH
/*******************************************************************
check on Kerberos authentication
********************************************************************/
static BOOL krb5_auth(char *user, char *password)
{
	krb5_data tgtname = {
		0,
		KRB5_TGS_NAME_SIZE,
		KRB5_TGS_NAME
	};
	krb5_context kcontext;
	krb5_principal kprinc;
	krb5_principal server;
	krb5_creds kcreds;
	int options = 0;
	krb5_address **addrs = (krb5_address **) 0;
	krb5_preauthtype *preauth = NULL;
	krb5_keytab keytab = NULL;
	krb5_timestamp now;
	krb5_ccache ccache = NULL;
	int retval;
	char *name;

	if (retval = krb5_init_context(&kcontext))
	{
		return (False);
	}

	if (retval = krb5_timeofday(kcontext, &now))
	{
		return (False);
	}

	if (retval = krb5_cc_default(kcontext, &ccache))
	{
		return (False);
	}

	if (retval = krb5_parse_name(kcontext, user, &kprinc))
	{
		return (False);
	}

	ZERO_STRUCT(kcreds);

	kcreds.client = kprinc;

	if ((retval = krb5_build_principal_ext(kcontext, &server,
					       krb5_princ_realm(kcontext,
								kprinc)->length,
					       krb5_princ_realm(kcontext,
								kprinc)->data,
					       tgtname.length, tgtname.data,
					       krb5_princ_realm(kcontext,
								kprinc)->length,
					       krb5_princ_realm(kcontext,
								kprinc)->data,
					       0)))
	{
		return (False);
	}

	kcreds.server = server;

	retval = krb5_get_in_tkt_with_password(kcontext,
					       options,
					       addrs,
					       NULL,
					       preauth,
					       password, 0, &kcreds, 0);

	if (retval)
	{
		return (False);
	}

	return (True);
}
#endif /* KRB5_AUTH */

#ifdef KRB4_AUTH
#include <krb.h>

/*******************************************************************
check on Kerberos authentication
********************************************************************/
static BOOL krb4_auth(char *user, char *password)
{
	char realm[REALM_SZ];
	char tkfile[MAXPATHLEN];

	if (krb_get_lrealm(realm, 1) != KSUCCESS)
	{
		(void)safe_strcpy(realm, KRB_REALM, sizeof(realm) - 1);
	}

	(void)slprintf(tkfile, sizeof(tkfile) - 1, "/tmp/samba_tkt_%d",
		       (int)getpid());

	krb_set_tkt_string(tkfile);
	if (krb_verify_user(user, "", realm, password, 0, "rmcd") == KSUCCESS)
	{
		unlink(tkfile);
		return 1;
	}
	unlink(tkfile);
	return 0;
}
#endif /* KRB4_AUTH */

#ifdef LINUX_BIGCRYPT
/****************************************************************************
an enhanced crypt for Linux to handle password longer than 8 characters
****************************************************************************/
static int linux_bigcrypt(char *password, char *salt1, char *crypted)
{
#define LINUX_PASSWORD_SEG_CHARS 8
	char salt[3];
	int i;

	StrnCpy(salt, salt1, 2);
	crypted += 2;

	for (i = strlen(password); i > 0; i -= LINUX_PASSWORD_SEG_CHARS)
	{
		char *p = crypt(password, salt) + 2;
		if (p == NULL)
		{
			DEBUG(1, ("linux_bigcrypt: crypt returned NULL!\n"));
			return 0;
		}
		if (strncmp(p, crypted, LINUX_PASSWORD_SEG_CHARS) != 0)
			return (0);
		password += LINUX_PASSWORD_SEG_CHARS;
		crypted += strlen(p);
	}

	return (1);
}
#endif

#ifdef OSF1_ENH_SEC
/****************************************************************************
an enhanced crypt for OSF1
****************************************************************************/
static char *osf1_bigcrypt(char *password, char *salt1)
{
	static char result[AUTH_MAX_PASSWD_LENGTH] = "";
	char *p1;
	char *p2 = password;
	char salt[3];
	int i;
	int parts = strlen(password) / AUTH_CLEARTEXT_SEG_CHARS;
	if (strlen(password) % AUTH_CLEARTEXT_SEG_CHARS)
	{
		parts++;
	}

	StrnCpy(salt, salt1, 2);
	StrnCpy(result, salt1, 2);

	for (i = 0; i < parts; i++)
	{
		p1 = crypt(p2, salt);
		if (p1 == NULL)
		{
			DEBUG(1, ("osf_bigcrypt: crypt returned NULL!\n"));
			return 0;
		}
		strncat(result, p1 + 2,
			AUTH_MAX_PASSWD_LENGTH - strlen(p1 + 2) - 1);
		StrnCpy(salt, &result[2 + i * AUTH_CIPHERTEXT_SEG_CHARS], 2);
		p2 += AUTH_CLEARTEXT_SEG_CHARS;
	}

	return (result);
}
#endif


/****************************************************************************
apply a function to upper/lower case combinations
of a string and return true if one of them returns true.
try all combinations with N uppercase letters.
offset is the first char to try and change (start with 0)
it assumes the string starts lowercased
****************************************************************************/
static BOOL string_combinations2(char *s, int offset, BOOL (*fn) (char *),
				 int N)
{
	int len = strlen(s);
	int i;

#ifdef PASSWORD_LENGTH
	len = MIN(len, PASSWORD_LENGTH);
#endif

	if (N <= 0 || offset >= len)
	{
		return (fn(s));
	}

	for (i = offset; i < (len - (N - 1)); i++)
	{
		char c = s[i];
		if (!islower(c))
			continue;
		s[i] = toupper(c);
		if (string_combinations2(s, i + 1, fn, N - 1))
			return (True);
		s[i] = c;
	}
	return (False);
}

/****************************************************************************
apply a function to upper/lower case combinations
of a string and return true if one of them returns true.
try all combinations with up to N uppercase letters.
offset is the first char to try and change (start with 0)
it assumes the string starts lowercased
****************************************************************************/
static BOOL string_combinations(char *s, BOOL (*fn) (char *), int N)
{
	int n;
	for (n = 1; n <= N; n++)
		if (string_combinations2(s, 0, fn, n))
			return (True);
	return (False);
}


/****************************************************************************
core of password checking routine
****************************************************************************/
static BOOL password_check(char *password)
{

#ifdef HAVE_PAM
	/* This falls through if the password check fails
	   - if HAVE_CRYPT is not defined this causes an error msg
	   saying Warning - no crypt available
	   - if HAVE_CRYPT is defined this is a potential security hole
	   as it may authenticate via the crypt call when PAM
	   settings say it should fail.
	   if (pam_auth(user,password)) return(True);
	   Hence we make a direct return to avoid a second chance!!!
	 */
	return (pam_auth(this_user, password));
#endif

#ifdef WITH_AFS
	if (afs_auth(this_user, password))
		return (True);
#endif

#ifdef WITH_DFS
	if (dfs_auth(this_user, password))
		return (True);
#endif

#ifdef KRB5_AUTH
	if (krb5_auth(this_user, password))
		return (True);
#endif

#ifdef KRB4_AUTH
	if (krb4_auth(this_user, password))
		return (True);
#endif

#ifdef OSF1_ENH_SEC
	{
		BOOL ret = (strcmp(osf1_bigcrypt(password, this_salt),
				   this_crypted) == 0);
		if (!ret)
		{
			char *p1 = (char *)crypt(password, this_salt);
			DEBUG(2,
			      ("OSF1_ENH_SEC failed. Trying normal crypt.\n"));
			if (p1 == NULL)
			{
				DEBUG(1,
				      ("password_check: crypt returned NULL!\n"));
				return 0;
			}
			ret = (strcmp(p1, this_crypted) == 0);
		}
		return ret;
	}
#endif

#ifdef ULTRIX_AUTH
	{
		char *p1 = (char *)crypt16(password, this_salt);
		if (p1 == NULL)
		{
			DEBUG(1,
			      ("password_check: crypt16 returned NULL!\n"));
			return 0;
		}
		return (strcmp(p1, this_crypted) == 0);
	}
#endif

#ifdef LINUX_BIGCRYPT
	return (linux_bigcrypt(password, this_salt, this_crypted));
#endif

#ifdef HAVE_BIGCRYPT
	{
		char *p1 = (char *)bigcrypt(password, this_salt);
		if (p1 == NULL)
		{
			DEBUG(1,
			      ("password_check: bigcrypt returned NULL!\n"));
			return 0;
		}
		return (strcmp(p1, this_crypted) == 0);
	}
#endif

#ifndef HAVE_CRYPT
	DEBUG(1, ("Warning - no crypt available\n"));
	return (False);
#else
	{
		char *p1 = (char *)crypt(password, this_salt);
		if (p1 == NULL)
		{
			DEBUG(1, ("password_check: crypt returned NULL!\n"));
			return 0;
		}
		return (strcmp(p1, this_crypted) == 0);
	}
#endif
}



/****************************************************************************
check if a username/password is OK
the function pointer fn() points to a function to call when a successful
match is found and is used to update the encrypted password file 
return True on correct match, False otherwise
****************************************************************************/
BOOL pass_check(const char *_user, const char *_password,
		int pwlen, const struct passwd *pwd,
		BOOL (*fn) (const char *, const char *))
{
	pstring pass2;
	int level = lp_passwordlevel();
	const struct passwd *pass;
	fstring password;
	fstring user;

	fstrcpy(user, _user);

#if DEBUG_PASSWORD
	DEBUG(100, ("checking user=[%s] pass=", user));
	dump_data(100, password, strlen(password));
#endif

	if (!_password)
	{
		return (False);
	}

	pwlen = MIN(sizeof(password) - 1, pwlen);
	memset(password, 0, sizeof(password));
	memcpy(password, _password, pwlen);

	if (((!*password) || (!pwlen)) && !lp_null_passwords())
	{
		return (False);
	}

	if (pwd != NULL && _user == NULL)
	{
		pass = (const struct passwd *)pwd;
		fstrcpy(user, pass->pw_name);
	}
	else
	{
		pass = Get_Pwnam(user, True);
	}


	DEBUG(4, ("Checking password for user %s (l=%d)\n", user, pwlen));

	if (pass == NULL)
	{
		DEBUG(3, ("Couldn't find user %s\n", user));
		return (False);
	}

	/* extract relevant info */
	fstrcpy(this_user, pass->pw_name);
	fstrcpy(this_salt, pass->pw_passwd);
	/* crypt on some platforms (HPUX in particular)
	   won't work with more than 2 salt characters. */
	this_salt[2] = 0;

	fstrcpy(this_crypted, pass->pw_passwd);

	if (!*this_crypted)
	{
		if (!lp_null_passwords())
		{
			DEBUG(2, ("Disallowing %s with null password\n",
				  this_user));
			return (False);
		}
		if (!*password)
		{
			DEBUG(3,
			      ("Allowing access to %s with null password\n",
			       this_user));
			return (True);
		}
	}

	/* try it as it came to us */
	if (password_check(password))
	{
		if (fn)
			fn(user, password);
		return (True);
	}

	/* if the password was given to us with mixed case then we don't
	   need to proceed as we know it hasn't been case modified by the
	   client */
	if (strhasupper(password) && strhaslower(password))
	{
		return (False);
	}

	/* make a copy of it */
	StrnCpy(pass2, password, sizeof(pstring) - 1);

	/* try all lowercase */
	strlower(password);
	if (password_check(password))
	{
		if (fn)
			fn(user, password);
		return (True);
	}

	/* give up? */
	if (level < 1)
	{

		/* restore it */
		fstrcpy(password, pass2);

		return (False);
	}

	/* last chance - all combinations of up to level chars upper! */
	strlower(password);

	if (string_combinations(password, password_check, level))
	{
		if (fn)
			fn(user, password);
		return (True);
	}

	/* restore it */
	fstrcpy(password, pass2);

	return (False);
}
