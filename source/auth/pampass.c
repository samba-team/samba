/* 
   Unix SMB/Netbios implementation.
   Version 2.2.
   PAM Password checking
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) John H Terpsta 1999-2001
   Copyright (C) Andrew Bartlett 2001
   
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

/*
 * This module provides PAM based functions for validation of
 * username/password pairs, account managment, session and access control.
 * Note: SMB password checking is done in smbpass.c
 */

#include "includes.h"

extern int DEBUGLEVEL;

#ifdef WITH_PAM

/*******************************************************************
 * Handle PAM authentication 
 * 	- Access, Authentication, Session, Password
 *   Note: See PAM Documentation and refer to local system PAM implementation
 *   which determines what actions/limitations/allowances become affected.
 *********************************************************************/

#include <security/pam_appl.h>

/*
 * Static variables used to communicate between the conversation function
 * and the server_login function
 */

static char *PAM_username;
static char *PAM_password;

/*
 *  Macros to help make life easy
 */
#define COPY_STRING(s) (s) ? strdup(s) : NULL

/*
 * PAM error handler.
 */
static BOOL pam_error_handler(pam_handle_t *pamh, int pam_error, char *msg, int dbglvl)
{

	if( pam_error != PAM_SUCCESS) {
		DEBUG(dbglvl, ("PAM: %s : %s\n", msg, pam_strerror(pamh, pam_error)));
		return False;
	}
	return True;
}

/*
 * PAM conversation function
 * Here we assume (for now, at least) that echo on means login name, and
 * echo off means password.
 */

static int PAM_conv(int num_msg,
		    const struct pam_message **msg,
		    struct pam_response **resp,
		    void *appdata_ptr)
{
	int replies = 0;
	struct pam_response *reply = NULL;

	reply = malloc(sizeof(struct pam_response) * num_msg);
	if (!reply)
		return PAM_CONV_ERR;

	for (replies = 0; replies < num_msg; replies++) {
		switch (msg[replies]->msg_style) {
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

/* 
 * PAM Closing out cleanup handler
 */
static BOOL proc_pam_end(pam_handle_t *pamh)
{
	int pam_error;
       
	if( pamh != NULL ) {
		pam_error = pam_end(pamh, 0);
		if(pam_error_handler(pamh, pam_error, "End Cleanup Failed", 2) == True) {
			DEBUG(4, ("PAM: PAM_END OK.\n"));
			return True;
		}
	}
	DEBUG(2,("PAM: not initialised"));
	return False;
}

/*
 * Start PAM authentication for specified account
 */
static BOOL proc_pam_start(pam_handle_t **pamh, char *user, char *rhost)
{
	int pam_error;

	DEBUG(4,("PAM: Init user: %s\n", user));

	pam_error = pam_start("samba", user, &PAM_conversation, pamh);
	if( !pam_error_handler(*pamh, pam_error, "Init Failed", 0)) {
		proc_pam_end(*pamh);
		return False;
	}

	if (rhost == NULL) {
		rhost = client_name();
		if (strequal(rhost,"UNKNOWN"))
			rhost = client_addr();
	}

#ifdef PAM_RHOST
	DEBUG(4,("PAM: setting rhost to: %s\n", rhost));
	pam_error = pam_set_item(*pamh, PAM_RHOST, rhost);
	if(!pam_error_handler(*pamh, pam_error, "set rhost failed", 0)) {
		proc_pam_end(*pamh);
		return False;
	}
#endif
#ifdef PAM_TTY
	DEBUG(4,("PAM: setting tty\n"));
	pam_error = pam_set_item(*pamh, PAM_TTY, "samba");
	if (!pam_error_handler(*pamh, pam_error, "set tty failed", 0)) {
		proc_pam_end(*pamh);
		return False;
	}
#endif
	DEBUG(4,("PAM: Init passed for user: %s\n", user));
	return True;
}

/*
 * PAM Authentication Handler
 */
static BOOL pam_auth(pam_handle_t *pamh, char *user, char *password)
{
	int pam_error;

	/*
	 * To enable debugging set in /etc/pam.d/samba:
	 *	auth required /lib/security/pam_pwdb.so nullok shadow audit
	 */
	
	DEBUG(4,("PAM: Authenticate User: %s\n", user));
	pam_error = pam_authenticate(pamh, PAM_SILENT); /* Can we authenticate user? */
	switch( pam_error ){
		case PAM_AUTH_ERR:
			DEBUG(2, ("PAM: Athentication Error\n"));
			break;
		case PAM_CRED_INSUFFICIENT:
			DEBUG(2, ("PAM: Insufficient Credentials\n"));
			break;
		case PAM_AUTHINFO_UNAVAIL:
			DEBUG(2, ("PAM: Authentication Information Unavailable\n"));
			break;
		case PAM_USER_UNKNOWN:
			DEBUG(2, ("PAM: Username NOT known to Authentication system\n"));
			break;
		case PAM_MAXTRIES:
			DEBUG(2, ("PAM: One or more authentication modules reports user limit exceeeded\n"));
			break;
		case PAM_ABORT:
			DEBUG(0, ("PAM: One or more PAM modules failed to load\n"));
			break;
	        case PAM_SUCCESS:
			DEBUG(4, ("PAM: User %s Authenticated OK\n", user));
		        break;
		default:
			DEBUG(0, ("PAM: UNKNOWN ERROR while authenticating user %s\n", user));
	}
	if(!pam_error_handler(pamh, pam_error, "Authentication Failure", 2)) {
		proc_pam_end(pamh);
		return False;
	}
	/* If this point is reached, the user has been authenticated. */
	return (True);
}

/* 
 * PAM Account Handler
 */
static BOOL pam_account(pam_handle_t *pamh, char * user, char * password, BOOL pam_auth)
{
	int pam_error;

	DEBUG(4,("PAM: Account Management for User: %s\n", user));
	pam_error = pam_acct_mgmt(pamh, PAM_SILENT); /* Is user account enabled? */
	switch( pam_error ) {
		case PAM_AUTHTOK_EXPIRED:
			DEBUG(2, ("PAM: User is valid but password is expired\n"));
			break;
		case PAM_ACCT_EXPIRED:
			DEBUG(2, ("PAM: User no longer permitted to access system\n"));
			break;
		case PAM_AUTH_ERR:
			DEBUG(2, ("PAM: There was an authentication error\n"));
			break;
		case PAM_PERM_DENIED:
			DEBUG(0, ("PAM: User is NOT permitted to access system at this time\n"));
			break;
		case PAM_USER_UNKNOWN:
			DEBUG(0, ("PAM: User \"%s\" is NOT known to account management\n", user));
			break;
	        case PAM_SUCCESS:
			DEBUG(4, ("PAM: Account OK for User: %s\n", user));
		        break;
		default:
			DEBUG(0, ("PAM: UNKNOWN ERROR for User: %s\n", user));
	}
	if(!pam_error_handler(pamh, pam_error, "Account Check Failed", 2)) {
		proc_pam_end(pamh);
		return False;
	}

	/* Skip the pam_setcred() call if we didn't use pam_authenticate()
	   for authentication -- it's an error to call pam_setcred without
	   calling pam_authenticate first */
	if (!pam_auth) {
		DEBUG(4, ("PAM: Skipping setcred for user: %s (using encrypted passwords)\n", user));
		return True;
	}

	/*
	 * This will allow samba to aquire a kerberos token. And, when
	 * exporting an AFS cell, be able to /write/ to this cell.
	 */

	DEBUG(4,("PAM: Account Management SetCredentials for User: %s\n", user));
	pam_error = pam_setcred(pamh, (PAM_ESTABLISH_CRED|PAM_SILENT)); 
	switch( pam_error ) {
		case PAM_CRED_UNAVAIL:
			DEBUG(0, ("PAM: Credentials not found for user:%s", user ));
			break;
		case PAM_CRED_EXPIRED:
			DEBUG(0, ("PAM: Credentials for user: \"%s\" EXPIRED!", user ));
			break;
		case PAM_USER_UNKNOWN:
			DEBUG(0, ("PAM: User: \"%s\" is NOT known so can not set credentials!", user ));
			break;
		case PAM_CRED_ERR:
			DEBUG(0, ("PAM: Unknown setcredentials error - unable to set credentials for %s", user ));
			break;
	        case PAM_SUCCESS:
			DEBUG(4, ("PAM: SetCredentials OK for User: %s\n", user));
		        break;
		default:
			DEBUG(0, ("PAM: Error Condition Unknown in pam_setcred function call!"));
	}
	if(!pam_error_handler(pamh, pam_error, "Set Credential Failure", 2)) {
		proc_pam_end(pamh);
		return False;
	}
	
	/* If this point is reached, the user has been authenticated. */
	return (True);
}


/*
 * PAM Internal Session Handler
 */
static BOOL proc_pam_session(pam_handle_t *pamh, char *user, char *tty, BOOL flag)
{
	int pam_error;

	PAM_password = NULL;
	PAM_username = user;

#ifdef PAM_TTY
	DEBUG(4,("PAM: tty set to: %s\n", tty));
	pam_error = pam_set_item(pamh, PAM_TTY, tty);
	if (!pam_error_handler(pamh, pam_error, "set tty failed", 0)) {
		proc_pam_end(pamh);
		return False;
	}
#endif

	if (flag) {
		pam_error = pam_open_session(pamh, PAM_SILENT);
		if (!pam_error_handler(pamh, pam_error, "session setup failed", 0)) {
			proc_pam_end(pamh);
			return False;
		}
	} else {
		pam_error = pam_close_session(pamh, PAM_SILENT);
		if (!pam_error_handler(pamh, pam_error, "session close failed", 0)) {
			proc_pam_end(pamh);
			return False;
		}
	}
	return (True);
}

/*
 * PAM Externally accessible Session handler
 */
BOOL pam_session(BOOL flag, const char *in_user, char *tty, char *rhost)
{
	pam_handle_t *pamh = NULL;
	char * user;

	user = malloc(strlen(in_user)+1);
	if ( user == NULL ) {
		DEBUG(0, ("PAM: PAM_session Malloc Failed!\n"));
		return False;
	}

	/* This is freed by PAM */
	StrnCpy(user, in_user, strlen(in_user)+1);

	if (!proc_pam_start(&pamh, user, rhost)) {
		proc_pam_end(pamh);
		return False;
	}

	if (proc_pam_session(pamh, user, tty, flag)) {
		return proc_pam_end(pamh);
	} else {
		proc_pam_end(pamh);
		return False;
	}
}

/*
 * PAM Externally accessible Account handler
 */
BOOL pam_accountcheck(char * user)
{
	pam_handle_t *pamh = NULL;

	PAM_username = user;
	PAM_password = NULL;

	if( proc_pam_start(&pamh, user, NULL)) {
		if ( pam_account(pamh, user, NULL, False)) {
			return( proc_pam_end(pamh));
		}
	}
	DEBUG(0, ("PAM: Account Validation Failed - Rejecting User!\n"));
	return( False );
}

/*
 * PAM Password Validation Suite
 */
BOOL pam_passcheck(char * user, char * password)
{
	pam_handle_t *pamh = NULL;

	PAM_username = user;
	PAM_password = password;

	if( proc_pam_start(&pamh, user, NULL)) {
		if ( pam_auth(pamh, user, password)) {
			if ( pam_account(pamh, user, password, True)) {
				return( proc_pam_end(pamh));
			}
		}
	}
	DEBUG(0, ("PAM: System Validation Failed - Rejecting User!\n"));
	return( False );
}

#else

/* If PAM not used, no PAM restrictions on accounts. */
 BOOL pam_accountcheck(char * user)
{
	return True;
}

#endif /* WITH_PAM */
