/* 
   Unix SMB/Netbios implementation.
   Version 2.2.
   PAM Password checking
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) John H Terpsta 1999-2001
   Copyright (C) Andrew Barton 2001
   
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
 * Macro converted to a function to simplyify this thing
 */
static BOOL pam_error_handler(pam_handle_t *pamh, int pam_error, char *msg, int dbglvl)
{

	int retval;

       	if( pam_error != PAM_SUCCESS)
	{
		DEBUG(dbglvl, ("PAM %s: %s\n", pam_strerror(pamh, pam_error)));
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

static BOOL proc_pam_end(pam_handle_t *pamh)
{
       int pam_error;
       
       if( pamh != NULL )
       {
		pam_error = pam_end(pamh, 0);
		if(pam_error_handler(pamh, pam_error, "End Cleanup Failed", 2) == True) {
    			return True;
		}
       }
       DEBUG(2,("PAM not initialised"));
       return False;
}


static BOOL pam_auth(char *user, char *password)
{
	pam_handle_t *pamh;
	int pam_error;

	/*
	 * Now use PAM to do authentication.  Bail out if there are any
	 * errors.
	 */

	PAM_password = password;
	PAM_username = user;
        DEBUG(4,("PAM Start for User: %s\n", user));
	pam_error = pam_start("samba", user, &PAM_conversation, &pamh);
	if(!pam_error_handler(pamh, pam_error, "start failure", 2)) {
		proc_pam_end(pamh);
		return False;
	}

	/*
	 * To enable debugging set in /etc/pam.d/samba:
	 *	auth required /lib/security/pam_pwdb.so nullok shadow audit
	 */
	
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
		default:
			DEBUG(4, ("PAM: User %s Authenticated OK\n", user));
	}
	if(!pam_error_handler(pamh, pam_error, "Authentication Failure", 2)) {
		proc_pam_end(pamh);
		return False;
	}

	/* 
	 * Now do account management control and validation
	 */
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
			DEBUG(2, ("PAM: User \"%s\" is NOT known to account management\n", user));
			break;
		default:
			DEBUG(4, ("PAM: Account OK for User: %s\n", user));
	}
	if(!pam_error_handler(pamh, pam_error, "Account Check Failed", 2)) {
		proc_pam_end(pamh);
		return False;
	}

	/*
	 * This will allow samba to aquire a kerberos token. And, when
	 * exporting an AFS cell, be able to /write/ to this cell.
	 */

	pam_error = pam_setcred(pamh, (PAM_ESTABLISH_CRED|PAM_SILENT)); 
	if(!pam_error_handler(pamh, pam_error, "Set Credential Failure", 2)) {
		proc_pam_end(pamh);
		return False;
	}
	
	if( !proc_pam_end(pamh))
		return False;

	/* If this point is reached, the user has been authenticated. */
	DEBUG(4, ("PAM: pam_authentication passed for User: %s\n", user));
	return (True);
}

#if NOTBLOCKEDOUT
/* Start PAM authentication for specified account */
static BOOL proc_pam_start(pam_handle_t **pamh, char *user)
{
       int pam_error;
       char * rhost;

       DEBUG(4,("PAM Init for user: %s\n", user));

       pam_error = pam_start("samba", user, &PAM_conversation, pamh);
       if( !pam_error_handler(*pamh, pam_error, "Init Failed", 0)) {
	       proc_pam_end(*pamh);
               return False;
       }

       rhost = client_name();
       if (strcmp(rhost,"UNKNOWN") == 0)
               rhost = client_addr();

#ifdef PAM_RHOST
       DEBUG(4,("PAM setting rhost to: %s\n", rhost));
       pam_error = pam_set_item(*pamh, PAM_RHOST, rhost);
       if(!pam_error_handler(*pamh, pam_error, "set rhost failed", 0)) {
	       proc_pam_end(*pamh);
               return False;
       }
#endif

#if defined(PAM_TTY_KLUDGE) && defined(PAM_TTY)
       pam_error = pam_set_item(*pamh, PAM_TTY, "samba");
       if (!pam_error_handler(*pamh, pam_error, "set tty failed", 0)) {
	       proc_pam_end(*pamh);
               return False;
       }
#endif

       return True;
}

static BOOL pam_session(pam_handle_t *pamh, char *user, char *tty, BOOL instance)
{
       int pam_error;

       PAM_password = NULL;
       PAM_username = user;

#ifdef PAM_TTY
       DEBUG(4,("PAM tty set to: %s\"\n", tty));
       pam_error = pam_set_item(pamh, PAM_TTY, tty);
       if (!pam_error_handler(pamh, pam_error, "set tty failed", 0)) {
	       proc_pam_end(pamh);
               return False;
       }
#endif

       if (instance) {
         pam_error = pam_open_session(pamh, PAM_SILENT);
         if (!pam_error_handler(pamh, pam_error, "session setup failed", 0)) {
	       proc_pam_end(pamh);
               return False;
         }
       }
       else
       {
         pam_error = pam_close_session(pamh, PAM_SILENT);
         if (!pam_error_handler(pamh, pam_error, "session close failed", 0)) {
	       proc_pam_end(pamh);
               return False;
         }
       }
      return (True);
}

static BOOL pam_account(pam_handle_t *pamh, char *user)
{
       int pam_error;

       PAM_password = NULL;
       PAM_username = user;

       DEBUG(4,("PAM starting account management for user: %s \n", user));

       pam_error = pam_acct_mgmt(pamh, PAM_SILENT);
       if (!pam_error_handler(pamh, pam_error, "PAM set account management failed", 0)) {
	   proc_pam_end(pamh);
           return False;
       } else {
           DEBUG(4,("PAM account management passed\n"));
       }

       /*
        * This will allow samba to aquire a kerberos token. And, when
        * exporting an AFS cell, be able to /write/ to this cell.
        */
       pam_error = pam_setcred(pamh, (PAM_ESTABLISH_CRED));
       if (!pam_error_handler(pamh, pam_error, "set credentials failed\n", 0)) {
	   proc_pam_end(pamh);
           return False;
       }

       /* If this point is reached, the user has been authenticated. */
       return (True);
}
static BOOL account_pam(char *user)
{
         /*
	  * Check the account with the PAM account module:
          *  - This means that accounts can be disabled
          *    and or expired with avoidance of samba then just
          *    bypassing the situation.
          */

         pam_handle_t *pamh = NULL;
         char * PAMuser;

         PAMuser = malloc(strlen(user)+1);
         /* This is freed by PAM */
         strncpy(PAMuser, user, strlen(user)+1);

         if (proc_pam_start(&pamh, PAMuser))
	 {
           if (pam_account(pamh, PAMuser))
	   {
             return proc_pam_end(pamh);
	   }
	 }
         proc_pam_end(pamh);
         return False;
}

BOOL PAM_session(BOOL instance, const connection_struct *conn, char *tty)
{
	pam_handle_t *pamh=NULL;
	char * user;

	user = malloc(strlen(conn->user)+1);

	/* This is freed by PAM */
	strncpy(user, conn->user, strlen(conn->user)+1);

	if (!proc_pam_start(&pamh, user))
	{
	  proc_pam_end(pamh);
	  return False;
	}

	if (pam_session(pamh, user, tty, instance))
	{
	  return proc_pam_end(pamh);
	}
	else
	{
	  proc_pam_end(pamh);
	  return False;
	}
}

BOOL pam_passcheck(char * user, char * password)
{
	pam_handle_t *pamh = NULL;

	PAM_username = user;
	PAM_password = password;

	if( proc_pam_start(&pamh, user))
	{
		if( pam_auth(user, password))
		{
			if( account_pam(user))
			{
				return( proc_pam_end(pamh));
			}
		}	
	}
	proc_pam_end(pamh);
	return( False );
}
#endif /* NOTBLOCKEDOUT */

BOOL pam_passcheck( char * user, char * password )
{
	return( pam_auth( user, password ));
	
}
#else

 /* Do *NOT* make this function static. Doing so breaks the compile on gcc */

 void pampass_dummy_function( void ) { } /*This stops compiler complaints */

#endif /* WITH_PAM */
