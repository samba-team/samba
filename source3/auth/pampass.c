/* 
   Unix SMB/Netbios implementation.
   Version 2.2.
   PAM Password checking
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) John H Terpsta 1999-2001
   Copyright (C) Andrew Bartlett 2001
   Copyright (C) Jeremy Allison 2001
   
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
 * Structure used to communicate between the conversation function
 * and the server_login/change password functions.
 */

struct smb_pam_userdata {
	char *PAM_username;
	char *PAM_password;
	char *PAM_newpassword;
};

typedef int (*smb_pam_conv_fn)(int, const struct pam_message **, struct pam_response **, void *appdata_ptr);

/*
 *  Macros to help make life easy
 */
#define COPY_STRING(s) (s) ? strdup(s) : NULL

/*******************************************************************
 PAM error handler.
 *********************************************************************/

static BOOL smb_pam_error_handler(pam_handle_t *pamh, int pam_error, char *msg, int dbglvl)
{

	if( pam_error != PAM_SUCCESS) {
		DEBUG(dbglvl, ("smb_pam_error_handler: PAM: %s : %s\n",
				msg, pam_strerror(pamh, pam_error)));
		return False;
	}
	return True;
}

/*******************************************************************
 This function is a sanity check, to make sure that we NEVER report
 failure as sucess.
*********************************************************************/

static BOOL smb_pam_nt_status_error_handler(pam_handle_t *pamh, int pam_error,
							char *msg, int dbglvl, uint32 *nt_status)
{
	if (smb_pam_error_handler(pamh, pam_error, msg, dbglvl))
		return True;

	if (*nt_status == NT_STATUS_NOPROBLEMO) {
		/* Complain LOUDLY */
		DEBUG(0, ("smb_pam_nt_status_error_handler: PAM: BUG: PAM and NT_STATUS \
error MISMATCH, forcing to NT_STATUS_LOGON_FAILURE"));
		*nt_status = NT_STATUS_LOGON_FAILURE;
	}
	return False;
}

/*
 * PAM conversation function
 * Here we assume (for now, at least) that echo on means login name, and
 * echo off means password.
 */

static int smb_pam_conv(int num_msg,
		    const struct pam_message **msg,
		    struct pam_response **resp,
		    void *appdata_ptr)
{
	int replies = 0;
	struct pam_response *reply = NULL;
	struct smb_pam_userdata *udp = (struct smb_pam_userdata *)appdata_ptr;

	*resp = NULL;

	reply = malloc(sizeof(struct pam_response) * num_msg);
	if (!reply)
		return PAM_CONV_ERR;

	for (replies = 0; replies < num_msg; replies++) {
		switch (msg[replies]->msg_style) {
			case PAM_PROMPT_ECHO_ON:
				reply[replies].resp_retcode = PAM_SUCCESS;
				reply[replies].resp = COPY_STRING(udp->PAM_username);
				/* PAM frees resp */
				break;

			case PAM_PROMPT_ECHO_OFF:
				reply[replies].resp_retcode = PAM_SUCCESS;
				reply[replies].resp = COPY_STRING(udp->PAM_password);
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

/*
 * PAM password change conversation function
 * Here we assume (for now, at least) that echo on means login name, and
 * echo off means password.
 */

static int smb_pam_passchange_conv(int num_msg,
				const struct pam_message **msg,
				struct pam_response **resp,
				void *appdata_ptr)
{
	int replies = 0;
	struct pam_response *reply = NULL;
	fstring currentpw_prompt;
	fstring newpw_prompt;
	fstring repeatpw_prompt;
	char *p = lp_passwd_chat();
	struct smb_pam_userdata *udp = (struct smb_pam_userdata *)appdata_ptr;

	/* Get the prompts... */

	if (!next_token(&p, currentpw_prompt, NULL, sizeof(fstring)))
		return PAM_CONV_ERR;
	if (!next_token(&p, newpw_prompt, NULL, sizeof(fstring)))
		return PAM_CONV_ERR;
	if (!next_token(&p, repeatpw_prompt, NULL, sizeof(fstring)))
		return PAM_CONV_ERR;

	*resp = NULL;

	reply = malloc(sizeof(struct pam_response) * num_msg);
	if (!reply)
		return PAM_CONV_ERR;

	for (replies = 0; replies < num_msg; replies++) {
		switch (msg[replies]->msg_style) {
		case PAM_PROMPT_ECHO_ON:
			reply[replies].resp_retcode = PAM_SUCCESS;
			reply[replies].resp = COPY_STRING(udp->PAM_username);
			/* PAM frees resp */
			break;

		case PAM_PROMPT_ECHO_OFF:
			reply[replies].resp_retcode = PAM_SUCCESS;
			DEBUG(10,("smb_pam_passchange_conv: PAM Replied: %s\n", msg[replies]->msg));
			if (strncmp(currentpw_prompt, msg[replies]->msg, strlen(currentpw_prompt)) == 0) {
				reply[replies].resp = COPY_STRING(udp->PAM_password);
			} else if (strncmp(newpw_prompt, msg[replies]->msg, strlen(newpw_prompt)) == 0) {
				reply[replies].resp = COPY_STRING(udp->PAM_newpassword);
			} else if (strncmp(repeatpw_prompt, msg[replies]->msg, strlen(repeatpw_prompt)) == 0) {
				reply[replies].resp = COPY_STRING(udp->PAM_newpassword);
			} else {
				DEBUG(3,("smb_pam_passchange_conv: Could not find reply for PAM prompt: %s\n",msg[replies]->msg));
				DEBUG(5,("smb_pam_passchange_conv: Prompts available:\n CurrentPW: \"%s\"\n NewPW: \"%s\"\n \
RepeatPW: \"%s\"\n",currentpw_prompt,newpw_prompt,repeatpw_prompt));
			}
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
			reply = NULL;
			return PAM_CONV_ERR;
		}
	}

	if (reply)
		*resp = reply;
	return PAM_SUCCESS;
}

/***************************************************************************
 Free up a malloced pam_conv struct.
****************************************************************************/

static void smb_free_pam_conv(struct pam_conv *pconv)
{
	if (pconv)
		safe_free(pconv->appdata_ptr);

	safe_free(pconv);
}

/***************************************************************************
 Allocate a pam_conv struct.
****************************************************************************/

static struct pam_conv *smb_setup_pam_conv(smb_pam_conv_fn smb_pam_conv_fnptr, char *user,
					char *passwd, char *newpass)
{
	struct pam_conv *pconv = (struct pam_conv *)malloc(sizeof(struct pam_conv));
	struct smb_pam_userdata *udp = (struct smb_pam_userdata *)malloc(sizeof(struct smb_pam_userdata));

	if (pconv == NULL || udp == NULL) {
		safe_free(pconv);
		safe_free(udp);
		return NULL;
	}

	udp->PAM_username = user;
	udp->PAM_password = passwd;
	udp->PAM_newpassword = newpass;

	pconv->conv = smb_pam_conv_fnptr;
	pconv->appdata_ptr = (void *)udp;
	return pconv;
}

/* 
 * PAM Closing out cleanup handler
 */

static BOOL smb_pam_end(pam_handle_t *pamh, struct pam_conv *smb_pam_conv_ptr)
{
	int pam_error;

	smb_free_pam_conv(smb_pam_conv_ptr);
       
	if( pamh != NULL ) {
		pam_error = pam_end(pamh, 0);
		if(smb_pam_error_handler(pamh, pam_error, "End Cleanup Failed", 2) == True) {
			DEBUG(4, ("smb_pam_end: PAM: PAM_END OK.\n"));
			return True;
		}
	}
	DEBUG(2,("smb_pam_end: PAM: not initialised"));
	return False;
}

/*
 * Start PAM authentication for specified account
 */

static BOOL smb_pam_start(pam_handle_t **pamh, char *user, char *rhost, struct pam_conv *pconv)
{
	int pam_error;

	*pamh = (pam_handle_t *)NULL;

	DEBUG(4,("smb_pam_start: PAM: Init user: %s\n", user));

	pam_error = pam_start("samba", user, pconv, pamh);
	if( !smb_pam_error_handler(*pamh, pam_error, "Init Failed", 0)) {
		*pamh = (pam_handle_t *)NULL;
		return False;
	}

	if (rhost == NULL) {
		rhost = client_name();
		if (strequal(rhost,"UNKNOWN"))
			rhost = client_addr();
	}

#ifdef PAM_RHOST
	DEBUG(4,("smb_pam_start: PAM: setting rhost to: %s\n", rhost));
	pam_error = pam_set_item(*pamh, PAM_RHOST, rhost);
	if(!smb_pam_error_handler(*pamh, pam_error, "set rhost failed", 0)) {
		smb_pam_end(*pamh, pconv);
		*pamh = (pam_handle_t *)NULL;
		return False;
	}
#endif
#ifdef PAM_TTY
	DEBUG(4,("smb_pam_start: PAM: setting tty\n"));
	pam_error = pam_set_item(*pamh, PAM_TTY, "samba");
	if (!smb_pam_error_handler(*pamh, pam_error, "set tty failed", 0)) {
		smb_pam_end(*pamh, pconv);
		*pamh = (pam_handle_t *)NULL;
		return False;
	}
#endif
	DEBUG(4,("smb_pam_start: PAM: Init passed for user: %s\n", user));
	return True;
}

/*
 * PAM Authentication Handler
 */
static uint32 smb_pam_auth(pam_handle_t *pamh, char *user)
{
	int pam_error;
	uint32 nt_status = NT_STATUS_LOGON_FAILURE;

	/*
	 * To enable debugging set in /etc/pam.d/samba:
	 *	auth required /lib/security/pam_pwdb.so nullok shadow audit
	 */
	
	DEBUG(4,("smb_pam_auth: PAM: Authenticate User: %s\n", user));
	pam_error = pam_authenticate(pamh, PAM_SILENT | lp_null_passwords() ? 0 : PAM_DISALLOW_NULL_AUTHTOK);
	switch( pam_error ){
		case PAM_AUTH_ERR:
			DEBUG(2, ("smb_pam_auth: PAM: Athentication Error for user %s\n", user));
			nt_status = NT_STATUS_WRONG_PASSWORD;
			break;
		case PAM_CRED_INSUFFICIENT:
			DEBUG(2, ("smb_pam_auth: PAM: Insufficient Credentials for user %s\n", user));
			nt_status = NT_STATUS_INSUFFICIENT_LOGON_INFO;
			break;
		case PAM_AUTHINFO_UNAVAIL:
			DEBUG(2, ("smb_pam_auth: PAM: Authentication Information Unavailable for user %s\n", user));
			nt_status = NT_STATUS_LOGON_FAILURE;
			break;
		case PAM_USER_UNKNOWN:
			DEBUG(2, ("smb_pam_auth: PAM: Username %s NOT known to Authentication system\n", user));
			nt_status = NT_STATUS_NO_SUCH_USER;
			break;
		case PAM_MAXTRIES:
			DEBUG(2, ("smb_pam_auth: PAM: One or more authentication modules reports user limit for user %s exceeeded\n", user));
			nt_status = NT_STATUS_REMOTE_SESSION_LIMIT;
			break;
		case PAM_ABORT:
			DEBUG(0, ("smb_pam_auth: PAM: One or more PAM modules failed to load for user %s\n", user));
			nt_status = NT_STATUS_LOGON_FAILURE;
			break;
		case PAM_SUCCESS:
			DEBUG(4, ("smb_pam_auth: PAM: User %s Authenticated OK\n", user));
			nt_status = NT_STATUS_NOPROBLEMO;
			break;
		default:
			DEBUG(0, ("smb_pam_auth: PAM: UNKNOWN ERROR while authenticating user %s\n", user));
			nt_status = NT_STATUS_LOGON_FAILURE;
			break;
	}

	smb_pam_nt_status_error_handler(pamh, pam_error, "Authentication Failure", 2, &nt_status);
	return nt_status;
}

/* 
 * PAM Account Handler
 */
static uint32 smb_pam_account(pam_handle_t *pamh, char * user)
{
	int pam_error;
	uint32 nt_status = NT_STATUS_ACCOUNT_DISABLED;

	DEBUG(4,("smb_pam_account: PAM: Account Management for User: %s\n", user));
	pam_error = pam_acct_mgmt(pamh, PAM_SILENT); /* Is user account enabled? */
	switch( pam_error ) {
		case PAM_AUTHTOK_EXPIRED:
			DEBUG(2, ("smb_pam_account: PAM: User %s is valid but password is expired\n", user));
			nt_status = NT_STATUS_PASSWORD_EXPIRED;
			break;
		case PAM_ACCT_EXPIRED:
			DEBUG(2, ("smb_pam_account: PAM: User %s no longer permitted to access system\n", user));
			nt_status = NT_STATUS_ACCOUNT_EXPIRED;
			break;
		case PAM_AUTH_ERR:
			DEBUG(2, ("smb_pam_account: PAM: There was an authentication error for user %s\n", user));
			nt_status = NT_STATUS_LOGON_FAILURE;
			break;
		case PAM_PERM_DENIED:
			DEBUG(0, ("smb_pam_account: PAM: User %s is NOT permitted to access system at this time\n", user));
			nt_status = NT_STATUS_ACCOUNT_RESTRICTION;
			break;
		case PAM_USER_UNKNOWN:
			DEBUG(0, ("smb_pam_account: PAM: User \"%s\" is NOT known to account management\n", user));
			nt_status = NT_STATUS_NO_SUCH_USER;
			break;
		case PAM_SUCCESS:
			DEBUG(4, ("smb_pam_account: PAM: Account OK for User: %s\n", user));
			nt_status = NT_STATUS_NOPROBLEMO;
			break;
		default:
			nt_status = NT_STATUS_ACCOUNT_DISABLED;
			DEBUG(0, ("smb_pam_account: PAM: UNKNOWN PAM ERROR (%d) during Account Management for User: %s\n", pam_error, user));
			break;
	}

	smb_pam_nt_status_error_handler(pamh, pam_error, "Account Check Failed", 2, &nt_status);
	return nt_status;
}

/*
 * PAM Credential Setting
 */

static uint32 smb_pam_setcred(pam_handle_t *pamh, char * user)
{
	int pam_error;
	uint32 nt_status = NT_STATUS_NO_TOKEN;

	/*
	 * This will allow samba to aquire a kerberos token. And, when
	 * exporting an AFS cell, be able to /write/ to this cell.
	 */

	DEBUG(4,("PAM: Account Management SetCredentials for User: %s\n", user));
	pam_error = pam_setcred(pamh, (PAM_ESTABLISH_CRED|PAM_SILENT)); 
	switch( pam_error ) {
		case PAM_CRED_UNAVAIL:
			DEBUG(0, ("smb_pam_setcred: PAM: Credentials not found for user:%s\n", user ));
			 nt_status = NT_STATUS_NO_TOKEN;
			break;
		case PAM_CRED_EXPIRED:
			DEBUG(0, ("smb_pam_setcred: PAM: Credentials for user: \"%s\" EXPIRED!\n", user ));
			nt_status = NT_STATUS_PASSWORD_EXPIRED;
			break;
		case PAM_USER_UNKNOWN:
			DEBUG(0, ("smb_pam_setcred: PAM: User: \"%s\" is NOT known so can not set credentials!\n", user ));
			nt_status = NT_STATUS_NO_SUCH_USER;
			break;
		case PAM_CRED_ERR:
			DEBUG(0, ("smb_pam_setcred: PAM: Unknown setcredentials error - unable to set credentials for %s\n", user ));
			nt_status = NT_STATUS_LOGON_FAILURE;
			break;
		case PAM_SUCCESS:
			DEBUG(4, ("smb_pam_setcred: PAM: SetCredentials OK for User: %s\n", user));
			nt_status = NT_STATUS_NOPROBLEMO;
			break;
		default:
			DEBUG(0, ("smb_pam_setcred: PAM: UNKNOWN PAM ERROR (%d) during SetCredentials for User: %s\n", pam_error, user));
			nt_status = NT_STATUS_NO_TOKEN;
			break;
	}

	smb_pam_nt_status_error_handler(pamh, pam_error, "Set Credential Failure", 2, &nt_status);
	return nt_status;
}

/*
 * PAM Internal Session Handler
 */
static BOOL smb_internal_pam_session(pam_handle_t *pamh, char *user, char *tty, BOOL flag)
{
	int pam_error;

#ifdef PAM_TTY
	DEBUG(4,("smb_internal_pam_session: PAM: tty set to: %s\n", tty));
	pam_error = pam_set_item(pamh, PAM_TTY, tty);
	if (!smb_pam_error_handler(pamh, pam_error, "set tty failed", 0))
		return False;
#endif

	if (flag) {
		pam_error = pam_open_session(pamh, PAM_SILENT);
		if (!smb_pam_error_handler(pamh, pam_error, "session setup failed", 0))
			return False;
	} else {
		pam_setcred(pamh, (PAM_DELETE_CRED|PAM_SILENT)); /* We don't care if this fails */
		pam_error = pam_close_session(pamh, PAM_SILENT); /* This will probably pick up the error anyway */
		if (!smb_pam_error_handler(pamh, pam_error, "session close failed", 0))
			return False;
	}
	return (True);
}

/*
 * Internal PAM Password Changer.
 */

static BOOL smb_pam_chauthtok(pam_handle_t *pamh, char * user)
{
	int pam_error;

	DEBUG(4,("smb_pam_chauthtok: PAM: Password Change for User: %s\n", user));

	pam_error = pam_chauthtok(pamh, PAM_SILENT); /* Change Password */

	switch( pam_error ) {
	case PAM_AUTHTOK_ERR:
		DEBUG(2, ("PAM: unable to obtain the new authentication token - is password to weak?\n"));
		break;
	case PAM_AUTHTOK_RECOVER_ERR:
		DEBUG(2, ("PAM: unable to obtain the old authentication token - was the old password wrong?.\n"));
		break;
	case PAM_AUTHTOK_LOCK_BUSY:
		DEBUG(2, ("PAM: unable to change the authentication token since it is currently locked.\n"));
		break;
	case PAM_AUTHTOK_DISABLE_AGING:
		DEBUG(2, ("PAM: Authentication token aging has been disabled.\n"));
		break;
	case PAM_PERM_DENIED:
		DEBUG(0, ("PAM: Permission denied.\n"));
		break;
	case PAM_TRY_AGAIN:
		DEBUG(0, ("PAM: Could not update all authentication token(s). No authentication tokens were updated.\n"));
		break;
	case PAM_USER_UNKNOWN:
		DEBUG(0, ("PAM: User not known to PAM\n"));
		break;
	case PAM_SUCCESS:
		DEBUG(4, ("PAM: Account OK for User: %s\n", user));
		break;
	default:
		DEBUG(0, ("PAM: UNKNOWN PAM ERROR (%d) for User: %s\n", pam_error, user));
	}
 
	if(!smb_pam_error_handler(pamh, pam_error, "Password Change Failed", 2)) {
		return False;
	}

	/* If this point is reached, the password has changed. */
	return True;
}

/*
 * PAM Externally accessible Session handler
 */

BOOL smb_pam_claim_session(char *user, char *tty, char *rhost)
{
	pam_handle_t *pamh = NULL;
	struct pam_conv *pconv = NULL;

	/* Ignore PAM if told to. */

	if (!lp_obey_pam_restrictions())
		return True;

	if ((pconv = smb_setup_pam_conv(smb_pam_conv, user, NULL, NULL)) == NULL)
		return False;

	if (!smb_pam_start(&pamh, user, rhost, pconv))
		return False;

	if (!smb_internal_pam_session(pamh, user, tty, True)) {
		smb_pam_end(pamh, pconv);
		return False;
	}

	return smb_pam_end(pamh, pconv);
}

/*
 * PAM Externally accessible Session handler
 */

BOOL smb_pam_close_session(char *user, char *tty, char *rhost)
{
	pam_handle_t *pamh = NULL;
	struct pam_conv *pconv = NULL;

	/* Ignore PAM if told to. */

	if (!lp_obey_pam_restrictions())
		return True;

	if ((pconv = smb_setup_pam_conv(smb_pam_conv, user, NULL, NULL)) == NULL)
		return False;

	if (!smb_pam_start(&pamh, user, rhost, pconv))
		return False;

	if (!smb_internal_pam_session(pamh, user, tty, False)) {
		smb_pam_end(pamh, pconv);
		return False;
	}

	return smb_pam_end(pamh, pconv);
}

/*
 * PAM Externally accessible Account handler
 */

uint32 smb_pam_accountcheck(char * user)
{
	uint32 nt_status = NT_STATUS_ACCOUNT_DISABLED;
	pam_handle_t *pamh = NULL;
	struct pam_conv *pconv = NULL;

	/* Ignore PAM if told to. */

	if (!lp_obey_pam_restrictions())
		return NT_STATUS_NOPROBLEMO;

	if ((pconv = smb_setup_pam_conv(smb_pam_conv, user, NULL, NULL)) == NULL)
		return False;

	if (!smb_pam_start(&pamh, user, NULL, pconv))
		return NT_STATUS_ACCOUNT_DISABLED;

	if ((nt_status = smb_pam_account(pamh, user)) != NT_STATUS_NOPROBLEMO)
		DEBUG(0, ("smb_pam_accountcheck: PAM: Account Validation Failed - Rejecting User %s!\n", user));

	smb_pam_end(pamh, pconv);
	return nt_status;
}

/*
 * PAM Password Validation Suite
 */

uint32 smb_pam_passcheck(char * user, char * password)
{
	pam_handle_t *pamh = NULL;
	uint32 nt_status = NT_STATUS_LOGON_FAILURE;
	struct pam_conv *pconv = NULL;

	/*
	 * Note we can't ignore PAM here as this is the only
	 * way of doing auths on plaintext passwords when
	 * compiled --with-pam.
	 */

	if ((pconv = smb_setup_pam_conv(smb_pam_conv, user, password, NULL)) == NULL)
		return False;

	if (!smb_pam_start(&pamh, user, NULL, NULL))
		return NT_STATUS_LOGON_FAILURE;

	if ((nt_status = smb_pam_auth(pamh, user)) != NT_STATUS_NOPROBLEMO) {
		DEBUG(0, ("smb_pam_passcheck: PAM: smb_pam_auth failed - Rejecting User %s !\n", user));
		smb_pam_end(pamh, pconv);
		return nt_status;
	}

	if ((nt_status = smb_pam_account(pamh, user)) != NT_STATUS_NOPROBLEMO) {
		DEBUG(0, ("smb_pam_passcheck: PAM: smb_pam_account failed - Rejecting User %s !\n", user));
		smb_pam_end(pamh, pconv);
		return nt_status;
	}

	if ((nt_status = smb_pam_setcred(pamh, user)) != NT_STATUS_NOPROBLEMO) {
		DEBUG(0, ("smb_pam_passcheck: PAM: smb_pam_setcred failed - Rejecting User %s !\n", user));
		smb_pam_end(pamh, pconv);
		return nt_status;
	}

	smb_pam_end(pamh, pconv);
	return nt_status;
}

/*
 * PAM Password Change Suite
 */

BOOL smb_pam_passchange(char * user, char * oldpassword, char * newpassword)
{
	/* Appropriate quantities of root should be obtained BEFORE calling this function */
	struct pam_conv *pconv = NULL;
	pam_handle_t *pamh = NULL;

	if ((pconv = smb_setup_pam_conv(smb_pam_passchange_conv, user, oldpassword, newpassword)) == NULL)
		return False;

	if(!smb_pam_start(&pamh, user, NULL, pconv))
		return False;

	if (!smb_pam_chauthtok(pamh, user)) {
		DEBUG(0, ("smb_pam_passchange: PAM: Password Change Failed for user %s!\n", user));
		smb_pam_end(pamh, pconv);
		return False;
	}

	return smb_pam_end(pamh, pconv);
}

#else

/* If PAM not used, no PAM restrictions on accounts. */
 uint32 smb_pam_accountcheck(char * user)
{
	return NT_STATUS_NOPROBLEMO;
}

/* If PAM not used, also no PAM restrictions on sessions. */
 BOOL smb_pam_claim_session(const char *user, char *tty, char *rhost)
{
	return True;
}

/* If PAM not used, also no PAM restrictions on sessions. */
 BOOL smb_pam_close_session(const char *in_user, char *tty, char *rhost)
{
	return True;
}
#endif /* WITH_PAM */
