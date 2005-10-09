/* 
   Unix SMB/CIFS implementation.
   PAM Password checking
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) John H Terpsta 1999-2001
   Copyright (C) Andrew Bartlett 2001
   Copyright (C) Jeremy Allison 2001
   Copyright (C) Simo Sorce 2005
   
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
 * username/password pairs.
 * Note: This module is a stripped down version of pampass.c of samba 3
 *       It has been adapted to perform only pam auth checks and code has
 *       been shaped out to meet samba4 coding stile
 */

#include "includes.h"

#ifdef HAVE_SECURITY_PAM_APPL_H

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
	const char *PAM_username;
	const char *PAM_password;
};

typedef int (*smb_pam_conv_fn)(int, const struct pam_message **, struct pam_response **, void *appdata_ptr);

/*******************************************************************
 PAM error handler.
 *********************************************************************/

static BOOL smb_pam_error_handler(pam_handle_t *pamh, int pam_error, const char *msg, int dbglvl)
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
					    const char *msg, int dbglvl, 
					    NTSTATUS *nt_status)
{
	*nt_status = pam_to_nt_status(pam_error);

	if (smb_pam_error_handler(pamh, pam_error, msg, dbglvl))
		return True;

	if (NT_STATUS_IS_OK(*nt_status)) {
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

	if (num_msg <= 0)
		return PAM_CONV_ERR;

	/*
	 * Apparantly HPUX has a buggy PAM that doesn't support the
	 * appdata_ptr. Fail if this is the case. JRA.
	 */

	if (udp == NULL) {
		DEBUG(0,("smb_pam_conv: PAM on this system is broken - appdata_ptr == NULL !\n"));
		return PAM_CONV_ERR;
	}

	reply = malloc_array_p(struct pam_response, num_msg);
	if (!reply)
		return PAM_CONV_ERR;

	memset(reply, '\0', sizeof(struct pam_response) * num_msg);

	for (replies = 0; replies < num_msg; replies++) {
		switch (msg[replies]->msg_style) {
			case PAM_PROMPT_ECHO_ON:
				reply[replies].resp_retcode = PAM_SUCCESS;
				reply[replies].resp = strdup(udp->PAM_username);
				/* PAM frees resp */
				break;

			case PAM_PROMPT_ECHO_OFF:
				reply[replies].resp_retcode = PAM_SUCCESS;
				reply[replies].resp = strdup(udp->PAM_password);
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
				if (reply)
					free(reply);
				return PAM_CONV_ERR;
		}
	}
	if (reply)
		*resp = reply;
	return PAM_SUCCESS;
}

/***************************************************************************
 Allocate a pam_conv struct.
****************************************************************************/

static struct pam_conv *smb_setup_pam_conv(TALLOC_CTX *ctx,
					   smb_pam_conv_fn smb_pam_conv_fnptr,
					   const char *username, const char *password)
{
	struct pam_conv *pconv;
	struct smb_pam_userdata *udp;

	pconv = talloc(ctx, struct pam_conv);
	if (pconv == NULL)
		return NULL;

	udp = talloc(ctx, struct smb_pam_userdata);
	if (udp == NULL)
		return NULL;

	udp->PAM_username = username;
	udp->PAM_password = password;

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

static BOOL smb_pam_start(pam_handle_t **pamh, const char *user, const char *rhost, struct pam_conv *pconv)
{
	int pam_error;
	const char *our_rhost;

	if (user == NULL || rhost == NULL || pconv == NULL) {
		return False;
	}

	*pamh = (pam_handle_t *)NULL;

	DEBUG(4,("smb_pam_start: PAM: Init user: %s\n", user));

	pam_error = pam_start("samba", user, pconv, pamh);
	if( !smb_pam_error_handler(*pamh, pam_error, "Init Failed", 0)) {
		*pamh = (pam_handle_t *)NULL;
		return False;
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
static NTSTATUS smb_pam_auth(pam_handle_t *pamh, const char *user)
{
	int pam_error;
	NTSTATUS nt_status = NT_STATUS_LOGON_FAILURE;

	/*
	 * To enable debugging set in /etc/pam.d/samba:
	 *	auth required /lib/security/pam_pwdb.so nullok shadow audit
	 */
	
	DEBUG(4,("smb_pam_auth: PAM: Authenticate User: %s\n", user));
	pam_error = pam_authenticate(pamh, PAM_SILENT | lp_null_passwords() ? 0 : PAM_DISALLOW_NULL_AUTHTOK);
	switch( pam_error ){
		case PAM_AUTH_ERR:
			DEBUG(2, ("smb_pam_auth: PAM: Athentication Error for user %s\n", user));
			break;
		case PAM_CRED_INSUFFICIENT:
			DEBUG(2, ("smb_pam_auth: PAM: Insufficient Credentials for user %s\n", user));
			break;
		case PAM_AUTHINFO_UNAVAIL:
			DEBUG(2, ("smb_pam_auth: PAM: Authentication Information Unavailable for user %s\n", user));
			break;
		case PAM_USER_UNKNOWN:
			DEBUG(2, ("smb_pam_auth: PAM: Username %s NOT known to Authentication system\n", user));
			break;
		case PAM_MAXTRIES:
			DEBUG(2, ("smb_pam_auth: PAM: One or more authentication modules reports user limit for user %s exceeeded\n", user));
			break;
		case PAM_ABORT:
			DEBUG(0, ("smb_pam_auth: PAM: One or more PAM modules failed to load for user %s\n", user));
			break;
		case PAM_SUCCESS:
			DEBUG(4, ("smb_pam_auth: PAM: User %s Authenticated OK\n", user));
			break;
		default:
			DEBUG(0, ("smb_pam_auth: PAM: UNKNOWN ERROR while authenticating user %s\n", user));
			break;
	}

	smb_pam_nt_status_error_handler(pamh, pam_error, "Authentication Failure", 2, &nt_status);
	return nt_status;
}

/*
 * PAM Password Validation Suite
 */

NTSTATUS unix_passcheck(TALLOC_CTX *ctx, const char *client, const char *username, const char *password)
{
	NTSTATUS nt_status = NT_STATUS_LOGON_FAILURE;
	pam_handle_t *pamh = NULL;
	struct pam_conv *pconv = NULL;

	if ((pconv = smb_setup_pam_conv(ctx, smb_pam_conv, username, password)) == NULL)
		return nt_status;

	if (!smb_pam_start(&pamh, username, client, pconv)) {
		talloc_free(pconv);
		return nt_status;
	}

	if (!NT_STATUS_IS_OK(nt_status = smb_pam_auth(pamh, username))) {
		DEBUG(0, ("smb_pam_passcheck: PAM: smb_pam_auth failed - Rejecting User %s !\n", username));
	}

	smb_pam_end(pamh, pconv);
	talloc_free(pconv);

	return nt_status;
}

#else

NTSTATUS unix_passcheck(TALLOC_CTX *ctx, const char *client, const char *username, const char *password)
{
	return NT_STATUS_LOGON_FAILURE;
}

#endif /* WITH_PAM */
