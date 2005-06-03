/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Bartlett		2001
   Copyright (C) Jeremy Allison			2001
   Copyright (C) Simo Sorce			2005
   
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

#include "includes.h"
#include "auth/auth.h"
#include "system/passwd.h"


/* TODO: look at how to best fill in parms retrieveing a struct passwd info
 * except in case USER_INFO_DONT_CHECK_UNIX_ACCOUNT is set
 */
static NTSTATUS authunix_make_server_info(TALLOC_CTX *mem_ctx,
					  const struct auth_usersupplied_info *user_info,
					  struct auth_serversupplied_info **_server_info)
{
	struct auth_serversupplied_info *server_info;

	server_info = talloc(mem_ctx, struct auth_serversupplied_info);
	NT_STATUS_HAVE_NO_MEMORY(server_info);

	server_info->authenticated = True;

	server_info->account_name = talloc_strdup(server_info, talloc_strdup(mem_ctx, user_info->account_name));
	NT_STATUS_HAVE_NO_MEMORY(server_info->account_name);

	server_info->domain_name = talloc_strdup(server_info, talloc_strdup(mem_ctx, "unix"));
	NT_STATUS_HAVE_NO_MEMORY(server_info->domain_name);


	/* is this correct? */
	server_info->account_sid = NULL;
	server_info->primary_group_sid = NULL;
	server_info->n_domain_groups = 0;
	server_info->domain_groups = NULL;
	server_info->user_session_key = data_blob(NULL,0);
	server_info->lm_session_key = data_blob(NULL,0);

	server_info->full_name = talloc_strdup(server_info, "");
	NT_STATUS_HAVE_NO_MEMORY(server_info->full_name);
	server_info->logon_script = talloc_strdup(server_info, "");
	NT_STATUS_HAVE_NO_MEMORY(server_info->logon_script);
	server_info->profile_path = talloc_strdup(server_info, "");
	NT_STATUS_HAVE_NO_MEMORY(server_info->profile_path);
	server_info->home_directory = talloc_strdup(server_info, "");
	NT_STATUS_HAVE_NO_MEMORY(server_info->home_directory);
	server_info->home_drive = talloc_strdup(server_info, "");
	NT_STATUS_HAVE_NO_MEMORY(server_info->home_drive);

	server_info->last_logon = 0;
	server_info->last_logoff = 0;
	server_info->acct_expiry = 0;
	server_info->last_password_change = 0;
	server_info->allow_password_change = 0;
	server_info->force_password_change = 0;
	server_info->logon_count = 0;
	server_info->bad_password_count = 0;
	server_info->acct_flags = 0;

	*_server_info = server_info;

	return NT_STATUS_OK;
}

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>

struct smb_pam_user_info {
	const char *account_name;
	const char *plaintext_password;
};

#define COPY_STRING(s) (s) ? strdup(s) : NULL

/* 
 * Check user password
 * Currently it uses PAM only and fails on systems without PAM
 * Samba3 code located in pass_check.c is to ugly to be used directly it will
 * need major rework that's why pass_check.c is still there.
*/

static int smb_pam_conv(int num_msg, const struct pam_message **msg,
			 struct pam_response **reply, void *appdata_ptr)
{
	struct smb_pam_user_info *info = (struct smb_pam_user_info *)appdata_ptr;
	int num;

	if (num_msg <= 0) {
		*reply = NULL;
		return PAM_CONV_ERR;
	}
	
	/*
	 * Apparantly HPUX has a buggy PAM that doesn't support the
	 * data pointer. Fail if this is the case. JRA.
	 */

	if (info == NULL) {
		*reply = NULL;
		return PAM_CONV_ERR;
	}

	/*
	 * PAM frees memory in reply messages by itself
	 * so use malloc instead of talloc here.
	 */
	*reply = malloc_array_p(struct pam_response, num_msg);
	if (*reply == NULL) {
		return PAM_CONV_ERR;
	}

	for (num = 0; num < num_msg; num++) {
		switch  (msg[num]->msg_style) {
			case PAM_PROMPT_ECHO_ON:
				(*reply)[num].resp_retcode = PAM_SUCCESS;
				(*reply)[num].resp = COPY_STRING(info->account_name);
				break;

			case PAM_PROMPT_ECHO_OFF:
				(*reply)[num].resp_retcode = PAM_SUCCESS;
				(*reply)[num].resp = COPY_STRING(info->plaintext_password);
				break;

			case PAM_TEXT_INFO:
				(*reply)[num].resp_retcode = PAM_SUCCESS;
				(*reply)[num].resp = NULL;
				DEBUG(4,("PAM Info message in conversation function: %s\n", (msg[num]->msg)));

			case PAM_ERROR_MSG:
				(*reply)[num].resp_retcode = PAM_SUCCESS;
				(*reply)[num].resp = NULL;
				DEBUG(4,("PAM Error message in conversation function: %s\n", (msg[num]->msg)));
				break;

			default:
				SAFE_FREE(*reply);
				*reply = NULL;
				DEBUG(1,("Error: PAM subsystme sent an UNKNOWN message type to the conversation function!\n"));
				return PAM_CONV_ERR;
		}
	}

	return PAM_SUCCESS;
}

/*
 * Start PAM authentication for specified account
 */

static NTSTATUS smb_pam_start(pam_handle_t **pamh, const char *account_name, const char *remote_host, struct pam_conv *pconv)
{
	NTSTATUS nt_status;
	int pam_error;

	if (account_name == NULL || remote_host == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(4,("smb_pam_start: PAM: Init user: %s\n", account_name));

	pam_error = pam_start("samba", account_name, pconv, pamh);
	if (pam_error != PAM_SUCCESS) {
		/* no vaild pamh here, can we reliably call pam_strerror ? */
		DEBUG(4,("smb_pam_start: pam_start failed!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

#ifdef PAM_RHOST
	DEBUG(4,("smb_pam_start: PAM: setting rhost to: %s\n", remote_host));
	pam_error = pam_set_item(*pamh, PAM_RHOST, remote_host);
	if (pam_error != PAM_SUCCESS) {
		DEBUG(4,("smb_pam_start: setting rhost failed with error: %s\n",
			 pam_strerror(*pamh, pam_error)));
		nt_status = pam_to_nt_status(pam_error);

		pam_error = pam_end(*pamh, 0);
		if (pam_error != PAM_SUCCESS) {
			/* no vaild pamh here, can we reliably call pam_strerror ? */
			DEBUG(4,("smb_pam_start: clean up failed, pam_end gave error %d.\n",
				 pam_error));
			return pam_to_nt_status(pam_error);
		}
		return nt_status;
	}
#endif
#ifdef PAM_TTY
	DEBUG(4,("smb_pam_start: PAM: setting tty\n"));
	pam_error = pam_set_item(*pamh, PAM_TTY, "samba");
	if (pam_error != PAM_SUCCESS) {
		DEBUG(4,("smb_pam_start: setting tty failed with error: %s\n",
			 pam_strerror(*pamh, pam_error)));
		nt_status = pam_to_nt_status(pam_error);

		pam_error = pam_end(*pamh, 0);
		if (pam_error != PAM_SUCCESS) {
			/* no vaild pamh here, can we reliably call pam_strerror ? */
			DEBUG(4,("smb_pam_start: clean up failed, pam_end gave error %d.\n",
				 pam_error));
			return pam_to_nt_status(pam_error);
		}
		return nt_status;
	}
#endif
	DEBUG(4,("smb_pam_start: PAM: Init passed for user: %s\n", account_name));

	return NT_STATUS_OK;
}

static NTSTATUS smb_pam_end(pam_handle_t *pamh)
{
	int pam_error;

	if (pamh != NULL) {
		pam_error = pam_end(pamh, 0);
		if (pam_error != PAM_SUCCESS) {
			/* no vaild pamh here, can we reliably call pam_strerror ? */
			DEBUG(4,("smb_pam_end: clean up failed, pam_end gave error %d.\n",
				 pam_error));
			return pam_to_nt_status(pam_error);
		}
		return NT_STATUS_OK;
	}

	DEBUG(2,("smb_pam_end: pamh is NULL, PAM not initialized ?\n"));
	return NT_STATUS_UNSUCCESSFUL;
}

/*
 * PAM Authentication Handler
 */
static NTSTATUS smb_pam_auth(pam_handle_t *pamh, const char *user)
{
	int pam_error;

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

	return pam_to_nt_status(pam_error);
}

/* 
 * PAM Account Handler
 */
static NTSTATUS smb_pam_account(pam_handle_t *pamh, const char * user)
{
	int pam_error;

	DEBUG(4,("smb_pam_account: PAM: Account Management for User: %s\n", user));

	pam_error = pam_acct_mgmt(pamh, PAM_SILENT); /* Is user account enabled? */
	switch( pam_error ) {
		case PAM_AUTHTOK_EXPIRED:
			DEBUG(2, ("smb_pam_account: PAM: User %s is valid but password is expired\n", user));
			break;
		case PAM_ACCT_EXPIRED:
			DEBUG(2, ("smb_pam_account: PAM: User %s no longer permitted to access system\n", user));
			break;
		case PAM_AUTH_ERR:
			DEBUG(2, ("smb_pam_account: PAM: There was an authentication error for user %s\n", user));
			break;
		case PAM_PERM_DENIED:
			DEBUG(0, ("smb_pam_account: PAM: User %s is NOT permitted to access system at this time\n", user));
			break;
		case PAM_USER_UNKNOWN:
			DEBUG(0, ("smb_pam_account: PAM: User \"%s\" is NOT known to account management\n", user));
			break;
		case PAM_SUCCESS:
			DEBUG(4, ("smb_pam_account: PAM: Account OK for User: %s\n", user));
			break;
		default:
			DEBUG(0, ("smb_pam_account: PAM: UNKNOWN PAM ERROR (%d) during Account Management for User: %s\n", pam_error, user));
			break;
	}

	return pam_to_nt_status(pam_error);
}

/*
 * PAM Credential Setting
 */

static NTSTATUS smb_pam_setcred(pam_handle_t *pamh, const char * user)
{
	int pam_error;

	/*
	 * This will allow samba to aquire a kerberos token. And, when
	 * exporting an AFS cell, be able to /write/ to this cell.
	 */

	DEBUG(4,("PAM: Account Management SetCredentials for User: %s\n", user));

	pam_error = pam_setcred(pamh, (PAM_ESTABLISH_CRED|PAM_SILENT)); 
	switch( pam_error ) {
		case PAM_CRED_UNAVAIL:
			DEBUG(0, ("smb_pam_setcred: PAM: Credentials not found for user:%s\n", user ));
			break;
		case PAM_CRED_EXPIRED:
			DEBUG(0, ("smb_pam_setcred: PAM: Credentials for user: \"%s\" EXPIRED!\n", user ));
			break;
		case PAM_USER_UNKNOWN:
			DEBUG(0, ("smb_pam_setcred: PAM: User: \"%s\" is NOT known so can not set credentials!\n", user ));
			break;
		case PAM_CRED_ERR:
			DEBUG(0, ("smb_pam_setcred: PAM: Unknown setcredentials error - unable to set credentials for %s\n", user ));
			break;
		case PAM_SUCCESS:
			DEBUG(4, ("smb_pam_setcred: PAM: SetCredentials OK for User: %s\n", user));
			break;
		default:
			DEBUG(0, ("smb_pam_setcred: PAM: UNKNOWN PAM ERROR (%d) during SetCredentials for User: %s\n", pam_error, user));
			break;
	}

	return pam_to_nt_status(pam_error);
}

static NTSTATUS check_unix_password(TALLOC_CTX *ctx, const struct auth_usersupplied_info *user_info)
{
	struct smb_pam_user_info *info;
	struct pam_conv *pamconv;
	pam_handle_t *pamh;
	NTSTATUS nt_status;

	info = talloc(ctx, struct smb_pam_user_info);
	if (info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	info->account_name = user_info->account_name;
	info->plaintext_password = (char *)(user_info->plaintext_password.data);

	pamconv = talloc(ctx, struct pam_conv);
	if (pamconv == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	pamconv->conv = smb_pam_conv;
	pamconv->appdata_ptr = (void *)info;

	/* TODO:
	 * check for user_info->flags & USER_INFO_CASE_INSENSITIVE_USERNAME
	 * if true set up a crack name routine.
	 */

	nt_status = smb_pam_start(&pamh, user_info->account_name, user_info->remote_host, pamconv);
	if (!NT_STATUS_IS_OK(nt_status)) {
		smb_pam_end(pamh);
		return nt_status;
	}

	nt_status = smb_pam_auth(pamh, user_info->account_name);
	if (!NT_STATUS_IS_OK(nt_status)) {
		smb_pam_end(pamh);
		return nt_status;
	}

	if ( ! (user_info->flags & USER_INFO_DONT_CHECK_UNIX_ACCOUNT)) {

		nt_status = smb_pam_account(pamh, user_info->account_name);
		if (!NT_STATUS_IS_OK(nt_status)) {
			smb_pam_end(pamh);
			return nt_status;
		}

		nt_status = smb_pam_setcred(pamh, user_info->account_name);
		if (!NT_STATUS_IS_OK(nt_status)) {
			smb_pam_end(pamh);
			return nt_status;
		}
	}

	smb_pam_end(pamh);
	return NT_STATUS_OK;	
}

#else

static NTSTATUS check_unix_password(TALLOC_CTX *ctx, const struct auth_usersupplied_info *user_info)
{
	return NT_STATUS_UNIMPLEMENTED;
}

#endif /*(HAVE_SECURITY_PAM_APPL_H)*/

/** Check a plaintext username/password
 *
 **/

static NTSTATUS authunix_check_password(struct auth_method_context *ctx,
					TALLOC_CTX *mem_ctx,
					const struct auth_usersupplied_info *user_info,
					struct  auth_serversupplied_info **server_info)
{
	TALLOC_CTX *check_ctx;
	NTSTATUS nt_status;

	if (! user_info->account_name && ! *user_info->account_name) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	check_ctx = talloc_named_const(mem_ctx, 0, "check_unix_password");
	if (check_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = check_unix_password(mem_ctx, user_info);
	if ( ! NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	nt_status = authunix_make_server_info(mem_ctx, user_info, server_info);
	if ( ! NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	return NT_STATUS_OK;
}

static const struct auth_operations unix_ops = {
	.name		= "unix",
	.get_challenge	= auth_get_challenge_not_implemented,
	.check_password = authunix_check_password
};

NTSTATUS auth_unix_init(void)
{
	NTSTATUS ret;

	ret = auth_register(&unix_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register unix auth backend!\n"));
		return ret;
	}

	return ret;
}
