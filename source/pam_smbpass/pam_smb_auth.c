/* Unix NT password database implementation, version 0.7.5.
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
*/

/* indicate the following groups are defined */
#define PAM_SM_AUTH

#include "includes.h"
#include "debug.h"

#ifndef LINUX

/* This is only used in the Sun implementation. */
#include <security/pam_appl.h>

#endif  /* LINUX */

#include <security/pam_modules.h>

#include "general.h"

#include "support.h"

#define AUTH_RETURN						\
do {								\
	if(ret_data) {						\
		*ret_data = retval;				\
		pam_set_data( pamh, "smb_setcred_return"	\
		              , (void *) ret_data, NULL );	\
	}							\
	return retval;						\
} while (0)

static int _smb_add_user(pam_handle_t *pamh, unsigned int ctrl,
                         const char *name, SAM_ACCOUNT *sampass, BOOL exist);

int make_remark(pam_handle_t *, unsigned int, int, const char *);


/*
 * pam_sm_authenticate() authenticates users against the samba password file.
 *
 *	First, obtain the password from the user. Then use a
 *      routine in 'support.c' to authenticate the user.
 */

#define _SMB_AUTHTOK  "-SMB-PASS"

int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                        int argc, const char **argv)
{
    unsigned int ctrl;
    int retval, *ret_data = NULL;
    SAM_ACCOUNT *sampass = NULL;
    extern BOOL in_client;
    const char *name;
    BOOL found;

    /* Points to memory managed by the PAM library. Do not free. */
    char *p = NULL;


    /* Samba initialization. */
    setup_logging("pam_smbpass",False);
    charset_initialise();
    codepage_initialise(lp_client_code_page());
    in_client = True;

    ctrl = set_ctrl(flags, argc, argv);

    /* Get a few bytes so we can pass our return value to
       pam_sm_setcred(). */
    ret_data = malloc(sizeof(int));

    /* get the username */
    retval = pam_get_user( pamh, &name, "Username: " );
    if ( retval != PAM_SUCCESS ) {
        if (on( SMB_DEBUG, ctrl )) {
	    _log_err(LOG_DEBUG, "auth: could not identify user");
        }
        AUTH_RETURN;
    }
    if (on( SMB_DEBUG, ctrl )) {
        _log_err( LOG_DEBUG, "username [%s] obtained", name );
    }

    if (!initialize_password_db(True)) {
        _log_err( LOG_ALERT, "Cannot access samba password database" );
        retval = PAM_AUTHINFO_UNAVAIL;
        AUTH_RETURN;
    }

    pdb_init_sam(&sampass);
    
    found = pdb_getsampwnam( sampass, name );

    if (on( SMB_MIGRATE, ctrl )) {
	retval = _smb_add_user(pamh, ctrl, name, sampass, found);
	pdb_free_sam(sampass);
	AUTH_RETURN;
    }

    if (!found) {
        _log_err(LOG_ALERT, "Failed to find entry for user %s.", name);
        retval = PAM_USER_UNKNOWN;
	pdb_free_sam(sampass);
	sampass = NULL;
        AUTH_RETURN;
    }
   
    /* if this user does not have a password... */

    if (_smb_blankpasswd( ctrl, sampass )) {
        pdb_free_sam(sampass);
        retval = PAM_SUCCESS;
        AUTH_RETURN;
    }

    /* get this user's authentication token */

    retval = _smb_read_password(pamh, ctrl, NULL, "Password: ", NULL, _SMB_AUTHTOK, &p);
    if (retval != PAM_SUCCESS ) {
	_log_err(LOG_CRIT, "auth: no password provided for [%s]"
		 , name);
        pdb_free_sam(sampass);
        AUTH_RETURN;
    }

    /* verify the password of this user */

    retval = _smb_verify_password( pamh, sampass, p, ctrl );
    pdb_free_sam(sampass);
    p = NULL;
    AUTH_RETURN;
}

/*
 * This function is for setting samba credentials.  If anyone comes up
 * with any credentials they think should be set, let me know.
 */

int pam_sm_setcred(pam_handle_t *pamh, int flags,
                   int argc, const char **argv)
{
    int retval, *pretval = NULL;

    retval = PAM_SUCCESS;

    pam_get_data(pamh, "smb_setcred_return", (const void **) &pretval);
    if(pretval) {
	retval = *pretval;
	SAFE_FREE(pretval);
    }
    pam_set_data(pamh, "smb_setcred_return", NULL, NULL);

    return retval;
}


/* Helper function for adding a user to the db. */
static int _smb_add_user(pam_handle_t *pamh, unsigned int ctrl,
                         const char *name, SAM_ACCOUNT *sampass, BOOL exist)
{
    pstring err_str;
    pstring msg_str;
    char *pass = NULL;
    int retval;

    err_str[0] = '\0';
    msg_str[0] = '\0';

    /* Get the authtok; if we don't have one, silently fail. */
    retval = pam_get_item( pamh, PAM_AUTHTOK, (const void **) &pass );

    if (retval != PAM_SUCCESS) {
	_log_err( LOG_ALERT
	          , "pam_get_item returned error to pam_sm_authenticate" );
	return PAM_AUTHTOK_RECOVER_ERR;
    } else if (pass == NULL) {
	return PAM_AUTHTOK_RECOVER_ERR;
    }

    /* Add the user to the db if they aren't already there. */
   if (!exist) {
	retval = local_password_change( name, LOCAL_ADD_USER,
	                                 pass, err_str,
	                                 sizeof(err_str),
	                                 msg_str, sizeof(msg_str) );
	if (!retval && *err_str)
	{
	    err_str[PSTRING_LEN-1] = '\0';
	    make_remark( pamh, ctrl, PAM_ERROR_MSG, err_str );
	}
	else if (*msg_str)
	{
	    msg_str[PSTRING_LEN-1] = '\0';
	    make_remark( pamh, ctrl, PAM_TEXT_INFO, msg_str );
	}
	pass = NULL;

	return PAM_IGNORE;
   }
   else {
    /* Change the user's password IFF it's null. */
    if ((pdb_get_lanman_passwd(sampass) == NULL) && (pdb_get_acct_ctrl(sampass) & ACB_PWNOTREQ))
    {
	retval = local_password_change( name, 0, pass, err_str, sizeof(err_str),
	                                 msg_str, sizeof(msg_str) );
	if (!retval && *err_str)
	{
	    err_str[PSTRING_LEN-1] = '\0';
	    make_remark( pamh, ctrl, PAM_ERROR_MSG, err_str );
	}
	else if (*msg_str)
	{
	    msg_str[PSTRING_LEN-1] = '\0';
	    make_remark( pamh, ctrl, PAM_TEXT_INFO, msg_str );
	}
    }
   }
    
    pass = NULL;

    return PAM_IGNORE;
}


/* static module data */
#ifdef PAM_STATIC
struct pam_module _pam_smbpass_auth_modstruct = {
     "pam_smbpass",
     pam_sm_authenticate,
     pam_sm_setcred,
     NULL,
     NULL,
     NULL,
     NULL
};
#endif

