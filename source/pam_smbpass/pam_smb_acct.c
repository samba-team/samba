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
#define PAM_SM_ACCT

#include "includes.h"

#ifndef LINUX

/* This is only used in the Sun implementation. */
#include <security/pam_appl.h>

#endif  /* LINUX */

#include <security/pam_modules.h>

#include "general.h"

#include "support.h"

/*
 * pam_sm_acct_mgmt() verifies whether or not the account is disabled.
 *
 */

int pam_sm_acct_mgmt( pam_handle_t *pamh, int flags,
                      int argc, const char **argv )
{
    unsigned int ctrl;
    int retval;

    const char *name;
    SAM_ACCOUNT *sampass = NULL;

    extern BOOL in_client;

    /* Samba initialization. */
    setup_logging( "pam_smbpass", False );
    charset_initialise();
    codepage_initialise(lp_client_code_page());
    in_client = True;

    ctrl = set_ctrl( flags, argc, argv );

    /* get the username */

    retval = pam_get_user( pamh, &name, "Username: " );
    if (retval != PAM_SUCCESS) {
        if (on( SMB_DEBUG, ctrl )) {
	    _log_err( LOG_DEBUG, "acct: could not identify user" );
        }
        return retval;
    }
    if (on( SMB_DEBUG, ctrl )) {
        _log_err( LOG_DEBUG, "acct: username [%s] obtained", name );
    }

    if (!initialize_password_db(True)) {
        _log_err( LOG_ALERT, "Cannot access samba password database" );
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* Get the user's record. */
    pdb_init_sam(&sampass);
    pdb_getsampwnam(sampass, name );

    if (!sampass)
        return PAM_USER_UNKNOWN;

    if (pdb_get_acct_ctrl(sampass) & ACB_DISABLED) {
        if (on( SMB_DEBUG, ctrl )) {
            _log_err( LOG_DEBUG
                      , "acct: account %s is administratively disabled", name );
        }
        make_remark( pamh, ctrl, PAM_ERROR_MSG
                     , "Your account has been disabled; "
                       "please see your system administrator." );

        return PAM_ACCT_EXPIRED;
    }

    /* TODO: support for expired passwords. */

    return PAM_SUCCESS;
}

/* static module data */
#ifdef PAM_STATIC
struct pam_module _pam_smbpass_acct_modstruct = {
     "pam_smbpass",
     NULL,
     NULL,
     pam_sm_acct_mgmt,
     NULL,
     NULL,
     NULL
};
#endif

