/* pam_winbind module

   Copyright Andrew Tridgell <tridge@samba.org> 2000

   largely based on pam_userdb by Christian Gafton <gafton@redhat.com> 
*/

#include <features.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define MODULE_NAME "pam_winbind"
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_PASSWORD
#include <security/pam_modules.h>
#include <security/_pam_macros.h>

#define PAM_DEBUG_ARG (1<<0)
#define PAM_USE_AUTHTOK_ARG (1<<1)
#define PAM_UNKNOWN_OK_ARG (1<<2)

#include "winbind_nss_config.h"
#include "winbindd_nss.h"

/* prototypes from common.c */
void init_request(struct winbindd_request *req,int rq_type);
int write_sock(void *buffer, int count);
int read_reply(struct winbindd_response *response);

/* some syslogging */
static void _pam_log(int err, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	openlog(MODULE_NAME, LOG_CONS|LOG_PID, LOG_AUTH);
	vsyslog(err, format, args);
	va_end(args);
	closelog();
}

static int ctrl	 = 0;

static int _pam_parse(int argc, const char **argv)
{
     /* step through arguments */
     for (ctrl = 0; argc-- > 0; ++argv) {

          /* generic options */

          if (!strcmp(*argv,"debug"))
               ctrl |= PAM_DEBUG_ARG;
	  else if (!strcasecmp(*argv, "use_authtok"))
	      ctrl |= PAM_USE_AUTHTOK_ARG;
	  else if (!strcasecmp(*argv, "unknown_ok"))
	      ctrl |= PAM_UNKNOWN_OK_ARG;
	  else {
               _pam_log(LOG_ERR, "pam_parse: unknown option; %s", *argv);
          }
     }

     return ctrl;
}

static int winbind_request(enum winbindd_cmd req_type,
                           struct winbindd_request *request,
                           struct winbindd_response *response)
{
	/* Fill in request and send down pipe */
	init_request(request, req_type);
	
	if (write_sock(request, sizeof(*request)) == -1) {
		return -2;
	}
	
	/* Wait for reply */
	if (read_reply(response) == -1) {
		return -2;
	}

	/* Copy reply data from socket */
	if (response->result != WINBINDD_OK) {
		return 1;
	}
	
	return 0;
}

/* talk to winbindd */
static int winbind_auth_request(const char *user, const char *pass)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);

	strncpy(request.data.auth.user, user, 
                sizeof(request.data.auth.user)-1);

	strncpy(request.data.auth.pass, pass, 
                sizeof(request.data.auth.pass)-1);
	
        return winbind_request(WINBINDD_PAM_AUTH, &request, &response);
}

/* talk to winbindd */
static int winbind_chauthtok_request(const char *user, const char *oldpass,
                                     const char *newpass)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);

        if (request.data.chauthtok.user == NULL) return -2;

	strncpy(request.data.chauthtok.user, user, 
                sizeof(request.data.chauthtok.user) - 1);

        if (oldpass != NULL) {
            strncpy(request.data.chauthtok.oldpass, oldpass, 
                    sizeof(request.data.chauthtok.oldpass) - 1);
        } else {
            request.data.chauthtok.oldpass[0] = '\0';
        }
	
        if (newpass != NULL) {
            strncpy(request.data.chauthtok.newpass, newpass, 
                    sizeof(request.data.chauthtok.newpass) - 1);
        } else {
            request.data.chauthtok.newpass[0] = '\0';
        }
	
        return winbind_request(WINBINDD_PAM_CHAUTHTOK, &request, &response);
}

/*
 * Looks up an user name and checks the password
 *
 * return values:
 *	 1  = User not found
 *	 0  = OK
 * 	-1  = Password incorrect
 *	-2  = System error
 */
static int user_lookup(const char *user, const char *pass)
{
	return winbind_auth_request(user, pass);
}

/*
 * Checks if a user has an account
 *
 * return values:
 *	 1  = User not found
 *	 0  = OK
 * 	-1  = System error
 */
static int valid_user(const char *user)
{
	if (getpwnam(user)) return 0;
	return 1;
}

/* --- authentication management functions --- */

/* Attempt a conversation */

static int converse(pam_handle_t *pamh, int nargs,
		    struct pam_message **message,
		    struct pam_response **response)
{
    int retval;
    struct pam_conv *conv;

    retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv ) ;
    if (retval == PAM_SUCCESS) {
	retval = conv->conv(nargs, (const struct pam_message **)message,
			    response, conv->appdata_ptr);
    }
	
    return retval; /* propagate error status */
}


static char *_pam_delete(register char *xx)
{
    _pam_overwrite(xx);
    _pam_drop(xx);
    return NULL;
}

/*
 * This is a conversation function to obtain the user's password
 */
static int auth_conversation(pam_handle_t *pamh)
{
    struct pam_message msg, *pmsg;
    struct pam_response *resp;
    int retval;
    char * token;
    
    pmsg = &msg;
    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = "Password: ";

    /* so call the conversation expecting i responses */
    resp = NULL;
    retval = converse(pamh, 1, &pmsg, &resp);

    if (resp != NULL) {
	char * const item;
	/* interpret the response */
	if (retval == PAM_SUCCESS) {     /* a good conversation */
	    token = x_strdup(resp[0].resp);
	    if (token == NULL) {
		return PAM_AUTHTOK_RECOVER_ERR;
	    }
	}

	/* set the auth token */
	retval = pam_set_item(pamh, PAM_AUTHTOK, token);
	token = _pam_delete(token);   /* clean it up */
	if ( (retval != PAM_SUCCESS) ||
	     (retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &item)) != PAM_SUCCESS ) {
	    return retval;
	}
	
	_pam_drop_reply(resp, 1);
    } else {
	retval = (retval == PAM_SUCCESS)
	    ? PAM_AUTHTOK_RECOVER_ERR:retval ;
    }

    return retval;
}

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags,
			int argc, const char **argv)
{
     const char *username;
     const char *password;
     int retval = PAM_AUTH_ERR;
    
     /* parse arguments */
     ctrl = _pam_parse(argc, argv);

     /* Get the username */
     retval = pam_get_user(pamh, &username, NULL);
     if ((retval != PAM_SUCCESS) || (!username)) {
        if (ctrl & PAM_DEBUG_ARG)
            _pam_log(LOG_DEBUG,"can not get the username");
        return PAM_SERVICE_ERR;
     }
     
     if ((ctrl & PAM_USE_AUTHTOK_ARG) == 0) {
	 /* Converse just to be sure we have the password */
	 retval = auth_conversation(pamh);
	 if (retval != PAM_SUCCESS) {
	     _pam_log(LOG_ERR, "could not obtain password for `%s'",
		      username);
	     return PAM_CONV_ERR;
	 }
     }
     
     /* Get the password */
     retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &password);
     if (retval != PAM_SUCCESS) {
	 _pam_log(LOG_ERR, "Could not retrive user's password");
	 return PAM_AUTHTOK_ERR;
     }
     
     if (ctrl & PAM_DEBUG_ARG)
	 _pam_log(LOG_INFO, "Verify user `%s' with password `%s'",
		  username, password);
     
     /* Now use the username to look up password */
     retval = user_lookup(username, password);
     switch (retval) {
	 case -2:
	     /* some sort of system error. The log was already printed */
	     return PAM_SERVICE_ERR;    
	 case -1:
	     /* incorrect password */
	     _pam_log(LOG_WARNING, "user `%s' denied access (incorrect password)", username);
	     return PAM_AUTH_ERR;
	 case 1:
		 /* the user does not exist */
	     if (ctrl & PAM_DEBUG_ARG)
		 _pam_log(LOG_NOTICE, "user `%s' not found",
			  username);
	     if (ctrl & PAM_UNKNOWN_OK_ARG) {
		 return PAM_IGNORE;
	     }	 
	     return PAM_USER_UNKNOWN;
	 case 0:
	     /* Otherwise, the authentication looked good */
	     _pam_log(LOG_NOTICE, "user '%s' granted acces", username);
	     return PAM_SUCCESS;
	 default:
	     /* we don't know anything about this return value */
	     _pam_log(LOG_ERR, "internal module error (retval = %d, user = `%s'",
		      retval, username);
	     return PAM_SERVICE_ERR;
     }
     /* should not be reached */
     return PAM_IGNORE;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags,
		   int argc, const char **argv)
{
    return PAM_SUCCESS;
}

/*
 * Account management. We want to verify that the account exists 
 * before returning PAM_SUCCESS
 */
PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		   int argc, const char **argv)
{
    const char *username;
    int retval = PAM_USER_UNKNOWN;

    /* parse arguments */
    ctrl = _pam_parse(argc, argv);

    /* Get the username */
    retval = pam_get_user(pamh, &username, NULL);
    if ((retval != PAM_SUCCESS) || (!username)) {
	if (ctrl & PAM_DEBUG_ARG)
	    _pam_log(LOG_DEBUG,"can not get the username");
	return PAM_SERVICE_ERR;
    }

    /* Verify the username */
    retval = valid_user(username);
    switch (retval) {
	case -1:
	    /* some sort of system error. The log was already printed */
	    return PAM_SERVICE_ERR;
	case 1:
	    /* the user does not exist */
	    if (ctrl & PAM_DEBUG_ARG)
		_pam_log(LOG_NOTICE, "user `%s' not found",
			 username);
	    if (ctrl & PAM_UNKNOWN_OK_ARG)
		return PAM_IGNORE;
	    return PAM_USER_UNKNOWN;
	case 0:
	    /* Otherwise, the authentication looked good */
	    _pam_log(LOG_NOTICE, "user '%s' granted acces", username);
	    return PAM_SUCCESS;
	default:
	    /* we don't know anything about this return value */
	    _pam_log(LOG_ERR, "internal module error (retval = %d, user = `%s'",
		     retval, username);
	    return PAM_SERVICE_ERR;
    }
    
    /* should not be reached */
    return PAM_IGNORE;
}


PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, 
                     const char **argv)
{
    int retval;
    char *newpw, *oldpw;
    const char *user;

    /* Get name of a user */

    retval = pam_get_user(pamh, &user, "Username: ");

    if (retval != PAM_SUCCESS) {
        return retval;
    }

    /* XXX check in domain format */

    /* Perform preliminary check and store requested password for updating
       later on */

    if (flags & PAM_PRELIM_CHECK) {
        struct pam_message msg[3], *pmsg[3];
        struct pam_response *resp;

        /* Converse to ensure we have the current password */

        retval = auth_conversation(pamh);

        if (retval != PAM_SUCCESS) {
            return retval;
        }

        /* Obtain and verify current password */

        pmsg[0] = &msg[0];
        msg[0].msg_style = PAM_TEXT_INFO;
        msg[0].msg = "Changing password for user %s";

        pmsg[1] = &msg[1];
        msg[1].msg_style = PAM_PROMPT_ECHO_OFF;
        msg[1].msg = "New NT password: ";

        pmsg[2] = &msg[2];
        msg[2].msg_style = PAM_PROMPT_ECHO_OFF;
        msg[2].msg = "Retype new NT password: ";

        resp = NULL;

        retval = converse(pamh, 3, pmsg, &resp);

        if (resp != NULL) {

            if (retval == PAM_SUCCESS) {

                /* Check password entered correctly */

                if (strcmp(resp[1].resp, resp[2].resp) != 0) { 
                    struct pam_response *resp2;

                    msg[0].msg_style = PAM_ERROR_MSG;
                    msg[0].msg = "Sorry, passwords do not match";

                    converse(pamh, 1, pmsg, &resp2);

                    _pam_drop_reply(resp, 3);
                    _pam_drop_reply(resp2, 1);

                    return PAM_AUTHTOK_RECOVER_ERR;
                }

                /* Store passwords */

                retval = pam_set_item(pamh, PAM_OLDAUTHTOK, resp[1].resp);
                _pam_drop_reply(resp, 3);
            }
        }

        /* XXX What happens if root? */
        /* XXX try first pass and use first pass args */

        return retval;
    }

    if (flags & PAM_UPDATE_AUTHTOK) {

        retval = pam_get_item(pamh, PAM_OLDAUTHTOK, (const void **)&newpw);
        if (retval != PAM_SUCCESS) {
            return PAM_AUTHTOK_ERR;
        }

        retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&oldpw);
        if (retval != PAM_SUCCESS) {
            return PAM_AUTHTOK_ERR;
        }

        fprintf(stderr, "oldpw = %s, newpw = %s\n", oldpw, newpw);

        if (retval == PAM_SUCCESS && 
            winbind_chauthtok_request(user, oldpw, newpw) == 0) {
            return PAM_SUCCESS;
        }

        return PAM_AUTHTOK_ERR;
    }

    return PAM_SERVICE_ERR;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_winbind_modstruct = {
     MODULE_NAME,
     pam_sm_authenticate,
     pam_sm_setcred,
     pam_sm_acct_mgmt,
     NULL,
     NULL,
     pam_sm_chauthtok
};

#endif

/*
 * Copyright (c) Andrew Tridgell <tridge@samba.org> 2000
 * Copyright (c) Tim Potter      <tpot@samba.org>   2000
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
 * THIS SOFTWARE IS PROVIDED `AS IS'' AND ANY EXPRESS OR IMPLIED
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
