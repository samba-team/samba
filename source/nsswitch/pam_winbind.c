/* pam_winbind module

   Copyright Andrew Tridgell <tridge@samba.org> 2000
   Copyright Tim Potter <tpot@samba.org> 2000
   Copyright Andrew Bartlett <abartlet@samba.org> 2002

   largely based on pam_userdb by Christian Gafton <gafton@redhat.com> 
   also contains large slabs of code from pam_unix by Elliot Lee <sopwith@redhat.com>
   (see copyright below for full details)
*/

#include "pam_winbind.h"

/* prototypes from common.c */
void init_request(struct winbindd_request *req,int rq_type);
int write_sock(void *buffer, int count);
int read_reply(struct winbindd_response *response);

/* data tokens */

#define MAX_PASSWD_TRIES	3

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

static int _pam_parse(int argc, const char **argv)
{
	int ctrl;
	/* step through arguments */
	for (ctrl = 0; argc-- > 0; ++argv) {

		/* generic options */
		
		if (!strcmp(*argv,"debug"))
			ctrl |= WINBIND_DEBUG_ARG;
		else if (!strcasecmp(*argv, "use_authtok"))
			ctrl |= WINBIND_USE_AUTHTOK_ARG;
		else if (!strcasecmp(*argv, "use_first_pass"))
			ctrl |= WINBIND_TRY_FIRST_PASS_ARG;
		else if (!strcasecmp(*argv, "try_first_pass"))
			ctrl |= WINBIND_USE_FIRST_PASS_ARG;
		else if (!strcasecmp(*argv, "unknown_ok"))
			ctrl |= WINBIND_UNKNOWN_OK_ARG;
		else {
			_pam_log(LOG_ERR, "pam_parse: unknown option; %s", *argv);
		}
	}
	
	return ctrl;
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


int _make_remark(pam_handle_t * pamh, int type, const char *text)
{
	int retval = PAM_SUCCESS;

	struct pam_message *pmsg[1], msg[1];
	struct pam_response *resp;
	
	pmsg[0] = &msg[0];
	msg[0].msg = text;
	msg[0].msg_style = type;
	
	resp = NULL;
	retval = converse(pamh, 1, pmsg, &resp);
	
	if (resp) {
		_pam_drop_reply(resp, 1);
	}
	return retval;
}

static int winbind_request(enum winbindd_cmd req_type,
                           struct winbindd_request *request,
                           struct winbindd_response *response)
{
	/* Fill in request and send down pipe */
	init_request(request, req_type);
	
	if (write_sock(request, sizeof(*request)) == -1) {
		_pam_log(LOG_ERR, "write to socket failed!");
		return PAM_SERVICE_ERR;
	}
	
	/* Wait for reply */
	if (read_reply(response) == -1) {
		_pam_log(LOG_ERR, "read from socket failed!");
		return PAM_SERVICE_ERR;
	}

	/* Copy reply data from socket */
	if (response->result != WINBINDD_OK) {
		if (response->data.auth.pam_error != PAM_SUCCESS) {
			_pam_log(LOG_ERR, "request failed, PAM error was %d, NT error was %s", 
				 response->data.auth.pam_error,
				 response->data.auth.nt_status_string);
			return response->data.auth.pam_error;
		} else {
			_pam_log(LOG_ERR, "request failed, but PAM error 0!");
			return PAM_SERVICE_ERR;
		}
	}
	
	return PAM_SUCCESS;
}

/* talk to winbindd */
static int winbind_auth_request(const char *user, const char *pass, int ctrl)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int retval;

	ZERO_STRUCT(request);

	strncpy(request.data.auth.user, user, 
                sizeof(request.data.auth.user)-1);

	strncpy(request.data.auth.pass, pass, 
                sizeof(request.data.auth.pass)-1);
	
        retval = winbind_request(WINBINDD_PAM_AUTH, &request, &response);

	switch (retval) {
	case PAM_AUTH_ERR:
		/* incorrect password */
		_pam_log(LOG_WARNING, "user `%s' denied access (incorrect password)", user);
		return retval;
	case PAM_USER_UNKNOWN:
		/* the user does not exist */
		if (ctrl & WINBIND_DEBUG_ARG)
			_pam_log(LOG_NOTICE, "user `%s' not found",
				 user);
		if (ctrl & WINBIND_UNKNOWN_OK_ARG) {
			return PAM_IGNORE;
		}	 
		return retval;
	case PAM_SUCCESS:
		/* Otherwise, the authentication looked good */
		_pam_log(LOG_NOTICE, "user '%s' granted acces", user);
		return retval;
	default:
		/* we don't know anything about this return value */
		_pam_log(LOG_ERR, "internal module error (retval = %d, user = `%s'",
			 retval, user);
		return retval;
	}
     /* should not be reached */
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

static char *_pam_delete(register char *xx)
{
    _pam_overwrite(xx);
    _pam_drop(xx);
    return NULL;
}

/*
 * obtain a password from the user
 */

int _winbind_read_password(pam_handle_t * pamh
			,unsigned int ctrl
			,const char *comment
			,const char *prompt1
			,const char *prompt2
			,const char **pass)
{
	int authtok_flag;
	int retval;
	const char *item;
	char *token;

	/*
	 * make sure nothing inappropriate gets returned
	 */

	*pass = token = NULL;

	/*
	 * which authentication token are we getting?
	 */

	authtok_flag = on(WINBIND__OLD_PASSWORD, ctrl) ? PAM_OLDAUTHTOK : PAM_AUTHTOK;

	/*
	 * should we obtain the password from a PAM item ?
	 */

	if (on(WINBIND_TRY_FIRST_PASS_ARG, ctrl) || on(WINBIND_USE_FIRST_PASS_ARG, ctrl)) {
		retval = pam_get_item(pamh, authtok_flag, (const void **) &item);
		if (retval != PAM_SUCCESS) {
			/* very strange. */
			_pam_log(LOG_ALERT, 
				 "pam_get_item returned error to unix-read-password"
			    );
			return retval;
		} else if (item != NULL) {	/* we have a password! */
			*pass = item;
			item = NULL;
			return PAM_SUCCESS;
		} else if (on(WINBIND_USE_FIRST_PASS_ARG, ctrl)) {
			return PAM_AUTHTOK_RECOVER_ERR;		/* didn't work */
		} else if (on(WINBIND_USE_AUTHTOK_ARG, ctrl)
			   && off(WINBIND__OLD_PASSWORD, ctrl)) {
			return PAM_AUTHTOK_RECOVER_ERR;
		}
	}
	/*
	 * getting here implies we will have to get the password from the
	 * user directly.
	 */

	{
		struct pam_message msg[3], *pmsg[3];
		struct pam_response *resp;
		int i, replies;

		/* prepare to converse */

		if (comment != NULL) {
			pmsg[0] = &msg[0];
			msg[0].msg_style = PAM_TEXT_INFO;
			msg[0].msg = comment;
			i = 1;
		} else {
			i = 0;
		}

		pmsg[i] = &msg[i];
		msg[i].msg_style = PAM_PROMPT_ECHO_OFF;
		msg[i++].msg = prompt1;
		replies = 1;

		if (prompt2 != NULL) {
			pmsg[i] = &msg[i];
			msg[i].msg_style = PAM_PROMPT_ECHO_OFF;
			msg[i++].msg = prompt2;
			++replies;
		}
		/* so call the conversation expecting i responses */
		resp = NULL;
		retval = converse(pamh, i, pmsg, &resp);

		if (resp != NULL) {

			/* interpret the response */

			if (retval == PAM_SUCCESS) {	/* a good conversation */

				token = x_strdup(resp[i - replies].resp);
				if (token != NULL) {
					if (replies == 2) {

						/* verify that password entered correctly */
						if (!resp[i - 1].resp
						    || strcmp(token, resp[i - 1].resp)) {
							_pam_delete(token);	/* mistyped */
							retval = PAM_AUTHTOK_RECOVER_ERR;
							_make_remark(pamh								    ,PAM_ERROR_MSG, MISTYPED_PASS);
						}
					}
				} else {
					_pam_log(LOG_NOTICE
						 ,"could not recover authentication token");
				}

			}
			/*
			 * tidy up the conversation (resp_retcode) is ignored
			 * -- what is it for anyway? AGM
			 */

			_pam_drop_reply(resp, i);

		} else {
			retval = (retval == PAM_SUCCESS)
			    ? PAM_AUTHTOK_RECOVER_ERR : retval;
		}
	}

	if (retval != PAM_SUCCESS) {
		if (on(WINBIND_DEBUG_ARG, ctrl))
			_pam_log(LOG_DEBUG,
			         "unable to obtain a password");
		return retval;
	}
	/* 'token' is the entered password */

	/* we store this password as an item */
	
	retval = pam_set_item(pamh, authtok_flag, token);
	_pam_delete(token);	/* clean it up */
	if (retval != PAM_SUCCESS
	    || (retval = pam_get_item(pamh, authtok_flag
				      ,(const void **) &item))
	    != PAM_SUCCESS) {
		
		_pam_log(LOG_CRIT, "error manipulating password");
		return retval;
		
	}

	*pass = item;
	item = NULL;		/* break link to password */

	return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags,
			int argc, const char **argv)
{
     const char *username;
     const char *password;
     int retval = PAM_AUTH_ERR;
    
     /* parse arguments */
     int ctrl = _pam_parse(argc, argv);

     /* Get the username */
     retval = pam_get_user(pamh, &username, NULL);
     if ((retval != PAM_SUCCESS) || (!username)) {
        if (ctrl & WINBIND_DEBUG_ARG)
            _pam_log(LOG_DEBUG,"can not get the username");
        return PAM_SERVICE_ERR;
     }
     
     retval = _winbind_read_password(pamh, ctrl, NULL, 
				     "Password: ", NULL,
				     &password);
     
     if (retval != PAM_SUCCESS) {
	 _pam_log(LOG_ERR, "Could not retrive user's password");
	 return PAM_AUTHTOK_ERR;
     }
     
     if (ctrl & WINBIND_DEBUG_ARG) {

	     /* Let's not give too much away in the log file */

#ifdef DEBUG_PASSWORD
	 _pam_log(LOG_INFO, "Verify user `%s' with password `%s'",
		  username, password);
#else
	 _pam_log(LOG_INFO, "Verify user `%s'", username);
#endif
     }

     /* Now use the username to look up password */
     return winbind_auth_request(username, password, ctrl);
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
    int ctrl = _pam_parse(argc, argv);

    /* Get the username */
    retval = pam_get_user(pamh, &username, NULL);
    if ((retval != PAM_SUCCESS) || (!username)) {
	if (ctrl & WINBIND_DEBUG_ARG)
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
	    if (ctrl & WINBIND_DEBUG_ARG)
		_pam_log(LOG_NOTICE, "user `%s' not found",
			 username);
	    if (ctrl & WINBIND_UNKNOWN_OK_ARG)
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

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
		                int argc, const char **argv)
{
	/* parse arguments */
	int ctrl = _pam_parse(argc, argv);
	if (ctrl & WINBIND_DEBUG_ARG)
		_pam_log(LOG_DEBUG,"libpam_winbind:pam_sm_open_session handler");
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
		                int argc, const char **argv)
{
	/* parse arguments */
	int ctrl = _pam_parse(argc, argv);
	if (ctrl & WINBIND_DEBUG_ARG)
		_pam_log(LOG_DEBUG,"libpam_winbind:pam_sm_close_session handler");
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t * pamh, int flags,
				int argc, const char **argv)
{
	unsigned int lctrl;
	int retval;
	unsigned int ctrl = _pam_parse(argc, argv);

	/* <DO NOT free() THESE> */
	const char *user;
	char *pass_old, *pass_new;
	/* </DO NOT free() THESE> */

	char *Announce;
	
	int retry = 0;

	/*
	 * First get the name of a user
	 */
	retval = pam_get_user(pamh, &user, "Username: ");
	if (retval == PAM_SUCCESS) {
		if (user == NULL) {
			_pam_log(LOG_ERR, "username was NULL!");
			return PAM_USER_UNKNOWN;
		}
		if (retval == PAM_SUCCESS && on(WINBIND_DEBUG_ARG, ctrl))
			_pam_log(LOG_DEBUG, "username [%s] obtained",
				 user);
	} else {
		if (on(WINBIND_DEBUG_ARG, ctrl))
			_pam_log(LOG_DEBUG,
				 "password - could not identify user");
		return retval;
	}

	/*
	 * obtain and verify the current password (OLDAUTHTOK) for
	 * the user.
	 */

	if (flags & PAM_PRELIM_CHECK) {
		
		/* instruct user what is happening */
#define greeting "Changing password for "
		Announce = (char *) malloc(sizeof(greeting) + strlen(user));
		if (Announce == NULL) {
		_pam_log(LOG_CRIT, 
			 "password - out of memory");
		return PAM_BUF_ERR;
		}
		(void) strcpy(Announce, greeting);
		(void) strcpy(Announce + sizeof(greeting) - 1, user);
#undef greeting
		
		lctrl = ctrl | WINBIND__OLD_PASSWORD;
		retval = _winbind_read_password(pamh, lctrl
						,Announce
						,"(current) NT password: "
						,NULL
						,(const char **) &pass_old);
		free(Announce);
		
		if (retval != PAM_SUCCESS) {
			_pam_log(LOG_NOTICE
				 ,"password - (old) token not obtained");
			return retval;
		}
		/* verify that this is the password for this user */
		
		retval = winbind_auth_request(user, pass_old, ctrl);
		
		if (retval != PAM_ACCT_EXPIRED 
		    && retval != PAM_NEW_AUTHTOK_REQD 
		    && retval != PAM_SUCCESS) {
			pass_old = NULL;
			return retval;
		}
		
		retval = pam_set_item(pamh, PAM_OLDAUTHTOK, (const void *) pass_old);
		pass_old = NULL;
		if (retval != PAM_SUCCESS) {
			_pam_log(LOG_CRIT, 
				 "failed to set PAM_OLDAUTHTOK");
		}
	} else if (flags & PAM_UPDATE_AUTHTOK) {
	
		/*
		 * obtain the proposed password
		 */
		
		/*
		 * get the old token back. 
		 */
		
		retval = pam_get_item(pamh, PAM_OLDAUTHTOK
				      ,(const void **) &pass_old);
		
		if (retval != PAM_SUCCESS) {
			_pam_log(LOG_NOTICE, "user not authenticated");
			return retval;
		}
		
		lctrl = ctrl;
		
		if (on(WINBIND_USE_AUTHTOK_ARG, lctrl)) {
			ctrl = WINBIND_USE_FIRST_PASS_ARG | lctrl;
		}
		retry = 0;
		retval = PAM_AUTHTOK_ERR;
		while ((retval != PAM_SUCCESS) && (retry++ < MAX_PASSWD_TRIES)) {
			/*
			 * use_authtok is to force the use of a previously entered
			 * password -- needed for pluggable password strength checking
			 */
			
			retval = _winbind_read_password(pamh, lctrl
							,NULL
							,"Enter new NT password: "
							,"Retype new NT password: "
							,(const char **) &pass_new);
			
			if (retval != PAM_SUCCESS) {
				if (on(WINBIND_DEBUG_ARG, ctrl)) {
					_pam_log(LOG_ALERT
						 ,"password - new password not obtained");
				}
				pass_old = NULL;/* tidy up */
				return retval;
			}

			/*
			 * At this point we know who the user is and what they
			 * propose as their new password. Verify that the new
			 * password is acceptable.
			 */
			
			if (pass_new[0] == '\0') {/* "\0" password = NULL */
				pass_new = NULL;
			}
		}
		
		/*
		 * By reaching here we have approved the passwords and must now
		 * rebuild the password database file.
		 */

		retval = winbind_chauthtok_request(user, pass_old, pass_new);
		_pam_overwrite(pass_new);
		_pam_overwrite(pass_old);
		pass_old = pass_new = NULL;
	} else {
		retval = PAM_SERVICE_ERR;
	}
	
	return retval;
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
 * Copyright (c) Andrew Tridgell  <tridge@samba.org>   2000
 * Copyright (c) Tim Potter       <tpot@samba.org>     2000
 * Copyright (c) Andrew Bartlettt <abartlet@samba.org> 2002
 * Copyright (c) Jan Rêkorajski 1999.
 * Copyright (c) Andrew G. Morgan 1996-8.
 * Copyright (c) Alex O. Yuriev, 1996.
 * Copyright (c) Cristian Gafton 1996.
 * Copyright (C) Elliot Lee <sopwith@redhat.com> 1996, Red Hat Software. 
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
