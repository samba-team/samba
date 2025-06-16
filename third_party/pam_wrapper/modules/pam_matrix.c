/*
 * Copyright (c) 2015 Andreas Schneider <asn@samba.org>
 * Copyright (c) 2015 Jakub Hrozek <jakub.hrozek@posteo.se>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#ifndef discard_const_p
#define discard_const_p(type, ptr) ((type *)discard_const(ptr))
#endif

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif
#ifdef HAVE_SECURITY_PAM_EXT_H
#include <security/pam_ext.h>
#endif

#include "pwrap_compat.h"

#define HOME_VAR	"HOMEDIR"
#define HOME_VAR_SZ	sizeof(HOME_VAR)-1

#define CRED_VAR	"CRED"
#define CRED_VAR_SZ	sizeof(CRED_VAR)-1

#define PAM_EXAMPLE_AUTH_DATA	    "pam_matrix:auth_data"

#define PASSDB_KEY	"passdb="
#define VERBOSE_KEY	"verbose"
#define ECHO_KEY	"echo"

#define PAM_MATRIX_FLG_VERBOSE	(1 << 0)
#define PAM_MATRIX_FLG_ECHO	(1 << 1)

#define MAX_AUTHTOK_SIZE 1024

/* Walks over the key until a colon (:) is find
 */
#define NEXT_KEY(buf, key) do {					\
	(key) = (buf) ? strpbrk((buf), ":") : NULL;		\
	if ((key) != NULL) {					\
		(key)[0] = '\0';				\
		(key)++;					\
	}							\
	while ((key) != NULL					\
		&& (isblank((int)(key)[0]))) {			\
		(key)++;					\
	}							\
} while(0);

#define wipe_authtok(tok) do {		\
	if (tok != NULL) {		\
		char *__tk = tok;	\
		while(*__tk != '\0') {	\
			*__tk = '\0';	\
		}			\
	}				\
} while(0);

struct pam_lib_items {
	const char *username;
	const char *service;
	char *password;
};

struct pam_matrix_mod_items {
	char *password;
	char *service;
};

struct pam_matrix_ctx {
	const char *passdb;
	int flags;

	struct pam_lib_items pli;
	struct pam_matrix_mod_items pmi;
};

/* Search the passdb for user entry and fill his info into pmi */
static int pam_matrix_mod_items_get(const char *db,
				    const char *username,
				    struct pam_matrix_mod_items *pmi)
{
	int rv;
	FILE *fp = NULL;
	char buf[BUFSIZ];
	char *file_user = NULL;
	char *file_password = NULL;
	char *file_svc = NULL;

	fp = fopen(db, "r");
	if (fp == NULL) {
		rv = errno;
		goto fail;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *q;

		/* Find the user, his password and allowed service */
		file_user = buf;
		file_password = NULL;

		/* Skip comments */
		if (file_user[0] == '#') {
			continue;
		}

		NEXT_KEY(file_user, file_password);
		NEXT_KEY(file_password, file_svc);

		q = file_svc;
		while(q[0] != '\n' && q[0] != '\0') {
			q++;
		}
		q[0] = '\0';

		if (file_password == NULL) {
			continue;
		}

		if (strcmp(file_user, username) == 0) {
			pmi->password = strdup(file_password);
			if (pmi->password == NULL) {
				rv = errno;
				goto fail;
			}

			pmi->service = strdup(file_svc);
			if (pmi->service == NULL) {
				rv = errno;
				goto fail;
			}

			break;
		}
	}

	fclose(fp);
	return 0;

fail:
	free(pmi->password);
	free(pmi->service);
	if (fp) {
		fclose(fp);
	}
	return rv;
}

/* Replace authtok of user in the database with the one from pli */
static int pam_matrix_lib_items_put(const char *db,
				    struct pam_lib_items *pli)
{
	int rv;
	mode_t old_mask;
	FILE *fp = NULL;
	FILE *fp_tmp = NULL;
	char buf[BUFSIZ];
	char template[PATH_MAX] = { '\0' };
	char *file_user = NULL;
	char *file_password = NULL;
	char *file_svc = NULL;

	rv = snprintf(template, sizeof(template),
		      "%s.XXXXXX", db);
	if (rv <= 0) {
		rv = PAM_BUF_ERR;
		goto done;
	}

	/* We don't support concurrent runs.. */
	old_mask = umask(S_IRWXO | S_IRWXG);
	rv = mkstemp(template);
	umask(old_mask);
	if (rv <= 0) {
		rv = PAM_BUF_ERR;
		goto done;
	}

	fp = fopen(db, "r");
	fp_tmp = fopen(template, "w");
	if (fp == NULL || fp_tmp == NULL) {
		rv = errno;
		goto done;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *q;

		file_user = buf;
		file_password = NULL;

		/* Skip comments */
		if (file_user[0] == '#') {
			continue;
		}

		/* Find the user, his password and allowed service */
		NEXT_KEY(file_user, file_password);
		NEXT_KEY(file_password, file_svc);

		q = file_svc;
		while(q[0] != '\n' && q[0] != '\0') {
			q++;
		}
		q[0] = '\0';

		if (file_password == NULL) {
			continue;
		}

		if (strcmp(file_user, pli->username) == 0) {
			if (pli->password) {
				file_password = pli->password;
			}
		}

		rv = fprintf(fp_tmp, "%s:%s:%s\n",
			     file_user, file_password, file_svc);
		if (rv < 0) {
			rv = PAM_CRED_ERR;
			goto done;
		}
	}

	rv = PAM_SUCCESS;
done:
	if (fp != NULL) {
		fclose(fp);
	}
	if (fp_tmp != NULL) {
		fflush(fp_tmp);
		fclose(fp_tmp);
	}

	if (rv == PAM_SUCCESS) {
		rv = rename(template, db);
		if (rv == -1) {
			rv = PAM_SYSTEM_ERR;
		}
	}

	if (template[0] != '\0') {
		unlink(template);
	};
	return rv;
}

static void pam_matrix_mod_items_free(struct pam_matrix_mod_items *pmi)
{
	if (pmi == NULL) {
		return;
	}

	free(pmi->password);
	free(pmi->service);
}

static int pam_matrix_conv(pam_handle_t *pamh,
			   const int msg_style,
			   const char *msg,
			   char **answer)
{
	int ret;
	const struct pam_conv *conv;
	const struct pam_message *mesg[1];
	struct pam_response *resp = NULL;
	struct pam_response **r = NULL;
	struct pam_message *pam_msg;

	ret = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
	if (ret != PAM_SUCCESS) {
		return ret;
	}

	pam_msg = malloc(sizeof(struct pam_message));
	if (pam_msg == NULL) {
		return PAM_BUF_ERR;
	}

	pam_msg->msg_style = msg_style;
	pam_msg->msg = discard_const_p(char, msg);

	if (msg_style == PAM_PROMPT_ECHO_ON ||
	    msg_style == PAM_PROMPT_ECHO_OFF) {
		r = &resp;
	}

	mesg[0] = (const struct pam_message *) pam_msg;
	ret = conv->conv(1, mesg, r, conv->appdata_ptr);
	free(pam_msg);
	if (ret != PAM_SUCCESS) {
		free(resp);
		return ret;
	}

	if (msg_style == PAM_PROMPT_ECHO_OFF ||
	    msg_style == PAM_PROMPT_ECHO_ON) {
		if (resp == NULL) {
			/* Response expected, but none find! */
			return PAM_SYSTEM_ERR;
		}

		if (resp[0].resp == NULL) {
			/* Empty password */
			*answer = NULL;
			free(resp);
			return PAM_SUCCESS;
		}

		*answer = strndup(resp[0].resp, MAX_AUTHTOK_SIZE);
		wipe_authtok(resp[0].resp);
		free(resp[0].resp);
		free(resp);
		if (*answer == NULL) {
			return PAM_BUF_ERR;
		}
	}

	return PAM_SUCCESS;
}

/* Read user password. If both prompts are provided, then ask twice and
 * assert that both passwords match.
 *
 * The authtok would be returned in _out_tok if needed and set in
 * authtok_item as well
 */
static int pam_matrix_read_password(pam_handle_t *pamh,
				     int flags,
				     int authtok_item,
				     const char *prompt1,
				     const char *prompt2,
				     const void **_out_tok)
{
	int rv = PAM_AUTHTOK_RECOVERY_ERR;
	char *authtok1 = NULL;
	char *authtok2 = NULL;
	const void *item;
	int read_flg = PAM_PROMPT_ECHO_OFF;

	if (flags & PAM_MATRIX_FLG_ECHO) {
		read_flg = PAM_PROMPT_ECHO_ON;
	}

	rv = pam_matrix_conv(pamh, read_flg, prompt1, &authtok1);
	if (authtok1 == NULL) {
		goto done;
	}

	if (rv == PAM_SUCCESS && prompt2 != NULL) {
		rv = pam_matrix_conv(pamh, read_flg,
				     prompt2, &authtok2);
		if (rv != PAM_SUCCESS) {
			goto done;
		}

		if (authtok2 == NULL) {
			rv = PAM_AUTHTOK_RECOVERY_ERR;
			goto done;
		}

		if (strcmp(authtok1, authtok2) != 0) {
			pam_matrix_conv(pamh, PAM_ERROR_MSG,
					"Passwords do not match",
					NULL);
			rv = PAM_AUTHTOK_RECOVERY_ERR;
			goto done;
		}
		wipe_authtok(authtok2);
		free(authtok2);
		authtok2 = NULL;
	}

	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = pam_set_item(pamh, authtok_item, authtok1);
	wipe_authtok(authtok1);
	free(authtok1);
	authtok1 = NULL;
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = pam_get_item(pamh, authtok_item, &item);
	if (_out_tok) {
		*_out_tok = item;
	}
	item = NULL;
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = PAM_SUCCESS;
done:
	wipe_authtok(authtok1);
	wipe_authtok(authtok2);
	return rv;
}

/* Retrieve user info -- username and service that were provided by
 * pam_start */
static int pam_lib_items_get(pam_handle_t *pamh,
			     struct pam_lib_items *pli)
{
	int rv;

	rv = pam_get_item(pamh, PAM_USER, (const void **) &(pli->username));
	if (rv != PAM_SUCCESS) {
		return rv;
	}

	if (pli->username == NULL) {
		return PAM_BAD_ITEM;
	}

	rv = pam_get_item(pamh, PAM_SERVICE, (const void **) &(pli->service));
	if (rv != PAM_SUCCESS) {
		return rv;
	}

	return PAM_SUCCESS;
}

/* Evaluate command line arguments and store info about them in the
 * pam_matrix context
 */
static void eval_args(struct pam_matrix_ctx *pe_ctx,
		      int argc,
		      const char *argv[])
{
	pe_ctx->flags = 0;

	for (; argc-- > 0; ++argv) {
		if (strncmp(*argv, PASSDB_KEY, strlen(PASSDB_KEY)) == 0) {
			if (*(*argv+strlen(PASSDB_KEY)) == '\0') {
				pe_ctx->passdb = NULL;
			} else {
				pe_ctx->passdb = *argv+strlen(PASSDB_KEY);
			}
		} else if (strncmp(*argv, VERBOSE_KEY,
				   strlen(VERBOSE_KEY)) == 0) {
			pe_ctx->flags |= PAM_MATRIX_FLG_VERBOSE;
		} else if (strncmp(*argv, ECHO_KEY,
				   strlen(ECHO_KEY)) == 0) {
			pe_ctx->flags |= PAM_MATRIX_FLG_ECHO;
		}
	}
}

/* Retrieve info about the user who is logging in and find his
 * record in the database
 */
static int pam_matrix_get(pam_handle_t *pamh,
			  int argc,
			  const char *argv[],
			  struct pam_matrix_ctx *pe_ctx)
{
    int rv;

    eval_args(pe_ctx, argc, argv);

    /* If no db is provided as argument, fall back to environment variable */
    if (pe_ctx->passdb == NULL) {
	pe_ctx->passdb = getenv("PAM_MATRIX_PASSWD");
	if (pe_ctx->passdb == NULL) {
		return PAM_AUTHINFO_UNAVAIL;
	}
    }


    rv = pam_lib_items_get(pamh, &pe_ctx->pli);
    if (rv != PAM_SUCCESS) {
		return rv;
    }

    rv = pam_matrix_mod_items_get(pe_ctx->passdb,
				  pe_ctx->pli.username,
				  &pe_ctx->pmi);
    if (rv != PAM_SUCCESS) {
		return PAM_AUTHINFO_UNAVAIL;
    }

    return PAM_SUCCESS;
}

static void pam_matrix_free(struct pam_matrix_ctx *pe_ctx)
{
	pam_matrix_mod_items_free(&pe_ctx->pmi);
}

static int _pam_matrix_auth(struct pam_matrix_ctx *pctx)
{
	int rv = PAM_AUTH_ERR;

	if (pctx->pli.password == NULL) {
		/* NULL passwords are not allowed */
		return PAM_CRED_ERR;
	}

	if (pctx->pli.password != NULL &&
	    pctx->pmi.password != NULL &&
	    strcmp(pctx->pli.password, pctx->pmi.password) == 0) {
		rv = PAM_SUCCESS;
	}

	return rv;
}

static int pam_matrix_auth(pam_handle_t *pamh, struct pam_matrix_ctx *pctx)
{
	int rv = PAM_AUTH_ERR;

	rv = _pam_matrix_auth(pctx);

	wipe_authtok(pctx->pli.password);
	wipe_authtok(pctx->pmi.password);

	if (pctx->flags & PAM_MATRIX_FLG_VERBOSE) {
		if (rv == PAM_SUCCESS) {
			pam_matrix_conv(pamh,
					PAM_TEXT_INFO,
					"Authentication succeeded",
					NULL);
		} else {
			pam_matrix_conv(pamh,
					PAM_ERROR_MSG,
					"Authentication failed",
					NULL);
		}
	}

	return rv;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
		    int argc, const char *argv[])
{
	struct pam_matrix_ctx pctx;
	const void *pwd = NULL;
	int rv;

	(void) flags; /* unused */

	memset(&pctx, 0, sizeof(struct pam_matrix_ctx));

	/* Search the user info in database */
	rv = pam_matrix_get(pamh, argc, argv, &pctx);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = pam_matrix_read_password(pamh, pctx.flags, PAM_AUTHTOK, "Password: ",
				      NULL, &pwd);
	if (rv != PAM_SUCCESS) {
		rv = PAM_AUTHINFO_UNAVAIL;
		goto done;
	}
	pctx.pli.password = discard_const(pwd);

	/* Auth and get rid of the authtok */
	rv = pam_matrix_auth(pamh, &pctx);
done:
	pam_matrix_free(&pctx);
	return rv;
}

/* Really silly setcred function that just sets a pam environment variable */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	       int argc, const char *argv[])
{
	struct pam_matrix_ctx pctx;
	int rv;
	char cred[PATH_MAX + CRED_VAR_SZ];

	(void) flags; /* unused */

	memset(&pctx, 0, sizeof(struct pam_matrix_ctx));

	rv = pam_matrix_get(pamh, argc, argv, &pctx);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = snprintf(cred, sizeof(cred),
		      "%s=/tmp/%s",
		      CRED_VAR, pctx.pli.username);
	if (rv <= 0) {
		rv = PAM_BUF_ERR;
		goto done;
	}

	rv = pam_putenv(pamh, cred);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = PAM_SUCCESS;
done:
	pam_matrix_free(&pctx);
	return rv;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		 int argc, const char *argv[])
{
	struct pam_matrix_ctx pctx;
	int rv;

	(void) flags; /* unused */

	memset(&pctx, 0, sizeof(struct pam_matrix_ctx));

	/* Search the user info in database */
	rv = pam_matrix_get(pamh, argc, argv, &pctx);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	/* Check if the allowed service matches the PAM service */
	if (pctx.pli.service != NULL &&
	    pctx.pmi.service != NULL &&
	    strcmp(pctx.pli.service, pctx.pmi.service) == 0) {
		rv = PAM_SUCCESS;
		goto done;
	}

	rv = PAM_PERM_DENIED;
done:
	pam_matrix_free(&pctx);
	return rv;
}

/* Really silly session function that just sets a pam environment variable */
PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, const char *argv[])
{
	struct pam_matrix_ctx pctx;
	int rv;
	char home[PATH_MAX + HOME_VAR_SZ];

	(void) flags; /* unused */

	memset(&pctx, 0, sizeof(struct pam_matrix_ctx));

	rv = pam_matrix_get(pamh, argc, argv, &pctx);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = snprintf(home, sizeof(home),
		      "%s=/home/%s",
		      HOME_VAR, pctx.pli.username);
	if (rv <= 0) {
		rv = PAM_BUF_ERR;
		goto done;
	}

	rv = pam_putenv(pamh, home);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = PAM_SUCCESS;
done:
	pam_matrix_free(&pctx);
	return rv;
}

/* Just unsets whatever session set */
PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, const char *argv[])
{
	struct pam_matrix_ctx pctx;
	int rv;

	(void) flags; /* unused */

	memset(&pctx, 0, sizeof(struct pam_matrix_ctx));

	rv = pam_matrix_get(pamh, argc, argv, &pctx);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

#if HAVE_OPENPAM
	/* OpenPAM does not support unsetting variable, set it to
	 * and empty string instead
	 */
	rv = pam_putenv(pamh, HOME_VAR"=");
#else
	rv = pam_putenv(pamh, HOME_VAR);
#endif
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = PAM_SUCCESS;
done:
	pam_matrix_free(&pctx);
	return rv;
}

static void pam_matrix_stamp_destructor(pam_handle_t *pamh,
					 void *data,
					 int error_status)
{
	(void) pamh;		/* unused */
	(void) error_status;	/* unused */

	free(data);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		 int argc, const char *argv[])
{
	struct pam_matrix_ctx pctx;
	const char *old_pass;
	const void *pwd = NULL;
	int rv;
	time_t *auth_stamp = NULL;
	const time_t *auth_stamp_out = NULL;

	(void) flags; /* unused */

	memset(&pctx, 0, sizeof(struct pam_matrix_ctx));

	rv = pam_matrix_get(pamh, argc, argv, &pctx);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	if (flags & PAM_PRELIM_CHECK) {
		rv = pam_matrix_read_password(
					pamh, pctx.flags, PAM_OLDAUTHTOK,
					"Old password: ", NULL,
					&pwd);
		if (rv != PAM_SUCCESS) {
			rv = PAM_AUTHINFO_UNAVAIL;
			goto done;
		}
		pctx.pli.password = discard_const(pwd);

		auth_stamp = malloc(sizeof(time_t));
		if (auth_stamp == NULL) {
			rv = PAM_BUF_ERR;
			goto done;
		}
		*auth_stamp = time(NULL);

		/* Not really useful, just test that between the two phases,
		 * data can be passed
		 */
		rv = pam_set_data(pamh, PAM_EXAMPLE_AUTH_DATA,
				auth_stamp, pam_matrix_stamp_destructor);
		if (rv != PAM_SUCCESS) {
			goto done;
		}

		rv = pam_matrix_auth(pamh, &pctx);
	} else if (flags & PAM_UPDATE_AUTHTOK) {
		rv = pam_get_item(pamh,
				  PAM_OLDAUTHTOK,
				  (const void **) &old_pass);
		if (rv != PAM_SUCCESS || old_pass == NULL) {
			rv = PAM_AUTHINFO_UNAVAIL;
			goto done;
		}


		rv = pam_get_data(pamh, PAM_EXAMPLE_AUTH_DATA,
				  (const void **) &auth_stamp_out);
		if (rv != PAM_SUCCESS) {
			goto done;
		}

		rv = pam_matrix_read_password(pamh,
					pctx.flags,
					PAM_AUTHTOK,
					"New Password :",
					"Verify New Password :",
					&pwd);
		if (rv != PAM_SUCCESS) {
			rv = PAM_AUTHINFO_UNAVAIL;
			goto done;
		}
		pctx.pli.password = discard_const(pwd);

		/* Write the new password to the db */
		rv = pam_matrix_lib_items_put(pctx.passdb, &pctx.pli);
	} else {
		rv = PAM_SYSTEM_ERR;
	}

done:
	pam_matrix_free(&pctx);
	return rv;
}
