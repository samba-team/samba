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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#include "config.h"

#define ITEM_FILE_KEY	"item_file="

static const char *envs[] = {
#ifndef HAVE_OPENPAM
	"PAM_SERVICE",
#endif
	"PAM_USER",
	"PAM_USER_PROMPT",
	"PAM_TTY",
	"PAM_RUSER",
	"PAM_RHOST",
	"PAM_AUTHTOK",
	"PAM_OLDAUTHTOK",
#ifdef PAM_XDISPLAY
	"PAM_XDISPLAY",
#endif
#ifdef PAM_AUTHTOK_TYPE
	"PAM_AUTHTOK_TYPE",
#endif
	NULL
};

static const int items[] = {
#ifndef HAVE_OPENPAM
	PAM_SERVICE,
#endif
	PAM_USER,
	PAM_USER_PROMPT,
	PAM_TTY,
	PAM_RUSER,
	PAM_RHOST,
	PAM_AUTHTOK,
	PAM_OLDAUTHTOK,
#ifdef PAM_XDISPLAY
	PAM_XDISPLAY,
#endif
#ifdef PAM_AUTHTOK_TYPE
	PAM_AUTHTOK_TYPE,
#endif
};

static void pam_setitem_env(pam_handle_t *pamh)
{
	int i;
	int rv;
	const char *v;

	for (i = 0; envs[i] != NULL; i++) {
		v = getenv(envs[i]);
		if (v == NULL) {
			continue;
		}

		rv = pam_set_item(pamh, items[i], v);
		if (rv != PAM_SUCCESS) {
			continue;
		}
	}
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
		    int argc, const char *argv[])
{
	(void) flags;	/* unused */
	(void) argc;	/* unused */
	(void) argv;	/* unused */

	pam_setitem_env(pamh);
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	       int argc, const char *argv[])
{
	(void) flags;	/* unused */
	(void) argc;	/* unused */
	(void) argv;	/* unused */

	pam_setitem_env(pamh);
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		 int argc, const char *argv[])
{
	(void) flags;	/* unused */
	(void) argc;	/* unused */
	(void) argv;	/* unused */

	pam_setitem_env(pamh);
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, const char *argv[])
{
	(void) flags;	/* unused */
	(void) argc;	/* unused */
	(void) argv;	/* unused */

	pam_setitem_env(pamh);
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, const char *argv[])
{
	(void) flags;	/* unused */
	(void) argc;	/* unused */
	(void) argv;	/* unused */

	pam_setitem_env(pamh);
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		 int argc, const char *argv[])
{
	(void) flags;	/* unused */
	(void) argc;	/* unused */
	(void) argv;	/* unused */

	pam_setitem_env(pamh);
	return PAM_SUCCESS;
}

