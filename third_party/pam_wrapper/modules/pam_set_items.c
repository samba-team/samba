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
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#include "config.h"

/* GCC have printf type attribute check. */
#ifdef HAVE_FUNCTION_ATTRIBUTE_FORMAT
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* HAVE_FUNCTION_ATTRIBUTE_FORMAT */

/*****************
 * LOGGING
 *****************/

enum pwrap_dbglvl_e {
	PWRAP_LOG_ERROR = 0,
	PWRAP_LOG_WARN,
	PWRAP_LOG_DEBUG,
	PWRAP_LOG_TRACE
};

static void pwrap_log(enum pwrap_dbglvl_e dbglvl,
		      const char *function,
		      const char *format, ...) PRINTF_ATTRIBUTE(3, 4);
# define PWRAP_LOG(dbglvl, ...) pwrap_log((dbglvl), __func__, __VA_ARGS__)

static void pwrap_vlog(enum pwrap_dbglvl_e dbglvl,
		       const char *function,
		       const char *format,
		       va_list args) PRINTF_ATTRIBUTE(3, 0);

static void pwrap_vlog(enum pwrap_dbglvl_e dbglvl,
		       const char *function,
		       const char *format,
		       va_list args)
{
	char buffer[1024];
	const char *d;
	unsigned int lvl = 0;
	const char *prefix = "PWRAP";

	d = getenv("PAM_WRAPPER_DEBUGLEVEL");
	if (d != NULL) {
		lvl = atoi(d);
	}

	if (lvl < dbglvl) {
		return;
	}

	vsnprintf(buffer, sizeof(buffer), format, args);

	switch (dbglvl) {
	case PWRAP_LOG_ERROR:
		prefix = "PWRAP_ERROR";
		break;
	case PWRAP_LOG_WARN:
		prefix = "PWRAP_WARN";
		break;
	case PWRAP_LOG_DEBUG:
		prefix = "PWRAP_DEBUG";
		break;
	case PWRAP_LOG_TRACE:
		prefix = "PWRAP_TRACE";
		break;
	}

	fprintf(stderr,
		"%s(%d) - PAM_SET_ITEM %s: %s\n",
		prefix,
		(int)getpid(),
		function,
		buffer);
}

static void pwrap_log(enum pwrap_dbglvl_e dbglvl,
		      const char *function,
		      const char *format, ...)
{
	va_list va;

	va_start(va, format);
	pwrap_vlog(dbglvl, function, format, va);
	va_end(va);
}

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

		PWRAP_LOG(PWRAP_LOG_TRACE, "%s=%s", envs[i], v);

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

	PWRAP_LOG(PWRAP_LOG_TRACE, "AUTHENTICATE");

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

	PWRAP_LOG(PWRAP_LOG_TRACE, "SETCRED");

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

	PWRAP_LOG(PWRAP_LOG_TRACE, "ACCT_MGMT");

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

	PWRAP_LOG(PWRAP_LOG_TRACE, "OPEN_SESSION");

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

	PWRAP_LOG(PWRAP_LOG_TRACE, "CLOSE_SESSION");

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

	PWRAP_LOG(PWRAP_LOG_TRACE, "CHAUTHTOK");

	pam_setitem_env(pamh);
	return PAM_SUCCESS;
}
