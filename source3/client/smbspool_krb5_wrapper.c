/*
 * Unix SMB/CIFS implementation.
 *
 * CUPS printing backend helper to execute smbspool
 *
 * Copyright (C) 2010-2011 Andreas Schneider <asn@samba.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#include "includes.h"
#include "system/filesys.h"
#include "system/kerberos.h"
#include "system/passwd.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <cups/backend.h>

#include "dynconfig/dynconfig.h"

#undef calloc

enum cups_smb_dbglvl_e {
	CUPS_SMB_LOG_DEBUG = 0,
	CUPS_SMB_LOG_ERROR,
};
static void cups_smb_debug(enum cups_smb_dbglvl_e lvl, const char *format, ...)
		PRINTF_ATTRIBUTE(2, 3);

#define CUPS_SMB_DEBUG(...) cups_smb_debug(CUPS_SMB_LOG_DEBUG, __VA_ARGS__)
#define CUPS_SMB_ERROR(...) cups_smb_debug(CUPS_SMB_LOG_DEBUG, __VA_ARGS__)

static void cups_smb_debug(enum cups_smb_dbglvl_e lvl, const char *format, ...)
{
	const char *prefix = "DEBUG";
	char buffer[1024];
	va_list va;

	va_start(va, format);
	vsnprintf(buffer, sizeof(buffer), format, va);
	va_end(va);

	switch (lvl) {
	case CUPS_SMB_LOG_DEBUG:
		prefix = "DEBUG";
		break;
	case CUPS_SMB_LOG_ERROR:
		prefix = "ERROR";
		break;
	}

	fprintf(stderr,
		"%s: SMBSPOOL_KRB5 - %s\n",
		prefix,
		buffer);
}

static bool kerberos_get_default_ccache(char *ccache_buf, size_t len)
{
	krb5_context ctx;
	const char *ccache_name = NULL;
	char *full_ccache_name = NULL;
	krb5_ccache ccache = NULL;
	krb5_error_code code;

	code = krb5_init_context(&ctx);
	if (code != 0) {
		return false;
	}

	ccache_name = krb5_cc_default_name(ctx);
	if (ccache_name == NULL) {
		krb5_free_context(ctx);
		return false;
	}

	code = krb5_cc_resolve(ctx, ccache_name, &ccache);
	if (code != 0) {
		krb5_free_context(ctx);
		return false;
	}

	code = krb5_cc_get_full_name(ctx, ccache, &full_ccache_name);
	krb5_cc_close(ctx, ccache);
	if (code != 0) {
		krb5_free_context(ctx);
		return false;
	}

	snprintf(ccache_buf, len, "%s", full_ccache_name);

#ifdef SAMBA4_USES_HEIMDAL
	free(full_ccache_name);
#else
	krb5_free_string(ctx, full_ccache_name);
#endif
	krb5_free_context(ctx);

	return true;
}

/*
 * This is a helper binary to execute smbspool.
 *
 * It needs to be installed or symlinked as:
 *      /usr/lib/cups/backend/smb
 *
 * The permissions of the binary need to be set to 0700 so that it is executed
 * as root. The binary switches to the user which is passed via the environment
 * variable AUTH_UID, so we can access the kerberos ticket.
 */
int main(int argc, char *argv[])
{
	char smbspool_cmd[PATH_MAX] = {0};
	struct passwd *pwd;
	struct group *g = NULL;
	char gen_cc[PATH_MAX] = {0};
	char *env = NULL;
	char auth_info_required[256] = {0};
	char device_uri[4096] = {0};
	uid_t uid = (uid_t)-1;
	gid_t gid = (gid_t)-1;
	gid_t groups[1] = { (gid_t)-1 };
	unsigned long tmp;
	bool ok;
	int cmp;
	int rc;

	env = getenv("DEVICE_URI");
	if (env != NULL && strlen(env) > 2) {
		snprintf(device_uri, sizeof(device_uri), "%s", env);
	}

	/* We must handle the following values of AUTH_INFO_REQUIRED:
	 *  none: Anonymous/guest printing
	 *  username,password: A username (of the form "username" or "DOMAIN\username")
	 *                     and password are required
	 *  negotiate: Kerberos authentication
	 *  NULL (not set): will never happen when called from cupsd
	 * https://www.cups.org/doc/spec-ipp.html#auth-info-required
	 * https://github.com/apple/cups/issues/5674
	 */
	env = getenv("AUTH_INFO_REQUIRED");

        /* If not set, then just call smbspool. */
	if (env == NULL || env[0] == 0) {
		CUPS_SMB_DEBUG("AUTH_INFO_REQUIRED is not set - "
			       "executing smbspool");
		/* Pass this printing task to smbspool without Kerberos auth */
		goto smbspool;
	} else {
		CUPS_SMB_DEBUG("AUTH_INFO_REQUIRED=%s", env);

		/* First test the value of AUTH_INFO_REQUIRED
		 * against known possible values
		 */
		cmp = strcmp(env, "none");
		if (cmp == 0) {
			CUPS_SMB_DEBUG("Authenticate using none (anonymous) - "
				       "executing smbspool");
			goto smbspool;
		}

		cmp = strcmp(env, "username,password");
		if (cmp == 0) {
			CUPS_SMB_DEBUG("Authenticate using username/password - "
				       "executing smbspool");
			goto smbspool;
		}

		/* Now, if 'goto smbspool' still has not happened,
		 * there are only two variants left:
		 * 1) AUTH_INFO_REQUIRED is "negotiate" and then
		 *    we have to continue working
		 * 2) or it is something not known to us, then Kerberos
		 *    authentication is not required, so just also pass
		 *    this task to smbspool
		 */
		cmp = strcmp(env, "negotiate");
		if (cmp != 0) {
			CUPS_SMB_DEBUG("Value of AUTH_INFO_REQUIRED is not known "
				       "to smbspool_krb5_wrapper, executing smbspool");
			goto smbspool;
		}

		snprintf(auth_info_required,
			 sizeof(auth_info_required),
			 "%s",
			 env);
	}

	uid = getuid();

	CUPS_SMB_DEBUG("Started with uid=%d\n", uid);
	if (uid != 0) {
		goto smbspool;
	}

	/*
	 * AUTH_UID gets only set if we have an incoming connection over the
	 * CUPS unix domain socket.
	 */
	env = getenv("AUTH_UID");
	if (env == NULL) {
		CUPS_SMB_ERROR("AUTH_UID is not set");
		fprintf(stderr, "ATTR: auth-info-required=negotiate\n");
		return CUPS_BACKEND_AUTH_REQUIRED;
	}

	if (strlen(env) > 10) {
		CUPS_SMB_ERROR("Invalid AUTH_UID");
		return CUPS_BACKEND_FAILED;
	}

	errno = 0;
	tmp = strtoul(env, NULL, 10);
	if (errno != 0 || tmp >= UINT32_MAX) {
		CUPS_SMB_ERROR("Failed to convert AUTH_UID=%s", env);
		return CUPS_BACKEND_FAILED;
	}
	uid = (uid_t)tmp;

	/* If we are printing as the root user, we're done here. */
	if (uid == 0) {
		goto smbspool;
	}

	pwd = getpwuid(uid);
	if (pwd == NULL) {
		CUPS_SMB_ERROR("Failed to find system user: %u - %s",
			       uid, strerror(errno));
		return CUPS_BACKEND_FAILED;
	}
	gid = pwd->pw_gid;

	rc = setgroups(0, NULL);
	if (rc != 0) {
		CUPS_SMB_ERROR("Failed to clear groups - %s",
			       strerror(errno));
		return CUPS_BACKEND_FAILED;
	}

	/*
	 * We need the primary group of the 'lp' user. This is needed to access
	 * temporary files in /var/spool/cups/.
	 */
	g = getgrnam("lp");
	if (g == NULL) {
		CUPS_SMB_ERROR("Failed to find user 'lp' - %s",
			       strerror(errno));
		return CUPS_BACKEND_FAILED;
	}

	CUPS_SMB_DEBUG("Adding group 'lp' (%u)", g->gr_gid);
	groups[0] = g->gr_gid;
	rc = setgroups(sizeof(groups), groups);
	if (rc != 0) {
		CUPS_SMB_ERROR("Failed to set groups for 'lp' - %s",
			       strerror(errno));
		return CUPS_BACKEND_FAILED;
	}

	CUPS_SMB_DEBUG("Switching to gid=%d", gid);
	rc = setgid(gid);
	if (rc != 0) {
		CUPS_SMB_ERROR("Failed to switch to gid=%u - %s",
			       gid,
			       strerror(errno));
		return CUPS_BACKEND_FAILED;
	}

	CUPS_SMB_DEBUG("Switching to uid=%u", uid);
	rc = setuid(uid);
	if (rc != 0) {
		CUPS_SMB_ERROR("Failed to switch to uid=%u - %s",
			       uid,
			       strerror(errno));
		return CUPS_BACKEND_FAILED;
	}

	env = getenv("KRB5CCNAME");
	if (env != NULL && env[0] != 0) {
		snprintf(gen_cc, sizeof(gen_cc), "%s", env);
		CUPS_SMB_DEBUG("User already set KRB5CCNAME [%s] as ccache",
			       gen_cc);

		goto create_env;
	}

	ok = kerberos_get_default_ccache(gen_cc, sizeof(gen_cc));
	if (ok) {
		CUPS_SMB_DEBUG("Use default KRB5CCNAME [%s]",
			       gen_cc);
		goto create_env;
	}

	/* Fallback to a FILE ccache */
	snprintf(gen_cc, sizeof(gen_cc), "FILE:/tmp/krb5cc_%u", uid);

create_env:
	/*
	 * Make sure we do not have LD_PRELOAD or other security relevant
	 * environment variables set.
	 */
#ifdef HAVE_CLEARENV
	clearenv();
#else
	{
		extern char **environ;
		environ = calloc(3, sizeof(*environ));
	}
#endif

	CUPS_SMB_DEBUG("Setting KRB5CCNAME to '%s'", gen_cc);
	setenv("KRB5CCNAME", gen_cc, 1);
	if (device_uri[0] != '\0') {
		setenv("DEVICE_URI", device_uri, 1);
	}
	if (auth_info_required[0] != '\0') {
		setenv("AUTH_INFO_REQUIRED", auth_info_required, 1);
	}

smbspool:
	snprintf(smbspool_cmd,
		 sizeof(smbspool_cmd),
		 "%s/smbspool",
		 get_dyn_BINDIR());

	return execv(smbspool_cmd, argv);
}
