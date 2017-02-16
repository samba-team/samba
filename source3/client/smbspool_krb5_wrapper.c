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
static void cups_smb_debug(enum cups_smb_dbglvl_e lvl, const char *format, ...);

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
	char gen_cc[PATH_MAX] = {0};
	struct stat sb;
	char *env;
	uid_t uid = (uid_t)-1;
	gid_t gid = (gid_t)-1;
	unsigned long tmp;
	int cmp;
	int rc;

	/* Check if AuthInfoRequired is set to negotiate */
	env = getenv("AUTH_INFO_REQUIRED");

        /* If not set, then just call smbspool. */
	if (env == NULL) {
		CUPS_SMB_ERROR("AUTH_INFO_REQUIRED is not set");
                goto smbspool;
	} else {
                CUPS_SMB_DEBUG("AUTH_INFO_REQUIRED=%s", env);
                cmp = strcmp(env, "negotiate");
                /* If AUTH_INFO_REQUIRED != "negotiate" then call smbspool. */
                if (cmp != 0) {
                          CUPS_SMB_ERROR(
                            "AUTH_INFO_REQUIRED is not set to negotiate");
                          goto smbspool;
                }
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

	CUPS_SMB_DEBUG("Switching to gid=%d", gid);
	rc = setgid(gid);
	if (rc != 0) {
		CUPS_SMB_ERROR("Failed to switch to gid=%u",
			       gid,
			       strerror(errno));
		return CUPS_BACKEND_FAILED;
	}

	CUPS_SMB_DEBUG("Switching to uid=%u", uid);
	rc = setuid(uid);
	if (rc != 0) {
		CUPS_SMB_ERROR("Failed to switch to uid=%u",
			       uid,
			       strerror(errno));
		return CUPS_BACKEND_FAILED;
	}

	snprintf(gen_cc, sizeof(gen_cc), "/tmp/krb5cc_%d", uid);

	rc = lstat(gen_cc, &sb);
	if (rc == 0) {
		snprintf(gen_cc, sizeof(gen_cc), "FILE:/tmp/krb5cc_%d", uid);
	} else {
		snprintf(gen_cc, sizeof(gen_cc), "/run/user/%d/krb5cc", uid);

		rc = lstat(gen_cc, &sb);
		if (rc == 0 && S_ISDIR(sb.st_mode)) {
			snprintf(gen_cc,
				 sizeof(gen_cc),
				 "DIR:/run/user/%d/krb5cc",
				 uid);
		} else {
#if defined(__linux__)
			snprintf(gen_cc,
				 sizeof(gen_cc),
				 "KEYRING:persistent:%d",
				 uid);
#endif
		}
	}

	/*
	 * Make sure we do not have LD_PRELOAD or other security relevant
	 * environment variables set.
	 */
#ifdef HAVE_CLEARENV
	clearenv();
#else
	{
		extern char **environ;
		environ = calloc(1, sizeof(*environ));
	}
#endif

	CUPS_SMB_DEBUG("Setting KRB5CCNAME to '%s'", gen_cc);
	setenv("KRB5CCNAME", gen_cc, 1);

smbspool:
	snprintf(smbspool_cmd,
		 sizeof(smbspool_cmd),
		 "%s/smbspool",
		 get_dyn_BINDIR());

	return execv(smbspool_cmd, argv);
}
