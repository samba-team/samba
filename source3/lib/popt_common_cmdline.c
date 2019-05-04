/*
   Unix SMB/CIFS implementation.
   Common popt routines only used by cmdline utils

   Copyright (C) Tim Potter 2001,2002
   Copyright (C) Jelmer Vernooij 2002,2003
   Copyright (C) James Peach 2006
   Copyright (C) Christof Schmitt 2018

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Handle command line options:
 *		-U,--user
 *		-A,--authentication-file
 *		-k,--use-kerberos
 *		-N,--no-pass
 *		-S,--signing
 *		-P --machine-pass
 *		-e --encrypt
 *		-C --use-ccache
 */

#include "popt_common_cmdline.h"
#include "includes.h"
#include "auth_info.h"
#include "cmdline_contexts.h"

static struct user_auth_info *cmdline_auth_info;

struct user_auth_info *popt_get_cmdline_auth_info(void)
{
	return cmdline_auth_info;
}
void popt_free_cmdline_auth_info(void)
{
	TALLOC_FREE(cmdline_auth_info);
}

static bool popt_common_credentials_ignore_missing_conf;
static bool popt_common_credentials_delay_post;

void popt_common_credentials_set_ignore_missing_conf(void)
{
	popt_common_credentials_ignore_missing_conf = true;
}

void popt_common_credentials_set_delay_post(void)
{
	popt_common_credentials_delay_post = true;
}

void popt_common_credentials_post(void)
{
	if (get_cmdline_auth_info_use_machine_account(cmdline_auth_info) &&
	    !set_cmdline_auth_info_machine_account_creds(cmdline_auth_info))
	{
		fprintf(stderr,
			"Failed to use machine account credentials\n");
		exit(1);
	}

	set_cmdline_auth_info_getpass(cmdline_auth_info);

	/*
	 * When we set the username during the handling of the options passed to
	 * the binary we haven't loaded the config yet. This means that we
	 * didn't take the 'winbind separator' into account.
	 *
	 * The username might contain the domain name and thus it hasn't been
	 * correctly parsed yet. If we have a username we need to set it again
	 * to run the string parser for the username correctly.
	 */
	reset_cmdline_auth_info_username(cmdline_auth_info);
}

static void popt_common_credentials_callback(poptContext con,
					enum poptCallbackReason reason,
					const struct poptOption *opt,
					const char *arg, const void *data)
{
	if (reason == POPT_CALLBACK_REASON_PRE) {
		struct user_auth_info *auth_info =
				user_auth_info_init(NULL);
		if (auth_info == NULL) {
			fprintf(stderr, "user_auth_info_init() failed\n");
			exit(1);
		}
		cmdline_auth_info = auth_info;
		return;
	}

	if (reason == POPT_CALLBACK_REASON_POST) {
		bool ok;

		ok = lp_load_client(get_dyn_CONFIGFILE());
		if (!ok) {
			const char *pname = poptGetInvocationName(con);

			fprintf(stderr, "%s: Can't load %s - run testparm to debug it\n",
				pname, get_dyn_CONFIGFILE());
			if (!popt_common_credentials_ignore_missing_conf) {
				exit(1);
			}
		}

		load_interfaces();

		set_cmdline_auth_info_guess(cmdline_auth_info);

		if (popt_common_credentials_delay_post) {
			return;
		}

		popt_common_credentials_post();
		return;
	}

	switch(opt->val) {
	case 'U':
		set_cmdline_auth_info_username(cmdline_auth_info, arg);
		break;

	case 'A':
		set_cmdline_auth_info_from_file(cmdline_auth_info, arg);
		break;

	case 'k':
#ifndef HAVE_KRB5
		d_printf("No kerberos support compiled in\n");
		exit(1);
#else
		set_cmdline_auth_info_use_krb5_ticket(cmdline_auth_info);
#endif
		break;

	case 'S':
		if (!set_cmdline_auth_info_signing_state(cmdline_auth_info,
				arg)) {
			fprintf(stderr, "Unknown signing option %s\n", arg );
			exit(1);
		}
		break;
	case 'P':
		set_cmdline_auth_info_use_machine_account(cmdline_auth_info);
		break;
	case 'N':
		set_cmdline_auth_info_password(cmdline_auth_info, "");
		break;
	case 'e':
		set_cmdline_auth_info_smb_encrypt(cmdline_auth_info);
		break;
	case 'C':
		set_cmdline_auth_info_use_ccache(cmdline_auth_info, true);
		break;
	case 'H':
		set_cmdline_auth_info_use_pw_nt_hash(cmdline_auth_info, true);
		break;
	}
}

/**
 * @brief Burn the commandline password.
 *
 * This function removes the password from the command line so we
 * don't leak the password e.g. in 'ps aux'.
 *
 * It should be called after processing the options and you should pass down
 * argv from main().
 *
 * @param[in]  argc     The number of arguments.
 *
 * @param[in]  argv[]   The argument array we will find the array.
 */
void popt_burn_cmdline_password(int argc, char *argv[])
{
	bool found = false;
	char *p = NULL;
	int i, ulen = 0;

	for (i = 0; i < argc; i++) {
		p = argv[i];
		if (p == NULL) {
			return;
		}

		if (strncmp(p, "-U", 2) == 0) {
			ulen = 2;
			found = true;
		} else if (strncmp(p, "--user", 6) == 0) {
			ulen = 6;
			found = true;
		}

		if (found) {
			if (strlen(p) == ulen) {
				continue;
			}

			p = strchr_m(p, '%');
			if (p != NULL) {
				memset_s(p, strlen(p), '\0', strlen(p));
			}
			found = false;
		}
	}
}

struct poptOption popt_common_credentials[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK|POPT_CBFLAG_PRE|POPT_CBFLAG_POST,
		.arg        = (void *)popt_common_credentials_callback,
	},
	{
		.longName   = "user",
		.shortName  = 'U',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'U',
		.descrip    = "Set the network username",
		.argDescrip = "USERNAME",
	},
	{
		.longName   = "no-pass",
		.shortName  = 'N',
		.argInfo    = POPT_ARG_NONE,
		.val        = 'N',
		.descrip    = "Don't ask for a password",
	},
	{
		.longName   = "kerberos",
		.shortName  = 'k',
		.argInfo    = POPT_ARG_NONE,
		.val        = 'k',
		.descrip    = "Use kerberos (active directory) authentication",
	},
	{
		.longName   = "authentication-file",
		.shortName  = 'A',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'A',
		.descrip    = "Get the credentials from a file",
		.argDescrip = "FILE",
	},
	{
		.longName   = "signing",
		.shortName  = 'S',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'S',
		.descrip    = "Set the client signing state",
		.argDescrip = "on|off|required",
	},
	{
		.longName   = "machine-pass",
		.shortName  = 'P',
		.argInfo    = POPT_ARG_NONE,
		.val        = 'P',
		.descrip    = "Use stored machine account password",
	},
	{
		.longName   = "encrypt",
		.shortName  = 'e',
		.argInfo    = POPT_ARG_NONE,
		.val        = 'e',
		.descrip    = "Encrypt SMB transport",
	},
	{
		.longName   = "use-ccache",
		.shortName  = 'C',
		.argInfo    = POPT_ARG_NONE,
		.val        = 'C',
		.descrip    = "Use the winbind ccache for authentication",
	},
	{
		.longName   = "pw-nt-hash",
		.shortName  = '\0',
		.argInfo    = POPT_ARG_NONE,
		.val        = 'H',
		.descrip    = "The supplied password is the NT hash",
	},
	POPT_TABLEEND
};
