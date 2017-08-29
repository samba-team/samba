/* 
   Unix SMB/CIFS implementation.
   Common popt routines

   Copyright (C) Tim Potter 2001,2002
   Copyright (C) Jelmer Vernooij 2002,2003
   Copyright (C) James Peach 2006

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

#include "includes.h"
#include "popt_common.h"
#include "lib/param/param.h"

/* Handle command line options:
 *		-d,--debuglevel 
 *		-s,--configfile 
 *		-O,--socket-options 
 *		-V,--version
 *		-l,--log-base
 *		-n,--netbios-name
 *		-W,--workgroup
 *		-i,--scope
 */

enum {OPT_OPTION=1};

extern bool override_logfile;

static void set_logfile(poptContext con, const char * arg)
{

	char *lfile = NULL;
	const char *pname;

	/* Find out basename of current program */
	pname = strrchr_m(poptGetInvocationName(con),'/');

	if (!pname)
		pname = poptGetInvocationName(con);
	else
		pname++;

	if (asprintf(&lfile, "%s/log.%s", arg, pname) < 0) {
		return;
	}
	lp_set_logfile(lfile);
	SAFE_FREE(lfile);
}

static bool PrintSambaVersionString;

static void popt_s3_talloc_log_fn(const char *message)
{
	DEBUG(0,("%s", message));
}

static void popt_common_callback(poptContext con,
			   enum poptCallbackReason reason,
			   const struct poptOption *opt,
			   const char *arg, const void *data)
{

	if (reason == POPT_CALLBACK_REASON_PRE) {
		set_logfile(con, get_dyn_LOGFILEBASE());
		talloc_set_log_fn(popt_s3_talloc_log_fn);
		talloc_set_abort_fn(smb_panic);
		return;
	}

	if (reason == POPT_CALLBACK_REASON_POST) {

		if (PrintSambaVersionString) {
			printf( "Version %s\n", samba_version_string());
			exit(0);
		}

		if (is_default_dyn_CONFIGFILE()) {
			if(getenv("SMB_CONF_PATH")) {
				set_dyn_CONFIGFILE(getenv("SMB_CONF_PATH"));
			}
		}

		/* Further 'every Samba program must do this' hooks here. */
		return;
	}

	switch(opt->val) {
	case OPT_OPTION:
	{
		struct loadparm_context *lp_ctx;

		lp_ctx = loadparm_init_s3(talloc_tos(), loadparm_s3_helpers());
		if (lp_ctx == NULL) {
			fprintf(stderr, "loadparm_init_s3() failed!\n");
			exit(1);
		}

		if (!lpcfg_set_option(lp_ctx, arg)) {
			fprintf(stderr, "Error setting option '%s'\n", arg);
			exit(1);
		}
		TALLOC_FREE(lp_ctx);
		break;
	}
	case 'd':
		if (arg) {
			lp_set_cmdline("log level", arg);
		}
		break;

	case 'V':
		PrintSambaVersionString = True;
		break;

	case 'O':
		if (arg) {
			lp_set_cmdline("socket options", arg);
		}
		break;

	case 's':
		if (arg) {
			set_dyn_CONFIGFILE(arg);
		}
		break;

	case 'n':
		if (arg) {
			lp_set_cmdline("netbios name", arg);
		}
		break;

	case 'l':
		if (arg) {
			set_logfile(con, arg);
			override_logfile = True;
			set_dyn_LOGFILEBASE(arg);
		}
		break;

	case 'i':
		if (arg) {
			lp_set_cmdline("netbios scope", arg);
		}
		break;

	case 'W':
		if (arg) {
			lp_set_cmdline("workgroup", arg);
		}
		break;
	}
}

struct poptOption popt_common_connection[] = {
	{ NULL, 0, POPT_ARG_CALLBACK, (void *)popt_common_callback },
	{ "socket-options", 'O', POPT_ARG_STRING, NULL, 'O', "socket options to use",
	  "SOCKETOPTIONS" },
	{ "netbiosname", 'n', POPT_ARG_STRING, NULL, 'n', "Primary netbios name", "NETBIOSNAME" },
	{ "workgroup", 'W', POPT_ARG_STRING, NULL, 'W', "Set the workgroup name", "WORKGROUP" },
	{ "scope", 'i', POPT_ARG_STRING, NULL, 'i', "Use this Netbios scope", "SCOPE" },

	POPT_TABLEEND
};

struct poptOption popt_common_samba[] = {
	{ NULL, 0, POPT_ARG_CALLBACK|POPT_CBFLAG_PRE|POPT_CBFLAG_POST, (void *)popt_common_callback },
	{ "debuglevel", 'd', POPT_ARG_STRING, NULL, 'd', "Set debug level", "DEBUGLEVEL" },
	{ "configfile", 's', POPT_ARG_STRING, NULL, 's', "Use alternate configuration file", "CONFIGFILE" },
	{ "log-basename", 'l', POPT_ARG_STRING, NULL, 'l', "Base name for log files", "LOGFILEBASE" },
	{ "version", 'V', POPT_ARG_NONE, NULL, 'V', "Print version" },
	{ "option",         0, POPT_ARG_STRING, NULL, OPT_OPTION, "Set smb.conf option from command line", "name=value" },
	POPT_TABLEEND
};

struct poptOption popt_common_configfile[] = {
	{ NULL, 0, POPT_ARG_CALLBACK|POPT_CBFLAG_PRE|POPT_CBFLAG_POST, (void *)popt_common_callback },
	{ "configfile", 0, POPT_ARG_STRING, NULL, 's', "Use alternate configuration file", "CONFIGFILE" },
	POPT_TABLEEND
};

struct poptOption popt_common_version[] = {
	{ NULL, 0, POPT_ARG_CALLBACK|POPT_CBFLAG_POST, (void *)popt_common_callback },
	{ "version", 'V', POPT_ARG_NONE, NULL, 'V', "Print version" },
	POPT_TABLEEND
};

struct poptOption popt_common_debuglevel[] = {
	{ NULL, 0, POPT_ARG_CALLBACK, (void *)popt_common_callback },
	{ "debuglevel", 'd', POPT_ARG_STRING, NULL, 'd', "Set debug level", "DEBUGLEVEL" },
	POPT_TABLEEND
};

struct poptOption popt_common_option[] = {
	{ NULL, 0, POPT_ARG_CALLBACK|POPT_CBFLAG_POST, (void *)popt_common_callback },
	{ "option",         0, POPT_ARG_STRING, NULL, OPT_OPTION, "Set smb.conf option from command line", "name=value" },
	POPT_TABLEEND
};

/* Handle command line options:
 *		-U,--user
 *		-A,--authentication-file
 *		-k,--use-kerberos
 *		-N,--no-pass
 *		-S,--signing
 *              -P --machine-pass
 * 		-e --encrypt
 * 		-C --use-ccache
 */

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
	popt_common_credentials_delay_post = true;
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
	 * didnn't take the 'winbind separator' into account.
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

		if (override_logfile) {
			setup_logging(lp_logfile(talloc_tos()), DEBUG_FILE );
		}

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
		if (strncmp(p, "-U", 2) == 0) {
			ulen = 2;
			found = true;
		} else if (strncmp(p, "--user", 6) == 0) {
			ulen = 6;
			found = true;
		}

		if (found) {
			if (p == NULL) {
				return;
			}

			if (strlen(p) == ulen) {
				continue;
			}

			p = strchr_m(p, '%');
			if (p != NULL) {
				memset(p, '\0', strlen(p));
			}
			found = false;
		}
	}
}

struct poptOption popt_common_credentials[] = {
	{ NULL, 0, POPT_ARG_CALLBACK|POPT_CBFLAG_PRE|POPT_CBFLAG_POST,
	  (void *)popt_common_credentials_callback, 0, NULL },
	{ "user", 'U', POPT_ARG_STRING, NULL, 'U', "Set the network username", "USERNAME" },
	{ "no-pass", 'N', POPT_ARG_NONE, NULL, 'N', "Don't ask for a password" },
	{ "kerberos", 'k', POPT_ARG_NONE, NULL, 'k', "Use kerberos (active directory) authentication" },
	{ "authentication-file", 'A', POPT_ARG_STRING, NULL, 'A', "Get the credentials from a file", "FILE" },
	{ "signing", 'S', POPT_ARG_STRING, NULL, 'S', "Set the client signing state", "on|off|required" },
	{"machine-pass", 'P', POPT_ARG_NONE, NULL, 'P', "Use stored machine account password" },
	{"encrypt", 'e', POPT_ARG_NONE, NULL, 'e', "Encrypt SMB transport" },
	{"use-ccache", 'C', POPT_ARG_NONE, NULL, 'C',
	 "Use the winbind ccache for authentication" },
	{"pw-nt-hash", '\0', POPT_ARG_NONE, NULL, 'H',
	 "The supplied password is the NT hash" },
	POPT_TABLEEND
};
