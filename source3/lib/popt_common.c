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

		if (override_logfile) {
			setup_logging(lp_logfile(talloc_tos()), DEBUG_FILE );
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
