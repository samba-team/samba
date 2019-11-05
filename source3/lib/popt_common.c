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

	char lfile[PATH_MAX];
	const char *pname;
	int ret;

	/* Find out basename of current program */
	pname = strrchr_m(poptGetInvocationName(con), '/');
	if (pname == NULL) {
		pname = poptGetInvocationName(con);
	} else {
		pname++;
	}

	ret = snprintf(lfile, sizeof(lfile), "%s/log.%s", arg, pname);
	if (ret >= sizeof(lfile)) {
		return;
	}
	lp_set_logfile(lfile);
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
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		exit(1);
	}

	if (reason == POPT_CALLBACK_REASON_PRE) {
		set_logfile(con, get_dyn_LOGFILEBASE());
		talloc_set_log_fn(popt_s3_talloc_log_fn);
		talloc_set_abort_fn(smb_panic);
		talloc_free(mem_ctx);
		return;
	}

	if (reason == POPT_CALLBACK_REASON_POST) {

		if (PrintSambaVersionString) {
			printf( "Version %s\n", samba_version_string());
			talloc_free(mem_ctx);
			exit(0);
		}

		if (is_default_dyn_CONFIGFILE()) {
			if (getenv("SMB_CONF_PATH")) {
				set_dyn_CONFIGFILE(getenv("SMB_CONF_PATH"));
			}
		}

		if (override_logfile) {
			const struct loadparm_substitution *lp_sub =
				loadparm_s3_global_substitution();
			char *logfile = lp_logfile(mem_ctx, lp_sub);
			if (logfile == NULL) {
				talloc_free(mem_ctx);
				exit(1);
			}
			setup_logging(logfile, DEBUG_FILE);
		}

		/* Further 'every Samba program must do this' hooks here. */
		talloc_free(mem_ctx);
		return;
	}

	switch(opt->val) {
	case OPT_OPTION:
	{
		struct loadparm_context *lp_ctx;
		bool ok;

		lp_ctx = loadparm_init_s3(mem_ctx, loadparm_s3_helpers());
		if (lp_ctx == NULL) {
			fprintf(stderr, "loadparm_init_s3() failed!\n");
			talloc_free(mem_ctx);
			exit(1);
		}

		ok = lpcfg_set_option(lp_ctx, arg);
		if (!ok) {
			fprintf(stderr, "Error setting option '%s'\n", arg);
			talloc_free(mem_ctx);
			exit(1);
		}
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

	talloc_free(mem_ctx);
}

struct poptOption popt_common_connection[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK,
		.arg        = (void *)popt_common_callback,
	},
	{
		.longName   = "socket-options",
		.shortName  = 'O',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'O',
		.descrip    = "socket options to use",
		.argDescrip = "SOCKETOPTIONS",
	},
	{
		.longName   = "netbiosname",
		.shortName  = 'n',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'n',
		.descrip    = "Primary netbios name",
		.argDescrip = "NETBIOSNAME"
	},
	{
		.longName   = "workgroup",
		.shortName  = 'W',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'W',
		.descrip    = "Set the workgroup name",
		.argDescrip = "WORKGROUP"
	},
	{
		.longName   = "scope",
		.shortName  = 'i',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'i',
		.descrip    = "Use this Netbios scope",
		.argDescrip = "SCOPE"
	},
	POPT_TABLEEND
};

struct poptOption popt_common_samba[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK|POPT_CBFLAG_PRE|POPT_CBFLAG_POST,
		.arg        = (void *)popt_common_callback,
	},
	{
		.longName   = "debuglevel",
		.shortName  = 'd',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'd',
		.descrip    = "Set debug level",
		.argDescrip = "DEBUGLEVEL",
	},
	{
		.longName   = "configfile",
		.shortName  = 's',
		.argInfo    = POPT_ARG_STRING,
		.val        = 's',
		.descrip    = "Use alternate configuration file",
		.argDescrip = "CONFIGFILE",
	},
	{
		.longName   = "log-basename",
		.shortName  = 'l',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'l',
		.descrip    = "Base name for log files",
		.argDescrip = "LOGFILEBASE",
	},
	{
		.longName   = "version",
		.shortName  = 'V',
		.argInfo    = POPT_ARG_NONE,
		.val        = 'V',
		.descrip    = "Print version",
	},
	{
		.longName   = "option",
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_OPTION,
		.descrip    = "Set smb.conf option from command line",
		.argDescrip = "name=value",
	},
	POPT_TABLEEND
};

struct poptOption popt_common_configfile[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK|POPT_CBFLAG_PRE|POPT_CBFLAG_POST,
		.arg        = (void *)popt_common_callback,
	},
	{
		.longName   = "configfile",
		.argInfo    = POPT_ARG_STRING,
		.val        = 's',
		.descrip    = "Use alternate configuration file",
		.argDescrip = "CONFIGFILE",
	},
	POPT_TABLEEND
};

struct poptOption popt_common_version[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK|POPT_CBFLAG_POST,
		.arg        = (void *)popt_common_callback
	},
	{
		.longName   = "version",
		.shortName  = 'V',
		.argInfo    = POPT_ARG_NONE,
		.val        = 'V',
		.descrip    = "Print version",
	},
	POPT_TABLEEND
};

struct poptOption popt_common_debuglevel[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK,
		.arg        = (void *)popt_common_callback,
	},
	{
		.longName   = "debuglevel",
		.shortName  = 'd',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'd',
		.descrip    = "Set debug level",
		.argDescrip = "DEBUGLEVEL",
	},
	POPT_TABLEEND
};

struct poptOption popt_common_option[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK|POPT_CBFLAG_POST,
		.arg        = (void *)popt_common_callback,
	},
	{
		.longName   = "option",
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_OPTION,
		.descrip    = "Set smb.conf option from command line",
		.argDescrip = "name=value",
	},
	POPT_TABLEEND
};
