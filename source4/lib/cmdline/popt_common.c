/* 
   Unix SMB/CIFS implementation.
   Common popt routines

   Copyright (C) Tim Potter 2001,2002
   Copyright (C) Jelmer Vernooij 2002,2003,2005

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
#include "version.h"
#include "lib/cmdline/popt_common.h"
#include "param/param.h"

/* Handle command line options:
 *		-d,--debuglevel 
 *		-s,--configfile 
 *		-O,--socket-options 
 *		-V,--version
 *		-l,--log-base
 *		-n,--netbios-name
 *		-W,--workgroup
 *		--realm
 *		-i,--scope
 */

enum {OPT_OPTION=1,OPT_LEAK_REPORT,OPT_LEAK_REPORT_FULL,OPT_DEBUG_STDERR};

static struct cli_credentials *cmdline_credentials = NULL;

void popt_set_cmdline_credentials(struct cli_credentials *creds)
{
	cmdline_credentials = creds;
}

struct cli_credentials *popt_get_cmdline_credentials(void)
{
	return cmdline_credentials;
}

void popt_free_cmdline_credentials(void)
{
	TALLOC_FREE(cmdline_credentials);
}

struct loadparm_context *cmdline_lp_ctx = NULL;

static void popt_version_callback(poptContext con,
			   enum poptCallbackReason reason,
			   const struct poptOption *opt,
			   const char *arg, const void *data)
{
	switch(opt->val) {
	case 'V':
		printf("Version %s\n", SAMBA_VERSION_STRING );
		exit(0);
	}
}

static void popt_s4_talloc_log_fn(const char *message)
{
	DEBUG(0,("%s", message));
}

static void popt_samba_callback(poptContext con, 
			   enum poptCallbackReason reason,
			   const struct poptOption *opt,
			   const char *arg, const void *data)
{
	const char *pname;

	if (reason == POPT_CALLBACK_REASON_POST) {
		if (lpcfg_configfile(cmdline_lp_ctx) == NULL) {
			lpcfg_load_default(cmdline_lp_ctx);
		}
		/* Hook any 'every Samba program must do this, after
		 * the smb.conf is setup' functions here */
		return;
	}

	/* Find out basename of current program */
	pname = strrchr_m(poptGetInvocationName(con),'/');

	if (!pname)
		pname = poptGetInvocationName(con);
	else 
		pname++;

	if (reason == POPT_CALLBACK_REASON_PRE) {
		/* Hook for 'almost the first thing to do in a samba program' here */
		/* setup for panics */
		fault_setup();

		/* and logging */
		setup_logging(pname, DEBUG_DEFAULT_STDOUT);
		talloc_set_log_fn(popt_s4_talloc_log_fn);
		talloc_set_abort_fn(smb_panic);

		cmdline_lp_ctx = loadparm_init_global(false);
		return;
	}

	switch(opt->val) {

	case OPT_LEAK_REPORT:
		talloc_enable_leak_report();
		break;

	case OPT_LEAK_REPORT_FULL:
		talloc_enable_leak_report_full();
		break;

	case OPT_OPTION:
		if (!lpcfg_set_option(cmdline_lp_ctx, arg)) {
			fprintf(stderr, "Error setting option '%s'\n", arg);
			exit(1);
		}
		break;

	case 'd':
		lpcfg_set_cmdline(cmdline_lp_ctx, "log level", arg);
		break;

	case OPT_DEBUG_STDERR:
		setup_logging(pname, DEBUG_STDERR);
		break;

	case 's':
		if (arg) {
			lpcfg_load(cmdline_lp_ctx, arg);
		}
		break;

	case 'l':
		if (arg) {
			char *new_logfile = talloc_asprintf(NULL, "%s/log.%s", arg, pname);
			lpcfg_set_cmdline(cmdline_lp_ctx, "log file", new_logfile);
			talloc_free(new_logfile);
		}
		break;
	

	}

}


static void popt_common_callback(poptContext con, 
			   enum poptCallbackReason reason,
			   const struct poptOption *opt,
			   const char *arg, const void *data)
{
	struct loadparm_context *lp_ctx = cmdline_lp_ctx;

	switch(opt->val) {
	case 'O':
		if (arg) {
			lpcfg_set_cmdline(lp_ctx, "socket options", arg);
		}
		break;
	
	case 'W':
		lpcfg_set_cmdline(lp_ctx, "workgroup", arg);
		break;

	case 'r':
		lpcfg_set_cmdline(lp_ctx, "realm", arg);
		break;
		
	case 'n':
		lpcfg_set_cmdline(lp_ctx, "netbios name", arg);
		break;
		
	case 'i':
		lpcfg_set_cmdline(lp_ctx, "netbios scope", arg);
		break;

	case 'm':
		lpcfg_set_cmdline(lp_ctx, "client max protocol", arg);
		break;

	case 'R':
		lpcfg_set_cmdline(lp_ctx, "name resolve order", arg);
		break;

	case 'S':
		lpcfg_set_cmdline(lp_ctx, "client signing", arg);
		break;

	}
}

struct poptOption popt_common_connection4[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK,
		.arg        = (void *)popt_common_callback,
	},
	{
		.longName   = "name-resolve",
		.shortName  = 'R',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'R',
		.descrip    = "Use these name resolution services only",
		.argDescrip = "NAME-RESOLVE-ORDER",
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
		.argDescrip = "NETBIOSNAME",
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
		.longName   = "workgroup",
		.shortName  = 'W',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'W',
		.descrip    = "Set the workgroup name",
		.argDescrip = "WORKGROUP",
	},
	{
		.longName   = "realm",
		.argInfo    = POPT_ARG_STRING,
		.val        = 'r',
		.descrip    = "Set the realm name",
		.argDescrip = "REALM",
	},
	{
		.longName   = "scope",
		.shortName  = 'i',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'i',
		.descrip    = "Use this Netbios scope",
		.argDescrip = "SCOPE",
	},
	{
		.longName   = "maxprotocol",
		.shortName  = 'm',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'm',
		.descrip    = "Set max protocol level",
		.argDescrip = "MAXPROTOCOL",
	},
	POPT_TABLEEND
};

struct poptOption popt_common_samba4[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK|POPT_CBFLAG_PRE|POPT_CBFLAG_POST,
		.arg        = (void *)popt_samba_callback,
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
		.longName   = "debug-stderr",
		.argInfo    = POPT_ARG_NONE,
		.val        = OPT_DEBUG_STDERR,
		.descrip    = "Send debug output to STDERR",
	},
	{
		.longName   = "configfile",
		.shortName  = 's',
		.argInfo    = POPT_ARG_STRING,
		.val        = 's',
		.descrip    = "Use alternative configuration file",
		.argDescrip = "CONFIGFILE",
	},
	{
		.longName   = "option",
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_OPTION,
		.descrip    = "Set smb.conf option from command line",
		.argDescrip = "name=value",
	},
	{
		.longName   = "log-basename",
		.shortName  = 'l',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'l',
		.descrip    = "Basename for log/debug files",
		.argDescrip = "LOGFILEBASE",
	},
	{
		.longName   = "leak-report",
		.argInfo    = POPT_ARG_NONE,
		.val        = OPT_LEAK_REPORT,
		.descrip    = "enable talloc leak reporting on exit",
	},
	{
		.longName   = "leak-report-full",
		.argInfo    = POPT_ARG_NONE,
		.val        = OPT_LEAK_REPORT_FULL,
		.descrip    = "enable full talloc leak reporting on exit",
	},
	POPT_TABLEEND
};

struct poptOption popt_common_version4[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK,
		.arg        = (void *)popt_version_callback,
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
