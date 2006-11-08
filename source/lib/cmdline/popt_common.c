/* 
   Unix SMB/CIFS implementation.
   Common popt routines

   Copyright (C) Tim Potter 2001,2002
   Copyright (C) Jelmer Vernooij 2002,2003,2005

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "version.h"
#include "lib/cmdline/popt_common.h"

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

struct cli_credentials *cmdline_credentials = NULL;

static void popt_common_callback(poptContext con, 
			   enum poptCallbackReason reason,
			   const struct poptOption *opt,
			   const char *arg, const void *data)
{
	const char *pname;

	if (reason == POPT_CALLBACK_REASON_POST) {
		lp_load();
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
		fault_setup(poptGetInvocationName(con));

		/* and logging */
		setup_logging(pname, DEBUG_STDOUT);
		return;
	}

	switch(opt->val) {
	case 'd':
		lp_set_cmdline("log level", arg);
		break;

	case OPT_DEBUG_STDERR:
		setup_logging(pname, DEBUG_STDERR);
		break;

	case 'V':
		printf( "Version %s\n", SAMBA_VERSION_STRING );
		exit(0);
		break;

	case 'O':
		if (arg) {
			lp_set_cmdline("socket options", arg);
		}
		break;

	case 's':
		if (arg) {
			lp_set_cmdline("config file", arg);
		}
		break;

	case 'l':
		if (arg) {
			char *new_logfile = talloc_asprintf(NULL, "%s/log.%s", arg, pname);
			lp_set_cmdline("log file", new_logfile);
			talloc_free(new_logfile);
		}
		break;
		
	case 'W':
		lp_set_cmdline("workgroup", arg);
		break;

	case 'r':
		lp_set_cmdline("realm", arg);
		break;
		
	case 'n':
		lp_set_cmdline("netbios name", arg);
		break;
		
	case 'i':
		lp_set_cmdline("netbios scope", arg);
		break;

	case 'm':
		lp_set_cmdline("client max protocol", arg);
		break;

	case 'R':
		lp_set_cmdline("name resolve order", arg);
		break;

	case OPT_OPTION:
		if (!lp_set_option(arg)) {
			fprintf(stderr, "Error setting option '%s'\n", arg);
			exit(1);
		}
		break;

	case OPT_LEAK_REPORT:
		talloc_enable_leak_report();
		break;

	case OPT_LEAK_REPORT_FULL:
		talloc_enable_leak_report_full();
		break;

	}
}

struct poptOption popt_common_connection[] = {
	{ NULL, 0, POPT_ARG_CALLBACK, popt_common_callback },
	{ "name-resolve", 'R', POPT_ARG_STRING, NULL, 'R', "Use these name resolution services only", "NAME-RESOLVE-ORDER" },
	{ "socket-options", 'O', POPT_ARG_STRING, NULL, 'O', "socket options to use", "SOCKETOPTIONS" },
	{ "netbiosname", 'n', POPT_ARG_STRING, NULL, 'n', "Primary netbios name", "NETBIOSNAME" },
	{ "workgroup", 'W', POPT_ARG_STRING, NULL, 'W', "Set the workgroup name", "WORKGROUP" },
	{ "realm", 0, POPT_ARG_STRING, NULL, 'r', "Set the realm name", "REALM" },
	{ "scope", 'i', POPT_ARG_STRING, NULL, 'i', "Use this Netbios scope", "SCOPE" },
	{ "maxprotocol", 'm', POPT_ARG_STRING, NULL, 'm', "Set max protocol level", "MAXPROTOCOL" },
	{ NULL }
};

struct poptOption popt_common_samba[] = {
	{ NULL, 0, POPT_ARG_CALLBACK|POPT_CBFLAG_PRE|POPT_CBFLAG_POST, popt_common_callback },
	{ "debuglevel",   'd', POPT_ARG_STRING, NULL, 'd', "Set debug level", "DEBUGLEVEL" },
	{ "debug-stderr", 0, POPT_ARG_NONE, NULL, OPT_DEBUG_STDERR, "Send debug output to STDERR", NULL },
	{ "configfile",   's', POPT_ARG_STRING, NULL, 's', "Use alternative configuration file", "CONFIGFILE" },
	{ "option",         0, POPT_ARG_STRING, NULL, OPT_OPTION, "Set smb.conf option from command line", "name=value" },
	{ "log-basename", 'l', POPT_ARG_STRING, NULL, 'l', "Basename for log/debug files", "LOGFILEBASE" },
	{ "leak-report",     0, POPT_ARG_NONE, NULL, OPT_LEAK_REPORT, "enable talloc leak reporting on exit", NULL },	
	{ "leak-report-full",0, POPT_ARG_NONE, NULL, OPT_LEAK_REPORT_FULL, "enable full talloc leak reporting on exit", NULL },
	{ NULL }
};

struct poptOption popt_common_version[] = {
	{ NULL, 0, POPT_ARG_CALLBACK, popt_common_callback },
	{ "version", 'V', POPT_ARG_NONE, NULL, 'V', "Print version" },
	{ NULL }
};

