/* 
   Unix SMB/CIFS implementation.
   Common popt routines

   Copyright (C) Tim Potter 2001,2002
   Copyright (C) Jelmer Vernooij 2002,2003

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
#include "dynconfig.h"
#include "system/filesys.h"
#include "system/passwd.h"
#include "lib/cmdline/popt_common.h"

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

enum {OPT_OPTION=1,OPT_LEAK_REPORT,OPT_LEAK_REPORT_FULL};

struct cli_credentials *cmdline_credentials = NULL;

static void popt_common_callback(poptContext con, 
			   enum poptCallbackReason reason,
			   const struct poptOption *opt,
			   const char *arg, const void *data)
{
	const char *pname;
	
	/* Find out basename of current program */
	pname = strrchr_m(poptGetInvocationName(con),'/');

	if (!pname)
		pname = poptGetInvocationName(con);
	else 
		pname++;

	if (reason == POPT_CALLBACK_REASON_PRE) {
		char *logfile = talloc_asprintf(NULL, "%s/log.%s", dyn_LOGFILEBASE, pname);
		lp_set_cmdline("log file", logfile);
		talloc_free(logfile);
		return;
	}

	switch(opt->val) {
	case 'd':
		lp_set_cmdline("log level", arg);
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
			pstrcpy(dyn_CONFIGFILE, arg);
		}
		break;

	case 'l':
		if (arg) {
			char *logfile = talloc_asprintf(NULL, "%s/log.%s", arg, pname);
			lp_set_cmdline("log file", logfile);
			talloc_free(logfile);
		}
		break;
		
	case 'W':
		lp_set_cmdline("workgroup", arg);
		break;
		
	case 'n':
		lp_set_cmdline("netbios name", arg);
		break;
		
	case 'i':
		lp_set_cmdline("netbios scope", arg);
		break;

	case 'm':
		lp_set_cmdline("max protocol", arg);
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
	{ "scope", 'i', POPT_ARG_STRING, NULL, 'i', "Use this Netbios scope", "SCOPE" },
	{ "maxprotocol", 'm', POPT_ARG_STRING, NULL, 'm', "Set max protocol level", "MAXPROTOCOL" },
	POPT_TABLEEND
};

struct poptOption popt_common_samba[] = {
	{ NULL, 0, POPT_ARG_CALLBACK|POPT_CBFLAG_PRE, popt_common_callback },
	{ "debuglevel",   'd', POPT_ARG_STRING, NULL, 'd', "Set debug level", "DEBUGLEVEL" },
	{ "configfile",   's', POPT_ARG_STRING, NULL, 's', "Use alternative configuration file", "CONFIGFILE" },
	{ "option",         0, POPT_ARG_STRING, NULL, OPT_OPTION, "Set smb.conf option from command line", "name=value" },
	{ "log-basename", 'l', POPT_ARG_STRING, NULL, 'l', "Basename for log/debug files", "LOGFILEBASE" },
	{ "leak-report",     0, POPT_ARG_NONE, NULL, OPT_LEAK_REPORT, "enable talloc leak reporting on exit", NULL },	
	{ "leak-report-full",0, POPT_ARG_NONE, NULL, OPT_LEAK_REPORT_FULL, "enable full talloc leak reporting on exit", NULL },
	POPT_TABLEEND
};

struct poptOption popt_common_version[] = {
	{ NULL, 0, POPT_ARG_CALLBACK, popt_common_callback },
	{ "version", 'V', POPT_ARG_NONE, NULL, 'V', "Print version" },
	POPT_TABLEEND
};

/* Handle command line options:
 *		-U,--user
 *		-A,--authentication-file
 *		-k,--use-kerberos
 *		-N,--no-pass
 *		-S,--signing
 *      -P --machine-pass
 */


static BOOL dont_ask = False;

static void popt_common_credentials_callback(poptContext con, 
						enum poptCallbackReason reason,
						const struct poptOption *opt,
						const char *arg, const void *data)
{
	if (reason == POPT_CALLBACK_REASON_PRE) {
		cmdline_credentials = talloc_zero(talloc_autofree_context(), struct cli_credentials);
		cli_credentials_guess(cmdline_credentials);

		return;
	}
	
	if (reason == POPT_CALLBACK_REASON_POST) {
		if (!dont_ask) {
			cli_credentials_set_cmdline_callbacks(cmdline_credentials);
		}
		return;
	}

	switch(opt->val) {
	case 'U':
		{
			char *lp;

			cli_credentials_parse_string(cmdline_credentials, arg, CRED_SPECIFIED);

			if ((lp=strchr_m(arg,'%'))) {
				memset(lp,0,strlen(cmdline_credentials->password));
			}
		}
		break;

	case 'A':
		cli_credentials_parse_file(cmdline_credentials, arg, CRED_SPECIFIED);
		break;

	case 'S':
		lp_set_cmdline("client signing", arg);
		break;

	case 'P':
	        {
			char *opt_password = NULL;
			/* it is very useful to be able to make ads queries as the
			   machine account for testing purposes and for domain leave */
			
			if (!secrets_init()) {
				d_printf("ERROR: Unable to open secrets database\n");
				exit(1);
			}
			
			opt_password = secrets_fetch_machine_password(lp_workgroup());
			
			if (!opt_password) {
				d_printf("ERROR: Unable to fetch machine password\n");
				exit(1);
			}
			cmdline_credentials->username = talloc_asprintf(cmdline_credentials, "%s$", lp_netbios_name());
			cmdline_credentials->username_obtained = CRED_SPECIFIED;
			cli_credentials_set_password(cmdline_credentials, opt_password, CRED_SPECIFIED);
			free(opt_password);

			cli_credentials_set_domain(cmdline_credentials, lp_workgroup(), CRED_SPECIFIED);
		}
		/* machine accounts only work with kerberos */

	case 'k':
#ifndef HAVE_KRB5
		d_printf("No kerberos support compiled in\n");
		exit(1);
#else
		lp_set_cmdline("gensec:krb5", "True");
		lp_set_cmdline("gensec:ms_krb5", "True");
#endif
		break;


	}
}



struct poptOption popt_common_credentials[] = {
	{ NULL, 0, POPT_ARG_CALLBACK|POPT_CBFLAG_PRE|POPT_CBFLAG_POST, popt_common_credentials_callback },
	{ "user", 'U', POPT_ARG_STRING, NULL, 'U', "Set the network username", "[DOMAIN\\]USERNAME[%PASSWORD]" },
	{ "no-pass", 'N', POPT_ARG_NONE, &dont_ask, True, "Don't ask for a password" },
	{ "kerberos", 'k', POPT_ARG_NONE, NULL, 'k', "Use kerberos (active directory) authentication" },
	{ "authentication-file", 'A', POPT_ARG_STRING, NULL, 'A', "Get the credentials from a file", "FILE" },
	{ "signing", 'S', POPT_ARG_STRING, NULL, 'S', "Set the client signing state", "on|off|required" },
	{ "machine-pass", 'P', POPT_ARG_NONE, NULL, 'P', "Use stored machine account password (implies -k)" },
	POPT_TABLEEND
};
