/* 
   Unix SMB/CIFS implementation.
   Common popt routines

   Copyright (C) Tim Potter 2001,2002
   Copyright (C) Jelmer Vernooij 2002

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

/* Handle command line options:
 *		d,--debuglevel 
 *		s,--configfile 
 *		O,--socket-options 
 *		V,--version
 *		l,--log-base
 *		n,--netbios-name
 */

extern pstring user_socket_options;
extern BOOL AllowDebugChange;

static void popt_common_callback(poptContext con, 
			   enum poptCallbackReason reason,
			   const struct poptOption *opt,
			   const char *arg, const void *data)
{
	pstring logfile;
	const char *pname;
	
	/* Find out basename of current program */
	pname = strrchr_m(poptGetInvocationName(con),'/');

	if (!pname)
		pname = poptGetInvocationName(con);
	else 
		pname++;

	if (reason == POPT_CALLBACK_REASON_PRE) {
		pstr_sprintf(logfile, "%s/log.%s", dyn_LOGFILEBASE, pname);
		lp_set_logfile(logfile);
		return;
	}

	switch(opt->val) {
	case 'd':
		if (arg) {
			debug_parse_levels(arg);
			AllowDebugChange = False;
		}
		break;

	case 'V':
		printf( "Version %s\n", VERSION );
		exit(0);
		break;

	case 'O':
		if (arg) {
			pstrcpy(user_socket_options,arg);
		}
		break;

	case 's':
		if (arg) {
			pstrcpy(dyn_CONFIGFILE, arg);
		}
		break;

	case 'n':
		if (arg) {
			set_global_myname(arg);
		}
		break;

	case 'l':
		if (arg) {
			pstr_sprintf(logfile, "%s/log.%s", arg, pname);
			lp_set_logfile(logfile);
		}
		break;
	}
}

struct poptOption popt_common_debug[] = {
	{ NULL, 0, POPT_ARG_CALLBACK, popt_common_callback },
	{ "debuglevel", 'd', POPT_ARG_STRING, NULL, 'd', "Set debug level", 
	  "DEBUGLEVEL" },
	{ 0 }
};

struct poptOption popt_common_configfile[] = {
	{ NULL, 0, POPT_ARG_CALLBACK, popt_common_callback },
	{ "configfile", 's', POPT_ARG_STRING, NULL, 's', "Use alternative configuration file" },
	{ 0 }
};

struct poptOption popt_common_socket_options[] = {
	{ NULL, 0, POPT_ARG_CALLBACK, popt_common_callback },
	{"socket-options", 'O', POPT_ARG_STRING, NULL, 'O', "socket options to use" },
	{ 0 }
};

struct poptOption popt_common_version[] = {
	{ NULL, 0, POPT_ARG_CALLBACK, popt_common_callback },
	{"version", 'V', POPT_ARG_NONE, NULL, 'V', "Print version" },
	{ 0 }
};

struct poptOption popt_common_netbios_name[] = {
	{ NULL, 0, POPT_ARG_CALLBACK, popt_common_callback },
	{"netbiosname", 'n', POPT_ARG_STRING, NULL, 'n', "Primary netbios name"},
	{ 0 }
};

struct poptOption popt_common_log_base[] = {
	{ NULL, 0, POPT_ARG_CALLBACK|POPT_CBFLAG_PRE, popt_common_callback },
	{ "log-basename", 'l', POPT_ARG_STRING, NULL, 'l', "Basename for log/debug files"},
	{ 0 }
};
