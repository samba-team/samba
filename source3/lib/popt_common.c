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

extern pstring user_socket_options;
extern BOOL AllowDebugChange;
extern BOOL override_logfile;

struct user_auth_info cmdline_auth_info;

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
		printf( "Version %s\n", SAMBA_VERSION_STRING);
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
			override_logfile = True;
		}
		break;

	case 'i':
		if (arg) {
			  set_global_scope(arg);
		}
		break;

	case 'W':
		if (arg) {
			set_global_myworkgroup(arg);
		}
		break;
	}
}

struct poptOption popt_common_connection[] = {
	{ NULL, 0, POPT_ARG_CALLBACK, popt_common_callback },
	{ "socket-options", 'O', POPT_ARG_STRING, NULL, 'O', "socket options to use",
	  "SOCKETOPTIONS" },
	{ "netbiosname", 'n', POPT_ARG_STRING, NULL, 'n', "Primary netbios name", "NETBIOSNAME" },
	{ "workgroup", 'W', POPT_ARG_STRING, NULL, 'W', "Set the workgroup name", "WORKGROUP" },
	{ "scope", 'i', POPT_ARG_STRING, NULL, 'i', "Use this Netbios scope", "SCOPE" },

	POPT_TABLEEND
};

struct poptOption popt_common_samba[] = {
	{ NULL, 0, POPT_ARG_CALLBACK|POPT_CBFLAG_PRE, popt_common_callback },
	{ "debuglevel", 'd', POPT_ARG_STRING, NULL, 'd', "Set debug level", "DEBUGLEVEL" },
	{ "configfile", 's', POPT_ARG_STRING, NULL, 's', "Use alternative configuration file", "CONFIGFILE" },
	{ "log-basename", 'l', POPT_ARG_STRING, NULL, 'l', "Basename for log/debug files", "LOGFILEBASE" },
	{ "version", 'V', POPT_ARG_NONE, NULL, 'V', "Print version" },
	POPT_TABLEEND
};

struct poptOption popt_common_version[] = {
	{ NULL, 0, POPT_ARG_CALLBACK, popt_common_callback },
	{ "version", 'V', POPT_ARG_NONE, NULL, 'V', "Print version" },
	POPT_TABLEEND
};



/****************************************************************************
 * get a password from a a file or file descriptor
 * exit on failure
 * ****************************************************************************/
static void get_password_file(struct user_auth_info *a)
{
	int fd = -1;
	char *p;
	BOOL close_it = False;
	pstring spec;
	char pass[128];

	if ((p = getenv("PASSWD_FD")) != NULL) {
		pstrcpy(spec, "descriptor ");
		pstrcat(spec, p);
		sscanf(p, "%d", &fd);
		close_it = False;
	} else if ((p = getenv("PASSWD_FILE")) != NULL) {
		fd = sys_open(p, O_RDONLY, 0);
		pstrcpy(spec, p);
		if (fd < 0) {
			fprintf(stderr, "Error opening PASSWD_FILE %s: %s\n",
					spec, strerror(errno));
			exit(1);
		}
		close_it = True;
	}

	for(p = pass, *p = '\0'; /* ensure that pass is null-terminated */
		p && p - pass < sizeof(pass);) {
		switch (read(fd, p, 1)) {
		case 1:
			if (*p != '\n' && *p != '\0') {
				*++p = '\0'; /* advance p, and null-terminate pass */
				break;
			}
		case 0:
			if (p - pass) {
				*p = '\0'; /* null-terminate it, just in case... */
				p = NULL; /* then force the loop condition to become false */
				break;
			} else {
				fprintf(stderr, "Error reading password from file %s: %s\n",
						spec, "empty password\n");
				exit(1);
			}

		default:
			fprintf(stderr, "Error reading password from file %s: %s\n",
					spec, strerror(errno));
			exit(1);
		}
	}
	pstrcpy(a->password, pass);
	if (close_it)
		close(fd);
}

static void get_credentials_file(const char *file, struct user_auth_info *info) 
{
	XFILE *auth;
	fstring buf;
	uint16 len = 0;
	char *ptr, *val, *param;

	if ((auth=x_fopen(file, O_RDONLY, 0)) == NULL)
	{
		/* fail if we can't open the credentials file */
		d_printf("ERROR: Unable to open credentials file!\n");
		exit(-1);
	}

	while (!x_feof(auth))
	{
		/* get a line from the file */
		if (!x_fgets(buf, sizeof(buf), auth))
			continue;
		len = strlen(buf);

		if ((len) && (buf[len-1]=='\n'))
		{
			buf[len-1] = '\0';
			len--;
		}
		if (len == 0)
			continue;

		/* break up the line into parameter & value.
		 * will need to eat a little whitespace possibly */
		param = buf;
		if (!(ptr = strchr_m (buf, '=')))
			continue;

		val = ptr+1;
		*ptr = '\0';

		/* eat leading white space */
		while ((*val!='\0') && ((*val==' ') || (*val=='\t')))
			val++;

		if (strwicmp("password", param) == 0)
		{
			pstrcpy(info->password, val);
			info->got_pass = True;
		}
		else if (strwicmp("username", param) == 0)
			pstrcpy(info->username, val);
		else if (strwicmp("domain", param) == 0)
			set_global_myworkgroup(val);
		memset(buf, 0, sizeof(buf));
	}
	x_fclose(auth);
}

/* Handle command line options:
 *		-U,--user
 *		-A,--authentication-file
 *		-k,--use-kerberos
 *		-N,--no-pass
 *		-S,--signing
 *              -P --machine-pass
 */


static void popt_common_credentials_callback(poptContext con, 
					enum poptCallbackReason reason,
					const struct poptOption *opt,
					const char *arg, const void *data)
{
	char *p;

	if (reason == POPT_CALLBACK_REASON_PRE) {
		cmdline_auth_info.use_kerberos = False;
		cmdline_auth_info.got_pass = False;
		cmdline_auth_info.signing_state = Undefined;
		pstrcpy(cmdline_auth_info.username, "GUEST");	

		if (getenv("LOGNAME"))pstrcpy(cmdline_auth_info.username,getenv("LOGNAME"));

		if (getenv("USER")) {
			pstrcpy(cmdline_auth_info.username,getenv("USER"));

			if ((p = strchr_m(cmdline_auth_info.username,'%'))) {
				*p = 0;
				pstrcpy(cmdline_auth_info.password,p+1);
				cmdline_auth_info.got_pass = True;
				memset(strchr_m(getenv("USER"),'%')+1,'X',strlen(cmdline_auth_info.password));
			}
		}

		if (getenv("PASSWD")) {
			pstrcpy(cmdline_auth_info.password,getenv("PASSWD"));
			cmdline_auth_info.got_pass = True;
		}

		if (getenv("PASSWD_FD") || getenv("PASSWD_FILE")) {
			get_password_file(&cmdline_auth_info);
			cmdline_auth_info.got_pass = True;
		}

		return;
	}

	switch(opt->val) {
	case 'U':
		{
			char *lp;

			pstrcpy(cmdline_auth_info.username,arg);
			if ((lp=strchr_m(cmdline_auth_info.username,'%'))) {
				*lp = 0;
				pstrcpy(cmdline_auth_info.password,lp+1);
				cmdline_auth_info.got_pass = True;
				memset(strchr_m(arg,'%')+1,'X',strlen(cmdline_auth_info.password));
			}
		}
		break;

	case 'A':
		get_credentials_file(arg, &cmdline_auth_info);
		break;

	case 'k':
#ifndef HAVE_KRB5
		d_printf("No kerberos support compiled in\n");
		exit(1);
#else
		cmdline_auth_info.use_kerberos = True;
		cmdline_auth_info.got_pass = True;
#endif
		break;

	case 'S':
		{
			cmdline_auth_info.signing_state = -1;
			if (strequal(arg, "off") || strequal(arg, "no") || strequal(arg, "false"))
				cmdline_auth_info.signing_state = False;
			else if (strequal(arg, "on") || strequal(arg, "yes") || strequal(arg, "true") ||
					strequal(arg, "auto") )
				cmdline_auth_info.signing_state = True;
			else if (strequal(arg, "force") || strequal(arg, "required") || strequal(arg, "forced"))
				cmdline_auth_info.signing_state = Required;
			else {
				fprintf(stderr, "Unknown signing option %s\n", arg );
				exit(1);
			}
		}
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
			
			opt_password = secrets_fetch_machine_password(lp_workgroup(), NULL, NULL);
			
			if (!opt_password) {
				d_printf("ERROR: Unable to fetch machine password\n");
				exit(1);
			}
			pstr_sprintf(cmdline_auth_info.username, "%s$", 
				     global_myname());
			pstrcpy(cmdline_auth_info.password,opt_password);
			SAFE_FREE(opt_password);

			/* machine accounts only work with kerberos */
			cmdline_auth_info.use_kerberos = True;
			cmdline_auth_info.got_pass = True;
		}
		break;
	}
}



struct poptOption popt_common_credentials[] = {
	{ NULL, 0, POPT_ARG_CALLBACK|POPT_CBFLAG_PRE, popt_common_credentials_callback },
	{ "user", 'U', POPT_ARG_STRING, NULL, 'U', "Set the network username", "USERNAME" },
	{ "no-pass", 'N', POPT_ARG_NONE, &cmdline_auth_info.got_pass, 0, "Don't ask for a password" },
	{ "kerberos", 'k', POPT_ARG_NONE, &cmdline_auth_info.use_kerberos, 'k', "Use kerberos (active directory) authentication" },
	{ "authentication-file", 'A', POPT_ARG_STRING, NULL, 'A', "Get the credentials from a file", "FILE" },
	{ "signing", 'S', POPT_ARG_STRING, NULL, 'S', "Set the client signing state", "on|off|required" },
	{"machine-pass", 'P', POPT_ARG_NONE, NULL, 'P', "Use stored machine account password" },
	POPT_TABLEEND
};
