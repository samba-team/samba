/* 
   Samba Unix/Linux SMB client library 
   Version 3.0
   Distributed SMB/CIFS Server Management Utility 
   Copyright (C) 2001 Steve French  (sfrench@us.ibm.com)
   Copyright (C) 2001 Jim McDonough (jmcd@us.ibm.com)
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)
   Copyright (C) 2001 Andrew Bartlett (abartlet@samba.org)

   Originally written by Steve and Jim. Largely rewritten by tridge in
   November 2001.

   Reworked again by abartlet in December 2001

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
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */
 
/*****************************************************/
/*                                                   */
/*   Distributed SMB/CIFS Server Management Utility  */
/*                                                   */
/*   The intent was to make the syntax similar       */
/*   to the NET utility (first developed in DOS      */
/*   with additional interesting & useful functions  */
/*   added in later SMB server network operating     */
/*   systems).                                       */
/*                                                   */
/*****************************************************/

#include "includes.h"
#include "../utils/net.h"

/***********************************************************************/
/* Beginning of internationalization section.  Translatable constants  */
/* should be kept in this area and referenced in the rest of the code. */
/*                                                                     */
/* No functions, outside of Samba or LSB (Linux Standards Base) should */
/* be used (if possible).                                              */
/***********************************************************************/

#define YES_STRING              "Yes"
#define NO_STRING               "No"

/************************************************************************************/
/*                       end of internationalization section                        */
/************************************************************************************/

/* Yes, these buggers are globals.... */
char *opt_requester_name = NULL;
char *opt_host = NULL; 
char *opt_password = NULL;
char *opt_user_name = NULL;
char *opt_workgroup = NULL;
int opt_long_list_entries = 0;
int opt_reboot = 0;
int opt_force = 0;
int opt_port = 0;
int opt_maxusers = -1;
char *opt_comment = "";
int opt_flags = -1;
int opt_jobid = 0;
int opt_timeout = 0;
char *opt_target_workgroup = NULL;

static BOOL got_pass = False;
BOOL opt_have_ip = False;
struct in_addr opt_dest_ip;

extern pstring global_myname;

/*
  run a function from a function table. If not found then
  call the specified usage function 
*/
int net_run_function(int argc, const char **argv, struct functable *table, 
		     int (*usage_fn)(int argc, const char **argv))
{
	int i;
	
	if (argc < 1) {
		d_printf("\nUsage: \n");
		return usage_fn(argc, argv);
	}
	for (i=0; table[i].funcname; i++) {
		if (StrCaseCmp(argv[0], table[i].funcname) == 0)
			return table[i].fn(argc-1, argv+1);
	}
	d_printf("No command: %s\n", argv[0]);
	return usage_fn(argc, argv);
}


/****************************************************************************
connect to \\server\ipc$  
****************************************************************************/
static struct cli_state *connect_to_ipc(struct in_addr *server_ip, const char *server_name)
{
	struct cli_state *c;
	NTSTATUS nt_status;

	if (!got_pass) {
		char *pass = getpass("Password:");
		if (pass) {
			opt_password = strdup(pass);
		}
	}
	
	nt_status = cli_full_connection(&c, opt_requester_name, server_name, 
					server_ip, opt_port,
					"IPC$", "IPC",  
					opt_user_name, opt_workgroup,
					opt_password, strlen(opt_password));
	
	if (NT_STATUS_IS_OK(nt_status)) {
		return c;
	} else {
		DEBUG(0,("Cannot connect to server.  Error was %s\n", 
			 get_nt_error_msg(nt_status)));

		/* Display a nicer message depending on the result */

		if (NT_STATUS_V(nt_status) == 
		    NT_STATUS_V(NT_STATUS_LOGON_FAILURE))
			d_printf("The username or password was not correct.\n");

		return NULL;
	}
}

/****************************************************************************
connect to \\server\ipc$ anonymously
****************************************************************************/
static struct cli_state *connect_to_ipc_anonymous(struct in_addr *server_ip, const char *server_name)
{
	struct cli_state *c;
	NTSTATUS nt_status;

	nt_status = cli_full_connection(&c, opt_requester_name, server_name, 
					server_ip, opt_port,
					"IPC$", "IPC",  
					"", "",
					"", 0);
	
	if (NT_STATUS_IS_OK(nt_status)) {
		return c;
	} else {
		DEBUG(0,("Cannot connect to server (anonymously).  Error was %s\n", get_nt_error_msg(nt_status)));
		return NULL;
	}
}

static BOOL net_find_server(unsigned flags, struct in_addr *server_ip, char **server_name)
{

	if (opt_host) {
		*server_name = strdup(opt_host);
	}		

	if (opt_have_ip) {
		*server_ip = opt_dest_ip;
		if (!*server_name) {
			*server_name = strdup(inet_ntoa(opt_dest_ip));
		}
	} else if (*server_name) {
		/* resolve the IP address */
		if (!resolve_name(*server_name, server_ip, 0x20))  {
			DEBUG(1,("Unable to resolve server name\n"));
			return False;
		}
	} else if (flags & NET_FLAGS_PDC) {
		struct in_addr *ip_list;
		int addr_count;
		if (get_dc_list(True /* PDC only*/, opt_target_workgroup, &ip_list, &addr_count)) {
			fstring dc_name;
			if (addr_count < 1) {
				return False;
			}
			
			*server_ip = *ip_list;
			
			if (is_zero_ip(*server_ip))
				return False;
			
			if (!lookup_dc_name(global_myname, opt_target_workgroup, server_ip, dc_name))
				return False;
				
			*server_name = strdup(dc_name);
		}
		
	} else if (flags & NET_FLAGS_DMB) {
		struct in_addr msbrow_ip;
		/*  if (!resolve_name(MSBROWSE, &msbrow_ip, 1)) */
		if (!resolve_name(opt_target_workgroup, &msbrow_ip, 0x1B))  {
			DEBUG(1,("Unable to resolve domain browser via name lookup\n"));
			return False;
		} else {
			*server_ip = msbrow_ip;
		}
		*server_name = strdup(inet_ntoa(opt_dest_ip));
	} else if (flags & NET_FLAGS_MASTER) {
		struct in_addr brow_ips;
		if (!resolve_name(opt_target_workgroup, &brow_ips, 0x1D))  {
				/* go looking for workgroups */
			DEBUG(1,("Unable to resolve master browser via name lookup\n"));
			return False;
		} else {
			*server_ip = brow_ips;
		}
		*server_name = strdup(inet_ntoa(opt_dest_ip));
	} else if (!(flags & NET_FLAGS_LOCALHOST_DEFAULT_INSANE)) {
		extern struct in_addr loopback_ip;
		*server_ip = loopback_ip;
		*server_name = strdup("127.0.0.1");
	}

	if (!server_name || !*server_name) {
		DEBUG(1,("no server to connect to\n"));
		return False;
	}

	return True;
}

struct cli_state *net_make_ipc_connection(unsigned flags)
{
	char *server_name = NULL;
	struct in_addr server_ip;
	struct cli_state *cli;

	if (!net_find_server(flags, &server_ip, &server_name)) {
		d_printf("\nUnable to find a suitable server\n");
		return NULL;
	}

	if (flags & NET_FLAGS_ANONYMOUS) {
		cli = connect_to_ipc_anonymous(&server_ip, server_name);
	} else {
		cli = connect_to_ipc(&server_ip, server_name);
	}
	SAFE_FREE(server_name);
	return cli;
}


static int net_usage(int argc, const char **argv)
{
	d_printf("  net ads [command]\tto run ADS commands\n"\
		 "  net rap [command]\tto run RAP (pre-RPC) commands\n"\
		 "  net rpc [command]\tto run RPC commands\n"\
		 "  net rap help\n"\
		 "\nType \"net help <option>\" to get more information on that option\n");
	return -1;
}

static int help_usage(int argc, const char **argv)
{
	d_printf(
"\n"\
"Usage: net help <function>\n"\
"\n"\
"Valid functions are:\n"\
"  RPC RAP ADS FILE SHARE SESSION SERVER DOMAIN PRINTQ USER GROUP VALIDATE\n"\
"  GROUPMEMBER ADMIN SERVICE PASSWORD TIME LOOKUP\n");
	return -1;
}

/*
  handle "net help *" subcommands
*/
static int net_help(int argc, const char **argv)
{
	struct functable func[] = {
		{"ADS", net_ads_usage},	
		{"RAP", net_rap_usage},
		{"RPC", net_rpc_usage},

		{"FILE", net_rap_file_usage},
		{"SHARE", net_rap_share_usage},
		{"SESSION", net_rap_session_usage},
		{"SERVER", net_rap_server_usage},
		{"DOMAIN", net_rap_domain_usage},
		{"PRINTQ", net_rap_printq_usage},
		{"USER", net_rap_user_usage},
		{"GROUP", net_rap_group_usage},
		{"VALIDATE", net_rap_validate_usage},
		{"GROUPMEMBER", net_rap_groupmember_usage},
		{"ADMIN", net_rap_admin_usage},
		{"SERVICE", net_rap_service_usage},
		{"PASSWORD", net_rap_password_usage},
		{"TIME", net_time_usage},
		{"LOOKUP", net_lookup_usage},

		{"HELP", help_usage},
		{NULL, NULL}};

	return net_run_function(argc, argv, func, help_usage);
}

/* main function table */
static struct functable net_func[] = {
	{"RPC", net_rpc},
	{"RAP", net_rap},
	{"ADS", net_ads},

	/* eventually these should auto-choose the transport ... */
	{"FILE", net_rap_file},
	{"SHARE", net_rap_share},
	{"SESSION", net_rap_session},
	{"SERVER", net_rap_server},
	{"DOMAIN", net_rap_domain},
	{"PRINTQ", net_rap_printq},
	{"USER", net_rap_user},
	{"GROUP", net_rap_group},
	{"VALIDATE", net_rap_validate},
	{"GROUPMEMBER", net_rap_groupmember},
	{"ADMIN", net_rap_admin},
	{"SERVICE", net_rap_service},	
	{"PASSWORD", net_rap_password},
	{"TIME", net_time},
	{"LOOKUP", net_lookup},

	{"HELP", net_help},
	{NULL, NULL}
};


/****************************************************************************
  main program
****************************************************************************/
 int main(int argc, const char **argv)
{
	int opt,i;
	char *p;
	int rc = 0;
	int argc_new = 0;
	const char ** argv_new;
	poptContext pc;
	static char *servicesf = dyn_CONFIGFILE;
	static int debuglevel;

	struct poptOption long_options[] = {
		{"help",        'h', POPT_ARG_NONE,   0,     'h'},
		{"workgroup",   'w', POPT_ARG_STRING, &opt_target_workgroup},
		{"myworkgroup", 'W', POPT_ARG_STRING, &opt_workgroup},
		{"user",        'U', POPT_ARG_STRING, &opt_user_name, 'U'},
		{"ipaddress",   'I', POPT_ARG_STRING, 0,     'I'},
		{"port",        'p', POPT_ARG_INT,    &opt_port},
		{"myname",      'n', POPT_ARG_STRING, &opt_requester_name},
		{"conf",        's', POPT_ARG_STRING, &servicesf},
		{"debug",       'd', POPT_ARG_INT,    &debuglevel, 'd'},
		{"debuglevel",  'd', POPT_ARG_INT,    &debuglevel, 'd'},
		{"server",      'S', POPT_ARG_STRING, &opt_host},
		{"comment",     'C', POPT_ARG_STRING, &opt_comment},
		{"maxusers",    'M', POPT_ARG_INT,    &opt_maxusers},
		{"flags",       'F', POPT_ARG_INT,    &opt_flags},
		{"jobid",       'j', POPT_ARG_INT,    &opt_jobid},
		{"long",        'l', POPT_ARG_NONE,   &opt_long_list_entries},
		{"reboot",        'r', POPT_ARG_NONE,   &opt_reboot},
		{"force",        'f', POPT_ARG_NONE,   &opt_force},
		{"timeout",       't', POPT_ARG_INT,    &opt_timeout},
		{ 0, 0, 0, 0}
	};

	got_pass = 0;
	zero_ip(&opt_dest_ip);

	dbf = x_stderr;
	
	pc = poptGetContext(NULL, argc, (const char **) argv, long_options, 
			    POPT_CONTEXT_KEEP_FIRST);
	
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'h':
			net_usage(argc, argv);
			exit(0);
			break;
		case 'I':
			opt_dest_ip = *interpret_addr2(poptGetOptArg(pc));
			if (is_zero_ip(opt_dest_ip))
				d_printf("\nInvalid ip address specified\n");
			else
				opt_have_ip = True;
			break;
		case 'U':
			opt_user_name = strdup(opt_user_name);
			p = strchr(opt_user_name,'%');
			if (p) {
				*p = 0;
				opt_password = p+1;
				got_pass = 1;
			}
			break;
		default:
			d_printf("\nInvalid option %c (%d)\n", (char)opt, opt);
			net_usage(argc, argv);
		}
	}

	lp_load(servicesf,True,False,False);       

	DEBUGLEVEL = debuglevel;

	argv_new = (const char **)poptGetArgs(pc);

	argc_new = argc;
	for (i=0; i<argc; i++) {
		if (argv_new[i] == NULL) {
			argc_new = i;
			break;
		}
	}
  	 
	if (!opt_requester_name) {
		static fstring myname;
		get_myname(myname);
		opt_requester_name = myname;
	}

	if (!opt_user_name && getenv("LOGNAME")) {
		opt_user_name = getenv("LOGNAME");
	}

	if (!opt_workgroup) {
		opt_workgroup = lp_workgroup();
	}
	
	if (!opt_target_workgroup) {
		opt_target_workgroup = lp_workgroup();
	}
	
	if (!*global_myname) {
		char *p2;

		fstrcpy(global_myname, myhostname());
		p2 = strchr_m(global_myname, '.');
		if (p2) 
                        *p2 = 0;
	}
	
	strupper(global_myname);

	load_interfaces();

	rc = net_run_function(argc_new-1, argv_new+1, net_func, net_usage);
	
	DEBUG(2,("return code = %d\n", rc));
	return rc;
}
