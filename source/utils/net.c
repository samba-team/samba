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

#define PASSWORD_PROMPT		"Password: "
#define YES_STRING              "Yes"
#define NO_STRING               "No"

/************************************************************************************/
/*                       end of internationalization section                        */
/************************************************************************************/

extern int optind, opterr, optopt;

/* Yes, these buggers are globals.... */
char *opt_requester_name = NULL;
char *opt_host = NULL; 
char *opt_password = NULL;
char *opt_user_name = NULL;
char *opt_workgroup = NULL;
int opt_long_list_entries = 0;
int opt_port = 0;
int opt_maxusers = -1;
char *opt_comment = "";
int opt_flags = -1;
int opt_jobid = 0;
char *opt_target_workgroup = NULL;

static BOOL got_pass = False;
static BOOL have_ip = False;
static struct in_addr dest_ip;

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
	struct nmb_name called, calling;
	struct in_addr ip;
	fstring sharename;

	make_nmb_name(&calling, opt_requester_name, 0x0);
	make_nmb_name(&called , server_name, 0x20);
	
again:
	ip = *server_ip;
	
	DEBUG(3,("Connecting to host=%s share=%s\n\n", 
		 server_name, "IPC$"));
	
	/* have to open a new connection */
	if (!(c=cli_initialise(NULL)) || cli_set_port(c, opt_port) != opt_port ||
	    !cli_connect(c, server_name, &ip)) {
		DEBUG(1,("Connection to %s failed\n", server_name));
		return NULL;
	}
	
	c->protocol = PROTOCOL_NT1;
	
	if (!cli_session_request(c, &calling, &called)) {
		char *p;
		DEBUG(1,("session request to %s failed (%s)\n", 
			 called.name, cli_errstr(c)));
		cli_shutdown(c);
		if ((p=strchr(called.name, '.'))) {
			*p = 0;
			goto again;
		}
		if (strcmp(called.name, "*SMBSERVER")) {
			make_nmb_name(&called , "*SMBSERVER", 0x20);
			goto again;
		}
		return NULL;
	}
	
	DEBUG(4,(" session request ok\n"));
	
	if (!cli_negprot(c)) {
		DEBUG(1,("protocol negotiation failed\n"));
		cli_shutdown(c);
		return NULL;
	}
	
	if (!got_pass) {
		char *pass = getpass(PASSWORD_PROMPT);
		if (pass) {
			opt_password = strdup(pass);
		}
	}
	
	if (!cli_session_setup(c, opt_user_name, 
			       opt_password, strlen(opt_password),
			       opt_password, strlen(opt_password),
			       opt_workgroup)) {
		/*  try again with a null username */
		if (!cli_session_setup(c, "", "", 0, "", 0, opt_workgroup)) { 
			DEBUG(1,("session setup failed: %s\n", cli_errstr(c)));
			cli_shutdown(c);
			return NULL;
		}
		DEBUG(3,("Anonymous login successful\n"));
	}
	
	snprintf(sharename, sizeof(sharename), "\\\\%s\\IPC$", server_name);

	DEBUG(4,(" session setup ok\n"));
	if (!cli_send_tconX(c, sharename, "?????",
			    opt_password, strlen(opt_password)+1)) {
		DEBUG(1,("tree connect failed: %s\n", cli_errstr(c)));
		cli_shutdown(c);
		return NULL;
	}
	
	DEBUG(4,(" tconx ok\n"));
	
	return c;
}

struct cli_state *net_make_ipc_connection(unsigned flags)
{
	char *server_name = opt_host;
	struct in_addr server_ip;
	struct cli_state *cli;
	if (have_ip) {
		server_ip = dest_ip;
		if (!server_name) {
			server_name = strdup(inet_ntoa(dest_ip));
		}
	} else if (server_name) {
		/* resolve the IP address */
		if (!resolve_name(server_name, &server_ip, 0x20))  {
			DEBUG(1,("Unable to resolve domain browser via name lookup\n"));
			return NULL;
		}
	} else if (flags & NET_FLAGS_DMB) {
		struct in_addr *ip_list;
		int addr_count;
		char *our_workgroup = lp_workgroup();
		struct in_addr msbrow_ip;
		/*  if (!resolve_name(MSBROWSE, &msbrow_ip, 1)) */
		if (!get_dmb_list(&ip_list,&addr_count)){
			DEBUG(1,("Unable to resolve global master browser via name lookup"));
			if (!resolve_name(our_workgroup, &msbrow_ip, 0x1D))  {
				DEBUG(1,("Unable to resolve domain browser via name lookup\n"));
				return NULL;
			} else {
				server_ip = msbrow_ip;
			}
		} else {
			server_ip = *ip_list;
		}
	} else if (flags & NET_FLAGS_MASTER) {
		char *temp_workgroup = lp_workgroup();
		char our_workgroup[16];
		struct in_addr brow_ips;

		/* find target server based on workgroup or domain */
		if((temp_workgroup == 0) || (temp_workgroup[0] == 0)) 
			temp_workgroup = lp_workgroup();  /* by default enum our local workgroup or domain */
		
		safe_strcpy(our_workgroup, temp_workgroup,15);
		
		if (!resolve_name(our_workgroup, &brow_ips, 0x1D))  {
				/* go looking for workgroups */
			DEBUG(1,("Unable to resolve master browser via name lookup\n"));
			return NULL;
		} else {
			server_ip = brow_ips;
		}
	} else if (!(flags & NET_FLAGS_LOCALHOST_DEFAULT_INSANE)) {
		extern struct in_addr loopback_ip;
		server_ip = loopback_ip;
		server_name = "127.0.0.1";
	}

	if (!server_name) {
		DEBUG(1,("no server to connect to\n"));
		return NULL;
	}

	cli = connect_to_ipc(&server_ip, server_name);
	if(!cli) {
		d_printf("\nUnable to connect to target server\n");
		return False;
	}
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
	d_printf("\n"\
"Usage: net help <function>\n"\
"\n"\
"Valid functions are:\n"\
"  RPC RAP ADS\n");
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
		{"HELP", help_usage},
		{NULL, NULL}};

	return net_run_function(argc, argv, func, help_usage);
}

/* main function table */
static struct functable net_func[] = {
	{"RPC", net_rpc},
	{"RAP", net_rap},
	{"ADS", net_ads},
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
	extern pstring global_myname;
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
		{ 0, 0, 0, 0}
	};

	got_pass = 0;
	zero_ip(&dest_ip);

	dbf = x_stdout;
	
	pc = poptGetContext(NULL, argc, (const char **) argv, long_options, 
			    POPT_CONTEXT_KEEP_FIRST);
	
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'h':
			net_usage(argc, argv);
			exit(0);
			break;
		case 'I':
			dest_ip = *interpret_addr2(poptGetOptArg(pc));
			if (is_zero_ip(dest_ip))
				d_printf("\nInvalid ip address specified\n");
			else
				have_ip = True;
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

	DEBUGLEVEL = debuglevel;

	lp_load(servicesf,True,False,False);       

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

	if (!*global_myname) {
		char *p2;

		fstrcpy(global_myname, myhostname());
		p2 = strchr_m(global_myname, '.');
		if (p2) 
                        *p2 = 0;
	}
	
	load_interfaces();

	rc = net_run_function(argc_new-1, argv_new+1, net_func, net_usage);
	
	DEBUG(2,("return code = %d\n", rc));
	return rc;
}
