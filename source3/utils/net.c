/* 
   Samba Unix/Linux SMB client library 
   Version 3.0
   Distributed SMB/CIFS Server Management Utility 
   Copyright (C) 2001 Steve French  (sfrench@us.ibm.com)
   Copyright (C) 2001 Jim McDonough (jmcd@us.ibm.com)
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)

   Originally written by Steve and Jim. Largely rewritten by tridge in
   November 2001.

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

#define NET_USAGE \
    "\nUsage: \n"\
    "  net domain \tto list domains \n"\
    "  net file \tto list open files on a server \n"\
    "  net group \tto list user groups  \n"\
    "  net groupmember to list users in a group \n"\
    "  net password\t to change the password of a user\n"\
    "  net printq \tto list the print queues on a server\n"\
    "  net server \tto list servers in a domain\n"\
    "  net session \tto list clients with open sessions to a server\n"\
    "  net share \tto list shares exported by a server\n"\
    "  net user \tto list users\n"\
    "  net validate \tto check whether a user and the corresponding password are valid\n"\
    "  net help\n"\
    "\nType \"net help <option>\" to get more information on that option\n"

#define NET_FILE_USAGE \
    "\nnet file [misc. options] [targets]"\
    "\n\tenumerates all open files on file server\n"\
    "\nnet file USER <username> [misc. options] [targets]"\
    "\n\tenumerates all files opened by username on file server\n"\
    "\nnet file CLOSE <id> [misc. options] [targets]"\
    "\n\tcloses specified file on target server\n"

#define FILE_INFO_DISPLAY \
    "File ID          %d\n"\
    "User name        %s\n"\
    "Locks            0x%-4.2x\n"\
    "Path             %s\n"\
    "Permissions      0x%x\n"
#define FILE_ENUM_DISPLAY \
    "\nEnumerating open files on remote server:\n\n"\
    "\n\tFileId  Opened by            Perms  Locks  Path \n"\
    "\t------  ---------            -----  -----  ---- \n"

#define NET_SHARE_USAGE \
    "\nnet share [misc. options] [targets] \n"\
    "\tenumerates all exported resources (network shares) on target server\n"\
    "\nnet share ADD <name=serverpath> [misc. options] [targets]"\
    "\n\tAdd a share from a server (makes the export active)\n"\
    "\nnet share DELETE <sharename> [misc. options] [targets]\n"\
    "\tor"\
    "\nnet share CLOSE <sharename> [misc. options] [targets]"\
    "\n\tDeletes a share from a server (makes the export inactive)\n"
    
#define SHARE_ENUM_DISPLAY \
    "\nEnumerating shared resources (exports) on remote server:\n\n"\
    "\nShare name   Type     Description\n"\
    "----------   ----     -----------\n"


#define NET_SESSION_USAGE \
    "\nnet session [misc. options] [targets]"\
    "\n\tenumerates all active SMB/CIFS sessions on target server\n"\
    "\nnet session DELETE <client_name> [misc. options] [targets] \n"\
    "\tor"\
    "\nnet session CLOSE <client_name> [misc. options] [targets]"\
    "\n\tDeletes (closes) a session from specified client to server\n"

#define SESSION_ENUM_DISPLAY \
    "Computer             User name            Client Type        Opens Idle time\n\n"\
    "------------------------------------------------------------------------------\n"


#define SESSION_DISPLAY_ONE \
    "User name       %-20.20s\n"\
    "Computer        %-20.20s\n"\
    "Guest logon     %-20.20s\n"\
    "Client Type     %-40.40s\n"\
    "Sess time       %2.2d:%2.2d:%2.2d\n"\
    "Idle time       %2.2d:%2.2d:%2.2d\n"

#define SESSION_DISPLAY_CONNS \
    "Share name     Type     # Opens\n"\
    "------------------------------------------------------------------------------\n"

#define NET_SERVER_USAGE \
    "\nUsage:\n"\
    "  net server [domain]\tlists the servers in the specified domain or workgroup.\n"\
    "    If domain is not specified, it uses the current domain or workgroup as\n"\
    "    the default.\n"

#define SERVER_ENUM_DISPLAY "\nEnumerating servers in this domain or workgroup: \n\n"  \
    "\n\tServer name          Server description\n"\
    "\t-------------        ----------------------------\n"


#define NET_DOMAIN_USAGE \
    "\nUsage:\n"\
    "  net domain [misc. options] [target]\n\tlists the domains "\
    "or workgroups visible on the current network\n"

#define DOMAIN_ENUM_DISPLAY \
    "\nEnumerating domains:\n\n"\
    "\n\tDomain name          Server name of Browse Master\n"\
    "\t-------------        ----------------------------\n"

#define NET_PRINTQ_USAGE \
    "\nUsage:\n"\
    " net printq [misc. options] [targets]\n"\
    "\tor\n"\
    " net printq list [<queue_name>] [misc. options] [targets]\n"\
    "\tlists the specified queue and jobs on the target server.\n"\
    "\tIf the queue name is not specified, all queues are listed.\n\n"\
    " net printq delete [<queue name>] [misc. options] [targets]\n"\
    "\tdeletes the specified job number on the target server, or the\n"\
    "\tprinter queue if no job number is specified\n"
#define PRINTQ_ENUM_DISPLAY \
    "Print queues at \\\\%s\n\n"\
    "Name                         Job #      Size            Status\n\n"\
    "------------------------------------------------------------------"\
    "-------------\n"
#define PRINTQ_DISPLAY_ONE "%-23.23s %5d jobs                      %-22.22s\n"
#define PRINTQ_PRINTER_ACTIVE "*Printer Active*"
#define PRINTQ_PRINTER_PAUSED "*Printer Paused*"
#define PRINTQ_PRINTER_ERROR "*Printer error*"
#define PRINTQ_PRINTER_DELPEND "*Delete Pending*"
#define PRINTQ_PRINTER_STATUNK "**UNKNOWN STATUS**"
#define PRINTQ_DISPLAY_JOB "     %-23.23s %5d %9d            %-22.22s\n"
#define PRINTQ_JOB_PRINTING "Printing"
#define PRINTQ_JOB_QUEUED "Waiting"
#define PRINTQ_JOB_PAUSED "Held in queue"
#define PRINTQ_JOB_SPOOLING "Spooling"
#define PRINTQ_QUEUE_WORD " Queue"

#define NET_USER_USAGE \
    "\nnet user [misc. options] [targets]\n\tEnumerate users\n"\
    "\nnet user DELETE <name> [misc. options] [targets]"\
    "\n\tDelete specified user\n"\
    "\nnet user INFO <name> [misc. options] [targets]"\
    "\n\tList the domain groups of the specified user\n"\
    "\nnet user ADD <name> [-F user flags] [misc. options] [targets]"\
    "\n\tAdd specified user\n"

#define USER_ENUM_DISPLAY \
    "\nEnumerating shared resources (exports) on remote server:\n\n"\
    "\nUser name             Description                                     Home Directory                          Profile Directory\n"\
    "---------             -----------                                     --------------                          -----------------\n"

#define NET_GROUP_USAGE \
    "\nnet group [misc. options] [targets]"\
    "\n\tEnumerate user groups\n"\
    "\nnet group DELETE <name> [misc. options] [targets]"\
    "\n\tDelete specified group\n"\
    "\nnet group ADD <name> [-C comment] [misc. options] [targets]"\
    "\n\tCreate specified group\n"

#define NET_GROUPMEMBER_USAGE \
    "\nnet groupmember LIST <group name> [misc. options] [targets]"\
    "\n\t Enumerate users in a group\n"\
    "\nnet groupmember DELETE <group name> <user name> [misc. options] "\
    "[targets]\n\t Delete sepcified user from specified group\n"\
    "\nnet groupmember ADD <group name> <user name> [misc. options] [targets]"\
    "\n\t Add specified user to specified group\n"

            
#define NET_ADMIN_USAGE \
    "\nnet admin <remote command to execute> [cmd arguments [environment]] [misc_options] [targets]\n"\
    "\texecutes a remote command on an os/2 target server\n"
    
#define NET_PASSWORD_USAGE \
    "\nnet password <user> <old password> <new password> [misc_options] [targets]\n"\
    "\tchanges the password for the specified user on a remote server\n"

#define NET_SERVICE_USAGE \
    "\nnet service [misc. options] [targets] \n"\
    "\tenumerates all running service daemons on target server\n"\
    "\nnet service ADD <name> [service startup arguments] [misc. options] [targets]"\
    "\n\tStart named service on remote server\n"\
    "\nnet service DELETE <name> [misc. options] [targets]\n"\
    "\n\tStop named service on remote server\n"
    

#define NET_VALIDATE_USAGE \
    "\nnet validate <username> [password]\n"\
    "\tValidate user and password to check whether they can access target server or domain\n"

#define TARGET_USAGE      "\nValid targets: choose one (none defaults to using the %s)\n"
#define GLBL_LCL_MASTER   "global browsemaster or local browse master if that is not found"
#define DOMAIN_MASTER     "local domain browse master"
#define LOCAL_HOST        "localhost"
#define MISC_OPT_USAGE    "\nValid miscellaneous options are:\n"
#define SERVER_USAGE      "\t-S or --server=<server>\t\tserver name\n"
#define IPADDRESS_USAGE   "\t-I or --ipaddress=<ipaddr>\tip address of target server\n"
#define PORT_USAGE        "\t-p or --port=<port number>\tconnection port on target server\n"
#define WORKGROUP_USAGE   "\t-w or --workgroup=<wg>\t\ttarget workgroup or domain name\n"
#define COMMENT_USAGE     "\t-C or --comment=<comment>\tdescriptive comment (for add only)\n"
#define MYWORKGROUP_USAGE "\t-W or --myworkgroup=<wg>\tclient workgroup\n"
#define DEBUG_USAGE       "\t-d or --debug=<level>\t\tdebug level (0-10)\n"
#define MYNAME_USAGE      "\t-n or --myname=<name>\t\tclient name\n"
#define USER_USAGE        "\t-U or --user=<name>\t\tuser name\n"
#define CONF_USAGE        "\t-s or --conf=<path>\t\tpathname of smb.conf file\n"
#define JOBID_USAGE       "\t-j or --jobid=<job id>\t\tjob id\n"
#define MAXUSERS_USAGE    "\t-M or --maxusers=<num>\t\tmax users allowed for share\n"
#define LONG_USAGE        "\t-l or --long\t\t\tDisplay full information\n"

#define ERRMSG_NOCONN_TARGET_SRVR	"\nUnable to connect to target server\n"
#define ERRMSG_NOCONN_BROWSE_MSTR	"\nUnable to connect to browse master\n"
#define ERRMSG_NOT_IMPLEMENTED		"\nNot implemented\n"
#define ERRMSG_FILEID_MISSING		"\nMissing fileid of file to close\n\n"
#define ERRMSG_GROUPNAME_MISSING        "\n\nGroup name not specified\n"
#define ERRMSG_USERNAME_MISSING        "\n\nUser name not specified\n"
#define ERRMSG_SHARENAME_MISSING        "\n\nShare name not specified\n"
#define ERRMSG_TARGET_WG_NOT_VALID      "\nTarget workgroup option not valid "\
					"except on net server command, ignored"
#define ERRMSG_INVALID_HELP_OPTION	"\nInvalid help option\n"
#define ERRMSG_INVALID_OPTION		"\nInvalid option %c (%d)\n"
#define ERRMSG_INVALID_IPADDRESS        "\nInvalid ip address specified\n"
#define ERRMSG_SPURIOUS_PARM            "\nInvalid paramater ignored: %s\n"
#define ERRMSG_BOTH_SERVER_IPADDRESS    "\nTarget server and IP address both "\
  "specified. Do not set both at the same time.  The target IP address was used\n"
#define ERRMSG_INVALID_DOMAIN_ACTION	"\nInvalid action for NET DOMAIN command"\
  " ignored. Only listing domains permitted.\n"

/* Column headers */
#define COMMENT_STR   "Comment "
#define USER_STR      "User name "
#define GROUP_STR     "Group name "  
#define SERVICE_STR   "Service name"
#define HOMED_STR     "Home directory "
#define LOGONS_STR    "Logon script "

#define FLAGS_MASTER 1
#define FLAGS_DMB 2

static const char *share_type[] = {
  "Disk",
  "Print",
  "Dev",
  "IPC"
};

/************************************************************************************/
/*                       end of internationalization section                        */
/************************************************************************************/

extern int optind, opterr, optopt;

static struct cli_state *cli;
static char *opt_requester_name;
static char *opt_host; 
static char *opt_password;
static char *opt_user_name;
static char *opt_workgroup;
static int opt_long_list_entries;
static int opt_port;
static int opt_maxusers = -1;
static char *opt_comment = "";
static int opt_flags = -1;
static int opt_jobid;
static char *opt_target_workgroup;

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

	if (argc < 1)
		return usage_fn(argc, argv);

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
static struct cli_state *connect_to_ipc(char *server)
{
	struct cli_state *c;
	struct nmb_name called, calling;
	struct in_addr ip;
	char *server_n;
	fstring servicename;
	char *sharename;

	/* make a copy so we don't modify the global string 'service' */
	safe_strcpy(servicename, "IPC$", sizeof(servicename)-1);
	sharename = servicename;
	if (*sharename == '\\') {
		server = sharename+2;
		sharename = strchr(server,'\\');
		if (!sharename) return NULL;
		*sharename = 0;
		sharename++;
	}
	
	if(server == NULL)
		return NULL;  /* if ip addr specified, ascii version of ip address is used as host name */
	
	server_n = server; 
	
        zero_ip(&ip);
	make_nmb_name(&calling, opt_requester_name, 0x0);
	make_nmb_name(&called , server, 0x20);
	
again:
	if (have_ip)
		ip = dest_ip;
	else 
                zero_ip(&ip);
	
	DEBUG(3,("Connecting to host=%s\\share=%s\n\n", 
		 server, "IPC$"));
	
	/* have to open a new connection */
	if (!(c=cli_initialise(NULL)) || cli_set_port(c, opt_port) != opt_port ||
	    !cli_connect(c, server_n, &ip)) {
		DEBUG(1,("Connection to %s failed\n", server_n));
		return NULL;
	}
	
	c->protocol = PROTOCOL_NT1;
	
	if (!cli_session_request(c, &calling, &called)) {
		char *p;
		DEBUG(1,("session request to %s failed (%s)\n", 
			 called.name, cli_errstr(c)));
		cli_shutdown(c);
		SAFE_FREE(c);
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
		SAFE_FREE(c);
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
			SAFE_FREE(c);
			return NULL;
		}
		DEBUG(3,("Anonymous login successful\n"));
	}
	
	DEBUG(4,(" session setup ok\n"));
	if (!cli_send_tconX(c, sharename, "?????",
			    opt_password, strlen(opt_password)+1)) {
		DEBUG(1,("tree connect failed: %s\n", cli_errstr(c)));
		cli_shutdown(c);
		SAFE_FREE(c);
		return NULL;
	}
	
	DEBUG(4,(" tconx ok\n"));
	
	return c;
}

static BOOL make_ipc_connection(unsigned flags)
{
	if (!opt_host && have_ip) {
		opt_host = strdup(inet_ntoa(dest_ip));
	} else if (!opt_host && (flags & FLAGS_DMB)) {
		struct in_addr *ip_list;
		int addr_count;
		char *our_workgroup = lp_workgroup();
		struct in_addr msbrow_ip;
		/*  if (!resolve_name(MSBROWSE, &msbrow_ip, 1)) */
		if (!get_dmb_list(&ip_list,&addr_count)){
			DEBUG(1,("Unable to resolve global master browser via name lookup"));
			if (!resolve_name(our_workgroup, &msbrow_ip, 0x1D))  {
				DEBUG(1,("Unable to resolve domain browser via name lookup\n"));
				return False;
			} else {
				have_ip = True;
				dest_ip = msbrow_ip;
			}
		} else {
			have_ip = True;
			dest_ip = *ip_list;
		}
	} else if (!opt_host && (flags & FLAGS_MASTER)) {
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
			return False;
		} else {
			have_ip = True;
			dest_ip = brow_ips;
		}
	} else {
		extern struct in_addr loopback_ip;
		dest_ip = loopback_ip;
		have_ip = True;
	}

	if (!opt_host && !have_ip) {
		DEBUG(1,("no server to connect to\n"));
		return False;
	}
	if (!opt_host) {
		opt_host = strdup(inet_ntoa(dest_ip));
	}
	
	cli = connect_to_ipc(opt_host);
	if(!cli) {
		d_printf(ERRMSG_NOCONN_TARGET_SRVR);
		return False;
	}
	return True;
}


static int general_usage(int argc, const char **argv)
{
	d_printf(TARGET_USAGE, LOCAL_HOST); /* target options */
	d_printf(SERVER_USAGE);
	d_printf(IPADDRESS_USAGE);
	
	d_printf(MISC_OPT_USAGE); /* misc options */
	d_printf(PORT_USAGE);
	d_printf(MYWORKGROUP_USAGE);
	d_printf(DEBUG_USAGE);
	d_printf(MYNAME_USAGE);
	d_printf(USER_USAGE);
	d_printf(CONF_USAGE);
	return -1;
}

static int net_usage(int argc, const char **argv)
{
	d_printf(NET_USAGE);
	return -1;
}

static int file_usage(int argc, const char **argv)
{
	d_printf(NET_FILE_USAGE); /* command syntax */

	general_usage(argc, argv);
	return -1;
}




/***************************************************************************
  list info on an open file
***************************************************************************/
static void file_fn(const char * pPath, const char * pUser, uint16 perms, 
		    uint16 locks, uint32 id)
{
	d_printf("\t%-7.1d %-20.20s 0x%-4.2x %-6.1d %s\n",
		 id, pUser, perms, locks, pPath);
}

static void one_file_fn(const char *pPath, const char *pUser, uint16 perms, 
			uint16 locks, uint32 id)
{
	d_printf(FILE_INFO_DISPLAY, id, pUser, locks, pPath, perms);
}


static int net_file_close(int argc, const char **argv)
{
	if (argc == 0)
		return file_usage(argc, argv);

	if (!make_ipc_connection(0)) 
                return -1;

	return cli_NetFileClose(cli, atoi(argv[0]));
}

static int net_file_info(int argc, const char **argv)
{
	if (argc == 0)
		return file_usage(argc, argv);

	if (!make_ipc_connection(0)) 
                return -1;

	return cli_NetFileGetInfo(cli, atoi(argv[0]), one_file_fn);
}

static int net_file_user(int argc, const char **argv)
{
	if (argc == 0)
		return file_usage(argc, argv);

	d_printf("net file user not implemented yet\n");
	return -1;
}

static int net_file(int argc, const char **argv)
{
	struct functable func[] = {
		{"CLOSE", net_file_close},
		{"USER", net_file_user},
		{"INFO", net_file_info},
		{NULL, NULL}
	};
	
	if (argc == 0) {
		if (!make_ipc_connection(0)) 
                        return -1;

		/* list open files */
		d_printf(FILE_ENUM_DISPLAY); /* file list header */
		return cli_NetFileEnum(cli, NULL, NULL, file_fn);
	}

	return net_run_function(argc, argv, func, file_usage);
}
		       
static int share_usage(int argc, const char **argv)
{
	d_printf(NET_SHARE_USAGE); /* command syntax */
	general_usage(argc, argv);
	return -1;
}

static void long_share_fn(const char *share_name, uint32 type, const char *comment, void *state)
{
	d_printf("%-12.12s %-8.8s %-50.50s\n", share_name, share_type[type], comment);
}

static void share_fn(const char *share_name, uint32 type, const char *comment, void *state)
{
	d_printf("%-12.12s\n", share_name);
}

static int net_share_delete(int argc, const char **argv)
{
	if (argc == 0) {
		d_printf(ERRMSG_SHARENAME_MISSING);
		return -1;
	}

	if (!make_ipc_connection(0)) 
                return -1;

	return cli_NetShareDelete(cli, argv[0]);
}

static int net_share_add(int argc, const char **argv)
{
	RAP_SHARE_INFO_2 sinfo;
	char *p;
	char *sharename;

	if (argc == 0) {
		d_printf(ERRMSG_SHARENAME_MISSING);
		return -1;
	}
			
	if (!make_ipc_connection(0)) 
                return -1;

	sharename = strdup(argv[0]);
	p = strchr(sharename, '=');
	*p = 0;
	strlcpy(sinfo.share_name, sharename, sizeof(sinfo.share_name));
	sinfo.reserved1 = '\0';
	sinfo.share_type = 0;
	sinfo.comment = opt_comment;
	sinfo.perms = 0;
	sinfo.maximum_users = opt_maxusers;
	sinfo.active_users = 0;
	sinfo.path = p+1;
	memset(sinfo.password, '\0', sizeof(sinfo.password));
	sinfo.reserved2 = '\0';
	
	return cli_NetShareAdd(cli, &sinfo);
}


static int net_share(int argc, const char **argv)
{
	struct functable func[] = {
		{"DELETE", net_share_delete},
		{"CLOSE", net_share_delete},
		{"ADD", net_share_add},
		{NULL, NULL}
	};

	if (argc == 0) {
		if (!make_ipc_connection(0)) 
                        return -1;
		if (opt_long_list_entries) {
			d_printf(SHARE_ENUM_DISPLAY);
			return cli_RNetShareEnum(cli, long_share_fn, NULL);
		}
		return cli_RNetShareEnum(cli, share_fn, NULL);
	}

	return net_run_function(argc, argv, func, share_usage);
}
		    
		
static int session_usage(int argc, const char **argv)
{
	d_printf(NET_SESSION_USAGE); /* command syntax */
	
	general_usage(argc, argv);
	return -1;
}
    
static void list_sessions_func(char *wsname, char *username, uint16 conns,
			uint16 opens, uint16 users, uint32 sess_time,
			uint32 idle_time, uint32 user_flags, char *clitype)
{
	int hrs = idle_time / 3600;
	int min = (idle_time / 60) % 60;
	int sec = idle_time % 60;
	
	d_printf("\\\\%-18.18s %-20.20s %-18.18s %5d %2.2d:%2.2d:%2.2d\n",
		 wsname, username, clitype, opens, hrs, min, sec);
}

static void display_session_func(const char *wsname, const char *username, uint16 conns,
				 uint16 opens, uint16 users, uint32 sess_time,
				 uint32 idle_time, uint32 user_flags, const char *clitype)
{
	int ihrs = idle_time / 3600;
	int imin = (idle_time / 60) % 60;
	int isec = idle_time % 60;
	int shrs = sess_time / 3600;
	int smin = (sess_time / 60) % 60;
	int ssec = sess_time % 60;
	d_printf(SESSION_DISPLAY_ONE, username, wsname, 
		 (user_flags&0x0)?YES_STRING:NO_STRING, clitype,
		 shrs, smin, ssec, ihrs, imin, isec);
}

static void display_conns_func(uint16 conn_id, uint16 conn_type, uint16 opens, uint16 users, uint32 conn_time, const char *username, const char *netname)
{
	d_printf("%-14.14s %-8.8s %5d\n", netname, share_type[conn_type], opens);
}

static int net_session_info(int argc, const char **argv)
{
	int res;
	const char *sessname;

	if (!make_ipc_connection(0)) 
                return -1;

	if (argc == 0) 
                return session_usage(argc, argv);

	sessname = argv[0];

	res = cli_NetSessionGetInfo(cli, sessname, display_session_func);
	if (res < 0) 
                return res;

	d_printf(SESSION_DISPLAY_CONNS);
	return cli_NetConnectionEnum(cli, sessname, display_conns_func);
}

static int net_session_delete(int argc, const char **argv)
{
	if (!make_ipc_connection(0)) return -1;

	if (argc == 0) 
                return session_usage(argc, argv);

	return cli_NetSessionDel(cli, argv[0]);
}

static int net_session(int argc, const char **argv)
{
	struct functable func[] = {
		{"INFO", net_session_info},
		{"DELETE", net_session_delete},
		{"CLOSE", net_session_delete},
		{NULL, NULL}
	};

	if (argc == 0) {
		if (!make_ipc_connection(0)) 
                        return -1;
		return cli_NetSessionEnum(cli, list_sessions_func);
	}

	return net_run_function(argc, argv, func, session_usage);
}
	
/****************************************************************************
list a server name
****************************************************************************/
static void display_server_func(const char *name, uint32 m, const char *comment, void * reserved)
{
	d_printf("\t%-16.16s     %s\n", name, comment);
}


static int server_usage(int argc, const char **argv)
{
	d_printf(NET_SERVER_USAGE); /* command syntax */
	
	general_usage(argc, argv);
	return -1;
}
		    
static int net_server(int argc, const char **argv)
{
	if (!make_ipc_connection(FLAGS_MASTER)) 
                return -1;
	d_printf(SERVER_ENUM_DISPLAY); /* header for list of servers */
	return cli_NetServerEnum(cli, cli->server_domain, SV_TYPE_ALL, display_server_func,NULL); 
}
		      
static int domain_usage(int argc, const char **argv)
{
	d_printf(NET_DOMAIN_USAGE); /* command syntax */
	
	general_usage(argc, argv);
	return -1;
}

		  
static int net_domain(int argc, const char **argv)
{
	if (!make_ipc_connection(FLAGS_DMB)) 
                return -1;
	d_printf(DOMAIN_ENUM_DISPLAY); /* header for list of domains */
	return cli_NetServerEnum(cli, cli->server_domain, SV_TYPE_DOMAIN_ENUM, display_server_func,NULL);	
}
		      
static int printq_usage(int argc, const char **argv)
{
	d_printf(NET_PRINTQ_USAGE);
	
	general_usage(argc, argv);
	return -1;
}	

static void enum_queue(const char *queuename, uint16 pri, uint16 start, uint16 until, 
		       const char *sep, const char *pproc, const char *dest, 
		       const char *qparms, const char *qcomment, uint16 status, 
		       uint16 jobcount) {
	pstring queuecol;
	pstring statcol;

	pstrcpy(queuecol, queuename);
	pstrcat(queuecol, PRINTQ_QUEUE_WORD);
	
	switch (status) {
	case 0:
		pstrcpy(statcol, PRINTQ_PRINTER_ACTIVE);
		break;
	case 1:
		pstrcpy(statcol, PRINTQ_PRINTER_PAUSED);
		break;
	case 2:
		pstrcpy(statcol, PRINTQ_PRINTER_ERROR);
		break;
	case 3:
		pstrcpy(statcol, PRINTQ_PRINTER_DELPEND);
		break;
	default:
		pstrcpy(statcol, PRINTQ_PRINTER_STATUNK);
	}
	d_printf(PRINTQ_DISPLAY_ONE, queuecol, jobcount, statcol);
}

static void enum_jobs(uint16 jobid, const char *ownername, const char *notifyname, 
		      const char *datatype, const char *jparms, uint16 pos, 
		      uint16 status, const char *jstatus, uint submitted, uint jobsize, 
		      const char *comment) {
	pstring statcol;

	switch (status) {
	case 0:
		pstrcpy(statcol, PRINTQ_JOB_QUEUED);
		break;
	case 1:
		pstrcpy(statcol, PRINTQ_JOB_PAUSED);
		break;
	case 2:
		pstrcpy(statcol, PRINTQ_JOB_SPOOLING);
		break;
	case 3:
		pstrcpy(statcol, PRINTQ_JOB_PRINTING);
		break;
	default:
		pstrcpy(statcol, PRINTQ_PRINTER_STATUNK);
	}
	d_printf(PRINTQ_DISPLAY_JOB, ownername, jobid, jobsize, statcol);
}

static int net_printq_info(int argc, const char **argv)
{
	if (argc == 0) 
                return printq_usage(argc, argv);

	if (!make_ipc_connection(0)) 
                return -1;

	return cli_NetPrintQGetInfo(cli, argv[0], enum_queue, enum_jobs);
}

static int net_printq_delete(int argc, const char **argv)
{
	if (argc == 0) 
                return printq_usage(argc, argv);

	if (!make_ipc_connection(0)) 
                return -1;

	return cli_printjob_del(cli, atoi(argv[0]));
}

static int net_printq(int argc, const char **argv)
{
	struct functable func[] = {
		{"INFO", net_printq_info},
		{"DELETE", net_printq_delete},
		{NULL, NULL}
	};

	if (argc == 0) {
		if (!make_ipc_connection(0)) 
                        return -1;
		return cli_NetPrintQEnum(cli, enum_queue, enum_jobs);
	}

	return net_run_function(argc, argv, func, printq_usage);
}

	
static int user_usage(int argc, const char **argv)
{
	d_printf(NET_USER_USAGE); /* command syntax */
	
	general_usage(argc, argv);
	return -1;
} 
	
static void user_fn(const char *user_name, const char *comment, const char * home_dir, 
		    const char * logon_script, void *state)
{
	d_printf("%-21.21s\n", user_name);
}

void long_user_fn(const char *user_name, const char *comment, const char * home_dir, const char * logon_script, void *state)
{
	d_printf("%-21.21s %-47.47s %-35.35s %35.35s\n", user_name, comment, home_dir, logon_script);
}
      		  
void group_member_fn(const char *user_name, void *state)
{
	d_printf("%-21.21s\n", user_name);
}

static int net_user_delete(int argc, const char **argv)
{
	if (argc == 0) 
                return user_usage(argc, argv);

	if (!make_ipc_connection(0)) 
                return -1;

	return cli_NetUserDelete(cli, argv[0]);
}

static int net_user_add(int argc, const char **argv)
{
	RAP_USER_INFO_1 userinfo;

	if (argc == 0) 
                return user_usage(argc, argv);

	if (!make_ipc_connection(0)) 
                return -1;
			
	safe_strcpy(userinfo.user_name, argv[0], sizeof(userinfo.user_name));
	if (opt_flags == -1) 
                opt_flags = 0x21; 
			
	userinfo.userflags = opt_flags;
	userinfo.reserved1 = '\0';
	userinfo.comment = opt_comment;
	userinfo.priv = 1; 
	userinfo.home_dir = NULL;
	userinfo.logon_script = NULL;
	
	return cli_NetUserAdd(cli, &userinfo);
}

static int net_user_info(int argc, const char **argv)
{
	if (argc == 0) 
                return user_usage(argc, argv);

	if (!make_ipc_connection(0)) 
                return -1;

	return cli_NetUserGetGroups(cli, argv[0], group_member_fn, NULL);
}

int net_user(int argc, const char **argv)
{
	struct functable func[] = {
		{"ADD", net_user_add},
		{"INFO", net_user_info},
		{"DELETE", net_user_delete},
		{NULL, NULL}
	};

	if (argc == 0) {
		if (!make_ipc_connection(0)) 
                        return -1;
		if (opt_long_list_entries) {
			d_printf(USER_ENUM_DISPLAY);
			return cli_RNetUserEnum(cli, long_user_fn, NULL);
		}
		return cli_RNetUserEnum(cli, user_fn, NULL); 
	}

	return net_run_function(argc, argv, func, user_usage);
}


static int group_usage(int argc, const char **argv)
{
	d_printf(NET_GROUP_USAGE); /* command syntax */
	
	general_usage(argc, argv);
	return -1;
}

static void long_group_fn(const char *group_name, const char *comment, void *state)
{
	d_printf("%-21.21s %-50.50s\n", group_name, comment);
}

static void group_fn(const char *group_name, const char *comment, void *state)
{
	d_printf("%-21.21s\n", group_name);
}

static int net_group_delete(int argc, const char **argv)
{
	if (argc == 0) 
                return group_usage(argc, argv);

	if (!make_ipc_connection(0)) 
                return -1;

	return cli_NetGroupDelete(cli, argv[0]);
}

static int net_group_add(int argc, const char **argv)
{
	RAP_GROUP_INFO_1 grinfo;

	if (argc == 0) 
                return group_usage(argc, argv);

	if (!make_ipc_connection(0)) 
                return -1;
			
	/* BB check for length 21 or smaller explicitly ? BB */
	safe_strcpy(grinfo.group_name, argv[0], sizeof(grinfo.group_name));
	grinfo.reserved1 = '\0';
	grinfo.comment = opt_comment;
	
	return cli_NetGroupAdd(cli, &grinfo);
}

static int net_group(int argc, const char **argv)
{
	struct functable func[] = {
		{"ADD", net_group_add},
		{"DELETE", net_group_delete},
		{NULL, NULL}
	};

	if (argc == 0) {
		if (!make_ipc_connection(0)) 
                        return -1;
		if (opt_long_list_entries) {
			d_printf("%-21.21s %-50.50s\n", GROUP_STR, COMMENT_STR); 
			d_printf("-----------------------------\n");
			return cli_RNetGroupEnum(cli, long_group_fn, NULL);
		}
		return cli_RNetGroupEnum(cli, group_fn, NULL); 
	}

	return net_run_function(argc, argv, func, group_usage);
}

static int groupmember_usage(int argc, const char **argv)
{
	d_printf(NET_GROUPMEMBER_USAGE); /* command syntax */
	
	general_usage(argc, argv);
	return -1;
}


static int net_groupmember_add(int argc, const char **argv)
{
	if (argc != 2) 
                return groupmember_usage(argc, argv);

	if (!make_ipc_connection(0)) 
                return -1;

	return cli_NetGroupAddUser(cli, argv[0], argv[1]);
}

static int net_groupmember_delete(int argc, const char **argv)
{
	if (argc != 2) 
                return groupmember_usage(argc, argv);

	if (!make_ipc_connection(0)) 
                return -1;

	return cli_NetGroupDelUser(cli, argv[0], argv[1]);
}

static int net_groupmember_list(int argc, const char **argv)
{
	if (argc == 0) 
                return groupmember_usage(argc, argv);

	if (!make_ipc_connection(0)) 
                return -1;

	return cli_NetGroupGetUsers(cli, argv[0], group_member_fn, NULL ); 
}

static int net_groupmember(int argc, const char **argv)
{
	struct functable func[] = {
		{"ADD", net_groupmember_add},
		{"LIST", net_groupmember_list},
		{"DELETE", net_groupmember_delete},
		{NULL, NULL}
	};
	
	return net_run_function(argc, argv, func, groupmember_usage);
}

static int validate_usage(int argc, const char **argv)
{
	d_printf(NET_VALIDATE_USAGE); /* command syntax */
	
	general_usage(argc, argv);
	return -1;
}

static int net_validate(int argc, const char **argv)
{
	d_printf(ERRMSG_NOT_IMPLEMENTED);
	return 0;
}

static int service_usage(int argc, const char **argv)
{
	d_printf(NET_SERVICE_USAGE); /* command syntax */
	
	general_usage(argc, argv);
	return -1;
}

static int net_service_add(int argc, const char **argv)
{
	d_printf(ERRMSG_NOT_IMPLEMENTED);
	return 0;
}

static int net_service_delete(int argc, const char **argv)
{
	d_printf(ERRMSG_NOT_IMPLEMENTED);
	return 0;
}

static int net_service(int argc, const char **argv)
{
	struct functable func[] = {
		{"ADD", net_service_add},
		{"DELETE", net_service_delete},
		{NULL, NULL}
	};

	if (argc == 0) {
		if (!make_ipc_connection(0)) 
                        return -1;
		if (opt_long_list_entries) {
			d_printf("%-15.15s %-50.50s\n", SERVICE_STR, COMMENT_STR); 
			d_printf("-----------------------------\n");
			return cli_RNetServiceEnum(cli, long_group_fn, NULL);
		}
		return cli_RNetServiceEnum(cli, group_fn, NULL); 
	}

	return net_run_function(argc, argv, func, service_usage);
}

static int password_usage(int argc, const char **argv)
{
	d_printf(NET_PASSWORD_USAGE); /* command syntax */
	
	general_usage(argc, argv);
	return -1;
}


static int net_password(int argc, const char **argv)
{
	if (argc < 3) 
                return password_usage(argc, argv);

	if (!make_ipc_connection(0)) 
                return -1;
	
	/* BB Add check for password lengths? */
	return cli_oem_change_password(cli, argv[0], argv[2], argv[1]);
}

static int admin_usage(int argc, const char **argv)
{
	d_printf(NET_ADMIN_USAGE); /* command syntax */
	
	general_usage(argc, argv);
	return -1;
}


static int net_admin(int argc, const char **argv)
{
	d_printf(ERRMSG_NOT_IMPLEMENTED);
	return 0;
}

static int help_usage(int argc, const char **argv)
{
	d_printf("\n"\
"Usage: net help <function>\n"\
"\n"\
"Valid functions are:\n"\
"  FILE SHARE SESSION SERVER DOMAIN PRINTQ USER GROUP\n"\
"  VALIDATE GROUPMEMBER ADMIN SERVICE PASSWORD ADS\n");
	return -1;
}

/*
  handle "net help *" subcommands
*/
static int net_help(int argc, const char **argv)
{
	struct functable func[] = {
		{"FILE", file_usage},
		{"SHARE", share_usage},
		{"SESSION", session_usage},
		{"SERVER", server_usage},
		{"DOMAIN", domain_usage},
		{"PRINTQ", printq_usage},
		{"USER", user_usage},
		{"GROUP", group_usage},
		{"VALIDATE", validate_usage},
		{"GROUPMEMBER", groupmember_usage},
		{"ADMIN", admin_usage},
		{"SERVICE", service_usage},
		{"PASSWORD", password_usage},
		{"ADS", net_ads_usage},
		{NULL, NULL}};

	return net_run_function(argc, argv, func, help_usage);
}

/* main function table */
static struct functable net_func[] = {
	{"FILE", net_file},
	{"SHARE", net_share},
	{"SESSION", net_session},
	{"SERVER", net_server},
	{"DOMAIN", net_domain},
	{"PRINTQ", net_printq},
	{"USER", net_user},
	{"GROUP", net_group},
	{"VALIDATE", net_validate},
	{"GROUPMEMBER", net_groupmember},
	{"ADMIN", net_admin},
	{"SERVICE", net_service},
	{"PASSWORD", net_password},
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
				d_printf(ERRMSG_INVALID_IPADDRESS);
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
			d_printf(ERRMSG_INVALID_OPTION, (char)opt, opt);
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
