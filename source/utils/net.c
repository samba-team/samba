/* 
   Samba Unix/Linux SMB client library 
   Version 3.0
   Distributed SMB/CIFS Server Management Utility 
   Copyright (C) 2001 Steve French  (sfrench@us.ibm.com)
   Copyright (C) 2001 Jim McDonough (jmcd@us.ibm.com)

   connect_to_ipc based on similar routine
   Copyright (C) Andrew Tridgell 1994-1998

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

#include <includes.h>

/***********************************************************************/
/* Beginning of internationalization section.  Translatable constants  */
/* should be kept in this area and referenced in the rest of the code. */
/*                                                                     */
/* No functions, outside of Samba or LSB (Linux Standards Base) should */
/* be used (if possible).                                              */
/***********************************************************************/

typedef struct _functable {
  int func;
  char funcname[12];
} functable;

/* functions available */
#define FILEF     1
#define SHAREF    2
#define SESSIONF  3
#define SERVERF   4
#define DOMAINF   5
#define PRINTQF   6 
#define USERF     7
#define GROUPF    8
#define VALIDATEF 9
#define GROUPMEMBERF 10
#define HELPF     11

const functable net_func[] = {
  { FILEF, "FILE"},
  { SHAREF, "SHARE"},
  { SESSIONF, "SESSION"},
  { SERVERF, "SERVER"},
  { DOMAINF, "DOMAIN"},
  { PRINTQF, "PRINTQ"},
  { USERF, "USER"},
  { GROUPF, "GROUP"},
  { VALIDATEF, "VALIDATE"},
  { GROUPMEMBERF, "GROUPMEMBER"},
  { HELPF, "HELP"}
};

/* subfunctions available */
#define OTHER_SF  0
#define LIST_SF   1  /* enumerate */
#define ADD_SF    2  /* also used for create and start */
#define DELETE_SF 3  /* also used for close and stop */
#define INFO_SF   4  /* get information */

const functable net_subfunc[] = {
  { LIST_SF, "LIST" },
  { LIST_SF, "ENUMERATE" },
  { ADD_SF, "ADD" },
  { ADD_SF, "CREATE" },
  { DELETE_SF, "CLOSE" },
  { DELETE_SF, "DELETE" }
};

const char share_type[][6] = {
  "Disk",
  "Print",
  "Dev",
  "IPC"
};

#define PASSWORD_PROMPT		"Password: "
#define YES_STRING              "Yes"
#define NO_STRING               "No"

#define NET_USAGE \
    "\nUsage: \n"\
    "  net domain \tto list domains \n"\
    "  net file \tto list open files on a server \n"\
    "  net group \tto list user groups  \n"\
    "  net groupmember to list users in a group \n"\
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
    "\nnet file <username> [misc. options] [targets]"\
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
    "\nnet user ADD <user> [-M user flags] [misc. options] [targets]"\
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
#define DEBUG_USAGE       "\t-d or --debug=<level>\t\tdebug level (1-9)\n"
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
#define HOMED_STR     "Home directory "
#define LOGONS_STR    "Logon script "
/************************************************************************************/
/*                       end of internationalization section                        */
/************************************************************************************/

extern int optind, opterr, optopt;
extern struct in_addr ipzero;

struct cli_state *cli;
static pstring global_requester_name;
static pstring host; /* target server */
static pstring password;
static pstring global_user_name;
static pstring global_workgroup;
static int port = SMB_PORT;
static int long_list_entries = 0;
static BOOL got_pass = False;
static BOOL have_ip = False;
struct in_addr dest_ip;

int get_func(const char *parm)
{
  int i;

  for (i=0;i<=sizeof(net_func);i++)
    if (StrnCaseCmp(parm, net_func[i].funcname,10) == 0)
      return net_func[i].func;
  return 0;
}

int get_subfunc(const char *parm)
{
  int i;

  for (i=0;i<=sizeof(net_subfunc);i++)
    if (StrnCaseCmp(parm, net_subfunc[i].funcname,10) == 0)
      return net_subfunc[i].func;
  return 0;
}

/****************************************************************************
  
****************************************************************************/
struct cli_state *connect_to_ipc(char *server)
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
	
  ip = ipzero;
  make_nmb_name(&calling, global_requester_name, 0x0);
  make_nmb_name(&called , server, 0x20);

 again:
  if (have_ip)
    ip = dest_ip;
  else ip = ipzero;

  DEBUG(3,("Connecting to host=%s\\share=%s\n\n", 
	   server, "IPC$"));

  /* have to open a new connection */
  if (!(c=cli_initialise(NULL)) || (cli_set_port(c, port) == 0) ||
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
      pstrcpy(password, pass);
    }
  }

  if (!cli_session_setup(c, global_user_name, 
			 password, strlen(password),
			 password, strlen(password),
			 global_workgroup)) {
    /*  try again with a null username */
    if (!cli_session_setup(c, "", "", 0, "", 0, global_workgroup)) { 
      DEBUG(1,("session setup failed: %s\n", cli_errstr(c)));
      cli_shutdown(c);
      SAFE_FREE(c);
      return NULL;
    }
    DEBUG(3,("Anonymous login successful\n"));
  }
	
  DEBUG(4,(" session setup ok\n"));
  if (!cli_send_tconX(c, sharename, "?????",
		      password, strlen(password)+1)) {
    DEBUG(1,("tree connect failed: %s\n", cli_errstr(c)));
    cli_shutdown(c);
    SAFE_FREE(c);
    return NULL;
  }

  DEBUG(4,(" tconx ok\n"));

  return c;
}


void usage(void)
{
  printf(NET_USAGE);
}

void file_usage(void)
{
  printf(NET_FILE_USAGE); /* command syntax */
  
  printf(TARGET_USAGE, LOCAL_HOST); /* target options */
  printf(SERVER_USAGE);
  printf(IPADDRESS_USAGE);

  printf(MISC_OPT_USAGE); /* misc options */
  printf(PORT_USAGE);
  printf(MYWORKGROUP_USAGE);
  printf(DEBUG_USAGE);
  printf(MYNAME_USAGE);
  printf(USER_USAGE);
  printf(CONF_USAGE);
}

/***************************************************************************
  list info on an open file
***************************************************************************/
static void file_fn(const char * pPath, const char * pUser, uint16 perms, uint16 locks, uint32 id)
{
  printf("\t%-7.1d %-20.20s 0x%-4.2x %-6.1d %s\n",
	 id, pUser, perms, locks, pPath);
}

static void one_file_fn(const char *pPath, const char *pUser, uint16 perms, uint16 locks, uint32 id)
{
  printf(FILE_INFO_DISPLAY, id, pUser, locks, pPath, perms);
}

int net_file(int subfunct, char * id)
{
  struct in_addr target_ip;
	
  if((have_ip == 0) && (host[0] == 0)) {
    if (!resolve_name("localhost", &target_ip, 0x20)) {
      DEBUG(1,("No remote server specified, unable to resolve connection to localhost via name lookup"));
      return -1;
    } else {
      have_ip = True;
      dest_ip = target_ip;
    }
  }
  if(host[0] == 0) strncpy(host, inet_ntoa(dest_ip),16);
  cli = connect_to_ipc(host);
  if(!cli) {
    printf(ERRMSG_NOCONN_TARGET_SRVR);
    return -2;
  }

  if(subfunct == DELETE_SF) { /* close open file on remote server */
    if(id == NULL) {
      printf(ERRMSG_FILEID_MISSING);
      return -1;
    } else 
      return cli_NetFileClose(cli, atoi(id));
  } else if(subfunct == LIST_SF) {
    printf(FILE_ENUM_DISPLAY); /* file list header */
    return cli_NetFileEnum(cli, NULL, NULL, file_fn);
  } else if ((subfunct == OTHER_SF) && id) {
    return cli_NetFileGetInfo(cli, atoi(id), one_file_fn);
  } else file_usage();
  return -1;
}
		       
void share_usage(void)
{
  printf(NET_SHARE_USAGE); /* command syntax */

  printf(TARGET_USAGE, LOCAL_HOST); /* target options */
  printf(SERVER_USAGE);
  printf(IPADDRESS_USAGE);

  printf(MISC_OPT_USAGE); /* misc options */
  printf(PORT_USAGE);
  printf(COMMENT_USAGE);
  printf(MAXUSERS_USAGE);
  printf(MYWORKGROUP_USAGE);
  printf(DEBUG_USAGE);
  printf(MYNAME_USAGE);
  printf(USER_USAGE);
  printf(CONF_USAGE);
}

void long_share_fn(const char *share_name, uint32 type, const char *comment, void *state)
{
   printf("%-12.12s %-8.8s %-50.50s\n", share_name, share_type[type], comment);
}

void share_fn(const char *share_name, uint32 type, const char *comment, void *state)
{
   printf("%-12.12s\n", share_name);
}

int net_share(int subfunct, char * sharename, char * comment, int maxusers)
{
  struct in_addr target_ip;
 
  if((have_ip == 0) && (host[0] == 0)) {
    if (!resolve_name("localhost", &target_ip, 0x20)) {
      DEBUG(1,("No remote server specified, unable to resolve connection to localhost via name lookup"));
      return -1;

    } else {
      have_ip = True;
      dest_ip = target_ip;
    }
  }
  if(host[0] == 0) 
    strncpy(host, inet_ntoa(dest_ip),16);
  cli = connect_to_ipc(host);
  if(!cli) {
    printf(ERRMSG_NOCONN_TARGET_SRVR);
    return -2;
  }
  if (subfunct == DELETE_SF) {
    if (sharename == NULL) {
      printf(ERRMSG_SHARENAME_MISSING);
      return -1;
    } else
      return cli_NetShareDelete(cli, sharename);
  } else if (subfunct == LIST_SF) {
      if(long_list_entries) {
       printf(SHARE_ENUM_DISPLAY);
       return cli_RNetShareEnum(cli, long_share_fn, NULL);
      } else {      
       return cli_RNetShareEnum(cli, share_fn, NULL);
      }
  } else if (subfunct == ADD_SF) {
    if (sharename == NULL) {
      printf(ERRMSG_SHARENAME_MISSING);
      return -1;
    } else {
      RAP_SHARE_INFO_2 sinfo;
      char *p;

      p = strchr(sharename, '=');
      strncpy(sinfo.share_name, sharename, PTR_DIFF(p,sharename));
      sinfo.reserved1 = '\0';
      sinfo.share_type = 0;
      sinfo.comment = comment;
      sinfo.perms = 0;
      sinfo.maximum_users = maxusers;
      sinfo.active_users = 0;
      sinfo.path = p+1;
      bzero(sinfo.password, sizeof(sinfo.password));
      sinfo.reserved2 = '\0';

      return cli_NetShareAdd(cli, &sinfo);
    }
  } else
    printf(ERRMSG_NOT_IMPLEMENTED);
  return -1;
}
		    
		
void session_usage(void)
{
  printf(NET_SESSION_USAGE); /* command syntax */

  printf(TARGET_USAGE, LOCAL_HOST); /* Target options */
  printf(SERVER_USAGE);
  printf(IPADDRESS_USAGE);

  printf(MISC_OPT_USAGE); /* Misc options */
  printf(PORT_USAGE);
  printf(MYWORKGROUP_USAGE);
  printf(DEBUG_USAGE);
  printf(MYNAME_USAGE);
  printf(USER_USAGE);
  printf(CONF_USAGE);
}
    
void list_sessions_func(char *wsname, char *username, uint16 conns,
			uint16 opens, uint16 users, uint32 sess_time,
			uint32 idle_time, uint32 user_flags, char *clitype)
{
  int hrs = idle_time / 3600;
  int min = (idle_time / 60) % 60;
  int sec = idle_time % 60;

  printf("\\\\%-18.18s %-20.20s %-18.18s %5d %2.2d:%2.2d:%2.2d\n",
	 wsname, username, clitype, opens, hrs, min, sec);
}

void display_session_func(char *wsname, char *username, uint16 conns,
			  uint16 opens, uint16 users, uint32 sess_time,
			  uint32 idle_time, uint32 user_flags, char *clitype)
{
  int ihrs = idle_time / 3600;
  int imin = (idle_time / 60) % 60;
  int isec = idle_time % 60;
  int shrs = sess_time / 3600;
  int smin = (sess_time / 60) % 60;
  int ssec = sess_time % 60;
  printf(SESSION_DISPLAY_ONE, username, wsname, 
	 (user_flags&0x0)?YES_STRING:NO_STRING, clitype,
	 shrs, smin, ssec, ihrs, imin, isec);
}

void display_conns_func(uint16 conn_id, uint16 conn_type, uint16 opens, uint16 users, uint32 conn_time, char *username, char *netname)
{
  printf("%-14.14s %-8.8s %5d\n", netname, share_type[conn_type], opens);
}

int net_session(int subfunct, char * sessname)
{
  struct in_addr target_ip;
  int res;
 
  if((have_ip == 0) && (host[0] == 0)) {
    if (!resolve_name("localhost", &target_ip, 0x20)) {
      DEBUG(1,("No remote server specified, unable to resolve connection to localhost via name lookup"));
      return -1;

    } else {
      have_ip = True;
      dest_ip = target_ip;
    }
  }
  if(host[0] == 0)  
    strncpy(host, inet_ntoa(dest_ip),16);
  cli = connect_to_ipc(host);
  if(!cli) {
    printf(ERRMSG_NOCONN_TARGET_SRVR);
    return -2;
  }
  switch(subfunct){
    case LIST_SF:
      if (sessname) {
	res = cli_NetSessionGetInfo(cli, sessname, display_session_func);
	if (res >= 0) {
	  printf(SESSION_DISPLAY_CONNS);
	  return cli_NetConnectionEnum(cli, sessname, display_conns_func);
	} else 
	  return res;
      } else {
	printf(SESSION_ENUM_DISPLAY);
	return cli_NetSessionEnum(cli, list_sessions_func);
      }
    case DELETE_SF:
      return cli_NetSessionDel(cli, sessname);
    default:
      printf(ERRMSG_NOT_IMPLEMENTED);
      session_usage();
  }
  return -1;
}
	
/****************************************************************************
list a server name
****************************************************************************/
static void display_server_func(const char *name, uint32 m, const char *comment, void * reserved)
{
  printf("\t%-16.16s     %s\n", name, comment);
}


void server_usage(void)
{
  printf(NET_SERVER_USAGE); /* command syntax */

  printf(TARGET_USAGE, DOMAIN_MASTER); /* Target options */
  printf(SERVER_USAGE);
  printf(IPADDRESS_USAGE);
  printf(WORKGROUP_USAGE);

  printf(MISC_OPT_USAGE); /* Misc options */
  printf(PORT_USAGE);
  printf(MYWORKGROUP_USAGE);
  printf(DEBUG_USAGE);
  printf(MYNAME_USAGE);
  printf(USER_USAGE);
  printf(CONF_USAGE);
}
		    
int net_server(char * temp_workgroup, int subfunct)
{
  /* try to find master browser for our domain - if we fail try to find pdc */
  char our_workgroup[16];
  struct in_addr brow_ips;

  if((have_ip == 0) && (host[0] == 0)) {
    /* find target server based on workgroup or domain */
    if((temp_workgroup == 0) || (temp_workgroup[0] == 0)) 
      temp_workgroup = lp_workgroup();  /* by default enum our local workgroup or domain */
	
    safe_strcpy(our_workgroup, temp_workgroup,15);
        
    if (!resolve_name(our_workgroup, &brow_ips, 0x1D))  {
      /* go looking for workgroups */
      DEBUG(1,("Unable to resolve master browser via name lookup\n"));
      return -2;
    } else {
      have_ip = True;
      dest_ip = brow_ips;
    }
  }
  if(host[0] == 0) strncpy(host, inet_ntoa(dest_ip),16);
  cli = connect_to_ipc(host);
  if(!cli) {
    printf(ERRMSG_NOCONN_BROWSE_MSTR);
    return -2;
  }
  printf(SERVER_ENUM_DISPLAY); /* header for list of servers */
  return cli_NetServerEnum(cli, cli->server_domain, SV_TYPE_ALL, display_server_func,NULL); 
	
  /* BB add mechanism to find PDC for our domain and send enum to it in this error case */ 
	   
  /* BB add server service (smb server daemon) start and stop */
}
		      
void domain_usage(void)
{
  printf(NET_DOMAIN_USAGE); /* command syntax */

  printf(TARGET_USAGE, GLBL_LCL_MASTER); /* target options */
  printf(SERVER_USAGE);
  printf(IPADDRESS_USAGE);
    
  printf(MISC_OPT_USAGE); /* misc options */
  printf(PORT_USAGE);
  printf(MYWORKGROUP_USAGE);
  printf(DEBUG_USAGE);
  printf(MYNAME_USAGE);
  printf(USER_USAGE);
  printf(CONF_USAGE);
}

		  
int net_domain(void)
{
  char *our_workgroup;
  struct in_addr msbrow_ip;
	

  our_workgroup = lp_workgroup();
  if((have_ip == 0) && (host[0] == 0)) {
    if (!resolve_name(MSBROWSE, &msbrow_ip, 1)) {
      DEBUG(1,("Unable to resolve global master browser via name lookup"));
      if (!resolve_name(our_workgroup, &msbrow_ip, 0x1D))  {
        DEBUG(1,("Unable to resolve domain browser via name lookup\n"));
        return -2;
        } else {
          have_ip = True;
          dest_ip = msbrow_ip;
        }
    } else {
      have_ip = True;
      dest_ip = msbrow_ip;
    }
  }
  if(host[0] == 0)
    strncpy(host, inet_ntoa(dest_ip),16);
  cli = connect_to_ipc(host);
  if(!cli) {
    printf(ERRMSG_NOCONN_BROWSE_MSTR);
    return -2;
  }
  printf(DOMAIN_ENUM_DISPLAY); /* header for list of domains */
  return cli_NetServerEnum(cli, cli->server_domain, SV_TYPE_DOMAIN_ENUM, display_server_func,NULL);	
	   
}
		      
void printq_usage(void)
{
  printf(NET_PRINTQ_USAGE);

  printf(TARGET_USAGE, LOCAL_HOST);
  printf(SERVER_USAGE);
  printf(IPADDRESS_USAGE);

  printf(MISC_OPT_USAGE);
  printf(PORT_USAGE);
  printf(JOBID_USAGE);
  printf(MYWORKGROUP_USAGE);
  printf(DEBUG_USAGE);
  printf(MYNAME_USAGE);
  printf(USER_USAGE);
  printf(CONF_USAGE);
}	

void enum_queue(char *queuename, uint16 pri, uint16 start, uint16 until, char *sep, char *pproc, char *dest, char *qparms, char *qcomment, uint16 status, uint16 jobcount) {
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
  printf(PRINTQ_DISPLAY_ONE, queuecol, jobcount, statcol);
}

void enum_jobs(uint16 jobid, char *ownername, char *notifyname, char *datatype, char *jparms, uint16 pos, uint16 status, char *jstatus, uint submitted, uint jobsize, char *comment) {
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
  printf(PRINTQ_DISPLAY_JOB, ownername, jobid, jobsize, statcol);
}

int net_printq(int subfunct, char * printq, int jobid)
{
  struct in_addr target_ip;
 
  if((have_ip == 0) && (host[0] == 0)) {
    if (!resolve_name("localhost", &target_ip, 0x20)) {
      DEBUG(1,("No remote server specified, unable to resolve connection to localhost via name lookup"));
      return -1;

    } else {
      have_ip = True;
      dest_ip = target_ip;
    }
  }
  if(host[0] == 0) 
    strncpy(host, inet_ntoa(dest_ip),16);
  cli = connect_to_ipc(host);
  if(!cli) {
    printf(ERRMSG_NOCONN_TARGET_SRVR);
    return -2;
  }
  switch(subfunct) {
    case LIST_SF:
	printf(PRINTQ_ENUM_DISPLAY, host);
      if (printq)
	return cli_NetPrintQGetInfo(cli, printq, enum_queue, enum_jobs);
      else
	return cli_NetPrintQEnum(cli, enum_queue, enum_jobs);
    case DELETE_SF:
      return cli_printjob_del(cli, jobid);
    default:
      printf(ERRMSG_NOT_IMPLEMENTED);
      return -1;
  }
}


	
void user_usage(void)
{
  printf(NET_USER_USAGE); /* command syntax */

  printf(TARGET_USAGE, LOCAL_HOST); /* target options */
  printf(SERVER_USAGE);
  printf(IPADDRESS_USAGE);
  printf(WORKGROUP_USAGE);
    
  printf(MISC_OPT_USAGE); /* misc options */
  printf(PORT_USAGE);
  printf(COMMENT_USAGE);
  printf(MYWORKGROUP_USAGE);
  printf(DEBUG_USAGE);
  printf(MYNAME_USAGE);
  printf(USER_USAGE);
  printf(CONF_USAGE);
  printf(LONG_USAGE);
} 
	
void user_fn(const char *user_name, const char *comment, const char * home_dir, const char * logon_script, void *state)
{
   printf("%-21.21s\n", user_name);
}

void long_user_fn(const char *user_name, const char *comment, const char * home_dir, const char * logon_script, void *state)
{
   printf("%-21.21s %-47.47s %-35.35s %35.35s\n", user_name, comment, home_dir, logon_script);
}
      		  
int net_user(int subfunct, char * username, char * comment, int flags)
{
  struct in_addr target_ip;
 
  if((have_ip == 0) && (host[0] == 0)) {
    if (!resolve_name("localhost", &target_ip, 0x20)) {
      DEBUG(1,("No remote server specified, unable to resolve connection to localhost via name lookup"));
      return -1;

    } else {
      have_ip = True;
      dest_ip = target_ip;
    }
  }
  if(host[0] == 0)  
    strncpy(host, inet_ntoa(dest_ip),16);
  cli = connect_to_ipc(host);
  if(!cli) {
    printf(ERRMSG_NOCONN_TARGET_SRVR);
    return -2;
  }
  if (subfunct == DELETE_SF) {
    if (username == NULL) {
      printf(ERRMSG_USERNAME_MISSING);
      return -1;
    } else
      return cli_NetUserDelete(cli, username);
  } else if (subfunct == LIST_SF) {
      if(long_list_entries) {
        printf(USER_ENUM_DISPLAY);
	    return cli_RNetUserEnum(cli, long_user_fn, NULL);
      }
      else
	  return cli_RNetUserEnum(cli, user_fn, NULL); 
  } else if (subfunct == ADD_SF) {
    if (username == NULL) {
      printf(ERRMSG_USERNAME_MISSING);
      return -1;
    } else {
      RAP_USER_INFO_1 userinfo;
      
      safe_strcpy(userinfo.user_name, username, sizeof(userinfo.user_name));
      if(flags == -1) flags = 0x21; 

      userinfo.userflags = flags;
      userinfo.reserved1 = '\0';
      userinfo.comment = comment;
      userinfo.priv = 1; 
      userinfo.home_dir = NULL;
      userinfo.logon_script = NULL;

      return cli_NetUserAdd(cli, &userinfo);
    }
  } else
    printf(ERRMSG_NOT_IMPLEMENTED);
  return -1;

}


void group_usage(void)
{
  printf(NET_GROUP_USAGE); /* command syntax */

  printf(TARGET_USAGE, LOCAL_HOST); /* target options */
  printf(SERVER_USAGE);
  printf(IPADDRESS_USAGE);

  printf(MISC_OPT_USAGE); /* misc options */
  printf(PORT_USAGE);
  printf(COMMENT_USAGE);
  printf(MYWORKGROUP_USAGE);
  printf(DEBUG_USAGE);
  printf(MYNAME_USAGE);
  printf(USER_USAGE);
  printf(WORKGROUP_USAGE);
  printf(CONF_USAGE);
  printf(LONG_USAGE);
}

void long_group_fn(const char *group_name, const char *comment, void *state)
{
   printf("%-21.21s %-50.50s\n", group_name, comment);
}

void group_fn(const char *group_name, const char *comment, void *state)
{
   printf("%-21.21s\n", group_name);
}

int net_group(int subfunct, char * groupname, char * comment)
{
  struct in_addr target_ip;
 
  if((have_ip == 0) && (host[0] == 0)) {
    if (!resolve_name("localhost", &target_ip, 0x20)) {
      DEBUG(1,("No remote server specified, unable to resolve connection to localhost via name lookup"));
      return -1;

    } else {
      have_ip = True;
      dest_ip = target_ip;
    }
  }
  if(host[0] == 0)  
    strncpy(host, inet_ntoa(dest_ip),16);
  cli = connect_to_ipc(host);
  if(!cli) {
    printf(ERRMSG_NOCONN_TARGET_SRVR);
    return -2;
  }
  if (subfunct == DELETE_SF) {
    if (groupname == NULL) {
      printf(ERRMSG_GROUPNAME_MISSING);
      return -1;
    } else
      return cli_NetGroupDelete(cli, groupname);
  } else if (subfunct == LIST_SF) {
    if(long_list_entries) {
	  printf("%-21.21s %-50.50s\n", GROUP_STR, COMMENT_STR); 
      printf("-----------------------------\n");
	  return cli_RNetGroupEnum(cli, long_group_fn, NULL);
    }
    else
      return cli_RNetGroupEnum(cli, group_fn, NULL); 
  } else if (subfunct == ADD_SF) {
    if (groupname == NULL) {
      printf(ERRMSG_GROUPNAME_MISSING);
      return -1;
    } else {
      RAP_GROUP_INFO_1 grinfo;

  /* BB check for length 21 or smaller explicitly ? BB */
      safe_strcpy(grinfo.group_name, groupname, sizeof(grinfo.group_name));
      grinfo.reserved1 = '\0';
      grinfo.comment = comment;

      return cli_NetGroupAdd(cli, &grinfo);
    }
  } else
    printf(ERRMSG_NOT_IMPLEMENTED);
  return -1;
}

void groupmember_usage(void)
{
  printf(NET_GROUPMEMBER_USAGE); /* command syntax */

  printf(TARGET_USAGE, LOCAL_HOST); /* target options */
  printf(SERVER_USAGE);
  printf(IPADDRESS_USAGE);

  printf(MISC_OPT_USAGE); /* misc options */
  printf(PORT_USAGE);
  printf(MYWORKGROUP_USAGE);
  printf(DEBUG_USAGE);
  printf(MYNAME_USAGE);
  printf(USER_USAGE);
  printf(WORKGROUP_USAGE);
  printf(CONF_USAGE);
}

void group_member_fn(const char *user_name, void *state)
{
   printf("%-21.21s\n", user_name);
}


int net_groupmember(int subfunct, char * groupname, char * username)
{
    struct in_addr target_ip;

    if((have_ip == 0) && (host[0] == 0)) {
        if (!resolve_name("localhost", &target_ip, 0x20)) {
            DEBUG(1,("No remote server specified, unable to resolve connection to localhost via name lookup"));
            return -1;
        } else {
            have_ip = True;
            dest_ip = target_ip;
        }
    }
    if(host[0] == 0)  
        strncpy(host, inet_ntoa(dest_ip),16);
    cli = connect_to_ipc(host);
    if(!cli) {
        printf(ERRMSG_NOCONN_TARGET_SRVR);
        return -2;
    }
    if (groupname == NULL) {
      printf(ERRMSG_GROUPNAME_MISSING);
      return -1;
    }

    if (subfunct == LIST_SF)
      return cli_NetGroupGetUsers(cli, groupname, group_member_fn, NULL ); 

    if (username == NULL) {
      printf(ERRMSG_USERNAME_MISSING);
      return -1;
    }

    if (subfunct == DELETE_SF)
      return cli_NetGroupDelUser(cli, groupname, username);
    else if (subfunct == ADD_SF)
      return cli_NetGroupAddUser(cli, groupname, username);
    else
      printf(ERRMSG_NOT_IMPLEMENTED);
    return -1;

}

void validate_usage(void)
{
  printf(NET_VALIDATE_USAGE); /* command syntax */
  
  printf(TARGET_USAGE, GLBL_LCL_MASTER); /* target options */
  printf(SERVER_USAGE);
  printf(IPADDRESS_USAGE);
  printf(WORKGROUP_USAGE);
    
  printf(MISC_OPT_USAGE); /* misc options */
  printf(PORT_USAGE);
  printf(MYWORKGROUP_USAGE);
  printf(DEBUG_USAGE);
  printf(MYNAME_USAGE);
  printf(USER_USAGE);
  printf(CONF_USAGE);
}

int net_validate(char * username)
{
  printf(ERRMSG_NOT_IMPLEMENTED);
  return 0;
}

/****************************************************************************
  main program
****************************************************************************/
int main(int argc,char *argv[])
{
  int opt,i;
  char *p;
  int rc = 0;
  int func = 0;
  int subfunc = LIST_SF;
  int argc_new = 0;
  char ** argv_new;
  poptContext pc;
  static char *servicesf = CONFIGFILE;
  static char *target_workgroup = NULL;
  static char *comment = "";
  static char *user_name = NULL;
  static char *my_workgroup = NULL;
  static char *requester_name = NULL;
  static char *dest_host = NULL;
  static int maxusers = -1;
  static int flagsarg = -1;
  static int jobid = 0;
  static int debuglevel;
  
  static struct poptOption long_options[] = {
    {"help",        'h', POPT_ARG_NONE,   0,     'h'},
    {"workgroup",   'w', POPT_ARG_STRING, &target_workgroup},
    {"myworkgroup", 'W', POPT_ARG_STRING, &my_workgroup},
    {"user",        'U', POPT_ARG_STRING, &user_name, 'U'},
    {"ipaddress",   'I', POPT_ARG_STRING, 0,     'I'},
    {"port",        'p', POPT_ARG_INT,    &port},
    {"myname",      'n', POPT_ARG_STRING, &requester_name},
    {"conf",        's', POPT_ARG_STRING, &servicesf},
    {"debug",       'd', POPT_ARG_INT,    &debuglevel, 'd'},
    {"server",      'S', POPT_ARG_STRING, &dest_host},
    {"comment",     'C', POPT_ARG_STRING, &comment},
    {"maxusers",    'M', POPT_ARG_INT,    &maxusers},
    {"flags",       'F', POPT_ARG_INT,    &flagsarg},
    {"jobid",       'j', POPT_ARG_INT,    &jobid},
    {"long",        'l', POPT_ARG_NONE,   &long_list_entries},
    { 0, 0, 0, 0}
  };

  got_pass = 0;
  dest_ip = ipzero;
  host[0] = 0;

  dbf = x_stdout;

  pc = poptGetContext(NULL, argc, (const char **) argv, long_options, 
		      POPT_CONTEXT_KEEP_FIRST);

  while((opt = poptGetNextOpt(pc)) != -1) {
    switch (opt) {
      case 'h':
        usage();
	exit(0);
	break;
      case 'd':
	DEBUGLEVEL=debuglevel;
	break;
      case 'I':
	dest_ip = *interpret_addr2(poptGetOptArg(pc));
	if(zero_ip(dest_ip))
	  printf(ERRMSG_INVALID_IPADDRESS);
	else
	  have_ip = True;
	break;
      case 'U':
	p = strchr(user_name,'%');
	pstrcpy(global_user_name, user_name);
	if (p) {
	  *p = 0;
	  pstrcpy(password,p+1);
	  got_pass = 1;
	}
	break;
      default:
	printf(ERRMSG_INVALID_OPTION, (char)opt, opt);
	usage();
    }
  }

  lp_load(servicesf,True,False,False);

  argv_new = poptGetArgs(pc);

  for (i=0; i<argc; i++) {
    if (argv_new[i] == NULL) {
      argc_new = i;
      break;
    }
  }
		 
  if (argc_new < 2) {
    usage();
    return -1;
  }

  func = get_func(argv_new[1]);

  if (func == 0)
    return -1;

  if (argc_new < 3) {
    if (func == VALIDATEF) {
      validate_usage();
      return -1;
    }
    if (func == HELPF) {
      usage();
      return 0;
    }
  }
        
  if (func == HELPF) {
    switch(get_func(argv_new[2])) { 
      case FILEF:
	file_usage();
	break;
      case SHAREF:
	share_usage();
	break;
      case SESSIONF:
	session_usage();
	break;
      case SERVERF:
	server_usage();
	break;
      case DOMAINF:
	domain_usage();
	break;
      case PRINTQF:
	printq_usage();
	break;
      case USERF:
	user_usage();
	break;
      case GROUPF:
	group_usage();
	break;
      case VALIDATEF:
	validate_usage();
	break;
      case GROUPMEMBERF:
	groupmember_usage();
	break;
      case HELPF:
	usage();
	break;
      default:
	printf(ERRMSG_INVALID_HELP_OPTION);
	usage();
    }
    return 0;
  }

  if (argc_new > 2) {
    /* parse next parm (argument 2) - i.e. sub function */
    subfunc = get_subfunc(argv_new[2]);
  }
  if (func == 0) return -1;

  if (requester_name)
    pstrcpy(global_requester_name, requester_name);
  else
    get_myname(global_requester_name);

  if (user_name)
    pstrcpy(global_user_name, user_name);
  else if (getenv("LOGNAME"))
    pstrcpy(global_user_name,getenv("LOGNAME"));

  fstrcpy(global_workgroup, my_workgroup ? my_workgroup :lp_workgroup());

  if (dest_host)
    pstrcpy(host, dest_host);

  if((have_ip) && (host[0]))
    printf(ERRMSG_BOTH_SERVER_IPADDRESS);

  while (!got_pass) {    /* BB if nulluser operation. why bother to ask for pword BB */
    p = getpass(PASSWORD_PROMPT);
    if (p) {
      pstrcpy(password, p);
      got_pass = 1;
    }
  }

  load_interfaces();

  switch (func) {
    case FILEF:
      if(argc_new <= 3) {
	if (subfunc == OTHER_SF)
	  rc = net_file(subfunc, argv_new[2]);
	else
	  rc = net_file(subfunc,NULL);
      } else 
	rc = net_file(subfunc,argv_new[3]);
      break;
    case SHAREF:
      if (argc_new == 2)
	rc = net_share(subfunc, NULL, NULL, 0);
      else
	rc = net_share(subfunc,argv_new[3], comment, maxusers);
      break;
    case SESSIONF:
      if (argc_new <= 3)
	rc = net_session(subfunc,NULL);
      else
	rc = net_session(subfunc,argv_new[3]);
      break;
    case SERVERF:
      rc = net_server(target_workgroup, subfunc);
      break;
    case DOMAINF:
      if(subfunc != LIST_SF)
	printf(ERRMSG_INVALID_DOMAIN_ACTION);
      rc = net_domain();
      break;
    case USERF:
      if (argc_new == 2)
	rc = net_user(subfunc, NULL, NULL, -1);
      else if(argc_new == 3)
	rc = net_user(subfunc,NULL, NULL, -1);
      else if(argc_new > 3)
	rc = net_user(subfunc,argv_new[3], comment, flagsarg);
      break;
    case GROUPF:
      if (argc_new == 2)
	rc = net_group(subfunc, NULL, NULL);
      else if(argc_new == 3)
	rc = net_group(subfunc,NULL, NULL);
      else if(argc_new > 3)
	rc = net_group(subfunc,argv_new[3], comment);
      break;
    case GROUPMEMBERF:
      if (argc_new == 4)
	rc = net_groupmember(subfunc, argv_new[3], NULL);
      else if (argc_new == 5)
	rc = net_groupmember(subfunc, argv_new[3], argv_new[4]);
      else {
	groupmember_usage();
	rc = -1;
      }
      break;
    case VALIDATEF:
      rc = net_validate(global_user_name);
      break;
    case PRINTQF:
      if (argc_new <= 3)
	rc = net_printq(subfunc, NULL, jobid);
      else
	rc = net_printq(subfunc, argv_new[3], jobid);
      break;
    default:
      usage();
      return -1;
  }	
  DEBUG(1,("return code = %d\n", rc));
  return rc;
}




